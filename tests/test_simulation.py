"""Ordinary simulation supplies the episode pool that trace-first grader inspection labels.

Only Harbor's Trial and Docker's archive reads are replaced, at the native boundary
the Docker tests in test_inspection.py cover. The run's queue, runner, verification-start hook,
capture producer, Oracle receipt, Inspector session and assessment are real.
"""

import asyncio
import base64
import hashlib
import json
import os
import shlex
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import litellm
import pytest
from aiohttp import web
from harbor.environments.base import ExecResult
from harbor.models.task.id import LocalTaskId
from harbor.models.trial.result import AgentInfo, ExceptionInfo, TrialResult
from harbor.models.verifier.result import VerifierResult
from harbor.trial.hooks import TrialEvent
from harbor.trial.trial import Trial

from nudi import checks, workflow
from nudi.records import (Assessment, Check, Claim, Content, Coverage, EpisodeResult, ErrorRecord, ModelConfig,
                          Observation, RunRecord)
from test_inspection import CHECKER, InspectorScript
from test_limits import credentials, new_run  # noqa: F401  (pytest fixture)
from test_runner import CONTRACT_TASK, serve, tree_digest

REQUIREMENT = "At verification start, /app/explanation.txt must exist."
SCORING = 'echo \'{"reward": 1.0, "answer_ok": 1.0}\''


def task_with_artifacts(tmp_path: Path, artifacts: str) -> Path:
    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    (task / "instruction.md").write_text("Write the number 42 to /app/answer.txt. " + REQUIREMENT + "\n")
    toml = task / "task.toml"
    toml.write_text(f"artifacts = {artifacts}\n" + toml.read_text())
    return task


def stored(run) -> RunRecord:
    return RunRecord.model_validate_json((run.config.output_dir / "run.json").read_text())


class LocalEnvironment:
    """Runs the Oracle adapter's command on the host, in place of the disposable container."""

    session_id = "local-check-instance"

    async def exec(self, *, command):
        args = shlex.split(command)
        process = await asyncio.create_subprocess_exec(sys.executable, *args[1:], stdout=asyncio.subprocess.PIPE,
                                                       stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        return ExecResult(stdout=stdout.decode(), stderr=stderr.decode(), return_code=process.returncode)


class Native:
    """Harbor trials and Docker archive reads. `files` maps an episode to the container
    files its agent leaves (absent: none); None makes that episode's archive read fail."""

    def __init__(self, monkeypatch, files=None, rewards=None, delay=0.05):
        self.files, self.rewards, self.delay = files or {}, rewards or {}, delay
        self.configs, self.instructions, self.containers = {}, {}, {}
        self.active = self.most = 0
        self.raises, self.after = set(), {}
        self.returned = {}
        """Episode name to the exception type Harbor returns in exception_info, still graded."""
        self.agents = {}
        """Episode name to an async stand-in for Terminus 2's work, given the trial config."""
        monkeypatch.setattr(Trial, "create", staticmethod(self.create))
        monkeypatch.setattr(checks, "host_command", self.docker)

    async def create(self, config):
        return FakeTrial(self, config)

    async def docker(self, command, *, timeout=30):
        if command[0] == "docker":
            return 0, command[4].removeprefix("label=com.docker.compose.project=") + "\n", ""
        container, location, ids = command[3], command[4], json.loads(command[5])
        files = self.files.get(self.containers[container], {})
        if files is None:
            return 1, "", "Error response from daemon: archive unavailable"
        state = {"location": location, "exists": location in files, "observed_start": "start", "observed_end": "end"}
        if location in files:
            state["base64"] = base64.b64encode(files[location]).decode()
        text = json.dumps(state, sort_keys=True)
        return 0, json.dumps({"state": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                              "location": location, "ids": ids}), ""


class FakeTrial:
    def __init__(self, native, config):
        self.native, self.config, self.hooks = native, config, []

    def add_hook(self, event, hook):
        if event == TrialEvent.VERIFICATION_START:
            self.hooks.append(hook)

    async def run(self):
        native, config = self.native, self.config
        name = config.trials_dir.parent.name
        native.active += 1
        native.most = max(native.most, native.active)
        try:
            native.configs[name] = config
            native.instructions[name] = (Path(config.task.path) / "instruction.md").read_text()
            await asyncio.sleep(native.delay)
            trial_dir = config.trials_dir / config.trial_name
            (trial_dir / "agent").mkdir(parents=True)
            if name in native.raises:
                raise RuntimeError("fake trial failure")
            if config.agent.import_path:
                agent = checks.RetainedOracle(**config.agent.kwargs, logs_dir=trial_dir / "agent")
                await agent.run("", LocalEnvironment(), None)
            else:
                if name in native.agents:
                    await native.agents[name](config)
                (trial_dir / "agent" / "trajectory.json").write_text(json.dumps({"ordinary": name}))
            failure = None
            if name in native.returned:
                failure = ExceptionInfo(exception_type=native.returned[name], exception_message="native outcome",
                                        exception_traceback="", occurred_at=datetime.now(timezone.utc))
            result = TrialResult(task_name="task", trial_name=config.trial_name, trial_uri=trial_dir.as_uri(),
                                 task_id=LocalTaskId(path=config.task.path), task_checksum="checksum", config=config,
                                 agent_info=AgentInfo(name="fake", version="0"), exception_info=failure,
                                 verifier_result=VerifierResult(rewards={"reward": native.rewards.get(name, 1.0)}))
            native.containers[config.trial_name.lower() + "__env"] = name
            for hook in self.hooks:
                await hook(SimpleNamespace(trial_name=config.trial_name, trial_id=result.id, result=result))
            (trial_dir / "result.json").write_text(result.model_dump_json())
            if name in native.after:
                native.after[name]()
            return result
        finally:
            native.active -= 1


@pytest.mark.parametrize("count", [None, 3])
def test_default_and_configured_counts_share_the_queue_and_original_task(tmp_path, monkeypatch, credentials, count):
    native = Native(monkeypatch)
    # 90% of 3 CPUs fits two one-CPU episodes at once.
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(3, 4096))
    simulation = asyncio.run(workflow.simulate(run) if count is None else workflow.simulate(run, count))
    expected = [f"{index:04d}-simulator" for index in range(count or 20)]
    assert simulation.requested == len(expected)
    assert simulation.episodes == expected == run.record.episodes
    assert simulation.status == "complete"
    assert (run.record.capacity.concurrency, native.most) == (2, 2)
    original = (CONTRACT_TASK / "instruction.md").read_text()
    for name in expected:
        agent = native.configs[name].agent
        assert (agent.name, agent.model_name, agent.import_path) == ("terminus-2", run.record.models["simulator"].model, None)
        assert native.instructions[name] == original
    assert stored(run).simulation == simulation


@pytest.mark.parametrize("count", [0, -2, 2.0, True])
def test_invalid_count_fails_before_any_episode(tmp_path, monkeypatch, credentials, count):
    Native(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    with pytest.raises(ValueError):
        asyncio.run(workflow.simulate(run, count))
    assert run.record.episodes == []


def test_failure_and_spending_cap_keep_every_attempt_without_retry(tmp_path, monkeypatch, credentials):
    native = Native(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096), spending_cap=1.0)
    native.raises = {"0001-simulator"}
    native.after["0002-simulator"] = lambda: setattr(run.record, "known_cost", 1.0)
    simulation = asyncio.run(workflow.simulate(run, 5))
    assert simulation.episodes == ["0000-simulator", "0001-simulator", "0002-simulator"] == run.record.episodes
    assert simulation.status == "spending_exhausted"
    assert list(simulation.failures) == ["0001-simulator"]
    assert simulation.failures["0001-simulator"][0].message == "fake trial failure"
    failed = json.loads((run.config.output_dir / "episodes" / "0001-simulator" / "episode.json").read_text())
    assert failed["errors"][0]["message"] == "fake trial failure"
    assert stored(run).simulation == simulation


def test_cancellation_records_the_partial_pool(tmp_path, monkeypatch, credentials):
    Native(monkeypatch, delay=5)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096))

    async def main():
        running = asyncio.create_task(workflow.simulate(run, 3))
        await asyncio.sleep(0.5)
        running.cancel()
        await asyncio.wait({running})

    asyncio.run(main())
    simulation = stored(run).simulation
    assert (simulation.status, simulation.episodes) == ("cancelled", ["0000-simulator"])
    episode = json.loads((run.config.output_dir / "episodes" / "0000-simulator" / "episode.json").read_text())
    assert episode["cancelled"]


def test_returned_native_failure_counts_without_a_raise(tmp_path, monkeypatch, credentials):
    """Harbor returns exception_info and still grades; the pool is then partial."""
    native = Native(monkeypatch)
    native.returned = {"0001-simulator": "AgentTimeoutError"}
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096))
    simulation = asyncio.run(workflow.simulate(run, 2))
    assert simulation.status == "partial"
    assert list(simulation.failures) == ["0001-simulator"]
    assert [error.type for error in simulation.failures["0001-simulator"]] == ["AgentTimeoutError"]
    timed_out = json.loads((run.config.output_dir / "episodes" / "0001-simulator" / "episode.json").read_text())
    assert timed_out["agent_timeout"] and timed_out["rewards"] == {"reward": 1.0}
    assert stored(run).simulation == simulation


class Provider:
    """An OpenAI-compatible endpoint returning scripted (status, body) replies in order."""

    def __init__(self, replies):
        self.replies, self.requests = iter(replies), []

    async def chat(self, request):
        self.requests.append(await request.json())
        status, body = next(self.replies)
        return web.json_response(body, status=status)


def completion(message: dict, finish_reason: str) -> dict:
    return {"id": "provider", "object": "chat.completion", "created": 0, "model": "grok-4.7",
            "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}}


async def terminus(config):
    """Terminus 2 sends its request through LiteLLM; a failed call ends its work."""
    try:
        await litellm.acompletion(model=config.agent.model_name, api_base=config.agent.kwargs["api_base"],
                                  messages=[{"role": "user", "content": "Solve the task."}], num_retries=0, max_retries=0)
    except Exception:
        pass


def test_explicit_model_refusals_stay_apart_from_failures_and_spending_admission(tmp_path, monkeypatch, credentials):
    native = Native(monkeypatch)
    provider = Provider([
        (200, completion({"role": "assistant", "content": None, "refusal": "I can't help with that."}, "content_filter")),
        (400, {"error": {"message": "Your request was rejected as a result of our safety system.",
                         "type": "invalid_request_error", "code": "content_policy_violation"}}),
        (500, {"error": {"message": "upstream unavailable", "type": "server_error"}}),
    ])

    async def main():
        async with serve(provider) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096), spending_cap=1.0,
                          models={"simulator": ModelConfig(model="xai/grok-4.7", api_base=base)})

            async def capped(config):
                run.record.known_cost = 1.0
                await terminus(config)

            native.agents = {"0000-simulator": terminus, "0001-simulator": terminus, "0002-simulator": terminus, "0003-simulator": capped}
            return run, await workflow.simulate(run, 4)

    run, simulation = asyncio.run(main())
    assert simulation.episodes == [f"{index:04d}-simulator" for index in range(4)]
    assert len(provider.requests) == 3
    assert simulation.refusals == {"0000-simulator": ["message.refusal: I can't help with that.", "finish_reason: content_filter"],
                                   "0001-simulator": ["ContentPolicyViolationError"]}
    calls = {call.episode: call for call in run.record.calls}
    assert calls["0002-simulator"].error and calls["0002-simulator"].refusals == []
    assert calls["0000-simulator"].error is None
    assert run.record.refused_calls == {"0003-simulator": 1}
    assert simulation.failures == {} and simulation.status == "complete"
    assert stored(run).simulation == simulation


def test_selection_uses_supported_main_service_sources_and_keeps_provenance(tmp_path):
    task = task_with_artifacts(tmp_path, '["/app/explanation.txt", {source = "/app/report.json", destination = "host/report.json"}, '
                                         '"relative.txt", "/app/output/", {source = "/app/logs", exclude = ["*.tmp"]}, '
                                         '"/logs/verifier/reward.json", "/tests/test.sh", {source = "/var/lib/db.sqlite", service = "db"}]')
    selection = checks.select_artifacts(task)
    assert [(item.declaration, item.source, item.selected) for item in selection] == [
        (0, "/app/explanation.txt", True), (1, "/app/report.json", True), (2, "relative.txt", False),
        (3, "/app/output/", False), (4, "/app/logs", False), (5, "/logs/verifier/reward.json", False),
        (6, "/tests/test.sh", False), (7, "/var/lib/db.sqlite", False)]
    assert selection[1].destination == "host/report.json"
    assert "absolute" in selection[2].reason
    assert all("director" in item.reason for item in selection[3:5])
    assert all("grader" in item.reason for item in selection[5:7])
    assert selection[7].service == "db" and "helper" in selection[7].reason


ANSWER = "Write the number 42 to /app/answer.txt."
ANSWER_CHECKER = '''import base64, hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs["submission"])
correct = int(state["exists"] and base64.b64decode(state["base64"]).strip() == b"42")
print(json.dumps({"input_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()}, "observations": {"correct": correct}, "results": {"deserved": correct}}))
'''
REFERENCES = {"explanation": {"episode": None, "path": "instruction.md", "excerpt": REQUIREMENT},
              "answer": {"episode": None, "path": "instruction.md", "excerpt": ANSWER},
              "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": SCORING}}


def probe(episode: str, requirement: str = "explanation") -> dict:
    location, program = ("/app/answer.txt", ANSWER_CHECKER) if requirement == "answer" else ("/app/explanation.txt", CHECKER)
    return {"category": "omitted_requirements", "case": f"{requirement} in {episode}", "episode": episode,
            "location": location, "capture_point": "verification_start",
            "timing": "The requirements apply to the submission at verification start.", "program": program,
            "requirement": REFERENCES[requirement], "scoring": REFERENCES["scoring"]}


def interpretation(validity: str, observation: str = "exists", **claim) -> dict:
    return {"claim": {"mechanism": "required work", "interpretation": "Full credit needs this requirement met.",
                      "derivation": {"observations": [observation], "minimum": "deserved", "maximum": "deserved", "validity": validity},
                      **claim}}


def coverage(requirements: list[str], checks: list[str]) -> dict:
    return {"requirements": [REFERENCES[name] for name in requirements], "scoring": REFERENCES["scoring"], "checks": checks,
            "explanation": "The grader awards 1.0 for this submission; the cited checks observe every requirement it needs."}


def test_selected_capture_reaches_supported_ordinary_labels_and_incomplete_support_stays_unknown(tmp_path, monkeypatch, credentials):
    """An all-pass pool. Explanation existence alone cannot make an episode legitimate;
    its answer must also be observed and the whole scoring outcome interpreted."""
    task = task_with_artifacts(tmp_path, '["/app/explanation.txt", "/app/answer.txt", "/logs/verifier/reward.json"]')
    complete = {"/app/answer.txt": b"42\n", "/app/explanation.txt": b"because\n"}
    native = Native(monkeypatch, files={"0000-simulator": {"/app/answer.txt": b"42\n"}, "0001-simulator": complete,
                                        "0002-simulator": None, "0003-simulator": complete, "0004-simulator": complete})
    unobserved = ["/app/answer.txt containing 42 has not been observed"]
    script = InspectorScript([
        {"probes": [probe("0001-simulator"), probe("0001-simulator", "answer"), probe("0003-simulator"),
                    probe("0004-simulator"), probe("0000-simulator")]},
        interpretation("supported"),
        interpretation("supported", "correct", coverage=coverage(["explanation", "answer"], ["check-0000", "check-0001"])),
        interpretation("supported", unresolved=unobserved),
        interpretation("supported", coverage=coverage(["explanation", "answer"], ["check-0003"])),
        interpretation("violated"),
    ])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 5)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["omitted_requirements"], focused_attempts=0)
            return run, simulation, report

    run, simulation, report = asyncio.run(main())
    assert [item.source for item in simulation.selection if item.selected] == ["/app/explanation.txt", "/app/answer.txt"]
    pool = [f"{index:04d}-simulator" for index in range(5)]
    assert simulation.episodes == pool
    broad = json.loads(script.requests[0]["messages"][-1]["content"])
    assert broad["capture_inventory"] == [item.model_dump() for item in simulation.selection]
    ordinary = broad["ordinary_episodes_read_first"]
    assert [episode["episode"] for episode in ordinary] == pool
    assert [episode["rewards"] for episode in ordinary] == [{"reward": 1.0}] * 5
    assert [state["location"] for state in ordinary[0]["captured"]] == ["/app/explanation.txt", "/app/answer.txt"]
    assert ordinary[2]["captured"] == [] and ordinary[2]["capture_failures"][0]["location"] == "/app/explanation.txt"
    assert [assessment.outcome for assessment in report.assessments] == ["legitimate"] * 4 + ["accepted_invalid"]
    labels = {name: label.label for name, label in report.ordinary.items()}
    assert labels == {"0000-simulator": "accepted_invalid", "0001-simulator": "legitimate", "0002-simulator": "unknown",
                      "0003-simulator": "unknown", "0004-simulator": "unknown"}
    reasons = {name: " ".join(label.reasons) for name, label in report.ordinary.items()}
    assert "archive unavailable" in reasons["0002-simulator"] and "not evidence of absence" in reasons["0002-simulator"]
    assert unobserved[0] in reasons["0003-simulator"]
    assert ANSWER in reasons["0004-simulator"] and "no cited check" in reasons["0004-simulator"]
    assert report.categories["omitted_requirements"] == "evidenced_issue"
    # The pool is reused: no further ordinary episode, and only checks ran afterwards.
    assert run.record.episodes == pool + [f"{index:04d}-inspector" for index in range(5, 10)]
    assert all(native.instructions[name] == (task / "instruction.md").read_text() for name in pool)


HALVES = "# The answer 42 and the explanation file each earn 0.5."
HALF_CHECKERS = {name: f'''import base64, hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs["submission"])
met = int({test})
print(json.dumps({{"input_sha256": {{k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()}}, "observations": {{"{name}": met}}, "results": {{"minimum": 0.5 * met, "maximum": 0.5 * met + 0.5}}}}))
''' for name, test in (("exists", 'state["exists"]'), ("correct", 'state["exists"] and base64.b64decode(state["base64"]).strip() == b"42"'))}


def test_combined_coverage_of_separate_checks_justifies_legitimate_partial_credit(tmp_path, monkeypatch, credentials):
    """Each requirement earns 0.5. The explanation is met ([0.5, 1]) and the answer
    omitted ([0, 0.5]); neither check alone is exact, and together they justify 0.5.
    Unresolved or failed cited evidence keeps the same combination unknown."""
    task = task_with_artifacts(tmp_path, '["/app/explanation.txt", "/app/answer.txt"]')
    with (task / "tests" / "test.sh").open("a") as file:
        file.write("\n" + HALVES + "\n")
    explanation_only = {"/app/explanation.txt": b"because\n"}
    pool = [f"{index:04d}-simulator" for index in range(3)]
    Native(monkeypatch, files=dict.fromkeys(pool, explanation_only), rewards=dict.fromkeys(pool, 0.5))
    scoring = {"episode": None, "path": "tests/test.sh", "excerpt": HALVES}

    def half(episode, requirement, program=None):
        name = "correct" if requirement == "answer" else "exists"
        return {**probe(episode, requirement), "category": "partial_credit", "scoring": scoring,
                "program": program or HALF_CHECKERS[name]}

    def bounded(validity, name, **claim):
        return {"claim": {"mechanism": "half credit", "interpretation": f"This requirement earns 0.5 of the reward; {name} measures it.",
                          "derivation": {"observations": [name], "minimum": "minimum", "maximum": "maximum", "validity": validity},
                          **claim}}

    def combined(checks):
        return {"requirements": [REFERENCES["explanation"], REFERENCES["answer"]], "scoring": scoring, "checks": checks,
                "explanation": "The explanation earns 0.5 and the omitted answer earns nothing, so the actual reward 0.5 is deserved."}

    script = InspectorScript([
        {"probes": [half("0000-simulator", "explanation"), half("0000-simulator", "answer"),
                    half("0001-simulator", "explanation"), half("0001-simulator", "answer"),
                    half("0002-simulator", "answer", program="import sys\nsys.exit(3)\n"), half("0002-simulator", "explanation")]},
        bounded("supported", "exists"),
        bounded("violated", "correct", coverage=combined(["check-0000", "check-0001"])),
        bounded("supported", "exists", unresolved=["whether the explanation is read at verification start"]),
        bounded("violated", "correct", coverage=combined(["check-0002", "check-0003"])),
        bounded("supported", "exists", coverage=combined(["check-0005", "check-0004"])),
    ])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 3)
            return await checks.inspect_grader(run, simulation.episodes, categories=["partial_credit"], focused_attempts=0)

    report = asyncio.run(main())
    assessments = report.assessments
    assert [assessment.outcome for assessment in assessments] == ["unknown"] * 6
    assert [(assessment.validity, assessment.discrepancy) for assessment in assessments[:2]] == [("supported", "none"), ("violated", "none")]
    assert assessments[4].check.exit_code != 0
    labels = {name: label.label for name, label in report.ordinary.items()}
    assert labels == {"0000-simulator": "legitimate", "0001-simulator": "unknown", "0002-simulator": "unknown"}
    reasons = {name: " ".join(label.reasons) for name, label in report.ordinary.items()}
    assert "actual reward 0.5 is deserved" in reasons["0000-simulator"]
    assert "check-0002" in reasons["0001-simulator"] and "verification start" in reasons["0001-simulator"]
    assert "check-0004" in reasons["0002-simulator"] and "complete scoring outcome" in reasons["0002-simulator"]


def test_without_declarations_ordinary_labels_stay_unknown_and_a_probe_never_backfills(tmp_path, monkeypatch, credentials):
    targeted = {**probe("unused"), "instruction": "Inspector-only targeted probe: skip the explanation."}
    del targeted["episode"]
    task = task_with_artifacts(tmp_path, "[]")
    native = Native(monkeypatch)
    script = InspectorScript([{"probes": [targeted]}, interpretation("violated")])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 2)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["omitted_requirements"], focused_attempts=0)
            return run, simulation, report

    run, simulation, report = asyncio.run(main())
    assert simulation.selection == [] and run.record.submissions[0].content.episode == "0002-inspector"
    assert any("cannot supply ordinary" in warning for warning in run.record.warnings)
    assert report.assessments[0].claim.episode == "0002-inspector"
    assert report.assessments[0].outcome == "accepted_invalid"
    assert report.categories["omitted_requirements"] == "evidenced_issue"
    assert set(report.ordinary) == {"0000-simulator", "0001-simulator"}
    for label in report.ordinary.values():
        assert label.label == "unknown" and label.assessments == []
        assert "not evidence of absence" in " ".join(label.reasons)
        assert "does not establish legitimacy" in " ".join(label.reasons)
    assert "Inspector-only" in native.instructions["0002-inspector"]
    assert not any("Inspector-only" in native.instructions[name] for name in simulation.episodes)


def test_labels_keep_partial_credit_unknowns_and_unavailable_rewards_apart_from_probes(tmp_path, monkeypatch, credentials):
    def episode(run, name, rewards, errors=()):
        directory = run.config.output_dir / "episodes" / name
        directory.mkdir(parents=True)
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir),
                               task_digest=tree_digest(run.config.task_dir), model="ordinary", reasoning_effort=None,
                               versions={}, rewards=rewards, errors=[ErrorRecord(type=error, message=error) for error in errors])
        (directory / "episode.json").write_text(result.model_dump_json())
        run.record.episodes.append(name)

    requirement = Observation(episode=None, path="instruction.md", excerpt="Write the number 42")
    scoring = Observation(episode=None, path="tests/test.sh", excerpt="reward")
    covered = Coverage(requirements=[requirement], scoring=scoring, checks=["check-a"],
                       explanation="One of two scored components is met, so the actual reward 0.5 is deserved.")
    pool = [f"{index:04d}-simulator" for index in range(8)]
    # (category, episode, outcome, claim fields, check id, missing)
    cases = [("partial_credit", "0000-simulator", "legitimate", {"coverage": covered}, "check-a", []),
             ("partial_credit", "0001-simulator", "unknown", {}, None, ["independent state at requested time 'grader_read'"]),
             ("partial_credit", "0004-simulator", "legitimate", {"coverage": covered.model_copy(update={"checks": ["check-c"]})}, "check-c", []),
             ("rejected_valid", "0004-simulator", "accepted_invalid", {}, None, []),
             ("partial_credit", "0005-simulator", "accepted_invalid", {"unresolved": ["whether the requirement applies at verification start"]}, None, []),
             ("partial_credit", "0006-simulator", "legitimate", {}, "check-d", []),
             ("accepted_invalid", "0006-simulator", "accepted_invalid", {}, None, []),
             ("partial_credit", "0007-simulator", "legitimate", {"coverage": covered}, "check-e", []),
             ("omitted_requirements", "0008-inspector", "accepted_invalid", {}, None, [])]
    probes = [{"category": category, "case": str(index), "location": f"/app/{index}",
               **({"instruction": "targeted"} if name.endswith("inspector") else {"episode": name})}
              for index, (category, name, *_) in enumerate(cases)]
    outcomes = iter(cases)

    async def investigate(run, probe, session):
        _, name, outcome, fields, check, missing = next(outcomes)
        checked = check and Check(id=check, content=Content(episode=name, path="state", sha256="hash"), ids={},
                                  requirement=requirement, scoring=scoring, command=[], exit_code=0, output="")
        # As assess() records it: a legitimate outcome has an exact supported bound.
        consistent = {"validity": "supported", "discrepancy": "none"} if outcome == "legitimate" else {}
        return Assessment(claim=Claim(mechanism=probe["case"], episode=name, check=check, **fields), outcome=outcome,
                          check=checked or None, missing=missing, **consistent)

    monkeypatch.setattr(checks, "investigate", investigate)
    script = InspectorScript([{"probes": probes}])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            for index, name in enumerate(pool + ["0008-inspector"]):
                rewards = {} if index == 2 else {"reward": {0: 0.5, 3: 0.0}.get(index, 1.0)}
                episode(run, name, rewards, ("VerifierRuntimeError",) if index == 2 else ())
            run.save()
            return await checks.inspect_grader(run, pool, focused_attempts=0,
                                               categories=["accepted_invalid", "rejected_valid", "omitted_requirements", "partial_credit"])

    report = asyncio.run(main())
    labels = report.ordinary
    reasons = {name: " ".join(label.reasons) for name, label in labels.items()}
    assert set(labels) == set(pool)
    assert (labels["0000-simulator"].label, labels["0000-simulator"].assessments) == ("legitimate", [0])
    assert covered.explanation in reasons["0000-simulator"]
    assert labels["0001-simulator"].label == "unknown" and "grader_read" in reasons["0001-simulator"]
    assert labels["0002-simulator"].label == "unavailable" and "VerifierRuntimeError" in labels["0002-simulator"].reasons[0]
    assert labels["0003-simulator"].label == "unknown" and labels["0003-simulator"].assessments == []
    assert "does not establish legitimacy" in reasons["0003-simulator"]
    assert labels["0004-simulator"].label == "unknown" and "disagree" in reasons["0004-simulator"]
    assert labels["0005-simulator"].label == "unknown" and "verification start" in reasons["0005-simulator"]
    assert labels["0006-simulator"].label == "accepted_invalid"
    assert labels["0007-simulator"].label == "unknown" and "check-a" in reasons["0007-simulator"]
    assert "complete scoring outcome" in reasons["0007-simulator"]
    assert report.assessments[-1].claim.episode == "0008-inspector"
    assert report.categories == {"accepted_invalid": "evidenced_issue", "rejected_valid": "evidenced_issue",
                                 "omitted_requirements": "evidenced_issue", "partial_credit": "no_evidenced_issue"}
