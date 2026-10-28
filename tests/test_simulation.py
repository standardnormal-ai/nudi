"""Ordinary simulation supplies the episode pool that trace-first grader inspection labels.

Only Harbor's Trial, Docker's archive reads and the Docker daemon's pause and stat
API are replaced, at the native boundary the Docker tests in test_inspection.py cover. Inspector
checks run in a sandbox double when the test installs one. The run's queue, runner,
verification-start hook, capture producer, Inspector session and assessment are real.
"""

import asyncio
import base64
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import httpx
import litellm
import pytest
from aiohttp import web
from harbor.models.task.id import LocalTaskId
from harbor.models.trial.result import AgentInfo, ExceptionInfo, TrialResult
from harbor.models.verifier.result import VerifierResult
from harbor.trial.hooks import TrialEvent
from harbor.trial.trial import Trial

from nudi import checks, report, sandbox, workflow
from nudi.records import (Assessment, Check, Claim, Content, Coverage, EpisodeResult, ErrorRecord, ModelConfig,
                          Observation, RunRecord)
from test_attack import FULL, GO_DIR, GO_FILE, GO_LINK, MINIMAL, stat_header
from test_inspection import CHECKER, InspectorScript, Sandboxes, sandbox_record
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


NOTHING = {"locations": []}
"""The Inspector's capture selection when it adds no file."""


def inspector(base: str) -> dict:
    return {"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)}


class Native:
    """Harbor trials, Docker archive reads and the daemon's pause and stat API. `files`
    maps an episode to the container files its agent leaves (absent: none); None makes
    that episode's archive read fail. `links` maps a container path to its symlink
    target, and `failing` names daemon actions (pause, unpause) that fail. `events`
    records daemon calls and archive reads in order."""

    def __init__(self, monkeypatch, files=None, rewards=None, delay=0.05, links=None, failing=()):
        self.files, self.rewards, self.delay = files or {}, rewards or {}, delay
        self.links, self.failing, self.events = links or {}, set(failing), []
        self.configs, self.instructions, self.containers = {}, {}, {}
        self.active = self.most = 0
        self.raises, self.after = set(), {}
        self.returned = {}
        """Episode name to the exception type Harbor returns in exception_info, still graded."""
        self.agents = {}
        """Episode name to an async stand-in for Terminus 2's work, given the trial config."""
        monkeypatch.setattr(Trial, "create", staticmethod(self.create))
        monkeypatch.setattr(checks, "host_command", self.docker)
        monkeypatch.setattr(checks, "unix_docker_socket", self.socket)
        monkeypatch.setattr(checks, "docker_client", self.client)

    async def create(self, config):
        return FakeTrial(self, config)

    async def socket(self):
        return "/native/docker.sock", None

    async def client(self, sock):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.daemon), base_url="http://docker"), "1.44"

    def daemon(self, request):
        container, action = request.url.path.split("/")[3:5]
        if request.method == "POST":
            self.events.append((action, container))
            return httpx.Response(500 if action in self.failing else 204)
        location = request.url.params["path"]
        self.events.append(("stat", location))
        files = self.files.get(self.containers[container]) or {}
        if location in self.links:
            header = stat_header(GO_LINK, self.links[location])
        elif location in files:
            header = stat_header(GO_FILE)
        elif location in ("/app", "/output") or any(path.startswith(location + "/") for path in [*files, *self.links]):
            header = stat_header(GO_DIR)
        else:
            return httpx.Response(404)
        return httpx.Response(200, headers={"X-Docker-Container-Path-Stat": header})

    async def docker(self, command, *, timeout=30):
        if command[0] == "docker":
            return 0, command[4].removeprefix("label=com.docker.compose.project=") + "\n", ""
        container, location, ids = command[3], command[4], json.loads(command[5])
        self.events.append(("read", location))
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
                raise AssertionError(f"a generated check must run in an Inspector sandbox, not native agent {config.agent.import_path}")
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

    async def main():
        async with serve(InspectorScript([NOTHING])) as base:
            # 90% of 3 CPUs fits two one-CPU episodes at once.
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(3, 4096), models=inspector(base))
            return run, await (workflow.simulate(run) if count is None else workflow.simulate(run, count))

    run, simulation = asyncio.run(main())
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
    native.raises = {"0001-simulator"}

    async def main():
        async with serve(InspectorScript([NOTHING])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096), spending_cap=1.0, models=inspector(base))
            native.after["0002-simulator"] = lambda: setattr(run.record, "known_cost", 1.0)
            return run, await workflow.simulate(run, 5)

    run, simulation = asyncio.run(main())
    assert simulation.episodes == ["0000-simulator", "0001-simulator", "0002-simulator"] == run.record.episodes
    assert simulation.status == "spending_exhausted"
    assert list(simulation.failures) == ["0001-simulator"]
    assert simulation.failures["0001-simulator"][0].message == "fake trial failure"
    failed = json.loads((run.config.output_dir / "episodes" / "0001-simulator" / "episode.json").read_text())
    assert failed["errors"][0]["message"] == "fake trial failure"
    assert stored(run).simulation == simulation


def test_cancellation_records_the_partial_pool(tmp_path, monkeypatch, credentials):
    Native(monkeypatch, delay=5)

    async def main():
        async with serve(InspectorScript([NOTHING])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096), models=inspector(base))
            running = asyncio.create_task(workflow.simulate(run, 3))
            await asyncio.sleep(0.5)
            running.cancel()
            await asyncio.wait({running})
            return run

    run = asyncio.run(main())
    simulation = stored(run).simulation
    assert (simulation.status, simulation.episodes) == ("cancelled", ["0000-simulator"])
    episode = json.loads((run.config.output_dir / "episodes" / "0000-simulator" / "episode.json").read_text())
    assert episode["cancelled"]


def test_returned_native_failure_counts_without_a_raise(tmp_path, monkeypatch, credentials):
    """Harbor returns exception_info and still grades; the pool is then partial."""
    native = Native(monkeypatch)
    native.returned = {"0001-simulator": "AgentTimeoutError"}

    async def main():
        async with serve(InspectorScript([NOTHING])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096), models=inspector(base))
            return run, await workflow.simulate(run, 2)

    run, simulation = asyncio.run(main())
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
        async with serve(provider) as base, serve(InspectorScript([NOTHING])) as selection:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096), spending_cap=1.0,
                          models={"simulator": ModelConfig(model="xai/grok-4.7", api_base=base), **inspector(selection)})

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
    Sandboxes(monkeypatch, native=native)
    unobserved = ["/app/answer.txt containing 42 has not been observed"]
    script = InspectorScript([
        NOTHING,
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
    selection = run.record.capture_selection.files
    assert [item.source for item in selection if item.selected] == ["/app/explanation.txt", "/app/answer.txt"]
    pool = [f"{index:04d}-simulator" for index in range(5)]
    assert simulation.episodes == pool
    broad = json.loads(script.requests[1]["messages"][-1]["content"])
    assert broad["capture_inventory"] == [item.model_dump() for item in selection]
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
    # The pool is reused: no further ordinary episode. The five checks are package sandboxes.
    assert run.record.episodes == pool
    assert run.record.sandboxes == [f"sandbox-{index:04d}" for index in range(5)]
    assert all(sandbox_record(run, name)["purpose"] == "check" for name in run.record.sandboxes)
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
    native = Native(monkeypatch, files=dict.fromkeys(pool, explanation_only), rewards=dict.fromkeys(pool, 0.5))
    Sandboxes(monkeypatch, native=native)
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
        NOTHING,
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


NEWLINE = "End /app/answer.txt with a newline."
EACH_HALF = "# The number 42 and the final newline each earn 0.5."
FACTS = {"answer": REFERENCES["answer"], "newline": {"episode": None, "path": "instruction.md", "excerpt": NEWLINE},
         "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": EACH_HALF}}
MEASURED = {"answer": "number", "newline": "newline"}
# One execution measures both requirements as Booleans. An absent file has no deserved score.
ANSWER_FACTS = '''import base64, hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs["submission"])
facts, results = {"exists": state["exists"]}, {}
if state["exists"]:
    data = base64.b64decode(state["base64"])
    facts.update(number=data.strip() == b"42", newline=data.endswith(b"\\n"))
    results["deserved"] = 0.5 * facts["number"] + 0.5 * facts["newline"]
print(json.dumps({"input_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in inputs.items()}, "observations": facts, "results": results}))
'''


def answer_task(tmp_path: Path) -> Path:
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    with (task / "instruction.md").open("a") as file:
        file.write(NEWLINE + "\n")
    with (task / "tests" / "test.sh").open("a") as file:
        file.write("\n" + EACH_HALF + "\n")
    return task


def facts_probe(episode: str, requirement: str = "answer") -> dict:
    return {**probe(episode, "answer"), "category": "partial_credit", "case": f"{requirement} in {episode}",
            "requirement": FACTS[requirement], "scoring": FACTS["scoring"], "program": ANSWER_FACTS}


def read(validity: str, observations: list[str], *, bounded=True, readings=(), **claim) -> dict:
    derivation = {"observations": observations, "validity": validity, "requirements": [
        {"requirement": FACTS[key], "observations": [MEASURED[key]], "validity": value,
         "interpretation": f"The {MEASURED[key]} fact measures this requirement."} for key, value in readings]}
    if bounded:
        derivation.update(minimum="deserved", maximum="deserved")
    return {"claim": {"mechanism": "answer facts", "interpretation": "Each requirement earns 0.5 of the reward.",
                      "derivation": derivation, **claim}}


def both(checks: list[str]) -> dict:
    return {"requirements": [FACTS["answer"], FACTS["newline"]], "scoring": FACTS["scoring"], "checks": checks,
            "explanation": "The cited facts settle both scored requirements and so the actual reward."}


def metric_basis(value: str, keys: list[str], checks: list[str]) -> dict:
    return {"completion": value, "requirements": [FACTS[key] for key in keys], "checks": checks, "explanation": f"completion {value}"}


def test_measured_facts_and_requirement_conclusions_reach_labels_and_reports(tmp_path, monkeypatch, credentials):
    """Measured absence with an unknown score, a failed capture, one check supporting the number while the
    newline is violated (legitimate partial credit), complete and partial coverage, and conflicting readings."""
    task = answer_task(tmp_path)
    pool = [f"{index:04d}-simulator" for index in range(6)]
    done = {"/app/answer.txt": b"42\n"}
    native = Native(monkeypatch, files={pool[0]: {}, pool[1]: None, pool[2]: {"/app/answer.txt": b"42"}, pool[3]: done,
                                        pool[4]: done, pool[5]: done}, rewards={pool[0]: 0.0, pool[2]: 0.5})
    Sandboxes(monkeypatch, native=native)
    script = InspectorScript([
        NOTHING,
        {"probes": [facts_probe(pool[0]), facts_probe(pool[1]), facts_probe(pool[2]), facts_probe(pool[3]),
                    facts_probe(pool[4]), facts_probe(pool[5], "newline"), facts_probe(pool[5])]},
        read("violated", ["exists"], bounded=False, basis=metric_basis("violated", ["answer"], ["check-0000"])),
        read("supported", ["number"], readings=[("newline", "violated")], coverage=both(["check-0001"]),
             basis=metric_basis("violated", ["newline"], ["check-0001"])),
        read("supported", ["number"], readings=[("newline", "supported")], coverage=both(["check-0002"]),
             basis=metric_basis("supported", ["answer", "newline"], ["check-0002"])),
        read("supported", ["number"], coverage=both(["check-0003"]), basis=metric_basis("supported", ["answer", "newline"], ["check-0003"])),
        read("supported", ["newline"]),
        read("supported", ["number"], readings=[("newline", "violated")], basis=metric_basis("violated", ["newline"], ["check-0005"])),
    ])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            simulation = await workflow.simulate(run, 6)
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["partial_credit"], focused_attempts=0)

    run, inspection = asyncio.run(main())
    assert len(script.requests) == 8 and len(run.record.checks) == 6
    assessments = inspection.assessments
    assert [(item.outcome, item.validity, item.discrepancy) for item in assessments] == [
        ("unknown", "violated", "unknown")] + [("legitimate", "supported", "none")] * 5
    assert [(item.requirement.excerpt, item.validity) for item in assessments[1].conclusions] == [(NEWLINE, "violated")]
    assert inspection.reviews[1].status == "tool_failure" and "Capture failed" in inspection.reviews[1].error
    labels = {name: label.label for name, label in inspection.ordinary.items()}
    assert labels == dict(zip(pool, ["unknown", "unknown", "legitimate", "legitimate", "unknown", "unknown"]))
    reasons = {name: " ".join(label.reasons) for name, label in inspection.ordinary.items()}
    assert "neither minimum nor maximum" in reasons[pool[0]] and "archive unavailable" in reasons[pool[1]]
    assert f"no cited check observes requirement instruction.md: {NEWLINE!r}" in reasons[pool[4]]

    built = report.build(run.config.output_dir)
    episodes = built["metrics"]["episodes"]
    assert [episodes[name]["completion"] for name in pool] == ["incomplete", "unknown", "incomplete", "complete", "unknown", "unknown"]
    assert any("conflicting" in reason for reason in episodes[pool[5]]["completion_reasons"])
    assert built["labels"]["review"]["unresolved"] == [pool[0], pool[1], pool[4], pool[5]]
    assert built["labels"]["review"]["unreviewed"] == {}
    findings = built["inspections"]["grader"]["findings"]
    absent = next(item for item in findings["suspected"] if item["claim"]["episode"] == pool[0])
    assert (absent["assessment"]["validity"], absent["assessment"]["discrepancy"]) == ("violated", "unknown")
    partial = next(item for item in findings["legitimate"] if item["claim"]["episode"] == pool[2])
    assert partial["assessment"]["conclusions"] == [{"requirement": FACTS["newline"], "validity": "violated", "reasons": []}]
    markdown = report.markdown(built).splitlines()
    assert "attempted but unresolved 4" in next(line for line in markdown if line.startswith("Review attempted"))
    line = next(line for line in markdown if line.startswith("- grader suspected:") and pool[0] in line)
    assert "validity violated" in line and "discrepancy unknown" in line
    line = next(line for line in markdown if line.startswith("- grader legitimate:") and pool[2] in line)
    assert f"requirement {NEWLINE!r} violated" in line and "native reward 0.5" in line


def test_completion_stays_unknown_when_a_cited_check_violation_is_omitted(tmp_path, monkeypatch, credentials):
    """A supported number and violated newline earn legitimate partial credit, not full completion."""
    task = answer_task(tmp_path)
    name = "0000-simulator"
    native = Native(monkeypatch, files={name: {"/app/answer.txt": b"42"}}, rewards={name: 0.5})
    Sandboxes(monkeypatch, native=native)
    script = InspectorScript([
        NOTHING,
        {"probes": [facts_probe(name)]},
        read("supported", ["number"], readings=[("newline", "violated")], coverage=both(["check-0000"]),
             basis=metric_basis("supported", ["answer"], ["check-0000"])),
    ])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            simulation = await workflow.simulate(run, 1)
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["partial_credit"], focused_attempts=0)

    run, inspection = asyncio.run(main())
    built = report.build(run.config.output_dir)
    episode = built["metrics"]["episodes"][name]
    assert episode["completion"] == "unknown"
    reasons = " ".join(episode["completion_reasons"])
    assert NEWLINE in reasons and "violated" in reasons and "completion basis" in reasons
    assert inspection.ordinary[name].label == "legitimate" and inspection.categories["partial_credit"] == "no_evidenced_issue"
    assert inspection.assessments[0].claim.basis.requirements == [Observation.model_validate(FACTS["answer"])]
    markdown = report.markdown(built).splitlines()
    assert any(line.startswith(f"- {name}: completion unknown;") for line in markdown)
    assert any(line.startswith("- grader legitimate:") and f"requirement {NEWLINE!r} violated" in line for line in markdown)


@pytest.mark.parametrize("case", ["uncontested", "conflicting", "unresolved"])
def test_secondary_conclusions_survive_unknown_primary_validity_in_labels_and_reports(tmp_path, monkeypatch, credentials, case):
    """An unmeasured primary requirement cannot hide a verified secondary violation or conflict."""
    task = answer_task(tmp_path)
    name = "0000-simulator"
    native = Native(monkeypatch, files={name: {"/app/answer.txt": b"42"}}, rewards={name: 0.5})
    Sandboxes(monkeypatch, native=native)
    probes = [facts_probe(name)] + ([facts_probe(name, "newline")] if case == "conflicting" else [])
    responses = [
        NOTHING,
        {"probes": probes},
        read("unknown", ["not_returned"], bounded=False, readings=[("newline", "violated")],
             basis=metric_basis("violated", ["newline"], ["check-0000"]),
             unresolved=["whether the newline requirement applies"] if case == "unresolved" else []),
    ]
    if case == "conflicting":
        responses.append(read("supported", ["newline"], readings=[("answer", "supported")], coverage=both(["check-0001"]),
                              basis=metric_basis("supported", ["newline"], ["check-0001"])))
    script = InspectorScript(responses)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            simulation = await workflow.simulate(run, 1)
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["partial_credit"], focused_attempts=0)

    run, inspection = asyncio.run(main())
    first = inspection.assessments[0]
    assert first.validity == "unknown" and first.discrepancy == "unknown"
    assert [(item.requirement.excerpt, item.validity) for item in first.conclusions] == [(NEWLINE, "violated")]
    assert len(script.requests) == 3 + (case == "conflicting") and len(run.record.checks) == len(probes)
    assert len(inspection.attempts) == 1 and inspection.unreviewed == {}
    built = report.build(run.config.output_dir)
    episode = built["metrics"]["episodes"][name]
    assert inspection.ordinary[name].label == "unknown", "requirement evidence alone cannot justify the scoring outcome"
    expected = "incomplete" if case == "uncontested" else "unknown"
    assert episode["completion"] == expected
    if case == "conflicting":
        for reasons in (episode["completion_reasons"], inspection.ordinary[name].reasons):
            assert any("conflicting" in reason and NEWLINE in reason for reason in reasons)
        assert inspection.assessments[1].outcome == "legitimate", "the independently supported reward bound stays separate"
    if case == "unresolved":
        assert first.claim.unresolved == ["whether the newline requirement applies"]
    markdown = report.markdown(built).splitlines()
    assert any(line.startswith(f"- {name}: completion {expected};") for line in markdown)
    assert any(line.startswith("- grader suspected:") and f"requirement {NEWLINE!r} violated" in line for line in markdown)


@pytest.mark.parametrize("case", ["corrected", "exhausted", "invalid"])
def test_corrected_interpretation_uses_the_next_existing_attempt_without_rerunning_the_check(tmp_path, monkeypatch, credentials, case):
    """A repair rides on the next budgeted planning response: no extra model request, check or sandbox.
    Repeating the probe is still a duplicate case, and with no attempt left the gap stays unknown."""
    task = answer_task(tmp_path)
    name = "0000-simulator"
    native = Native(monkeypatch, files={name: {"/app/answer.txt": b"42\n"}})
    Sandboxes(monkeypatch, native=native)
    corrected = read("supported", ["number"], readings=[("newline", "supported")], coverage=both(["check-0000"]),
                     basis=metric_basis("supported", ["answer", "newline"], ["check-0000"]))
    repair = {"check": "check-0009" if case == "invalid" else "check-0000", "category": "partial_credit", **corrected}
    responses = [NOTHING, {"probes": [facts_probe(name)]}, read("supported", ["number"], coverage=both(["check-0000"]))]
    if case != "exhausted":
        responses.append({"probes": [facts_probe(name)], "reinterpretations": [repair]})
    script = InspectorScript(responses)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            simulation = await workflow.simulate(run, 1)
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["partial_credit"],
                                                    focused_attempts=0 if case == "exhausted" else 1)

    run, inspection = asyncio.run(main())
    built = report.build(run.config.output_dir)
    assert len(script.requests) == len(responses), "a repair adds no model request"
    assert len(run.record.checks) == 1 and run.record.sandboxes == ["sandbox-0000"], "a repair executes nothing again"
    original = inspection.assessments[0]
    assert (original.outcome, original.conclusions) == ("legitimate", [])
    label = inspection.ordinary[name]
    if case == "corrected":
        payload = json.loads(script.requests[3]["messages"][-1]["content"])
        assert payload["unreviewed_ordinary_episodes"] == [] and "reinterpretations" in payload["instruction"]
        diagnostics = payload["unresolved_ordinary_reviews"][name]
        assert [item["id"] for item in diagnostics["checks"]] == ["check-0000"] and NEWLINE in json.dumps(diagnostics["reasons"])
        assert [item.status for item in inspection.attempts] == ["no_evidenced_issue", "duplicate_case"]
        repaired = inspection.reviews[1]
        assert (repaired.episode, repaired.reinterprets, repaired.status, repaired.checks, repaired.assessment) == (
            name, "check-0000", "assessed", {}, 1)
        assert [item.validity for item in inspection.assessments[1].conclusions] == ["supported"]
        assert label.label == "legitimate" and built["metrics"]["episodes"][name]["completion"] == "complete"
        assert built["labels"]["review"]["unresolved"] == [] and inspection.unreviewed == {}
    else:
        assert len(inspection.assessments) == 1 and label.label == "unknown" and NEWLINE in " ".join(label.reasons)
        assert built["labels"]["review"]["unresolved"] == [name] and built["labels"]["review"]["unreviewed"] == {}
        if case == "invalid":
            assert inspection.attempts[1].status == "model_output_failure" and "check-0009" in inspection.attempts[1].error


@pytest.mark.parametrize(("invalid", "error"), [
    ("unlisted", "check-0009"),
    ("item", "no listed unresolved review check"),
    ("claim", "Invalid Claim"),
    ("list", "reinterpretations must be a list"),
])
def test_invalid_reinterpretation_preserves_other_repairs_and_ordinary_probes(tmp_path, monkeypatch, credentials, invalid, error):
    """One invalid repair stays a reported failure while independent work uses the same attempt."""
    task = answer_task(tmp_path)
    first, second = "0000-simulator", "0001-simulator"
    native = Native(monkeypatch, files={name: {"/app/answer.txt": b"42\n"} for name in (first, second)})
    Sandboxes(monkeypatch, native=native)
    corrected = read("supported", ["number"], readings=[("newline", "supported")], coverage=both(["check-0000"]),
                     basis=metric_basis("supported", ["answer", "newline"], ["check-0000"]))
    repair = {"check": "check-0000", "category": "partial_credit", **corrected}
    malformed = {
        "unlisted": {**repair, "check": "check-0009"},
        "item": None,
        "claim": {"check": "check-0000", "claim": {"derivation": "invalid"}},
    }
    repairs = {} if invalid == "list" else [malformed[invalid], repair]
    responses = [
        NOTHING,
        {"probes": [facts_probe(first)]},
        read("supported", ["number"], coverage=both(["check-0000"])),
        {"reinterpretations": repairs, "probes": [facts_probe(second)]},
        read("supported", ["number"], readings=[("newline", "supported")], coverage=both(["check-0001"]),
             basis=metric_basis("supported", ["answer", "newline"], ["check-0001"])),
    ]
    script = InspectorScript(responses)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            simulation = await workflow.simulate(run, 2)
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["partial_credit"], focused_attempts=1)

    run, inspection = asyncio.run(main())
    built = report.build(run.config.output_dir)
    assert len(script.requests) == 5, "the ordinary probe runs without a replacement planning call"
    assert len(run.record.checks) == 2 and run.record.sandboxes == ["sandbox-0000", "sandbox-0001"]
    assert len(inspection.attempts) == 2 and inspection.attempts[1].status == "model_output_failure"
    assert error in inspection.attempts[1].error and inspection.status == "partial"
    assert inspection.unreviewed == {} and inspection.ordinary[second].label == "legitimate"
    assert built["metrics"]["episodes"][second]["completion"] == "complete"
    assert built["inspections"]["grader"]["attempts"][1]["status"] == "model_output_failure"
    if invalid == "list":
        assert inspection.ordinary[first].label == "unknown"
    else:
        assert inspection.ordinary[first].label == "legitimate"
        assert built["metrics"]["episodes"][first]["completion"] == "complete"
        assert any(review.reinterprets == "check-0000" and review.status == "assessed" for review in inspection.reviews)
    assert (inspection.assessments[0].outcome, inspection.assessments[0].conclusions) == ("legitimate", [])


def test_unsupported_runtime_keeps_the_check_failed_and_the_label_unknown(tmp_path, monkeypatch, credentials):
    """The check never ran, so nothing is interpreted and the Inspector receives the input contract."""
    task = task_with_artifacts(tmp_path, '["/app/explanation.txt"]')
    native = Native(monkeypatch, files={"0000-simulator": {"/app/explanation.txt": b"because\n"}})
    sandboxes = Sandboxes(monkeypatch, native=native, pythons={"python": "2"})
    script = InspectorScript([NOTHING, {"probes": [probe("0000-simulator")]}])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 1)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["omitted_requirements"], focused_attempts=0)
            return run, report

    run, report = asyncio.run(main())
    check = run.record.checks[0]
    assert (check.command, check.exit_code) == ([], None)
    assert check.output.startswith(checks.UNSUPPORTED_RUNTIME)
    assert run.record.episodes == ["0000-simulator"] and run.record.sandboxes == ["sandbox-0000"]
    assert not (run.config.output_dir / "episodes" / "0001-inspector").exists()
    record = sandbox_record(run, "sandbox-0000")
    probes = [entry for entry in record["commands"] if checks.VERSION_PROBE in entry["argv"]]
    assert [(entry["argv"][0], entry["exit_code"]) for entry in probes] == [("python3", 127), ("python", 0)]
    assert probes[1]["output"].strip() == "2"
    assert all(entry["argv"][1:] != [sandbox.CHECK_PROGRAM] for entry in record["commands"])
    assert sandboxes.environments["sandbox-0000"].uploads[sandbox.CHECK_PROGRAM]
    assert report.assessments[0].outcome == "unknown"
    assert (report.attempts[0].status, report.status) == ("unobservable", "partial")
    assert report.ordinary["0000-simulator"].label == "unknown"
    history = [json.loads(message["content"]) for message in report.sessions["grader-broad"][1:]]
    feedback = next(item for item in reversed(history) if "investigation_result" in item)
    assert feedback["check_input_contract"] == checks.CHECK_INPUT_CONTRACT
    assert history[-1]["investigation_status"] == "unobservable"
    assert len(script.requests) == 2, "a check that did not run is never sent for interpretation"


def test_without_declarations_ordinary_labels_stay_unknown_and_a_probe_never_backfills(tmp_path, monkeypatch, credentials):
    privileged = "Inspector-only targeted probe: skip the explanation.\n"
    targeted = {**probe("unused"), "setup_program": privileged}
    del targeted["episode"]
    task = task_with_artifacts(tmp_path, "[]")
    native = Native(monkeypatch)
    sandboxes = Sandboxes(monkeypatch, native=native)
    script = InspectorScript([NOTHING, {"probes": [targeted]}, interpretation("violated")])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 2)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["omitted_requirements"], focused_attempts=0)
            return run, simulation, report

    run, simulation, report = asyncio.run(main())
    probe_sandbox = run.record.sandboxes[0]
    assert run.record.capture_selection.files == []
    assert run.record.submissions[0].content.episode == probe_sandbox
    assert run.record.submissions[0].execution_scope == "package"
    assert any("cannot supply ordinary" in warning for warning in run.record.warnings)
    assert report.assessments[0].claim.episode == probe_sandbox
    assert report.assessments[0].execution_scope == "package"
    assert report.assessments[0].outcome == "accepted_invalid"
    assert report.categories["omitted_requirements"] == "evidenced_issue"
    assert set(report.ordinary) == {"0000-simulator", "0001-simulator"}
    for label in report.ordinary.values():
        assert label.label == "unknown" and label.assessments == []
        assert "not evidence of absence" in " ".join(label.reasons)
        assert "does not establish legitimacy" in " ".join(label.reasons)
    assert sandboxes.environments[probe_sandbox].uploads[sandbox.SETUP] == privileged.encode()
    assert run.record.episodes == simulation.episodes
    assert not any(privileged.strip() in text for text in native.instructions.values())


def test_package_assessment_cannot_label_a_native_ordinary_episode(tmp_path, monkeypatch, credentials):
    """A stored package result cannot become an ordinary label by naming its episode."""
    run = new_run(tmp_path, monkeypatch, credentials)
    name = "0000-simulator"
    directory = run.config.output_dir / "episodes" / name
    directory.mkdir(parents=True)
    episode = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir),
                            task_digest=tree_digest(run.config.task_dir), model="ordinary", reasoning_effort=None,
                            versions={}, rewards={"reward": 1.0})
    (directory / "episode.json").write_text(episode.model_dump_json())
    run.record.episodes.append(name)
    run.save()
    inspection = checks.InspectionResult(mode="grader", status="complete", categories={}, applicability={},
                                        assessments=[Assessment(claim=Claim(mechanism="package result", episode=name),
                                                                outcome="accepted_invalid", execution_scope="package")])
    label = checks.label_ordinary(run, [name], inspection)[name]
    assert label.label == "unknown" and label.assessments == []


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
                                 "omitted_requirements": "evidenced_issue", "partial_credit": "unknown"}


RESULT = "Also write a JSON summary to /output/result.json."


def proposal(path, excerpt: str = ANSWER, **fields) -> dict:
    return {"path": path, "reason": "The instruction names this deliverable.",
            "references": [{"episode": None, "path": "instruction.md", "excerpt": excerpt}], **fields}


class Selector(InspectorScript):
    """Also records how many episodes had started when each Inspector request arrived."""

    def __init__(self, responses, native):
        super().__init__(responses)
        self.native, self.started = native, []

    async def chat(self, request):
        self.started.append(len(self.native.configs))
        return await super().chat(request)


def test_inspector_selects_files_before_ordinary_episodes_when_the_task_declares_none(tmp_path, monkeypatch, credentials):
    """artifacts = []: one Inspector request, before any episode, adds cited files that every
    ordinary episode captures at verification start. Uncaptured state stays unknown."""
    task = task_with_artifacts(tmp_path, "[]")
    with (task / "instruction.md").open("a") as file:
        file.write(RESULT + "\n")
    native = Native(monkeypatch, files={"0000-simulator": {"/output/result.json": b"{}", "/app/answer.txt": b"42\n"}})
    selector = Selector([{"locations": [proposal("/output/result.json", RESULT), proposal("/app/answer.txt")]},
                         {"probes": []}], native)

    async def main():
        async with serve(selector) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, capacity=(1, 4096),
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 2)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["omitted_requirements"], focused_attempts=0)
            return run, simulation, report

    run, simulation, report = asyncio.run(main())
    assert selector.started[0] == 0, "selection precedes every ordinary episode"
    request = json.loads(selector.requests[0]["messages"][-1]["content"])
    assert (request["phase"], request["maximum_locations"], request["capture_inventory"]) == ("capture_selection", 8, [])
    assert RESULT in request["task"]["untrusted_task_files"]["instruction.md"]
    selection = run.record.capture_selection
    assert selection.status == "complete"
    assert [(item.declaration, item.source, item.selected) for item in selection.files] == [
        (None, "/output/result.json", True), (None, "/app/answer.txt", True)]
    assert selection.files[0].references[0].excerpt == RESULT
    assert selection.files[0].inspector_reason == "The instruction names this deliverable."
    assert not any("cannot supply ordinary" in warning for warning in run.record.warnings)
    # Selection is Inspector cost outside every episode; the ordinary pool is unchanged.
    assert (run.record.calls[0].role, run.record.calls[0].episode) == ("inspector", "capture-selection")
    assert simulation.episodes == run.record.episodes[:2] == ["0000-simulator", "0001-simulator"]
    captured = [(state.content.episode, state.location, state.ids["trial_name"]) for state in run.record.submissions]
    assert captured == [(name, location, native.configs[name].trial_name) for name in simulation.episodes
                        for location in ("/output/result.json", "/app/answer.txt")]
    states = [json.loads((run.config.output_dir / "episodes" / state.content.episode / state.content.path).read_text())
              for state in run.record.submissions]
    assert base64.b64decode(states[0]["base64"]) == b"{}"
    assert (states[2]["location"], states[2]["exists"], "base64" in states[2]) == ("/output/result.json", False, False)
    broad = json.loads(selector.requests[1]["messages"][-1]["content"])
    assert broad["capture_inventory"] == [item.model_dump() for item in selection.files]
    assert [state["location"] for state in broad["ordinary_episodes_read_first"][1]["captured"]] == [
        "/output/result.json", "/app/answer.txt"]
    assert {name: label.label for name, label in report.ordinary.items()} == dict.fromkeys(simulation.episodes, "unknown")
    assert (stored(run).simulation, stored(run).capture_selection) == (simulation, selection)


UNSUPPORTED = {
    "/app/../etc/passwd": "normalized absolute",
    "app/answer.txt": "normalized absolute",
    "/app/out/": "normalized absolute",
    "//app/answer.txt": "normalized absolute",
    "": "malformed",
    "/app/*.txt": "glob",
    "/logs/verifier/reward.json": "harness",
    "/logs/agent/trajectory.json": "harness",
    "/logs/artifacts/report.json": "harness",
    "/tests/test.sh": "harness",
    "/solution/solve.sh": "harness",
    "/proc/self/environ": "pseudo-file",
    "/etc/hosts": "pseudo-file",
}


def test_selection_keeps_declarations_deduplicates_and_rejects_unsupported_proposals(tmp_path, monkeypatch, credentials):
    task = task_with_artifacts(tmp_path, '["/app/answer.txt", "/app/answer.txt"]')
    native = Native(monkeypatch, files={"0000-simulator": {"/app/answer.txt": b"42\n"}})
    notes = [f"/app/notes/{index}.txt" for index in range(9)]
    malformed = [{"path": "/app/c.txt", "reason": " ", "references": proposal("/app/c.txt")["references"]},
                 {"path": "/app/d.txt", "reason": "cited", "references": []}, "/app/e.txt", proposal(7)]
    ungrounded = [proposal("/app/a.txt", "This sentence is not in the task."), proposal("/app/b.txt", ""),
                  {**proposal("/app/f.txt"), "references": [{"episode": "0000-simulator", "path": "instruction.md", "excerpt": ANSWER}]}]
    selector = Selector([{"locations": [proposal(path) for path in UNSUPPORTED] + malformed + ungrounded + [
        proposal("/app/answer.txt"), proposal("/var/lib/db.sqlite", service="db")] + [proposal(path) for path in notes]}], native)

    async def main():
        async with serve(selector) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return run, await workflow.simulate(run, 1)

    run, simulation = asyncio.run(main())
    assert len(selector.requests) == 1, "one bounded selection request"
    selection = run.record.capture_selection
    assert selection.status == "complete"
    declared = [(item.declaration, item.selected) for item in selection.files if item.declaration is not None]
    assert declared == [(0, True), (1, False)] and "duplicate" in selection.files[1].reason
    proposed = {item.source: item for item in selection.files if item.declaration is None}
    for path, reason in UNSUPPORTED.items():
        assert not proposed[path].selected and reason in proposed[path].reason, path
    assert all("malformed" in proposed[source].reason for source in ("/app/c.txt", "/app/d.txt", '"/app/e.txt"', "7"))
    assert all("verbatim" in proposed[source].reason for source in ("/app/a.txt", "/app/b.txt", "/app/f.txt"))
    assert "already selected" in proposed["/app/answer.txt"].reason
    assert "helper" in proposed["/var/lib/db.sqlite"].reason
    assert [proposed[path].selected for path in notes] == [True] * 8 + [False]
    assert "eight" in proposed[notes[-1]].reason
    assert not any(item.selected for item in proposed.values() if item.source not in notes)
    assert [state.location for state in run.record.submissions] == ["/app/answer.txt"] + notes[:8]
    assert (stored(run).simulation, stored(run).capture_selection) == (simulation, selection)


@pytest.mark.parametrize(("reply", "status", "detail"), [
    ((400, {"error": {"message": "bad selection request", "type": "invalid_request_error"}}), "failed", "BadRequestError"),
    ((200, completion({"role": "assistant", "content": "not json"}, "stop")), "malformed", "JSONDecodeError"),
    ((200, completion({"role": "assistant", "content": json.dumps({"refusal": "I will not select files."})}, "stop")),
     "model_inability", "I will not select files."),
    ((200, completion({"role": "assistant", "content": None, "refusal": "no"}, "content_filter")), "refused", "content_filter"),
    ((200, completion({"role": "assistant", "content": json.dumps({"locations": "/app/answer.txt"})}, "stop")),
     "malformed", "list"),
])
def test_failed_selection_keeps_declared_capture_and_is_not_repeated(tmp_path, monkeypatch, credentials, reply, status, detail):
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    Native(monkeypatch, files={"0000-simulator": {"/app/answer.txt": b"42\n"}})
    provider = Provider([reply])

    async def main():
        async with serve(provider) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return run, await workflow.simulate(run, 1)

    run, simulation = asyncio.run(main())
    assert len(provider.requests) == 1
    selection = stored(run).capture_selection
    assert selection.status == status and detail in " ".join(selection.limits)
    assert any(detail in warning for warning in run.record.warnings)
    assert [(item.source, item.selected) for item in selection.files] == [("/app/answer.txt", True)]
    assert (simulation.status, simulation.episodes) == ("complete", ["0000-simulator"])
    assert [state.location for state in run.record.submissions] == ["/app/answer.txt"]
    assert run.record.calls[0].episode == "capture-selection"
    assert stored(run).simulation == simulation


def test_spending_cap_reached_before_selection_sends_nothing_and_starts_no_episode(tmp_path, monkeypatch, credentials):
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    native = Native(monkeypatch)
    provider = Provider([])

    async def main():
        async with serve(provider) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, spending_cap=1.0,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            run.record.known_cost = 1.0
            return run, await workflow.simulate(run, 2)

    run, simulation = asyncio.run(main())
    assert provider.requests == [] and native.configs == {}
    selection = stored(run).capture_selection
    assert selection.status == "spending_exhausted" and "spending cap" in " ".join(selection.limits)
    assert (simulation.status, simulation.episodes) == ("spending_exhausted", [])
    assert [(item.source, item.selected) for item in selection.files] == [("/app/answer.txt", True)]
    assert stored(run).simulation == simulation


class Held:
    """An endpoint that holds the selection request until released."""

    def __init__(self):
        self.started, self.release = asyncio.Event(), asyncio.Event()

    async def chat(self, request):
        self.started.set()
        await self.release.wait()
        return web.json_response({}, status=500)


def test_cancellation_during_selection_records_it_and_starts_no_episode(tmp_path, monkeypatch, credentials):
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    native = Native(monkeypatch)
    held = Held()

    async def main():
        async with serve(held) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            running = asyncio.create_task(workflow.simulate(run, 2))
            try:
                await asyncio.wait_for(held.started.wait(), 5)
            finally:
                running.cancel()
                await asyncio.wait({running})
                held.release.set()
            return run

    run = asyncio.run(main())
    record = stored(run)
    assert (record.simulation.status, record.capture_selection.status, record.simulation.episodes) == ("cancelled", "cancelled", [])
    assert native.configs == {}


@pytest.mark.parametrize(("links", "detail"), [
    ({"/app/link": "/logs/verifier"}, "/logs/verifier"),
    ({"/app/link": "../../logs/verifier"}, "symlink"),
    ({"/app/link": "/safe", "/safe": "/logs/verifier"}, "symlink"),
    ({"/app/link": "/srv/data"}, "symlink"),
], ids=["excluded", "relative", "nested", "benign"])
def test_capture_rejects_every_parent_alias_before_reading(tmp_path, monkeypatch, credentials, links, detail):
    """The proposal passes the lexical check, but /app/link is a symlink. Its target may hold
    further aliases, here /safe into the verifier's state, so no symlinked parent is followed.
    The paused container's metadata is checked before any byte of it is read."""
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    files = {"/app/link/probe.bin": b"verifier state", "/app/answer.txt": b"42\n"}
    native = Native(monkeypatch, files={"0000-simulator": files}, links=links)
    selector = Selector([{"locations": [proposal("/app/link/probe.bin")]}], native)

    async def main():
        async with serve(selector) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            return run, await workflow.simulate(run, 1)

    run, simulation = asyncio.run(main())
    assert [failure.location for failure in run.record.capture_errors] == ["/app/link/probe.bin"]
    message = run.record.capture_errors[0].error.message
    assert "rejected" in message and detail in message
    container = native.configs["0000-simulator"].trial_name.lower() + "__env"
    assert native.events == [
        ("pause", container), ("stat", "/app"), ("stat", "/app/answer.txt"), ("read", "/app/answer.txt"), ("unpause", container),
        ("pause", container), ("stat", "/app"), ("stat", "/app/link"), ("stat", "/app/link/probe.bin"), ("unpause", container)]
    answer, = run.record.submissions
    assert answer.location == "/app/answer.txt" and answer.path_resolution["verified"]
    window, = answer.observation_windows
    assert window["paused"] and window["resumed_at"] and window["resume_error"] is None
    assert simulation.status == "complete"
    assert [item.source for item in stored(run).capture_selection.files if item.selected] == ["/app/answer.txt", "/app/link/probe.bin"]


def test_unavailable_pause_fails_the_capture_without_reading(tmp_path, monkeypatch, credentials):
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    native = Native(monkeypatch, files={"0000-simulator": {"/app/answer.txt": b"42\n"}}, failing={"pause"})

    async def main():
        async with serve(InspectorScript([NOTHING])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            return run, await workflow.simulate(run, 1)

    run, simulation = asyncio.run(main())
    assert run.record.submissions == []
    assert not any(event[0] in ("stat", "read") for event in native.events)
    assert [failure.location for failure in run.record.capture_errors] == ["/app/answer.txt"]
    assert "could not be paused" in run.record.capture_errors[0].error.message
    assert simulation.status == "complete"


def test_failed_resume_stops_the_episode_and_keeps_the_capture_failure(tmp_path, monkeypatch, credentials):
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    native = Native(monkeypatch, files={"0000-simulator": {"/app/answer.txt": b"42\n"}}, failing={"unpause"})

    async def main():
        async with serve(InspectorScript([NOTHING])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            return run, await workflow.simulate(run, 1)

    run, simulation = asyncio.run(main())
    assert ("unpause", native.configs["0000-simulator"].trial_name.lower() + "__env") in native.events
    assert [(failure.location, failure.error.type) for failure in run.record.capture_errors] == [("/app/answer.txt", "InfrastructureAbort")]
    assert run.record.submissions == []
    assert [error.type for error in simulation.failures["0000-simulator"]] == ["InfrastructureAbort"]
    assert simulation.status == "partial"


ORDERS = "/app/state/orders.db"
PLANNER = "PLANNER-REASON-314"
SHARED = {"locations": [proposal("/output/result.json", RESULT), proposal(ORDERS, reason=PLANNER)]}
CLAIM = {"claim": {"mechanism": "candidate", "interpretation": "unproven", "unresolved": ["no independent check"]}}


def declaring_nothing(tmp_path: Path) -> Path:
    task = task_with_artifacts(tmp_path, "[]")
    with (task / "instruction.md").open("a") as file:
        file.write(RESULT + "\n")
    return task


def test_one_selection_serves_ordinary_and_every_hint_condition_without_reaching_the_attacker(tmp_path, monkeypatch, credentials):
    """artifacts = []: the selection made before ordinary episodes is reused unchanged by
    every hint condition. Its paths, reasons and references never reach an Attacker."""
    task = declaring_nothing(tmp_path)
    native = Native(monkeypatch, files={"0001-attacker": {"/output/result.json": b"{}"}})
    selector = Selector([SHARED] + [CLAIM] * 3, native)

    async def main():
        async with serve(selector) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            await workflow.simulate(run, 1)
            return run, await checks.attack(run, maximum_attempts=1, full=FULL, minimal=MINIMAL)

    run, result = asyncio.run(main())
    phases = [json.loads(body["messages"][-1]["content"]).get("phase") for body in selector.requests]
    assert phases.count("capture_selection") == 1, "one selection for the whole run"
    expected = ["/output/result.json", ORDERS]
    assert [attempt.level for attempt in result.attempts] == ["none", "full", "minimal"]
    assert [attempt.capture_locations for attempt in result.attempts] == [expected] * 3
    attackers = [attempt.episode for attempt in result.attempts]
    assert [(state.content.episode, state.location) for state in run.record.submissions] == [
        (name, location) for name in ["0000-simulator", *attackers] for location in expected]
    original = (task / "instruction.md").read_text()
    for attempt in result.attempts:
        seen = native.instructions[attempt.episode].removeprefix(original) + json.dumps(result.sessions[attempt.context])
        assert not any(text in seen for text in (ORDERS, PLANNER, "result.json", "capture_selection")), attempt.level
    none_episode = next(attempt.episode for attempt in result.attempts if attempt.level == "none")
    none = native.instructions[none_episode].removeprefix(original)
    assert checks.CAPTURE_LIMIT in none and "same files" in checks.CAPTURE_LIMIT
    assert checks.CAPTURE_LIMIT in result.limits
    selection = stored(run).capture_selection
    assert selection.status == "complete" and [item.source for item in selection.files if item.selected] == expected
    collection = report.build(run.config.output_dir)["collection"]
    assert (collection["status"], collection["selected"], collection["calls"]) == ("complete", expected, 1)


def test_hacking_only_attack_selects_once_before_its_first_episode_without_a_simulation(tmp_path, monkeypatch, credentials):
    task = declaring_nothing(tmp_path)
    native = Native(monkeypatch)
    selector = Selector([SHARED, CLAIM], native)

    async def main():
        async with serve(selector) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            return run, await checks.attack(run, maximum_attempts=1)

    run, result = asyncio.run(main())
    assert selector.started == [0, 1], "selection precedes the first attacker episode"
    assert [attempt.level for attempt in result.attempts] == ["none"]
    assert result.attempts[0].capture_locations == ["/output/result.json", ORDERS]
    assert [state.location for state in run.record.submissions] == ["/output/result.json", ORDERS]
    assert run.record.calls[0].episode == "capture-selection"
    record = stored(run)
    assert record.simulation is None and record.capture_selection.status == "complete"


def test_disabled_attack_makes_no_selection_request(tmp_path, monkeypatch, credentials):
    task = declaring_nothing(tmp_path)
    native = Native(monkeypatch)
    provider = Provider([])

    async def main():
        async with serve(provider) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            return run, await checks.attack(run, maximum_attempts=0, discovery_attempts=0)

    run, result = asyncio.run(main())
    assert result.status == "disabled" and provider.requests == [] and native.configs == {}
    assert run.record.capture_selection is None


def test_refused_attack_selection_keeps_declared_capture_for_every_condition(tmp_path, monkeypatch, credentials):
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    Native(monkeypatch)
    refusal = completion({"role": "assistant", "content": json.dumps({"refusal": "I will not select files."})}, "stop")
    provider = Provider([(200, refusal)] + [(200, completion({"role": "assistant", "content": json.dumps(CLAIM)}, "stop"))] * 2)

    async def main():
        async with serve(provider) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            return run, await checks.attack(run, maximum_attempts=1, full=FULL)

    run, result = asyncio.run(main())
    assert len(provider.requests) == 3
    assert [attempt.capture_locations for attempt in result.attempts] == [["/app/answer.txt"]] * 2
    assert any("I will not select files." in warning for warning in run.record.warnings)
    selection = stored(run).capture_selection
    assert selection.status == "model_inability" and "I will not select files." in " ".join(selection.limits)
    assert report.build(run.config.output_dir)["collection"]["status"] == "model_inability"


def test_attack_selection_at_the_spending_cap_sends_nothing_and_starts_no_episode(tmp_path, monkeypatch, credentials):
    task = declaring_nothing(tmp_path)
    native = Native(monkeypatch)
    provider = Provider([])

    async def main():
        async with serve(provider) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, spending_cap=1.0, models=inspector(base))
            run.record.known_cost = 1.0
            return run, await checks.attack(run, maximum_attempts=1)

    run, result = asyncio.run(main())
    assert provider.requests == [] and native.configs == {}
    assert result.status == "spending_exhausted"
    assert stored(run).capture_selection.status == "spending_exhausted"


def test_cancelling_attack_during_selection_records_it_and_starts_no_episode(tmp_path, monkeypatch, credentials):
    task = declaring_nothing(tmp_path)
    native = Native(monkeypatch)
    held = Held()

    async def main():
        async with serve(held) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            running = asyncio.create_task(checks.attack(run, maximum_attempts=1))
            try:
                await asyncio.wait_for(held.started.wait(), 5)
            finally:
                running.cancel()
                await asyncio.wait({running})
                held.release.set()
            return run

    run = asyncio.run(main())
    assert native.configs == {}
    attack = checks.AttackResult.model_validate_json((run.config.output_dir / "attack.json").read_text())
    assert (attack.status, attack.attempts) == ("cancelled", [])
    assert stored(run).capture_selection.status == "cancelled"
