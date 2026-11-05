"""Ordinary simulation supplies the episode pool that trace-first grader inspection labels.

Only Harbor's Trial and the Docker CLI and daemon calls are replaced: the trial double
calls the run's state copy callback at both points and commits record the episode's
files. Inspector checks run in a sandbox double when the test installs one. The run's
queue, runner, copy producer, Inspector session and assessment are real.
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
from harbor.models.task.task import Task
from harbor.models.trial.result import AgentInfo, ExceptionInfo, TrialResult
from harbor.models.verifier.result import VerifierResult
from harbor.trial.hooks import TrialEvent
from harbor.trial.trial import Trial

from nudi import checks, copies, report, runner, sandbox, workflow
from nudi.records import (Assessment, Check, Claim, Content, Coverage, DiskFull, EpisodeResult, ErrorRecord, ModelConfig,
                          Observation, RunRecord)
from test_attack import GO_DIR, GO_FILE, GO_LINK, stat_header
from test_inspection import CHECKER, Images, InspectorScript, Sandboxes, sandbox_record
from test_limits import credentials, new_run, session_messages  # noqa: F401  (pytest fixture)
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


def inspector(base: str) -> dict:
    return {"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)}


class Native:
    """Harbor trials, Docker commits and reads, and the daemon's pause and stat API. `files`
    maps an episode to the container files its agent leaves (absent: none); None makes
    that episode's commit and archive read fail. `links` maps a container path to its symlink
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
        self.images = Images()
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

    def files_of(self, container):
        return self.files.get(self.containers[container], {})

    async def docker(self, command, *, timeout=30):
        if (result := self.images.handle(command, self.files_of, None)) is not None:
            return result
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
            if config.agent.import_path not in (None, "nudi.runner:HostTerminus"):
                raise AssertionError(
                    f"a generated check must run in an Inspector sandbox, not native agent {config.agent.import_path}"
                )
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
                                 verifier_result=None if native.rewards.get(name, 1.0) is None else VerifierResult(
                                     rewards={"reward": native.rewards.get(name, 1.0)}))
            native.containers[config.trial_name.lower() + "__env"] = name
            for hook in self.hooks:
                await hook(SimpleNamespace(trial_name=config.trial_name, trial_id=result.id, result=result, config=config))
            # RewardVerifier's two copies, around a grader this double does not run.
            if take := runner.state_copy.get():
                verifier = SimpleNamespace(
                    environment=SimpleNamespace(session_id=config.trial_name + "__env", context_id=result.id),
                    trial_paths=SimpleNamespace(trial_dir=trial_dir),
                    task=SimpleNamespace(checksum="checksum", config=Task(Path(config.task.path)).config))
                for point in ("verification_start", "grading_end"):
                    await take(verifier, point)
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
        async with serve(InspectorScript([])) as base:
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
        assert (agent.name, agent.model_name, agent.import_path) == (
            None, run.record.models["simulator"].model, "nudi.runner:HostTerminus")
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
        async with serve(InspectorScript([])) as base:
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
        async with serve(InspectorScript([])) as base:
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


def test_a_full_disk_in_one_worker_stops_the_other_workers_before_it_propagates(tmp_path, monkeypatch, credentials):
    """With two workers, a full disk in one cancels the other before the error propagates, so no episode runs during
    cleanup."""
    run = new_run(tmp_path, monkeypatch, credentials)
    events, second = [], asyncio.Event()

    async def episode(run, role):
        if not events:
            events.append("first")
            await second.wait()
            raise DiskFull("no space left on the records host to write run.json")
        events.append("second")
        second.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            events.append("second cancelled")
            raise

    monkeypatch.setattr(workflow, "run_role_episode", episode)

    async def main():
        with pytest.raises(DiskFull):
            await workflow.simulate(run, 2)
        events.append("propagated")

    asyncio.run(main())
    assert events == ["first", "second", "second cancelled", "propagated"]


def consuming(events, started):
    """Native episodes. The first sets `started` and waits; cancelled, it finishes its teardown and returns
    normally, the way Harbor's shielded environment stop (`Trial._stop_agent_environment`) consumes the
    cancellation. Later ones return at once."""
    async def episode(run, role):
        number = sum(event.startswith("episode") for event in events)
        events.append(f"episode {number}")
        if number == 0:
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                await asyncio.sleep(0.05)
                events.append("teardown finished")
        return SimpleNamespace(errors=[], rewards={"reward": 1.0})

    return episode


def test_a_worker_whose_cancellation_harbor_consumes_starts_no_episode_after_a_full_disk(tmp_path, monkeypatch, credentials):
    """Such a worker must not go back to its loop and start a third episode."""
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(3, 4096))
    assert run.record.capacity.concurrency == 2
    events, started, calls = [], asyncio.Event(), []
    native = consuming(events, started)

    async def episode(run, role):
        calls.append(role)
        if len(calls) == 2:
            await started.wait()
            raise DiskFull("no space left on the records host to write run.json")
        return await native(run, role)

    monkeypatch.setattr(workflow, "run_role_episode", episode)

    async def main():
        with pytest.raises(DiskFull):
            await workflow.simulate(run, 3)
        events.append("propagated")

    asyncio.run(main())
    assert events == ["episode 0", "teardown finished", "propagated"]


def test_a_worker_whose_cancellation_harbor_consumes_starts_no_episode_after_ctrl_c(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(2, 4096))
    assert run.record.capacity.concurrency == 1
    events, started = [], asyncio.Event()
    monkeypatch.setattr(workflow, "run_role_episode", consuming(events, started))

    async def main():
        running = asyncio.create_task(workflow.simulate(run, 3))
        await started.wait()
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
        events.append("cancelled")

    asyncio.run(main())
    assert events == ["episode 0", "teardown finished", "cancelled"]
    assert stored(run).simulation.status == "cancelled"


@pytest.mark.parametrize("reward, status", [(0.0, "complete"), (None, "partial")])
def test_returned_native_failure_counts_without_a_raise(tmp_path, monkeypatch, credentials, reward, status):
    """Harbor returns exception_info and still grades. The failure stays recorded; the pool is partial only
    when the episode has no usable reward."""
    native = Native(monkeypatch, rewards={"0001-simulator": reward})
    native.returned = {"0001-simulator": "AgentTimeoutError"}

    async def main():
        async with serve(InspectorScript([])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(1, 4096), models=inspector(base))
            return run, await workflow.simulate(run, 2)

    run, simulation = asyncio.run(main())
    assert simulation.status == status
    assert list(simulation.failures) == ["0001-simulator"]
    assert [error.type for error in simulation.failures["0001-simulator"]] == ["AgentTimeoutError"]
    timed_out = json.loads((run.config.output_dir / "episodes" / "0001-simulator" / "episode.json").read_text())
    assert timed_out["agent_timeout"] and timed_out["rewards"] == ({} if reward is None else {"reward": reward})
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
        async with serve(provider) as base, serve(InspectorScript([])) as selection:
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


ANSWER = "Write the number 42 to /app/answer.txt."
# Checks read the copy in place; the sandbox double keeps its files under COPY_ROOT.
READ = '''import json, os, sys
inputs = json.load(sys.stdin)
def read(path):
    path = os.environ.get("COPY_ROOT", "") + path
    return open(path, "rb").read() if os.path.isfile(path) else None
'''
ANSWER_CHECKER = READ + '''data = read("/app/answer.txt")
correct = int(data is not None and data.strip() == b"42")
print(json.dumps({"observations": {"correct": correct}, "results": {"deserved": correct}}))
'''
REFERENCES = {"explanation": {"episode": None, "path": "instruction.md", "excerpt": REQUIREMENT},
              "answer": {"episode": None, "path": "instruction.md", "excerpt": ANSWER},
              "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": SCORING}}


def probe(episode: str, requirement: str = "explanation") -> dict:
    location, program = ("/app/answer.txt", ANSWER_CHECKER) if requirement == "answer" else ("/app/explanation.txt", CHECKER)
    return {"category": "accepted_invalid", "case": f"{requirement} in {episode}", "episode": episode,
            "location": location, "capture_point": "verification_start",
            "timing": "The requirements apply to the submission at verification start.", "program": program,
            "requirement": REFERENCES[requirement], "scoring": REFERENCES["scoring"]}


def interpretation(validity: str, observation: str = "exists", **claim) -> dict:
    return {"claim": {"mechanism": "required work", "interpretation": "Full credit needs this requirement met.",
                      "derivation": {"observations": [observation], "validity": validity},
                      **claim}}


def coverage(requirements: list[str], checks: list[str]) -> dict:
    return {"requirements": [REFERENCES[name] for name in requirements], "scoring": REFERENCES["scoring"], "checks": checks,
            "explanation": "The grader awards 1.0 for this submission; the cited checks observe every requirement it needs."}


def test_copies_reach_supported_ordinary_labels_and_incomplete_support_stays_unknown(tmp_path, monkeypatch, credentials):
    """An all-pass pool. Explanation existence alone cannot make an episode legitimate;
    its answer must also be observed and the whole scoring outcome interpreted."""
    task = task_with_artifacts(tmp_path, '["/app/explanation.txt", "/app/answer.txt", "/logs/verifier/reward.json"]')
    complete = {"/app/answer.txt": b"42\n", "/app/explanation.txt": b"because\n"}
    native = Native(monkeypatch, files={"0000-simulator": {"/app/answer.txt": b"42\n"}, "0001-simulator": complete,
                                        "0002-simulator": None, "0003-simulator": complete, "0004-simulator": complete})
    Sandboxes(monkeypatch, native=native)
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
            report = await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)
            return run, simulation, report

    run, simulation, report = asyncio.run(main())
    pool = [f"{index:04d}-simulator" for index in range(5)]
    assert simulation.episodes == pool
    broad = json.loads(script.requests[0]["messages"][-1]["content"])
    ordinary = broad["ordinary_episodes_read_first"]
    assert [episode["episode"] for episode in ordinary] == pool
    assert [episode["rewards"] for episode in ordinary] == [{"reward": 1.0}] * 5
    assert [(copy["point"], copy["excluded"], copy["error"]) for copy in ordinary[0]["copies"]] == [
        ("verification_start", copies.excluded(), None), ("grading_end", copies.excluded(), None)]
    assert [copy["point"] for copy in ordinary[2]["copies"]] == ["verification_start", "grading_end"]
    assert all("commit failed" in copy["error"] for copy in ordinary[2]["copies"])
    assert [assessment.outcome for assessment in report.assessments] == ["legitimate"] * 4 + ["accepted_invalid"]
    labels = {name: label.label for name, label in report.ordinary.items()}
    assert labels == {"0000-simulator": "accepted_invalid", "0001-simulator": "legitimate", "0002-simulator": "unknown",
                      "0003-simulator": "unknown", "0004-simulator": "unknown"}
    reasons = {name: " ".join(label.reasons) for name, label in report.ordinary.items()}
    assert "commit failed" in reasons["0002-simulator"] and "not evidence of absence" in reasons["0002-simulator"]
    assert unobserved[0] in reasons["0003-simulator"]
    assert ANSWER in reasons["0004-simulator"] and "no cited check" in reasons["0004-simulator"]
    assert report.categories["accepted_invalid"] == "evidenced_issue"
    # The pool is reused: no further ordinary episode. The five checks are package sandboxes.
    assert run.record.episodes == pool
    assert len(run.record.sandboxes) == 6 and sandbox_record(run, run.record.sandboxes[0])["purpose"] == "workspace"
    assert all(sandbox_record(run, name)["purpose"] == "check" for name in run.record.sandboxes[1:])
    assert all(native.instructions[name] == (task / "instruction.md").read_text() for name in pool)


HALVES = "# The answer 42 and the explanation file each earn 0.5."
# Each half is one file, so a check of one file cannot compute the whole deserved score and omits it.
HALF_CHECKERS = {name: READ + f'''met = int({test})
print(json.dumps({{"observations": {{"{name}": met}}, "results": {{}}}}))
''' for name, test in (("exists", 'read("/app/explanation.txt") is not None'), ("correct", '(read("/app/answer.txt") or b"").strip() == b"42"'))}


def test_separate_checks_of_separate_files_leave_partial_credit_unknown(tmp_path, monkeypatch, credentials):
    """Each requirement earns 0.5 and lives in its own file. No single check sees both, so none has a deserved
    score and combined coverage cannot justify the reward: a recorded limit of the single deserved score.
    Unresolved or failed cited evidence keeps the same combination unknown for its own reason too."""
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
        return {**probe(episode, requirement), "category": "accepted_invalid", "scoring": scoring,
                "program": program or HALF_CHECKERS[name]}

    def bounded(validity, name, **claim):
        return {"claim": {"mechanism": "half credit", "interpretation": f"This requirement earns 0.5 of the reward; {name} measures it.",
                          "derivation": {"observations": [name], "validity": validity},
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
            return await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)

    report = asyncio.run(main())
    assessments = report.assessments
    assert [assessment.outcome for assessment in assessments] == ["unknown"] * 6
    assert [(assessment.validity, assessment.discrepancy) for assessment in assessments[:2]] == [("supported", "unknown"), ("violated", "unknown")]
    assert all("no finite `results.deserved`" in " ".join(assessment.reasons) for assessment in assessments[:2])
    assert assessments[4].check.exit_code != 0
    labels = {name: label.label for name, label in report.ordinary.items()}
    assert labels == dict.fromkeys(pool, "unknown")
    reasons = {name: " ".join(label.reasons) for name, label in report.ordinary.items()}
    assert "results.deserved" in reasons["0000-simulator"]
    assert "check-0002" in reasons["0001-simulator"] and "verification start" in reasons["0001-simulator"]
    assert "check-0004" in reasons["0002-simulator"] and "complete scoring outcome" in reasons["0002-simulator"]


NEWLINE = "End /app/answer.txt with a newline."
EACH_HALF = "# The number 42 and the final newline each earn 0.5."
FACTS = {"answer": REFERENCES["answer"], "newline": {"episode": None, "path": "instruction.md", "excerpt": NEWLINE},
         "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": EACH_HALF}}
MEASURED = {"answer": "number", "newline": "newline"}
# One execution measures both requirements as Booleans. An absent file has no deserved score.
ANSWER_FACTS = READ + '''data = read("/app/answer.txt")
facts, results = {"exists": data is not None}, {}
if data is not None:
    facts.update(number=data.strip() == b"42", newline=data.endswith(b"\\n"))
    results["deserved"] = 0.5 * facts["number"] + 0.5 * facts["newline"]
print(json.dumps({"observations": facts, "results": results}))
'''


def answer_task(tmp_path: Path) -> Path:
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    with (task / "instruction.md").open("a") as file:
        file.write(NEWLINE + "\n")
    with (task / "tests" / "test.sh").open("a") as file:
        file.write("\n" + EACH_HALF + "\n")
    return task


def facts_probe(episode: str, requirement: str = "answer") -> dict:
    return {**probe(episode, "answer"), "category": "accepted_invalid", "case": f"{requirement} in {episode}",
            "requirement": FACTS[requirement], "scoring": FACTS["scoring"], "program": ANSWER_FACTS}


def read(validity: str, observations: list[str], *, readings=(), **claim) -> dict:
    derivation = {"observations": observations, "validity": validity, "requirements": [
        {"requirement": FACTS[key], "observations": [MEASURED[key]], "validity": value,
         "interpretation": f"The {MEASURED[key]} fact measures this requirement."} for key, value in readings]}
    return {"claim": {"mechanism": "answer facts", "interpretation": "Each requirement earns 0.5 of the reward.",
                      "derivation": derivation, **claim}}


def both(checks: list[str]) -> dict:
    return {"requirements": [FACTS["answer"], FACTS["newline"]], "scoring": FACTS["scoring"], "checks": checks,
            "explanation": "The cited facts settle both scored requirements and so the actual reward."}


def metric_basis(value: str, keys: list[str], checks: list[str]) -> dict:
    return {"completion": value, "requirements": [FACTS[key] for key in keys], "checks": checks, "explanation": f"completion {value}"}


def test_measured_facts_and_requirement_conclusions_reach_labels_and_reports(tmp_path, monkeypatch, credentials):
    """Measured absence with an unknown score, a failed copy, one check supporting the number while the
    newline is violated (legitimate partial credit), complete and partial coverage, and conflicting readings."""
    task = answer_task(tmp_path)
    pool = [f"{index:04d}-simulator" for index in range(6)]
    done = {"/app/answer.txt": b"42\n"}
    native = Native(monkeypatch, files={pool[0]: {}, pool[1]: None, pool[2]: {"/app/answer.txt": b"42"}, pool[3]: done,
                                        pool[4]: done, pool[5]: done}, rewards={pool[0]: 0.0, pool[2]: 0.5})
    Sandboxes(monkeypatch, native=native)
    script = InspectorScript([
        {"probes": [facts_probe(pool[0]), facts_probe(pool[1]), facts_probe(pool[2]), facts_probe(pool[3]),
                    facts_probe(pool[4]), facts_probe(pool[5], "newline"), facts_probe(pool[5])]},
        read("violated", ["exists"], basis=metric_basis("violated", ["answer"], ["check-0000"])),
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
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)

    run, inspection = asyncio.run(main())
    assert len(script.requests) == 7 and len(run.record.checks) == 6
    assessments = inspection.assessments
    assert [(item.outcome, item.validity, item.discrepancy) for item in assessments] == [
        ("unknown", "violated", "unknown"), ("unknown", "unknown", "unknown")] + [("legitimate", "supported", "none")] * 5
    assert [(item.requirement.excerpt, item.validity) for item in assessments[2].conclusions] == [(NEWLINE, "violated")]
    # A failed copy is unavailable state: the review is assessed without a check and nothing is interpreted.
    assert inspection.reviews[1].status == "assessed" and "copy-0002 failed" in " ".join(assessments[1].missing)
    labels = {name: label.label for name, label in inspection.ordinary.items()}
    assert labels == dict(zip(pool, ["unknown", "unknown", "legitimate", "legitimate", "unknown", "unknown"]))
    reasons = {name: " ".join(label.reasons) for name, label in inspection.ordinary.items()}
    assert "no finite `results.deserved`" in reasons[pool[0]] and "commit failed" in reasons[pool[1]]
    assert f"no cited check observes requirement instruction.md: {NEWLINE!r}" in reasons[pool[4]]

    built = report.build(run.config.output_dir)
    episodes = built["metrics"]["episodes"]
    # No check of pool[4] reads the newline requirement: it is listed as unobserved and keeps completion unknown.
    assert [episodes[name]["completion"] for name in pool] == ["incomplete", "unknown", "incomplete", "complete", "unknown", "unknown"]
    assert episodes[pool[4]]["unobserved"] == [f"instruction.md: {NEWLINE!r}"] and episodes[pool[3]]["unobserved"] == []
    assert any("conflicting" in reason for reason in episodes[pool[5]]["completion_reasons"])
    assert built["labels"]["review"]["unresolved"] == [pool[0], pool[1], pool[4], pool[5]]
    assert built["labels"]["review"]["unreviewed"] == {}
    findings = built["inspections"]["grader_inspector"]["findings"]
    absent = next(item for item in findings["inconclusive"] if item["claim"]["episode"] == pool[0])
    assert (absent["assessment"]["validity"], absent["assessment"]["discrepancy"]) == ("violated", "unknown")
    partial = next(item for item in findings["legitimate"] if item["claim"]["episode"] == pool[2])
    assert partial["assessment"]["conclusions"] == [{"requirement": FACTS["newline"], "validity": "violated", "reasons": []}]
    markdown = report.markdown(built).splitlines()
    assert "attempted but unresolved 4" in next(line for line in markdown if line.startswith("Review attempted"))
    line = next(line for line in markdown if line.startswith("- grader_inspector inconclusive:") and pool[0] in line)
    assert "validity violated" in line and "discrepancy unknown" in line
    line = next(line for line in markdown if line.startswith("- grader_inspector legitimate:") and pool[2] in line)
    assert f"requirement {NEWLINE!r} violated" in line and "native reward 0.5" in line


def test_completion_stays_unknown_when_a_cited_check_violation_is_omitted(tmp_path, monkeypatch, credentials):
    """A supported number and violated newline earn legitimate partial credit, not full completion."""
    task = answer_task(tmp_path)
    name = "0000-simulator"
    native = Native(monkeypatch, files={name: {"/app/answer.txt": b"42"}}, rewards={name: 0.5})
    Sandboxes(monkeypatch, native=native)
    script = InspectorScript([
        {"probes": [facts_probe(name)]},
        read("supported", ["number"], readings=[("newline", "violated")], coverage=both(["check-0000"]),
             basis=metric_basis("supported", ["answer"], ["check-0000"])),
    ])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            simulation = await workflow.simulate(run, 1)
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)

    run, inspection = asyncio.run(main())
    built = report.build(run.config.output_dir)
    episode = built["metrics"]["episodes"][name]
    assert episode["completion"] == "unknown"
    reasons = " ".join(episode["completion_reasons"])
    assert NEWLINE in reasons and "violated" in reasons and "completion basis" in reasons
    assert inspection.ordinary[name].label == "legitimate" and inspection.categories["accepted_invalid"] == "no_evidenced_issue"
    assert inspection.assessments[0].claim.basis.requirements == [Observation.model_validate(FACTS["answer"])]
    markdown = report.markdown(built).splitlines()
    assert any(line.startswith(f"- {name}: completion unknown;") for line in markdown)
    assert any(line.startswith("- grader_inspector legitimate:") and f"requirement {NEWLINE!r} violated" in line for line in markdown)


@pytest.mark.parametrize("case", ["uncontested", "conflicting", "unresolved"])
def test_secondary_conclusions_survive_unknown_primary_validity_in_labels_and_reports(tmp_path, monkeypatch, credentials, case):
    """An unmeasured primary requirement cannot hide a verified secondary violation or conflict."""
    task = answer_task(tmp_path)
    name = "0000-simulator"
    native = Native(monkeypatch, files={name: {"/app/answer.txt": b"42"}}, rewards={name: 0.5})
    Sandboxes(monkeypatch, native=native)
    probes = [facts_probe(name)] + ([facts_probe(name, "newline")] if case == "conflicting" else [])
    responses = [
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
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)

    run, inspection = asyncio.run(main())
    first = inspection.assessments[0]
    assert first.validity == "unknown" and first.discrepancy == "unknown"
    assert [(item.requirement.excerpt, item.validity) for item in first.conclusions] == [(NEWLINE, "violated")]
    assert len(script.requests) == 2 + (case == "conflicting") and len(run.record.checks) == len(probes)
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
    assert any(line.startswith("- grader_inspector inconclusive:") and f"requirement {NEWLINE!r} violated" in line for line in markdown)


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
    repair = {"check": "check-0009" if case == "invalid" else "check-0000", "category": "accepted_invalid", **corrected}
    responses = [{"probes": [facts_probe(name)]}, read("supported", ["number"], coverage=both(["check-0000"]))]
    if case != "exhausted":
        responses.append({"probes": [facts_probe(name)], "reinterpretations": [repair]})
    script = InspectorScript(responses)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, models=inspector(base))
            simulation = await workflow.simulate(run, 1)
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"],
                                                    focused_attempts=0 if case == "exhausted" else 1)

    run, inspection = asyncio.run(main())
    built = report.build(run.config.output_dir)
    assert len(script.requests) == len(responses), "a repair adds no model request"
    assert len(run.record.checks) == 1 and sum(sandbox_record(run, name)["purpose"] == "check" for name in run.record.sandboxes) == 1, "a repair executes nothing again"
    original = inspection.assessments[0]
    assert (original.outcome, original.conclusions) == ("legitimate", [])
    label = inspection.ordinary[name]
    if case == "corrected":
        payload = json.loads(script.requests[2]["messages"][-1]["content"])
        assert payload["unreviewed_ordinary_episodes"] == [] and "interpret_experiment" in payload["instruction"]
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
            assert inspection.attempts[1].status == "duplicate_case", "an unknown experiment assesses nothing and fails nothing"
            shown = json.dumps(session_messages(run.config.output_dir, "grader-accepted_invalid"))
            assert "invalid_experiment" in shown and "check-0009" in shown


@pytest.mark.parametrize(("invalid", "error"), [
    ("unlisted", None),
    ("item", None),
    ("claim", "Invalid Claim"),
    ("list", None),
])
def test_invalid_reinterpretation_preserves_other_repairs_and_ordinary_probes(tmp_path, monkeypatch, credentials, invalid, error):
    """An invalid claim stays a reported failure; a repair naming no retained check is returned to the model as
    invalid_experiment and fails nothing. Independent work uses the same attempt either way."""
    task = answer_task(tmp_path)
    first, second = "0000-simulator", "0001-simulator"
    native = Native(monkeypatch, files={name: {"/app/answer.txt": b"42\n"} for name in (first, second)})
    Sandboxes(monkeypatch, native=native)
    corrected = read("supported", ["number"], readings=[("newline", "supported")], coverage=both(["check-0000"]),
                     basis=metric_basis("supported", ["answer", "newline"], ["check-0000"]))
    repair = {"check": "check-0000", "category": "accepted_invalid", **corrected}
    malformed = {
        "unlisted": {**repair, "check": "check-0009"},
        "item": None,
        "claim": {"check": "check-0000", "claim": {"derivation": "invalid"}},
    }
    repairs = {} if invalid == "list" else [malformed[invalid], repair]
    responses = [
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
            return run, await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=1)

    run, inspection = asyncio.run(main())
    built = report.build(run.config.output_dir)
    assert len(script.requests) == 4, "the ordinary probe runs without a replacement planning call"
    assert len(run.record.checks) == 2 and sum(sandbox_record(run, name)["purpose"] == "check" for name in run.record.sandboxes) == 2
    status = "model_output_failure" if error else "no_evidenced_issue"
    assert len(inspection.attempts) == 2 and inspection.attempts[1].status == status
    assert built["inspections"]["grader_inspector"]["attempts"][1]["status"] == status
    if error:
        assert error in inspection.attempts[1].error
    else:
        assert "invalid_experiment" in json.dumps(session_messages(run.config.output_dir, "grader-accepted_invalid"))
    # Without a usable repair the first episode stays unknown, so only a corrected unknown reference completes.
    assert inspection.status == ("complete" if invalid in ("unlisted", "item") else "partial")
    assert inspection.unreviewed == {} and inspection.ordinary[second].label == "legitimate"
    assert built["metrics"]["episodes"][second]["completion"] == "complete"
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
    script = InspectorScript([{"probes": [probe("0000-simulator")]}])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 1)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)
            return run, report

    run, report = asyncio.run(main())
    assert run.record.checks == [], "the unsupported workspace offers no checker or inference tools"
    assert run.record.episodes == ["0000-simulator"]
    record = sandbox_record(run, "sandbox-0000")
    assert record["purpose"] == "workspace" and record["cleanup"]["removed"] is True
    probes = [entry for entry in record["commands"] if checks.VERSION_PROBE in entry["argv"]]
    assert [(entry["argv"][0], entry["exit_code"]) for entry in probes] == [("python3", 127), ("python", 0)]
    assert probes[1]["output"].strip() == "2"
    assert sandbox.CHECK_PROGRAM not in sandboxes.environments["sandbox-0000"].uploads
    assert report.assessments == [] and (report.attempts[0].status, report.status) == ("tool_failure", "partial")
    assert "python3" in report.attempts[0].error and report.ordinary["0000-simulator"].label == "unknown"
    assert script.requests == [], "no unsupported agent inference starts"


def test_a_package_probe_never_backfills_ordinary_labels(tmp_path, monkeypatch, credentials):
    privileged = "Inspector-only targeted probe: skip the explanation.\n"
    targeted = {**probe("unused"), "setup_program": privileged}
    del targeted["episode"]
    task = task_with_artifacts(tmp_path, "[]")
    native = Native(monkeypatch)
    sandboxes = Sandboxes(monkeypatch, native=native)
    script = InspectorScript([{"probes": [targeted]}, interpretation("violated")])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 2)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)
            return run, simulation, report

    run, simulation, report = asyncio.run(main())
    probe_sandbox = next(name for name in run.record.sandboxes if sandbox_record(run, name)["purpose"] == "probe")
    assert [copy.episode for copy in run.record.copies] == ["0000-simulator"] * 2 + ["0001-simulator"] * 2 + [probe_sandbox] * 2
    assert report.assessments[0].check.state_copy == run.record.copies[4].id
    assert report.assessments[0].claim.episode == probe_sandbox
    assert report.assessments[0].execution_scope == "package"
    assert report.assessments[0].outcome == "accepted_invalid"
    assert report.categories["accepted_invalid"] == "evidenced_issue"
    assert set(report.ordinary) == {"0000-simulator", "0001-simulator"}
    for label in report.ordinary.values():
        assert label.label == "unknown"
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
    assert label.label == "unknown"


def test_a_sole_named_reward_labels_like_reward_and_several_keys_stay_unavailable(tmp_path, monkeypatch, credentials):
    """The native reward is the pool's sole reward key, as reports read a configuration, else `reward`.
    Several keys without `reward`, in one episode or across the pool, give none."""
    def labels(*rewards):
        run = new_run(tmp_path, monkeypatch, credentials, name="_".join("-".join(item) for item in rewards))
        pool = ["0000-simulator", "0001-simulator"]
        for name, episode_rewards in zip(pool, rewards * 2 if len(rewards) == 1 else rewards):
            directory = run.config.output_dir / "episodes" / name
            directory.mkdir(parents=True)
            (directory / "episode.json").write_text(EpisodeResult(
                path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir),
                task_digest=tree_digest(run.config.task_dir), model="ordinary", reasoning_effort=None,
                versions={}, rewards=episode_rewards).model_dump_json())
            run.record.episodes.append(name)
        run.save()
        inspection = checks.InspectionResult(mode="grader", status="complete", categories={}, applicability={}, normal=[pool[1]],
                                            assessments=[Assessment(claim=Claim(mechanism="verified", episode=pool[0]),
                                                                    outcome="accepted_invalid")])
        return {name: (label.label, label.basis, label.reasons) for name, label in checks.label_ordinary(run, pool, inspection).items()}

    expected = labels({"reward": 1.0})
    assert [item[:2] for item in expected.values()] == [("accepted_invalid", "verified"), ("legitimate", "presumed")]
    assert labels({"passed": 1.0}) == expected
    for several in (labels({"passed": 1.0, "style": 0.5}), labels({"passed": 1.0}, {"style": 1.0})):
        assert all(label == "unavailable" for label, *_ in several.values())
        assert "no native reward 'reward'" in several["0001-simulator"][2][0]


def test_labels_keep_partial_credit_unknowns_and_unavailable_rewards_apart_from_probes(tmp_path, monkeypatch, credentials):
    from test_inspection import mock_experiments
    Sandboxes(monkeypatch)

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
    cases = [("accepted_invalid", "0000-simulator", "legitimate", {"coverage": covered}, "check-a", []),
             ("accepted_invalid", "0001-simulator", "unknown", {}, None, ["independent state at requested time 'grader_read'"]),
             ("accepted_invalid", "0004-simulator", "legitimate", {"coverage": covered.model_copy(update={"checks": ["check-c"]})}, "check-c", []),
             ("rejected_valid", "0004-simulator", "accepted_invalid", {}, None, []),
             # An issue with an open condition is verified and shows it; its category is already settled, so the setup probe below still runs.
             ("rejected_valid", "0005-simulator", "accepted_invalid", {"unresolved": ["whether the requirement applies at verification start"]}, None, []),
             ("accepted_invalid", "0006-simulator", "legitimate", {}, "check-d", []),
             # A setup probe runs only while its category is unsettled; ordinary reviews always run.
             ("accepted_invalid", "0008-inspector", "accepted_invalid", {}, None, []),
             ("accepted_invalid", "0006-simulator", "accepted_invalid", {}, None, []),
             ("accepted_invalid", "0007-simulator", "legitimate", {"coverage": covered}, "check-e", [])]
    probes = [{"category": category, "case": str(index), "location": f"/app/{index}",
               **({"setup_program": "targeted"} if name.endswith("inspector") else {"episode": name})}
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

    mock_experiments(monkeypatch, investigate)
    script = InspectorScript([{"probes": probes}])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            for index, name in enumerate(pool + ["0008-inspector"]):
                rewards = {} if index == 2 else {"reward": {0: 0.5, 3: 0.0}.get(index, 1.0)}
                episode(run, name, rewards, ("VerifierRuntimeError",) if index == 2 else ())
            run.save()
            return await checks.inspect_grader(run, pool, focused_attempts=0,
                                               categories=["accepted_invalid", "rejected_valid"])

    report = asyncio.run(main())
    labels = report.ordinary
    reasons = {name: " ".join(label.reasons) for name, label in labels.items()}
    assert set(labels) == set(pool)
    assert labels["0000-simulator"].label == "legitimate"
    assert covered.explanation in reasons["0000-simulator"]
    assert labels["0001-simulator"].label == "unknown" and "grader_read" in reasons["0001-simulator"]
    assert labels["0002-simulator"].label == "unavailable" and "VerifierRuntimeError" in labels["0002-simulator"].reasons[0]
    assert labels["0003-simulator"].label == "unknown"
    assert "does not establish legitimacy" in reasons["0003-simulator"]
    assert labels["0004-simulator"].label == "unknown" and "disagree" in reasons["0004-simulator"]
    assert (labels["0005-simulator"].label, labels["0005-simulator"].basis) == ("accepted_invalid", "verified")
    assert "verification start" in reasons["0005-simulator"]
    assert labels["0006-simulator"].label == "accepted_invalid"
    assert labels["0007-simulator"].label == "unknown" and "check-a" in reasons["0007-simulator"]
    assert "complete scoring outcome" in reasons["0007-simulator"]
    assert report.assessments[6].claim.episode == "0008-inspector"
    assert report.categories == {"accepted_invalid": "evidenced_issue", "rejected_valid": "evidenced_issue"}


def test_disabled_attack_makes_no_request(tmp_path, monkeypatch, credentials):
    native = Native(monkeypatch)
    provider = Provider([])

    async def main():
        async with serve(provider) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models=inspector(base))
            return run, await checks.attack(run, maximum_attempts=0, discovery_attempts=0)

    run, result = asyncio.run(main())
    assert result.status == "complete" and provider.requests == [] and native.configs == {}
    assert run.record.copies == []
