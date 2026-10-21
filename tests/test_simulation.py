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
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import pytest
from harbor.environments.base import ExecResult
from harbor.models.task.id import LocalTaskId
from harbor.models.trial.result import AgentInfo, TrialResult
from harbor.models.verifier.result import VerifierResult
from harbor.trial.hooks import TrialEvent
from harbor.trial.trial import Trial

from nudi import checks, workflow
from nudi.records import Assessment, Claim, EpisodeResult, ErrorRecord, ModelConfig, RunRecord
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
                (trial_dir / "agent" / "trajectory.json").write_text(json.dumps({"ordinary": name}))
            result = TrialResult(task_name="task", trial_name=config.trial_name, trial_uri=trial_dir.as_uri(),
                                 task_id=LocalTaskId(path=config.task.path), task_checksum="checksum", config=config,
                                 agent_info=AgentInfo(name="fake", version="0"),
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
    assert simulation.failures["0001-simulator"].message == "fake trial failure"
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


def probe(episode: str) -> dict:
    return {"category": "omitted_requirements", "case": f"explanation in {episode}", "episode": episode,
            "location": "/app/explanation.txt", "capture_point": "verification_start",
            "timing": "The requirement names verification start.", "program": CHECKER,
            "requirement": {"episode": None, "path": "instruction.md", "excerpt": REQUIREMENT},
            "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": SCORING}}


def interpretation(validity: str) -> dict:
    return {"claim": {"mechanism": "omitted required explanation",
                      "interpretation": "The task requires the explanation; full credit is deserved only when it exists.",
                      "derivation": {"observations": ["exists"], "minimum": "deserved", "maximum": "deserved", "validity": validity}}}


def test_selected_capture_reaches_supported_ordinary_labels_and_failed_capture_stays_unknown(tmp_path, monkeypatch, credentials):
    """An all-pass pool: one episode omits required work, one does it, one has no capture."""
    task = task_with_artifacts(tmp_path, '["/app/explanation.txt", "/logs/verifier/reward.json"]')
    native = Native(monkeypatch, files={"0000-simulator": {"/app/answer.txt": b"42\n"},
                                        "0001-simulator": {"/app/answer.txt": b"42\n", "/app/explanation.txt": b"because\n"},
                                        "0002-simulator": None})
    script = InspectorScript([{"probes": [probe("0001-simulator"), probe("0000-simulator")]},
                              interpretation("supported"), interpretation("violated")])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 3)
            report = await checks.inspect_grader(run, simulation.episodes, categories=["omitted_requirements"], focused_attempts=0)
            return run, simulation, report

    run, simulation, report = asyncio.run(main())
    assert [item.source for item in simulation.selection if item.selected] == ["/app/explanation.txt"]
    pool = ["0000-simulator", "0001-simulator", "0002-simulator"]
    assert simulation.episodes == pool
    broad = json.loads(script.requests[0]["messages"][-1]["content"])
    assert broad["capture_inventory"] == [item.model_dump() for item in simulation.selection]
    ordinary = broad["ordinary_episodes_read_first"]
    assert [episode["episode"] for episode in ordinary] == pool
    assert [episode["rewards"] for episode in ordinary] == [{"reward": 1.0}] * 3
    assert [state["location"] for state in ordinary[0]["captured"]] == ["/app/explanation.txt"]
    assert ordinary[2]["captured"] == [] and ordinary[2]["capture_failures"][0]["location"] == "/app/explanation.txt"
    labels = {name: label.label for name, label in report.ordinary.items()}
    assert labels == {"0000-simulator": "accepted_invalid", "0001-simulator": "legitimate", "0002-simulator": "unknown"}
    reasons = " ".join(report.ordinary["0002-simulator"].reasons)
    assert "archive unavailable" in reasons and "not evidence of absence" in reasons
    assert report.categories["omitted_requirements"] == "evidenced_issue"
    # The pool is reused: no further ordinary episode, and only checks ran afterwards.
    assert run.record.episodes == pool + ["0003-inspector", "0004-inspector"]
    assert all(native.instructions[name] == (task / "instruction.md").read_text() for name in pool)


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

    pool = [f"{index:04d}-simulator" for index in range(5)]
    cases = [("partial_credit", "0000-simulator", "legitimate", []),
             ("accepted_invalid", "0001-simulator", "unknown", ["independent state at requested time 'grader_read'"]),
             ("partial_credit", "0004-simulator", "legitimate", []),
             ("rejected_valid", "0004-simulator", "accepted_invalid", []),
             ("omitted_requirements", "0005-inspector", "accepted_invalid", [])]
    probes = [{"category": category, "case": str(index), "location": f"/app/{index}",
               **({"instruction": "targeted"} if name.endswith("inspector") else {"episode": name})}
              for index, (category, name, _, _) in enumerate(cases)]
    outcomes = iter(cases)

    async def investigate(run, probe, session):
        _, name, outcome, missing = next(outcomes)
        return Assessment(claim=Claim(mechanism=probe["case"], episode=name), outcome=outcome, missing=missing)

    monkeypatch.setattr(checks, "investigate", investigate)
    script = InspectorScript([{"probes": probes}])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            for name, rewards, errors in (("0000-simulator", {"reward": 0.5}, ()), ("0001-simulator", {"reward": 1.0}, ()),
                                          ("0002-simulator", {}, ("VerifierRuntimeError",)), ("0003-simulator", {"reward": 0.0}, ()),
                                          ("0004-simulator", {"reward": 1.0}, ()), ("0005-inspector", {"reward": 1.0}, ())):
                episode(run, name, rewards, errors)
            run.save()
            return await checks.inspect_grader(run, pool, focused_attempts=0,
                                               categories=["accepted_invalid", "rejected_valid", "omitted_requirements", "partial_credit"])

    report = asyncio.run(main())
    labels = report.ordinary
    assert set(labels) == set(pool)
    assert (labels["0000-simulator"].label, labels["0000-simulator"].assessments) == ("legitimate", [0])
    assert labels["0001-simulator"].label == "unknown" and "grader_read" in " ".join(labels["0001-simulator"].reasons)
    assert labels["0002-simulator"].label == "unavailable" and "VerifierRuntimeError" in labels["0002-simulator"].reasons[0]
    assert labels["0003-simulator"].label == "unknown" and labels["0003-simulator"].assessments == []
    assert "does not establish legitimacy" in " ".join(labels["0003-simulator"].reasons)
    assert labels["0004-simulator"].label == "unknown" and "disagree" in " ".join(labels["0004-simulator"].reasons)
    assert report.assessments[4].claim.episode == "0005-inspector"
    assert report.categories["omitted_requirements"] == "evidenced_issue"
