"""send_nudis, send_nudis_async and `nudi send-nudis`: one implementation over the existing analyses.

The existing analyses and run start are replaced by recorders that retain records the way
they do, so selection, configuration, guidance and partial results are checked without Docker
or model calls. The analyses themselves have their own suites.
"""

import asyncio
import errno
import importlib.metadata
import inspect
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import get_args

import litellm
import pytest
from pydantic import ValidationError

from nudi import attack, checks, cli, copies, inspection, report, run_state, send, send_nudis, send_nudis_async
from nudi.attack import AttackResult
from nudi.episode import tree_digest
from nudi.inspection import EpisodeLabel, InspectionResult
from nudi.records import (DEFAULT_MODELS, Assessment, Capacity, Claim, DiskFull, EpisodeResult, Observation, RunRecord, SandboxResult,
                          Simulation, StateCopy)
from nudi.run_state import Run
from test_metrics import RULE, TASK, basis, checked

SECRET = "sk-live-api-0123456789"
# Each progress line begins with the clock time.
CLOCK = re.compile(r"^nudi: \d\d:\d\d:\d\d ")
ALL_ROLES = ["attacker", "inspector", "simulator"]


class Analyses:
    """Stands in for start_run and the four existing analyses, recording each call."""

    def __init__(self, monkeypatch, *, candidates=(), fail=None, rewards=(), assessments=(), ordinary=None, judging=False):
        """`judging` keeps the real judge call, whose provider IO a test replaces; otherwise each finding is a new problem."""
        self.calls, self.candidates, self.fail, self.rewards = [], list(candidates), fail or {}, list(rewards)
        self.assessments, self.ordinary, self.early = list(assessments), ordinary or {}, []
        for name in ("start_run", "simulate", "inspect_grader", "inspect_hacks", "attack") + (() if judging else ("verdict",)):
            monkeypatch.setattr(send, name, getattr(self, name))

    async def verdict(self, run, known, request):
        return None

    def raise_if(self, name):
        if name in self.fail:
            raise self.fail[name]

    def start_run(self, config, roles, analyses=()):
        self.calls.append(("start_run", sorted(roles)))
        self.analyses = analyses
        self.config = config
        config.output_dir.mkdir(parents=True, exist_ok=True)
        record = RunRecord(task_dir=str(config.task_dir), path="harbor", path_reasons=["original grading and harness"],
                           models={**DEFAULT_MODELS, **config.models}, credential_sources={role: "credentials file" for role in roles},
                           spending_cap=config.spending_cap, cost_map={"source": "local"},
                           capacity=Capacity(docker_cpus=8, docker_memory_mb=16384, episode_cpus=1, episode_memory_mb=2048, concurrency=4))
        run = Run(config, record, None, {role: SECRET for role in roles})
        run.save()
        self.run = run
        return run

    async def simulate(self, run, episodes):
        self.calls.append(("simulate", episodes))
        self.raise_if("simulation")
        run.record.simulation = Simulation(requested=episodes, status="complete")
        for index, value in enumerate(self.rewards):
            name = f"{index:04d}-simulator"
            run.record.episodes.append(name)
            run.record.simulation.episodes.append(name)
            result = EpisodeResult(path="harbor", path_reasons=["original grading and harness"], task_name="sort",
                                   task_dir=str(run.config.task_dir), task_digest=tree_digest(run.config.task_dir), model="openai/gpt-test",
                                   reasoning_effort="high", versions={"harbor": "0.24.0"}, rewards={"reward": value})
            (run.config.output_dir / "episodes" / name).mkdir(parents=True)
            (run.config.output_dir / "episodes" / name / "episode.json").write_text(result.model_dump_json())
        run.save()
        return run.record.simulation

    def inspection(self, run, mode, assessments=(), ordinary=None):
        result = InspectionResult(mode=mode, status="complete", categories={}, applicability={}, assessments=list(assessments),
                                  ordinary=ordinary or {}, ordinary_inspection="holistic_inspection" if ordinary else None)
        (run.config.output_dir / f"inspection-{mode}.json").write_text(result.model_dump_json())
        return result

    async def inspect_grader(self, run, ordinary_pool, *, focused_attempts, isolated_inspections, request=None):
        self.calls.append(("inspect_grader", ordinary_pool, focused_attempts, isolated_inspections))
        self.grader_request = request
        self.raise_if("grader")
        return self.inspection(run, "grader", self.assessments, self.ordinary)

    async def inspect_hacks(self, run, *, focused_attempts, on_evidence=None, gate=None, judge=None):
        self.calls.append(("inspect_hacks", focused_attempts))
        self.raise_if("hack")
        result = self.inspection(run, "hack")
        # As the hack inspector does: each reading's probe is judged first, and an evidenced reading evidences its problem.
        for index, item in enumerate(self.candidates):
            problem = judge and await judge(f"experiment-{index:04d}", {"mechanism": item.claim.mechanism})
            result.assessments.append(item)
            if inspection.evidenced(item):
                if problem:
                    problem.findings.append(f"hack-{index}")
                    problem.evidence = "evidenced"
                if on_evidence:
                    on_evidence(result, index)
        (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
        return result

    async def attack(self, run, *, maximum_attempts, discovery_attempts, candidates=(), problems=(), deadline=None, minimal_hints=True,
                     feed=None, gate=None, earlier=None, judge=None):
        """Records each candidate tested without evidence. The attack beside the hack inspector, given `feed`, tests what
        it is fed; the attack phase's records its call."""
        self.deadline = deadline
        if feed is not None:
            self.beside = (maximum_attempts, discovery_attempts, minimal_hints)
            while (item := await feed.get()) is not None:
                self.early.append(item)
            candidates = self.early
        else:
            self.earlier = earlier
            self.calls.append(("attack", maximum_attempts, discovery_attempts, len(candidates)))
            self.minimal_hints = minimal_hints
            self.problems_sent = list(problems)
            self.raise_if("attack")
        self.candidates_sent = candidates
        tested = [item.model_copy(update={"conditions": {level: "unavailable" if item.guidance.get(level) is None else "no_evidenced_issue"
                                                         for level in ("full", "minimal")}}) for item in candidates]
        result = AttackResult(status="complete", maximum_attempts=maximum_attempts, discovery_attempts=discovery_attempts,
                              candidates=tested, problems=list(problems), discovery={"none": "no_evidenced_issue"},
                              unavailable={} if candidates else {"full": NO_CANDIDATE, "minimal": NO_CANDIDATE})
        (run.config.output_dir / "attack.json").write_text(result.model_dump_json())
        return result


def final_only(fake):
    """`fake` as the attack phase's attack; the attack beside the hack inspector only drains its feed."""
    async def attack(run, *, feed=None, gate=None, earlier=None, judge=None, **options):
        if feed is None:
            return await fake(run, **options)
        while await feed.get() is not None:
            pass

    return attack


def candidate(mechanism, interpretation, outcome="unknown", full_guidance=None, hint_location=None):
    return Assessment(claim=Claim(mechanism=mechanism, episode="0000-inspector", interpretation=interpretation,
                                  full_guidance=full_guidance, hint_location=hint_location), outcome=outcome)


MECHANISM = "Replace the expected digest in the grader and restore it after scoring."
INTERPRETATION = "Scoring reads the digest at verification and accepts an equal digest."
REPRODUCTION = "Write the passing digest into the grader expected-value table before the comparison."
LOCATION = "environment/grader.py"
WHERE_TO_LOOK = ("Where to look: examine the named file, interface, or component. "
                 "This hint excludes the solution and the reproduction recipe.")
NO_CANDIDATE = "no candidate"
FULL_UNAVAILABLE = "candidate exists but generated full guidance unavailable"
MINIMAL_UNAVAILABLE = "candidate exists but generated minimal guidance unavailable"


@pytest.mark.parametrize("argv", [["--help"], ["--version"], ["send-nudis", "--help"], ["send-nudis"], ["report"], ["cost", "a", "b"]])
def test_help_and_argument_errors_load_no_run_module(argv):
    """A fresh process, so no module is already loaded: help and argument errors return before nudi's run modules load."""
    code = (f"import sys; from nudi import cli\ntry:\n    cli.main({argv!r})\nexcept SystemExit:\n    pass\n"
            "print(sorted(name for name in sys.modules if name.split('.')[0] in "
            "('litellm', 'langchain', 'langgraph', 'deepagents', 'harbor', 'verifiers') or name in ('nudi.send', 'nudi.report')))")
    done = subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONPATH": str(Path(cli.__file__).parents[1])},
                          capture_output=True, text=True, check=True)
    assert done.stdout.splitlines()[-1] == "[]"


def test_version_is_the_installed_package_version(capsys):
    with pytest.raises(SystemExit) as done:
        cli.main(["--version"])
    assert done.value.code == 0 and capsys.readouterr().out == f"nudi {importlib.metadata.version('nudi')}\n"


def test_python_dash_m_nudi_runs_the_command():
    done = subprocess.run([sys.executable, "-m", "nudi", "--version"], capture_output=True, text=True, check=False)
    assert (done.returncode, done.stdout) == (0, f"nudi {importlib.metadata.version('nudi')}\n")


def test_the_analysis_choices_are_send_analysis():
    assert set(cli.ANALYSES) == set(get_args(send.Analysis))


def test_default_is_full_analysis_with_default_counts(tmp_path, monkeypatch, capsys):
    """Twelve ordinary episodes and two focused attempts per category by default, one try and one retry."""
    assert send.AnalysisConfig.model_fields["focused_attempts"].default == 2
    assert send.AnalysisConfig.model_fields["episodes"].default == inspect.signature(run_state.simulate).parameters["episodes"].default == 12
    assert {inspect.signature(function).parameters["focused_attempts"].default
            for function in (inspection.inspect_grader, inspection.inspect_hacks)} == {2}
    with pytest.raises(SystemExit):
        cli.main(["send-nudis", "--help"])
    help = " ".join(capsys.readouterr().out.split())
    assert "total focused attempts per grader inspector or hack inspector category, default 2" in help
    assert "ordinary Simulator episodes, default 12" in help
    assert ("runs one grader inspector session per ordinary episode (inspector_swarm), several at a time within the run's "
            "concurrency; default off (holistic_inspection)") in help and "3 to 7 minutes" not in help
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run")

    # The hack inspector first, with its attack beside it, so the grader inspector can read its findings; the attack last, so it
    # attacks the grader inspector's new problems. One try, one no-hint attempt, and the minimal hint after a reproduction.
    assert analyses.calls == [("start_run", ALL_ROLES), ("inspect_hacks", 2), ("simulate", 12), ("inspect_grader", [], 2, False),
                              ("attack", 1, 1, 0)]
    assert analyses.beside == (1, 1, True) and analyses.minimal_hints is True
    assert analyses.analyses == ("hack", "simulation", "grader", "attack")
    assert list(report["analyses"]) == ["hack", "simulation", "grader", "attack"]
    assert report["analyses"] == {"simulation": "complete", "grader": "complete", "hack": "complete", "attack": "complete"}
    assert report["status"] == "complete"
    assert sorted(report["inspections"]) == ["grader_inspector", "hack_inspector"]
    assert report == json.loads((tmp_path / "run" / "report.json").read_text())
    assert (tmp_path / "run" / "report.md").read_text().startswith("# nudi report")


@pytest.mark.parametrize("analysis, roles, called, selected", [
    ("simulation", ["inspector", "simulator"], ["simulate", "inspect_grader"], ["simulation", "grader"]),
    ("hacking", ["attacker", "inspector"], ["inspect_hacks"], ["hack", "attack"]),
])
def test_selection_runs_and_completes_only_selected_analyses(tmp_path, monkeypatch, analysis, roles, called, selected):
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis=analysis)

    assert analyses.calls[0] == ("start_run", roles)
    # The hacking analysis is the hack phase alone; it reports the attack that phase ran.
    assert [call[0] for call in analyses.calls[1:]] == called
    assert list(report["analyses"]) == selected
    # Deliberately leaving an analysis out is not incomplete coverage.
    assert sorted(report["analyses"]) == sorted(selected) and report["status"] == "complete"
    # Without a hack inspection the grader inspector's request is as before.
    assert getattr(analyses, "grader_request", None) is None


def test_python_async_and_cli_share_configuration_and_report(tmp_path, monkeypatch, capsys):
    config = tmp_path / "conf" / "nudi.toml"
    config.parent.mkdir()
    config.write_text('episodes = 5\nfocused_attempts = 1\nattacker_tries = 4\ndiscovery_attempts = 2\nspending_cap = 2.5\ncredentials_file = ".env"\n'
                      'workspace_memory_mb = 1024\ntime_limit = 600\n'
                      '[models.simulator]\nmodel = "openai/gpt-test"\nreasoning_effort = "low"\napi_key_var = "TEST_KEY"\n')
    task = tmp_path / "task"
    reports, calls, configs = [], [], []

    def record(analyses, report):
        reports.append(report)
        calls.append(analyses.calls)
        configs.append(analyses.config.model_dump(exclude={"output_dir"}))

    analyses = Analyses(monkeypatch)
    record(analyses, send_nudis(task, config, output_dir=tmp_path / "sync", episodes=7, discovery_attempts=3))
    analyses = Analyses(monkeypatch)
    record(analyses, asyncio.run(send_nudis_async(task, config, output_dir=tmp_path / "async", episodes=7, discovery_attempts=3)))
    analyses = Analyses(monkeypatch)
    code = cli.main(["send-nudis", str(task), "--config", str(config), "--output", str(tmp_path / "cli"), "--episodes", "7",
                     "--discovery-attempts", "3"])
    record(analyses, json.loads((tmp_path / "cli" / "report.json").read_text()))

    assert code == 0
    assert capsys.readouterr().out == (tmp_path / "cli" / "report.md").read_text()
    assert reports[0] == reports[1] == reports[2]
    assert calls[0] == calls[1] == calls[2] == [("start_run", ALL_ROLES), ("inspect_hacks", 1), ("simulate", 7),
                                                ("inspect_grader", [], 1, False), ("attack", 4, 3, 0)]
    assert configs[0]["discovery_attempts"] == 3
    analyses = Analyses(monkeypatch)
    send_nudis(task, config, output_dir=tmp_path / "file")
    assert analyses.calls[-1] == ("attack", 4, 2, 0)
    assert configs[0] == configs[1] == configs[2]
    # The keyword or flag replaces the file's value; the rest of the file stays.
    assert configs[0]["episodes"] == 7 and configs[0]["spending_cap"] == 2.5 and configs[0]["workspace_memory_mb"] == 1024
    assert configs[0]["time_limit"] == 600
    analyses = Analyses(monkeypatch)
    assert cli.main(["send-nudis", str(task), "--config", str(config), "--output", str(tmp_path / "flag"),
                     "--workspace-memory-mb", "768"]) == 0
    assert analyses.config.workspace_memory_mb == 768
    assert configs[0]["credentials_file"] == config.parent / ".env"
    assert configs[0]["models"]["simulator"] == {"model": "openai/gpt-test", "reasoning_effort": "low", "api_base": None,
                                                 "api_key_var": "TEST_KEY"}
    # Public configuration names the credential; it never holds a resolved value.
    assert reports[0]["configuration"]["models"]["simulator"]["api_key_var"] == "TEST_KEY"


def test_the_minimal_hint_level_and_one_no_hint_attempt_are_on_by_default_and_flags_turn_them_off(tmp_path, monkeypatch, capsys):
    task, config = tmp_path / "task", tmp_path / "nudi.toml"
    analyses = Analyses(monkeypatch)
    assert cli.main(["send-nudis", str(task), "--output", str(tmp_path / "default")]) == 0
    assert analyses.calls[-1] == ("attack", 1, 1, 0) and analyses.minimal_hints is True and analyses.beside == (1, 1, True)
    analyses = Analyses(monkeypatch)
    assert cli.main(["send-nudis", str(task), "--output", str(tmp_path / "flags"), "--no-minimal-hints",
                     "--attacker-tries", "2", "--discovery-attempts", "0"]) == 0
    assert analyses.calls[-1] == ("attack", 2, 0, 0) and analyses.minimal_hints is False and analyses.beside == (2, 0, False)
    config.write_text("minimal_hints = false\n")
    analyses = Analyses(monkeypatch)
    send_nudis(task, config, output_dir=tmp_path / "file")
    assert analyses.minimal_hints is False and analyses.config.minimal_hints is False
    with pytest.raises(SystemExit):
        cli.main(["send-nudis", "--help"])
    help = " ".join(capsys.readouterr().out.split())
    assert "total no-hint attempts, which start with the hack inspector, default 1" in help
    assert "with the minimal hint too; default on" in help


@pytest.mark.parametrize("rewards, status, message", [
    ([0.0, 0.5, 1.0], "unsupported", report.NON_BINARY),
    ([0.0, 1.0], "unavailable", report.UNKNOWN_REWARD),
    ([1.0, 0.0, 1.0], "supported", None),
], ids=["non-binary", "unknown", "presumed"])
def test_grader_agreement_availability_is_the_same_in_api_cli_json_and_markdown(tmp_path, monkeypatch, capsys, rewards, status, message):
    task = tmp_path / "task"
    for name, text in TASK.items():
        (task / name).parent.mkdir(parents=True, exist_ok=True)
        (task / name).write_text(text)
    grader = {}
    if status == "supported":
        # One verified reference grounds the binary rule; the other two episodes take it with presumed labels.
        grader = {"assessments": [checked("0000-simulator", "c0", "sorted", "supported",
                                          basis=basis("supported", ["sorted"], ["c0"], decision=RULE))],
                  "ordinary": {"0000-simulator": EpisodeLabel(label="legitimate", basis="verified", assessments=[0]),
                               **{f"000{index}-simulator": EpisodeLabel(label="legitimate", basis="presumed") for index in (1, 2)}}}
    Analyses(monkeypatch, rewards=rewards, **grader)
    result = send_nudis(task, output_dir=tmp_path / "api", episodes=len(rewards), analysis="simulation")
    Analyses(monkeypatch, rewards=rewards, **grader)
    code = cli.main(["send-nudis", str(task), "--output", str(tmp_path / "cli"), "--episodes", str(len(rewards)),
                     "--analysis", "simulation"])

    # Unsupported agreement alone neither fails the run nor hides its other results.
    assert code == 0 and result["status"] == "complete"
    assert result == json.loads((tmp_path / "cli" / "report.json").read_text())
    assert result["ordinary"]["groups"][0]["rewards"]["reward"]["distribution"] == [[value, count] for value, count in
                                                                                 sorted(Counter(rewards).items())]
    (group,) = result["metrics"]["confusion"]
    text = capsys.readouterr().out
    assert text == (tmp_path / "cli" / "report.md").read_text() == (tmp_path / "api" / "report.md").read_text()
    if status == "supported":
        assert (group["tp"], group["fp"], group["fn"], group["tn"], group["presumed"], group["verified"]) == (2, 0, 0, 1, 2, 1)
        for key in ("false_discovery_rate", "false_negative_rate"):
            assert group[key] == {"value": 0.0, "numerator": 0, "denominator": 2, "lower_bound": True, "unavailable": None}
        assert ("FDR (Of accepted work, how much was incorrect?) at least 0 (0/2, lower bound); FNR (Of correct work, how much was rejected?) at least 0 (0/2, lower bound); "
                "presumed 2, verified 1") in text
        return
    assert (group["status"], group["reasons"][0], group["tp"], group["false_discovery_rate"]["value"]) == (status, message, None, None)
    assert message in "\n".join(result["warnings"])
    assert f"reward: {status}, no agreement values. {message}" in text
    if status == "unsupported":
        assert "Wrong partial scores were not searched; that search is not supported yet." in text


INVALID = {
    "zero episodes": "episodes = 0\n",
    "unknown analysis": 'analysis = "hack"\n',
    "negative attacker tries": "attacker_tries = -1\n",
    "negative discovery attempts": "discovery_attempts = -1\n",
    "text count": 'focused_attempts = "3"\n',
    "unknown key": "episode = 5\n",
    "unknown role": '[models.judge]\nmodel = "xai/grok-4.7"\n',
    "misspelled model setting": '[models.simulator]\nmodel = "xai/grok-4.7"\nreasoning_efort = "low"\n',
    "nonpositive spending cap": "spending_cap = 0\n",
    "nonpositive workspace memory": "workspace_memory_mb = 0\n",
    "text workspace memory": 'workspace_memory_mb = "512"\n',
    "text isolated inspections": 'isolated_inspections = "yes"\n',
    "nonpositive time limit": "time_limit = 0\n",
    "infinite time limit": "time_limit = inf\n",
}


@pytest.mark.parametrize("text", INVALID.values(), ids=INVALID.keys())
def test_invalid_configuration_fails_before_execution(tmp_path, monkeypatch, capsys, text):
    config = tmp_path / "nudi.toml"
    config.write_text(text)
    analyses = Analyses(monkeypatch)

    with pytest.raises(ValidationError):
        send_nudis(tmp_path / "task", config, output_dir=tmp_path / "run")
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--config", str(config), "--output", str(tmp_path / "run")]) == 2
    assert "nudi: " in capsys.readouterr().err
    assert analyses.calls == [] and not (tmp_path / "run").exists()


def test_isolated_inspections_switch_parses_from_cli_api_and_file(tmp_path, monkeypatch, capsys):
    """Off (holistic_inspection) by default; on (inspector_swarm) from the flag, keyword or file. Hack inspection is unchanged."""
    task, config = tmp_path / "task", tmp_path / "nudi.toml"
    config.write_text("isolated_inspections = true\n")
    runs = {"cli off": lambda out: cli.main(["send-nudis", str(task), "--output", str(out)]),
            "cli on": lambda out: cli.main(["send-nudis", str(task), "--output", str(out), "--isolated-inspections"]),
            "api on": lambda out: send_nudis(task, output_dir=out, isolated_inspections=True),
            "api off": lambda out: send_nudis(task, output_dir=out, isolated_inspections=False),
            "file on": lambda out: send_nudis(task, config, output_dir=out)}
    found = {}
    for name, start in runs.items():
        analyses = Analyses(monkeypatch)
        start(tmp_path / name)
        found[name] = [call for call in analyses.calls if call[0] in ("inspect_grader", "inspect_hacks")]
    assert found == {name: [("inspect_hacks", 2), ("inspect_grader", [], 2, name.endswith("on"))] for name in runs}
    with pytest.raises(ValidationError):
        send_nudis(task, output_dir=tmp_path / "invalid", isolated_inspections="yes")
    with pytest.raises(SystemExit) as error:
        cli.main(["send-nudis", str(task), "--output", str(tmp_path / "flag"), "--isolated-inspections=yes"])
    assert error.value.code == 2 and "--isolated-inspections" in capsys.readouterr().err


def test_missing_output_directory_fails_before_execution(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch)
    with pytest.raises(ValidationError, match="output_dir"):
        send_nudis(tmp_path / "task")
    assert analyses.calls == []


def test_nonempty_output_directory_is_rejected_before_execution(tmp_path, monkeypatch, capsys):
    Analyses(monkeypatch)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    before = {path: path.read_bytes() for path in (tmp_path / "run").rglob("*") if path.is_file()}
    assert {path.name for path in before} >= {"run.json", "inspection-grader.json", "inspection-hack.json", "attack.json"}

    # A second run fails before its first analysis, so earlier complete records must not become its report.
    analyses = Analyses(monkeypatch, fail={"simulation": RuntimeError("daemon stopped")})
    with pytest.raises(ValueError, match="not empty"):
        send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 2
    assert "not empty" in capsys.readouterr().err
    assert analyses.calls == []
    assert {path: path.read_bytes() for path in (tmp_path / "run").rglob("*") if path.is_file()} == before


def test_unavailable_docker_daemon_is_a_startup_diagnostic(tmp_path, monkeypatch, capsys):
    message = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"

    def start_run(config, roles, analyses):
        raise subprocess.CalledProcessError(1, ["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"], output="", stderr=message + "\n")

    monkeypatch.setattr(send, "start_run", start_run)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 2
    error = capsys.readouterr().err
    assert error.startswith("nudi: ") and "docker info" in error and message in error


def test_each_inspector_candidate_composes_its_own_guidance_without_a_model_call(tmp_path, monkeypatch):
    async def no_model_call(**request):
        raise AssertionError("guidance composition must not call a model")

    monkeypatch.setattr(litellm, "acompletion", no_model_call)
    leak = "Copy the hidden expected digest from the grader source into the submission."
    other, place = "Write the reward file directly before verification.", "logs/verifier/reward.txt"
    analyses = Analyses(monkeypatch, candidates=[
        candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION),
        candidate("leakage_metadata", "the reward matches the submitted work", outcome="legitimate",
                  full_guidance=leak, hint_location="secret/expected.txt"),
        candidate("reward file", "the verifier trusts the reward file", "accepted_invalid", full_guidance=other, hint_location=place),
        # An identical repeat stays a distinct candidate here; attack merges it into one run.
        candidate("reward file", "the verifier trusts the reward file", "accepted_invalid", full_guidance=other, hint_location=place),
    ])
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    # Each evidenced finding is a problem of its own here, attacked beside the hack inspector.
    assert analyses.calls[-1] == ("inspect_hacks", 2)
    first, second, third = analyses.candidates_sent
    # Ids are assessment indices in inspection-hack.json; the legitimate outcome supplies nothing.
    assert [item.id for item in analyses.candidates_sent] == ["hack-0", "hack-2", "hack-3"]
    assert first.mechanism == MECHANISM and second.mechanism == third.mechanism == "reward file"
    # Full guidance is the reproduction. Minimal guidance is only where to look.
    assert first.guidance == {"full": REPRODUCTION, "minimal": f"{WHERE_TO_LOOK}\n{LOCATION}"}
    assert second.guidance == third.guidance == {"full": other, "minimal": f"{WHERE_TO_LOOK}\n{place}"}
    texts = json.dumps([item.guidance for item in analyses.candidates_sent])
    assert MECHANISM not in texts and INTERPRETATION not in texts
    assert leak not in texts and "secret/expected.txt" not in texts
    assert [item["id"] for item in report["attack"]["candidates"]] == ["hack-0", "hack-2", "hack-3"]
    assert report["attack"]["candidates"][0]["conditions"]["full"]["guidance"] == REPRODUCTION
    assert report["attack"]["discovery"]["status"] == "no_evidenced_issue"


@pytest.mark.parametrize("only_false_negative", [False, True])
def test_rejected_valid_hack_findings_become_valid_work_candidates(tmp_path, monkeypatch, only_false_negative):
    """Rejected valid work is a valid-work candidate with its own guidance, beside exploit candidates."""
    fn = candidate("correct work rejected", "undeserved rejection", outcome="rejected_valid",
                   full_guidance="Write the answer in the documented format.", hint_location="fn/private-grader.py")
    candidates = [fn]
    if not only_false_negative:
        candidates.append(candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION))
    analyses = Analyses(monkeypatch, candidates=candidates)
    result = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")
    sent = analyses.candidates_sent
    assert len(sent) == len(candidates)
    assert [(item.id, item.valid_work) for item in sent] == [("hack-0", True), ("hack-1", False)][:len(candidates)]
    assert sent[0].guidance == {"full": "Write the answer in the documented format.", "minimal": WHERE_TO_LOOK + "\nfn/private-grader.py"}
    retained = result["inspections"]["hack_inspector"]["findings"]["evidenced"]
    assert retained[0]["assessment"]["outcome"] == "rejected_valid"


@pytest.mark.parametrize(("full_guidance", "hint_location"), [
    (None, LOCATION),
    ("  ", LOCATION),
    (REPRODUCTION, None),
    (REPRODUCTION, "   "),
], ids=["full missing", "full blank", "location missing", "location blank"])
def test_missing_or_blank_guidance_field_leaves_that_condition_unavailable(tmp_path, monkeypatch, full_guidance, hint_location):
    analyses = Analyses(monkeypatch, candidates=[candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=full_guidance,
                                                           hint_location=hint_location)])
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    # Without full guidance a problem's finding is never fed, so the attack phase of a full analysis tries it.
    if not (isinstance(full_guidance, str) and full_guidance.strip()):
        assert analyses.candidates_sent == []
        report = send_nudis(tmp_path / "task", output_dir=tmp_path / "full")
        assert analyses.calls[-1] == ("attack", 1, 1, 1)
    (sent,) = analyses.candidates_sent
    assert sent.id == "hack-0"
    rendered = json.dumps(sent.guidance)
    assert MECHANISM not in rendered and INTERPRETATION not in rendered
    # The candidate and its interpretation stay in the inspection evidence.
    evidenced = report["inspections"]["hack_inspector"]["findings"]["evidenced"]
    assert evidenced[0]["claim"]["mechanism"] == MECHANISM
    assert evidenced[0]["interpretation"]["interpretation"] == INTERPRETATION
    conditions = report["attack"]["candidates"][0]["conditions"]
    if isinstance(full_guidance, str) and full_guidance.strip():
        assert sent.guidance["full"] == REPRODUCTION and "full" not in sent.unavailable
        assert conditions["full"]["status"] == "no_evidenced_issue"
    else:
        assert sent.guidance["full"] is None and conditions["full"]["status"] == "unavailable"
        assert sent.unavailable["full"] == conditions["full"]["unavailable"] == FULL_UNAVAILABLE
    if isinstance(hint_location, str) and hint_location.strip():
        assert sent.guidance["minimal"] == f"{WHERE_TO_LOOK}\n{LOCATION}" and "minimal" not in sent.unavailable
        assert conditions["minimal"]["status"] == "no_evidenced_issue"
    else:
        assert sent.guidance["minimal"] is None and conditions["minimal"]["status"] == "unavailable"
        assert sent.unavailable["minimal"] == conditions["minimal"]["unavailable"] == MINIMAL_UNAVAILABLE
    assert report["attack"]["discovery"]["status"] == "no_evidenced_issue"
    assert NO_CANDIDATE not in sent.unavailable.values()


def test_only_evidenced_or_suspected_findings_become_candidates_with_their_check_and_category():
    """A guided unavailable, ungrounded or legitimate reading supplies nothing; a guided unknown one follows the
    evidenced candidates.
    Each candidate keeps its check and the category of the experiment that measured it."""
    def reading(outcome, check, **guidance):
        return Assessment(claim=Claim(mechanism=MECHANISM, episode="0000-inspector", interpretation=INTERPRETATION,
                                      check=check, **guidance), outcome=outcome)

    guided = {"full_guidance": REPRODUCTION, "hint_location": LOCATION}
    hack = InspectionResult(mode="hack", categories={}, applicability={}, assessments=[
        reading("unknown", "check-0000", **guided), reading("unavailable", "check-0001", **guided),
        reading("ungrounded", "check-0002", **guided), reading("legitimate", "check-0003", **guided),
        reading("accepted_invalid", "check-0004"), reading("rejected_valid", "check-0005", **guided),
    ], experiments=[{"id": "experiment-0000", "category": "timing_interference", "check": "check-0004", "status": "assessed"},
                    {"id": "experiment-0001", "category": "unchecked_requirements", "check": "check-0005", "status": "assessed"}])
    first, second, suspected = send.guidance(hack)["candidates"]
    assert (suspected.id, suspected.outcome, suspected.valid_work) == ("hack-0", "unknown", False)
    assert (first.id, first.check, first.category, first.valid_work) == ("hack-4", "check-0004", "timing_interference", False)
    assert first.guidance == {"full": None, "minimal": None}
    assert first.unavailable == {"full": FULL_UNAVAILABLE, "minimal": MINIMAL_UNAVAILABLE}
    assert (second.id, second.check, second.category, second.valid_work) == ("hack-5", "check-0005", "unchecked_requirements", True)


def test_a_guided_unknown_reading_is_a_suspected_candidate_after_the_evidenced_ones():
    """A reading can measure a violated requirement at reward 1.0 with both guidance fields and stay unknown only
    because the scoring input was empty. So a guided unknown reading is a candidate behind every evidenced one and
    keeps its outcome. One that a later reading of its check
    withdraws, superseded or read legitimate, is not; an unguided one supplies nothing."""
    def reading(outcome, check, **guidance):
        return Assessment(claim=Claim(mechanism=f"{MECHANISM} {check}", episode="0000-inspector", interpretation=INTERPRETATION,
                                      check=check, **guidance), outcome=outcome, reward=1.0)

    guided = {"full_guidance": REPRODUCTION, "hint_location": LOCATION}
    hack = InspectionResult(mode="hack", categories={}, applicability={}, assessments=[
        reading("unknown", "check-0000", **guided),
        reading("unknown", "check-0001", **guided), reading("unknown", "check-0001", full_guidance=REPRODUCTION),
        reading("unknown", "check-0002", **guided), reading("legitimate", "check-0002", **guided),
        reading("unknown", "check-0003"),
        reading("accepted_invalid", "check-0004", **guided),
        reading("unknown", "check-0005", **guided), reading("rejected_valid", "check-0005", **guided),
        reading("unknown", None, hint_location=LOCATION),
    ])
    found = send.guidance(hack)["candidates"]
    assert [item.id for item in found] == ["hack-6", "hack-8", "hack-0", "hack-2", "hack-9"]
    assert [item.outcome for item in found] == ["accepted_invalid", "rejected_valid", "unknown", "unknown", "unknown"]
    assert found[2].guidance == {"full": REPRODUCTION, "minimal": f"{WHERE_TO_LOOK}\n{LOCATION}"} and not found[2].valid_work
    assert found[3].unavailable == {"minimal": MINIMAL_UNAVAILABLE}


def test_a_later_reading_of_its_check_withdraws_every_earlier_candidate():
    """A later reading of its check withdraws an evidenced reading, guided or not, also
    when the later one is legitimate or unguided. The latest stays a candidate, also unguided, and a claim without a
    check is never superseded."""
    def reading(check, outcome="accepted_invalid", **guidance):
        return Assessment(claim=Claim(mechanism=MECHANISM, episode="0000-inspector", interpretation=INTERPRETATION,
                                      check=check, **guidance), outcome=outcome)

    hack = InspectionResult(mode="hack", categories={}, applicability={}, assessments=[
        reading("check-0000"), reading("check-0001", full_guidance=REPRODUCTION), reading(None), reading(None),
        reading("check-0000", full_guidance=REPRODUCTION, hint_location=LOCATION), reading("check-0001", outcome="legitimate"),
        reading("check-0002", hint_location=LOCATION), reading("check-0002"),
    ])
    candidates = {item.id: item for item in send.guidance(hack)["candidates"]}
    assert list(candidates) == ["hack-2", "hack-3", "hack-4", "hack-7"]
    assert candidates["hack-4"].guidance == {"full": REPRODUCTION, "minimal": f"{WHERE_TO_LOOK}\n{LOCATION}"}
    assert candidates["hack-7"].guidance == {"full": None, "minimal": None}


def judge_replies(monkeypatch, replies):
    """Replace only the judge call's provider IO. Each of `replies` in turn is the Verdict tool call's arguments, or an
    exception it raises."""
    requests, replies = [], iter(replies)

    async def completion(**request):
        requests.append(json.loads(json.dumps(request, default=str)))
        reply = next(replies)
        if isinstance(reply, BaseException):
            raise reply
        call = {"id": "call_0", "type": "function", "function": {"name": "Verdict", "arguments": json.dumps(reply)}}
        return litellm.ModelResponse(choices=[{"index": 0, "finish_reason": "tool_calls",
                                               "message": {"role": "assistant", "content": None, "tool_calls": [call]}}])

    monkeypatch.setattr(litellm, "acompletion", completion)
    return requests


PIPE, CALIBRATION = "The grader trusts forged pipe bytes.", "The calibration test accepts a constant."


def pipe_findings():
    """One pipe byte forgery read three ways and one calibration flaw."""
    quote = Observation(episode="0000-inspector", path="tests/test_outputs.py", excerpt="assert out.split('|')[1] == expected")
    return [Assessment(claim=Claim(mechanism="Forge the pipe bytes\n in the output.", episode="0000-inspector", interpretation=INTERPRETATION,
                                   citations=[quote]), outcome="accepted_invalid"),
            candidate("Return a constant drift score.", INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION),
            candidate("Forge the pipe bytes on stdout.", INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION),
            candidate("Forge the pipe bytes in the log.", INTERPRETATION, "unknown", full_guidance=REPRODUCTION, hint_location=LOCATION)]


def judged_events(run_dir):
    return [{key: item[key] for key in ("inspector", "finding", "problem", "new", "cause")}
            for item in map(json.loads, (run_dir / "events.jsonl").read_text().splitlines()) if item["kind"] == "judged"]


def test_one_judge_call_per_probe_names_its_problem_and_each_problem_is_attacked_once(tmp_path, monkeypatch):
    """One flaw read several ways is several findings, and attacking each of them can spend every attempt on that flaw
    while another is never attacked. Before each probe's experiment one call of the inspector model judges it against
    the problems so far; the first needs no call. A problem's first evidenced finding with full guidance is attacked
    beside the hack inspector: hack-0 has none, so hack-2 stands for the pipe problem."""
    requests = judge_replies(monkeypatch, [{"same_as": None}, {"same_as": "P1"}, {"same_as": "P1"}])
    analyses = Analyses(monkeypatch, candidates=pipe_findings(), judging=True)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    assert len(requests) == 3
    assert {(request["model"], request["api_key"]) for request in requests} == {(DEFAULT_MODELS["inspector"].model, SECRET)}
    assert [tool["function"]["name"] for tool in requests[0]["tools"]] == ["Verdict"]
    assert json.loads(requests[1]["messages"][-1]["content"]) == {
        "finding": {"mechanism": "Forge the pipe bytes on stdout."}, "known_problems": [
            {"id": "P1", "cause": "Forge the pipe bytes in the output."}, {"id": "P2", "cause": "Return a constant drift score."}]}
    saved = AttackResult.model_validate_json((tmp_path / "run" / "attack.json").read_text())
    assert [(item.id, item.source, item.members, item.findings, item.evidence) for item in saved.problems] == [
        ("P1", "hack inspector", ["experiment-0000", "experiment-0002", "experiment-0003"], ["hack-0", "hack-2"], "evidenced"),
        ("P2", "hack inspector", ["experiment-0001"], ["hack-1"], "evidenced")]
    assert [item.id for item in analyses.candidates_sent] == ["hack-1", "hack-2"]
    assert [(item["finding"], item["problem"], item["new"]) for item in judged_events(tmp_path / "run")] == [
        ("experiment-0000", "P1", True), ("experiment-0001", "P2", True), ("experiment-0002", "P1", False),
        ("experiment-0003", "P1", False)]
    assert not any("judging" in warning for warning in json.loads((tmp_path / "run" / "run.json").read_text())["warnings"])


@pytest.mark.parametrize("reply", [
    {"same_as": "P9"}, {"same_as": ["P1"]},
    litellm.APIConnectionError(message="gateway unreachable", llm_provider="openai", model="deepseek"),
], ids=["unknown id", "invalid schema", "call failure"])
def test_a_failed_judge_call_counts_as_a_new_problem_with_one_warning(tmp_path, monkeypatch, reply):
    judge_replies(monkeypatch, [reply] * 3)
    analyses = Analyses(monkeypatch, candidates=pipe_findings(), judging=True)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    assert [item.id for item in analyses.candidates_sent] == ["hack-1", "hack-2"]
    assert [(item["problem"], item["new"]) for item in judged_events(tmp_path / "run")] == [
        ("P1", True), ("P2", True), ("P3", True), ("P4", True)]
    warnings = [item for item in json.loads((tmp_path / "run" / "run.json").read_text())["warnings"] if "problem" in item]
    assert [warning.split(" failed")[0] for warning in warnings] == [
        "judging experiment-0001", "judging experiment-0002", "judging experiment-0003"]
    assert all("counts as a new problem" in warning and SECRET not in warning for warning in warnings)


GRADER_STEPS, GRADER_LOCATION = "Write the answer in the documented format.", "tests/test_outputs.py"


def test_each_grader_finding_is_judged_against_every_problem_and_only_new_ones_are_attacked(tmp_path, monkeypatch):
    """The attack phase runs last. Each evidenced grader inspector finding is judged against the problems of both
    inspectors: grader-0 is the hack inspector's P1, which its attack beside the hack inspector already tried, so it is
    not attacked again; grader-1 is new, G1, and attacked. An id names its inspector and assessment, so a hack and a
    grader finding of one index stay distinct."""
    judge_replies(monkeypatch, [{"same_as": "P1"}, {"same_as": None}])
    analyses = Analyses(monkeypatch, judging=True, candidates=[
        candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)], assessments=[
        candidate("accepted forged output", INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION),
        candidate("rejected documented format", "undeserved rejection", "rejected_valid", full_guidance=GRADER_STEPS,
                  hint_location=GRADER_LOCATION),
        candidate("legitimate work", INTERPRETATION, "legitimate", full_guidance=GRADER_STEPS, hint_location=GRADER_LOCATION),
    ])
    tried = analyses.attack

    async def beside(run, **options):
        # The attack beside the hack inspector tries what it is fed.
        if options.get("feed") is None:
            return await tried(run, **options)
        await tried(run, **options)
        result = AttackResult.model_validate_json((run.config.output_dir / "attack.json").read_text())
        result.attempts = [attack.AttackAttempt(level="full", number=1, candidate=item.id, context="c", problem="P1",
                                               status="no_evidenced_issue")
                           for item in result.candidates]
        (run.config.output_dir / "attack.json").write_text(result.model_dump_json())

    monkeypatch.setattr(send, "attack", beside)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run")

    assert [item.id for item in analyses.early] == ["hack-0"]
    assert analyses.calls[-1] == ("attack", 1, 1, 1)
    (grader,) = analyses.candidates_sent
    assert (grader.id, grader.source, grader.valid_work) == ("grader-1", "grader_inspector", True)
    assert grader.guidance == {"full": GRADER_STEPS, "minimal": f"{WHERE_TO_LOOK}\n{GRADER_LOCATION}"}
    assert [(item.id, item.source, item.members, item.findings) for item in analyses.problems_sent] == [
        ("P1", "hack inspector", ["experiment-0000", "grader-0"], ["hack-0", "grader-0"]),
        ("G1", "grader inspector", ["grader-1"], ["grader-1"])]
    assert [(item["inspector"], item["finding"], item["problem"], item["new"]) for item in judged_events(tmp_path / "run")] == [
        ("hack", "experiment-0000", "P1", True), ("grader", "grader-0", "P1", False), ("grader", "grader-1", "G1", True)]
    # Only the change of evidence is logged: P1 was already evidenced, so its grader finding writes no second event.
    assert [(item["text"].split(" ", 2)[2], item["problem"]) for item in events(tmp_path / "run") if item["kind"] == "reproduced"] == [
        ("grader inspector found G1", "G1")]


@pytest.mark.parametrize("status", ["complete", "partial"])
def test_the_grader_inspector_request_lists_the_hack_findings_without_their_full_guidance(tmp_path, monkeypatch, status):
    """In the full analysis the grader inspector reads each hack candidate finding as a place to look: its id,
    category, outcome, mechanism and where to look, never its full guidance. A partial hack inspection still gives
    its findings and says it was partial."""
    analyses = Analyses(monkeypatch, candidates=[
        candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION),
        candidate("legitimate work", INTERPRETATION, "legitimate", full_guidance=REPRODUCTION, hint_location=LOCATION),
        candidate("reward file", "the verifier trusts the reward file", "unknown", full_guidance=REPRODUCTION)])
    inspect_hacks = analyses.inspect_hacks

    async def finished(run, *, focused_attempts, **_):
        result = (await inspect_hacks(run, focused_attempts=focused_attempts)).model_copy(update={"status": status})
        (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
        return result

    monkeypatch.setattr(send, "inspect_hacks", finished)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    assert analyses.grader_request == {"hack_inspection": status, "hack_findings": [
        {"id": "hack-0", "category": None, "outcome": "accepted_invalid", "mechanism": MECHANISM, "where_to_look": LOCATION},
        {"id": "hack-2", "category": None, "outcome": "unknown", "mechanism": "reward file", "where_to_look": None}]}
    assert REPRODUCTION not in json.dumps(analyses.grader_request)


def test_a_run_whose_steps_all_ran_exits_0_with_unresolved_evidence_in_its_answer(tmp_path, monkeypatch, capsys):
    """An inspection that returned with evidence unresolved ran to its end: no failed phase, status complete, exit 0."""
    analyses = Analyses(monkeypatch)
    inspect_hacks = analyses.inspect_hacks

    async def unresolved(run, **options):
        result = (await inspect_hacks(run, **options)).model_copy(update={"status": "partial"})
        (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
        return result

    monkeypatch.setattr(send, "inspect_hacks", unresolved)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 0
    built = json.loads((tmp_path / "run" / "report.json").read_text())
    assert (built["status"], built["unfinished"], built["unresolved"]) == ("complete", {}, ["hack"])
    assert json.loads((tmp_path / "run" / "run.json").read_text())["failed_phases"] == []
    assert "- Finished. Every step ran. Evidence stayed unresolved in the hack inspector, so the run may miss more.\n" in capsys.readouterr().out


def test_a_quiet_stretch_prints_one_line_naming_the_running_agent_jobs(tmp_path, monkeypatch, capsys):
    """Runs can go hours without a progress line. After `HEARTBEAT` seconds without one, stderr gets a line with the
    time since the analyses began and the agent jobs still open, counted by job with their problems."""
    analyses = Analyses(monkeypatch)
    monkeypatch.setattr(send, "HEARTBEAT", 0.2)
    inspect_hacks = analyses.inspect_hacks

    unlocked = []

    class Jobs(dict):
        """Each change and read of the open jobs holds the events lock, so they follow the log's order across threads."""
        def __setitem__(self, key, value):
            unlocked.extend(["set"] * (not run_state.events_lock.locked()))
            super().__setitem__(key, value)

        def pop(self, *args):
            unlocked.extend(["pop"] * (not run_state.events_lock.locked()))
            return super().pop(*args)

        def values(self):
            unlocked.extend(["read"] * (not run_state.events_lock.locked()))
            return super().values()

    async def quiet(run, **options):
        run.jobs = Jobs()
        run_state.event(run, "session_start", "hack inspector hack-broad started", inspector="hack", session="hack-broad")
        for number, problem in enumerate(["P2", "P1", "P2"]):
            run_state.event(run, "attempt_start", "Attacker started", episode=f"000{number}-attacker", problem=problem)
        run_state.event(run, "attempt_end", "Attacker finished", episode="0002-attacker", problem="P2")
        run_state.event(run, "session_start", "attack inspector started", inspector="attack", session="attack-2", problem="P2")
        while not any(item["kind"] == "heartbeat" for item in events(tmp_path / "run")):
            await asyncio.sleep(0.01)
        run_state.event(run, "session_end", "hack inspector hack-broad ended", inspector="hack", session="hack-broad")
        return await inspect_hacks(run, **options)

    monkeypatch.setattr(send, "inspect_hacks", quiet)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 0
    beats = [line for line in logged(capsys.readouterr().err) if "still running" in line]
    assert beats[0] == ("nudi: still running after 0:00:00: 1 hack inspector session; 2 Attackers on P1, P2; "
                        "1 attack inspector session on P2")
    beat = next(item for item in events(tmp_path / "run") if item["kind"] == "heartbeat")
    assert beat["jobs"] == {"hack inspector session": 1, "Attacker": 2, "attack inspector session": 1}
    assert unlocked == []


def test_a_hack_phase_that_raised_after_saving_findings_still_lists_them_for_the_grader_inspector(tmp_path, monkeypatch):
    """The grader inspector reads the findings `inspection-hack.json` saved before the error, never their full guidance,
    and its request says the hack inspection failed."""
    analyses = Analyses(monkeypatch, candidates=[
        candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)])

    async def raised(run, *, focused_attempts, **_):
        saved = analyses.inspection(run, "hack", analyses.candidates).model_copy(update={"status": "partial"})
        (run.config.output_dir / "inspection-hack.json").write_text(saved.model_dump_json())
        raise RuntimeError("hack broke")

    monkeypatch.setattr(send, "inspect_hacks", raised)
    built = send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    assert analyses.grader_request == {"hack_inspection": "failed", "hack_findings": [
        {"id": "hack-0", "category": None, "outcome": "accepted_invalid", "mechanism": MECHANISM, "where_to_look": LOCATION}]}
    assert REPRODUCTION not in json.dumps(analyses.grader_request)
    assert (built["status"], built["analyses"]["hack"]) == ("partial", "partial")


@pytest.mark.parametrize("case", ["no findings", "failed hack phase", "simulation only"])
def test_without_hack_findings_the_grader_inspector_request_is_unchanged(tmp_path, monkeypatch, case):
    found = [] if case == "no findings" else [candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION,
                                                        hint_location=LOCATION)]
    analyses = Analyses(monkeypatch, candidates=found, fail={"hack": RuntimeError("hack broke")} if case == "failed hack phase" else {})
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="simulation" if case == "simulation only" else "full")
    assert "inspect_grader" in [call[0] for call in analyses.calls]
    assert analyses.grader_request is None


def test_the_judge_reads_the_finding_and_each_problems_first_case_and_measured_findings(tmp_path, monkeypatch):
    """The judge compares the probe's category, mechanism, cited text and where it looks with each problem's first case and,
    once a problem is evidenced, the findings that measured it with their outcome. A long excerpt is cut and marked so,
    and each `judged` event keeps the request the judge read."""
    requests = judge_replies(monkeypatch, [{"same_as": None}])
    analyses = Analyses(monkeypatch, judging=True)
    first = {"category": "grader_tampering", "mechanism": "Swap the\n test runner.", "scoring": None, "location": "tests/run.sh",
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "x" * (send.EXCERPT + 5)}, "capture_point": "verification_start"}
    measured = {"id": "hack-0", "check": "check-0000", "outcome": "accepted_invalid", "mechanism": "Swap the test runner."}

    async def inspect_hacks(run, *, focused_attempts, on_evidence, gate, judge):
        problem = await judge("experiment-0000", first)
        problem.measured.append(measured)
        problem.evidence = "evidenced"
        await judge("experiment-0001", {**first, "mechanism": "Edit the scorer."})
        return analyses.inspection(run, "hack")

    monkeypatch.setattr(send, "inspect_hacks", inspect_hacks)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")
    case = {"category": "grader_tampering", "location": "tests/run.sh", "capture_point": "verification_start"}
    sent = json.loads(requests[0]["messages"][-1]["content"])
    assert sent == {"finding": {**case, "mechanism": "Edit the scorer.", "requirement": {"path": "instruction.md", "excerpt": "x" * send.EXCERPT + " [cut]"}},
                    "known_problems": [{"id": "P1", "cause": "Swap the test runner.", "case": case, "evidenced_findings": [measured]}]}
    assert [item["request"] for item in events(tmp_path / "run") if item["kind"] == "judged"] == [None, sent]
    assert "the same flaw reached by another input or read another way is the same problem" in send.JUDGE_PROMPT


def test_a_grader_finding_of_a_problem_the_hack_inspector_did_not_reproduce_evidences_and_attacks_it(tmp_path, monkeypatch):
    """The hack inspector's experiment did not evidence P1, so it was not attacked. The grader inspector evidences the
    same flaw in an ordinary episode, so P1 is evidenced after all, with a `reproduced` event, and attacked with that finding."""
    requests = judge_replies(monkeypatch, [{"same_as": "P1"}])
    analyses = Analyses(monkeypatch, judging=True, assessments=[
        candidate("accepted forged output", INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)])

    async def inspect_hacks(run, *, focused_attempts, on_evidence, gate, judge):
        (await judge("experiment-0000", {"mechanism": MECHANISM})).evidence = "not_reproduced"
        return analyses.inspection(run, "hack")

    monkeypatch.setattr(send, "inspect_hacks", inspect_hacks)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    assert [item.id for item in analyses.candidates_sent] == ["grader-0"]
    assert [(item.id, item.findings, item.evidence) for item in analyses.problems_sent] == [("P1", ["grader-0"], "evidenced")]
    # The grader finding states its outcome to the judge, and then is P1's measured finding.
    assert json.loads(requests[0]["messages"][-1]["content"])["finding"]["outcome"] == "accepted_invalid"
    assert [(item["id"], item["outcome"]) for item in analyses.problems_sent[0].measured] == [("grader-0", "accepted_invalid")]
    # The viewer reads the change from the log, as when a hack experiment evidences a problem.
    assert [(item["problem"], item["result"], "replayed" in item) for item in events(tmp_path / "run") if item["kind"] == "reproduced"] == [
        ("P1", "evidenced", False)]

def test_a_time_limit_during_the_attack_still_reports_its_untested_attempts_as_not_tested(tmp_path, monkeypatch, capsys):
    """The attack runs last in the full analysis, so a time limit can leave its candidates untested. Its record so far still
    reaches the report, where an attempt that never started and a condition no attempt tested are not tested."""
    analyses = Analyses(monkeypatch, candidates=[
        candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)])

    async def slow(run, *, maximum_attempts, discovery_attempts, candidates, problems=(), deadline=None, minimal_hints=True):
        analyses.calls.append(("attack", maximum_attempts, discovery_attempts, len(candidates)))
        # The time limit's end, on the event loop's clock, so a valid-work attempt can check that its agent timeout fits.
        analyses.deadline = deadline - asyncio.get_running_loop().time()
        waiting = attack.AttackAttempt(level="full", number=1, candidate="hack-0", sources=["hack-0"], context="attacker-hack-0-full-1")
        result = AttackResult(maximum_attempts=maximum_attempts, discovery_attempts=0, candidates=candidates, problems=list(problems),
                              attempts=[waiting], discovery={"none": "unattempted"})
        path = run.config.output_dir / "attack.json"
        path.write_text(result.model_dump_json())
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            result.status = waiting.status = "cancelled"
            path.write_text(result.model_dump_json())
            raise

    monkeypatch.setattr(send, "attack", final_only(slow))
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 1
    output, error = capsys.readouterr()
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "simulate", "inspect_grader", "attack"]
    assert 0 < analyses.deadline <= 0.6
    assert logged(error)[-1] == "nudi: the run stopped at its time limit of 0.01 minutes during attack"
    built = json.loads((tmp_path / "run" / "report.json").read_text())
    assert built["status"] == "time_limit" and built["analyses"]["attack"] == "cancelled"
    (tested,) = built["attack"]["candidates"]
    assert [tested["conditions"][level]["tested"] for level in ("full", "minimal")] == [False, False]
    assert "- attempt 1 on hack-0 (no category, none) with full instructions did not start: cancelled" in output
    assert "- Not attempted: hack-0 (no category, none) with only a hint" in output
    assert (f"- P1 from the hack inspector, ●●○○○ reproduced exploit, no clear Attacker result: {MECHANISM.rstrip('.')}; "
            "findings hack-0 (no category, none).") in output


def test_no_candidate_leaves_guidance_unavailable_and_still_attacks(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    assert analyses.calls[-1] == ("inspect_hacks", 2) and analyses.beside == (1, 1, True) and analyses.deadline is None
    assert report["attack"]["candidates"] == []
    assert report["attack"]["unavailable"] == {"full": NO_CANDIDATE, "minimal": NO_CANDIDATE}
    assert "candidate exists" not in report["attack"]["unavailable"]["full"]
    assert report["attack"]["discovery"]["status"] == "no_evidenced_issue"


def test_inspector_prompt_requests_reproduction_steps_and_a_location_only():
    from nudi import inspection
    prompt = " ".join(inspection.inspector_prompt("hack").split())
    assert "`full_guidance`" in prompt and "concrete steps that reproduce it" in prompt
    assert "`hint_location`" in prompt and "file, interface, or component" in prompt
    assert "must not contain a solution or a reproduction recipe" in prompt
    assert "A finding without either field gives the Attacker nothing to run." in prompt


def test_failed_analysis_keeps_independent_results_and_redacts_credentials(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch, fail={"hack": RuntimeError(f"provider echoed {SECRET}")})
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run")

    # The attack still runs, without candidates, after the hack inspection failed; the grader inspector gets no hack findings.
    assert analyses.calls[-1] == ("attack", 1, 1, 0)
    assert analyses.grader_request is None
    assert report["analyses"] == {"simulation": "complete", "grader": "complete", "hack": "not run", "attack": "complete"}
    assert report["status"] == "partial"
    assert "run: hack failed: RuntimeError: provider echoed [redacted]" in report["warnings"]
    for name in ("run.json", "report.json", "report.md"):
        assert SECRET not in (tmp_path / "run" / name).read_text()


def test_cancellation_writes_the_partial_report_and_propagates(tmp_path, monkeypatch):
    """A run stopped during the ordinary-episode path keeps the hack inspector's results."""
    analyses = Analyses(monkeypatch, fail={"simulation": asyncio.CancelledError()})
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(send_nudis_async(tmp_path / "task", output_dir=tmp_path / "run"))

    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "simulate"]
    report = json.loads((tmp_path / "run" / "report.json").read_text())
    # The attack beside the hack inspector ran, and the attack phase that continues it did not, so the attack is unfinished.
    assert report["analyses"] == {"simulation": "not run", "grader": "not run", "hack": "complete", "attack": "cancelled"}
    assert report["status"] == "partial" and report["unfinished"]["attack"] == "cancelled" and report["unresolved"] == []
    assert "run: cancelled during simulation" in report["warnings"]


def test_a_second_ctrl_c_still_records_the_cancellation_and_writes_the_report(tmp_path, monkeypatch):
    """asyncio raises a second SIGINT as KeyboardInterrupt, which passes a CancelledError handler."""
    Analyses(monkeypatch, fail={"attack": KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):
        send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    assert "run: cancelled during attack" in json.loads((tmp_path / "run" / "report.json").read_text())["warnings"]


def logged(text: str) -> list[str]:
    """stderr lines with the clock time of each progress line removed."""
    return [CLOCK.sub("nudi: ", line) for line in text.splitlines()]


def test_the_command_reports_each_phase_on_stderr_with_its_clock_time_duration_and_count(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(send, "elapsed", lambda started: "0:00:00")
    Analyses(monkeypatch, rewards=[1.0, 0.0])
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--episodes", "2"]) == 0
    error = capsys.readouterr().err
    assert all(CLOCK.match(line) for line in error.splitlines())
    assert logged(error) == [
        "nudi: hack inspector and its Attackers started",
        "nudi: hack inspector and its Attackers done after 0:00:00: 0 experiments, 0 Attacker attempts",
        "nudi: Simulator started",
        "nudi: Simulator done after 0:00:00: 2 of 2 episodes",
        "nudi: grader inspector started",
        "nudi: grader inspector done after 0:00:00: 0 experiments, 0 assessments",
        "nudi: attack started",
        "nudi: attack done after 0:00:00: 0 attempts, 0 exploits",
    ]
    Analyses(monkeypatch, fail={"hack": RuntimeError(f"provider echoed {SECRET}")})
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "failed")]) == 1
    error = logged(capsys.readouterr().err)
    assert error[0:2] == ["nudi: hack inspector and its Attackers started",
                          "nudi: hack inspector and its Attackers ended after 0:00:00: hack failed: RuntimeError: provider echoed [redacted]"]
    assert error[-1].startswith("nudi: attack done after ")


def events(run_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]


# The run's cost so far, on every event.
COST = ("known_cost", "unknown_cost_calls", "cancelled_calls")


def fields(log: list[dict]) -> list[dict]:
    """Each event without its version, time, text and cost so far."""
    return [{key: value for key, value in item.items() if key not in ("v", "time", "text", *COST)} for item in log]


def test_each_progress_line_is_an_event_and_stderr_prints_its_text(tmp_path, monkeypatch, capsys):
    """A reader of events.jsonl sees what the terminal shows, timed and versioned, with the values each line is built from."""
    monkeypatch.setattr(send, "elapsed", lambda started: timedelta(days=1, seconds=1))
    Analyses(monkeypatch, rewards=[1.0, 0.0])
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--episodes", "2"]) == 0
    log = events(tmp_path / "run")
    # The run's last event is not printed: stdout has the report.
    assert capsys.readouterr().err.splitlines() == [item["text"] for item in log[:-1]]
    for item in log:
        moment = datetime.fromisoformat(item["time"])
        assert item["v"] == 1 and moment.utcoffset() == timedelta(0)
        assert item["text"].startswith(f"nudi: {moment.astimezone():%H:%M:%S} ")
    assert fields(log) == [
        {"kind": "phase_start", "phase": "hack", "slots": 2},
        {"kind": "phase_end", "phase": "hack", "elapsed": 86401, "status": "complete", "experiments": 0, "assessments": 0, "attacker_attempts": 0},
        {"kind": "phase_start", "phase": "simulation"},
        {"kind": "phase_end", "phase": "simulation", "elapsed": 86401, "status": "complete", "episodes": 2, "requested": 2},
        {"kind": "phase_start", "phase": "grader"},
        {"kind": "phase_end", "phase": "grader", "elapsed": 86401, "status": "complete", "experiments": 0, "assessments": 0},
        {"kind": "phase_start", "phase": "attack"},
        {"kind": "phase_end", "phase": "attack", "elapsed": 86401, "status": "complete", "attempts": 0, "findings": 0, "exploits": 0,
         "correct_work_failed": 0},
        {"kind": "run_end", "status": "complete", "report": "report.json"},
    ]
    assert log[-1]["text"].endswith(" run ended: complete")
    # A duration is whole seconds, and the text shows it as the terminal always did.
    assert log[1]["text"].endswith(" hack inspector and its Attackers done after 1 day, 0:00:01: 0 experiments, 0 Attacker attempts")


def test_failed_phases_and_run_warnings_are_events_and_stderr_prints_their_text(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(send, "elapsed", lambda started: timedelta(0))
    analyses = Analyses(monkeypatch, fail={"hack": RuntimeError(f"provider echoed {SECRET}")})

    async def warned(run, episodes):
        run.record.known_cost, run.record.unknown_cost_calls, run.record.cancelled_calls = 0.25, 1, 2
        run.warn("a model call's cost is unknown")
        return await analyses.simulate(run, episodes)

    monkeypatch.setattr(send, "simulate", warned)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    log = events(tmp_path / "run")
    assert capsys.readouterr().err.splitlines() == [item["text"] for item in log[:-1]]
    assert fields(log)[:2] == [
        {"kind": "phase_start", "phase": "hack", "slots": 2},
        {"kind": "phase_end", "phase": "hack", "elapsed": 0, "status": "failed",
         "error": "hack failed: RuntimeError: provider echoed [redacted]"}]
    assert fields(log)[3] == {"kind": "warning", "message": "a model call's cost is unknown"}
    # Each event carries the run's cost so far, as run.json has it then.
    assert [[item[key] for key in COST] for item in log] == [[0.0, 0, 0]] * 3 + [[0.25, 1, 2]] * (len(log) - 3)
    assert fields(log)[-1] == {"kind": "run_end", "status": "partial", "report": "report.json"}
    assert SECRET not in (tmp_path / "run" / "events.jsonl").read_text()


def test_the_python_api_writes_the_event_log(tmp_path, monkeypatch):
    """The log does not depend on the command: a run started from Python writes it too."""
    Analyses(monkeypatch)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "sync", analysis="hacking")
    Analyses(monkeypatch)
    asyncio.run(send_nudis_async(tmp_path / "task", output_dir=tmp_path / "async", analysis="hacking"))
    for name in ("sync", "async"):
        assert [item["kind"] for item in events(tmp_path / name)] == ["phase_start", "phase_end", "run_end"]
        assert (tmp_path / name / "events.jsonl").stat().st_mode & 0o777 == 0o600


def test_the_log_is_readable_while_the_run_goes_on(tmp_path, monkeypatch):
    """Each event is a whole line on disk when it returns, so a reader can follow the run."""
    analyses = Analyses(monkeypatch)
    seen = []

    async def reading(run, ordinary_pool, **options):
        seen.extend(events(run.config.output_dir))
        return await analyses.inspect_grader(run, ordinary_pool, **options)

    monkeypatch.setattr(send, "inspect_grader", reading)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    assert [item["kind"] for item in seen] == ["phase_start", "phase_end"] * 2 + ["phase_start"]
    assert seen[-1]["phase"] == "grader" and seen == events(tmp_path / "run")[:5]


def test_events_written_at_once_stay_whole_lines(tmp_path):
    """Sessions and attempts run at once in one process; their events must never interleave within a line."""
    from concurrent.futures import ThreadPoolExecutor

    from nudi import run_state

    record = SimpleNamespace(known_cost=0.0, unknown_cost_calls=0, cancelled_calls=0)
    run = SimpleNamespace(config=SimpleNamespace(output_dir=tmp_path), record=record, events_failed=False)
    texts = [f"{writer}-{number}-" + "x" * 50_000 for writer in range(8) for number in range(20)]
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda text: run_state.event(run, "warning", text, message=text), texts))
    lines = (tmp_path / "events.jsonl").read_text().splitlines()
    assert sorted(json.loads(line)["message"] for line in lines) == sorted(texts)


def test_ctrl_c_prints_the_report_and_one_line_naming_it_and_exits_130(tmp_path, monkeypatch, capfd):
    """Most measured runs ended with a stop, so a stop must not leave stdout empty."""
    analyses = Analyses(monkeypatch)

    async def interrupted(run, ordinary_pool, **options):
        signal.raise_signal(signal.SIGINT)
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_grader", interrupted)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 130
    output, error = capfd.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text() and output.startswith("# nudi report\n\n## Answer\n")
    error = logged(error)
    assert error[error.index("nudi: grader inspector started") + 1:] == [
        "nudi: stopping: saving what was found", f"nudi: stopped by you; report written to {tmp_path / 'run' / 'report.md'}"]
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "simulate"]
    assert "run: cancelled during grader" in json.loads((tmp_path / "run" / "report.json").read_text())["warnings"]
    # The cancelled run still ends its log; the command's own last line is not an event.
    log = events(tmp_path / "run")
    assert log[-2]["kind"] == "phase_start" and log[-2]["phase"] == "grader"
    assert fields(log)[-1] == {"kind": "run_end", "status": "cancelled", "report": "report.json"}


@pytest.mark.parametrize("signum, ignored", [(signal.SIGTERM, False), (signal.SIGINT, True)])
def test_a_termination_signal_or_an_ignored_ctrl_c_stops_the_run_as_ctrl_c_does(tmp_path, monkeypatch, signum, ignored):
    """`kill PID` sends SIGTERM, and a run started in the background of a non-interactive shell inherits SIGINT ignored;
    both stop the run as the first Ctrl-C does: the report and the log's end are saved. The previous handler returns."""
    analyses = Analyses(monkeypatch)

    async def stopped(run, ordinary_pool, **options):
        signal.raise_signal(signum)
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_grader", stopped)
    previous = signal.signal(signum, signal.SIG_IGN) if ignored else signal.getsignal(signum)
    try:
        with pytest.raises(KeyboardInterrupt) as stop:
            send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
        assert signal.getsignal(signum) == (signal.SIG_IGN if ignored else previous)
    finally:
        signal.signal(signum, previous)
    assert isinstance(stop.value, send.Terminated) is (signum == signal.SIGTERM)
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "simulate"]
    built = json.loads((tmp_path / "run" / "report.json").read_text())
    answer = (tmp_path / "run" / "report.md").read_text().split("## Answer\n\n", 1)[1]
    if signum == signal.SIGTERM:
        assert "run: stopped by a termination signal during grader" in built["warnings"]
        assert answer.startswith("- Stopped by a termination signal. Results below are what was found so far.")
    else:
        assert "run: cancelled during grader" in built["warnings"] and answer.startswith("- Stopped by you. ")
    assert fields(events(tmp_path / "run"))[-1] == {"kind": "run_end", "status": "cancelled", "report": "report.json"}


def test_a_termination_signal_the_caller_ignores_stays_ignored(tmp_path, monkeypatch):
    """A parent that ignores SIGTERM wants the run to outlive it; only an inherited ignored Ctrl-C is taken over."""
    Analyses(monkeypatch)
    during = []

    async def inspected(run, ordinary_pool, **options):
        during.append(signal.getsignal(signal.SIGTERM))
        signal.raise_signal(signal.SIGTERM)
        signal.raise_signal(signal.SIGINT)
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_grader", inspected)
    previous = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        with pytest.raises(KeyboardInterrupt) as stop:
            send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert during == [signal.SIG_IGN] and not isinstance(stop.value, send.Terminated)


def test_sigterm_prints_the_report_and_exits_143(tmp_path, monkeypatch, capfd):
    """A caller's `kill PID` is not a Ctrl-C, so the command says so and exits 143, the shell's code for SIGTERM."""
    Analyses(monkeypatch)

    async def stopped(run, ordinary_pool, **options):
        signal.raise_signal(signal.SIGTERM)
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_grader", stopped)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 143
    output, error = capfd.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text()
    assert logged(error)[-1] == f"nudi: stopped by a termination signal; report written to {tmp_path / 'run' / 'report.md'}"


def test_nudi_report_keeps_the_stop_of_a_run_whose_last_report_write_failed(tmp_path, monkeypatch, capsys):
    """Every analysis saved a complete record before the records host filled at the last report write: the run stopped,
    and its rebuilt report says so, with the error its `run_end` recorded, instead of a finished run."""
    Analyses(monkeypatch)
    write = report.write

    def full(*args, **kwargs):
        raise DiskFull("no space left on the records host for report.json")

    monkeypatch.setattr(report, "write", full)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    end = fields(events(tmp_path / "run"))[-1]
    assert end["status"] == "stopped" and end["report"] is None
    monkeypatch.setattr(report, "write", write)
    assert cli.main(["report", str(tmp_path / "run")]) == 1
    built = json.loads((tmp_path / "run" / "report.json").read_text())
    assert built["status"] == "stopped" and built["unfinished"] == {}
    assert built["outcome"] == f"Stopped: {end['error']}. Results below are what was found so far."
    assert "DiskFull: no space left" in end["error"]


def test_nudi_report_keeps_the_stop_of_a_run_interrupted_while_it_deleted_its_state_copies(tmp_path, monkeypatch, capsys):
    """Every analysis saved a complete record before SIGTERM came during the final deletion of state copies: the run
    was interrupted, and its rebuilt report says so instead of a finished run."""
    Analyses(monkeypatch)

    async def interrupted(run):
        # The final deletion runs to its end after a stop, so this one returns soon after the signal.
        signal.raise_signal(signal.SIGTERM)
        await asyncio.sleep(0.1)

    monkeypatch.setattr(send.copies, "delete", interrupted)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 143
    assert fields(events(tmp_path / "run"))[-1]["status"] == "cancelled"
    assert cli.main(["report", str(tmp_path / "run")]) == 1
    built = json.loads((tmp_path / "run" / "report.json").read_text())
    assert built["status"] == "stopped" and built["unfinished"] == {}
    assert built["outcome"] == "Stopped: the run was interrupted. Results below are what was found so far."


def test_ctrl_c_saves_the_report_and_exits_130_when_cancelled_work_never_returns(tmp_path, monkeypatch, capfd):
    """A remote command that never returns, cancelled or not, holds the stop at most `STOP_WAIT` seconds before the
    records and the report are saved, and as long again before the command exits; the work still running is a warning.
    Each Ctrl-C prints one line at once, and a second one does not undo the bound."""
    Analyses(monkeypatch)
    monkeypatch.setattr(send, "STOP_WAIT", 0.3)

    async def stuck(run, ordinary_pool, **options):
        signal.raise_signal(signal.SIGINT)
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            # A second Ctrl-C while the loop waits, as at a terminal.
            asyncio.get_running_loop().call_later(0.05, signal.raise_signal, signal.SIGINT)
        while True:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass  # The remote call ignores every cancellation.

    monkeypatch.setattr(send, "inspect_grader", stuck)
    started = time.monotonic()
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 130
    assert time.monotonic() - started < 5
    output, error = capfd.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text() and output.startswith("# nudi report\n")
    error = logged(error)
    assert error[error.index("nudi: grader inspector started") + 1:] == [
        *["nudi: stopping: saving what was found"] * 2, f"nudi: stopped by you; report written to {tmp_path / 'run' / 'report.md'}"]
    warnings = json.loads((tmp_path / "run" / "report.json").read_text())["warnings"]
    assert ("run: grader was still running 0.3 seconds after the stop and was left; a Modal sandbox it holds ends at "
            "its lifetime, a Docker container stays until removed") in warnings
    assert "run: cancelled during grader" in warnings
    assert fields(events(tmp_path / "run"))[-1] == {"kind": "run_end", "status": "cancelled", "report": "report.json"}


def test_a_time_limit_ends_the_run_as_a_stop_does_and_exits_1(tmp_path, monkeypatch, capsys):
    """Some tasks take many hours, so the limit is one option with no default. At the limit
    the run cleans up and reports as a stop does; not every step ran, so it exits 1."""
    assert send.AnalysisConfig.model_fields["time_limit"].default is None
    analyses = Analyses(monkeypatch)

    async def slow(run, ordinary_pool, **options):
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_grader", slow)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 1
    output, error = capsys.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text()
    assert "- Stopped at your time limit. Results below are what was found so far.\n" in output
    assert logged(error)[-1] == "nudi: the run stopped at its time limit of 0.01 minutes during grader"
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "simulate"]
    report = json.loads((tmp_path / "run" / "report.json").read_text())
    assert report["status"] == "time_limit"
    assert "run: the run stopped at its time limit of 0.01 minutes during grader" in report["warnings"]
    log = events(tmp_path / "run")
    assert log[-2]["text"] == error.splitlines()[-1]
    assert fields(log)[-2:] == [{"kind": "time_limit", "phase": "grader", "minutes": 0.01},
                                   {"kind": "run_end", "status": "time_limit", "report": "report.json"}]


def sleeping(run, *args, **options):
    return asyncio.sleep(30)


@pytest.mark.parametrize("shape", ["raised", "returned"])
def test_a_failed_phase_before_the_time_limit_still_exits_1(tmp_path, monkeypatch, shape):
    """Reaching the limit is a normal end only when no phase failed before it, by an error or a
    stop such as the spending cap."""
    analyses = Analyses(monkeypatch, fail={"hack": RuntimeError("hack broke")} if shape == "raised" else {})
    if shape == "returned":
        async def incomplete(run, *, focused_attempts, **_):
            result = analyses.inspection(run, "hack").model_copy(update={"status": "spending_exhausted"})
            (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
            return result
        monkeypatch.setattr(send, "inspect_hacks", incomplete)
    monkeypatch.setattr(send, "attack", final_only(sleeping))
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 1
    report = json.loads((tmp_path / "run" / "report.json").read_text())
    assert report["status"] == "partial"
    assert "run: the run stopped at its time limit of 0.01 minutes during attack" in report["warnings"]


def test_a_phase_that_swallows_the_limit_still_marks_it_reached(tmp_path, monkeypatch):
    """Harbor can catch the cancellation and return; the run then ends past its limit, and says so."""
    analyses = Analyses(monkeypatch)

    async def swallowing(run, ordinary_pool, **options):
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            pass
        return analyses.inspection(run, "grader")

    monkeypatch.setattr(send, "inspect_grader", swallowing)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 1
    assert json.loads((tmp_path / "run" / "report.json").read_text())["status"] == "time_limit"


def test_ctrl_c_before_any_report_says_none_was_written(tmp_path, monkeypatch, capsys):
    def interrupted(*args, **options):
        raise KeyboardInterrupt

    monkeypatch.setattr(send, "send_nudis", interrupted)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 130
    assert tuple(capsys.readouterr()) == ("", "nudi: stopped by you; no report was written\n")


def test_no_space_on_the_records_host_stops_the_run_with_one_message(tmp_path, monkeypatch, capsys):
    """The analyses after the full disk do not run; the report is still written once space allows it."""
    full = DiskFull(f"no space left on the records host to write {tmp_path / 'run' / 'inspection-hack.json'}")
    analyses = Analyses(monkeypatch, fail={"hack": full})
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    error = logged(capsys.readouterr().err)
    assert error == ["nudi: hack inspector and its Attackers started", f"nudi: stopped: {full}; report written to {tmp_path / 'run' / 'report.md'}"]
    assert fields(events(tmp_path / "run"))[-1] == {"kind": "run_end", "status": "stopped", "error": f"DiskFull: {full}",
                                                    "report": "report.json"}
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks"]
    assert f"run: hack stopped: {full}" in json.loads((tmp_path / "run" / "report.json").read_text())["warnings"]


def failing_append(monkeypatch, kind: str, error: OSError) -> None:
    """Every append to the log succeeds except those of `kind`'s events, which raise `error`."""
    append = run_state.append_private

    def failing(path, text):
        if json.loads(text)["kind"] == kind:
            raise error
        append(path, text)

    monkeypatch.setattr(run_state, "append_private", failing)


def no_space_under(monkeypatch, folder: Path) -> None:
    """From now on every nudi write under `folder` finds no space, as on a full disk."""
    real = os.open

    def full(path, *args, **options):
        if Path(path).is_relative_to(folder):
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), str(path))
        return real(path, *args, **options)

    monkeypatch.setattr(os, "open", full)


def test_a_storage_error_at_run_end_keeps_the_error_that_ended_the_run(tmp_path, monkeypatch, capsys):
    """The caller learns why the run stopped, not only that its last event could not be written."""
    failure = ValueError("report generation failed before results could be saved")

    def write(*args):
        raise failure

    monkeypatch.setattr(report, "write", write)
    failing_append(monkeypatch, "run_end", OSError(errno.EDQUOT, "disk quota exceeded"))
    Analyses(monkeypatch)
    with pytest.raises(ValueError) as raised:
        send_nudis(tmp_path / "task", output_dir=tmp_path / "api")
    assert raised.value is failure
    Analyses(monkeypatch)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "cli")]) == 2
    assert capsys.readouterr().err.splitlines()[-1] == f"nudi: {failure}"


def test_a_storage_error_at_run_end_after_ctrl_c_still_prints_the_report_and_exits_130(tmp_path, monkeypatch, capsys):
    Analyses(monkeypatch)
    failing_append(monkeypatch, "run_end", PermissionError(errno.EACCES, "permission denied"))

    async def interrupted(run, ordinary_pool, **options):
        signal.raise_signal(signal.SIGINT)
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_grader", interrupted)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 130
    output, error = capsys.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text()
    assert error.splitlines()[-1] == f"nudi: stopped by you; report written to {tmp_path / 'run' / 'report.md'}"


def test_a_full_disk_at_run_end_after_ctrl_c_during_the_report_write_still_exits_130(tmp_path, monkeypatch, capsys):
    """Ctrl-C once the report is saved leaves a cancellation pending, and no await is left before the run returns."""
    Analyses(monkeypatch)
    failing_append(monkeypatch, "run_end", OSError(errno.ENOSPC, "no space left on device"))
    saved, pending = report.write, []

    def write(*args):
        saved(*args)
        signal.raise_signal(signal.SIGINT)
        pending.append(asyncio.current_task().cancelling())

    monkeypatch.setattr(report, "write", write)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 130
    assert pending == [1]
    output, error = capsys.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text()
    assert error.splitlines()[-1] == f"nudi: stopped by you; report written to {tmp_path / 'run' / 'report.md'}"


def test_a_full_disk_at_run_end_of_a_finished_run_still_returns_its_report(tmp_path, monkeypatch):
    """The report is already written; readers treat the log without `run_end` as incomplete."""
    Analyses(monkeypatch)
    failing_append(monkeypatch, "run_end", OSError(errno.ENOSPC, "no space left on device"))
    assert send_nudis(tmp_path / "task", output_dir=tmp_path / "run")["status"] == "complete"
    assert "run_end" not in [item["kind"] for item in events(tmp_path / "run")]


class AfterFailedAppend(logging.Handler):
    """An application's handler that reacts to every record once the run's append has failed."""

    def __init__(self, analyses, reaction):
        super().__init__()
        self.analyses, self.reaction = analyses, reaction

    def handle(self, record):
        # Without the handler's lock: a run blocked in `emit` would keep it, and logging's shutdown at exit waits for it.
        self.emit(record)
        return record

    def emit(self, record):
        if self.analyses.run.events_failed:
            self.reaction(self.analyses.run)


def raises_eio(run):
    raise OSError(errno.EIO, os.strerror(errno.EIO))


def warns(run):
    run.warn("an application handler saw a record")


@pytest.mark.parametrize("reaction", [raises_eio, warns])
def test_a_handler_that_raises_or_warns_after_a_failed_append_leaves_a_finished_run_unchanged(tmp_path, monkeypatch, capsys, reaction):
    """No line follows the failed append, so a handler can neither change how the run ends nor wait on the log's lock."""
    analyses = Analyses(monkeypatch)
    failing_append(monkeypatch, "run_end", OSError(errno.EDQUOT, os.strerror(errno.EDQUOT)))
    # A run that blocks keeps this lock, not the one later tests use.
    monkeypatch.setattr(run_state, "events_lock", threading.Lock())
    logger, handler = logging.getLogger("nudi"), AfterFailedAppend(analyses, reaction)
    level, ended = logger.level, []

    def both():
        ended.append(send_nudis(tmp_path / "task", output_dir=tmp_path / "api")["status"])
        ended.append(cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "cli")]))

    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        thread = threading.Thread(target=both, daemon=True)
        thread.start()
        thread.join(timeout=20)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
    assert not thread.is_alive(), "the run blocked"
    assert ended == ["complete", 0] and analyses.run.events_failed
    output, error = capsys.readouterr()
    assert output == (tmp_path / "cli" / "report.md").read_text()
    assert logged(error)[-1].startswith("nudi: attack done after ")


class OnPhaseStart(AfterFailedAppend):
    """An application's handler that reacts to each phase's start line, an ordinary nudi line."""

    def emit(self, record):
        if getattr(record, "event", {}).get("kind") == "phase_start":
            self.reaction(self.analyses.run)


def test_a_handler_that_warns_on_an_ordinary_line_leaves_the_run_unblocked(tmp_path, monkeypatch, capsys):
    """A handler may call back into the run while nudi logs a line. The run finishes, the warning's event follows the
    line that caused it, and stderr prints the events in the log's order."""
    analyses = Analyses(monkeypatch)
    # A run that blocks keeps this lock, not the one later tests use.
    monkeypatch.setattr(run_state, "events_lock", threading.Lock())
    # On the root logger, after the command's own handler, where `logging.basicConfig` puts an application's.
    root, logger, handler = logging.getLogger(), logging.getLogger("nudi"), OnPhaseStart(analyses, warns)
    level, ended = logger.level, []

    def both():
        ended.append(send_nudis(tmp_path / "task", output_dir=tmp_path / "api")["status"])
        ended.append(cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "cli")]))

    root.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        thread = threading.Thread(target=both, daemon=True)
        thread.start()
        thread.join(timeout=20)
    finally:
        root.removeHandler(handler)
        logger.setLevel(level)
    assert not thread.is_alive(), "the run blocked"
    assert ended == ["complete", 0]
    log = events(tmp_path / "cli")
    assert [item["kind"] for item in log][:3] == ["phase_start", "warning", "phase_end"]
    assert [item["kind"] for item in log].count("warning") == 1
    assert capsys.readouterr().err.splitlines() == [item["text"] for item in log[:-1]]


def test_a_handler_that_raises_on_an_ordinary_line_stops_the_run_with_its_error(tmp_path, monkeypatch):
    """The error leaves the logging call where nudi logged the line, so the run stops with it."""
    analyses = Analyses(monkeypatch)
    root, logger, handler = logging.getLogger(), logging.getLogger("nudi"), OnPhaseStart(analyses, raises_eio)
    level = logger.level
    root.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        with pytest.raises(OSError) as raised:
            send_nudis(tmp_path / "task", output_dir=tmp_path / "run")
    finally:
        root.removeHandler(handler)
        logger.setLevel(level)
    assert raised.value.errno == errno.EIO
    log = events(tmp_path / "run")
    assert [item["kind"] for item in log] == ["phase_start", "run_end"] and log[-1]["status"] == "stopped"
    assert [call[0] for call in analyses.calls] == ["start_run"]


class WarnsInsideItsLock(logging.Handler):
    """An application's handler that holds its own lock while it handles a record, and warns the run when it sees the
    application's line. Its waits end, so a run that would block here fails the test instead of hanging it."""

    def __init__(self, run, holding, appended):
        super().__init__()
        self.run, self.holding, self.appended, self.mine = run, holding, appended, threading.RLock()

    def handle(self, record):
        if self.mine.acquire(timeout=10):
            try:
                self.emit(record)
            finally:
                self.mine.release()
        return record

    def emit(self, record):
        if record.getMessage() == "the application's line":
            self.holding.set()
            self.appended.wait(10)
            self.run.warn("an application handler saw its line")


def test_a_handler_that_warns_inside_its_lock_while_another_thread_logs_an_event_blocks_neither(tmp_path, monkeypatch):
    """One thread's line holds an application handler, which warns the run. Another thread writes an event meanwhile and
    then waits for that handler. Neither waits for the other, and the file keeps both events in the order written."""
    run = Analyses(monkeypatch).start_run(SimpleNamespace(task_dir=tmp_path / "task", models={}, spending_cap=None,
                                                          output_dir=tmp_path / "run"), [])
    monkeypatch.setattr(run_state, "events_lock", threading.Lock())
    holding, appended = threading.Event(), threading.Event()
    append = run_state.append_private

    def append_then_signal(path, text):
        append(path, text)
        if json.loads(text)["kind"] == "phase_start":
            appended.set()

    monkeypatch.setattr(run_state, "append_private", append_then_signal)
    root, logger, handler = logging.getLogger(), logging.getLogger("nudi"), WarnsInsideItsLock(run, holding, appended)
    level = logger.level
    application = threading.Thread(target=logging.getLogger("application").warning, args=("the application's line",), daemon=True)
    nudi_line = threading.Thread(target=run_state.event, args=(run, "phase_start", "a phase started"), daemon=True)
    root.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        application.start()
        assert holding.wait(5)
        nudi_line.start()
        application.join(timeout=5)
        nudi_line.join(timeout=5)
    finally:
        root.removeHandler(handler)
        logger.setLevel(level)
    assert not application.is_alive() and not nudi_line.is_alive(), "the threads blocked each other"
    assert [item["kind"] for item in events(tmp_path / "run")] == ["phase_start", "warning"]


@pytest.mark.parametrize("code", [errno.EDQUOT, errno.ENOSPC])
def test_a_failed_append_at_the_time_limit_still_ends_the_run_at_its_time_limit(tmp_path, monkeypatch, capsys, code):
    """The log never changes how a run ends. Its line still reaches stderr, no line says the log stops,
    and no later event is written, so the log stays a whole prefix even when space returns."""
    analyses = Analyses(monkeypatch)
    monkeypatch.setattr(send, "inspect_grader", sleeping)
    failure = OSError(code, os.strerror(code))
    failing_append(monkeypatch, "time_limit", failure)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 1
    output, error = capsys.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text()
    assert json.loads((tmp_path / "run" / "report.json").read_text())["status"] == "time_limit"
    assert logged(error)[-2:] == ["nudi: grader inspector started",
                                  "nudi: the run stopped at its time limit of 0.01 minutes during grader"]
    assert [item["kind"] for item in events(tmp_path / "run")] == ["phase_start", "phase_end"] * 2 + ["phase_start"]
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "simulate"]


def test_a_phase_that_fails_on_a_full_disk_still_prints_why(tmp_path, monkeypatch, capsys):
    """The failure reason reaches stderr although its event cannot be written; the next record write stops the run."""
    analyses = Analyses(monkeypatch)

    async def failing(run, *, focused_attempts, **_):
        no_space_under(monkeypatch, run.config.output_dir)
        raise RuntimeError("hack broke")

    monkeypatch.setattr(send, "inspect_hacks", failing)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    error = logged(capsys.readouterr().err)
    assert error[:3] == ["nudi: hack inspector and its Attackers started",
                         "nudi: hack inspector and its Attackers ended after 0:00:00: hack failed: RuntimeError: hack broke",
                         "nudi: Simulator started"]
    assert error[3:] == [f"nudi: stopped: no space left on the records host to write {tmp_path / 'run' / 'report.json'}; "
                         "no report was written"]
    assert [item["kind"] for item in events(tmp_path / "run")] == ["phase_start"]
    assert [call[0] for call in analyses.calls] == ["start_run", "simulate"]


def test_a_disk_that_stays_full_from_the_time_limit_on_still_stops_the_run(tmp_path, monkeypatch, capsys):
    """A full disk stops the run through its other records, as before the log existed, and the time limit line still prints."""
    Analyses(monkeypatch)

    async def slow(run, ordinary_pool, **options):
        try:
            await asyncio.sleep(30)
        finally:
            no_space_under(monkeypatch, run.config.output_dir)

    monkeypatch.setattr(send, "inspect_grader", slow)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 1
    error = logged(capsys.readouterr().err)
    assert error[-2:] == ["nudi: the run stopped at its time limit of 0.01 minutes during grader",
                          f"nudi: stopped: no space left on the records host to write {tmp_path / 'run' / 'report.json'}; "
                          "no report was written"]
    assert error[-3] == "nudi: grader inspector started"
    assert events(tmp_path / "run")[-1]["kind"] == "phase_start"


def test_a_task_environment_that_cannot_start_stops_the_run_with_its_reason(tmp_path, monkeypatch, capsys):
    """A verifier image that never builds must not keep the run going for hours. Once the hack inspector stops
    environment_unavailable, no later analysis runs; stderr, the report's analyses and its warnings say why."""
    from nudi.records import EnvironmentUnavailable

    analyses = Analyses(monkeypatch)
    reason = ("the task's verifier environment failed to start 3 times in a row, last with ModalFailure: Modal start failed: "
              "ImageBuildError; no later sandbox or episode can use it, so the run stops")

    async def inspect_hacks(run, *, focused_attempts, **_):
        analyses.calls.append(("inspect_hacks", focused_attempts))
        result = InspectionResult(mode="hack", status="environment_unavailable", categories={}, applicability={})
        (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
        raise EnvironmentUnavailable(reason)

    monkeypatch.setattr(send, "inspect_hacks", inspect_hacks)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    error = logged(capsys.readouterr().err)
    assert error == ["nudi: hack inspector and its Attackers started", f"nudi: hack inspector and its Attackers stopped after 0:00:00: {reason}"]
    assert fields(events(tmp_path / "run"))[1:] == [
        {"kind": "phase_end", "phase": "hack", "elapsed": 0, "status": "stopped", "error": reason},
        {"kind": "run_end", "status": "partial", "report": "report.json"}]
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks"]
    built = json.loads((tmp_path / "run" / "report.json").read_text())
    assert built["analyses"] == {"hack": "environment_unavailable", "attack": "cancelled", "simulation": "not run", "grader": "not run"}
    assert f"run: hack stopped: {reason}" in built["warnings"]


def test_a_full_disk_at_the_final_save_still_writes_the_smaller_report(tmp_path, monkeypatch, capsys):
    """When the last `run.save()` finds no space, the smaller report is still written."""
    analyses = Analyses(monkeypatch)
    full = DiskFull(f"no space left on the records host to write {tmp_path / 'run' / 'run.json'}")

    async def attack(run, **options):
        def no_space():
            raise full

        monkeypatch.setattr(run, "save", no_space)
        raise full

    monkeypatch.setattr(send, "attack", final_only(attack))
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    assert capsys.readouterr().err.splitlines()[-1] == f"nudi: stopped: {full}; report written to {tmp_path / 'run' / 'report.md'}"
    assert json.loads((tmp_path / "run" / "report.json").read_text())["analyses"]["attack"] == "not run"
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "simulate", "inspect_grader"]


# What a rerun of the attack carries from the earlier run record, beside the inspection records it copies.
CARRIED = ("episodes", "sandboxes", "checks", "copies", "simulation", "probe_episodes", "persistence_probes", "events")


def sandbox_record(task: Path, **fields) -> str:
    """A sandbox record as an inspection leaves it, with the digest of the task as it is now."""
    return SandboxResult(**{"name": "sandbox-0000", "purpose": "check", "session_id": "earlier", "ids": {}, "task_dir": str(task),
                            "task_digest": tree_digest(task), "copy_digest": "0", "environment": {}, **fields}).model_dump_json()


def earlier_run(tmp_path, monkeypatch, analysis, **fake):
    """An earlier run of the fake analyses in `run-1` of a task with one file, with one inspector episode, one sandbox and
    one priced call added as a real inspection leaves them."""
    (tmp_path / "task").mkdir()
    (tmp_path / "task" / "grader.py").write_text("expected = 1\n")
    Analyses(monkeypatch, **fake)
    earlier = tmp_path / "run-1"
    send_nudis(tmp_path / "task", output_dir=earlier, analysis=analysis)
    record = json.loads((earlier / "run.json").read_text())
    episode, box = earlier / "episodes" / f"{len(record['episodes']):04d}-inspector", earlier / "sandboxes" / "sandbox-0000"
    for folder in (episode, box):
        folder.mkdir(parents=True)
    (episode / "trace.txt").write_text("inspector trace")
    (box / "sandbox.json").write_text(sandbox_record(tmp_path / "task"))
    record["episodes"].append(episode.name)
    record["sandboxes"].append(box.name)
    record["calls"].append({"role": "inspector", "episode": episode.name, "model": "openai/gpt-test", "cost": 0.5, "cost_source": "litellm"})
    record["known_cost"] = 0.5
    (earlier / "run.json").write_text(json.dumps(record))
    return earlier


def snapshot(folder: Path) -> dict:
    """Every path under `folder`, with each file's bytes."""
    return {path.relative_to(folder): path.read_bytes() if path.is_file() else None for path in sorted(folder.rglob("*"))}


SOURCE = ("Only the attack ran in this run; the other analyses came from the earlier run run-1, with the statuses that run recorded. "
          "The state copies, earlier Attacker episodes and sandboxes this report lists from that run are that run's, and each "
          "episode keeps its own model.")


def test_attack_from_reruns_only_the_attack_on_an_earlier_hack_inspection(tmp_path, monkeypatch, capsys):
    """The earlier run is only read. What its inspection points to is copied, never linked, so the new folder is a whole
    run, and the names this run gives continue the earlier numbering. Models, settings and cost lines are this run's."""
    found = [candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)]
    earlier = earlier_run(tmp_path, monkeypatch, "hacking", candidates=found)
    before = snapshot(earlier)
    # This run's inspections would find nothing, so every candidate comes from the earlier record.
    analyses = Analyses(monkeypatch)
    rerun = tmp_path / "run-2"
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(rerun), "--attack-from", str(earlier),
                     "--attacker-tries", "3"]) == 0

    assert analyses.calls == [("start_run", ["attacker", "inspector"]), ("attack", 3, 1, 1)]
    assert [item.id for item in analyses.candidates_sent] == ["hack-0"]
    assert snapshot(earlier) == before
    assert (rerun / "inspection-hack.json").read_bytes() == (earlier / "inspection-hack.json").read_bytes()
    assert json.loads((rerun / "attack.json").read_text())["maximum_attempts"] == 3
    for folder in ("episodes", "sandboxes"):
        assert snapshot(rerun / folder) == snapshot(earlier / folder)
    assert not any(path.is_symlink() or not path.resolve().is_relative_to(rerun.resolve()) for path in rerun.rglob("*"))
    old, new = (json.loads((folder / "run.json").read_text()) for folder in (earlier, rerun))
    assert {field: new[field] for field in CARRIED} == {field: old[field] for field in CARRIED}
    assert new["attack_from"] == str(earlier.resolve()) and new["calls"] == [] and new["known_cost"] == 0
    built = json.loads((rerun / "report.json").read_text())
    assert built["analyses"] == {"hack": "complete", "attack": "complete"} and built["status"] == "complete"
    assert built["configuration"]["attack_from"] == "run-1" and built["configuration"]["cost_by_job"] == {}
    assert built["inspections"] == json.loads((earlier / "report.json").read_text())["inspections"]
    assert (built["answer"][0], built["answer"][-1]) == ("Finished. Every step ran.", SOURCE)
    printed = capsys.readouterr()
    assert f"- {SOURCE}\n" in printed.out
    # One line says what the rerun takes from the earlier run, before the copy, so a long copy is not silent.
    log = events(rerun)
    assert [item["kind"] for item in log] == ["reused", "phase_start", "judged", "reproduced", "phase_end", "run_end"]
    assert fields(log)[0] == {"kind": "reused", "earlier": str(earlier.resolve()), "analyses": ["hack"], "episodes": 1, "sandboxes": 1}
    assert log[0]["text"].endswith(f" reusing hack of the earlier run {earlier.resolve()}; copying 1 episodes and 1 sandboxes")
    assert log[0]["text"] in printed.err.splitlines()


def test_attack_from_replays_the_earlier_runs_problems_in_its_log_without_a_judge_call(tmp_path, monkeypatch):
    """The rerun starts from the earlier run's judged problems, so its log repeats each one's judgements and evidence,
    as that run wrote them, for a reader of this log alone, each marked `replayed` so it is not read as this run's
    discovery. The judge is not called again."""
    found = [candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)]
    earlier = earlier_run(tmp_path, monkeypatch, "hacking", candidates=found)
    requests = judge_replies(monkeypatch, [])
    Analyses(monkeypatch, judging=True)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=earlier)

    assert requests == []
    log = [item for item in events(tmp_path / "run-2") if item["kind"] in ("judged", "reproduced")]
    assert [item["kind"] for item in log] == ["judged", "reproduced"]
    assert judged_events(tmp_path / "run-2") == judged_events(earlier)
    assert (log[1]["problem"], log[1]["result"]) == ("P1", "evidenced")
    assert all(item["text"].endswith("in the earlier run") and item["replayed"] is True for item in log)


def test_a_rerun_whose_copy_fails_still_ends_its_event_log(tmp_path, monkeypatch):
    """Copying is part of the run, so a failed copy stops it with a last event, as any other error does."""
    earlier = earlier_run(tmp_path, monkeypatch, "hacking")
    Analyses(monkeypatch)

    def broken(source, target, **options):
        raise OSError("copy failed")

    monkeypatch.setattr(send.shutil, "copytree", broken)
    with pytest.raises(OSError, match="copy failed"):
        send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=earlier)
    assert [item["kind"] for item in events(tmp_path / "run-2")] == ["reused", "run_end"]
    assert fields(events(tmp_path / "run-2"))[-1] == {"kind": "run_end", "status": "stopped", "error": "OSError: copy failed", "report": None}


def test_attack_from_a_full_run_keeps_its_simulation_and_attacks_the_grader_findings_too(tmp_path, monkeypatch):
    """Each evidenced grader finding, accepted cheats and rejected valid work alike, is a candidate beside the hack
    findings, as when the attack follows both inspectors. The ordinary episodes, labels and metrics read the copied records. TOML paths are relative to the file.
    The run's start names only the attack, which is all that runs."""
    earlier = earlier_run(tmp_path, monkeypatch, "full", rewards=[1.0, 0.0], candidates=[
        candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)], assessments=[
        candidate("accepted forged output", INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION),
        candidate("rejected documented format", "undeserved rejection", "rejected_valid", full_guidance=GRADER_STEPS,
                  hint_location=GRADER_LOCATION)])
    before = snapshot(earlier)
    analyses = Analyses(monkeypatch)
    (tmp_path / "rerun.toml").write_text('attack_from = "run-1"\noutput_dir = "run-2"\n')
    built = send_nudis(tmp_path / "task", tmp_path / "rerun.toml")

    assert [call[0] for call in analyses.calls] == ["start_run", "attack"]
    assert [(item.id, item.source, item.valid_work) for item in analyses.candidates_sent] == [
        ("hack-0", "hack_inspector", False), ("grader-0", "grader_inspector", False), ("grader-1", "grader_inspector", True)]
    # Only the attack runs, so the start event names only it; the report still lists the reused analyses.
    assert analyses.analyses == ("attack",)
    assert snapshot(earlier) == before
    assert built["analyses"] == {"hack": "complete", "simulation": "complete", "grader": "complete", "attack": "complete"}
    earlier_report = json.loads((earlier / "report.json").read_text())
    for section in ("ordinary", "labels", "metrics", "inspections"):
        assert built[section] == earlier_report[section]
    assert built["ordinary"]["attempted"] == 2
    assert SOURCE in built["answer"]


def test_attack_from_a_run_whose_grader_inspection_left_no_record_is_partial(tmp_path, monkeypatch):
    """A grader inspection that raised before its first save left no record. The rerun does not run it again, reads
    partial, and its Answer's source line names the analysis without a record."""
    earlier = earlier_run(tmp_path, monkeypatch, "full", rewards=[1.0, 0.0], fail={"grader": RuntimeError("grader broke")})
    assert not (earlier / "inspection-grader.json").exists()
    analyses = Analyses(monkeypatch)
    built = send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=earlier)

    assert [call[0] for call in analyses.calls] == ["start_run", "attack"]
    assert built["analyses"] == {"hack": "complete", "simulation": "complete", "grader": "not run", "attack": "complete"}
    assert built["status"] == "partial"
    assert (built["answer"][0], built["answer"][-1]) == (
        "Finished with gaps: the grader inspector did not run. Results below are what was found.",
        SOURCE.replace("that run recorded.", "that run recorded; grader left no record there."))


def test_attack_from_a_run_stopped_in_its_hack_inspection_keeps_that_status(tmp_path, monkeypatch):
    """A stopped inspection keeps the findings it recorded, so the attack runs on them and the report keeps its status."""
    analyses = Analyses(monkeypatch)

    async def stopped(run, *, focused_attempts, **_):
        result = analyses.inspection(run, "hack", [
            candidate(MECHANISM, INTERPRETATION, "accepted_invalid", full_guidance=REPRODUCTION, hint_location=LOCATION)])
        box = run.config.output_dir / "sandboxes" / "sandbox-0000"
        box.mkdir(parents=True)
        (box / "sandbox.json").write_text(sandbox_record(run.config.task_dir))
        run.record.sandboxes.append(box.name)
        run.save()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            result.status = "cancelled"
            (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
            raise

    monkeypatch.setattr(send, "inspect_hacks", stopped)
    earlier = tmp_path / "run-1"
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(earlier), "--analysis", "hacking", "--time-limit", "0.01"]) == 1
    assert json.loads((earlier / "report.json").read_text())["analyses"] == {"hack": "cancelled", "attack": "not run"}

    analyses = Analyses(monkeypatch)
    built = send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=earlier)
    assert analyses.calls == [("start_run", ["attacker", "inspector"]), ("attack", 1, 1, 1)]
    assert built["analyses"] == {"hack": "cancelled", "attack": "complete"} and built["status"] == "partial"
    assert "hack cancelled: its coverage is incomplete" in built["warnings"]
    assert (built["answer"][0], built["answer"][-1]) == (
        "Finished with gaps: the hack inspector cancelled. Results below are what was found.", SOURCE)


@pytest.mark.parametrize("case, refusal", [
    ("no hack record", "has no usable hack inspection record"),
    ("broken hack record", "has no usable hack inspection record"),
    ("another task", "is a run of the task"),
    ("output not empty", "is not empty"),
    ("output inside the earlier run", "is inside the earlier run"),
    ("absolute link", "contains links, which nudi does not copy: episodes/0000-inspector/linked"),
    ("relative link", "contains links, which nudi does not copy: episodes/0000-inspector/linked"),
    ("linked episodes folder", "contains links, which nudi does not copy: episodes"),
    ("linked hack record", "contains links, which nudi does not copy: inspection-hack.json"),
    ("changed task", "changed since the earlier run"),
    ("no sandbox record", "has no usable sandbox record"),
    ("no sandbox listed", "has no sandbox record"),
    ("one of two sandbox records missing", "has no usable sandbox record"),
    ("one of two sandbox folders missing", "has no usable sandbox record"),
])
def test_attack_from_refuses_before_any_model_call_or_sandbox(tmp_path, monkeypatch, capsys, case, refusal):
    """A copied link would still point into the earlier run or outside both runs, so a source with links is refused,
    also when one of its folders or a copied file is the link. The earlier inspection describes the task its sandboxes
    recorded, so a task changed since, a run with no sandbox record to tell, or a listed sandbox without its record is
    refused too."""
    earlier = earlier_run(tmp_path, monkeypatch, "simulation" if case == "no hack record" else "hacking")
    if case == "broken hack record":
        (earlier / "inspection-hack.json").write_text("{")
    task, rerun = tmp_path / ("other" if case == "another task" else "task"), tmp_path / "run-2"
    if case == "output not empty":
        rerun.mkdir()
        (rerun / "notes.txt").write_text("kept")
    elif case == "output inside the earlier run":
        rerun = earlier / "rerun"
    elif case in ("absolute link", "relative link"):
        episode = earlier / "episodes" / "0000-inspector"
        (episode / "linked").symlink_to(episode / "trace.txt" if case == "absolute link" else "trace.txt")
    elif case in ("linked episodes folder", "linked hack record"):
        name = "episodes" if case == "linked episodes folder" else "inspection-hack.json"
        (earlier / name).rename(tmp_path / name)
        (earlier / name).symlink_to(tmp_path / name)
    elif case == "changed task":
        (task / "grader.py").write_text("expected = 2\n")
    elif case == "no sandbox record":
        (earlier / "sandboxes" / "sandbox-0000" / "sandbox.json").unlink()
    elif case in ("no sandbox listed", "one of two sandbox records missing", "one of two sandbox folders missing"):
        # The listed sandbox-0000 keeps its record of this unchanged task.
        record = json.loads((earlier / "run.json").read_text())
        record["sandboxes"] = [] if case == "no sandbox listed" else [*record["sandboxes"], "sandbox-0001"]
        (earlier / "run.json").write_text(json.dumps(record))
        if case == "one of two sandbox records missing":
            (earlier / "sandboxes" / "sandbox-0001").mkdir()
    before = snapshot(earlier)
    analyses = Analyses(monkeypatch)

    with pytest.raises(ValueError, match=refusal):
        send_nudis(task, output_dir=rerun, attack_from=earlier)
    assert cli.main(["send-nudis", str(task), "--output", str(rerun), "--attack-from", str(earlier)]) == 2
    assert refusal in capsys.readouterr().err
    assert analyses.calls == []
    assert snapshot(earlier) == before
    assert not rerun.exists() or case == "output not empty"


@pytest.mark.parametrize("name", ["../../outside/payload", "absolute", "tunnel/payload", ".", "..", "", "twice"])
@pytest.mark.parametrize("field", ["episodes", "sandboxes"])
def test_attack_from_refuses_earlier_names_that_are_not_single_folder_names_or_listed_twice(tmp_path, monkeypatch, capsys, field, name):
    """Each episode and sandbox name of the earlier record is joined to both run folders, so a name with a parent part, an
    absolute name, a name through a linked middle part, `.`, `..` or an empty name could copy from or write outside them.
    A name listed twice would be copied twice, which fails after the run started."""
    earlier = earlier_run(tmp_path, monkeypatch, "hacking")
    outside = tmp_path / "outside" / "payload"
    outside.mkdir(parents=True)
    (outside / "marker.txt").write_text("outside both runs")
    record = json.loads((earlier / "run.json").read_text())
    if name == "absolute":
        name = str(outside)
    elif name == "tunnel/payload":
        (earlier / field / "tunnel").symlink_to(tmp_path / "outside")
    elif name == "twice":
        name = record[field][0]
    record[field].append(name)
    (earlier / "run.json").write_text(json.dumps(record))
    before = snapshot(earlier)
    analyses = Analyses(monkeypatch)
    rerun = tmp_path / "new-root" / "rerun"

    with pytest.raises(ValueError, match="names that are not single folder names"):
        send_nudis(tmp_path / "task", output_dir=rerun, attack_from=earlier)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(rerun), "--attack-from", str(earlier)]) == 2
    assert f"which nudi does not copy: {name!r}" in capsys.readouterr().err
    assert analyses.calls == []
    assert snapshot(earlier) == before
    assert not (tmp_path / "new-root").exists()


@pytest.mark.parametrize("given", [".", "latest"])
def test_attack_from_the_current_directory_or_a_link_keeps_the_earlier_run_name(tmp_path, monkeypatch, given):
    """`.` and a link naming the earlier run, such as `runs/latest`, are read as the folder they name."""
    earlier = earlier_run(tmp_path, monkeypatch, "hacking")
    (tmp_path / "latest").symlink_to(earlier)
    before = snapshot(earlier)
    Analyses(monkeypatch)
    monkeypatch.chdir(earlier if given == "." else tmp_path)
    built = send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=given)
    assert json.loads((tmp_path / "run-2" / "run.json").read_text())["attack_from"] == str(earlier.resolve())
    assert built["configuration"]["attack_from"] == "run-1" and SOURCE in built["answer"]
    assert snapshot(tmp_path / "run-2" / "episodes") == snapshot(earlier / "episodes") and snapshot(earlier) == before


def rerun_with(monkeypatch, backend, before_attack):
    """The `Analyses` fake on `backend`, whose attack first awaits `before_attack(run)`, as the real attack admits
    sandboxes and deletes earlier attempts' copies before each attempt."""
    analyses = Analyses(monkeypatch)
    start, attack_fake = analyses.start_run, analyses.attack

    def start_on(config, roles, analyses=()):
        run = start(config, roles, analyses)
        run.record.backend = backend
        return run

    async def attacking(run, **options):
        await before_attack(run)
        return await attack_fake(run, **options)

    monkeypatch.setattr(send, "start_run", start_on)
    monkeypatch.setattr(send, "attack", attacking)


def stored_copy(id, episode, backend, tag, image) -> dict:
    """A finished state copy, not deleted, as `run.json` stores it."""
    receipt = {"episode": episode, "path": f"nudi-evidence/{id}.json", "sha256": "a" * 64}
    return StateCopy(id=id, episode=episode, point="verification_start", environment="agent", backend=backend, ids={}, tag=tag,
                     image=image, receipt=receipt, started_at="2026-01-01T00:00:00+00:00",
                     finished_at="2026-01-01T00:00:01+00:00").model_dump(mode="json")


@pytest.mark.parametrize("backend", ["docker", "modal"])
def test_attack_from_never_deletes_or_marks_the_earlier_runs_state_copies(tmp_path, monkeypatch, backend):
    """The earlier run's copies stay as its evidence, and that run may still use them: neither the attack's mid-run
    deletion nor run-end cleanup touches them or their deletion flag. This run's own copy is deleted as usual."""
    earlier = earlier_run(tmp_path, monkeypatch, "hacking")
    record = json.loads((earlier / "run.json").read_text())
    record["copies"] = [stored_copy("copy-0000", "0000-inspector", backend, "nudi-copy-earlier-0000", "im-earlier")]
    (earlier / "run.json").write_text(json.dumps(record))
    removed = []

    async def host(command, **kwargs):
        if command[:3] == ["docker", "image", "rm"]:
            removed.extend(command[3:])
        return 0, "", ""

    async def delete(image):
        removed.append(image)

    async def take_and_discard(run):
        tag = f"nudi-copy-{run.record.run_id}-0001"
        run.record.copies.append(StateCopy.model_validate(stored_copy("copy-0001", "0001-attacker", backend, tag, "im-new")))
        await copies.discard(run)

    monkeypatch.setattr(checks, "host_command", host)
    if backend == "modal":
        monkeypatch.setattr(pytest.importorskip("modal.experimental").image_delete, "aio", delete)
    rerun_with(monkeypatch, backend, take_and_discard)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=earlier)

    new = RunRecord.model_validate_json((tmp_path / "run-2" / "run.json").read_text())
    assert [copy.deleted for copy in new.copies] == [None, True]
    assert removed == [new.copies[1].tag if backend == "docker" else "im-new"]


@pytest.mark.parametrize("cleanup", [{"removed": False}, {"removed": None}, {}])
def test_attack_from_admits_containers_past_the_earlier_runs_sandbox_cleanup(tmp_path, monkeypatch, cleanup):
    """Admission counts only sandboxes this run opened. An earlier sandbox whose removal failed, is unverified or was never
    recorded neither stops a new container nor uses this run's capacity, and its cleanup facts stay as recorded."""
    earlier = earlier_run(tmp_path, monkeypatch, "hacking")
    # Counted as held, a sandbox with Docker's whole capacity would leave no room for another container.
    box = sandbox_record(tmp_path / "task", environment={"cpus": 8, "memory_mb": 16384}, cleanup=cleanup)
    (earlier / "sandboxes" / "sandbox-0000" / "sandbox.json").write_text(box)

    async def admit(run):
        run.admit_container("check")

    rerun_with(monkeypatch, "docker", admit)
    built = send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=earlier)
    assert built["analyses"]["attack"] == "complete", built["warnings"]
    copied = tmp_path / "run-2" / "sandboxes" / "sandbox-0000" / "sandbox.json"
    assert copied.read_bytes() == (earlier / "sandboxes" / "sandbox-0000" / "sandbox.json").read_bytes()


def hack_findings(*readings) -> InspectionResult:
    """A hack inspection whose reading N, of check N in its category, has an outcome, a category and full guidance or none."""
    result = InspectionResult(mode="hack", status="complete", categories={}, applicability={})
    for index, (outcome, category, full) in enumerate(readings):
        result.experiments.append({"id": f"experiment-{index}", "category": category, "status": "assessed", "assessment": index,
                                   "check": f"check-{index}"})
        result.assessments.append(Assessment(claim=Claim(mechanism=f"way {index}", episode="0000-inspector", check=f"check-{index}",
                                                         full_guidance=full, hint_location=LOCATION), outcome=outcome))
    return result


async def evidence_each(report, judge, on_evidence, readings):
    """As the hack inspector does for each of `readings`: its probe is judged, then its evidenced reading evidences the problem."""
    for index in readings:
        problem = await judge(f"experiment-{index:04d}", {"mechanism": report.assessments[index].claim.mechanism})
        problem.findings.append(f"hack-{index}")
        problem.evidence = "evidenced"
        on_evidence(report, index)


def real_early_attack(monkeypatch, analyses, judge):
    """The real attack beside the hack inspector, with each Attacker episode rewarded and its attack inspector session
    `judge(target, episode)`, with target `none` for a no-hint attempt; the attack phase keeps the `Analyses` fake."""
    from test_attack import judged

    async def native(run, role, instruction, reminder=None):
        name = f"{len(run.record.episodes):04d}-attacker"
        run.record.episodes.append(name)
        (run.config.output_dir / "episodes" / name / "nudi-evidence").mkdir(parents=True)
        (run.config.output_dir / "episodes" / name / "nudi-evidence" / "extension.md").write_text(instruction)
        return SimpleNamespace(rewards={"reward": 1.0}, errors=[], agent_timeout=False, verifier_timeout=False, cancelled=False,
                               artifacts={})

    async def inspect(run, mode, pool, *args, request, **kwargs):
        outcome = await judge((request["target_candidate"] or {"id": "none"})["id"], pool[0])
        return judged(pool[0], outcome)

    async def attacking(run, **options):
        return await (attack.attack if options.get("feed") else analyses.attack)(run, **options)

    monkeypatch.setattr(run_state, "run_role_episode", native)
    monkeypatch.setattr(attack, "inspect", inspect)
    monkeypatch.setattr(send, "attack", attacking)


def test_a_time_limit_during_the_hack_inspection_keeps_the_early_reproduction(tmp_path, monkeypatch):
    """hack-0's full and single hint attempts reproduced and hack-1's was still judged when the time limit stopped the
    hack inspection. The attack record is cancelled and keeps the reproductions."""
    from test_runner import CONTRACT_TASK

    analyses = Analyses(monkeypatch)

    async def judge(target, episode):
        if target == "hack-1":
            await asyncio.sleep(30)
        return "accepted_invalid"

    real_early_attack(monkeypatch, analyses, judge)

    async def inspect_hacks(run, *, focused_attempts, on_evidence, gate, judge):
        report = hack_findings(("accepted_invalid", "grader_tampering", REPRODUCTION), ("accepted_invalid", "package_oracles", REPRODUCTION))
        (run.config.output_dir / "inspection-hack.json").write_text(report.model_dump_json())
        await evidence_each(report, judge, on_evidence, range(2))
        await asyncio.sleep(30)

    monkeypatch.setattr(send, "inspect_hacks", inspect_hacks)
    built = send_nudis(CONTRACT_TASK, output_dir=tmp_path / "run", analysis="hacking", time_limit=0.01, discovery_attempts=0)
    saved = json.loads((tmp_path / "run" / "attack.json").read_text())
    assert saved["status"] == "cancelled"
    assert [(item["candidate"], item["level"], item["status"]) for item in saved["attempts"]] == [
        ("hack-0", "full", "evidenced_issue"), ("hack-1", "full", "cancelled"), ("hack-0", "minimal", "evidenced_issue")]
    assert built["status"] == "time_limit" and built["analyses"]["attack"] == "cancelled"
    assert [item["candidate"] for item in built["attack"]["exploits"]["reproduction"]] == ["hack-0", "hack-0"]


def test_a_time_limit_after_the_hack_inspection_returned_cancels_the_early_attempt_it_waits_for(tmp_path, monkeypatch):
    """The hack inspector has finished, and the hack phase waits for hack-1's early attempt, still judged. The time limit
    cancels that attempt at once instead of waiting for its judgment."""
    from test_runner import CONTRACT_TASK

    analyses = Analyses(monkeypatch)

    async def judge(target, episode):
        if target == "hack-1":
            await asyncio.sleep(30)
        return "accepted_invalid"

    real_early_attack(monkeypatch, analyses, judge)

    async def inspect_hacks(run, *, focused_attempts, on_evidence, gate, judge):
        report = hack_findings(("accepted_invalid", "grader_tampering", REPRODUCTION), ("accepted_invalid", "package_oracles", REPRODUCTION))
        (run.config.output_dir / "inspection-hack.json").write_text(report.model_dump_json())
        await evidence_each(report, judge, on_evidence, range(2))
        return report

    monkeypatch.setattr(send, "inspect_hacks", inspect_hacks)
    started = time.monotonic()
    built = send_nudis(CONTRACT_TASK, output_dir=tmp_path / "run", analysis="hacking", time_limit=0.05, discovery_attempts=0)
    assert time.monotonic() - started < 10
    saved = json.loads((tmp_path / "run" / "attack.json").read_text())
    assert saved["status"] == "cancelled"
    assert [(item["candidate"], item["level"], item["status"]) for item in saved["attempts"]] == [
        ("hack-0", "full", "evidenced_issue"), ("hack-1", "full", "cancelled"), ("hack-0", "minimal", "evidenced_issue")]
    assert built["status"] == "time_limit" and built["analyses"]["hack"] == "complete"


def test_a_raising_early_attack_is_one_warning_and_the_hack_phase_keeps_its_status(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch)

    async def attacking(run, **options):
        if options.get("feed"):
            raise RuntimeError("attack broke")
        return await analyses.attack(run, **options)

    monkeypatch.setattr(send, "attack", attacking)
    built = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")
    assert built["warnings"].count("run: the attack during the hack inspection stopped: RuntimeError: attack broke") == 1
    assert built["analyses"]["hack"] == "complete"
    # The attack failed, so not every step ran.
    assert built["status"] == "partial" and "attack" in built["unfinished"]


def test_hack_sessions_and_early_attempts_share_the_slots_of_the_run(tmp_path, monkeypatch):
    """At concurrency 2 one holder runs at a time, so a hack inspector session, the no-hint attempt and the problem's
    attempts never hold containers beside each other."""
    analyses = Analyses(monkeypatch)
    start, holders, peak = analyses.start_run, set(), [0]

    def on_two(config, roles, analyses=()):
        run = start(config, roles, analyses)
        run.record.capacity.concurrency = 2
        return run

    async def hold(name):
        holders.add(name)
        peak[0] = max(peak[0], len(holders))
        await asyncio.sleep(0.02)
        holders.discard(name)

    async def judge(target, episode):
        await hold(target)
        return "accepted_invalid"

    real_early_attack(monkeypatch, analyses, judge)

    async def inspect_hacks(run, *, focused_attempts, on_evidence, gate, judge):
        report = hack_findings(("accepted_invalid", "grader_tampering", REPRODUCTION))
        (run.config.output_dir / "inspection-hack.json").write_text(report.model_dump_json())
        async with gate:
            await evidence_each(report, judge, on_evidence, [0])
            await hold("broad")
        for name in ("focused-1", "focused-2"):
            async with gate:
                await hold(name)
        return report

    monkeypatch.setattr(send, "start_run", on_two)
    monkeypatch.setattr(send, "inspect_hacks", inspect_hacks)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")
    assert peak[0] == 1
    saved = AttackResult.model_validate_json((tmp_path / "run" / "attack.json").read_text())
    assert [(item.candidate, item.level, item.status) for item in saved.attempts] == [
        (None, "none", "evidenced_issue"), ("hack-0", "full", "evidenced_issue"), ("hack-0", "minimal", "evidenced_issue")]


def test_an_attack_only_rerun_continues_no_earlier_attack(tmp_path, monkeypatch):
    """The earlier run's `attack.json` is not copied, so the rerun's attack starts fresh from the full level."""
    earlier = earlier_run(tmp_path, monkeypatch, "hacking")
    assert (earlier / "attack.json").is_file()
    analyses = Analyses(monkeypatch)
    send_nudis(tmp_path / "task", output_dir=tmp_path / "run-2", attack_from=earlier)
    assert analyses.calls[-1][0] == "attack" and analyses.earlier is None


def test_library_warnings_go_to_a_log_in_the_run_folder_and_nudi_warnings_stay_on_stderr(tmp_path, monkeypatch, capsys):
    """Libraries' own warnings, such as asyncio's about a closed TLS connection, would fill stderr; they go to
    RUN/library.log, which holds none of nudi's lines, and LiteLLM's sessions close on the run's loop."""
    analyses = Analyses(monkeypatch)
    closed = []

    async def close():
        closed.append(asyncio.get_running_loop())

    monkeypatch.setattr(litellm, "close_litellm_async_clients", close)

    async def noisy(run, ordinary_pool, **options):
        logging.getLogger("asyncio").warning("SSL connection is closed")
        run.warn("the grader inspector saw a test warning")
        return await Analyses.inspect_grader(analyses, run, ordinary_pool, **options)

    monkeypatch.setattr(send, "inspect_grader", noisy)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 0
    error = capsys.readouterr().err
    assert "SSL connection is closed" not in error and "the grader inspector saw a test warning" in error
    library = (tmp_path / "run" / "library.log").read_text()
    assert "SSL connection is closed" in library and "test warning" not in library
    assert len(closed) == 1 and not any(getattr(item, "baseFilename", "").endswith("library.log") for item in logging.getLogger().handlers)


@pytest.mark.parametrize("new", [0, 1])
def test_the_attack_line_counts_only_its_new_attempts_apart_from_the_hack_phase(tmp_path, monkeypatch, capsys, new):
    """The attack phase continues the attack of the hack phase, so its record holds those attempts and their status.
    Its line on stderr says what it added; its event keeps the status and all the attempts."""
    from nudi.attack import AttackAttempt

    monkeypatch.setattr(send, "elapsed", lambda started: "0:00:00")
    Analyses(monkeypatch)
    unclear = AttackAttempt(level="none", number=1, context="attacker-none-1", status="unknown")

    async def attacking(run, *, feed=None, earlier=None, **options):
        if feed is not None:
            while await feed.get() is not None:
                pass
            (run.config.output_dir / "attack.json").write_text(AttackResult(status="partial", attempts=[unclear]).model_dump_json())
            return
        added = [AttackAttempt(level="full", number=1, context="attacker-hack-0-full-1", status="no_evidenced_issue")] * new
        return AttackResult(status="partial", attempts=[*earlier.attempts, *added])

    monkeypatch.setattr(send, "attack", attacking)
    cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")])
    line = logged(capsys.readouterr().err)[-1]
    assert line == ("nudi: attack done after 0:00:00: 1 new attempt, 2 in all, 0 exploits; some results unclear" if new else
                    "nudi: attack done after 0:00:00: nothing new to attack; the 1 attempt during the hack inspection left some results unclear")
    end = [item for item in events(tmp_path / "run") if item["kind"] == "phase_end" and item["phase"] == "attack"][0]
    assert (end["status"], end["attempts"], end["new_attempts"]) == ("partial", 1 + new, new)


def test_the_attack_line_counts_exploits_apart_from_cases_where_correct_work_failed():
    from types import SimpleNamespace as Item

    readings = [Item(outcome="accepted_invalid"), Item(outcome="rejected_valid"), Item(outcome="rejected_valid")]
    result = Item(attempts=[Item()] * 3, findings=[Item(assessment=index) for index in range(3)], assessments=readings)
    counts = send.PHASES["attack"][2](result)
    assert counts == {"attempts": 3, "findings": 3, "exploits": 1, "correct_work_failed": 2}
    assert send.found(counts) == "1 exploit, 2 cases where correct work failed"
    assert send.found({**counts, "exploits": 0, "correct_work_failed": 1}) == "0 exploits, 1 case where correct work failed"


def test_a_litellm_close_that_never_ends_does_not_hold_the_exit(monkeypatch):
    """The final close waits for no task left running, also LiteLLM's own close."""
    monkeypatch.setattr(send, "STOP_WAIT", 0.1)

    async def never():
        while True:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass

    async def main():
        return 1

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(close_litellm_async_clients=never))
    started = time.monotonic()
    assert send.run_bounded(main()) == 1
    assert time.monotonic() - started < 2


def test_a_count_of_one_on_a_step_line_is_singular():
    assert send.phase_words("attack", {"attempts": 1, "findings": 0, "exploits": 0, "correct_work_failed": 0}) == "1 attempt, 0 exploits"
    assert send.phase_words("hack", {"experiments": 1, "assessments": 2, "attacker_attempts": 1}) == "1 experiment, 1 Attacker attempt"
    assert send.phase_words("grader", {"experiments": 2, "assessments": 1}) == "2 experiments, 1 assessment"
