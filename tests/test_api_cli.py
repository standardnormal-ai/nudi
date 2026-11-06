"""send_nudis, send_nudis_async and `nudi send-nudis`: one implementation over the existing analyses.

The existing analyses and run start are replaced by recorders that retain records the way
they do, so selection, configuration, guidance and partial results are checked without Docker
or model calls. The analyses themselves have their own suites.
"""

import asyncio
import inspect
import json
import re
import signal
import subprocess
from collections import Counter
from pathlib import Path

import litellm
import pytest
from pydantic import ValidationError

from nudi import api, checks, cli, report, send_nudis, send_nudis_async
from nudi.checks import AttackResult, EpisodeLabel, InspectionResult
from nudi.records import DEFAULT_MODELS, Assessment, Capacity, Claim, DiskFull, EpisodeResult, RunRecord, Simulation
from nudi.runner import tree_digest
from nudi.workflow import Run
from test_metrics import RULE, TASK, basis, checked

SECRET = "sk-live-api-0123456789"
# Each progress line begins with the clock time.
CLOCK = re.compile(r"^nudi: \d\d:\d\d:\d\d ")
ALL_ROLES = ["attacker", "inspector", "simulator"]


class Analyses:
    """Stands in for start_run and the four existing analyses, recording each call."""

    def __init__(self, monkeypatch, *, candidates=(), fail=None, rewards=(), assessments=(), ordinary=None):
        self.calls, self.candidates, self.fail, self.rewards = [], list(candidates), fail or {}, list(rewards)
        self.assessments, self.ordinary = list(assessments), ordinary or {}
        for name in ("start_run", "simulate", "inspect_grader", "inspect_hacks", "attack"):
            monkeypatch.setattr(api, name, getattr(self, name))

    def raise_if(self, name):
        if name in self.fail:
            raise self.fail[name]

    def start_run(self, config, roles):
        self.calls.append(("start_run", sorted(roles)))
        self.config = config
        config.output_dir.mkdir(parents=True, exist_ok=True)
        record = RunRecord(task_dir=str(config.task_dir), path="harbor", path_reasons=["original grading and harness"],
                           models={**DEFAULT_MODELS, **config.models}, credential_sources={role: "credentials file" for role in roles},
                           spending_cap=config.spending_cap, cost_map={"source": "local"},
                           capacity=Capacity(docker_cpus=8, docker_memory_mb=16384, episode_cpus=1, episode_memory_mb=2048, concurrency=4))
        run = Run(config, record, None, {role: SECRET for role in roles})
        run.save()
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

    async def inspect_grader(self, run, ordinary_pool, *, focused_attempts, isolated_inspections):
        self.calls.append(("inspect_grader", ordinary_pool, focused_attempts, isolated_inspections))
        self.raise_if("grader")
        return self.inspection(run, "grader", self.assessments, self.ordinary)

    async def inspect_hacks(self, run, *, focused_attempts):
        self.calls.append(("inspect_hacks", focused_attempts))
        self.raise_if("hack")
        return self.inspection(run, "hack", self.candidates)

    async def attack(self, run, *, maximum_attempts, discovery_attempts, candidates):
        self.calls.append(("attack", maximum_attempts, discovery_attempts, len(candidates)))
        self.candidates_sent = candidates
        self.raise_if("attack")
        tested = [item.model_copy(update={"conditions": {level: "unavailable" if item.guidance.get(level) is None else "no_evidenced_issue"
                                                         for level in ("full", "minimal")}}) for item in candidates]
        result = AttackResult(status="complete", maximum_attempts=maximum_attempts, discovery_attempts=discovery_attempts,
                              candidates=tested, discovery={"none": "no_evidenced_issue"},
                              unavailable={} if candidates else {"full": NO_CANDIDATE, "minimal": NO_CANDIDATE})
        (run.config.output_dir / "attack.json").write_text(result.model_dump_json())
        return result


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


def test_default_is_full_analysis_with_default_counts(tmp_path, monkeypatch, capsys):
    """Two focused attempts per category by default, one try and one retry."""
    assert api.AnalysisConfig.model_fields["focused_attempts"].default == 2
    assert {inspect.signature(function).parameters["focused_attempts"].default
            for function in (checks.inspect_grader, checks.inspect_hacks)} == {2}
    with pytest.raises(SystemExit):
        cli.main(["send-nudis", "--help"])
    help = " ".join(capsys.readouterr().out.split())
    assert "total focused attempts per grader inspector or hack inspector category, default 2" in help
    assert "runs one grader inspector per ordinary episode (inspector_swarm)" in help
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run")

    # The hack chain runs first: its result needs no Simulator or grader inspector result.
    assert analyses.calls == [("start_run", ALL_ROLES), ("inspect_hacks", 2), ("attack", 2, 1, 0), ("simulate", 20),
                              ("inspect_grader", [], 2, False)]
    assert report["analyses"] == {"simulation": "complete", "grader": "complete", "hack": "complete", "attack": "complete"}
    assert report["status"] == "complete"
    assert sorted(report["inspections"]) == ["grader_inspector", "hack_inspector"]
    assert report == json.loads((tmp_path / "run" / "report.json").read_text())
    assert (tmp_path / "run" / "report.md").read_text().startswith("# nudi report")


@pytest.mark.parametrize("analysis, roles, called, selected", [
    ("simulation", ["inspector", "simulator"], ["simulate", "inspect_grader"], ["simulation", "grader"]),
    ("hacking", ["attacker", "inspector"], ["inspect_hacks", "attack"], ["hack", "attack"]),
])
def test_selection_runs_and_completes_only_selected_analyses(tmp_path, monkeypatch, analysis, roles, called, selected):
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis=analysis)

    assert analyses.calls[0] == ("start_run", roles)
    assert [call[0] for call in analyses.calls[1:]] == called
    # Deliberately leaving an analysis out is not incomplete coverage.
    assert sorted(report["analyses"]) == sorted(selected) and report["status"] == "complete"


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
    assert calls[0] == calls[1] == calls[2] == [("start_run", ALL_ROLES), ("inspect_hacks", 1), ("attack", 4, 3, 0),
                                                ("simulate", 7), ("inspect_grader", [], 1, False)]
    assert configs[0]["discovery_attempts"] == 3
    analyses = Analyses(monkeypatch)
    send_nudis(task, config, output_dir=tmp_path / "file")
    assert analyses.calls[2] == ("attack", 4, 2, 0)
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
        assert ("false discovery rate at least 0 (0/2, lower bound); false negative rate at least 0 (0/2, lower bound); "
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

    def start_run(config, roles):
        raise subprocess.CalledProcessError(1, ["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"], output="", stderr=message + "\n")

    monkeypatch.setattr(api, "start_run", start_run)
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

    assert analyses.calls[-1] == ("attack", 2, 1, 3)
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
    assert analyses.calls[-1] == ("attack", 2, 1, len(candidates))
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

    assert analyses.calls[-1] == ("attack", 2, 1, 1)
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
    first, second, suspected = api.guidance(hack)["candidates"]
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
    found = api.guidance(hack)["candidates"]
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
    candidates = {item.id: item for item in api.guidance(hack)["candidates"]}
    assert list(candidates) == ["hack-2", "hack-3", "hack-4", "hack-7"]
    assert candidates["hack-4"].guidance == {"full": REPRODUCTION, "minimal": f"{WHERE_TO_LOOK}\n{LOCATION}"}
    assert candidates["hack-7"].guidance == {"full": None, "minimal": None}


def test_no_candidate_leaves_guidance_unavailable_and_still_attacks(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    assert analyses.calls[-1] == ("attack", 2, 1, 0)
    assert report["attack"]["candidates"] == []
    assert report["attack"]["unavailable"] == {"full": NO_CANDIDATE, "minimal": NO_CANDIDATE}
    assert "candidate exists" not in report["attack"]["unavailable"]["full"]
    assert report["attack"]["discovery"]["status"] == "no_evidenced_issue"


def test_inspector_prompt_requests_reproduction_steps_and_a_location_only():
    from nudi import checks
    prompt = " ".join(checks.inspector_prompt("hack").split())
    assert "`full_guidance`" in prompt and "concrete steps that reproduce it" in prompt
    assert "`hint_location`" in prompt and "file, interface, or component" in prompt
    assert "must not contain a solution or a reproduction recipe" in prompt
    assert "A finding without either field gives the Attacker nothing to run." in prompt


def test_failed_analysis_keeps_independent_results_and_redacts_credentials(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch, fail={"hack": RuntimeError(f"provider echoed {SECRET}")})
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run")

    # The attack still runs, without candidates, after the hack inspection failed.
    assert analyses.calls[2] == ("attack", 2, 1, 0)
    assert report["analyses"] == {"simulation": "complete", "grader": "complete", "hack": "not run", "attack": "complete"}
    assert report["status"] == "partial"
    assert "run: hack failed: RuntimeError: provider echoed [redacted]" in report["warnings"]
    for name in ("run.json", "report.json", "report.md"):
        assert SECRET not in (tmp_path / "run" / name).read_text()


def test_cancellation_writes_the_partial_report_and_propagates(tmp_path, monkeypatch):
    """A run stopped during the ordinary-episode path keeps the hack chain's results."""
    analyses = Analyses(monkeypatch, fail={"simulation": asyncio.CancelledError()})
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(send_nudis_async(tmp_path / "task", output_dir=tmp_path / "run"))

    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "attack", "simulate"]
    report = json.loads((tmp_path / "run" / "report.json").read_text())
    assert report["analyses"] == {"simulation": "not run", "grader": "not run", "hack": "complete", "attack": "complete"}
    assert report["status"] == "partial"
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
    monkeypatch.setattr(api, "elapsed", lambda started: "0:00:00")
    Analyses(monkeypatch, rewards=[1.0, 0.0])
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--episodes", "2"]) == 0
    error = capsys.readouterr().err
    assert all(CLOCK.match(line) for line in error.splitlines())
    assert logged(error) == [
        "nudi: hack inspector started",
        "nudi: hack inspector finished after 0:00:00: 0 experiments, 0 assessments; status complete",
        "nudi: attack started",
        "nudi: attack finished after 0:00:00: 0 Attacker attempts, 0 findings; status complete",
        "nudi: Simulator started",
        "nudi: Simulator finished after 0:00:00: 2 of 2 episodes; status complete",
        "nudi: grader inspector started",
        "nudi: grader inspector finished after 0:00:00: 0 experiments, 0 assessments; status complete",
    ]
    Analyses(monkeypatch, fail={"hack": RuntimeError(f"provider echoed {SECRET}")})
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "failed")]) == 1
    error = logged(capsys.readouterr().err)
    assert error[0:2] == ["nudi: hack inspector started",
                          "nudi: hack inspector ended after 0:00:00: hack failed: RuntimeError: provider echoed [redacted]"]
    assert error[-1].startswith("nudi: grader inspector finished after ")


def test_ctrl_c_prints_the_report_and_one_line_naming_it_and_exits_130(tmp_path, monkeypatch, capsys):
    """Most measured runs ended with a stop, so a stop must not leave stdout empty."""
    analyses = Analyses(monkeypatch)

    async def interrupted(run, ordinary_pool, **options):
        signal.raise_signal(signal.SIGINT)
        await asyncio.sleep(30)

    monkeypatch.setattr(api, "inspect_grader", interrupted)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 130
    output, error = capsys.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text() and output.startswith("# nudi report\n\n## Answer\n")
    error = logged(error)
    assert error[error.index("nudi: grader inspector started") + 1:] == [
        f"nudi: cancelled; report written to {tmp_path / 'run' / 'report.md'}"]
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "attack", "simulate"]
    assert "run: cancelled during grader" in json.loads((tmp_path / "run" / "report.json").read_text())["warnings"]


def test_a_time_limit_ends_the_run_as_a_stop_does_but_exits_0(tmp_path, monkeypatch, capsys):
    """Some tasks take many hours, so the limit is one option with no default. At the limit
    the run cleans up and reports as a stop does; reaching the limit is a normal end."""
    assert api.AnalysisConfig.model_fields["time_limit"].default is None
    analyses = Analyses(monkeypatch)

    async def slow(run, ordinary_pool, **options):
        await asyncio.sleep(30)

    monkeypatch.setattr(api, "inspect_grader", slow)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 0
    output, error = capsys.readouterr()
    assert output == (tmp_path / "run" / "report.md").read_text()
    assert ("- The run reached its time limit, so it may miss more: hack complete, attack complete, simulation complete, "
            "grader not run.\n") in output
    assert logged(error)[-1] == "nudi: the run stopped at its time limit of 0.01 minutes during grader"
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks", "attack", "simulate"]
    report = json.loads((tmp_path / "run" / "report.json").read_text())
    assert report["status"] == "time_limit"
    assert "run: the run stopped at its time limit of 0.01 minutes during grader" in report["warnings"]


def sleeping(run, *args, **options):
    return asyncio.sleep(30)


@pytest.mark.parametrize("shape", ["raised", "returned"])
def test_a_failed_phase_before_the_time_limit_still_exits_1(tmp_path, monkeypatch, shape):
    """Reaching the limit is a normal end only when no phase failed before it, by an error or an
    incomplete result."""
    analyses = Analyses(monkeypatch, fail={"hack": RuntimeError("hack broke")} if shape == "raised" else {})
    if shape == "returned":
        async def incomplete(run, *, focused_attempts):
            result = analyses.inspection(run, "hack").model_copy(update={"status": "partial"})
            (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
            return result
        monkeypatch.setattr(api, "inspect_hacks", incomplete)
    monkeypatch.setattr(api, "attack", sleeping)
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

    monkeypatch.setattr(api, "inspect_grader", swallowing)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run"), "--time-limit", "0.01"]) == 0
    assert json.loads((tmp_path / "run" / "report.json").read_text())["status"] == "time_limit"


def test_ctrl_c_before_any_report_says_none_was_written(tmp_path, monkeypatch, capsys):
    def interrupted(*args, **options):
        raise KeyboardInterrupt

    monkeypatch.setattr(api, "send_nudis", interrupted)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 130
    assert tuple(capsys.readouterr()) == ("", "nudi: cancelled; no report was written\n")


def test_no_space_on_the_records_host_stops_the_run_with_one_message(tmp_path, monkeypatch, capsys):
    """The analyses after the full disk do not run; the report is still written once space allows it."""
    full = DiskFull(f"no space left on the records host to write {tmp_path / 'run' / 'inspection-hack.json'}")
    analyses = Analyses(monkeypatch, fail={"hack": full})
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    error = logged(capsys.readouterr().err)
    assert error == ["nudi: hack inspector started", f"nudi: stopped: {full}; report written to {tmp_path / 'run' / 'report.md'}"]
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks"]
    assert f"run: hack stopped: {full}" in json.loads((tmp_path / "run" / "report.json").read_text())["warnings"]


def test_a_task_environment_that_cannot_start_stops_the_run_with_its_reason(tmp_path, monkeypatch, capsys):
    """A verifier image that never builds must not keep the run going for hours. Once the hack inspector stops
    environment_unavailable, no later analysis runs; stderr, the report's analyses and its warnings say why."""
    from nudi.records import EnvironmentUnavailable

    analyses = Analyses(monkeypatch)
    reason = ("the task's verifier environment failed to start 3 times in a row, last with ModalFailure: Modal start failed: "
              "ImageBuildError; no later sandbox or episode can use it, so the run stops")

    async def inspect_hacks(run, *, focused_attempts):
        analyses.calls.append(("inspect_hacks", focused_attempts))
        result = InspectionResult(mode="hack", status="environment_unavailable", categories={}, applicability={})
        (run.config.output_dir / "inspection-hack.json").write_text(result.model_dump_json())
        raise EnvironmentUnavailable(reason)

    monkeypatch.setattr(api, "inspect_hacks", inspect_hacks)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    error = logged(capsys.readouterr().err)
    assert error == ["nudi: hack inspector started", f"nudi: hack inspector stopped after 0:00:00: {reason}"]
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks"]
    built = json.loads((tmp_path / "run" / "report.json").read_text())
    assert built["analyses"] == {"hack": "environment_unavailable", "attack": "not run", "simulation": "not run", "grader": "not run"}
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

    monkeypatch.setattr(api, "attack", attack)
    assert cli.main(["send-nudis", str(tmp_path / "task"), "--output", str(tmp_path / "run")]) == 1
    assert capsys.readouterr().err.splitlines()[-1] == f"nudi: stopped: {full}; report written to {tmp_path / 'run' / 'report.md'}"
    assert json.loads((tmp_path / "run" / "report.json").read_text())["analyses"]["attack"] == "not run"
    assert [call[0] for call in analyses.calls] == ["start_run", "inspect_hacks"]
