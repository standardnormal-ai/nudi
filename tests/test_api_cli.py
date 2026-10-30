"""send_nudis, send_nudis_async and `nudi send-nudis`: one implementation over the existing analyses.

The existing analyses and run start are replaced by recorders that retain records the way
they do, so selection, configuration, guidance and partial results are checked without Docker
or model calls. The analyses themselves have their own suites.
"""

import asyncio
import json
import subprocess
from pathlib import Path

import litellm
import pytest
from pydantic import ValidationError

from nudi import api, cli, send_nudis, send_nudis_async
from nudi.checks import AttackResult, InspectionResult
from nudi.records import DEFAULT_MODELS, Assessment, Capacity, Claim, RunRecord, Simulation
from nudi.workflow import Run

SECRET = "sk-live-api-0123456789"
ALL_ROLES = ["attacker", "inspector", "simulator"]


class Analyses:
    """Stands in for start_run and the four existing analyses, recording each call."""

    def __init__(self, monkeypatch, *, candidates=(), fail=None):
        self.calls, self.candidates, self.fail = [], list(candidates), fail or {}
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
        run.save()
        return run.record.simulation

    def inspection(self, run, mode, assessments=()):
        result = InspectionResult(mode=mode, status="complete", categories={}, applicability={}, assessments=list(assessments))
        (run.config.output_dir / f"inspection-{mode}.json").write_text(result.model_dump_json())
        return result

    async def inspect_grader(self, run, ordinary_pool, *, focused_attempts, isolated_inspections):
        self.calls.append(("inspect_grader", ordinary_pool, focused_attempts, isolated_inspections))
        self.raise_if("grader")
        return self.inspection(run, "grader")

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


def test_default_is_full_analysis_with_default_counts(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run")

    assert analyses.calls == [("start_run", ALL_ROLES), ("simulate", 20), ("inspect_grader", [], 3, False), ("inspect_hacks", 3),
                              ("attack", 2, 1, 0)]
    assert report["analyses"] == {"simulation": "complete", "grader": "complete", "hack": "complete", "attack": "complete"}
    assert report["status"] == "complete"
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
                      'workspace_memory_mb = 1024\n'
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
    assert calls[0] == calls[1] == calls[2] == [("start_run", ALL_ROLES), ("simulate", 7), ("inspect_grader", [], 1, False),
                                                ("inspect_hacks", 1), ("attack", 4, 3, 0)]
    assert configs[0]["discovery_attempts"] == 3
    analyses = Analyses(monkeypatch)
    send_nudis(task, config, output_dir=tmp_path / "file")
    assert analyses.calls[-1] == ("attack", 4, 2, 0)
    assert configs[0] == configs[1] == configs[2]
    # The keyword or flag replaces the file's value; the rest of the file stays.
    assert configs[0]["episodes"] == 7 and configs[0]["spending_cap"] == 2.5 and configs[0]["workspace_memory_mb"] == 1024
    analyses = Analyses(monkeypatch)
    assert cli.main(["send-nudis", str(task), "--config", str(config), "--output", str(tmp_path / "flag"),
                     "--workspace-memory-mb", "768"]) == 0
    assert analyses.config.workspace_memory_mb == 768
    assert configs[0]["credentials_file"] == config.parent / ".env"
    assert configs[0]["models"]["simulator"] == {"model": "openai/gpt-test", "reasoning_effort": "low", "api_base": None,
                                                 "api_key_var": "TEST_KEY"}
    # Public configuration names the credential; it never holds a resolved value.
    assert reports[0]["configuration"]["models"]["simulator"]["api_key_var"] == "TEST_KEY"


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
    assert found == {name: [("inspect_grader", [], 3, name.endswith("on")), ("inspect_hacks", 3)] for name in runs}
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
        candidate(MECHANISM, INTERPRETATION, full_guidance=REPRODUCTION, hint_location=LOCATION),
        candidate("leakage_metadata", "the reward matches the submitted work", outcome="legitimate",
                  full_guidance=leak, hint_location="secret/expected.txt"),
        candidate("reward file", "the verifier trusts the reward file", full_guidance=other, hint_location=place),
        # An identical repeat stays a distinct candidate: no semantic deduplication.
        candidate("reward file", "the verifier trusts the reward file", full_guidance=other, hint_location=place),
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
def test_known_false_negative_findings_never_supply_exploit_guidance(tmp_path, monkeypatch, only_false_negative):
    fn = candidate("correct work rejected", "undeserved rejection", outcome="rejected_valid",
                   full_guidance="FN reproduction must not reach attackers", hint_location="fn/private-grader.py")
    candidates = [fn]
    if not only_false_negative:
        candidates.append(candidate(MECHANISM, INTERPRETATION, full_guidance=REPRODUCTION, hint_location=LOCATION))
    analyses = Analyses(monkeypatch, candidates=candidates)
    result = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")
    if only_false_negative:
        assert analyses.calls[-1] == ("attack", 2, 1, 0)
        assert result["attack"]["unavailable"] == {"full": NO_CANDIDATE, "minimal": NO_CANDIDATE}
    else:
        (sent,) = analyses.candidates_sent
        assert sent.id == "hack-1" and sent.guidance["full"] == REPRODUCTION
    retained = result["inspections"]["hack"]["findings"]["evidenced"]
    assert retained[0]["assessment"]["outcome"] == "rejected_valid"


@pytest.mark.parametrize(("full_guidance", "hint_location"), [
    (None, LOCATION),
    ("  ", LOCATION),
    (REPRODUCTION, None),
    (REPRODUCTION, "   "),
    (None, None),
    ("", ""),
], ids=["full missing", "full blank", "location missing", "location blank", "both missing", "both blank"])
def test_missing_or_blank_guidance_field_leaves_that_condition_unavailable(tmp_path, monkeypatch, full_guidance, hint_location):
    analyses = Analyses(monkeypatch, candidates=[candidate(MECHANISM, INTERPRETATION, full_guidance=full_guidance, hint_location=hint_location)])
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    assert analyses.calls[-1] == ("attack", 2, 1, 1)
    (sent,) = analyses.candidates_sent
    assert sent.id == "hack-0"
    rendered = json.dumps(sent.guidance)
    assert MECHANISM not in rendered and INTERPRETATION not in rendered
    # The candidate and its interpretation stay in the inspection evidence.
    suspected = report["inspections"]["hack"]["findings"]["suspected"]
    assert suspected[0]["claim"]["mechanism"] == MECHANISM
    assert suspected[0]["interpretation"]["interpretation"] == INTERPRETATION
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


def test_no_candidate_leaves_guidance_unavailable_and_still_attacks(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch)
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run", analysis="hacking")

    assert analyses.calls[-1] == ("attack", 2, 1, 0)
    assert report["attack"]["candidates"] == []
    assert report["attack"]["unavailable"] == {"full": NO_CANDIDATE, "minimal": NO_CANDIDATE}
    assert "candidate exists" not in report["attack"]["unavailable"]["full"]
    assert report["attack"]["discovery"]["status"] == "no_evidenced_issue"


def test_inspector_prompt_requests_reproduction_steps_and_a_location_only():
    prompt = (Path(api.__file__).parent / "prompts" / "inspector.md").read_text()
    assert "`full_guidance`" in prompt and "concrete steps that reproduce the loophole" in prompt
    assert "`hint_location`" in prompt and "file, interface, or component" in prompt
    assert "must not contain a solution or a reproduction recipe" in prompt


def test_failed_analysis_keeps_independent_results_and_redacts_credentials(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch, fail={"hack": RuntimeError(f"provider echoed {SECRET}")})
    report = send_nudis(tmp_path / "task", output_dir=tmp_path / "run")

    # The attack still runs, without candidates, after the hack inspection failed.
    assert analyses.calls[-1] == ("attack", 2, 1, 0)
    assert report["analyses"] == {"simulation": "complete", "grader": "complete", "hack": "not run", "attack": "complete"}
    assert report["status"] == "partial"
    assert "run: hack failed: RuntimeError: provider echoed [redacted]" in report["warnings"]
    for name in ("run.json", "report.json", "report.md"):
        assert SECRET not in (tmp_path / "run" / name).read_text()


def test_cancellation_writes_the_partial_report_and_propagates(tmp_path, monkeypatch):
    analyses = Analyses(monkeypatch, fail={"grader": asyncio.CancelledError()})
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(send_nudis_async(tmp_path / "task", output_dir=tmp_path / "run"))

    assert [call[0] for call in analyses.calls] == ["start_run", "simulate", "inspect_grader"]
    report = json.loads((tmp_path / "run" / "report.json").read_text())
    assert report["analyses"] == {"simulation": "complete", "grader": "not run", "hack": "not run", "attack": "not run"}
    assert report["status"] == "partial"
    assert "run: cancelled during grader" in report["warnings"]
