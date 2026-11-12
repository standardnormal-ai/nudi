"""JSON and Markdown reports: provenance, attempts, coverage and redaction."""

import json
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from nudi import cli, inspection, report
from nudi.assessment import CHECK_LIMIT
from nudi.attack import DISABLED_LIMIT, AttackAttempt, AttackFinding, AttackResult, Candidate, Problem
from nudi.inspection import InspectionAttempt, InspectionResult, OrdinaryReview
from nudi.persistence import TIMING_LIMIT
from nudi.records import CANCELLED, Assessment, CallRecord, Claim, Derivation, ErrorRecord, PersistenceProbe, Requirement, RunRecord
from test_metrics import RunDir as MetricsRunDir, basis, checked

# The approved list these fixtures' readings read: invalid work reads `exists` violated, valid work reads it supported.
APPROVED = [Requirement(text="Write the explanation file", observation="exists")]


class RunDir(MetricsRunDir):
    """A run directory given the approved list, so the strong words of these fixtures' problems stand."""

    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.record.requirements = APPROVED

SECRET = "sk-live-0123456789abcdef"


def evidenced(episode: str, check: str) -> Assessment:
    assessment = checked(episode, check, "summary", "violated", outcome="accepted_invalid")
    assessment.discrepancy, assessment.reward, assessment.ids = "over", 1.0, {"trial_id": episode}
    assessment.claim.derivation, assessment.claim.marks = Derivation(observations=["exists"], validity="violated"), ["exists"]
    assessment.check.output = json.dumps({"observations": {"exists": False}})
    assessment.check.state_copy = "copy-0000"
    assessment.reasons, assessment.limits = ["violating content received 1.0, above the deserved score 0.0"], [CHECK_LIMIT]
    return assessment


def attacked(run: RunDir) -> None:
    full = run.episode("attacker", {"reward": 1.0})
    minimal = run.episode("attacker", {"reward": 0.0})
    none = run.episode("attacker", {}, errors=[ErrorRecord(type="DockerEnvironmentError", message=f"daemon said {SECRET}")])
    later = run.episode("attacker", {"reward": 0.0})
    run.record.calls = [CallRecord(role="attacker", episode=later, model="xai/grok-4.7", cost=None, cost_source="unknown: no price")]
    run.record.unknown_cost_calls = 1
    run.attack = AttackResult(
        status="spending_exhausted", conditions={"full": "evidenced_issue", "minimal": "refused", "none": "spending_exhausted"},
        guidance={"full": "the summary is never read", "minimal": "look at the summary", "none": None},
        attempts=[
            AttackAttempt(level="full", number=1, context="attacker-full-1", episode=full, rewards={"reward": 1.0},
                          status="evidenced_issue", assessment=0),
            AttackAttempt(level="minimal", number=1, context="attacker-minimal-1", episode=minimal, rewards={"reward": 0.0},
                          status="refused", error="finish_reason: content_filter"),
            AttackAttempt(level="none", number=1, context="attacker-none-1", episode=none, status="infrastructure_failure",
                          error=f"daemon said {SECRET}"),
            AttackAttempt(level="minimal", number=2, context="attacker-minimal-2", episode=later, status="inference_failure",
                          error="InferenceFailure: RateLimitError"),
            AttackAttempt(level="none", number=2, context="attacker-none-2", status="spending_exhausted"),
        ],
        assessments=[evidenced(full, "attack-check")], limits=[])


def test_reports_are_deterministic_and_never_expose_resolved_credentials(tmp_path):
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0}, errors=[ErrorRecord(type="AuthenticationError", message=f"bad key {SECRET}")])
    run.record.warnings = [f"provider echoed {SECRET}"]
    attacked(run)
    run.save()

    first = report.write(run.path, secrets=[SECRET, ""])
    texts = [path.read_text() for path in first]
    second = report.write(run.path, secrets=[SECRET])
    assert first == (run.path / "report.json", run.path / "report.md") == second
    assert [path.read_text() for path in second] == texts
    for text in texts:
        assert SECRET not in text and "[redacted]" in text
    loaded = json.loads(texts[0])
    assert loaded == report.build(run.path, secrets=[SECRET])
    # Credentials appear only as references: the variable name and where it was found.
    assert loaded["configuration"]["models"]["inspector"]["model"] == "openai/deepseek/deepseek-v4.1-flash-1017"
    assert loaded["configuration"]["credential_sources"]["inspector"] == "environment"
    assert loaded["ordinary"]["groups"][0]["configuration"]["versions"] == {"harbor": "0.24.0"}
    assert "openai/deepseek/deepseek-v4.1-flash-1017" in texts[1] and "harbor 0.24.0" in texts[1]


def test_attack_reports_actual_attempts_and_failure_kinds_without_a_success_rate(tmp_path):
    run = RunDir(tmp_path)
    attacked(run)
    result = run.report()
    attack = result["attack"]
    full, minimal, none = (attack["conditions"][level] for level in ("full", "minimal", "none"))
    assert (full["status"], full["evidence"], full["attempts"]) == ("evidenced_issue", "found", 1)
    assert (minimal["status"], minimal["evidence"], minimal["attempts"]) == ("refused", "not found", 2)
    assert minimal["outcomes"] == {"inference_failure": 1, "refused": 1}
    # The second no-hint entry was blocked by the cap before any episode ran.
    assert none["outcomes"] == {"infrastructure_failure": 1} and none["attempts"] == 1
    assert full["guidance"] == "the summary is never read" and none["guidance"] is None
    assert [attempt["episode"] for attempt in attack["attempts"]] == [item.episode for item in run.attack.attempts]
    assert attack["unknown_cost_calls"] == 1
    assert not any("safe" in limit for limit in attack["limits"])
    text = json.dumps(result)
    assert "rate" not in json.dumps(attack["conditions"])
    assert any("no unbiased success-rate" in note for note in result["notes"])
    # Attacker rewards stay out of the ordinary pool.
    assert result["ordinary"]["attempted"] == 0 and len(result["other_episodes"]["attacker"]) == 4
    assert "attack spending_exhausted" in "\n".join(result["warnings"]) and "unknown prices" in text
    assert result["status"] == "partial"

    disabled = RunDir(tmp_path / "disabled")
    disabled.attack = AttackResult(status="complete", maximum_attempts=0, limits=[DISABLED_LIMIT])
    result = disabled.report()
    assert result["analyses"]["attack"] == "complete" and result["status"] == "complete"
    assert DISABLED_LIMIT in result["attack"]["limits"]


def test_blocked_attack_entries_are_neither_attempts_nor_tested_conditions(tmp_path):
    run = RunDir(tmp_path)
    started = run.episode("attacker", {"reward": 1.0})
    # checks.attack records an entry, and may name its episode, before the cap admits it.
    run.attack = AttackResult(
        status="spending_exhausted", conditions={"full": "evidenced_issue", "minimal": "spending_exhausted", "none": "spending_exhausted"},
        guidance={"full": "the summary is never read", "minimal": "look at the summary", "none": None},
        attempts=[
            AttackAttempt(level="full", number=1, context="attacker-full-1", episode=started, status="evidenced_issue"),
            AttackAttempt(level="minimal", number=1, context="attacker-minimal-1", status="spending_exhausted"),
            AttackAttempt(level="none", number=1, context="attacker-none-1", episode="0001-attacker", status="spending_exhausted"),
        ])

    attack = run.report()["attack"]
    assert attack["tested_conditions"] == ["full"]
    full, minimal, none = (attack["conditions"][level] for level in ("full", "minimal", "none"))
    assert (full["tested"], full["attempts"], full["evidence"], full["blocked"]) == (True, 1, "found", [])
    for condition, episode in ((minimal, None), (none, "0001-attacker")):
        assert (condition["tested"], condition["attempts"], condition["evidence"]) == (False, 0, "not attempted")
        assert condition["outcomes"] == {}
        assert condition["blocked"] == [{"number": 1, "episode": episode, "status": "spending_exhausted", "error": None,
                                         "reason": "no episode of this entry started"}]
    assert len(attack["attempts"]) == 3


def test_configuration_keeps_retained_digests_and_pins_without_simulation(tmp_path):
    run = RunDir(tmp_path)
    run.record.simulation = None
    recorded = run.episode("attacker", {"reward": 0.0})
    run.record.episodes.append("0001-attacker")  # started, but its runner left no episode record
    run.attack = AttackResult(status="complete", conditions={"none": "no_evidenced_issue"}, guidance={"none": None},
                              attempts=[AttackAttempt(level="none", number=1, context="attacker-none-1", episode=recorded,
                                                      status="no_evidenced_issue")])

    result = run.report()
    assert result["ordinary"] is None and "simulation" not in result["analyses"]
    (provenance,) = result["configuration"]["provenance"]
    assert provenance["episodes"] == [recorded]
    assert provenance["configuration"] == {"task_name": "sort", "task_digest": run.digest, "model": "xiaomi_mimo/mimo-v2.6-pro",
                                           "reasoning_effort": "high", "path": "harbor", "versions": {"harbor": "0.24.0"}}
    assert result["configuration"]["provenance_unavailable"] == {
        "0001-attacker": "no retained episode record, so its task digest and version pins are unavailable"}
    markdown = report.markdown(result)
    assert run.digest in markdown and "harbor 0.24.0" in markdown and "0001-attacker" in markdown

    empty = RunDir(tmp_path / "empty")
    empty.record.simulation = None
    empty.attack = AttackResult(status="disabled", maximum_attempts=0)
    configuration = empty.report()["configuration"]
    assert configuration["provenance"] == [] and configuration["provenance_unavailable"] == {}
    text = report.markdown(empty.report())
    assert "no retained episode record" in text
    assert "Neither the grader inspector nor the hack inspector was selected or run." in text
    assert "The grader inspector was not selected or not run." in text


def test_findings_keep_claims_captured_facts_and_interpretations_apart(tmp_path):
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    suspect = checked(graded, "c1", "sorted", "unknown")
    suspect.reasons, suspect.missing = ["no check has tested the graded submission"], ["a host check"]
    run.label(graded, "accepted_invalid", evidenced(graded, "c0"), suspect)

    findings = run.report()["inspections"]["grader_inspector"]["findings"]
    (issue,) = findings["evidenced"]
    assert issue["claim"] == {"mechanism": "unchecked requirement", "episode": graded, "reward": "reward", "unresolved": [],
                              "limits": [], "marks": ["exists"]}
    captured = issue["captured"]
    assert captured["observations"] == {"exists": False}
    assert captured["native_reward"] == 1.0 and captured["ids"] == {"trial_id": graded}
    assert captured["check"]["id"] == "c0" and captured["check"]["exit_code"] == 0
    assert captured["check"]["content"]["sha256"] == "a" * 64
    assert captured["check"]["state_copy"] == "copy-0000"
    assert issue["interpretation"]["interpretation"] == "summary is violated"
    assert issue["interpretation"]["derivation"]["validity"] == "violated"
    assert issue["assessment"]["outcome"] == "accepted_invalid" and CHECK_LIMIT in issue["assessment"]["limits"]
    (provisional,) = findings["inconclusive"]
    assert provisional["assessment"]["missing"] == ["a host check"]


def test_reports_expose_retained_investigation_evidence_and_capture_limits(tmp_path):
    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status="partial", categories={"package_oracles": "unknown"}, applicability={},
        artifacts={"hack-broad": {"transcript": "sandboxes/sandbox-0000/transcript.jsonl",
                                  "tool_outputs": "sandboxes/sandbox-0000/tool-outputs"}},
        limits=["SDK shell capture retains at most 10 MiB; uncaptured bytes are unavailable."])
    result = run.report()
    visible = result["inspections"]["hack_inspector"]
    assert visible["artifacts"]["hack-broad"]["transcript"].endswith("transcript.jsonl")
    assert "10 MiB" in visible["limits"][0]
    markdown = report.markdown(result)
    assert "sandboxes/sandbox-0000/transcript.jsonl" in markdown and "tool-outputs" in markdown and "10 MiB" in markdown


def test_records_before_requirement_conclusions_stay_readable_without_invented_evidence(tmp_path):
    """An older record has only the check's own requirement; a missing reward stays unavailable, not zero."""
    run = MetricsRunDir(tmp_path)
    name = run.episode(rewards={})
    run.label(name, "unavailable", checked(name, "c0", "sorted", "violated", basis=basis("violated", ["sorted"], ["c0"])))
    run.save()
    path = run.path / "inspection-grader.json"
    legacy = json.loads(path.read_text())
    for item in legacy["assessments"]:
        del item["conclusions"]
    path.write_text(json.dumps(legacy))

    result = report.build(run.path)
    assert (result["metrics"]["episodes"][name]["completion"], result["metrics"]["episodes"][name]["decision"]) == ("incomplete", None)
    (finding,) = result["inspections"]["grader_inspector"]["findings"]["inconclusive"]
    assert finding["assessment"]["conclusions"] == [] and finding["captured"]["native_reward"] is None
    line = next(line for line in report.markdown(result).splitlines() if line.startswith("- grader_inspector inconclusive:"))
    assert "native reward unavailable" in line and "validity violated" in line


def test_a_record_saved_before_the_single_deserved_score_loads_and_reports_its_stored_outcomes(tmp_path):
    """Old fields stay in the raw JSON and are not reassessed or converted: supports, min/max, the label's
    assessment indices, the embedded session copies and an attribution with a checks list."""
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    run.label(graded, "accepted_invalid", evidenced(graded, "c0"))
    attacked = run.episode("attacker", {"reward": 1.0})
    run.attack = AttackResult(status="complete", conditions={"none": "evidenced_issue"}, attempts=[
        AttackAttempt(level="none", number=1, context="attacker-none-none-1", episode=attacked, rewards={"reward": 1.0},
                      status="evidenced_issue", assessment=0)],
        assessments=[evidenced(attacked, "c1")])
    run.save()
    support = {"basis": "explicit", "sources": [{"episode": None, "path": "instruction.md", "excerpt": "Write the numbers sorted"}],
               "rationale": "stated", "uncertainty": []}
    for name in ("inspection-grader.json", "attack.json"):
        path = run.path / name
        legacy = json.loads(path.read_text())
        for item in legacy["assessments"]:
            item["claim"].update(requirement_support=support, scoring_support=support)
            item["claim"]["derivation"].update(minimum={"field": "minimum"}, maximum={"field": "maximum"},
                                               requirements=[{"requirement": support["sources"][0], "observations": ["exists"],
                                                              "validity": "violated", "interpretation": "old", "support": support}])
        if name == "attack.json":
            legacy["sessions"] = {"inspector-attacker-none-none-1": [{"role": "system", "content": "old prompt"}]}
            legacy["findings"] = [{"kind": "discovery", "attempt": 0, "assessment": 0, "checks": ["c1"]}]
        else:
            legacy["sessions"] = {"grader-broad": [{"role": "human", "content": "old request"}]}
            legacy["ordinary"][graded]["assessments"] = [0]
        path.write_text(json.dumps(legacy))

    result = report.build(run.path)
    grader = result["inspections"]["grader_inspector"]
    (finding,) = grader["findings"]["evidenced"]
    assert finding["assessment"]["outcome"] == "accepted_invalid" and finding["assessment"]["discrepancy"] == "over"
    assert "above the deserved score 0.0" in " ".join(finding["assessment"]["reasons"])
    assert finding["interpretation"]["citations"] == [] and "requirement_support" not in json.dumps(finding)
    derivation = finding["interpretation"]["derivation"]
    assert {"minimum", "maximum"}.isdisjoint(derivation) and "support" not in derivation["requirements"][0]
    assert result["labels"]["episodes"][graded]["label"] == "accepted_invalid"
    assert result["attack"]["attempts"][0]["status"] == "evidenced_issue"
    assert report.markdown(result)


def test_package_sandbox_evidence_stays_marked_apart_from_native_findings(tmp_path):
    run = RunDir(tmp_path)
    native = run.episode("attacker", {"reward": 1.0})
    run.record.sandboxes = ["sandbox-0000", "sandbox-0001"]
    package = evidenced("sandbox-0000", "package-check")
    package.execution_scope, package.ids = "package", {"sandbox": "sandbox-0000", "session_id": "nudi-ab-sandbox-0000"}
    package.check.sandbox = "sandbox-0001"
    package.claim.limits = ["whether the copied grader matches the hosted one"]
    attacker = evidenced(native, "native-check")
    attacker.claim.limits = ["whether the task meant the explanation to be graded"]
    run.hack = InspectionResult(mode="hack", status="complete", categories={"package_oracles": "evidenced_issue"}, applicability={},
                                assessments=[package])
    run.attack = AttackResult(status="complete", conditions={"none": "evidenced_issue"}, guidance={"none": None},
                              attempts=[AttackAttempt(level="none", number=1, context="attacker-none-1", episode=native,
                                                      status="evidenced_issue", assessment=0)],
                              assessments=[attacker])

    result = run.report()
    findings = result["inspections"]["hack_inspector"]["findings"]
    assert findings["inconclusive"] == []
    (copy,) = findings["evidenced"]
    assert copy["execution_scope"] == "package" and copy["claim"]["episode"] == "sandbox-0000"
    assert copy["captured"]["check"]["sandbox"] == "sandbox-0001"
    assert copy["captured"]["copied_grader_reward"] == 1.0 and "native_reward" not in copy["captured"]
    assert any("not native accessibility" in limit for limit in copy["assessment"]["limits"])
    (issue,) = result["attack"]["findings"]["evidenced"]
    assert issue["execution_scope"] == "native"
    assert issue["captured"]["native_reward"] == 1.0 and "copied_grader_reward" not in issue["captured"]
    assert result["other_episodes"]["sandboxes"] == ["sandbox-0000", "sandbox-0001"]
    markdown = report.markdown(result)
    assert "2 Inspector sandboxes" in markdown
    package_line = next(line for line in markdown.splitlines() if line.startswith("- hack_inspector evidenced (package):"))
    assert "copied grader reward 1" in package_line and "native reward" not in package_line
    # The package limit is stated once for every package finding.
    assert markdown.count(report.PACKAGE_LIMIT) == 1
    for part in ("not native accessibility", "copied tests", "after the verification_start copy", "isolation parity"):
        assert part in report.PACKAGE_LIMIT
    # A finding's scope notes stay visible beside it, native or package.
    assert "Scope notes: whether the copied grader matches the hosted one" in package_line
    native_line = next(line for line in markdown.splitlines() if line.startswith("- attack evidenced:"))
    assert "Scope notes: whether the task meant the explanation to be graded" in native_line


def test_incomplete_selected_coverage_and_persistence_limits_are_reported(tmp_path):
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.record.simulation.requested, run.record.simulation.status = 3, "spending_exhausted"
    run.label("0000-simulator", "unknown")
    run.grader.status = "partial"
    run.grader.categories = {"accepted_invalid": "no_evidenced_issue", "rejected_valid": "unknown"}
    run.hack = InspectionResult(mode="hack", status="complete", categories={"persistence": "restricted"}, applicability={},
                                attempts=[InspectionAttempt(phase="broad", number=0, status="no_evidenced_issue")])
    run.record.persistence_probes = [PersistenceProbe(location="/app/marker", mount_relationship="writable_layer",
                                                      classification="survived", limits=[TIMING_LIMIT])]

    result = run.report(selected=["simulation", "grader", "hack", "attack"])
    assert result["analyses"] == {"simulation": "spending_exhausted", "grader": "partial", "hack": "complete", "attack": "not run"}
    assert result["status"] == "partial"
    warnings = "\n".join(result["warnings"])
    assert "simulation attempted 1 of 3 requested" in warnings
    assert "grader inspector category rejected_valid is unknown" not in warnings
    assert "hack inspector category persistence is restricted" not in warnings
    assert "attack was selected but not run" in warnings
    assert "1 of 1 ordinary episodes have no supported local label" in warnings
    (probe,) = result["persistence"]
    # The stored classification is not accepted; teardown was never observed.
    assert probe["classification"] == "unknown" and TIMING_LIMIT in probe["limits"]
    assert "persistence probe /app/marker is unknown" in warnings
    assert "F1 is unavailable" in warnings and "AUROC is unavailable" in warnings

    unselected = run.report(selected=["simulation"])
    assert set(unselected["analyses"]) == {"simulation"}
    assert "attack was selected" not in "\n".join(unselected["warnings"])

    markdown = (report.write(run.path, selected=["simulation", "grader", "hack", "attack"])[1]).read_text()
    for heading in ("## Configuration", "## Ordinary rewards", "## Local grader labels", "## Metrics",
                    "## Findings", "## Attack", "## Persistence", "## Warnings"):
        assert heading in markdown
    assert "attack: not run" in markdown and TIMING_LIMIT in markdown


def packaged(sandbox: str, check: str, *unresolved: str) -> Assessment:
    """A package-sandbox accepted_invalid finding, evidenced unless something stays unresolved."""
    assessment = evidenced(sandbox, check)
    assessment.execution_scope, assessment.claim.unresolved = "package", list(unresolved)
    return assessment


def experiment(number: int, category: str, check: str, status: str = "assessed") -> dict:
    return {"id": f"experiment-{number:04d}", "category": category, "status": status, "check": check}


def test_findings_are_grouped_by_result_and_keep_their_scope_category_and_open_items(tmp_path):
    """Doubt is one-sided: an issue with an open condition is a finding shown with it; a legitimate result with one is not clean."""
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    run.record.sandboxes = ["sandbox-0000", "sandbox-0001"]
    unresolved = "whether the copied grader is the hosted grader"
    run.label(graded, "unknown", packaged("sandbox-0000", "check-0000"), packaged("sandbox-0001", "check-0001", unresolved),
              checked(graded, "check-0002", "sorted", "unknown"),
              checked(graded, "check-0003", "sorted", "supported", outcome="legitimate", unresolved=["whether sorting is graded"]))
    run.grader.categories = {"accepted_invalid": "evidenced_issue"}
    run.grader.experiments = [experiment(0, "accepted_invalid", "check-0000"), experiment(1, "accepted_invalid", "check-0001")]

    result = run.report()
    findings = result["inspections"]["grader_inspector"]["findings"]
    assert set(findings) == {"evidenced", "legitimate", "inconclusive"}
    (issue, doubted), (unknown, doubted_legitimate) = findings["evidenced"], findings["inconclusive"]
    assert (issue["execution_scope"], issue["category"], issue["captured"]["check"]["id"]) == ("package", "accepted_invalid", "check-0000")
    assert (doubted["claim"]["unresolved"], doubted["category"]) == ([unresolved], "accepted_invalid")
    assert (unknown["execution_scope"], unknown["category"], unknown["assessment"]["outcome"]) == ("native", None, "unknown")
    assert doubted_legitimate["assessment"]["outcome"] == "legitimate" and findings["legitimate"] == []

    lines = report.markdown(result).splitlines()
    assert lines[lines.index("## Findings") + 2] == "Evidenced findings: 2, 1 of them with open conditions."
    first, second = [line for line in lines if line.startswith("- grader_inspector evidenced (package):")]
    assert "check check-0000; category accepted_invalid" in first and "copied grader reward 1" in first
    assert "Interpretation: summary is violated" in first and "Open conditions" not in first
    assert report.PACKAGE_LIMIT not in first and CHECK_LIMIT not in first
    assert f"Open conditions: {unresolved}" in second and "check check-0001" in second
    assert any(line.startswith("- grader_inspector inconclusive:") and "check check-0002;" in line for line in lines)
    # Limits shared by findings are listed once, apart from the finding lines.
    text = "\n".join(lines)
    assert text.count(report.PACKAGE_LIMIT) == 1 and text.count(CHECK_LIMIT) == 1


@pytest.mark.parametrize("validity, outcome, later", [("unknown", "unknown", "inconclusive"),
                                                     ("supported", "legitimate", "legitimate")])
def test_an_earlier_reading_stays_listed_and_names_the_later_reading_that_superseded_it(tmp_path, validity, outcome, later):
    """Evidence later read as unknown or contradicted still explains the label and the category, which keep it."""
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    candidates = [Assessment(claim=Claim(mechanism=f"candidate {number}", episode=graded), outcome="unknown") for number in (1, 2)]
    run.label(graded, "accepted_invalid", evidenced(graded, "check-0000"), checked(graded, "check-0000", "summary", validity, outcome=outcome),
              *candidates)
    run.grader.categories = {"accepted_invalid": "evidenced_issue"}
    run.grader.experiments = [experiment(0, "accepted_invalid", "check-0000")]

    result = run.report()
    findings = result["inspections"]["grader_inspector"]["findings"]
    (earlier,) = findings["evidenced"]
    (current,) = [item for item in findings[later] if item["captured"]["check"]]
    assert (earlier["index"], earlier["superseded_by"], earlier["category"]) == (0, {"index": 1, "result": later}, "accepted_invalid")
    assert (current["index"], current["superseded_by"], current["category"]) == (1, None, "accepted_invalid")
    # Claims without a check are never superseded.
    candidates = [item for item in findings["inconclusive"] if item["captured"]["check"] is None]
    assert [(item["claim"]["mechanism"], item["superseded_by"]) for item in candidates] == [("candidate 1", None), ("candidate 2", None)]
    assert result["labels"]["episodes"][graded]["label"] == "accepted_invalid"

    lines = report.markdown(result).splitlines()
    assert any(line.startswith(f"- grader_inspector evidenced, superseded by the later {later} reading of check-0000: ") for line in lines)
    assert any(line.startswith(f"- grader_inspector {later}: ") and "check check-0000;" in line for line in lines)
    assert "- grader_inspector: accepted_invalid" in lines


def test_the_evidenced_count_reads_only_the_latest_reading_of_each_check(tmp_path):
    """A check read twice counts once: a superseded reading stays listed but is not counted."""
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    doubted = evidenced(graded, "check-0000")
    doubted.claim.unresolved = ["whether the copied grader is the hosted grader"]
    run.label(graded, "accepted_invalid", doubted, evidenced(graded, "check-0000"), evidenced(graded, "check-0001"),
              checked(graded, "check-0001", "summary", "unknown"))
    run.grader.categories = {"accepted_invalid": "evidenced_issue"}

    lines = report.markdown(run.report()).splitlines()
    assert lines[lines.index("## Findings") + 2] == "Evidenced findings: 1, 0 of them with open conditions."
    assert sum(line.startswith("- grader_inspector evidenced") for line in lines) == 3


def test_a_repair_evidences_the_category_of_its_session_and_keeps_its_experiment(tmp_path):
    """Broad measured a check for accepted_invalid; a rejected_valid session reinterpreted it and evidenced an issue."""
    run = RunDir(tmp_path)
    graded = "0000-simulator"
    run.grader = InspectionResult(
        mode="grader", status="complete", categories={"accepted_invalid": "no_evidenced_issue", "rejected_valid": "evidenced_issue"},
        applicability={},
        attempts=[InspectionAttempt(phase="broad", number=0, status="no_evidenced_issue"),
                  InspectionAttempt(phase="focused", number=1, category="accepted_invalid", status="no_evidenced_issue"),
                  InspectionAttempt(phase="focused", number=1, category="rejected_valid", status="evidenced_issue")],
        assessments=[checked(graded, "check-0000", "summary", "unknown"), evidenced(graded, "check-0000")],
        reviews=[OrdinaryReview(episode=graded, attempt=0, status="assessed", checks={"check-0000": 0}, assessment=0),
                 OrdinaryReview(episode=graded, attempt=2, status="assessed", reinterprets="check-0000", assessment=1)],
        experiments=[{**experiment(0, "accepted_invalid", "check-0000"), "assessment": 0}])

    result = run.report(selected=["grader"])
    findings = result["inspections"]["grader_inspector"]["findings"]
    (repair,), (earlier,) = findings["evidenced"], findings["inconclusive"]
    assert (repair["category"], repair["experiment"], repair["superseded_by"]) == ("rejected_valid", "experiment-0000", None)
    assert (earlier["category"], earlier["superseded_by"]) == ("accepted_invalid", {"index": 1, "result": "evidenced"})
    lines = report.markdown(result).splitlines()
    assert "- grader_inspector: accepted_invalid, rejected_valid" in lines
    line = next(line for line in lines if line.startswith("- grader_inspector evidenced: "))
    assert "check check-0000; category rejected_valid; reinterprets experiment-0000, measured for accepted_invalid;" in line


def test_every_experiment_is_listed_once_with_its_result_whatever_its_category(tmp_path):
    """Each experiment that ran is listed with the outcome of its check's latest reading, or its status without one:
    unfinished work stays visible beside an evidenced category, without a category, and after a failure."""
    run = RunDir(tmp_path)
    run.record.sandboxes = ["sandbox-0000"]
    run.grader = InspectionResult(
        mode="grader", status="partial", categories={"accepted_invalid": "evidenced_issue", "rejected_valid": "unknown"},
        applicability={},
        assessments=[packaged("sandbox-0000", "check-0000")],
        experiments=[experiment(0, "accepted_invalid", "check-0000"),
                     {**experiment(1, "accepted_invalid", "check-0001", "measured"), "episode": "0000-simulator"},
                     {"id": "experiment-0002", "category": None, "status": "measured", "check": "check-0002"},
                     {"id": "experiment-0003", "status": "model_output_failure"},
                     {"id": "experiment-0004", "category": "accepted_invalid", "status": "known_problem", "problem": "P1"}])

    text = report.markdown(run.report(selected=["grader"]))
    assert ("- grader_inspector experiments: experiment-0000 (accepted_invalid, check-0000): accepted_invalid; "
            "experiment-0001 (accepted_invalid, check-0001, 0000-simulator): measured; experiment-0002 (no category, check-0002): measured; "
            "experiment-0003 (no category): model_output_failure") in text.splitlines()
    # The Answer names the failed experiment as lost work; the rest of the report lists each once.
    answer, rest = text.split("\n## Configuration\n")
    assert "- Finished, but work was lost: a grader inspector experiment failed: experiment-0003 (model_output_failure)." in answer
    for number in (1, 2, 3):
        assert rest.count(f"experiment-000{number}") == 1
    # A probe judged the same as an evidenced problem ran nothing, so it awaits no assessment.
    assert "experiment-0004" not in text
    assert "- grader_inspector: accepted_invalid" in text.splitlines()
    assert "rejected_valid: no focused attempt or experiment recorded" in text


def test_each_open_category_gets_one_markdown_line_naming_what_keeps_it_open(tmp_path):
    """`open` reaches report.json as recorded, and report.md lists each open category once with its experiments."""
    run = RunDir(tmp_path)
    open_entries = [
        {"id": "experiment-0000", "category": "package_oracles", "reason": "its reading leaves unresolved: whether the fix is graded",
         "next": "measure it"},
        {"id": "experiment-0001", "category": "package_oracles", "reason": "its draft reading is open", "next": "complete it"},
        {"id": "fabricated_answers", "category": "fabricated_answers", "reason": "no reading of this category agrees", "next": "measure"}]
    run.hack = InspectionResult(mode="hack", status="partial", categories={"package_oracles": "unknown", "fabricated_answers": "unknown"},
                                applicability={}, open=open_entries)
    result = run.report(selected=["hack"])
    assert result["inspections"]["hack_inspector"]["open"] == open_entries
    lines = report.markdown(result).splitlines()
    assert ("- hack_inspector package_oracles leads: experiment-0000: its reading leaves unresolved: whether the fix is graded; "
            "experiment-0001: its draft reading is open") in lines
    assert "- hack_inspector fabricated_answers leads: fabricated_answers: no reading of this category agrees" in lines


def test_a_measured_suspicion_left_unread_at_run_end_is_a_suspected_exploit_and_no_problem(tmp_path):
    """A measured experiment whose reading ended unfinished or unknown, in a category and case no evidenced reading has,
    is listed as a suspected exploit beside the leads, with its category and check, and is no problem. An experiment
    with nothing measured stays a plain lead, and an evidenced reading of the same case suppresses the line."""
    run = RunDir(tmp_path)
    box = "sandbox-0000"
    run.record.sandboxes = [box]
    assessments = [checked(box, "check-0", "summary", "unknown"), checked(box, "check-1", "summary", "unknown"),
                   checked(box, "check-2", "summary", "unknown"), evidenced(box, "check-3")]
    experiments = [{**experiment(0, "package_oracles", "check-0", "unfinished"), "case": "a", "assessment": 0},
                   {**experiment(1, "fabricated_answers", "check-1"), "case": "b", "assessment": 1},
                   {**experiment(2, "grader_tampering", "check-2", "unfinished"), "case": "c", "assessment": 2},
                   {**experiment(3, "grader_tampering", "check-3"), "case": "c", "assessment": 3},
                   {"id": "experiment-0004", "category": "leakage_metadata", "case": "d", "status": "running"}]
    open_entries = [{"id": "experiment-0004", "category": "leakage_metadata", "reason": "its reading is unknown", "next": "measure"}]
    run.hack = InspectionResult(mode="hack", status="partial", categories={}, applicability={}, assessments=assessments,
                                experiments=experiments, open=open_entries)
    run.attack = AttackResult(status="complete", discovery={"none": "no_evidenced_issue"})
    built = run.report(selected=["hack", "attack"])
    assert ([item["id"] for item in built["attack"]["problems"]], built["attack"]["leads"]) == (["hack-3"], [])
    assert built["inspections"]["hack_inspector"]["suspected"] == [
        {"category": "package_oracles", "check": "check-0"}, {"category": "fabricated_answers", "check": "check-1"}]
    lines = report.markdown(built).splitlines()
    assert "- hack_inspector ●○○○○ suspected exploit (package_oracles, check-0)" in lines
    assert "- hack_inspector ●○○○○ suspected exploit (fabricated_answers, check-1)" in lines
    assert sum("●○○○○" in line for line in lines) == 2
    assert "- hack_inspector leakage_metadata leads: experiment-0004: its reading is unknown" in lines


def test_a_reused_case_name_suppresses_no_suspicion_measured_elsewhere():
    """Two experiments that share a case name but measure different paths in different episodes are separate cases:
    an evidenced reading of one leaves the other's unknown reading a suspected exploit."""
    readings = [checked("sandbox-0000", "check-0", "summary", "unknown"), evidenced("sandbox-0001", "check-1")]
    rows = [{**experiment(0, "grader_tampering", "check-0"), "case": "baseline", "assessment": 0, "episode": "sandbox-0000",
             "location": "/app/cache.json"},
            {**experiment(1, "grader_tampering", "check-1"), "case": "baseline", "assessment": 1, "episode": "sandbox-0001",
             "location": "/app/test.sh"}]
    result = InspectionResult(mode="hack", status="partial", categories={}, applicability={}, assessments=readings, experiments=rows)
    assert report.inspection("hack", result, [])["suspected"] == [{"category": "grader_tampering", "check": "check-0"}]


def test_a_category_whose_attempt_failed_is_listed_as_not_finished_not_as_a_lead(tmp_path):
    """A failed attempt suspected nothing, so it is no lead: its categories are listed together, with the failure."""
    run = RunDir(tmp_path)
    failed = "an attempt failed: inference_failure: APIError: API key spend limit exceeded."
    open_entries = [{"id": category, "category": category, "reason": failed, "next": "a later attempt"}
                    for category in ("leakage_metadata", "package_oracles")]
    run.hack = InspectionResult(mode="hack", status="partial", categories={"leakage_metadata": "unknown", "package_oracles": "unknown"},
                                applicability={}, open=open_entries)
    lines = report.markdown(run.report(selected=["hack"])).splitlines()
    assert f"- hack_inspector leakage_metadata, package_oracles not finished: {failed}" in lines
    assert not any(" leads: " in line for line in lines)


def test_markdown_lists_searched_categories_without_verdicts(tmp_path):
    """Search names and findings remain visible, with no category verdict or applicability prose."""
    run = RunDir(tmp_path)
    run.record.sandboxes = ["sandbox-0000", "sandbox-0001"]
    prose = "Four measured cases confirm the omission."
    run.grader = InspectionResult(
        mode="grader", status="partial",
        categories={"accepted_invalid": "evidenced_issue", "rejected_valid": "unknown"},
        applicability={"rejected_valid": prose},
        attempts=[InspectionAttempt(phase="broad", number=0, status="unobservable", error="Invalid probe: reference"),
                  InspectionAttempt(phase="focused", number=1, category="accepted_invalid", status="evidenced_issue"),
                  InspectionAttempt(phase="focused", number=1, category="rejected_valid", status="model_output_failure",
                                    error="Invalid probe: 'category'"),
                  InspectionAttempt(phase="focused", number=2, category="rejected_valid", status="no_evidenced_issue"),
                  InspectionAttempt(phase="episode", number=1, episode="0000-simulator", status="tool_failure")],
        assessments=[packaged("sandbox-0000", "check-0000"), checked("sandbox-0001", "check-0001", "sorted", "unknown")],
        experiments=[experiment(0, "accepted_invalid", "check-0000"), experiment(1, "rejected_valid", "check-0001"),
                     experiment(2, "rejected_valid", "check-0002", "measured")])

    result = run.report(selected=["grader"])
    warnings = "\n".join(result["warnings"])
    assert "grader inspector category rejected_valid is unknown" not in warnings
    assert prose not in warnings
    assert "grader inspector episode attempt 1 (0000-simulator) tool_failure, no error message recorded" in warnings and "None" not in warnings
    assert result["inspections"]["grader_inspector"]["applicability"]["rejected_valid"] == prose
    text = report.markdown(result)
    assert prose not in text
    lines = text.splitlines()
    start = lines.index("## Categories searched") + 2
    assert lines[start:start + 2] == [
        "- grader_inspector: accepted_invalid, rejected_valid",
        "- grader_inspector experiments: experiment-0000 (accepted_invalid, check-0000): accepted_invalid; "
        "experiment-0001 (rejected_valid, check-0001): unknown; experiment-0002 (rejected_valid, check-0002): measured",
    ]
    assert "evidenced_issue" not in text
    assert not any(note.startswith("A category is") for note in result["notes"])


@pytest.mark.parametrize("state", ["evidenced_issue", "no_evidenced_issue", "unknown", "restricted"])
def test_category_states_stay_in_json_not_customer_output(tmp_path, monkeypatch, capsys, state):
    from nudi import send

    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status="complete", categories={"grader_tampering": state}, applicability={})
    result = run.report(selected=["hack"])
    assert result["inspections"]["hack_inspector"]["categories"] == {"grader_tampering": state}
    monkeypatch.setattr(send, "configure", lambda *args: SimpleNamespace(output_dir=tmp_path))
    monkeypatch.setattr(send, "send_nudis", lambda *args, **kwargs: result)
    assert cli.main(["send-nudis", str(tmp_path), "--output", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "grader_tampering" in output
    for word in ("evidenced_issue", "no_evidenced_issue", "unknown", "restricted", "safe", "clean"):
        assert word not in output.lower()



def test_configuration_names_the_task_without_its_host_path_and_states_what_cost_excludes(tmp_path):
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.record.credential_sources = {"inspector": "environment"}
    run.record.unknown_cost_calls, run.record.sandboxes = 85, ["sandbox-0000", "sandbox-0001"]

    result = run.report()
    assert result["configuration"]["task_dir"] == "task"
    text = report.markdown(result)
    assert str(tmp_path) not in text and str(tmp_path) not in json.dumps(result)
    assert "known cost $0.000000, excluding 85 calls with unknown prices" in text
    assert "provider-reported" not in text
    assert "inspector: openai/deepseek/deepseek-v4.1-flash-1017, reasoning effort high, credential from environment" in text
    assert "- attacker: openai/deepseek/deepseek-v4.1-flash-1017, reasoning effort high, no credential resolved; the selected analyses do not run this role" in text
    assert "nowhere" not in text
    # Session workspaces are Inspector sandboxes too, not package experiments only.
    assert "Outside the ordinary pool: 2 Inspector sandboxes (session workspaces and package experiments), 0 persistence probes" in text


def test_cost_lines_separate_provider_reported_cost_from_estimates(tmp_path):
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.record.calls = [CallRecord(role="inspector", episode="grader-inspector", model="xai/grok-4.7", cost=0.05, cost_source="litellm.completion_cost"),
                        CallRecord(role="inspector", episode="grader-inspector", model="openai/unpriced", cost=0.25,
                                   cost_source="provider-reported usage.cost", provider_cost=0.25)]
    run.record.known_cost = 0.3

    text = report.markdown(run.report())
    assert "- Spending cap: 5.0; known cost $0.300000, $0.250000 of it provider-reported" in text


def test_calls_with_unknown_prices_are_counted_by_reason_and_older_reports_by_count():
    reasons = {"no response before its calls ended": 2, "the request failed": 1}
    assert report.left_out({"unknown_cost_calls": 3, "cancelled_calls": 0, "unknown_reasons": reasons}) == (
        ", excluding 3 calls with unknown prices (2 without a response before their calls ended, 1 whose request failed)")
    assert report.left_out({"unknown_cost_calls": 3, "cancelled_calls": 0}) == ", excluding 3 calls with unknown prices"


def test_cost_is_given_per_job_summing_to_the_known_cost_and_cancelled_calls_are_labelled_cancelled(tmp_path):
    run = RunDir(tmp_path)
    simulator = run.episode(rewards={"reward": 1.0})
    attacker = run.episode("attacker", {"reward": 0.0})
    probe = run.episode("attacker", {})
    run.record.probe_episodes = [probe]
    judge = "attack_inspector-attacker-none-none-1"

    def call(role, episode, cost, tokens=(0, 0), source="litellm.completion_cost", **fields):
        return CallRecord(role=role, episode=episode, model="xai/grok-4.7", prompt_tokens=tokens[0], completion_tokens=tokens[1],
                          cost=cost, cost_source=source, **fields)

    run.record.calls = [
        call("simulator", simulator, 0.10, (100, 10)), call("inspector", "grader-broad", 0.20, (200, 20)),
        call("inspector", f"grader-episode-{simulator}", 0.05), call("inspector", "hack-broad", 0.30),
        call("inspector", "hack-package_oracles", None, source="unknown: no price"), call("inspector", "problems", 0.01),
        call("inspector", "judge", 0.01),
        call("attacker", attacker, 0.40), call("inspector", judge, 0.02),
        CallRecord(role="inspector", episode=judge, model="xai/grok-4.7", cost=None, cost_source=CANCELLED, error="CancelledError"),
        call("attacker", probe, 0.03)]
    run.record.known_cost = sum(item.cost for item in run.record.calls if item.cost is not None)
    run.record.unknown_cost_calls, run.record.cancelled_calls = 1, 1
    run.attack = AttackResult(status="complete", discovery={"none": "no_evidenced_issue"}, attempts=[
        AttackAttempt(level="none", number=1, context="attacker-none-none-1", episode=attacker, status="no_evidenced_issue")])

    result = run.report()
    jobs = result["configuration"]["cost_by_job"]
    # The judge's calls, and an older record's grouping call, are jobs of their own.
    assert list(jobs) == ["Simulator", "grader inspector", "hack inspector", "judge", "grouping", "Attacker", "attack inspector",
                          "persistence probe"]
    assert jobs["grader inspector"] == {"calls": 2, "known_cost": pytest.approx(0.25), "prompt_tokens": 200, "completion_tokens": 20,
                                        "unknown_cost_calls": 0, "cancelled_calls": 0, "unknown_reasons": {}}
    assert (jobs["hack inspector"]["unknown_cost_calls"], jobs["attack inspector"]["cancelled_calls"]) == (1, 1)
    assert sum(item["calls"] for item in jobs.values()) == len(run.record.calls)
    assert round(sum(item["known_cost"] for item in jobs.values()), 2) == round(result["configuration"]["known_cost"], 2) == 1.12
    # The attack section counts its attack inspector calls beside the Attacker's.
    assert (result["attack"]["unknown_cost_calls"], result["attack"]["cancelled_calls"]) == (0, 1)
    assert (result["configuration"]["unknown_cost_calls"], result["configuration"]["cancelled_calls"]) == (1, 1)
    assert "1 model calls have unknown prices; the known cost excludes them" in result["warnings"]
    assert "1 model calls were cancelled in flight, so their usage is unknown; the known cost excludes them" in result["warnings"]

    text = report.markdown(result)
    assert "known cost $1.120000, excluding 1 call with unknown prices (1 not priced: no price) and 1 call cancelled in flight" in text
    assert "  - grader inspector: known cost $0.250000 in 2 calls, 200 prompt and 20 completion tokens\n" in text
    assert "  - attack inspector: known cost $0.020000 in 2 calls, 0 prompt and 0 completion tokens, excluding 1 call cancelled in flight" in text
    assert "; 0 Attacker and attack inspector calls with unknown prices and 1 cancelled in flight." in text


@pytest.mark.parametrize("episode,expected", [("inspector-attacker-hack-1-full-1", "attack inspector"),
                                              ("replay-inspector-attacker-none-none-1", "attack inspector"), ("0003-inspector", "inspector")])
def test_older_inspector_session_names_keep_their_job(episode, expected):
    """Older records named attack inspector sessions `inspector-attacker-...` and `replay-inspector-attacker-...`."""
    call = CallRecord(role="inspector", episode=episode, model="xai/grok-4.7", cost=0.01, cost_source="litellm.completion_cost")
    assert report.job(call, SimpleNamespace(probe_episodes=[])) == expected


def test_labels_failures_and_metric_coverage_state_their_counts_without_contradiction(tmp_path):
    run = RunDir(tmp_path)
    timeout = ErrorRecord(type="AgentTimeoutError", message="Agent execution timed out after 900.0 seconds")
    names = [run.episode(rewards={"reward": 0.0}, errors=[timeout]), run.episode(rewards={"reward": 1.0})]
    for name in names:
        run.label(name, "legitimate")
        run.grader.ordinary[name].basis = "presumed"

    result = run.report()
    text = report.markdown(result)
    assert (f"- {names[0]} recorded AgentTimeoutError: Agent execution timed out after 900.0 seconds; "
            "its retained reward is summarized below") in text
    review = next(line for line in text.splitlines() if line.startswith("Review attempted"))
    assert review == "Review attempted for 0 (attempted but unresolved 0); not reviewed 2, of which presumed 2; supported label for 0."
    # An unavailable metric uses no episode.
    warnings = "\n".join(result["warnings"])
    assert "F1 is unavailable" in warnings and "F1 uses 0 of" not in warnings


def test_an_older_experiment_without_a_check_id_links_its_category_through_its_assessment(tmp_path):
    run = RunDir(tmp_path)
    run.record.sandboxes = ["sandbox-0000"]
    run.grader = InspectionResult(mode="grader", status="complete", categories={"accepted_invalid": "evidenced_issue"}, applicability={},
                                  assessments=[packaged("sandbox-0000", "check-0000")],
                                  experiments=[{"id": "experiment-0000", "category": "accepted_invalid", "status": "assessed", "assessment": 0}])
    result = run.report(selected=["grader"])
    (issue,) = result["inspections"]["grader_inspector"]["findings"]["evidenced"]
    assert issue["category"] == "accepted_invalid"
    assert "- grader_inspector: accepted_invalid" in report.markdown(result)


def rejecting(sandbox: str, check: str) -> Assessment:
    """A package-sandbox rejected_valid finding, whose check reads the approved requirement supported."""
    assessment = packaged(sandbox, check)
    assessment.outcome, assessment.discrepancy, assessment.validity = "rejected_valid", "under", "supported"
    assessment.claim.derivation.validity = "supported"
    return assessment


def answered(run: RunDir) -> None:
    """The grader inspector and the hack inspector evidence package findings; one Attacker reproduces
    hack-1 and another has valid work for hack-2 rejected. hack-N is the hack inspector's assessment N."""
    graded = run.episode(rewards={"reward": 1.0})
    run.record.sandboxes = ["sandbox-0000"]
    run.label(graded, "legitimate", packaged("sandbox-0000", "check-0000"), rejecting("sandbox-0000", "check-0001"))
    run.grader.categories = {"accepted_invalid": "evidenced_issue", "rejected_valid": "evidenced_issue"}
    run.grader.experiments = [experiment(0, "accepted_invalid", "check-0000"), experiment(1, "rejected_valid", "check-0001")]
    run.hack = InspectionResult(
        mode="hack", status="complete", categories={"grader_tampering": "evidenced_issue", "unchecked_requirements": "unknown"},
        applicability={}, assessments=[checked("sandbox-0000", "check-0002", "sorted", "supported", outcome="legitimate"),
                                       packaged("sandbox-0000", "check-0003"), rejecting("sandbox-0000", "check-0004")],
        experiments=[experiment(2, "grader_tampering", "check-0002"), experiment(3, "grader_tampering", "check-0003"),
                     experiment(4, "unchecked_requirements", "check-0004")])
    reproduced, refused = run.episode("attacker", {"reward": 1.0}), run.episode("attacker", {"reward": 0.0})
    shim, rejected = evidenced(reproduced, "check-0005"), evidenced(refused, "check-0006")
    shim.claim.mechanism = "planted a bash shim\nthat prints the pass marker"
    rejected.outcome, rejected.claim.mechanism = "rejected_valid", "wrote the answer with leading zeros"
    guidance = {"full": "plant the shim", "minimal": "look at PATH"}
    run.attack = AttackResult(
        status="complete", discovery_attempts=0,
        candidates=[Candidate(id="hack-1", mechanism="a bash shim", guidance=guidance,
                              conditions={"full": "evidenced_issue", "minimal": "unattempted"}),
                    Candidate(id="hack-2", mechanism="leading zeros", guidance=guidance, valid_work=True,
                              conditions={"full": "evidenced_issue", "minimal": "unattempted"})],
        attempts=[AttackAttempt(level="full", number=1, candidate="hack-1", sources=["hack-1"], context="attacker-hack-1-full-1",
                                episode=reproduced, rewards={"reward": 1.0}, status="evidenced_issue", assessment=0, reproduced=True),
                  AttackAttempt(level="full", number=1, candidate="hack-2", sources=["hack-2"], context="attacker-hack-2-full-1",
                                episode=refused, rewards={"reward": 0.0}, status="evidenced_issue", assessment=1, reproduced=True)],
        assessments=[shim, rejected],
        findings=[AttackFinding(kind="reproduction", candidate="hack-1", sources=["hack-1"], attempt=0, assessment=0, relation="target",
                                rationale="the planted shim printed the pass marker"),
                  AttackFinding(kind="reproduction", candidate="hack-2", sources=["hack-2"], attempt=1, assessment=1, relation="target")])


def test_the_answer_gives_one_line_per_problem_led_by_its_facts_and_its_quotes_stay_in_the_attack_section(tmp_path):
    """Each problem has its own Answer line, by the judge's id or else its finding's: the reward, the values its check
    measured for its marks, its label and how many assessed attempts reproduced it, exploits first. An attempt's
    quotation stays in its attempt line in Attack, which keeps the finding ids."""
    run = RunDir(tmp_path)
    answered(run)
    run.attack.attempts[0].problem, run.attack.attempts[1].problem = "P2", "P3"
    run.attack.problems = [Problem(id="P2", source="hack inspector", cause="A bash shim.", members=["experiment-0003"], findings=["hack-1"], evidence="evidenced"),
                           Problem(id="P3", source="hack inspector", cause="Leading zeros.", members=["experiment-0004"], findings=["hack-2"], evidence="evidenced"),
                           Problem(id="G1", source="grader inspector", cause="Empty output.", members=["grader-0"], findings=["grader-0"], evidence="evidenced")]
    result = run.report()
    assert result["answer"] == [
        "Finished. Every step ran.",
        "The grader can be cheated, and it misjudges work.",
        "P2: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0003; ●●●○○ exploit executable by learner with full information; "
        "1 of 1 assessed attempts reproduced it.",
        "G1: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0000; ●●○○○ reproduced exploit, evidenced in a package sandbox; "
        "no attempt was assessed.",
        "P3: reward 1; exists = false measured by check check-0004; Correct work failed, reproduced by an Attacker with full "
        "instructions; 1 of 1 assessed attempts reproduced it.",
        "grader-1: reward 1; exists = false measured by check check-0001; Correct work failed, evidenced in a package sandbox; no attempt was assessed.",
        report.LEGEND]
    text = report.markdown(result)
    assert "planted a bash shim" not in "\n".join(result["answer"])
    assert ('- 0001-attacker exploited hack-1 (grader_tampering, check-0003) with full instructions: reward 1. '
            'How: "planted a bash shim that prints the pass marker"') in text


def test_a_problem_where_correct_work_failed_is_named_so(tmp_path):
    """hack-2 is valid work the grader rejects, which an Attacker with full instructions reproduced. It is a grader that
    fails correct work, as the simulation chart's FN says, not an exploit: its type is a false negative."""
    run = RunDir(tmp_path)
    answered(run)
    run.attack.attempts[0].problem, run.attack.attempts[1].problem = "P2", "P3"
    run.attack.problems = [Problem(id="P2", source="hack inspector", cause="A bash shim.", members=["experiment-0003"], findings=["hack-1"], evidence="evidenced"),
                           Problem(id="P3", source="hack inspector", cause="Leading zeros.", members=["experiment-0004"], findings=["hack-2"], evidence="evidenced")]
    built = run.report()
    labels = {item["id"]: (item["finding"], item["type"], item["level"], item["label"]) for item in built["attack"]["problems"] if item["id"].startswith("P")}
    assert labels == {"P2": ("hack-1", "hack", 3, "●●●○○ exploit executable by learner with full information"),
                      "P3": ("hack-2", "false_negative", 3, "Correct work failed, reproduced by an Attacker with full instructions")}
    lines = report.problem_lines(built)
    assert ("- P3 from the hack inspector, Correct work failed, reproduced by an Attacker with full instructions: Leading zeros; "
            "findings hack-2 (unchecked_requirements, check-0004).") in lines


def test_a_problem_that_holds_no_case_is_a_lead(tmp_path):
    """An older record's problems formed before measurement, which hold no case, are leads: report.json lists them
    apart from the problems, and report.md names them on one line with no level and no verdict."""
    run = RunDir(tmp_path)
    answered(run)
    run.attack.attempts[0].problem = "P2"
    run.attack.problems = [Problem(id="P1", source="hack inspector", cause="A bash shim.", members=["experiment-0002"], evidence="not_reproduced"),
                           Problem(id="P2", source="hack inspector", cause="Leading zeros.", members=["experiment-0003"], findings=["hack-1"], evidence="evidenced"),
                           Problem(id="P3", source="hack inspector", cause="A stale log.", members=["experiment-0004"])]
    built = run.report()
    assert [item["id"] for item in built["attack"]["problems"]] == ["P2", "hack-2", "grader-0", "grader-1"]
    assert built["attack"]["leads"] == [{"id": "P1", "cause": "A bash shim.", "origin": None}, {"id": "P3", "cause": "A stale log.", "origin": None}]
    lines = report.problem_lines(built)
    assert ("- P2 from the hack inspector, ●●●○○ exploit executable by learner with full information: Leading zeros; "
            "findings hack-1 (grader_tampering, check-0003).") in lines
    assert lines[-1] == "- Leads, which no evidence confirmed: P1 (A bash shim), P3 (A stale log)."
    markdown = report.markdown(built)
    assert "suspected exploit" not in markdown and "tested in" not in markdown


def test_a_case_says_whether_a_package_copy_or_a_native_episode_evidenced_it(tmp_path):
    """Below an Attacker's exploit, a case is a reproduced exploit, the chart's words; where it was evidenced, by its
    execution scope, follows the label on its line."""
    run = RunDir(tmp_path)
    answered(run)
    native = run.episode(rewards={"reward": 1.0})
    run.hack.assessments.append(evidenced(native, "check-0007"))
    run.hack.experiments.append(experiment(7, "grader_tampering", "check-0007"))
    run.attack.problems = [Problem(id="P4", source="hack inspector", cause="Echo the input.", members=["hack-3"], findings=["hack-3"], evidence="evidenced"),
                           Problem(id="G1", source="grader inspector", cause="Empty output.", members=["grader-0"], findings=["grader-0"], evidence="evidenced")]
    built = run.report()
    labels = {item["id"]: (item["level"], item["label"], item["scope"]) for item in built["problems"] if item["id"] != item["finding"]}
    assert labels == {"P4": (2, "●●○○○ reproduced exploit", "native"), "G1": (2, "●●○○○ reproduced exploit", "package")}
    assert any(line.startswith("P4: ") and "; ●●○○○ reproduced exploit, evidenced in a native episode; " in line for line in built["answer"])
    assert any(line.startswith("G1: ") and "; ●●○○○ reproduced exploit, evidenced in a package sandbox; " in line for line in built["answer"])
    # Each category's latest readings that read legitimate are counted, with no verdict on the category.
    assert "- hack_inspector legitimate readings: grader_tampering 1" in report.markdown(built).splitlines()


def test_each_problem_shows_its_cause_with_its_cases_beneath(tmp_path):
    """A problem's line gives its cause; each case the judge placed in it follows on its own line."""
    run = RunDir(tmp_path)
    answered(run)
    run.attack.attempts[0].problem = "P2"
    cases = [{"id": "hack-1", "check": "check-0003", "outcome": "accepted_invalid", "mechanism": "A shim\non PATH.",
              "location": "/usr/bin/bash", "capture_point": "verification_start"},
             {"id": "hack-4", "check": "check-0008", "outcome": "accepted_invalid", "mechanism": "A shim in /bin."}]
    run.attack.problems = [Problem(id="P2", source="hack inspector", cause="A bash shim.", members=["hack-1", "hack-4"], findings=["hack-1"],
                                   evidence="evidenced", cases=cases)]
    built = run.report()
    section = report.markdown(built).split("\n## Attack\n")[1].splitlines()
    at = next(index for index, line in enumerate(section) if line.startswith("- P2 from"))
    assert section[at + 1:at + 3] == ["  - hack-1: A shim on PATH; check check-0003; location /usr/bin/bash; capture point verification_start",
                                      "  - hack-4: A shim in /bin; check check-0008"]
    assert not any(line.startswith("  - ") for line in built["answer"])


def test_the_report_names_the_hack_findings_given_to_the_grader_inspector_and_each_candidate_source(tmp_path):
    """The grader inspection record names the hack findings its request listed; report.json and report.md repeat
    them. `grader-N` is the grader inspector's assessment N, and each candidate names the inspector it came from."""
    run = RunDir(tmp_path)
    answered(run)
    run.grader.hack_inspection, run.grader.hack_findings = "complete", ["hack-1", "hack-2"]
    run.attack.candidates.append(Candidate(id="grader-1", mechanism="rejected leading zeros", valid_work=True, source="grader_inspector",
                                           guidance={"full": "write leading zeros", "minimal": None},
                                           conditions={"full": "unattempted", "minimal": "unavailable"}))
    built = run.report()
    grader = built["inspections"]["grader_inspector"]
    assert (grader["hack_inspection"], grader["hack_findings"]) == ("complete", ["hack-1", "hack-2"])
    assert "hack_findings" not in built["inspections"]["hack_inspector"]
    assert [item["source"] for item in built["attack"]["candidates"]] == [None, None, "grader_inspector"]
    text = report.markdown(built)
    assert "- grader_inspector was configured with hack findings hack-1, hack-2 from a complete hack inspection as places to look." in text
    assert "; attack candidate grader-1" in text
    assert "grader-1 (rejected_valid, check-0001) with full instructions" in text.split("- Not attempted: ")[1].splitlines()[0]


def test_the_report_opens_with_a_plain_answer_built_from_its_cases(tmp_path):
    """The report first says whether the grader can be cheated or misjudges work, then one line per case."""
    run = RunDir(tmp_path)
    answered(run)
    result = run.report()
    expected = [
        "Finished. Every step ran.",
        "The grader can be cheated, and it misjudges work.",
        "hack-1: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0003; ●●●○○ exploit executable by learner with full information; "
        "1 of 1 assessed attempts reproduced it.",
        "grader-0: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0000; ●●○○○ reproduced exploit, evidenced in a package sandbox; "
        "no attempt was assessed.",
        "hack-2: reward 1; exists = false measured by check check-0004; Correct work failed, reproduced by an Attacker with full "
        "instructions; 1 of 1 assessed attempts reproduced it.",
        "grader-1: reward 1; exists = false measured by check check-0001; Correct work failed, evidenced in a package sandbox; "
        "no attempt was assessed.",
    ]
    assert result["answer"] == expected
    lines = report.markdown(result).splitlines()
    assert lines[:4] == ["# nudi report", "", "## Answer", ""]
    assert lines[4:10] == [f"- {line}" for line in expected] and lines[10:12] == ["", "## Configuration"]

    # Package evidence alone does not show that a task agent can cheat.
    assert run.report(selected=["simulation", "grader", "hack"])["answer"] == [
        "Finished. Every step ran.",
        "The grader can be cheated in a copy of the task package, not yet in a real episode, and it misjudges work.",
        "hack-1: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0003; ●●○○○ reproduced exploit, evidenced in a package sandbox.",
        "grader-0: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0000; ●●○○○ reproduced exploit, evidenced in a package sandbox.",
        "hack-2: reward 1; exists = false measured by check check-0004; Correct work failed, evidenced in a package sandbox.",
        "grader-1: reward 1; exists = false measured by check check-0001; Correct work failed, evidenced in a package sandbox."]


def test_with_nothing_evidenced_the_answer_says_so_and_never_calls_the_grader_safe(tmp_path):
    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status="partial", categories={"grader_tampering": "unknown"}, applicability={},
                                assessments=[checked("sandbox-0000", "check-0000", "sorted", "unknown")])
    result = run.report()
    # Every step ran: evidence the inspection left unresolved is its result, not a failed run.
    assert (result["status"], result["unfinished"], result["unresolved"]) == ("complete", {}, ["hack"])
    assert result["answer"] == ["Finished. Every step ran. Evidence stayed unresolved in the hack inspector, so the run may miss more.",
                                "No cheat and no misjudged work was evidenced."]
    assert report.markdown(result).splitlines()[4:6] == [f"- {line}" for line in result["answer"]]


def test_a_step_that_failed_or_stopped_makes_the_run_partial_apart_from_unresolved_evidence(tmp_path):
    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status="partial", categories={"grader_tampering": "unknown"}, applicability={})
    run.record.failed_phases = ["hack"]
    run.record.simulation.status = "spending_exhausted"
    result = run.report()
    assert (result["status"], result["unfinished"], result["unresolved"]) == (
        "partial", {"simulation": "spending_exhausted", "hack": "partial"}, [])
    assert result["answer"][0] == ("Finished with gaps: the Simulator stopped by the spending cap, the hack inspector failed. "
                                   "Results below are what was found.")


def test_an_older_pooled_attack_record_answers_from_its_evidenced_attempts(tmp_path):
    run = RunDir(tmp_path)
    attacked(run)
    result = run.report()
    assert result["answer"] == ["Finished with gaps: the attack stopped by the spending cap; work was also lost: an attack attempt failed "
                                "in 0001-attacker, 0002-attacker, 0003-attacker. Results below are what was found.",
                                "The grader can be cheated.",
                                "0000-attacker: requirement \"Write the explanation file\"; reward 1; exists = false measured by check attack-check; with full instructions; "
                                "●●●○○ exploit executable by learner with full information."]
    # Its attempts are listed one per line too, after the pooled conditions.
    lines = report.markdown(result).splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("- 0000-attacker cheated"))
    assert lines[start:start + 5] == [
        '- 0000-attacker cheated with full instructions: reward 1. How: "unchecked requirement"',
        "- 0001-attacker searched with only a hint: reward 0; refused: finish_reason: content_filter",
        f"- 0002-attacker searched with no extra information: no reward; infrastructure_failure: daemon said {SECRET}",
        "- 0003-attacker searched with only a hint: no reward; inference_failure: InferenceFailure: RateLimitError",
        "- attempt 2 with no extra information did not start: stopped by the spending cap"]


def test_the_attempt_lines_quote_each_mechanism_whole_and_the_answer_quotes_none(tmp_path):
    """The Answer stays short and states only measured facts; what the Attacker did is in its attempt line."""
    run = RunDir(tmp_path)
    answered(run)
    long = "wrote every answer with leading zeros, " * 5 + "and the grader rejected them all"
    run.attack.assessments[0].claim.mechanism = "Planted a bash shim. It prints the pass marker."
    run.attack.assessments[1].claim.mechanism = long
    result = run.report()
    assert not any("Planted" in line or "leading zeros" in line for line in result["answer"])
    lines = report.markdown(result).splitlines()
    assert any('How: "Planted a bash shim. It prints the pass marker."' in line for line in lines)
    assert any(f'How: "{long}"' in line for line in lines)


def test_a_secret_across_the_answer_cut_never_appears_even_in_part(tmp_path):
    """Scrubbing matches whole secrets, so the answer is cut only from already redacted text."""
    run = RunDir(tmp_path)
    answered(run)
    spaced = "Zq9vX2 w8Lp3T kR7m"
    # Each secret starts before the 140-character cut of a measured value and ends after it: one after a run with no
    # space, one with spaces inside.
    run.hack.assessments[1].check.output = json.dumps({"observations": {"exists": "/opt/" + "a/" * 62 + f"key={SECRET} was echoed"}})
    run.grader.assessments[0].check.output = json.dumps({"observations": {"exists": "w " * 60 + spaced + " was echoed"}})
    result = run.report(secrets=[SECRET, spaced])
    for text in (json.dumps(result), report.markdown(result)):
        for secret in (SECRET, spaced):
            assert secret[:6] not in text
    assert " ".join(result["answer"]).count("[redac") == 2


def test_an_attempt_line_keeps_every_mechanism_of_findings_with_the_same_wording(tmp_path):
    """Two other-mechanism findings on one attempt read the same; each mechanism stays, in order, once."""
    run = RunDir(tmp_path)
    answered(run)
    episode = run.attack.attempts[0].episode
    run.attack.assessments[0].claim.mechanism = "planted a shell shim"
    run.attack.assessments += [evidenced(episode, "check-0007"), evidenced(episode, "check-0008")]
    run.attack.assessments[2].claim.mechanism, run.attack.assessments[3].claim.mechanism = "forged the reward file", "planted a shell shim"
    run.attack.findings[0:1] = [AttackFinding(kind="other", candidate="hack-1", sources=["hack-1"], attempt=0, assessment=number,
                                              relation="other") for number in (0, 2, 3)]
    run.attack.attempts[0].reproduced = False
    lines = report.markdown(run.report()).splitlines()
    assert ('- 0001-attacker cheated through another mechanism while testing hack-1 (grader_tampering, check-0003) with full instructions: '
            'reward 1. How: "planted a shell shim". How: "forged the reward file"') in lines
    # The Answer gives that attempt one case.
    assert " ".join(run.report()["answer"]).count("0001-attacker") == 1


def test_the_answer_reads_only_the_latest_reading_of_each_check(tmp_path):
    """A native reading later read as legitimate neither shows a cheat nor makes the cheat real."""
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    run.record.sandboxes = ["sandbox-0000"]
    run.hack = InspectionResult(
        mode="hack", status="complete", categories={"grader_tampering": "evidenced_issue"}, applicability={},
        assessments=[evidenced(graded, "check-0000"), checked(graded, "check-0000", "summary", "supported", outcome="legitimate"),
                     packaged("sandbox-0000", "check-0001")],
        experiments=[experiment(0, "grader_tampering", "check-0000"), experiment(1, "grader_tampering", "check-0001")])
    assert run.report()["answer"] == [
        "Finished. Every step ran.",
        "The grader can be cheated in a copy of the task package, not yet in a real episode.",
        "hack-2: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0001; ●●○○○ reproduced exploit, evidenced in a package sandbox."]

    run.hack.assessments.pop()
    assert run.report()["answer"][1] == "No cheat and no misjudged work was evidenced."


def test_an_evidenced_attack_finding_outside_the_requested_outcome_is_its_own_case(tmp_path):
    """Testing valid work, an Attacker had incorrect work passed; testing a cheat, another had correct work
    failed. Neither confirms its candidate, so neither is an exploit entry, but each is a case on its own evidence,
    at the help its Attacker had for another problem."""
    run = RunDir(tmp_path)
    invalid, valid = run.episode("attacker", {"reward": 1.0}), run.episode("attacker", {"reward": 0.0})
    rejected = evidenced(valid, "check-0001")
    rejected.outcome, rejected.validity, rejected.claim.derivation.validity = "rejected_valid", "supported", "supported"
    run.attack = AttackResult(
        status="complete", discovery_attempts=0,
        candidates=[Candidate(id="valid-0", guidance={"full": "write leading zeros"}, valid_work=True, conditions={"full": "no_evidenced_issue"}),
                    Candidate(id="hack-0", guidance={"full": "plant the shim"}, conditions={"full": "no_evidenced_issue"})],
        attempts=[AttackAttempt(level="full", number=1, candidate="valid-0", sources=["valid-0"], context="attacker-valid-0-full-1",
                                episode=invalid, rewards={"reward": 1.0}, status="no_evidenced_issue", assessment=0),
                  AttackAttempt(level="full", number=1, candidate="hack-0", sources=["hack-0"], context="attacker-hack-0-full-1",
                                episode=valid, rewards={"reward": 0.0}, status="no_evidenced_issue", assessment=1)],
        assessments=[evidenced(invalid, "check-0000"), rejected])
    result = run.report()
    assert result["answer"] == [
        "Finished. Every step ran.",
        "The grader can be cheated, and it misjudges work.",
        "0000-attacker: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-0000; with full instructions while testing valid-0; "
        "no reproduction of valid-0 was established; ●●●○○ exploit executable by learner with full information.",
        "0001-attacker: reward 1; exists = false measured by check check-0001; with full instructions while testing hack-0; "
        "no reproduction of hack-0 was established; Correct work failed, reproduced by an Attacker with full instructions."]
    # Neither attempt line claims what was submitted.
    lines = report.markdown(result).splitlines()
    assert "- 0000-attacker tested valid-0 with full instructions: reward 1; no case where correct work failed was found" in lines
    assert "- 0001-attacker tested hack-0 with full instructions: reward 0; no exploit was evidenced" in lines


def test_each_attack_attempt_is_one_line_naming_the_finding_it_tested_and_its_outcome(tmp_path):
    """Each attempt names its candidate and source check, outcomes are plain, and conditions never attempted are grouped."""
    run = RunDir(tmp_path)
    answered(run)
    honest, failed = run.episode("attacker", {"reward": 1.0}), run.episode("attacker", {"reward": 1.0})
    run.attack.assessments.append(checked(honest, "check-0007", "sorted", "violated", outcome="legitimate"))
    run.attack.findings[0].rationale = "Matches the target.\nThe check shows the shim ran."
    run.attack.candidates[0].conditions["minimal"], run.attack.candidates[1].conditions["minimal"] = "no_evidenced_issue", "model_output_failure"
    run.attack.candidates += [
        Candidate(id="hack-5", guidance={"full": "f"}, unavailable={"minimal": "candidate exists but generated minimal guidance unavailable"},
                  conditions={"full": "unattempted", "minimal": "unavailable"}),
        Candidate(id="hack-6", guidance={"full": "f", "minimal": "m"}, conditions={"full": "unattempted", "minimal": "unattempted"})]
    run.attack.attempts += [
        AttackAttempt(level="minimal", number=1, candidate="hack-1", sources=["hack-1"], context="attacker-hack-1-minimal-1", episode=honest,
                      rewards={"reward": 0.5}, status="no_evidenced_issue", assessment=2),
        AttackAttempt(level="minimal", number=1, candidate="hack-2", sources=["hack-2"], context="attacker-hack-2-minimal-1", episode=failed,
                      rewards={"reward": 1.0}, status="model_output_failure", error="Invalid Claim: 1 validation error for Claim\nmechanism\n  Field required"),
        AttackAttempt(level="full", number=2, candidate="hack-1", sources=["hack-1"], context="attacker-hack-1-full-2", status="spending_exhausted")]

    result = run.report()
    lines = report.markdown(result).splitlines()
    start = lines.index("## Attack") + 2
    assert lines[start:lines.index("## Persistence") - 1] == [
        "Status complete; at most 2 attempts per candidate and hint level; 0 Attacker and attack inspector calls with unknown prices and 0 cancelled in flight.",
        "Independent attacker with no extra information: 0 started of at most 0.",
        "- hack-1 from the hack inspector, ●●●○○ exploit executable by learner with full information.",
        "  - With full instructions: 1 of 1 attempts reproduced it, openai/deepseek/deepseek-v4.1-flash-1017, evidenced_issue.",
        "  - With only a hint: 0 of 1 attempts reproduced it, openai/deepseek/deepseek-v4.1-flash-1017, no_evidenced_issue.",
        "- hack-2 from the hack inspector, Correct work failed, reproduced by an Attacker with full instructions.",
        "  - With full instructions: 1 of 1 attempts reproduced it, openai/deepseek/deepseek-v4.1-flash-1017, evidenced_issue.",
        "  - With only a hint: No attempt was assessed. Not run or not assessed: 0004-attacker, reward 1, "
        "model_output_failure: Invalid Claim: 1 validation error for Claim.",
        "- grader-0 from the grader inspector, ●●○○○ reproduced exploit, evidenced in a package sandbox.",
        "- grader-1 from the grader inspector, Correct work failed, evidenced in a package sandbox.",
        '- 0001-attacker exploited hack-1 (grader_tampering, check-0003) with full instructions: reward 1. '
        'How: "planted a bash shim that prints the pass marker". Attack inspector: Matches the target. The check shows the shim ran.',
        '- 0002-attacker had correct work failed while testing hack-2 (unchecked_requirements, check-0004) with full instructions: reward 0. '
        'How: "wrote the answer with leading zeros"',
        "- 0003-attacker tested hack-1 (grader_tampering, check-0003) with only a hint: reward 0.5; no exploit was evidenced",
        "- 0004-attacker tested hack-2 (unchecked_requirements, check-0004) with only a hint: reward 1; "
        "model_output_failure: Invalid Claim: 1 validation error for Claim",
        "- attempt 2 on hack-1 (grader_tampering, check-0003) with full instructions did not start: stopped by the spending cap",
        "- Not attempted: hack-5 with full instructions, hack-6 with full instructions and only a hint",
        "- Not attempted, no guidance: hack-5 with only a hint",
    ]
    # Each hack inspector finding that became a candidate names it.
    finding = next(line for line in lines if line.startswith("- hack_inspector evidenced (package):") and "check check-0003;" in line)
    assert "check check-0003; category grader_tampering; attack candidate hack-1;" in finding
    # The JSON keeps every attempt and condition in full.
    assert result["attack"]["attempts"][3]["error"].endswith("Field required")
    assert result["attack"]["exploits"]["reproduction"][0]["rationale"] == "Matches the target.\nThe check shows the shim ran."
    assert result["attack"]["candidates"][2]["conditions"]["minimal"]["unavailable"] == "candidate exists but generated minimal guidance unavailable"


def test_repeated_warnings_are_grouped_and_multi_line_errors_shortened_in_markdown(tmp_path):
    """Attack conditions get one warning per status; category states stay out of warnings."""
    run = RunDir(tmp_path)
    answered(run)
    error = "Invalid Claim: 1 validation error for Claim\nmechanism\n  Field required"
    run.hack.categories.update(leakage_metadata="unknown", persistence="restricted")
    run.hack.applicability["persistence"] = "Native persistence readback is a separate observation."
    run.hack.attempts = [InspectionAttempt(phase="focused", number=1, category="leakage_metadata", status="model_output_failure", error=error)]
    run.attack.candidates += [Candidate(id=f"hack-{number}", guidance={"full": "f", "minimal": "m"},
                                        conditions={"full": "unattempted", "minimal": "unattempted"}) for number in (5, 6)]

    result = run.report()
    assert "hack inspector categories unchecked_requirements, leakage_metadata are unknown" not in result["warnings"]
    assert "hack inspector category persistence is restricted: Native persistence readback is a separate observation." not in result["warnings"]
    assert not any("category leakage_metadata is unknown" in warning for warning in result["warnings"])
    assert "attack candidates hack-1 minimal, hack-2 minimal, hack-5 full and minimal, hack-6 full and minimal are unattempted" in result["warnings"]
    assert sum("attack candidate" in warning for warning in result["warnings"]) == 1
    failure = f"hack inspector focused attempt 1 (leakage_metadata) model_output_failure: {error}"
    assert failure in result["warnings"]
    lines = report.markdown(result).splitlines()
    assert f"- {failure.splitlines()[0]} (full text in report.json)" in lines
    assert "mechanism" not in lines and "  Field required" not in lines


def inspected(run: RunDir, count: int = 1) -> None:
    """The hack inspector evidences `count` package findings, hack-0 onwards, each a current reading of its own check."""
    run.record.sandboxes = ["sandbox-0000"]
    run.hack = InspectionResult(mode="hack", status="complete", categories={"grader_tampering": "evidenced_issue"}, applicability={},
                                assessments=[packaged("sandbox-0000", f"check-{index:04d}") for index in range(count)],
                                experiments=[experiment(index, "grader_tampering", f"check-{index:04d}") for index in range(count)])


def test_an_attempt_that_was_not_run_or_not_assessed_is_listed_apart_from_the_attempts_that_exploited(tmp_path):
    """"0 of 1 attempts reproduced it" reads as an assessed negative. An attempt whose Attacker or attack inspector failed
    is out of that count and listed with its reward and reason, and the step it blocked says which step failed."""
    run = RunDir(tmp_path)
    inspected(run)
    full, failed, empty = (run.episode("attacker", {"reward": 1.0}) for _ in range(3))
    run.attack = AttackResult(status="partial", candidates=[Candidate(
        id="hack-0", mechanism="m", outcome="accepted_invalid", guidance={"full": "steps", "minimal": "look"},
        conditions={"full": "evidenced_issue", "minimal": "inference_failure", "none": "unattempted"})],
        attempts=[AttackAttempt(level="full", number=1, context="c0", candidate="hack-0", sources=["hack-0"], episode=full,
                                status="evidenced_issue", problem="P1", rewards={"reward": 1.0}, reproduced=True, assessment=0),
                  AttackAttempt(level="minimal", number=1, context="c1", candidate="hack-0", sources=["hack-0"], episode=failed,
                                status="inference_failure", error="the attack inspector failed: APIError: spend limit", rewards={"reward": 1.0}),
                  AttackAttempt(level="minimal", number=2, context="c2", candidate="hack-0", sources=["hack-0"], episode=empty,
                                status="no_evidenced_issue", rewards={"reward": 0.0})],
        assessments=[evidenced(full, "check-0100")],
        findings=[AttackFinding(kind="reproduction", candidate="hack-0", sources=["hack-0"], attempt=0, assessment=0, relation="target")],
        problems=[Problem(id="P1", source="hack inspector", cause="Skip the test.", findings=["hack-0"], evidence="evidenced")],
        discovery={"none": "unattempted"})
    built = run.report(selected=["hack", "attack"])
    assert [(row["condition"], row["attempts"], row.get("not_assessed", [])) for row in built["problems"][0]["conditions"][:2]] == [
        ("full", 1, []), ("minimal", 1, [{"episode": failed, "status": "inference_failure", "reward": "reward 1",
                                          "error": "the attack inspector failed: APIError: spend limit"}])]
    model = "openai/deepseek/deepseek-v4.1-flash-1017"
    section = report.markdown(built).split("\n## Attack\n")[1].splitlines()
    at = section.index(next(line for line in section if line.startswith("- P1 ")))
    # No-hint search attempts never count for an inspector's problem, so its conditions end with the aimed ones.
    assert section[at + 2:at + 5] == [
        f"  - With only a hint: 0 of 1 attempts reproduced it, {model}, inference_failure. Not run or not assessed: {failed}, "
        "reward 1, inference_failure: the attack inspector failed: APIError: spend limit.",
        "  - With no extra information, aimed at it: Not attempted, the step with only a hint failed (inference_failure).",
        f'- {full} exploited hack-0 (grader_tampering, check-0000) with full instructions: reward 1. How: "unchecked requirement"']


def test_a_native_timeout_without_reward_or_assessment_is_not_an_attempt(tmp_path):
    """An Attacker episode that timed out with no reward was not assessed, so it is listed apart and is not counted."""
    run = RunDir(tmp_path)
    inspected(run)
    timed_out = run.episode("attacker")
    run.attack = AttackResult(status="partial", candidates=[Candidate(
        id="hack-0", mechanism="m", outcome="accepted_invalid", guidance={"full": "steps", "minimal": "look"},
        conditions={"full": "native_timeout", "minimal": "unattempted", "none": "unattempted"})],
        attempts=[AttackAttempt(level="full", number=1, context="c0", candidate="hack-0", sources=["hack-0"], episode=timed_out,
                                status="native_timeout", error="the Attacker failed: agent_timeout")],
        problems=[Problem(id="P1", source="hack inspector", cause="Skip the test.", findings=["hack-0"], evidence="evidenced")],
        discovery={"none": "unattempted"})
    built = run.report(selected=["hack", "attack"])
    (row, *_) = built["problems"][0]["conditions"]
    assert (row["condition"], row["attempts"], row["not_assessed"]) == (
        "full", 0, [{"episode": timed_out, "status": "native_timeout", "reward": "no reward", "error": "the Attacker failed: agent_timeout"}])
    assert "of 1 attempts" not in report.markdown(built)


def grouped(run: RunDir, problems: list[Problem]) -> dict:
    """hack-0 no Attacker reproduced, hack-1 one with a hint reproduced and hack-2 one with full instructions reproduced;
    a no-hint Attacker found its own exploit, the judge's A1. Reported with these problems."""
    inspected(run, 3)
    episodes = [run.episode("attacker", {"reward": 1.0}) for _ in range(6)]
    levels = {"hack-0": ("no_evidenced_issue", "not_needed"), "hack-1": ("evidenced_issue", "evidenced_issue"),
              "hack-2": ("evidenced_issue", "no_evidenced_issue")}
    candidates = [Candidate(id=name, mechanism=name, outcome="accepted_invalid", guidance={"full": "steps", "minimal": "look"},
                            conditions={"full": full, "minimal": minimal}) for name, (full, minimal) in levels.items()]
    attempts = [AttackAttempt(level="none", number=1, context="attacker-none-1", episode=episodes[0], status="evidenced_issue",
                              problem="A1", assessment=0, rewards={"reward": 1.0})]
    findings = [AttackFinding(kind="discovery", attempt=0, assessment=0, problem="A1")]
    for name, (full, minimal) in levels.items():
        for level, status in (("full", full), ("minimal", minimal)):
            if status != "not_needed":
                found = status == "evidenced_issue"
                attempts.append(AttackAttempt(level=level, number=1, context=f"attacker-{name}-{level}-1", candidate=name, sources=[name],
                                              episode=episodes[len(attempts)], status=status, reproduced=found or None,
                                              assessment=len(attempts), rewards={"reward": 1.0}))
                findings += [AttackFinding(kind="reproduction", candidate=name, sources=[name], attempt=len(attempts) - 1,
                                           assessment=len(attempts) - 1)] * found
    readings = [evidenced(item.episode, f"check-{100 + index}") if item.status == "evidenced_issue"
                else checked(item.episode, f"check-{100 + index}", "summary", "supported", outcome="legitimate") for index, item in enumerate(attempts)]
    run.attack = AttackResult(status="complete", candidates=candidates, attempts=attempts, problems=problems, findings=findings,
                              assessments=readings, discovery={"none": "evidenced_issue"})
    return run.report(selected=["hack", "attack"])


def test_each_problem_has_its_own_level_and_the_judges_same_as_is_only_a_note(tmp_path):
    """A problem's level is the least help under which an Attacker reproduced it, and a no-hint exploit's is 5. The
    judge merges nothing: its `same_as` is a note that changes no level or count. A judge's problem that is none of
    nudi's is a lead. Beneath each problem each hint level Attackers aimed at it shows its attempts."""
    def problems(note):
        return [Problem(id="P1", source="hack inspector", cause="Forge the digest.", findings=["hack-0"], evidence="evidenced"),
                Problem(id="P2", source="hack inspector", cause="Forge it again.", findings=["hack-1"], evidence="evidenced", same_as=note),
                Problem(id="P3", source="hack inspector", cause="Skip the test.", findings=["hack-2"], evidence="evidenced"),
                Problem(id="A1", source="Attacker", cause="Write the score file.", members=["0000-attacker"], same_as=note),
                Problem(id="P5", source="hack inspector", cause="Read the key.", members=["experiment-0009"], evidence="not_reproduced")]

    built = grouped(RunDir(tmp_path / "a"), problems("P1"))
    levels = [(item["id"], item["finding"], item["level"], item["reproduced"], item.get("note")) for item in built["problems"]]
    note = {"target": "P1", "kind": "same_as"}
    assert levels == [("P1", "hack-0", 2, 0, None), ("P2", "hack-1", 4, 2, note), ("P3", "hack-2", 3, 1, None), ("A1", "0000-attacker", 5, None, note)]
    assert built["attack"]["problems"] == built["problems"]
    assert built["attack"]["leads"] == [{"id": "P5", "cause": "Read the key.", "origin": None}]
    again = grouped(RunDir(tmp_path / "b"), problems(None))
    assert [(item["id"], item["level"], item["reproduced"]) for item in again["problems"]] == [row[:1] + row[2:4] for row in levels]
    model = "openai/deepseek/deepseek-v4.1-flash-1017"
    section = report.markdown(built).split("\n## Attack\n")[1].split("\n## ")[0].splitlines()
    p1 = section.index("- P1 from the hack inspector, ●●○○○ reproduced exploit, evidenced in a package sandbox: Forge the digest; findings hack-0 (grader_tampering, check-0000).")
    assert section[p1 + 1:p1 + 3] == [f"  - With full instructions: 0 of 1 attempts reproduced it, {model}, no_evidenced_issue.",
                                      "  - With only a hint: Not run, no reproduction was established with more help."]
    assert ("- P2 from the hack inspector, ●●●●○ exploit executable by learner with hint: Forge it again; "
            "findings hack-1 (grader_tampering, check-0001); possibly the same as P1.") in section
    assert ("- A1 from the Attacker, ●●●●● exploit executable by unaided learner: Write the score file; found in 0000-attacker; "
            "possibly the same as P1.") in section
    assert "- Leads, which no evidence confirmed: P5 (Read the key)." in section
    assert [line.split(":")[0] for line in built["answer"][2:6]] == ["A1", "P2", "P3", "P1"]
    assert built["answer"][2].endswith("; ●●●●● exploit executable by unaided learner; possibly the same as P1.")


def test_an_attacker_case_takes_the_level_of_the_help_its_own_attacker_had(tmp_path):
    """An exploit an Attacker found is its own case at the help its Attacker was given: one found while the Attacker held
    full instructions or a hint for another finding is at that rung and says the rerun of that finding's check did not reproduce it; one a
    no-hint Attacker found is at 5. Its problem is a display group: a later member the judge grouped with it raises
    nothing, and the inspector case those Attackers aimed at keeps its own level."""
    run = RunDir(tmp_path)
    inspected(run)
    reproduced, full, hinted, unaided = (run.episode("attacker", {"reward": 1.0}) for _ in range(4))
    candidate = Candidate(id="hack-0", source="hack_inspector", mechanism="m", outcome="accepted_invalid",
                          guidance={"full": "steps", "minimal": "look"}, conditions={"full": "evidenced_issue", "minimal": "no_evidenced_issue"})
    aimed = {"candidate": "hack-0", "sources": ["hack-0"]}
    attempts = [AttackAttempt(level="full", number=1, context="c0", episode=reproduced, status="evidenced_issue", reproduced=True, assessment=0, **aimed),
                AttackAttempt(level="full", number=2, context="c1", episode=full, status="other_exploit", problem="A1", reproduced=False,
                              assessment=1, **aimed),
                AttackAttempt(level="minimal", number=1, context="c2", episode=hinted, status="other_exploit", problem="A2", reproduced=False,
                              assessment=2, **aimed),
                AttackAttempt(level="none", number=1, context="c3", episode=unaided, status="evidenced_issue", problem="A3", assessment=3)]
    findings = [AttackFinding(kind="reproduction", candidate="hack-0", sources=["hack-0"], attempt=0, assessment=0),
                AttackFinding(kind="other", candidate="hack-0", sources=["hack-0"], attempt=1, assessment=1, problem="A1"),
                AttackFinding(kind="other", candidate="hack-0", sources=["hack-0"], attempt=2, assessment=2, problem="A2"),
                AttackFinding(kind="discovery", attempt=3, assessment=3, problem="A3")]
    problems = [Problem(id="P1", source="hack inspector", cause="Skip the test.", members=["experiment-0000"], findings=["hack-0"], evidence="evidenced"),
                Problem(id="A1", source="Attacker", cause="Hide the module.", members=[full, unaided]),
                Problem(id="A2", source="Attacker", cause="Patch the runner.", members=[hinted, hinted]),
                Problem(id="A3", source="Attacker", cause="Write the score file.", members=[unaided])]
    run.attack = AttackResult(status="complete", candidates=[candidate], attempts=attempts, problems=problems, findings=findings,
                              assessments=[evidenced(item.episode, f"check-{100 + index}") for index, item in enumerate(attempts)],
                              discovery={"none": "evidenced_issue"})

    built = run.report(selected=["hack", "attack"])
    assert [(item["id"], item["finding"], item["level"], item["label"], item["help"]) for item in built["problems"]] == [
        ("P1", "hack-0", 3, "●●●○○ exploit executable by learner with full information", None),
        ("A1", full, 3, "●●●○○ exploit executable by learner with full information", "full instructions"),
        ("A2", hinted, 4, "●●●●○ exploit executable by learner with hint", "only a hint"),
        ("A3", unaided, 5, "●●●●● exploit executable by unaided learner", "no extra information")]
    assert [(item["episode"], item["counts_for"], item["created"]) for item in built["attack"]["attempts"]] == [
        (reproduced, "P1", None), (full, None, "A1"), (hinted, None, "A2"), (unaided, None, "A3")]
    assert built["answer"][2] == ("A3: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-103; with no extra information; "
                                  "●●●●● exploit executable by unaided learner.")
    assert built["answer"][3] == ("A2: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-102; with only a hint while testing hack-0; "
                                  "the rerun of hack-0's check did not reproduce it; ●●●●○ exploit executable by learner with hint.")


def test_a_problem_whose_findings_later_readings_withdrew_is_a_lead(tmp_path):
    """hack-0 evidenced P1, and a later reading of its check read it legitimate, as a run stopped during its hack phase
    may leave it; P2's finding still stands. The report reads the current readings, so P1 is a lead."""
    run = RunDir(tmp_path)
    first, other = evidenced("sandbox-0000", "check-0"), evidenced("sandbox-0000", "check-1")
    run.hack = InspectionResult(mode="hack", status="partial", categories={}, applicability={},
                                assessments=[first, other, first.model_copy(update={"outcome": "legitimate"})])
    run.attack = AttackResult(status="cancelled", discovery={"none": "no_evidenced_issue"}, problems=[
        Problem(id="P1", source="hack inspector", cause="Skip the test.", members=["hack-0"], findings=["hack-0"], evidence="evidenced"),
        Problem(id="P2", source="hack inspector", cause="Forge the digest.", members=["hack-1"], findings=["hack-1"], evidence="evidenced")])
    built = run.report(selected=["hack", "attack"])
    assert [item["id"] for item in built["attack"]["problems"]] == ["P2"]
    assert built["attack"]["leads"] == [{"id": "P1", "cause": "Skip the test.", "origin": None}]


def test_a_problem_whose_findings_are_all_other_names_its_proposed_family(tmp_path):
    """A finding outside every listed family carries the family its reading proposes. Its problem names it, and report.md
    lists such novel families in one line; a run without one has no such line."""
    run = RunDir(tmp_path)
    listed = evidenced("sandbox-0000", "check-1")
    novel = evidenced("sandbox-0000", "check-0")
    novel = novel.model_copy(update={"claim": novel.claim.model_copy(update={"family": "trusted cache file"})})
    problems = [Problem(id="P1", source="hack inspector", cause="Plant the cache.", members=["hack-0"], findings=["hack-0"], evidence="evidenced"),
                Problem(id="P2", source="hack inspector", cause="Forge the digest.", members=["hack-1"], findings=["hack-1"], evidence="evidenced")]
    run.attack = AttackResult(status="cancelled", discovery={"none": "no_evidenced_issue"}, problems=problems)
    run.hack = InspectionResult(mode="hack", status="partial", categories={}, applicability={}, assessments=[novel, listed])
    built = run.report(selected=["hack", "attack"])
    assert [(item["id"], item["family"]) for item in built["attack"]["problems"]] == [("P1", "trusted cache file"), ("P2", None)]
    lines = report.problem_lines(built)
    assert [line for line in lines if line.startswith("Novel families")] == ["Novel families, outside every listed one: P1 (trusted cache file)."]
    assert "Novel families, outside every listed one: P1 (trusted cache file)." in report.markdown(built)
    run.hack = InspectionResult(mode="hack", status="partial", categories={}, applicability={}, assessments=[listed, listed])
    assert not any(line.startswith("Novel families") for line in report.problem_lines(run.report(selected=["hack", "attack"])))


def test_an_attacker_reproduction_of_a_withdrawn_finding_is_its_own_case(tmp_path):
    """A later reading withdrew hack-0, so it is no case. An Attacker's full-instruction exploit aimed at it stands on its
    own evidence, as its own case at full information in hack-0's problem; P2, whose finding was also withdrawn, holds no
    case and is a lead."""
    run = RunDir(tmp_path)
    first, other = packaged("sandbox-0000", "check-0"), packaged("sandbox-0000", "check-1")
    run.record.sandboxes = ["sandbox-0000"]
    run.hack = InspectionResult(mode="hack", status="partial", categories={}, applicability={}, assessments=[
        first, other, first.model_copy(update={"outcome": "legitimate"}), other.model_copy(update={"outcome": "legitimate"})])
    episode = run.episode("attacker", {"reward": 1.0})
    candidate = Candidate(id="hack-0", source="hack_inspector", mechanism="m", outcome="accepted_invalid", guidance={"full": "steps", "minimal": None},
                          conditions={"full": "evidenced_issue", "minimal": "unavailable", "none": "unattempted"})
    attempt = AttackAttempt(level="full", number=1, context="attacker-hack-0-full-1", candidate="hack-0", sources=["hack-0"], episode=episode,
                            status="evidenced_issue", reproduced=True, assessment=0, rewards={"reward": 1.0})
    run.attack = AttackResult(status="complete", candidates=[candidate], attempts=[attempt], discovery={"none": "no_evidenced_issue"},
                              assessments=[evidenced(episode, "check-0100")],
                              findings=[AttackFinding(kind="reproduction", candidate="hack-0", sources=["hack-0"], attempt=0, assessment=0)],
                              problems=[Problem(id="P1", source="hack inspector", cause="Skip the test.", members=["hack-0"], findings=["hack-0"]),
                                        Problem(id="P2", source="hack inspector", cause="Forge the digest.", members=["hack-1"], findings=["hack-1"])])
    built = run.report(selected=["hack", "attack"])
    assert [(item["id"], item["finding"], item["source"], item["level"], item["kind"]) for item in built["problems"]] == [
        ("P1", episode, "Attacker", 3, "reproduction")]
    assert built["attack"]["attempts"][0]["counts_for"] == "P1"
    assert built["attack"]["leads"] == [{"id": "P2", "cause": "Forge the digest.", "origin": None}]


def test_a_no_hint_attempt_aimed_at_a_case_is_listed_apart_and_another_exploit_it_found_is_its_own_case(tmp_path):
    """hack-0's full hint, its single hint and then a no-hint attempt aimed at it reproduced it, so it is at 5, yet no
    independent Attacker found it. The first no-hint attempt aimed at it exploited something its rerun did not show,
    which the judge grouped with P2: its own case at 5, which raises neither hack-0 nor P2's hack-1. Correct work the
    grader fails gets no single hint and no no-hint attempt."""
    run = RunDir(tmp_path)
    inspected(run, 2)
    graded = run.episode(rewards={"reward": 1.0})
    run.label(graded, "legitimate", rejecting("sandbox-0000", "check-0009"))
    run.grader.categories, run.grader.experiments = {"rejected_valid": "evidenced_issue"}, [experiment(9, "rejected_valid", "check-0009")]
    episodes = [run.episode("attacker", {"reward": 1.0}) for _ in range(6)]
    candidates = [Candidate(id="hack-0", source="hack_inspector", mechanism="m", outcome="accepted_invalid", guidance={"full": "steps", "minimal": "look"},
                            conditions={"full": "evidenced_issue", "minimal": "evidenced_issue", "none": "evidenced_issue"}),
                  Candidate(id="grader-0", source="grader_inspector", mechanism="v", outcome="rejected_valid", valid_work=True,
                            guidance={"full": "steps", "minimal": "look"},
                            conditions={"full": "evidenced_issue", "minimal": "not_applicable", "none": "not_applicable"})]
    aimed = [("full", 1, "evidenced_issue"), ("minimal", 1, "evidenced_issue"), ("none", 1, "other_exploit"), ("none", 2, "evidenced_issue")]
    attempts = [AttackAttempt(level=level, number=number, context=f"attacker-hack-0-{level}-{number}", candidate="hack-0", sources=["hack-0"],
                              episode=episodes[index], status=status, reproduced=status == "evidenced_issue", assessment=index, rewards={"reward": 1.0})
                for index, (level, number, status) in enumerate(aimed)]
    attempts.append(AttackAttempt(level="none", number=1, context="attacker-none-none-1", episode=episodes[5], status="no_evidenced_issue"))
    attempts.append(AttackAttempt(level="full", number=1, context="attacker-grader-0-full-1", candidate="grader-0", sources=["grader-0"],
                                  episode=episodes[4], status="evidenced_issue", reproduced=True, assessment=4, rewards={"reward": 0.0}))
    readings = [evidenced(item.episode, f"check-{100 + index}") for index, item in enumerate(attempts[:4])]
    readings.append(evidenced(episodes[4], "check-0104").model_copy(update={"outcome": "rejected_valid"}))
    problems = [Problem(id="P1", source="hack inspector", cause="Skip the test.", members=["hack-0"], findings=["hack-0"], evidence="evidenced"),
                Problem(id="P2", source="hack inspector", cause="Forge the digest.", members=["hack-1"], findings=["hack-1"], evidence="evidenced"),
                Problem(id="G1", source="grader inspector", cause="Reject zeros.", members=["grader-0"], findings=["grader-0"], evidence="evidenced"),
                Problem(id="A1", source="Attacker", cause="Forge the digest.", members=[episodes[2]], same_as="P2")]
    findings = [AttackFinding(kind="other" if index == 2 else "reproduction", candidate="hack-0", sources=["hack-0"], attempt=index,
                              assessment=index, problem="A1" if index == 2 else None) for index in range(4)]
    findings.append(AttackFinding(kind="reproduction", candidate="grader-0", sources=["grader-0"], attempt=5, assessment=4))
    run.attack = AttackResult(status="partial", candidates=candidates, attempts=attempts, problems=problems, findings=findings,
                              assessments=readings, discovery={"none": "no_evidenced_issue"})

    built = run.report()
    assert [(item["id"], item["finding"], item["level"], item.get("note")) for item in built["problems"]] == [
        ("P1", "hack-0", 5, None), ("P2", "hack-1", 2, None), ("G1", "grader-0", 3, None),
        ("A1", episodes[2], 5, {"target": "P2", "kind": "same_as"})]
    model = "openai/deepseek/deepseek-v4.1-flash-1017"
    section = report.markdown(built).split("\n## Attack\n")[1].split("\n## ")[0].splitlines()
    at = section.index(f"  - With full instructions: 1 of 1 attempts reproduced it, {model}, evidenced_issue.")
    assert section[at + 1:at + 3] == [
        f"  - With only a hint: 1 of 1 attempts reproduced it, {model}, evidenced_issue.",
        f"  - With no extra information, aimed at it: 1 of 2 attempts reproduced it, {model}, evidenced_issue."]
    g1 = section.index(next(line for line in section if line.startswith("- G1 ")))
    assert section[g1 + 1:g1 + 4] == [
        f"  - With full instructions: 1 of 1 attempts reproduced it, {model}, evidenced_issue.",
        "  - With only a hint: Not attempted, no hint for correct work.",
        "  - With no extra information, aimed at it: Not attempted, no hint for correct work."]
    line = next(line for line in built["answer"] if line.startswith("A1: "))
    assert line == ("A1: requirement \"Write the explanation file\"; reward 1; exists = false measured by check check-102; with no extra information while testing hack-0; "
                    "the rerun of hack-0's check did not reproduce it; ●●●●● exploit executable by unaided learner; possibly the same as P2.")


def test_a_case_without_an_attack_candidate_says_no_attempt_was_assessed(tmp_path):
    """The hacking analysis attacks only during the hack phase, which takes no finding without guidance, so such a
    case has no attack candidate, and neither has a guided finding after a stop: no attempt was assessed."""
    run = RunDir(tmp_path)
    guided, unguided = evidenced("sandbox-0000", "check-0"), evidenced("sandbox-0000", "check-1")
    guided.claim.full_guidance = "Write the reward file."
    run.hack = InspectionResult(mode="hack", status="complete", categories={}, applicability={}, assessments=[guided, unguided])
    run.attack = AttackResult(status="complete", discovery={"none": "no_evidenced_issue"}, problems=[
        Problem(id="P1", source="hack inspector", cause="Skip the test.", members=["experiment-0001"], findings=["hack-1"], evidence="evidenced"),
        Problem(id="P2", source="hack inspector", cause="Forge the digest.", members=["experiment-0000"], findings=["hack-0"], evidence="evidenced")])
    built = run.report(selected=["hack", "attack"])
    assert [(item["id"], item["finding"], item["conditions"], item["attempts"]) for item in built["problems"]] == [
        ("P2", "hack-0", [], 0), ("P1", "hack-1", [], 0)]
    assert all(line.endswith("; no attempt was assessed.") for line in built["answer"][2:4])


def test_limits_retained_in_older_records_render_without_their_verdicts(tmp_path):
    """The report is built anew, but the limits of older inspection and attack records, as a rerun copies, are kept."""
    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status="complete", categories={"grader_tampering": "unknown"}, applicability={},
                                limits=["hack inspection stopped (cancelled) before every session of grader_tampering ended, so they are unknown"])
    attacked(run)
    run.attack.limits.append("Unsupported candidates and zero evidenced successes do not establish that the task is safe.")
    text = report.markdown(run.report())
    assert "before every session of grader_tampering ended" in text
    for word in ("task is safe", "so they are unknown"):
        assert word not in text


def test_search_scope_keeps_attempts_exclusions_and_legacy_reasons(tmp_path):
    run = RunDir(tmp_path)
    run.hack = InspectionResult(
        mode="hack", status="partial",
        categories={"grader_tampering": "no_evidenced_issue", "online_lookup": "unknown", "persistence": "restricted"},
        applicability={"persistence": "the task resets nothing between episodes"},
        attempts=[InspectionAttempt(phase="focused", number=1, category="grader_tampering", status="no_evidenced_issue")],
        limits=["Search stopped at the spending cap."])
    text = report.markdown(run.report(selected=["hack"]))
    assert "- hack_inspector: grader_tampering\n" in text
    assert "online_lookup: no focused attempt or experiment recorded" in text
    assert "persistence: the task resets nothing between episodes" in text
    assert "focused attempt 1 (grader_tampering): completed" in text
    assert "Search stopped at the spending cap." in text
    for verdict in ("no_evidenced_issue", "is unknown", "is restricted"):
        assert verdict not in text


def test_a_broad_attempt_alone_searches_no_category_and_measured_work_does():
    section = {"categories": {"online_lookup": "unknown", "persistence": "restricted"},
               "attempts": [{"phase": "broad", "status": "no_evidenced_issue"}]}
    assert report.search_scope(section) == []
    section["experiments"] = [{"category": "persistence"}]
    assert report.search_scope(section) == ["persistence"]


def test_the_answer_opens_with_how_the_run_ended_in_plain_words(tmp_path):
    """The first line says how the run ended; `status` and the exit code keep saying it for scripts."""
    run = RunDir(tmp_path)
    run.record.started_at, run.record.ended_at = "2026-01-01T10:00:00+00:00", "2026-01-01T11:05:59+00:00"
    assert run.report()["outcome"] == run.report()["answer"][0] == "Finished. Every step ran."
    run.record.failed_phases = ["simulation"]
    run.record.warnings = ["cancelled during grader"]
    assert run.report()["answer"][0] == ("Stopped by you after 1:05; before that the Simulator failed. "
                                         "Results below are what was found so far.")
    run.record.warnings, run.record.failed_phases, run.record.time_limit_reached = [], [], True
    built = run.report()
    assert (built["answer"][0], built["status"]) == ("Stopped at your time limit after 1:05. Results below are what was found so far.",
                                                     "time_limit")
    run.record.time_limit_reached, run.record.simulation, run.record.warnings = False, None, ["hack stopped: Docker is unavailable"]
    assert run.report(selected=["hack"])["answer"][0] == "Could not start: Docker is unavailable."


# `nudi report RUN_DIR`: the report again from a run's records, such as after the process was killed.


def logged(run: RunDir, *events: dict) -> None:
    (run.path / "events.jsonl").write_text("".join(json.dumps(item) + "\n" for item in events))


def ended_pid() -> int:
    process = subprocess.Popen([sys.executable, "-c", ""])
    process.wait()
    return process.pid


def test_a_report_so_far_says_the_run_is_still_running_and_names_no_gap_yet(tmp_path):
    """While the run goes, an analysis still running or without a record yet is no warning: the run has not ended."""
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.record.simulation.status = "running"
    run.hack = InspectionResult(mode="hack", status="running", categories={"package_oracles": "pending"}, applicability={})
    run.save()
    report.write(run.path, selected=["simulation", "hack", "attack"], running=True)
    built = json.loads((run.path / "report.json").read_text())
    assert built["status"] == "running" and built["analyses"] == {"simulation": "running", "hack": "running", "attack": "not started"}
    assert built["outcome"] == "Still running. Results below are what was found so far; the final report replaces this one."
    assert not [warning for warning in built["warnings"] if "simulation" in warning or "hack" in warning or "attack" in warning]


def test_nudi_report_on_a_killed_run_replaces_its_report_so_far_with_a_stopped_one(tmp_path, capsys):
    """A run killed after a confirmation leaves a report with status `running`; `nudi report` says it stopped."""
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.record.simulation.status = "running"
    run.save()
    report.write(run.path, selected=["simulation"], running=True)
    logged(run, {"kind": "run_start", "pid": ended_pid(), "analyses": ["simulation"]})
    assert cli.main(["report", str(run.path)]) == 1
    built = json.loads((run.path / "report.json").read_text())
    assert built["status"] == "stopped" and built["unfinished"] == {"simulation": "running"}
    assert capsys.readouterr().out.startswith("# nudi report\n\n## Answer\n\n- Stopped: the nudi process ended without closing out")


def test_one_report_so_far_of_a_large_run_builds_within_a_second(tmp_path):
    """Each confirmation rebuilds the report on the event loop, so one build of a run larger than a long measured one,
    with 60 ordinary episodes, 3000 model calls and 60 Attacker attempts, takes under a second; a slower build would need
    fewer rebuilds."""
    run = RunDir(tmp_path)
    for index in range(60):
        name = run.episode(rewards={"reward": float(index % 2)})
        run.label(name, "unknown", checked(name, f"check-{name}", "sorted", "violated" if index % 2 else "supported",
                                           basis=basis("supported", ["sorted"], [f"check-{name}"])))
    run.hack = InspectionResult(mode="hack", status="complete", categories={"package_oracles": "evidenced_issue"}, applicability={},
                                assessments=[evidenced(name, f"hack-check-{index}") for index, name in enumerate(run.record.episodes)])
    attempts = []
    for index in range(60):
        name = run.episode("attacker", {"reward": 1.0})
        attempts.append(AttackAttempt(level="full", number=1, context=f"attacker-hack-{index}-full-1", episode=name, rewards={"reward": 1.0},
                                      status="evidenced_issue", assessment=index))
    run.attack = AttackResult(status="running", attempts=attempts,
                              assessments=[evidenced(item.episode, f"attack-check-{index}") for index, item in enumerate(attempts)])
    run.record.calls = [CallRecord(role="inspector", episode=run.record.episodes[index % 120], model="openai/gpt-test", cost=0.001,
                                   cost_source="litellm", prompt_tokens=1000, completion_tokens=100) for index in range(3000)]
    run.save()
    started = time.perf_counter()
    report.write(run.path, running=True)
    took = time.perf_counter() - started
    assert json.loads((run.path / "report.json").read_text())["status"] == "running"
    assert took < 1, f"one report build took {took:.2f} s"


def test_nudi_report_says_a_killed_run_stopped_without_closing_out(tmp_path, monkeypatch, capsys):
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.record.simulation.status = "complete"
    run.hack = InspectionResult(mode="hack", status="running", categories={"package_oracles": "pending"}, applicability={})
    run.record.warnings = [f"provider echoed {SECRET}"]
    run.save()
    monkeypatch.setenv(run.record.models["inspector"].key_name(), SECRET)
    # The process died mid-write: its last line is cut, and no run_end follows.
    logged(run, {"kind": "run_start", "pid": ended_pid(), "analyses": ["simulation", "hack", "attack"]})
    with (run.path / "events.jsonl").open("a") as log:
        log.write('{"kind": "phase_')
    assert not (run.path / "report.json").exists()

    assert cli.main(["report", str(run.path)]) == 1
    built = json.loads((run.path / "report.json").read_text())
    assert built["status"] == "stopped" and built["schema_version"] == report.SCHEMA_VERSION
    assert built["outcome"] == "Stopped: the nudi process ended without closing out the run. Results below are what was found so far."
    assert built["unfinished"] == {"hack": "running", "attack": "not run"}
    assert capsys.readouterr().out == (run.path / "report.md").read_text()
    assert SECRET not in (run.path / "report.json").read_text() + (run.path / "report.md").read_text()


def test_nudi_report_rebuilds_an_ended_run_and_refuses_a_running_one(tmp_path, capsys):
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.save()
    logged(run, {"kind": "run_start", "pid": os.getpid(), "analyses": ["simulation"]})
    assert cli.main(["report", str(run.path)]) == 2
    assert capsys.readouterr().err == f"nudi: nudi (pid {os.getpid()}) is still running this run; it writes the report when it ends\n"
    assert not (run.path / "report.json").exists()

    logged(run, {"kind": "run_start", "pid": os.getpid(), "analyses": ["simulation"]}, {"kind": "run_end", "status": "complete"})
    assert cli.main(["report", str(run.path)]) == 0
    assert json.loads((run.path / "report.json").read_text())["status"] == "complete"
    assert cli.main(["report", str(tmp_path / "missing")]) == 2
    # A pid on another host cannot be checked, so that run counts as ended.
    logged(run, {"kind": "run_start", "pid": os.getpid(), "host": "another-host", "analyses": ["simulation"]})
    assert cli.main(["report", str(run.path)]) == 1
    assert json.loads((run.path / "report.json").read_text())["status"] == "stopped"


def test_a_problem_names_every_inspector_whose_finding_it_holds():
    """A member names its inspector: a hack inspector finding, `hack-N`, or an older run's hack inspector experiment, and
    a grader inspector finding."""
    for member in ("hack-3", "experiment-0003"):
        assert report.problem_sources({"source": "grader inspector", "members": ["grader-0", member]}) == (
            "the grader inspector and the hack inspector")


def test_the_report_states_its_elapsed_time_and_why_it_stopped_as_data(tmp_path):
    """Beside the outcome's words: the seconds the run took, null in a record without both times, and the stop's kind,
    analysis, time limit and the reason `nudi report` gives or the provider's account refusal, null for a run that ended on its own."""
    run = RunDir(tmp_path)
    built = run.report()
    assert (built["elapsed"], built["stop"]) == (None, None)
    run.record.started_at, run.record.ended_at = "2026-01-01T10:00:00+00:00", "2026-01-01T11:05:59+00:00"
    assert run.report()["elapsed"] == 3959
    for warning, kind in (("cancelled during grader", "cancelled"), ("stopped by a termination signal during grader", "terminated")):
        run.record.warnings = [warning]
        assert run.report()["stop"] == {"kind": kind, "phase": "grader", "minutes": None, "reason": None}
    assert run.report(stop="the run was interrupted")["stop"]["reason"] == "the run was interrupted"
    run.record.warnings, run.record.time_limit_reached = ["the run stopped at its time limit of 0.5 minutes during attack"], True
    assert run.report()["stop"] == {"kind": "time_limit", "phase": "attack", "minutes": 0.5, "reason": None}
    run.record.warnings = []
    assert run.report()["stop"] == {"kind": "time_limit", "phase": None, "minutes": None, "reason": None}
    run.record.time_limit_reached, run.record.simulation.status = False, "spending_exhausted"
    assert run.report()["stop"] == {"kind": "spending_cap", "phase": "simulation", "minutes": None, "reason": None}
    assert run.report(stop="the run stopped")["stop"] == {"kind": "stopped", "phase": None, "minutes": None, "reason": "the run stopped"}
    run.record.stop_reason = "the model provider refused a call of the attacker: insufficient_quota"
    built = run.report()
    assert (built["status"], built["stop"]) == ("stopped", {"kind": "provider_refused", "phase": None, "minutes": None,
                                                            "reason": run.record.stop_reason})


def test_each_analysis_that_raised_keeps_its_error_as_data(tmp_path):
    run = RunDir(tmp_path)
    run.record.failed_phases = ["simulation", "hack"]
    run.record.warnings = ["simulation failed: RuntimeError: boom", "hack stopped: Docker is unavailable",
                           "the attack during the hack inspection stopped: RuntimeError: late"]
    assert run.report()["phase_errors"] == {"simulation": "RuntimeError: boom", "hack": "Docker is unavailable"}


def test_a_judges_problem_that_is_no_problem_of_nudis_is_a_lead_and_unjudged_findings_are_listed_by_id(tmp_path):
    """A judge's problem whose Attacker episode only reproduced an inspector's problem is none of nudi's, so it is a
    lead. Inspector findings that the judge placed in no problem keep their own ids and are listed."""
    run = RunDir(tmp_path)
    answered(run)
    run.attack.problems = [Problem(id="P2", source="hack inspector", cause="A bash shim.", findings=["hack-1"], evidence="evidenced"),
                           Problem(id="P3", source="hack inspector", cause="Leading zeros.", findings=["hack-2"], evidence="evidenced"),
                           Problem(id="A1", source="Attacker", cause="A shim found alone.", members=["0001-attacker"],
                                   cases=[{"id": "0001-attacker", "outcome": "accepted_invalid"}])]
    result = run.report()
    assert [(item["id"], item["finding"]) for item in result["attack"]["problems"]] == [
        ("P2", "hack-1"), ("P3", "hack-2"), ("grader-0", "grader-0"), ("grader-1", "grader-1")]
    assert [item["id"] for item in result["attack"]["leads"]] == ["A1"]
    assert result["ungrouped"] == ["grader-0", "grader-1"]
    run.attack = None
    (run.path / "attack.json").unlink()
    assert run.report()["ungrouped"] == ["hack-1", "hack-2", "grader-0", "grader-1"]


def test_each_ordinary_group_keeps_every_episode_reward_with_null_for_a_value_that_is_not_finite(tmp_path):
    run = RunDir(tmp_path)
    one, other = run.episode(rewards={"reward": 1.0}), run.episode(rewards={"reward": float("nan"), "tests": 0.5})
    (group,) = run.report()["ordinary"]["groups"]
    assert group["episode_rewards"] == {one: {"reward": 1.0}, other: {"reward": None, "tests": 0.5}}


def test_a_replaced_experiment_is_read_through_its_replacement_as_open_reads_it():
    """An experiment a later one names in `replaces` is superseded by that one's reading, so it is no current finding
    and no suspected exploit; without the replacement both stay current."""
    unknown = Assessment(claim=Claim(mechanism="unclear", episode="case", check="check-0"), outcome="unknown", execution_scope="package")
    legitimate = Assessment(claim=Claim(mechanism="graded fix", episode="case", check="check-1"), outcome="legitimate", execution_scope="package")
    for replaces, superseded in (("experiment-0000", {"index": 1, "result": "legitimate"}), (None, None)):
        rows = [{"id": "experiment-0000", "category": "package_oracles", "status": "assessed", "check": "check-0", "assessment": 0, "package": True},
                {"id": "experiment-0001", "category": "package_oracles", "status": "assessed", "check": "check-1", "assessment": 1, "package": True,
                 **({"replaces": replaces} if replaces else {})}]
        result = InspectionResult(mode="hack", status="complete", categories={"package_oracles": "no_evidenced_issue"}, applicability={},
                                  assessments=[unknown, legitimate], experiments=rows)
        shown = report.inspection("hack", result, [])
        assert shown["findings"]["inconclusive"][0]["superseded_by"] == superseded
        assert shown["suspected"] == ([] if replaces else [{"category": "package_oracles", "check": "check-0"}])


def test_a_replacement_answers_only_an_open_reading_of_its_own_scope_once_it_has_a_reading():
    """`replaces` answers an earlier experiment only when the replacement has a reading, both measure the same native
    episode or both are package experiments, and the earlier reading is not evidenced; a missing episode matches nothing.
    The report then never lets a replacement withdraw an evidenced reading."""
    def reading(check, outcome):
        return Assessment(claim=Claim(mechanism="read", episode="case", check=check), outcome=outcome, execution_scope="package")

    def answered(earlier, later, outcome="unknown", assessments=None):
        rows = [{"id": "experiment-0000", "status": "incomplete", "check": "check-0", **earlier},
                {"id": "experiment-0001", "status": "assessed", "check": "check-1", "replaces": "experiment-0000", **later}]
        return inspection.replaced(rows, [reading("check-0", outcome), reading("check-1", "legitimate")] if assessments is None else assessments)

    assert answered({"episode": "0000-simulator"}, {"episode": "0000-simulator"}) == {"experiment-0000", "check-0"}
    assert answered({"package": True, "episode": "package-a"}, {"package": True, "episode": "package-b"}) == {"experiment-0000", "check-0"}
    assert answered({"episode": "0000-simulator"}, {"episode": "0001-simulator"}) == set()
    assert answered({}, {"episode": "0000-simulator"}) == set()
    found = evidenced("case", "check-0")
    found.execution_scope = "package"
    assert answered({"episode": "0000-simulator"}, {"episode": "0000-simulator"}, assessments=[found, reading("check-1", "legitimate")]) == set()
    # A strong outcome without marks is no evidenced reading, so a replacement answers it.
    assert answered({"episode": "0000-simulator"}, {"episode": "0000-simulator"}, outcome="accepted_invalid") == {"experiment-0000", "check-0"}
    assert answered({"episode": "0000-simulator"}, {"episode": "0000-simulator", "status": "running"}, assessments=[reading("check-0", "unknown")]) == set()
    rows = [{"id": "experiment-0000", "category": "package_oracles", "status": "assessed", "check": "check-0", "assessment": 0, "package": True},
            {"id": "experiment-0001", "category": "package_oracles", "status": "assessed", "check": "check-1", "assessment": 1, "package": True,
             "replaces": "experiment-0000"}]
    result = InspectionResult(mode="hack", status="complete", categories={"package_oracles": "evidenced_issue"}, applicability={},
                              assessments=[found, reading("check-1", "legitimate")], experiments=rows)
    shown = report.inspection("hack", result, [])
    assert [(item["index"], item["superseded_by"]) for item in shown["findings"]["evidenced"]] == [(0, None)]


def test_correct_work_no_attacker_reproduced_says_where_it_was_shown(tmp_path):
    """A valid-work case no Attacker reproduced was shown only where its reading was evidenced; a reproduced one keeps
    its label alone."""
    run = RunDir(tmp_path)
    answered(run)
    lines = run.report()["answer"]
    assert any(line.startswith("grader-1: ") and line.endswith("; Correct work failed, evidenced in a package sandbox; no attempt was assessed.")
               for line in lines)
    assert any(line.startswith("hack-2: ") and "; Correct work failed, reproduced by an Attacker with full instructions; " in line for line in lines)


def test_the_legend_says_when_inspector_findings_joined_an_attacker_problem():
    """An A problem an Attacker found first can gain inspector findings later; the legend then names it."""
    alone = {"id": "A1", "source": "Attacker", "findings": []}
    joined = {"id": "A2", "source": "Attacker", "findings": ["hack-0"]}
    assert report.legend([alone])[0].endswith("A: found by an Attacker, not among the inspectors' findings.")
    legend = report.legend([alone, joined])[0]
    assert "not among the inspectors' findings" not in legend
    assert legend.endswith("A: first found by an Attacker; inspector findings joined A2 later.")


def failing(tmp_path, attempts=(), experiments=(), hack_attempts=(), hack_status="complete"):
    """A run whose attack and hack inspection have these attempts and experiments, every category settled."""
    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status=hack_status, categories={"package_oracles": "no_evidenced_issue"}, applicability={},
                                attempts=list(hack_attempts), experiments=list(experiments))
    run.attack = AttackResult(status="partial" if attempts else "complete", attempts=list(attempts))
    for attempt in attempts:
        assert run.episode("attacker", attempt.rewards) == attempt.episode
    return run.report(selected=["hack", "attack"])["answer"][0]


def test_a_grader_that_wrote_no_reward_is_named_and_no_failure_to_run(tmp_path):
    """An Attacker that worked in an episode whose grader wrote no reward did not fail to run; the attack's unresolved
    evidence says what happened."""
    attempts = [AttackAttempt(level="none", number=1, context="attacker-none-1", episode="0000-attacker", status="no_reward",
                              error="the grader wrote no reward in 0000-attacker: RewardFileNotFoundError: no file")]
    assert failing(tmp_path, attempts) == ("Finished. Every step ran. Evidence stayed unresolved in the attack (the grader wrote no "
                                           "reward in 0000-attacker), so the run may miss more.")


def test_a_simulator_episode_that_never_started_is_named_with_its_reason_and_claims_no_reward(tmp_path):
    """One line names the episode and why; the ordinary rewards section claims no retained reward it does not have, and
    a replaced episode names the fresh attempt that took its place."""
    run = RunDir(tmp_path)
    setup = ErrorRecord(type="RuntimeError", message="Failed to start tmux session.\nError: tmux: command not found\n")
    replaced = run.episode(rewards={}, errors=[setup])
    run.record.simulation.episodes.remove(replaced)
    run.record.simulation.requested -= 1
    first, retry = run.episode(rewards={"reward": 1.0}), run.episode(rewards={}, errors=[setup])
    run.record.simulation.retries = {retry: replaced}
    run.record.simulation.status, run.record.failed_phases = "partial", ["simulation"]
    result = run.report(selected=["simulation"])
    assert result["answer"][0] == (f"Finished with gaps: 1 of 2 Simulator episodes did not start: {retry} (RuntimeError: Failed to "
                                   "start tmux session. Error: tmux: command not found). Results below are what was found.")
    text = report.markdown(result)
    assert (f"- {replaced} recorded RuntimeError: Failed to start tmux session. Error: tmux: command not found; it made no model call, "
            f"so {retry} replaced it") in text
    assert f"- {retry} recorded RuntimeError: Failed to start tmux session. Error: tmux: command not found; it has no reward" in text
    assert first not in result["ordinary"]["no_reward"]


def test_a_lead_whose_reason_starts_with_its_id_names_it_once():
    item = {"open": [{"id": "experiment-0025", "category": "grader_tampering",
                      "reason": "experiment-0025: its episode has no native reward to compare"}], "findings": {"legitimate": []}}
    assert report.still_open("hack_inspector", item) == [
        "- hack_inspector grader_tampering leads: experiment-0025: its episode has no native reward to compare"]


def test_failed_attempts_of_one_session_are_numbered_in_one_clause(tmp_path):
    attempts = [InspectionAttempt(phase="focused", category="package_oracles", number=1, status="inference_failure", error="slow"),
                InspectionAttempt(phase="focused", category="package_oracles", number=2, status="out_of_memory", error="oom")]
    assert failing(tmp_path, hack_attempts=attempts) == (
        "Finished, but work was lost: the hack inspector's focused session of package_oracles failed in attempt 1 (inference_failure) "
        "and attempt 2 (out_of_memory). Results below are what was found.")


def test_the_headline_names_the_agent_that_failed_and_the_work_lost(tmp_path):
    """Each failure is named by its agent: an Attacker that failed to run, an attack inspector that failed on a rewarded
    episode, a hack inspector experiment or session; a recovered failure is still lost work, so the run never reads
    as one where every step ran."""
    attempts = [AttackAttempt(level="none", number=1, context="attacker-none-1", episode="0000-attacker", status="episode_failure",
                              failed="Attacker", error="the Attacker failed: the episode ended without a reward: RuntimeError"),
                AttackAttempt(level="none", number=2, context="attacker-none-2", episode="0001-attacker", status="tool_failure",
                              failed="attack inspector", rewards={"reward": 1.0}, error="the attack inspector failed: probe")]
    headline = failing(tmp_path / "attack", attempts)
    assert headline == ("Finished with gaps: the Attacker failed to run in 0000-attacker; the attack inspector failed on 0001-attacker, "
                        "its reward kept. Results below are what was found.")
    broad = InspectionAttempt(phase="broad", number=1, status="out_of_memory", error="out of memory")
    focused = InspectionAttempt(phase="focused", category="package_oracles", number=1, status="out_of_memory", error="experiment-0001: oom")
    later = InspectionAttempt(phase="focused", category="package_oracles", number=2, status="no_evidenced_issue")
    rows = [{"id": "experiment-0001", "category": "package_oracles", "status": "out_of_memory", "error": "experiment-0001: oom"}]
    assert failing(tmp_path / "hack", hack_attempts=[broad, focused, later], experiments=rows) == (
        "Finished, but work was lost: the hack inspector's broad session failed (out_of_memory); a hack inspector experiment "
        "failed: experiment-0001 (out_of_memory). Results below are what was found.")


def test_correct_work_failed_needs_an_approved_list_every_requirement_of_which_its_reading_reads_supported(tmp_path):
    """Rejected work its check measured is a problem with its level whatever the list. Only its words depend on the list:
    "Correct work failed" and its type need the reading to read every approved requirement supported; otherwise it is
    work the grader failed, with why completeness is unknown, and the headline names no misjudged work."""
    sorted_list = [Requirement(text="Write the numbers sorted", observation="sorted")]
    for requirements, measured, reason in ((None, {"sorted": True}, inspection.NO_LIST), (sorted_list, {"exists": True}, inspection.NOT_ALL),
                                           (sorted_list, {"sorted": True}, None)):
        run = RunDir(tmp_path / str(len(list(tmp_path.iterdir()))))
        run.record.requirements = requirements
        graded = run.episode(rewards={"reward": 0.0})
        rejected = checked(graded, "check-0000", "sorted", "supported", outcome="rejected_valid")
        rejected.discrepancy, rejected.reward, rejected.check.output = "under", 0.0, json.dumps({"observations": measured})
        rejected.claim.marks = list(measured)
        rejected.claim.derivation.observations = list(measured)
        run.label(graded, "rejected_valid", rejected)
        run.grader.categories = {"accepted_invalid": "no_evidenced_issue", "rejected_valid": "evidenced_issue"}
        run.grader.experiments = [experiment(0, "rejected_valid", "check-0000")]
        built = run.report(selected=["grader"])
        observed = ", ".join(f"{key} = true" for key in measured)
        if reason is None:
            assert built["answer"][1] == "The grader misjudges work."
            assert [(item["level"], item["label"], item["type"]) for item in built["problems"]] == [(2, "Correct work failed", "false_negative")]
            continue
        assert built["answer"][1:3] == [report.UNCONFIRMED,
                                        f"grader-0: reward 0; {observed} measured by check check-0000; Work the grader failed, "
                                        f"evidenced in a native episode; {reason}."]
        assert [(item["id"], item["type"], item["level"], item["reason"]) for item in built["problems"]] == [("grader-0", None, 2, reason)]
        assert "orrect work failed" not in report.markdown(built).split("## Metrics")[0]


def test_a_reading_without_marks_is_a_scoped_fact_and_one_with_marks_is_a_problem_whatever_the_list(tmp_path):
    """A strong reading whose check measured its marks is a problem, and an Attacker reproduction counts for it, whether or
    not an approved list names a requirement it reads violated; only its type and the headline need the list. A strong
    reading without marks is printed as a scoped fact."""
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    route, trust, bare = evidenced(graded, "check-0000"), evidenced(graded, "check-0001"), evidenced(graded, "check-0002")
    bare.claim.marks = []
    attacker = run.episode("attacker", {"reward": 1.0})
    run.hack = InspectionResult(mode="hack", status="complete", categories={"online_lookup": "evidenced_issue", "grader_tampering": "evidenced_issue"},
                                applicability={}, assessments=[route, trust, bare],
                                experiments=[experiment(0, "online_lookup", "check-0000"), experiment(1, "grader_tampering", "check-0001"),
                                             experiment(2, "grader_tampering", "check-0002")])
    run.attack = AttackResult(status="complete", discovery_attempts=0, candidates=[Candidate(
        id="hack-0", mechanism="m", guidance={"full": "steps"}, conditions={"full": "evidenced_issue"})],
        attempts=[AttackAttempt(level="full", number=1, context="c0", candidate="hack-0", sources=["hack-0"], episode=attacker,
                                status="evidenced_issue", reproduced=True, rewards={"reward": 1.0}, assessment=0)],
        findings=[AttackFinding(kind="reproduction", candidate="hack-0", sources=["hack-0"], attempt=0, assessment=0)],
        assessments=[evidenced(attacker, "check-0003")])
    for requirements, kind in ((None, None), ([Requirement(text="Write the numbers sorted", observation="exists")], "hack")):
        run.record.requirements = requirements
        built = run.report(selected=["hack", "attack"])
        assert [(item["id"], item["type"], item["level"]) for item in built["problems"]] == [
            ("hack-0", kind, 3), ("hack-1", kind, 2), ("hack-2", None, None)]
        assert built["attack"]["attempts"][0]["counts_for"] == "hack-0"
        assert built["answer"][1] == (report.UNCONFIRMED if kind is None else "The grader can be cheated.")
        assert f"{graded}, check check-0002: reward 1, above the score its check measured; observed exists = false; {report.NO_MARKS}." in built["answer"]


def test_readings_without_marks_alone_are_named_in_the_headline(tmp_path):
    """With only readings that claim an exploit without marks, the headline says no cheat was evidenced and that the lines
    below claim one without an observation that shows it."""
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    bare = evidenced(graded, "check-0000")
    bare.claim.marks = []
    run.hack = InspectionResult(mode="hack", status="complete", categories={"grader_tampering": "unknown"}, applicability={},
                                assessments=[bare], experiments=[experiment(0, "grader_tampering", "check-0000")])
    answer = run.report(selected=["hack"])["answer"]
    assert answer[1:] == [report.UNMARKED,
                          f"{graded}, check check-0000: reward 1, above the score its check measured; observed exists = false; {report.NO_MARKS}."]


def test_a_reproduction_of_a_later_reading_of_a_fed_check_counts_for_that_readings_problem(tmp_path):
    """hack-0 was fed and a later reading of its check, hack-1, stood when its Attacker started; that attempt names hack-1,
    and its confirmed reproduction counts for hack-1 at the attempt's level, with no Attacker problem of its own."""
    run = RunDir(tmp_path)
    first = evidenced("sandbox-0000", "check-0000")
    run.hack = InspectionResult(mode="hack", status="complete", categories={}, applicability={}, assessments=[first, first.model_copy()])
    attacker = run.episode("attacker", {"reward": 1.0})
    run.attack = AttackResult(status="complete", discovery_attempts=0, candidates=[Candidate(
        id="hack-0", mechanism="m", guidance={"full": "steps"}, conditions={"full": "evidenced_issue"})],
        attempts=[AttackAttempt(level="full", number=1, context="c0", candidate="hack-0", sources=["hack-1"], episode=attacker,
                                status="evidenced_issue", reproduced=True, rewards={"reward": 1.0}, assessment=0)],
        findings=[AttackFinding(kind="reproduction", candidate="hack-0", sources=["hack-1"], attempt=0, assessment=0)],
        assessments=[evidenced(attacker, "check-0100")])
    built = run.report(selected=["hack", "attack"])
    assert [(item["id"], item["level"], item["reproduced"]) for item in built["problems"]] == [("hack-1", 3, 1)]
    assert built["attack"]["attempts"][0]["counts_for"] == "hack-1" and built["attack"]["attempts"][0]["created"] is None


def test_a_valid_work_attempt_keeps_an_exploit_a_later_reading_of_another_check_does_not_withdraw(tmp_path):
    """Testing valid work, the attack inspector evidenced an exploit with one check and then read another check legitimate;
    the exploit is the latest reading of its own check, so it stays the attempt's problem."""
    run = RunDir(tmp_path)
    attacker = run.episode("attacker", {"reward": 1.0})
    exploit, honest = evidenced(attacker, "check-0000"), evidenced(attacker, "check-0001")
    honest.outcome = "legitimate"
    run.attack = AttackResult(status="complete", discovery_attempts=0, candidates=[Candidate(
        id="valid-0", guidance={"full": "write it"}, valid_work=True, conditions={"full": "no_evidenced_issue"})],
        attempts=[AttackAttempt(level="full", number=1, context="c0", candidate="valid-0", sources=["valid-0"], episode=attacker,
                                status="no_evidenced_issue", rewards={"reward": 1.0}, assessment=1)],
        assessments=[exploit, honest])
    built = run.report()
    assert [(item["id"], item["check"], item["level"]) for item in built["problems"]] == [(attacker, "check-0000", 3)]
    assert built["answer"][1] == "The grader can be cheated."


def test_an_empty_approved_list_is_no_list(tmp_path):
    """No requirement read supported makes no work complete: an empty list is refused as a record and reads unknown."""
    assert inspection.correctness([], []) == ("unknown", inspection.NO_LIST)
    with pytest.raises(ValidationError):
        RunRecord.model_validate({**RunDir(tmp_path).record.model_dump(mode="json"), "requirements": []})


def test_complete_work_in_the_metrics_needs_the_approved_list(tmp_path):
    """Correct work passed and correct work failed count complete work, so without the list no episode is complete."""
    run = RunDir(tmp_path)
    run.record.requirements = None
    name = run.episode(rewards={"reward": 1.0})
    run.label(name, "unknown", checked(name, f"check-{name}", "sorted", "supported", basis=basis("supported", ["sorted"], [f"check-{name}"])))
    entry = run.report(selected=["grader"])["metrics"]["episodes"][name]
    assert entry["completion"] == "unknown" and entry["completion_reasons"][-1] == inspection.NO_LIST
