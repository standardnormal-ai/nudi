"""JSON and Markdown reports: provenance, attempts, coverage and redaction."""

import json

import pytest

from nudi import report
from nudi.assessment import CHECK_LIMIT
from nudi.checks import (DISABLED_LIMIT, SAFETY_LIMIT, TIMING_LIMIT, AttackAttempt, AttackFinding, AttackResult, Candidate, InspectionAttempt,
                         InspectionResult, OrdinaryReview)
from nudi.records import Assessment, CallRecord, Claim, Derivation, ErrorRecord, PersistenceProbe
from test_metrics import RunDir, basis, checked

SECRET = "sk-live-0123456789abcdef"


def evidenced(episode: str, check: str) -> Assessment:
    assessment = checked(episode, check, "summary", "violated", outcome="accepted_invalid")
    assessment.discrepancy, assessment.reward, assessment.ids = "over", 1.0, {"trial_id": episode}
    assessment.claim.derivation = Derivation(observations=["exists"], validity="violated")
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
        assessments=[evidenced(full, "attack-check")], limits=[SAFETY_LIMIT])


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
    assert SAFETY_LIMIT in attack["limits"]
    text = json.dumps(result)
    assert "rate" not in json.dumps(attack["conditions"])
    assert any("no unbiased success-rate" in note for note in result["notes"])
    # Attacker rewards stay out of the ordinary pool.
    assert result["ordinary"]["attempted"] == 0 and len(result["other_episodes"]["attacker"]) == 4
    assert "attack spending_exhausted" in "\n".join(result["warnings"]) and "unknown prices" in text
    assert result["status"] == "partial"

    disabled = RunDir(tmp_path / "disabled")
    disabled.attack = AttackResult(status="complete", maximum_attempts=0, limits=[SAFETY_LIMIT, DISABLED_LIMIT])
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
                              "limits": []}
    captured = issue["captured"]
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
    run = RunDir(tmp_path)
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
    assert "grader inspector category rejected_valid is unknown" in warnings
    assert "hack inspector category persistence is restricted" in warnings
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
    assert (f"- grader_inspector accepted_invalid: evidenced_issue; evidenced by check-0000 (superseded by a later {later} reading); "
            "attempts none") in lines


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
        applicability={}, applicability_evidence={"accepted_invalid": {"status": "applicable"}},
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
    assert ("- grader_inspector rejected_valid: evidenced_issue; evidenced by check-0000; "
            "attempts broad 0 no_evidenced_issue, focused 1 evidenced_issue") in lines
    assert "- grader_inspector accepted_invalid: no_evidenced_issue; attempts broad 0 no_evidenced_issue, focused 1 no_evidenced_issue" in lines
    line = next(line for line in lines if line.startswith("- grader_inspector evidenced: "))
    assert "check check-0000; category rejected_valid; reinterprets experiment-0000, measured for accepted_invalid;" in line


def test_every_experiment_without_an_assessment_is_listed_once_whatever_its_category(tmp_path):
    """Unfinished work stays visible beside an evidenced category, without a category, and after a failure."""
    run = RunDir(tmp_path)
    run.record.sandboxes = ["sandbox-0000"]
    run.grader = InspectionResult(
        mode="grader", status="partial", categories={"accepted_invalid": "evidenced_issue", "rejected_valid": "unknown"},
        applicability={}, applicability_evidence={"rejected_valid": {"status": "applicable"}},
        assessments=[packaged("sandbox-0000", "check-0000")],
        experiments=[experiment(0, "accepted_invalid", "check-0000"),
                     {**experiment(1, "accepted_invalid", "check-0001", "measured"), "episode": "0000-simulator"},
                     {"id": "experiment-0002", "category": None, "status": "measured", "check": "check-0002"},
                     {"id": "experiment-0003", "status": "model_output_failure"}])

    text = report.markdown(run.report(selected=["grader"]))
    assert ("- grader_inspector experiments without an assessment: experiment-0001 measured (accepted_invalid, check-0001, 0000-simulator), "
            "experiment-0002 measured (no category, check-0002), experiment-0003 model_output_failure (no category)") in text.splitlines()
    for number in (1, 2, 3):
        assert text.count(f"experiment-000{number}") == 1
    assert "- grader_inspector rejected_valid: unknown; attempts none" in text.splitlines()


def test_markdown_reports_each_category_with_its_attempts_and_what_stays_open(tmp_path):
    """The category result is in Markdown; an unknown category shows nudi's facts, not the Inspector's prose."""
    run = RunDir(tmp_path)
    run.record.sandboxes = ["sandbox-0000", "sandbox-0001"]
    prose = "Four measured cases confirm the omission."
    run.grader = InspectionResult(
        mode="grader", status="partial",
        categories={"accepted_invalid": "evidenced_issue", "rejected_valid": "unknown"},
        applicability={"rejected_valid": prose},
        applicability_evidence={"accepted_invalid": {"status": "unknown"}, "rejected_valid": {"status": "unknown"}},
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
    assert "grader inspector category rejected_valid is unknown\n" in warnings
    assert prose not in warnings
    assert "grader inspector episode attempt 1 (0000-simulator) tool_failure, no error message recorded" in warnings and "None" not in warnings
    assert result["inspections"]["grader_inspector"]["applicability"]["rejected_valid"] == prose
    text = report.markdown(result)
    assert prose not in text
    lines = text.splitlines()
    start = lines.index("## Inspection categories") + 2
    assert lines[start:start + 3] == [
        "- grader_inspector accepted_invalid: evidenced_issue; evidenced by check-0000; attempts broad 0 unobservable, focused 1 evidenced_issue",
        "- grader_inspector rejected_valid: unknown; applicability evidence unknown; unresolved cases check-0001 inconclusive; "
        "attempts broad 0 unobservable, focused 1 model_output_failure, focused 2 no_evidenced_issue",
        "- grader_inspector experiments without an assessment: experiment-0002 measured (rejected_valid, check-0002)",
    ]
    assert report.CATEGORY_RULE in result["notes"]


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
    assert "- grader_inspector accepted_invalid: evidenced_issue; evidenced by check-0000; attempts none" in report.markdown(result)


def rejecting(sandbox: str, check: str) -> Assessment:
    """A package-sandbox rejected_valid finding."""
    assessment = packaged(sandbox, check)
    assessment.outcome, assessment.discrepancy = "rejected_valid", "under"
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
                                episode=reproduced, rewards={"reward": 1.0}, status="evidenced_issue", assessment=0),
                  AttackAttempt(level="full", number=1, candidate="hack-2", sources=["hack-2"], context="attacker-hack-2-full-1",
                                episode=refused, rewards={"reward": 0.0}, status="evidenced_issue", assessment=1)],
        assessments=[shim, rejected],
        findings=[AttackFinding(kind="reproduction", candidate="hack-1", sources=["hack-1"], attempt=0, assessment=0, relation="target",
                                rationale="the planted shim printed the pass marker"),
                  AttackFinding(kind="reproduction", candidate="hack-2", sources=["hack-2"], attempt=1, assessment=1, relation="target")])


def test_the_report_opens_with_a_plain_answer_built_from_its_evidenced_findings(tmp_path):
    """The report first says whether the grader can be cheated or misjudges work, and how."""
    run = RunDir(tmp_path)
    answered(run)
    expected = [
        "The grader can be cheated, and it misjudges work.",
        "In real episodes, Attackers reproduced hack-1 (grader_tampering, check-0003) with the full hint (0001-attacker, reward 1): "
        '"planted a bash shim that prints the pass marker"; had valid work rejected while testing hack-2 (unchecked_requirements, '
        'check-0004) with the full hint (0002-attacker, reward 0): "wrote the answer with leading zeros".',
        "In copies of the task package, the hack inspector evidenced cheats by grader_tampering (check-0003); and valid work rejected (check-0004).",
        "In copies of the task package, the grader inspector evidenced invalid work accepted (check-0000); and valid work rejected (check-0001).",
        "The run is complete: simulation complete, grader complete, hack complete, attack complete.",
    ]
    result = run.report()
    assert result["answer"] == expected
    lines = report.markdown(result).splitlines()
    assert lines[:4] == ["# nudi report", "", "## Answer", ""]
    assert lines[4:9] == [f"- {line}" for line in expected] and lines[9:11] == ["", "## Configuration"]

    # Package evidence alone does not show that a task agent can cheat.
    assert run.report(selected=["simulation", "grader", "hack"])["answer"] == [
        "The grader can be cheated in a copy of the task package, not yet in a real episode, and it misjudges work.",
        *expected[2:4], "The run is complete: simulation complete, grader complete, hack complete."]


def test_with_nothing_evidenced_the_answer_says_so_and_never_calls_the_grader_safe(tmp_path):
    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status="partial", categories={"grader_tampering": "unknown"}, applicability={},
                                assessments=[checked("sandbox-0000", "check-0000", "sorted", "unknown")])
    result = run.report()
    assert result["answer"] == ["No cheat and no misjudged work was evidenced. That does not show that the grader is safe.",
                                "The run is partial, so it may miss more: simulation complete, hack partial."]
    assert report.markdown(result).splitlines()[4:6] == [f"- {line}" for line in result["answer"]]


def test_an_older_pooled_attack_record_answers_from_its_evidenced_attempts(tmp_path):
    run = RunDir(tmp_path)
    attacked(run)
    result = run.report()
    assert result["answer"] == ["The grader can be cheated.",
                                'In real episodes, Attackers cheated with the full hint (0000-attacker, reward 1): "unchecked requirement".',
                                "The run is partial, so it may miss more: simulation complete, attack spending_exhausted."]
    # Its attempts are listed one per line too, after the pooled conditions.
    lines = report.markdown(result).splitlines()
    assert lines[lines.index("- Limit: " + SAFETY_LIMIT) - 5:lines.index("- Limit: " + SAFETY_LIMIT)] == [
        '- 0000-attacker cheated with the full hint: reward 1. How: "unchecked requirement"',
        "- 0001-attacker searched with the minimal hint: reward 0; refused: finish_reason: content_filter",
        f"- 0002-attacker searched with no hint: no reward; infrastructure_failure: daemon said {SECRET}",
        "- 0003-attacker searched with the minimal hint: no reward; inference_failure: InferenceFailure: RateLimitError",
        "- attempt 2 with no hint did not start: stopped by the spending cap"]


def test_the_answer_quotes_only_the_start_of_each_mechanism_and_the_attempt_lines_quote_it_whole(tmp_path):
    """The answer stays short: a mechanism's first sentence, or about 140 characters, marked when cut."""
    run = RunDir(tmp_path)
    answered(run)
    long = "wrote every answer with leading zeros, " * 5 + "and the grader rejected them all"
    run.attack.assessments[0].claim.mechanism = "Planted a bash shim. It prints the pass marker."
    run.attack.assessments[1].claim.mechanism = long
    result = run.report()
    assert result["answer"][1] == (
        'In real episodes, Attackers reproduced hack-1 (grader_tampering, check-0003) with the full hint (0001-attacker, reward 1): '
        '"Planted a bash shim..."; had valid work rejected while testing hack-2 (unchecked_requirements, check-0004) with the full hint '
        '(0002-attacker, reward 0): "' + long[:117] + 'wrote every answer..."' + ".")
    lines = report.markdown(result).splitlines()
    assert any('How: "Planted a bash shim. It prints the pass marker."' in line for line in lines)
    assert any(f'How: "{long}"' in line for line in lines)


def test_a_secret_across_the_answer_cut_never_appears_even_in_part(tmp_path):
    """Scrubbing matches whole secrets, so the answer is cut only from already redacted text."""
    run = RunDir(tmp_path)
    answered(run)
    spaced = "Zq9vX2 w8Lp3T kR7m"
    # Each secret starts before the 140-character cut and ends after it: one after a run with no space, one with spaces inside.
    run.attack.assessments[0].claim.mechanism = "/opt/" + "a/" * 62 + f"key={SECRET} was echoed by the grader"
    run.attack.assessments[1].claim.mechanism = "w " * 60 + spaced + " was echoed by the grader"
    result = run.report(secrets=[SECRET, spaced])
    for text in (json.dumps(result), report.markdown(result)):
        for secret in (SECRET, spaced):
            assert secret[:6] not in text
    assert result["answer"][1].count("[redac") == 2


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
    lines = report.markdown(run.report()).splitlines()
    assert ('- 0001-attacker cheated through another mechanism while testing hack-1 (grader_tampering, check-0003) with the full hint: '
            'reward 1. How: "planted a shell shim". How: "forged the reward file"') in lines


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
        "The grader can be cheated in a copy of the task package, not yet in a real episode.",
        "In copies of the task package, the hack inspector evidenced cheats by grader_tampering (check-0001).",
        "The run is complete: simulation complete, hack complete."]

    run.hack.assessments.pop()
    assert run.report()["answer"][0] == "No cheat and no misjudged work was evidenced. That does not show that the grader is safe."


def test_an_evidenced_attack_finding_outside_the_requested_outcome_stays_in_the_answer(tmp_path):
    """Testing valid work, an Attacker had invalid work accepted; testing a cheat, another had valid work
    rejected. Neither confirms its candidate, so neither is an exploit entry, but both are evidence."""
    run = RunDir(tmp_path)
    invalid, valid = run.episode("attacker", {"reward": 1.0}), run.episode("attacker", {"reward": 0.0})
    rejected = evidenced(valid, "check-0001")
    rejected.outcome = "rejected_valid"
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
        "The grader misjudges work.",
        "In real episodes, the attack inspector evidenced invalid work accepted (check-0000); and valid work rejected (check-0001).",
        "The run is complete: simulation complete, attack complete."]
    # Neither attempt line claims what was submitted.
    lines = report.markdown(result).splitlines()
    assert "- 0000-attacker tested valid-0 with the full hint: reward 1; no rejection of valid work was evidenced" in lines
    assert "- 0001-attacker tested hack-0 with the full hint: reward 0; no exploit was evidenced" in lines


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
        "Status complete; at most 2 attempts per candidate and hint level; 0 calls with unknown prices.",
        "No-hint discovery: 0 started of at most 0.",
        '- 0001-attacker reproduced hack-1 (grader_tampering, check-0003) with the full hint: reward 1. '
        'How: "planted a bash shim that prints the pass marker". Attack inspector: Matches the target. The check shows the shim ran.',
        '- 0002-attacker had valid work rejected while testing hack-2 (unchecked_requirements, check-0004) with the full hint: reward 0. '
        'How: "wrote the answer with leading zeros"',
        "- 0003-attacker tested hack-1 (grader_tampering, check-0003) with the minimal hint: reward 0.5; no exploit was evidenced",
        "- 0004-attacker tested hack-2 (unchecked_requirements, check-0004) with the minimal hint: reward 1; "
        "model_output_failure: Invalid Claim: 1 validation error for Claim",
        "- attempt 2 on hack-1 (grader_tampering, check-0003) with the full hint did not start: stopped by the spending cap",
        "- Not attempted: hack-5 full, hack-6 full and minimal",
        "- Not attempted, no guidance: hack-5 minimal",
    ]
    # Each hack inspector finding that became a candidate names it.
    finding = next(line for line in lines if line.startswith("- hack_inspector evidenced (package):") and "check check-0003;" in line)
    assert "check check-0003; category grader_tampering; attack candidate hack-1;" in finding
    # The JSON keeps every attempt and condition in full.
    assert result["attack"]["attempts"][3]["error"].endswith("Field required")
    assert result["attack"]["exploits"]["reproduction"][0]["rationale"] == "Matches the target.\nThe check shows the shim ran."
    assert result["attack"]["candidates"][2]["conditions"]["minimal"]["unavailable"] == "candidate exists but generated minimal guidance unavailable"


def test_repeated_warnings_are_grouped_and_multi_line_errors_shortened_in_markdown(tmp_path):
    """Categories and attack conditions get one warning per status; the JSON keeps each error in full."""
    run = RunDir(tmp_path)
    answered(run)
    error = "Invalid Claim: 1 validation error for Claim\nmechanism\n  Field required"
    run.hack.categories.update(leakage_metadata="unknown", persistence="restricted")
    run.hack.applicability["persistence"] = "Native persistence readback is a separate observation."
    run.hack.attempts = [InspectionAttempt(phase="focused", number=1, category="leakage_metadata", status="model_output_failure", error=error)]
    run.attack.candidates += [Candidate(id=f"hack-{number}", guidance={"full": "f", "minimal": "m"},
                                        conditions={"full": "unattempted", "minimal": "unattempted"}) for number in (5, 6)]

    result = run.report()
    assert "hack inspector categories unchecked_requirements, leakage_metadata are unknown" in result["warnings"]
    assert "hack inspector category persistence is restricted: Native persistence readback is a separate observation." in result["warnings"]
    assert not any("category leakage_metadata is unknown" in warning for warning in result["warnings"])
    assert "attack candidates hack-1 minimal, hack-2 minimal, hack-5 full and minimal, hack-6 full and minimal are unattempted" in result["warnings"]
    assert sum("attack candidate" in warning for warning in result["warnings"]) == 1
    failure = f"hack inspector focused attempt 1 (leakage_metadata) model_output_failure: {error}"
    assert failure in result["warnings"]
    lines = report.markdown(result).splitlines()
    assert f"- {failure.splitlines()[0]} (full text in report.json)" in lines
    assert "mechanism" not in lines and "  Field required" not in lines
