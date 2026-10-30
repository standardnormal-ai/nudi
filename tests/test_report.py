"""JSON and Markdown reports: provenance, attempts, coverage and redaction."""

import json

from nudi import report
from nudi.assessment import CHECK_LIMIT
from nudi.checks import CAPTURE_LIMIT, DISABLED_LIMIT, SAFETY_LIMIT, TIMING_LIMIT, AttackAttempt, AttackResult, InspectionAttempt, InspectionResult
from nudi.records import Assessment, CallRecord, Derivation, ErrorRecord, PersistenceProbe, Submission
from test_metrics import RunDir, basis, checked

SECRET = "sk-live-0123456789abcdef"


def evidenced(episode: str, check: str) -> Assessment:
    assessment = checked(episode, check, "summary", "violated", outcome="accepted_invalid")
    assessment.discrepancy, assessment.reward, assessment.ids = "over", 1.0, {"trial_id": episode}
    assessment.claim.derivation = Derivation(observations=["exists"], maximum="deserved", validity="violated")
    assessment.check.submission = Submission(content=assessment.check.content, ids={"trial_id": episode}, location="/app/summary.txt",
                                             capture_point="verification_start", command=["python", "-c", "capture"],
                                             program="capture", exit_code=0, output="{}")
    assessment.reasons, assessment.limits = ["violating content received 1.0, above the deserved maximum 0.0"], [CHECK_LIMIT]
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
        assessments=[evidenced(full, "attack-check")], limits=[SAFETY_LIMIT, CAPTURE_LIMIT])


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
    assert loaded["configuration"]["models"]["inspector"]["model"] == "xai/grok-4.7"
    assert loaded["configuration"]["credential_sources"]["inspector"] == "environment"
    assert loaded["ordinary"]["groups"][0]["configuration"]["versions"] == {"harbor": "0.24.0"}
    assert "xai/grok-4.7" in texts[1] and "harbor 0.24.0" in texts[1]


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
    disabled.attack = AttackResult(status="disabled", maximum_attempts=0, limits=[SAFETY_LIMIT, CAPTURE_LIMIT, DISABLED_LIMIT])
    result = disabled.report()
    assert result["analyses"]["attack"] == "disabled" and result["status"] == "partial"
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
    assert "no retained episode record" in report.markdown(empty.report())


def test_findings_keep_claims_captured_facts_and_interpretations_apart(tmp_path):
    run = RunDir(tmp_path)
    graded = run.episode(rewards={"reward": 1.0})
    suspect = checked(graded, "c1", "sorted", "unknown")
    suspect.reasons, suspect.missing = ["no check has tested the graded submission"], ["a host check"]
    run.label(graded, "accepted_invalid", evidenced(graded, "c0"), suspect)

    findings = run.report()["inspections"]["grader"]["findings"]
    (issue,) = findings["evidenced"]
    assert issue["claim"] == {"mechanism": "omitted_requirements", "episode": graded, "reward": "reward", "unresolved": []}
    captured = issue["captured"]
    assert captured["native_reward"] == 1.0 and captured["ids"] == {"trial_id": graded}
    assert captured["check"]["id"] == "c0" and captured["check"]["exit_code"] == 0
    assert captured["check"]["content"]["sha256"] == "a" * 64
    assert captured["check"]["submission"] == {"location": "/app/summary.txt", "capture_point": "verification_start",
                                               "sha256": "a" * 64}
    assert issue["interpretation"]["interpretation"] == "summary is violated"
    assert issue["interpretation"]["derivation"]["validity"] == "violated"
    assert issue["assessment"]["outcome"] == "accepted_invalid" and CHECK_LIMIT in issue["assessment"]["limits"]
    (provisional,) = findings["suspected"]
    assert provisional["assessment"]["missing"] == ["a host check"]


def test_reports_expose_retained_investigation_evidence_and_capture_limits(tmp_path):
    run = RunDir(tmp_path)
    run.hack = InspectionResult(mode="hack", status="partial", categories={"package_oracles": "unknown"}, applicability={},
        artifacts={"hack-broad": {"transcript": "sandboxes/sandbox-0000/transcript.jsonl",
                                  "tool_outputs": "sandboxes/sandbox-0000/tool-outputs"}},
        limits=["SDK shell capture retains at most 10 MiB; uncaptured bytes are unavailable."])
    result = run.report()
    visible = result["inspections"]["hack"]
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
    (finding,) = result["inspections"]["grader"]["findings"]["suspected"]
    assert finding["assessment"]["conclusions"] == [] and finding["captured"]["native_reward"] is None
    line = next(line for line in report.markdown(result).splitlines() if line.startswith("- grader suspected:"))
    assert "native reward unavailable" in line and "validity violated" in line


def test_package_sandbox_evidence_is_reported_apart_from_native_findings(tmp_path):
    run = RunDir(tmp_path)
    native = run.episode("attacker", {"reward": 1.0})
    run.record.sandboxes = ["sandbox-0000", "sandbox-0001"]
    package = evidenced("sandbox-0000", "package-check")
    package.execution_scope, package.ids = "package", {"sandbox": "sandbox-0000", "session_id": "nudi-ab-sandbox-0000"}
    package.check.sandbox = "sandbox-0001"
    run.hack = InspectionResult(mode="hack", status="complete", categories={"package_oracles": "evidenced_issue"}, applicability={},
                                assessments=[package])
    run.attack = AttackResult(status="complete", conditions={"none": "evidenced_issue"}, guidance={"none": None},
                              attempts=[AttackAttempt(level="none", number=1, context="attacker-none-1", episode=native,
                                                      status="evidenced_issue", assessment=0)],
                              assessments=[evidenced(native, "native-check")])

    result = run.report()
    findings = result["inspections"]["hack"]["findings"]
    assert findings["evidenced"] == [] and findings["suspected"] == []
    (copy,) = findings["package"]
    assert copy["execution_scope"] == "package" and copy["claim"]["episode"] == "sandbox-0000"
    assert copy["captured"]["check"]["sandbox"] == "sandbox-0001"
    assert copy["captured"]["copied_grader_reward"] == 1.0 and "native_reward" not in copy["captured"]
    assert any("not native accessibility" in limit for limit in copy["assessment"]["limits"])
    (issue,) = result["attack"]["findings"]["evidenced"]
    assert issue["execution_scope"] == "native"
    assert issue["captured"]["native_reward"] == 1.0 and "copied_grader_reward" not in issue["captured"]
    assert result["other_episodes"]["sandboxes"] == ["sandbox-0000", "sandbox-0001"]
    markdown = report.markdown(result)
    assert "hack package: evidenced_issue" not in markdown
    assert "2 Inspector package sandboxes" in markdown and "hack package:" in markdown
    package_line = next(line for line in markdown.splitlines() if line.startswith("- hack package:"))
    assert "copied grader reward 1" in package_line and "native reward" not in package_line
    assert "not native accessibility" in package_line and "copied tests" in package_line
    assert "after capture" in package_line and "isolation parity" in package_line


def test_incomplete_selected_coverage_and_persistence_limits_are_reported(tmp_path):
    run = RunDir(tmp_path)
    run.episode(rewards={"reward": 1.0})
    run.record.simulation.requested, run.record.simulation.status = 3, "spending_exhausted"
    run.label("0000-simulator", "unknown")
    run.grader.status = "partial"
    run.grader.categories = {"accepted_invalid": "no_evidenced_issue", "partial_credit": "unknown"}
    run.hack = InspectionResult(mode="hack", status="complete", categories={"persistence": "restricted"}, applicability={},
                                attempts=[InspectionAttempt(phase="broad", number=0, status="no_evidenced_issue")])
    run.record.persistence_probes = [PersistenceProbe(location="/app/marker", mount_relationship="writable_layer",
                                                      classification="survived", limits=[TIMING_LIMIT])]

    result = run.report(selected=["simulation", "grader", "hack", "attack"])
    assert result["analyses"] == {"simulation": "spending_exhausted", "grader": "partial", "hack": "complete", "attack": "not run"}
    assert result["status"] == "partial"
    warnings = "\n".join(result["warnings"])
    assert "simulation attempted 1 of 3 requested" in warnings
    assert "grader category partial_credit is unknown" in warnings
    assert "hack category persistence is restricted" in warnings
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
