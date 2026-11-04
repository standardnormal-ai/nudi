"""Ordinary reward summaries and grader metrics from retained run records."""

import asyncio
import json
from pathlib import Path

import pytest

from nudi import checks, report, workflow
from nudi.checks import AttackResult, EpisodeLabel, InspectionResult
from nudi.records import (
    DEFAULT_MODELS,
    Assessment,
    Capacity,
    Check,
    Claim,
    Conclusion,
    Content,
    DecisionRule,
    EpisodeResult,
    ErrorRecord,
    MetricBasis,
    ModelConfig,
    Observation,
    Ordering,
    RunRecord,
    Simulation,
)
from nudi.report import NON_BINARY, UNKNOWN_REWARD
from nudi.runner import tree_digest
from test_inspection import InspectorScript, Sandboxes
from test_limits import credentials, new_run  # noqa: F401  (pytest fixture)
from test_runner import serve
from test_simulation import HALF_CHECKERS, HALVES, REFERENCES, Native, probe, task_with_artifacts

TASK = {
    "instruction.md": "Write the numbers sorted to /app/out.txt.\nWrite a one-line summary to /app/summary.txt.\n",
    "tests/test.sh": "# reward is 1 when the score is at least 0.5\nawk '{ if ($1 >= 0.5) print 1; else print 0 }'\n",
}
REQUIREMENTS = {"sorted": "Write the numbers sorted", "summary": "Write a one-line summary"}
RULE = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="at least 0.5"), comparison=">=", threshold=0.5,
                    values=[0.0, 1.0])
ORDER = Ordering(source=Observation(episode=None, path="tests/test.sh", excerpt="reward is 1 when the score"), higher_completes=True)


class RunDir:
    """A run directory laid out as nudi retains it."""

    def __init__(self, tmp_path: Path):
        self.task = tmp_path / "task"
        for name, text in TASK.items():
            (self.task / name).parent.mkdir(parents=True, exist_ok=True)
            (self.task / name).write_text(text)
        self.digest = tree_digest(self.task)
        self.path = tmp_path / "run"
        (self.path / "episodes").mkdir(parents=True)
        self.record = RunRecord(
            task_dir=str(self.task), path="harbor", path_reasons=["original grading and harness"],
            models=dict(DEFAULT_MODELS), credential_sources={role: "environment" for role in DEFAULT_MODELS},
            spending_cap=5.0, capacity=Capacity(docker_cpus=8, docker_memory_mb=16384, episode_cpus=1,
                                                episode_memory_mb=2048, concurrency=4),
            cost_map={"source": "local"}, simulation=Simulation(requested=0, status="complete"))
        self.grader: InspectionResult | None = None
        self.hack: InspectionResult | None = None
        self.attack: AttackResult | None = None

    def episode(self, role="simulator", rewards=None, *, model="xiaomi_mimo/mimo-v2.6-pro", errors=(), retained=True) -> str:
        name = f"{len(self.record.episodes):04d}-{role}"
        self.record.episodes.append(name)
        if role == "simulator":
            self.record.simulation.episodes.append(name)
            self.record.simulation.requested += 1
            if errors:
                self.record.simulation.failures[name] = list(errors)
        if retained:
            result = EpisodeResult(path="harbor", path_reasons=["original grading and harness"], task_name="sort",
                                   task_dir=str(self.task), task_digest=self.digest, model=model, reasoning_effort="high",
                                   versions={"harbor": "0.24.0"}, rewards=rewards or {}, errors=list(errors))
            directory = self.path / "episodes" / name
            directory.mkdir()
            # json.dumps keeps a non-finite upstream value that model_dump_json would turn into null.
            (directory / "episode.json").write_text(json.dumps(result.model_dump()))
        return name

    def label(self, name: str, label: str, *assessments: Assessment) -> None:
        if self.grader is None:
            self.grader = InspectionResult(mode="grader", status="complete", categories={"accepted_invalid": "no_evidenced_issue"},
                                           applicability={})
        self.grader.assessments.extend(assessments)
        self.grader.ordinary[name] = EpisodeLabel(label=label, reasons=[f"{label} label"])

    def save(self) -> None:
        (self.path / "run.json").write_text(self.record.model_dump_json(indent=2))
        for name, result in (("inspection-grader.json", self.grader), ("inspection-hack.json", self.hack), ("attack.json", self.attack)):
            if result is not None:
                (self.path / name).write_text(result.model_dump_json(indent=2))

    def report(self, **options) -> dict:
        self.save()
        return report.build(self.path, **options)


def requirement(key: str) -> Observation:
    return Observation(episode=None, path="instruction.md", excerpt=REQUIREMENTS[key])


def checked(episode: str, check: str, key: str, validity: str, *, outcome="unknown", unresolved=(), basis=None) -> Assessment:
    """A retained assessment whose check of `episode` observed requirement `key`."""
    return Assessment(
        claim=Claim(mechanism="unchecked requirement", episode=episode, check=check, interpretation=f"{key} is {validity}",
                    unresolved=list(unresolved), basis=basis),
        outcome=outcome, validity=validity, discrepancy="unknown" if validity == "unknown" else "none",
        check=Check(id=check, content=Content(episode=episode, path="nudi-evidence/out.json", sha256="a" * 64),
                    ids={"trial_id": episode}, requirement=requirement(key), command=["python", "-c", "check"],
                    exit_code=0, output="{}"))


def basis(completion: str, keys: list[str], checks: list[str], **fields) -> MetricBasis:
    return MetricBasis(completion=completion, requirements=[requirement(key) for key in keys], checks=checks,
                       explanation=f"completion {completion}", **fields)


def referenced(run: RunDir, completion: str, rewards: dict, *, model="xiaomi_mimo/mimo-v2.6-pro", errors=(), **fields) -> str:
    """An ordinary episode whose one check settles its single-requirement completion."""
    name = run.episode(rewards=rewards, model=model, errors=errors)
    check = f"check-{name}"
    validity = "supported" if completion == "supported" else "violated"
    run.label(name, "unknown", checked(name, check, "sorted", validity, basis=basis(completion, ["sorted"], [check], **fields)))
    return name


def test_reward_summary_groups_configurations_and_never_turns_missing_or_invalid_rewards_into_zero(tmp_path):
    run = RunDir(tmp_path)
    usable = [run.episode(rewards={"reward": value}) for value in (1.0, 0.0, 1.0)]
    absent = run.episode(rewards={})
    empty = run.episode(rewards={"reward": None}, errors=[ErrorRecord(type="VerifierTimeoutError", message="grader timed out")])
    invalid = run.episode(rewards={"reward": float("nan")})
    unrecorded = run.episode(errors=[ErrorRecord(type="RuntimeError", message="runner raised")], retained=False)
    single = run.episode(rewards={"reward": 0.5}, model="openai/gpt-6")
    none = run.episode(rewards={"reward": None}, model="xai/grok-4.7")
    run.episode("inspector", {"reward": 0.0})
    run.episode("attacker", {"reward": 1.0})

    result = run.report()
    ordinary = result["ordinary"]
    assert ordinary["requested"] == ordinary["attempted"] == 9
    assert list(ordinary["unrecorded"]) == [unrecorded]
    groups = {group["configuration"]["model"]: group for group in ordinary["groups"]}
    assert set(groups) == {"xiaomi_mimo/mimo-v2.6-pro", "openai/gpt-6", "xai/grok-4.7"}

    mimo = groups["xiaomi_mimo/mimo-v2.6-pro"]
    assert mimo["episodes"] == [*usable, absent, empty, invalid]
    reward = mimo["rewards"]["reward"]
    assert (reward["attempted"], reward["usable"]) == (6, 3)
    assert reward["missing"] == [absent, empty] and reward["invalid"] == [invalid]
    assert reward["mean"] == 2 / 3 and abs(reward["sd"] - 0.5773502691896257) < 1e-12
    assert reward["distribution"] == [[0.0, 1], [1.0, 2]]

    one = groups["openai/gpt-6"]["rewards"]["reward"]
    assert one["mean"] == 0.5 and one["sd"] is None
    assert any("fewer than two usable" in reason for reason in one["unavailable"])
    nothing = groups["xai/grok-4.7"]["rewards"]["reward"]
    assert nothing["mean"] is None and nothing["sd"] is None and nothing["distribution"] == []
    assert any("no usable" in reason for reason in nothing["unavailable"])

    # A retained run from before Inspector sandboxes still lists its native Inspector episode.
    assert result["other_episodes"] == {"sandboxes": [], "inspector": ["0009-inspector"], "attacker": ["0010-attacker"], "probes": []}
    warnings = "\n".join(result["warnings"])
    assert "excluded, never zero" in warnings and unrecorded in warnings
    assert "sample SD" in warnings and "mean" in warnings


def test_constant_and_mixed_rewards_are_descriptive_notes_not_warnings(tmp_path):
    run = RunDir(tmp_path)
    for _ in range(3):
        run.episode(rewards={"reward": 1.0, "partial": 0.5})
    run.episode(rewards={"reward": 0.0, "partial": 0.25})

    result = run.report()
    notes, warnings = "\n".join(result["notes"]), "\n".join(result["warnings"])
    assert "reward: mixed" in notes and "partial: mixed" in notes
    assert "difficulty" in notes and "sampling" in notes and "execution" in notes
    assert "mixed" not in warnings and "constant" not in warnings

    constant = RunDir(tmp_path / "constant")
    constant.episode(rewards={"reward": 1.0})
    constant.episode(rewards={"reward": 1.0})
    result = constant.report()
    assert any("reward: constant 1.0" in note for note in result["notes"])
    assert not any("constant" in warning for warning in result["warnings"])


def test_completion_references_and_native_decisions_count_each_ordinary_episode_once(tmp_path):
    run = RunDir(tmp_path)
    both = ["sorted", "summary"]
    complete_pass = run.episode(rewards={"reward": 1.0})
    run.label(complete_pass, "legitimate", checked(complete_pass, "c0", "sorted", "supported", outcome="legitimate"),
              checked(complete_pass, "c1", "summary", "supported", outcome="legitimate",
                      basis=basis("supported", both, ["c0", "c1"], decision=RULE)))
    # One observed violation of a necessary requirement decides; an unrelated unknown check does not erase it.
    violated_pass = run.episode(rewards={"reward": 1.0})
    run.label(violated_pass, "accepted_invalid",
              checked(violated_pass, "c2", "summary", "violated", outcome="accepted_invalid",
                      basis=basis("violated", ["summary"], ["c2", "c3"], decision=RULE)),
              checked(violated_pass, "c3", "sorted", "unknown"))
    # Legitimate partial credit without a completion basis supplies neither label. Its fractional
    # reward would contradict the binary rule, so it runs under another model configuration.
    partial = run.episode(rewards={"reward": 0.4}, model="openai/gpt-6")
    run.label(partial, "legitimate", checked(partial, "c4", "sorted", "supported", outcome="legitimate"))
    complete_fail = run.episode(rewards={"reward": 0.0})
    run.label(complete_fail, "rejected_valid", checked(complete_fail, "c5", "sorted", "supported", outcome="rejected_valid"),
              checked(complete_fail, "c6", "summary", "supported", basis=basis("supported", both, ["c5", "c6"], decision=RULE)))
    # A local over-credit label is not a matrix cell when the basis leaves a relevant condition unresolved.
    unresolved = run.episode(rewards={"reward": 1.0})
    run.label(unresolved, "accepted_invalid", checked(
        unresolved, "c7", "summary", "violated", outcome="accepted_invalid",
        basis=basis("violated", ["summary"], ["c7"], decision=RULE, unresolved=["whether the summary is required"])))
    violated_fail = run.episode(rewards={"reward": 0.0})
    run.label(violated_fail, "unknown", checked(violated_fail, "c8", "sorted", "violated",
                                               basis=basis("violated", ["sorted"], ["c8"], decision=RULE)))
    uncovered = run.episode(rewards={"reward": 1.0})
    run.label(uncovered, "unknown", checked(uncovered, "c9", "sorted", "supported",
                                           basis=basis("supported", both, ["c9"], decision=RULE)))
    no_reward = run.episode(rewards={})
    run.label(no_reward, "unavailable", checked(no_reward, "c10", "sorted", "supported"),
              checked(no_reward, "c11", "summary", "supported", basis=basis("supported", both, ["c10", "c11"], decision=RULE)))

    result = run.report()
    episodes = result["metrics"]["episodes"]
    names = [complete_pass, violated_pass, partial, complete_fail, unresolved, violated_fail, uncovered, no_reward]
    assert [episodes[name]["completion"] for name in names] == [
        "complete", "incomplete", "unknown", "complete", "unknown", "incomplete", "unknown", "complete"]
    assert any("no metric basis" in reason for reason in episodes[partial]["completion_reasons"])
    assert any("whether the summary is required" in reason for reason in episodes[unresolved]["completion_reasons"])
    assert any(REQUIREMENTS["summary"] in reason for reason in episodes[uncovered]["completion_reasons"])
    assert episodes[no_reward]["decision"] is None
    assert any("no native reward" in reason for reason in episodes[no_reward]["decision_reasons"])
    assert [episodes[name]["decision"] for name in (complete_pass, violated_pass, complete_fail, violated_fail)] == [
        "pass", "pass", "fail", "fail"]

    group, fractional = result["metrics"]["confusion"]
    assert fractional["status"] == "unavailable" and fractional["episodes"] == []
    assert group["episodes"] == [complete_pass, violated_pass, complete_fail, violated_fail]
    assert (group["tp"], group["fp"], group["fn"], group["tn"]) == (1, 1, 1, 1)
    assert group["f1"] == 0.5 and group["rule"]["threshold"] == 0.5
    # Local findings stay separate from binary labels.
    assert result["labels"]["counts"] == {"accepted_invalid": 2, "legitimate": 2, "rejected_valid": 1,
                                          "unavailable": 1, "unknown": 2}


def test_an_evidenced_finding_with_an_open_claim_condition_still_counts_in_grader_error_rates(tmp_path):
    """Doubt is one-sided: an open claim item keeps neither error direction out of the metrics,
    while a legitimate check with one is still not a resolved completion reference."""
    run = RunDir(tmp_path)
    both, open_item = ["sorted", "summary"], ["whether the copied grader is the hosted one"]
    false_positive = run.episode(rewards={"reward": 1.0})
    run.label(false_positive, "accepted_invalid", checked(
        false_positive, "c0", "summary", "violated", outcome="accepted_invalid", unresolved=open_item,
        basis=basis("violated", ["summary"], ["c0"], decision=RULE)))
    false_negative = run.episode(rewards={"reward": 0.0})
    run.label(false_negative, "rejected_valid",
              checked(false_negative, "c1", "sorted", "supported", outcome="rejected_valid", unresolved=open_item),
              checked(false_negative, "c2", "summary", "supported", basis=basis("supported", both, ["c1", "c2"], decision=RULE)))
    doubted_legitimate = run.episode(rewards={"reward": 1.0})
    run.label(doubted_legitimate, "unknown", checked(
        doubted_legitimate, "c3", "sorted", "supported", outcome="legitimate", unresolved=open_item,
        basis=basis("supported", ["sorted"], ["c3"], decision=RULE)))

    metrics = run.report()["metrics"]
    episodes = metrics["episodes"]
    assert [episodes[name]["completion"] for name in (false_positive, false_negative, doubted_legitimate)] == [
        "incomplete", "complete", "unknown"]
    assert any("c3 is not a resolved check" in reason for reason in episodes[doubted_legitimate]["completion_reasons"])
    (group,) = metrics["confusion"]
    assert (group["fp"], group["fn"]) == (1, 1)


def test_reports_show_the_mode_and_presumed_and_verified_counts_without_counting_presumption_as_evidence(tmp_path):
    run = RunDir(tmp_path)
    verified = run.episode(rewards={"reward": 1.0})
    run.label(verified, "legitimate", checked(verified, "c0", "sorted", "supported", outcome="legitimate"),
              checked(verified, "c1", "summary", "supported", outcome="legitimate",
                      basis=basis("supported", ["sorted", "summary"], ["c0", "c1"], decision=RULE)))
    run.grader.ordinary[verified].basis = "verified"
    presumed = run.episode(rewards={"reward": 0.0})
    run.grader.ordinary[presumed] = EpisodeLabel(label="legitimate", basis="presumed", reasons=["presumed to follow the grader"])
    run.grader.ordinary_inspection = "holistic_inspection"

    result = run.report()
    assert result["labels"]["mode"] == "holistic_inspection"
    assert result["labels"]["basis"] == {"presumed": 1, "verified": 1}
    assert result["labels"]["episodes"][presumed]["basis"] == "presumed"
    assert result["labels"]["review"]["supported"] == [verified]
    # A presumed label is no completion reference; it enters a binary matrix only as a marked presumption.
    (group,) = result["metrics"]["confusion"]
    assert group["episodes"] == [verified, presumed] and (group["presumed"], group["verified"]) == (1, 1)
    assert result["metrics"]["episodes"][presumed]["completion"] == "unknown"
    assert group["false_negative_rate"]["lower_bound"] is True
    text = report.markdown(result)
    assert "Mode: holistic_inspection; presumed 1, verified 1." in text
    assert f"- {presumed}: legitimate (presumed)" in text and f"- {verified}: legitimate (verified)" in text


def test_rewards_alone_never_supply_a_native_decision_and_f1_needs_a_denominator(tmp_path):
    run = RunDir(tmp_path)
    invented = RULE.model_copy(update={"source": Observation(episode=None, path="tests/test.sh", excerpt="at least 0.9")})
    encoded = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="print 1"), pass_values=[1.0], values=[0.0, 1.0])
    binary = referenced(run, "violated", {"reward": 0.0})
    ungrounded = referenced(run, "violated", {"reward": 1.0}, decision=invented)
    by_value = referenced(run, "violated", {"reward": 0.0}, decision=encoded)
    by_threshold = referenced(run, "violated", {"reward": 0.0}, decision=RULE)
    conflicting = referenced(run, "violated", {"reward": 0.0}, decision=RULE)
    run.grader.assessments.append(checked(conflicting, "other", "sorted", "violated",
                                          basis=basis("violated", ["sorted"], ["other"], decision=encoded)))

    metrics = run.report()["metrics"]
    episodes = metrics["episodes"]
    assert episodes[binary]["decision"] is None
    assert any("no source-grounded native decision rule" in reason for reason in episodes[binary]["decision_reasons"])
    assert episodes[ungrounded]["decision"] is None
    assert any("at least 0.9" in reason for reason in episodes[ungrounded]["decision_reasons"])
    assert episodes[conflicting]["decision"] is None
    assert any("incompatible" in reason for reason in episodes[conflicting]["decision_reasons"])

    groups = metrics["confusion"]
    assert [group["episodes"] for group in groups] == [[by_value], [by_threshold]]
    for group in groups:
        assert (group["tp"], group["fp"], group["fn"], group["tn"]) == (0, 0, 0, 1)
        assert group["f1"] is None and "denominator" in group["unavailable"]


def binary_matrix(run: RunDir, tp: int, fp: int, fn: int, tn: int, **fields) -> list[str]:
    """Ordinary episodes with resolved references under the binary RULE, in TP, FP, FN, TN order."""
    cells = (("supported", 1.0, tp), ("violated", 1.0, fp), ("supported", 0.0, fn), ("violated", 0.0, tn))
    return [referenced(run, completion, {"reward": value}, decision=RULE, **fields)
            for completion, value, count in cells for _ in range(count)]


def test_false_discovery_and_false_negative_rates_count_the_eligible_binary_subset(tmp_path):
    run = RunDir(tmp_path)
    eligible = binary_matrix(run, 8, 2, 1, 9)
    before = run.report()["metrics"]["confusion"]
    # Unresolved and unreviewed episodes change coverage, never a rate denominator.
    inconclusive = run.episode(rewards={"reward": 1.0})
    run.label(inconclusive, "unknown", checked(inconclusive, "c-open", "sorted", "unknown",
                                               basis=basis("unknown", ["sorted"], ["c-open"], decision=RULE)))
    unreviewed = run.episode(rewards={"reward": 0.0})

    result = run.report()
    (group,) = result["metrics"]["confusion"]
    assert (group["status"], group["reasons"]) == ("supported", [])
    assert group["episodes"] == eligible and (group["presumed"], group["verified"]) == (0, 20)
    assert (group["tp"], group["fp"], group["fn"], group["tn"]) == (8, 2, 1, 9)
    assert group["false_discovery_rate"] == {"value": 0.2, "numerator": 2, "denominator": 10, "lower_bound": False, "unavailable": None}
    assert group["false_negative_rate"] == {"value": 1 / 9, "numerator": 1, "denominator": 9, "lower_bound": False, "unavailable": None}
    assert {key: group[key] for key in ("false_discovery_rate", "false_negative_rate", "f1")} == {
        key: before[0][key] for key in ("false_discovery_rate", "false_negative_rate", "f1")}
    assert group["f1"] == 16 / 19
    # The native pass rate counts every usable reward, separate from the eligible subset.
    assert group["pass_rate"] == {"value": 0.5, "numerator": 11, "denominator": 22, "lower_bound": False, "unavailable": None}
    assert result["metrics"]["coverage"] == {
        "ordinary": 22, "resolved": 20, "eligible": 20,
        "excluded": {"operational_failure": [], "missing_reward": [], "unreviewed": [unreviewed], "inconclusive": [inconclusive],
                     "no_decision_rule": [], "no_binary_contract": []}}
    assert result["status"] == "complete"
    assert any("rough estimates" in note and "FP / (FP + TN)" in note and "eligible subset" in note for note in result["notes"])
    assert "F1 uses 20 of 22 ordinary episodes" in "\n".join(result["warnings"])
    text = report.markdown(result)
    assert ("- Coverage: 20 of 22 ordinary episodes have a resolved completion reference; 20 of 22 enter grader agreement; "
            "excluded: unreviewed 1, inconclusive 1") in text
    assert ("TP 8, FP 2, FN 1, TN 9; false discovery rate 0.2 (2/10); false negative rate 0.1111 (1/9); "
            "presumed 0, verified 20") in text
    assert "- Native pass rate for xiaomi_mimo/mimo-v2.6-pro reward (>= 0.5): 0.5 (11/22)" in text


def test_zero_denominators_all_unknown_and_low_coverage_never_become_zero_rates(tmp_path):
    run = RunDir(tmp_path)
    binary_matrix(run, 0, 0, 0, 2)
    result = run.report()
    (group,) = result["metrics"]["confusion"]
    assert (group["tp"], group["fp"], group["fn"], group["tn"]) == (0, 0, 0, 2)
    for key, terms in (("false_discovery_rate", "TP + FP"), ("false_negative_rate", "TP + FN")):
        assert (group[key]["value"], group[key]["denominator"]) == (None, 0)
        assert terms in group[key]["unavailable"] and group[key]["unavailable"] in "\n".join(result["warnings"])
    assert "false discovery rate unavailable (0/0)" in report.markdown(result)

    unknown = RunDir(tmp_path / "unknown")
    names = [unknown.episode(rewards={"reward": value}) for value in (1.0, 0.0, 1.0)]
    for name in names:
        unknown.label(name, "unknown", checked(name, f"c-{name}", "sorted", "unknown",
                                               basis=basis("unknown", ["sorted"], [f"c-{name}"], decision=RULE)))
    metrics = unknown.report()["metrics"]
    (group,) = metrics["confusion"]
    assert (group["status"], group["episodes"], group["tp"], group["tn"]) == ("supported", [], 0, 0)
    assert group["false_discovery_rate"]["value"] is None and group["false_negative_rate"]["value"] is None
    assert metrics["coverage"]["resolved"] == metrics["coverage"]["eligible"] == 0
    assert metrics["coverage"]["excluded"]["inconclusive"] == names

    low = RunDir(tmp_path / "low")
    binary_matrix(low, 1, 0, 0, 1)
    for _ in range(18):
        name = low.episode(rewards={"reward": 1.0})
        low.label(name, "unknown", checked(name, f"c-{name}", "sorted", "unknown"))
    result = low.report()
    (group,) = result["metrics"]["confusion"]
    # A rate with a nonzero denominator may be zero; small eligible coverage stays visible beside it.
    assert group["false_discovery_rate"]["value"] == 0.0 and group["false_discovery_rate"]["denominator"] == 1
    assert (result["metrics"]["coverage"]["eligible"], result["metrics"]["coverage"]["ordinary"]) == (2, 20)
    assert "F1 uses 2 of 20 ordinary episodes" in "\n".join(result["warnings"])
    assert "2 of 20 enter grader agreement" in report.markdown(result)


def test_grader_agreement_groups_by_configuration_and_rule_and_keeps_exclusions_distinguishable(tmp_path):
    run = RunDir(tmp_path)
    accepted, contaminated = binary_matrix(run, 1, 1, 0, 0)
    # A duplicated assessment still counts its episode once.
    run.grader.assessments.append(run.grader.assessments[-1])
    other = binary_matrix(run, 0, 0, 0, 1, model="openai/gpt-6")
    encoded = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="print 1"), pass_values=[1.0], values=[0.0, 1.0])
    # Two grounded rules of one binary configuration keep separate groups.
    mixed = [referenced(run, "supported", {"reward": 1.0}, model="xai/grok-4.7", decision=rule) for rule in (RULE, encoded)]
    timeout = referenced(run, "supported", {"reward": None}, decision=RULE,
                         errors=[ErrorRecord(type="VerifierTimeoutError", message="grader timed out")])
    unrecorded = run.episode(errors=[ErrorRecord(type="RuntimeError", message="runner raised")], retained=False)
    missing = referenced(run, "supported", {}, decision=RULE)
    undecided = referenced(run, "supported", {"reward": 1.0})
    # Attacker and probe episodes stay outside the ordinary pool and its observed reward values.
    run.episode("attacker", {"reward": 0.5})
    run.record.probe_episodes.append(run.episode("attacker", {"reward": 0.5}))

    metrics = run.report()["metrics"]
    groups = {group["configuration"]["model"]: group for group in metrics["confusion"]}
    assert list(groups) == ["xiaomi_mimo/mimo-v2.6-pro", "openai/gpt-6", "xai/grok-4.7"]
    mimo = groups["xiaomi_mimo/mimo-v2.6-pro"]
    assert mimo["episodes"] == [accepted, contaminated] and (mimo["tp"], mimo["fp"], mimo["fn"], mimo["tn"]) == (1, 1, 0, 0)
    assert mimo["configuration"]["task_digest"] == run.digest
    assert groups["openai/gpt-6"]["episodes"] == other and groups["openai/gpt-6"]["tn"] == 1
    grok = [group for group in metrics["confusion"] if group["configuration"]["model"] == "xai/grok-4.7"]
    assert [(group["status"], group["episodes"], group["tp"]) for group in grok] == [("supported", [name], 1) for name in mixed]
    assert metrics["coverage"]["excluded"] == {
        "operational_failure": [timeout, unrecorded], "missing_reward": [missing], "unreviewed": [], "inconclusive": [],
        "no_decision_rule": [undecided], "no_binary_contract": []}


ENCODED = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="print 1"), pass_values=[1.0], values=[0.0, 1.0])
RUBRIC = RULE.model_copy(update={"values": [0.0, 0.5, 1.0]})


@pytest.mark.parametrize("first, second, hidden, status, split", [
    (RULE, ENCODED, (), "supported", True),
    (RULE, RULE.model_copy(update={"values": [1.0, 0.0]}), (), "supported", False),
    (RULE, RULE.model_copy(update={"values": []}), (), "supported", False),
    (RUBRIC, ENCODED, (), "unsupported", True),
    (RULE, ENCODED.model_copy(update={"pass_values": [0.0]}), (), "unavailable", True),
    # Each declaration names every value, so one-value declarations never combine into a binary contract.
    (RULE.model_copy(update={"values": [0.0]}), ENCODED.model_copy(update={"values": [1.0]}), (), "unsupported", True),
    (RULE, RULE.model_copy(update={"values": [0.0]}), (), "unsupported", False),
    # A declaration counts even on an episode whose conflicting rules leave it without a decision.
    (RULE, ENCODED, (RULE, RUBRIC), "unsupported", True),
    (RULE, ENCODED, (RULE, ENCODED.model_copy(update={"pass_values": [0.0]})), "unavailable", True),
], ids=["different_rules", "value_order", "omitted_values", "non_binary_declaration", "opposite_direction", "single_values",
        "partial_declaration", "hidden_non_binary", "hidden_opposite_direction"])
def test_one_reward_contract_per_configuration_keeps_each_decision_rule_group(tmp_path, first, second, hidden, status, split):
    run = RunDir(tmp_path)
    names = [referenced(run, completion, {"reward": value}, decision=rule)
             for rule in (first, second) for completion, value in (("supported", 1.0), ("violated", 0.0))]
    if hidden:
        names.append(referenced(run, "supported", {"reward": 1.0}, decision=hidden[0]))
        run.grader.assessments.append(checked(names[-1], "other", "sorted", "supported",
                                              basis=basis("supported", ["sorted"], ["other"], decision=hidden[1])))
    # A presumed label takes its configuration's decision rule only when that rule is the only one.
    assumed = presumed(run, 1.0)

    metrics = run.report()["metrics"]
    groups, excluded = metrics["confusion"], metrics["coverage"]["excluded"]
    assert [group["status"] for group in groups] == [status] * (2 if split else 1)
    if status != "supported":
        assert groups[0]["reasons"][0] == {"unsupported": NON_BINARY, "unavailable": UNKNOWN_REWARD}[status]
        assert all(group["episodes"] == [] and group["tp"] is None for group in groups)
        assert excluded["no_binary_contract"] == names + [assumed]
    elif split:
        assert [(group["episodes"], group["tp"], group["tn"]) for group in groups] == [(names[:2], 1, 1), (names[2:], 1, 1)]
        assert excluded["no_decision_rule"] == [assumed]
    else:
        (group,) = groups
        assert (group["episodes"], group["tp"], group["tn"], group["presumed"]) == (names + [assumed], 3, 2, 1)


def test_a_binary_contract_without_any_chosen_decision_rule_leaves_agreement_unavailable(tmp_path):
    run = RunDir(tmp_path)
    # Both rules pass 1 of [0, 1], so the contract is supported, but every episode cites both and has no one decision.
    names = []
    for completion, value in (("supported", 1.0), ("violated", 0.0)):
        names.append(referenced(run, completion, {"reward": value}, decision=RULE))
        run.grader.assessments.append(checked(names[-1], "other", "sorted", completion,
                                              basis=basis(completion, ["sorted"], ["other"], decision=ENCODED)))
    run.save()

    paths = report.write(run.path)
    metrics = json.loads(paths[0].read_text())["metrics"]
    (group,) = metrics["confusion"]
    assert (group["status"], group["rule"], group["episodes"], group["tp"], group["f1"]) == ("unavailable", None, [], None, None)
    assert group["false_discovery_rate"]["value"] is None and group["false_negative_rate"]["value"] is None
    assert metrics["coverage"]["excluded"]["no_decision_rule"] == names
    assert "reward: unavailable, no agreement values." in paths[1].read_text()


def test_agreement_follows_the_environment_reward_and_keeps_established_binary_components(tmp_path):
    run = RunDir(tmp_path)
    cells = (("supported", 1.0), ("violated", 0.0))
    whole = [referenced(run, completion, {"reward": value, "tests": value}, decision=RULE) for completion, value in cells]
    tests = [referenced(run, completion, {"reward": value, "tests": value}, decision=RULE.model_copy(update={"reward": "tests"}))
             for completion, value in cells]
    # A component without its own declared binary values stays out, even in a binary environment.
    referenced(run, "supported", {"reward": 1.0, "tests": 1.0, "style": 0.5},
               decision=RULE.model_copy(update={"reward": "style", "values": []}))

    groups = {group["reward"]: group for group in run.report()["metrics"]["confusion"]}
    assert [groups[key]["status"] for key in ("reward", "tests", "style")] == ["supported", "supported", "unavailable"]
    for key, names in (("reward", whole), ("tests", tests)):
        assert (groups[key]["episodes"], groups[key]["tp"], groups[key]["tn"], groups[key]["f1"]) == (names, 1, 1, 1.0)
    assert groups["style"]["episodes"] == []

    # Harbor reads a single reward key as the environment reward, whatever its name.
    single = RunDir(tmp_path / "single")
    names = [referenced(single, completion, {"passed": value}, decision=RULE.model_copy(update={"reward": "passed"}))
             for completion, value in cells]
    (group,) = single.report()["metrics"]["confusion"]
    assert (group["status"], group["reward"], group["episodes"], group["f1"]) == ("supported", "passed", names, 1.0)

    # A missing overall reward never promotes a component past the environment's own contract.
    promoted = RunDir(tmp_path / "promoted")
    referenced(promoted, "supported", {}, decision=RUBRIC)
    for completion, value in cells:
        referenced(promoted, completion, {"tests": value}, decision=RULE.model_copy(update={"reward": "tests"}))
    assert [(group["reward"], group["status"], group["tp"]) for group in promoted.report()["metrics"]["confusion"]] == [
        ("reward", "unsupported", None), ("tests", "unsupported", None)]

    # With several reward keys and none named reward, the environment reward stays unidentified.
    unnamed = RunDir(tmp_path / "unnamed")
    for completion, value in cells:
        referenced(unnamed, completion, {"passed": value, "aux": 0.5}, decision=RULE.model_copy(update={"reward": "passed"}))
    (group,) = unnamed.report()["metrics"]["confusion"]
    assert (group["status"], group["reasons"][0], group["episodes"]) == ("unavailable", UNKNOWN_REWARD, [])


def build_eligibility_case(run: RunDir, case: str) -> list[str]:
    """Ordinary episodes for one reward contract; each reward 1.0 is complete work and every other value is not."""
    rewards, rule = [1.0, 0.0, 1.0], RULE
    if case == "rubric_threshold":
        rewards, rule = [1.0, 0.5, 0.0], RUBRIC
    elif case == "non_binary_with_binary_sample":
        rule = RUBRIC
    elif case == "rubric_without_threshold":
        rewards, rule = [0.25, 0.5, 0.75], None
    elif case == "undeclared_values":
        rule = RULE.model_copy(update={"values": []})
    elif case == "no_rule":
        rule = None
    elif case == "contradicted":
        # The fractional reward invalidates the declaration even though its episode is unreviewed.
        run.episode(rewards={"reward": 0.5})
    elif case == "binary_component":
        rewards, rule = [1.0, 0.5, 0.0], RULE.model_copy(update={"reward": "tests"})
    elif case == "internal_criteria":
        (run.task / "tests/test.sh").write_text("# three criteria: reward is 1 when the score meets all three, otherwise 0\n")
        run.digest = tree_digest(run.task)
        rule = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="otherwise 0"), pass_values=[1.0],
                            values=[0.0, 1.0])
    fields = {"decision": rule} if rule else {}
    return [referenced(run, "supported" if value == 1.0 else "violated",
                       {"reward": value, **({"tests": float(value == 1.0)} if case == "binary_component" else {})},
                       ordering=ORDER, **fields) for value in rewards]


@pytest.mark.parametrize("case, status", [
    ("rubric_threshold", "unsupported"), ("non_binary_with_binary_sample", "unsupported"), ("rubric_without_threshold", "unsupported"),
    ("undeclared_values", "unavailable"), ("no_rule", "unavailable"), ("contradicted", "unsupported"),
    ("binary_component", "unsupported"), ("internal_criteria", "supported"),
])
def test_grader_agreement_needs_an_established_binary_reward_contract(tmp_path, case, status):
    message = {"unsupported": NON_BINARY, "unavailable": UNKNOWN_REWARD}.get(status)
    run = RunDir(tmp_path)
    names = build_eligibility_case(run, case)

    result = run.report()
    (group,) = result["metrics"]["confusion"]
    (curve,) = result["metrics"]["auroc"]
    text = report.markdown(result)
    assert group["status"] == status
    # The run itself stays complete and keeps its reward distribution.
    assert result["status"] == "complete" and result["ordinary"]["groups"][0]["rewards"]["reward"]["distribution"]
    # A native pass rate describes every usable reward under the rule, whatever the agreement status.
    if group["rule"]:
        summary = result["ordinary"]["groups"][0]["rewards"][group["reward"]]
        assert (group["pass_rate"]["denominator"], group["pass_rate"]["unavailable"]) == (summary["usable"], None)
        assert f"- Native pass rate for xiaomi_mimo/mimo-v2.6-pro {group['reward']}" in text
    else:
        assert group["pass_rate"]["value"] is None and "no source-grounded native decision rule" in group["pass_rate"]["unavailable"]
    if case == "rubric_threshold":
        assert group["pass_rate"]["numerator"] == 2
    if status == "supported":
        assert (group["reasons"], group["episodes"], group["tp"], group["tn"]) == ([], names, 2, 1)
        assert curve["auroc"] == 1.0
        return
    assert group["reasons"][0] == message and group["episodes"] == []
    values = [group[key] for key in ("tp", "fp", "fn", "tn", "f1", "presumed", "verified")]
    values += [group[key]["value"] for key in ("false_discovery_rate", "false_negative_rate")]
    assert values == [None] * 9
    assert (curve["positives"], curve["negatives"], curve["auroc"]) == (None, None, None)
    assert f"grader agreement is {status}" in curve["unavailable"]
    assert message in "\n".join(result["warnings"])
    assert f"{group['reward']}: {status}, no agreement values. {message}" in text and "TP 0" not in text
    assert result["metrics"]["coverage"]["excluded"]["no_binary_contract"] == names
    if case == "contradicted":
        assert "0.5" in " ".join(group["reasons"])


def presumed(run: RunDir, value: float) -> str:
    name = run.episode(rewards={"reward": value})
    run.grader.ordinary[name] = EpisodeLabel(label="legitimate", basis="presumed", reasons=["presumed to follow the grader"])
    run.grader.ordinary_inspection = "holistic_inspection"
    return name


def test_rates_that_use_presumed_labels_are_marked_lower_bounds(tmp_path):
    run = RunDir(tmp_path)
    verified = binary_matrix(run, 1, 1, 1, 0)
    assumed = [presumed(run, value) for value in (1.0, 1.0, 0.0)]

    result = run.report()
    (group,) = result["metrics"]["confusion"]
    assert group["episodes"] == verified + assumed and (group["presumed"], group["verified"]) == (3, 3)
    assert (group["tp"], group["fp"], group["fn"], group["tn"]) == (3, 1, 1, 1)
    assert [result["metrics"]["episodes"][name]["decision"] for name in assumed] == ["pass", "pass", "fail"]
    for key in ("false_discovery_rate", "false_negative_rate"):
        assert group[key] == {"value": 0.25, "numerator": 1, "denominator": 4, "lower_bound": True, "unavailable": None}
    assert result == json.loads(report.write(run.path)[0].read_text())
    text = (run.path / "report.md").read_text()
    assert ("false discovery rate at least 0.25 (1/4, lower bound); false negative rate at least 0.25 (1/4, lower bound); "
            "presumed 3, verified 3") in text
    assert any("lower bounds" in note for note in result["notes"])

    # Only a presumed rejection can hide a false negative; it cannot hide a false discovery.
    rejected = RunDir(tmp_path / "rejected")
    binary_matrix(rejected, 1, 0, 0, 0)
    presumed(rejected, 0.0)
    (group,) = rejected.report()["metrics"]["confusion"]
    assert group["false_discovery_rate"]["lower_bound"] is False and group["false_negative_rate"]["lower_bound"] is True

    # A presumption is never a way around the binary reward contract.
    alone = RunDir(tmp_path / "alone")
    alone.label(alone.episode(rewards={"reward": 1.0}), "unknown")
    presumed(alone, 1.0)
    presumed(alone, 0.0)
    (group,) = alone.report()["metrics"]["confusion"]
    assert (group["status"], group["reasons"][0], group["episodes"], group["presumed"]) == ("unavailable", UNKNOWN_REWARD, [], None)


def test_native_decisions_use_exact_encodings_without_tolerance(tmp_path):
    run = RunDir(tmp_path)
    encoded = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="print 1"), pass_values=[1.0])
    equal = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="print 1"), comparison="==", threshold=1.0)
    near = 1.0000000005
    names = [referenced(run, "violated", {"reward": value}, decision=rule)
             for value, rule in ((near, encoded), (1.0, encoded), (near, equal), (1.0, equal))]

    episodes = run.report()["metrics"]["episodes"]
    assert [episodes[name]["decision"] for name in names] == ["fail", "pass", "fail", "pass"]


def test_one_check_supports_one_requirement_while_violating_another(tmp_path):
    """A supported A and a violated B from one check stay distinct conclusions."""
    run = RunDir(tmp_path)

    def mixed(completion, keys):
        name = run.episode(rewards={"reward": 0.5})
        assessment = checked(name, f"check-{name}", "sorted", "supported", basis=basis(completion, keys, [f"check-{name}"]))
        assessment.conclusions = [Conclusion(requirement=requirement("summary"), validity="violated")]
        run.label(name, "unknown", assessment)
        return name

    names = [mixed("violated", ["summary"]), mixed("supported", ["sorted", "summary"]), mixed("supported", ["sorted"])]
    episodes = run.report()["metrics"]["episodes"]
    assert [episodes[name]["completion"] for name in names] == ["incomplete", "unknown", "unknown"]
    for name in names[1:]:
        reasons = " ".join(episodes[name]["completion_reasons"])
        assert REQUIREMENTS["summary"] in reasons and "violated" in reasons
    assert "completion basis" in " ".join(episodes[names[2]]["completion_reasons"])


def test_conflicting_requirement_conclusions_keep_completion_unknown(tmp_path):
    run = RunDir(tmp_path)
    contested = run.episode(rewards={"reward": 1.0})
    run.label(contested, "unknown", checked(contested, "k0", "sorted", "supported"),
              checked(contested, "k1", "sorted", "violated", basis=basis("violated", ["sorted"], ["k1"])))
    claimed = run.episode(rewards={"reward": 1.0})
    run.label(claimed, "unknown", checked(claimed, "k2", "sorted", "violated"),
              checked(claimed, "k3", "sorted", "supported", basis=basis("supported", ["sorted"], ["k3"])))
    # One uncontested violation still decides beside a contested one.
    decided = run.episode(rewards={"reward": 1.0})
    run.label(decided, "unknown", checked(decided, "k4", "sorted", "supported"), checked(decided, "k5", "sorted", "violated"),
              checked(decided, "k6", "summary", "violated", basis=basis("violated", ["sorted", "summary"], ["k5", "k6"])))

    episodes = run.report()["metrics"]["episodes"]
    assert [episodes[name]["completion"] for name in (contested, claimed, decided)] == ["unknown", "unknown", "incomplete"]
    for name in (contested, claimed):
        assert any("conflicting" in reason for reason in episodes[name]["completion_reasons"])


COMPLETE = "# Only a reward of 1.0 means the whole task is complete."


def test_requested_basis_is_retained_and_partial_credit_can_have_a_noncompletion_reference(tmp_path, monkeypatch, credentials):
    """Legitimate partial credit: the explanation earns 0.5 and the answer is omitted.
    The Inspector separately establishes noncompletion; finding a defect is unnecessary."""
    task = task_with_artifacts(tmp_path, '["/app/explanation.txt", "/app/answer.txt"]')
    with (task / "tests" / "test.sh").open("a") as file:
        file.write(f"\n{HALVES}\n{COMPLETE}\n")
    native = Native(monkeypatch, files={"0000-simulator": {"/app/explanation.txt": b"because\n"}}, rewards={"0000-simulator": 0.5})
    Sandboxes(monkeypatch, native=native)
    scoring = {"episode": None, "path": "tests/test.sh", "excerpt": HALVES}
    rule = {"source": {"episode": None, "path": "tests/test.sh", "excerpt": COMPLETE}, "pass_values": [1.0], "values": [0.0, 0.5, 1.0]}
    reference = {"completion": "violated", "requirements": [REFERENCES["answer"]], "checks": ["check-0001"],
                 "explanation": "The task requires the answer, which is absent.", "decision": rule}
    covered = {"requirements": [REFERENCES["explanation"], REFERENCES["answer"]], "scoring": scoring,
               "checks": ["check-0000", "check-0001"], "explanation": "The explanation alone earns the actual 0.5."}

    def half(requirement):
        name = "correct" if requirement == "answer" else "exists"
        return {**probe("0000-simulator", requirement), "category": "accepted_invalid", "scoring": scoring,
                "program": HALF_CHECKERS[name]}

    def bounded(validity, name, **claim):
        return {"claim": {"mechanism": "half credit", "interpretation": f"{name} earns 0.5 of the reward.",
                          "derivation": {"observations": [name], "validity": validity},
                          **claim}}

    script = InspectorScript([{"probes": [half("explanation"), half("answer")]}, bounded("supported", "exists"),
                              bounded("violated", "correct", coverage=covered, basis=reference)])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 1)
            inspection = await checks.inspect_grader(run, simulation.episodes, categories=["accepted_invalid"], focused_attempts=0)
            return run, inspection

    run, inspection = asyncio.run(main())
    assert "`basis`" in script.requests[0]["messages"][0]["content"]
    # Each half lives in its own file, so no check has the whole deserved score and the label stays unknown (a recorded limit).
    assert inspection.ordinary["0000-simulator"].label == "unknown"
    assert inspection.status == "partial", "an unresolved ordinary review keeps the grader inspection partial"
    retained = InspectionResult.model_validate_json((run.config.output_dir / "inspection-grader.json").read_text())
    assert retained.assessments[1].claim.basis.completion == "violated"
    assert retained.assessments[1].claim.basis.decision.values == [0.0, 0.5, 1.0]

    metrics = report.build(run.config.output_dir)["metrics"]
    episode = metrics["episodes"]["0000-simulator"]
    assert (episode["completion"], episode["decision"]) == ("incomplete", "fail")
    # The rubric total is not binary, so its pass rule supplies no grader agreement.
    (group,) = metrics["confusion"]
    assert (group["status"], group["reasons"][0]) == ("unsupported", NON_BINARY)
    assert (group["tp"], group["fp"], group["fn"], group["tn"], group["f1"]) == (None,) * 5


def test_auroc_needs_a_binary_contract_grounded_ordering_and_both_classes_and_counts_ties_as_half(tmp_path):
    run = RunDir(tmp_path)
    for completion, value in (("supported", 1.0), ("supported", 0.0), ("violated", 0.0), ("violated", 0.0)):
        referenced(run, completion, {"reward": value}, decision=RULE, ordering=ORDER)
    unordered = referenced(run, "supported", {"reward": 1.0})
    lower = ORDER.model_copy(update={"reward": "loss", "higher_completes": False})
    low_loss = referenced(run, "supported", {"loss": 0.1}, ordering=lower)
    referenced(run, "violated", {"loss": 0.3}, ordering=lower)
    one_class = ORDER.model_copy(update={"reward": "partial"})
    referenced(run, "supported", {"partial": 0.2}, ordering=one_class)
    # A configuration without an established binary reward contract reports no AUROC value.
    for completion, value in (("supported", 1.0), ("violated", 0.5)):
        referenced(run, completion, {"reward": value}, model="openai/gpt-6", ordering=ORDER)

    metrics = run.report()["metrics"]
    groups = {(group["configuration"]["model"], group["reward"]): group for group in metrics["auroc"]}
    reward = groups["xiaomi_mimo/mimo-v2.6-pro", "reward"]
    assert (reward["positives"], reward["negatives"]) == (2, 2)
    assert reward["auroc"] == 0.75
    loss = groups["xiaomi_mimo/mimo-v2.6-pro", "loss"]
    assert loss["higher_completes"] is False and loss["auroc"] == 1.0
    assert metrics["episodes"][low_loss]["score"] == 0.1
    partial = groups["xiaomi_mimo/mimo-v2.6-pro", "partial"]
    assert partial["auroc"] is None and "both classes" in partial["unavailable"]
    assert metrics["episodes"][unordered]["score"] is None
    assert any("no source-grounded score ordering" in reason for reason in metrics["episodes"][unordered]["ordering_reasons"])
    unknown = groups["openai/gpt-6", "reward"]
    assert (unknown["positives"], unknown["negatives"], unknown["auroc"]) == (None, None, None)
    assert "grader agreement is unavailable" in unknown["unavailable"]


@pytest.mark.parametrize("invalid", ["package", "other_episode"])
def test_ordinary_metrics_exclude_package_or_other_episode_evidence(tmp_path, invalid):
    run = RunDir(tmp_path)
    supported = referenced(run, "supported", {"reward": 1.0}, decision=RULE, ordering=ORDER)
    violated = referenced(run, "violated", {"reward": 0.0}, decision=RULE, ordering=ORDER)
    for assessment in run.grader.assessments:
        if invalid == "package":
            assessment.execution_scope = "package"
        else:
            assessment.check.content.episode = "another-episode"
    metrics = run.report()["metrics"]
    assert [(metrics["episodes"][name]["completion"], metrics["episodes"][name]["decision"],
             metrics["episodes"][name]["score"]) for name in (supported, violated)] == [
                 ("unknown", None, None), ("unknown", None, None)]
    (group,) = metrics["confusion"]
    assert (group["status"], group["episodes"], group["tp"]) == ("unavailable", [], None) and metrics["auroc"] == []
    assert report.reference(supported, run.grader.assessments)[0] == "unknown"
