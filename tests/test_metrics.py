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
RULE = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="at least 0.5"), comparison=">=", threshold=0.5)
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
        start = len(self.grader.assessments)
        self.grader.assessments.extend(assessments)
        self.grader.ordinary[name] = EpisodeLabel(label=label, reasons=[f"{label} label"],
                                                  assessments=list(range(start, len(self.grader.assessments))))

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
        claim=Claim(mechanism="omitted_requirements", episode=episode, check=check, interpretation=f"{key} is {validity}",
                    unresolved=list(unresolved), basis=basis),
        outcome=outcome, validity=validity, discrepancy="unknown" if validity == "unknown" else "none",
        check=Check(id=check, content=Content(episode=episode, path="nudi-evidence/out.json", sha256="a" * 64),
                    ids={"trial_id": episode}, requirement=requirement(key), command=["python", "-c", "check"],
                    exit_code=0, output="{}"))


def basis(completion: str, keys: list[str], checks: list[str], **fields) -> MetricBasis:
    return MetricBasis(completion=completion, requirements=[requirement(key) for key in keys], checks=checks,
                       explanation=f"completion {completion}", **fields)


def referenced(run: RunDir, completion: str, rewards: dict, **fields) -> str:
    """An ordinary episode whose one check settles its single-requirement completion."""
    name = run.episode(rewards=rewards)
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
    # Legitimate partial credit without a completion basis supplies neither label.
    partial = run.episode(rewards={"reward": 0.4})
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

    (group,) = result["metrics"]["confusion"]
    assert group["episodes"] == [complete_pass, violated_pass, complete_fail, violated_fail]
    assert (group["tp"], group["fp"], group["fn"], group["tn"]) == (1, 1, 1, 1)
    assert group["f1"] == 0.5 and group["rule"]["threshold"] == 0.5
    # Local findings stay separate from binary labels.
    assert result["labels"]["counts"] == {"accepted_invalid": 2, "legitimate": 2, "rejected_valid": 1,
                                          "unavailable": 1, "unknown": 2}


def test_rewards_alone_never_supply_a_native_decision_and_f1_needs_a_denominator(tmp_path):
    run = RunDir(tmp_path)
    invented = RULE.model_copy(update={"source": Observation(episode=None, path="tests/test.sh", excerpt="at least 0.9")})
    encoded = DecisionRule(source=Observation(episode=None, path="tests/test.sh", excerpt="print 1"), pass_values=[1.0])
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
    rule = {"source": {"episode": None, "path": "tests/test.sh", "excerpt": COMPLETE}, "pass_values": [1.0]}
    reference = {"completion": "violated", "requirements": [REFERENCES["answer"]], "checks": ["check-0001"],
                 "explanation": "The task requires the answer, which is absent.", "decision": rule}
    covered = {"requirements": [REFERENCES["explanation"], REFERENCES["answer"]], "scoring": scoring,
               "checks": ["check-0000", "check-0001"], "explanation": "The explanation alone earns the actual 0.5."}

    def half(requirement):
        name = "correct" if requirement == "answer" else "exists"
        return {**probe("0000-simulator", requirement), "category": "partial_credit", "scoring": scoring,
                "program": HALF_CHECKERS[name]}

    def bounded(validity, name, **claim):
        return {"claim": {"mechanism": "half credit", "interpretation": f"{name} earns 0.5 of the reward.",
                          "derivation": {"observations": [name], "minimum": "minimum", "maximum": "maximum", "validity": validity},
                          **claim}}

    script = InspectorScript([{"locations": []}, {"probes": [half("explanation"), half("answer")]}, bounded("supported", "exists"),
                              bounded("violated", "correct", coverage=covered, basis=reference)])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            simulation = await workflow.simulate(run, 1)
            inspection = await checks.inspect_grader(run, simulation.episodes, categories=["partial_credit"], focused_attempts=0)
            return run, inspection

    run, inspection = asyncio.run(main())
    assert "`basis`" in script.requests[0]["messages"][0]["content"]
    assert inspection.ordinary["0000-simulator"].label == "legitimate"
    retained = InspectionResult.model_validate_json((run.config.output_dir / "inspection-grader.json").read_text())
    assert retained.assessments[1].claim.basis.completion == "violated"

    metrics = report.build(run.config.output_dir)["metrics"]
    episode = metrics["episodes"]["0000-simulator"]
    assert (episode["completion"], episode["decision"]) == ("incomplete", "fail")
    (group,) = metrics["confusion"]
    assert (group["tp"], group["fp"], group["fn"], group["tn"]) == (0, 0, 0, 1)


def test_auroc_needs_grounded_ordering_both_classes_and_counts_ties_as_half(tmp_path):
    run = RunDir(tmp_path)
    for completion, value in (("supported", 1.0), ("supported", 0.5), ("violated", 0.5), ("violated", 0.0)):
        referenced(run, completion, {"reward": value}, ordering=ORDER)
    unordered = referenced(run, "supported", {"reward": 1.0})
    lower = ORDER.model_copy(update={"reward": "loss", "higher_completes": False})
    low_loss = referenced(run, "supported", {"loss": 0.1}, ordering=lower)
    referenced(run, "violated", {"loss": 0.3}, ordering=lower)
    one_class = ORDER.model_copy(update={"reward": "partial"})
    referenced(run, "supported", {"partial": 0.2}, ordering=one_class)

    metrics = run.report()["metrics"]
    groups = {group["reward"]: group for group in metrics["auroc"]}
    assert (groups["reward"]["positives"], groups["reward"]["negatives"]) == (2, 2)
    assert groups["reward"]["auroc"] == 0.875
    assert groups["loss"]["higher_completes"] is False and groups["loss"]["auroc"] == 1.0
    assert metrics["episodes"][low_loss]["score"] == 0.1
    assert groups["partial"]["auroc"] is None and "both classes" in groups["partial"]["unavailable"]
    assert metrics["episodes"][unordered]["score"] is None
    assert any("no source-grounded score ordering" in reason for reason in metrics["episodes"][unordered]["ordering_reasons"])
    assert not metrics["confusion"]


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
    assert metrics["confusion"] == [] and metrics["auroc"] == []
    assert report.reference(supported, run.grader.assessments)[0] == "unknown"
