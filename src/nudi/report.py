"""Deterministic JSON and Markdown reports from a run's retained records.

A report reads `run.json`, episode records, `inspection-*.json` and `attack.json`; it
starts no episode or model call. Claims and references are Inspector interpretations:
nudi checks their retained provenance and consistency, not semantic correctness.
Resolved credentials passed as `secrets` never reach the output.
"""

import json
import math
import operator
import statistics
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from nudi.assessment import Evidence, Ungrounded, classify_probe, conclusions
from nudi.checks import AttackResult, InspectionResult, evidenced
from nudi.records import PROVIDER_REPORTED, Assessment, EpisodeResult, MetricBasis, Observation, RunRecord, write_private

ANALYSES = ("simulation", "grader", "hack", "attack")
FILES = {"grader": "inspection-grader.json", "hack": "inspection-hack.json", "attack": "attack.json"}
SETTLED = ("evidenced_issue", "no_evidenced_issue")
UNSUPPORTED_LABELS = ("unknown", "unavailable", "ungrounded", "unreviewed")
COMPARISONS = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "==": operator.eq}
DESCRIPTIVE = "descriptive only; difficulty, sampling and execution conditions limit what rewards show"
LOCAL_LIMIT = (
    "Local over-credit and under-credit labels compare one native reward with one deserved score. "
    "They are not binary FP/FN labels, and legitimate partial credit is not a false pass."
)
METRIC_LIMIT = (
    "F1, AUROC and the false discovery and false negative rates compare native decisions and scores with "
    "evidence-grounded grader inspector references. nudi checks their retained provenance and consistency, not semantic "
    "correctness or calibrated accuracy. Whether a reference's requirements match the grader's acceptance rule is "
    "the grader inspector's interpretation, not independently validated."
)
NON_BINARY = ("Non-binary rewards are currently not supported in grader agreement analysis. "
              "Wrong partial scores were not searched; that search is not supported yet.")
UNKNOWN_REWARD = "Reward type could not be established; grader agreement analysis currently supports binary rewards only."
AGREEMENT_LIMIT = (
    "Grader agreement covers binary rewards only. False discovery rate is FP / (TP + FP) and false negative rate is "
    "FN / (TP + FN); both are observed proportions of the eligible episodes, not multiple-testing guarantees, and the "
    "false positive rate FP / (FP + TN) is a different quantity. The default 20 ordinary runs give rough estimates. "
    "Unresolved episodes may be systematically harder, so the rates describe the eligible subset, not the whole pool. "
    "A presumed label stands in for the grader's own verdict, so rates that use one are lower bounds and F1 is then an upper bound."
)
# Why an ordinary episode stays out of grader agreement, in the order they are checked.
EXCLUDED = ("operational_failure", "missing_reward", "unreviewed", "inconclusive", "no_binary_contract", "no_decision_rule")
PACKAGE_LIMIT = (
    "Package evidence: an Inspector sandbox ran a copy of the task package, so this finding establishes what the "
    "copied package did, not native accessibility to a task agent. Setup privileges include copied tests, helpers "
    "and verifier outputs. Original host tests are uploaded after the verification_start copy, so replacement test "
    "bytes in that copy do not prove their later execution. Separate-verifier configurations do not establish native isolation parity."
)
NO_RATE = (
    "Each candidate, hint level, and no-hint discovery stops at its first independently evidenced exploit, "
    "so attempt counts give no unbiased success-rate estimate. Not found means not found within the actual attempts. "
    "Only the attack inspector's attribution to a check of the same episode confirms the candidate under test; "
    "an unrelated or unattributed exploit does not."
)
FINDINGS_NOTE = (
    "An evidenced finding is accepted_invalid (violating work received more than its deserved score) or rejected_valid "
    "(valid work received less than it deserved). A finding with open conditions is still evidenced; its open conditions "
    "are listed beside it. A legitimate finding has a reward equal to its deserved score and no open condition, which does "
    "not judge the work. An inconclusive finding established no outcome, or is legitimate with an open condition. Package findings come from an Inspector sandbox "
    "running a copy of the task package, native findings from a task episode. An earlier reading of a check stays listed, "
    "marked with the later reading that superseded it. Category settlement and the evidenced count read the latest "
    "reading of each check; local labels and metrics read every reading."
)
CATEGORY_RULE = (
    "A category is evidenced_issue once one of its cases is evidenced (for the hack inspector, an accepted_invalid case), and a "
    "later reading does not withdraw it. It is no_evidenced_issue only when its attempts completed after any failure, its "
    "applicability evidence is applicable, and the latest reading of each case measured before the episode sessions is "
    "consistent with its reward or evidenced; otherwise it stays unknown. A case belongs to the category of its experiment. "
    "A hack inspector case outside the requested categories keeps its own family, or `other` when none fits, and leaves "
    "the requested categories alone; an open grader inspector case without an inspected category keeps every category open. A repair, which interprets an ordinary "
    "check again in a later session, evidences the category of that session. The Inspector's applicability text is in "
    "the JSON report."
)


def build(run_dir: Path, secrets=(), selected=None) -> dict:
    """The report of the run in `run_dir`. `selected` names the requested analyses,
    by default those with retained records; completion is relative to them."""
    record = RunRecord.model_validate_json((run_dir / "run.json").read_text())
    present = {"simulation": record.simulation is not None, **{name: (run_dir / file).is_file() for name, file in FILES.items()}}
    selected = [name for name in ANALYSES if present[name]] if selected is None else list(selected)
    if any(name not in ANALYSES for name in selected):
        raise ValueError(f"analyses must be among {', '.join(ANALYSES)}")
    loaded = {name: (AttackResult if name == "attack" else InspectionResult).model_validate_json((run_dir / file).read_text())
              for name, file in FILES.items() if name in selected and present[name]}
    warnings, notes, analyses = [f"run: {warning}" for warning in record.warnings], [], {}
    for name in selected:
        if not present[name]:
            analyses[name] = "not run"
            warnings.append(f"{name} was selected but not run")
            continue
        analyses[name] = record.simulation.status if name == "simulation" else loaded[name].status
        if analyses[name] != "complete":
            warnings.append(f"{name} {analyses[name]}: its coverage is incomplete")
    if record.unknown_cost_calls:
        warnings.append(f"{record.unknown_cost_calls} model calls have unknown prices; the known cost excludes them")

    results = {name: episode(run_dir, name) for name in record.episodes}
    pool = record.simulation.episodes if record.simulation else []
    report = {
        "status": "complete" if all(status == "complete" for status in analyses.values()) else "partial",
        "analyses": analyses,
        "configuration": configuration_section(record, results),
        "copies": state_copies(record),
        "ordinary": ordinary(record, results, warnings, notes) if "simulation" in selected and present["simulation"] else None,
        "other_episodes": {
            "sandboxes": list(record.sandboxes),
            # Native Inspector episodes exist only in runs retained before Inspector sandboxes.
            "inspector": [name for name in record.episodes if name.endswith("-inspector") and name not in record.probe_episodes],
            "attacker": [name for name in record.episodes if name.endswith("-attacker") and name not in record.probe_episodes],
            "probes": list(record.probe_episodes),
        },
        "labels": None,
        "metrics": None,
        "inspections": {f"{mode}_inspector": inspection(mode, loaded[mode], warnings) for mode in ("grader", "hack") if mode in loaded},
        "attack": attack(loaded["attack"], record, warnings) if "attack" in loaded else None,
        "persistence": persistence(record, warnings),
        "warnings": warnings,
        "notes": notes,
    }
    if "grader" in loaded:
        report["labels"] = labels(pool, loaded["grader"], warnings)
        report["metrics"] = metrics(run_dir, pool, results, loaded["grader"], warnings)
        notes += [LOCAL_LIMIT, METRIC_LIMIT, AGREEMENT_LIMIT]
    if "attack" in loaded:
        notes.append(NO_RATE)
    if loaded:
        notes.append(FINDINGS_NOTE)
    if report["inspections"]:
        notes.append(CATEGORY_RULE)
    return scrub(report, [secret for secret in secrets if secret])


def write(run_dir: Path, secrets=(), selected=None) -> tuple[Path, Path]:
    """Write `report.json` and `report.md` beside the run's records."""
    report = build(run_dir, secrets, selected)
    paths = run_dir / "report.json", run_dir / "report.md"
    write_private(paths[0], json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_private(paths[1], markdown(report))
    return paths


def scrub(value, secrets: list[str]):
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[redacted]")
        return value
    if isinstance(value, dict):
        return {scrub(key, secrets): scrub(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, secrets) for item in value]
    return value


def state_copies(record: RunRecord) -> list[dict]:
    """The run's state copies, failed ones with their error."""
    return [copy.model_dump(mode="json", exclude={"ids", "started_at", "finished_at", "receipt"}) for copy in record.copies]


def episode(run_dir: Path, name: str) -> EpisodeResult | None:
    path = run_dir / "episodes" / name / "episode.json"
    return EpisodeResult.model_validate_json(path.read_text()) if path.is_file() else None


def configuration(result: EpisodeResult) -> dict:
    """Task, model, harness and configuration: ordinary statistics never mix them."""
    return {"task_name": result.task_name, "task_digest": result.task_digest, "model": result.model,
            "reasoning_effort": result.reasoning_effort, "path": result.path, "versions": result.versions}


# Modal's prices per core second and per GiB second (modal.com/pricing, read 2026-11-04).
MODAL_CORE_SECOND, MODAL_GIB_SECOND = 0.00003942, 0.00000667
# Harbor's default Modal sandbox lifetime, which nudi keeps.
MODAL_LIFETIME = timedelta(hours=24)


def modal_cost(record: RunRecord) -> dict | None:
    """An upper-bound estimate of a Modal run's compute: each stopped sandbox's CPU and memory
    limits over its lifetime. Modal bills the larger of request and use, and nudi's requests
    stay below the limits. It is outside the spending cap. A sandbox without declared limits
    is counted apart, and one that still runs after stop counts its whole 24 h lifetime."""
    if record.backend != "modal":
        return None
    estimate, without_limits = 0.0, 0
    for sandbox in record.modal:
        if sandbox.cpus is None or sandbox.memory_mb is None:
            without_limits += 1
            continue
        started = datetime.fromisoformat(sandbox.started_at)
        stopped = datetime.fromisoformat(sandbox.stopped_at) if sandbox.removed else started + MODAL_LIFETIME
        seconds = (stopped - started).total_seconds()
        estimate += seconds * (sandbox.cpus * MODAL_CORE_SECOND + sandbox.memory_mb / 1024 * MODAL_GIB_SECOND)
    return {"estimate": estimate, "sandboxes": len(record.modal), "without_limits": without_limits,
            "still_running": sum(not sandbox.removed for sandbox in record.modal)}


def configuration_section(record: RunRecord, results: dict) -> dict:
    """Credentials appear only as their variable names and where they were found.

    `provenance` groups every retained episode record, of any role, by its task digest,
    model and version pins; episodes without a record are listed as unavailable."""
    provenance = {}
    for name, result in results.items():
        if result is not None:
            provenance.setdefault(json.dumps(configuration(result), sort_keys=True), []).append(name)
    # The task directory's name only; its host path stays in run.json, out of a report that may be shared.
    return {"task_dir": Path(record.task_dir).name, "path": record.path, "path_reasons": record.path_reasons,
            "provenance": [{"configuration": json.loads(key), "episodes": names} for key, names in provenance.items()],
            "provenance_unavailable": {name: "no retained episode record, so its task digest and version pins are unavailable"
                                       for name, result in results.items() if result is None},
            "models": {role: model.model_dump(mode="json") for role, model in record.models.items()},
            "credential_sources": record.credential_sources, "spending_cap": record.spending_cap,
            "known_cost": record.known_cost, "provider_reported_cost": reported(record.calls), "unknown_cost_calls": record.unknown_cost_calls,
            "refused_calls": record.refused_calls, "capacity": record.capacity.model_dump(mode="json"),
            "backend": record.backend, "modal_cost": modal_cost(record),
            "cost_map": record.cost_map, "limitations": record.limitations}


def summarize(key: str, names: list[str], results: dict) -> dict:
    """Missing and non-finite rewards are excluded and listed, never zero."""
    values, missing, invalid = [], [], []
    for name in names:
        value = results[name].rewards.get(key)
        if value is None:
            missing.append(name)
        elif not math.isfinite(value):
            invalid.append(name)
        else:
            values.append(value)
    unavailable = []
    if not values:
        unavailable.append(f"no usable {key!r} reward, so its mean is unavailable")
    if len(values) < 2:
        unavailable.append(f"fewer than two usable {key!r} rewards, so its sample SD is unavailable")
    return {"attempted": len(names), "usable": len(values), "missing": missing, "invalid": invalid,
            "mean": statistics.fmean(values) if values else None,
            "sd": statistics.stdev(values) if len(values) > 1 else None,
            "distribution": [[value, count] for value, count in sorted(Counter(values).items())],
            "unavailable": unavailable}


def ordinary(record: RunRecord, results: dict, warnings: list[str], notes: list[str]) -> dict:
    """The ordinary Simulator pool only; targeted probes and attacker episodes stay outside."""
    simulation = record.simulation
    groups, unrecorded = {}, {}
    for name in simulation.episodes:
        if results.get(name) is None:
            unrecorded[name] = [f"{error.type}: {error.message}" for error in simulation.failures.get(name, [])]
        else:
            groups.setdefault(json.dumps(configuration(results[name]), sort_keys=True), []).append(name)
    if len(simulation.episodes) < simulation.requested:
        warnings.append(f"simulation attempted {len(simulation.episodes)} of {simulation.requested} requested ordinary episodes")
    if unrecorded:
        warnings.append(f"{len(unrecorded)} attempted ordinary episodes have no retained record ({', '.join(unrecorded)}); "
                        "they are excluded, never zero")
    summaries = []
    for key, names in groups.items():
        config = json.loads(key)
        rewards = {reward: summarize(reward, names, results)
                   for reward in sorted({"reward", *(item for name in names for item in results[name].rewards)})}
        for reward, summary in rewards.items():
            label, excluded = f"{config['model']} {reward}", summary["missing"] + summary["invalid"]
            if excluded:
                warnings.append(f"{label}: {len(excluded)} of {summary['attempted']} ordinary episodes have no usable reward "
                                f"(missing: {', '.join(summary['missing']) or 'none'}; invalid: {', '.join(summary['invalid']) or 'none'}); "
                                "they are excluded, never zero")
            warnings += [f"{label}: {reason}" for reason in summary["unavailable"]]
            distribution = summary["distribution"]
            if len(distribution) == 1:
                notes.append(f"{label}: constant {distribution[0][0]} across {summary['usable']} usable rewards; {DESCRIPTIVE}")
            elif distribution:
                notes.append(f"{label}: mixed, from {distribution[0][0]} to {distribution[-1][0]}; {DESCRIPTIVE}")
        summaries.append({"configuration": config, "episodes": names, "rewards": rewards})
    return {"requested": simulation.requested, "attempted": len(simulation.episodes), "status": simulation.status,
            "unrecorded": unrecorded, "refusals": simulation.refusals,
            "failures": {name: [f"{error.type}: {error.message}" for error in errors] for name, errors in simulation.failures.items()},
            "groups": summaries}


def labels(pool: list[str], result: InspectionResult, warnings: list[str]) -> dict:
    """Local grader labels of the ordinary pool, separate from binary metrics."""
    unreviewed = {"label": "unreviewed", "basis": None, "reasons": ["the grader inspector retained no label for this episode"]}
    episodes = {name: result.ordinary[name].model_dump(mode="json", include={"label", "basis", "reasons"})
                if name in result.ordinary else unreviewed for name in pool}
    counts = dict(sorted(Counter(item["label"] for item in episodes.values()).items()))
    basis = {kind: sum(item["basis"] == kind for item in episodes.values()) for kind in ("presumed", "verified")}
    if basis["presumed"]:
        warnings.append(f"{basis['presumed']} of {len(pool)} ordinary episodes have presumed labels that follow the grader's reward; "
                        "a presumed label is not evidence of grader correctness")
    lacking = {label: counts[label] for label in UNSUPPORTED_LABELS if label in counts}
    if lacking:
        warnings.append(f"{sum(lacking.values())} of {len(pool)} ordinary episodes have no supported local label "
                        f"({', '.join(f'{label} {count}' for label, count in lacking.items())}); "
                        "they are excluded, not counted as correct")
    if result.unreviewed:
        warnings.append(f"{len(result.unreviewed)} of {len(pool)} ordinary episodes were not reviewed: "
                        + "; ".join(f"{name}: {reason}" for name, reason in result.unreviewed.items()))
    # Attempted, unreviewed and supported are separate: a reviewed but inconclusive episode stays unknown.
    attempted = [name for name in pool if any(item.episode == name for item in result.reviews)]
    review = {"attempted": attempted, "unreviewed": result.unreviewed,
              "unresolved": [name for name in attempted if episodes[name]["label"] == "unknown"],
              "supported": [name for name, item in episodes.items()
                            if item["label"] not in UNSUPPORTED_LABELS and item["basis"] != "presumed"]}
    return {"mode": result.ordinary_inspection, "counts": counts, "basis": basis, "review": review, "episodes": episodes}


def completion_gaps(basis: MetricBasis, own: list[Assessment], run_dir: Path, name: str) -> tuple[list[str], list[Observation]]:
    """Why a basis does not establish completion, empty when it does, and the cited requirements
    no check of this episode reads. `own` are the episode's own checked assessments, each with
    one conclusion per requirement it read. An unread requirement is listed, not a reason, while a
    cited check observes another cited requirement satisfied, no check of this episode observes a
    violation and its quote is in the task.
    Semantic completeness stays the grader inspector's interpretation."""
    if basis.completion == "unknown":
        return [f"the grader inspector left completion unknown: {basis.explanation}"], []
    gaps = [f"unresolved: {item}" for item in basis.unresolved]
    if not basis.explanation.strip():
        gaps.append("its basis explains nothing")
    if not basis.requirements:
        gaps.append("it cites no completion requirement")
    gaps += [f"requirement {item.path}: {item.excerpt!r} is not task context" for item in basis.requirements if item.episode is not None]
    # Doubt is one-sided: an evidenced issue counts with its open claim items; any other assessment needs none.
    resolved = [item for item in own if (evidenced(item) or not item.claim.unresolved)
                and any(validity != "unknown" for _, validity in conclusions(item))]
    cited = [item for item in resolved if item.check.id in basis.checks]
    every = [found for item in resolved for found in conclusions(item) if found[1] != "unknown"]
    observed = [found for item in cited for found in conclusions(item) if found[1] != "unknown"]

    def contested(requirement: Observation) -> bool:
        return {"supported", "violated"} <= {validity for other, validity in every if other == requirement}

    conflicts = [f"this episode's checks reach conflicting conclusions on requirement {item.path}: {item.excerpt!r}"
                 for item in basis.requirements if contested(item)]
    if basis.completion == "violated":
        # One uncontested violation suffices; unrelated unknown or contested conclusions do not erase it.
        if not any(validity == "violated" and item in basis.requirements and not contested(item) for item, validity in observed):
            gaps += conflicts or ["no cited resolved check of this episode observed a violation of a cited requirement"]
        return gaps, []
    gaps += [f"cited check {id} is not a resolved check of this episode" for id in basis.checks if all(item.check.id != id for item in cited)]
    gaps += conflicts
    gaps += [f"cited check observed requirement {item.path}: {item.excerpt!r} violated outside the completion basis; its relevance is unresolved"
             for item, validity in observed if validity == "violated" and item not in basis.requirements]
    read = [requirement for item in own for requirement, _ in conclusions(item)]
    violation = any(validity == "violated" for item in own for _, validity in conclusions(item))
    unobserved = []
    for item in basis.requirements:
        if contested(item):
            continue
        if (item, "violated") in every:
            gaps.append(f"requirement {item.path}: {item.excerpt!r} was observed violated")
        elif item not in read:
            # A violation may be this requirement quoted differently.
            if violation:
                gaps.append(f"no check reads requirement {item.path}: {item.excerpt!r} and a check of this episode observed a violation")
            elif reason := grounded(run_dir, name, item):
                gaps.append(f"requirement {item.path}: {item.excerpt!r}: {reason}")
            else:
                # Grounding the quote does not establish the episode met it.
                gaps.append(f"no check reads requirement {item.path}: {item.excerpt!r}; whether the episode met it is unknown")
                unobserved.append(item)
        elif (item, "supported") not in observed:
            gaps.append(f"no cited check observes requirement {item.path}: {item.excerpt!r} satisfied")
    if basis.requirements and not any((item, "supported") in observed for item in basis.requirements):
        gaps.append("no cited check observes a cited requirement satisfied")
    return gaps, unobserved


def ordinary_assessments(name: str, assessments: list[Assessment]) -> list[Assessment]:
    """Only native assessments whose check belongs to this ordinary episode."""
    return [item for item in assessments if item.execution_scope == "native" and item.claim.episode == name
            and item.check is not None and item.check.content.episode == name]


def reference(name: str, own: list[Assessment], run_dir: Path) -> tuple[str, list[str], list[str]]:
    """The episode's completion reference: complete, incomplete or unknown, with reasons and
    the cited requirements no check reads, each of which keeps completion unknown.
    Reward never supplies it, and legitimate partial credit alone is neither label."""
    own = ordinary_assessments(name, own)
    bases = [assessment.claim.basis for assessment in own if assessment.claim.basis is not None]
    if not bases:
        return "unknown", ["no metric basis was supplied for this episode; missing evidence stays unknown"], []
    found, reasons, unobserved = set(), [], {}
    for basis in bases:
        gaps, missing = completion_gaps(basis, own, run_dir, name)
        reasons += gaps or [basis.explanation]
        unobserved.update((f"{item.path}: {item.excerpt!r}", None) for item in missing)
        if not gaps:
            found.add("complete" if basis.completion == "supported" else "incomplete")
    if len(found) == 1:
        return found.pop(), reasons, list(unobserved)
    if found:
        reasons.append("its completion references disagree")
    return "unknown", reasons, list(unobserved)


def grounded(run_dir: Path, name: str, source: Observation) -> str | None:
    try:
        Evidence(run_dir, name).excerpt(source)
    except Ungrounded as error:
        return f"its source is not retained evidence: {error}"
    return None


def rule_gap(rule) -> str | None:
    if (rule.comparison is None) != (rule.threshold is None) or bool(rule.pass_values) == (rule.threshold is not None):
        return "it needs exactly one encoding: pass_values, or a comparison with a threshold"
    if not all(math.isfinite(value) for value in rule.pass_values + rule.values + ([rule.threshold] if rule.threshold is not None else [])):
        return "its encoding is not finite"
    return None


def passes(rule, value: float) -> bool:
    """Exact native comparison; no tolerance unless the retained rule states one."""
    if rule.pass_values:
        return value in rule.pass_values
    return COMPARISONS[rule.comparison](value, rule.threshold)


def identity(item, *exclude: str) -> str:
    """An interpretation without its source; the order of a list of values never distinguishes two."""
    dump = item.model_dump(mode="json", exclude={"source", *exclude})
    return json.dumps({key: sorted(set(value)) if isinstance(value, list) else value for key, value in dump.items()}, sort_keys=True)


def chosen(items: list, kind: str, run_dir: Path, name: str, gap=lambda item: None):
    """The episode's one grounded `kind`, every reason others are not used, and every valid `kind`."""
    valid, reasons = {}, []
    for item in items:
        problem = gap(item) or grounded(run_dir, name, item.source)
        if problem:
            reasons.append(f"{kind} not used: {problem}")
        else:
            valid.setdefault(identity(item), item)
    if not valid:
        reasons.append(f"no source-grounded {kind}; observed reward values alone establish none")
    elif len(valid) > 1:
        reasons.append(f"incompatible {kind}s: {'; '.join(valid)}")
    return (next(iter(valid.values())) if len(valid) == 1 else None), reasons, list(valid.values())


def contract(key: str, rules: list, names: list[str], results: dict) -> tuple[str, list[str]]:
    """The binary contract of reward `key` in one configuration, `supported`, `unsupported` or
    `unavailable` with reasons. Every grounded rule's declaration must name the same two values;
    observed rewards can contradict a declaration but never establish one."""
    rules = [rule for rule in rules if rule.reward == key]
    declarations = sorted({tuple(sorted(set(rule.values))) for rule in rules if rule.values})
    observed = {value for name in names if (value := native_value(results[name], key)[0]) is not None}
    if not declarations:
        if len(observed) > 2:
            return "unsupported", [NON_BINARY, f"The ordinary pool returned {len(observed)} distinct {key!r} values."]
        return "unavailable", [UNKNOWN_REWARD] + ([f"Its native decision rules declare no {key!r} values."] if rules else [])
    if len(declarations) != 1 or len(declarations[0]) != 2:
        listed = " and ".join(str(list(values)) for values in declarations)
        return "unsupported", [NON_BINARY, f"Its native decision rules declare the {key!r} values {listed}."]
    declared = list(declarations[0])
    if outside := sorted(observed - set(declared)):
        return "unsupported", [NON_BINARY, f"Observed {key!r} values {outside} contradict the declared binary values {declared}."]
    passing = {tuple(value for value in declared if passes(rule, value)) for rule in rules}
    if len(passing) != 1 or len(passing.pop()) != 1:
        return "unavailable", [UNKNOWN_REWARD, f"Its native decision rules do not pass the same one of {declared}."]
    return "supported", []


def rate(label: str, terms: str, numerator: int, denominator: int, lower: bool = False, missing: str | None = None) -> dict:
    """An observed proportion beside its counts. A zero denominator gives null, never zero;
    `missing` says why nothing is counted."""
    if missing:
        return {"value": None, "numerator": None, "denominator": None, "lower_bound": False,
                "unavailable": f"{label} is unavailable: {missing}"}
    return {"value": numerator / denominator if denominator else None, "numerator": numerator, "denominator": denominator,
            "lower_bound": lower and denominator > 0,
            "unavailable": None if denominator else f"{label} is unavailable: its denominator {terms} is zero"}


def native_value(result: EpisodeResult | None, key: str) -> tuple[float | None, list[str]]:
    value = result.rewards.get(key) if result is not None else None
    if value is None:
        return None, [f"no native reward {key!r}"]
    if not math.isfinite(value):
        return None, [f"native reward {key!r} is not finite"]
    return value, []


def metrics(run_dir: Path, pool: list[str], results: dict, result: InspectionResult, warnings: list[str]) -> dict:
    """Grader agreement per configuration and native decision rule under an established binary
    reward contract: TP/FP/FN/TN, false discovery and false negative rates and F1 over the same
    eligible episodes, each counted once, beside the rule's native pass rate; plus AUROC and
    coverage of the ordinary pool. Local discrepancy labels never become matrix cells. A
    presumed label enters as the grader's own verdict and marks the rates it changes as lower bounds."""
    episodes, configs, rules, valid, auroc = {}, {}, {}, {}, {}
    for name in pool:
        own = ordinary_assessments(name, result.assessments)
        bases = [assessment.claim.basis for assessment in own if assessment.claim.basis is not None]
        completion, completion_reasons, unobserved = reference(name, own, run_dir)
        entry = episodes[name] = {"completion": completion, "completion_reasons": completion_reasons, "unobserved": unobserved,
                                  "decision": None, "score": None}
        config = json.dumps(configuration(results[name]), sort_keys=True) if results.get(name) else ""
        if config:
            configs.setdefault(config, []).append(name)
        rule, entry["decision_reasons"], valid[name] = chosen([basis.decision for basis in bases if basis.decision],
                                                              "native decision rule", run_dir, name, rule_gap)
        if rule is not None:
            rules[name] = rule
            value, missing = native_value(results.get(name), rule.reward)
            entry["decision_reasons"] += missing
            if value is not None:
                entry["decision"] = "pass" if passes(rule, value) else "fail"
        ordering, entry["ordering_reasons"], _ = chosen([basis.ordering for basis in bases if basis.ordering], "score ordering",
                                                     run_dir, name)
        if ordering is not None:
            value, missing = native_value(results.get(name), ordering.reward)
            entry["ordering_reasons"] += missing
            entry["score"] = value
            if value is not None and completion != "unknown":
                auroc.setdefault((config, ordering.reward, ordering.higher_completes), []).append(name)

    kinds = {name: "operational_failure" for name in pool if results.get(name) is None}
    matrices, statuses = [], {}
    for config, names in configs.items():
        # The contract uses every grounded rule, also on episodes left without a decision or a reward.
        found = [rule for name in names for rule in valid[name]]
        keys = {rule.reward for rule in found} | {key for name in names for key in results[name].rewards}
        # Harbor reads a single reward key as the reward, whatever its name.
        environment = next(iter(keys)) if len(keys) == 1 else "reward"
        statuses[config] = contract(environment, found, names, results)
        # One group per chosen native decision rule; a configuration without any keeps one group for its status.
        groups = {identity(rule, "values"): rule for name in names if (rule := rules.get(name))} or {None: None}
        # Without a chosen rule a supported reward still gives no decision to compare.
        contracts = {key: statuses[config] if statuses[config][0] != "supported" else contract(rule.reward, found, names, results)
                     if rule else ("unavailable", ["No episode of this configuration has one grounded native decision rule."])
                     for key, rule in groups.items()}
        # A presumed episode's reference follows its native decision.
        members, presumed = {key: [] for key in groups}, {}
        for name in names:
            entry, label, rule = episodes[name], result.ordinary.get(name), rules.get(name)
            assumed = label is not None and label.basis == "presumed" and entry["completion"] == "unknown"
            # An episode without a usable rule of its own takes its configuration's one native decision rule.
            if rule is None and len(groups) == 1 and (assumed or not valid[name]):
                rule = next(iter(groups.values()))
                if rule and not assumed and (value := native_value(results[name], rule.reward)[0]) is not None:
                    entry["decision_reasons"].append("it takes this configuration's one native decision rule")
                    entry["decision"] = "pass" if passes(rule, value) else "fail"
            key = identity(rule, "values") if rule else None
            if native_value(results[name], environment)[0] is None:
                kinds[name] = "operational_failure" if results[name].errors else "missing_reward"
            elif label is None or name in result.unreviewed:
                kinds[name] = "unreviewed"
            elif entry["completion"] == "unknown" and not assumed:
                kinds[name] = "inconclusive"
            elif (contracts[key] if rule else statuses[config])[0] != "supported":
                kinds[name] = "no_binary_contract"
            elif assumed and rule and (value := native_value(results[name], rule.reward)[0]) is not None:
                if name not in rules:
                    entry["decision_reasons"].append("its presumed label takes this configuration's one native decision rule")
                entry["decision"] = "pass" if passes(rule, value) else "fail"
                presumed[name] = "complete" if passes(rule, value) else "incomplete"
            elif entry["decision"] is None or assumed:
                kinds[name] = "no_decision_rule"
            if name not in kinds:
                members[key].append(name)
        for key, rule in groups.items():
            (status, reasons), group = contracts[key], members[key]
            cells = Counter((presumed.get(name, episodes[name]["completion"]), episodes[name]["decision"]) for name in group)
            tp, fp, fn, tn = cells["complete", "pass"], cells["incomplete", "pass"], cells["complete", "fail"], cells["incomplete", "fail"]
            presumptions = [name for name in group if name in presumed]
            supported, denominator = status == "supported", 2 * tp + fp + fn
            counts = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "presumed": len(presumptions), "verified": len(group) - len(presumptions)}
            suppressed = None if supported else f"grader agreement is {status}"
            f1_reason = suppressed or (None if denominator else "its denominator 2TP + FP + FN is zero")
            reward = rule.reward if rule else environment
            # The native pass rate describes the reward distribution, apart from agreement and its references.
            usable = [value for name in names if (value := native_value(results[name], reward)[0]) is not None]
            passed = sum(passes(rule, value) for value in usable) if rule else 0
            matrices.append({
                "configuration": json.loads(config), "reward": reward, "status": status, "reasons": reasons,
                "rule": json.loads(key) if rule else None, "episodes": group,
                **{name: value if supported else None for name, value in counts.items()},
                "false_discovery_rate": rate("false discovery rate", "TP + FP", fp, tp + fp,
                                             any(presumed[name] == "complete" for name in presumptions), suppressed),
                "false_negative_rate": rate("false negative rate", "TP + FN", fn, tp + fn, bool(presumptions), suppressed),
                "pass_rate": rate("native pass rate", f"usable {reward!r} rewards", passed, len(usable),
                                  missing=None if rule else "no source-grounded native decision rule"),
                "f1": None if f1_reason else 2 * tp / denominator, "unavailable": f"F1 is unavailable: {f1_reason}" if f1_reason else None})

    curves = []
    for (config, reward, higher), names in auroc.items():
        if statuses[config][0] != "supported":
            curves.append({"configuration": json.loads(config), "reward": reward, "higher_completes": higher, "episodes": [],
                           "positives": None, "negatives": None, "auroc": None,
                           "unavailable": f"AUROC is unavailable: grader agreement is {statuses[config][0]}"})
            continue
        sign = 1 if higher else -1
        positives = [sign * episodes[name]["score"] for name in names if episodes[name]["completion"] == "complete"]
        negatives = [sign * episodes[name]["score"] for name in names if episodes[name]["completion"] == "incomplete"]
        pairs = [1.0 if positive > negative else 0.5 if positive == negative else 0.0 for positive in positives for negative in negatives]
        curves.append({"configuration": json.loads(config), "reward": reward, "higher_completes": higher, "episodes": names,
                       "positives": len(positives), "negatives": len(negatives),
                       "auroc": sum(pairs) / len(pairs) if pairs else None,
                       "unavailable": None if pairs else "AUROC is unavailable: it needs both classes"})

    for group in matrices:
        model = group["configuration"]["model"]
        if group["status"] != "supported":
            warnings.append(f"grader agreement for {model} {group['reward']} is {group['status']}: {' '.join(group['reasons'])}")
            continue
        warnings += [f"{model}: {group[key]['unavailable']}" for key in ("false_discovery_rate", "false_negative_rate")
                     if group[key]["unavailable"]]
    for metric, groups, needs in (("F1", matrices, "native decision"), ("AUROC", curves, "score ordering")):
        if not groups:
            warnings.append(f"{metric} is unavailable: no ordinary episode has both an eligible completion reference "
                            f"and a source-grounded {needs}")
        warnings += [f"{group['unavailable']} for {group['reward']}" for group in groups if group["unavailable"]]
        # An unavailable metric uses no episode.
        used = sum(len(group["episodes"]) for group in groups if not group["unavailable"])
        if used and used < len(pool):
            warnings.append(f"{metric} uses {used} of {len(pool)} ordinary episodes; the rest are excluded with retained reasons")
    coverage = {"ordinary": len(pool), "resolved": sum(episodes[name]["completion"] != "unknown" for name in pool),
                "eligible": sum(len(group["episodes"]) for group in matrices),
                "excluded": {kind: [name for name in pool if kinds.get(name) == kind] for kind in EXCLUDED}}
    return {"episodes": episodes, "confusion": matrices, "auroc": curves, "coverage": coverage}


def dump(item) -> dict | None:
    return item.model_dump(mode="json") if item is not None else None


def finding(assessment: Assessment, category: str | None = None, experiment: str | None = None) -> dict:
    """The claim, nudi's captured facts, the Inspector's interpretation and nudi's assessment, kept apart."""
    claim, check = assessment.claim, assessment.check
    limits = assessment.limits + [PACKAGE_LIMIT] * (assessment.execution_scope == "package")
    return {
        "execution_scope": assessment.execution_scope, "category": category, "experiment": experiment,
        "claim": {"mechanism": claim.mechanism, "episode": claim.episode, "reward": claim.reward, "unresolved": claim.unresolved,
                  "limits": claim.limits},
        "captured": {
            "copied_grader_reward" if assessment.execution_scope == "package" else "native_reward": assessment.reward,
            "ids": assessment.ids,
            "errors": [f"{error.type}: {error.message}" for error in assessment.errors],
            "check": None if check is None else {
                "id": check.id, "exit_code": check.exit_code, "environment": check.environment, "sandbox": check.sandbox,
                "content": dump(check.content),
                "inputs": {key: dump(item) for key, item in check.inputs.items()},
                "requirement": dump(check.requirement), "scoring": dump(check.scoring),
                "state_copy": check.state_copy},
            "replay": dump(assessment.replay), "planted": dump(claim.planted), "persisted": dump(claim.persisted),
        },
        "interpretation": {"interpretation": claim.interpretation, "timing": check.timing if check else None,
                           "citations": [dump(item) for item in claim.citations],
                           "derivation": dump(claim.derivation), "coverage": dump(claim.coverage), "basis": dump(claim.basis)},
        "assessment": {**assessment.model_dump(mode="json", include={"outcome", "validity", "discrepancy", "conclusions", "reasons",
                                                                     "missing", "persistence", "persistence_reasons"}), "limits": limits},
    }


def result_of(assessment: Assessment) -> str:
    if evidenced(assessment):
        return "evidenced"
    return "legitimate" if assessment.outcome == "legitimate" and not assessment.claim.unresolved else "inconclusive"


def findings(assessments: list[Assessment], links: dict[int, dict] | None = None) -> dict:
    """Every finding by nudi's result, with its index into the inspection's assessments.

    Category settlement reads a check's latest reading, so an earlier one names that reading as superseding it
    and stays listed, since its evidence and open conditions can still explain a label, metric or category.
    A claim without a check is never superseded. Each finding keeps its execution scope, so package evidence
    stays distinct from native accessibility, and the category and experiment `links` give it."""
    latest = {item.claim.check: index for index, item in enumerate(assessments) if item.claim.check}
    groups = {"evidenced": [], "legitimate": [], "inconclusive": []}
    for index, assessment in enumerate(assessments):
        later = latest.get(assessment.claim.check, index)
        superseded = None if later == index else {"index": later, "result": result_of(assessments[later])}
        groups[result_of(assessment)].append({"index": index, "superseded_by": superseded,
                                              **finding(assessment, **(links or {}).get(index, {}))})
    return groups


def inspection(mode: str, result: InspectionResult, warnings: list[str]) -> dict:
    for category, status in result.categories.items():
        if status not in SETTLED:
            # A restriction keeps its grounded reason. Other applicability text is the Inspector's and stays in the JSON.
            reason = result.applicability.get(category) if status == "restricted" else None
            warnings.append(f"{mode} inspector category {category} is {status}" + (f": {reason}" if reason else ""))
    warnings += [f"{mode} inspector {item.phase} attempt {item.number} ({item.category or item.episode or 'all categories'}) {item.status}"
                 + (f": {item.error}" if item.error else ", no error message recorded")
                 for item in result.attempts if item.status in ("refused", "model_inability", "model_output_failure", "unobservable", "inference_failure", "tool_failure")]
    measured = {}
    for item in result.experiments:
        # Older records name an experiment's check only through its assessment.
        index = item.get("assessment")
        if check := item.get("check") or (index is not None and result.assessments[index].claim.check):
            measured[check] = item
    links = {index: {"category": measured[item.claim.check].get("category"), "experiment": measured[item.claim.check]["id"]}
             for index, item in enumerate(result.assessments) if item.claim.check in measured}
    for review in result.reviews:
        # A repair evidences the category of the session that made it; its experiment stays as provenance.
        category = result.attempts[review.attempt].category
        if review.reinterprets and review.assessment is not None and category:
            links.setdefault(review.assessment, {})["category"] = category
    return {"status": result.status, "categories": result.categories, "applicability": result.applicability,
            "applicability_evidence": result.applicability_evidence,
            "artifacts": result.artifacts, "limits": result.limits, "experiments": result.experiments,
            "attempts": [item.model_dump(mode="json") for item in result.attempts], "findings": findings(result.assessments, links)}


def _condition_view(status, guidance, unavailable, entries, record: RunRecord) -> dict:
    attempts = [item for item in entries if item.episode in record.episodes]
    return {
        "status": status, "guidance": guidance, "unavailable": unavailable, "tested": bool(attempts), "attempts": len(attempts),
        "outcomes": dict(sorted(Counter(item.status for item in attempts).items())),
        "evidence": "found" if any(item.status == "evidenced_issue" for item in attempts) else "not found" if attempts else "not attempted",
        "blocked": [{"number": item.number, "episode": item.episode, "status": item.status, "error": item.error,
                     "reason": "no episode of this entry started"} for item in entries if item.episode not in record.episodes],
    }


def _separated_attack(result: AttackResult, record: RunRecord, warnings: list[str]) -> dict:
    """Candidate reproduction and no-hint discovery. Started episodes are the only attempts."""
    quiet = {"evidenced_issue", "no_evidenced_issue", "unavailable"}
    candidates = []
    for item in result.candidates:
        conditions = {}
        for level in ("full", "minimal"):
            entries = [attempt for attempt in result.attempts if attempt.level == level and item.id in (
                attempt.sources or ([attempt.candidate] if attempt.candidate else []))]
            status = item.conditions.get(level, "unattempted")
            conditions[level] = _condition_view(status, item.guidance.get(level), item.unavailable.get(level), entries, record)
            if status not in quiet:
                warnings.append(f"attack candidate {item.id} {level} is {status}")
        candidates.append({"id": item.id, "mechanism": item.mechanism, "valid_work": item.valid_work, "conditions": conditions})
    discovery_entries = [attempt for attempt in result.attempts if attempt.level == "none"]
    discovery_status = result.discovery.get("none", "unattempted")
    discovery = _condition_view(discovery_status, None, None, discovery_entries, record)
    discovery["maximum_attempts"] = result.discovery_attempts
    if discovery_status not in quiet and not (discovery_status == "unattempted" and result.discovery_attempts == 0):
        warnings.append(f"attack no-hint discovery is {discovery_status}")
    if not result.candidates:
        for level, reason in result.unavailable.items():
            warnings.append(f"attack condition {level} is unavailable: {reason}")
    exploits = {"reproduction": [], "other": [], "unattributed": [], "discovery": []}
    for finding in result.findings:
        if finding.kind in exploits:
            exploits[finding.kind].append({
                "candidate": finding.candidate, "sources": finding.sources, "attempt": finding.attempt,
                "assessment": finding.assessment, "relation": finding.relation, "rationale": finding.rationale,
            })
    names = {item.episode for item in result.attempts if item.episode}
    return {"status": result.status, "maximum_attempts": result.maximum_attempts, "discovery_attempts": result.discovery_attempts,
            "candidates": candidates, "discovery": discovery, "unavailable": result.unavailable, "exploits": exploits,
            "attempts": [item.model_dump(mode="json") for item in result.attempts], "findings": findings(result.assessments),
            "limits": result.limits, "unknown_cost_calls": sum(call.cost is None for call in record.calls if call.episode in names)}


def attack(result: AttackResult, record: RunRecord, warnings: list[str]) -> dict:
    """Evidence found or not found within the actual attempts of each tested hint condition.

    An entry is an attempt only when its episode started. `checks.attack` records an entry,
    and may name its episode, before the spending cap admits it; such blocked entries stay
    listed with their status, but neither count as attempts nor make a condition tested.
    A result that names candidates or discovery uses that separated shape. Older records
    keep the pooled conditions."""
    if result.candidates or result.discovery:
        return _separated_attack(result, record, warnings)
    conditions = {}
    for level, status in result.conditions.items():
        entries = [item for item in result.attempts if item.level == level]
        attempts = [item for item in entries if item.episode in record.episodes]
        conditions[level] = {
            "status": status, "guidance": result.guidance.get(level), "unavailable": result.unavailable.get(level),
            "tested": bool(attempts), "attempts": len(attempts),
            "outcomes": dict(sorted(Counter(item.status for item in attempts).items())),
            "evidence": "found" if any(item.status == "evidenced_issue" for item in attempts) else "not found" if attempts else "not attempted",
            "blocked": [{"number": item.number, "episode": item.episode, "status": item.status, "error": item.error,
                         "reason": "no episode of this entry started"} for item in entries if item.episode not in record.episodes],
        }
        if status not in SETTLED:
            reason = result.unavailable.get(level)
            warnings.append(f"attack condition {level} is {status}" + (f": {reason}" if reason else ""))
    names = {item.episode for item in result.attempts if item.episode}
    return {"status": result.status, "maximum_attempts": result.maximum_attempts, "conditions": conditions,
            "tested_conditions": [level for level, item in conditions.items() if item["tested"]],
            "attempts": [item.model_dump(mode="json") for item in result.attempts], "findings": findings(result.assessments),
            "limits": result.limits, "unknown_cost_calls": sum(call.cost is None for call in record.calls if call.episode in names)}


def persistence(record: RunRecord, warnings: list[str]) -> list[dict]:
    """Each probe classified again from its lifecycle fields; a stored classification is not accepted."""
    probes = []
    for probe in record.persistence_probes:
        kind, reasons, limits, missing = classify_probe(probe)
        probes.append({"location": probe.location, "classification": kind, "reasons": reasons,
                       "limits": list(dict.fromkeys([*probe.limits, *limits])), "missing": missing,
                       "mount_relationship": probe.mount_relationship, "plant_episode": probe.plant_episode,
                       "receiver_episode": probe.receiver_episode, "observation_windows": probe.observation_windows})
        if kind in ("unknown", "unsupported"):
            warnings.append(f"persistence probe {probe.location} is {kind}: {'; '.join(reasons or probe.limits)}")
    return probes


def number(value) -> str:
    return "unavailable" if value is None else f"{value:.4g}"


def ratio(label: str, item: dict) -> str:
    """A rate beside its numerator and denominator, marked when presumed labels make it a lower bound."""
    if item["lower_bound"]:
        return f"{label} at least {number(item['value'])} ({item['numerator']}/{item['denominator']}, lower bound)"
    return f"{label} {number(item['value'])} ({item['numerator']}/{item['denominator']})"


def reported(calls) -> float:
    """The part of the known cost that providers reported, not LiteLLM estimates."""
    return sum(call.cost for call in calls if call.cost_source == PROVIDER_REPORTED)


def cost(known: float, provider: float, unknown: int) -> str:
    return (f"known cost ${known:.6f}" + (f", ${provider:.6f} of it provider-reported" if provider else "")
            + (f", excluding {unknown} calls with unknown prices" if unknown else ""))


def check_id(item: dict) -> str:
    return item["captured"]["check"]["id"] if item["captured"]["check"] else "none"


def category_line(mode: str, item: dict, category: str, status: str) -> str:
    """A category's status beside what nudi retained about it: its evidencing checks, or why it is
    not settled, and the broad and focused attempts that covered it."""
    cases = [(kind, found) for kind, group in item["findings"].items() for found in group if found["category"] == category]
    parts = [f"- {mode} {category}: {status}"]
    if status == "evidenced_issue":
        evidence = [check_id(found) + (f" (superseded by a later {found['superseded_by']['result']} reading)" if found["superseded_by"] else "")
                    for kind, found in cases if kind == "evidenced"
                    and (mode == "grader_inspector" or found["assessment"]["outcome"] == "accepted_invalid")]
        parts.append("evidenced by " + (", ".join(evidence) or "a finding the report cannot link to this category"))
    elif status != "no_evidenced_issue":
        applicability = item["applicability_evidence"].get(category, {}).get("status")
        if status == "restricted":
            parts.append(item["applicability"].get(category) or "no restriction reason retained")
        elif applicability != "applicable":
            parts.append(f"applicability evidence {applicability or 'missing'}")
        unresolved = [f"{check_id(found)} {kind}" for kind, found in cases
                      if kind == "inconclusive" and not found["superseded_by"]]
        if unresolved:
            parts.append("unresolved cases " + ", ".join(unresolved))
    attempts = [f"{entry['phase']} {entry['number']} {entry['status']}" for entry in item["attempts"]
                if entry["category"] in (category, None) and entry["episode"] is None]
    return "; ".join(parts + ["attempts " + (", ".join(attempts) or "none")])


def unassessed(mode: str, item: dict) -> list[str]:
    """Each experiment with no assessment, once, whatever its category's status."""
    read = {check_id(found) for group in item["findings"].values() for found in group}
    entries = [f"{entry['id']} {entry['status']} ({entry.get('category') or 'no category'}"
               + "".join(f", {entry[key]}" for key in ("check", "episode") if entry.get(key))
               + (", with a reading in Findings" if entry.get("check") in read else "") + ")"
               for entry in item["experiments"] if entry.get("status") != "assessed"]
    return [f"- {mode} experiments without an assessment: " + ", ".join(entries)] if entries else []


def markdown(report: dict) -> str:
    """A readable rendering of `build`'s report; the JSON keeps every field."""
    config = report["configuration"]
    lines = ["# nudi report", "", f"Status: {report['status']}, relative to the selected analyses.", "", "## Configuration", ""]
    for role, model in config["models"].items():
        source = config["credential_sources"].get(role)
        lines.append(f"- {role}: {model['model']}, reasoning effort {model['reasoning_effort']}, "
                     + (f"credential from {source}" if source else "no credential resolved; the selected analyses do not run this role"))
    lines += [f"- Task: {config['task_dir']}; execution path {config['path']}: {'; '.join(config['path_reasons'])}",
              f"- Spending cap: {config['spending_cap']}; {cost(config['known_cost'], config['provider_reported_cost'], config['unknown_cost_calls'])}"]
    if modal := config["modal_cost"]:
        lines.append(f"- Modal compute: estimated at most ${modal['estimate']:.6f} for {modal['sandboxes']} sandboxes, an upper "
                     "bound from their CPU and memory limits and lifetimes, outside the spending cap"
                     + (f"; {modal['without_limits']} without declared limits are excluded" if modal["without_limits"] else "")
                     + (f"; {modal['still_running']} still ran after stop and count their whole 24 h lifetime"
                        if modal["still_running"] else ""))
    for item in config["provenance"]:
        setup = item["configuration"]
        versions = ", ".join(f"{name} {version}" for name, version in setup["versions"].items())
        lines.append(f"- Task {setup['task_name']} digest {setup['task_digest']}; {setup['model']}, reasoning effort "
                     f"{setup['reasoning_effort']}, {setup['path']} ({versions}): {', '.join(item['episodes'])}")
    lines += [f"- {name}: {reason}" for name, reason in config["provenance_unavailable"].items()]
    if not config["provenance"]:
        lines.append("- Task digest and version pins: unavailable, no retained episode record")
    lines += ["", "## Analyses", ""] + [f"- {name}: {status}" for name, status in report["analyses"].items()]

    lines += ["", "## Inspection categories", ""]
    lines += [line for mode, item in report["inspections"].items() for line in
              [category_line(mode, item, category, status) for category, status in item["categories"].items()]
              + unassessed(mode, item)] or ["Neither the grader inspector nor the hack inspector was selected or run."]

    lines += ["", "## State copies", ""]
    for copy in report["copies"]:
        if copy["error"] or copy["seconds"] is None:
            state = f"failed: {copy['error'] or 'it never finished'}"
        else:
            state = f"took {copy['seconds']:.1f} s, omits {', '.join(copy['excluded'])}"
        deleted = {True: "deleted", False: "not deleted", None: "deletion unconfirmed"}[copy["deleted"]]
        lines.append(f"- {copy['id']}: {copy['episode']} at {copy['point']}, {copy['environment']} environment on "
                     f"{copy['backend']}; {state}; {deleted}")
    if not report["copies"]:
        lines.append("No state copy was recorded.")

    lines += ["", "## Ordinary rewards", ""]
    pool = report["ordinary"]
    if pool is None:
        lines.append("No ordinary pool was selected.")
    else:
        lines.append(f"{pool['attempted']} of {pool['requested']} requested episodes attempted; status {pool['status']}.")
        lines += [f"- {name}: no retained record; {'; '.join(errors) or 'cause unknown'}" for name, errors in pool["unrecorded"].items()]
        lines += [f"- {name} recorded {'; '.join(errors)}; its retained reward is summarized below"
                  for name, errors in pool["failures"].items() if errors and name not in pool["unrecorded"]]
        for group in pool["groups"]:
            setup = group["configuration"]
            versions = ", ".join(f"{name} {version}" for name, version in setup["versions"].items())
            lines += ["", f"### {setup['task_name']}, {setup['model']}, reasoning effort {setup['reasoning_effort']}, "
                          f"{setup['path']} ({versions})", ""]
            for key, summary in group["rewards"].items():
                distribution = ", ".join(f"{value}: {count}" for value, count in summary["distribution"]) or "none"
                lines.append(f"- {key}: {summary['usable']} usable of {summary['attempted']}; missing {len(summary['missing'])}, "
                             f"invalid {len(summary['invalid'])}; mean {number(summary['mean'])}; sample SD {number(summary['sd'])}; "
                             f"distribution {distribution}")
    other = report["other_episodes"]
    earlier = f"{len(other['inspector'])} native Inspector episodes from an earlier version, " if other["inspector"] else ""
    lines += ["", f"Outside the ordinary pool: {len(other['sandboxes'])} Inspector sandboxes (session workspaces and package "
                  f"experiments), {earlier}{len(other['probes'])} persistence probes and {len(other['attacker'])} attacker episodes."]

    lines += ["", "## Local grader labels", ""]
    if report["labels"] is None:
        lines.append("The grader inspector was not selected or not run.")
    else:
        labeled = report["labels"]
        lines.append(f"Mode: {labeled['mode']}; presumed {labeled['basis']['presumed']}, verified {labeled['basis']['verified']}.")
        lines.append(", ".join(f"{label} {count}" for label, count in labeled["counts"].items()) or "No ordinary episode.")
        review = labeled["review"]
        skipped = [name for name in labeled["episodes"] if name not in review["attempted"]]
        presumed = sum(labeled["episodes"][name]["basis"] == "presumed" for name in skipped)
        lines.append(f"Review attempted for {len(review['attempted'])} (attempted but unresolved {len(review['unresolved'])}); "
                     f"not reviewed {len(skipped)}, of which presumed {presumed}; supported label for {len(review['supported'])}.")
        lines += [f"- {name}: {item['label']}" + (f" ({item['basis']})" if item["basis"] else "") for name, item in labeled["episodes"].items()]

    lines += ["", "## Metrics", ""]
    metric = report["metrics"]
    if metric is None:
        lines.append("The grader inspector was not selected or not run, so no metric reference exists.")
    else:
        lines += [f"- {name}: completion {item['completion']}; native decision {item['decision'] or 'unavailable'}; "
                  f"score {number(item['score'])}"
                  + (f"; unobserved requirements: {', '.join(item['unobserved'])}" if item["unobserved"] else "")
                  for name, item in metric["episodes"].items()]
        coverage = metric["coverage"]
        excluded = ", ".join(f"{kind.replace('_', ' ')} {len(names)}" for kind, names in coverage["excluded"].items() if names)
        lines.append(f"- Coverage: {coverage['resolved']} of {coverage['ordinary']} ordinary episodes have a resolved completion "
                     f"reference; {coverage['eligible']} of {coverage['ordinary']} enter grader agreement; excluded: {excluded or 'none'}")
        for group in metric["confusion"]:
            subject, rule, encoding = f"{group['configuration']['model']} {group['reward']}", group["rule"], ""
            if rule:
                encoding = f" (pass values {rule['pass_values']})" if rule["pass_values"] else f" ({rule['comparison']} {rule['threshold']})"
                lines.append(f"- {ratio(f'Native pass rate for {subject}{encoding}:', group['pass_rate'])}")
            heading = f"- Grader agreement for {subject}"
            if group["status"] != "supported":
                lines.append(f"{heading}: {group['status']}, no agreement values. {' '.join(group['reasons'])}")
                continue
            rates = "; ".join(ratio(label, group[key]) for label, key in (
                ("false discovery rate", "false_discovery_rate"), ("false negative rate", "false_negative_rate")))
            lines.append(f"{heading}{encoding}: TP {group['tp']}, FP {group['fp']}, "
                         f"FN {group['fn']}, TN {group['tn']}; {rates}; presumed {group['presumed']}, verified {group['verified']}; "
                         f"F1 {number(group['f1'])}")
        for group in metric["auroc"]:
            if group["positives"] is None:
                lines.append(f"- {group['unavailable']} for {group['reward']}")
                continue
            direction = "higher" if group["higher_completes"] else "lower"
            lines.append(f"- AUROC for {group['reward']}, {direction} toward completion: {group['positives']} complete, "
                         f"{group['negatives']} incomplete; AUROC {number(group['auroc'])}")

    lines += ["", "## Findings", ""]
    sections = list(report["inspections"].items()) + ([("attack", report["attack"])] if report["attack"] else [])
    entries, limits, total, doubted = [], [], 0, 0
    for source, section in sections:
        measured = {entry["id"]: entry.get("category") for entry in section.get("experiments", [])}
        for kind, items in section["findings"].items():
            for item in items:
                claim, outcome, later = item["claim"], item["assessment"], item["superseded_by"]
                package = item["execution_scope"] == "package"
                reward_name, reward_key = ("copied grader reward", "copied_grader_reward") if package else ("native reward", "native_reward")
                readings = "".join(f"; requirement {found['requirement']['excerpt']!r} {found['validity']}"
                                   for found in outcome["conclusions"])
                category = f"; category {item['category']}" if item["category"] else ""
                if item["experiment"] and measured.get(item["experiment"]) != item["category"]:
                    category += f"; reinterprets {item['experiment']}, measured for {measured[item['experiment']] or 'no category'}"
                replaced = f", superseded by the later {later['result']} reading of {check_id(item)}" if later else ""
                entries.append(f"- {source} {kind}{' (package)' if package else ''}{replaced}: {claim['mechanism']} in {claim['episode']}; "
                               f"{reward_name} {number(item['captured'][reward_key])}; check {check_id(item)}{category}; "
                               f"validity {outcome['validity']}; discrepancy {outcome['discrepancy']}{readings}; "
                               f"{outcome['outcome']}: {'; '.join(outcome['reasons']) or 'no reason recorded'}")
                interpretation = item["interpretation"]["interpretation"].strip()
                for label, values in (("Interpretation", [interpretation] * bool(interpretation)), ("Missing", outcome["missing"]),
                                      ("Open conditions", claim["unresolved"]), ("Scope notes", claim["limits"])):
                    if values:
                        entries[-1] += f". {label}: " + "; ".join(values)
                limits += [limit for limit in outcome["limits"] if limit not in limits]
                total += kind == "evidenced" and not later
                doubted += kind == "evidenced" and not later and bool(claim["unresolved"])
    lines += [f"Evidenced findings: {total}, {doubted} of them with open conditions.", ""] * bool(entries)
    lines += entries or ["None retained."]
    # Limits that many findings share are stated once; the JSON keeps each finding's own list.
    lines += [f"- Finding limit: {limit}" for limit in limits]

    for mode, item in report["inspections"].items():
        for session, artifacts in item["artifacts"].items():
            lines.append(f"- {mode} retained investigation {session}: " + "; ".join(f"{key}: {path}" for key, path in artifacts.items()))
        lines += [f"- {mode} limitation: {limit}" for limit in item["limits"]]

    lines += ["", "## Attack", ""]
    result = report["attack"]
    if result is None:
        lines.append("Not selected or not run.")
    elif "discovery" in result:
        lines.append(f"Status {result['status']}; at most {result['maximum_attempts']} attempts per candidate and hint level; "
                     f"{result['unknown_cost_calls']} calls with unknown prices.")
        discovery = result["discovery"]
        lines.append(f"No-hint discovery: {discovery['status']}; {discovery.get('attempts', 0)} started "
                     f"of at most {discovery.get('maximum_attempts', result.get('discovery_attempts', 0))}.")
        for candidate in result["candidates"]:
            # A valid-work candidate's reproduction is rejected valid work, not an exploit.
            lines.append(f"- {candidate['id']}{' (valid work)' if candidate.get('valid_work') else ''}:")
            for level, item in candidate["conditions"].items():
                outcomes = ", ".join(f"{status} {count}" for status, count in item["outcomes"].items()) or "none"
                guidance = "supplied" if item["guidance"] else item["unavailable"] or "none"
                blocked = "; ".join(f"entry {entry['number']} {entry['status']}: {entry['reason']}" for entry in item["blocked"])
                lines.append(f"  - {level}: {item['status']}; {'tested' if item['tested'] else 'not tested'}; evidence "
                             f"{item['evidence']} in {item['attempts']} started attempts ({outcomes}); guidance {guidance}"
                             + (f"; blocked {blocked}" if blocked else ""))
        for kind, items in result["exploits"].items():
            if items:
                rendered = []
                for item in items:
                    label = item["candidate"] or "environment"
                    sources = item.get("sources") or []
                    if sources and sources != [label]:
                        label += " [" + ", ".join(sources) + "]"
                    if item.get("rationale"):
                        label += ": " + item["rationale"]
                    rendered.append(label)
                lines.append(f"- {kind}: {'; '.join(rendered)}")
        if result.get("unavailable"):
            lines.append("- Missing candidates: " + "; ".join(f"{level}: {reason}" for level, reason in result["unavailable"].items()))
        lines += [f"- Limit: {limit}" for limit in result["limits"]]
    else:
        lines.append(f"Status {result['status']}; at most {result['maximum_attempts']} attempts per condition; "
                     f"{result['unknown_cost_calls']} calls with unknown prices.")
        for level, item in result["conditions"].items():
            outcomes = ", ".join(f"{status} {count}" for status, count in item["outcomes"].items()) or "none"
            guidance = "supplied" if item["guidance"] else item["unavailable"] or "none"
            blocked = "; ".join(f"entry {entry['number']} {entry['status']}: {entry['reason']}" for entry in item["blocked"])
            lines.append(f"- {level}: {item['status']}; {'tested' if item['tested'] else 'not tested'}; evidence "
                         f"{item['evidence']} in {item['attempts']} started attempts ({outcomes}); guidance {guidance}"
                         + (f"; blocked {blocked}" if blocked else ""))
        lines += [f"- Limit: {limit}" for limit in result["limits"]]

    lines += ["", "## Persistence", ""]
    lines += [f"- {probe['location']}: {probe['classification']}; {'; '.join(probe['reasons'] + probe['limits'])}"
              for probe in report["persistence"]] or ["No persistence probe ran."]
    lines += ["", "## Warnings", ""] + ([f"- {warning}" for warning in report["warnings"]] or ["None."])
    lines += ["", "## Notes", ""] + ([f"- {note}" for note in report["notes"]] or ["None."])
    return "\n".join(lines) + "\n"
