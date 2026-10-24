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
from pathlib import Path

from nudi.assessment import Evidence, Ungrounded, classify_probe
from nudi.checks import SELECTION_SESSION, AttackResult, InspectionResult, evidenced
from nudi.records import Assessment, EpisodeResult, MetricBasis, Observation, RunRecord

ANALYSES = ("simulation", "grader", "hack", "attack")
FILES = {"grader": "inspection-grader.json", "hack": "inspection-hack.json", "attack": "attack.json"}
SETTLED = ("evidenced_issue", "no_evidenced_issue")
UNSUPPORTED_LABELS = ("unknown", "unavailable", "ungrounded", "unreviewed")
COMPARISONS = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "==": operator.eq}
DESCRIPTIVE = "descriptive only; difficulty, sampling and execution conditions limit what rewards show"
LOCAL_LIMIT = (
    "Local over-credit and under-credit labels compare one native reward with checked bounds. "
    "They are not binary FP/FN labels, and legitimate partial credit is not a false pass."
)
METRIC_LIMIT = (
    "F1 and AUROC compare native decisions and scores with evidence-grounded Inspector references. nudi checks "
    "their retained provenance and consistency, not semantic correctness or calibrated accuracy."
)
NO_RATE = (
    "Each hint condition stops at its first evidenced issue, so attempt counts give no unbiased success-rate "
    "estimate. Not found means not found within the actual attempts."
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
        "collection": collection(record),
        "ordinary": ordinary(record, results, warnings, notes) if "simulation" in selected and present["simulation"] else None,
        "other_episodes": {
            "inspector": [name for name in record.episodes if name.endswith("-inspector") and name not in record.probe_episodes],
            "attacker": [name for name in record.episodes if name.endswith("-attacker")],
            "probes": list(record.probe_episodes),
        },
        "labels": None,
        "metrics": None,
        "inspections": {mode: inspection(mode, loaded[mode], warnings) for mode in ("grader", "hack") if mode in loaded},
        "attack": attack(loaded["attack"], record, warnings) if "attack" in loaded else None,
        "persistence": persistence(record, warnings),
        "warnings": warnings,
        "notes": notes,
    }
    if "grader" in loaded:
        report["labels"] = labels(pool, loaded["grader"], warnings)
        report["metrics"] = metrics(run_dir, pool, results, loaded["grader"], warnings)
        notes += [LOCAL_LIMIT, METRIC_LIMIT]
    if "attack" in loaded:
        notes.append(NO_RATE)
    return scrub(report, [secret for secret in secrets if secret])


def write(run_dir: Path, secrets=(), selected=None) -> tuple[Path, Path]:
    """Write `report.json` and `report.md` beside the run's records."""
    report = build(run_dir, secrets, selected)
    paths = run_dir / "report.json", run_dir / "report.md"
    paths[0].write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    paths[1].write_text(markdown(report))
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


def collection(record: RunRecord) -> dict | None:
    """The run's one capture selection, its Inspector cost and every failed capture; None
    for a run that never selected."""
    selection = record.capture_selection
    if selection is None:
        return None
    calls = [call for call in record.calls if call.episode == SELECTION_SESSION]
    return {"status": selection.status, "files": [item.model_dump(mode="json") for item in selection.files],
            "selected": [item.source for item in selection.files if item.selected], "limits": selection.limits,
            "calls": len(calls), "known_cost": sum(call.cost or 0.0 for call in calls),
            "unknown_cost_calls": sum(call.cost is None for call in calls),
            "capture_failures": [failure.model_dump(mode="json") for failure in record.capture_errors]}


def episode(run_dir: Path, name: str) -> EpisodeResult | None:
    path = run_dir / "episodes" / name / "episode.json"
    return EpisodeResult.model_validate_json(path.read_text()) if path.is_file() else None


def configuration(result: EpisodeResult) -> dict:
    """Task, model, harness and configuration: ordinary statistics never mix them."""
    return {"task_name": result.task_name, "task_digest": result.task_digest, "model": result.model,
            "reasoning_effort": result.reasoning_effort, "path": result.path, "versions": result.versions}


def configuration_section(record: RunRecord, results: dict) -> dict:
    """Credentials appear only as their variable names and where they were found.

    `provenance` groups every retained episode record, of any role, by its task digest,
    model and version pins; episodes without a record are listed as unavailable."""
    provenance = {}
    for name, result in results.items():
        if result is not None:
            provenance.setdefault(json.dumps(configuration(result), sort_keys=True), []).append(name)
    return {"task_dir": record.task_dir, "path": record.path, "path_reasons": record.path_reasons,
            "provenance": [{"configuration": json.loads(key), "episodes": names} for key, names in provenance.items()],
            "provenance_unavailable": {name: "no retained episode record, so its task digest and version pins are unavailable"
                                       for name, result in results.items() if result is None},
            "models": {role: model.model_dump(mode="json") for role, model in record.models.items()},
            "credential_sources": record.credential_sources, "spending_cap": record.spending_cap,
            "known_cost": record.known_cost, "unknown_cost_calls": record.unknown_cost_calls,
            "refused_calls": record.refused_calls, "capacity": record.capacity.model_dump(mode="json"),
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
    unreviewed = {"label": "unreviewed", "reasons": ["grader inspection retained no label for this episode"]}
    episodes = {name: result.ordinary[name].model_dump(mode="json", include={"label", "reasons"})
                if name in result.ordinary else unreviewed for name in pool}
    counts = dict(sorted(Counter(item["label"] for item in episodes.values()).items()))
    lacking = {label: counts[label] for label in UNSUPPORTED_LABELS if label in counts}
    if lacking:
        warnings.append(f"{sum(lacking.values())} of {len(pool)} ordinary episodes have no supported local label "
                        f"({', '.join(f'{label} {count}' for label, count in lacking.items())}); "
                        "they are excluded, not counted as correct")
    return {"counts": counts, "episodes": episodes}


def completion_gaps(basis: MetricBasis, checks: dict[str, Assessment]) -> list[str]:
    """Why a basis does not establish completion; empty when it does. `checks` are the
    episode's own checks. Semantic completeness stays the Inspector's interpretation."""
    if basis.completion == "unknown":
        return [f"the Inspector left completion unknown: {basis.explanation}"]
    gaps = [f"unresolved: {item}" for item in basis.unresolved]
    if not basis.explanation.strip():
        gaps.append("its basis explains nothing")
    if not basis.requirements:
        gaps.append("it cites no completion requirement")
    gaps += [f"requirement {item.path}: {item.excerpt!r} is not task context" for item in basis.requirements if item.episode is not None]
    cited = {id: checks[id] for id in basis.checks
             if id in checks and checks[id].validity != "unknown" and not checks[id].claim.unresolved}
    if basis.completion == "violated":
        # One decisive violation suffices; unrelated unknown checks do not erase it.
        if not any(item.validity == "violated" and item.check.requirement in basis.requirements for item in cited.values()):
            gaps.append("no cited resolved check of this episode observed a violation of a cited requirement")
        return gaps
    gaps += [f"cited check {id} is not a resolved check of this episode" for id in basis.checks if id not in cited]
    gaps += [f"no cited check observes requirement {item.path}: {item.excerpt!r} satisfied" for item in basis.requirements
             if not any(check.validity == "supported" and check.check.requirement == item for check in cited.values())]
    gaps += [f"cited check {id} observed a violation" for id, check in cited.items() if check.validity == "violated"]
    return gaps


def reference(name: str, own: list[Assessment]) -> tuple[str, list[str]]:
    """The episode's completion reference: complete, incomplete or unknown, with reasons.
    Reward never supplies it, and legitimate partial credit alone is neither label."""
    bases = [assessment.claim.basis for assessment in own if assessment.claim.basis is not None]
    if not bases:
        return "unknown", ["no metric basis was supplied for this episode; missing evidence stays unknown"]
    checks = {item.check.id: item for item in own if item.check is not None and item.check.content.episode == name}
    found, reasons = set(), []
    for basis in bases:
        gaps = completion_gaps(basis, checks)
        reasons += gaps or [basis.explanation]
        if not gaps:
            found.add("complete" if basis.completion == "supported" else "incomplete")
    if len(found) == 1:
        return found.pop(), reasons
    if found:
        reasons.append("its completion references disagree")
    return "unknown", reasons


def grounded(run_dir: Path, name: str, source: Observation) -> str | None:
    try:
        Evidence(run_dir, name).excerpt(source)
    except Ungrounded as error:
        return f"its source is not retained evidence: {error}"
    return None


def rule_gap(rule) -> str | None:
    if (rule.comparison is None) != (rule.threshold is None) or bool(rule.pass_values) == (rule.threshold is not None):
        return "it needs exactly one encoding: pass_values, or a comparison with a threshold"
    if not all(math.isfinite(value) for value in rule.pass_values + ([rule.threshold] if rule.threshold is not None else [])):
        return "its encoding is not finite"
    return None


def passes(rule, value: float) -> bool:
    """Exact native comparison; no tolerance unless the retained rule states one."""
    if rule.pass_values:
        return value in rule.pass_values
    return COMPARISONS[rule.comparison](value, rule.threshold)


def chosen(items: list, kind: str, run_dir: Path, name: str, gap=lambda item: None):
    """The episode's one grounded `kind`, with every reason others are not used."""
    valid, reasons = {}, []
    for item in items:
        problem = gap(item) or grounded(run_dir, name, item.source)
        if problem:
            reasons.append(f"{kind} not used: {problem}")
        else:
            valid.setdefault(json.dumps(item.model_dump(mode="json", exclude={"source"}), sort_keys=True), item)
    if not valid:
        reasons.append(f"no source-grounded {kind}; observed reward values alone establish none")
    elif len(valid) > 1:
        reasons.append(f"incompatible {kind}s: {'; '.join(valid)}")
    return (next(iter(valid.values())) if len(valid) == 1 else None), reasons


def native_value(result: EpisodeResult | None, key: str) -> tuple[float | None, list[str]]:
    value = result.rewards.get(key) if result is not None else None
    if value is None:
        return None, [f"no native reward {key!r}"]
    if not math.isfinite(value):
        return None, [f"native reward {key!r} is not finite"]
    return value, []


def metrics(run_dir: Path, pool: list[str], results: dict, result: InspectionResult, warnings: list[str]) -> dict:
    """Confusion counts/F1 and AUROC against eligible references, each ordinary episode
    counted once. Local discrepancy labels never become matrix cells."""
    episodes, confusion, auroc = {}, {}, {}
    for name in pool:
        own = [assessment for assessment in result.assessments if assessment.claim.episode == name]
        bases = [assessment.claim.basis for assessment in own if assessment.claim.basis is not None]
        completion, completion_reasons = reference(name, own)
        entry = episodes[name] = {"completion": completion, "completion_reasons": completion_reasons, "decision": None, "score": None}
        config = json.dumps(configuration(results[name]), sort_keys=True) if results.get(name) else ""
        rule, entry["decision_reasons"] = chosen([basis.decision for basis in bases if basis.decision], "native decision rule",
                                                 run_dir, name, rule_gap)
        if rule is not None:
            value, missing = native_value(results.get(name), rule.reward)
            entry["decision_reasons"] += missing
            if value is not None:
                entry["decision"] = "pass" if passes(rule, value) else "fail"
                if completion != "unknown":
                    confusion.setdefault((config, json.dumps(rule.model_dump(mode="json", exclude={"source"}), sort_keys=True)), []).append(name)
        ordering, entry["ordering_reasons"] = chosen([basis.ordering for basis in bases if basis.ordering], "score ordering",
                                                     run_dir, name)
        if ordering is not None:
            value, missing = native_value(results.get(name), ordering.reward)
            entry["ordering_reasons"] += missing
            entry["score"] = value
            if value is not None and completion != "unknown":
                auroc.setdefault((config, ordering.reward, ordering.higher_completes), []).append(name)

    matrices = []
    for (config, rule), names in confusion.items():
        cells = Counter((episodes[name]["completion"], episodes[name]["decision"]) for name in names)
        tp, fp, fn, tn = cells["complete", "pass"], cells["incomplete", "pass"], cells["complete", "fail"], cells["incomplete", "fail"]
        denominator = 2 * tp + fp + fn
        rule = json.loads(rule)
        matrices.append({"configuration": json.loads(config), "reward": rule["reward"], "rule": rule, "episodes": names,
                         "tp": tp, "fp": fp, "fn": fn, "tn": tn, "f1": 2 * tp / denominator if denominator else None,
                         "unavailable": None if denominator else "F1 is unavailable: its denominator 2TP + FP + FN is zero"})
    curves = []
    for (config, reward, higher), names in auroc.items():
        sign = 1 if higher else -1
        positives = [sign * episodes[name]["score"] for name in names if episodes[name]["completion"] == "complete"]
        negatives = [sign * episodes[name]["score"] for name in names if episodes[name]["completion"] == "incomplete"]
        pairs = [1.0 if positive > negative else 0.5 if positive == negative else 0.0 for positive in positives for negative in negatives]
        curves.append({"configuration": json.loads(config), "reward": reward, "higher_completes": higher, "episodes": names,
                       "positives": len(positives), "negatives": len(negatives),
                       "auroc": sum(pairs) / len(pairs) if pairs else None,
                       "unavailable": None if pairs else "AUROC is unavailable: it needs both classes"})

    for metric, groups, needs in (("F1", matrices, "native decision"), ("AUROC", curves, "score ordering")):
        if not groups:
            warnings.append(f"{metric} is unavailable: no ordinary episode has both an eligible completion reference "
                            f"and a source-grounded {needs}")
        warnings += [f"{group['unavailable']} for {group['reward']}" for group in groups if group["unavailable"]]
        used = sum(len(group["episodes"]) for group in groups)
        if groups and used < len(pool):
            warnings.append(f"{metric} uses {used} of {len(pool)} ordinary episodes; the rest are excluded with retained reasons")
    return {"episodes": episodes, "confusion": matrices, "auroc": curves}


def dump(item) -> dict | None:
    return item.model_dump(mode="json") if item is not None else None


def finding(assessment: Assessment) -> dict:
    """The claim, nudi's captured facts, the Inspector's interpretation and nudi's assessment, kept apart."""
    claim, check = assessment.claim, assessment.check
    return {
        "claim": {"mechanism": claim.mechanism, "episode": claim.episode, "reward": claim.reward, "unresolved": claim.unresolved},
        "captured": {
            "native_reward": assessment.reward, "ids": assessment.ids,
            "errors": [f"{error.type}: {error.message}" for error in assessment.errors],
            "check": None if check is None else {
                "id": check.id, "exit_code": check.exit_code, "environment": check.environment, "content": dump(check.content),
                "inputs": {key: dump(item) for key, item in check.inputs.items()},
                "requirement": dump(check.requirement), "scoring": dump(check.scoring),
                "submission": None if check.submission is None else {
                    "location": check.submission.location, "capture_point": check.submission.capture_point,
                    "sha256": check.submission.content.sha256}},
            "replay": dump(assessment.replay), "planted": dump(claim.planted), "persisted": dump(claim.persisted),
        },
        "interpretation": {"interpretation": claim.interpretation, "timing": check.timing if check else None,
                           "derivation": dump(claim.derivation), "coverage": dump(claim.coverage), "basis": dump(claim.basis)},
        "assessment": assessment.model_dump(mode="json", include={"outcome", "validity", "discrepancy", "reasons", "missing",
                                                                  "limits", "persistence", "persistence_reasons"}),
    }


def findings(assessments: list[Assessment]) -> dict:
    groups = {"evidenced": [], "suspected": [], "legitimate": []}
    for assessment in assessments:
        kind = "evidenced" if evidenced(assessment) else "legitimate" if (
            assessment.outcome == "legitimate" and not assessment.claim.unresolved) else "suspected"
        groups[kind].append(finding(assessment))
    return groups


def inspection(mode: str, result: InspectionResult, warnings: list[str]) -> dict:
    for category, status in result.categories.items():
        if status not in SETTLED:
            reason = result.applicability.get(category)
            warnings.append(f"{mode} category {category} is {status}" + (f": {reason}" if reason else ""))
    warnings += [f"{mode} {item.phase} attempt {item.number} ({item.category or 'all categories'}) {item.status}: {item.error}"
                 for item in result.attempts if item.status in ("refused", "inference_failure", "tool_failure")]
    return {"status": result.status, "categories": result.categories, "applicability": result.applicability,
            "applicability_evidence": result.applicability_evidence,
            "attempts": [item.model_dump(mode="json") for item in result.attempts], "findings": findings(result.assessments)}


def attack(result: AttackResult, record: RunRecord, warnings: list[str]) -> dict:
    """Evidence found or not found within the actual attempts of each tested hint condition.

    An entry is an attempt only when its episode started. `checks.attack` records an entry,
    and may name its episode, before the spending cap admits it; such blocked entries stay
    listed with their status, but neither count as attempts nor make a condition tested."""
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


def markdown(report: dict) -> str:
    """A readable rendering of `build`'s report; the JSON keeps every field."""
    config = report["configuration"]
    lines = ["# nudi report", "", f"Status: {report['status']}, relative to the selected analyses.", "", "## Configuration", ""]
    lines += [f"- {role}: {model['model']}, reasoning effort {model['reasoning_effort']}, "
              f"credential from {config['credential_sources'].get(role, 'nowhere: not resolved')}"
              for role, model in config["models"].items()]
    lines += [f"- Task: {config['task_dir']}; execution path {config['path']}: {'; '.join(config['path_reasons'])}",
              f"- Spending cap: {config['spending_cap']}; known cost ${config['known_cost']:.6f}; "
              f"calls with unknown prices: {config['unknown_cost_calls']}"]
    for item in config["provenance"]:
        setup = item["configuration"]
        versions = ", ".join(f"{name} {version}" for name, version in setup["versions"].items())
        lines.append(f"- Task {setup['task_name']} digest {setup['task_digest']}; {setup['model']}, reasoning effort "
                     f"{setup['reasoning_effort']}, {setup['path']} ({versions}): {', '.join(item['episodes'])}")
    lines += [f"- {name}: {reason}" for name, reason in config["provenance_unavailable"].items()]
    if not config["provenance"]:
        lines.append("- Task digest and version pins: unavailable, no retained episode record")
    lines += ["", "## Analyses", ""] + [f"- {name}: {status}" for name, status in report["analyses"].items()]

    lines += ["", "## Evidence collection", ""]
    selection = report["collection"]
    if selection is None:
        lines.append("No capture selection was recorded.")
    else:
        lines.append(f"Selection {selection['status']} in {selection['calls']} Inspector calls; known cost "
                     f"${selection['known_cost']:.6f}; calls with unknown prices: {selection['unknown_cost_calls']}.")
        lines.append(f"- Captured files: {', '.join(selection['selected']) or 'none'}")
        lines += [f"- Limit: {limit}" for limit in selection["limits"]]
        lines += [f"- {failure['episode']}: capture of {failure['location']} failed: {failure['error']['type']}: "
                  f"{failure['error']['message']}" for failure in selection["capture_failures"]]

    lines += ["", "## Ordinary rewards", ""]
    pool = report["ordinary"]
    if pool is None:
        lines.append("No ordinary pool was selected.")
    else:
        lines.append(f"{pool['attempted']} of {pool['requested']} requested episodes attempted; status {pool['status']}.")
        lines += [f"- {name}: no retained record; {'; '.join(errors) or 'cause unknown'}" for name, errors in pool["unrecorded"].items()]
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
    lines += ["", f"Outside the ordinary pool: {len(other['inspector'])} targeted Inspector, {len(other['probes'])} "
                  f"persistence probe and {len(other['attacker'])} attacker episodes."]

    lines += ["", "## Local grader labels", ""]
    if report["labels"] is None:
        lines.append("Grader inspection was not selected or not run.")
    else:
        lines.append(", ".join(f"{label} {count}" for label, count in report["labels"]["counts"].items()) or "No ordinary episode.")
        lines += [f"- {name}: {item['label']}" for name, item in report["labels"]["episodes"].items()]

    lines += ["", "## Metrics", ""]
    metric = report["metrics"]
    if metric is None:
        lines.append("Grader inspection was not selected or not run, so no metric reference exists.")
    else:
        lines += [f"- {name}: completion {item['completion']}; native decision {item['decision'] or 'unavailable'}; "
                  f"score {number(item['score'])}" for name, item in metric["episodes"].items()]
        for group in metric["confusion"]:
            rule = group["rule"]
            encoding = f"pass values {rule['pass_values']}" if rule["pass_values"] else f"{rule['comparison']} {rule['threshold']}"
            lines.append(f"- F1 for {group['reward']} ({encoding}): TP {group['tp']}, FP {group['fp']}, FN {group['fn']}, "
                         f"TN {group['tn']}; F1 {number(group['f1'])}")
        for group in metric["auroc"]:
            direction = "higher" if group["higher_completes"] else "lower"
            lines.append(f"- AUROC for {group['reward']}, {direction} toward completion: {group['positives']} complete, "
                         f"{group['negatives']} incomplete; AUROC {number(group['auroc'])}")

    lines += ["", "## Findings", ""]
    sections = [(mode, item["findings"]) for mode, item in report["inspections"].items()]
    sections += [("attack", report["attack"]["findings"])] if report["attack"] else []
    entries = []
    for source, groups in sections:
        for kind, items in groups.items():
            for item in items:
                claim, outcome, check = item["claim"], item["assessment"], item["captured"]["check"]
                entries.append(f"- {source} {kind}: {claim['mechanism']} in {claim['episode']}; native reward "
                               f"{number(item['captured']['native_reward'])}; check {check['id'] if check else 'none'}; "
                               f"{outcome['outcome']}: {'; '.join(outcome['reasons'] + outcome['missing'])}")
    lines += entries or ["None retained."]

    lines += ["", "## Attack", ""]
    result = report["attack"]
    if result is None:
        lines.append("Not selected or not run.")
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
