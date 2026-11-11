"""Deterministic JSON and Markdown reports from a run's retained records.

A report reads `run.json`, episode records, `inspection-*.json` and `attack.json`; it
starts no episode or model call. Claims and references are Inspector interpretations:
nudi checks their retained provenance and consistency, not semantic correctness.
Resolved credentials passed as `secrets` never reach the output.
"""

import json
import logging
import math
import operator
import re
import statistics
from collections import Counter
from datetime import datetime, timedelta
from fractions import Fraction
from pathlib import Path

from nudi.assessment import Evidence, Ungrounded, classify_probe, conclusions, satisfied
from nudi.attack import SESSION_FAILURES, AttackAttempt, AttackResult
from nudi.inspection import InspectionResult, evidenced, replaced, scope as inspection_scope
from nudi.records import (CANCELLED, PROVIDER_REPORTED, Assessment, CallRecord, EpisodeResult, MetricBasis, Observation, RunRecord,
                          write_private)

ANALYSES = ("simulation", "grader", "hack", "attack")
FILES = {"grader": "inspection-grader.json", "hack": "inspection-hack.json", "attack": "attack.json"}
SETTLED = ("evidenced_issue", "no_evidenced_issue")
UNSUPPORTED_LABELS = ("unknown", "unavailable", "ungrounded", "unreviewed")
# Jobs in report order, and the session name prefixes of the Inspector's; older records name attack inspector
# sessions `inspector-attacker-...` and `replay-inspector-attacker-...`, and have a grouping call instead of the judge.
JOBS = ("Simulator", "grader inspector", "hack inspector", "judge", "grouping", "Attacker", "attack inspector", "persistence probe", "inspector")
INSPECTOR_JOBS = (("grader-", "grader inspector"), ("hack-", "hack inspector"), ("judge", "judge"), ("problems", "grouping"),
                  ("attack_inspector-", "attack inspector"), ("inspector-attacker-", "attack inspector"),
                  ("replay-inspector-attacker-", "attack inspector"))
COMPARISONS = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "==": operator.eq}
DESCRIPTIVE = "descriptive only; difficulty, sampling and execution conditions limit what rewards show"
# Distribution flags need this many usable rewards; below it quartiles rest on two or three values.
FLAG_MINIMUM = 10
Z95 = statistics.NormalDist().inv_cdf(0.975)
# Each distribution flag names its episodes and states no cause.
FLAG_TEXT = {
    "identical_rewards": (
        "All {usable} usable {key} rewards are {value}. {position} The 95% Wilson interval still allows another value in up to "
        "{bound} of episodes. {tags} Identical rewards can come from a task that is easy or too hard for {model} at this setting, "
        "from an environment failure shared by every episode, or from a grader that returns {value} whatever the work; rewards "
        "alone do not show which. If the policy being trained behaves like this Simulator, groups with identical rewards give "
        "zero advantage under group relative estimators such as GRPO."),
    "low_minority": (
        "{count} of {usable} usable {key} rewards are below the rest by the quartile rule ({named}; median {median}, lower fence "
        "{fence}). {tags} A few lower rewards in a mostly higher pool can come from model mistakes, sampling, time limits, "
        "refusals or infrastructure failures, or from the tail of an ordinary spread. They can also come from a grader that "
        "rejects valid work or a prompt that admits another reading. This is a reward pattern, not a finding; reading these "
        "episodes beside higher ones is the next step."),
    "high_minority": (
        "{count} of {usable} usable {key} rewards are above the rest by the quartile rule ({named}; median {median}, upper fence "
        "{fence}). {tags} A few higher rewards in a mostly lower pool can come from occasional success on a hard task, sampling, "
        "or the tail of an ordinary spread. They can also come from a grader that accepts invalid work or a shortcut. This is a "
        "reward pattern, not a finding; reading these episodes beside lower ones is the next step."),
}
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
    "false positive rate FP / (FP + TN) is a different quantity. The default 12 ordinary runs give rough estimates. "
    "Unresolved episodes may be systematically harder, so the rates describe the eligible subset, not the whole pool. "
    "A presumed label stands in for the grader's own verdict, so rates that use one are lower bounds and F1 is then an upper bound."
)
# Raised when a field of report.json changes meaning or goes away; a new field keeps it.
SCHEMA_VERSION = 1
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
    "marked with the later reading that superseded it. The evidenced count reads the latest "
    "reading of each check; local labels and metrics read every reading."
)


def retained(run_dir: Path, record: RunRecord) -> dict[str, bool]:
    """Whether each analysis left a record in `run_dir`."""
    return {"simulation": record.simulation is not None, **{name: (run_dir / file).is_file() for name, file in FILES.items()}}


def build(run_dir: Path, secrets=(), selected=None, stop=None, running=False) -> dict:
    """The report of the run in `run_dir`. `selected` names the requested analyses,
    by default those with retained records; completion is relative to them. `stop` says why a run
    stopped without closing out, such as a killed process or the error its `run_end` recorded: its status is `stopped`.
    `running` builds the report so far of a run still going: its status is `running`, a selected analysis without a
    record is `not started`, and neither that nor an analysis still running is a warning."""
    record = RunRecord.model_validate_json((run_dir / "run.json").read_text())
    present = retained(run_dir, record)
    selected = [name for name in ANALYSES if present[name]] if selected is None else list(selected)
    if any(name not in ANALYSES for name in selected):
        raise ValueError(f"analyses must be among {', '.join(ANALYSES)}")
    loaded = {name: (AttackResult if name == "attack" else InspectionResult).model_validate_json((run_dir / file).read_text())
              for name, file in FILES.items() if name in selected and present[name]}
    warnings, notes, analyses = [f"run: {warning}" for warning in record.warnings], [], {}
    for name in selected:
        if not present[name]:
            analyses[name] = "not started" if running else "not run"
            if not running:
                warnings.append(f"{name} was selected but not run")
            continue
        analyses[name] = record.simulation.status if name == "simulation" else loaded[name].status
        if analyses[name] != "complete" and not (running and analyses[name] == "running"):
            warnings.append(f"{name} {analyses[name]}: its coverage is incomplete")
    if record.unknown_cost_calls:
        warnings.append(f"{record.unknown_cost_calls} model calls have unknown prices; the known cost excludes them")
    if record.cancelled_calls:
        warnings.append(f"{record.cancelled_calls} model calls were cancelled in flight, so their usage is unknown; the known cost excludes them")

    # Execution apart from evidence: a step that failed, stopped or never ran is unfinished; one that ran to its end with
    # a status other than complete left evidence unresolved, which is its result and keeps the run complete. A partial step
    # with an attempt that failed to execute and that no later attempt of the same work recovered did not run to its end.
    failed = {*record.failed_phases, *(name for name, result in loaded.items() if result.status == "partial" and unrecovered(result))}
    unfinished = {name: status for name, status in analyses.items()
                  if name in failed or not present[name] or status not in ("complete", "partial", "not run")}
    results = {name: episode(run_dir, name) for name in record.episodes}
    # Each inspector finding by its candidate id, `hack-N` or `grader-N`.
    inspected = {f"{mode}-{index}": item for mode in ("hack", "grader") if mode in loaded for index, item in enumerate(loaded[mode].assessments)}
    pool = record.simulation.episodes if record.simulation else []
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "stopped" if stop or record.stop_reason else "running" if running else ("partial" if failed else "time_limit") if record.time_limit_reached
                  else "partial" if unfinished else "complete",
        "unfinished": unfinished,
        "unresolved": [name for name, status in analyses.items() if status != "complete" and name not in unfinished],
        "elapsed": (datetime.fromisoformat(record.ended_at) - datetime.fromisoformat(record.started_at)).total_seconds()
                   if record.started_at and record.ended_at else None,
        "stop": stopped(record, analyses, stop),
        "phase_errors": phase_errors(record),
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
        "attack": attack(loaded["attack"], record, warnings, inspected) if "attack" in loaded else None,
        "persistence": persistence(record, warnings),
        "warnings": warnings,
        "notes": notes,
    }
    held = {name for item in (report["attack"] or {}).get("problems", []) for name in item["findings"]}
    report["ungrouped"] = [name for mode in ("grader", "hack") if mode in loaded
                           for item in current(report["inspections"][f"{mode}_inspector"]) if (name := f"{mode}-{item['index']}") not in held]
    if "grader" in loaded:
        report["labels"] = labels(pool, loaded["grader"], warnings)
        report["metrics"] = metrics(run_dir, pool, results, loaded["grader"], warnings)
        notes += [LOCAL_LIMIT, METRIC_LIMIT, AGREEMENT_LIMIT]
    if report["ordinary"]:
        # After labels and metrics, which the flags cite.
        distribution_flags(report, results, record.simulation)
    if "attack" in loaded:
        notes.append(NO_RATE)
    if loaded:
        notes.append(FINDINGS_NOTE)
    secrets = [secret for secret in secrets if secret]
    # Scrubbing matches whole secrets and the answer cuts text, so the answer reads the scrubbed report.
    report = scrub(report, secrets)
    report["outcome"] = scrub(headline(report, record, stop), secrets)
    report["answer"] = [report["outcome"], *scrub(answer(report), secrets)]
    return report


def stopped(record: RunRecord, analyses: dict, stop: str | None) -> dict | None:
    """Why the run stopped before its end, as data: its `kind`, the analysis it stopped (`phase`), the time limit's
    `minutes`, and the `reason` a caller such as `nudi report` gave or the provider's account refusal; None for a run
    that ended on its own. Ctrl-C, SIGTERM and the time limit are read from the warnings the run recorded, the spending
    cap from the analyses' statuses."""
    found = {"kind": None, "phase": None, "minutes": None, "reason": stop}
    if record.stop_reason:
        return found | {"kind": "provider_refused", "reason": record.stop_reason}
    for warning in record.warnings:
        if match := re.fullmatch(r"(cancelled|stopped by a termination signal) during (.+)", warning):
            return found | {"kind": "cancelled" if match[1] == "cancelled" else "terminated", "phase": match[2]}
    if stop:
        return found | {"kind": "stopped"}
    if record.time_limit_reached:
        for warning in record.warnings:
            if match := re.fullmatch(r"the run stopped at its time limit of (\S+) minutes during (.+)", warning):
                return found | {"kind": "time_limit", "minutes": float(match[1]), "phase": match[2]}
        return found | {"kind": "time_limit"}
    if capped := [name for name, status in analyses.items() if status == "spending_exhausted"]:
        return found | {"kind": "spending_cap", "phase": capped[0]}
    return None


def phase_errors(record: RunRecord) -> dict[str, str]:
    """The error of each analysis that raised one, from its `NAME failed: ERROR` or `NAME stopped: ERROR` warning."""
    return {match[1]: match[2] for warning in record.warnings
            if (match := re.fullmatch(rf"({'|'.join(ANALYSES)}) (?:failed|stopped): (.*)", warning, re.DOTALL))}


def write(run_dir: Path, secrets=(), selected=None, stop=None, running=False) -> tuple[Path, Path]:
    """Write `report.json` and `report.md` beside the run's records, each replacing the earlier one whole."""
    report = build(run_dir, secrets, selected, stop, running)
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
# Harbor's Modal request under each hard limit, or the limit when smaller (harbor/environments/modal.py).
MODAL_CORE_REQUEST, MODAL_MIB_REQUEST = 0.125, 128
# Harbor's default Modal sandbox lifetime, which nudi keeps.
MODAL_LIFETIME = timedelta(hours=24)


def modal_cost(record: RunRecord) -> dict | None:
    """An estimate of a Modal run's sandbox compute, each stopped sandbox's lifetime times its CPU
    and memory: at least its requests, at most its limits, since Modal bills the larger of request
    and use. It is outside the spending cap; `nudi cost` reads Modal's bill. A sandbox without
    declared limits is counted apart, and one that still runs after stop counts its whole 24 h lifetime."""
    if record.backend != "modal":
        return None
    at_requests = at_limits = 0.0
    without_limits = 0
    for sandbox in record.modal:
        if sandbox.cpus is None or sandbox.memory_mb is None:
            without_limits += 1
            continue
        started = datetime.fromisoformat(sandbox.started_at)
        stopped = datetime.fromisoformat(sandbox.stopped_at) if sandbox.removed else started + MODAL_LIFETIME
        seconds = (stopped - started).total_seconds()
        at_requests += seconds * (min(sandbox.cpus, MODAL_CORE_REQUEST) * MODAL_CORE_SECOND
                                  + min(sandbox.memory_mb, MODAL_MIB_REQUEST) / 1024 * MODAL_GIB_SECOND)
        at_limits += seconds * (sandbox.cpus * MODAL_CORE_SECOND + sandbox.memory_mb / 1024 * MODAL_GIB_SECOND)
    return {"at_requests": at_requests, "at_limits": at_limits, "app": f"nudi-{record.run_id}", "sandboxes": len(record.modal),
            "without_limits": without_limits, "still_running": sum(not sandbox.removed for sandbox in record.modal)}


def billed_cost(record: RunRecord) -> float | None:
    """The backend's bill for the run's sandboxes, or None with a one-line reason logged. Only
    Modal reports one; a provider with a billing API adds its branch here and its function beside
    its environment. Nothing calls it during a run: it reports cost and limits nothing."""
    if record.backend == "modal":
        try:
            from nudi.modal_env import billed_cost as modal_bill
        except Exception as error:
            # Importing the Modal SDK reads the user's profile; the TOML parser's error text can quote a token.
            logging.getLogger("nudi").warning(f"Modal's bill cannot be read: loading Modal raised {type(error).__name__}")
            return None
        return modal_bill(record)
    logging.getLogger("nudi").warning(f"{record.backend} has no bill to read")
    return None


def configuration_section(record: RunRecord, results: dict) -> dict:
    """Credentials appear only as their variable names and where they were found.

    `provenance` groups every retained episode record, of any role, by its task digest,
    model and version pins; episodes without a record are listed as unavailable."""
    provenance = {}
    for name, result in results.items():
        if result is not None:
            provenance.setdefault(json.dumps(configuration(result), sort_keys=True), []).append(name)
    # The task and earlier run directories' names only; their host paths stay in run.json, out of a report that may be shared.
    return {"task_dir": Path(record.task_dir).name, "attack_from": record.attack_from and Path(record.attack_from).name,
            "path": record.path, "path_reasons": record.path_reasons,
            "provenance": [{"configuration": json.loads(key), "episodes": names} for key, names in provenance.items()],
            "provenance_unavailable": {name: "no retained episode record, so its task digest and version pins are unavailable"
                                       for name, result in results.items() if result is None},
            "models": {role: model.model_dump(mode="json") for role, model in record.models.items()},
            "credential_sources": record.credential_sources, "spending_cap": record.spending_cap,
            "known_cost": record.known_cost, "provider_reported_cost": reported(record.calls), "unknown_cost_calls": record.unknown_cost_calls,
            "unknown_reasons": unknown_reasons(record.calls), "cancelled_calls": record.cancelled_calls, "cost_by_job": cost_by_job(record),
            "refused_calls": record.refused_calls, "capacity": record.capacity.model_dump(mode="json"),
            "backend": record.backend, "modal_cost": modal_cost(record),
            "cost_map": record.cost_map, "limitations": record.limitations}


def wilson(count: int, total: int) -> list[float]:
    """The 95% Wilson score interval for a share of `count` in `total`."""
    centre, half = count + Z95 ** 2 / 2, Z95 * math.sqrt(count * (total - count) / total + Z95 ** 2 / 4)
    return [max(0.0, (centre - half) / (total + Z95 ** 2)), min(1.0, (centre + half) / (total + Z95 ** 2))]


def skewness(values: list[float]) -> float:
    """The adjusted Fisher-Pearson coefficient G1 of values that are not all equal. Exact moments keep
    tiny or huge finite rewards from under- or overflowing; m3^2 / m2^3 does not depend on scale."""
    n, exact = len(values), [Fraction(value) for value in values]
    mean = sum(exact) / n
    m2, m3 = (sum((value - mean) ** power for value in exact) / n for power in (2, 3))
    g1 = math.sqrt(m3 ** 2 / m2 ** 3)
    return math.sqrt(n * (n - 1)) / (n - 2) * (-g1 if m3 < 0 else g1)


def summarize(key: str, names: list[str], results: dict) -> dict:
    """Missing and non-finite rewards are excluded and listed, never zero. With two observed values,
    the share at the higher one has its 95% Wilson interval and, with exclusions, the shares it would
    have had every excluded episode received the lower or the higher value."""
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
    distribution, sd, share = sorted(Counter(values).items()), statistics.stdev(values) if len(values) > 1 else None, None
    if len(distribution) == 2:
        (lower, _), (higher, count) = distribution
        excluded = len(names) - len(values)
        share = {"value": higher, "lower": lower, "count": count, "interval": wilson(count, len(values)),
                 "range": [count / len(names), (count + excluded) / len(names)] if excluded else None}
    return {"attempted": len(names), "usable": len(values), "missing": missing, "invalid": invalid,
            "mean": statistics.fmean(values) if values else None, "sd": sd,
            "median": statistics.median(values) if values else None, "minimum": min(values, default=None),
            "maximum": max(values, default=None), "skewness": skewness(values) if len(values) > 2 and sd > 0 else None,
            "share": share, "distribution": [[value, count] for value, count in distribution], "unavailable": unavailable}


def recorded(named: list[str], results: dict, simulation) -> dict[str, dict]:
    """The timeouts, error types and refusal signals each named episode recorded."""
    return {name: {"agent_timeout": results[name].agent_timeout, "verifier_timeout": results[name].verifier_timeout,
                   "errors": [error.type for error in simulation.failures.get(name, [])],
                   "refusals": list(simulation.refusals.get(name, []))} for name in named}


def tags(facts: dict[str, dict]) -> str:
    """What the episodes of `recorded` recorded, each by name."""
    found = {name: ["agent timeout"] * item["agent_timeout"] + ["verifier timeout"] * item["verifier_timeout"]
             + [f"error {error}" for error in item["errors"]] + [f"refusal {signal}" for signal in item["refusals"]]
             for name, item in facts.items()}
    listing = "; ".join(f"{name} {', '.join(items)}" for name, items in found.items() if items)
    tagged = sum(bool(items) for items in found.values())
    if not tagged:
        return "None recorded an error, timeout or refusal."
    if tagged == len(found):
        return f"Every one recorded an error, timeout or refusal ({listing}), so time limits or infrastructure may explain the pattern."
    return f"{tagged} of them recorded an agent timeout, verifier timeout, error or refusal ({listing})."


def label_clause(named: list[str], labels: dict) -> str:
    """The grader inspector's local labels of the named episodes; no label confirms a flag."""
    items = [labels[name] for name in named]
    if all(item["basis"] == "presumed" or item["label"] in UNSUPPORTED_LABELS for item in items):
        return "Every named episode has a presumed or unsupported label, so grader inspection did not examine this pattern."
    return ("Grader inspection labels: " + ", ".join(f"{name} {item['label']}" + (f" ({item['basis']})" if item["basis"] else "")
                                                    for name, item in zip(named, items))
            + ". A label describes its episode, not this pattern.")


def distribution_flags(report: dict, results: dict, simulation) -> None:
    """Add its distribution flags to each ordinary reward summary. A flag is a reward pattern that names
    the episodes to read, never a finding: it changes no status, label, category or rate and stays out of
    the warnings. Flags need FLAG_MINIMUM usable rewards; the minority flags use Tukey's outer fences,
    3 IQR beyond the inclusive quartiles."""
    labels = report["labels"]["episodes"] if report["labels"] else None
    confusion = report["metrics"]["confusion"] if report["metrics"] else []
    for group in report["ordinary"]["groups"]:
        keys = {key for name in group["episodes"] for key in results[name].rewards}
        environment = next(iter(keys)) if len(keys) == 1 else "reward"
        for key, summary in group["rewards"].items():
            values = {name: value for name in group["episodes"] if (value := native_value(results[name], key)[0]) is not None}
            summary["flags"], summary["flags_not_evaluated"] = [], None
            if len(values) < FLAG_MINIMUM:
                summary["flags_not_evaluated"] = (f"Distribution flags are not evaluated for {key!r}: {len(values)} usable rewards, "
                                                  f"fewer than {FLAG_MINIMUM}.")
                continue
            fields = {"usable": len(values), "key": repr(key), "median": number(summary["median"]),
                      "model": group["configuration"]["model"], "value": number(summary["minimum"])}
            if len(summary["distribution"]) == 1:
                rule = [item for item in confusion if item["status"] == "supported"
                        and (item["configuration"], item["reward"]) == (group["configuration"], key)]
                fields["position"] = (
                    f"Every usable episode {'passes' if rule[0]['pass_rate']['numerator'] else 'fails'} its grounded decision rule."
                    if rule else f"Whether {fields['value']} is the grader's maximum or minimum is not established.")
                fields["bound"] = f"{wilson(0, len(values))[1]:.0%}"
                found, quartiles = {"identical_rewards": (list(values), None)}, None
            else:
                q1, _, q3 = statistics.quantiles(values.values(), n=4, method="inclusive")
                low, high, quartiles = q1 - 3 * (q3 - q1), q3 + 3 * (q3 - q1), [q1, q3]
                found = {"low_minority": ([name for name, value in values.items() if value < low], low),
                         "high_minority": ([name for name, value in values.items() if value > high], high)}
            share, excluded, shared = summary["share"], summary["attempted"] - len(values), []
            if share:
                higher, (lowest, highest) = number(share["value"]), share["interval"]
                shared.append(f"{share['count']} of {len(values)} are {higher} (95% Wilson interval {lowest:.2f} to {highest:.2f} for "
                              "its share, assuming independent episodes); SD and skewness follow from this share.")
            if excluded:
                shared.append(f"{excluded} of {summary['attempted']} attempted episodes have no usable reward and are excluded"
                              + (f"; had all of them received {higher}, or all {number(share['lower'])}, the share at {higher} "
                                 f"would be {share['range'][1]:.2f} or {share['range'][0]:.2f}" if share else "") + ".")
            if len(summary["distribution"]) > 2:
                shared.append("The reward range is not established; differences are in reward units.")
            if key != environment:
                shared.append(f"{key!r} is a component or metric; its use as a training reward is not established.")
            for flag, (named, fence) in found.items():
                if named:
                    facts = recorded(named, results, simulation)
                    text = FLAG_TEXT[flag].format(**fields, count=len(named), fence=number(fence),
                                                  named=", ".join(f"{name} {number(values[name])}" for name in named), tags=tags(facts))
                    clauses = [text, *shared]
                    if labels is not None:
                        clauses.append(label_clause(named, labels))
                    summary["flags"].append({"flag": flag, "episodes": named, "text": " ".join(clauses), "quartiles": quartiles,
                                             "fence": fence, "minimum": FLAG_MINIMUM, "recorded": facts})


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
            if len(distribution) > 1:
                notes.append(f"{label}: mixed, from {distribution[0][0]} to {distribution[-1][0]}; {DESCRIPTIVE}")
            elif distribution and summary["usable"] < FLAG_MINIMUM:
                # From FLAG_MINIMUM usable rewards the identical_rewards flag replaces this note.
                notes.append(f"{label}: constant {distribution[0][0]} across {summary['usable']} usable rewards; {DESCRIPTIVE}")
        # A value that is not a finite number is null, as JSON has no other.
        by_episode = {name: {key: value if value is not None and math.isfinite(value) else None
                             for key, value in results[name].rewards.items()} for name in names}
        summaries.append({"configuration": config, "episodes": names, "rewards": rewards, "episode_rewards": by_episode})
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


def resolved(own: list[Assessment]) -> list[Assessment]:
    """The checked assessments with a conclusive reading.
    Doubt is one-sided: an evidenced issue counts with its open claim items; any other assessment needs none."""
    return [item for item in own if (evidenced(item) or not item.claim.unresolved)
            and any(validity != "unknown" for _, validity in conclusions(item))]


def completion_gaps(basis: MetricBasis, own: list[Assessment], run_dir: Path, name: str) -> tuple[list[str], list[Observation]]:
    """Why a basis does not establish completion, empty when it does, and the cited requirements
    no check of this episode reads. `own` are the episode's own checked assessments, each with
    one conclusion per requirement it read. Supported completion needs every cited requirement
    observed satisfied by a cited check; incomplete needs one uncontested observed violation of a
    cited requirement. An unread requirement is listed when no check of this episode observes a
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
    settled = resolved(own)
    cited = [item for item in settled if item.check.id in basis.checks]
    every = [found for item in settled for found in conclusions(item) if found[1] != "unknown"]
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
        elif satisfied(item, observed):
            continue
        elif item not in read:
            # A violation may be this requirement quoted differently.
            if violation:
                gaps.append(f"no check reads requirement {item.path}: {item.excerpt!r} and a check of this episode observed a violation")
            elif reason := grounded(run_dir, name, item):
                gaps.append(f"requirement {item.path}: {item.excerpt!r}: {reason}")
            else:
                # Grounding the quote does not establish the episode met it.
                gaps.append(f"no check reads requirement {item.path}: {item.excerpt!r}; whether the episode met it is unknown")
                if item.episode is None:
                    unobserved.append(item)
        else:
            gaps.append(f"no cited check observes requirement {item.path}: {item.excerpt!r} satisfied")
    if basis.requirements and not any(satisfied(item, observed) for item in basis.requirements):
        gaps.append("no cited check observes a cited requirement satisfied")
    return gaps, unobserved


def ordinary_assessments(name: str, assessments: list[Assessment]) -> list[Assessment]:
    """Only native assessments whose check belongs to this ordinary episode."""
    return [item for item in assessments if item.execution_scope == "native" and item.claim.episode == name
            and item.check is not None and item.check.content.episode == name]


def reference(name: str, assessments: list[Assessment], run_dir: Path) -> tuple[str, list[str], list[str]]:
    """The episode's completion reference: complete, incomplete or unknown, with reasons and
    the cited requirements no check reads, each of which keeps completion unknown.
    Reward never supplies it, and legitimate partial credit alone is neither label.
    Only the episode's own checked assessments supply a basis or an observation; a basis
    without a check still keeps complete unknown until its task requirements are observed satisfied."""
    own = ordinary_assessments(name, assessments)
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
    if found == {"complete"}:
        # Every task requirement any native basis of this episode cites, checked or not, must be observed
        # satisfied and never violated.
        observed = [conclusion for item in resolved(own) for conclusion in conclusions(item)]
        cited = [item for assessment in assessments if assessment.execution_scope == "native" and assessment.claim.episode == name
                 and assessment.claim.basis for item in assessment.claim.basis.requirements if item.episode is None]
        if any(not satisfied(item, observed) or (item, "violated") in observed for item in cited):
            found.clear()
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
    eligible episodes, each counted once, beside the rule's native pass rate with its 95% Wilson interval; plus AUROC and
    coverage of the ordinary pool. Local discrepancy labels never become matrix cells. A
    presumed label enters as the grader's own verdict and marks the rates it changes as lower bounds."""
    episodes, configs, rules, valid, auroc = {}, {}, {}, {}, {}
    for name in pool:
        own = ordinary_assessments(name, result.assessments)
        bases = [assessment.claim.basis for assessment in own if assessment.claim.basis is not None]
        completion, completion_reasons, unobserved = reference(name, result.assessments, run_dir)
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
                                  missing=None if rule else "no source-grounded native decision rule")
                | {"interval": wilson(passed, len(usable)) if rule and usable else None},
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
                  "limits": claim.limits, "use": dump(claim.use)},
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
            "planted": dump(claim.planted), "persisted": dump(claim.persisted),
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


def findings(assessments: list[Assessment], links: dict[int, dict] | None = None, experiments: list[dict] = ()) -> dict:
    """Every finding by nudi's result, with its index into the inspection's assessments.

    Category settlement reads a check's latest reading, and an experiment that a later one of `experiments` replaces
    through its replacement's, as `open` does, so an earlier one names that reading as superseding it
    and stays listed, since its evidence and open conditions can still explain a label, metric or category.
    A claim without a check is never superseded. Each finding keeps its execution scope, so package evidence
    stays distinct from native accessibility, and the category and experiment `links` give it."""
    latest = {item.claim.check: index for index, item in enumerate(assessments) if item.claim.check}
    answered, checks = replaced(experiments, assessments), {row["id"]: row.get("check") for row in experiments}
    for row in experiments:
        if (gone := checks.get(row.get("replaces"))) in answered and row.get("check") in latest:
            latest[gone] = latest[row["check"]]
    groups = {"evidenced": [], "legitimate": [], "inconclusive": []}
    for index, assessment in enumerate(assessments):
        later = latest.get(assessment.claim.check, index)
        superseded = None if later == index else {"index": later, "result": result_of(assessments[later])}
        groups[result_of(assessment)].append({"index": index, "superseded_by": superseded,
                                              **finding(assessment, **(links or {}).get(index, {}))})
    return groups


def together(one: str, many: str, names: list[str], status: str) -> str:
    """One warning for every name in the same state."""
    return f"{one} {names[0]} is {status}" if len(names) == 1 else f"{many} {', '.join(names)} are {status}"


def inspection(mode: str, result: InspectionResult, warnings: list[str]) -> dict:
    warnings += [f"{mode} inspector {item.phase} attempt {item.number} ({item.category or item.episode or 'all categories'}) {item.status}"
                 + (f": {item.error}" if item.error else ", no error message recorded")
                 for item in result.attempts if item.status in ("refused", "model_inability", "model_output_failure", "unobservable", "inference_failure",
                                                                 "tool_failure", "out_of_memory", "step_limit")]
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
    given = {"hack_inspection": result.hack_inspection, "hack_findings": result.hack_findings} if mode == "grader" else {}
    return {"status": result.status, "open": result.open, "suspected": suspected(result, measured), "categories": result.categories,
            "applicability": result.applicability,
            "artifacts": result.artifacts, "limits": result.limits, "experiments": result.experiments,
            "attempts": [item.model_dump(mode="json") for item in result.attempts], "findings": findings(result.assessments, links, result.experiments), **given}


def suspected(result: InspectionResult, measured: dict) -> list[dict]:
    """Each suspected exploit, by its category and check: a measured experiment, not a control and not replaced, whose check's
    latest reading ended unknown, also when the run ended before it was read, in a category and case no evidenced reading has.
    A case is its name with what it measured: the episode or package, location and capture point.
    It is never a problem. `measured` maps each check to its experiment."""
    latest = {item.claim.check: item for item in result.assessments if item.claim.check}
    read = {check: row for check, row in measured.items() if check in latest and not row.get("control")
            and row.get("status") in ("assessed", "unfinished") and check not in replaced(result.experiments, result.assessments)}

    def case(row) -> tuple:
        return (row.get("category"), row.get("case") or row.get("check"), inspection_scope(row), row.get("location"),
                row.get("capture_point") or "verification_start")
    shown = {case(row) for check, row in read.items() if evidenced(latest[check])}
    return [{"category": row.get("category"), "check": check} for check, row in read.items()
            if latest[check].outcome == "unknown" and case(row) not in shown]


def _condition_view(status, guidance, unavailable, entries, record: RunRecord) -> dict:
    attempts = [item for item in entries if item.episode in record.episodes]
    return {
        "status": status, "guidance": guidance, "unavailable": unavailable, "tested": bool(attempts), "attempts": len(attempts),
        "outcomes": dict(sorted(Counter(item.status for item in attempts).items())),
        "evidence": "found" if any(item.status == "evidenced_issue" for item in attempts) else "not found" if attempts else "not attempted",
        "blocked": [{"number": item.number, "episode": item.episode, "status": item.status, "error": item.error,
                     "reason": "no episode of this entry started"} for item in entries if item.episode not in record.episodes],
    }


def _separated_attack(result: AttackResult, record: RunRecord, warnings: list[str], inspected: dict[str, Assessment]) -> dict:
    """Candidate reproduction and no-hint discovery. Started episodes are the only attempts. A problem neither an
    inspector's evidence nor an Attacker's exploit confirms, as an older record's problem judged before measurement or
    one whose findings later readings withdrew, is a lead and has no level."""
    quiet = {"evidenced_issue", "no_evidenced_issue", "unavailable", "not_requested", "not_needed", "not_applicable"}
    candidates, pending = [], {}
    for item in result.candidates:
        views = {}
        for level in ("full", "minimal", "none") if "none" in item.conditions else ("full", "minimal"):
            entries = [attempt for attempt in result.attempts if attempt.level == level and item.id in (
                attempt.sources or ([attempt.candidate] if attempt.candidate else []))]
            status = item.conditions.get(level, "unattempted")
            views[level] = _condition_view(status, item.guidance.get(level), item.unavailable.get(level), entries, record)
            if status not in quiet:
                pending.setdefault(status, {}).setdefault(item.id, []).append(level)
        candidates.append({"id": item.id, "source": item.source, "mechanism": item.mechanism, "outcome": item.outcome,
                           "valid_work": item.valid_work, "conditions": views})
    warnings += [together("attack candidate", "attack candidates", [f"{name} {' and '.join(levels)}" for name, levels in found.items()], status)
                 for status, found in pending.items()]
    discovery_entries = [attempt for attempt in result.attempts if attempt.level == "none" and attempt.candidate is None]
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
                "problem": finding.problem,
            })
    # A reproduction is judged against its candidate's problem cause, and different causes never share a run,
    # so it confirms only that problem. Of its findings, only those the reproducing attempt tested are reproduced.
    reproduced = {name for finding in result.findings if finding.kind == "reproduction" for name in finding.sources or [finding.candidate]}
    tested, valid = {item.id for item in result.candidates}, {item.id for item in result.candidates if item.valid_work}
    # Findings without full guidance: the attack gets none of them as a candidate.
    unguided = {name for name, item in inspected.items() if not (item.claim.full_guidance or "").strip()}
    # The current readings: each check's latest, by inspector, as the attack's candidates are. A problem whose findings
    # the inspections hold all lost their evidence, as when a stop came after a later reading withdrew them, is not evidenced.
    latest = {(name.split("-")[0], item.claim.check or name): name for name, item in inspected.items()}
    current = {name for name in latest.values() if evidenced(inspected[name])}
    problems, leads = [], []
    for problem in result.problems:
        needed, valid_work = exploited_with(problem, result, unguided), any(name in valid for name in problem.findings)
        withdrawn = bool(problem.findings) and set(problem.findings) <= inspected.keys() and not current & set(problem.findings)
        if (problem.id and (problem.evidence != "evidenced" or withdrawn) and needed not in LEVELS
                and not any(name.endswith("-attacker") for name in problem.members)):
            leads.append({"id": problem.id, "cause": problem.cause})
            continue
        scopes = {inspected[name].execution_scope for name in problem.findings if name in inspected}
        outcomes = {item.get("outcome") for item in problem.cases} | {inspected[name].outcome for name in problem.findings if name in inspected}
        outcomes &= {"accepted_invalid", "rejected_valid"}
        scope = "native" if "native" in scopes else next(iter(scopes), None)
        # Only a reading of an `other` experiment proposes a family, so a problem whose findings all do is outside every listed one.
        families = [inspected[name].claim.family if name in inspected else None for name in problem.findings]
        rank = ladder(needed, valid_work)
        if problem.origin and needed not in LEVELS:  # This run's Attackers did not find it again.
            before = ladder(problem.earlier_exploited_with, valid_work)
            rank = {"level": before["level"], "label": f"evidenced in run {problem.origin} at {before['label']}; not found again here"}
        problems.append({
            "id": problem.id, "source": problem.source, "members": problem.members, "cause": problem.cause, "findings": problem.findings,
            "cases": problem.cases, "candidate": next((name for name in problem.findings if name in tested), None),
            "reproduced": bool(reproduced & set(problem.findings)),
            "reproduced_findings": [name for name in problem.findings if name in reproduced], "exploited_with": needed,
            "conditions": conditions(problem, result, record, valid_work), "scope": scope,
            "outcome": outcomes.pop() if len(outcomes) == 1 else None,
            "family": families[0] if families and None not in families else None,
            # Unknown without the inspections, as when only the attack is selected.
            "evidenced_by_inspector": None if problem.findings and not inspected.keys() & set(problem.findings)
                                      else bool(current & set(problem.findings)),
            "origin": problem.origin, "earlier_exploited_with": problem.earlier_exploited_with,
            # An attempt that targeted another problem and exploited this one, as the judge named it, once for all its readings.
            "exploited_by": [{"episode": episode, "target": target} for episode, target in dict.fromkeys(
                (result.attempts[finding.attempt].episode, result.attempts[finding.attempt].problem)
                for finding in result.findings if finding.kind == "other" and problem.id and finding.problem == problem.id)],
            **rank})
    return {"status": result.status, "maximum_attempts": result.maximum_attempts, "discovery_attempts": result.discovery_attempts,
            "minimal_hints": result.minimal_hints, "candidates": candidates, "problems": problems, "leads": leads, "discovery": discovery,
            "unavailable": result.unavailable, "exploits": exploits,
            "attempts": [item.model_dump(mode="json") for item in result.attempts], "findings": findings(result.assessments),
            "limits": result.limits, **attack_calls(record)}


def unrecovered(result) -> bool:
    """An attempt failed to execute, such as an inference or tool failure or a native timeout without a reward or an
    interpretation, and no later attempt of the same work ended without one: the same candidate at the same hint level,
    or the same inspector category or episode, every unrestricted category for a broad session."""
    def work(item) -> set:
        return {(item.level, item.candidate)} if isinstance(item, AttackAttempt) else ({item.category or item.episode} - {None}) or {
            key for key, value in result.categories.items() if value != "restricted"}
    later, failures = set(), FAILURES
    for item in reversed(result.attempts):  # Records keep each work's attempts in the order they started.
        if item.status in failures and not (work(item) and work(item) <= later):
            return True
        later |= set() if item.status in failures else work(item)
    return False


LADDER = {2: "●●○○○ reproduced exploit", 3: "●●●○○ exploit executable by learner with full information",
          4: "●●●●○ exploit executable by learner with hint", 5: "●●●●● exploit executable by unaided learner"}
# The order to list problems in, by the least information under which an exploit was observed; older reports' values too.
# An exploit found under a hint or full instructions for another problem is at the rung of the information given.
LEVELS = {"none": 5, "minimal": 4, "full": 3, "elsewhere_minimal": 4, "elsewhere_full": 3, "found_alone": 5, "single_hint": 4,
          "full_info": 3, "full_info_or_less": 3}
ELSEWHERE = " (its help was for another problem)"
# Where a problem's findings were evidenced, after a level-2 label; unknown without the inspections, as when only the attack is selected.
SCOPES = {"package": "evidenced in a package sandbox", "native": "evidenced in a native episode"}


# A problem whose findings are correct work the grader fails is no exploit: the simulation chart's FN words, then how an Attacker reproduced it.
VALID_WORK = {3: ", reproduced by an Attacker with full instructions", 4: ", reproduced by an Attacker with only a hint",
              5: ", reproduced by an Attacker with no extra information"}


def ladder(needed: str, valid_work: bool = False) -> dict:
    """A problem's place in the list, 2 to 5, and its label. Below an Attacker's exploit, an evidenced problem is at 2.
    A problem of correct work the grader fails keeps its place and is labelled "Correct work failed"."""
    level = LEVELS.get(needed, 2)
    label = "Correct work failed" + VALID_WORK.get(level, "") if valid_work else LADDER[level]
    return {"level": level, "label": label + ELSEWHERE * str(needed).startswith("elsewhere_")}


def rung(item: dict, valid: set) -> tuple[int, str]:
    """A problem's level and label, also from a report written before them, where `not_reproduced` makes a lead, at 1.
    `valid` names the valid-work candidates."""
    if item.get("level"):
        return item["level"], item["label"]
    if item.get("help_needed") == "not_reproduced":
        return 1, ""
    found = ladder(item.get("exploited_with", item.get("help_needed", "unknown")), bool(valid & set(item.get("findings", []))))
    return found["level"], found["label"]


def exploited_with(problem, result: AttackResult, unguided: set[str]) -> str:
    """The least information under which an Attacker exploit of `problem` was observed, `none`, `minimal` or `full`: an
    order, not the least help needed. A no-hint exploit counts whether its attempt aimed at the problem, searched
    independently or aimed at another problem, as the judge names it; a hinted or full-information attempt aimed at
    another problem gives `elsewhere_minimal` or `elsewhere_full`, below the aimed level of the same information.
    Without an exploit, why: `not_exploited`, `no_guidance` or `unknown`."""
    def given(item) -> str:
        aimed = (item.candidate is None or item.level == "none" or problem.id and item.problem == problem.id
                 or set(item.sources or [item.candidate]) & set(problem.findings))
        return item.level if aimed else f"elsewhere_{item.level}"
    seen = {given(item) for item in result.attempts if item.episode in problem.members
            or problem.id and item.problem == problem.id and item.status == "evidenced_issue"}
    states = [item.conditions for item in result.candidates if item.id in problem.findings]
    seen |= {level for item in states for level, state in item.items() if state == "evidenced_issue"}
    if found := next((level for level in ("none", "minimal", "elsewhere_minimal", "full", "elsewhere_full") if level in seen), None):
        return found
    if any(item.get("full") == "no_evidenced_issue" for item in states):
        return "not_exploited"
    # Its findings gave the Attacker no guidance, so nothing was attacked. Without an attack candidate, since the attack
    # takes no finding without guidance, its retained findings say so.
    if states and all(item.get("full") == "unavailable" for item in states) or not states and set(problem.findings or [None]) <= unguided:
        return "no_guidance"
    return "unknown"


def conditions(problem, result: AttackResult, record: RunRecord, valid_work: bool) -> list[dict]:
    """Each condition an Attacker tried `problem` under, by the stream of its attempts: `full`, `minimal` and `none` aimed
    at its findings, in the cascade's order; then `elsewhere_LEVEL`, attempts aimed at another problem, when one of them
    exploited this one, as the judge named it; then `independent`, the no-hint search, which correct work the grader
    fails has not. Each has its started attempts, how many exploited the problem, the Attacker model and its status."""
    states = [item.conditions for item in result.candidates if item.id in problem.findings]
    model = record.models.get("attacker")

    def stream(item) -> str:
        return ("independent" if item.candidate is None else item.level if set(item.sources or [item.candidate]) & set(problem.findings)
                else f"elsewhere_{item.level}")

    rows = []
    for name in ("full", "minimal", "none", "elsewhere_full", "elsewhere_minimal", "elsewhere_none", "independent"):
        aimed, found = name in ("full", "minimal", "none"), [item[name] for item in states if name in item]
        if aimed and not found or name == "independent" and valid_work:
            continue
        started = [item for item in result.attempts if item.episode in record.episodes and stream(item) == name]
        # An attempt that failed to run or to be judged showed nothing, so it is listed apart and not counted.
        apart = [item for item in started if item.status in UNASSESSED and item.episode not in problem.members]
        assessed = [item for item in started if item not in apart]
        # An aimed attempt's own problem is its target; any other exploited this problem when the judge put it here.
        exploited = sum(item.episode in problem.members or item.status == "evidenced_issue" and (
            aimed or name == "independent" and bool(problem.id) and item.problem == problem.id) for item in assessed)
        if not (aimed or exploited or name == "independent"):
            continue
        independent = result.discovery.get("none", "unattempted")
        status = ("evidenced_issue" if "evidenced_issue" in found else found[0]) if aimed else "evidenced_issue" if exploited else (
            "no_evidenced_issue" if independent == "evidenced_issue" else independent)
        rows.append({"condition": name, "attempts": len(assessed), "exploited": exploited,
                     "model": model.model if model and started else None, "status": status,
                     **({"not_assessed": [{"episode": item.episode, "status": item.status, "reward": rewards(item.model_dump()),
                                           "error": item.error} for item in apart]} if apart else {})})
    return rows


def attack(result: AttackResult, record: RunRecord, warnings: list[str], inspected: dict[str, Assessment] = {}) -> dict:
    """Evidence found or not found within the actual attempts of each tested hint condition.

    An entry is an attempt only when its episode started. `attack.attack` records an entry,
    and may name its episode, before the spending cap admits it; such blocked entries stay
    listed with their status, but neither count as attempts nor make a condition tested.
    A result that names candidates or discovery uses that separated shape. Older records
    keep the pooled conditions."""
    if result.candidates or result.discovery:
        return _separated_attack(result, record, warnings, inspected)
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
    return {"status": result.status, "maximum_attempts": result.maximum_attempts, "conditions": conditions,
            "tested_conditions": [level for level, item in conditions.items() if item["tested"]],
            "attempts": [item.model_dump(mode="json") for item in result.attempts], "findings": findings(result.assessments),
            "limits": result.limits, **attack_calls(record)}


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


def job(call: CallRecord, record: RunRecord) -> str:
    """The agent job that made a call. An Inspector call names its session, `<mode>-...`, `judge`, `problems` for grouping or
    `attack_inspector-...`; an older record's native Inspector episode is `inspector`."""
    if call.episode in record.probe_episodes:
        return "persistence probe"
    if call.role != "inspector":
        return call.role.capitalize()
    return next((name for prefix, name in INSPECTOR_JOBS if call.episode.startswith(prefix)), "inspector")


def costs(calls: list[CallRecord]) -> dict:
    cancelled = sum(call.cost_source == CANCELLED for call in calls)
    return {"calls": len(calls), "known_cost": sum(call.cost for call in calls if call.cost is not None),
            "prompt_tokens": sum(call.prompt_tokens or 0 for call in calls),
            "completion_tokens": sum(call.completion_tokens or 0 for call in calls),
            "unknown_cost_calls": sum(call.cost is None for call in calls) - cancelled, "cancelled_calls": cancelled,
            "unknown_reasons": unknown_reasons(calls)}


def unknown_reasons(calls: list[CallRecord]) -> dict[str, int]:
    """How many calls with an unknown price, not cancelled, have each reason `record_call` gave."""
    found = {}
    for call in calls:
        if call.cost is None and call.cost_source != CANCELLED:
            reason = call.cost_source.removeprefix("unknown: ")
            found[reason] = found.get(reason, 0) + 1
    return found


def cost_by_job(record: RunRecord) -> dict:
    """Calls, known cost and tokens of each job that made a call. Every call has one job, so the known costs sum to the run's."""
    grouped = {}
    for call in record.calls:
        grouped.setdefault(job(call, record), []).append(call)
    return {name: costs(grouped[name]) for name in JOBS if name in grouped}


def attack_calls(record: RunRecord) -> dict:
    """The Attacker's and attack inspector's calls without a known cost."""
    found = costs([call for call in record.calls if job(call, record) in ("Attacker", "attack inspector")])
    return {key: found[key] for key in ("unknown_cost_calls", "cancelled_calls")}


# Why a call has no price, in words after its count; LiteLLM's own pricing errors keep their text.
UNPRICED = {"no response before its calls ended": "without a response before their calls ended",
            "the request failed": "whose request failed"}


def left_out(item: dict) -> str:
    """What a known cost leaves out, with the reasons calls have no price. Reports from before the reasons give a count."""
    why = ", ".join(f"{count} {UNPRICED.get(reason, f'not priced: {brief(reason)}')}" for reason, count in item.get("unknown_reasons", {}).items())
    parts = ([f"{item['unknown_cost_calls']} calls with unknown prices" + f" ({why})" * bool(why)] * bool(item["unknown_cost_calls"])
             + [f"{item['cancelled_calls']} calls cancelled in flight"] * bool(item["cancelled_calls"]))
    return f", excluding {' and '.join(parts)}" if parts else ""


def cost(config: dict) -> str:
    provider = config["provider_reported_cost"]
    return f"known cost ${config['known_cost']:.6f}" + (f", ${provider:.6f} of it provider-reported" if provider else "") + left_out(config)


def check_id(item: dict) -> str:
    return item["captured"]["check"]["id"] if item["captured"]["check"] else "none"


def unassessed(mode: str, item: dict) -> list[str]:
    """Each experiment with no assessment, once, whatever its category's status. A probe judged the same as an evidenced
    problem ran nothing."""
    read = {check_id(found) for group in item["findings"].values() for found in group}
    entries = [f"{entry['id']} {entry['status']} ({entry.get('category') or 'no category'}"
               + "".join(f", {entry[key]}" for key in ("check", "episode") if entry.get(key))
               + (", with a reading in Findings" if entry.get("check") in read else "") + ")"
               for entry in item["experiments"] if entry.get("status") not in ("assessed", "known_problem")]
    return [f"- {mode} experiments without an assessment: " + ", ".join(entries)] if entries else []


def still_open(mode: str, item: dict) -> list[str]:
    """The leads: one line per category, or for a grader inspector's ordinary episodes, that `open` names, with each of
    its entries; then each suspected exploit; then the categories an attempt failed in, one line per failure; then how many
    of each category's latest readings read legitimate, a count and no verdict."""
    groups, failed = {}, {}
    for entry in item.get("open", []):  # Older reports have no `open`.
        if entry["id"] == entry["category"] and entry["reason"].startswith("an attempt failed: "):
            failed.setdefault(entry["reason"], []).append(entry["category"])
        else:
            groups.setdefault(entry["category"] or "ordinary episodes", []).append(f"{entry['id']}: {entry['reason']}")
    counts = Counter(entry["category"] or "no category" for entry in item["findings"]["legitimate"] if entry["superseded_by"] is None)
    return ([f"- {mode} {category} leads: {'; '.join(entries)}" for category, entries in groups.items()]
            + [f"- {mode} ●○○○○ suspected exploit ({entry['category'] or 'no category'}, {entry['check']})" for entry in item.get("suspected", [])]
            + [f"- {mode} {', '.join(categories)} not finished: {reason}" for reason, categories in failed.items()]
            + [f"- {mode} legitimate readings: " + ", ".join(f"{category} {count}" for category, count in counts.items())] * bool(counts))


SUSPECTED = " (suspected: its hack inspector reading was unknown)"


def candidate_sources(report: dict) -> dict[str, str]:
    """What follows each attack candidate or problem finding id in the report: its inspector finding's
    category and check, as `hack-N` and `grader-N` come from that inspector's assessment N (`send.guidance`), and
    the suspected label when a hack reading was unknown. A later native reproduction keeps the label."""
    sources, unknown = {}, set()
    for prefix in ("hack", "grader"):
        inspection = report["inspections"].get(f"{prefix}_inspector")
        for item in (item for group in (inspection["findings"].values() if inspection else []) for item in group):
            sources[f"{prefix}-{item['index']}"] = f" ({item['category'] or 'no category'}, {check_id(item)})"
            if prefix == "hack" and item["assessment"]["outcome"] == "unknown":
                unknown.add(f"hack-{item['index']}")
    unknown |= {item["id"] for item in (report["attack"] or {}).get("candidates", []) if item.get("outcome") == "unknown"}
    for name in unknown:
        sources[name] = sources.get(name, "") + SUSPECTED
    return sources


def named(name: str, sources: dict) -> str:
    return name + sources.get(name, "")


# The help an Attacker attempt had, as the exploit chart names it.
HINTS = {"full": "full instructions", "minimal": "only a hint", "none": "no extra information"}


def tried(attempt: dict, sources: dict) -> tuple[str, str]:
    """The candidates an Attacker attempt tested, each with its source, and its hint."""
    names = attempt.get("sources") or ([attempt["candidate"]] if attempt.get("candidate") else [])
    return " and ".join(named(name, sources) for name in names), HINTS[attempt["level"]]


EXPLOITS = {"reproduction": "exploited {target} with {hint}",
            "other": "cheated through another mechanism while testing {target} with {hint}",
            "unattributed": "cheated while testing {target} with {hint}, not confirmed as that finding",
            "discovery": "cheated with {hint}"}


def exploits(attack: dict, sources: dict, by_problem: bool = False) -> list[tuple[int, int | None, str, bool]]:
    """Each Attacker exploit with evidence, once: its attempt, its assessment, what the Attacker did, and whether
    it is rejected valid work. `by_problem` names what an attempt tested by its problem's id when it has one.
    A record from before separated candidates has only its attempts' statuses."""
    if "exploits" in attack:
        found = [(item["attempt"], item["assessment"], kind, item["candidate"]) for kind, items in attack["exploits"].items() for item in items]
    else:
        found = [(index, item["assessment"], "discovery", None) for index, item in enumerate(attack["attempts"])
                 if item["status"] == "evidenced_issue"]
    valid = {item["id"] for item in attack.get("candidates", []) if item["valid_work"]}
    done = {}
    for index, assessment, kind, candidate in sorted(found, key=lambda item: item[0]):
        target, hint = tried(attack["attempts"][index], sources)
        target = attack["attempts"][index].get("problem") if by_problem and attack["attempts"][index].get("problem") else target
        if candidate in valid:
            text = f"had correct work failed while testing {target} with {hint}" + ("" if kind == "reproduction" else ", not confirmed as that finding")
        else:
            text = EXPLOITS[kind].format(target=target, hint=hint)
        done[index, assessment, text, candidate in valid] = None
    return list(done)


def oneline(text: str) -> str:
    return " ".join(text.split())


def brief(text: str) -> str:
    """The first sentence or about 140 characters of `text`, whichever is shorter, marked when cut."""
    sentence = re.match(r".*?[.!?](?=\s|$)", text)
    short = sentence.group() if sentence else text
    if len(short) > 140:
        short = short[:140].rsplit(" ", 1)[0]
    return text if short == text else short.rstrip(".") + "..."


def mechanism(attack: dict, assessment: int | None) -> str:
    """What the attack inspector says the Attacker did, on one line."""
    found = [item["claim"]["mechanism"] for group in attack["findings"].values() for item in group if item["index"] == assessment]
    return oneline(found[0]) if found else ""


def rewards(attempt: dict) -> str:
    return ", ".join(f"{key} {number(value)}" for key, value in attempt["rewards"].items()) or "no reward"


# An Attacker attempt that did not run or was not judged: it shows nothing, so no count of attempts includes it.
UNASSESSED = {*SESSION_FAILURES, "cancelled", "spending_exhausted", "environment_unavailable", "infrastructure_failure", "native_timeout",
              "episode_failure", "running"}
STOPPED = {"unknown": "result unclear", "cancelled": "cancelled", "spending_exhausted": "stopped by the spending cap", "running": "unfinished",
           "insufficient_time": "its agent timeout is longer than the time left before the time limit"}
WAITING = {"unattempted": "Not attempted", "unavailable": "Not attempted, no guidance", "not_requested": "Not attempted, hints not requested",
           "not_needed": "Not run, the previous step did not exploit it",
           "not_applicable": "Not attempted, no hint for correct work", "withdrawn": "Not attempted, a later reading withdrew the finding"}


def ending(attempt: dict, valid_work: bool) -> str:
    """A started attempt's outcome without an exploit, in plain words. A legitimate reading does not
    establish that the Attacker did the task, so no outcome claims what it submitted."""
    status = attempt["status"]
    if status == "no_evidenced_issue":
        return "no case where correct work failed was found" if valid_work else "no exploit was evidenced"
    if status in STOPPED:
        return STOPPED[status]
    return f"{status}: {attempt['error'].splitlines()[0]}" if attempt["error"] else status


def problem_sources(item: dict, level: int) -> str:
    """Who found a problem: its source, every other inspector whose finding the judge placed in it, and the independent
    attacker when its no-hint search exploited a problem an inspector found."""
    names = [item["source"]] if item.get("source") else []
    for member in item.get("members", []):
        found = {"hack": "hack inspector", "experiment": "hack inspector", "grader": "grader inspector"}.get(member.split("-")[0])
        names += [found] * (found is not None and found not in names)
    rows = item.get("conditions")  # Older reports have none, and a no-hint exploit there was independent.
    alone = any(row["condition"] == "independent" and row["exploited"] for row in rows) if rows is not None else level == 5
    names += ["independent attacker"] * (alone and item.get("source") != "Attacker")
    names = [f"the {name}" for name in names]
    return " and ".join(filter(None, [", ".join(names[:-1]), names[-1]])) if names else "an unnamed source"


# What each inspector did to its evidenced findings, in the words of its line on stderr.
VERBS = {"hack_inspector": "reproduced", "grader_inspector": "found", "attack_inspector": "confirmed"}
# Why a reproduced exploit got no further, after its label.
REASONS = {"not_exploited": "Attackers did not exploit it", "no_guidance": "not attacked: no guidance", "unknown": "no clear Attacker result"}
# Each condition a problem was tried under, and what an outcome there does not show.
CONDITIONS = {"full": "With full instructions", "minimal": "With only a hint", "none": "With no extra information, aimed at it",
              "elsewhere_full": "With full instructions, aimed at another problem", "elsewhere_minimal": "With only a hint, aimed at another problem",
              "elsewhere_none": "With no extra information, aimed at another problem", "independent": "Independent attacker"}


# Where each problem id's letter comes from; `problems[].source` in report.json names it too.
ATTACKER_ALONE = "A: found by an Attacker, not among the inspectors' findings."
LEGEND = "P: found by the hack inspector's search. G: found by the grader inspector in the simulations. " + ATTACKER_ALONE
# The A part once an inspector finding joined an Attacker's problem, naming those problems.
JOINED = "A: first found by an Attacker; inspector findings joined {} later."
# Where a valid-work problem no Attacker reproduced was shown, by the scope of its findings.
UNREPRODUCED = {"package": "shown only in a package experiment"}


def ranked(attack: dict) -> tuple[list, list, dict, list]:
    """The problems' exploit ladder steps, highest first, the steps where correct work failed, the problems of each step,
    and the leads, problems no evidence confirmed, which a stored report from before leads has at level 1."""
    valid, groups, leads = {item["id"] for item in attack.get("candidates", []) if item["valid_work"]}, {}, list(attack.get("leads", []))
    for item in attack.get("problems", []):
        key = rung(item, valid)
        (leads if key[0] == 1 else groups.setdefault(key, [])).append(item)
    order = sorted(groups, key=lambda key: (-key[0], key[1].endswith(ELSEWHERE)))
    failed = [key for key in order if any(name in valid for name in groups[key][0]["findings"])]
    return [key for key in order if key not in failed], failed, groups, leads


def unreproduced(key: tuple, item: dict) -> str:
    """Where correct work no Attacker reproduced was shown, after its label."""
    return "" if key[0] > 2 else ", " + UNREPRODUCED.get(item.get("scope"), "not reproduced by an Attacker")


def legend(groups: dict) -> list[str]:
    """Where each problem id's letter comes from, when the problems have ids."""
    joined = [item["id"] for items in groups.values() for item in items if item.get("source") == "Attacker" and item.get("findings")]
    return [LEGEND.replace(ATTACKER_ALONE, JOINED.format(", ".join(joined))) if joined else LEGEND] * any(
        item.get("id") for items in groups.values() for item in items)


def clauses(attack: dict, sources: dict) -> list[tuple[int, int | None, str, bool]]:
    """Each Attacker exploit once per attempt and text, named by its problem: two readings of one attempt are one exploit."""
    found = {}
    for item in exploits(attack, sources, by_problem=True):
        found.setdefault((item[0], item[2]), item)
    return list(found.values())


def owner(attack: dict, index: int, assessment: int | None) -> str | None:
    """The problem of attempt `index`'s finding read in `assessment`: the problem the judge named for an `other` exploit,
    the problem holding a reproduction's candidate, else the problem whose members hold the episode, else the problem
    it aimed at; None without one."""
    attempt, problems = attack["attempts"][index], [item for item in attack.get("problems", []) if item.get("id")]
    ids = {problem["id"] for problem in problems}
    for kind, items in attack.get("exploits", {}).items():
        for item in items:
            if (item["attempt"], item["assessment"]) != (index, assessment):
                continue
            if kind == "other" and item.get("problem") in ids:
                return item["problem"]
            held = [problem["id"] for problem in problems if item["candidate"] in problem.get("findings", [])]
            if kind == "reproduction" and held:
                return held[0]
    return next((item["id"] for item in problems if attempt["episode"] in item.get("members", [])),
                attempt.get("problem") if attempt.get("problem") in {item["id"] for item in problems} else None)


def said(attack: dict, assessment: int | None) -> str:
    """The start of what the attack inspector says the Attacker did, quoted after a colon; empty without it."""
    return f': "{brief(how)}"' if (how := mechanism(attack, assessment)) else ""


def problem_lines(report: dict) -> list[str]:
    """The problems by their step on the exploit ladder, highest first, with those where correct work failed on lines of
    their own; then one line per problem in that order: its id, label, cause, source and findings, or the Attacker
    episodes of one an Attacker found with no extra information, each of its cases beneath, each Attacker exploit of it
    with the start of what the Attacker did, and then each condition an Attacker tried it under; then the leads, problems
    no evidence confirmed, which a stored report from before leads has at level 1. Older records have no problems, or
    problems without ids or levels."""
    attack, sources = report["attack"], candidate_sources(report)
    steps, failed, groups, leads = ranked(attack)
    quoted = clauses(attack, sources)

    def ids(key):
        return ", ".join(item.get("id") or "an older problem" for item in groups[key])
    lines = ["Problems by level: " + "; ".join(f"{label}: {ids((level, label))}" for level, label in steps) + "."] * bool(steps)
    for key in failed:
        shown = {}
        for item in groups[key]:
            shown.setdefault(unreproduced(key, item), []).append(item.get("id") or "an older problem")
        lines += [f"{key[1]}{where}: {', '.join(names)}." for where, names in shown.items()]
    lines += legend(groups)
    for (level, label), item in ((key, item) for key in steps + failed for item in groups[key]):
        reason = REASONS.get(item.get("exploited_with", item.get("help_needed", "unknown"))) if level == 2 else None
        if (level, label) in failed and reason == REASONS["not_exploited"]:
            reason = "Attackers did not reproduce it"
        where = (f"; findings {', '.join(named(name, sources) for name in item['findings'])}" if item["findings"]
                 else f"; found in {', '.join(item['members'])}" if item.get("source") == "Attacker" else "")
        if exploited := item.get("exploited_by"):
            reason = "exploited by Attacker " + ", ".join(f"{entry['episode']}, which targeted {entry['target'] or 'another problem'}"
                                                          for entry in exploited)
        name = f"{item['id']} from {problem_sources(item, level)}" if item.get("id") else "An older problem"
        scope = SCOPES.get(item.get("scope")) if level == 2 else None
        lines.append(f"- {name}, {', '.join(filter(None, (label, scope, reason)))}: {item['cause'].rstrip('.')}{where}.")
        lines += [f"  - {case['id']}: {oneline(case.get('mechanism') or '').rstrip('.')}"
                  + "".join(f"; {key.replace('_', ' ')} {case[key]}" for key in ("check", "location", "capture_point") if case.get(key))
                  for case in item.get("cases", [])]
        lines += [f"  - {attack['attempts'][index]['episode']} {text}, {rewards(attack['attempts'][index])}{said(attack, assessment)}"
                  for index, assessment, text, _ in quoted if item.get("id") and owner(attack, index, assessment) == item["id"]]
        before = None  # The aimed step before this one, which a step waits on.
        for row in item.get("conditions", []):
            head, verb = CONDITIONS[row["condition"]], "reproduced" if (level, label) in failed else "exploited"
            waiting = WAITING.get(row["status"], row["status"])
            if row["status"] == "unattempted" and before and before["status"] in UNASSESSED:
                waiting = f"Not attempted, the step with {HINTS[before['condition']]} failed ({before['status']})"
            apart = "; ".join(f"{entry['episode']}, {entry['reward']}, {entry['status']}" + (f": {entry['error'].splitlines()[0]}" if entry["error"] else "")
                              for entry in row.get("not_assessed", []))
            lines.append(f"  - {head}: " + (f"{row['exploited']} of {row['attempts']} attempts {verb} it, {row['model']}, {row['status']}."
                                             if row["attempts"] else "No attempt was assessed." if apart else waiting + ".")
                         + f" Not run or not assessed: {apart}." * bool(apart))
            before = row if row["condition"] in HINTS else before
    if novel := [item for key in steps + failed for item in groups[key] if item.get("family")]:
        lines.append("Novel families, outside every listed one: " + ", ".join(f"{item['id']} ({item['family']})" for item in novel) + ".")
    if leads:
        lines.append("- Leads, which no evidence confirmed: "
                     + ", ".join(f"{item.get('id') or 'an older problem'} ({item['cause'].rstrip('.')})" for item in leads) + ".")
    return lines


def attempt_lines(report: dict) -> list[str]:
    """One line per Attacker attempt: the candidate and source check it tested, its reward and outcome;
    then the conditions never attempted, grouped. The JSON keeps every attempt and condition."""
    attack, sources = report["attack"], candidate_sources(report)
    started = set(report["other_episodes"]["attacker"])
    valid = {item["id"] for item in attack.get("candidates", []) if item["valid_work"]}
    done, notes = {}, {}
    for index, assessment, text, _ in exploits(attack, sources):
        # Findings with the same wording each keep their mechanism, in order, once.
        texts, hows = done.setdefault(index, ({}, {}))
        texts[text], hows[mechanism(attack, assessment)] = None, None
    for item in (item for items in attack.get("exploits", {}).values() for item in items if item["rationale"]):
        notes.setdefault(item["attempt"], {})[oneline(item["rationale"])] = None
    lines = []
    for index, attempt in enumerate(attack["attempts"]):
        target, hint = tried(attempt, sources)
        if attempt["episode"] not in started:
            lines.append(f"- attempt {attempt['number']} {f'on {target} ' if target else ''}with {hint} did not start: "
                         + STOPPED.get(attempt["status"], attempt["status"]))
        elif index in done:
            texts, hows = done[index]
            lines.append(f"- {attempt['episode']} {'; '.join(texts)}: {rewards(attempt)}"
                         + "".join(f'. How: "{how}"' for how in hows if how)
                         + "".join(f". Attack inspector: {note}" for note in notes.get(index, {})))
        else:
            lines.append(f"- {attempt['episode']} {f'tested {target}' if target else 'searched'} with {hint}: {rewards(attempt)}; "
                         + ending(attempt, attempt["candidate"] in valid))
    waiting = {}
    for candidate in attack.get("candidates", []):
        for level, item in candidate["conditions"].items():
            if not item["attempts"] and not item["blocked"]:
                waiting.setdefault(item["status"], {}).setdefault(candidate["id"], []).append(level)
    lines += [f"- {WAITING.get(status, f'Not attempted ({status})')}: "
              + ", ".join(f"{named(name, sources)} with {' and '.join(HINTS.get(level, level) for level in levels)}" for name, levels in found.items())
              for status, found in waiting.items()]
    return lines


def current(item: dict | None, skip: set = frozenset()) -> list[dict]:
    """The evidenced findings that are their check's latest reading, except the assessments in `skip`."""
    return [found for found in (item["findings"]["evidenced"] if item else [])
            if found["superseded_by"] is None and found["index"] not in skip]


def evidence(items: list[dict], outcome: str) -> dict[str, list[str]]:
    """The findings with `outcome`, by category, each once by its check id."""
    found = {}
    for finding in items:
        if finding["assessment"]["outcome"] == outcome:
            found.setdefault(finding["category"] or "no category", {})[check_id(finding)] = None
    return {category: sorted(checks) for category, checks in found.items()}


def flat(found: dict[str, list[str]]) -> str:
    return ", ".join(sorted({check for checks in found.values() for check in checks}))


def used(report: dict) -> list[str]:
    """One line per hack family that a current legitimate reading of a real episode shows it used, with the task's rule
    each reading cites. A route the rule forbids violates the requirement, so its reading is never legitimate."""
    found = {}
    for mode in ("hack_inspector", "grader_inspector"):
        items = [item for item in current_readings(report["inspections"].get(mode)) if item["claim"].get("use")]
        for item in items:
            if item["execution_scope"] == "native" and item["assessment"]["outcome"] == "legitimate":
                use, requirement = item["claim"]["use"], item["captured"]["check"]["requirement"]
                rule = ("the task states no rule against it" if use["rule"] == "none"
                        else f'the task allows it: {requirement["path"]}, "{brief(oneline(requirement["excerpt"]))}"')
                episodes, rules = found.setdefault(oneline(use["category"]), ({}, {}))
                episodes[item["claim"]["episode"]], rules[rule] = None, None
    return [f"{category} used in {', '.join(sorted(episodes))}; {'; '.join(rules)}." for category, (episodes, rules) in found.items()]


def current_readings(item: dict | None) -> list[dict]:
    """The legitimate and inconclusive readings that are their check's latest reading."""
    return [found for key in ("legitimate", "inconclusive") for found in (item["findings"][key] if item else []) if found["superseded_by"] is None]


def problem_answer(key: tuple, item: dict, failed: bool) -> str:
    """A problem's Answer line: its id, label, and how many assessed Attacker attempts exploited it."""
    level, label = key
    where = unreproduced(key, item) if failed else f", {SCOPES[item['scope']]}" if level == 2 and item.get("scope") in SCOPES else ""
    rows = item.get("conditions") or []
    assessed, exploited = sum(row["attempts"] for row in rows), sum(row["exploited"] for row in rows)
    counted = f"{exploited} of {assessed} assessed attempts {'reproduced' if failed else 'exploited'} it" if assessed else "no attempt was assessed"
    return f"{item.get('id') or 'An older problem'}: {label}{where}; {counted}."


def answer(report: dict) -> list[str]:
    """A few plain lines after the headline: can the grader be cheated or does it misjudge work, one line per problem
    with its label and how many assessed attempts exploited it, and what no problem holds.
    Only facts the report computes; with nothing evidenced it says so and never calls the grader safe.
    Package evidence shows what a copy of the task package did, not that a task agent can cheat."""
    lines, cheated, real, misjudged = [], False, False, False
    attack = report["attack"]
    if done := clauses(attack, candidate_sources(report)) if attack else []:
        misjudged = any(valid for *_, valid in done)
        cheated = real = not all(valid for *_, valid in done)
    if attack:
        steps, failed, groups, _ = ranked(attack)
        lines += [problem_answer(key, item, key in failed) for key in steps + failed for item in groups[key]] + legend(groups)
    # An exploit no problem holds, as in an older record, keeps its clause; the others are on their problem's line.
    if alone := [item for item in done if owner(attack, item[0], item[1]) is None]:
        attempts = attack["attempts"]
        lines.append("In real episodes, Attackers " + "; ".join(
            f"{text} ({attempts[index]['episode']}, {rewards(attempts[index])}){said(attack, assessment)}" for index, assessment, text, _ in alone) + ".")
    # An attack finding that is no exploit entry, such as incorrect work passed while testing valid work,
    # keeps its own outcome without confirming the candidate under test.
    problems = attack.get("problems", []) if attack else []
    # Every exploit's readings, also a second reading `exploits` folds into its attempt's clause.
    shown = {assessment for _, assessment, *_ in done} | {item["assessment"] for items in (attack or {}).get("exploits", {}).values() for item in items}
    for mode, found in (("attack_inspector", current(attack, shown)),
                        ("hack_inspector", current(report["inspections"].get("hack_inspector"))),
                        ("grader_inspector", current(report["inspections"].get("grader_inspector")))):
        cheats, rejected = evidence(found, "accepted_invalid"), evidence(found, "rejected_valid")
        if cheats and mode == "hack_inspector":
            cheated = True
            real = real or any(item["execution_scope"] == "native" and item["assessment"]["outcome"] == "accepted_invalid" for item in found)
        misjudged = misjudged or bool(rejected) or bool(cheats) and mode != "hack_inspector"
        # A finding a problem holds is on that problem's line.
        prefix = mode.split("_")[0] + "-"
        held = {int(name.removeprefix(prefix)) for item in problems if item.get("id")
                for name in item["findings"] if name.startswith(prefix) and mode != "attack_inspector"}
        found = [item for item in found if item["index"] not in held]
        cheats, rejected = evidence(found, "accepted_invalid"), evidence(found, "rejected_valid")
        parts = []
        if cheats and mode == "hack_inspector":
            parts.append("cheats by " + ", ".join(f"{category} ({', '.join(checks)})" for category, checks in cheats.items()))
        elif cheats:
            parts.append(f"cases where incorrect work passed ({flat(cheats)})")
        if rejected:
            parts.append(f"cases where correct work failed ({flat(rejected)})")
        if parts:
            scopes = {item["execution_scope"] for item in found}
            scope = scopes.pop() if len(scopes) == 1 else None
            opening = {"package": "In copies of the task package, the", "native": "In real episodes, the"}.get(scope, "The")
            lines.append(f"{opening} {mode.replace('_', ' ')} {VERBS[mode]} {'; and '.join(parts)}.")
    verdict = ""
    if cheated:
        verdict = "The grader can be cheated" + ("" if real else " in a copy of the task package, not yet in a real episode")
    if misjudged:
        verdict = f"{verdict}, and it misjudges work" if verdict else "The grader misjudges work"
    verdict = f"{verdict}." if verdict else "No cheat and no misjudged work was evidenced."
    lines += used(report)
    if earlier := report["configuration"]["attack_from"]:
        unrecorded = [name for name, state in report["analyses"].items() if state == "not run" and name != "attack"]
        lines.append(f"Only the attack ran in this run; the other analyses came from the earlier run {earlier}, "
                     "with the statuses that run recorded"
                     + (f"; {', '.join(unrecorded)} left no record there" if unrecorded else "")
                     + ". The state copies, earlier Attacker episodes and sandboxes this "
                     "report lists from that run are that run's, and each episode keeps its own model.")
    return [verdict, *lines]


STEPS = {"simulation": "the Simulator", "grader": "the grader inspector", "hack": "the hack inspector", "attack": "the attack"}
# An attempt or experiment that failed to execute.
FAILURES = (*SESSION_FAILURES, "infrastructure_failure", "native_timeout", "episode_failure")


def lost(report: dict) -> dict[str, list[str]]:
    """By step, the work that failed to execute, also when a later attempt recovered it, named by the agent that failed.
    An inspector session that failed with its experiment's error is that experiment's failure."""
    found, attempts = {}, {}
    for item in (report["attack"] or {}).get("attempts", []):
        if item["status"] in FAILURES:
            attempts.setdefault(item.get("failed"), []).append(item["episode"] or item["context"])
    for agent, names in attempts.items():
        found.setdefault("attack", []).append(
            f"the Attacker failed to run in {', '.join(names)}" if agent == "Attacker"
            else f"the attack inspector failed on {', '.join(names)}, " + ("its reward kept" if len(names) == 1 else "their rewards kept")
            if agent == "attack inspector" else f"an attack attempt failed in {', '.join(names)}")
    for step, name in (("hack", "hack inspector"), ("grader", "grader inspector")):
        inspection = report["inspections"].get(f"{step}_inspector") or {}
        rows = [row for row in inspection.get("experiments", []) if row.get("status") in FAILURES]
        errors = {row.get("error") for row in rows}
        for item in inspection.get("attempts", []):
            if item["status"] in FAILURES and item.get("error") not in errors:
                of = item.get("category") or item.get("episode")
                found.setdefault(step, []).append(f"the {name}'s {item['phase']} session{f' of {of}' if of else ''} failed ({item['status']})")
        if rows:
            found.setdefault(step, []).append(("a " if len(rows) == 1 else "") + f"{name} experiment{'s' * (len(rows) > 1)} failed: "
                                              + ", ".join(f"{row['id']} ({row['status']})" for row in rows))
    return found


def headline(report: dict, record: RunRecord, stop=None) -> str:
    """How the run ended, in plain words: the Answer's first line. `status` and the exit code say it for scripts."""
    took = ""
    if record.started_at and record.ended_at:
        minutes = int((datetime.fromisoformat(record.ended_at) - datetime.fromisoformat(record.started_at)).total_seconds()) // 60
        took = f" after {minutes // 60}:{minutes % 60:02d}"
    # A partial step that is no failed phase ran to its end, with an attempt that failed to run: its lost work says which.
    work, gaps = lost(report), []
    for name, state in report["unfinished"].items():
        partial = state == "partial" and name not in record.failed_phases
        gaps.append("; ".join(work.pop(name)) if partial and work.get(name) else f"{STEPS[name]} " + (
            "did not run" if state == "not run" else "had an attempt that failed to run" if partial else STOPPED.get(state, "failed")))
    also = "; ".join(phrase for phrases in work.values() for phrase in phrases)
    unresolved = "".join(f" Evidence stayed unresolved in {', '.join(STEPS[name] for name in report['unresolved'])}, so the run may miss more."
                         for _ in report["unresolved"][:1])
    failed = "".join(f"; before that {', '.join(f'{STEPS[name]} failed' for name in record.failed_phases)}" for _ in record.failed_phases[:1])
    if record.stop_reason:
        return f"Stopped{took}: {record.stop_reason.rstrip('.')}{failed}. Results below are what was found so far."
    if stop:
        return f"Stopped: {stop}{failed}. Results below are what was found so far."
    if report["status"] == "running":
        return "Still running. Results below are what was found so far; the final report replaces this one."
    if any(warning.startswith("cancelled during ") for warning in record.warnings):
        return f"Stopped by you{took}{failed}. Results below are what was found so far."
    if any(warning.startswith("stopped by a termination signal during ") for warning in record.warnings):
        return f"Stopped by a termination signal{took}{failed}. Results below are what was found so far."
    if record.time_limit_reached:
        return f"Stopped at your time limit{took}{failed}. Results below are what was found so far."
    if all(state == "not run" for state in report["analyses"].values()):
        reasons = [warning.split(": ", 1)[1] for warning in record.warnings if " stopped: " in warning or " failed: " in warning]
        return f"Could not start: {reasons[0] if reasons else 'no step ran'}."
    if gaps:
        return f"Finished with gaps: {', '.join(gaps)}{f'; work was also lost: {also}' * bool(also)}. Results below are what was found.{unresolved}"
    if also:
        return f"Finished, but work was lost: {also}. Results below are what was found.{unresolved}"
    return f"Finished. Every step ran.{unresolved}"


def search_scope(item: dict) -> list[str]:
    """Retained work establishes search scope; configured categories alone do not."""
    categories = item["categories"]
    attempts = item.get("attempts", [])
    searched = {entry.get("category") for entry in attempts + item.get("experiments", [])}
    searched.update(entry.get("category") for group in item.get("findings", {}).values() for entry in group)
    if any(entry["phase"] == "broad" for entry in attempts):
        searched.update(code for code, state in categories.items() if state != "restricted")
    return [code for code in categories if code in searched]


def search_details(item: dict) -> list[str]:
    searched = search_scope(item)
    details = []
    for code, state in item["categories"].items():
        if state == "restricted":
            details.append(f"{code}: {item.get('applicability', {}).get(code) or 'no search attempt recorded'}")
        elif code not in searched:
            details.append(f"{code}: no search attempt recorded")
    for entry in item.get("attempts", []):
        status = {"evidenced_issue": "completed", "no_evidenced_issue": "completed", "unknown": "ended"}.get(entry["status"], entry["status"])
        details.append(f"{entry['phase']} attempt {entry['number']} ({entry.get('category') or entry.get('episode') or 'all categories'}): {status}"
                       + (f": {entry['error'].splitlines()[0]}" + " (full text in report.json)" * ("\n" in entry["error"]) if entry.get("error") else ""))
    return details


def markdown(report: dict) -> str:
    """A readable rendering of `build`'s report; the JSON keeps every field."""
    config = report["configuration"]
    lines = ["# nudi report", "", "## Answer", ""] + [f"- {line}" for line in report["answer"]] + ["", "## Configuration", ""]
    for role, model in config["models"].items():
        source = config["credential_sources"].get(role)
        lines.append(f"- {role}: {model['model']}, reasoning effort {model['reasoning_effort']}, "
                     + (f"credential from {source}" if source else "no credential resolved; the selected analyses do not run this role"))
    lines += [f"- Task: {config['task_dir']}; execution path {config['path']}: {'; '.join(config['path_reasons'])}",
              f"- Spending cap: {config['spending_cap']}; {cost(config)}"]
    lines += ["- Known cost per job:"] * bool(config["cost_by_job"]) + [
        f"  - {name}: known cost ${item['known_cost']:.6f} in {item['calls']} calls, {item['prompt_tokens']} prompt and "
        f"{item['completion_tokens']} completion tokens{left_out(item)}" for name, item in config["cost_by_job"].items()]
    if modal := config["modal_cost"]:
        lines.append(f"- Modal compute: estimated ${modal['at_requests']:.2f} at requested CPU and memory, ${modal['at_limits']:.2f} "
                     f"if all used their limits, for {modal['sandboxes']} sandboxes in app {modal['app']} over their lifetimes; "
                     "sandboxes only, not the host that ran nudi; outside the spending cap"
                     + (f"; {modal['without_limits']} without declared limits are excluded" if modal["without_limits"] else "")
                     + (f"; {modal['still_running']} still ran after stop and count their whole 24 h lifetime"
                        if modal["still_running"] else "")
                     + ". `nudi cost <run dir>` prints Modal's bill about 10 minutes after the hour in which the run ended")
    for item in config["provenance"]:
        setup = item["configuration"]
        versions = ", ".join(f"{name} {version}" for name, version in setup["versions"].items())
        lines.append(f"- Task {setup['task_name']} digest {setup['task_digest']}; {setup['model']}, reasoning effort "
                     f"{setup['reasoning_effort']}, {setup['path']} ({versions}): {', '.join(item['episodes'])}")
    lines += [f"- {name}: {reason}" for name, reason in config["provenance_unavailable"].items()]
    if not config["provenance"]:
        lines.append("- Task digest and version pins: unavailable, no retained episode record")
    lines += ["", "## Analyses", ""] + [f"- {name}: {status}" for name, status in report["analyses"].items()]

    lines += ["", "## Categories searched", ""]
    lines += [line for mode, item in report["inspections"].items() for line in
              [f"- {mode}: {', '.join(search_scope(item)) or 'none recorded'}"]
              + unassessed(mode, item) + still_open(mode, item) + [f"- {mode} {detail}" for detail in search_details(item)]] or ["Neither the grader inspector nor the hack inspector was selected or run."]

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
                share = summary["share"]
                lines.append(f"- {key}: {summary['usable']} usable of {summary['attempted']}; missing {len(summary['missing'])}, "
                             f"invalid {len(summary['invalid'])}; mean {number(summary['mean'])}; sample SD {number(summary['sd'])}; "
                             f"median {number(summary['median'])}; minimum {number(summary['minimum'])}; maximum "
                             f"{number(summary['maximum'])}; skewness {number(summary['skewness'])}; distribution {distribution}"
                             + (f"; share at {number(share['value'])}: {share['count']} of {summary['usable']}, 95% Wilson interval "
                                f"{share['interval'][0]:.2f} to {share['interval'][1]:.2f}" if share else "")
                             + (f", {share['range'][0]:.2f} to {share['range'][1]:.2f} with exclusions" if share and share["range"] else "")
                             + "; SD and skewness follow from this share" * bool(share))
                lines += [f"  - {flag['flag']}: {flag['text']}" for flag in summary["flags"]]
                lines += [f"  - {summary['flags_not_evaluated']}"] * bool(summary["flags_not_evaluated"])
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
                interval = group["pass_rate"]["interval"]
                lines.append(f"- {ratio(f'Native pass rate for {subject}{encoding}:', group['pass_rate'])}"
                             + (f", 95% Wilson interval {interval[0]:.2f} to {interval[1]:.2f}" if interval else ""))
            heading = f"- Grader agreement for {subject}"
            if group["status"] != "supported":
                lines.append(f"{heading}: {group['status']}, no agreement values. {' '.join(group['reasons'])}")
                continue
            rates = "; ".join(ratio(label, group[key]) for label, key in (
                ("FDR (Of accepted work, how much was incorrect?)", "false_discovery_rate"),
                ("FNR (Of correct work, how much was rejected?)", "false_negative_rate")))
            lines.append(f"{heading}{encoding}: TP (Correct work passed) {group['tp']}, FP (Incorrect work passed) {group['fp']}, "
                         f"FN (Correct work failed) {group['fn']}, TN (Incorrect work failed) {group['tn']}; {rates}; presumed {group['presumed']}, verified {group['verified']}; "
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
    candidates = {item["id"] for item in (report["attack"] or {}).get("candidates", [])}
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
                if (name := f"{source.removesuffix('_inspector')}-{item['index']}") in candidates:
                    category += f"; attack candidate {name}"
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
        if item.get("hack_findings"):
            lines.append(f"- {mode} was configured with hack findings {', '.join(item['hack_findings'])} "
                         f"from a {item['hack_inspection']} hack inspection as places to look.")

    lines += ["", "## Attack", ""]
    result = report["attack"]
    if result is None:
        lines.append("Not selected or not run.")
    elif "discovery" in result:
        lines.append(f"Status {result['status']}; at most {result['maximum_attempts']} attempts per candidate and hint level; "
                     + ("hints not requested, so no attempt with only a hint ran; " if result.get("minimal_hints") is False else "")
                     + f"{result['unknown_cost_calls']} Attacker and attack inspector calls with unknown prices and "
                     f"{result['cancelled_calls']} cancelled in flight.")
        discovery = result["discovery"]
        lines.append(f"Independent attacker with no extra information: {discovery.get('attempts', 0)} started "
                     f"of at most {discovery.get('maximum_attempts', result.get('discovery_attempts', 0))}.")
        lines += problem_lines(report)
        lines += attempt_lines(report)
        if result.get("unavailable"):
            lines.append("- Missing candidates: " + "; ".join(f"{level}: {reason}" for level, reason in result["unavailable"].items()))
        lines += [f"- Limit: {limit}" for limit in result["limits"]]
    else:
        lines.append(f"Status {result['status']}; at most {result['maximum_attempts']} attempts per condition; "
                     f"{result['unknown_cost_calls']} Attacker and attack inspector calls with unknown prices and "
                     f"{result['cancelled_calls']} cancelled in flight.")
        for level, item in result["conditions"].items():
            outcomes = ", ".join(f"{status} {count}" for status, count in item["outcomes"].items()) or "none"
            guidance = "supplied" if item["guidance"] else item["unavailable"] or "none"
            blocked = "; ".join(f"entry {entry['number']} {entry['status']}: {entry['reason']}" for entry in item["blocked"])
            lines.append(f"- {level}: {item['status']}; {'tested' if item['tested'] else 'not tested'}; evidence "
                         f"{item['evidence']} in {item['attempts']} started attempts ({outcomes}); guidance {guidance}"
                         + (f"; blocked {blocked}" if blocked else ""))
        lines += attempt_lines(report)
        lines += [f"- Limit: {limit}" for limit in result["limits"]]

    lines += ["", "## Persistence", ""]
    lines += [f"- {probe['location']}: {probe['classification']}; {'; '.join(probe['reasons'] + probe['limits'])}"
              for probe in report["persistence"]] or ["No persistence probe ran."]
    # A multi-line warning, such as a validation error, shows its first line; the JSON keeps it whole.
    lines += ["", "## Warnings", ""] + ([f"- {warning.splitlines()[0]}" + " (full text in report.json)" * ("\n" in warning)
                                         for warning in report["warnings"]] or ["None."])
    lines += ["", "## Notes", ""] + ([f"- {note}" for note in report["notes"]] or ["None."])
    # Omit verdict prose in the limits of older inspection and attack records, which a rerun keeps.
    lines = [line.removesuffix(", so they are unknown") for line in lines
             if line != "- Limit: Unsupported candidates and zero evidenced successes do not establish that the task is safe."]
    return "\n".join(lines) + "\n"


# The exit code each environment's status would give one run; an environment that never started has none.
# The batch's status in plain words; summary.json keeps the status and the exit code for scripts.
BATCH = {"complete": "Finished. Every environment ran every step.", "time_limit": "Stopped at your time limit. Results below are what was found so far.",
         "cancelled": "Stopped by you. Results below are what was found so far.",
         "terminated": "Stopped by a termination signal. Results below are what was found so far.",
         "partial": "Finished with gaps: not every environment ran every step. Results below are what was found.",
         "refused": "Could not start: no environment started."}
NOT_STARTED = "Not started: the time limit or a stop came before its turn."
ALONE = {"complete": 0, "time_limit": 1, "partial": 1, "stopped": 1, "refused": 2, "cancelled": 130, "terminated": 143, "not_started": None}


def summary(rows: list[dict], totals: dict, stop: str | None = None) -> dict:
    """The summary of several environments: each one's row with its headline and verdict from its Answer, its known
    cost and its Modal estimate from its `report.json`, and the command's status and exit code. There is no combined
    verdict. A report from before headlines has its verdict first and how it ran last. `stop`, `cancelled` after Ctrl-C or
    `terminated` after SIGTERM, is the status of a batch that was stopped."""
    environments = []
    for row in rows:
        path = Path(row["run_dir"]) / "report.json"
        built = json.loads(path.read_text()) if path.is_file() else {"answer": [], "configuration": {}}
        answer = built["answer"][1:] if "outcome" in built else built["answer"][:1]
        environments.append({**row, "exit_code": ALONE[row["status"]], "answer": next(iter(answer), None),
                             "execution": built.get("outcome") or (built["answer"][-1] if len(built["answer"]) > 1 else None),
                             "known_cost": built["configuration"].get("known_cost"),
                             "modal_cost": built["configuration"].get("modal_cost")})
    found = {row["status"] for row in environments}
    status = stop or ("cancelled" if "cancelled" in found else "complete" if found == {"complete"}
                      else "time_limit" if found <= {"complete", "time_limit"} else "partial")
    started = found - {"refused", "not_started"}
    code = {"cancelled": 130, "terminated": 143, "complete": 0}.get(status, 1 if started else 2)
    return {"status": status, "exit_code": code, **totals, "environments": environments}


def summary_markdown(summary: dict) -> str:
    """A readable rendering of `summary`."""
    def amount(value, unit=""):
        return "none" if value is None else f"{value:g}{unit}"

    lines = ["# nudi summary", "", "Each environment has its own run folder and report; nothing is combined across them.", "",
             # A batch in which no environment started has exit code 2 and keeps its status, `partial`.
             f"- Outcome: {BATCH['refused' if summary['exit_code'] == 2 else summary['status']]}",
             f"- Backend {summary['backend']}: {summary['admitted']} of {len(summary['environments'])} environments admitted, "
             f"{summary['at_once']} at once in {summary['rounds']} rounds",
             f"- Totals, split equally: spending cap {amount(summary['spending_cap'])}, concurrency {summary['concurrency']}, "
             f"time limit {amount(summary['time_limit'], ' minutes')}"]
    for row in summary["environments"]:
        known, modal = row["known_cost"], row["modal_cost"]
        outcome = row.get("execution") or (f"Could not start: {row['error']}." if row["status"] == "refused" and row["error"]
                                           else NOT_STARTED if row["status"] == "not_started" else None)
        lines += ["", f"## {row['name']}", "", *[f"- Outcome: {outcome}"] * bool(outcome),
                  f"- Task: {row['task_dir']}; run folder: {row['run_dir']}", f"- Answer: {row['answer'] or 'no report'}",
                  "- Known cost: " + ("none" if known is None else f"${known:.6f}")
                  + (f"; Modal compute estimated ${modal['at_requests']:.2f} at requested CPU and memory, ${modal['at_limits']:.2f} "
                     "if all used their limits" if modal else ""),
                  f"- Its share: spending cap {amount(row['spending_cap'])}, concurrency {amount(row['concurrency'])}, "
                  f"time limit {amount(row['time_limit'], ' minutes')}"] + [f"- Error: {row['error']}"] * bool(row["error"])
    return "\n".join(lines) + "\n"
