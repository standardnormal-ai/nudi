"""The public workflow. `send_nudis`, `send_nudis_async` and `nudi send-nudis` share this
one implementation over the existing analyses.

Full analysis selects simulation, the grader inspector, the hack inspector and the attack;
`simulation` and `hacking` select two of them. A failed analysis is recorded and the
independent ones still run, unless a task environment cannot start: then none runs after it.
The report covers the selected analyses only, and resolved credentials never reach it.
"""

import asyncio
import time
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field

from nudi import copies, report
from nudi.checks import (FULL_UNAVAILABLE, MINIMAL_UNAVAILABLE, Candidate, InspectionResult, attack, evidenced, finish_cleanup,
                         inspect_grader, inspect_hacks, redacted)
from nudi.records import DiskFull, EnvironmentUnavailable, RunConfig
from nudi.workflow import elapsed, logger, simulate, start_run

Analysis = Literal["full", "simulation", "hacking"]
# The hack chain first: it needs no Simulator or grader inspector result, and its finding comes hours earlier.
SELECTED = {"full": ("hack", "attack", "simulation", "grader"), "simulation": ("simulation", "grader"),
            "hacking": ("hack", "attack")}
# Each step's name on stderr and what it produced.
PHASES = {
    "simulation": ("Simulator", lambda result: f"{len(result.episodes)} of {result.requested} episodes"),
    "grader": ("grader inspector", lambda result: f"{len(result.experiments)} experiments, {len(result.assessments)} assessments"),
    "hack": ("hack inspector", lambda result: f"{len(result.experiments)} experiments, {len(result.assessments)} assessments"),
    "attack": ("attack", lambda result: f"{len(result.attempts)} Attacker attempts, {len(result.findings)} findings"),
}
ROLES = {"full": frozenset({"simulator", "inspector", "attacker"}), "simulation": frozenset({"simulator", "inspector"}),
         "hacking": frozenset({"inspector", "attacker"})}


class AnalysisConfig(RunConfig):
    """A run's configuration with the selected analysis and its counts. Unknown keys are errors."""

    model_config = ConfigDict(extra="forbid")
    analysis: Analysis = "full"
    episodes: int = Field(20, ge=1, strict=True)
    """Ordinary Simulator episodes."""
    focused_attempts: int = Field(2, ge=0, strict=True)
    """Total focused attempts of the grader inspector and the hack inspector for each category after broad inspection."""
    isolated_inspections: bool = Field(False, strict=True)
    """Grader inspector: off, `holistic_inspection`, presumes labels for episodes it names normal;
    on, `inspector_swarm`, verifies each ordinary episode in its own grader inspector forked from broad."""
    attacker_tries: int = Field(2, ge=0, strict=True)
    """Maximum Attacker attempts for each candidate and hint level."""
    discovery_attempts: int = Field(1, ge=0, strict=True)
    """Total no-hint discovery attempts for the environment. The default is one, with no extra retry."""


def configure(task_dir, config, options: dict) -> AnalysisConfig:
    """The TOML file's fields, replaced by `options`. Relative paths in the file are
    relative to the file."""
    values = {}
    if config is not None:
        config = Path(config)
        values = tomllib.loads(config.read_text())
        for key in ("output_dir", "credentials_file"):
            if isinstance(values.get(key), str):
                values[key] = config.parent / values[key]
    return AnalysisConfig.model_validate({**values, **options, "task_dir": task_dir})


WHERE_TO_LOOK = (
    "Where to look: examine the named file, interface, or component. "
    "This hint excludes the solution and the reproduction recipe."
)


def _supplied(value: str | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def guidance(hack: InspectionResult | None) -> dict:
    """One candidate per evidenced or suspected hack finding, composed without a model call.

    Only the latest reading of a check is a candidate: any later reading of that check, legitimate
    or unguided included, withdraws it, and the inspection report keeps it as superseded. A claim
    without a check is never superseded. An evidenced reading, accepted invalid or rejected valid,
    is a candidate. A suspected one, an unknown reading that supplies a guidance field, follows
    every evidenced candidate and keeps its `unknown` outcome: a candidate is a suspected mismatch,
    and a missing scoring input must not hide a measured flaw. A legitimate, unavailable or
    ungrounded reading supplies nothing, also with guidance. A rejected valid finding, work meeting every
    stated requirement that got less than deserved, is a valid-work candidate. Full guidance is
    that candidate's `full_guidance`. Minimal guidance is the fixed where-to-look line plus that
    candidate's `hint_location`. Mechanism and interpretation are never copied. A missing or blank
    field is unavailable for that candidate only. Each candidate keeps its check and the category
    of the experiment that measured it. Identical text stays distinct here. Attack shares one
    native run only for records of the same kind and category with the same exact mechanism and
    the same full and minimal guidance.
    """
    candidates = []
    assessments = hack.assessments if hack else []
    category = {item["check"]: item.get("category") for item in (hack.experiments if hack else []) if item.get("check")}
    latest = {item.claim.check: index for index, item in enumerate(assessments) if item.claim.check}
    for index, item in enumerate(assessments):
        full, location = _supplied(item.claim.full_guidance), _supplied(item.claim.hint_location)
        guided = full is not None or location is not None
        if latest.get(item.claim.check, index) != index or not (evidenced(item) or item.outcome == "unknown" and guided):
            continue
        unavailable = {}
        if full is None:
            unavailable["full"] = FULL_UNAVAILABLE
        if location is None:
            unavailable["minimal"] = MINIMAL_UNAVAILABLE
        candidates.append(Candidate(
            id=f"hack-{index}", mechanism=item.claim.mechanism, check=item.claim.check, category=category.get(item.claim.check),
            outcome=item.outcome, guidance={"full": full, "minimal": None if location is None else WHERE_TO_LOOK + "\n" + location},
            unavailable=unavailable, valid_work=item.outcome == "rejected_valid",
        ))
    # A stable sort keeps record order within the evidenced and the suspected candidates.
    candidates.sort(key=lambda item: item.outcome == "unknown")
    return {"candidates": candidates}


async def send_nudis_async(task_dir, config=None, **options) -> dict:
    """Run the selected analyses of the Harbor task at `task_dir` and return its report.

    `config` is an optional TOML file of `AnalysisConfig` fields, with models under
    `[models.<role>]`; keyword options replace the file's values. Configuration and the
    selected roles' credentials are validated before any episode starts, and the output
    directory must be new or empty. The report is
    also written as `report.json` and `report.md` in the output directory, after
    cancellation too. With `time_limit` the run stops at that many minutes as a cancelled
    run does, and returns its report with status `time_limit`, or `partial` when a phase
    failed before. Every state copy of the run is deleted first, also after a failure."""
    settings = configure(task_dir, config, options)
    # Earlier records there would otherwise be reported as this run's results.
    if settings.output_dir.exists() and any(settings.output_dir.iterdir()):
        raise ValueError(f"output directory {settings.output_dir} is not empty; choose a new or empty directory")
    selected = SELECTED[settings.analysis]
    run = start_run(settings, ROLES[settings.analysis])
    results = {}
    steps = {
        "simulation": lambda: simulate(run, settings.episodes),
        "grader": lambda: inspect_grader(run, run.record.simulation.episodes if run.record.simulation else [],
                                         focused_attempts=settings.focused_attempts,
                                         isolated_inspections=settings.isolated_inspections),
        "hack": lambda: inspect_hacks(run, focused_attempts=settings.focused_attempts),
        "attack": lambda: attack(run, maximum_attempts=settings.attacker_tries,
                                 discovery_attempts=settings.discovery_attempts, **guidance(results.get("hack"))),
    }
    try:
        # The time limit cancels the run as Ctrl-C does, so it stops and cleans up the same way.
        async with asyncio.timeout(settings.time_limit and settings.time_limit * 60) as limit:
            for name in selected:
                phase, produced = PHASES[name]
                started = time.monotonic()
                logger.info(f"{phase} started")
                try:
                    results[name] = await steps[name]()
                    logger.info(f"{phase} finished after {elapsed(started)}: {produced(results[name])}; status {results[name].status}")
                    if results[name].status != "complete":
                        run.record.failed_phases.append(name)
                # asyncio raises a second Ctrl-C as KeyboardInterrupt, past a CancelledError handler.
                except (asyncio.CancelledError, KeyboardInterrupt):
                    if limit.expired():
                        stopped = f"the run stopped at its time limit of {settings.time_limit:g} minutes during {name}"
                        run.record.warnings.append(stopped)
                        logger.info(stopped)
                    else:
                        # Recorded without a stderr line: the command prints one cancellation message.
                        run.record.warnings.append(f"cancelled during {name}")
                    raise
                except DiskFull as error:
                    run.record.warnings.append(f"{name} stopped: {error}")
                    run.record.failed_phases.append(name)
                    raise
                except EnvironmentUnavailable as error:
                    reason = redacted(run, str(error))
                    run.record.warnings.append(f"{name} stopped: {reason}")
                    run.record.failed_phases.append(name)
                    logger.warning(f"{phase} stopped after {elapsed(started)}: {reason}")
                    break
                except Exception as error:
                    failure = f"{name} failed: {type(error).__name__}: {redacted(run, str(error))}"
                    run.record.warnings.append(failure)
                    run.record.failed_phases.append(name)
                    logger.warning(f"{phase} ended after {elapsed(started)}: {failure}")
        # A phase that caught the limit's cancellation and returned ends the block normally.
        run.record.time_limit_reached = limit.expired()
    except TimeoutError:
        # Only the time limit raises it here: each phase's own errors are caught above.
        run.record.time_limit_reached = True
    finally:
        try:
            await finish_cleanup(asyncio.create_task(copies.delete(run)))
        finally:
            try:
                run.save()
            finally:
                # Tried also when the save found no space: the smaller report may still fit.
                report.write(settings.output_dir, run.keys.values(), selected)
    return report.build(settings.output_dir, run.keys.values(), selected)


def send_nudis(task_dir, config=None, **options) -> dict:
    """`send_nudis_async`, run to completion."""
    return asyncio.run(send_nudis_async(task_dir, config, **options))
