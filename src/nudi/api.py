"""The public workflow. `send_nudis`, `send_nudis_async` and `nudi send-nudis` share this
one implementation over the existing analyses.

Full analysis selects simulation, grader inspection, hack inspection and the attack;
`simulation` and `hacking` select two of them. A failed analysis is recorded and the
independent ones still run. The report covers the selected analyses only, and resolved
credentials never reach it.
"""

import asyncio
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field

from nudi import report
from nudi.checks import FULL_UNAVAILABLE, MINIMAL_UNAVAILABLE, Candidate, InspectionResult, attack, inspect_grader, inspect_hacks, redacted
from nudi.records import RunConfig
from nudi.workflow import simulate, start_run

Analysis = Literal["full", "simulation", "hacking"]
SELECTED = {"full": ("simulation", "grader", "hack", "attack"), "simulation": ("simulation", "grader"),
            "hacking": ("hack", "attack")}
ROLES = {"full": frozenset({"simulator", "inspector", "attacker"}), "simulation": frozenset({"simulator", "inspector"}),
         "hacking": frozenset({"inspector", "attacker"})}


class AnalysisConfig(RunConfig):
    """A run's configuration with the selected analysis and its counts. Unknown keys are errors."""

    model_config = ConfigDict(extra="forbid")
    analysis: Analysis = "full"
    episodes: int = Field(20, ge=1, strict=True)
    """Ordinary Simulator episodes."""
    focused_attempts: int = Field(3, ge=0, strict=True)
    """Total focused Inspector attempts for each category after broad inspection."""
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
    """One candidate per hack finding that can guide reproduction, composed without a model call.

    Legitimate outcomes and rejected valid findings supply nothing. Full guidance is that
    candidate's `full_guidance`. Minimal guidance is the fixed where-to-look line plus
    that candidate's `hint_location`. Mechanism and interpretation are never copied.
    A missing or blank field is unavailable for that candidate only. Identical text stays
    distinct here. Attack shares one native run only for records with the same mechanism
    and the same full and minimal guidance. A shared hint string alone stays separate.
    """
    candidates = []
    for index, item in enumerate(hack.assessments if hack else []):
        if item.outcome in ("legitimate", "rejected_valid"):
            continue
        full, location = _supplied(item.claim.full_guidance), _supplied(item.claim.hint_location)
        unavailable = {}
        if full is None:
            unavailable["full"] = FULL_UNAVAILABLE
        if location is None:
            unavailable["minimal"] = MINIMAL_UNAVAILABLE
        candidates.append(Candidate(
            id=f"hack-{index}", mechanism=item.claim.mechanism,
            guidance={"full": full, "minimal": None if location is None else WHERE_TO_LOOK + "\n" + location},
            unavailable=unavailable,
        ))
    return {"candidates": candidates}


async def send_nudis_async(task_dir, config=None, **options) -> dict:
    """Run the selected analyses of the Harbor task at `task_dir` and return its report.

    `config` is an optional TOML file of `AnalysisConfig` fields, with models under
    `[models.<role>]`; keyword options replace the file's values. Configuration and the
    selected roles' credentials are validated before any episode starts, and the output
    directory must be new or empty. The report is
    also written as `report.json` and `report.md` in the output directory, after
    cancellation too."""
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
                                         focused_attempts=settings.focused_attempts),
        "hack": lambda: inspect_hacks(run, focused_attempts=settings.focused_attempts),
        "attack": lambda: attack(run, maximum_attempts=settings.attacker_tries,
                                 discovery_attempts=settings.discovery_attempts, **guidance(results.get("hack"))),
    }
    try:
        for name in selected:
            try:
                results[name] = await steps[name]()
            except asyncio.CancelledError:
                run.warn(f"cancelled during {name}")
                raise
            except Exception as error:
                run.warn(f"{name} failed: {type(error).__name__}: {redacted(run, str(error))}")
    finally:
        run.save()
        report.write(settings.output_dir, run.keys.values(), selected)
    return report.build(settings.output_dir, run.keys.values(), selected)


def send_nudis(task_dir, config=None, **options) -> dict:
    """`send_nudis_async`, run to completion."""
    return asyncio.run(send_nudis_async(task_dir, config, **options))
