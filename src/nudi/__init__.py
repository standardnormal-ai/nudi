"""nudi: run Harbor tasks and retain the episodes for inspection."""

import importlib

# Each export's module. They load on first use, so `import nudi.cli` stays fast and `nudi --help` returns at once.
# Verifiers loads the taskset id "nudi" from this package: it takes the Taskset and Env subclasses `__all__` names.
EXPORTS = {
    "AnalysisConfig": "nudi.send",
    "CapacityError": "nudi.run_state",
    "EpisodeConfig": "nudi.records",
    "EpisodeResult": "nudi.records",
    "LocalHarborTaskset": "nudi.episode",
    "ModelConfig": "nudi.records",
    "ObservedHarborEnv": "nudi.episode",
    "RunConfig": "nudi.records",
    "RunRecord": "nudi.records",
    "SpendingCapReached": "nudi.run_state",
    "UnsupportedTask": "nudi.episode",
    "run_episode": "nudi.episode",
    "run_role_episode": "nudi.run_state",
    "send_environments": "nudi.send",
    "send_environments_async": "nudi.send",
    "send_nudis": "nudi.send",
    "send_nudis_async": "nudi.send",
    "start_run": "nudi.run_state",
}
__all__ = list(EXPORTS)


def __getattr__(name: str):
    if name not in EXPORTS:
        raise AttributeError(f"module 'nudi' has no attribute {name!r}")
    return getattr(importlib.import_module(EXPORTS[name]), name)
