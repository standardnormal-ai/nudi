"""Test-only taskset: one local Harbor task directory, parsed in place.

Verifiers resolves `--env.taskset.id local_harbor` to this module. The upstream
HarborTaskset only loads downloaded datasets from its global cache.
"""

from collections.abc import Iterator
from pathlib import Path

from verifiers.v1.taskset import Taskset
from verifiers.v1.tasksets.harbor import HarborEnv
from verifiers.v1.tasksets.harbor.taskset import (
    HarborConfig,
    HarborTask,
    HarborTaskset,
    parse_task,
)


class LocalHarborConfig(HarborConfig):
    task_dir: Path


class LocalHarborTaskset(HarborTaskset, Taskset[HarborTask, LocalHarborConfig]):
    def load(self) -> Iterator[HarborTask]:
        yield HarborTask(parse_task(self.config.task_dir, 0, self.config), self.config.task)


__all__ = ["HarborEnv", "LocalHarborTaskset"]
