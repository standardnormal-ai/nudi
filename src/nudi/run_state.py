"""Shared run state: models and credentials for each role, the backend and its capacity,
and the optional spending cap, applied to every episode and model call of one run.

Episodes keep the original grading and harness, which selects native Harbor, and run
through one Harbor TrialQueue sized by the capacity check. A LiteLLM callback,
registered once, acts only on calls made inside `model_calls`: it supplies that role's
credential, refuses new calls once the run's known cost reaches its cap, and records
each call's usage and estimated cost.
"""

import asyncio
import contextlib
import json
import logging
import math
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
import tomllib
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import get_args

import litellm
from dotenv import dotenv_values
from harbor.environments.factory import EnvironmentFactory
from harbor.models.task.task import Task
from harbor.trial.queue import TrialQueue
from harbor.utils.optional_import import MissingExtraError
from litellm.integrations.custom_logger import CustomLogger
from litellm.litellm_core_utils.get_model_cost_map import get_model_cost_map_source_info

from nudi.episode import (HELPER_STATE, MODAL_BOX, UnsupportedTask, check_backend, check_output, compose_services, dropped_links, episode_queue,
                          run_episode, select_path)
from nudi.records import (
    CANCELLED,
    DEFAULT_MODELS,
    PROVIDER_REPORTED,
    CallRecord,
    Capacity,
    EpisodeConfig,
    EpisodeEvent,
    EpisodeResult,
    ErrorRecord,
    InfrastructureAbort,
    NativeBehavior,
    Role,
    RunConfig,
    RunRecord,
    SandboxResult,
    Simulation,
    append_private,
    private_dir,
    write_private,
)

ROLES: frozenset[Role] = frozenset(DEFAULT_MODELS)
# Requesting every behavior the adapter changes keeps the original grading and harness.
ORIGINAL_BEHAVIOR: frozenset[NativeBehavior] = frozenset(get_args(NativeBehavior))
LIMITATIONS = [
    "Concurrency uses 90% of Docker's CPUs and memory against the task's declarations. "
    "This is not a guarantee: image builds, Docker itself, host processes and the host-side "
    "Terminus 2 harness are not bounded by declarations.",
    "A held Inspector workspace has its own memory limit, by default the smaller of 512 MiB and the "
    "task's declaration; measured file, search and JSON work stayed far below 512 MiB, but an "
    "arbitrary command may exceed the limit and fail. Experiments and native episodes keep the "
    "task's limits. A workspace and one fresh experiment may together use every Docker CPU.",
    "The spending cap is checked when a call is admitted. Calls admitted before known cost "
    "reaches the cap finish and may exceed the cap. Calls of unknown cost do not count toward it. "
    "Terminus 2 and Harbor's LiteLLM wrapper retry a refused call with backoff, up to 9 attempts, "
    "so the episode's agent ends on the refusal or on its own deadline; Harbor still grades the "
    "actual task state after an agent deadline.",
    "Harbor's whole-episode retries are disabled, so every attempted episode stays recorded. "
    "Terminus 2 and Harbor's LiteLLM wrapper each retry a failed request up to 3 attempts; "
    "each sent attempt is a call.",
]
MODAL_LIMITATIONS = [
    "On Modal, `concurrency` containers run at once. Each declared CPU and memory value is a hard limit "
    "with a small request; an undeclared value has no limit. Hardware differs from a local Docker host, "
    "so timing-sensitive grading can differ between backends.",
    "On Modal, task files, episode files and the Attacker's work are uploaded to Modal. Modal compute is "
    "outside the spending cap; the report estimates its sandboxes' compute as a range from their requests "
    "and limits over their lifetimes, and `nudi cost` reads Modal's bill for the run's App once Modal has "
    "reported it. A sandbox nudi fails to remove can run up to 24 h and is reported as a warning.",
    "On Modal, a held Inspector workspace has the task's memory limit unless `workspace_memory_mb` sets one; "
    "a command beyond it ends the whole workspace.",
]
MIMO_LIMITATION = (
    "MiMo requests enable thinking explicitly and send the requested reasoning effort; "
    "whether MiMo gives differentiated intensity for that effort is unverified."
)
# Representative workspace file, search and JSON work peaked at 14-16 MiB in the measured task images.
# Docker only: there the workspace and an experiment share the machine. On Modal, workspaces of
# 512 MiB ran out of memory in 4 of 5 measured runs, so there a workspace keeps the task's limit.
WORKSPACE_MEMORY_MB = 512
OVERSHOOT = "known cost exceeded the spending cap: calls admitted before it was reached finished"
# Free bytes a run needs where records go, and where Docker stores data when nudi can measure it: one
# measured run's copy images reached 8.5 GB, and on Linux and Docker Desktop hosts Docker's storage is
# usually on the same disk as the records.
FREE_DISK_MINIMUM = 10 * 2**30

logger = logging.getLogger("nudi")
EVENTS_VERSION = 1
# Sessions and attempts write events at once; one writer at a time keeps each line whole and in order.
events_lock = threading.Lock()
# The name of the environment whose run writes events in this context, when one command runs several.
environment: ContextVar[str | None] = ContextVar("nudi_environment", default=None)


class CapacityError(RuntimeError):
    """One episode cannot fit Docker's capacity, so the run does not start."""


class MissingCredential(ValueError):
    """A requested role has no credential, so the run does not start."""


class SpendingCapReached(RuntimeError):
    """Known cost reached the run's spending cap, so no new call or episode starts."""


class BackendUnavailable(RuntimeError):
    """The backend's preflight failed, so the run does not start."""


class CapacityUnavailable(RuntimeError):
    """A held Inspector sandbox leaves no room under the run's concurrency, so another
    container does not start; it is refused at once rather than queued."""


def docker_capacity() -> tuple[int, int, int | None, str]:
    """Docker's CPUs and memory in MiB, as the daemon reports them, the free bytes where it stores
    data, and that data directory. The free bytes are measured only through a unix socket,
    `DOCKER_HOST` or else the current context's endpoint, to a daemon whose name is this host's and
    whose data directory is here. Docker Desktop, Colima and other virtual machines report another
    name or a directory that is not here, and a remote daemon is never measured: their free bytes,
    and any that cannot be learned, are None."""
    if shutil.which("docker") is None:
        raise BackendUnavailable("Docker is not installed: no docker command on PATH; install Docker or use --backend modal")
    info = subprocess.run(["docker", "info", "--format", "{{.NCPU}}\n{{.MemTotal}}\n{{.Name}}\n{{.DockerRootDir}}"],
                          capture_output=True, text=True, check=True)
    cpus, memory, name, root = info.stdout.splitlines()
    endpoint = os.environ.get("DOCKER_HOST", "")
    if not endpoint:
        with contextlib.suppress(OSError):
            context = subprocess.run(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                                     capture_output=True, text=True)
            if context.returncode == 0:
                endpoint = context.stdout
    free = None
    if endpoint.strip().startswith("unix://") and name == socket.gethostname() and os.path.isdir(root):
        with contextlib.suppress(OSError):
            free = shutil.disk_usage(root).free
    return int(cpus), int(memory) // 2**20, free, root


def declared_requirements(task_dir: Path) -> tuple[int | None, int | None]:
    """Declared CPUs and memory_mb of one episode's largest container; None when undeclared.

    The raw TOML decides whether a value is declared; Harbor's parsed config supplies it,
    converting the legacy `memory` string. A separate grader runs after the task container,
    in `[verifier.environment]` when declared, so the larger of the two is the requirement.
    Helper services of a compose file run beside the task container without the declared
    limits, Harbor applying them to the main service only, so their requirement is undeclared.
    """
    if len(compose_services(task_dir)) > 1:
        return None, None
    raw = tomllib.loads((task_dir / "task.toml").read_text())
    config = Task(task_dir).config
    tables = [(raw.get("environment", {}), config.environment),
              (raw.get("verifier", {}).get("environment", {}), config.verifier.environment)]
    cpus = [parsed.cpus for table, parsed in tables if "cpus" in table]
    memory_mb = [parsed.memory_mb for table, parsed in tables if {"memory_mb", "memory"} & table.keys()]
    for name, needs in (("CPUs", cpus), ("MiB of memory", memory_mb)):
        for need in needs:
            if need <= 0:
                raise ValueError(f"one episode declares {need} {name}; a declared value must be positive")
    return max(cpus, default=None), max(memory_mb, default=None)


def plan_concurrency(
    docker_cpus: int, docker_memory_mb: int, cpus: int | None, memory_mb: int | None
) -> tuple[int, list[str]]:
    """Episodes to run at once within 90% of Docker's capacity, and the warnings."""
    for name, need, have in (("CPUs", cpus, docker_cpus), ("MiB of memory", memory_mb, docker_memory_mb)):
        if need is not None and need > have:
            raise CapacityError(f"one episode declares {need} {name}, which exceeds Docker's {have}")
    if cpus is None or memory_mb is None:
        return 1, [
            "the task does not declare both cpus and memory_mb for every container, so fit cannot be established: "
            "episodes run one at a time, a task's helper containers can exceed the concurrency setting, "
            "and even one episode may exhaust Docker's memory"
        ]
    fits = min(9 * docker_cpus // (10 * cpus), 9 * docker_memory_mb // (10 * memory_mb))
    if fits == 0:
        return 1, ["one episode needs more than 90% of Docker's capacity: episodes run one at a time without reserved headroom"]
    return fits, []


@dataclass
class Run:
    config: RunConfig
    record: RunRecord
    queue: TrialQueue
    keys: dict[Role, str] = field(repr=False)
    """Resolved credentials; held in memory only."""
    native_episodes: int = 0
    """Native episodes started and not yet returned, queued or running."""
    images: dict = field(default_factory=dict)
    """Modal snapshot images by copy id, for check sandboxes; held in memory only."""
    failed_starts: dict[str, int] = field(default_factory=dict)
    """Failed starts in a row of each task environment, by its name in `inspector_sandbox.sandbox`."""
    events_failed: bool = False
    """An append to `events.jsonl` failed, so the run writes no more events."""
    imported_copies: int = 0
    """State copies carried first from an earlier run's record, as its evidence: this run never deletes or marks them."""
    imported_sandboxes: int = 0
    """Sandboxes carried first from an earlier run's record, as its evidence: admission counts only later ones."""
    last_line: float = field(default_factory=time.monotonic)
    """When the last progress line was logged, a `time.monotonic()` value."""
    jobs: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    """Inspector sessions and Attacker episodes between their start and end events: each one's job and problem."""
    time_limit: tuple[float, float] | None = None
    """The run's time limit while it runs: its deadline on the event loop's clock and its length in seconds."""

    def save(self) -> None:
        write_private(self.config.output_dir / "run.json", self.record.model_dump_json(indent=2))

    def warn(self, message: str) -> None:
        if message not in self.record.warnings:
            self.record.warnings.append(message)
            event(self, "warning", message, logging.WARNING, message=message)

    def check_cap(self) -> None:
        cap = self.record.spending_cap
        if cap is not None and self.record.known_cost >= cap:
            raise SpendingCapReached(f"known cost ${self.record.known_cost:.6f} reached the spending cap ${cap}")

    def admit_container(self, purpose: str) -> None:
        """Admit another container, a sandbox `purpose` or "native", only after every closed
        Inspector sandbox was removed. Native episodes alone keep waiting in the run's queue;
        a held sandbox would make them wait on itself. Otherwise held sandboxes and native
        episodes in flight must leave room under the `concurrency` setting, except that a
        held workspace always admits one fresh experiment. On Modal that count is all. On
        Docker the recorded limits of held sandboxes, the declaration of each native episode
        in flight and the new container must also fit 90% of Docker's CPUs and memory.
        Undeclared resources keep one container for each slot of the run's concurrency, and a
        held workspace still admits one fresh experiment, unchecked, with a warning. Only a held
        workspace and one fresh experiment may use every CPU, still within the memory
        allowance, with a warning. Sandboxes carried from an earlier run are not this run's and are not counted."""
        held = []
        for name in self.record.sandboxes[self.imported_sandboxes:]:
            path = self.config.output_dir / "sandboxes" / name / "sandbox.json"
            box = SandboxResult.model_validate_json(path.read_text())
            if "removed" not in box.cleanup:
                held.append(box)
            elif box.cleanup["removed"] is not True:
                raise InfrastructureAbort(f"{name}: sandbox removal is unverified; another container cannot start")
        if not held and (purpose == "native" or not self.native_episodes):
            return
        capacity = self.record.capacity
        pair = [box.purpose for box in held] == ["workspace"] and not self.native_episodes and purpose in ("probe", "check")
        setting = capacity.concurrency_setting
        if setting is not None and len(held) + self.native_episodes >= setting and not pair:
            raise CapacityUnavailable(f"{len(held)} held sandboxes and {self.native_episodes} native episodes fill the "
                                      f"run's concurrency of {setting}; another container cannot start")
        if self.record.backend == "modal":
            return
        if capacity.episode_cpus is None or capacity.episode_memory_mb is None:
            if len(held) + self.native_episodes >= capacity.concurrency and not pair:
                raise CapacityUnavailable(f"{len(held)} held sandboxes and {self.native_episodes} native episodes fill the "
                                          f"run's concurrency of {capacity.concurrency}; another container cannot start")
            if pair:
                self.warn("a held workspace and one fresh experiment run without a resource check: the task's resources "
                          "are undeclared, helper services included")
            return
        memory_mb = capacity.workspace_memory_mb if purpose == "workspace" else capacity.episode_memory_mb
        limits = ([(box.environment["cpus"], box.environment["memory_mb"]) for box in held]
                  + [(capacity.episode_cpus, capacity.episode_memory_mb)] * self.native_episodes
                  + [(capacity.episode_cpus, memory_mb)])
        cpus, memory_mb = map(sum, zip(*limits))
        headroom = 10 * cpus <= 9 * capacity.docker_cpus
        if 10 * memory_mb > 9 * capacity.docker_memory_mb or not (headroom or pair and cpus <= capacity.docker_cpus):
            raise CapacityUnavailable(f"{len(held)} held sandboxes and {self.native_episodes} native episodes leave no room "
                                      f"for another container within 90% of Docker's {capacity.docker_cpus} CPUs and "
                                      f"{capacity.docker_memory_mb} MiB; it cannot start")
        if not headroom:
            self.warn(f"a held Inspector workspace and one fresh experiment use all {capacity.docker_cpus} of Docker's "
                      "CPUs: no CPU headroom remains for Docker, image builds or host processes")


# The share of a bound left at which an agent is told, so it can still finish before the bound stops it.
NOTICE_SHARE = 0.2


def notice(run, finish: str, *, turns: tuple[int, int] | None = None, agent: tuple[float, float] | None = None) -> str | None:
    """One plain line for an agent once 20% or less of a bound it works under is left, else None: `turns`, the model turns
    it used and their bound; `agent`, its agent timeout's deadline on the event loop's clock and its length in seconds; the
    run's time limit; and the spending cap. `finish` says how to wrap up."""
    now, left = asyncio.get_running_loop().time(), []
    if turns and (turns[1] - turns[0]) <= NOTICE_SHARE * turns[1]:
        count = max(turns[1] - turns[0], 0)
        left.append(f"{count} model turn{'s' * (count != 1)}")
    for bound, name in ((agent, "the agent timeout"), (run.time_limit, "the run's time limit")):
        if bound and bound[0] - now <= NOTICE_SHARE * bound[1]:
            minutes = math.ceil(max(bound[0] - now, 0) / 60)
            left.append(f"{minutes} minute{'s' * (minutes != 1)} before {name}")
    cap = run.record.spending_cap
    if cap and cap - run.record.known_cost <= NOTICE_SHARE * cap:
        left.append(f"${max(cap - run.record.known_cost, 0):.2f} of the spending cap")
    if not left:
        return None
    said = ", ".join(left[:-1]) + " and " + left[-1] if len(left) > 1 else left[0]
    return f"Your session ends soon, with {said} left. {finish}"


def elapsed(started: float) -> timedelta:
    """Wall time since `started`, a `time.monotonic()` value, in whole seconds; it prints as H:MM:SS."""
    return timedelta(seconds=round(time.monotonic() - started))


def event(run, kind: str, message: str, severity: int | None = logging.INFO, /, **fields) -> None:
    """Append one event to the run's `events.jsonl`, then log `message` at `severity` with the event attached;
    `nudi send-nudis` prints the event's `text` on stderr, where the name of the `environment` set in this context
    begins the message. With no severity the event is not logged.

    A failed append ends the log silently and changes nothing else, so the log stays a whole prefix of the events; the
    message is still logged. The message is logged after the lock is released, so no logging handler runs while it is
    held, and one that writes an event, from any thread, cannot block on it. The handlers can therefore receive lines
    written at once, or an event a handler writes while it receives one, in another order than the log's. A handler
    that raises raises from this call. A full disk stops the run through its other records."""
    with events_lock:
        moment = datetime.now(timezone.utc)
        # JSON has no duration, so a duration is whole seconds.
        fields = {key: round(value.total_seconds()) if isinstance(value, timedelta) else value for key, value in fields.items()}
        # The clock time tells a hung run from a working one, which can go hours with no line.
        item = {"v": EVENTS_VERSION, "time": moment.isoformat(timespec="microseconds"), "kind": kind, **fields,
                "known_cost": run.record.known_cost, "unknown_cost_calls": run.record.unknown_cost_calls,
                "cancelled_calls": run.record.cancelled_calls,
                "text": f"nudi: {moment.astimezone():%H:%M:%S} {name + ': ' if (name := environment.get()) else ''}{message}"}
        if not run.events_failed:
            try:
                append_private(run.config.output_dir / "events.jsonl", json.dumps(item) + "\n")
            except OSError:
                run.events_failed = True
        # The open jobs change with the log, in its order; the heartbeat reads them under the same lock.
        key = fields.get("session") or fields.get("episode")
        if kind in ("session_start", "attempt_start"):
            run.jobs[key] = ("Attacker" if kind == "attempt_start" else f"{fields['inspector']} inspector session", fields.get("problem"))
        elif kind in ("session_end", "attempt_end", "attempt_result"):
            run.jobs.pop(key, None)
        if severity is not None:
            run.last_line = time.monotonic()
    if severity is not None:
        logger.log(severity, message, extra={"event": item})


def resolve_credentials(config: RunConfig, models, roles) -> tuple[dict[Role, str], dict[Role, str]]:
    """Each role's credential and its source: the credentials file first, then the environment."""
    if config.credentials_file and not config.credentials_file.is_file():
        raise MissingCredential(f"credentials file {config.credentials_file} does not exist")
    file = dotenv_values(config.credentials_file) if config.credentials_file else {}
    keys, sources = {}, {}
    for role in sorted(roles):
        name = models[role].key_name()
        if file.get(name):
            keys[role], sources[role] = file[name], "credentials file"
        elif os.environ.get(name):
            keys[role], sources[role] = os.environ[name], "environment"
        else:
            raise MissingCredential(f"{role}: {name} is set in neither the credentials file nor the environment")
    return keys, sources


def start_run(config: RunConfig, roles: frozenset[Role] = ROLES, analyses: tuple[str, ...] = ()) -> Run:
    """Settle models, credentials, path, backend and capacity for `roles` before any episode
    starts. `run_start` names the selected `analyses`. Docker's capacity comes from `docker info`; on Modal, Harbor's preflight
    checks for a Modal credential instead, which nudi never reads."""
    if not (config.task_dir / "task.toml").exists():
        raise UnsupportedTask(f"{config.task_dir} is not a Harbor task folder: it has no task.toml")
    check_output(config.output_dir, config.task_dir)
    records = next(path for path in [config.output_dir, *config.output_dir.parents] if path.exists())
    free = shutil.disk_usage(records).free
    if free < FREE_DISK_MINIMUM:
        raise CapacityError(f"{free / 2**30:.1f} GiB is free where records go ({config.output_dir}); "
                            f"a run needs at least {FREE_DISK_MINIMUM // 2**30} GiB there")
    if config.credentials_file and config.credentials_file.resolve().is_relative_to(config.task_dir.resolve()):
        raise UnsupportedTask(f"the credentials file {config.credentials_file} is inside the task")
    # Copies, so a change to one run's models reaches no default or other run.
    models = {role: model.model_copy() for role, model in {**DEFAULT_MODELS, **config.models}.items()}
    keys, sources = resolve_credentials(config, models, roles)
    path, reasons = select_path(config.task_dir, ORIGINAL_BEHAVIOR)
    if path != "harbor":
        raise UnsupportedTask("run-level credentials and spending controls cover native Harbor only")
    check_backend(config.task_dir, config.backend)
    cpus, memory_mb = declared_requirements(config.task_dir)
    if config.backend == "modal":
        try:
            EnvironmentFactory.run_preflight(type=None, import_path=MODAL_BOX)
        except MissingExtraError:
            raise BackendUnavailable("Modal is unavailable: the Modal extra is not installed; "
                                     "run pip install -e '.[modal]' in the nudi checkout") from None
        except (SystemExit, ImportError) as error:
            # Harbor's login message is a fixed text.
            raise BackendUnavailable(f"Modal is unavailable: {error}") from None
        except Exception as error:
            # Importing the Modal SDK reads the user's profile; its error text can quote that file.
            raise BackendUnavailable(f"Modal is unavailable: loading or checking Modal raised {type(error).__name__}") from None
        docker_cpus = docker_memory_mb = docker_free = None
        # nudi itself runs here, with its model calls; the sandboxes run on Modal.
        host_cpus, host_memory_mb = os.cpu_count(), os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // 2**20
        concurrency, warnings = config.concurrency, []
    else:
        host_cpus = host_memory_mb = None
        docker_cpus, docker_memory_mb, docker_free, docker_root = docker_capacity()
        if docker_free is not None and docker_free < FREE_DISK_MINIMUM:
            raise CapacityError(f"{docker_free / 2**30:.1f} GiB is free where Docker stores data ({docker_root}); "
                                f"a run needs at least {FREE_DISK_MINIMUM // 2**30} GiB there")
        concurrency, warnings = plan_concurrency(docker_cpus, docker_memory_mb, cpus, memory_mb)
        concurrency = min(concurrency, config.concurrency)
    workspace_memory_mb = config.workspace_memory_mb or (
        memory_mb if config.backend == "modal" else min(WORKSPACE_MEMORY_MB, memory_mb or WORKSPACE_MEMORY_MB))
    if docker_memory_mb is not None and 10 * workspace_memory_mb > 9 * docker_memory_mb:
        raise CapacityError(f"the Inspector workspace's {workspace_memory_mb} MiB of memory exceeds 90% of Docker's "
                            f"{docker_memory_mb} MiB")
    mimo = any(models[role].model.startswith("xiaomi_mimo/") for role in roles)
    record = RunRecord(
        task_dir=str(config.task_dir),
        path=path,
        path_reasons=reasons,
        models=models,
        credential_sources=sources,
        spending_cap=config.spending_cap,
        capacity=Capacity(
            docker_cpus=docker_cpus,
            docker_memory_mb=docker_memory_mb,
            episode_cpus=cpus,
            episode_memory_mb=memory_mb,
            concurrency=concurrency,
            concurrency_setting=config.concurrency,
            workspace_memory_mb=workspace_memory_mb,
        ),
        backend=config.backend,
        run_id=secrets.token_hex(4),
        started_at=datetime.now(timezone.utc).isoformat(),
        cost_map=get_model_cost_map_source_info(),
        warnings=warnings,
        limitations=(LIMITATIONS if config.backend == "docker" else MODAL_LIMITATIONS + LIMITATIONS[2:])
        + [MIMO_LIMITATION] * mimo + [HELPER_STATE.strip()] * (len(compose_services(config.task_dir)) > 1),
    )
    machine = (f"this host has {host_cpus} CPUs and {host_memory_mb} MiB, and each sandbox has the CPUs and memory the task declares"
               if docker_cpus is None else f"Docker has {docker_cpus} CPUs and {docker_memory_mb} MiB")
    storage = "" if config.backend == "modal" else (
        "free space where Docker stores data not measured; " if docker_free is None
        else f"{docker_free / 2**30:.1f} GiB free where Docker stores data; ")
    cap = "no spending cap" if config.spending_cap is None else f"spending cap ${config.spending_cap:.2f}"
    reason = warnings[0] if warnings else (
        f"the task's declared {cpus} CPUs and {memory_mb} MiB per episode fit {concurrency} within 90% of Docker's capacity"
        if concurrency < config.concurrency else None)
    if not any(isinstance(callback, RunCalls) for callback in litellm.callbacks):
        litellm.callbacks.append(RunCalls())
    # The root becomes 0700 and nudi creates new directories 0700 and new files 0600 under it.
    # Each episode restricts its Harbor or Verifiers tree once it ends; entries the host user does
    # not own, and files that already existed, keep their modes under the private root.
    private_dir(config.output_dir)
    config.output_dir.chmod(0o700)
    run = Run(config, record, episode_queue(concurrency), keys)
    run.save()
    event(run, "run_start", f"backend {config.backend}; {machine}; {free / 2**30:.1f} GiB free where records go ({config.output_dir}); "
          f"{storage}{cap}; concurrency {concurrency} of {config.concurrency}" + (f": {reason}" if reason else ""),
          logging.WARNING if warnings else logging.INFO, run_id=record.run_id, backend=config.backend, docker_cpus=docker_cpus,
          docker_memory_mb=docker_memory_mb, host_cpus=host_cpus, host_memory_mb=host_memory_mb, free_bytes=free,
          docker_free_bytes=docker_free, spending_cap=config.spending_cap, concurrency=concurrency,
          concurrency_setting=config.concurrency, reason=reason, pid=os.getpid(), host=socket.gethostname(),
          analyses=list(analyses))
    return run


# The run, role and episode of the model calls made in this context.
current: ContextVar[tuple[Run, Role, str] | None] = ContextVar("nudi_run_calls", default=None)
pending_calls: ContextVar[dict[str, dict] | None] = ContextVar("nudi_pending_calls", default=None)


@contextlib.contextmanager
def model_calls(run: Run, role: Role, episode: str):
    """Apply the run's credential, cap and accounting to LiteLLM calls made inside. A call still without a response or
    failure at the end keeps a record: cancelled when the calls end with an error, of unknown cost otherwise."""
    token = current.set((run, role, episode))
    pending = {}
    pending_token = pending_calls.set(pending)
    try:
        yield
    except BaseException as error:
        # LiteLLM's deployment failure hook does not catch cancellation. Keep admitted
        # calls without an observed completion, but never duplicate completed callbacks.
        while pending:
            _, request = pending.popitem()
            record_call(run, role, episode, request, error=type(error).__name__, cancelled=True)
        raise
    else:
        # A cancellation swallowed inside, as at an agent timeout in Harbor, ends the calls normally with calls admitted.
        while pending:
            _, request = pending.popitem()
            record_call(run, role, episode, request, unknown="unknown: no response before its calls ended")
    finally:
        pending_calls.reset(pending_token)
        current.reset(token)


def refusal_signals(response) -> list[str]:
    """Explicit refusal signals the provider returned; the model's text is never classified."""
    choice = response.choices[0]
    signals = []
    # LiteLLM's Message has no refusal field; it keeps the provider's under provider_specific_fields.
    if refusal := (choice.message.provider_specific_fields or {}).get("refusal"):
        signals.append(f"message.refusal: {refusal}")
    if choice.finish_reason == "content_filter":
        signals.append("finish_reason: content_filter")
    return signals


def record_call(run: Run, role: Role, episode: str, request: dict, response=None, error: str | None = None,
                refusals: list[str] | None = None, cancelled: bool = False,
                unknown: str = "unknown: the request failed", started: str | None = None) -> None:
    model = request["model"]
    usage = getattr(response, "usage", None)
    cost, source = None, CANCELLED if cancelled else unknown
    if response is not None:
        try:
            cost, source = litellm.completion_cost(completion_response=response, model=model), "litellm.completion_cost"
        except Exception as failure:
            source = f"unknown: {type(failure).__name__}: {failure}"
            provider = getattr(usage, "cost", None)
            if isinstance(provider, (int, float)) and math.isfinite(provider):
                cost, source = provider, PROVIDER_REPORTED
    run.record.calls.append(
        CallRecord(
            role=role,
            episode=episode,
            model=model,
            prompt_tokens=getattr(usage, "prompt_tokens", None),
            completion_tokens=getattr(usage, "completion_tokens", None),
            cost=cost,
            cost_source=source,
            provider_cost=getattr(usage, "cost", None),
            error=error,
            refusals=refusals or [],
            started=started or request.get("started"),
            ended=datetime.now(timezone.utc).isoformat(),
        )
    )
    if cancelled:
        run.record.cancelled_calls += 1
        run.warn(f"{model}: a call was cancelled in flight; its cost is unknown and does not count toward the spending cap")
    elif cost is None:
        run.record.unknown_cost_calls += 1
        run.warn(f"{model}: a call's cost is unknown and does not count toward the spending cap")
    else:
        run.record.known_cost += cost
        if run.record.spending_cap is not None and run.record.known_cost > run.record.spending_cap:
            run.warn(OVERSHOOT)
    run.save()


class RunCalls(CustomLogger):
    """Process-wide LiteLLM callback that acts only within `model_calls`."""

    async def async_pre_call_deployment_hook(self, kwargs, call_type):
        if (scope := current.get()) is None:
            return None
        run, role, episode = scope
        try:
            run.check_cap()
        except SpendingCapReached:
            run.record.refused_calls[episode] = run.record.refused_calls.get(episode, 0) + 1
            run.save()
            raise
        if (pending := pending_calls.get()) is not None:
            pending[kwargs["litellm_call_id"]] = {"model": kwargs["model"], "started": datetime.now(timezone.utc).isoformat()}
        return {**kwargs, "api_key": run.keys[role]}

    async def async_post_call_success_deployment_hook(self, request_data, response, call_type):
        if ((scope := current.get()) is not None
                and (pending := pending_calls.get()) is not None
                and (admitted := pending.pop(request_data["litellm_call_id"], None)) is not None):
            record_call(*scope, request_data, response=response, refusals=refusal_signals(response), started=admitted["started"])

    async def async_post_call_failure_deployment_hook(self, request_data, exception, call_type, fallback_depth=None):
        if ((scope := current.get()) is not None
                and (pending := pending_calls.get()) is not None
                and (admitted := pending.pop(request_data["litellm_call_id"], None)) is not None):
            refusals = [type(exception).__name__] if isinstance(exception, litellm.ContentPolicyViolationError) else []
            record_call(*scope, request_data, error=type(exception).__name__, refusals=refusals, started=admitted["started"])


async def run_role_episode(run: Run, role: Role, *, instruction: str | None = None, agent=None,
                           on_agent_start=None, on_trial_end=None, on_verification=None,
                           probe: bool = False, reminder: str | None = None) -> EpisodeResult:
    """Run one episode of `role` through the run's queue, under its credential and cap.

    The grader's environment is copied before grading and after the grader, unless cancelled
    (`nudi.copies`). Its lifecycle events record execution order. `finished` means the
    runner returned; Harbor may return after a failed environment stop. Neither return nor
    ordering establishes successful teardown or a normal reset.

    The Inspector is never a native task actor; it executes only in sandboxes of a package copy."""
    from nudi import copies

    if role == "inspector":
        raise ValueError("the Inspector never runs as a native task actor; use an Inspector sandbox")
    run.check_cap()
    run.admit_container("native")
    model = run.record.models[role]
    name = f"{len(run.record.episodes):04d}-{role}"
    run.record.episodes.append(name)
    if probe:
        run.record.probe_episodes.append(name)
    run.record.events.append(EpisodeEvent(episode=name, event="started"))
    run.save()
    config = EpisodeConfig(
        task_dir=run.config.task_dir,
        output_dir=run.config.output_dir / "episodes" / name,
        model=model.model,
        api_base=model.api_base,
        api_key_var=model.key_name(),
        reasoning_effort=model.reasoning_effort,
        native=ORIGINAL_BEHAVIOR,
        backend=run.config.backend,
        attacker=role == "attacker",
    )
    run.native_episodes += 1
    try:
        observe = None
        if on_verification is not None:
            async def observe(event):
                try:
                    await on_verification(event)
                except InfrastructureAbort:
                    raise
                except Exception as error:
                    message = str(error)
                    for secret in run.keys.values():
                        message = message.replace(secret, "[redacted]")
                    run.warn(f"{name}: verification observation failed: {type(error).__name__}: {message}")

        async def copy(verifier, point):
            ids = {"trial_id": str(verifier.environment.context_id), "trial_name": verifier.trial_paths.trial_dir.name,
                   "task_checksum": verifier.task.checksum}
            await copies.take(run, verifier, point, episode=name, owner=config.output_dir, ids=ids)

        def dropped(paths):
            run.warn(f"{name}: links and special files were removed from the collected artifacts before upload: {paths}")

        token = dropped_links.set(dropped)
        try:
            with model_calls(run, role, name):
                result = await run_episode(config, run.queue, instruction=instruction, agent=agent, copy=copy,
                                           on_verification=observe, on_agent_start=on_agent_start, on_trial_end=on_trial_end,
                                           credentials=run.config.credentials_file, reminder=reminder)
        finally:
            dropped_links.reset(token)
        run.record.events.append(EpisodeEvent(episode=name, event="finished"))
        return result
    finally:
        run.native_episodes -= 1
        run.save()


async def simulate(run: Run, episodes: int = 12) -> Simulation:
    """Run `episodes` ordinary Simulator episodes of the original task and harness.

    Every count takes this path. As many workers as the run's queue runs at once admit
    an episode only while the spending cap allows; admitted episodes finish. Failed
    episodes stay recorded and are not retried; the pool is partial only when one has no
    usable reward. Each episode's state copies serve grader inspection, which reuses this pool."""
    from nudi.checks import finish_cleanup, redacted

    if type(episodes) is not int or episodes < 1:
        raise ValueError("episodes must be a positive integer")
    simulation = Simulation(requested=episodes)
    run.record.simulation = simulation
    run.save()
    unusable = set()

    async def worker():
        # Harbor's shielded environment stop consumes a cancellation and the trial returns normally.
        while not asyncio.current_task().cancelling() and len(simulation.episodes) < episodes:
            try:
                run.check_cap()
            except SpendingCapReached:
                simulation.status = "spending_exhausted"
                return
            # run_role_episode assigns this name before its first await.
            name = f"{len(run.record.episodes):04d}-simulator"
            simulation.episodes.append(name)
            try:
                result = await run_role_episode(run, "simulator")
                if result.errors:
                    simulation.failures[name] = [error.model_copy(update={"message": redacted(run, error.message)})
                                                 for error in result.errors]
                if not any(value is not None and math.isfinite(value) for value in result.rewards.values()):
                    unusable.add(name)
            except Exception as error:
                simulation.failures[name] = [ErrorRecord(type=type(error).__name__, message=redacted(run, str(error)))]
                unusable.add(name)
            finally:
                if refusals := [signal for call in run.record.calls if call.episode == name for signal in call.refusals]:
                    simulation.refusals[name] = refusals
                run.save()

    workers = [asyncio.create_task(worker()) for _ in range(min(episodes, run.record.capacity.concurrency))]

    async def stop():
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    try:
        await asyncio.gather(*workers)
        if simulation.status == "running":
            simulation.status = "partial" if unusable else "complete"
    except asyncio.CancelledError:
        simulation.status = "cancelled"
        raise
    finally:
        # gather passes on one worker's stop, a full disk among them, while the others keep running.
        await finish_cleanup(asyncio.create_task(stop()))
        run.save()
    return simulation
