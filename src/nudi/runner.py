"""Run one local Harbor task with Terminus 2 and retain the episode.

The Verifiers Harbor adapter runs the episode unless one of its demonstrated
differences prevents a requested native behavior; native Harbor runs it then.
"""

import asyncio
import contextlib
import hashlib
import importlib.metadata
import json
import math
import os
import shutil
import stat
import tempfile
import tomllib
from collections.abc import Iterator
from contextvars import ContextVar
from collections.abc import Awaitable, Callable
from pathlib import Path

from harbor.agents.terminus_2.terminus_2 import Terminus2
from harbor.models.job.config import RetryConfig
from harbor.models.task.artifacts import is_convention_entry, source_host_path
from harbor.models.task.config import ArtifactConfig
from harbor.models.task.task import Task
from harbor.models.trial.paths import EnvironmentPaths
from harbor.trial.artifact_handler import artifact_host_path
from harbor.models.task.verifier_mode import resolve_verifier_environment_definition
from harbor.models.trial.config import AgentConfig, TaskConfig, TrialConfig, VerifierConfig
from harbor.models.trial.result import TrialResult
from harbor.trial.queue import TrialQueue
from harbor.trial.hooks import TrialHookEvent
from harbor.verifier.verifier import RewardFileEmptyError, Verifier, VerifierOutputParseError
from verifiers.v1.cli.eval.runner import run_eval
from verifiers.v1.configs.cli.eval import EvalConfig
from verifiers.v1.env import RunSlot
from verifiers.v1.taskset import Taskset
from verifiers.v1.tasksets.harbor import HarborEnv
from verifiers.v1.tasksets.harbor.taskset import (
    HarborConfig,
    HarborTask,
    HarborTaskset,
    parse_task,
)
from verifiers.v1.utils.trace_store import type_adapter

from nudi.records import (EpisodeConfig, EpisodeResult, ErrorRecord, ExecutionPath, InfrastructureAbort, NativeBehavior,
                          private_dir, write_private)

# task.toml fields the upstream contract tests exercise on both execution paths.
VERIFIED_FIELDS = {
    ("schema_version",),
    ("task",),
    ("metadata",),
    ("artifacts",),
    ("agent", "timeout_sec"),
    ("verifier", "timeout_sec"),
    ("verifier", "environment_mode"),
    ("environment", "docker_image"),
    ("environment", "cpus"),
    ("environment", "memory_mb"),
}
# Harbor 0.24.0 parses these exactly as if they were omitted, on both paths.
OMITTED = {
    ("verifier", "env"): lambda value: value == {},
    ("solution", "env"): lambda value: value == {},
}
# Native Harbor 0.24.0 treats all but storage_mb as omitted, and its Docker environment never
# reads storage_mb. The adapter is unchecked for them and turns storage into a disk request.
NATIVE_ONLY = {
    ("environment", "gpus"): lambda value: type(value) is int and value == 0,
    ("environment", "allow_internet"): lambda value: value is True,
    ("environment", "build_timeout_sec"): lambda value: type(value) in (int, float) and value == 600,
    ("environment", "env"): lambda value: value == {},
    ("environment", "mcp_servers"): lambda value: value == [],
    ("environment", "storage_mb"): lambda value: type(value) is int and value > 0,
}
STORAGE = (
    "[environment].storage_mb = {} is recorded but not enforced; Harbor's Docker environment "
    "sets no storage quota, so disk fit is not established"
)
VERSIONED = ("nudi", "verifiers", "harbor", "litellm")
DOCKERFILE = "Dockerfile-only environment: the Verifiers adapter does not build Dockerfiles"
# Demonstrated adapter differences, with what requesting the native behavior is called.
DIFFERENCES = {
    "shared_grading": (
        "native shared grading requested",
        "the adapter deletes agent-written reward files before shared grading; "
        "native Harbor grades them",
    ),
    "host_harness": (
        "host-side Terminus 2 requested",
        "the adapter runs Terminus 2 inside the task container with a readable "
        "interception secret; native Harbor runs it on the host",
    ),
    "atif": (
        "ATIF trajectory requested",
        "the adapter deletes the Terminus 2 ATIF trajectory; native Harbor retains it",
    ),
}


# The Verifiers adapter's bound on a reward file.
REWARD_LIMIT = 2**20


class UnsupportedTask(ValueError):
    """The task uses a feature nudi has not verified, so it is not started."""


def read_reward(path: Path) -> str:
    """A container-written reward file's text, read on the host without following a link
    or blocking on a FIFO, and bounded. Errors name the file, never its content."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise VerifierOutputParseError(f"Reward file {path} is a link or cannot be opened: {error.strerror}") from None
    with os.fdopen(descriptor, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise VerifierOutputParseError(f"Reward file {path} is not a regular file")
        data = file.read(REWARD_LIMIT + 1)
    if len(data) > REWARD_LIMIT:
        raise VerifierOutputParseError(f"Reward file {path} exceeds {REWARD_LIMIT} bytes")
    if not data:
        raise RewardFileEmptyError(f"Reward file is empty at {path}")
    try:
        return data.decode()
    except UnicodeDecodeError:
        raise VerifierOutputParseError(f"Reward file {path} is not UTF-8") from None


class RewardVerifier(Verifier):
    """Harbor's Verifier, parsing rewards through `read_reward` with Harbor's rules. Harbor
    0.24.0 follows reward links on the host and puts invalid values in its errors.

    Its import-path factory drops the bundled-tests flag Harbor resolves for a separate
    verifier, so an unset `skip_tests_upload` is resolved here the same way."""

    def __init__(self, *, task: Task, skip_tests_upload: bool | None = None, **kwargs):
        if skip_tests_upload is None:
            definition = resolve_verifier_environment_definition(task.config, task.paths)
            skip_tests_upload = definition is not None and definition.bundled_tests
        super().__init__(task=task, skip_tests_upload=skip_tests_upload, **kwargs)

    def _parse_reward_text(self) -> dict[str, float | int]:
        path = self.trial_paths.reward_text_path
        try:
            value = float(read_reward(path))
        except ValueError:
            raise VerifierOutputParseError(f"Failed to parse rewards from text file {path}") from None
        if not math.isfinite(value):
            raise VerifierOutputParseError(f"Non-finite reward in text file {path}")
        return {"reward": value}

    def _parse_reward_json(self) -> dict[str, float | int]:
        path = self.trial_paths.reward_json_path
        try:
            rewards = json.loads(read_reward(path))
        except ValueError:
            raise VerifierOutputParseError(f"Failed to parse rewards from JSON file {path}") from None
        if not isinstance(rewards, dict):
            raise VerifierOutputParseError(f"Rewards in JSON file {path} are not an object")
        for value in rewards.values():
            if not isinstance(value, (int, float)) or isinstance(value, float) and not math.isfinite(value):
                raise VerifierOutputParseError(f"Non-numeric or non-finite reward in JSON file {path}")
        return rewards


def snapshot(task_dir: Path, destination: Path, credentials: Path | None = None) -> None:
    """Copy the task to a new `destination` as regular files and directories only. A link
    inside the task is copied as its target. A link leaving the task or forming a directory
    cycle, any other file type, and the run's credentials file are refused. Callers use only
    the copy."""
    root = task_dir.resolve()
    secret = credentials.resolve() if credentials is not None else None

    def copy(source: Path, target: Path, ancestors: frozenset[Path]) -> None:
        path, name = source.resolve(), source.relative_to(task_dir)
        if not path.is_relative_to(root):
            raise UnsupportedTask(f"{name} points outside the task")
        if path == secret:
            raise UnsupportedTask(f"{name} is the run's credentials file")
        if path.is_dir():
            if path in ancestors:
                raise UnsupportedTask(f"{name} forms a directory cycle")
            target.mkdir()
            for child in sorted(source.iterdir()):
                copy(child, target / child.name, ancestors | {path})
        elif path.is_file():
            shutil.copyfile(path, target)
        else:
            raise UnsupportedTask(f"{name} is not a regular file")
        shutil.copystat(path, target)

    copy(task_dir, destination, frozenset())


def unverified_fields(table: dict, prefix: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], object]]:
    known = VERIFIED_FIELDS | OMITTED.keys() | NATIVE_ONLY.keys()
    for key, value in table.items():
        path = (*prefix, key)
        if path in VERIFIED_FIELDS:
            continue
        if isinstance(value, dict) and any(len(f) > len(path) and f[: len(path)] == path for f in known):
            yield from unverified_fields(value, path)
        else:
            yield path, value


def label(path: tuple[str, ...]) -> str:
    return f"[{'.'.join(path[:-1])}].{path[-1]}" if len(path) > 1 else f"[{path[0]}]"


def excluded_convention_artifact(entries: object) -> bool:
    """A main-service convention directory with exclude is downloaded into its own mount."""
    if not isinstance(entries, list):
        return False
    convention = EnvironmentPaths().artifacts_dir.as_posix()
    root = Path("artifacts")
    mount = source_host_path(root, convention)
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("exclude"):
            continue
        try:
            artifact = ArtifactConfig.model_validate(entry)
        except ValueError:
            continue
        if not is_convention_entry(artifact, convention):
            continue
        if artifact_host_path(root, artifact) == mount:
            return True
    return False


def check_task(task_dir: Path) -> dict[tuple[str, ...], object]:
    """Reject escaping file references, special files and unverified task features.

    Returns the accepted declarations that only native Harbor may run."""
    root = task_dir.resolve()
    for path in sorted(task_dir.rglob("*")):
        if path.is_symlink() and not path.resolve().is_relative_to(root):
            raise UnsupportedTask(f"{path.relative_to(task_dir)} points outside the task")
        if not (path.is_dir() or path.is_file()):
            raise UnsupportedTask(f"{path.relative_to(task_dir)} is not a regular file")
    for name in ("docker-compose.yaml", "docker-compose.yml"):
        if (task_dir / "environment" / name).exists():
            raise UnsupportedTask(f"environment/{name} is not verified")

    # Raw fields: Harbor's parsed config silently drops keys it does not know.
    raw = tomllib.loads((task_dir / "task.toml").read_text())
    if excluded_convention_artifact(raw.get("artifacts")):
        raise UnsupportedTask("the conventional artifacts directory with exclude is not verified")
    # The legacy names Harbor renames before parsing (harbor/models/task/config.py).
    # It drops a non-string `memory` instead, so that stays unverified.
    if "version" in raw and "schema_version" not in raw:
        raw["schema_version"] = raw.pop("version")
    environment = raw.get("environment", {})
    if isinstance(environment.get("memory"), str) and "memory_mb" not in environment:
        environment["memory_mb"] = environment.pop("memory")
    native_only = {}
    for path, value in unverified_fields(raw):
        if path in NATIVE_ONLY and NATIVE_ONLY[path](value):
            native_only[path] = value
        elif not (path in OMITTED and OMITTED[path](value)):
            raise UnsupportedTask(f"{label(path)} is not verified")

    config = Task(task_dir).config
    dockerfile = task_dir / "environment" / "Dockerfile"
    if not config.environment.docker_image and not dockerfile.is_file():
        raise UnsupportedTask("the task declares no docker_image or environment/Dockerfile")
    return native_only


def select_path(
    task_dir: Path, native: frozenset[NativeBehavior]
) -> tuple[ExecutionPath, list[str]]:
    """The execution path and the reasons for it, decided before anything starts."""
    native_only = check_task(task_dir)
    storage_mb = native_only.get(("environment", "storage_mb"))
    storage = [STORAGE.format(storage_mb)] if storage_mb else []
    try:
        data = parse_task(task_dir, 0, HarborConfig(ignore_timeouts=False))
    except ValueError as error:
        if "needs a pullable docker_image" in str(error):
            return "harbor", [DOCKERFILE, *storage]
        raise UnsupportedTask(str(error)) from error

    applicable = set(DIFFERENCES) - ({"shared_grading"} if data.verifier is not None else set())
    if requested := sorted(applicable & native):
        return "harbor", [f"{DIFFERENCES[b][0]}: {DIFFERENCES[b][1]}" for b in requested] + storage
    if native_only:
        raise UnsupportedTask(f"{label(next(iter(native_only)))} is not verified on the Verifiers adapter")
    accepted = sorted(applicable)
    return "verifiers", [f"accepted adapter difference: {DIFFERENCES[b][1]}" for b in accepted]


class LocalHarborConfig(HarborConfig):
    task_dir: Path


class LocalHarborTaskset(HarborTaskset, Taskset[HarborTask, LocalHarborConfig]):
    """One local task package parsed in place; the upstream taskset loads only its cache."""

    def load(self) -> Iterator[HarborTask]:
        yield HarborTask(parse_task(self.config.task_dir, 0, self.config), self.config.task)


# The slots of the adapter run in this context; upstream fills their traces live.
observed_slots: ContextVar[list[RunSlot]] = ContextVar("observed_slots")


class ObservedHarborEnv(HarborEnv):
    """The upstream Harbor env, with its planned slots visible to the runner."""

    def slots(self, task: HarborTask, n: int = 1) -> list[RunSlot]:
        slots = super().slots(task, n)
        observed_slots.get([]).extend(slots)
        return slots


def tree_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(directory)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


async def run_verifiers(config: EpisodeConfig, task_dir: Path, result: EpisodeResult) -> None:
    eval_config = EvalConfig.model_validate(
        {
            "env": {
                # Verifiers imports a taskset id as a package; `nudi` exports LocalHarborTaskset.
                "taskset": {"id": "nudi", "task_dir": str(task_dir), "ignore_timeouts": False},
                "agent": {
                    # The harness defaults to Harbor 0.23.0; match the host's Harbor instead.
                    "harness": {"id": "terminus-2", "version": importlib.metadata.version("harbor")},
                    "runtime": {"type": "docker"},
                },
            },
            "model": config.model,
            "client": {"type": "eval", "base_url": config.api_base, "api_key_var": config.api_key_var},
            "sampling": {"reasoning_effort": config.reasoning_effort} if config.reasoning_effort else {},
            "num_rollouts": 1,
            "max_concurrent": 1,
            "push": False,
            "rich": None,
            "output_dir": str(config.output_dir / "verifiers"),
        }
    )
    slots: list[RunSlot] = []
    observed_slots.set(slots)
    try:
        await run_eval(eval_config)
    finally:
        # The run id exists once upstream opens the run.
        with contextlib.suppress(RuntimeError):
            result.ids["run_id"] = eval_config.run.id
        record_slots(slots, config.output_dir, Path("verifiers") / eval_config.run.dir, result)


def record_slots(slots: list[RunSlot], output_dir: Path, run_dir: Path, result: EpisodeResult) -> None:
    errors = []
    for slot in slots:
        if slot.episode is not None:
            result.ids["episode_id"] = slot.episode.id
            errors += slot.episode.errors
        elif slot.traces:
            # Upstream persists only finished episodes; keep the live traces, model calls included.
            lines = [type_adapter(type(trace)).dump_json(trace, exclude_none=True) for trace in slot.traces]
            write_private(output_dir / run_dir / "partial-traces.jsonl", b"\n".join(lines) + b"\n")
        for trace in slot.traces:
            result.ids["trace_id"] = trace.id
            for name, reward in trace.rewards.items():
                result.rewards[name] = None if reward is None else reward.score
            result.metrics.update(trace.metrics)
            result.agent_timeout |= trace.stop_condition == "agent_timeout"
            result.verifier_timeout |= trace.stop_condition == "scoring_timeout"
            errors += trace.errors
    result.errors = [ErrorRecord(type=e.type, message=e.message) for e in errors]
    for name, relative in (("run", ""), ("traces", "traces.jsonl"), ("partial_traces", "partial-traces.jsonl")):
        if (output_dir / run_dir / relative).exists():
            result.artifacts[name] = str(run_dir / relative)


# Sibling of the trial's agent directory. Harbor bind-mounts agent/ into the container
# and does not mount this directory.
HOST_AGENT_LOGS = "agent-host"


def trajectory_path(trial_dir: Path) -> Path | None:
    """The ATIF file outside the mounted agent directory, or a regular file at the
    mounted name. A link is not a trajectory."""
    for relative in (f"{HOST_AGENT_LOGS}/trajectory.json", "agent/trajectory.json"):
        path = trial_dir / relative
        if not path.is_symlink() and path.is_file():
            return path
    return None


def record_trial(trial: TrialResult, output_dir: Path, result: EpisodeResult) -> None:
    trial_dir = Path("harbor") / trial.trial_name
    result.ids.update(
        trial_id=str(trial.id), trial_name=trial.trial_name, task_checksum=trial.task_checksum
    )
    root = output_dir / trial_dir
    for name, relative in (
        ("trial", ""),
        ("result", "result.json"),
        ("collected", "artifacts"),
    ):
        if (root / relative).exists():
            result.artifacts[name] = str(trial_dir / relative)
    if trajectory := trajectory_path(root):
        result.artifacts["trajectory"] = str(trajectory.relative_to(output_dir))
    if trial.verifier_result is not None:
        result.rewards.update(trial.verifier_result.rewards or {})
    if info := trial.exception_info:
        result.errors = [ErrorRecord(type=info.exception_type, message=info.exception_message)]
        result.agent_timeout = info.exception_type == "AgentTimeoutError"
        result.verifier_timeout = info.exception_type == "VerifierTimeoutError"


verification_capture: ContextVar[Callable[[TrialHookEvent], Awaitable[None]] | None] = ContextVar("nudi_capture", default=None)
agent_start_capture: ContextVar[Callable[[TrialHookEvent], Awaitable[None]] | None] = ContextVar("nudi_agent_start", default=None)
trial_end_capture: ContextVar[Callable[[TrialHookEvent], Awaitable[None]] | None] = ContextVar("nudi_trial_end", default=None)


async def _run_hook(callback: Callable[[TrialHookEvent], Awaitable[None]] | None, event: TrialHookEvent) -> None:
    """An unset callback does nothing. CancelledError and InfrastructureAbort are re-raised.

    InfrastructureAbort stops the episode after a failed resume. Any other exception is swallowed
    so the trial continues; the episode callback records its own errors.
    """
    if callback is None:
        return
    try:
        await callback(event)
    except asyncio.CancelledError:
        raise
    except InfrastructureAbort:
        raise
    except Exception:
        return


async def capture_at_verification(event: TrialHookEvent) -> None:
    await _run_hook(verification_capture.get(), event)


async def capture_at_agent_start(event: TrialHookEvent) -> None:
    await _run_hook(agent_start_capture.get(), event)


async def capture_at_trial_end(event: TrialHookEvent) -> None:
    await _run_hook(trial_end_capture.get(), event)


def ensure_lifecycle_hooks(queue: TrialQueue) -> None:
    """Register the native boundaries once. Each hook no-ops unless this episode set a callback."""
    if getattr(queue, "_nudi_lifecycle_registered", False):
        return
    queue.on_agent_started(capture_at_agent_start)
    queue.on_verification_started(capture_at_verification)
    queue.on_trial_ended(capture_at_trial_end)
    queue._nudi_lifecycle_registered = True
    queue._nudi_capture_registered = True


def episode_queue(n_concurrent: int) -> TrialQueue:
    """Harbor's queue running at most `n_concurrent` episodes. Its whole-episode retries
    are disabled because Harbor deletes a retried episode's directory."""
    return TrialQueue(n_concurrent, retry_config=RetryConfig(max_retries=0))


class HostTerminus(Terminus2):
    """Terminus 2 with host logs outside the directory Harbor mounts into the container.

    Harbor 0.24.0 passes logs_dir as the trial agent directory and bind-mounts that
    directory at /logs/agent. Terminus writes trajectory.json, trajectory.cont-N.json
    and trajectory.summarization-N-*.json there with a plain open, so a link planted
    in the mount is followed on the host. Those files are written in the sibling
    directory agent-host, which is not mounted. Terminal recording is off because
    Harbor would download recording.cast into the mounted directory.
    """

    def __init__(self, logs_dir: Path, *args, **kwargs):
        kwargs["record_terminal_session"] = False
        host_logs = Path(logs_dir).parent / HOST_AGENT_LOGS
        host_logs.mkdir(parents=True, exist_ok=True)
        super().__init__(host_logs, *args, **kwargs)


async def run_harbor(config: EpisodeConfig, task_dir: Path, result: EpisodeResult, queue: TrialQueue, agent: AgentConfig | None = None) -> None:
    ensure_lifecycle_hooks(queue)
    kwargs = {"api_base": config.api_base, "reasoning_effort": config.reasoning_effort}
    if config.model.startswith("xiaomi_mimo/") and config.reasoning_effort not in (None, "none"):
        # MiMo Chat thinks only when asked through this field; the effort is still sent.
        kwargs["llm_call_kwargs"] = {"extra_body": {"thinking": {"type": "enabled"}}}
    trial_config = TrialConfig(
        task=TaskConfig(path=task_dir),
        trials_dir=config.output_dir / "harbor",
        verifier=VerifierConfig(import_path="nudi.runner:RewardVerifier"),
        agent=agent or AgentConfig(
            import_path="nudi.runner:HostTerminus",
            model_name=config.model,
            kwargs={key: value for key, value in kwargs.items() if value is not None},
        ),
    )
    try:
        await queue.submit(trial_config)
    finally:
        # Harbor writes result.json on success, failure and cancellation, before re-raising.
        path = config.output_dir / "harbor" / trial_config.trial_name / "result.json"
        if path.exists():
            record_trial(TrialResult.model_validate_json(path.read_text()), config.output_dir, result)


def restrict(directory: Path) -> None:
    """Make a retained tree owner-only once its containers have stopped. Harbor and Verifiers
    create it with default modes, and Harbor opens bind-mounted directories to the container's
    users. Links are left alone; an entry the host user does not own keeps its mode."""
    if directory.is_symlink() or not directory.is_dir():
        return
    os.chmod(directory, 0o700)
    for parent, directories, files in os.walk(directory):
        for names, mode in ((directories, 0o700), (files, 0o600)):
            for name in names:
                path = os.path.join(parent, name)
                if not os.path.islink(path):
                    with contextlib.suppress(PermissionError):
                        os.chmod(path, mode)


def check_output(output_dir: Path, task_dir: Path) -> None:
    """Reject an output directory equal to or inside the task, symlink aliases included."""
    if output_dir.resolve().is_relative_to(task_dir.resolve()):
        raise ValueError(f"output_dir {output_dir} overlaps the task {task_dir}")


async def run_episode(config: EpisodeConfig, queue: TrialQueue | None = None, *, instruction: str | None = None,
                      agent: AgentConfig | None = None, capture=None, on_agent_start=None, on_trial_end=None,
                      credentials: Path | None = None) -> EpisodeResult:
    """Run one episode on a disposable task snapshot; the record is written even on failure.

    Native Harbor episodes run through `queue`, shared by a run, or a queue of their own.
    `credentials` is the run's credentials file, which the snapshot refuses."""
    check_output(config.output_dir, config.task_dir)
    path, reasons = select_path(config.task_dir, config.native)
    result = EpisodeResult(
        path=path,
        path_reasons=reasons,
        task_name=config.task_dir.name,
        task_dir=str(config.task_dir),
        task_digest=tree_digest(config.task_dir),
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        versions={name: importlib.metadata.version(name) for name in VERSIONED},
    )
    private_dir(config.output_dir)
    config.output_dir.chmod(0o700)
    token = verification_capture.set(capture)
    agent_token = agent_start_capture.set(on_agent_start)
    end_token = trial_end_capture.set(on_trial_end)
    try:
        with tempfile.TemporaryDirectory(prefix="nudi-task-") as temp:
            task_dir = Path(temp) / config.task_dir.name
            snapshot(config.task_dir, task_dir, credentials)
            if instruction is not None:
                write_private(config.output_dir / "nudi-evidence" / "extension.md", instruction)
                with (task_dir / "instruction.md").open("a") as file:
                    file.write("\n\n" + instruction)
            if path == "verifiers":
                await run_verifiers(config, task_dir, result)
            else:
                await run_harbor(config, task_dir, result, queue or episode_queue(1), agent)
    except asyncio.CancelledError:
        result.cancelled = True
        raise
    except Exception as error:
        result.errors.append(ErrorRecord(type=type(error).__name__, message=str(error)))
        raise
    finally:
        verification_capture.reset(token)
        agent_start_capture.reset(agent_token)
        trial_end_capture.reset(end_token)
        if (config.output_dir / "nudi-evidence").is_dir():
            result.artifacts["nudi_evidence"] = "nudi-evidence"
        write_private(config.output_dir / "episode.json", result.model_dump_json(indent=2))
        for tree in ("harbor", "verifiers"):
            restrict(config.output_dir / tree)
    return result
