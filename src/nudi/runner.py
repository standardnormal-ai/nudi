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
import re
import shutil
import stat
import tempfile
import tomllib
from collections.abc import Iterator
from contextvars import ContextVar
from collections.abc import Awaitable, Callable
from pathlib import Path

import yaml
from harbor.agents.terminus_2.terminus_2 import Terminus2
from harbor.models.environment_type import EnvironmentType
from harbor.models.job.config import RetryConfig
from harbor.constants import MAIN_SERVICE_NAME
from harbor.models.task.artifacts import is_convention_entry, sidecar_services, source_host_path
from harbor.models.task.config import ArtifactConfig
from harbor.models.task.task import Task
from harbor.models.trial.paths import EnvironmentPaths, TrialPaths
from harbor.trial.artifact_handler import artifact_host_path
from harbor.models.task.verifier_mode import VerifierEnvironmentMode, resolve_task_verifier_mode, resolve_verifier_environment_definition
from harbor.models.trial.config import AgentConfig, EnvironmentConfig, ResourceMode, TaskConfig, TrialConfig, VerifierConfig
from harbor.models.trial.result import TrialResult
from harbor.trial.queue import TrialQueue
from harbor.trial.hooks import TrialHookEvent
from harbor.utils.env import is_env_template
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

from nudi.records import (Backend, EpisodeConfig, EpisodeResult, ErrorRecord, ExecutionPath, InfrastructureAbort, NativeBehavior,
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
# Native Harbor 0.24.0 treats these as omitted, except that it waits build_timeout_sec for an
# environment to start, its Docker environment never reads storage_mb, and it requests declared
# GPUs, which nudi admits on Modal only (`check_backend`). The adapter is unchecked for them and
# turns storage into a disk request.
ENVIRONMENT_RULES = {
    "gpus": lambda value: type(value) is int and value >= 0,
    "gpu_types": lambda value: isinstance(value, list) and all(isinstance(item, str) for item in value),
    "allow_internet": lambda value: value is True,
    "build_timeout_sec": lambda value: type(value) in (int, float) and 0 < value < math.inf,
    "env": lambda value: value == {},
    "mcp_servers": lambda value: value == [],
    "storage_mb": lambda value: type(value) is int and value > 0,
}
# A `[verifier.environment]` table is the separate grader's environment, which native Harbor
# resolves with resolve_verifier_environment_definition; its image and resources are honored
# there and in a probe's verifier sandbox, the same way. The adapter is unchecked for it.
NATIVE_ONLY = {
    **{("environment", key): rule for key, rule in ENVIRONMENT_RULES.items()},
    # Native Harbor starts the verifier within the main environment's build_timeout_sec, so check_task
    # admits the verifier's own only when it is the same value.
    **{("verifier", "environment", key): rule for key, rule in ENVIRONMENT_RULES.items()},
    ("verifier", "environment", "docker_image"): lambda value: isinstance(value, str) and bool(value),
    ("verifier", "environment", "cpus"): lambda value: type(value) is int and value > 0,
    ("verifier", "environment", "memory_mb"): lambda value: type(value) is int and value > 0,
    # Harbor's trial runs the healthcheck after the main environment starts, as nudi's sandboxes
    # of the task environment do. skills_dir and mcp_servers reach only the agent (Terminus 2 lists
    # them in its prompt), so they do not change package experiments.
    ("environment", "healthcheck"): lambda value: isinstance(value, dict) and bool(value),
    ("environment", "skills_dir"): lambda value: isinstance(value, str),
    ("environment", "mcp_servers"): lambda value: isinstance(value, list),
    # Harbor's Verifier gives these to the grader on both paths. A `${VAR}` value is refused: Harbor
    # resolves it from nudi's own environment, which contains the run's credentials.
    ("verifier", "env"): lambda value: isinstance(value, dict) and bool(value) and all(
        isinstance(item, str) and not is_env_template(item) for item in value.values()),
    # Harbor's trial runs these hooks before it collects artifacts; package_probe runs Harbor's own collection.
    ("verifier", "collect"): lambda value: isinstance(value, list),
}
# environment/docker-compose.yaml: the service keys and build keys nudi admits, the ones Terminal-Bench 4
# tasks use. Harbor runs compose with nudi's own environment, which contains the run's credentials, so no
# variable is interpolated, and no service reaches a host path or passes a host variable through.
COMPOSE_SERVICE_KEYS = {"build", "cap_add", "command", "cpus", "depends_on", "environment", "expose", "healthcheck",
                        "image", "network_mode", "pull_policy", "shm_size"}
COMPOSE_BUILD_KEYS = {"context", "dockerfile", "no_cache"}
INTERPOLATION = re.compile(r"\$(\{|[A-Za-z_])")
STORAGE = (
    "{} = {} is recorded but not enforced; Harbor's Docker environment "
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


# Bounds one state copy operation; the margin covers cancellation and bookkeeping outside them.
COPY_TIMEOUT = 120
COPY_MARGIN = 30

# Takes a state copy of a verifier's environment at a named point; set by nudi for each episode.
state_copy: ContextVar[Callable[["RewardVerifier", str], Awaitable[None]] | None] = ContextVar("nudi_state_copy", default=None)


def grading_bound(timeout_sec: float) -> float:
    """The outer limit of `RewardVerifier.verify`: the grader's own limit plus two copies."""
    return timeout_sec + 2 * COPY_TIMEOUT + COPY_MARGIN


class RewardVerifier(Verifier):
    """Harbor's Verifier, parsing rewards through `read_reward` with Harbor's rules. Harbor
    0.24.0 follows reward links on the host and puts invalid values in its errors.

    Its import-path factory drops the bundled-tests flag Harbor resolves for a separate
    verifier, so an unset `skip_tests_upload` is resolved here the same way.

    With a `state_copy` callback it copies the grading environment before grading and after
    the grader, also after a grader error or timeout; only cancellation skips the second
    copy. A grader error's text names its direct cause, which Harbor's own text drops. The
    grader keeps the task's own limit; its caller's limit is `grading_bound`. The callback
    bounds and records its own failures."""

    def __init__(self, *, task: Task, skip_tests_upload: bool | None = None, **kwargs):
        if skip_tests_upload is None:
            definition = resolve_verifier_environment_definition(task.config, task.paths)
            skip_tests_upload = definition is not None and definition.bundled_tests
        super().__init__(task=task, skip_tests_upload=skip_tests_upload, **kwargs)

    async def verify(self):
        take = state_copy.get()
        if take is not None:
            await take(self, "verification_start")
        try:
            return await asyncio.wait_for(super().verify(), self.task.config.verifier.timeout_sec)
        except (asyncio.CancelledError, KeyboardInterrupt):
            take = None
            raise
        except Exception as error:
            # Harbor and nudi record str(error) only, which can be just "Failed to download verifier directory".
            if isinstance(error.__cause__, Exception):
                error.args = (f"{error}: {type(error.__cause__).__name__}: {error.__cause__}",)
            raise
        finally:
            if take is not None:
                await take(self, "grading_end")

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


def named(directory: Path, *names: str) -> list[Path]:
    """The entries of `directory` whose casefolded name is one of `names`."""
    return sorted(p for p in directory.iterdir() if p.name.casefold() in names) if directory.is_dir() else []


def check_task(task_dir: Path) -> dict[tuple[str, ...], object]:
    """Reject escaping file references, special files and unverified task features.

    Returns the accepted declarations that only native Harbor may run."""
    root = task_dir.resolve()
    for path in sorted(task_dir.rglob("*")):
        if path.is_symlink() and not path.resolve().is_relative_to(root):
            raise UnsupportedTask(f"{path.relative_to(task_dir)} points outside the task")
        if not (path.is_dir() or path.is_file()):
            raise UnsupportedTask(f"{path.relative_to(task_dir)} is not a regular file")
    # Harbor builds environments from these directories and merges a compose file found there
    # (harbor/models/task/verifier_mode.py, resolve_verifier_environment_definition). Names are
    # casefolded: a snapshot on a case-insensitive volume finds case variants under Harbor's names.
    # Only environment/docker-compose.yaml is admitted, the file Harbor's Docker environment merges.
    steps = [step for folder in named(task_dir, "steps") if folder.is_dir() for step in sorted(folder.iterdir())]
    # Compose also reads .env from its project directory, which Harbor sets to the environment
    # definition directory, and it can set Compose and Docker controls such as DOCKER_HOST. This
    # also closes a path older than compose task admission: compose already ran with environment/ as its project
    # directory.
    for directory in [*named(task_dir, "environment", "tests"), *(t for step in steps for t in named(step, "tests"))]:
        for path in named(directory, "docker-compose.yaml", "docker-compose.yml", ".env"):
            if (directory.name.casefold(), path.name.casefold()) != ("environment", "docker-compose.yaml"):
                raise UnsupportedTask(f"{path.relative_to(task_dir)} is not verified")
    compose = compose_services(task_dir)

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

    # Native Harbor gives the verifier the main environment's limit policies, which need both values.
    verifier = raw.get("verifier", {}).get("environment")
    if isinstance(verifier, dict):
        for key in ("cpus", "memory_mb"):
            if key not in verifier:
                raise UnsupportedTask(f"[verifier.environment].{key} is not declared, which native Harbor needs")
    config = Task(task_dir).config
    if isinstance(verifier, dict) and "build_timeout_sec" in verifier and (
            config.verifier.environment.build_timeout_sec != config.environment.build_timeout_sec):
        raise UnsupportedTask("[verifier.environment].build_timeout_sec is not verified unless it equals "
                              "[environment].build_timeout_sec, the bound native Harbor waits for the verifier")
    if compose:
        native_only[("environment", "docker-compose.yaml")] = compose
    # Native Harbor refuses such a task before it starts (Trial._validate_artifact_configuration);
    # a package probe would run the hook best-effort and grade without it.
    hooks = {hook.service for hook in config.verifier.collect if hook.service != MAIN_SERVICE_NAME}
    if missing := sorted((sidecar_services(config.artifacts) | hooks) - set(compose)):
        raise UnsupportedTask(f"service {missing[0]!r}, named by an artifact or a [verifier].collect hook, "
                              "is not a service of environment/docker-compose.yaml")
    # Harbor reads and writes manifest.json in its collection directory after the downloads,
    # through any link a download left there (harbor/trial/artifact_handler.py, _write_manifest).
    collection = Path("artifacts")
    for index, entry in enumerate(config.artifacts):
        artifact = ArtifactConfig(source=entry) if isinstance(entry, str) else entry
        host = artifact_host_path(collection, artifact)
        if host == collection or host.is_relative_to(collection / "manifest.json"):
            raise UnsupportedTask(f"artifacts[{index}] ({artifact.source}) is collected onto Harbor's artifacts directory or its manifest.json")
    dockerfile = task_dir / "environment" / "Dockerfile"
    if not config.environment.docker_image and not dockerfile.is_file():
        raise UnsupportedTask("the task declares no docker_image or environment/Dockerfile")
    return native_only


def compose_services(task_dir: Path) -> list[str]:
    """The services of the task's environment/docker-compose.yaml, main included, or [] without one.
    A file using anything but `services` with COMPOSE_SERVICE_KEYS is refused, and so is a build
    outside environment/, an environment entry without a value (compose would pass nudi's own),
    network_mode other than another service's, a capability other than SYS_PTRACE, and cpus or
    image on main, which would override the task's declared environment."""
    files = [file for environment in named(task_dir, "environment") for file in named(environment, "docker-compose.yaml")]
    services = {}
    for file in files:
        def refuse(what: str):
            raise UnsupportedTask(f"{file.relative_to(task_dir)}: {what} is not verified")

        try:
            document = yaml.safe_load(file.read_text())
        except yaml.YAMLError:
            refuse("a file that does not parse as YAML")
        # Compose interpolates the decoded strings, so an escape such as "\u0024{X}" is one too.
        try:
            texts = strings(document)
        except TypeError as error:
            refuse(f"a YAML {error} value")
        if any(INTERPOLATION.search(text.replace("$$", "")) for text in texts):
            refuse("variable interpolation")
        if not isinstance(document, dict) or set(document) != {"services"} or not isinstance(document["services"], dict):
            refuse("a top level other than one services table")
        root = file.parent.resolve()
        for name, service in document["services"].items():
            service = {} if service is None else service
            if not isinstance(service, dict):
                refuse(f"services.{name} that is not a table")
            for key in sorted(map(str, service.keys() - COMPOSE_SERVICE_KEYS)):
                refuse(f"services.{name}.{key}")
            if name == "main" and (overrides := sorted(service.keys() & {"cpus", "image"})):
                refuse(f"services.main.{overrides[0]}")
            build = service.get("build", {})
            build = {"context": build} if isinstance(build, str) else build
            if not isinstance(build, dict) or build.keys() - COMPOSE_BUILD_KEYS:
                refuse(f"services.{name}.build other than {sorted(COMPOSE_BUILD_KEYS)}")
            context = (root / str(build.get("context", "."))).resolve()
            dockerfile = (context / str(build.get("dockerfile", "Dockerfile"))).resolve()
            if not (context.is_dir() and context.is_relative_to(root) and dockerfile.is_relative_to(root)):
                refuse(f"services.{name}.build outside environment/")
            environment = service.get("environment", [])
            entries = environment.values() if isinstance(environment, dict) else [
                item if isinstance(item, str) and "=" in item else None for item in environment]
            if any(item is None for item in entries):
                refuse(f"services.{name}.environment entry without a value")
            if not str(service.get("network_mode", "service:")).startswith("service:"):
                refuse(f"services.{name}.network_mode other than service:<name>")
            if set(service.get("cap_add", [])) - {"SYS_PTRACE"}:
                refuse(f"services.{name}.cap_add other than SYS_PTRACE")
            services[name] = service
    return sorted({"main", *services}) if files else []


def strings(node) -> list[str]:
    """Every string in a decoded YAML document, keys included. Any value but a string, number,
    boolean, null, table or list raises TypeError: PyYAML decodes tags such as !!binary and !!set
    to other types, which compose-go reads as text."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [text for key, value in node.items() for text in strings(key) + strings(value)]
    if isinstance(node, list):
        return [text for item in node for text in strings(item)]
    if node is None or isinstance(node, (bool, int, float)):
        return []
    raise TypeError(type(node).__name__)


HELPER_STATE = (" Helper-service state is not copied: a copy is the grading container's filesystem only, so a helper's "
                "files absent from it are unavailable evidence, never missing work.")


def check_backend(task_dir: Path, backend: Backend) -> None:
    """Refuse what nudi admits on one backend only: a compose file on Modal, where Harbor would select
    Docker-in-Docker, and GPUs on Docker."""
    if backend == "modal" and compose_services(task_dir):
        raise UnsupportedTask("environment/docker-compose.yaml is not verified on Modal")
    config = Task(task_dir).config
    if backend == "docker":
        for name, environment in (("environment", config.environment), ("verifier.environment", config.verifier.environment)):
            if environment is not None and environment.gpus:
                raise UnsupportedTask(f"[{name}].gpus = {environment.gpus} is not verified on Docker")


def select_path(
    task_dir: Path, native: frozenset[NativeBehavior]
) -> tuple[ExecutionPath, list[str]]:
    """The execution path and the reasons for it, decided before anything starts."""
    native_only = check_task(task_dir)
    storage = [STORAGE.format(label(path), value) for path, value in native_only.items() if path[-1] == "storage_mb"]
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


verification_hook: ContextVar[Callable[[TrialHookEvent], Awaitable[None]] | None] = ContextVar("nudi_verification", default=None)
dropped_links: ContextVar[Callable[[list[str]], None] | None] = ContextVar("nudi_dropped_links", default=None)
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


def drop_links(directory: Path) -> list[str]:
    """Remove every symlink, hardlinked file and entry that is neither a regular file nor a directory
    under `directory`, without following links, and return their relative paths. Collected artifacts are
    copied out of an untrusted container, and Harbor's upload follows links to host paths."""
    removed = []
    for root, directories, files in os.walk(directory):
        for name in [*directories, *files]:
            path = Path(root, name)
            status = path.lstat()
            # A hardlink looks regular, so its link count gives it away.
            if not (stat.S_ISDIR(status.st_mode) or (stat.S_ISREG(status.st_mode) and status.st_nlink == 1)):
                path.unlink()
                removed.append(path.relative_to(directory).as_posix())
        directories[:] = [name for name in directories if Path(root, name).is_dir()]
    return sorted(removed)


async def capture_at_verification(event: TrialHookEvent) -> None:
    # A separate verifier uploads the collected artifacts after this event; the agent environment has stopped.
    if resolve_task_verifier_mode(Task(event.config.task.path).config) == VerifierEnvironmentMode.SEPARATE:
        removed = drop_links(TrialPaths(event.config.trials_dir / event.config.trial_name).artifacts_dir)
        if removed and (warn := dropped_links.get()):
            warn(removed)
    await _run_hook(verification_hook.get(), event)


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


MODAL_BOX = "nudi.modal_box:ModalBox"


def environment_config(backend: Backend, cpus: int | None, memory_mb: int | None) -> EnvironmentConfig:
    """Harbor's environment for `backend`, Docker or nudi's `ModalBox`. Each declared CPU and
    memory value is a hard limit on both: Harbor's Docker default, and on Modal a small
    request under that limit. An undeclared value keeps Harbor's default, which on Modal is
    no limit."""
    def mode(declared: int | None) -> ResourceMode:
        return ResourceMode.AUTO if declared is None else ResourceMode.LIMIT

    where = {"type": EnvironmentType.DOCKER} if backend == "docker" else {"import_path": MODAL_BOX}
    return EnvironmentConfig(**where, cpu_enforcement_policy=mode(cpus), memory_enforcement_policy=mode(memory_mb))


async def run_harbor(config: EpisodeConfig, task_dir: Path, result: EpisodeResult, queue: TrialQueue, agent: AgentConfig | None = None) -> None:
    ensure_lifecycle_hooks(queue)
    kwargs = {"api_base": config.api_base, "reasoning_effort": config.reasoning_effort}
    if config.model.startswith("xiaomi_mimo/") and config.reasoning_effort not in (None, "none"):
        # MiMo Chat thinks only when asked through this field; the effort is still sent.
        kwargs["llm_call_kwargs"] = {"extra_body": {"thinking": {"type": "enabled"}}}
    # Harbor builds a separate verifier environment from the same settings.
    declared = Task(task_dir).config
    trial_config = TrialConfig(
        task=TaskConfig(path=task_dir),
        trials_dir=config.output_dir / "harbor",
        environment=environment_config(config.backend, declared.environment.cpus, declared.environment.memory_mb),
        verifier=VerifierConfig(import_path="nudi.runner:RewardVerifier",
                                override_timeout_sec=grading_bound(declared.verifier.timeout_sec)),
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
                      agent: AgentConfig | None = None, copy=None, on_verification=None, on_agent_start=None,
                      on_trial_end=None, credentials: Path | None = None) -> EpisodeResult:
    """Run one episode on a disposable task snapshot; the record is written even on failure.

    Native Harbor episodes run through `queue`, shared by a run, or a queue of their own.
    `copy` is the `state_copy` callback of a native episode; the hooks run at Harbor's
    lifecycle events. `credentials` is the run's credentials file, which the snapshot refuses."""
    check_output(config.output_dir, config.task_dir)
    path, reasons = select_path(config.task_dir, config.native)
    check_backend(config.task_dir, config.backend)
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
    copy_token = state_copy.set(copy)
    token = verification_hook.set(on_verification)
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
    except (asyncio.CancelledError, KeyboardInterrupt):  # KeyboardInterrupt: a second Ctrl-C
        result.cancelled = True
        raise
    except Exception as error:
        result.errors.append(ErrorRecord(type=type(error).__name__, message=str(error)))
        raise
    finally:
        state_copy.reset(copy_token)
        verification_hook.reset(token)
        agent_start_capture.reset(agent_token)
        trial_end_capture.reset(end_token)
        if (config.output_dir / "nudi-evidence").is_dir():
            result.artifacts["nudi_evidence"] = "nudi-evidence"
        write_private(config.output_dir / "episode.json", result.model_dump_json(indent=2))
        for tree in ("harbor", "verifiers"):
            restrict(config.output_dir / tree)
    return result
