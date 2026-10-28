"""Shared run state: models and credentials for each role, Docker capacity and the
optional spending cap, applied to every episode and model call of one run.

Episodes keep the original grading and harness, which selects native Harbor, and run
through one Harbor TrialQueue sized by the capacity check. A LiteLLM callback,
registered once, acts only on calls made inside `model_calls`: it supplies that role's
credential, refuses new calls once the run's known cost reaches its cap, and records
each call's usage and estimated cost.
"""

import asyncio
import contextlib
import logging
import os
import subprocess
import tomllib
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_args

import litellm
from dotenv import dotenv_values
from harbor.models.task.task import Task
from harbor.trial.queue import TrialQueue
from litellm.integrations.custom_logger import CustomLogger
from litellm.litellm_core_utils.get_model_cost_map import get_model_cost_map_source_info

from nudi.records import (
    DEFAULT_MODELS,
    CallRecord,
    CaptureFailure,
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
)
from nudi.runner import UnsupportedTask, check_output, episode_queue, run_episode, select_path

ROLES: frozenset[Role] = frozenset(DEFAULT_MODELS)
# Requesting every behavior the adapter changes keeps the original grading and harness.
ORIGINAL_BEHAVIOR: frozenset[NativeBehavior] = frozenset(get_args(NativeBehavior))
LIMITATIONS = [
    "Concurrency uses 90% of Docker's CPUs and memory against the task's declarations. "
    "This is not a guarantee: image builds, Docker itself, host processes and the host-side "
    "Terminus 2 harness are not bounded by declarations.",
    "The spending cap is checked when a call is admitted. Calls admitted before known cost "
    "reaches the cap finish and may exceed the cap. Calls of unknown cost do not count toward it. "
    "Terminus 2 and Harbor's LiteLLM wrapper retry a refused call with backoff, up to 9 attempts, "
    "so the episode's agent ends on the refusal or on its own deadline; Harbor still grades the "
    "actual task state after an agent deadline.",
    "Harbor's whole-episode retries are disabled, so every attempted episode stays recorded. "
    "Terminus 2 and Harbor's LiteLLM wrapper each retry a failed request up to 3 attempts; "
    "each sent attempt is a call.",
]
MIMO_LIMITATION = (
    "MiMo requests enable thinking explicitly and send the requested reasoning effort; "
    "whether MiMo gives differentiated intensity for that effort is unverified."
)
OVERSHOOT = "known cost exceeded the spending cap: calls admitted before it was reached finished"

logger = logging.getLogger("nudi")


class CapacityError(RuntimeError):
    """One episode cannot fit Docker's capacity, so the run does not start."""


class MissingCredential(ValueError):
    """A requested role has no credential, so the run does not start."""


class SpendingCapReached(RuntimeError):
    """Known cost reached the run's spending cap, so no new call or episode starts."""


def docker_capacity() -> tuple[int, int]:
    """Docker's CPUs and memory in MiB, as the daemon reports them."""
    info = subprocess.run(
        ["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"], capture_output=True, text=True, check=True
    )
    cpus, memory = info.stdout.split()
    return int(cpus), int(memory) // 2**20


def declared_requirements(task_dir: Path) -> tuple[int | None, int | None]:
    """Declared CPUs and memory_mb of one episode's largest container; None when undeclared.

    The raw TOML decides whether a value is declared; Harbor's parsed config supplies it,
    converting the legacy `memory` string. A separate grader runs after the task
    container with a copy of its environment (an explicit `[verifier.environment]` and
    Compose helpers are rejected as unverified), so the larger requirement is the task's.
    """
    raw = tomllib.loads((task_dir / "task.toml").read_text()).get("environment", {})
    environment = Task(task_dir).config.environment
    cpus = environment.cpus if "cpus" in raw else None
    memory_mb = environment.memory_mb if {"memory_mb", "memory"} & raw.keys() else None
    return cpus, memory_mb


def plan_concurrency(
    docker_cpus: int, docker_memory_mb: int, cpus: int | None, memory_mb: int | None
) -> tuple[int, list[str]]:
    """Episodes to run at once within 90% of Docker's capacity, and the warnings."""
    for name, need, have in (("CPUs", cpus, docker_cpus), ("MiB of memory", memory_mb, docker_memory_mb)):
        if need is not None and need <= 0:
            raise ValueError(f"one episode declares {need} {name}; a declared value must be positive")
        if need is not None and need > have:
            raise CapacityError(f"one episode declares {need} {name}, which exceeds Docker's {have}")
    if cpus is None or memory_mb is None:
        return 1, [
            "the task does not declare both cpus and memory_mb, so fit cannot be established: "
            "episodes run one at a time and even one may exhaust Docker's memory"
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

    def save(self) -> None:
        (self.config.output_dir / "run.json").write_text(self.record.model_dump_json(indent=2))

    def warn(self, message: str) -> None:
        if message not in self.record.warnings:
            self.record.warnings.append(message)
            logger.warning(message)

    def check_cap(self) -> None:
        cap = self.record.spending_cap
        if cap is not None and self.record.known_cost >= cap:
            raise SpendingCapReached(f"known cost ${self.record.known_cost:.6f} reached the spending cap ${cap}")

    def check_sandboxes_closed(self) -> None:
        """Admit another container only after every Inspector sandbox was removed."""
        for name in self.record.sandboxes:
            path = self.config.output_dir / "sandboxes" / name / "sandbox.json"
            result = SandboxResult.model_validate_json(path.read_text())
            if result.cleanup.get("removed") is not True:
                raise InfrastructureAbort(f"{name}: sandbox removal is unverified; another container cannot start")


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


def start_run(config: RunConfig, roles: frozenset[Role] = ROLES) -> Run:
    """Settle models, credentials, path and capacity for `roles` before any episode starts."""
    check_output(config.output_dir, config.task_dir)
    # Copies, so a change to one run's models reaches no default or other run.
    models = {role: model.model_copy() for role, model in {**DEFAULT_MODELS, **config.models}.items()}
    keys, sources = resolve_credentials(config, models, roles)
    path, reasons = select_path(config.task_dir, ORIGINAL_BEHAVIOR)
    if path != "harbor":
        raise UnsupportedTask("run-level credentials and spending controls cover native Harbor only")
    docker_cpus, docker_memory_mb = docker_capacity()
    cpus, memory_mb = declared_requirements(config.task_dir)
    concurrency, warnings = plan_concurrency(docker_cpus, docker_memory_mb, cpus, memory_mb)
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
        ),
        cost_map=get_model_cost_map_source_info(),
        warnings=warnings,
        limitations=LIMITATIONS + [MIMO_LIMITATION] * mimo,
    )
    for warning in warnings:
        logger.warning(warning)
    if not any(isinstance(callback, RunCalls) for callback in litellm.callbacks):
        litellm.callbacks.append(RunCalls())
    config.output_dir.mkdir(parents=True, exist_ok=True)
    run = Run(config, record, episode_queue(concurrency), keys)
    run.save()
    return run


# The run, role and episode of the model calls made in this context.
current: ContextVar[tuple[Run, Role, str] | None] = ContextVar("nudi_run_calls", default=None)


@contextlib.contextmanager
def model_calls(run: Run, role: Role, episode: str):
    """Apply the run's credential, cap and accounting to LiteLLM calls made inside."""
    token = current.set((run, role, episode))
    try:
        yield
    finally:
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
                refusals: list[str] | None = None) -> None:
    model = request["model"]
    usage = getattr(response, "usage", None)
    cost, source = None, "unknown: the request failed"
    if response is not None:
        try:
            cost, source = litellm.completion_cost(completion_response=response, model=model), "litellm.completion_cost"
        except Exception as failure:
            source = f"unknown: {type(failure).__name__}: {failure}"
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
        )
    )
    if cost is None:
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
        return {**kwargs, "api_key": run.keys[role]}

    async def async_post_call_success_deployment_hook(self, request_data, response, call_type):
        if (scope := current.get()) is not None:
            record_call(*scope, request_data, response=response, refusals=refusal_signals(response))

    async def async_post_call_failure_deployment_hook(self, request_data, exception, call_type, fallback_depth=None):
        if (scope := current.get()) is not None:
            refusals = [type(exception).__name__] if isinstance(exception, litellm.ContentPolicyViolationError) else []
            record_call(*scope, request_data, error=type(exception).__name__, refusals=refusals)


async def run_role_episode(run: Run, role: Role, *, instruction: str | None = None,
                           capture_locations: list[str] | None = None, agent=None,
                           on_agent_start=None, on_trial_end=None, on_verification=None,
                           probe: bool = False) -> EpisodeResult:
    """Run one episode of `role` through the run's queue, under its credential and cap.

    Its lifecycle events record execution order. `finished` means the runner returned;
    Harbor may return after a failed environment stop. Neither return nor ordering
    establishes successful teardown or a normal reset.

    The Inspector is never a native task actor; it executes only in sandboxes of a package copy."""
    if role == "inspector":
        raise ValueError("the Inspector never runs as a native task actor; use an Inspector sandbox")
    if capture_locations:
        from nudi.checks import capture_location_problem

        for location in capture_locations:
            if problem := capture_location_problem(location):
                raise ValueError(f"capture of {location!r} rejected before native episode: {problem}")
    run.check_cap()
    run.check_sandboxes_closed()
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
    )
    try:
        capture = None
        if capture_locations or on_verification is not None:
            from nudi.checks import protected_capture

            async def capture(event):
                if on_verification is not None:
                    try:
                        await on_verification(event)
                    except InfrastructureAbort:
                        raise
                    except Exception as error:
                        message = str(error)
                        for secret in run.keys.values():
                            message = message.replace(secret, "[redacted]")
                        run.warn(f"{name}: verification observation failed: {type(error).__name__}: {message}")
                for location in capture_locations or []:
                    try:
                        submission = await protected_capture(event, name, config.output_dir, location)
                        run.record.submissions.append(submission)
                    except Exception as error:
                        message = str(error)
                        for secret in run.keys.values():
                            message = message.replace(secret, "[redacted]")
                        run.record.capture_errors.append(CaptureFailure(episode=name, location=location,
                            error=ErrorRecord(type=type(error).__name__, message=message)))
                        run.warn(f"{name}: capture of {location} failed: {type(error).__name__}: {error}")
                        if isinstance(error, InfrastructureAbort):
                            raise
                    finally:
                        run.save()
        with model_calls(run, role, name):
            if instruction is None and agent is None and capture is None and on_agent_start is None and on_trial_end is None:
                result = await run_episode(config, run.queue)
            else:
                result = await run_episode(config, run.queue, instruction=instruction, agent=agent, capture=capture,
                                           on_agent_start=on_agent_start, on_trial_end=on_trial_end)
        run.record.events.append(EpisodeEvent(episode=name, event="finished"))
        return result
    finally:
        run.save()


async def simulate(run: Run, episodes: int = 20) -> Simulation:
    """Run `episodes` ordinary Simulator episodes of the original task and harness.

    Every count takes this path. As many workers as the run's queue runs at once admit
    an episode only while the spending cap allows; admitted episodes finish. Failed
    episodes stay recorded and are not retried. The run's capture selection, made before
    the first episode, is captured at verification start for grader inspection, which
    reuses this pool."""
    from nudi.checks import capture_selection, redacted

    if type(episodes) is not int or episodes < 1:
        raise ValueError("episodes must be a positive integer")
    simulation = Simulation(requested=episodes)
    run.record.simulation = simulation
    run.save()

    async def worker():
        while len(simulation.episodes) < episodes:
            try:
                run.check_cap()
            except SpendingCapReached:
                simulation.status = "spending_exhausted"
                return
            # run_role_episode assigns this name before its first await.
            name = f"{len(run.record.episodes):04d}-simulator"
            simulation.episodes.append(name)
            try:
                result = await run_role_episode(run, "simulator", capture_locations=locations)
                if result.errors:
                    simulation.failures[name] = [error.model_copy(update={"message": redacted(run, error.message)})
                                                 for error in result.errors]
            except Exception as error:
                simulation.failures[name] = [ErrorRecord(type=type(error).__name__, message=redacted(run, str(error)))]
            finally:
                if refusals := [signal for call in run.record.calls if call.episode == name for signal in call.refusals]:
                    simulation.refusals[name] = refusals
                run.save()

    try:
        locations = [item.source for item in (await capture_selection(run)).files if item.selected]
        await asyncio.gather(*(worker() for _ in range(min(episodes, run.record.capacity.concurrency))))
        if simulation.status == "running":
            simulation.status = "partial" if simulation.failures else "complete"
    except asyncio.CancelledError:
        simulation.status = "cancelled"
        raise
    finally:
        run.save()
    return simulation
