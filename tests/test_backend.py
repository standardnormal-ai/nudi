"""The backend switch and the concurrency setting.

Harbor 0.24.0's real Docker and Modal environment classes and its real Trial run here. Only
external operations are replaced: Docker's daemon and CLI, and the Modal SDK calls
`App.lookup`, `Sandbox.create`, `terminate` and `poll` (with the sandbox's exec and file
copy). No test calls Modal or Docker, and none needs a Modal account.
"""

import asyncio
import errno
import json
import logging
import os
import socket
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import litellm
import pytest
from harbor.environments import modal as harbor_modal
from harbor.environments.base import ExecResult
from harbor.environments.docker.docker import DockerEnvironment
from harbor.environments.factory import EnvironmentFactory
from harbor.models.environment_type import EnvironmentType
from harbor.models.task.task import Task
from harbor.models.task.verifier_mode import resolve_verifier_environment_definition
from harbor.models.trial.config import EnvironmentConfig, ResourceMode
from harbor.models.trial.paths import TrialPaths
from harbor.trial.trial import Trial
from pydantic import ValidationError

from nudi import checks, cli, episode, inspector_sandbox, modal_env, persistence, records, report, run_state, send
from nudi.records import DiskFull, EpisodeConfig, EpisodeResult, ModalSandbox, RunConfig, RunRecord
from test_inspection import Sandboxes, sandbox_record
from test_limits import credentials, new_run  # noqa: F401  (pytest fixture)
from test_runner import CONTRACT_TASK, SEPARATE_TASK, VERIFIER_ENVIRONMENT, task_with

try:
    import modal as modal_sdk
    from grpclib.metadata import encode_metadata
except ImportError:  # Without the modal extra, the tests that drive Harbor's Modal environment skip.
    modal_sdk = None
needs_modal = pytest.mark.skipif(modal_sdk is None, reason="needs the modal extra: pip install 'nudi[modal]'")

TOKEN_ID, TOKEN_SECRET = "ak-nudi-sentinel-modal-token-id", "as-nudi-sentinel-modal-token-secret"


class Aio:
    """One Modal SDK method; Harbor and nudi call its `.aio` form."""

    def __init__(self, function):
        self.aio = function


async def value(result):
    return result


def leak():
    """Raise grpclib's real error for Modal's credential metadata with a newline; its text quotes the secret."""
    encode_metadata({"x-modal-token-id": TOKEN_ID, "x-modal-token-secret": TOKEN_SECRET + "\n"})


class FakeSandbox:
    """A Modal sandbox that ends after `terminations` terminate calls; None never ends.
    Each operation named in `fail` raises `leak()`; "body-exec" fails only a command
    containing "nudi-leak". With `hang`, `wait` never returns. A command containing "nudi-bytes"
    prints output that is not UTF-8, which Modal's text mode fails to decode."""

    def __init__(self, object_id, terminations, entrypoint, kwargs, fail=(), hang=False):
        self.object_id, self.terminations, self.entrypoint, self.kwargs = object_id, terminations, entrypoint, kwargs
        self.fail, self.hang = fail, hang
        self.terminate_calls, self.commands, self.copies = 0, [], []
        self.exec, self.terminate, self.poll, self.wait = Aio(self._exec), Aio(self._terminate), Aio(self._poll), Aio(self._wait)
        self.filesystem = SimpleNamespace(copy_from_local=Aio(self._copy))

    @property
    def running(self) -> bool:
        return self.terminations is None or self.terminate_calls < self.terminations

    async def _exec(self, *argv, text=True, **kwargs):
        self.commands.append(" ".join(argv))
        if "exec" in self.fail or ("body-exec" in self.fail and "nudi-leak" in argv[-1]):
            leak()
        data = b"half \xff\n" if "nudi-bytes" in argv[-1] else b""
        return SimpleNamespace(stdout=SimpleNamespace(read=Aio(lambda: value(data.decode() if text else data))),
                               stderr=SimpleNamespace(read=Aio(lambda: value("" if text else b""))), wait=Aio(lambda: value(0)))

    async def _copy(self, source, target):
        self.copies.append(target)

    async def _terminate(self, *, wait=False):
        if "terminate" in self.fail:
            leak()
        self.terminate_calls += 1
        return 137 if wait and not self.running else None

    async def _poll(self):
        if "poll" in self.fail:
            leak()
        return None if self.running else 137

    async def _wait(self, *, raise_on_termination=True):
        if self.hang:
            await asyncio.Event().wait()


class Modal:
    """Replaces Modal's `App` and `Sandbox` in Harbor's Modal module and records each sandbox."""

    def __init__(self, monkeypatch, terminations=1, fail=(), hang=False):
        self.terminations, self.fail, self.hang, self.created, self.apps = terminations, fail, hang, [], []
        monkeypatch.setattr(harbor_modal, "App", SimpleNamespace(lookup=Aio(self.lookup)))
        monkeypatch.setattr(harbor_modal, "Sandbox", SimpleNamespace(create=Aio(self.create)))
        # Harbor's sandbox creation sets this variable; monkeypatch removes it afterwards.
        monkeypatch.setenv("MODAL_SANDBOX_V2", "1")

    async def lookup(self, name, create_if_missing):
        self.apps.append(name)
        return SimpleNamespace(name=name)

    async def create(self, *entrypoint, **kwargs):
        if "create" in self.fail:
            leak()
        box = FakeSandbox(f"sb-{len(self.created)}", self.terminations, entrypoint, kwargs, self.fail, self.hang)
        self.created.append(box)
        return box


def no_docker(monkeypatch):
    """A Modal run must never ask Docker anything."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"Docker was called on Modal: {args}")

    async def refuse_command(command, **kwargs):
        raise AssertionError(f"Docker command on Modal: {command}")

    monkeypatch.setattr(run_state, "docker_capacity", refuse)
    monkeypatch.setattr(checks, "host_command", refuse_command)
    monkeypatch.setattr(persistence, "host_command", refuse_command)


def modal_login(tmp_path, monkeypatch):
    """Sentinel Modal credentials in the environment and a home without `.modal.toml`."""
    (tmp_path / "home").mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MODAL_TOKEN_ID", TOKEN_ID)
    monkeypatch.setenv("MODAL_TOKEN_SECRET", TOKEN_SECRET)


def modal_run(tmp_path, monkeypatch, **fields):
    modal_login(tmp_path, monkeypatch)
    no_docker(monkeypatch)
    fields.setdefault("task_dir", CONTRACT_TASK)
    return run_state.start_run(RunConfig(output_dir=tmp_path / "run", backend="modal", **fields), frozenset())


def stored(run) -> RunRecord:
    return RunRecord.model_validate_json((run.config.output_dir / "run.json").read_text())


def assert_no_modal_credential(directory):
    for path in directory.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert TOKEN_ID.encode() not in data and TOKEN_SECRET.encode() not in data, path


class Queue:
    """Captures the TrialConfig nudi submits instead of running it."""

    _nudi_lifecycle_registered = True

    async def submit(self, config):
        self.config = config


def trial_config(tmp_path, backend, task=CONTRACT_TASK):
    queue = Queue()
    config = EpisodeConfig(task_dir=task, output_dir=tmp_path / backend, model="xai/grok-4.7",
                           api_key_var="XAI_API_KEY", backend=backend)
    result = EpisodeResult(path="harbor", path_reasons=[], task_name=task.name, task_dir=str(task), task_digest="",
                           model=config.model, reasoning_effort=None, versions={})
    asyncio.run(episode.run_harbor(config, task, result, queue))
    return queue.config


# Docker stays the default; a native episode changes only how its Compose commands end.


def test_docker_is_the_default_and_its_resource_compose_file_is_unchanged(tmp_path):
    config = RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "run")
    assert (config.backend, config.concurrency) == ("docker", 16)
    native = trial_config(tmp_path, "docker").environment
    assert (native.type, native.import_path) == (None, "nudi.episode:NativeDocker")
    assert native.cpu_enforcement_policy == native.memory_enforcement_policy == ResourceMode.LIMIT
    task = Task(CONTRACT_TASK)

    def resources(environment, name):
        paths = TrialPaths(tmp_path / name)
        paths.mkdir()
        box = EnvironmentFactory.create_environment_from_config(
            config=environment, environment_dir=task.paths.environment_dir, environment_name=task.short_name,
            session_id="nudi-test", trial_paths=paths, task_env_config=task.config.environment)
        assert isinstance(box, DockerEnvironment)
        return asyncio.run(box._write_resources_compose_file()).read_text()

    assert resources(native, "nudi") == resources(EnvironmentConfig(type=EnvironmentType.DOCKER), "harbor")
    # An undeclared value keeps Harbor's default, which a hard limit would refuse.
    undeclared = episode.environment_config("modal", None, 512)
    assert (undeclared.cpu_enforcement_policy, undeclared.memory_enforcement_policy) == (ResourceMode.AUTO, ResourceMode.LIMIT)


def test_a_native_docker_episode_is_removed_at_once(tmp_path, monkeypatch):
    """PID 1 of Harbor's main service, `sh -c "sleep infinity"`, ignores SIGTERM, so a plain `down`
    waits Docker's 10 s stop timeout. Harbor's own Compose runner is replaced."""
    commands = []

    async def compose(self, command, check=True, **kwargs):
        commands.append(command)
        return ExecResult(stdout="", stderr="", return_code=0)

    monkeypatch.setattr(DockerEnvironment, "_run_docker_compose_command", compose)
    task = Task(CONTRACT_TASK)
    paths = TrialPaths(tmp_path / "trial")
    paths.mkdir()
    box = EnvironmentFactory.create_environment_from_config(
        config=trial_config(tmp_path, "docker").environment, environment_dir=task.paths.environment_dir,
        environment_name=task.short_name, session_id="nudi-test", trial_paths=paths, task_env_config=task.config.environment)
    assert type(box) is episode.NativeDocker
    asyncio.run(box.stop(delete=True))
    assert commands[-1] == ["down", "--timeout", "0", "--rmi", "local", "--volumes", "--remove-orphans"]


def test_backend_and_concurrency_come_from_the_cli_the_api_and_the_file(tmp_path, monkeypatch, credentials):
    seen = []

    def start_run(config, roles, analyses):
        seen.append((config.backend, config.concurrency))
        raise ValueError("stopped after configuration")

    monkeypatch.setattr(send, "start_run", start_run)
    file = tmp_path / "nudi.toml"
    file.write_text('backend = "modal"\nconcurrency = 5\n')
    assert cli.main(["send-nudis", str(CONTRACT_TASK), "--output", str(tmp_path / "a"),
                     "--backend", "modal", "--concurrency", "3"]) == 2
    for call in (lambda: send.send_nudis(CONTRACT_TASK, output_dir=tmp_path / "b", backend="modal", concurrency=4),
                 lambda: send.send_nudis(CONTRACT_TASK, file, output_dir=tmp_path / "c")):
        with pytest.raises(ValueError, match="stopped"):
            call()
    assert seen == [("modal", 3), ("modal", 4), ("modal", 5)]
    for bad in ({"backend": "podman"}, {"concurrency": 0}, {"concurrency": "8"}):
        with pytest.raises(ValidationError):
            RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "d", **bad)
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=3)
    assert (stored(run).backend, stored(run).capacity.concurrency_setting) == ("docker", 3)


def test_docker_admission_also_respects_the_concurrency_setting(tmp_path, monkeypatch, credentials):
    """Docker's capacity fits seven episodes; a setting of one caps the queue and the containers: the second waits for
    the first to end, and the bound cancels it first."""
    Sandboxes(monkeypatch)

    async def probe(run):
        async with inspector_sandbox.sandbox(run, "probe"):
            pass

    async def nested(run, bound):
        async with inspector_sandbox.sandbox(run, "check"):
            await asyncio.wait_for(probe(run), bound)

    free = new_run(tmp_path, monkeypatch, credentials, name="free", capacity=(8, 16384))
    asyncio.run(nested(free, 5))
    capped = new_run(tmp_path, monkeypatch, credentials, name="capped", capacity=(8, 16384), concurrency=1)
    assert (free.record.capacity.concurrency, capped.record.capacity.concurrency) == (7, 1)
    with pytest.raises(TimeoutError):
        asyncio.run(nested(capped, 0.2))
    assert (len(free.record.sandboxes), len(capped.record.sandboxes)) == (2, 1)


# Modal: startup, admission, resources, removal, cost, credentials.


@pytest.mark.parametrize("failure", [pytest.param("no credential", marks=needs_modal), "no extra", pytest.param("load failure", marks=needs_modal)])
def test_failed_modal_preflight_stops_before_any_model_call_with_exit_code_2(tmp_path, monkeypatch, credentials, capsys, failure):
    """A load failure stands for the Modal SDK refusing an unreadable profile on import: its text can quote the file."""
    modal_login(tmp_path, monkeypatch)
    if failure == "no credential":
        monkeypatch.delenv("MODAL_TOKEN_ID")
        monkeypatch.delenv("MODAL_TOKEN_SECRET")
    elif failure == "no extra":
        monkeypatch.setattr(harbor_modal, "_HAS_MODAL", False)
    else:
        (tmp_path / "nudi_broken_modal.py").write_text(
            f"from modal.exception import InvalidError\nraise InvalidError('cannot read token_secret = {TOKEN_SECRET}')\n")
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.setattr(run_state, "MODAL_BOX", "nudi_broken_modal:ModalBox")
    no_docker(monkeypatch)

    async def no_model_call(*args, **kwargs):
        raise AssertionError("a model was called")

    monkeypatch.setattr(litellm, "acompletion", no_model_call)
    code = cli.main(["send-nudis", str(CONTRACT_TASK), "--output", str(tmp_path / "run"), "--backend", "modal",
                     "--credentials-file", str(credentials)])

    error = capsys.readouterr().err
    assert code == 2 and error.startswith("nudi: Modal is unavailable: ")
    expected = {"no credential": "modal token new", "no extra": "pip install -e '.[modal]'", "load failure": "InvalidError"}
    assert expected[failure] in error and TOKEN_SECRET not in error
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize("block", ["no Modal SDK", "unreadable Modal profile"])
def test_importing_nudi_and_starting_docker_never_import_the_modal_sdk(tmp_path, block):
    profile = tmp_path / "modal.toml"
    profile.write_text("[broken\n")
    program = "\n".join([
        "import sys",
        "sys.modules['modal'] = None" if block == "no Modal SDK" else "",
        "import nudi, nudi.send, nudi.checks, nudi.inspection, nudi.attack, nudi.persistence, nudi.cli, nudi.report, nudi.episode, nudi.inspector_sandbox, nudi.run_state",
        "from pathlib import Path",
        "from harbor.environments.factory import EnvironmentFactory",
        "from harbor.models.task.task import Task",
        "from harbor.models.trial.paths import TrialPaths",
        f"task, paths = Task(Path({str(CONTRACT_TASK)!r})), TrialPaths(Path({str(tmp_path / 'trial')!r}))",
        "paths.mkdir()",
        "EnvironmentFactory.create_environment_from_config(config=nudi.episode.environment_config('docker', 1, 512),",
        "    environment_dir=task.paths.environment_dir, environment_name=task.short_name, session_id='nudi-test',",
        "    trial_paths=paths, task_env_config=task.config.environment)",
        "loaded = {'modal', 'harbor.environments.modal', 'nudi.modal_env'} & set(sys.modules)",
        "assert not loaded or sys.modules.get('modal', 0) is None and loaded == {'modal'}, loaded",
    ])
    environment = {**os.environ, "MODAL_CONFIG_PATH": str(profile), "PYTHONPATH": str(Path(inspector_sandbox.__file__).parents[1])}
    done = subprocess.run([sys.executable, "-c", program], env=environment, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


@needs_modal
def test_modal_run_records_its_backend_and_never_asks_docker(tmp_path, monkeypatch):
    run = modal_run(tmp_path, monkeypatch, concurrency=3)
    record = stored(run)
    assert record.backend == "modal"
    capacity = record.capacity
    assert (capacity.docker_cpus, capacity.docker_memory_mb, capacity.concurrency, capacity.concurrency_setting) == (None, None, 3, 3)
    assert run.queue._semaphore._value == 3
    assert any("Modal" in limitation and "spending cap" in limitation for limitation in record.limitations)
    assert not any("90% of Docker" in limitation for limitation in record.limitations)

    episodes = []

    async def native(config, queue, **kwargs):
        episodes.append(config)
        return SimpleNamespace()

    monkeypatch.setattr(run_state, "run_episode", native)
    asyncio.run(run_state.run_role_episode(run, "simulator"))
    assert [config.backend for config in episodes] == ["modal"]


@pytest.mark.parametrize(("environment", "override", "expected"), [
    ("cpus = 1\nmemory_mb = 4096", None, 4096),
    ("cpus = 1", None, None),
    ("cpus = 1\nmemory_mb = 4096", 1600, 1600),
])
@needs_modal
def test_a_modal_workspace_has_the_task_memory_unless_set(tmp_path, monkeypatch, environment, override, expected):
    """512 MiB workspaces ran out of memory in 4 of 5 measured Modal runs. On Modal no workspace
    shares a host with an experiment, so it keeps the task's limit as experiments do."""
    task = task_with(tmp_path, CONTRACT_TASK, f'schema_version = "1.4"\n[environment]\ndocker_image = "python:3.12-slim"\n{environment}\n')
    record = stored(modal_run(tmp_path, monkeypatch, task_dir=task, workspace_memory_mb=override))
    assert record.capacity.workspace_memory_mb == expected
    assert not any("512 MiB" in limitation for limitation in record.limitations)


@pytest.mark.parametrize(("terminations", "removed"), [(1, True), (2, True), (None, False)])
@needs_modal
def test_modal_sandbox_has_hard_limits_and_verified_removal(tmp_path, monkeypatch, terminations, removed):
    """Harbor's stop terminates once; a sandbox still running is terminated once more, and one
    that stays is recorded with a warning. Removal is checked through Modal, not `docker ps`."""
    modal = Modal(monkeypatch, terminations)
    run = modal_run(tmp_path, monkeypatch)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe"):
            pass

    asyncio.run(main())
    box, = modal.created
    assert (box.kwargs["cpu"], box.kwargs["memory"]) == ((0.125, 1), (128, 512))
    # The verifier directory is created inside the sandbox; Modal ignores the host side of the mount.
    assert any("/logs/verifier" in command for command in box.commands)
    assert box.terminate_calls == min(terminations or 2, 2)
    assert modal.apps == [f"nudi-{stored(run).run_id}"], "each run's sandboxes share one App named for the run"
    record = sandbox_record(run, "sandbox-0000")
    assert record["environment"]["type"] == "modal"
    assert record["environment"]["cpu_enforcement"] == record["environment"]["memory_enforcement"] == "limit"
    assert record["cleanup"] == {"sandbox_id": "sb-0", "removed": removed}
    modal_record = stored(run)
    assert [(use.sandbox_id, use.cpus, use.memory_mb, use.removed) for use in modal_record.modal] == [("sb-0", 1, 512, removed)]
    warnings = [warning for warning in modal_record.warnings if "sb-0" in warning]
    assert len(warnings) == (0 if removed else 1) and all("24 h" in warning for warning in warnings)
    if not removed:
        with pytest.raises(run_state.InfrastructureAbort, match="unverified"):
            asyncio.run(run.admit_container("probe"))
    report.write(run.config.output_dir, (), ["simulation"])
    assert_no_modal_credential(run.config.output_dir)


# Modal's maximum sandbox lifetime is 24 h.
@pytest.mark.parametrize(("time_limit", "lifetime"), [(None, 86400), (90, 90 * 60 + 15 * 60), (1440, 86400)])
@needs_modal
def test_each_modal_sandbox_gets_the_run_limit_plus_grace_capped_at_24_hours(tmp_path, monkeypatch, time_limit, lifetime):
    """A host that dies without cleanup leaves its sandboxes running until Modal ends them.
    Without a time limit Harbor's 24 h lifetime stays, with no idle timeout."""
    modal = Modal(monkeypatch)
    run = modal_run(tmp_path, monkeypatch, time_limit=time_limit)
    config = trial_config(tmp_path, "modal", CONTRACT_TASK)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe"):
            pass
        with run_state.model_calls(run, "simulator", "0000-simulator"):
            trial = await Trial.create(config)
            trial._init_agent_environment()
            await trial.agent_environment.start(force_build=False)
            await trial.agent_environment.stop(delete=True)

    asyncio.run(main())
    assert [(box.kwargs["timeout"], box.kwargs["idle_timeout"]) for box in modal.created] == [(lifetime, None)] * 2


@pytest.mark.parametrize(("terminations", "removed"), [(1, True), (2, True), (None, False)])
@needs_modal
def test_modal_agent_and_separate_verifier_environments_have_hard_limits_and_verified_removal(
        tmp_path, monkeypatch, terminations, removed):
    """The TrialConfig nudi submits makes Harbor's own Trial build ModalBox for both containers."""
    modal = Modal(monkeypatch, terminations)
    run = modal_run(tmp_path, monkeypatch, task_dir=SEPARATE_TASK)
    config = trial_config(tmp_path, "modal", SEPARATE_TASK)

    async def main():
        with run_state.model_calls(run, "simulator", "0000-simulator"):
            trial = await Trial.create(config)
            trial._init_agent_environment()
            agent = trial.agent_environment
            await agent.start(force_build=False)
            await agent.stop(delete=True)
            definition = resolve_verifier_environment_definition(trial.task.config, trial.task.paths)
            async with trial._separate_verifier_env(definition, key="test",
                                                    plan=trial._network_plan(env_config=definition.config)) as verifier:
                pass
        return agent, verifier

    agent, verifier = asyncio.run(main())
    assert type(agent) is type(verifier) is modal_env.ModalBox
    assert [(box.kwargs["cpu"], box.kwargs["memory"]) for box in modal.created] == [((0.125, 1), (128, 512))] * 2
    assert [box.terminate_calls for box in modal.created] == [min(terminations or 2, 2)] * 2
    record = stored(run)
    assert modal.apps == [f"nudi-{record.run_id}"] * 2
    assert [(use.sandbox_id, use.removed) for use in record.modal] == [("sb-0", removed), ("sb-1", removed)]
    assert len([warning for warning in record.warnings if "still runs" in warning]) == (0 if removed else 2)
    assert_no_modal_credential(run.config.output_dir)


@needs_modal
def test_two_modal_runs_at_once_put_their_sandboxes_only_into_their_own_apps(tmp_path, monkeypatch):
    """Several environments in one command run as separate runs in one process; their sessions overlap here."""
    modal = Modal(monkeypatch)
    modal_login(tmp_path, monkeypatch)
    no_docker(monkeypatch)
    runs = [run_state.start_run(RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / name, backend="modal"), frozenset())
            for name in ("run-a", "run-b")]
    both = asyncio.Barrier(2)

    async def session(run):
        async with inspector_sandbox.sandbox(run, "probe"):
            await both.wait()

    async def main():
        await asyncio.gather(*(session(run) for run in runs))

    asyncio.run(main())
    apps = {box.object_id: box.kwargs["app"].name for box in modal.created}
    for run in runs:
        record = stored(run)
        assert [apps[use.sandbox_id] for use in record.modal] == [f"nudi-{record.run_id}"]
    assert len(set(apps.values())) == 2


@needs_modal
def test_a_native_verifier_environment_grades_in_its_declared_image_with_its_declared_limits(tmp_path, monkeypatch):
    """A [verifier.environment] task: Harbor's own Trial builds the verifier container from the
    declared image and resources, with the tests bundled in that image, as nudi submits it."""
    modal = Modal(monkeypatch)
    pulled = []
    monkeypatch.setattr(harbor_modal, "Image", SimpleNamespace(from_registry=lambda image, **kwargs: pulled.append(image) or image))
    task = task_with(tmp_path, SEPARATE_TASK, VERIFIER_ENVIRONMENT)
    run = modal_run(tmp_path, monkeypatch, task_dir=task)
    config = trial_config(tmp_path, "modal", task)

    async def main():
        with run_state.model_calls(run, "simulator", "0000-simulator"):
            trial = await Trial.create(config)
            definition = resolve_verifier_environment_definition(trial.task.config, trial.task.paths)
            async with trial._separate_verifier_env(definition, key="test",
                                                    plan=trial._network_plan(env_config=definition.config)) as verifier:
                pass
        return definition, verifier

    definition, verifier = asyncio.run(main())
    assert (definition.config.docker_image, definition.bundled_tests) == ("python:3.13-slim", True)
    assert type(verifier) is modal_env.ModalBox
    (box,) = modal.created
    assert (box.kwargs["cpu"][1], box.kwargs["memory"][1]) == (2, 4096), "the declared values are hard limits"
    assert pulled == ["python:3.13-slim"] and box.kwargs["image"] == "python:3.13-slim"
    assert verifier.task_env_config.docker_image == "python:3.13-slim"


@pytest.mark.parametrize("terminations", [1, None])
@needs_modal
def test_a_modal_stop_whose_wait_never_returns_is_bounded_then_checked(tmp_path, monkeypatch, terminations):
    """Harbor's stop waits for termination without a limit; each Modal call of nudi's stop has one."""
    monkeypatch.setattr(modal_env, "REMOVAL_TIMEOUT", 0.05)
    modal = Modal(monkeypatch, terminations, hang=True)
    run = modal_run(tmp_path, monkeypatch)
    config = trial_config(tmp_path, "modal")

    async def main():
        async with inspector_sandbox.sandbox(run, "probe"):
            pass
        with run_state.model_calls(run, "simulator", "0000-simulator"):
            trial = await Trial.create(config)
            trial._init_agent_environment()
            await trial.agent_environment.start(force_build=False)
            await trial.agent_environment.stop(delete=True)

    asyncio.run(asyncio.wait_for(main(), 30))
    removed = terminations is not None
    assert [box.terminate_calls for box in modal.created] == [1 if removed else 2] * 2
    record = stored(run)
    assert [(use.sandbox_id, use.removed) for use in record.modal] == [("sb-0", removed), ("sb-1", removed)]
    assert len([warning for warning in record.warnings if "still runs" in warning]) == (0 if removed else 2)
    assert sandbox_record(run, "sandbox-0000")["cleanup"] == {"sandbox_id": "sb-0", "removed": removed}


@needs_modal
def test_a_sandbox_command_whose_output_is_not_utf8_returns_it_with_replacement_characters(tmp_path, monkeypatch):
    """Modal decodes command output strictly as UTF-8. A nudi sandbox reads the bytes and replaces what does not decode,
    as Harbor's Docker environment does, so the command returns instead of ending the session."""
    Modal(monkeypatch)
    run = modal_run(tmp_path, monkeypatch)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe") as box:
            return await box.exec(["echo", "nudi-bytes"], runtime=None)

    result = asyncio.run(main())
    assert (result["output"], result["exit_code"], result["error"]) == ("half \ufffd\n", 0, None)


@pytest.mark.parametrize("failure", ["create", "exec", "stop"])
@needs_modal
def test_a_modal_error_quoting_the_credential_reaches_no_file_log_or_error_of_a_sandbox(tmp_path, monkeypatch, caplog, failure):
    """grpclib's real metadata check quotes the token secret; ModalBox names only the operation and the type."""
    caplog.set_level(logging.DEBUG)
    Modal(monkeypatch, fail={"create": {"create"}, "exec": {"body-exec"}, "stop": {"terminate", "poll"}}[failure])
    run = modal_run(tmp_path, monkeypatch)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe") as box:
            await box.exec(["echo", "nudi-leak"], runtime=None)

    if failure == "stop":
        asyncio.run(main())
        assert any("(ValueError)" in warning and "still runs" in warning for warning in stored(run).warnings)
        assert sandbox_record(run, "sandbox-0000")["cleanup"] == {"sandbox_id": "sb-0", "removed": False}
    else:
        with pytest.raises(modal_env.ModalFailure) as raised:
            asyncio.run(main())
        assert str(raised.value) == f"Modal {'start' if failure == 'create' else 'exec'} failed: ValueError"
        assert TOKEN_SECRET not in "".join(traceback.format_exception(raised.value))
    report.write(run.config.output_dir, (), ["simulation"])
    assert TOKEN_SECRET not in caplog.text and TOKEN_ID not in caplog.text
    assert_no_modal_credential(tmp_path)


@pytest.mark.parametrize("failure", ["create", "exec and stop"])
@needs_modal
def test_a_modal_error_quoting_the_credential_reaches_no_file_or_log_of_a_harbor_trial(tmp_path, monkeypatch, caplog, failure):
    """Harbor's own Trial logs the error, writes its traceback and stops the environment."""
    caplog.set_level(logging.DEBUG)
    Modal(monkeypatch, fail={"create"} if failure == "create" else {"exec", "terminate", "poll"})
    run = modal_run(tmp_path, monkeypatch)
    config = trial_config(tmp_path, "modal")

    async def main():
        with run_state.model_calls(run, "simulator", "0000-simulator"):
            return await (await Trial.create(config)).run()

    info = asyncio.run(main()).exception_info
    assert info.exception_type == "ModalFailure" and info.exception_message.endswith("failed: ValueError")
    if failure != "create":
        assert [(use.sandbox_id, use.removed) for use in stored(run).modal] == [("sb-0", False)]
    assert TOKEN_SECRET not in caplog.text and TOKEN_ID not in caplog.text
    assert_no_modal_credential(tmp_path)


@needs_modal
def test_modal_admission_counts_containers_against_concurrency(tmp_path, monkeypatch):
    """Two containers fill a concurrency of two; a held workspace still admits one experiment at one."""
    Modal(monkeypatch)
    run = modal_run(tmp_path, monkeypatch, concurrency=2)

    async def start(purpose):
        async with inspector_sandbox.sandbox(run, purpose):
            pass

    async def main():
        # A third container waits for one to end; the bound cancels it first.
        async with inspector_sandbox.sandbox(run, "check"):
            async with inspector_sandbox.sandbox(run, "probe"):
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(start("probe"), 0.2)
        run.record.capacity = run.record.capacity.model_copy(update={"concurrency_setting": 1})
        async with inspector_sandbox.sandbox(run, "workspace"):
            async with inspector_sandbox.sandbox(run, "probe"):
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(start("check"), 0.2)

    asyncio.run(main())
    assert len(run.record.sandboxes) == 4


@needs_modal
def test_modal_cost_is_a_report_only_estimate_from_requests_to_limits_outside_the_spending_cap(tmp_path, monkeypatch):
    run = modal_run(tmp_path, monkeypatch, spending_cap=1e-9)
    run.record.modal = [
        ModalSandbox(session_id="a", sandbox_id="sb-a", cpus=2, memory_mb=2048, started_at="2026-11-04T00:00:00+00:00",
                     stopped_at="2026-11-04T00:01:40+00:00", removed=True),
        ModalSandbox(session_id="b", sandbox_id="sb-b", cpus=None, memory_mb=512, started_at="2026-11-04T00:00:00+00:00",
                     stopped_at="2026-11-04T00:00:10+00:00", removed=True),
    ]
    run.save()
    run.check_cap()

    built = report.build(run.config.output_dir)
    estimate = built["configuration"]["modal_cost"]
    # Modal bills the larger of request and use; Harbor requests 0.125 cores and 128 MiB under each limit.
    assert estimate["at_requests"] == pytest.approx(100 * (0.125 * 0.00003942 + 0.125 * 0.00000667))
    assert estimate["at_limits"] == pytest.approx(100 * (2 * 0.00003942 + 2 * 0.00000667))
    assert (estimate["sandboxes"], estimate["without_limits"], estimate["app"]) == (2, 1, f"nudi-{run.record.run_id}")
    assert built["configuration"]["known_cost"] == 0
    text = report.markdown(built)
    assert (f"- Modal compute: estimated $0.00 at requested CPU and memory, $0.01 if all used their limits, for 2 sandboxes in app "
            f"nudi-{run.record.run_id} over their lifetimes; ") in text
    assert "sandboxes only, not the host that ran nudi; outside the spending cap" in text and "`nudi cost <run dir>`" in text


@needs_modal
def test_a_modal_sandbox_left_running_counts_up_to_its_24_h_lifetime(tmp_path, monkeypatch):
    run = modal_run(tmp_path, monkeypatch)
    run.record.modal = [ModalSandbox(session_id="a", sandbox_id="sb-a", cpus=1, memory_mb=512, started_at="2026-11-04T00:00:00+00:00",
                                     stopped_at="2026-11-04T00:01:40+00:00", removed=False)]
    run.save()
    estimate = report.build(run.config.output_dir)["configuration"]["modal_cost"]
    assert estimate["at_limits"] == pytest.approx(3.694032)
    assert estimate["still_running"] == 1


def test_records_from_before_the_backend_switch_still_load_and_report(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)
    path = run.config.output_dir / "run.json"
    legacy = json.loads(path.read_text())
    for key in ("backend", "modal"):
        del legacy[key]
    del legacy["capacity"]["concurrency_setting"]
    path.write_text(json.dumps(legacy))

    record = RunRecord.model_validate_json(path.read_text())
    assert (record.backend, record.modal, record.capacity.concurrency_setting) == ("docker", [], None)
    assert report.build(run.config.output_dir)["configuration"]["modal_cost"] is None


def use(started_at, stopped_at, removed=True):
    return ModalSandbox(session_id="a", sandbox_id="sb-a", cpus=1, memory_mb=512, started_at=started_at,
                        stopped_at=stopped_at, removed=removed)


def billing(monkeypatch, rows=(), error=None):
    """Modal's `Workspace.from_context().billing.report`: it records each query and returns
    `rows`, (App, cost) pairs, or raises `error`. No test calls Modal."""
    queries = []

    def billing_report(**query):
        queries.append(query)
        if error is not None:
            raise error
        return [SimpleNamespace(description=app, cost=Decimal(cost)) for app, cost in rows]

    workspace = SimpleNamespace(billing=SimpleNamespace(report=billing_report))
    monkeypatch.setattr(modal_sdk, "Workspace", SimpleNamespace(from_context=lambda: workspace))
    return queries


@needs_modal
def test_the_modal_bill_sums_the_runs_app_over_the_whole_hours_its_sandboxes_ran(tmp_path, monkeypatch):
    run = modal_run(tmp_path, monkeypatch)
    app = f"nudi-{run.record.run_id}"
    run.record.modal = [use("2026-11-04T00:10:00+00:00", "2026-11-04T01:20:00+00:00"),
                        use("2026-11-04T00:30:00+00:00", "2026-11-04T00:40:00+00:00")]
    queries = billing(monkeypatch, [(app, "0.50"), ("__harbor__", "9"), (app, "0.25"), ("nudi-other", "1")])
    assert report.billed_cost(run.record) == 0.75
    assert queries == [{"start": datetime(2026, 11, 4, 0, tzinfo=timezone.utc),
                        "end": datetime(2026, 11, 4, 2, tzinfo=timezone.utc), "resolution": "h"}]
    # A sandbox Modal never ended is billed until its 24 h lifetime, so the bill waits for it.
    run.record.modal.append(use("2026-11-04T00:30:00+00:00", "2026-11-04T00:40:00+00:00", removed=False))
    report.billed_cost(run.record)
    assert queries[-1]["end"] == datetime(2026, 11, 5, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("case", ["not reported yet", "report failed", "no row for the app", "no sandbox", "docker"])
@needs_modal
def test_no_bill_is_none_with_a_one_line_reason_and_never_quotes_the_credential(tmp_path, monkeypatch, caplog, case):
    run = modal_run(tmp_path, monkeypatch)
    app = f"nudi-{run.record.run_id}"
    past = use("2026-11-04T00:10:00+00:00", "2026-11-04T01:20:00+00:00")
    run.record.modal = {"not reported yet": [use(inspector_sandbox._now(), inspector_sandbox._now())], "no sandbox": []}.get(case, [past])
    run.record.backend = "docker" if case == "docker" else "modal"
    queries = billing(monkeypatch, [("__harbor__", "1")],
                      ValueError(f"token secret {TOKEN_SECRET}") if case == "report failed" else None)
    assert report.billed_cost(run.record) is None
    (reason,) = [record.getMessage() for record in caplog.records if record.name == "nudi"]
    assert "\n" not in reason and TOKEN_SECRET not in caplog.text
    assert len(queries) == (case in ("report failed", "no row for the app"))
    assert {"not reported yet": f"bill for app {app} is not complete; try again after",
            "report failed": "failed with ValueError; it needs a Modal Team or Enterprise plan",
            "no row for the app": f"no row for app {app} from 2026-11-04 00:00Z to 2026-11-04 02:00Z",
            "no sandbox": "no Modal sandbox", "docker": "docker has no bill"}[case] in reason


@needs_modal
def test_nudi_cost_prints_the_bill_or_when_to_try_again(tmp_path, monkeypatch, capsys):
    """`nudi cost` only reads Modal's report: it limits and stops nothing. Exit 1 says a later try can succeed, exit 2
    that no bill will ever exist."""
    run = modal_run(tmp_path, monkeypatch)
    app = f"nudi-{run.record.run_id}"
    run.record.modal = [use("2026-11-04T00:10:00+00:00", "2026-11-04T01:20:00+00:00")]
    run.save()
    billing(monkeypatch, [(app, "1.6249")])
    assert cli.main(["cost", str(run.config.output_dir)]) == 0
    assert capsys.readouterr().out == (f"Modal billed $1.62 for the sandboxes in app {app}, metered before credits; "
                                       "the host that ran nudi is not counted\n")
    run.record.modal = [use(inspector_sandbox._now(), inspector_sandbox._now())]
    run.save()
    assert cli.main(["cost", str(run.config.output_dir)]) == 1
    printed = capsys.readouterr()
    assert printed.out == "" and printed.err.startswith(f"nudi: Modal's bill for app {app} is not complete; try again after ")
    run.record.modal = []
    run.save()
    assert cli.main(["cost", str(run.config.output_dir)]) == 2
    assert capsys.readouterr().err == f"nudi: the run recorded no Modal sandbox, so app {app} has no bill\n"
    run.record.backend = "docker"
    run.save()
    assert cli.main(["cost", str(run.config.output_dir)]) == 2
    assert capsys.readouterr().err == "nudi: docker has no bill to read\n"
    assert cli.main(["cost", str(tmp_path / "missing")]) == 2


@needs_modal
def test_nudi_cost_names_only_the_type_of_an_unreadable_modal_profile(tmp_path, monkeypatch):
    """Importing the Modal SDK reads the profile, and the TOML parser's error text can quote a token.
    A fresh process, so the SDK is not already imported; the profile is synthetic."""
    run = modal_run(tmp_path, monkeypatch)
    # A recent stop: a profile that did load would stop at the time rule, before any Modal call.
    run.record.modal = [use(inspector_sandbox._now(), inspector_sandbox._now())]
    run.save()
    sentinel = "as-nudi-sentinel-profile-token"
    profile = tmp_path / "modal.toml"
    profile.write_text(f"[default]\ntoken_secret = {sentinel}\n")
    environment = {**os.environ, "MODAL_CONFIG_PATH": str(profile), "PYTHONPATH": str(Path(inspector_sandbox.__file__).parents[1])}
    done = subprocess.run([sys.executable, "-c", "import sys; from nudi import cli; sys.exit(cli.main(sys.argv[1:]))",
                           "cost", str(run.config.output_dir)], env=environment, capture_output=True, text=True)
    assert done.returncode == 1
    assert done.stderr == "nudi: Modal's bill cannot be read: loading Modal raised InvalidError\n"
    # The SDK prints its own installation banner to stdout before raising; it quotes nothing.
    assert "Modal billed" not in done.stdout and sentinel not in done.stdout + done.stderr


# Refusals a first run meets: one line each, exit 2, no run folder.


def refused(capsys, tmp_path, argv) -> str:
    assert cli.main(argv) == 2
    error = capsys.readouterr().err
    assert error.startswith("nudi: ") and error.count("\n") == 1
    assert not (tmp_path / "run").exists()
    return error


@pytest.mark.parametrize("folder", ["missing", "no task.toml"])
def test_a_folder_that_is_not_a_task_is_refused_before_credentials_are_checked(tmp_path, monkeypatch, capsys, folder):
    monkeypatch.delenv("MERGE_GATEWAY_API_KEY", raising=False)
    task = tmp_path / "task"
    if folder == "no task.toml":
        task.mkdir()
    error = refused(capsys, tmp_path, ["send-nudis", str(task), "--output", str(tmp_path / "run")])
    assert "task.toml" in error and "MERGE_GATEWAY_API_KEY" not in error


def test_a_missing_output_says_the_flag_is_required(tmp_path, capsys):
    assert refused(capsys, tmp_path, ["send-nudis", str(CONTRACT_TASK)]) == "nudi: --output is required\n"


def test_no_docker_command_says_docker_is_not_installed_and_names_modal(tmp_path, monkeypatch, capsys, credentials):
    monkeypatch.setenv("PATH", str(tmp_path))
    error = refused(capsys, tmp_path, ["send-nudis", str(CONTRACT_TASK), "--output", str(tmp_path / "run"),
                                       "--credentials-file", str(credentials)])
    assert "Docker is not installed" in error and "--backend modal" in error


def test_nudi_cost_on_a_folder_without_run_json_says_so(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    assert "has no run.json" in refused(capsys, tmp_path, ["cost", str(tmp_path / "empty")])
    (tmp_path / "empty" / "run.json").write_text("{")
    assert refused(capsys, tmp_path, ["cost", str(tmp_path / "empty")]).startswith(f"nudi: {tmp_path / 'empty' / 'run.json'}: Invalid JSON")


# Both backends: the start line, free space where records go, and a full records host.


def free_space(monkeypatch, gib):
    """`shutil.disk_usage` reporting `gib` free; it records each path asked."""
    asked = []

    def usage(path):
        asked.append(Path(path))
        return SimpleNamespace(total=2**40, used=0, free=int(gib * 2**30))

    monkeypatch.setattr(run_state.shutil, "disk_usage", usage)
    return asked


def nudi_lines(caplog):
    return [(record.levelname, record.getMessage()) for record in caplog.records if record.name == "nudi"]


def test_a_run_states_its_backend_capacity_free_space_cap_and_concurrency_in_one_line(tmp_path, monkeypatch, credentials, caplog):
    caplog.set_level(logging.INFO, logger="nudi")
    free_space(monkeypatch, 123.4)
    undeclared = task_with(tmp_path, CONTRACT_TASK, 'schema_version = "1.4"\n[environment]\ndocker_image = "python:3.12-slim"\n')
    runs = [new_run(tmp_path, monkeypatch, credentials, name="lower"),
            new_run(tmp_path, monkeypatch, credentials, name="setting", concurrency=2, docker_free=50 * 2**30, spending_cap=5),
            new_run(tmp_path, monkeypatch, credentials, name="undeclared", task_dir=undeclared)]
    docker = "backend docker; Docker has 8 CPUs and 4096 MiB; 123.4 GiB free where records go"
    unmeasured = "free space where Docker stores data not measured; no spending cap"
    assert nudi_lines(caplog) == [
        ("INFO", f"{docker} ({tmp_path / 'lower'}); {unmeasured}; concurrency 7 of 16: the task's declared 1 CPUs and 512 MiB "
                 "per episode fit 7 within 90% of Docker's capacity"),
        ("INFO", f"{docker} ({tmp_path / 'setting'}); 50.0 GiB free where Docker stores data; spending cap $5.00; concurrency 2 of 2"),
        ("WARNING", f"{docker} ({tmp_path / 'undeclared'}); {unmeasured}; concurrency 1 of 16: "
                    f"{run_state.plan_concurrency(8, 4096, None, None)[1][0]}"),
    ]
    docker = {"backend": "docker", "docker_cpus": 8, "docker_memory_mb": 4096, "host_cpus": None, "host_memory_mb": None}
    assert started_events(runs, caplog) == [
        {**docker, "docker_free_bytes": None, "spending_cap": None, "concurrency": 7, "concurrency_setting": 16,
         "reason": "the task's declared 1 CPUs and 512 MiB per episode fit 7 within 90% of Docker's capacity"},
        {**docker, "docker_free_bytes": 50 * 2**30, "spending_cap": 5.0, "concurrency": 2, "concurrency_setting": 2,
         "reason": None},
        {**docker, "docker_free_bytes": None, "spending_cap": None, "concurrency": 1, "concurrency_setting": 16,
         "reason": run_state.plan_concurrency(8, 4096, None, None)[1][0]},
    ]


@needs_modal
def test_a_modal_run_states_this_hosts_capacity_free_space_cap_and_concurrency_in_one_line(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="nudi")
    free_space(monkeypatch, 123.4)
    run = modal_run(tmp_path, monkeypatch, concurrency=3, spending_cap=0.5)
    # On Modal the host runs only nudi itself; its own CPUs and memory still say what machine ran the run.
    host_cpus, host_memory_mb = os.cpu_count(), os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // 2**20
    assert nudi_lines(caplog) == [
        ("INFO", f"backend modal; this host has {host_cpus} CPUs and {host_memory_mb} MiB, and each sandbox has the CPUs and memory "
                 f"the task declares; 123.4 GiB free where records go ({tmp_path / 'run'}); spending cap $0.50; concurrency 3 of 3"),
    ]
    assert started_events([run], caplog) == [
        {"backend": "modal", "docker_cpus": None, "docker_memory_mb": None, "host_cpus": host_cpus,
         "host_memory_mb": host_memory_mb, "docker_free_bytes": None, "spending_cap": 0.5, "concurrency": 3,
         "concurrency_setting": 3, "reason": None},
    ]


def started_events(runs, caplog) -> list[dict]:
    """Each run's first event, the line that opens its log, with the values it is built from, less the fields that
    every run_start has alike, after checking them."""
    started = [json.loads((run.config.output_dir / "events.jsonl").read_text()) for run in runs]
    assert [item.pop("text").split(" ", 2)[2] for item in started] == [message for _, message in nudi_lines(caplog)]
    assert [item.pop("run_id") for item in started] == [stored(run).run_id for run in runs]
    # A reader on the same host tells a quiet run from one whose process is gone.
    assert [item.pop("pid") for item in started] == [os.getpid()] * len(runs)
    assert [item.pop("host") for item in started] == [socket.gethostname()] * len(runs)
    start = {"kind": "run_start", "known_cost": 0.0, "unknown_cost_calls": 0, "cancelled_calls": 0,
             "free_bytes": int(123.4 * 2**30), "analyses": []}
    for item in started:
        assert {key: item.pop(key) for key in start} == start
        del item["v"], item["time"]
    return started

LOCAL_SOCKET = "unix:///var/run/docker.sock"


def docker_reports(monkeypatch, name, root, context=LOCAL_SOCKET):
    """`docker info` reporting the daemon's `name` and data directory `root`, and `docker context
    inspect` printing the current context's endpoint `context`, or failing when it is None."""
    def run(command, **kwargs):
        if command[1] == "context":
            return SimpleNamespace(returncode=1, stdout="") if context is None else SimpleNamespace(returncode=0, stdout=f"{context}\n")
        return SimpleNamespace(returncode=0, stdout=f"8\n{4096 * 2**20}\n{name}\n{root}\n")

    monkeypatch.setattr(run_state.subprocess, "run", run)
    docker_installed(monkeypatch)


def docker_installed(monkeypatch):
    """A docker command on PATH; the doubles answer every command it would run."""
    monkeypatch.setattr(run_state.shutil, "which", lambda name: f"/usr/bin/{name}")


@pytest.mark.parametrize("host, context, name, folder, measured", [
    (None, LOCAL_SOCKET, "builder", True, True),
    (LOCAL_SOCKET, "tcp://10.0.0.5:2376", "builder", True, True),
    (None, LOCAL_SOCKET, "docker-desktop", True, False),
    (None, LOCAL_SOCKET, "builder", False, False),
    ("tcp://10.0.0.5:2376", LOCAL_SOCKET, "builder", True, False),
    ("ssh://builder", LOCAL_SOCKET, "builder", True, False),
    (None, "tcp://10.0.0.5:2376", "builder", True, False),
    (None, "ssh://builder", "builder", True, False),
    (None, None, "builder", True, False),
], ids=["local socket", "DOCKER_HOST wins", "another name", "no such folder", "tcp host", "ssh host", "tcp context",
        "ssh context", "context unknown"])
def test_docker_storage_is_measured_only_through_a_local_socket_to_a_daemon_on_this_host(tmp_path, monkeypatch, host, context,
                                                                                          name, folder, measured):
    """A unix socket is on this machine. Docker Desktop, Colima and other virtual machines then report another name, or a
    data directory that is not here. A remote daemon can report this host's name and a directory that also exists here."""
    if host is None:
        monkeypatch.delenv("DOCKER_HOST", raising=False)
    else:
        monkeypatch.setenv("DOCKER_HOST", host)
    monkeypatch.setattr(run_state.socket, "gethostname", lambda: "builder")
    root = tmp_path if folder else tmp_path / "elsewhere"
    docker_reports(monkeypatch, name, root, context)
    asked = free_space(monkeypatch, 42)
    assert run_state.docker_capacity() == (8, 4096, 42 * 2**30 if measured else None, str(root))
    assert asked == ([tmp_path] if measured else [])


@pytest.mark.parametrize("endpoint", [LOCAL_SOCKET, "tcp://10.0.0.5:2376", "ssh://builder"])
def test_only_a_local_socket_refuses_the_start_on_dockers_short_disk(tmp_path, monkeypatch, credentials, endpoint):
    """A remote daemon reports this host's name and a directory that exists here with 1 GiB free. That disk is not
    Docker's, so the start does not read it."""
    monkeypatch.setattr(run_state, "FREE_DISK_MINIMUM", 10 * 2**30)  # the suite's conftest lowers it for every other test
    monkeypatch.setenv("DOCKER_HOST", endpoint)
    monkeypatch.setattr(run_state.socket, "gethostname", lambda: "builder")
    root = tmp_path / "docker"
    root.mkdir()
    docker_reports(monkeypatch, "builder", root)
    monkeypatch.setattr(run_state.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=2**30 if Path(path) == root else 50 * 2**30))
    config = RunConfig(output_dir=tmp_path / "run", credentials_file=credentials, task_dir=CONTRACT_TASK)
    if endpoint == LOCAL_SOCKET:
        with pytest.raises(run_state.CapacityError) as error:
            run_state.start_run(config)
        assert str(error.value) == f"1.0 GiB is free where Docker stores data ({root}); a run needs at least 10 GiB there"
        return
    run_state.start_run(config)
    assert json.loads((tmp_path / "run" / "events.jsonl").read_text().splitlines()[0])["docker_free_bytes"] is None


@pytest.mark.parametrize("failure", ["raises", "exits nonzero"])
def test_a_failed_context_lookup_leaves_dockers_short_disk_unmeasured(tmp_path, monkeypatch, credentials, failure):
    """A context inspect that cannot run, or that exits nonzero after printing a local socket, does not name the
    endpoint, so a short disk here neither refuses the start nor counts as Docker's."""
    monkeypatch.setattr(run_state, "FREE_DISK_MINIMUM", 10 * 2**30)  # the suite's conftest lowers it for every other test
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setattr(run_state.socket, "gethostname", lambda: "builder")
    root = tmp_path / "docker"
    root.mkdir()

    def run(command, **kwargs):
        if command[1] != "context":
            return SimpleNamespace(returncode=0, stdout=f"8\n{4096 * 2**20}\nbuilder\n{root}\n")
        if failure == "raises":
            raise PermissionError(13, "Permission denied", command[0])
        return SimpleNamespace(returncode=1, stdout=f"{LOCAL_SOCKET}\n")

    monkeypatch.setattr(run_state.subprocess, "run", run)
    docker_installed(monkeypatch)
    monkeypatch.setattr(run_state.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=2**30 if Path(path) == root else 50 * 2**30))
    assert run_state.docker_capacity() == (8, 4096, None, str(root))
    run_state.start_run(RunConfig(output_dir=tmp_path / "run", credentials_file=credentials, task_dir=CONTRACT_TASK))
    assert json.loads((tmp_path / "run" / "events.jsonl").read_text().splitlines()[0])["docker_free_bytes"] is None


def test_a_failed_storage_measurement_leaves_dockers_free_space_unmeasured(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", LOCAL_SOCKET)
    monkeypatch.setattr(run_state.socket, "gethostname", lambda: "builder")
    docker_reports(monkeypatch, "builder", tmp_path)

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(run_state.shutil, "disk_usage", denied)
    assert run_state.docker_capacity() == (8, 4096, None, str(tmp_path))


def test_too_little_free_space_where_docker_stores_data_stops_the_run_with_exit_code_2(tmp_path, monkeypatch, credentials):
    monkeypatch.setattr(run_state, "FREE_DISK_MINIMUM", 10 * 2**30)  # the suite's conftest lowers it for every other test
    free_space(monkeypatch, 20)
    with pytest.raises(run_state.CapacityError) as error:
        new_run(tmp_path, monkeypatch, credentials, docker_free=int(9.5 * 2**30))
    assert str(error.value) == "9.5 GiB is free where Docker stores data (/var/lib/docker); a run needs at least 10 GiB there"
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize("backend", ["docker", "modal"])
def test_too_little_free_space_where_records_go_stops_the_run_with_exit_code_2(tmp_path, monkeypatch, credentials, capsys, backend):
    monkeypatch.setattr(run_state, "FREE_DISK_MINIMUM", 10 * 2**30)  # the suite's conftest lowers it for every other test
    asked = free_space(monkeypatch, 9.5)
    with pytest.raises(run_state.CapacityError) as error:
        modal_run(tmp_path, monkeypatch) if backend == "modal" else new_run(tmp_path, monkeypatch, credentials)
    assert str(error.value) == f"9.5 GiB is free where records go ({tmp_path / 'run'}); a run needs at least 10 GiB there"
    assert asked == [tmp_path] and not (tmp_path / "run").exists()
    assert cli.main(["send-nudis", str(CONTRACT_TASK), "--output", str(tmp_path / "run"), "--backend", backend]) == 2
    assert capsys.readouterr().err == f"nudi: {error.value}\n"


@pytest.mark.parametrize("backend", ["docker", pytest.param("modal", marks=needs_modal)])
def test_no_space_left_for_a_record_stops_the_run_and_keeps_the_earlier_record(tmp_path, monkeypatch, credentials, backend):
    run = modal_run(tmp_path, monkeypatch) if backend == "modal" else new_run(tmp_path, monkeypatch, credentials)
    path = run.config.output_dir / "run.json"
    earlier = path.read_text()

    def full(descriptor, *args, **kwargs):
        os.close(descriptor)
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(records, "open", full, raising=False)
    run.record.warnings.append("unsaved")
    with pytest.raises(DiskFull) as stopped:
        run.save()
    assert str(stopped.value) == f"no space left on the records host to write {path}"
    assert not isinstance(stopped.value, Exception)
    assert path.read_text() == earlier and not list(path.parent.glob(".*"))
