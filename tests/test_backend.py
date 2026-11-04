"""The backend switch and the concurrency setting.

Harbor 0.24.0's real Docker and Modal environment classes and its real Trial run here. Only
external operations are replaced: Docker's daemon and CLI, and the Modal SDK calls
`App.lookup`, `Sandbox.create`, `terminate` and `poll` (with the sandbox's exec and file
copy). No test calls Modal or Docker, and none needs a Modal account.
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace

import litellm
import pytest
from grpclib.metadata import encode_metadata
from harbor.environments import modal as harbor_modal
from harbor.environments.docker.docker import DockerEnvironment
from harbor.environments.factory import EnvironmentFactory
from harbor.models.environment_type import EnvironmentType
from harbor.models.task.task import Task
from harbor.models.task.verifier_mode import resolve_verifier_environment_definition
from harbor.models.trial.config import EnvironmentConfig, ResourceMode
from harbor.models.trial.paths import TrialPaths
from harbor.trial.trial import Trial
from pydantic import ValidationError

from nudi import api, checks, cli, modal_box, report, runner, sandbox, workflow
from nudi.records import EpisodeConfig, EpisodeResult, ModalSandbox, RunConfig, RunRecord
from test_inspection import Sandboxes, sandbox_record
from test_limits import credentials, new_run  # noqa: F401  (pytest fixture)
from test_runner import CONTRACT_TASK, SEPARATE_TASK, VERIFIER_ENVIRONMENT, task_with

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
    containing "nudi-leak". With `hang`, `wait` never returns."""

    def __init__(self, object_id, terminations, entrypoint, kwargs, fail=(), hang=False):
        self.object_id, self.terminations, self.entrypoint, self.kwargs = object_id, terminations, entrypoint, kwargs
        self.fail, self.hang = fail, hang
        self.terminate_calls, self.commands, self.copies = 0, [], []
        self.exec, self.terminate, self.poll, self.wait = Aio(self._exec), Aio(self._terminate), Aio(self._poll), Aio(self._wait)
        self.filesystem = SimpleNamespace(copy_from_local=Aio(self._copy))

    @property
    def running(self) -> bool:
        return self.terminations is None or self.terminate_calls < self.terminations

    async def _exec(self, *argv, **kwargs):
        self.commands.append(" ".join(argv))
        if "exec" in self.fail or ("body-exec" in self.fail and "nudi-leak" in argv[-1]):
            leak()
        return SimpleNamespace(stdout=SimpleNamespace(read=Aio(lambda: value(""))),
                               stderr=SimpleNamespace(read=Aio(lambda: value(""))), wait=Aio(lambda: value(0)))

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
        self.terminations, self.fail, self.hang, self.created = terminations, fail, hang, []
        monkeypatch.setattr(harbor_modal, "App", SimpleNamespace(lookup=Aio(self.lookup)))
        monkeypatch.setattr(harbor_modal, "Sandbox", SimpleNamespace(create=Aio(self.create)))
        # Harbor's sandbox creation sets this variable; monkeypatch removes it afterwards.
        monkeypatch.setenv("MODAL_SANDBOX_V2", "1")

    async def lookup(self, name, create_if_missing):
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

    monkeypatch.setattr(workflow, "docker_capacity", refuse)
    monkeypatch.setattr(checks, "host_command", refuse_command)


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
    return workflow.start_run(RunConfig(output_dir=tmp_path / "run", backend="modal", **fields), frozenset())


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
    asyncio.run(runner.run_harbor(config, task, result, queue))
    return queue.config


# Docker stays the default and unchanged.


def test_docker_is_the_default_and_its_resource_compose_file_is_unchanged(tmp_path):
    config = RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "run")
    assert (config.backend, config.concurrency) == ("docker", 8)
    native = trial_config(tmp_path, "docker").environment
    assert (native.type, native.import_path) == (EnvironmentType.DOCKER, None)
    assert native.cpu_enforcement_policy == native.memory_enforcement_policy == ResourceMode.LIMIT
    task = Task(CONTRACT_TASK)

    def resources(environment, name):
        paths = TrialPaths(tmp_path / name)
        paths.mkdir()
        box = EnvironmentFactory.create_environment_from_config(
            config=environment, environment_dir=task.paths.environment_dir, environment_name=task.short_name,
            session_id="nudi-test", trial_paths=paths, task_env_config=task.config.environment)
        assert type(box) is DockerEnvironment
        return asyncio.run(box._write_resources_compose_file()).read_text()

    assert resources(native, "nudi") == resources(EnvironmentConfig(type=EnvironmentType.DOCKER), "harbor")
    # An undeclared value keeps Harbor's default, which a hard limit would refuse.
    undeclared = runner.environment_config("modal", None, 512)
    assert (undeclared.cpu_enforcement_policy, undeclared.memory_enforcement_policy) == (ResourceMode.AUTO, ResourceMode.LIMIT)


def test_backend_and_concurrency_come_from_the_cli_the_api_and_the_file(tmp_path, monkeypatch, credentials):
    seen = []

    def start_run(config, roles):
        seen.append((config.backend, config.concurrency))
        raise ValueError("stopped after configuration")

    monkeypatch.setattr(api, "start_run", start_run)
    file = tmp_path / "nudi.toml"
    file.write_text('backend = "modal"\nconcurrency = 5\n')
    assert cli.main(["send-nudis", str(CONTRACT_TASK), "--output", str(tmp_path / "a"),
                     "--backend", "modal", "--concurrency", "3"]) == 2
    for call in (lambda: api.send_nudis(CONTRACT_TASK, output_dir=tmp_path / "b", backend="modal", concurrency=4),
                 lambda: api.send_nudis(CONTRACT_TASK, file, output_dir=tmp_path / "c")):
        with pytest.raises(ValueError, match="stopped"):
            call()
    assert seen == [("modal", 3), ("modal", 4), ("modal", 5)]
    for bad in ({"backend": "podman"}, {"concurrency": 0}, {"concurrency": "8"}):
        with pytest.raises(ValidationError):
            RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "d", **bad)
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=3)
    assert (stored(run).backend, stored(run).capacity.concurrency_setting) == ("docker", 3)


def test_docker_admission_also_respects_the_concurrency_setting(tmp_path, monkeypatch, credentials):
    """Docker's capacity fits seven episodes; a setting of one caps the queue and the containers."""
    Sandboxes(monkeypatch)

    async def nested(run):
        async with sandbox.sandbox(run, "check"):
            async with sandbox.sandbox(run, "probe"):
                pass

    free = new_run(tmp_path, monkeypatch, credentials, name="free", capacity=(8, 16384))
    asyncio.run(nested(free))
    capped = new_run(tmp_path, monkeypatch, credentials, name="capped", capacity=(8, 16384), concurrency=1)
    assert (free.record.capacity.concurrency, capped.record.capacity.concurrency) == (7, 1)
    with pytest.raises(workflow.CapacityUnavailable, match="concurrency of 1"):
        asyncio.run(nested(capped))
    assert (len(free.record.sandboxes), len(capped.record.sandboxes)) == (2, 1)


# Modal: startup, admission, resources, removal, cost, credentials.


@pytest.mark.parametrize("failure", ["no credential", "no extra", "load failure"])
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
        monkeypatch.setattr(workflow, "MODAL_BOX", "nudi_broken_modal:ModalBox")
    no_docker(monkeypatch)

    async def no_model_call(*args, **kwargs):
        raise AssertionError("a model was called")

    monkeypatch.setattr(litellm, "acompletion", no_model_call)
    code = cli.main(["send-nudis", str(CONTRACT_TASK), "--output", str(tmp_path / "run"), "--backend", "modal",
                     "--credentials-file", str(credentials)])

    error = capsys.readouterr().err
    assert code == 2 and error.startswith("nudi: Modal is unavailable: ")
    expected = {"no credential": "modal token new", "no extra": "harbor[modal]", "load failure": "InvalidError"}
    assert expected[failure] in error and TOKEN_SECRET not in error
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize("block", ["no Modal SDK", "unreadable Modal profile"])
def test_importing_nudi_and_starting_docker_never_import_the_modal_sdk(tmp_path, block):
    profile = tmp_path / "modal.toml"
    profile.write_text("[broken\n")
    program = "\n".join([
        "import sys",
        "sys.modules['modal'] = None" if block == "no Modal SDK" else "",
        "import nudi, nudi.api, nudi.checks, nudi.cli, nudi.report, nudi.runner, nudi.sandbox, nudi.workflow",
        "from pathlib import Path",
        "from harbor.environments.factory import EnvironmentFactory",
        "from harbor.models.task.task import Task",
        "from harbor.models.trial.paths import TrialPaths",
        f"task, paths = Task(Path({str(CONTRACT_TASK)!r})), TrialPaths(Path({str(tmp_path / 'trial')!r}))",
        "paths.mkdir()",
        "EnvironmentFactory.create_environment_from_config(config=nudi.runner.environment_config('docker', 1, 512),",
        "    environment_dir=task.paths.environment_dir, environment_name=task.short_name, session_id='nudi-test',",
        "    trial_paths=paths, task_env_config=task.config.environment)",
        "loaded = {'modal', 'harbor.environments.modal', 'nudi.modal_box'} & set(sys.modules)",
        "assert not loaded or sys.modules.get('modal', 0) is None and loaded == {'modal'}, loaded",
    ])
    environment = {**os.environ, "MODAL_CONFIG_PATH": str(profile), "PYTHONPATH": str(Path(sandbox.__file__).parents[1])}
    done = subprocess.run([sys.executable, "-c", program], env=environment, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


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

    monkeypatch.setattr(workflow, "run_episode", native)
    asyncio.run(workflow.run_role_episode(run, "simulator"))
    assert [config.backend for config in episodes] == ["modal"]


@pytest.mark.parametrize(("terminations", "removed"), [(1, True), (2, True), (None, False)])
def test_modal_sandbox_has_hard_limits_and_verified_removal(tmp_path, monkeypatch, terminations, removed):
    """Harbor's stop terminates once; a sandbox still running is terminated once more, and one
    that stays is recorded with a warning. Removal is checked through Modal, not `docker ps`."""
    modal = Modal(monkeypatch, terminations)
    run = modal_run(tmp_path, monkeypatch)

    async def main():
        async with sandbox.sandbox(run, "probe"):
            pass

    asyncio.run(main())
    box, = modal.created
    assert (box.kwargs["cpu"], box.kwargs["memory"]) == ((0.125, 1), (128, 512))
    # The verifier directory is created inside the sandbox; Modal ignores the host side of the mount.
    assert any("/logs/verifier" in command for command in box.commands)
    assert box.terminate_calls == min(terminations or 2, 2)
    record = sandbox_record(run, "sandbox-0000")
    assert record["environment"]["type"] == "modal"
    assert record["environment"]["cpu_enforcement"] == record["environment"]["memory_enforcement"] == "limit"
    assert record["cleanup"] == {"sandbox_id": "sb-0", "removed": removed}
    modal_record = stored(run)
    assert [(use.sandbox_id, use.cpus, use.memory_mb, use.removed) for use in modal_record.modal] == [("sb-0", 1, 512, removed)]
    warnings = [warning for warning in modal_record.warnings if "sb-0" in warning]
    assert len(warnings) == (0 if removed else 1) and all("24 h" in warning for warning in warnings)
    if not removed:
        with pytest.raises(workflow.InfrastructureAbort, match="unverified"):
            run.admit_container("probe")
    report.write(run.config.output_dir, (), ["simulation"])
    assert_no_modal_credential(run.config.output_dir)


@pytest.mark.parametrize(("terminations", "removed"), [(1, True), (2, True), (None, False)])
def test_modal_agent_and_separate_verifier_environments_have_hard_limits_and_verified_removal(
        tmp_path, monkeypatch, terminations, removed):
    """The TrialConfig nudi submits makes Harbor's own Trial build ModalBox for both containers."""
    modal = Modal(monkeypatch, terminations)
    run = modal_run(tmp_path, monkeypatch, task_dir=SEPARATE_TASK)
    config = trial_config(tmp_path, "modal", SEPARATE_TASK)

    async def main():
        with workflow.model_calls(run, "simulator", "0000-simulator"):
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
    assert type(agent) is type(verifier) is modal_box.ModalBox
    assert [(box.kwargs["cpu"], box.kwargs["memory"]) for box in modal.created] == [((0.125, 1), (128, 512))] * 2
    assert [box.terminate_calls for box in modal.created] == [min(terminations or 2, 2)] * 2
    record = stored(run)
    assert [(use.sandbox_id, use.removed) for use in record.modal] == [("sb-0", removed), ("sb-1", removed)]
    assert len([warning for warning in record.warnings if "still runs" in warning]) == (0 if removed else 2)
    assert_no_modal_credential(run.config.output_dir)


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
        with workflow.model_calls(run, "simulator", "0000-simulator"):
            trial = await Trial.create(config)
            definition = resolve_verifier_environment_definition(trial.task.config, trial.task.paths)
            async with trial._separate_verifier_env(definition, key="test",
                                                    plan=trial._network_plan(env_config=definition.config)) as verifier:
                pass
        return definition, verifier

    definition, verifier = asyncio.run(main())
    assert (definition.config.docker_image, definition.bundled_tests) == ("python:3.13-slim", True)
    assert type(verifier) is modal_box.ModalBox
    (box,) = modal.created
    assert (box.kwargs["cpu"][1], box.kwargs["memory"][1]) == (2, 4096), "the declared values are hard limits"
    assert pulled == ["python:3.13-slim"] and box.kwargs["image"] == "python:3.13-slim"
    assert verifier.task_env_config.docker_image == "python:3.13-slim"


@pytest.mark.parametrize("terminations", [1, None])
def test_a_modal_stop_whose_wait_never_returns_is_bounded_then_checked(tmp_path, monkeypatch, terminations):
    """Harbor's stop waits for termination without a limit; each Modal call of nudi's stop has one."""
    monkeypatch.setattr(modal_box, "REMOVAL_TIMEOUT", 0.05)
    modal = Modal(monkeypatch, terminations, hang=True)
    run = modal_run(tmp_path, monkeypatch)
    config = trial_config(tmp_path, "modal")

    async def main():
        async with sandbox.sandbox(run, "probe"):
            pass
        with workflow.model_calls(run, "simulator", "0000-simulator"):
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


@pytest.mark.parametrize("failure", ["create", "exec", "stop"])
def test_a_modal_error_quoting_the_credential_reaches_no_file_log_or_error_of_a_sandbox(tmp_path, monkeypatch, caplog, failure):
    """grpclib's real metadata check quotes the token secret; ModalBox names only the operation and the type."""
    caplog.set_level(logging.DEBUG)
    Modal(monkeypatch, fail={"create": {"create"}, "exec": {"body-exec"}, "stop": {"terminate", "poll"}}[failure])
    run = modal_run(tmp_path, monkeypatch)

    async def main():
        async with sandbox.sandbox(run, "probe") as box:
            await box.exec(["echo", "nudi-leak"], runtime=None)

    if failure == "stop":
        asyncio.run(main())
        assert any("(ValueError)" in warning and "still runs" in warning for warning in stored(run).warnings)
        assert sandbox_record(run, "sandbox-0000")["cleanup"] == {"sandbox_id": "sb-0", "removed": False}
    else:
        with pytest.raises(modal_box.ModalFailure) as raised:
            asyncio.run(main())
        assert str(raised.value) == f"Modal {'start' if failure == 'create' else 'exec'} failed: ValueError"
        assert TOKEN_SECRET not in "".join(traceback.format_exception(raised.value))
    report.write(run.config.output_dir, (), ["simulation"])
    assert TOKEN_SECRET not in caplog.text and TOKEN_ID not in caplog.text
    assert_no_modal_credential(tmp_path)


@pytest.mark.parametrize("failure", ["create", "exec and stop"])
def test_a_modal_error_quoting_the_credential_reaches_no_file_or_log_of_a_harbor_trial(tmp_path, monkeypatch, caplog, failure):
    """Harbor's own Trial logs the error, writes its traceback and stops the environment."""
    caplog.set_level(logging.DEBUG)
    Modal(monkeypatch, fail={"create"} if failure == "create" else {"exec", "terminate", "poll"})
    run = modal_run(tmp_path, monkeypatch)
    config = trial_config(tmp_path, "modal")

    async def main():
        with workflow.model_calls(run, "simulator", "0000-simulator"):
            return await (await Trial.create(config)).run()

    info = asyncio.run(main()).exception_info
    assert info.exception_type == "ModalFailure" and info.exception_message.endswith("failed: ValueError")
    if failure != "create":
        assert [(use.sandbox_id, use.removed) for use in stored(run).modal] == [("sb-0", False)]
    assert TOKEN_SECRET not in caplog.text and TOKEN_ID not in caplog.text
    assert_no_modal_credential(tmp_path)


def test_modal_admission_counts_containers_against_concurrency(tmp_path, monkeypatch):
    """Two containers fill a concurrency of two; a held workspace still admits one experiment at one."""
    Modal(monkeypatch)
    run = modal_run(tmp_path, monkeypatch, concurrency=2)

    async def main():
        async with sandbox.sandbox(run, "check"):
            async with sandbox.sandbox(run, "probe"):
                with pytest.raises(workflow.CapacityUnavailable, match="concurrency of 2"):
                    async with sandbox.sandbox(run, "probe"):
                        pass
        run.record.capacity = run.record.capacity.model_copy(update={"concurrency_setting": 1})
        async with sandbox.sandbox(run, "workspace"):
            async with sandbox.sandbox(run, "probe"):
                with pytest.raises(workflow.CapacityUnavailable, match="concurrency of 1"):
                    async with sandbox.sandbox(run, "check"):
                        pass

    asyncio.run(main())
    assert len(run.record.sandboxes) == 4


def test_modal_cost_is_a_report_only_upper_bound_outside_the_spending_cap(tmp_path, monkeypatch):
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
    assert estimate["estimate"] == pytest.approx(100 * (2 * 0.00003942 + 2 * 0.00000667))
    assert (estimate["sandboxes"], estimate["without_limits"]) == (2, 1)
    assert built["configuration"]["known_cost"] == 0
    text = report.markdown(built)
    assert "Modal compute" in text and "upper bound" in text and "outside the spending cap" in text


def test_a_modal_sandbox_left_running_counts_up_to_its_24_h_lifetime(tmp_path, monkeypatch):
    run = modal_run(tmp_path, monkeypatch)
    run.record.modal = [ModalSandbox(session_id="a", sandbox_id="sb-a", cpus=1, memory_mb=512, started_at="2026-11-04T00:00:00+00:00",
                                     stopped_at="2026-11-04T00:01:40+00:00", removed=False)]
    run.save()
    estimate = report.build(run.config.output_dir)["configuration"]["modal_cost"]
    assert estimate["estimate"] == pytest.approx(3.694032)
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
