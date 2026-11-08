"""Admission part 2: Harbor 0.24.0 parity where nudi builds an environment itself.

Probe, check and workspace sandboxes start an environment from nudi's own arguments, so each
admitted field is compared with what Harbor's real Trial, Verifier and environment classes do
with it. Docker is the `Sandboxes` double of `test_inspection` with Harbor's own healthcheck
and main-service methods; Modal's SDK calls go through the fakes of `test_backend`. No test
calls Docker or Modal, except the integration test at the end, which needs Docker and is
skipped without it.
"""

import asyncio
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from harbor.environments.base import ExecResult
from harbor.environments.docker.docker import DockerEnvironment
from harbor.environments.factory import EnvironmentFactory
from harbor.models.task.verifier_mode import resolve_verifier_environment_definition
from harbor.trial.trial import Trial
from harbor.verifier.verifier import Verifier

from nudi import checks, copies, episode, inspection, inspector_sandbox
from nudi.episode import HELPER_STATE, UnsupportedTask
from nudi.records import StateCopy
from nudi.run_state import CapacityUnavailable
from test_backend import needs_modal, Modal, modal_run, trial_config
from test_inspection import SandboxEnvironment, Sandboxes, no_native_actor, retained_copy, sandbox_record
from test_limits import credentials, new_run  # noqa: F401  (pytest fixture)
from test_runner import CONTRACT_TASK, SEPARATE_TASK, VERIFIER_ENVIRONMENT, compose_task, docker_env, task_variant, task_with  # noqa: F401

# Harbor's own environment factory, kept before any test replaces it.
HARBOR_CREATE = EnvironmentFactory.create_environment


class Services(SandboxEnvironment):
    """The double with helper services: their exec and the main service's stop are recorded."""

    async def stop_service(self, service):
        self.event("stop_service", service)

    async def service_exec(self, command, *, service=None, **kwargs):
        if self.is_main_service(service):
            return await super().service_exec(command, service=service, **kwargs)
        self.event("service_exec", service, command)
        return ExecResult(stdout="", stderr="", return_code=0)


def doubles(monkeypatch, harbor=None):
    """Sandboxes of the `Services` double; with `harbor`, a dict, also Harbor's own environment
    built from the same arguments, by sandbox name."""
    sandboxes = Sandboxes(monkeypatch)

    def create(**config):
        environment = Services(sandboxes, **config)
        sandboxes.environments[environment.name] = environment
        if harbor is not None:
            harbor[environment.name] = HARBOR_CREATE(**config)
        return environment

    monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(create))
    no_native_actor(monkeypatch)
    return sandboxes


def commands(sandboxes, name):
    return [event for event in sandboxes.events if event[1] == name and event[0] in ("exec", "service_exec", "stop_service")]


# environment/docker-compose.yaml with helper services, merged as Harbor's Docker environment merges it.


def test_a_sandbox_of_the_task_environment_merges_its_compose_file_as_harbors_trial_does(tmp_path, monkeypatch, credentials):
    harbor = {}
    doubles(monkeypatch, harbor)
    task = compose_task(tmp_path)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe") as box:
            # The sandbox's package copy is removed with it.
            mine = harbor[box.record.name]
            assert mine._uses_compose and mine._environment_docker_compose_path in mine._docker_compose_paths
            return mine, [path.read_text() for path in mine._user_compose_paths()]

    mine, merged = asyncio.run(main())
    config = trial_config(tmp_path, "docker", task)
    monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(HARBOR_CREATE))

    async def native():
        trial = await Trial.create(config)
        trial._init_agent_environment()
        return trial.agent_environment

    agent = asyncio.run(native())
    assert type(mine) is DockerEnvironment and type(agent) is episode.NativeDocker
    compose = (task / "environment" / "docker-compose.yaml").read_text()
    assert merged == [path.read_text() for path in agent._user_compose_paths()] == [compose]


def test_a_run_counts_helper_services_as_undeclared_and_keeps_compose_off_modal(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=compose_task(tmp_path), capacity=(8, 16384))
    assert (run.record.capacity.episode_cpus, run.record.capacity.episode_memory_mb, run.record.capacity.concurrency) == (None, None, 1)
    assert any("for every container" in warning and "helper containers can exceed the concurrency setting" in warning
               for warning in run.record.warnings)
    assert run.record.limitations[-1] == HELPER_STATE.strip()
    assert inspection.task_context(run)["check_input_contract"] == checks.CHECK_INPUT_CONTRACT + HELPER_STATE
    plain = new_run(tmp_path / "plain", monkeypatch, credentials, capacity=(8, 16384))
    assert HELPER_STATE.strip() not in plain.record.limitations
    assert inspection.task_context(plain)["check_input_contract"] == checks.CHECK_INPUT_CONTRACT
    with pytest.raises(UnsupportedTask, match="docker-compose.yaml is not verified on Modal"):
        modal_run(tmp_path, monkeypatch, task_dir=compose_task(tmp_path / "modal"))


def test_a_held_workspace_admits_one_unchecked_experiment_on_an_undeclared_task_with_one_warning(tmp_path, monkeypatch, credentials):
    doubles(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=compose_task(tmp_path), capacity=(8, 16384))
    unchecked = [warning for warning in run.record.warnings if "without a resource check" in warning]
    assert run.record.capacity.concurrency == 1 and not unchecked

    async def main():
        async with inspector_sandbox.sandbox(run, "workspace"):
            for purpose in ("probe", "check"):
                async with inspector_sandbox.sandbox(run, purpose):
                    with pytest.raises(CapacityUnavailable, match="concurrency of 1"):
                        async with inspector_sandbox.sandbox(run, "probe"):
                            pass

    asyncio.run(main())
    assert [sandbox_record(run, name)["purpose"] for name in run.record.sandboxes] == ["workspace", "probe", "check"]
    assert [warning for warning in run.record.warnings if "without a resource check" in warning] == [
        "a held workspace and one fresh experiment run without a resource check: the task's resources are undeclared, "
        "helper services included"]


def test_a_docker_run_refuses_gpus_by_name(tmp_path, monkeypatch, credentials):
    task = task_variant(tmp_path, CONTRACT_TASK, "gpus = 1\n")
    with pytest.raises(UnsupportedTask, match=r"^\[environment\]\.gpus = 1 is not verified on Docker$"):
        new_run(tmp_path, monkeypatch, credentials, task_dir=task)


# [environment].healthcheck runs after the task environment starts, as Harbor's trial runs it.


def test_the_healthcheck_runs_in_sandboxes_of_the_task_environment_only(tmp_path, monkeypatch, credentials):
    sandboxes = doubles(monkeypatch)
    task = task_variant(tmp_path, CONTRACT_TASK, '\n[environment.healthcheck]\ncommand = "nudi-health"\ntimeout_sec = 7\n')
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    copy = retained_copy(run, sandboxes)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe") as probe:
            pass
        async with inspector_sandbox.sandbox(run, "check", copy=copy) as check:
            pass
        return probe.record.name, check.record.name

    probe, check = asyncio.run(main())
    # Harbor's trial calls BaseEnvironment.run_healthcheck after start, before any upload.
    events = [event[:3] for event in sandboxes.events if event[1] == probe]
    assert events[:2] == [("start", probe, False), ("exec", probe, "nudi-health")]
    assert ("exec", check, "nudi-health") not in [event[:3] for event in sandboxes.events]


def test_a_separate_verifier_sandbox_runs_no_healthcheck(tmp_path, monkeypatch, credentials):
    """Harbor's separate verifier environment does not run the task healthcheck either."""
    sandboxes = doubles(monkeypatch)
    task = task_with(tmp_path, SEPARATE_TASK, VERIFIER_ENVIRONMENT.replace(
        "memory_mb = 512\n", 'memory_mb = 512\n[environment.healthcheck]\ncommand = "nudi-health"\n', 1))
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe", definition=True) as box:
            return box.record.name

    name = asyncio.run(main())
    assert "nudi-health" not in json.dumps(commands(sandboxes, name))


# [verifier].collect runs through Harbor's own trial collection before grading.

HOOKS = '\n[[verifier.collect]]\ncommand = "nudi-main-hook"\n'


def test_collect_hooks_run_before_the_shared_grader_in_its_sandbox(tmp_path, monkeypatch, credentials):
    sandboxes = doubles(monkeypatch)
    task = task_variant(tmp_path, CONTRACT_TASK, HOOKS)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    name = asyncio.run(inspection.package_probe(run, "true\n"))
    order = [event[2] for event in commands(sandboxes, name)]
    hook = order.index("nudi-main-hook")
    assert any(inspector_sandbox.SETUP in command for command in order[:hook])
    assert any("/tests/test.sh" in command and "chmod" not in command for command in order[hook:])
    assert sandbox_record(run, name)["rewards"] == {"reward": 1.0}


def test_a_failed_collect_hook_is_a_run_warning_and_the_probe_still_grades(tmp_path, monkeypatch, credentials):
    doubles(monkeypatch)

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        if command == "nudi-main-hook":
            return ExecResult(stdout="partial export", stderr="disk full", return_code=7)
        return await SandboxEnvironment.exec(self, command, cwd, env, timeout_sec, user)

    monkeypatch.setattr(Services, "exec", exec)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task_variant(tmp_path, CONTRACT_TASK, HOOKS))
    name = asyncio.run(inspection.package_probe(run, "true\n"))
    assert sandbox_record(run, name)["rewards"] == {"reward": 1.0}
    assert [warning for warning in run.record.warnings if "Collect hook" in warning] == [
        f"{name}: Collect hook in service 'main' exited with code 7: 'nudi-main-hook'. stdout: partial export stderr: disk full"]


def test_separate_mode_collects_the_main_service_then_stops_it_before_helper_hooks(tmp_path, monkeypatch, credentials):
    """Harbor's `_collect_artifacts_phased(stop_main_before_sidecars=True)`, unchanged, over the setup sandbox."""
    sandboxes = doubles(monkeypatch)
    sandboxes.files["sandbox-0000"] = {"/app/answer.txt": b"42"}
    task = task_variant(tmp_path, SEPARATE_TASK, HOOKS + '\n[[verifier.collect]]\nservice = "helper"\ncommand = "nudi-helper-hook"\n')
    (task / "environment").mkdir(exist_ok=True)
    (task / "environment" / "docker-compose.yaml").write_text("services:\n  main: {}\n  helper:\n    image: python:3.12-slim\n")
    # As in every Terminal-Bench 4 compose task, the separate verifier builds from tests/, not environment/.
    (task / "tests" / "Dockerfile").write_text("FROM python:3.12-slim\n")
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    name = asyncio.run(inspection.package_probe(run, "true\n"))
    setup = sandbox_record(run, name)["setup"]
    collection = [event for event in commands(sandboxes, setup) if event[0] != "exec" or "nudi-" in event[2]]
    assert collection == [("exec", setup, "nudi-main-hook", None, 60), ("stop_service", setup, "main"),
                          ("service_exec", setup, "helper", "nudi-helper-hook")]
    stopped = sandboxes.events.index(("stop", setup, True))
    assert all(sandboxes.events.index(event) < stopped for event in collection)
    assert [entry["source"] for entry in sandbox_record(run, name)["artifact_manifest"]] == ["/logs/artifacts", "/app/answer.txt"]


# [verifier].env reaches the copied grader as Harbor's Verifier gives it.


def test_the_grader_gets_verifier_env_as_harbors_verifier_gives_it(tmp_path, monkeypatch, credentials):
    doubles(monkeypatch)
    graded = []

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        if "/tests/test.sh" in command and not command.startswith("chmod"):
            graded.append(env)
        return await SandboxEnvironment.exec(self, command, cwd, env, timeout_sec, user)

    monkeypatch.setattr(Services, "exec", exec)
    task = task_variant(tmp_path, CONTRACT_TASK, '\n[verifier.env]\nMODE = "strict"\n')
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe") as box:
            await box.grade()
            await Verifier(task=box.task, trial_paths=box.paths, environment=box.environment).verify()

    asyncio.run(main())
    assert graded == [{"MODE": "strict"}] * 2


# GPUs, on Modal only, requested as Harbor's trial requests them.


@needs_modal
def test_a_modal_sandbox_requests_the_gpus_harbors_trial_requests(tmp_path, monkeypatch):
    modal = Modal(monkeypatch)
    task = task_variant(tmp_path, CONTRACT_TASK, 'gpus = 1\ngpu_types = ["H100"]\n')
    run = modal_run(tmp_path, monkeypatch, task_dir=task)
    config = trial_config(tmp_path, "modal", task)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe"):
            pass
        trial = await Trial.create(config)
        trial._init_agent_environment()
        await trial.agent_environment.start(force_build=False)
        await trial.agent_environment.stop(delete=True)

    asyncio.run(main())
    mine, native = modal.created
    assert mine.kwargs["gpu"] == native.kwargs["gpu"] == "H100:1"


@needs_modal
def test_a_copy_sandbox_requests_the_gpus_of_the_environment_it_copies(tmp_path, monkeypatch):
    """Harbor's trial requests the agent environment's GPUs from task.config.environment and the
    separate verifier's from definition.config; a check of either copy requests the same."""
    modal = Modal(monkeypatch)
    task = task_with(tmp_path, SEPARATE_TASK, VERIFIER_ENVIRONMENT.replace("memory_mb = 512\n", 'memory_mb = 512\ngpus = 1\ngpu_types = ["A100"]\n')
                     .replace("gpus = 0\n", 'gpus = 2\ngpu_types = ["H100"]\n'))
    run = modal_run(tmp_path, monkeypatch, task_dir=task)
    config = trial_config(tmp_path, "modal", task)
    copies = {environment: StateCopy(id=f"copy-{environment}", episode="0000-simulator", point="verification_start",
                                     environment=environment, backend="modal", ids={}, image=f"im-{environment}",
                                     started_at="2026-01-01T00:00:00+00:00") for environment in ("agent", "verifier")}
    for copy in copies.values():
        run.images[copy.id] = SimpleNamespace(object_id=copy.image)

    async def main():
        for copy in copies.values():
            async with inspector_sandbox.sandbox(run, "check", copy=copy):
                pass
        trial = await Trial.create(config)
        trial._init_agent_environment()
        definition = resolve_verifier_environment_definition(trial.task.config, trial.task.paths)
        verifier = EnvironmentFactory.create_environment_from_config(
            config=config.environment, environment_dir=definition.directory, environment_name=trial.task.short_name,
            session_id="native-verifier", trial_paths=trial.paths, task_env_config=definition.config)
        for environment in (trial.agent_environment, verifier):
            await environment.start(force_build=False)
            await environment.stop(delete=True)

    asyncio.run(main())
    agent, checked, native_agent, native_verifier = [box.kwargs["gpu"] for box in modal.created]
    assert (agent, checked) == (native_agent, native_verifier) == ("A100:1", "H100:2")
    assert [sandbox_record(run, name)["environment"]["cpus"] for name in run.record.sandboxes] == [1, 2]


# Integration: one helper service on real Docker.


def test_a_real_docker_probe_reaches_a_helper_service(tmp_path, docker_env, monkeypatch, credentials):
    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    (task / "environment").mkdir(exist_ok=True)
    (task / "environment" / "docker-compose.yaml").write_text(
        "services:\n  main:\n    depends_on: [helper]\n"
        "  helper:\n    image: python:3.12-slim\n    command: [\"python3\", \"-m\", \"http.server\", \"8080\"]\n")
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    setup = ("python3 -c \"import time, urllib.request\nfor _ in range(30):\n    try:\n"
             "        urllib.request.urlopen('http://helper:8080'); break\n    except OSError: time.sleep(1)\n"
             "\" && mkdir -p /app && echo 42 > /app/answer.txt\n")

    name = asyncio.run(inspection.package_probe(run, setup))
    asyncio.run(copies.delete(run))
    record = sandbox_record(run, name)
    assert record["rewards"]["reward"] == 1.0 and record["cleanup"]["removed"] is True
    assert [copy.error for copy in run.record.copies] == [None, None] and all(copy.deleted for copy in run.record.copies)
    assert Path(record["task_dir"]) == task
