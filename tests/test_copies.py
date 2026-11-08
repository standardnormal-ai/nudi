"""State copies: the grading environment copied before grading and after the grader.

Harbor 0.24.0's real Trial, Verifier and Modal environment run here. Most Docker tests use the
`Sandboxes` double of `test_inspection`, which replaces Harbor's Docker environment itself as
well as `host_command` and the Docker socket client. Modal's SDK calls go through the fakes of
`test_backend`, and Modal's file download is replaced. The acceptance test at the end runs
Harbor's real DockerEnvironment with only the `docker` executable replaced (`fake_docker`).
No test calls Docker or Modal, except the one integration test, which needs Docker and is
skipped without it.
"""

import asyncio
import hashlib
import json
import shutil
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from harbor.environments import modal as harbor_modal
from harbor.models.task.verifier_mode import resolve_verifier_environment_definition
from harbor.trial.trial import Trial
from harbor.trial.errors import VerifierTimeoutError
from harbor.verifier.verifier import DownloadVerifierDirError

from nudi import checks, copies, episode, inspection, inspector_sandbox, run_state, send
from nudi.episode import COPY_TIMEOUT, UnsupportedTask, grading_bound
from nudi.records import Assessment, Check, Observation, RunRecord, StateCopy, write_private
from test_backend import needs_modal, Aio, Modal, leak, modal_run, stored, trial_config, TOKEN_SECRET
from test_inspection import Images, Sandboxes, explained_task, no_native_actor, retained_copy
from test_limits import credentials, new_run  # noqa: F401  (pytest fixture)
from test_runner import CONTRACT_TASK, SEPARATE_TASK, docker_env  # noqa: F401  (pytest fixture)


class Snapshots(Modal):
    """Modal fakes whose sandboxes take filesystem snapshots. The snapshot calls numbered in
    `fail` raise grpclib's credential-quoting error, those in `hang` never return; each moves
    `clock`, when given, by 2 s. With `slow_grader`, the copied grader's command never returns."""

    def __init__(self, monkeypatch, *, fail=(), hang=(), slow_grader=False, clock=None):
        super().__init__(monkeypatch)
        self.snapshots, self.fail_at, self.hang_at, self.slow_grader = [], set(fail), set(hang), slow_grader
        self.graded, self.clock = [], clock

        async def download(environment, source_dir, target_dir):
            # Modal's file copy: the copied grader's reward reaches the host.
            (Path(target_dir) / "reward.txt").write_text("1")

        monkeypatch.setattr(harbor_modal.ModalEnvironment, "_sdk_download_dir", download)

    async def create(self, *entrypoint, **kwargs):
        box = await super().create(*entrypoint, **kwargs)
        execute = box.exec.aio

        async def exec(*argv, **options):
            if "/tests/test.sh" in argv[-1] and "chmod" not in argv[-1]:
                self.graded.append(box.object_id)
                if self.slow_grader:
                    await asyncio.Event().wait()
            return await execute(*argv, **options)

        async def snapshot(timeout, *, ttl):
            self.snapshots.append((box.object_id, timeout, ttl))
            if self.clock:
                self.clock.now += 2
            number = len(self.snapshots)
            if number in self.fail_at:
                leak()
            if number in self.hang_at:
                await asyncio.Event().wait()
            return SimpleNamespace(object_id=f"im-{number}")

        box.exec, box.snapshot_filesystem = Aio(exec), Aio(snapshot)
        return box


class Clock:
    """The monotonic clock `copies` times calls with, which moves only when a fake moves `now`."""

    def __init__(self, monkeypatch):
        self.now = 0.0
        monkeypatch.setattr(copies, "time", SimpleNamespace(monotonic=lambda: self.now))


def taking(run, owner):
    """The `state_copy` callback a native episode gets, for episode 0000-simulator."""
    async def copy(verifier, point):
        await copies.take(run, verifier, point, episode="0000-simulator", owner=owner,
                          ids={"trial_id": str(verifier.environment.context_id)})
    return copy


async def verify(trial, separate, tmp_path):
    """Grade through Harbor's own Trial verifier step, as `Trial.run` does after the agent."""
    trial._init_agent_environment()
    await trial.agent_environment.start(force_build=False)
    try:
        timeout = trial.config.verifier.override_timeout_sec
        if separate:
            return await trial._run_separate_verifier(key="test", timeout_sec=timeout, artifacts_dir=tmp_path / "artifacts", user=None)
        return await trial._run_shared_verifier(timeout_sec=timeout, user=None)
    finally:
        await trial.agent_environment.stop(delete=True)


@pytest.mark.parametrize("separate", [False, True])
@needs_modal
def test_the_real_verifier_copies_the_environment_it_grades_in(tmp_path, monkeypatch, separate):
    """Shared mode copies the agent's sandbox, separate mode the verifier's, before grading
    and after the grader. Each snapshot is bounded and kept 24 h at most; its receipt is
    written under the episode."""
    modal = Snapshots(monkeypatch)
    task = SEPARATE_TASK if separate else CONTRACT_TASK
    run = modal_run(tmp_path, monkeypatch, task_dir=task)
    config = trial_config(tmp_path, "modal", task)
    assert config.verifier.override_timeout_sec == grading_bound(60.0) == 60 + 2 * COPY_TIMEOUT + episode.COPY_MARGIN
    owner = tmp_path / "episode"

    async def main():
        token = episode.state_copy.set(taking(run, owner))
        try:
            with run_state.model_calls(run, "simulator", "0000-simulator"):
                return await verify(await Trial.create(config), separate, tmp_path)
        finally:
            episode.state_copy.reset(token)

    result = asyncio.run(main())
    assert result.rewards == {"reward": 1}
    grader = "sb-1" if separate else "sb-0"
    assert modal.graded == [grader]
    assert modal.snapshots == [(grader, COPY_TIMEOUT, copies.SNAPSHOT_TTL)] * 2
    record = stored(run)
    assert [(copy.point, copy.environment, copy.image, copy.error) for copy in record.copies] == [
        ("verification_start", "verifier" if separate else "agent", "im-1", None),
        ("grading_end", "verifier" if separate else "agent", "im-2", None)]
    for copy in record.copies:
        assert copy.excluded == copies.excluded() and copy.seconds is not None and copy.tag is None
        text = (owner / copy.receipt.path).read_text()
        assert copy.receipt.sha256 == hashlib.sha256(text.encode()).hexdigest()
        assert StateCopy.model_validate_json(text).id == copy.id
    assert list(run.images) == ["copy-0000", "copy-0001"]


@needs_modal
def test_a_modal_copy_records_the_snapshot_call_duration_and_no_size(tmp_path, monkeypatch):
    """The pause is the snapshot call's own duration, without the copy's other work, here its record
    saves; a failed snapshot's pause is null, not 0. Modal reports no snapshot size and nudi runs
    nothing in the sandbox to measure one, so the size is null."""
    clock = Clock(monkeypatch)
    modal = Snapshots(monkeypatch, fail=[2], clock=clock)
    run = modal_run(tmp_path, monkeypatch)
    config = trial_config(tmp_path, "modal")
    save = run.save

    def saving():
        clock.now += 3
        save()

    monkeypatch.setattr(run, "save", saving)

    async def main():
        token = episode.state_copy.set(taking(run, tmp_path / "episode"))
        try:
            with run_state.model_calls(run, "simulator", "0000-simulator"):
                return await verify(await Trial.create(config), False, tmp_path)
        finally:
            episode.state_copy.reset(token)

    assert asyncio.run(main()).rewards == {"reward": 1}
    box, = modal.created
    assert len(modal.snapshots) == 2 and not any("du " in command for command in box.commands)
    start, end = stored(run).copies
    assert (start.size_bytes, start.error, start.pause_seconds) == (None, None, 2)
    assert end.size_bytes is None and end.pause_seconds is None and end.error.startswith("ModalFailure")


@needs_modal
def test_a_grader_past_its_limit_times_out_as_harbor_reports_it(tmp_path, monkeypatch):
    """The grader keeps the task's own limit inside the longer outer one, so Harbor still
    records VerifierTimeoutError; the second copy is still taken."""
    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    (task / "task.toml").write_text((task / "task.toml").read_text().replace("timeout_sec = 60.0", "timeout_sec = 0.2"))
    Snapshots(monkeypatch, slow_grader=True)
    run = modal_run(tmp_path, monkeypatch, task_dir=task)
    config = trial_config(tmp_path, "modal", task)

    async def main():
        token = episode.state_copy.set(taking(run, tmp_path / "episode"))
        try:
            with run_state.model_calls(run, "simulator", "0000-simulator"):
                return await verify(await Trial.create(config), False, tmp_path)
        finally:
            episode.state_copy.reset(token)

    started = time.monotonic()
    with pytest.raises(VerifierTimeoutError):
        asyncio.run(main())
    assert time.monotonic() - started < 10
    assert [copy.point for copy in stored(run).copies] == ["verification_start", "grading_end"]


@needs_modal
def test_a_grader_error_still_copies_grading_end_and_names_its_cause(tmp_path, monkeypatch):
    """A failed verifier-directory download must not skip grading_end or keep only Harbor's
    own text; otherwise malformed_rewards and resource_exhaustion probes read unobservable."""
    Snapshots(monkeypatch)

    async def failing(environment, source_dir, target_dir):
        raise OSError("the grader filled the disk")

    monkeypatch.setattr(harbor_modal.ModalEnvironment, "_sdk_download_dir", failing)
    run = modal_run(tmp_path, monkeypatch, task_dir=CONTRACT_TASK)
    config = trial_config(tmp_path, "modal", CONTRACT_TASK)

    async def main():
        token = episode.state_copy.set(taking(run, tmp_path / "episode"))
        try:
            with run_state.model_calls(run, "simulator", "0000-simulator"):
                return await verify(await Trial.create(config), False, tmp_path)
        finally:
            episode.state_copy.reset(token)

    with pytest.raises(DownloadVerifierDirError) as raised:
        asyncio.run(main())
    # The Modal cause is named by type only, as ModalBox records every Modal failure.
    assert str(raised.value) == ("Failed to download verifier directory from environment: "
                                 "ModalFailure: Modal download failed: OSError")
    assert [copy.point for copy in stored(run).copies] == ["verification_start", "grading_end"]


@pytest.mark.parametrize("failure", ["error", "timeout"])
@pytest.mark.parametrize("number", [1, 2])
@needs_modal
def test_a_failed_copy_is_recorded_and_grading_keeps_its_reward(tmp_path, monkeypatch, failure, number):
    """A copy that fails or passes COPY_TIMEOUT is recorded on the copy and as a warning,
    without the Modal credential; grading goes on and its reward stays."""
    monkeypatch.setattr(copies, "COPY_TIMEOUT", 0.05)
    Snapshots(monkeypatch, **{"fail" if failure == "error" else "hang": [number]})
    run = modal_run(tmp_path, monkeypatch)
    config = trial_config(tmp_path, "modal")

    async def main():
        token = episode.state_copy.set(taking(run, tmp_path / "episode"))
        try:
            with run_state.model_calls(run, "simulator", "0000-simulator"):
                return await verify(await Trial.create(config), False, tmp_path)
        finally:
            episode.state_copy.reset(token)

    assert asyncio.run(main()).rewards == {"reward": 1}
    record = stored(run)
    failed = record.copies[number - 1]
    expected = "ModalFailure: Modal snapshot failed: ValueError" if failure == "error" else "TimeoutError"
    assert failed.error.startswith(expected) and failed.receipt is None and failed.finished_at and failed.seconds is not None
    assert [copy.error is None for copy in record.copies] == [number == 2, number == 1]
    assert any(f"copy {failed.id} failed" in warning for warning in record.warnings)
    assert TOKEN_SECRET not in (run.config.output_dir / "run.json").read_text()


@needs_modal
def test_cancelling_a_copy_records_it_and_propagates(tmp_path, monkeypatch):
    Snapshots(monkeypatch, hang=[1])
    run = modal_run(tmp_path, monkeypatch)
    config = trial_config(tmp_path, "modal")

    async def main():
        token = episode.state_copy.set(taking(run, tmp_path / "episode"))
        try:
            with run_state.model_calls(run, "simulator", "0000-simulator"):
                grading = asyncio.create_task(verify(await Trial.create(config), False, tmp_path))
                while not run.record.copies:
                    await asyncio.sleep(0.01)
                grading.cancel()
                await grading
        finally:
            episode.state_copy.reset(token)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main())
    copy, = stored(run).copies
    assert copy.error == "cancelled" and copy.receipt is None


def recording(monkeypatch, sandboxes):
    """The Docker commands of the `Sandboxes` double, in order."""
    commands, docker = [], sandboxes.docker

    async def host(command, **kwargs):
        commands.append(command)
        return await docker(command, **kwargs)

    monkeypatch.setattr(checks, "host_command", host)
    return commands


def test_a_docker_copy_runs_no_startup_code_and_omits_what_it_does_not_contain(tmp_path, monkeypatch, credentials):
    """`Sandbox.grade` copies its probe sandbox: the image has no entrypoint, only sleeps and
    has no healthcheck, so a check sandbox starts from it. Its volumes, the container's mounts
    and tmpfs paths, /logs and the runtime's own paths are excluded."""
    sandboxes = Sandboxes(monkeypatch, files={"sandbox-0000": {"/app/answer.txt": b"42\n"}})
    commands = recording(monkeypatch, sandboxes)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    prefix = f"nudi-copy-{run.record.run_id}-"
    sandboxes.images.volumes[prefix + "0000"] = {"/var/lib/data": {}}
    sandboxes.images.mounts = [{"Type": "bind", "Source": "/host/data", "Destination": "/srv/shared"}]
    sandboxes.images.tmpfs = {"/run/scratch": "size=64m"}
    name = asyncio.run(inspection.package_probe(run, "true\n"))
    session = sandboxes.environments[name].session_id
    commits = [command for command in commands if command[:2] == ["docker", "commit"]]
    assert commits == [["docker", "commit", "--change", "ENTRYPOINT []", "--change", 'CMD ["sh","-c","sleep infinity"]',
                        "--change", copies.HEALTHY, "--change", "LABEL com.docker.compose.project=",
                        session, prefix + f"{number:04d}"] for number in (0, 1)]
    start, end = run.record.copies
    assert (start.point, end.point) == ("verification_start", "grading_end")
    base = ["/dev", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/logs", "/proc", "/run/scratch", "/srv/shared", "/sys"]
    assert start.excluded == sorted([*base, "/var/lib/data"]) and end.excluded == base
    assert start.image == Images.id(start.tag) and sandboxes.images.files[start.tag] == {"/app/answer.txt": b"42\n"}
    assert (start.episode, start.environment, start.ids) == (name, "agent", {"sandbox": name, "session_id": session})
    receipt = run.config.output_dir / "sandboxes" / name / start.receipt.path
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == start.receipt.sha256

    async def check():
        async with inspector_sandbox.sandbox(run, "check", copy=start) as box:
            return box.record

    assert asyncio.run(check()).state_copy == start.id
    sandboxes.images.changes[start.tag].remove(copies.HEALTHY)
    with pytest.raises(RuntimeError, match="unhealthy"):
        asyncio.run(check())
    sandboxes.images.changes[start.tag].append("HEALTHCHECK NONE")
    with pytest.raises(RuntimeError, match="has no healthcheck configured"):
        asyncio.run(check())


def test_a_copy_whose_mounts_cannot_be_listed_fails(tmp_path, monkeypatch, credentials):
    """Without the mount list the copy cannot say what it lacks, so it is not complete."""
    sandboxes = Sandboxes(monkeypatch)
    sandboxes.images.mounts = None
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    asyncio.run(inspection.package_probe(run, "true\n"))
    assert all("mounts failed" in copy.error and copy.receipt is None for copy in run.record.copies)
    assert sandboxes.images.commits == []


def test_a_copy_over_the_size_bound_is_not_committed(tmp_path, monkeypatch, credentials):
    """Copies stay until the run ends, so a container whose writable layer exceeds COPY_BYTES is
    not committed: its copy fails, and checks of it are unavailable rather than filling Docker's disk."""
    sandboxes = Sandboxes(monkeypatch)
    sandboxes.images.size = copies.COPY_BYTES + 1
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    asyncio.run(inspection.package_probe(run, "true\n"))
    assert run.record.copies and all(
        f"over the {copies.COPY_BYTES}-byte copy bound" in copy.error and copy.receipt is None and copy.tag is None
        and copy.size_bytes == copies.COPY_BYTES + 1 and copy.pause_seconds is None
        for copy in run.record.copies)
    assert sandboxes.images.commits == []


@pytest.mark.parametrize("reported, recorded", [(4096, 4096), (0, 0), (-1, None)])
def test_a_docker_copy_records_its_writable_layer_and_the_commit_call_duration(tmp_path, monkeypatch, credentials,
                                                                                 reported, recorded):
    """The size is the writable layer `docker inspect --size` reports before the commit; Docker's -1,
    a size it could not compute, is null, and a reported 0 stays 0. The pause is the `docker commit`
    call's own duration, during which Docker pauses the container, without the inspections around it."""
    clock = Clock(monkeypatch)
    sandboxes = Sandboxes(monkeypatch)
    sandboxes.images.size = reported
    docker = sandboxes.docker

    async def host(command, **kwargs):
        clock.now += {("docker", "inspect"): 3, ("docker", "commit"): 2, ("docker", "image"): 5}.get(tuple(command[:2]), 0)
        return await docker(command, **kwargs)

    monkeypatch.setattr(checks, "host_command", host)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    asyncio.run(inspection.package_probe(run, "true\n"))
    copied = stored(run).copies
    assert [(copy.error, copy.size_bytes, copy.pause_seconds) for copy in copied] == [(None, recorded, 2)] * 2


def hung_commit(monkeypatch, sandboxes):
    """A `docker commit` client that never returns, as one waiting on a slow daemon."""
    docker = sandboxes.docker

    async def host(command, **kwargs):
        if command[:2] == ["docker", "commit"]:
            await asyncio.Event().wait()
        return await docker(command, **kwargs)

    monkeypatch.setattr(checks, "host_command", host)
    monkeypatch.setattr(episode, "COPY_TIMEOUT", 0.05)
    monkeypatch.setattr(copies, "COPY_TIMEOUT", 0.05)


def test_a_timed_out_commit_unpauses_the_container_before_grading(tmp_path, monkeypatch, credentials):
    """The copy records its tag before the commit starts. After the timeout the container is
    unpaused, ignoring the error, and the copy stays failed."""
    sandboxes = Sandboxes(monkeypatch)
    hung_commit(monkeypatch, sandboxes)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    unpause = sandboxes.images.handle

    def failing(command, *args):
        if command[:2] == ["docker", "unpause"]:
            sandboxes.images.unpaused.append(command[2])
            sandboxes.events.append(("unpause", command[2]))
            return 1, "", "Error response from daemon: container is not paused"
        return unpause(command, *args)

    sandboxes.images.handle = failing
    name = asyncio.run(inspection.package_probe(run, "true\n"))
    session = sandboxes.environments[name].session_id
    assert sandboxes.images.unpaused == [session, session]
    start, end = stored(run).copies
    assert [copy.tag for copy in (start, end)] == [f"nudi-copy-{run.record.run_id}-{n:04d}" for n in (0, 1)]
    assert all(copy.error and copy.image is None and copy.receipt is None and copy.pause_seconds is None for copy in (start, end))
    actions =[event[0] if event[0] != "exec" or "/tests/test.sh" not in event[2] else "grade" for event in sandboxes.events]
    assert actions.index("unpause") < actions.index("grade")


def test_a_late_image_of_a_failed_copy_is_unknown_not_deleted(tmp_path, monkeypatch, credentials):
    """A failed copy whose image was not listed at run end may still be committed by the
    daemon. Its deletion is unknown, and one warning names the prefix and the removal."""
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    done = retained_copy(run, sandboxes)
    failed = retained_copy(run, sandboxes, error="TimeoutError: ", image=None)
    del sandboxes.images.files[failed.tag]
    asyncio.run(copies.delete(run))
    sandboxes.images.files[failed.tag] = {}  # the daemon finishes the commit after cleanup
    record = stored(run)
    assert [copy.deleted for copy in record.copies] == [True, None]
    prefix = f"nudi-copy-{run.record.run_id}-"
    late = [warning for warning in record.warnings if "copy-0001" in warning]
    assert late == [f"copies copy-0001 failed before Docker listed their images, which the daemon may still commit after "
                    f"this run; remove them with `docker image rm $(docker image ls -q --filter 'reference={prefix}*')`"]
    assert done.tag not in sandboxes.images.files and failed.tag in sandboxes.images.files


def test_a_failed_docker_commit_is_redacted(tmp_path, monkeypatch, credentials):
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    key = next(iter(run.keys.values()))
    docker = sandboxes.docker

    async def host(command, **kwargs):
        if command[:2] == ["docker", "commit"]:
            return 1, "", f"daemon echoed {key}"
        return await docker(command, **kwargs)

    monkeypatch.setattr(checks, "host_command", host)
    asyncio.run(inspection.package_probe(run, "true\n"))
    assert all(copy.error and "[redacted]" in copy.error for copy in run.record.copies)
    assert key not in (run.config.output_dir / "run.json").read_text()


def test_every_copy_image_of_the_run_is_deleted_also_one_committed_late(tmp_path, monkeypatch, credentials):
    """Deletion lists the run's tag prefix, so an image committed after its client timed out
    goes too; another run's images stay."""
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    copy = retained_copy(run, sandboxes)
    late, other = f"nudi-copy-{run.record.run_id}-0001", "nudi-copy-otherrun-0000"
    sandboxes.images.files.update({late: {}, other: {}})
    asyncio.run(copies.delete(run))
    assert list(sandboxes.images.files) == [other]
    assert stored(run).copies[0].deleted is True and copy.tag not in sandboxes.images.files


def test_an_image_that_stays_is_a_warning(tmp_path, monkeypatch, credentials):
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    copy = retained_copy(run, sandboxes)
    docker = sandboxes.docker

    async def host(command, **kwargs):
        if command[:3] == ["docker", "image", "rm"]:
            return 1, "", "image is in use"
        return await docker(command, **kwargs)

    monkeypatch.setattr(checks, "host_command", host)
    asyncio.run(copies.delete(run))
    record = stored(run)
    assert record.copies[0].deleted is False
    assert any(copy.tag in warning and "docker image rm" in warning for warning in record.warnings)


@pytest.mark.parametrize("failure", [RuntimeError("simulation failed"), asyncio.CancelledError()])
def test_the_run_deletes_its_copies_after_a_failure_or_cancellation(tmp_path, monkeypatch, credentials, failure):
    images = Images()

    async def host(command, **kwargs):
        return images.handle(command, lambda container: {}, None)

    async def simulate(run, episodes):
        tag = f"nudi-copy-{run.record.run_id}-0000"
        images.files[tag] = {}
        run.record.copies.append(StateCopy(id="copy-0000", episode="0000-simulator", point="verification_start",
                                           environment="agent", backend="docker", ids={}, tag=tag, image=Images.id(tag),
                                           started_at="2026-01-01T00:00:00+00:00"))
        raise failure

    original = send.start_run

    def start(settings, roles, analyses):
        run = original(settings, roles, analyses)
        monkeypatch.setattr(checks, "host_command", host)
        return run

    monkeypatch.setattr(send, "start_run", start)
    monkeypatch.setattr(send, "simulate", simulate)

    async def unused(run, *args, **kwargs):
        raise RuntimeError("not run in this test")

    monkeypatch.setattr(send, "inspect_grader", unused)
    new_run(tmp_path / "unused", monkeypatch, credentials)  # the docker capacity and credential setup
    if isinstance(failure, asyncio.CancelledError):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(send.send_nudis_async(CONTRACT_TASK, output_dir=tmp_path / "run", analysis="simulation", credentials_file=credentials))
    else:
        asyncio.run(send.send_nudis_async(CONTRACT_TASK, output_dir=tmp_path / "run", analysis="simulation", credentials_file=credentials))
    assert images.files == {}
    record = RunRecord.model_validate_json((tmp_path / "run" / "run.json").read_text())
    assert record.copies[0].deleted is True
    # A copy its process never finished, as a crash leaves it.
    assert ("- copy-0000: 0000-simulator at verification_start, agent environment on docker; failed: it never finished; deleted"
            in (tmp_path / "run" / "report.md").read_text())


def test_a_run_cancelled_while_deleting_its_copies_keeps_its_reports(tmp_path, monkeypatch, credentials):
    async def simulate(run, episodes):
        run.record.copies.append(StateCopy(id="copy-0000", episode="0000-simulator", point="verification_start",
                                           environment="agent", backend="docker", ids={}, started_at="2026-01-01T00:00:00+00:00"))

    async def unused(run, *args, **kwargs):
        raise RuntimeError("not run in this test")

    monkeypatch.setattr(send, "simulate", simulate)
    monkeypatch.setattr(send, "inspect_grader", unused)
    new_run(tmp_path / "unused", monkeypatch, credentials)  # the docker capacity and credential setup

    async def main():
        started, release = asyncio.Event(), asyncio.Event()

        async def slow_delete(run):
            started.set()
            await release.wait()

        monkeypatch.setattr(copies, "delete", slow_delete)
        task = asyncio.create_task(send.send_nudis_async(CONTRACT_TASK, output_dir=tmp_path / "run", analysis="simulation",
                                                        credentials_file=credentials))
        await started.wait()
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    record = RunRecord.model_validate_json((tmp_path / "run" / "run.json").read_text())
    assert [copy.id for copy in record.copies] == ["copy-0000"]
    assert "copy-0000" in (tmp_path / "run" / "report.md").read_text()


@pytest.mark.parametrize("fails", [False, True])
@needs_modal
def test_modal_snapshots_are_deleted_at_run_end(tmp_path, monkeypatch, fails):
    from modal.experimental import image_delete

    deleted = []

    async def delete(image):
        deleted.append(image)
        if fails:
            leak()

    monkeypatch.setattr(image_delete, "aio", delete)
    run = modal_run(tmp_path, monkeypatch)
    run.record.copies = [StateCopy(id=f"copy-{n:04d}", episode="0000-simulator", point="verification_start", environment="agent",
                                   backend="modal", ids={}, image=image, started_at="2026-01-01T00:00:00+00:00")
                         for n, image in enumerate(["im-1", None])]
    asyncio.run(copies.delete(run))
    assert deleted == ["im-1"]
    record = stored(run)
    assert [copy.deleted for copy in record.copies] == [not fails, None]
    assert any("im-1" in warning and "24 h" in warning for warning in record.warnings) == fails
    assert TOKEN_SECRET not in json.dumps(record.warnings)


def test_a_finished_docker_copy_is_deleted_mid_run_by_its_own_tag(tmp_path, monkeypatch, credentials):
    """`discard` removes each finished copy by its own tag and marks it deleted; a failed copy, whose
    image the daemon may still commit, and a copy whose removal fails stay for run-end deletion,
    which keeps the mid-run result and removes the rest."""
    sandboxes = Sandboxes(monkeypatch)
    commands = recording(monkeypatch, sandboxes)
    run = new_run(tmp_path, monkeypatch, credentials)
    done, refused = retained_copy(run, sandboxes), retained_copy(run, sandboxes)
    failed = retained_copy(run, sandboxes, error="TimeoutError: ", image=None)
    failed.receipt = None
    docker = sandboxes.docker

    async def host(command, **kwargs):
        commands.append(command)
        if command == ["docker", "image", "rm", refused.tag]:
            return 1, "", "image is in use"
        return await docker(command, **kwargs)

    monkeypatch.setattr(checks, "host_command", host)
    asyncio.run(copies.discard(run))
    assert [command for command in commands if command[:3] == ["docker", "image", "rm"]] == [
        ["docker", "image", "rm", done.tag], ["docker", "image", "rm", refused.tag]]
    assert [copy.deleted for copy in stored(run).copies] == [True, None, None]
    assert done.tag not in sandboxes.images.files and {refused.tag, failed.tag} <= set(sandboxes.images.files)
    asyncio.run(copies.discard(run))
    assert sum(command == ["docker", "image", "rm", done.tag] for command in commands) == 1, "a deleted copy is not removed again"
    monkeypatch.setattr(checks, "host_command", docker)
    asyncio.run(copies.delete(run))
    assert [copy.deleted for copy in stored(run).copies] == [True, True, True] and sandboxes.images.files == {}


@needs_modal
def test_a_finished_modal_snapshot_is_deleted_mid_run_and_not_again_at_run_end(tmp_path, monkeypatch):
    from modal.experimental import image_delete

    deleted = []

    async def delete(image):
        deleted.append(image)

    monkeypatch.setattr(image_delete, "aio", delete)
    run = modal_run(tmp_path, monkeypatch)
    receipt = {"episode": "0000-simulator", "path": "nudi-evidence/copy-0000.json", "sha256": "a" * 64}
    run.record.copies = [StateCopy(id="copy-0000", episode="0000-simulator", point="verification_start", environment="agent",
                                   backend="modal", ids={}, image="im-1", receipt=receipt, started_at="2026-01-01T00:00:00+00:00")]
    run.images["copy-0000"] = SimpleNamespace(object_id="im-1")
    asyncio.run(copies.discard(run))
    assert deleted == ["im-1"] and stored(run).copies[0].deleted is True and run.images == {}
    asyncio.run(copies.delete(run))
    assert deleted == ["im-1"] and stored(run).copies[0].deleted is True and stored(run).warnings == []


# Check sandboxes: started from the copy, never from a task compose file.


def sentinel_compose(task: Path) -> None:
    """Compose files where Harbor would merge them, written after the run's admission,
    which refuses them."""
    for directory in ("environment", "tests"):
        (task / directory).mkdir(exist_ok=True)
        (task / directory / "docker-compose.yaml").write_text("services: {main: {command: sentinel}}\n")


@pytest.mark.parametrize("compose", [False, True])
def test_a_copy_sandbox_starts_from_the_copy_alone(tmp_path, monkeypatch, credentials, compose):
    sandboxes = Sandboxes(monkeypatch)
    task = explained_task(tmp_path)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    copy = retained_copy(run, sandboxes)
    if compose:
        sentinel_compose(task)

    async def main():
        async with inspector_sandbox.sandbox(run, "check", copy=copy) as box:
            return box, sandboxes.environments[box.record.name].config

    box, config = asyncio.run(main())
    assert config["task_env_config"].docker_image == copy.tag
    assert config["enable_environment_dir_upload"] is False
    assert list(Path(config["environment_dir"]).parts)[-1] == "environment"
    assert config["environment_dir"] != run.config.task_dir / "environment"
    assert (box.record.state_copy, box.record.image) == (copy.id, copy.image)
    assert not any(event[0] == "upload_dir" and event[2] == inspector_sandbox.PACKAGE for event in sandboxes.events)


def test_a_copy_sandbox_on_another_image_is_refused(tmp_path, monkeypatch, credentials):
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    copy = retained_copy(run, sandboxes, image="sha256:" + "f" * 64)

    async def main():
        async with inspector_sandbox.sandbox(run, "check", copy=copy):
            raise AssertionError("the sandbox started")

    with pytest.raises(RuntimeError, match="not copy-0000's image"):
        asyncio.run(main())


def test_a_definition_sandbox_never_merges_a_task_compose_file(tmp_path, monkeypatch, credentials):
    """The separate verifier's environment definition is the tests directory when it contains a
    compose file; the sandbox refuses it before any environment exists."""
    sandboxes = Sandboxes(monkeypatch)
    task = tmp_path / "task"
    shutil.copytree(SEPARATE_TASK, task)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    sentinel_compose(task)
    definition = resolve_verifier_environment_definition(episode.Task(task).config, episode.Task(task).paths)
    assert definition.directory == episode.Task(task).paths.tests_dir

    async def main():
        async with inspector_sandbox.sandbox(run, "probe", definition=True):
            raise AssertionError("the sandbox started")

    with pytest.raises(UnsupportedTask, match="docker-compose.yaml"):
        asyncio.run(main())
    assert sandboxes.environments == {}


@needs_modal
def test_a_modal_copy_sandbox_starts_from_the_snapshot(tmp_path, monkeypatch):
    modal = Snapshots(monkeypatch)
    run = modal_run(tmp_path, monkeypatch)
    copy = StateCopy(id="copy-0000", episode="0000-simulator", point="verification_start", environment="agent",
                     backend="modal", ids={}, image="im-1", started_at="2026-01-01T00:00:00+00:00")
    run.images[copy.id] = snapshot = SimpleNamespace(object_id="im-1")

    async def main():
        async with inspector_sandbox.sandbox(run, "check", copy=copy) as box:
            return box.record

    record = asyncio.run(main())
    box, = modal.created
    assert box.kwargs["image"] is snapshot
    assert (record.state_copy, record.image) == ("copy-0000", "im-1")
    del run.images[copy.id]
    with pytest.raises(RuntimeError, match="not held by this run"):
        asyncio.run(main())


# Experiments read the copy in place.


@pytest.mark.parametrize(("location", "root"), [("/srv/shared/answer.txt", "/srv/shared"), ("/var/lib/data/answer.txt", "/var/lib/data")])
def test_a_location_under_an_excluded_path_is_unavailable_not_absent(tmp_path, monkeypatch, credentials, location, root):
    """A bind-mount destination and an image volume are not in the copy, so a location under
    one is unavailable and no check sandbox starts."""
    sandboxes = Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    sandboxes.images.mounts = [{"Type": "bind", "Source": "/host/data", "Destination": "/srv/shared"}]
    task = explained_task(tmp_path)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    sandboxes.images.volumes[f"nudi-copy-{run.record.run_id}-0000"] = {"/var/lib/data": {}}
    probe = {"category": "package_oracles", "setup_program": "true\n", "location": location,
             "timing": "at verification start", "program": "print(1)",
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"}}
    receipt = asyncio.run(inspection.measure_experiment(run, probe))
    assert "check" not in receipt
    assert receipt["missing"] == [f"{location} lies under {root}, which copy-0000 omits; it is unavailable, not absent"]
    assert list(sandboxes.environments) == [receipt["episode"]]


@pytest.mark.parametrize(("location", "root"), [("/dev/shm/answer.txt", "/dev"), ("/logs/verifier/reward.json", "/logs")])
def test_a_location_no_copy_keeps_is_refused_before_anything_runs(tmp_path, monkeypatch, credentials, location, root):
    """Harbor's logs and the runtime's paths are in no copy, so such a probe is returned to the model unrun."""
    sandboxes = Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    probe = {"category": "package_oracles", "setup_program": "true\n", "location": location,
             "timing": "at verification start", "program": "print(1)",
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"}}
    with pytest.raises(inspection.InvalidProbe, match=f"{location} lies under {root}, which no state copy keeps"):
        asyncio.run(inspection.measure_experiment(run, probe))
    assert not sandboxes.environments and run.record.sandboxes == []


@pytest.mark.parametrize("location", ["app/answer.txt", "/app/../etc/passwd", "/app//answer.txt", "//app", "/app/*.txt",
                                      "/app/answer.txt/", "/app/\x00", None, 3])
def test_a_location_is_one_normalized_absolute_path(location):
    assert inspection.location_problem(location) is not None


def test_excluded_paths_cover_the_path_and_its_children_only():
    copy = StateCopy(id="copy-0000", episode="e", point="verification_start", environment="agent", backend="docker", ids={},
                     excluded=["/logs", "/data"], started_at="now")
    assert [copies.excluded_by(copy.excluded, path) for path in ("/logs", "/logs/verifier/reward.txt", "/data/x", "/datafile", "/app")] == [
        "/logs", "/logs", "/data", None, None]
    assert inspection.location_problem("/app/answer.txt") is None


def test_records_from_before_state_copies_still_load_and_report(tmp_path, monkeypatch, credentials):
    """A one-file capture record, with its selection, submissions and replays, loads with no copies. Those fields
    are no longer written."""
    from nudi import report

    run = new_run(tmp_path, monkeypatch, credentials)
    raw = json.loads((run.config.output_dir / "run.json").read_text())
    for key in ("copies", "run_id"):
        raw.pop(key)
    raw["capture_selection"] = {"files": [], "status": "complete"}
    raw["submissions"] = [{"content": {"episode": "0000-simulator", "path": "nudi-evidence/state.json", "sha256": "a" * 64},
                           "ids": {}, "location": "/app/answer.txt", "capture_point": "verification_start",
                           "command": ["python3", "-c", "capture"], "program": "capture", "exit_code": 0, "output": "{}"}]
    raw["capture_errors"], raw["replays"] = [], []
    (run.config.output_dir / "run.json").write_text(json.dumps(raw))
    record = RunRecord.model_validate_json((run.config.output_dir / "run.json").read_text())
    assert record.copies == [] and record.run_id == ""
    assert not {"capture_selection", "submissions", "capture_errors", "replays"} & set(record.model_dump())
    assert "submission" not in Check.model_fields and "replay" not in Assessment.model_fields
    report.write(run.config.output_dir, (), ["simulation"])
    assert (run.config.output_dir / "report.md").is_file()


def test_a_real_docker_copy_is_checked_in_place_and_deleted(tmp_path, docker_env, monkeypatch, credentials):
    """Integration: Docker commits a real probe sandbox with a passing healthcheck; a check container
    started from the image reads the file in place. `discard` then deletes the first probe's copies
    by their own tags mid-run, and run end deletes a later probe's copies by the run's tag prefix."""
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))

    async def listed():
        _, output, _ = await checks.host_command(["docker", "image", "ls", "--format", "{{.Repository}}",
                                                  "--filter", f"reference=nudi-copy-{run.record.run_id}-*"])
        return set(output.split())

    async def main():
        await inspection.package_probe(run, "mkdir -p /app && echo 42 > /app/answer.txt\n")
        copy = run.record.copies[0]
        _, health, _ = await checks.host_command(["docker", "image", "inspect", "--format", "{{json .Config.Healthcheck}}", copy.tag])
        assert json.loads(health)["Test"] == ["CMD", "sh", "-c", "exit 0"]
        program = "import json; print(json.dumps({'observations': {'answer': open('/app/answer.txt').read().strip()}}))"
        check = await checks.check_submission(run, copy, Observation(episode=None, path="instruction.md", excerpt="Write the number 42"),
                                              None, program, timing="at verification start")
        await copies.discard(run)
        first = [copy.tag for copy in run.record.copies]
        after_discard = await listed()
        await inspection.package_probe(run, "true\n")
        later = await listed()
        await copies.delete(run)
        return check, first, after_discard, later, await listed()

    check, first, after_discard, later, remaining = asyncio.run(main())
    assert check.exit_code == 0 and '"answer": "42"' in check.output
    assert len(first) == 2 and not after_discard & set(first)
    assert later == {copy.tag for copy in run.record.copies[2:]} and len(later) == 2
    assert remaining == set() and all(copy.deleted for copy in run.record.copies)


# Acceptance: the real pinned DockerEnvironment, with only the docker CLI replaced.


ACCEPTANCE_INSTRUCTION = ("Create the directory /app/out containing a.txt. Write /app/big.bin with more than 2 MiB. "
                          "After grading, /app/graded.txt records the grade.\n")
ACCEPTANCE_SCORING = "# Full credit needs /app/out and a /app/big.bin over 2 MiB."
ACCEPTANCE_GRADER = f'''#!/bin/bash
{ACCEPTANCE_SCORING}
mkdir -p "$COPY_ROOT/logs/verifier"
reward=0
if [ -d "$COPY_ROOT/app/out" ] && [ "$(wc -c < "$COPY_ROOT/app/big.bin")" -gt 2097152 ]; then reward=1; fi
echo "$reward" > "$COPY_ROOT/app/graded.txt"
echo "$reward" > "$COPY_ROOT/logs/verifier/reward.txt"
'''
ACCEPTANCE_SETUP = '''mkdir -p "$COPY_ROOT/app/out"
echo a > "$COPY_ROOT/app/out/a.txt"
head -c 3145728 /dev/zero > "$COPY_ROOT/app/big.bin"
'''
# Each check reads the copy in place; the stand-in keeps a container's root in COPY_ROOT.
ACCEPTANCE_CHECKS = {
    "directory": ("verification_start", "Create the directory /app/out containing a.txt.", '''import json, os
path = os.environ["COPY_ROOT"] + "/app/out"
entries = sorted(os.listdir(path)) if os.path.isdir(path) else None
print(json.dumps({"observations": {"entries": entries}, "results": {"deserved": float(entries == ["a.txt"])}}))
'''),
    "large file": ("verification_start", "Write /app/big.bin with more than 2 MiB.", '''import json, os
size = os.path.getsize(os.environ["COPY_ROOT"] + "/app/big.bin")
print(json.dumps({"observations": {"size": size}, "results": {"deserved": float(size > 2 * 1024 * 1024)}}))
'''),
    "grader-written file": ("grading_end", "After grading, /app/graded.txt records the grade.", '''import json, os
grade = float(open(os.environ["COPY_ROOT"] + "/app/graded.txt").read())
print(json.dumps({"observations": {"grade": grade}, "results": {"deserved": grade}}))
'''),
}


def test_copies_of_a_directory_a_large_file_and_a_grader_written_file_reach_judge(tmp_path, monkeypatch, credentials):
    """The probe sandbox and every check sandbox start through Harbor's DockerEnvironment;
    only the `docker` executable is replaced. Each check reads its copy in place and its
    claim is judged."""
    from fake_docker import install

    from nudi.assessment import assess
    from nudi.records import Claim, Derivation

    state = install(tmp_path / "docker", monkeypatch)
    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    (task / "instruction.md").write_text(ACCEPTANCE_INSTRUCTION)
    (task / "tests" / "test.sh").write_text(ACCEPTANCE_GRADER)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    async def main():
        name = await inspection.package_probe(run, ACCEPTANCE_SETUP)
        scoring = Observation(episode=None, path="tests/test.sh", excerpt=ACCEPTANCE_SCORING)
        found = {}
        for case, (point, excerpt, program) in ACCEPTANCE_CHECKS.items():
            copy, = [copy for copy in run.record.copies if copy.point == point]
            requirement = Observation(episode=None, path="instruction.md", excerpt=excerpt)
            found[case] = await checks.check_submission(run, copy, requirement, scoring, program, timing=f"It applies at {point}.")
        await copies.delete(run)
        return name, found

    name, found = asyncio.run(main())
    start, end = run.record.copies
    assert start.error is None and end.error is None and "/logs/verifier" in start.excluded
    observed = {case: json.loads(check.output.strip().splitlines()[-1])["observations"] for case, check in found.items()}
    assert observed == {"directory": {"entries": ["a.txt"]}, "large file": {"size": 3145728}, "grader-written file": {"grade": 1.0}}
    for case, check in found.items():
        claim = Claim(mechanism=case, episode=name, check=check.id, interpretation=f"The copy shows the {case} the task requires.",
                      derivation=Derivation(observations=list(observed[case]), validity="supported"))
        assessment = assess(claim, run.config.output_dir)
        assert assessment.outcome == "legitimate", (case, assessment.reasons, assessment.missing)
        assert check.state_copy == (end.id if case == "grader-written file" else start.id)
    assert list((state / "images").iterdir()) == [] and list((state / "projects").iterdir()) == []
    assert all(copy.deleted is True for copy in run.record.copies)


def test_a_docker_sandbox_is_removed_without_waiting_for_its_stop_timeout(tmp_path, monkeypatch, credentials):
    """PID 1 is `sh -c "sleep infinity"`, which ignores SIGTERM, so a plain `down` waits Docker's 10 s stop timeout."""
    from fake_docker import install

    state = install(tmp_path / "docker", monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe"):
            pass

    asyncio.run(main())
    downs = [command for command in map(json.loads, (state / "compose.log").read_text().splitlines()) if command[0] == "down"]
    assert downs and all(command[1:3] == ["--timeout", "0"] for command in downs)
    assert list((state / "projects").iterdir()) == []


@needs_modal
def test_a_modal_sandbox_keeps_harbor_removal(tmp_path, monkeypatch):
    """The Docker removal change is skipped on Modal, whose sandbox is terminated, not brought down."""
    modal = Modal(monkeypatch)
    run = modal_run(tmp_path, monkeypatch)

    async def main():
        async with inspector_sandbox.sandbox(run, "probe") as box:
            return box.environment

    environment = asyncio.run(main())
    assert "_run_docker_compose_command" not in vars(environment)
    assert [box.terminate_calls for box in modal.created] == [1]
    assert json.loads((run.config.output_dir / "sandboxes" / "sandbox-0000" / "sandbox.json").read_text())["cleanup"]["removed"] is True


@needs_modal
def test_a_sandbox_names_its_nudi_evidence_directory_only_when_it_was_written(tmp_path, monkeypatch):
    """390 of 616 sandbox records and all 38 inspector sessions named a missing `nudi-evidence` directory."""
    Modal(monkeypatch)
    run = modal_run(tmp_path, monkeypatch)

    async def main(write):
        async with inspector_sandbox.sandbox(run, "probe") as box:
            if write:
                write_private(box.directory / "nudi-evidence" / "copy-0000.json", "{}")
            return box.directory

    for write in (False, True):
        directory = asyncio.run(main(write))
        artifacts = json.loads((directory / "sandbox.json").read_text())["artifacts"]
        assert artifacts == ({"nudi_evidence": "nudi-evidence"} if write else {})
        assert all((directory / path).is_dir() for path in artifacts.values())
