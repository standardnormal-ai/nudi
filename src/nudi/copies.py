"""State copies: nudi's copies of the container filesystem that grades an episode.

`RewardVerifier.verify` calls the run's callback before grading and after the grader,
unless the run is cancelled. On Docker the main container is committed to an image tagged
`nudi-copy-<run id>-<n>`, with its entrypoint emptied and a sleep command, so a check
container started from it runs none of the task's startup code. On Modal the sandbox's
filesystem is snapshotted.

A copy is read by checks of its own episode or sandbox and as an attack inspector's workspace.
The grader inspector reads Simulator copies and its own probes' copies; the hack inspector's
experiments may name any retained episode or sandbox, so every copy stays through the hack phase.
In the full analysis the attack runs last, so the copies of the hack, Simulator and grader inspector
phases all stay until the attack phase's first Attacker attempt, also those of the Attacker attempts
that ran during the hack phase. An attack inspector reads only its own Attacker
attempt's copies, so `discard` deletes every copy taken so far, except those of attempts still
running, before each attempt. `delete` at run end, right after the attack, removes everything left,
also after a failure. Both leave the copies an attack rerun carries from an earlier run, listed first,
as that run recorded them.
"""

import asyncio
import contextlib
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path, PurePosixPath

from harbor.environments.docker.docker import _sanitize_docker_compose_project_name
from harbor.models.task.config import VerifierEnvironmentMode
from harbor.models.task.verifier_mode import resolve_task_verifier_mode

from nudi.episode import COPY_TIMEOUT
from nudi.inspector_sandbox import _now
from nudi.records import Content, StateCopy, write_private

# Harbor bind-mounts its log directories on Docker; Modal keeps them in the copy, but they
# are excluded on both backends so checks behave the same.
LOGS = "/logs"
# Modal keeps a snapshot this long when run-end deletion did not happen.
SNAPSHOT_TTL = 24 * 3600
# The copy image runs no startup code. An inherited healthcheck would fail without the task's
# entrypoint, and compose's `up --wait` refuses a disabled one ("has no healthcheck configured"),
# so the copy gets one that passes; it needs `sh`, as the command does. A commit keeps the
# container's labels, and Harbor's `compose down --rmi local` removes every image labelled with
# its project, so the copied compose project label is cleared or stopping the source deletes the copy.
HEALTHY = 'HEALTHCHECK --interval=1s --timeout=10s --retries=30 CMD ["sh","-c","exit 0"]'
COMMIT_CHANGES = ("--change", "ENTRYPOINT []", "--change", 'CMD ["sh","-c","sleep infinity"]', "--change", HEALTHY,
                  "--change", "LABEL com.docker.compose.project=")
# Every path the container has from a mount rather than its own filesystem, and the size of its
# writable layer, which `docker inspect --size` reports.
MOUNTS_FORMAT = '{"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}},"size":{{json .SizeRw}}}'
# Copies taken before the attack phase stay until it starts, so one container that wrote more than
# this is not copied: a probe writing large files would otherwise fill Docker's disk with copies of them.
COPY_BYTES = 2 * 1024 ** 3
UNPAUSE_TIMEOUT = 10


def excluded():
    """The paths no copy keeps: Harbor's logs and the runtime's own files. On Docker the
    container's mounts, tmpfs paths and image volumes are added."""
    from nudi.persistence import RUNTIME_FILES, RUNTIME_ROOTS

    return sorted({LOGS, *map(str, RUNTIME_ROOTS), *map(str, RUNTIME_FILES)})


def excluded_by(excluded: list[str], location: str) -> str | None:
    """The excluded path `location` lies under, if any."""
    path = PurePosixPath(location)
    return next((root for root in excluded if path == PurePosixPath(root) or PurePosixPath(root) in path.parents), None)


async def take(run, verifier, point: str, *, episode: str, owner: Path, ids: dict[str, str]) -> None:
    """Copy the environment `verifier` grades in and write its receipt under `owner`.

    The whole operation is bounded by `COPY_TIMEOUT`. A failure is recorded on the copy and
    as a run warning, never raised; cancellation is recorded and propagates."""
    from nudi.checks import redacted

    mode = resolve_task_verifier_mode(verifier.task.config)
    copy = StateCopy(id=f"copy-{len(run.record.copies):04d}", episode=episode, point=point, ids=ids,
                     environment="verifier" if mode == VerifierEnvironmentMode.SEPARATE else "agent",
                     backend=run.record.backend, excluded=excluded(), started_at=_now())
    run.record.copies.append(copy)
    run.save()
    try:
        await asyncio.wait_for(_copy(run, verifier.environment, copy, owner), COPY_TIMEOUT)
    except asyncio.CancelledError:
        copy.error = "cancelled"
        raise
    except Exception as error:
        copy.error = redacted(run, f"{type(error).__name__}: {error}")
        run.warn(f"{episode}: {point} copy {copy.id} failed: {copy.error}")
    finally:
        if copy.finished_at is None:
            copy.finished_at = _now()
        copy.seconds = _seconds(copy)
        run.save()


async def _copy(run, environment, copy: StateCopy, owner: Path) -> None:
    from nudi.checks import host_command, project_container

    if copy.backend == "docker":
        container = await project_container(_sanitize_docker_compose_project_name(environment.session_id))
        status, output, error = await host_command(["docker", "inspect", "--size", "--format", MOUNTS_FORMAT, container])
        if status:
            raise RuntimeError(f"docker inspect of the mounts failed: {error.strip()}")
        mounts = json.loads(output)
        # Docker reports -1 for a size it could not compute.
        copy.size_bytes = None if (mounts.get("size") or 0) < 0 else mounts.get("size")
        if (copy.size_bytes or 0) > COPY_BYTES:
            raise RuntimeError(f"the container's writable layer is {copy.size_bytes} bytes, over the {COPY_BYTES}-byte copy bound")
        copy.excluded = sorted({*copy.excluded, *(mount["Destination"] for mount in mounts["mounts"] or []), *(mounts["tmpfs"] or {})})
        # Recorded before the commit starts, so run-end deletion knows an image may come late.
        copy.tag = f"nudi-copy-{run.record.run_id}-{copy.id.removeprefix('copy-')}"
        run.save()
        started = time.monotonic()
        try:
            status, output, error = await host_command(["docker", "commit", *COMMIT_CHANGES, container, copy.tag], timeout=COPY_TIMEOUT)
        except BaseException:
            # The daemon pauses the container while it commits and may keep committing after
            # the client stops, so grading must not start against a paused container.
            with contextlib.suppress(Exception):
                await host_command(["docker", "unpause", container], timeout=UNPAUSE_TIMEOUT)
            raise
        if status:
            raise RuntimeError(f"docker commit failed: {error.strip()}")
        copy.pause_seconds = time.monotonic() - started
        copy.image = output.strip()
        status, output, error = await host_command(["docker", "image", "inspect", "--format", "{{json .Config.Volumes}}", copy.tag])
        if status:
            raise RuntimeError(f"docker image inspect failed: {error.strip()}")
        copy.excluded = sorted({*copy.excluded, *(json.loads(output) or {})})
    else:
        from nudi.modal_env import _guarded

        # Modal reports no snapshot size, so `size_bytes` stays None.
        started = time.monotonic()
        image = await _guarded("snapshot", environment._sandbox.snapshot_filesystem.aio(timeout=COPY_TIMEOUT, ttl=SNAPSHOT_TTL))
        copy.pause_seconds = time.monotonic() - started
        run.images[copy.id] = image
        copy.image = image.object_id
    copy.finished_at = _now()
    copy.seconds = _seconds(copy)
    text = copy.model_dump_json(exclude={"receipt", "deleted", "error"}, indent=2)
    name = f"nudi-evidence/{copy.id}.json"
    write_private(owner / name, text)
    copy.receipt = Content(episode=copy.episode, path=name, sha256=hashlib.sha256(text.encode()).hexdigest())


def _seconds(copy: StateCopy) -> float:
    return (datetime.fromisoformat(copy.finished_at) - datetime.fromisoformat(copy.started_at)).total_seconds()


async def discard(run, keep=()) -> None:
    """Delete every finished copy not yet deleted, except those of the episodes in `keep`, each by its
    own tag on Docker or its snapshot on Modal, and mark it deleted. A failed copy, and one whose
    deletion fails, is left to `delete`. Copies taken meanwhile stay, since they may be a running attempt's."""
    from nudi.checks import host_command

    for copy in [copy for copy in run.record.copies[run.imported_copies:] if copy.episode not in keep]:
        if copy.receipt is None or copy.deleted:
            continue
        with contextlib.suppress(Exception):
            if run.record.backend == "docker":
                status, _, _ = await host_command(["docker", "image", "rm", copy.tag], timeout=COPY_TIMEOUT)
                if status == 0:
                    copy.deleted = True
            else:
                from modal.experimental import image_delete

                from nudi.modal_env import _guarded

                await asyncio.wait_for(_guarded("image delete", image_delete.aio(copy.image)), COPY_TIMEOUT)
                copy.deleted = True
                run.images.pop(copy.id, None)
    run.save()


async def delete(run) -> None:
    """Delete every copy of the run. On Docker this is every image with the run's tag prefix,
    so an image committed after its client timed out goes too. What remains is a warning, and
    so is a failed copy whose image was not listed: the daemon may still commit it later."""
    from nudi.checks import host_command

    own = run.record.copies[run.imported_copies:]
    if not own:
        return
    if run.record.backend == "docker":
        prefix = f"nudi-copy-{run.record.run_id}-"
        listing = ["docker", "image", "ls", "--format", "{{.Repository}}", "--filter", f"reference={prefix}*"]
        listed, remaining = set(), None
        try:
            status, output, _ = await host_command(listing)
            listed = set() if status else set(output.split())
            if listed:
                await host_command(["docker", "image", "rm", *sorted(listed)], timeout=COPY_TIMEOUT)
            status, output, _ = await host_command(listing)
            remaining = None if status else set(output.split())
        except Exception:
            pass
        late = [copy.id for copy in own if copy.tag and copy.error and copy.tag not in listed]
        for copy in own:
            copy.deleted = copy.deleted or (None if remaining is None or copy.tag is None or copy.id in late else copy.tag not in remaining)
        if remaining != set():
            run.warn(f"copy images named {prefix}* may remain: {sorted(remaining or [])}; remove them with `docker image rm`")
        if late:
            run.warn(f"copies {', '.join(late)} failed before Docker listed their images, which the daemon "
                     f"may still commit after this run; remove them with "
                     f"`docker image rm $(docker image ls -q --filter 'reference={prefix}*')`")
    else:
        from modal.experimental import image_delete

        from nudi.modal_env import _guarded

        for copy in own:
            if copy.image is None or copy.deleted:
                continue
            try:
                await asyncio.wait_for(_guarded("image delete", image_delete.aio(copy.image)), COPY_TIMEOUT)
                copy.deleted = True
            except Exception as error:
                copy.deleted = False
                run.warn(f"Modal snapshot {copy.image} of {copy.id} was not deleted ({type(error).__name__}); "
                         f"Modal removes it after {SNAPSHOT_TTL // 3600} h")
    run.save()
