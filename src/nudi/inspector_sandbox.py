"""Inspector sandboxes: a copy of the task package in Harbor's Docker or Modal environment.

The Inspector never acts inside the task harness. A sandbox starts the copied package's
own environment directly, with its declared resources and network policy (a held
workspace has the run's workspace memory limit instead), and runs only
nudi's commands: generated setup programs, the copied grader through Harbor's
`Verifier`, generated checks and, in a held workspace, the Inspector's tool commands.
There is no Trial, agent or actor timer. Host records
stay under the run's `sandboxes/` directory, outside the mounted verifier directory; a setup
sandbox for a separate verifier binds only its own `artifacts/logs/artifacts` there.
A sandbox result establishes what the copied package did, not native accessibility.
"""

import asyncio
import functools
import hashlib
import os
import secrets
import shlex
import stat
import tempfile
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path

from harbor.environments.factory import EnvironmentFactory
from harbor.models.task.artifacts import source_host_path
from harbor.models.task.config import TaskOS
from harbor.models.task.task import Task
from harbor.models.task.verifier_mode import resolve_verifier_environment_definition
from harbor.models.trial.config import ServiceVolumeBind, ServiceVolumeConfig
from harbor.models.trial.paths import EnvironmentPaths, TrialPaths

from nudi.episode import (RewardVerifier, UnsupportedTask, compose_command, environment_config, grading_bound, named, snapshot,
                          tree_digest)
from nudi.records import EnvironmentUnavailable, ErrorRecord, SandboxResult, private_dir, write_private

# Failed starts in a row of one task environment that stop the run. One or two can be a flaky backend;
# a successful start of that environment resets the count. Error texts are not compared: Docker's
# names each sandbox's compose project and includes its build output.
START_FAILURES = 3
# The names of the sandboxes the current experiment opened. Experiments run at once, so each reads only its own.
opened: ContextVar[list[str] | None] = ContextVar("nudi_opened", default=None)
PACKAGE = "/nudi/package"
RUNNER = "/nudi/run.py"
SETUP = "/nudi/setup.sh"
CHECK_PROGRAM = "/nudi/check/program.py"
CHECK_INPUTS = "/nudi/check/inputs.json"
OUTPUT_LIMIT = 65536
# Bounds a command's combined output inside the container, before it reaches the host.
RUNNER_SCRIPT = f'''import os, select, subprocess, sys
with open(sys.argv[1], "rb") as source:
    child = subprocess.Popen(sys.argv[2:], stdin=source, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
stream = child.stdout.fileno()
os.set_blocking(stream, False)
output, eof = bytearray(), False
while len(output) <= {OUTPUT_LIMIT}:
    finished = child.poll() is not None
    try:
        chunk = os.read(stream, min(65536, {OUTPUT_LIMIT + 1} - len(output)))
    except BlockingIOError:
        if finished:
            break
        select.select([stream], [], [], 0.05)
        continue
    if not chunk:
        eof = True
        break
    output.extend(chunk)
truncated = len(output) > {OUTPUT_LIMIT}
if truncated and child.poll() is None:
    child.kill()
code = child.wait()
if not eof:
    # Keep a reader for descendants without retaining later output or holding exec's logs open.
    os.set_blocking(stream, True)
    if os.fork() == 0:
        null = os.open(os.devnull, os.O_RDWR)
        for descriptor in (0, 1, 2):
            os.dup2(null, descriptor)
        try:
            while os.read(stream, 65536):
                pass
        finally:
            os._exit(0)
child.stdout.close()
sys.stdout.buffer.write(output)
sys.exit(125 if truncated else code if code >= 0 else 128 - code)
'''


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _protect_subprocesses(environment) -> None:
    """Adapt the async subprocess paths of supported Harbor 0.24.0 Docker, so a cancelled or
    timed-out wait ends its host child before the sandbox is removed.

    nudi admits only public networking and zero GPUs. Compose collection, image OS inspection
    and the engine `ps` and `cp` that a download falls back to after a compose `cp` failure are
    the remaining async child paths; daemon inspection is synchronous and already has Harbor's
    timeout. These changes belong only to this environment.
    """
    from nudi.checks import finish_cleanup, host_command

    original = environment._collect_buffered_output

    async def collect(process, **kwargs):
        try:
            return await original(process, **kwargs)
        except BaseException:
            await finish_cleanup(asyncio.create_task(environment._terminate_process(process)))
            raise

    async def validate_image_os(image_name: str) -> None:
        try:
            status, output, _ = await host_command(list(type(environment)._engine_cmd("inspect", "--format", "{{.Os}}", image_name)))
        except Exception as error:
            environment.logger.debug(f"Skipping image OS validation for {image_name}: {error}")
            return
        if status:
            environment.logger.debug(f"Skipping image OS validation for {image_name}: docker inspect returned {status}")
            return
        image_os = output.strip().lower()
        expected = "windows" if environment.os == TaskOS.WINDOWS else "linux"
        if image_os and image_os != expected:
            raise RuntimeError(f"Task declares {expected} but Docker image {image_name!r} reports OS {image_os!r}")

    # Harbor's lookup and copy have no limit of their own and decode with replacement; the caller's bound stops them.
    async def resolve_service_container(service: str) -> str:
        # nudi's session id is already a valid compose project name.
        project = environment.session_id
        _, output, _ = await host_command(list(type(environment)._engine_cmd(
            "ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.ID}}\t{{.Names}}")),
            timeout=None, errors="replace")
        for line in output.splitlines():
            container, _, name = line.partition("\t")
            if name.strip().endswith((f"_{service}_1", f"-{service}-1")):
                return container.strip() or name.strip()
        raise RuntimeError(f"Could not resolve container for compose service {service!r} in project {project!r}.")

    async def engine_cp(source: str, destination: str) -> None:
        status, output, _ = await host_command(list(type(environment)._engine_cmd("cp", source, destination)),
                                               timeout=None, errors="replace", merge_stderr=True)
        if status:
            raise RuntimeError(f"Engine cp failed ({source!r} -> {destination!r}): {output}")

    environment._collect_buffered_output = collect
    environment._validate_image_os = validate_image_os
    environment._platform._resolve_service_container = resolve_service_container
    environment._platform._engine_cp = engine_cp


class Sandbox:
    """One started sandbox. Every call is recorded before it runs and saved after."""

    def __init__(self, run, record: SandboxResult, task: Task, paths: TrialPaths, scratch: Path):
        self.run, self.record, self.task, self.paths, self.scratch = run, record, task, paths, scratch
        self.directory = run.config.output_dir / "sandboxes" / record.name
        self.environment = None

    def save(self) -> None:
        write_private(self.directory / "sandbox.json", self.record.model_dump_json(indent=2))

    async def upload_dir(self, source: Path, target: str) -> None:
        self.record.files[target] = tree_digest(source)
        self.save()
        await self.environment.upload_dir(source, target)

    async def upload_text(self, text: str, target: str) -> None:
        await self.upload(text.encode(), target)

    async def upload(self, data: bytes, target: str) -> None:
        source = self.scratch / "uploads" / _sha256(target.encode())
        source.parent.mkdir(exist_ok=True)
        source.write_bytes(data)
        self.record.files[target] = _sha256(data)
        self.save()
        await self.environment.upload_file(source, target)

    async def exec(self, argv: list[str], stdin: str = "/dev/null", *, runtime: str | None, timeout: int | None = None,
                   output_limit: int | None = OUTPUT_LIMIT) -> dict:
        """Use the selected Python 3 runner, or execute a trusted capability probe directly.
        `timeout` is the caller's own limit for this command, passed to Harbor. The SDK
        backend uses direct execution and retains complete results before its own eviction."""
        entry = {"argv": list(argv), "stdin": stdin, "exit_code": None, "output": "", "truncated": False,
                 "error": None, "started_at": _now(), "finished_at": None}
        self.record.commands.append(entry)
        self.save()
        try:
            command = argv if runtime is None else [runtime, RUNNER, stdin, *argv]
            result = await self.environment.exec(shlex.join(command), timeout_sec=timeout)
            output = ((result.stdout or "") + (result.stderr or "")).encode()
            entry["truncated"] = output_limit is not None and len(output) > output_limit
            entry["output"] = output[:output_limit].decode(errors="replace")
            entry["exit_code"] = result.return_code
        except Exception as error:
            entry["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            entry["finished_at"] = _now()
            self.save()
        return entry

    async def grade(self) -> None:
        """Run the copied grader through Harbor's Verifier, as its declared user and under
        its own verifier limit, with the run's `state_copy` callback when one is set; the
        outer limit adds the two copies. Harbor uploads the snapshot's tests after setup,
        using its normal overlay and reward precedence, unless the separate verifier's image
        bundles them, as Harbor decides; no actor timer applies. Rewards are read without
        following links."""
        verifier = self.task.config.verifier
        grader = RewardVerifier(task=self.task, trial_paths=self.paths, environment=self.environment)
        self.record.grader = {"runner": "nudi.episode.RewardVerifier", "skip_tests_upload": grader._skip_tests_upload,
                              "timeout_sec": verifier.timeout_sec, "user": verifier.user, "test_stdout": None}
        self.save()
        try:
            with self.environment.with_default_user(verifier.user):
                result = await asyncio.wait_for(grader.verify(), grading_bound(verifier.timeout_sec))
            self.record.rewards = dict(result.rewards or {})
        except TimeoutError:
            self.record.verifier_timeout = True
        except Exception as error:
            self.record.errors.append(ErrorRecord(type=type(error).__name__, message=str(error)))
        finally:
            output, error = _bounded(self.paths.test_stdout_path)
            self.record.grader.update(test_stdout=output, test_stdout_error=error)
            self.save()


def _bounded(path: Path) -> tuple[str | None, str | None]:
    """Read a regular file without blocking on a FIFO or following a symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        return None, f"{type(error).__name__}: {error}"
    with os.fdopen(descriptor, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            return None, "grader output is not a regular file; unavailable"
        return file.read(OUTPUT_LIMIT).decode(errors="replace"), None


async def _running_image(project: str) -> str:
    from nudi.checks import host_command, project_container

    status, output, error = await host_command(["docker", "inspect", "--format", "{{.Image}}", await project_container(project)])
    if status:
        raise RuntimeError(f"docker inspect failed: {error.strip()}")
    return output.strip()


@asynccontextmanager
async def sandbox(run, purpose: str, *, copy=None, definition: bool = False, artifacts: bool = False):
    """Start a fresh sandbox of a copy of the run's task, then always remove it.

    With `copy`, a `StateCopy`, it starts from that copy instead, from an empty environment
    directory without uploads, and only a workspace gets the package; on Docker the running container's image
    must be the copy's. With `definition`, it starts the task's separate verifier environment
    when the task has one. Only a sandbox of the task's own environment merges its
    environment/docker-compose.yaml, as Harbor's Docker environment does, and runs its
    `[environment].healthcheck` after start, as Harbor's trial does; a copy or a definition
    directory with a compose file is refused. With `artifacts`, as in Harbor's main environment,
    /logs/artifacts is bound to `artifacts/logs/artifacts` under the sandbox record, where
    Harbor's artifact collection reads it.

    The third failed start in a row of the task's environment, or of its separate verifier environment,
    raises `EnvironmentUnavailable` instead of the error, and so does every later sandbox of it, without a start. The spending cap and the run's container admission, which may wait for room, are checked first. Removal is
    shielded from cancellation and then verified, because upstream stop logs its failures:
    on Docker the project's containers are listed, on Modal `ModalBox` asks Modal."""
    from nudi import checks

    run.check_cap()
    await run.admit_container(purpose)
    name = f"sandbox-{len(run.record.sandboxes):04d}"
    session_id = f"nudi-{secrets.token_hex(4)}-{name}"
    # Its cleanup also removes copied read-only directories.
    temporary = tempfile.TemporaryDirectory(prefix=f"nudi-{name}-", ignore_cleanup_errors=True)
    scratch = Path(temporary.name)
    package = scratch / "package"
    try:
        snapshot(run.config.task_dir, package, run.config.credentials_file)
    except BaseException:
        temporary.cleanup()
        raise
    task = Task(package)
    paths = TrialPaths(scratch / "trial")
    paths.mkdir()
    paths.chmod_dir()
    config, directory, upload, own = task.config.environment, task.paths.environment_dir, True, True
    if copy is not None:
        directory, upload, own = scratch / "environment", False, False
        directory.mkdir()
        # The copied environment's declaration, so its GPUs and resources follow it, as Harbor's verifier uses definition.config.
        if copy.environment == "verifier":
            config = resolve_verifier_environment_definition(task.config, task.paths).config
        config = config.model_copy(update={"docker_image": copy.tag or copy.image})
    elif definition and (found := resolve_verifier_environment_definition(task.config, task.paths)):
        config, directory, upload, own = found.config, found.directory, not found.bundled_tests, False
    # The task environment this sandbox builds, whose failed starts count; a state copy builds none.
    kind = None if copy is not None else "environment" if own else "verifier environment"
    policy = config.resolve_baseline()
    # Harbor's override applies to this environment only; the copied files keep the declaration.
    override = run.record.capacity.workspace_memory_mb if purpose == "workspace" else None
    backend = run.config.backend
    settings = environment_config(backend, config.cpus, override or config.memory_mb)
    record = SandboxResult(
        name=name, purpose=purpose, session_id=session_id, ids={"sandbox": name, "session_id": session_id},
        task_dir=str(run.config.task_dir), task_digest=tree_digest(run.config.task_dir), copy_digest=tree_digest(package),
        environment={"type": backend, "cpus": config.cpus, "memory_mb": override or config.memory_mb,
                     "cpu_enforcement": settings.cpu_enforcement_policy.value,
                     "memory_enforcement": settings.memory_enforcement_policy.value,
                     "docker_image": config.docker_image,
                     "network_mode": str(policy.network_mode), "allowed_hosts": policy.allowed_hosts},
        state_copy=copy.id if copy is not None else None)
    box = Sandbox(run, record, task, paths, scratch)
    private_dir(box.directory.parent)
    box.directory.mkdir(mode=0o700)
    run.record.sandboxes.append(name)
    if (names := opened.get()) is not None:
        names.append(name)
    run.save()
    box.save()
    try:
        # Sessions running at once finish after one raised; none of them starts the environment again.
        if kind is not None and run.failed_starts.get(kind, 0) >= START_FAILURES:
            raise EnvironmentUnavailable(f"the task's {kind} already failed to start {START_FAILURES} times in a row; "
                                         "no later sandbox or episode can use it, so the run stops")
        if not own and (compose := named(directory, "docker-compose.yaml", "docker-compose.yml")):
            raise UnsupportedTask(f"{compose[0].name} in the sandbox's environment directory is not verified")
        extra = {}
        if backend == "modal":
            extra["run"] = run
            if copy is not None:
                if copy.id not in run.images:
                    raise RuntimeError(f"the Modal snapshot of {copy.id} is not held by this run")
                extra["copy_image"] = run.images[copy.id]
        # Docker binds these directories; Modal only creates their targets, and Harbor downloads them.
        mounts = [ServiceVolumeConfig(type="bind", source=paths.verifier_dir.resolve().as_posix(),
                                      target=str(EnvironmentPaths.verifier_dir), bind=ServiceVolumeBind(selinux="z"))]
        if artifacts:
            # Harbor's layout: the convention directory mirrored under the collection directory.
            published = source_host_path(box.directory / "artifacts", str(EnvironmentPaths.artifacts_dir))
            published.mkdir(parents=True)
            published.chmod(0o777)
            mounts.append(ServiceVolumeConfig(type="bind", source=published.resolve().as_posix(),
                                              target=str(EnvironmentPaths.artifacts_dir), bind=ServiceVolumeBind(selinux="z")))
        box.environment = EnvironmentFactory.create_environment_from_config(
            config=settings, environment_dir=directory, environment_name=task.short_name, session_id=session_id,
            trial_paths=paths, task_env_config=config, mounts=mounts, network_policy=policy, override_memory_mb=override,
            enable_environment_dir_upload=upload, **extra)
        if backend == "docker":
            _protect_subprocesses(box.environment)
            # As in a native episode, the sandbox is removed at once.
            box.environment._run_docker_compose_command = functools.partial(
                compose_command, box.environment._run_docker_compose_command)
        try:
            # As in Harbor's trial, a verifier definition also starts within the main environment's bound.
            await asyncio.wait_for(box.environment.start(force_build=False), task.config.environment.build_timeout_sec)
            if own:
                await box.environment.run_healthcheck()
        except Exception as error:
            if kind is not None:
                run.failed_starts[kind] = run.failed_starts.get(kind, 0) + 1
                if run.failed_starts[kind] >= START_FAILURES:
                    raise EnvironmentUnavailable(
                        f"the task's {kind} failed to start {START_FAILURES} times in a row, last with {type(error).__name__}: "
                        f"{error}; no later sandbox or episode can use it, so the run stops") from error
            raise
        # A count that stopped the run stays, also when a start already running then succeeds.
        if run.failed_starts.get(kind, 0) < START_FAILURES:
            run.failed_starts.pop(kind, None)
        if copy is not None:
            record.image = copy.image if backend == "modal" else await _running_image(session_id)
            box.save()
            if record.image != copy.image:
                raise RuntimeError(f"the sandbox runs image {record.image}, not {copy.id}'s image {copy.image}")
        # A check reads only its copy; a workspace from a copy still gets the complete task sources.
        if copy is None or purpose == "workspace":
            await box.upload_dir(package, PACKAGE)
        await box.upload_text(RUNNER_SCRIPT, RUNNER)
        yield box
    except asyncio.CancelledError:
        record.cancelled = True
        raise
    except Exception as error:
        record.errors.append(ErrorRecord(type=type(error).__name__, message=str(error)))
        raise
    finally:
        async def remove() -> None:
            if box.environment is not None:
                try:
                    await box.environment.stop(delete=True)
                except Exception as error:
                    record.cleanup["stop_error"] = f"{type(error).__name__}: {error}"
            if backend == "modal":
                # ModalBox asked Modal and warned about a sandbox that still runs.
                record.cleanup.update(sandbox_id=getattr(box.environment, "sandbox_id", None),
                                      removed=getattr(box.environment, "removed", True))
                return
            try:
                status, output, error = await checks.host_command(
                    ["docker", "ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={session_id}"])
                remaining = output.split()
                record.cleanup.update(project=session_id, remaining=remaining, removed=not status and not remaining,
                                      error=error.strip() if status else None)
            except Exception as error:
                record.cleanup.update(project=session_id, remaining=None, removed=None, error=f"{type(error).__name__}: {error}")

        try:
            await checks.finish_cleanup(asyncio.create_task(remove()))
        finally:
            temporary.cleanup()
            if backend == "docker" and record.cleanup.get("removed") is not True:
                run.warn(f"{name}: sandbox containers may remain after removal of project {session_id}: {record.cleanup}")
            if tree_digest(run.config.task_dir) != record.task_digest:
                record.errors.append(ErrorRecord(type="TaskChanged", message="the original task changed while the sandbox ran"))
                run.warn(f"{name}: the original task changed while the sandbox ran")
            if (box.directory / "nudi-evidence").is_dir():
                record.artifacts["nudi_evidence"] = "nudi-evidence"
            box.save()
            run.save()
