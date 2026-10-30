"""Inspector sandboxes: a copy of the task package in Harbor's Docker environment.

The Inspector never acts inside the task harness. A sandbox starts the copied package's
own environment directly, with its declared resources and network policy (a held
workspace has the run's workspace memory limit instead), and runs only
nudi's commands: generated setup programs, the copied grader through Harbor's
`Verifier`, generated checks and, in a held workspace, the Inspector's tool commands.
There is no Trial, agent or actor timer. Host records
stay under the run's `sandboxes/` directory, outside the one mounted verifier directory.
A sandbox result establishes what the copied package did, not native accessibility.
"""

import asyncio
import hashlib
import os
import secrets
import shlex
import shutil
import stat
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from harbor.environments.factory import EnvironmentFactory
from harbor.models.environment_type import EnvironmentType
from harbor.models.task.config import TaskOS
from harbor.models.task.task import Task
from harbor.models.trial.config import ServiceVolumeBind, ServiceVolumeConfig
from harbor.models.trial.paths import EnvironmentPaths, TrialPaths
from harbor.verifier.verifier import Verifier

from nudi.records import ErrorRecord, SandboxResult
from nudi.runner import tree_digest

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


def _protect_startup(environment) -> None:
    """Adapt the two async subprocess paths in supported Harbor 0.24.0 Docker startup.

    nudi admits only public networking and zero GPUs. Compose collection and image OS
    inspection are the remaining async child paths; daemon inspection is synchronous
    and already has Harbor's timeout. These changes belong only to this environment.
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

    environment._collect_buffered_output = collect
    environment._validate_image_os = validate_image_os


class Sandbox:
    """One started sandbox. Every call is recorded before it runs and saved after."""

    def __init__(self, run, record: SandboxResult, task: Task, paths: TrialPaths, scratch: Path):
        self.run, self.record, self.task, self.paths, self.scratch = run, record, task, paths, scratch
        self.directory = run.config.output_dir / "sandboxes" / record.name
        self.environment = None

    def save(self) -> None:
        (self.directory / "sandbox.json").write_text(self.record.model_dump_json(indent=2))

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
        its own verifier limit. Harbor uploads the original host tests after setup and
        capture, using its normal overlay and reward precedence; no actor timer applies."""
        verifier = self.task.config.verifier
        self.record.grader = {"runner": "harbor.verifier.verifier.Verifier", "skip_tests_upload": False,
                              "timeout_sec": verifier.timeout_sec, "user": verifier.user, "test_stdout": None}
        self.save()
        try:
            with self.environment.with_default_user(verifier.user):
                grader = Verifier(task=self.task, trial_paths=self.paths, environment=self.environment)
                result = await asyncio.wait_for(grader.verify(), verifier.timeout_sec)
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


@asynccontextmanager
async def sandbox(run, purpose: str):
    """Start a fresh sandbox of a copy of the run's task, then always remove it.

    The spending cap and the run's container admission are checked first. Removal is
    shielded from cancellation, and the project's containers are listed afterwards,
    because upstream stop logs its failures."""
    from nudi import checks

    run.check_cap()
    run.admit_container(purpose)
    name = f"sandbox-{len(run.record.sandboxes):04d}"
    session_id = f"nudi-{secrets.token_hex(4)}-{name}"
    scratch = Path(tempfile.mkdtemp(prefix=f"nudi-{name}-"))
    copy = scratch / "package"
    shutil.copytree(run.config.task_dir, copy)
    task = Task(copy)
    paths = TrialPaths(scratch / "trial")
    paths.mkdir()
    paths.chmod_dir()
    config = task.config.environment
    policy = config.resolve_baseline()
    # Harbor's override applies to this environment only; the copied files keep the declaration.
    override = run.record.capacity.workspace_memory_mb if purpose == "workspace" else None
    record = SandboxResult(
        name=name, purpose=purpose, session_id=session_id, ids={"sandbox": name, "session_id": session_id},
        task_dir=str(run.config.task_dir), task_digest=tree_digest(run.config.task_dir), copy_digest=tree_digest(copy),
        environment={"type": "docker", "cpus": config.cpus, "memory_mb": override or config.memory_mb,
                     "docker_image": config.docker_image,
                     "network_mode": str(policy.network_mode), "allowed_hosts": policy.allowed_hosts})
    box = Sandbox(run, record, task, paths, scratch)
    box.directory.mkdir(parents=True)
    run.record.sandboxes.append(name)
    run.save()
    box.save()
    try:
        mount = ServiceVolumeConfig(type="bind", source=paths.verifier_dir.resolve().as_posix(),
                                    target=str(EnvironmentPaths.verifier_dir), bind=ServiceVolumeBind(selinux="z"))
        box.environment = EnvironmentFactory.create_environment(
            type=EnvironmentType.DOCKER, environment_dir=task.paths.environment_dir, environment_name=task.short_name,
            session_id=session_id, trial_paths=paths, task_env_config=config, mounts=[mount], network_policy=policy,
            override_memory_mb=override)
        _protect_startup(box.environment)
        await asyncio.wait_for(box.environment.start(force_build=False), config.build_timeout_sec)
        await box.upload_dir(copy, PACKAGE)
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
            shutil.rmtree(scratch, ignore_errors=True)
            if record.cleanup.get("removed") is not True:
                run.warn(f"{name}: sandbox containers may remain after removal of project {session_id}: {record.cleanup}")
            if tree_digest(run.config.task_dir) != record.task_digest:
                record.errors.append(ErrorRecord(type="TaskChanged", message="the original task changed while the sandbox ran"))
                run.warn(f"{name}: the original task changed while the sandbox ran")
            box.save()
            run.save()
