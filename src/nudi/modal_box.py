"""Harbor's Modal environment for every Modal container of a nudi run: native agent and
separate verifier environments and Inspector sandboxes.

Only `runner.MODAL_BOX`, Harbor's import path, names this module, so importing nudi or
running on Docker never imports the Modal SDK, which reads the user's Modal profile.
"""

import asyncio

from harbor.environments import modal
from harbor.utils.optional_import import MissingExtraError

from nudi.records import ModalSandbox
from nudi.sandbox import _now
from nudi.workflow import current

# Bounds each Modal call of a stop: the termination, the wait for it and each removal check.
REMOVAL_TIMEOUT = 60


class ModalFailure(RuntimeError):
    """A Modal SDK or transport failure, named only by its operation and exception type. The
    original text can quote the Modal credential, as grpclib's metadata check does, so it is
    dropped before Harbor or nudi logs or records the error."""


async def _guarded(operation: str, call):
    try:
        return await call
    except ModalFailure:
        raise
    except TimeoutError:
        raise TimeoutError(f"Modal {operation} timed out") from None
    except Exception as error:
        raise ModalFailure(f"Modal {operation} failed: {type(error).__name__}") from None


def _bounded(call):
    return asyncio.wait_for(call, REMOVAL_TIMEOUT)


class ModalBox(modal.ModalEnvironment):
    """Harbor's Modal environment with every SDK failure translated into a `ModalFailure`.

    Stop terminates the sandbox and asks Modal whether it ended; if not, it terminates it
    once more. Each Modal call of a stop is bounded by `REMOVAL_TIMEOUT`. Each stopped
    sandbox is recorded in the run, with a warning when it still runs: it can run up to
    Harbor's 24 h lifetime. The run is the one given, else the run whose model calls
    surround the trial. With `copy_image`, the snapshot of a state copy, the sandbox starts from it."""

    def __init__(self, *args, run=None, copy_image=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.run, self.created_at, self.removed, self.sandbox_id = run, _now(), None, None
        self.copy_image = copy_image

    async def _create_sandbox(self, **kwargs):
        # A check sandbox starts from the snapshot of a state copy, not the task's image.
        if self.copy_image is not None:
            self._image = self.copy_image
        return await super()._create_sandbox(**kwargs)

    @classmethod
    def preflight(cls) -> None:
        if not modal._HAS_MODAL:
            raise MissingExtraError(package="modal", extra="modal")
        super().preflight()

    async def start(self, force_build: bool):
        await _guarded("start", super().start(force_build))

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        return await _guarded("exec", super().exec(command, cwd=cwd, env=env, timeout_sec=timeout_sec, user=user))

    async def upload_file(self, source_path, target_path):
        await _guarded("upload", super().upload_file(source_path, target_path))

    async def upload_dir(self, source_dir, target_dir):
        await _guarded("upload", super().upload_dir(source_dir, target_dir))

    async def download_file(self, source_path, target_path):
        await _guarded("download", super().download_file(source_path, target_path))

    async def download_dir(self, source_dir, target_dir):
        await _guarded("download", super().download_dir(source_dir, target_dir))

    async def is_dir(self, path, user=None):
        return await _guarded("exec", super().is_dir(path, user))

    async def is_file(self, path, user=None):
        return await _guarded("exec", super().is_file(path, user))

    async def _apply_network_policy(self, network_policy):
        await _guarded("network policy", super()._apply_network_policy(network_policy))

    async def _raise_if_unexpected_exit_137(self, *, cause: Exception) -> None:
        """Harbor's check, without logging the text of a failed status read."""
        if self._sandbox is None or self._sandbox_termination_requested:
            return
        try:
            return_code = await self._sandbox.poll.aio()
        except Exception:
            return
        if return_code == 137:
            raise modal.SandboxLikelyOutOfMemoryError(requested_memory_mb=self._requested_memory_mb())

    async def stop(self, delete: bool):
        # Harbor's Modal stop tears the sandbox down whatever `delete` says; so does this one.
        sandbox = self._sandbox
        if sandbox is None:
            self.removed = True
            return
        self.sandbox_id, failure = sandbox.object_id, ""
        self._sandbox_termination_requested = True
        try:
            await _bounded(sandbox.terminate.aio())
            await _bounded(sandbox.wait.aio(raise_on_termination=False))
        except Exception:
            pass  # The check below decides.
        finally:
            self._sandbox = self._app = self._image = self._stream_handle = None
        try:
            if await _bounded(sandbox.poll.aio()) is None:
                await _bounded(sandbox.terminate.aio(wait=True))
            self.removed = await _bounded(sandbox.poll.aio()) is not None
        except Exception as error:
            self.removed, failure = False, f" ({type(error).__name__})"
        self._record(failure)

    def _record(self, failure: str) -> None:
        run = self.run or (scope[0] if (scope := current.get()) else None)
        message = (f"Modal sandbox {self.sandbox_id} ({self.session_id}) still runs after two terminations{failure}; "
                   "it can run up to 24 h and is billed until Modal ends it")
        if run is None:
            if not self.removed:
                self.logger.warning(message)
            return
        run.record.modal.append(ModalSandbox(
            session_id=self.session_id, sandbox_id=self.sandbox_id, cpus=self._effective_cpus,
            memory_mb=self._effective_memory_mb, started_at=self.created_at, stopped_at=_now(), removed=self.removed))
        if not self.removed:
            run.warn(message)
        run.save()
