"""Internal Inspector runtime: one Deep Agents conversation in one owned Harbor workspace.

Task experiments use the existing sandbox/episode functions and their admission separately.
The workspace is never a native actor or a grader, and its files never become host inputs
to a fresh experiment implicitly.
"""

import asyncio
import hashlib
import json
import os
import shutil
import stat
import sys
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from uuid import uuid4

import litellm
from deepagents import create_deep_agent
from deepagents.backends.protocol import ExecuteResponse, FileDownloadResponse, FileUploadResponse
from deepagents.backends.sandbox import BaseSandbox
from deepagents.profiles import GeneralPurposeSubagentProfile, HarnessProfile, register_harness_profile
from langchain.agents.middleware import AgentMiddleware
from langchain.agents.structured_output import StructuredOutputError, ToolStrategy
from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.messages import BaseMessage, HumanMessage, message_to_dict
from langchain_litellm import ChatLiteLLM
from langgraph.checkpoint.memory import InMemorySaver
from langsmith import tracing_context

from nudi import checks, sandbox
from nudi.records import ErrorRecord, InfrastructureAbort
from nudi.workflow import SpendingCapReached, model_calls

# The profile identity is private to nudi; LiteLLM still receives the configured route.
register_harness_profile("nudi-inspector", HarnessProfile(
    general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
    excluded_tools=frozenset({"task", "write_todos"}),
))


class InspectorModel(ChatLiteLLM):
    def _get_ls_params(self, *args, **kwargs):
        return {**super()._get_ls_params(*args, **kwargs), "ls_provider": "nudi-inspector"}


class HarborBackend(BaseSandbox):
    """The SDK's file/search implementations over a single nudi-owned sandbox."""

    enable_capture_offload = True

    def __init__(self, box):
        self.box = box
        self.interrupted = []

    @property
    def id(self) -> str:
        return self.box.record.session_id

    def execute(self, command, *, timeout=None):
        raise NotImplementedError("The Harbor Inspector backend is asynchronous; use aexecute")

    def upload_files(self, files):
        raise NotImplementedError("Use aupload_files")

    def download_files(self, paths):
        raise NotImplementedError("Use adownload_files")

    async def aexecute(self, command, *, timeout=None):
        execution = asyncio.create_task(self.box.exec(
            ["sh", "-c", command], runtime=None, timeout=timeout, output_limit=None))
        try:
            result = await asyncio.shield(execution)
        except asyncio.CancelledError:
            # Harbor's compose subprocess can retain inherited output pipes when cancelled.
            # Keep this call owned until sandbox removal stops it, then drain it below.
            self.interrupted.append(execution)
            raise
        return ExecuteResponse(output=result["output"], exit_code=result["exit_code"], truncated=result["truncated"])

    async def aupload_files(self, files):
        results = []
        for path, data in files:
            try:
                await self.box.upload(data, path)
                results.append(FileUploadResponse(path=path))
            except Exception as error:
                results.append(FileUploadResponse(path=path, error=checks.redacted(self.box.run, str(error))))
        return results

    async def adownload_files(self, paths):
        results = []
        for path in paths:
            # A sandbox path never determines a host destination.
            target = self.box.scratch / ("download-" + uuid4().hex)
            try:
                await self.box.environment.download_file(path, target)
                descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise ValueError("download is not a regular file")
                    data = source.read()
                results.append(FileDownloadResponse(path=path, content=data))
            except Exception as error:
                results.append(FileDownloadResponse(path=path, error=checks.redacted(self.box.run, str(error))))
            finally:
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
        return results


class Transcript(AsyncCallbackHandler):
    """Save raw messages before SDK compaction, including its summary model's replies."""

    raise_error = True

    def __init__(self, run, directory, backend):
        self.run, self.directory, self.backend, self.seen = run, directory, backend, set()
        (directory / "transcript.jsonl").touch()

    def save(self, messages):
        with (self.directory / "transcript.jsonl").open("a") as output:
            for message in messages:
                if message.id is None:
                    message.id = uuid4().hex
                key = (message.type, getattr(message, "tool_call_id", None) or message.id)
                if key in self.seen:
                    continue
                self.seen.add(key)
                output.write(checks.redacted(self.run, json.dumps(message_to_dict(message), ensure_ascii=False)) + "\n")

    async def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        with (self.directory / "inferences.jsonl").open("a") as output:
            output.write(checks.redacted(self.run, json.dumps({"id": str(run_id), "messages": [
                [message_to_dict(message) for message in batch] for batch in messages]}, ensure_ascii=False)) + "\n")
        # Restore protected history/results before inference, including summaries. Tools
        # can change their sandbox copies but cannot change these retained host sources.
        sources = [(self.directory / "transcript.jsonl", "/conversation_history/transcript.jsonl")]
        sources.extend((source, f"/nudi/evidence/tool-results/{source.name}")
                       for source in sorted((self.directory / "tool-outputs").iterdir()))
        for source, destination in sources:
            response, = await self.backend.aupload_files([(destination, source.read_bytes())])
            if response.error:
                raise RuntimeError(f"Cannot preserve searchable history/results: {response.error}")

    async def on_tool_end(self, output, **kwargs):
        if isinstance(output, BaseMessage):
            if isinstance(output.artifact, dict) and (path := output.artifact.get("output_file")):
                captured, = await self.backend.adownload_files([path])
                if captured.error or captured.content is None:
                    raise RuntimeError(f"Cannot retain captured tool output: {captured.error or 'missing bytes'}")
                digest = hashlib.sha256(captured.content).hexdigest()
                relative = f"tool-outputs/{digest}"
                retained = self.directory / relative
                if not retained.exists():
                    retained.write_bytes(captured.content)
                output.artifact.update(retained_output=relative, sha256=digest)
                output.content = f"{output.content}\nRetained captured bytes: /nudi/evidence/tool-results/{digest}"
            self.save([output])

    async def on_llm_end(self, response, **kwargs):
        messages = [generation.message for batch in response.generations for generation in batch]
        self.save(messages)
        for message in messages:
            if message.response_metadata.get("finish_reason") == "content_filter":
                raise checks.ProviderRefusal("finish_reason: content_filter")
            if refusal := (message.additional_kwargs.get("refusal")
                           or (message.additional_kwargs.get("provider_specific_fields") or {}).get("refusal")):
                raise checks.ProviderRefusal(checks.redacted(self.run, str(refusal)))


class ToolOwnership(AgentMiddleware):
    """Join SDK tool tasks before a failed turn can close its workspace.

    The SDK runs one reply's tool calls together. This investigation's experiments take turns,
    since admission may leave room for only one beside the workspace; other tools stay
    parallel. Larger hosts are also limited to one experiment at a time per investigation.
    """

    def __init__(self):
        self.pending, self.experiments = set(), asyncio.Lock()

    async def awrap_tool_call(self, request, handler):
        task = asyncio.current_task()
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)
        if request.tool_call["name"] != "run_experiment":
            return await handler(request)
        async with self.experiments:
            try:
                return await handler(request)
            except BaseException:
                # A raised experiment ends the turn; stop queued experiments before they start.
                for other in self.pending - {task}:
                    other.cancel()
                raise

    async def cancel(self):
        tasks = tuple(self.pending)
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Investigation:
    """One conversation and workspace. `ask` continues it and returns a validated schema."""

    def __init__(self, run, name, prompt, box, backend):
        self.run, self.name, self.prompt, self.box, self.backend = run, name, prompt, box, backend
        self.state, self.closed, self.busy, self.retained = {"messages": []}, False, False, False
        self.checkpointer = InMemorySaver()
        self.ownership = ToolOwnership()
        (box.directory / "tool-outputs").mkdir()
        self.transcript = Transcript(run, box.directory, backend)
        config = run.record.models["inspector"]
        kwargs = {}
        if config.reasoning_effort is not None:
            kwargs["reasoning_effort"] = config.reasoning_effort
        if config.model.startswith("xiaomi_mimo/") and config.reasoning_effort not in (None, "none"):
            kwargs["extra_body"] = {"thinking": {"type": "enabled"}}
        self.model = InspectorModel(model=config.model, api_base=config.api_base, api_key=run.keys["inspector"],
                                 model_kwargs=kwargs, streaming=False, max_retries=1, cache=False,
                                 callbacks=[self.transcript])
        (box.directory / "system-prompt.txt").write_text(checks.redacted(run, prompt))
        (box.directory / "results.jsonl").touch()
        (box.directory / "inferences.jsonl").touch()
        (box.directory / "state.json").write_text('{"messages": []}')
        box.record.artifacts.update(transcript="transcript.jsonl", inferences="inferences.jsonl", workspace="workspace",
                                    state="state.json", results="results.jsonl", system_prompt="system-prompt.txt",
                                    tool_outputs="tool-outputs")
        box.save()

    def graph(self, tools=(), schema=None):
        return create_deep_agent(
            model=self.model, tools=tools, backend=self.backend, system_prompt=self.prompt,
            middleware=[self.ownership],
            response_format=ToolStrategy(schema, handle_errors=False) if schema else None,
            subagents=[], skills=None, memory=None, interrupt_on=None, checkpointer=self.checkpointer, store=None,
        )

    async def ask(self, context: str, schema, *, tools=()):
        if self.closed or self.busy:
            raise RuntimeError("An investigation must be open and have only one active turn")
        self.run.check_cap()
        self.busy = True
        message = HumanMessage(content=context, id=uuid4().hex)
        self.transcript.save([message])
        try:
            agent = self.graph(tools, schema)
            with model_calls(self.run, "inspector", self.name), tracing_context(enabled=False):
                async for state in agent.astream(
                    {"messages": [message]}, stream_mode="values",
                    config={"callbacks": [self.transcript], "configurable": {"thread_id": self.box.record.session_id}},
                ):
                    self.state = state
                    self.transcript.save(state["messages"])
            result = self.state.get("structured_response")
            if result is None:
                raise checks.ModelOutputFailure("The Inspector returned no structured result")
            with (self.box.directory / "results.jsonl").open("a") as output:
                output.write(checks.redacted(self.run, json.dumps({"schema": schema.__name__, "result": result.model_dump()})) + "\n")
            return result
        except (asyncio.CancelledError, SpendingCapReached, InfrastructureAbort, checks.ProviderRefusal, checks.ModelOutputFailure):
            raise
        except litellm.ContentPolicyViolationError as error:
            raise checks.ProviderRefusal(checks.redacted(self.run, str(error))) from error
        except StructuredOutputError as error:
            raise checks.ModelOutputFailure(checks.redacted(self.run, str(error))) from error
        except Exception as error:
            raise checks.InferenceFailure(checks.redacted(self.run, f"{type(error).__name__}: {error}")) from error
        finally:
            await checks.finish_cleanup(asyncio.create_task(self.ownership.cancel()))
            self.busy = False
            (self.box.directory / "state.json").write_text(checks.redacted(
                self.run, json.dumps(self.state, default=lambda value: value.model_dump(), ensure_ascii=False)))

    async def fork(self, source):
        """Continue a copy of another investigation's final SDK state on a new thread of its
        checkpointer: every channel, compaction included, so this conversation starts as its
        model last saw it. The SDK keeps messages in a DeltaChannel and InMemorySaver has no
        copy_thread, so the copy goes through LangGraph's state API, not the head checkpoint."""
        self.checkpointer = source.checkpointer
        graph = self.graph()
        values = (await graph.aget_state({"configurable": {"thread_id": source.box.record.session_id}})).values
        await graph.aupdate_state({"configurable": {"thread_id": self.box.record.session_id}}, values, as_node="model")
        self.state = values
        # The searchable raw history continues the source's, pre-compaction messages included.
        shutil.copyfile(source.box.directory / "transcript.jsonl", self.box.directory / "transcript.jsonl")
        self.transcript.seen = set(source.transcript.seen)

    async def retain(self):
        """Copy only regular workspace and SDK artifact files to host records before removal."""
        listing = await self.backend.aexecute(
            "find /nudi/workspace /conversation_history /large_tool_results -type f -print0")
        if listing.exit_code or listing.truncated:
            raise RuntimeError("Workspace retention listing failed or exceeded its output limit")
        root = self.box.directory / "workspace"
        root.mkdir(exist_ok=True)
        for name in listing.output.split("\0"):
            if not name:
                continue
            path = PurePosixPath(name)
            if ".." in path.parts or not any(path.is_relative_to(prefix) for prefix in (
                    "/nudi/workspace", "/conversation_history", "/large_tool_results")):
                raise ValueError("Workspace retention returned a path outside its scope")
            response, = await self.backend.adownload_files([name])
            if response.error:
                raise RuntimeError(f"Cannot retain {name}: {response.error}")
            target = root / path.relative_to("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(response.content)
        self.retained = True


@asynccontextmanager
async def investigation(run, name: str, prompt: str, evidence: dict[str, Path], fork: Investigation | None = None):
    """Own one sandbox until all turns and fresh experiments finish, then retain and remove it.

    Evidence is an explicit selection of files already retained within this run, mapped to
    relative names under `/nudi/evidence`. No host directory or credential file is mounted.
    A fork continues a closed investigation's conversation; its retained workspace files are
    restored at their original paths, which that conversation may reference.
    `CapacityUnavailable` means no new container starts; callers report incomplete evidence.
    """
    selected = {}
    for name_in_box, source in evidence.items():
        relative = PurePosixPath(name_in_box)
        path = source.resolve()
        if (relative.is_absolute() or ".." in relative.parts or not relative.parts
                or not path.is_relative_to(run.config.output_dir.resolve()) or not path.is_file()
                or (run.config.credentials_file and path == run.config.credentials_file.resolve())):
            raise ValueError("Investigation evidence must be a selected run file with a relative destination")
        selected[relative] = path
    backend = None
    try:
        async with sandbox.sandbox(run, "workspace") as box:
            runtime, _ = await checks.python3_runtime(box)
            if runtime != "python3":
                raise RuntimeError("unsupported_runtime: Deep Agents file tools require the python3 executable")
            seed = box.scratch / "workspace-seed"
            for directory in ("nudi/workspace", "nudi/evidence/tool-results", "conversation_history", "large_tool_results"):
                (seed / directory).mkdir(parents=True, exist_ok=True)
            for relative, path in selected.items():
                target = seed / "nudi/evidence" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                data = path.read_bytes()
                for secret in run.keys.values():
                    data = data.replace(secret.encode(), b"[redacted]")
                target.write_bytes(data)
            if fork is not None and (fork.box.directory / "workspace").is_dir():
                shutil.copytree(fork.box.directory / "workspace", seed, dirs_exist_ok=True)
            await box.upload_dir(seed, "/")
            backend = HarborBackend(box)
            session = Investigation(run, name, prompt, box, backend)
            if fork is not None:
                await session.fork(fork)
            try:
                yield session
            finally:
                session.closed = True
                interrupted = sys.exception() is not None
                try:
                    await checks.finish_cleanup(asyncio.create_task(session.retain()))
                except Exception as error:
                    message = checks.redacted(run, f"{type(error).__name__}: {error}")
                    box.record.errors.append(ErrorRecord(type="WorkspaceRetentionError", message=message))
                    run.warn(f"{box.record.name}: workspace artifacts are incomplete: {message}")
                    box.save()
                    if not interrupted:
                        raise
    finally:
        if backend is not None and backend.interrupted:
            async def drain():
                results = await asyncio.gather(*backend.interrupted, return_exceptions=True)
                for result in results:
                    if isinstance(result, dict):
                        result["interrupted"] = True
                backend.box.save()

            await checks.finish_cleanup(asyncio.create_task(drain()))
