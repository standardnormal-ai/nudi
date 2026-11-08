"""Contracts for the pinned Verifiers Harbor adapter and native Harbor.

Docker episodes and native trials run one at a time against a local scripted
OpenAI-compatible endpoint. No model provider is called.
"""

import asyncio
import base64
import contextlib
import functools
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import litellm
import pytest
from aiohttp import web
from harbor.models.trial.config import AgentConfig, TaskConfig, TrialConfig
from harbor.trial.trial import Trial
from verifiers.v1.cli.eval.runner import run_eval
from verifiers.v1.configs.cli.eval import EvalConfig
from verifiers.v1.tasksets.harbor import HarborEnv
from verifiers.v1.tasksets.harbor import taskset as harbor_taskset
from verifiers.v1.tasksets.harbor.taskset import HarborConfig, parse_task
from verifiers.v1.utils.loaders import environment_class, load_taskset, taskset_config_type

VERIFIERS_VERSION = "0.4.1.dev12"
# Package entries of the verified wheel's RECORD.
VERIFIERS_RECORD_DIGEST = "4130103379da1031c9aa9363299df083d453532aea733ade831fcf9c450e1f09"
HARBOR_VERSION = "0.24.0"
LITELLM_VERSION = "1.106.0"
# The Inspector runtime: Deep Agents over ChatLiteLLM, on LangChain's agent and LangGraph.
SDK_VERSIONS = {"deepagents": "0.7.32", "langchain-litellm": "0.11.1", "langchain": "1.4.7",
                "langchain-core": "1.7.1", "langgraph": "1.2.18"}
FIXTURES = Path(__file__).parent / "fixtures"
CONTRACT_TASK = FIXTURES / "contract-task"
SEPARATE_TASK = FIXTURES / "separate-verifier-task"
DOCKERFILE_TASK = FIXTURES / "dockerfile-task"
SLOW_GRADER_TASK = FIXTURES / "slow-grader-task"
PROVIDER_KEY = "nudi-contract-provider-key"
HOST_SECRET = "nudi-host-secret-must-not-leak"
DOCKER = shutil.which("docker") is not None and subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def masked(text: str) -> str:
    """A grep pattern for `text` that does not contain `text` itself."""
    return f"'{text[:-1]}[{text[-1]}]'"


# Outputs differ from the command text, since Terminus observations echo the typed command.
# Patterns are masked so that stored traces contain a secret only if it really leaked.
ARGV = "cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' '"
PROBE_AND_ANSWER = (
    "echo tests_$(test -e /tests && echo visible || echo hidden); "
    "echo marker_$(test -e /app/marker && echo present || echo absent); "
    "touch /app/marker; "
    "cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max; "
    f"echo host_secret_count=$(env | grep -c {masked(HOST_SECRET)}); "
    f"echo provider_key_count=$(env | grep -c {masked(PROVIDER_KEY)}); "
    f"echo api_key_args=$({ARGV} | grep -o -- {masked('--api-key=')} | wc -l); "
    f"echo provider_key_args=$({ARGV} | grep -o -- {masked(PROVIDER_KEY)} | wc -l); "
    "echo 42 > /app/answer.txt"
)


def assert_probe(output: str) -> None:
    for expected in (
        "tests_hidden",
        "marker_absent",
        "100000 100000",
        str(512 * 1024 * 1024),
        "host_secret_count=0",
        "provider_key_count=0",
        "provider_key_args=0",
    ):
        assert expected in output


FIRST_USAGE = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18, "cost": 0.0005}
LAST_USAGE = {"prompt_tokens": 13, "completion_tokens": 2, "total_tokens": 15}


class ScriptedModel:
    """Chat endpoint that requests one bash call, then answers."""

    def __init__(self, command: str):
        self.command = command
        self.requests: list[tuple[dict, dict]] = []

    def reply(self, body: dict) -> tuple[dict, str, dict]:
        if any(message.get("role") == "tool" for message in body["messages"]):
            return {"role": "assistant", "content": "done"}, "stop", LAST_USAGE
        call = {
            "index": 0,
            "id": f"call_{len(self.requests)}",
            "type": "function",
            "function": {"name": "bash", "arguments": json.dumps({"command": self.command})},
        }
        message = {"role": "assistant", "content": None, "tool_calls": [call]}
        return message, "tool_calls", FIRST_USAGE

    async def chat(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.requests.append((dict(request.headers), body))
        message, finish, usage = self.reply(body)
        head = {"id": "chatcmpl-contract", "created": 0, "model": body["model"]}
        if not body.get("stream"):
            choice = {"index": 0, "message": message, "finish_reason": finish}
            return web.json_response(
                {**head, "object": "chat.completion", "choices": [choice], "usage": usage}
            )
        chunk = {**head, "object": "chat.completion.chunk"}
        events = [
            {**chunk, "choices": [{"index": 0, "delta": message, "finish_reason": finish}]},
            {**chunk, "choices": [], "usage": usage},
        ]
        text = "".join(f"data: {json.dumps(event)}\n\n" for event in events)
        return web.Response(text=text + "data: [DONE]\n\n", content_type="text/event-stream")

    def tool_outputs(self) -> list[str]:
        return [
            str(message["content"])
            for _, body in self.requests
            for message in body["messages"]
            if message.get("role") == "tool"
        ]


class TerminusScript(ScriptedModel):
    """Terminus 2 JSON replies: type the command and claim completion, then confirm."""

    def __init__(self, command: str, duration: float = 2.0):
        super().__init__(command)
        self.duration = duration

    def reply(self, body: dict) -> tuple[dict, str, dict]:
        first = not any(message["role"] == "assistant" for message in body["messages"])
        commands = [{"keystrokes": f"{self.command}\n", "duration": self.duration}] if first else []
        content = json.dumps(
            {"analysis": "Scripted.", "plan": "Scripted.", "commands": commands, "task_complete": True}
        )
        return {"role": "assistant", "content": content}, "stop", FIRST_USAGE if first else LAST_USAGE

    def observations(self) -> list[str]:
        """The terminal text Terminus sent back after the first turn."""
        return [str(body["messages"][-1]["content"]) for _, body in self.requests[1:]]


async def list_models(request: web.Request) -> web.Response:
    return web.json_response({"object": "list", "data": []})


@contextlib.asynccontextmanager
async def serve(scripted: ScriptedModel):
    """Serve the scripted model on a free local port; yields its base URL."""
    app = web.Application()
    app.router.add_post("/v1/chat/completions", scripted.chat)
    app.router.add_get("/v1/models", list_models)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0).start()
    try:
        yield f"http://127.0.0.1:{runner.addresses[0][1]}/v1"
    finally:
        await runner.cleanup()


def labelled_containers(label: str) -> set[str]:
    result = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"label={label}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return set(result.stdout.split())


def cache_listing() -> list[str] | None:
    """The global Harbor cache contents, or None when it does not exist."""
    if not harbor_taskset.CACHE.exists():
        return None
    return sorted(str(path) for path in harbor_taskset.CACHE.rglob("*"))


def files_with_secrets(directory: Path) -> list[Path]:
    secrets = (PROVIDER_KEY.encode(), HOST_SECRET.encode())
    return [
        path
        for path in directory.rglob("*")
        if path.is_file() and any(secret in path.read_bytes() for secret in secrets)
    ]


def tree_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(directory)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


@pytest.fixture
def episode_env(tmp_path, monkeypatch):
    """Controlled host variables; checks container cleanup and the global cache."""
    if not DOCKER:
        pytest.skip("Docker is not available")
    monkeypatch.setenv("NUDI_CONTRACT_PROVIDER_KEY", PROVIDER_KEY)
    monkeypatch.setenv("NUDI_CONTRACT_HOST_SECRET", HOST_SECRET)
    containers, cache = labelled_containers("verifiers.run"), cache_listing()
    yield tmp_path
    assert labelled_containers("verifiers.run") == containers, "episode containers remain"
    assert cache_listing() == cache, "the global Harbor cache changed"


@pytest.fixture
def native_env(episode_env, monkeypatch):
    """Provider keys in the host environment, where LiteLLM reads them; checks compose cleanup."""
    monkeypatch.setenv("XAI_API_KEY", PROVIDER_KEY)
    monkeypatch.setenv("XIAOMI_MIMO_API_KEY", PROVIDER_KEY)
    containers = labelled_containers("com.docker.compose.project")
    yield episode_env
    assert labelled_containers("com.docker.compose.project") == containers, "trial containers remain"


def run_episodes(
    tmp_path: Path,
    task_dir: Path,
    command: str,
    *,
    model: str,
    sampling: dict,
    rollouts: int = 1,
    taskset: dict | None = None,
    harness: dict | None = None,
    script: Callable[[str], ScriptedModel] = ScriptedModel,
):
    scripted = script(command)

    async def main():
        async with serve(scripted) as base_url:
            config = EvalConfig.model_validate(
                {
                    "env": {
                        "taskset": {
                            "id": "local_harbor",
                            "task_dir": str(task_dir),
                            **(taskset or {}),
                        },
                        "agent": {
                            "harness": harness or {"id": "bash", "compaction": None},
                            "runtime": {"type": "docker"},
                            "max_turns": 4,
                        },
                    },
                    "model": model,
                    "client": {
                        "type": "eval",
                        "base_url": base_url,
                        "api_key_var": "NUDI_CONTRACT_PROVIDER_KEY",
                    },
                    "sampling": sampling,
                    "num_rollouts": rollouts,
                    "max_concurrent": 1,
                    "push": False,
                    "rich": None,
                    "output_dir": str(tmp_path / "outputs"),
                }
            )
            return await run_eval(config), config

    episodes, config = asyncio.run(main())
    return episodes, scripted, tmp_path / "outputs" / config.run.dir


def run_native_trial(
    tmp_path: Path,
    command: str,
    *,
    model: str,
    reasoning_effort: str,
    duration: float = 2.0,
    task_dir: Path = DOCKERFILE_TASK,
):
    """One native Harbor trial with Harbor's Terminus 2."""
    scripted = TerminusScript(command, duration)

    async def main():
        async with serve(scripted) as base_url:
            config = TrialConfig(
                task=TaskConfig(path=task_dir),
                trials_dir=tmp_path / "trials",
                agent=AgentConfig(
                    name="terminus-2",
                    model_name=model,
                    kwargs={"api_base": base_url, "reasoning_effort": reasoning_effort},
                ),
            )
            trial = await Trial.create(config)
            return await trial.run()

    result = asyncio.run(main())
    return result, scripted, tmp_path / "trials" / result.trial_name


def error_text(episode) -> str:
    errors = [*episode.errors, *(e for t in episode.traces for e in t.errors)]
    return "\n".join(f"{e.type}: {e.message}" for e in errors)


def test_installed_upstream_pins():
    assert importlib.metadata.version("verifiers") == VERIFIERS_VERSION
    assert importlib.metadata.version("harbor") == HARBOR_VERSION
    assert importlib.metadata.version("litellm") == LITELLM_VERSION
    assert {name: importlib.metadata.version(name) for name in SDK_VERSIONS} == SDK_VERSIONS

    # The published wheel's source commit is attested, not installed: its SHA256 and
    # provenance were checked when it was pinned, and VERIFIERS_RECORD_DIGEST derived from its RECORD.
    verifiers = importlib.metadata.distribution("verifiers")
    direct_url = json.loads(verifiers.read_text("direct_url.json") or "{}")
    assert "vcs_info" not in direct_url and "dir_info" not in direct_url
    entries = sorted(
        line for line in verifiers.read_text("RECORD").splitlines() if line.startswith("verifiers/")
    )
    assert hashlib.sha256("\n".join(entries).encode()).hexdigest() == VERIFIERS_RECORD_DIGEST
    for path in verifiers.files:
        if str(path).startswith("verifiers/"):
            digest = hashlib.sha256(path.locate().read_bytes()).digest()
            assert path.hash.value == base64.urlsafe_b64encode(digest).rstrip(b"=").decode(), path


def test_adapter_drops_task_timeouts_by_default_and_keeps_resources():
    default = parse_task(CONTRACT_TASK, 0, HarborConfig())
    assert default.prompt == "Write the number 42 to /app/answer.txt."
    assert (default.resources.cpu, default.resources.memory) == (1, 0.5)
    assert (default.timeout.agent, default.timeout.scoring) == (None, None)

    native = parse_task(CONTRACT_TASK, 0, HarborConfig(ignore_timeouts=False))
    assert (native.timeout.agent, native.timeout.scoring) == (20.0, 60.0)


def test_local_registry_tasks_are_not_loadable(tmp_path, monkeypatch):
    # Harbor resolves local registry entries in place and exports nothing, while
    # HarborTaskset expects an export directory. Local task packages need a loader.
    monkeypatch.setattr(harbor_taskset, "CACHE", tmp_path / "harbor-cache")
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            [
                {
                    "name": "nudi-contract",
                    "version": "1.0",
                    "description": "",
                    "tasks": [{"name": CONTRACT_TASK.name, "path": str(CONTRACT_TASK)}],
                }
            ]
        )
    )
    config = HarborConfig(dataset="nudi-contract@1.0", registry_path=registry)

    with pytest.raises(FileNotFoundError, match="export"):
        list(harbor_taskset.HarborTaskset(config).load())


def test_local_loader_parses_task_in_place_without_cache():
    cache_before = cache_listing()
    config_type = taskset_config_type("local_harbor")
    config = config_type(id="local_harbor", task_dir=CONTRACT_TASK, ignore_timeouts=False)

    (task,) = load_taskset(config).load()

    assert task.data.task_dir == str(CONTRACT_TASK)
    assert task.data.prompt == "Write the number 42 to /app/answer.txt."
    assert (task.data.timeout.agent, task.data.timeout.scoring) == (20.0, 60.0)
    assert environment_class("local_harbor") is HarborEnv
    assert cache_listing() == cache_before


def test_adapter_rejects_unsupported_task_shapes(tmp_path):
    def variant(name: str, extra_toml: str, docker_image: bool = True) -> Path:
        task = tmp_path / name
        shutil.copytree(CONTRACT_TASK, task)
        toml = (task / "task.toml").read_text()
        if not docker_image:
            toml = toml.replace('docker_image = "python:3.12-slim"\n', "")
            (task / "environment").mkdir()
            (task / "environment" / "Dockerfile").write_text("FROM python:3.12-slim\n")
        (task / "task.toml").write_text(toml + extra_toml)
        return task

    with pytest.raises(ValueError, match="needs a pullable docker_image"):
        parse_task(variant("dockerfile-only", "", docker_image=False), 0, HarborConfig())
    multi_step = variant("multi-step", '\n[[steps]]\nname = "one"\n')
    shutil.copytree(multi_step / "tests", multi_step / "steps" / "one" / "tests")
    shutil.copy(multi_step / "instruction.md", multi_step / "steps" / "one")
    with pytest.raises(ValueError, match="multi-step Harbor tasks are not supported"):
        parse_task(multi_step, 0, HarborConfig())
    verifier_user = variant("verifier-user", "")
    toml = (verifier_user / "task.toml").read_text()
    (verifier_user / "task.toml").write_text(
        toml.replace("[verifier]\n", '[verifier]\nuser = "root"\n')
    )
    with pytest.raises(ValueError, match=r"\[verifier\].user is not supported"):
        parse_task(verifier_user, 0, HarborConfig())


@pytest.mark.parametrize(
    ("model", "input_price", "output_price"),
    [("xai/grok-4.7", 2e-06, 6e-06), ("xiaomi_mimo/mimo-v2.6-pro", 4.35e-07, 8.7e-07)],
)
def test_litellm_bundled_prices_for_default_models(model, input_price, output_price):
    prompt_cost, completion_cost = litellm.cost_per_token(
        model=model, prompt_tokens=11, completion_tokens=7
    )
    assert prompt_cost == pytest.approx(11 * input_price)
    assert completion_cost == pytest.approx(7 * output_price)


def test_litellm_refuses_unknown_prices():
    with pytest.raises(Exception, match="(?i)isn't mapped|not mapped"):
        litellm.cost_per_token(
            model="xiaomi_mimo/nudi-unpriced-model", prompt_tokens=11, completion_tokens=7
        )


def test_litellm_forwards_requested_reasoning_effort_unchanged():
    def mapped(model: str, provider: str, effort: str) -> dict:
        config = litellm.ProviderConfigManager.get_provider_chat_config(
            model=model, provider=litellm.LlmProviders(provider)
        )
        return config.map_openai_params({"reasoning_effort": effort}, {}, model, False)

    assert mapped("grok-4.7", "xai", "xhigh") == {"reasoning_effort": "xhigh"}
    assert mapped("mimo-v2.6-pro", "xiaomi_mimo", "high") == {"reasoning_effort": "high"}


def test_shared_grading_episode_contract(episode_env):
    fixture_digest = tree_digest(CONTRACT_TASK)

    episodes, scripted, run_dir = run_episodes(
        episode_env,
        CONTRACT_TASK,
        PROBE_AND_ANSWER,
        model="xai/grok-4.7",
        sampling={"reasoning_effort": "xhigh"},
        rollouts=2,
    )

    assert len(episodes) == 2
    for episode in episodes:
        assert episode.ok, error_text(episode)
        (trace,) = episode.traces
        assert trace.reward == 1.0
        assert trace.metrics["answer_ok"] == 1.0
        first, second = trace.calls
        assert first.model == "xai/grok-4.7"
        assert first.sampling.reasoning_effort == "xhigh"
        assert (first.usage.prompt_tokens, first.usage.completion_tokens) == (11, 7)
        assert first.usage.cost == 0.0005
        assert second.usage.cost is None

    outputs = scripted.tool_outputs()
    assert len(outputs) == 2
    for output in outputs:
        assert_probe(output)

    assert len(scripted.requests) == 4
    for headers, body in scripted.requests:
        assert headers["Authorization"] == f"Bearer {PROVIDER_KEY}"
        assert body["model"] == "xai/grok-4.7"
        assert body["reasoning_effort"] == "xhigh"
        assert "bash" in {tool["function"]["name"] for tool in body["tools"]}

    assert len((run_dir / "traces.jsonl").read_text().splitlines()) == 2
    assert files_with_secrets(run_dir) == []
    assert tree_digest(CONTRACT_TASK) == fixture_digest


def test_planted_reward_is_removed_and_missing_reward_is_an_error(episode_env):
    command = (
        "mkdir -p /logs/verifier; "
        """echo '{"reward": 1.0}' > /logs/verifier/reward.json; """
        "echo 1 > /logs/verifier/reward.txt; "
        "touch /app/crash_grader"
    )

    (episode,), scripted, _ = run_episodes(
        episode_env,
        CONTRACT_TASK,
        command,
        model="xiaomi_mimo/mimo-v2.6-pro",
        sampling={"reasoning_effort": "high"},
    )

    assert not episode.ok
    assert "produced no reward.json and no valid reward.txt" in error_text(episode)
    # Trace.reward sums present values and reads 0.0 here, so check Trace.rewards.
    (trace,) = episode.traces
    assert trace.rewards == {"solved": None}
    assert trace.reward == 0.0
    for _, body in scripted.requests:
        assert body["model"] == "xiaomi_mimo/mimo-v2.6-pro"
        assert body["reasoning_effort"] == "high"
        assert "thinking" not in body


def test_enabled_task_agent_timeout_stops_agent_then_grades(episode_env):
    (episode,), _, _ = run_episodes(
        episode_env,
        CONTRACT_TASK,
        "sleep 120",
        model="xai/grok-4.7",
        sampling={},
        taskset={"ignore_timeouts": False},
    )

    # Upstream records the timeout, adds no error and still grades.
    assert episode.ok, error_text(episode)
    (trace,) = episode.traces
    assert trace.is_timeout
    assert trace.stop_condition == "agent_timeout"
    assert 19 < trace.timing.agent.duration < 30
    assert trace.reward == 0.0
    assert trace.metrics["answer_ok"] == 0.0


def test_separate_grading_receives_only_declared_artifacts(episode_env):
    command = "echo 42 > /app/answer.txt; echo agent-only > /app/scratch.txt"

    (episode,), _, _ = run_episodes(
        episode_env,
        SEPARATE_TASK,
        command,
        model="xai/grok-4.7",
        sampling={},
    )

    assert episode.ok, error_text(episode)
    (trace,) = episode.traces
    assert trace.reward == 1.0
    assert trace.metrics["undeclared_file_present"] == 0.0


def test_verifiers_terminus_2_harness_runs_harbor_terminus_2(episode_env):
    (episode,), scripted, run_dir = run_episodes(
        episode_env,
        CONTRACT_TASK,
        PROBE_AND_ANSWER,
        model="xai/grok-4.7",
        sampling={"reasoning_effort": "xhigh"},
        harness={"id": "terminus-2", "version": HARBOR_VERSION},
        script=TerminusScript,
    )

    assert episode.ok, error_text(episode)
    (trace,) = episode.traces
    assert trace.reward == 1.0
    assert trace.metrics["answer_ok"] == 1.0
    assert len(scripted.requests) == 2
    for headers, body in scripted.requests:
        assert headers["Authorization"] == f"Bearer {PROVIDER_KEY}"
        assert body["model"] == "xai/grok-4.7"
        assert body["reasoning_effort"] == "xhigh"
        assert "tools" not in body
    (observation,) = scripted.observations()
    assert_probe(observation)
    # The harness program runs in the task box with the rollout secret in its arguments.
    assert "api_key_args=1" in observation
    assert files_with_secrets(run_dir) == []


def test_native_harbor_terminus_2_runs_dockerfile_task(native_env):
    fixture_digest = tree_digest(DOCKERFILE_TASK)

    # Two sequential trials: each must start without the marker the other wrote.
    for _ in range(2):
        result, scripted, trial_dir = run_native_trial(
            native_env, PROBE_AND_ANSWER, model="xai/grok-4.7", reasoning_effort="xhigh"
        )

        assert result.exception_info is None, result.exception_info
        assert result.verifier_result.rewards == {"reward": 1.0, "answer_ok": 1.0}
        assert len(scripted.requests) == 2
        for headers, body in scripted.requests:
            assert headers["Authorization"] == f"Bearer {PROVIDER_KEY}"
            assert body["model"] == "grok-4.7"
            assert body["reasoning_effort"] == "xhigh"
            assert "tools" not in body
        (observation,) = scripted.observations()
        assert_probe(observation)
        assert "api_key_args=0" in observation
        trajectory = json.loads((trial_dir / "agent" / "trajectory.json").read_text())
        assert trajectory["schema_version"] == "ATIF-v1.8"
        # Provider-reported cost for the first call plus LiteLLM's bundled price for the second.
        assert result.agent_result.cost_usd == pytest.approx(0.0005 + 13 * 2e-06 + 2 * 6e-06)
        assert trajectory["final_metrics"]["total_cost_usd"] == result.agent_result.cost_usd
        assert files_with_secrets(trial_dir) == []

    assert len(list((native_env / "trials").iterdir())) == 2
    assert tree_digest(DOCKERFILE_TASK) == fixture_digest


def test_native_harbor_missing_reward_is_an_exception(native_env):
    result, scripted, _ = run_native_trial(
        native_env,
        "touch /app/crash_grader",
        model="xiaomi_mimo/mimo-v2.6-pro",
        reasoning_effort="high",
    )

    assert result.verifier_result is None
    assert result.exception_info.exception_type == "RewardFileNotFoundError"
    assert len(scripted.requests) == 2
    for _, body in scripted.requests:
        assert body["model"] == "mimo-v2.6-pro"
        assert body["reasoning_effort"] == "high"
        assert "thinking" not in body
    # Unlike xai, the provider-reported usage.cost is ignored: both calls use bundled prices.
    assert result.agent_result.cost_usd == pytest.approx(24 * 4.35e-07 + 9 * 8.7e-07)


def test_native_harbor_shared_grading_keeps_planted_reward(native_env):
    # Verifiers deletes these files before grading (see the planted reward test above).
    command = (
        "mkdir -p /logs/verifier; "
        """echo '{"reward": 1.0}' > /logs/verifier/reward.json; """
        "touch /app/crash_grader"
    )

    result, _, _ = run_native_trial(
        native_env, command, model="xai/grok-4.7", reasoning_effort="xhigh"
    )

    assert result.exception_info is None
    assert result.verifier_result.rewards == {"reward": 1.0}


def test_native_harbor_applies_task_agent_timeout(native_env):
    result, _, _ = run_native_trial(
        native_env, "sleep 120", model="xai/grok-4.7", reasoning_effort="xhigh", duration=60.0
    )

    execution = result.agent_execution
    assert 19 < (execution.finished_at - execution.started_at).total_seconds() < 30
    assert result.exception_info.exception_type == "AgentTimeoutError"
    assert result.verifier_result.rewards == {"reward": 0.0, "answer_ok": 0.0}


def test_enabled_verifier_timeout_stops_grader(episode_env):
    (episode,), _, _ = run_episodes(
        episode_env,
        SLOW_GRADER_TASK,
        "echo 42 > /app/answer.txt",
        model="xai/grok-4.7",
        sampling={},
        taskset={"ignore_timeouts": False},
    )

    # The grader is stopped at 5 s: a timeout flag, no error and a missing reward.
    assert episode.ok, error_text(episode)
    (trace,) = episode.traces
    assert trace.is_timeout
    assert trace.stop_condition == "scoring_timeout"
    assert trace.errors == []
    assert trace.rewards == {"solved": None}
    assert 4 < trace.timing.scoring.duration < 15


def test_native_harbor_applies_verifier_timeout(native_env):
    result, _, _ = run_native_trial(
        native_env,
        "echo 42 > /app/answer.txt",
        model="xai/grok-4.7",
        reasoning_effort="xhigh",
        task_dir=SLOW_GRADER_TASK,
    )

    assert result.exception_info.exception_type == "VerifierTimeoutError"
    assert result.verifier_result is None
    verifier = result.verifier
    assert 4 < (verifier.finished_at - verifier.started_at).total_seconds() < 15


def test_native_harbor_separate_grading_receives_only_declared_artifacts(native_env):
    # Unlike the Verifiers runtime, native Harbor starts an image-only task in / without /app.
    command = (
        "echo cwd_$(pwd) app_$(test -d /app && echo present || echo absent); "
        "mkdir -p /app; echo 42 > /app/answer.txt; echo agent-only > /app/scratch.txt"
    )

    result, scripted, trial_dir = run_native_trial(
        native_env, command, model="xai/grok-4.7", reasoning_effort="xhigh", task_dir=SEPARATE_TASK
    )

    (observation,) = scripted.observations()
    assert "cwd_/ app_absent" in observation
    assert result.exception_info is None, result.exception_info
    assert result.verifier_environment_mode == "separate"
    assert result.verifier_result.rewards == {"reward": 1.0, "undeclared_file_present": 0.0}
    collected = trial_dir / "artifacts" / "app"
    assert (collected / "answer.txt").read_text() == "42\n"
    assert not (collected / "scratch.txt").exists()


def test_verifiers_terminus_2_harness_applies_task_agent_timeout(episode_env):
    (episode,), scripted, _ = run_episodes(
        episode_env,
        CONTRACT_TASK,
        "sleep 120",
        model="xai/grok-4.7",
        sampling={"reasoning_effort": "xhigh"},
        taskset={"ignore_timeouts": False},
        harness={"id": "terminus-2", "version": HARBOR_VERSION},
        script=functools.partial(TerminusScript, duration=60.0),
    )

    assert episode.ok, error_text(episode)
    (trace,) = episode.traces
    assert trace.is_timeout
    assert trace.stop_condition == "agent_timeout"
    assert 19 < trace.timing.agent.duration < 30
    assert len(scripted.requests) == 1
    assert trace.rewards["reward"].score == 0.0
    assert trace.metrics["answer_ok"] == 0.0


class WorkspaceAgent(ScriptedModel):
    """Requests one `execute` call in the Inspector workspace, then its structured result."""

    def reply(self, body: dict) -> tuple[dict, str, dict]:
        done = any(message.get("role") == "tool" for message in body["messages"])
        name, arguments = ("Finding", {"summary": "done"}) if done else ("execute", {"command": self.command})
        call = {"index": 0, "id": f"call_{len(self.requests)}", "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)}}
        return {"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls", FIRST_USAGE


WORKSPACE_TOOLS = {"ls", "read_file", "write_file", "edit_file", "delete", "glob", "grep", "execute"}


def test_importing_inspector_preserves_unrelated_chatlitellm_agents():
    """Importing nudi must not change another caller's SDK tool configuration."""
    script = r'''
import asyncio, json, litellm
from deepagents import create_deep_agent
from langchain.agents.structured_output import ToolStrategy
from langchain_litellm import ChatLiteLLM
from pydantic import BaseModel

class Finding(BaseModel):
    summary: str

requests = []
async def completion(**kwargs):
    requests.append(sorted(tool["function"]["name"] for tool in kwargs["tools"]))
    return litellm.ModelResponse(choices=[{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": None, "tool_calls": [{"id": "done", "type": "function",
        "function": {"name": "Finding", "arguments": '{"summary":"done"}'}}]}}])
litellm.acompletion = completion

async def tools():
    agent = create_deep_agent(model=ChatLiteLLM(model="openai/nudi-unrelated", api_key="fake-key"),
                              subagents=[], response_format=ToolStrategy(Finding))
    await agent.ainvoke({"messages": [{"role": "user", "content": "Finish."}]})
    return requests[-1]

before = asyncio.run(tools())
import nudi.inspector
after = asyncio.run(tools())
print(json.dumps({"before": before, "after": after}))
'''
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120, check=True)
    offered = json.loads(completed.stdout.splitlines()[-1])
    assert "task" in offered["before"]
    assert offered["after"] == offered["before"]


@pytest.mark.skipif(not DOCKER, reason="Docker is not available")
def test_deep_agents_workspace_offers_only_file_search_and_shell_tools(tmp_path, monkeypatch):
    """The released SDK, as nudi assembles it over a Harbor Docker workspace, offers file,
    search and shell tools and the structured result only: no delegation `task`, todo list,
    memory files, skills or approval interrupt. Its shell sees no credential or Docker socket."""
    from pydantic import BaseModel

    from nudi import inspector
    from nudi.records import ModelConfig, RunConfig
    from nudi.run_state import start_run

    class Finding(BaseModel):
        summary: str

    credentials = tmp_path / "credentials.env"
    credentials.write_text(f"XAI_API_KEY={PROVIDER_KEY}\n")
    monkeypatch.setenv("NUDI_CONTRACT_HOST_SECRET", HOST_SECRET)
    probe = (f"echo provider_key_count=$(env | grep -c {masked(PROVIDER_KEY)}); "
             f"echo host_secret_count=$(env | grep -c {masked(HOST_SECRET)}); "
             "echo docker_socket_$(test -S /var/run/docker.sock && echo present || echo absent); ls /nudi")
    scripted = WorkspaceAgent(probe)

    async def main():
        async with serve(scripted) as base_url:
            model = ModelConfig(model="xai/grok-4.7", reasoning_effort="xhigh", api_base=base_url)
            run = start_run(RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "run", credentials_file=credentials,
                                      models={"inspector": model}), frozenset({"inspector"}))
            async with inspector.investigation(run, "contract", "Inspect the copied package.", {}) as session:
                return session, await session.ask("Investigate.", Finding)

    session, result = asyncio.run(main())
    assert result.summary == "done" and len(scripted.requests) == 2
    for _, body in scripted.requests:
        assert {tool["function"]["name"] for tool in body["tools"]} == WORKSPACE_TOOLS | {"Finding"}
    output, = scripted.tool_outputs()
    for expected in ("provider_key_count=0", "host_secret_count=0", "docker_socket_absent", "package"):
        assert expected in output
    record = session.box.record
    # Only nudi's Python probe, the one shell call and the retention listing ran: no memory or skill reads.
    assert [entry["argv"][:2] for entry in record.commands] == [["python3", "-c"], ["sh", "-c"], ["sh", "-c"]]
    assert record.cleanup["removed"] is True
    assert labelled_containers(f"com.docker.compose.project={record.session_id}") == set()
    assert files_with_secrets(tmp_path / "run") == []


@pytest.mark.skipif(not DOCKER, reason="Docker is not available")
def test_workspace_memory_override_reaches_docker_beside_an_experiment_at_task_limits(tmp_path):
    """Docker enforces the recorded limits: Harbor's override sets the held workspace's memory,
    a fresh experiment beside it keeps the task's declaration, and both are removed."""
    from nudi import inspector_sandbox
    from nudi.records import RunConfig
    from nudi.run_state import start_run

    credentials = tmp_path / "credentials.env"
    credentials.write_text(f"MERGE_GATEWAY_API_KEY={PROVIDER_KEY}\n")
    run = start_run(RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "run", credentials_file=credentials,
                              workspace_memory_mb=256), frozenset({"inspector"}))

    def enforced(box) -> dict:
        container, = labelled_containers(f"com.docker.compose.project={box.record.session_id}")
        memory, cpus = subprocess.run(["docker", "inspect", "--format", "{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}",
                                       container], capture_output=True, text=True, check=True).stdout.split()
        return {"cpus": int(cpus) // 10**9, "memory_mb": int(memory) // 2**20}

    async def main():
        async with inspector_sandbox.sandbox(run, "workspace") as workspace:
            async with inspector_sandbox.sandbox(run, "check") as check:
                return [(box.record, enforced(box)) for box in (workspace, check)]

    (workspace, held), (check, fresh) = asyncio.run(main())
    assert held == {"cpus": workspace.environment["cpus"], "memory_mb": workspace.environment["memory_mb"]} == {"cpus": 1, "memory_mb": 256}
    assert fresh == {"cpus": check.environment["cpus"], "memory_mb": check.environment["memory_mb"]} == {"cpus": 1, "memory_mb": 512}
    for record in (workspace, check):
        assert record.cleanup["removed"] is True
        assert labelled_containers(f"com.docker.compose.project={record.session_id}") == set()
