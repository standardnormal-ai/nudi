"""Runner contracts: path selection, confinement, retained records and cleanup.

Docker episodes run one at a time against a local scripted Terminus 2 endpoint.
No model provider is called.
"""

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import pytest
from aiohttp import web
from harbor.models.task.task import Task
from verifiers.v1.cli.eval import runner as verifiers_runner

from nudi.records import EpisodeResult, EpisodeConfig
from nudi.runner import DOCKERFILE, UnsupportedTask, compose_services, run_episode, select_path

FIXTURES = Path(__file__).parent / "integration" / "fixtures"
CONTRACT_TASK = FIXTURES / "contract-task"
DOCKERFILE_TASK = FIXTURES / "dockerfile-task"
SEPARATE_TASK = FIXTURES / "separate-verifier-task"
SLOW_GRADER_TASK = FIXTURES / "slow-grader-task"
MODEL = "xai/grok-4.7"
PROVIDER_KEY = "nudi-runner-provider-key"
SENTINEL = "nudi-host-result-sentinel"


def masked(text: str) -> str:
    """A grep or find pattern for `text` that does not contain `text` itself."""
    return f"'{text[:-1]}[{text[-1]}]'"


# Native Harbor starts an image-only task in / without /app, so the probe creates it.
PROBE = (
    "mkdir -p /app; "
    "echo docker_socket_$(test -S /var/run/docker.sock && echo present || echo absent); "
    f"echo provider_key_env=$(env | grep -c {masked(PROVIDER_KEY)}); "
    "echo provider_key_args=$(cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' "
    f"| grep -o -- {masked(PROVIDER_KEY)} | wc -l); "
    f"echo host_results=$(find / -path /proc -prune -o -name {masked(SENTINEL)} -print 2>/dev/null "
    "| wc -l); "
    "echo 42 > /app/answer.txt"
)
CONFINED = ("docker_socket_absent", "provider_key_env=0", "provider_key_args=0", "host_results=0")


class TerminusScript:
    """Terminus 2 JSON replies: type the command and claim completion, then confirm."""

    def __init__(self, command: str, duration: float = 2.0):
        self.command, self.duration = command, duration
        self.requests: list[dict] = []
        self.first_request = asyncio.Event()

    async def chat(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.requests.append(body)
        self.first_request.set()
        first = len(self.requests) == 1
        commands = [{"keystrokes": f"{self.command}\n", "duration": self.duration}] if first else []
        content = json.dumps(
            {"analysis": "Scripted.", "plan": "Scripted.", "commands": commands, "task_complete": True}
        )
        message = {"role": "assistant", "content": content}
        usage = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
        head = {"id": "chatcmpl-runner", "created": 0, "model": body["model"]}
        if not body.get("stream"):
            choice = {"index": 0, "message": message, "finish_reason": "stop"}
            return web.json_response({**head, "object": "chat.completion", "choices": [choice], "usage": usage})
        chunk = {**head, "object": "chat.completion.chunk"}
        events = [
            {**chunk, "choices": [{"index": 0, "delta": message, "finish_reason": "stop"}]},
            {**chunk, "choices": [], "usage": usage},
        ]
        text = "".join(f"data: {json.dumps(event)}\n\n" for event in events)
        return web.Response(text=text + "data: [DONE]\n\n", content_type="text/event-stream")

    def observations(self) -> list[str]:
        """The terminal text Terminus sent back after the first turn."""
        return [str(body["messages"][-1]["content"]) for body in self.requests[1:]]


@contextlib.asynccontextmanager
async def serve(script: TerminusScript):
    app = web.Application()
    app.router.add_post("/v1/chat/completions", script.chat)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0).start()
    try:
        yield f"http://127.0.0.1:{runner.addresses[0][1]}/v1"
    finally:
        await runner.cleanup()


def docker_ids(kind: str, label: str) -> set[str]:
    result = subprocess.run(
        ["docker", kind, "ls", "-q", *(["-a"] if kind == "container" else []), "--filter", f"label={label}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return set(result.stdout.split())


def docker_resources() -> dict[str, set[str]]:
    labels = ("verifiers.run", "com.docker.compose.project")
    return {f"{kind} {label}": docker_ids(kind, label) for kind in ("container", "network") for label in labels}


def tree_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(directory)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def files_with_secret(directory: Path) -> list[Path]:
    return [p for p in directory.rglob("*") if p.is_file() and PROVIDER_KEY.encode() in p.read_bytes()]


@pytest.fixture
def docker_env(tmp_path, monkeypatch):
    """Host provider key and result sentinel; checks Docker and temporary-file cleanup."""
    if shutil.which("docker") is None or subprocess.run(["docker", "info"], capture_output=True).returncode:
        pytest.skip("Docker is not available")
    monkeypatch.setenv("XAI_API_KEY", PROVIDER_KEY)
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    output = tmp_path / "output"
    output.mkdir()
    (output / SENTINEL).write_text("A host result file that task tools must not see.\n")
    before = docker_resources()
    copies_before = copy_images()
    yield output
    # A run deletes its copies at run end; a test that calls a probe directly leaves them.
    if left := copy_images() - copies_before:
        subprocess.run(["docker", "rmi", "--force", *left], capture_output=True)
    assert docker_resources() == before, "episode containers or networks remain"
    assert list(temp.iterdir()) == [], "temporary task copies remain"


def copy_images() -> set[str]:
    listed = subprocess.run(["docker", "images", "--format", "{{.Repository}}", "nudi-copy-*"], capture_output=True, text=True)
    return set(listed.stdout.split())


def episode(output: Path, task_dir: Path, command: str, *, native=frozenset(), duration=2.0):
    """Run one episode against the scripted model."""
    script = TerminusScript(command, duration)

    async def main():
        async with serve(script) as base_url:
            config = EpisodeConfig(
                task_dir=task_dir,
                output_dir=output,
                model=MODEL,
                api_base=base_url,
                api_key_var="XAI_API_KEY",
                reasoning_effort="high",
                native=native,
            )
            return await run_episode(config)

    return asyncio.run(main()), script


def stored(output: Path) -> EpisodeResult:
    return EpisodeResult.model_validate_json((output / "episode.json").read_text())


def task_variant(tmp_path: Path, source: Path, extra_toml: str = "") -> Path:
    task = tmp_path / source.name
    shutil.copytree(source, task)
    with (task / "task.toml").open("a") as toml:
        toml.write(extra_toml)
    return task


def test_image_task_uses_adapter_and_discloses_its_differences():
    path, reasons = select_path(CONTRACT_TASK, frozenset())

    assert path == "verifiers"
    assert any("deletes agent-written reward files" in reason for reason in reasons)
    assert any("inside the task container" in reason for reason in reasons)
    assert any("ATIF" in reason for reason in reasons)


def test_separate_grading_task_discloses_no_shared_grading_difference():
    path, reasons = select_path(SEPARATE_TASK, frozenset())

    assert path == "verifiers"
    assert not any("reward files" in reason for reason in reasons)


def test_dockerfile_task_falls_back_to_native_harbor():
    path, reasons = select_path(DOCKERFILE_TASK, frozenset())

    assert path == "harbor"
    assert reasons == [DOCKERFILE]


@pytest.mark.parametrize(
    ("behavior", "reason"),
    [
        ("shared_grading", "native shared grading requested"),
        ("host_harness", "host-side Terminus 2 requested"),
        ("atif", "ATIF trajectory requested"),
    ],
)
def test_requested_native_behavior_falls_back_to_native_harbor(behavior, reason):
    path, reasons = select_path(CONTRACT_TASK, frozenset({behavior}))

    assert path == "harbor"
    assert len(reasons) == 1 and reasons[0].startswith(reason)


def test_native_shared_grading_request_does_not_apply_to_separate_grading():
    assert select_path(SEPARATE_TASK, frozenset({"shared_grading"}))[0] == "verifiers"


@pytest.mark.parametrize(
    ("tables", "environment", "reason"),
    [
        ('[agent]\nuser = "agent"\n', "", r"\[agent\]\.user"),
        ('[verifier]\nuser = "root"\n', "", r"\[verifier\]\.user"),
        ('[verifier.env]\nTOKEN = "${HOST_TOKEN}"\n', "", r"\[verifier\]\.env"),
        ("", 'network_mode = "no-network"\n', r"\[environment\]\.network_mode"),
        ("", "storage_mb = 1024\n", r"\[environment\]\.storage_mb"),
        ("", '[environment.env]\nTOKEN = "${HOST_TOKEN}"\n', r"\[environment\]\.env"),
        ("", '[environment.healthcheck]\ncommand = "true"\n', r"\[environment\]\.healthcheck"),
    ],
)
def test_rejects_unverified_task_features_before_starting(tmp_path, tables, environment, reason):
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "task.toml").write_text(
        f'schema_version = "1.4"\n{tables}\n[environment]\ndocker_image = "python:3.12-slim"\n'
        + environment
    )

    with pytest.raises(UnsupportedTask, match=f"{reason} is not verified"):
        select_path(task, frozenset())


def test_rejects_task_without_declared_environment(tmp_path):
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "task.toml").write_text('schema_version = "1.4"\n')

    with pytest.raises(UnsupportedTask, match="declares no docker_image or environment/Dockerfile"):
        select_path(task, frozenset())


# Harbor builds an environment from each of these directories, merging a compose file found there,
# and compose reads .env from it as its project directory, on the native path too.
# environment/docker-compose.yaml, the file Harbor's Docker environment merges, is checked instead.
@pytest.mark.parametrize(("directory", "name"), [
    ("environment", "docker-compose.yml"), ("tests", "docker-compose.yaml"), ("tests", "docker-compose.yml"),
    ("steps/one/tests", "docker-compose.yaml"), ("steps/one/tests", "docker-compose.yml"),
    ("environment", ".env"), ("environment", ".ENV"), ("tests", ".env"), ("steps/one/tests", ".Env")])
def test_rejects_compose_file_in_any_environment_definition(tmp_path, directory, name):
    from nudi.workflow import ORIGINAL_BEHAVIOR

    task = task_variant(tmp_path, SEPARATE_TASK)
    (task / directory).mkdir(parents=True, exist_ok=True)
    (task / directory / name).write_text("DOCKER_HOST=tcp://task.example:2375\n" if "env" in name.casefold() else
                                         "# nudi sentinel, not a compose definition\n")

    for native in (frozenset(), ORIGINAL_BEHAVIOR):
        with pytest.raises(UnsupportedTask, match=f"^{directory}/{name} is not verified$"):
            select_path(task, native)


@pytest.fixture
def exact_names(monkeypatch, tmp_path):
    """Lookups under tmp_path match exact names only, as on a case-sensitive source volume.
    The snapshot's case-insensitive volume would then find these names as compose files."""
    exists = Path.exists

    def exact(path, **kwargs):
        inside = [p for p in (path, *path.parents) if p.is_relative_to(tmp_path) and p != tmp_path]
        return exists(path, **kwargs) and all(p.name in os.listdir(p.parent) for p in inside)

    monkeypatch.setattr(Path, "exists", exact)


# One name at a time: a case-insensitive test volume cannot hold two names that differ only in case.
# U+212A (Kelvin sign) and U+017F (long s) casefold to k and s.
@pytest.mark.parametrize(
    ("directory", "name"),
    [("tests", "Docker-Compose.YAML"), ("tests", "docKer-compose.yaml"), ("tests", "docker-compoſe.yml"),
     ("Tests", "docker-compose.yaml"), ("steps/one/TESTS", "docker-compose.yml")],
)
def test_rejects_compose_names_a_case_insensitive_copy_would_find(tmp_path, exact_names, directory, name):
    task = task_variant(tmp_path, SEPARATE_TASK)
    if directory == "Tests":
        (task / "tests").rename(task / "Tests")
    (task / directory).mkdir(parents=True, exist_ok=True)
    (task / directory / name).write_text("# nudi sentinel, not a compose definition\n")

    with pytest.raises(UnsupportedTask, match=f"^{re.escape(f'{directory}/{name}')} is not verified$"):
        select_path(task, frozenset())


def test_rejects_multi_step_task(tmp_path):
    task = task_variant(tmp_path, CONTRACT_TASK, '\n[[steps]]\nname = "one"\n')
    shutil.copytree(task / "tests", task / "steps" / "one" / "tests")
    shutil.copy(task / "instruction.md", task / "steps" / "one")

    with pytest.raises(UnsupportedTask, match=r"\[steps\] is not verified"):
        select_path(task, frozenset())


def test_rejects_file_reference_escaping_the_task(tmp_path):
    outside = tmp_path / "outside.sh"
    outside.write_text("echo outside\n")
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "tests" / "helper.sh").symlink_to(outside)

    with pytest.raises(UnsupportedTask, match="tests/helper.sh points outside the task"):
        select_path(task, frozenset())


def test_run_rejects_unsupported_task_without_starting(tmp_path):
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "task.toml").write_text('schema_version = "1.4"\n[agent]\nuser = "agent"\n')
    config = EpisodeConfig(task_dir=task, output_dir=tmp_path / "output", model=MODEL, api_key_var="XAI_API_KEY")

    with pytest.raises(UnsupportedTask, match=r"\[agent\]\.user is not verified"):
        asyncio.run(run_episode(config))
    assert not (tmp_path / "output").exists()


def test_native_episode_retains_trial_ids_rewards_and_trajectory(docker_env):
    digest = tree_digest(DOCKERFILE_TASK)

    result, script = episode(docker_env, DOCKERFILE_TASK, PROBE)

    assert (result.path, result.path_reasons) == ("harbor", [DOCKERFILE])
    assert result.errors == [] and not (result.cancelled or result.agent_timeout)
    assert result.rewards == {"reward": 1.0, "answer_ok": 1.0}
    trial = json.loads((docker_env / result.artifacts["result"]).read_text())
    assert result.ids == {
        "trial_id": trial["id"],
        "trial_name": trial["trial_name"],
        "task_checksum": trial["task_checksum"],
    }
    trajectory = json.loads((docker_env / result.artifacts["trajectory"]).read_text())
    assert trajectory["schema_version"] == "ATIF-v1.8"
    assert result.versions["harbor"] == "0.24.0"
    (observation,) = script.observations()
    for expected in CONFINED:
        assert expected in observation, observation
    assert stored(docker_env) == result
    assert files_with_secret(docker_env) == []
    assert tree_digest(DOCKERFILE_TASK) == digest == result.task_digest


def test_adapter_episode_retains_trace_ids_rewards_and_components(docker_env, tmp_path):
    original_digest = tree_digest(CONTRACT_TASK)
    task = task_variant(tmp_path, CONTRACT_TASK)
    manifest = task / "task.toml"
    # This retention test allows cold imports and tmux installation; deadline enforcement has its own test.
    manifest.write_text(manifest.read_text().replace("timeout_sec = 20.0", "timeout_sec = 60.0", 1))
    digest = tree_digest(task)

    result, script = episode(docker_env, task, PROBE)

    assert result.path == "verifiers"
    assert len(result.path_reasons) == 3
    assert result.errors == [] and not (result.cancelled or result.agent_timeout)
    assert (result.rewards, result.metrics) == ({"reward": 1.0}, {"answer_ok": 1.0})
    (line,) = (docker_env / result.artifacts["traces"]).read_text().splitlines()
    upstream = json.loads(line)
    (trace,) = upstream["traces"]
    assert (result.ids["episode_id"], result.ids["trace_id"]) == (upstream["id"], trace["id"])
    assert result.versions["verifiers"] == "0.4.1.dev12"
    (observation,) = script.observations()
    for expected in CONFINED:
        assert expected in observation, observation
    assert stored(docker_env) == result
    assert files_with_secret(docker_env) == []
    assert tree_digest(task) == digest == result.task_digest
    assert tree_digest(CONTRACT_TASK) == original_digest


@pytest.mark.parametrize(
    ("native", "rewards", "error"),
    [
        (frozenset(), {"solved": None}, "produced no reward.json and no valid reward.txt"),
        (frozenset({"host_harness"}), {}, "RewardFileNotFoundError"),
    ],
)
def test_missing_reward_stays_missing(docker_env, native, rewards, error):
    result, _ = episode(docker_env, CONTRACT_TASK, "mkdir -p /app; touch /app/crash_grader", native=native)

    # Verifiers also reports an aggregate reward of 0.0 here; the record keeps it missing.
    assert result.rewards == rewards
    assert error in "\n".join(f"{e.type}: {e.message}" for e in result.errors)
    assert stored(docker_env) == result


@pytest.mark.parametrize(
    ("native", "rewards", "errors"),
    [(frozenset(), {"solved": None}, []), (frozenset({"host_harness"}), {}, ["VerifierTimeoutError"])],
)
def test_verifier_timeout_is_a_flag_without_an_inferred_cause(docker_env, native, rewards, errors):
    result, _ = episode(docker_env, SLOW_GRADER_TASK, "mkdir -p /app; echo 42 > /app/answer.txt", native=native)

    assert (result.agent_timeout, result.verifier_timeout) == (False, True)
    assert result.rewards == rewards
    assert [e.type for e in result.errors] == errors


@pytest.mark.parametrize("native", [frozenset(), frozenset({"host_harness"})])
def test_failed_start_is_recorded_and_releases_resources(docker_env, tmp_path, native):
    task = task_variant(tmp_path, CONTRACT_TASK)
    toml = (task / "task.toml").read_text()
    (task / "task.toml").write_text(toml.replace("python:3.12-slim", "nudi-test/missing-image:none"))

    result, script = episode(docker_env, task, PROBE, native=native)

    assert script.requests == []
    assert result.errors and not result.cancelled
    assert "missing-image" in "\n".join(e.message for e in result.errors)
    assert stored(docker_env) == result


def long_agent_budget(tmp_path: Path, source: Path) -> Path:
    """A copy whose agent may run for 600 s, so no task deadline ends it during a test."""
    task = task_variant(tmp_path, source)
    toml = (task / "task.toml").read_text()
    (task / "task.toml").write_text(toml.replace("timeout_sec = 20.0", "timeout_sec = 600.0"))
    return task


async def until(condition, running: asyncio.Task) -> None:
    """Wait for `condition()`; fail at once if the runner ends first instead of hanging."""
    while not condition():
        if running.done():
            pytest.fail(f"run_episode ended before the cancellation point: {running!r}")
        await asyncio.sleep(0.05)


def cancel_episode(output: Path, task_dir: Path, command: str, cancel_after) -> TerminusScript:
    """Start an episode, cancel it once `cancel_after(script)` holds, and require propagation."""
    script = TerminusScript(command, duration=60.0)

    async def main():
        async with serve(script) as base_url:
            config = EpisodeConfig(
                task_dir=task_dir,
                output_dir=output,
                model=MODEL,
                api_base=base_url,
                api_key_var="XAI_API_KEY",
            )
            running = asyncio.create_task(run_episode(config))
            await until(lambda: cancel_after(script), running)
            # False would mean the runner had already finished, so nothing was cancelled.
            assert running.cancel(), f"run_episode ended before the cancellation: {running!r}"
            await asyncio.wait({running})
            assert running.cancelled(), f"cancellation did not propagate: {running.result()!r}"

    asyncio.run(main())
    return script


def assert_artifacts_retained(output: Path, result: EpisodeResult) -> None:
    for name, relative in result.artifacts.items():
        assert (output / relative).exists(), f"{name} refers to missing {relative}"


@pytest.mark.parametrize(("source", "path"), [(CONTRACT_TASK, "verifiers"), (DOCKERFILE_TASK, "harbor")])
def test_cancellation_during_agent_keeps_partial_evidence(docker_env, tmp_path, source, path):
    task = long_agent_budget(tmp_path, source)
    first_seen: list[float] = []

    def five_seconds_after_first_request(script: TerminusScript) -> bool:
        if script.requests and not first_seen:
            first_seen.append(time.monotonic())
        return bool(first_seen) and time.monotonic() - first_seen[0] > 5

    cancel_episode(docker_env, task, "sleep 120", five_seconds_after_first_request)

    result = stored(docker_env)
    assert result.path == path and result.cancelled
    assert result.rewards == {}
    assert_artifacts_retained(docker_env, result)
    assert files_with_secret(docker_env) == []
    if path == "harbor":
        assert result.ids["trial_name"]
        assert "result" in result.artifacts
    else:
        # No episode exists yet; the run and the live trace do, with the model call observed.
        assert {"run_id", "trace_id"} <= set(result.ids) and "episode_id" not in result.ids
        (line,) = (docker_env / result.artifacts["partial_traces"]).read_text().splitlines()
        trace = json.loads(line)
        assert trace["id"] == result.ids["trace_id"]
        assert [call["model"] for call in trace["calls"]] == [MODEL]


def test_cancellation_during_adapter_close_out_propagates_and_keeps_the_episode(
    docker_env, tmp_path, monkeypatch
):
    task = long_agent_budget(tmp_path, CONTRACT_TASK)
    # After the episode is appended, Verifiers closes the run in a shielded worker
    # thread. The episode ends within one poll of the append, so the close-out is held
    # open for a second to place the cancellation inside it.
    closing = threading.Event()
    finish_run = verifiers_runner.finish_run

    def held_finish_run(*args):
        closing.set()
        time.sleep(1)
        return finish_run(*args)

    monkeypatch.setattr(verifiers_runner, "finish_run", held_finish_run)

    cancel_episode(docker_env, task, "echo 42 > /app/answer.txt", lambda script: closing.is_set())

    result = stored(docker_env)
    assert result.cancelled and result.errors == []
    assert (result.rewards, result.metrics) == ({"reward": 1.0}, {"answer_ok": 1.0})
    (line,) = (docker_env / result.artifacts["traces"]).read_text().splitlines()
    upstream = json.loads(line)
    assert (result.ids["episode_id"], result.ids["trace_id"]) == (upstream["id"], upstream["traces"][0]["id"])
    assert_artifacts_retained(docker_env, result)


@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("inside", ["", "results"])
def test_output_overlapping_the_task_is_rejected_before_writing(tmp_path, monkeypatch, alias, inside):
    def started(*args):
        raise AssertionError("the episode started")

    # Guards against starting Docker or any model call if the check is missing.
    monkeypatch.setattr("nudi.runner.run_verifiers", started)
    task = task_variant(tmp_path, CONTRACT_TASK)
    digest = tree_digest(task)
    root = task
    if alias:
        root = tmp_path / "alias"
        root.symlink_to(task)
    config = EpisodeConfig(task_dir=task, output_dir=root / inside, model=MODEL, api_key_var="XAI_API_KEY")

    with pytest.raises(ValueError, match="output_dir .* overlaps the task"):
        asyncio.run(run_episode(config))
    assert tree_digest(task) == digest
    assert not (task / "results").exists()


@pytest.mark.parametrize(
    ("toml", "reason"),
    [
        ("[environment]\nprivileged = true\n", r"\[environment\]\.privileged"),
        ("unknown_setting = 1\n[environment]\n", r"\[unknown_setting\]"),
        ("[agent]\nretries = 3\n[environment]\n", r"\[agent\]\.retries"),
        # Harbor drops a numeric legacy `memory` without applying any limit.
        ("[environment]\nmemory = 512\n", r"\[environment\]\.memory"),
    ],
)
def test_rejects_unknown_raw_fields_that_upstream_parsing_drops(tmp_path, toml, reason):
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "task.toml").write_text(f'schema_version = "1.4"\n{toml}docker_image = "python:3.12-slim"\n')

    with pytest.raises(UnsupportedTask, match=f"{reason} is not verified"):
        select_path(task, frozenset())


def test_accepts_supported_legacy_aliases(tmp_path):
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "task.toml").write_text(
        'version = "1.4"\n[environment]\ndocker_image = "python:3.12-slim"\nmemory = "512M"\n'
    )

    assert select_path(task, frozenset())[0] == "verifiers"


@pytest.mark.parametrize("source", [CONTRACT_TASK, DOCKERFILE_TASK, SEPARATE_TASK, SLOW_GRADER_TASK])
def test_supported_fixtures_are_accepted(source):
    assert select_path(source, frozenset())[0] in ("verifiers", "harbor")


# Synthetic declarations in the shape of a published Harbor task.toml.
HARBOR_DECLARATIONS = """\
version = "1.0"

[metadata]
author_name = "Example Author"
author_email = "author@example.com"
difficulty = "medium"
category = "system-administration"
tags = [ "example", "git",]
expert_time_estimate_min = 180.0
junior_time_estimate_min = 360.0

[verifier]
timeout_sec = 180.0

[agent]
timeout_sec = 900.0

[environment]
build_timeout_sec = 600.0
cpus = 1
memory_mb = 2048
storage_mb = 10240
gpus = 0
allow_internet = true

[verifier.env]

[solution.env]
"""
# The declarations of terminal-bench 2 image tasks such as fix-git, with their explicit
# empty collections; descriptive metadata is left out.
IMAGE_DECLARATIONS = """\
schema_version = "1.1"
artifacts = []

[task]
name = "terminal-bench/fix-git"
[[task.authors]]
name = "TheMikeMerrill"

[verifier]
timeout_sec = 900.0

[agent]
timeout_sec = 900.0

[environment]
build_timeout_sec = 600.0
docker_image = "alexgshaw/fix-git:20251031"
cpus = 1
memory_mb = 2048
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []

[verifier.env]

[environment.env]

[solution.env]
"""


def task_with(tmp_path: Path, source: Path, toml: str) -> Path:
    task = task_variant(tmp_path, source)
    (task / "task.toml").write_text(toml)
    return task


def harbor_reads(task: Path) -> tuple:
    """What native Harbor's Docker environment and trial read from these declarations."""
    config = Task(task).config
    environment = config.environment
    return (environment.gpus or 0, environment.build_timeout_sec, environment.resolve_baseline(),
            environment.env, environment.mcp_servers, config.verifier.env, config.solution.env)


def test_retained_real_task_declarations_run_on_native_harbor(tmp_path):
    task = task_with(tmp_path, DOCKERFILE_TASK, HARBOR_DECLARATIONS)

    path, reasons = select_path(task, frozenset({"shared_grading", "host_harness", "atif"}))

    assert path == "harbor"
    assert reasons[0] == DOCKERFILE
    assert len(reasons) == 2 and "storage_mb = 10240 is recorded but not enforced" in reasons[1]


def test_image_task_declarations_run_on_native_harbor_only(tmp_path):
    task = task_with(tmp_path, CONTRACT_TASK, IMAGE_DECLARATIONS)

    path, reasons = select_path(task, frozenset({"shared_grading", "host_harness", "atif"}))

    assert path == "harbor" and len(reasons) == 4
    assert [reason.split(":")[0] for reason in reasons[:3]] == [
        "ATIF trajectory requested", "host-side Terminus 2 requested", "native shared grading requested"
    ]
    assert "storage_mb = 10240 is recorded but not enforced" in reasons[3]
    with pytest.raises(UnsupportedTask, match="is not verified on the Verifiers adapter"):
        select_path(task, frozenset())


@pytest.mark.parametrize(
    ("source", "tables", "environment"),
    [
        (CONTRACT_TASK, "[verifier.env]\n", ""),
        (CONTRACT_TASK, "[solution.env]\n", ""),
        (DOCKERFILE_TASK, "[verifier.env]\n[solution.env]\n", ""),
        (DOCKERFILE_TASK, "", "gpus = 0\n"),
        (DOCKERFILE_TASK, "", "allow_internet = true\n"),
        (DOCKERFILE_TASK, "", "build_timeout_sec = 600.0\n"),
        (DOCKERFILE_TASK, "", "build_timeout_sec = 600\n"),
        (DOCKERFILE_TASK, "[environment.env]\n", ""),
        (DOCKERFILE_TASK, "", "mcp_servers = []\n"),
    ],
)
def test_accepted_default_declarations_equal_omission(tmp_path, source, tables, environment):
    image = 'docker_image = "python:3.12-slim"\n' if source == CONTRACT_TASK else ""
    omitted = task_with(tmp_path / "omitted", source, f'schema_version = "1.4"\n[environment]\n{image}cpus = 1\n')
    declared = task_with(
        tmp_path / "declared", source, f'schema_version = "1.4"\n{tables}[environment]\n{image}cpus = 1\n{environment}'
    )

    assert select_path(declared, frozenset()) == select_path(omitted, frozenset())
    assert harbor_reads(declared) == harbor_reads(omitted)


def test_native_storage_declaration_is_kept_and_disclosed_as_unenforced(tmp_path):
    task = task_with(tmp_path, DOCKERFILE_TASK, 'schema_version = "1.4"\n[environment]\nstorage_mb = 4096\n')

    path, reasons = select_path(task, frozenset())

    assert (path, reasons[:1], len(reasons)) == ("harbor", [DOCKERFILE], 2)
    assert "storage_mb = 4096 is recorded but not enforced" in reasons[1] and "guarantee" not in reasons[1]
    assert Task(task).config.environment.storage_mb == 4096


@pytest.mark.parametrize("timeout", ["900.0", "1800", "0.5"])
def test_native_path_admits_and_uses_any_finite_positive_build_timeout(tmp_path, timeout):
    task = task_with(tmp_path, DOCKERFILE_TASK, f'schema_version = "1.4"\n[environment]\nbuild_timeout_sec = {timeout}\n')

    assert select_path(task, frozenset()) == ("harbor", [DOCKERFILE])
    assert harbor_reads(task)[1] == float(timeout)


@pytest.mark.parametrize(
    ("tables", "environment", "reason"),
    [
        ('[verifier.env]\nTOKEN = "${HOST_TOKEN}"\n', "", r"\[verifier\]\.env"),
        ('[verifier.env]\nTOKEN = "${HOST_TOKEN:-x}"\n', "", r"\[verifier\]\.env"),
        ("[verifier.env]\nTOKEN = 1\n", "", r"\[verifier\]\.env"),
        ("[verifier.env.nested]\n", "", r"\[verifier\]\.env"),
        ('[solution.env]\nTOKEN = "${HOST_TOKEN}"\n', "", r"\[solution\]\.env"),
        ("[solution]\nother = 1\n", "", r"\[solution\]\.other"),
        ("", "gpus = -1\n", r"\[environment\]\.gpus"),
        ("", "gpus = false\n", r"\[environment\]\.gpus"),
        ("", "gpus = 0.0\n", r"\[environment\]\.gpus"),
        ("", 'gpus = "0"\n', r"\[environment\]\.gpus"),
        ("", "allow_internet = false\n", r"\[environment\]\.allow_internet"),
        ("", "allow_internet = 1\n", r"\[environment\]\.allow_internet"),
        ("", 'allow_internet = "true"\n', r"\[environment\]\.allow_internet"),
        ("", 'build_timeout_sec = "600"\n', r"\[environment\]\.build_timeout_sec"),
        ("", "build_timeout_sec = true\n", r"\[environment\]\.build_timeout_sec"),
        ("", "build_timeout_sec = 0\n", r"\[environment\]\.build_timeout_sec"),
        ("", "build_timeout_sec = -600.0\n", r"\[environment\]\.build_timeout_sec"),
        ("", "build_timeout_sec = inf\n", r"\[environment\]\.build_timeout_sec"),
        ("", "build_timeout_sec = nan\n", r"\[environment\]\.build_timeout_sec"),
        ("", "storage_mb = 0\n", r"\[environment\]\.storage_mb"),
        ("", "storage_mb = -1024\n", r"\[environment\]\.storage_mb"),
        ("", "storage_mb = 1024.0\n", r"\[environment\]\.storage_mb"),
        ("", 'storage_mb = "1024"\n', r"\[environment\]\.storage_mb"),
        ("", "storage_mb = true\n", r"\[environment\]\.storage_mb"),
        ("", 'storage = "10G"\n', r"\[environment\]\.storage"),
        ('[environment.env]\nTOKEN = "literal"\n', "", r"\[environment\]\.env"),
        ("[environment.env.nested]\n", "", r"\[environment\]\.env"),
        ("", "env = []\n", r"\[environment\]\.env"),
        ("", "mcp_servers = {}\n", r"\[environment\]\.mcp_servers"),
        ("", "gpu_types = [1]\n", r"\[environment\]\.gpu_types"),
        ("", "skills_dir = 1\n", r"\[environment\]\.skills_dir"),
        ('[verifier]\ncollect = "true"\n', "", r"\[verifier\]\.collect"),
        # Only the approved empty collections are accepted.
        ("", "allowed_hosts = []\n", r"\[environment\]\.allowed_hosts"),
        ("[environment.healthcheck]\n", "", r"\[environment\]\.healthcheck"),
    ],
)
def test_native_path_still_rejects_unverified_values_and_types(tmp_path, tables, environment, reason):
    task = task_with(tmp_path, DOCKERFILE_TASK, f'schema_version = "1.4"\n{tables}[environment]\n{environment}')

    with pytest.raises(UnsupportedTask, match=f"{reason} is not verified"):
        select_path(task, frozenset())


@pytest.mark.parametrize(
    "declaration",
    ["gpus = 0", "allow_internet = true", "build_timeout_sec = 600.0", "build_timeout_sec = 1800", "storage_mb = 1024", "env = {}", "mcp_servers = []"],
)
def test_adapter_rejects_declarations_verified_only_on_native_harbor(tmp_path, declaration):
    task = task_with(
        tmp_path, CONTRACT_TASK, f'schema_version = "1.4"\n[environment]\ndocker_image = "python:3.12-slim"\n{declaration}\n'
    )
    field = declaration.split(" = ")[0]

    with pytest.raises(UnsupportedTask, match=rf"\[environment\]\.{field} is not verified on the Verifiers adapter"):
        select_path(task, frozenset())
    # A requested native behavior keeps its existing fallback reason.
    path, reasons = select_path(task, frozenset({"host_harness"}))
    assert path == "harbor" and reasons[0].startswith("host-side Terminus 2 requested")


# A separate grader's own environment, in the shape of the terminal-bench 4 tasks that declare one.
VERIFIER_ENVIRONMENT = """\
schema_version = "1.4"
artifacts = ["/app/answer.txt"]

[verifier]
timeout_sec = 60.0

[environment]
docker_image = "python:3.12-slim"
cpus = 1
memory_mb = 512

[verifier.environment]
docker_image = "python:3.13-slim"
cpus = 2
memory_mb = 4096
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []
"""


def test_a_verifier_environment_is_admitted_natively_with_harbors_definition(tmp_path):
    from harbor.models.task.verifier_mode import resolve_verifier_environment_definition

    from nudi.workflow import ORIGINAL_BEHAVIOR, declared_requirements

    task = task_with(tmp_path, SEPARATE_TASK, VERIFIER_ENVIRONMENT)
    path, reasons = select_path(task, ORIGINAL_BEHAVIOR)
    assert path == "harbor"
    assert "[verifier.environment].storage_mb = 10240 is recorded but not enforced" in reasons[-1]
    with pytest.raises(UnsupportedTask, match=r"\[verifier\.environment\]\.\w+ is not verified on the Verifiers adapter"):
        select_path(task, frozenset())
    # Harbor's trial grades in the declared image, from the tests directory, with the tests in that image.
    definition = resolve_verifier_environment_definition(Task(task).config, Task(task).paths)
    assert (definition.config.docker_image, definition.config.cpus, definition.config.memory_mb) == ("python:3.13-slim", 2, 4096)
    assert (definition.directory, definition.bundled_tests) == (Task(task).paths.tests_dir, True)
    # Admission control counts the larger of the two containers.
    assert declared_requirements(task) == (2, 4096)


@pytest.mark.parametrize(
    ("declaration", "reason"),
    [
        # Harbor's separate verifier enforces no internet through its egress-control sidecar, a
        # startup path nudi's Docker sandboxes do not apply.
        ("allow_internet = false", "allow_internet"),
        ('os = "windows"', "os"),
        ('network_mode = "no-network"', "network_mode"),
        ("storage_mb = 0", "storage_mb"),
        ("cpus = 0", "cpus"),
        ('docker_image = ""', "docker_image"),
        ('env = { TOKEN = "literal" }', "env"),
        ("[verifier.environment.healthcheck]", "healthcheck"),
        ("build_timeout_sec = 900.0", "build_timeout_sec"),  # native Harbor waits the main environment's bound
    ],
)
def test_verifier_environment_fields_nudi_cannot_honor_stay_refused_by_name(tmp_path, declaration, reason):
    key = declaration.split(" = ")[0]
    kept = "".join(line + "\n" for line in VERIFIER_ENVIRONMENT.splitlines() if not line.startswith(key + " = "))
    task = task_with(tmp_path, SEPARATE_TASK, kept + declaration + "\n")

    with pytest.raises(UnsupportedTask, match=rf"\[verifier\.environment\]\.{reason} is not verified"):
        select_path(task, frozenset({"shared_grading", "host_harness", "atif"}))


@pytest.mark.parametrize("key", ["cpus", "memory_mb"])
def test_a_verifier_environment_without_both_resources_is_refused_by_name(tmp_path, key):
    """Native Harbor gives the verifier the main environment's limit policies, which fail without a value."""
    kept = "".join(line + "\n" for line in VERIFIER_ENVIRONMENT.splitlines() if not line.startswith(key + " = "))
    task = task_with(tmp_path, SEPARATE_TASK, kept)
    with pytest.raises(UnsupportedTask, match=rf"\[verifier\.environment\]\.{key} is not declared"):
        select_path(task, frozenset({"shared_grading", "host_harness", "atif"}))


# Admission part 2: the fields native Harbor 0.24.0 handles itself and nudi's package path honors or does not reach.
NATIVE_FIELDS = [
    ('[verifier.env]\nMODE = "strict"\n', ""),
    ("", 'gpus = 1\ngpu_types = ["H100"]\n'),
    ("", 'skills_dir = "/skills"\n'),
    ("", 'mcp_servers = [{ name = "tools", transport = "stdio", command = "true" }]\n'),
    ("[[verifier.collect]]\ncommand = \"true\"\n", ""),
]


@pytest.mark.parametrize(("tables", "environment"), [*NATIVE_FIELDS, ("", '[environment.healthcheck]\ncommand = "true"\n')])
def test_native_harbor_admits_the_fields_it_handles_itself(tmp_path, tables, environment):
    from nudi.workflow import ORIGINAL_BEHAVIOR

    image = 'docker_image = "python:3.12-slim"\ncpus = 1\n'
    if environment.startswith("["):
        image, environment = image + environment, ""
    task = task_with(tmp_path, CONTRACT_TASK, f'schema_version = "1.4"\n{tables}[environment]\n{image}{environment}')

    assert select_path(task, ORIGINAL_BEHAVIOR)[0] == "harbor"
    with pytest.raises(UnsupportedTask, match="is not verified on the Verifiers adapter"):
        select_path(task, frozenset())


def test_a_verifier_build_timeout_equal_to_the_main_one_is_admitted(tmp_path):
    from nudi.workflow import ORIGINAL_BEHAVIOR

    declared = VERIFIER_ENVIRONMENT.replace("memory_mb = 512\n", "memory_mb = 512\nbuild_timeout_sec = 900\n") + "build_timeout_sec = 900.0\n"
    task = task_with(tmp_path, SEPARATE_TASK, declared)
    assert select_path(task, ORIGINAL_BEHAVIOR)[0] == "harbor"
    assert Task(task).config.verifier.environment.build_timeout_sec == Task(task).config.environment.build_timeout_sec == 900


# environment/docker-compose.yaml in the shape of the Terminal-Bench 4 tasks that declare helper services.
COMPOSE = """\
services:
  main:
    build:
      context: .
      dockerfile: Dockerfile
    depends_on:
      helper:
        condition: service_healthy
    cap_add: [SYS_PTRACE]
  helper:
    build: ./helper
    command: ["sh", "-c", "echo $$PATH && sleep infinity"]
    environment:
      - MODE=strict
    expose: ["8080"]
    shm_size: 1gb
    cpus: 1.0
    healthcheck:
      test: ["CMD", "true"]
      interval: 1s
  cache:
    image: redis:7-alpine
    pull_policy: missing
    network_mode: service:helper
    environment:
      LEVEL: "1"
"""


def compose_task(tmp_path: Path, compose: str = COMPOSE) -> Path:
    task = task_variant(tmp_path, DOCKERFILE_TASK)
    (task / "environment" / "helper").mkdir()
    (task / "environment" / "helper" / "Dockerfile").write_text("FROM python:3.12-slim\n")
    (task / "environment" / "docker-compose.yaml").write_text(compose)
    return task


def test_a_compose_file_with_helper_services_is_admitted_natively_on_docker_only(tmp_path):
    from nudi.runner import check_backend, compose_services
    from nudi.workflow import ORIGINAL_BEHAVIOR, declared_requirements

    task = compose_task(tmp_path)
    assert compose_services(task) == ["cache", "helper", "main"]
    assert select_path(task, ORIGINAL_BEHAVIOR)[0] == "harbor"
    with pytest.raises(UnsupportedTask, match=r"docker-compose\.yaml is not verified on the Verifiers adapter"):
        select_path(task, frozenset())
    check_backend(task, "docker")
    with pytest.raises(UnsupportedTask, match=r"^environment/docker-compose\.yaml is not verified on Modal$"):
        check_backend(task, "modal")
    # Harbor gives the declared limits to the main service only, so the helpers' needs are undeclared.
    assert declared_requirements(task) == (None, None)


@pytest.mark.parametrize(("change", "reason"), [
    (("  cache:\n", "  cache:\n    volumes: [\"/:/host\"]\n"), r"services\.cache\.volumes"),
    (("  cache:\n", "  cache:\n    env_file: .env\n"), r"services\.cache\.env_file"),
    (("  cache:\n", "  cache:\n    privileged: true\n"), r"services\.cache\.privileged"),
    (("services:\n", "volumes: {}\nservices:\n"), "a top level other than one services table"),
    (("- MODE=strict", "- MODE=${HOST_TOKEN}"), "variable interpolation"),
    (("- MODE=strict", "- MODE=$HOST_TOKEN"), "variable interpolation"),
    (("- MODE=strict", '- "MODE=\\u0024{HOST_TOKEN}"'), "variable interpolation"),
    (('LEVEL: "1"', '"\\u0024{HOST_TOKEN}": "1"'), "variable interpolation"),
    (("  cache:\n", '  cache:\n    healthcheck: {test: ["CMD", "\\x24HOST_TOKEN"]}\n'), "variable interpolation"),
    # PyYAML decodes these tags to bytes and a set, which compose-go reads as text.
    (('LEVEL: "1"', "LEVEL: !!binary JHtIT1NUX1RPS0VOfQ=="), "a YAML bytes value"),
    (('LEVEL: "1"', 'LEVEL: !!set {"\\u0024{HOST_TOKEN}": null}'), "a YAML set value"),
    (("- MODE=strict", "- HOST_TOKEN"), r"services\.helper\.environment entry without a value"),
    (('LEVEL: "1"', "LEVEL:"), r"services\.cache\.environment entry without a value"),
    (("build: ./helper", "build: .."), r"services\.helper\.build outside environment/"),
    (("dockerfile: Dockerfile", "dockerfile: ../task.toml"), r"services\.main\.build outside environment/"),
    (("build: ./helper", "build: { context: ./helper, args: { A: b } }"), r"services\.helper\.build other than"),
    (("network_mode: service:helper", "network_mode: host"), r"services\.cache\.network_mode other than"),
    (("cap_add: [SYS_PTRACE]", "cap_add: [SYS_ADMIN]"), r"services\.main\.cap_add other than SYS_PTRACE"),
    (("services:\n", "services: [\n"), "a file that does not parse as YAML"),
    (("cap_add: [SYS_PTRACE]", "cap_add: [SYS_PTRACE]\n    cpus: 4.0"), r"services\.main\.cpus"),
    (("cap_add: [SYS_PTRACE]", "cap_add: [SYS_PTRACE]\n    image: ubuntu:24.04"), r"services\.main\.image"),
])
def test_a_compose_file_reaching_the_host_is_refused_by_name(tmp_path, change, reason):
    """Harbor runs compose with nudi's own environment, which contains the run's credentials."""
    task = compose_task(tmp_path, COMPOSE.replace(*change))
    with pytest.raises(UnsupportedTask, match=rf"^environment/docker-compose\.yaml: {reason}.* is not verified$"):
        select_path(task, frozenset({"shared_grading", "host_harness", "atif"}))


def test_an_escaped_dollar_stays_literal_after_yaml_decoding(tmp_path):
    """Compose reads $$ as a literal $, also when YAML decodes it from an escape."""
    task = compose_task(tmp_path, COMPOSE.replace("- MODE=strict", '- "MODE=\\u0024\\u0024{LITERAL}"'))
    assert compose_services(task) == ["cache", "helper", "main"]


@pytest.mark.parametrize(("toml", "service"), [
    ('\n[[verifier.collect]]\nservice = "helper"\ncommand = "true"\n', "helper"),
    ('\n[[verifier.collect]]\nservice = "db"\ncommand = "true"\n', "db"),
    ('artifacts = [{ source = "/data/out.json", service = "db" }]\n', "db"),
])
def test_a_helper_service_named_outside_the_compose_file_is_refused_by_name(tmp_path, toml, service):
    """Native Harbor refuses it before the trial starts; without compose, only main exists."""
    from nudi.workflow import ORIGINAL_BEHAVIOR

    plain = task_variant(tmp_path / "plain", DOCKERFILE_TASK)
    (plain / "task.toml").write_text(toml + (plain / "task.toml").read_text() if toml.startswith("artifacts") else
                                     (plain / "task.toml").read_text() + toml)
    with pytest.raises(UnsupportedTask, match=rf"^service '{service}', named by an artifact or a \[verifier\]\.collect hook, is not a service"):
        select_path(plain, ORIGINAL_BEHAVIOR)
    composed = compose_task(tmp_path)
    (composed / "task.toml").write_text(toml + (composed / "task.toml").read_text() if toml.startswith("artifacts") else
                                        (composed / "task.toml").read_text() + toml)
    if service == "helper":
        assert select_path(composed, ORIGINAL_BEHAVIOR)[0] == "harbor"
    else:
        with pytest.raises(UnsupportedTask, match=f"service '{service}'"):
            select_path(composed, ORIGINAL_BEHAVIOR)


@pytest.mark.parametrize("table", ["environment", "verifier.environment"])
def test_gpus_are_admitted_on_modal_and_refused_on_docker_by_name(tmp_path, table):
    from nudi.runner import check_backend

    declared = VERIFIER_ENVIRONMENT.replace("gpus = 0\n", "") + "gpus = 1\n" if table == "verifier.environment" else (
        VERIFIER_ENVIRONMENT.replace("memory_mb = 512\n", "memory_mb = 512\ngpus = 1\n"))
    task = task_with(tmp_path, SEPARATE_TASK, declared)
    check_backend(task, "modal")
    with pytest.raises(UnsupportedTask, match=rf"^\[{re.escape(table)}\]\.gpus = 1 is not verified on Docker$"):
        check_backend(task, "docker")


@pytest.mark.parametrize("artifact", ['"/manifest.json"', '"/"', '"/manifest.json/inner"',
                                      '{ source = "/app/answer.txt", destination = "./manifest.json" }'])
def test_an_artifact_collected_onto_the_manifest_or_the_collection_directory_is_refused(tmp_path, artifact):
    """Harbor writes manifest.json in the collection directory after downloading, through any link left there."""
    declared = VERIFIER_ENVIRONMENT.replace('artifacts = ["/app/answer.txt"]', f"artifacts = [{artifact}]")
    task = task_with(tmp_path, SEPARATE_TASK, declared)
    with pytest.raises(UnsupportedTask, match=r"artifacts\[0\] .* artifacts directory or its manifest\.json"):
        select_path(task, frozenset({"shared_grading", "host_harness", "atif"}))
    # Admission itself refuses it, before either path is chosen.
    with pytest.raises(UnsupportedTask, match=r"artifacts\[0\]"):
        select_path(task, frozenset())
