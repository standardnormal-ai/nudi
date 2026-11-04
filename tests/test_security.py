"""Public release security: malicious task fixtures for reward reading, task snapshots,
log redaction and owner-only raw evidence. Docker tests run one native episode against a
local scripted Terminus 2 endpoint; no provider is called."""

import asyncio
import json
import os
import signal
import stat
import tempfile
import traceback
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import pytest
from harbor.environments.base import ExecResult
from harbor.environments.factory import EnvironmentFactory
from harbor.models.task.task import Task
from harbor.models.trial.config import VerifierConfig
from harbor.models.trial.paths import TrialPaths
from harbor.verifier.factory import VerifierFactory
from harbor.verifier.verifier import VerifierOutputParseError

from nudi import checks, runner, workflow
from nudi.records import EpisodeConfig
from nudi.runner import UnsupportedTask
from test_inspection import Sandboxes, SandboxEnvironment, explained_task, no_native_actor, sandbox_record
from test_limits import FILE_KEY, credentials, new_run  # noqa: F401  (pytest fixture)
from test_inspection import AgentScript, Finding, inspector_run
from test_runner import (CONTRACT_TASK, SEPARATE_TASK, docker_env, episode, serve, stored,  # noqa: F401  (pytest fixture)
                         task_variant)

HOST_SECRET = "nudi-host-secret-value"
INVALID = "nudi-invalid-reward-value"
OUTSIDE = "nudi-outside-task-content"
SCALAR = "298761234570912345"


def host_secret(tmp_path: Path) -> Path:
    """Host JSON a malicious grader tries to make the host parse as its reward."""
    path = tmp_path / "host-secret.json"
    path.write_text(json.dumps({"token": HOST_SECRET}))
    return path


def malicious_grader(monkeypatch, plant) -> Sandboxes:
    """Sandboxes whose copied grader calls `plant(verifier_dir)` instead of writing a reward."""
    sandboxes = Sandboxes(monkeypatch)

    class Grader(SandboxEnvironment):
        async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
            if "/tests/test.sh" in command and not command.startswith("chmod"):
                plant(self.trial_paths.verifier_dir)
                return ExecResult(stdout="", stderr="", return_code=0)
            return await super().exec(command, cwd, env, timeout_sec, user)

    def create(**config):
        environment = Grader(sandboxes, **config)
        sandboxes.environments[environment.name] = environment
        return environment

    monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(create))
    no_native_actor(monkeypatch)
    return sandboxes


def probe(run) -> str:
    return asyncio.run(checks.package_probe(run, "true\n"))


# Rewards: read without following links, bounded, invalid values kept out of errors.


@pytest.mark.parametrize(("case", "expected"), [
    ("reward symlink to host JSON", "link"),
    ("reward FIFO", "not a regular file"),
    ("oversized reward", "exceeds"),
    ("invalid reward value", "Non-numeric"),
    ("numeric JSON scalar", "not an object"),
    ("invalid UTF-8 key", "UTF-8"),
])
def test_sandbox_grading_refuses_malicious_reward_files(tmp_path, monkeypatch, credentials, case, expected):
    secret = host_secret(tmp_path)

    def plant(verifier: Path):
        reward = verifier / "reward.json"
        if case == "reward symlink to host JSON":
            reward.symlink_to(secret)
        elif case == "reward FIFO":
            os.mkfifo(reward)
        elif case == "oversized reward":
            reward.write_text('{"reward": 1.0}' + " " * 2**20)
        elif case == "numeric JSON scalar":
            reward.write_text(SCALAR)
        elif case == "invalid UTF-8 key":
            reward.write_bytes(b'{"reward":1,"aux_\xff":0}')
        else:
            reward.write_text(json.dumps({"reward": INVALID}))

    malicious_grader(monkeypatch, plant)
    run = new_run(tmp_path, monkeypatch, credentials)
    record = sandbox_record(run, probe(run))
    assert record["rewards"] == {}
    error, = record["errors"]
    assert error["type"] == "VerifierOutputParseError" and expected in error["message"], error
    text = json.dumps(record)
    assert HOST_SECRET not in text and INVALID not in text and SCALAR not in text


@pytest.mark.parametrize(("name", "content"), [
    ("reward.json", json.dumps({"reward": INVALID})),
    ("reward.json", INVALID),
    ("reward.txt", INVALID),
    ("reward.json", SCALAR),
])
def test_invalid_reward_values_stay_out_of_the_whole_error_chain(tmp_path, name, content):
    """Native Harbor stores the formatted traceback, chained causes included."""
    paths = TrialPaths(tmp_path / "trial")
    paths.mkdir()
    (paths.verifier_dir / name).write_text(content)
    verifier = runner.RewardVerifier(task=Task(CONTRACT_TASK), trial_paths=paths, environment=SimpleNamespace())
    parse = verifier._parse_reward_json if name == "reward.json" else verifier._parse_reward_text
    with pytest.raises(VerifierOutputParseError) as caught:
        parse()
    formatted = "".join(traceback.format_exception(caught.value))
    assert INVALID not in formatted and SCALAR not in formatted


def test_native_trials_grade_through_the_reward_verifier(tmp_path):
    submitted = []

    class Queue:
        def on_agent_started(self, hook): pass
        def on_verification_started(self, hook): pass
        def on_trial_ended(self, hook): pass

        async def submit(self, config):
            submitted.append(config)

    config = EpisodeConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path, model="xai/grok-4.7", api_key_var="XAI_API_KEY")
    asyncio.run(runner.run_harbor(config, CONTRACT_TASK, None, Queue()))
    trial, = submitted
    paths = TrialPaths(tmp_path / "trial")
    verifier = VerifierFactory.create_verifier_from_config(
        trial.verifier, task=Task(CONTRACT_TASK), trial_paths=paths, environment=SimpleNamespace())
    assert isinstance(verifier, runner.RewardVerifier)


def test_native_grader_symlink_to_host_json_is_refused(tmp_path, docker_env):
    secret = host_secret(tmp_path)
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "tests" / "test.sh").write_text(f"#!/bin/bash\nmkdir -p /logs/verifier\nln -sf {secret} /logs/verifier/reward.json\n")

    result, _ = episode(docker_env, task, "true", native=frozenset({"host_harness"}))

    assert result.rewards == {}
    assert [error.type for error in result.errors] == ["VerifierOutputParseError"]
    assert stored(docker_env) == result
    # The planted link stays as retained evidence; no retained file contains the target's bytes.
    leaked = [path for path in docker_env.rglob("*")
              if not path.is_symlink() and path.is_file() and HOST_SECRET.encode() in path.read_bytes()]
    assert leaked == [] and any(path.is_symlink() for path in (docker_env / "harbor").rglob("reward.json"))


# Names Terminus 2 writes with a plain open into the mounted agent directory.
# Continuation and summarization files use that same directory when produced.
AGENT_LOG_LINKS = (
    "trajectory.json",
    "trajectory.cont-1.json",
    "trajectory.summarization-1-summary.json",
    "recording.cast",
)
HOST_RECORD = b"nudi-synthetic-host-record\n"


def test_planted_agent_log_links_leave_the_host_record_unchanged(tmp_path, docker_env):
    """A container-planted link at a trajectory name must not receive the host write."""
    record = tmp_path / "host-record"
    record.write_bytes(HOST_RECORD)
    planted = " && ".join(f"ln -sf {record} /logs/agent/{name}" for name in AGENT_LOG_LINKS)
    command = f"mkdir -p /logs/agent /app && {planted} && echo 42 > /app/answer.txt"

    result, _ = episode(docker_env, CONTRACT_TASK, command, native=frozenset({"host_harness"}))

    assert record.read_bytes() == HOST_RECORD
    agent_dir = next((docker_env / "harbor").glob("*/agent"))
    for name in AGENT_LOG_LINKS:
        link = agent_dir / name
        assert link.is_symlink() and os.readlink(link) == str(record)
    trajectory = docker_env / result.artifacts["trajectory"]
    assert not trajectory.is_symlink() and trajectory.is_file()
    assert trajectory.parent.name == "agent-host"
    assert json.loads(trajectory.read_text())["schema_version"] == "ATIF-v1.8"
    assert result.rewards == {"reward": 1.0, "answer_ok": 1.0}
    assert stored(docker_env) == result
    leaked = [path for path in docker_env.rglob("*")
              if not path.is_symlink() and path.is_file() and HOST_RECORD in path.read_bytes()]
    assert leaked == []


# One task snapshot for the package, runner and tests uploads.


def linked_outside(tmp_path: Path, task: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text(OUTSIDE)
    (task / "tests" / "helper.sh").symlink_to(outside)


@pytest.mark.parametrize(("case", "expected"), [
    ("link leaving the task", "points outside the task"),
    ("FIFO in the task", "not a regular file"),
    ("directory link cycle", "forms a directory cycle"),
    ("the credentials file", "credentials file"),
])
def test_snapshot_refuses_what_it_must_not_copy(tmp_path, case, expected):
    task = explained_task(tmp_path)
    credentials = None
    if case == "link leaving the task":
        linked_outside(tmp_path, task)
    elif case == "FIFO in the task":
        os.mkfifo(task / "tests" / "pipe")
    elif case == "directory link cycle":
        (task / "tests" / "loop").symlink_to(task, target_is_directory=True)
    else:
        credentials = task / "tests" / "test.sh"
    with pytest.raises(UnsupportedTask, match=expected):
        runner.snapshot(task, tmp_path / "copy", credentials)


def test_snapshot_keeps_links_inside_the_task_as_regular_files(tmp_path, monkeypatch, credentials):
    task = explained_task(tmp_path)
    (task / "tests" / "same.sh").symlink_to(task / "tests" / "test.sh")
    (task / "linked-tests").symlink_to(task / "tests", target_is_directory=True)
    copied = tmp_path / "copy"
    runner.snapshot(task, copied)
    assert not any(path.is_symlink() for path in copied.rglob("*"))
    assert (copied / "tests" / "same.sh").read_bytes() == (task / "tests" / "test.sh").read_bytes()
    assert (copied / "linked-tests" / "test.sh").read_bytes() == (task / "tests" / "test.sh").read_bytes()
    assert os.stat(copied / "tests" / "test.sh").st_mode == os.stat(task / "tests" / "test.sh").st_mode


def test_snapshot_streams_large_files(tmp_path):
    task = explained_task(tmp_path)
    (task / "tests" / "dataset.bin").write_bytes(os.urandom(2**24))
    tracemalloc.start()
    try:
        runner.snapshot(task, tmp_path / "copy")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert (tmp_path / "copy" / "tests" / "dataset.bin").read_bytes() == (task / "tests" / "dataset.bin").read_bytes()
    assert peak < 2**20


@pytest.mark.parametrize("refused", [True, False])
def test_sandbox_scratch_with_a_read_only_copied_directory_is_removed(tmp_path, monkeypatch, credentials, refused):
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    task = explained_task(tmp_path)
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    (task / "a-read-only").mkdir()
    (task / "a-read-only" / "data.txt").write_text("copied first\n")
    (task / "a-read-only").chmod(0o500)
    if refused:
        os.mkfifo(task / "tests" / "pipe")
    try:
        if refused:
            with pytest.raises(UnsupportedTask, match="not a regular file"):
                probe(run)
        else:
            probe(run)
    finally:
        (task / "a-read-only").chmod(0o700)
    assert list(temp.iterdir()) == []


@pytest.mark.parametrize("name", ["task.toml", "instruction.md"])
def test_startup_refuses_a_special_task_file_before_reading_it(tmp_path, monkeypatch, credentials, name):
    task = explained_task(tmp_path)
    (task / name).unlink()
    os.mkfifo(task / name)

    def blocked(signum, frame):
        raise TimeoutError(f"startup blocked on {name}")

    previous = signal.signal(signal.SIGALRM, blocked)
    signal.alarm(5)
    try:
        with pytest.raises(UnsupportedTask, match=f"{name} is not a regular file"):
            new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_an_excluded_convention_artifacts_directory_is_refused(tmp_path):
    refused = tmp_path / "refused"
    refused.mkdir()
    task = task_variant(
        refused, CONTRACT_TASK, '\n[[artifacts]]\nsource = "/logs/artifacts"\nexclude = ["*.txt"]\n'
    )
    with pytest.raises(UnsupportedTask, match="exclude"):
        runner.check_task(task)
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    redirected = task_variant(
        mounted,
        CONTRACT_TASK,
        '\n[[artifacts]]\nsource = "/logs/artifacts"\nexclude = ["*.txt"]\ndestination = "logs/artifacts"\n',
    )
    with pytest.raises(UnsupportedTask, match="exclude"):
        runner.check_task(redirected)

    accepted = tmp_path / "accepted"
    accepted.mkdir()
    plain = task_variant(accepted, CONTRACT_TASK)
    toml = plain / "task.toml"
    toml.write_text('artifacts = ["/app/answer.txt"]\n' + toml.read_text())
    runner.check_task(plain)


def test_a_credentials_file_inside_the_task_is_refused_before_the_run(tmp_path, monkeypatch):
    task = explained_task(tmp_path)
    (task / ".env").write_text(f"XAI_API_KEY={FILE_KEY}\nXIAOMI_MIMO_API_KEY={FILE_KEY}\n")
    for name in ("XAI_API_KEY", "XIAOMI_MIMO_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(UnsupportedTask, match="credentials file"):
        new_run(tmp_path, monkeypatch, task / ".env", task_dir=task)
    assert not (tmp_path / "run").exists()


# Redaction and owner-only raw evidence.


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def permissive_umask():
    previous = os.umask(0)
    yield
    os.umask(previous)


def modes(root: Path) -> dict[str, int]:
    """Every retained directory and file under `root` that is not owner-only."""
    entries = [root, *root.rglob("*")]
    return {str(path.relative_to(root)): mode(path) for path in entries if not path.is_symlink()
            and mode(path) != (0o700 if path.is_dir() else 0o600)}


async def harbor_tree(config, task_dir, result, queue, agent=None):
    """The retained trial tree as native Harbor 0.24.0 leaves it: default modes, and the
    directories it opens to the container's users."""
    trial = config.output_dir / "harbor" / "trial"
    for directory in ("agent", "verifier"):
        (trial / directory).mkdir(parents=True)
        (trial / directory).chmod(0o777)
    (trial / "result.json").write_text("{}")
    (trial / "verifier" / "reward.txt").write_text("1")


def test_raw_evidence_is_owner_only_under_a_permissive_umask(tmp_path, monkeypatch, credentials, permissive_umask):
    (tmp_path / "run").mkdir(mode=0o755)
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    probe(run)
    monkeypatch.setattr(workflow, "run_episode", runner.run_episode)
    monkeypatch.setattr(runner, "run_harbor", harbor_tree)
    monkeypatch.setattr(runner, "select_path", lambda task_dir, native: ("harbor", []))
    asyncio.run(workflow.run_role_episode(run, "simulator", instruction="Also explain the answer."))
    assert (run.config.output_dir / "episodes" / run.record.episodes[0] / "nudi-evidence" / "extension.md").is_file()
    assert modes(run.config.output_dir) == {}


def test_inspector_evidence_is_owner_only_under_a_permissive_umask(tmp_path, docker_env, permissive_umask):
    from nudi import inspector

    script = AgentScript(
        ("execute", {"command": "python3 -c \"print('x' * 100000); print('NUDI_OUTPUT_TAIL')\"; mkdir -p /nudi/workspace/a/b; echo kept > /nudi/workspace/a/b/note.txt"}),
        ("Finding", {"summary": "retained"}))

    async def main():
        async with serve(script) as base_url:
            run = inspector_run(tmp_path, base_url)
            async with inspector.investigation(run, "owner-only", "Inspect the copied package.", {}) as session:
                await session.ask("Write nested workspace files.", Finding)
            return session

    session = asyncio.run(main())
    assert (session.box.directory / "workspace/nudi/workspace/a/b/note.txt").read_text() == "kept\n"
    assert any((session.box.directory / "tool-outputs").iterdir())
    assert modes(session.box.directory) == {}


# Bundled verifier tests: an image that owns /tests/test.sh keeps it.

BUNDLED_GRADER = """FROM python:3.12-slim
RUN mkdir -p /tests && printf '#!/bin/bash\\nmkdir -p /logs/verifier\\necho 1 > /logs/verifier/reward.txt\\n' > /tests/test.sh
"""


def bundled_task(tmp_path: Path, host_script: bool) -> Path:
    task = task_variant(tmp_path, SEPARATE_TASK)
    (task / "tests" / "Dockerfile").write_text(BUNDLED_GRADER)
    if host_script:
        (task / "tests" / "test.sh").write_text("#!/bin/bash\nmkdir -p /logs/verifier\necho 0 > /logs/verifier/reward.txt\n")
    else:
        (task / "tests" / "test.sh").unlink()
    return task


@pytest.mark.parametrize("host_script", [True, False])
def test_bundled_verifier_tests_are_not_uploaded(tmp_path, host_script):
    task = Task(bundled_task(tmp_path, host_script))
    verifier = VerifierFactory.create_verifier_from_config(
        VerifierConfig(import_path="nudi.runner:RewardVerifier"), task=task,
        trial_paths=TrialPaths(tmp_path / "trial"), environment=SimpleNamespace(os=task.config.environment.os))
    assert verifier._resolve_tests()[0] == []


@pytest.mark.parametrize("host_script", [True, False])
def test_native_bundled_grader_runs_the_image_test_script(tmp_path, docker_env, host_script):
    result, _ = episode(docker_env, bundled_task(tmp_path, host_script), "true", native=frozenset({"host_harness"}))
    assert result.errors == [] and result.rewards == {"reward": 1.0}
