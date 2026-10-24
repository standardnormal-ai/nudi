"""Run-level limits: Docker capacity, models and credentials for each role, and the
optional spending cap. Model calls go to a local scripted endpoint; no provider is called.
Docker episodes run one at a time.
"""

import asyncio
import json
import os
import types

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import litellm
import pytest
from aiohttp import web
from harbor.trial.trial import Trial
from litellm.integrations.custom_logger import CustomLogger

from nudi.records import DEFAULT_MODELS, ModelConfig, RunConfig, RunRecord
from nudi.workflow import (
    CapacityError,
    MissingCredential,
    SpendingCapReached,
    declared_requirements,
    model_calls,
    plan_concurrency,
    run_role_episode,
    start_run,
)
from test_runner import (
    CONFINED,
    CONTRACT_TASK,
    PROBE,
    PROVIDER_KEY,
    SEPARATE_TASK,
    TerminusScript,
    docker_env,  # noqa: F401  (pytest fixture)
    files_with_secret,
    long_agent_budget,
    serve,
    task_variant,
    tree_digest,
)

FILE_KEY = "nudi-limits-file-key"
OUTSIDE_KEY = "nudi-limits-outside-key"
UNPRICED = "openai/nudi-unpriced-model"
TINY_CAP = 1e-12


class Endpoint:
    """A chat completions endpoint that records each request body and its credential."""

    def __init__(self, delay: float = 0.0, usage: dict | None = None):
        self.delay, self.usage = delay, usage or {}
        self.requests: list[dict] = []
        self.auth: list[str | None] = []

    async def chat(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.requests.append(body)
        self.auth.append(request.headers.get("Authorization"))
        await asyncio.sleep(self.delay)
        usage = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18, **self.usage}
        choice = {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
        return web.json_response(
            {"id": "chatcmpl-limits", "object": "chat.completion", "created": 0, "model": body["model"],
             "choices": [choice], "usage": usage}
        )


class RecordingTerminus(TerminusScript):
    """The runner's Terminus 2 script, also recording each request's credential."""

    def __init__(self, command: str):
        super().__init__(command)
        self.auth: list[str | None] = []

    async def chat(self, request: web.Request) -> web.Response:
        self.auth.append(request.headers.get("Authorization"))
        return await super().chat(request)


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    """A credentials file; the provider variables are absent from the environment."""
    for name in ("XAI_API_KEY", "XIAOMI_MIMO_API_KEY", "NUDI_UNPRICED_KEY"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "credentials.env"
    path.write_text(
        f"XAI_API_KEY={FILE_KEY}\nXIAOMI_MIMO_API_KEY={FILE_KEY}\nNUDI_UNPRICED_KEY={FILE_KEY}\n"
    )
    return path


def new_run(tmp_path, monkeypatch, credentials, *, name="run", capacity=(8, 4096), **fields):
    monkeypatch.setattr("nudi.workflow.docker_capacity", lambda: capacity)
    fields.setdefault("task_dir", CONTRACT_TASK)
    config = RunConfig(output_dir=tmp_path / name, credentials_file=credentials, **fields)
    return start_run(config)


def stored_run(run) -> RunRecord:
    return RunRecord.model_validate_json((run.config.output_dir / "run.json").read_text())


async def call(base_url: str, model: str = "xai/grok-4.7", **kwargs):
    return await litellm.acompletion(
        model=model, api_base=base_url, messages=[{"role": "user", "content": "hi"}], **kwargs
    )


# Capacity: 90% of Docker's CPUs and memory sizes concurrency.


@pytest.mark.parametrize(
    ("docker", "declared", "expected"),
    [
        ((8, 4096), (1, 512), 7),
        ((10, 10000), (3, 1000), 3),
        ((10, 10000), (1, 3000), 3),  # memory exactly at the allowance
        ((10, 10000), (1, 3001), 2),
        ((10, 10000), (9, 100), 1),  # CPUs exactly at the allowance
    ],
)
def test_concurrency_uses_ninety_percent_of_docker_capacity(docker, declared, expected):
    assert plan_concurrency(*docker, *declared) == (expected, [])


@pytest.mark.parametrize("declared", [(10, 100), (1, 9001), (1, 10000)])
def test_episode_beyond_the_allowance_but_within_capacity_runs_alone_with_warning(declared):
    concurrency, warnings = plan_concurrency(10, 10000, *declared)

    assert concurrency == 1
    assert len(warnings) == 1 and "headroom" in warnings[0]


@pytest.mark.parametrize("declared", [(11, 100), (1, 10001), (11, None)])
def test_episode_beyond_physical_capacity_stops(declared):
    with pytest.raises(CapacityError, match="exceeds Docker's"):
        plan_concurrency(10, 10000, *declared)


@pytest.mark.parametrize("declared", [(None, 512), (1, None), (None, None)])
def test_missing_declarations_run_one_episode_with_exhaustion_warning(declared):
    concurrency, warnings = plan_concurrency(10, 10000, *declared)

    assert concurrency == 1
    assert len(warnings) == 1 and "may exhaust" in warnings[0]


@pytest.mark.parametrize("declared", [(0, 512), (-1, 512), (1, 0), (1, -512), (0, None), (None, -1)])
def test_nonpositive_declarations_are_rejected(declared):
    with pytest.raises(ValueError, match="must be positive"):
        plan_concurrency(10, 10000, *declared)


@pytest.mark.parametrize("environment", ["cpus = 0\nmemory_mb = 512", "cpus = 1\nmemory_mb = -512"])
def test_nonpositive_declaration_stops_the_run_before_it_writes(tmp_path, monkeypatch, credentials, environment):
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "task.toml").write_text(
        f'schema_version = "1.4"\n[environment]\ndocker_image = "python:3.12-slim"\n{environment}\n'
    )

    with pytest.raises(ValueError, match="must be positive"):
        new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    assert not (tmp_path / "run").exists()


def test_declared_requirements_come_from_the_raw_task(tmp_path):
    legacy = task_variant(tmp_path, CONTRACT_TASK)
    (legacy / "task.toml").write_text(
        'schema_version = "1.4"\n[environment]\ndocker_image = "python:3.12-slim"\nmemory = "1G"\n'
    )

    assert declared_requirements(CONTRACT_TASK) == (1, 512)
    # The separate grader runs after the task container, with the same declaration.
    assert declared_requirements(SEPARATE_TASK) == (1, 512)
    assert declared_requirements(legacy) == (None, 1024)


# Preflight: path, models, credentials and capacity are settled before any episode.


@pytest.mark.parametrize(("task", "reasons"), [(CONTRACT_TASK, 3), (SEPARATE_TASK, 2)])
def test_run_keeps_native_grading_and_harness_without_user_flags(
    tmp_path, monkeypatch, credentials, task, reasons
):
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    assert run.record.path == "harbor"
    assert len(run.record.path_reasons) == reasons
    assert stored_run(run) == run.record


def test_run_records_defaults_capacity_and_limitations_without_secrets(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)

    record = stored_run(run)
    assert record.models == DEFAULT_MODELS
    assert record.models["simulator"].model == "xiaomi_mimo/mimo-v2.6-pro"
    assert record.models["simulator"].reasoning_effort == "high"
    assert record.models["inspector"] == ModelConfig(model="xai/grok-4.7", reasoning_effort="xhigh")
    assert record.credential_sources == {role: "credentials file" for role in DEFAULT_MODELS}
    capacity = record.capacity
    assert (capacity.docker_cpus, capacity.docker_memory_mb) == (8, 4096)
    assert (capacity.episode_cpus, capacity.episode_memory_mb, capacity.concurrency) == (1, 512, 7)
    assert record.spending_cap is None and record.warnings == []
    assert record.cost_map
    limits = "\n".join(record.limitations)
    for disclosed in ("not a guarantee", "may exceed the cap", "differentiated", "whole-episode retries"):
        assert disclosed in limits
    assert FILE_KEY not in (run.config.output_dir / "run.json").read_text()


def test_overrides_win_for_their_role(tmp_path, monkeypatch, credentials):
    override = ModelConfig(model=UNPRICED, reasoning_effort="low", api_key_var="NUDI_UNPRICED_KEY")
    run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": override})

    assert run.record.models == {**DEFAULT_MODELS, "inspector": override}


def test_run_models_are_copies_so_changes_reach_no_default_or_other_run(tmp_path, monkeypatch, credentials):
    override = ModelConfig(model="xai/grok-4.7", api_base="http://override")
    first = new_run(tmp_path, monkeypatch, credentials, name="first", models={"attacker": override})
    second = new_run(tmp_path, monkeypatch, credentials, name="second", models={"attacker": override})
    first.record.models["inspector"].api_base = first.record.models["attacker"].api_base = "http://changed"

    assert DEFAULT_MODELS["inspector"] == ModelConfig(model="xai/grok-4.7", reasoning_effort="xhigh")
    assert second.record.models["inspector"].api_base is None
    assert override.api_base == second.record.models["attacker"].api_base == "http://override"


def test_environment_credentials_are_used_when_no_file_names_them(tmp_path, monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", OUTSIDE_KEY)
    monkeypatch.setenv("XIAOMI_MIMO_API_KEY", OUTSIDE_KEY)
    run = new_run(tmp_path, monkeypatch, None)

    assert run.record.credential_sources == {role: "environment" for role in DEFAULT_MODELS}


def test_credentials_file_does_not_change_the_environment(tmp_path, monkeypatch, credentials):
    before = dict(os.environ)

    new_run(tmp_path, monkeypatch, credentials)

    assert dict(os.environ) == before


def test_missing_credential_fails_before_execution(tmp_path, monkeypatch, credentials):
    credentials.write_text(f"XAI_API_KEY={FILE_KEY}\n")

    with pytest.raises(MissingCredential, match="simulator.*XIAOMI_MIMO_API_KEY") as error:
        new_run(tmp_path, monkeypatch, credentials)
    assert FILE_KEY not in str(error.value)
    assert not (tmp_path / "run").exists()


def test_only_the_requested_roles_need_credentials(tmp_path, monkeypatch, credentials):
    credentials.write_text(f"XAI_API_KEY={FILE_KEY}\n")
    monkeypatch.setattr("nudi.workflow.docker_capacity", lambda: (8, 4096))
    config = RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "run", credentials_file=credentials)

    run = start_run(config, roles=frozenset({"inspector", "attacker"}))

    assert set(run.record.credential_sources) == {"inspector", "attacker"}


@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("inside", ["", "results"])
def test_output_overlapping_the_task_is_rejected_before_the_run_writes(
    tmp_path, monkeypatch, credentials, alias, inside
):
    task = task_variant(tmp_path, CONTRACT_TASK)
    digest = tree_digest(task)
    root = task
    if alias:
        root = tmp_path / "alias"
        root.symlink_to(task)
    monkeypatch.setattr("nudi.workflow.docker_capacity", lambda: (8, 4096))
    config = RunConfig(task_dir=task, output_dir=root / inside, credentials_file=credentials)

    with pytest.raises(ValueError, match="output_dir .* overlaps the task"):
        start_run(config)
    assert tree_digest(task) == digest
    assert not (task / "results").exists()


def test_episode_beyond_docker_capacity_stops_before_starting(tmp_path, monkeypatch, credentials):
    with pytest.raises(CapacityError):
        new_run(tmp_path, monkeypatch, credentials, capacity=(8, 256))
    assert not (tmp_path / "run").exists()


def test_undeclared_task_runs_one_episode_and_records_the_warning(tmp_path, monkeypatch, credentials):
    task = task_variant(tmp_path, CONTRACT_TASK)
    (task / "task.toml").write_text('schema_version = "1.4"\n[environment]\ndocker_image = "python:3.12-slim"\n')

    record = stored_run(new_run(tmp_path, monkeypatch, credentials, task_dir=task))

    assert record.capacity.concurrency == 1
    assert any("may exhaust" in warning for warning in record.warnings)


def test_run_records_the_storage_declaration_as_unenforced(tmp_path, monkeypatch, credentials):
    task = task_variant(tmp_path, CONTRACT_TASK, "storage_mb = 4096\n")

    record = stored_run(new_run(tmp_path, monkeypatch, credentials, task_dir=task))

    assert record.path == "harbor" and len(record.path_reasons) == 4
    assert "storage_mb = 4096 is recorded but not enforced" in record.path_reasons[-1]
    # Storage plays no part in the fit: CPUs and memory alone size concurrency.
    assert record.capacity.concurrency == 7


# Upstream execution: the run's limit reaches Harbor's TrialQueue.


class FakeTrial:
    """Stands in for a Harbor trial, recording how many run at once."""

    created = 0
    active = 0
    most = 0

    def __init__(self, config, outcome):
        self.config, self.outcome = config, outcome
        self.hooks = {}

    def add_hook(self, event, hook):
        self.hooks.setdefault(event, []).append(hook)

    async def run(self):
        cls = FakeTrial
        cls.active += 1
        cls.most = max(cls.most, cls.active)
        try:
            await asyncio.sleep(0.2)
            (self.config.trials_dir / self.config.trial_name).mkdir(parents=True)
            return self.outcome()
        finally:
            cls.active -= 1


def fake_trials(monkeypatch, outcome):
    FakeTrial.created = FakeTrial.active = FakeTrial.most = 0

    async def create(config):
        FakeTrial.created += 1
        return FakeTrial(config, outcome)

    monkeypatch.setattr(Trial, "create", staticmethod(create))


def raise_failure():
    raise RuntimeError("fake trial")


def test_calculated_limit_bounds_concurrent_episodes(tmp_path, monkeypatch, credentials):
    fake_trials(monkeypatch, raise_failure)
    # 90% of 3 CPUs leaves room for two one-CPU episodes.
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(3, 4096))

    async def main():
        return await asyncio.gather(*(run_role_episode(run, "simulator") for _ in range(5)), return_exceptions=True)

    outcomes = asyncio.run(main())

    assert run.record.capacity.concurrency == 2
    assert (FakeTrial.created, FakeTrial.most) == (5, 2)
    assert all(isinstance(outcome, RuntimeError) for outcome in outcomes)
    assert len(stored_run(run).episodes) == 5


def test_failed_episode_is_not_retried_and_keeps_its_directory(tmp_path, monkeypatch, credentials):
    failed = types.SimpleNamespace(exception_info=types.SimpleNamespace(exception_type="EnvironmentStartTimeoutError"))
    fake_trials(monkeypatch, lambda: failed)
    run = new_run(tmp_path, monkeypatch, credentials)

    asyncio.run(run_role_episode(run, "simulator"))

    assert FakeTrial.created == 1
    (episode,) = run.record.episodes
    (trial_dir,) = (run.config.output_dir / "episodes" / episode / "harbor").iterdir()
    assert trial_dir.is_dir()


def test_cancelled_episode_is_recorded(tmp_path, monkeypatch, credentials):
    fake_trials(monkeypatch, raise_failure)
    run = new_run(tmp_path, monkeypatch, credentials)

    async def main():
        running = asyncio.create_task(run_role_episode(run, "simulator"))
        await asyncio.sleep(0.1)
        running.cancel()
        await asyncio.wait({running})
        return running

    assert asyncio.run(main()).cancelled()
    (episode,) = stored_run(run).episodes
    stored = json.loads((run.config.output_dir / "episodes" / episode / "episode.json").read_text())
    assert stored["cancelled"]


def test_lifecycle_orders_episodes_only_when_one_returned_before_the_next_started(tmp_path, monkeypatch, credentials):
    fake_trials(monkeypatch, lambda: types.SimpleNamespace(exception_info=None))
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(3, 4096))

    async def main():
        await run_role_episode(run, "simulator")
        await run_role_episode(run, "attacker")
        await asyncio.gather(run_role_episode(run, "simulator"), run_role_episode(run, "attacker"))
        running = asyncio.create_task(run_role_episode(run, "inspector"))
        await asyncio.sleep(0.1)
        running.cancel()
        await asyncio.wait({running})

    asyncio.run(main())

    events = [(event.episode, event.event) for event in stored_run(run).events]
    assert events[:4] == [
        ("0000-simulator", "started"), ("0000-simulator", "finished"),
        ("0001-attacker", "started"), ("0001-attacker", "finished"),
    ]
    assert events[4:6] == [("0002-simulator", "started"), ("0003-attacker", "started")]
    assert sorted(events[6:8]) == [("0002-simulator", "finished"), ("0003-attacker", "finished")]
    # A cancelled episode may still be stopping its container, so it never finishes.
    assert events[8:] == [("0004-inspector", "started")]


# Model calls: credentials are injected and costs counted for the run's calls only.


def test_run_calls_receive_the_file_credential_without_the_environment(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)
    endpoint = Endpoint()

    async def main():
        async with serve(endpoint) as base_url:
            with model_calls(run, "inspector", "probe"):
                await call(base_url, reasoning_effort="xhigh")

    asyncio.run(main())

    assert endpoint.auth == [f"Bearer {FILE_KEY}"]
    assert (endpoint.requests[0]["model"], endpoint.requests[0]["reasoning_effort"]) == ("grok-4.7", "xhigh")
    assert "XAI_API_KEY" not in os.environ


def test_each_call_is_counted_once_with_a_litellm_estimate(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)
    endpoint = Endpoint()

    async def main():
        async with serve(endpoint) as base_url:
            with model_calls(run, "inspector", "probe"):
                await call(base_url)
                await call(base_url)

    asyncio.run(main())

    expected = sum(litellm.cost_per_token(model="xai/grok-4.7", prompt_tokens=11, completion_tokens=7))
    record = stored_run(run)
    assert [(c.role, c.episode, c.model) for c in record.calls] == [("inspector", "probe", "xai/grok-4.7")] * 2
    assert [c.cost for c in record.calls] == [pytest.approx(expected)] * 2
    assert {c.cost_source for c in record.calls} == {"litellm.completion_cost"}
    assert (record.known_cost, record.unknown_cost_calls) == (pytest.approx(2 * expected), 0)
    assert FILE_KEY not in (run.config.output_dir / "run.json").read_text()


def test_provider_reported_cost_is_kept_beside_the_estimate(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)
    endpoint = Endpoint(usage={"cost": 0.25})

    async def main():
        async with serve(endpoint) as base_url:
            with model_calls(run, "inspector", "probe"):
                await call(base_url)

    asyncio.run(main())

    (recorded,) = run.record.calls
    assert recorded.provider_cost == 0.25
    assert recorded.cost is not None


def test_unknown_price_stays_unknown_warns_and_continues(tmp_path, monkeypatch, credentials):
    override = ModelConfig(model=UNPRICED, api_key_var="NUDI_UNPRICED_KEY")
    run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": override}, spending_cap=TINY_CAP)
    endpoint = Endpoint()

    async def main():
        async with serve(endpoint) as base_url:
            with model_calls(run, "inspector", "probe"):
                await call(base_url, model=UNPRICED)
                await call(base_url, model=UNPRICED)

    asyncio.run(main())

    record = stored_run(run)
    assert len(endpoint.requests) == 2 and endpoint.auth == [f"Bearer {FILE_KEY}"] * 2
    assert [c.cost for c in record.calls] == [None, None]
    assert all(c.cost_source.startswith("unknown") for c in record.calls)
    assert (record.known_cost, record.unknown_cost_calls, record.refused_calls) == (0.0, 2, {})
    assert len([w for w in record.warnings if UNPRICED in w]) == 1


def test_cap_refuses_new_calls_and_episodes_once_known_cost_reaches_it(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials, spending_cap=TINY_CAP)
    endpoint = Endpoint()
    fake_trials(monkeypatch, raise_failure)

    async def main():
        async with serve(endpoint) as base_url:
            with model_calls(run, "inspector", "probe"):
                await call(base_url)
                with pytest.raises(SpendingCapReached) as refused:
                    await call(base_url)
                assert FILE_KEY not in str(refused.value)
        with pytest.raises(SpendingCapReached):
            await run_role_episode(run, "simulator")

    asyncio.run(main())

    assert len(endpoint.requests) == 1
    assert FakeTrial.created == 0
    record = stored_run(run)
    assert (len(record.calls), record.refused_calls) == (1, {"probe": 1})
    assert record.episodes == []


def test_known_cost_equal_to_the_cap_reaches_it(tmp_path, monkeypatch, credentials):
    fake_trials(monkeypatch, raise_failure)
    run = new_run(tmp_path, monkeypatch, credentials, spending_cap=0.5)
    run.record.known_cost = 0.5

    with pytest.raises(SpendingCapReached):
        asyncio.run(run_role_episode(run, "simulator"))
    assert FakeTrial.created == 0


def test_concurrent_admitted_calls_finish_and_the_overshoot_is_disclosed(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials, spending_cap=TINY_CAP)
    endpoint = Endpoint(delay=0.3)

    async def main():
        async with serve(endpoint) as base_url:
            with model_calls(run, "inspector", "probe"):
                await asyncio.gather(*(call(base_url) for _ in range(3)))
                with pytest.raises(SpendingCapReached):
                    await call(base_url)

    asyncio.run(main())

    record = stored_run(run)
    assert (len(endpoint.requests), len(record.calls), record.refused_calls) == (3, 3, {"probe": 1})
    assert record.known_cost > TINY_CAP
    assert len([w for w in record.warnings if "exceeded the spending cap" in w]) == 1


class Unrelated(CustomLogger):
    def __init__(self):
        self.seen = 0

    async def async_pre_call_deployment_hook(self, kwargs, call_type):
        self.seen += 1


def test_overlapping_runs_are_isolated_and_unrelated_callbacks_kept(tmp_path, monkeypatch, credentials):
    monkeypatch.setenv("XAI_API_KEY", OUTSIDE_KEY)
    capped = new_run(tmp_path, monkeypatch, credentials, name="capped", spending_cap=TINY_CAP)
    other = new_run(tmp_path, monkeypatch, credentials, name="other")
    endpoint = Endpoint(delay=0.1)
    unrelated = Unrelated()
    litellm.callbacks.append(unrelated)

    async def in_run(run, base_url, n):
        with model_calls(run, "inspector", run.config.output_dir.name):
            for _ in range(n):
                await call(base_url)

    async def main():
        async with serve(endpoint) as base_url:
            await asyncio.gather(in_run(capped, base_url, 1), in_run(other, base_url, 2), call(base_url))
            # The capped run refuses; the other run and calls outside any run do not.
            with pytest.raises(SpendingCapReached):
                await in_run(capped, base_url, 1)
            await asyncio.gather(in_run(other, base_url, 1), call(base_url))

    try:
        asyncio.run(main())
        assert unrelated in litellm.callbacks
    finally:
        litellm.callbacks.remove(unrelated)

    assert (len(capped.record.calls), capped.record.refused_calls) == (1, {"capped": 1})
    assert (len(other.record.calls), other.record.refused_calls) == (3, {})
    assert {c.episode for c in capped.record.calls} == {"capped"}
    assert len(endpoint.requests) == unrelated.seen == 6
    assert sorted(endpoint.auth) == sorted([f"Bearer {FILE_KEY}"] * 4 + [f"Bearer {OUTSIDE_KEY}"] * 2)


# Docker: the actual path, through native Harbor.

LIMITS_PROBE = f"{PROBE}; echo cgroup_memory=$(cat /sys/fs/cgroup/memory.max) cgroup_cpu=$(cat /sys/fs/cgroup/cpu.max)"


def docker_run(output, credentials, script, monkeypatch, role, task=CONTRACT_TASK, **fields):
    """Start a run with real Docker capacity and run one episode of `role` against `script`."""
    monkeypatch.delenv("XAI_API_KEY", raising=False)

    async def main():
        async with serve(script) as base_url:
            models = {role: DEFAULT_MODELS[role].model_copy(update={"api_base": base_url})}
            config = RunConfig(
                task_dir=task, output_dir=output, models=models, credentials_file=credentials, **fields
            )
            run = start_run(config, roles=frozenset({role}))
            try:
                return run, await run_role_episode(run, role)
            except Exception as error:
                return run, error

    return asyncio.run(main())


def test_simulator_episode_routes_mimo_with_the_file_credential_and_keeps_task_limits(
    docker_env, credentials, monkeypatch
):
    credentials.write_text(f"XIAOMI_MIMO_API_KEY={PROVIDER_KEY}\n")
    script = RecordingTerminus(LIMITS_PROBE)

    run, result = docker_run(docker_env, credentials, script, monkeypatch, "simulator")

    assert result.path == "harbor" and result.errors == []
    assert result.rewards["reward"] == 1.0
    for body in script.requests:
        assert body["model"] == "mimo-v2.6-pro"
        assert body["reasoning_effort"] == "high"
        assert body["thinking"] == {"type": "enabled"}
    assert script.auth == [f"Bearer {PROVIDER_KEY}"] * len(script.requests)
    (observation,) = script.observations()
    for expected in (*CONFINED, "cgroup_memory=536870912", "cgroup_cpu=100000 100000"):
        assert expected in observation, observation
    record = stored_run(run)
    assert record.capacity.concurrency >= 1 and record.capacity.episode_memory_mb == 512
    assert len(record.calls) == len(script.requests) >= 2
    assert all(c.cost is not None and c.role == "simulator" for c in record.calls)
    assert "XIAOMI_MIMO_API_KEY" not in os.environ
    assert files_with_secret(docker_env) == []


def test_cap_reached_during_an_episode_refuses_calls_without_inventing_a_reward(
    docker_env, credentials, monkeypatch, tmp_path
):
    credentials.write_text(f"XAI_API_KEY={PROVIDER_KEY}\n")
    script = RecordingTerminus("mkdir -p /app; echo 42 > /app/answer.txt")
    # A 600 s agent budget, so the refused calls rather than the task deadline end the agent.
    task = long_agent_budget(tmp_path, CONTRACT_TASK)

    run, result = docker_run(
        docker_env, credentials, script, monkeypatch, "inspector", task=task, spending_cap=TINY_CAP
    )

    assert len(script.requests) == 1
    assert result.rewards == {} and not (result.cancelled or result.agent_timeout)
    assert [e.type for e in result.errors] == ["SpendingCapReached"]
    record = stored_run(run)
    (episode,) = record.episodes
    # Terminus 2 tries a turn 3 times; each try is Harbor's LiteLLM call, also tried 3 times.
    assert (len(record.calls), record.refused_calls) == (1, {episode: 9})
    assert record.known_cost > TINY_CAP
    assert (docker_env / "episodes" / episode / result.artifacts["result"]).exists()
    assert files_with_secret(docker_env) == []
