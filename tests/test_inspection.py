"""Inspector investigations use package sandboxes and retained state, never a native task actor or a model verdict."""

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import httpx
import pytest
from aiohttp import web
from harbor.environments.base import ExecResult
from harbor.environments.docker.docker import DockerEnvironment
from harbor.environments.factory import EnvironmentFactory
from harbor.models.environment_type import EnvironmentType
from harbor.models.task.config import TaskOS
from pydantic import BaseModel

from nudi import checks, inspector, sandbox, workflow
from nudi.assessment import assess
from nudi.checks import host_command as trusted_host_command
from nudi.records import Assessment, Claim, Derivation, ModelConfig, Observation, RunConfig
from test_attack import GO_DIR, GO_FILE, stat_header
from test_limits import credentials, new_run
from test_runner import (  # noqa: F401
    CONTRACT_TASK,
    PROVIDER_KEY,
    SENTINEL,
    TerminusScript,
    docker_env,
    files_with_secret,
    masked,
    serve,
    tree_digest,
)


CHECKER = '''import hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs["submission"])
exists = int(state["exists"])
print(json.dumps({"input_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()}, "observations": {"exists": exists}, "results": {"deserved": exists}}))
'''


@pytest.fixture
def unit_sandboxes(request, monkeypatch):
    """Unit scenarios use the existing Harbor double; Docker contracts opt into docker_env."""
    if "docker_env" not in request.fixturenames:
        Sandboxes(monkeypatch)


def test_native_absence_capture_and_isolated_check_preserve_timing_limit(tmp_path, monkeypatch, docker_env):
    """A missing required file can contradict a reward; a later read cannot be invented."""
    async def main(root):
        task = root / "task"
        shutil.copytree(CONTRACT_TASK, task)
        requirement = "At verification start, /app/explanation.txt must exist."
        (task / "instruction.md").write_text("Write 42 to /app/answer.txt. " + requirement)
        original = tree_digest(task)
        script = TerminusScript("mkdir -p /app; echo 42 > /app/answer.txt", duration=0.1)
        async with serve(script) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = workflow.start_run(RunConfig(task_dir=task, output_dir=root / "run", models={"simulator": model}), frozenset({"simulator"}))
            result = await workflow.run_role_episode(run, "simulator", capture_locations=["/app/explanation.txt"])
            from nudi import checks
            submission = run.record.submissions[0]
            check = await checks.check_submission(
                run, submission,
                Observation(episode=None, path="instruction.md", excerpt=requirement),
                Observation(episode=None, path="tests/test.sh", excerpt='echo \'{"reward": 1.0, "answer_ok": 1.0}\''),
                CHECKER, capture_point="verification_start", timing="The requirement explicitly applies when verification starts.",
            )
            claim = Claim(mechanism="omitted required explanation", episode=submission.content.episode,
                          check=check.id, interpretation="The required file is absent, so no task credit is deserved.",
                          derivation=Derivation(observations=["exists"], minimum="deserved", maximum="deserved", validity="violated"))
            assert result.rewards["reward"] == 1
            assert assess(claim, run.config.output_dir).outcome == "accepted_invalid"
            assert check.environment and check.content in check.inputs.values()
            assert check.timing == "The requirement explicitly applies when verification starts."
            assert submission.capture_point == "verification_start"
            captured = json.loads((run.config.output_dir / "episodes" / submission.content.episode / submission.content.path).read_text())
            assert captured["exists"] is False
            assert captured["observed_start"] <= captured["observed_end"]
            unavailable = await checks.check_submission(
                run, submission, check.requirement, check.scoring, CHECKER,
                capture_point="grader_read", timing="This requirement applies only at the later grader read.",
            )
            claim.check = unavailable.id
            assert assess(claim, run.config.output_dir).outcome == "unknown"
            assert unavailable.submission is None
            assert len(run.record.episodes) == 1, "a retained check must not launch a substitute episode"
            assert len(run.record.sandboxes) == 1, "unsupported timing starts no substitute checker sandbox"
            assert tree_digest(task) == original
            assert all(call.role == "simulator" for call in run.record.calls)
            failed = await checks.check_submission(run, submission, check.requirement, check.scoring,
                                                    CHECKER + "\nraise SystemExit(3)\n", capture_point="verification_start", timing=check.timing)
            claim.check = failed.id
            assert failed.exit_code == 3
            assert assess(claim, run.config.output_dir).outcome == "unknown"

            later_task = root / "later-task"
            shutil.copytree(CONTRACT_TASK, later_task)
            late_requirement = "The answer must be 42 at the later grader read; background repair before that read is permitted."
            (later_task / "instruction.md").write_text(late_requirement)
            grader = later_task / "tests" / "test.sh"
            grader.write_text("#!/bin/bash\nsleep 6\n" + grader.read_text())
            script.requests.clear()
            script.command = "mkdir -p /app; echo 0 > /app/answer.txt; (sleep 5; echo 42 > /app/answer.txt) >/dev/null 2>&1 &"
            late_run = workflow.start_run(RunConfig(task_dir=later_task, output_dir=root / "later-run", models={"simulator": model}), frozenset({"simulator"}))
            later = await workflow.run_role_episode(late_run, "simulator", capture_locations=["/app/answer.txt"])
            late_state = late_run.record.submissions[0]
            captured = json.loads((late_run.config.output_dir / "episodes" / late_state.content.episode / late_state.content.path).read_text())
            assert base64.b64decode(captured["base64"]) == b"0\n"
            assert later.rewards["reward"] == 1
            provisional = await checks.check_submission(late_run, late_state,
                Observation(episode=None, path="instruction.md", excerpt=late_requirement),
                Observation(episode=None, path="tests/test.sh", excerpt="sleep 6"), CHECKER,
                capture_point="grader_read", timing="The relevant requirement applies to a later read, not this observation.")
            late_claim = Claim(mechanism="unobserved later state", episode=late_state.content.episode, check=provisional.id)
            assert assess(late_claim, late_run.config.output_dir).outcome == "unknown"
            assert len(late_run.record.episodes) == 1
            assert result.path == later.path == "harbor"
            assert "trial_id" in result.ids and "trial_id" in later.ids
            assert submission.execution_scope == late_state.execution_scope == "native"
            print("NUDI_ABSENCE " + json.dumps({"source_digest": original, "native": result.model_dump(),
                  "submission": submission.model_dump(), "check": check.model_dump(),
                  "checker_cleanup": [sandbox_record(run, name)["cleanup"] for name in run.record.sandboxes],
                  "unsupported": unavailable.model_dump(), "failed_exit_code": failed.exit_code,
                  "later_native": later.model_dump(), "later_captured": captured,
                  "later_outcome": assess(late_claim, late_run.config.output_dir).outcome}, sort_keys=True))

    monkeypatch.setenv("XAI_API_KEY", "nudi-local-key")
    asyncio.run(main(tmp_path))


def test_native_capture_rejects_a_parent_alias_into_verifier_state(tmp_path, docker_env):
    """The paused container's metadata is checked before each read: a regular file reached
    through /app/link -> /logs/verifier is rejected, and the answer beside it is captured."""
    async def main():
        task = tmp_path / "task"
        shutil.copytree(CONTRACT_TASK, task)
        script = TerminusScript("mkdir -p /app; ln -sfn /logs/verifier /app/link; echo planted > /app/link/probe.bin; "
                                "echo 42 > /app/answer.txt", duration=0.1)
        async with serve(script) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = workflow.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run", models={"simulator": model}), frozenset({"simulator"}))
            await workflow.run_role_episode(run, "simulator", capture_locations=["/app/link/probe.bin", "/app/answer.txt"])
        failure, = run.record.capture_errors
        assert failure.location == "/app/link/probe.bin", failure
        assert "rejected" in failure.error.message and "/logs/verifier" in failure.error.message, failure
        answer, = run.record.submissions
        assert answer.location == "/app/answer.txt" and answer.path_resolution["verified"]
        window, = answer.observation_windows
        assert window["paused"] and window["resumed_at"] and window["resume_error"] is None, window
        state = json.loads((run.config.output_dir / "episodes" / answer.content.episode / answer.content.path).read_text())
        assert base64.b64decode(state["base64"]) == b"42\n"

    asyncio.run(main())


class InspectorScript:
    """Translate existing scenario fixtures into scripted tool calls for the released SDK.

    The fixture supplies the model policy only. Nudi's real experiment, assessment,
    retry and ordinary-label code executes every call. Auxiliary requests stay scoped.
    """

    def __init__(self, responses, *, automatic_applicability=True):
        self.responses = iter(responses)
        self.requests = []
        self.turn = None
        self.automatic_applicability = automatic_applicability

    def next(self):
        response = next(self.responses)
        if isinstance(response, BaseException):
            raise response
        return response

    def message(self, body):
        if not body.get("tools"):
            self.requests.append(body)
            response = self.next()
            return {"role": "assistant", "content": response if isinstance(response, str) else json.dumps(response)}
        context_text = next(message["content"] for message in reversed(body["messages"]) if message["role"] == "user")
        context = json.loads(context_text)
        if self.turn is None or self.turn["context"] != context_text:
            self.requests.append(body)
            response = dict(self.next())
            if self.automatic_applicability and context.get("phase") == "broad" and "applicability" not in response:
                response["applicability"] = {category: {"scope": "package", "status": "applicable", "facts": {"package_copy": True},
                                                       "reason": "The Inspector can inspect the copied package."} for category in context["categories"]}
            repairs = response.get("reinterpretations", [])
            self.turn = {"context": context_text, "response": response, "probes": list(response.get("probes", [])),
                         "repairs": list(repairs) if isinstance(repairs, list) else [repairs], "waiting": None}
        turn = self.turn
        if turn["waiting"] == "measure":
            receipt = json.loads(body["messages"][-1]["content"])
            turn["waiting"] = None
            if receipt.get("check", {}).get("exit_code") == 0:
                if "scripted_claim" in receipt:
                    response = {"claim": receipt["scripted_claim"]}
                else:
                    request = json.loads(json.dumps(body))
                    request["messages"].append({"role": "user", "content": json.dumps({"check": receipt["check"], "rewards": receipt["rewards"]})})
                    self.requests.append(request)
                    response = self.next()
                if response.get("refusal"):
                    return self.call(body, "InspectionSummary", {"refusal": response["refusal"]})
                claim = response.get("claim", {})
                if isinstance(claim, dict):
                    probe = turn["probe"]
                    claim.setdefault("requirement_support", support(probe.get("requirement", {"episode": None, "path": "instruction.md", "excerpt": "42"})))
                    claim.setdefault("scoring_support", support(probe["scoring"]) if probe.get("scoring") else {
                        "basis": "unknown", "sources": [], "rationale": "No scoring source is available.", "uncertainty": []})
                    for reading in (claim["derivation"].get("requirements", []) if isinstance(claim.get("derivation"), dict) else []):
                        reading.setdefault("support", support(reading["requirement"]))
                turn["waiting"] = "interpret"
                return self.call(body, "interpret_experiment", {"experiment": receipt["id"], "claim": claim})
        elif turn["waiting"] == "interpret":
            turn["waiting"] = None
        if turn["repairs"]:
            repair = turn["repairs"].pop(0)
            repair = repair if isinstance(repair, dict) else {}
            identity, claim = repair.get("check", "invalid-check"), repair.get("claim", {})
            listed = [check for review in context.get("unresolved_ordinary_reviews", {}).values() for check in review["checks"]
                      if check["id"] == identity]
            if isinstance(claim, dict) and listed:
                claim.setdefault("requirement_support", support(listed[0]["requirement"]))
                claim.setdefault("scoring_support", support(listed[0]["scoring"]) if listed[0].get("scoring") else {
                    "basis": "unknown", "sources": [], "rationale": "No scoring source is available.", "uncertainty": []})
                for reading in (claim["derivation"].get("requirements", []) if isinstance(claim.get("derivation"), dict) else []):
                    reading.setdefault("support", support(reading["requirement"]))
            turn["waiting"] = "interpret"
            return self.call(body, "interpret_experiment", {"experiment": identity, "claim": claim})
        if turn["probes"]:
            turn["probe"] = turn["probes"].pop(0)
            turn["waiting"] = "measure"
            return self.call(body, "run_experiment", {"probe": turn["probe"]})
        return self.call(body, "InspectionSummary", {"applicability": turn["response"].get("applicability", {}),
            "completed": turn["response"].get("completed", context["categories"]), "refusal": turn["response"].get("refusal"),
            "normal_episodes": turn["response"].get("normal_episodes", [])})

    @staticmethod
    def call(body, name, arguments):
        return {"role": "assistant", "content": None, "tool_calls": [{"id": f"call_{len(body['messages'])}", "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)}}]}

    async def chat(self, request):
        body = await request.json()
        response = self.message(body)
        return web.json_response({"id": "inspection", "object": "chat.completion", "created": 0,
                                  "model": body["model"], "choices": [{"index": 0, "finish_reason": "tool_calls" if response.get("tool_calls") else "stop",
                                  "message": response}],
                                  "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})


def inspector_responses(monkeypatch, responses):
    """Replace only provider IO; keep the Inspector's parsing and workflow real."""
    script = InspectorScript(responses, automatic_applicability=False)

    async def completion(**request):
        body = json.loads(json.dumps(request))
        message = script.message(body)
        return checks.litellm.ModelResponse(choices=[{"index": 0, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop", "message": message}])

    monkeypatch.setattr(checks.litellm, "acompletion", completion)
    return script.requests


def mock_experiments(monkeypatch, callback):
    """Replace measurement and assessment for tests of orchestration.

    Capture/provenance/semantic tests use real measurements. These existing tests
    supply a chosen assessment to exercise stopping, retries and ordinary obligations.
    """
    original, assessments = checks.assess, {}

    async def measure(run, probe):
        before = len(run.record.checks)
        assessment = await callback(run, probe, None)
        check = run.record.checks[-1] if len(run.record.checks) > before else None
        identity = check.id if check else f"scripted-check-{len(assessments)}"
        assessments[identity] = assessment
        claim = assessment.claim.model_dump()
        for field in ("requirement_support", "scoring_support"):
            if claim[field] is None:
                claim.pop(field)
        return {"episode": assessment.claim.episode, "rewards": {"reward": 1.0},
                "check": check.model_dump() if check else {"id": identity, "exit_code": 0}, "scripted_claim": claim}

    def assess(claim, directory):
        return assessments[claim.check] if claim.check in assessments else original(claim, directory)

    monkeypatch.setattr(checks, "measure_experiment", measure)
    monkeypatch.setattr(checks, "assess", assess)


@pytest.mark.parametrize(("content", "valid"), [
    ('{"probes": []}', True),
    (' \n```json\n{"probes": []}\n```\n ', True),
    ('```json\n{"probes": []}\n``` trailing', False),
    ('Here is the result: {"probes": []}', False),
    ('{"probes": []} {"probes": []}', False),
    ('```json\n{"probes": []\n```', False),
    ('[]', False),
    ('{"probes": [], "value": NaN}', False),
])
def test_inspector_accepts_only_one_complete_json_object(tmp_path, monkeypatch, credentials, content, valid):
    inspector_responses(monkeypatch, [content])
    run = new_run(tmp_path, monkeypatch, credentials)
    if valid:
        assert asyncio.run(checks.InspectorSession(run, "capture-selection").ask("{}")) == {"probes": []}
    else:
        with pytest.raises(checks.ModelOutputFailure):
            asyncio.run(checks.InspectorSession(run, "capture-selection").ask("{}"))
    assert run.record.episodes == run.record.sandboxes == []


def test_hack_inspector_receives_the_static_checklist_shared_with_no_hint_attackers(tmp_path, monkeypatch, credentials, unit_sandboxes):
    requests = inspector_responses(monkeypatch, [
        {"probes": [], "applicability": package_applicability()},
        {"probes": []},
    ])
    run = new_run(tmp_path, monkeypatch, credentials)
    asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1))
    broad, focused = (json.loads(request["messages"][-1]["content"]) for request in requests)
    assert (broad["phase"], focused["phase"]) == ("broad", "focused")
    assert broad["checklist"] == checks.HACK_CHECKLIST and "checklist" not in focused
    assert broad["instruction"].startswith("You are the hack inspector.")
    assert requests[1]["messages"][:2] == requests[0]["messages"], "the fork keeps broad's checklist in its history"
    # One static list covers every approved hack category; it does not claim exhaustive coverage.
    assert all(category in checks.HACK_CHECKLIST for category in checks.HACK_CATEGORIES)
    assert "not exhaustive" in checks.HACK_CHECKLIST


def test_broad_then_two_focused_attempts_by_default_continue_one_fork_per_category(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """Two focused attempts per category by default, one try and one retry."""
    from nudi import checks

    script = InspectorScript([{"probes": []}] * 5)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            result = await checks.inspect_hacks(run, categories=["package_oracles", "fabricated_answers"])
            assert result.status == "complete"
            assert [attempt.phase for attempt in result.attempts] == ["broad"] + ["focused"] * 4
            assert [attempt.category for attempt in result.attempts[1:]] == ["package_oracles"] * 2 + ["fabricated_answers"] * 2
            lengths = [len(request["messages"]) for request in script.requests]
            # Each category forks broad's final state (request, reply, result), then adds its own turns.
            assert lengths == [2, 5, 8, 5, 8]
            focused = json.loads(script.requests[3]["messages"][-1]["content"])
            assert focused["categories"] == ["fabricated_answers"]
            assert "checklist" not in focused
            assert "package_oracles" not in focused["categories"]
            assert len(run.record.calls) == 5
            assert run.record.episodes == []

    asyncio.run(main())


def test_each_focused_category_forks_the_final_broad_conversation(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """A focused session starts from a copy of broad's final SDK state and adds a short request.
    Categories fork from broad, never from each other."""
    script = InspectorScript([{"probes": []}] * 3)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return await checks.inspect_hacks(run, categories=["package_oracles", "fabricated_answers"], focused_attempts=1)

    result = asyncio.run(main())
    broad, first, second = (request["messages"] for request in script.requests)
    assert first[:len(broad)] == second[:len(broad)] == broad
    assert first[len(broad):-1] == second[len(broad):-1] and len(first) == len(second) == len(broad) + 3, \
        "broad's final reply and result, then one request; the second fork excludes the first's turns"
    for messages, category in ((first, "package_oracles"), (second, "fabricated_answers")):
        request = json.loads(messages[-1]["content"])
        assert request["phase"] == "focused" and request["categories"] == [category]
        assert not {"task", "ordinary_episodes_read_first", "capture_inventory", "checklist", "broad_history"} & set(request)
        assert len(messages[-1]["content"]) < 2000
    assert json.loads(result.sessions["hack-fabricated_answers"][0]["content"])["categories"] == ["fabricated_answers"]
    assert result.status == "complete"


def test_fork_keeps_broad_compaction_without_summarizing_again(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """A compacted broad state is copied with its summarization event: the fork sees what broad saw last."""
    finish = ("InspectionSummary", {"applicability": package_applicability(), "completed": []})
    script = AgentScript(*[("execute", {"command": "true"})] * 4, "overflow", finish, finish, summary="BROAD_SUMMARY")

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1)

    asyncio.run(main())
    bodies = [body for _, body in script.requests]
    assert sum(not body.get("tools") for body in bodies) == 1, "the fork does not summarize again"
    compacted, focused = bodies[-2]["messages"], bodies[-1]["messages"]
    assert "BROAD_SUMMARY" in json.dumps(compacted)
    assert focused[:len(compacted)] == compacted and len(focused) == len(compacted) + 3
    # The broad request was compacted away; only the new request's attempt index names the broad phase.
    assert not any('"phase": "broad", "number"' in str(message.get("content")) for message in focused), "uncompacted history stays evicted"


def test_fork_workspace_has_the_files_broad_context_references(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """Offloaded results, compacted history and workspace notes from broad resolve at the same paths in a fork."""
    retain, upload, seeds = inspector.Investigation.retain, SandboxEnvironment.upload_dir, {}
    paths = ["large_tool_results/call_1", "conversation_history/session_1.md", "nudi/workspace/notes.txt"]

    async def retained(session):
        await retain(session)
        for path in paths if session.name == "hack-broad" else ():
            target = session.box.directory / "workspace" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"broad {path}")

    async def upload_dir(environment, source_dir, target_dir):
        seeds[environment.name] = {str(path.relative_to(source_dir)): path.read_bytes()
                                   for path in Path(source_dir).rglob("*") if path.is_file()}
        await upload(environment, source_dir, target_dir)

    monkeypatch.setattr(inspector.Investigation, "retain", retained)
    monkeypatch.setattr(SandboxEnvironment, "upload_dir", upload_dir)
    read_bytes, whole = Path.read_bytes, []
    monkeypatch.setattr(Path, "read_bytes", lambda path: whole.append(path) or read_bytes(path))
    script = InspectorScript([{"probes": []}] * 2)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1)

    result = asyncio.run(main())
    fork = Path(result.artifacts["hack-package_oracles"]["sandbox"]).parent.name
    assert {path: seeds[fork].get(path) for path in paths} == {path: f"broad {path}".encode() for path in paths}
    assert not [path for path in whole if path.is_relative_to(tmp_path) and "workspace" in path.parts], "the restore streams"


def test_broad_failure_before_any_reply_keeps_a_fresh_focused_conversation(tmp_path, monkeypatch, credentials, unit_sandboxes):
    requests = inspector_responses(monkeypatch, [TimeoutError("broad request timed out"), {"probes": []}])
    run = new_run(tmp_path, monkeypatch, credentials)
    asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1))
    focused = requests[1]["messages"]
    assert [message["role"] for message in focused] == ["system", "user"]
    request = json.loads(focused[-1]["content"])
    assert request["task"] and request["checklist"] == checks.HACK_CHECKLIST
    assert request["broad_history"]["transcript"] == "/nudi/evidence/broad/transcript.jsonl"
    assert request["instruction"].startswith("You are the hack inspector.")
    assert request["broad_history"]["label"].startswith("Prior broad hack inspector investigation")


def test_broad_retention_failure_keeps_a_fresh_focused_conversation(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """Broad replied, but its files were not retained in full: a fork would reference missing paths."""
    retain = inspector.Investigation.retain

    async def partial(session):
        if session.name == "hack-broad":
            target = session.box.directory / "workspace" / "nudi/workspace/notes.txt"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("partial")
            raise RuntimeError("retention interrupted")
        await retain(session)

    monkeypatch.setattr(inspector.Investigation, "retain", partial)
    requests = inspector_responses(monkeypatch, [{"probes": []}, {"probes": []}])
    run = new_run(tmp_path, monkeypatch, credentials)
    asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1))
    focused = requests[1]["messages"]
    assert [message["role"] for message in focused] == ["system", "user"]
    request = json.loads(focused[-1]["content"])
    assert request["task"] and request["checklist"] == checks.HACK_CHECKLIST
    assert request["broad_history"]["transcript"] == "/nudi/evidence/broad/transcript.jsonl"


def test_index_lists_experiment_identities_and_inspection_status_returns_it(tmp_path, monkeypatch, credentials, unit_sandboxes):
    async def investigate(run, probe, session):
        return Assessment(claim=Claim(mechanism="graded fix", episode="case", unresolved=["whether the fix is graded"]),
                          outcome="accepted_invalid", execution_scope="package")

    mock_experiments(monkeypatch, investigate)
    probe = setup_probe()
    claim = {"mechanism": "graded fix", "requirement_support": support(probe["requirement"]), "scoring_support": support(probe["scoring"])}
    finish = ("InspectionSummary", {"applicability": package_applicability(), "completed": []})
    script = AgentScript(("run_experiment", {"probe": probe}), ("interpret_experiment", {"experiment": "experiment-0000", "claim": claim}),
                         finish, ("inspection_status", {}), finish)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1)

    asyncio.run(main())
    focused = json.loads(script.requests[3][1]["messages"][-1]["content"])
    assert focused["experiments"] == [{"id": "experiment-0000", "category": "package_oracles", "case": "answer without explanation",
                                       "episode": "case", "status": "assessed", "assessment": 0, "outcome": "accepted_invalid",
                                       "check": "scripted-check-0", "unresolved": ["whether the fix is graded"]}]
    assert json.loads(script.tool_results()[-1])["experiments"] == focused["experiments"]


def test_candidate_continues_until_evidence_and_only_stops_its_category(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks

    probe = {"category": "package_oracles", "case": "one", "setup_program": "first case"}
    script = InspectorScript([{"probes": [probe]}, {"probes": [{**probe, "case": "two", "setup_program": "second case"}]}, {"probes": []}])
    outcomes = iter(["unknown", "accepted_invalid"])

    async def investigate(run, candidate, session):
        return Assessment(claim=Claim(mechanism="candidate", episode="case"), outcome=next(outcomes))

    mock_experiments(monkeypatch, investigate)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            result = await checks.inspect_hacks(run, categories=["package_oracles", "fabricated_answers"], focused_attempts=1)
            assert len(result.attempts) == 3
            assert [assessment.outcome for assessment in result.assessments] == ["unknown", "accepted_invalid"]
            assert result.categories["package_oracles"] == "evidenced_issue"
            assert result.categories["fabricated_answers"] == "no_evidenced_issue"

    asyncio.run(main())


@pytest.mark.parametrize("dropped", ["omitted_requirements", "partial_credit"])
def test_grader_inspector_has_two_categories_and_accepted_invalid_covers_unchecked_requirements(tmp_path, monkeypatch, credentials, dropped):
    """A stated requirement the grader never checks, with credit still given, is accepted_invalid;
    partial_credit is not supported yet."""
    assert checks.GRADER_CATEGORIES == ("accepted_invalid", "rejected_valid")
    with pytest.raises(ValueError, match="approved inspection categories"):
        asyncio.run(checks.inspect_grader(new_run(tmp_path, monkeypatch, credentials), [], categories=[dropped]))
    prompt = " ".join((Path(checks.__file__).parent / "prompts/inspector.md").read_text().split())
    assert dropped not in prompt
    assert ("`accepted_invalid` covers work that receives credit it does not deserve, including a stated requirement "
            "that the grader never checks while the work still receives credit.") in prompt
    assert "When every ordinary episode passes, check each stated requirement against what the grader reads" in prompt
    assert "In mode grader you are the grader inspector" in prompt and "In mode hack you are the hack inspector" in prompt


@pytest.mark.parametrize("mode,category,expected", [("hack", "grader_tampering", ["rejected_valid", "accepted_invalid"]),
                                                   ("grader", "rejected_valid", ["rejected_valid"])])
def test_hack_stopping_requires_undeserved_reward_while_grader_keeps_both_directions(tmp_path, monkeypatch, credentials, mode, category, expected, unit_sandboxes):
    requests = inspector_responses(monkeypatch, [
        {"probes": [{"category": category, "case": "false rejection", "setup_program": "false rejection"}], "applicability": package_applicability(category)},
        {"probes": [{"category": category, "case": "false acceptance", "setup_program": "false acceptance"}]}, {"probes": []},
    ])

    async def investigate(run, probe, session):
        return Assessment(claim=Claim(mechanism=probe["case"], episode=probe["case"]), execution_scope="package",
                          outcome="rejected_valid" if probe["case"] == "false rejection" else "accepted_invalid")

    mock_experiments(monkeypatch, investigate)
    run = new_run(tmp_path, monkeypatch, credentials)
    result = asyncio.run(checks.inspect(run, mode, [], 2, [category]))
    assert [assessment.outcome for assessment in result.assessments] == expected
    assert len(requests) == len(expected) and result.categories[category] == "evidenced_issue"
    assert result.assessments[0].claim.mechanism == "false rejection", "incidental FN evidence must be retained"


def test_attacker_false_rejection_does_not_stop_any_hint_condition(tmp_path, monkeypatch, credentials):
    from test_attack import linked_attribution, linked_check, scripted_episodes
    monkeypatch.setattr(workflow, "run_episode", scripted_episodes)
    claims = []
    for mechanism in ["false rejection"] * 3 + ["false acceptance"] * 3:
        if mechanism == "false acceptance":
            attribution = linked_attribution("check-reward")
        else:
            attribution = {"relation": "target", "basis": f"observed {mechanism}"}
        claims.append({"claim": {"mechanism": mechanism, "attribution": attribution}})
    inspector_responses(monkeypatch, [{"locations": []}] + claims)

    def assessed(claim, directory):
        check = linked_check(claim.episode, "check-reward") if claim.mechanism == "false acceptance" else None
        return Assessment(claim=claim, execution_scope="native", check=check,
                          outcome="rejected_valid" if claim.mechanism == "false rejection" else "accepted_invalid")

    monkeypatch.setattr(checks, "assess", assessed)
    run = new_run(tmp_path, monkeypatch, credentials)
    result = asyncio.run(checks.attack(run, maximum_attempts=2, full="full guidance", minimal="minimal hint"))
    # The default no-hint stream is one attempt. False rejection does not stop full or minimal, so each continues.
    assert [attempt.level for attempt in result.attempts] == ["none", "full", "minimal", "full", "minimal"]
    assert [attempt.status for attempt in result.attempts] == ["no_evidenced_issue"] * 3 + ["evidenced_issue"] * 2
    assert [assessment.outcome for assessment in result.assessments] == ["rejected_valid"] * 3 + ["accepted_invalid"] * 2
    assert all(result.assessments[attempt.assessment].claim.episode == attempt.episode for attempt in result.attempts)
    assert result.conditions == {"full": "evidenced_issue", "minimal": "evidenced_issue", "none": "no_evidenced_issue"}


def test_grader_reads_existing_traces_and_rejects_repeated_cases(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks
    from nudi.records import EpisodeResult

    script = InspectorScript([{"probes": []}, {"probes": [{"category": "accepted_invalid", "case": "same", "episode": "ordinary"}]},
                              {"probes": [{"category": "accepted_invalid", "case": "same", "episode": "ordinary"}]}])
    investigated = []

    async def investigate(run, probe, session):
        investigated.append(probe)
        return Assessment(claim=Claim(mechanism="candidate", episode="ordinary"), outcome="unknown")

    mock_experiments(monkeypatch, investigate)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            episode = run.config.output_dir / "episodes" / "ordinary"
            episode.mkdir(parents=True)
            (episode / "trace.txt").write_text("ordinary trajectory omitted the required work")
            result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir),
                                   task_digest=tree_digest(run.config.task_dir), model="ordinary", reasoning_effort=None,
                                   versions={}, rewards={"reward": 1}, artifacts={"trajectory": "trace.txt"})
            (episode / "episode.json").write_text(result.model_dump_json())
            run.record.episodes.append("ordinary")
            run.save()
            report = await checks.inspect_grader(run, ["ordinary"], categories=["accepted_invalid"], focused_attempts=2)
            initial = script.requests[0]["messages"][1]["content"]
            assert "ordinary trajectory omitted the required work" not in initial, "the model reads the trace file itself"
            assert '"retained_trace": "/nudi/evidence/episodes/ordinary/trace.txt"' in initial
            assert len(investigated) == 1
            assert "new case" in script.requests[-1]["messages"][-1]["content"].lower()
            assert report.attempts[-1].status == "duplicate_case"
            assert run.record.episodes == ["ordinary"]

    asyncio.run(main())


def test_grader_request_shows_beginning_and_end_of_long_traces(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """A long trace keeps early and late actions around a marked omission, read in bounded memory."""
    import tracemalloc
    from nudi.records import EpisodeResult

    script = InspectorScript([{"probes": []}] * 3)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            secret = run.keys["inspector"]
            traces = {"short": "é" * 65536,
                      "long": "EARLY-ACTION 漢 " + "middle 😀 " * 400_000 + "MIDDLE-ONLY" + "ü 😀 " * 100_000 + f" {secret} LATE-ACTION 終",
                      # Credentials fill both read buffers; of two offsets, at least one cuts a
                      # credential at each excerpt boundary.
                      **{f"cross-{pad}": "<" * pad + secret * 7000 + "middle " * 20_000 + secret * 7000 + ">" * pad for pad in range(2)}}
            digests = {}
            for name, text in traces.items():
                episode = run.config.output_dir / "episodes" / name
                episode.mkdir(parents=True)
                (episode / "trace.txt").write_bytes(text.encode())
                digests[name] = hashlib.sha256((episode / "trace.txt").read_bytes()).hexdigest()
                result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir),
                                       task_digest=tree_digest(run.config.task_dir), model="ordinary", reasoning_effort=None,
                                       versions={}, rewards={"reward": 1}, artifacts={"trajectory": "trace.txt"})
                (episode / "episode.json").write_text(result.model_dump_json())
                run.record.episodes.append(name)
            run.save()
            shown = {item["episode"]: item for item in checks.ordinary_context(run, list(traces))}
            system = {"content": (Path(checks.__file__).parent / "prompts/inspector.md").read_text()}
            assert shown["short"]["trace"] == traces["short"] and shown["short"]["trace_truncated"] is False
            trace = shown["long"]["trace"]
            assert shown["long"]["trace_truncated"] is True and len(trace) <= 65536
            assert trace.startswith("EARLY-ACTION 漢") and trace.endswith(" [redacted] LATE-ACTION 終")
            assert trace.count("[nudi omitted the middle") == 1 and "MIDDLE-ONLY" not in trace and "�" not in trace
            for pad in range(2):
                head, _, rest = shown[f"cross-{pad}"]["trace"].partition("\n[nudi omitted the middle")
                tail = rest.split("]\n", 1)[1]
                # Only whole or cut "[redacted]" tokens remain, never part of the credential.
                assert head[pad:].replace("[redacted]", "") in "[redacted]", head[-40:]
                assert tail[:len(tail) - pad].replace("[redacted]", "") in "[redacted]", tail[:40]
            # Only the tool-less Attacker interpreter receives trace bodies; the grader path keeps the path.
            assert "retained_trace" not in trace and shown["long"]["retained_trace"].endswith("/long/trace.txt")
            assert secret not in json.dumps(script.requests)
            assert "retained_trace" in system["content"]
            tracemalloc.start()
            checks.ordinary_context(run, ["long"])
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            size = (run.config.output_dir / "episodes" / "long" / "trace.txt").stat().st_size
            assert peak < size // 2, "the reader must not load a whole long trace to find its end"
            for name in traces:
                assert hashlib.sha256((run.config.output_dir / "episodes" / name / "trace.txt").read_bytes()).hexdigest() == digests[name]
        for pad in range(4):  # the end seek lands inside a four-byte character unless pad is 0
            path = tmp_path / f"emoji-{pad}.txt"
            path.write_bytes(("😀" * 70_000 + "a" * pad).encode())
            excerpt, truncated = checks.trace_excerpt(run, path)
            assert truncated and len(excerpt) <= 65536 and "�" not in excerpt and excerpt.endswith("😀" + "a" * pad)
        long_key = SimpleNamespace(keys={"inspector": "k" * 200 + "!"})
        for pad in range(2):  # redaction shrinks both buffers, so each excerpt reaches its cut buffer edge
            path = tmp_path / f"keys-{pad}.txt"
            path.write_text("<" * pad + long_key.keys["inspector"] * 1000 + ">" * pad)
            excerpt, truncated = checks.trace_excerpt(long_key, path)
            assert truncated and "k" not in excerpt and excerpt.count("[redacted]") > 600

    asyncio.run(main())


@pytest.mark.parametrize(("response", "expected"), [({"refusal": "cannot inspect"}, "model_inability"), ({"probes": []}, "no_evidenced_issue")])
def test_refusal_is_distinct_from_finished_investigation(tmp_path, monkeypatch, credentials, response, expected, unit_sandboxes):
    from nudi import checks

    async def main():
        async with serve(InspectorScript([response])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.attempts[0].status == expected
    asyncio.run(main())


def test_cap_and_cancellation_preserve_partial_inspection(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks

    async def main():
        async with serve(InspectorScript([{"probes": []}])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, spending_cap=0.000001,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            run.record.known_cost = 1
            report = await checks.inspect_hacks(run, categories=["package_oracles"])
            assert report.status == "spending_exhausted"
            assert run.record.calls == []
            run.record.known_cost = 0
            async def cancelled(*args, **kwargs):
                raise asyncio.CancelledError()
            monkeypatch.setattr(inspector.Investigation, "ask", cancelled)
            with pytest.raises(asyncio.CancelledError):
                await checks.inspect_hacks(run, categories=["package_oracles"])
            saved = json.loads((run.config.output_dir / "inspection-hack.json").read_text())
            assert saved["status"] == "cancelled"
            assert saved["attempts"][0]["status"] == "cancelled"
    asyncio.run(main())


def test_actual_reset_restriction_prevents_focused_retries(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks

    script = InspectorScript([{"probes": []}])
    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            report = await checks.inspect_hacks(run, categories=["persistence"])
            assert len(report.attempts) == 1
            assert report.categories == {"persistence": "restricted"}
            assert "reset" in report.applicability["persistence"].lower()
    asyncio.run(main())


@pytest.mark.parametrize("broad_fails", [False, True])
def test_restricted_persistence_lets_hack_inspection_complete(tmp_path, monkeypatch, credentials, broad_fails, unit_sandboxes):
    """A restriction with its stated reason settles persistence; the inspection is complete once the other categories settle,
    also when a focused attempt recovers from a failed broad request, which persistence never gets."""
    from nudi import report
    no_native_actor(monkeypatch)
    settled = {"probes": [], "applicability": package_applicability()}
    inspector_responses(monkeypatch, [TimeoutError("broad request timed out"), settled] if broad_fails else [settled])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles", "persistence"], focused_attempts=int(broad_fails)))
    assert [attempt.status for attempt in result.attempts] == ["inference_failure"] * broad_fails + ["no_evidenced_issue"]
    assert result.categories == {"package_oracles": "no_evidenced_issue", "persistence": "restricted"}
    assert result.status == "complete"
    warnings = []
    report.inspection("hack", result, warnings)
    assert any("persistence is restricted" in warning and "reset" in warning for warning in warnings)


def test_inference_and_tool_failures_remain_distinct(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks

    async def main():
        async with serve(InspectorScript([{"probes": [{"category": "package_oracles", "case": "broken"}]}])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            async def broken_tool(*args):
                raise RuntimeError("native tool failed")
            mock_experiments(monkeypatch, broken_tool)
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.status == "partial"
            assert report.attempts[0].status == "tool_failure"
            async def broken_inference(*args, **kwargs):
                raise checks.InferenceFailure("local endpoint failed")
            monkeypatch.setattr(inspector.Investigation, "ask", broken_inference)
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.attempts[0].status == "inference_failure"
            assert report.status == "partial" and len(report.attempts) == 1
            assert report.categories == {"package_oracles": "unknown"}
    asyncio.run(main())


def retained_native_submission(run, text: str):
    """One ordinary episode whose retained state file is exactly `text`."""
    from nudi.records import Content, EpisodeResult, Submission

    name = "0000-simulator"
    directory = run.config.output_dir / "episodes" / name
    (directory / "nudi-evidence").mkdir(parents=True, exist_ok=True)
    (directory / "nudi-evidence" / "state.json").write_text(text)
    ids = {"trial_id": "native-trial", "trial_name": "trial", "task_checksum": "sum"}
    task = Path(run.config.task_dir)
    result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(task), task_digest=tree_digest(task),
                           model="ordinary", reasoning_effort=None, versions={}, ids=ids, rewards={"reward": 1.0},
                           artifacts={"nudi_evidence": "nudi-evidence"})
    (directory / "episode.json").write_text(result.model_dump_json())
    if name not in run.record.episodes:
        run.record.episodes.append(name)
    run.save()
    content = Content(episode=name, path="nudi-evidence/state.json", sha256=hashlib.sha256(text.encode()).hexdigest())
    return Submission(content=content, ids=ids, location="/app/answer.txt", capture_point="verification_start",
                      command=[sys.executable, "-c", checks.CAPTURE_PROGRAM], program=checks.CAPTURE_PROGRAM,
                      exit_code=0, output=text)


def test_tool_exit_and_cancellation_are_host_records_not_task_logs(tmp_path, monkeypatch, credentials):
    """A check exit and a cancellation are host sandbox records, never task-mounted logs."""
    from nudi.records import Observation

    mounted = tmp_path / "task-mounted"
    mounted.mkdir()
    program = 'import sys\nprint(\'{"measured": 1}\')\nsys.exit(3)\n'
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    requirement = Observation(episode=None, path="instruction.md", excerpt="Write the number 42")
    submission = retained_native_submission(run, "{}")

    check = asyncio.run(checks.check_submission(run, submission, requirement, None, program,
                                                capture_point="verification_start", timing="The check records its own exit."))
    record = sandbox_record(run, "sandbox-0000")
    assert (check.exit_code, check.output) == (3, '{"measured": 1}\n')
    assert check.command == ["python3", sandbox.CHECK_PROGRAM] and program not in check.command
    assert check.environment.startswith("Inspector package sandbox ")
    assert record["commands"][-1]["argv"] == check.command
    assert (record["commands"][-1]["exit_code"], record["commands"][-1]["output"]) == (3, '{"measured": 1}\n')
    assert run.record.episodes == ["0000-simulator"]
    receipt = run.config.output_dir / "sandboxes" / "sandbox-0000" / "sandbox.json"
    assert not any(mounted.rglob("*"))
    assert not receipt.resolve().is_relative_to(mounted.resolve())
    assert not receipt.resolve().is_relative_to(Path(run.config.task_dir).resolve())
    mount = Path(sandboxes.environments["sandbox-0000"].config["mounts"][0]["source"]).resolve()
    assert not receipt.resolve().is_relative_to(mount)

    original_exec = SandboxEnvironment.exec

    async def cancel_check(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        if sandbox.CHECK_PROGRAM in shlex.split(command) and checks.VERSION_PROBE not in command:
            raise asyncio.CancelledError()
        return await original_exec(self, command, cwd=cwd, env=env, timeout_sec=timeout_sec, user=user)

    monkeypatch.setattr(SandboxEnvironment, "exec", cancel_check)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(checks.check_submission(run, submission, requirement, None, program,
                                            capture_point="verification_start", timing="The check records its own exit."))
    cancelled = sandbox_record(run, "sandbox-0001")
    assert cancelled["cancelled"] is True and cancelled["cleanup"]["removed"] is True
    assert cancelled["commands"][-1]["argv"] == ["python3", sandbox.CHECK_PROGRAM]
    assert cancelled["commands"][-1]["exit_code"] is None and cancelled["commands"][-1]["finished_at"]
    assert run.record.checks[-1].exit_code is None
    assert sandbox_record(run, "sandbox-0000")["commands"][-1]["exit_code"] == 3
    assert not any(mounted.rglob("*"))
    assert run.record.episodes == ["0000-simulator"]


@pytest.mark.parametrize(("versions", "selected"), [
    ({"python3": "3"}, "python3"),  # the stopped live run: no python, python3 installed
    ({"python": "3"}, "python"),
    ({"python3": "2", "python": "3"}, "python"),
    ({"python": "2"}, None),
    ({}, None),
])
def test_check_uses_the_instance_python3_or_records_an_unsupported_runtime(tmp_path, monkeypatch, credentials, versions, selected):
    """Probes and the check share one check sandbox. Python 2 never runs a check."""
    from nudi.records import Observation

    mounted = tmp_path / "task-mounted"
    mounted.mkdir()
    state = json.dumps({"base64": base64.b64encode(b"42\n").decode(), "exists": True, "location": "/app/answer.txt",
                        "observed_end": "end", "observed_start": "start"}, sort_keys=True)
    sandboxes = Sandboxes(monkeypatch, pythons=versions)
    run = new_run(tmp_path, monkeypatch, credentials)
    requirement = Observation(episode=None, path="instruction.md", excerpt="Write the number 42")
    check = asyncio.run(checks.check_submission(
        run, retained_native_submission(run, state), requirement, None, CHECKER,
        capture_point="verification_start", timing="The requirements apply at verification start."))
    record = sandbox_record(run, "sandbox-0000")
    probes = [entry for entry in record["commands"] if entry["argv"][1:] == ["-c", checks.VERSION_PROBE]]
    for entry in probes:
        name = entry["argv"][0]
        assert entry["exit_code"] == (0 if name in versions else 127)
        if name in versions:
            assert entry["output"].strip() == versions[name]
    assert record["files"][sandbox.CHECK_PROGRAM] == hashlib.sha256(CHECKER.encode()).hexdigest()
    receipt = run.config.output_dir / "sandboxes" / "sandbox-0000" / "sandbox.json"
    assert not any(mounted.rglob("*"))
    assert not receipt.resolve().is_relative_to(mounted.resolve())
    assert not receipt.resolve().is_relative_to(Path(run.config.task_dir).resolve())
    mount = Path(sandboxes.environments["sandbox-0000"].config["mounts"][0]["source"]).resolve()
    assert not receipt.resolve().is_relative_to(mount)
    if selected:
        assert [entry["argv"][0] for entry in probes] == list(checks.PYTHON_CANDIDATES[:checks.PYTHON_CANDIDATES.index(selected) + 1])
        assert check.command == record["commands"][-1]["argv"] == [selected, sandbox.CHECK_PROGRAM]
        assert record["commands"][-1]["stdin"] == sandbox.CHECK_INPUTS
        assert CHECKER not in check.command
        assert check.exit_code == 0 and json.loads(check.output)["observations"] == {"exists": 1}
    else:
        assert [entry["argv"][0] for entry in probes] == list(checks.PYTHON_CANDIDATES)
        assert all(entry["argv"][1:] != [sandbox.CHECK_PROGRAM] for entry in record["commands"])
        assert (check.command, check.exit_code) == ([], None)
        assert check.output.startswith(checks.UNSUPPORTED_RUNTIME)


FAKE_DOCKER = '''import io, sys, tarfile
if sys.argv[1] == "inspect":
    print("true")
    sys.exit(0)
location = sys.argv[2].split(":", 1)[1]
if location != "/app/answer.txt":
    sys.stderr.write("Error response from daemon: Could not find the file " + location + " in container\\n")
    sys.exit(1)
data, buffer = b"42\\n", io.BytesIO()
with tarfile.open(fileobj=buffer, mode="w") as archive:
    member = tarfile.TarInfo("answer.txt")
    member.size = len(data)
    archive.addfile(member, io.BytesIO(data))
sys.stdout.buffer.write(buffer.getvalue())
'''
MEASURE = '''observations = {"exists": int(data is not None)}
if data is not None:
    observations["bytes"] = list(data)
print(json.dumps({"input_sha256": input_sha256, "observations": observations, "results": {}}))
'''


def test_prompt_decoder_reads_actual_capture_states_and_rejects_malformed_fields(tmp_path, monkeypatch, credentials):
    """The trusted capture program's real state format, read through a stand-in docker CLI,
    decoded by the prompt's example. Malformed fields exit nonzero with no structured result."""
    import sys
    from nudi import checks
    from nudi.assessment import captured_object

    docker = tmp_path / "bin" / "docker"
    docker.parent.mkdir()
    docker.write_text(f"#!{sys.executable}\n" + FAKE_DOCKER)
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{docker.parent}{os.pathsep}{os.environ['PATH']}")
    evidence = tmp_path / "evidence"
    present = asyncio.run(checks.read_exact("container", "/app/answer.txt", evidence, "present.json"))
    absent = asyncio.run(checks.read_exact("container", "/app/missing.txt", evidence, "absent.json"))
    assert set(present["state"]) == {"location", "exists", "base64", "observed_start", "observed_end"}
    assert set(absent["state"]) == {"location", "exists", "observed_start", "observed_end"}

    prompt = (Path(checks.__file__).parent / "prompts" / "inspector.md").read_text()
    program = prompt.split("```python\n")[1].split("```")[0] + MEASURE
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    requirement = Observation(episode=None, path="instruction.md", excerpt="Write the number 42")
    scoring = Observation(episode=None, path="tests/test.sh", excerpt="answer_ok")

    def check(submission: str):
        # The prompt example runs from the uploaded program file, with inputs uploaded beside it.
        done = asyncio.run(checks.check_submission(
            run, retained_native_submission(run, submission), requirement, scoring, program,
            capture_point="verification_start", timing="The requirement applies at verification start."))
        uploaded = json.loads(sandboxes.environments[done.sandbox].uploads[sandbox.CHECK_INPUTS])
        assert sandboxes.environments[done.sandbox].uploads[sandbox.CHECK_PROGRAM] == program.encode()
        assert done.command == ["python3", sandbox.CHECK_PROGRAM] and program not in done.command
        return done.exit_code, captured_object(done.output), uploaded

    for name, retained, expected in (("present.json", present, {"exists": 1, "bytes": list(b"42\n")}),
                                     ("absent.json", absent, {"exists": 0})):
        status, result, inputs = check((evidence / name).read_text())
        assert status == 0
        assert result["observations"] == expected
        assert result["input_sha256"]["submission"] == retained["file_sha"]
        assert result["input_sha256"] == {key: hashlib.sha256(value.encode()).hexdigest() for key, value in inputs.items()}

    state, missing = present["state"], absent["state"]
    interval = {key: value for key, value in state.items() if key not in ("observed_start", "observed_end")}
    malformed = [
        {**{key: value for key, value in state.items() if key != "base64"}, "bytes_base64": state["base64"]},
        {**interval, "interval": {"start": state["observed_start"], "end": state["observed_end"]}},
        {**state, "base64": "not base64!"},
        {**missing, "exists": "false"},
        {**missing, "base64": ""},
    ]
    for submission in malformed:
        status, result, _ = check(json.dumps(submission, sort_keys=True))
        assert status != 0 and result is None, submission


def test_inspector_failure_does_not_retain_credentials(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks

    run = new_run(tmp_path, monkeypatch, credentials)
    secret = run.keys["inspector"]
    async def failure(**kwargs):
        raise RuntimeError("provider echoed " + secret)
    monkeypatch.setattr(checks.litellm, "acompletion", failure)
    report = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert report.attempts[0].status == "inference_failure"
    assert secret not in (run.config.output_dir / "inspection-hack.json").read_text()


def test_targeted_probe_dispatch_keeps_privilege_out_of_later_ordinary_episode(tmp_path, monkeypatch, credentials):
    """A setup program stays in its probe sandbox. The later ordinary episode receives neither it nor a native Inspector."""
    from nudi import checks
    from nudi.records import EpisodeResult

    privileged = "Privileged Inspector-only targeted probe.\n"
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    dispatched = []
    async def native(config, queue, **work):
        assert queue is run.queue
        assert workflow.current.get()[0] is run
        dispatched.append((config, work))
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(config.task_dir),
                               task_digest=tree_digest(config.task_dir), model=config.model, reasoning_effort=config.reasoning_effort,
                               versions={}, ids={"trial_id": str(len(dispatched))}, rewards={"reward": 1})
        config.output_dir.mkdir(parents=True)
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result
    monkeypatch.setattr(workflow, "run_episode", native)
    probe = {"category": "accepted_invalid", "case": "later-state", "location": "/app/answer.txt",
             "capture_point": "grader_read", "timing": "This case requires a later read.", "program": CHECKER,
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"},
             "setup_program": privileged}
    async def main():
        assessment = await checks.investigate(run, probe, None)
        assert assessment.outcome == "unknown"
        assert "grader_read" in assessment.missing[-1]
        await workflow.run_role_episode(run, "simulator")
    asyncio.run(main())
    assert sandboxes.environments["sandbox-0000"].uploads[sandbox.SETUP] == privileged.encode()
    assert any(event[0] == "exec" and event[1] == "sandbox-0000" and sandbox.SETUP in event[2] for event in sandboxes.events)
    assert run.record.sandboxes == ["sandbox-0000"]
    (config, work), = dispatched
    assert work == {"credentials": run.config.credentials_file} and config.native == workflow.ORIGINAL_BEHAVIOR
    assert config.output_dir.name == "0000-simulator"
    assert run.record.episodes == ["0000-simulator"]
    assert privileged not in (run.config.task_dir / "instruction.md").read_text()
    assert privileged not in json.dumps(work, default=str)


def test_failed_and_provisional_feedback_reaches_same_inspector_retry(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks
    script = InspectorScript([{"probes": []}, {"probes": [{"category": "package_oracles"}]}, {"probes": []}])
    async def investigate(*args):
        return Assessment(claim=Claim(mechanism="candidate", episode="case"), outcome="unknown", missing=["measured retry feedback"])
    mock_experiments(monkeypatch, investigate)
    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=2)
            assert "measured retry feedback" in json.dumps(script.requests[2]["messages"])
    asyncio.run(main())


def test_broad_applicability_controls_focused_coverage(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks
    decision = {"scope": "package", "status": "restricted", "facts": {"package_copy": True}, "reason": "No available tool for this case."}
    script = InspectorScript([{"probes": [], "applicability": {"package_oracles": decision}}] + [{"probes": []}] * 3)
    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=3)
            assert len(script.requests) == 4
            assert report.status == "partial"
            assert report.categories["package_oracles"] == "unknown"
    asyncio.run(main())


def test_capture_failure_is_structured_and_partial(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """A failed package-sandbox capture is a structured host record, and the report stays partial."""
    from nudi import checks
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    async def failed_capture(*args, **kwargs):
        raise RuntimeError("archive unavailable")
    monkeypatch.setattr(checks, "protected_state", failed_capture)
    probe = {"category": "package_oracles", "setup_program": "echo targeted\n", "location": "/app/answer.txt",
             "capture_point": "verification_start", "timing": "at verification start", "program": CHECKER,
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "42"}}
    script = InspectorScript([{"probes": [probe]}])
    async def main():
        async with serve(script) as base:
            run.record.models["inspector"].api_base = base
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.attempts[0].status == "tool_failure"
            assert report.status == "partial"
            failure = run.record.capture_errors[0]
            assert (failure.episode, failure.location, failure.error.type) == ("sandbox-0001", "/app/answer.txt", "RuntimeError")
            assert failure.error.message == "archive unavailable"
            assert "archive unavailable" in json.dumps(report.sessions)
            assert run.record.episodes == []
    asyncio.run(main())


class SandboxEnvironment:
    """One Inspector sandbox, standing in for Harbor's Docker environment."""

    _collect_buffered_output = staticmethod(DockerEnvironment._collect_buffered_output)
    _terminate_process = staticmethod(DockerEnvironment._terminate_process)

    def __init__(self, owner, **config):
        self.owner, self.config = owner, config
        self.session_id = config["session_id"]
        self.name = self.session_id[self.session_id.index("sandbox-"):]
        self.trial_paths = config["trial_paths"]
        self.os = TaskOS.LINUX
        self.capabilities = SimpleNamespace(mounted=True)
        self.default_user = None
        self.uploads = {}

    def event(self, action, *detail):
        self.owner.events.append((action, self.name, *detail))
        if failure := self.owner.fail.get((action, self.name)):
            raise failure

    @contextlib.contextmanager
    def with_default_user(self, user):
        previous, self.default_user = self.default_user, user
        try:
            yield
        finally:
            self.default_user = previous

    async def start(self, force_build):
        self.owner.running.add(self.name)
        self.event("start", force_build)

    async def upload_dir(self, source_dir, target_dir):
        self.event("upload_dir", target_dir, tree_digest(Path(source_dir)))

    async def upload_file(self, source_path, target_path):
        self.uploads[target_path] = Path(source_path).read_bytes()
        self.event("upload_file", target_path, self.uploads[target_path])

    async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
        user = self.default_user if user is None else user
        self.event("exec", command, user, timeout_sec)
        args = shlex.split(command)
        if args[1:] == ["-c", checks.VERSION_PROBE]:
            if args[0] not in self.owner.pythons:
                return ExecResult(stdout=f"sh: {args[0]}: not found\n", stderr="", return_code=127)
            return ExecResult(stdout=self.owner.pythons[args[0]] + "\n", stderr="", return_code=0)
        if "/tests/test.sh" in command and not command.startswith("chmod"):
            reward = self.owner.rewards.get(self.name, 1.0)
            if reward is not None:
                (self.trial_paths.verifier_dir / "reward.json").write_text(json.dumps({"reward": reward}))
            (self.trial_paths.verifier_dir / "test-stdout.txt").write_text("graded copy\n")
            return ExecResult(stdout="", stderr="", return_code=0)
        if len(args) < 2 or args[1] != sandbox.RUNNER:
            return ExecResult(stdout="", stderr="", return_code=0)
        assert self.owner.pythons[args[0]] == "3", "the trusted collector needs the selected Python 3"
        stdin, argv = args[2], args[3:]
        if argv == ["sh", sandbox.SETUP]:
            if self.name in self.owner.blocked:
                await self.owner.blocked[self.name].wait()
            return ExecResult(stdout="setup ran\n", stderr="", return_code=0)
        if argv[0] not in self.owner.pythons:
            return ExecResult(stdout=f"sh: {argv[0]}: not found\n", stderr="", return_code=127)
        # A stand-in for the container's Python 3, reading the uploaded program and input files.
        assert argv[1:] == [sandbox.CHECK_PROGRAM] and stdin == sandbox.CHECK_INPUTS, args
        done = subprocess.run([sys.executable, "-c", self.uploads[sandbox.CHECK_PROGRAM].decode()],
                              input=self.uploads[sandbox.CHECK_INPUTS], capture_output=True, timeout=30)
        output = (done.stdout + done.stderr)[:sandbox.OUTPUT_LIMIT + 1]
        return ExecResult(stdout=output.decode(errors="replace"), stderr="", return_code=done.returncode)

    async def stop(self, delete):
        self.owner.running.discard(self.name)
        self.event("stop", delete)


class Sandboxes:
    """Harbor's Docker environment factory and the Docker CLI and daemon calls that observe
    Inspector sandboxes; nothing reaches Docker. `files` maps a sandbox name to the files its
    setup program leaves, `rewards` to the reward its copied grader writes (default 1.0;
    None writes none). `pythons` maps an executable to the major version it reports.
    `events` records every environment call as (action, sandbox, detail...) in order.
    Unknown containers are delegated to `native`, the native episode double, when given."""

    def __init__(self, monkeypatch, *, files=None, rewards=None, pythons=None, native=None):
        self.files, self.rewards, self.native = files or {}, rewards or {}, native
        self.pythons = {"python3": "3"} if pythons is None else pythons
        self.events, self.environments, self.running, self.remaining = [], {}, set(), set()
        self.fail, self.blocked = {}, {}
        monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(self.create))
        monkeypatch.setattr(checks, "host_command", self.docker)
        monkeypatch.setattr(checks, "unix_docker_socket", self.socket)
        monkeypatch.setattr(checks, "docker_client", self.client)

    def create(self, **config):
        environment = SandboxEnvironment(self, **config)
        self.environments[environment.name] = environment
        return environment

    def owner(self, container):
        return next((name for name, item in self.environments.items() if item.session_id == container), None)

    async def socket(self):
        return "/sandbox/docker.sock", None

    async def client(self, sock):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.daemon), base_url="http://docker"), "1.44"

    def daemon(self, request):
        container, action = request.url.path.split("/")[3:5]
        name = self.owner(container)
        if name is None:
            return self.native.daemon(request)
        if request.method == "POST":
            self.events.append((action, name))
            return httpx.Response(204)
        location, files = request.url.params["path"], self.files.get(name, {})
        if location in files:
            header = stat_header(GO_FILE)
        elif location == "/app" or any(path.startswith(location + "/") for path in files):
            header = stat_header(GO_DIR)
        else:
            return httpx.Response(404)
        return httpx.Response(200, headers={"X-Docker-Container-Path-Stat": header})

    async def docker(self, command, *, timeout=30):
        if command[:2] == ["docker", "ps"]:
            project = next(arg for arg in command if arg.startswith("label=com.docker.compose.project=")).split("=", 2)[2]
            name = self.owner(project)
            if name is None:
                return await self.native.docker(command, timeout=timeout)
            alive = name in self.running or name in self.remaining
            return 0, project + "\n" if alive else "", ""
        name = self.owner(command[3])
        if name is None:
            return await self.native.docker(command, timeout=timeout)
        location, ids, files = command[4], json.loads(command[5]), self.files.get(name, {})
        self.events.append(("read", name, location))
        state = {"location": location, "exists": location in files, "observed_start": "start", "observed_end": "end"}
        if location in files:
            state["base64"] = base64.b64encode(files[location]).decode()
        text = json.dumps(state, sort_keys=True)
        return 0, json.dumps({"state": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                              "location": location, "ids": ids}), ""


EXPLANATION = "At verification start, /app/explanation.txt must exist."
SCORING_LINE = 'echo \'{"reward": 1.0, "answer_ok": 1.0}\''
SETUP_PROGRAM = "mkdir -p /app\necho 42 > /app/answer.txt\n"


def explained_task(tmp_path) -> Path:
    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    (task / "instruction.md").write_text("Write the number 42 to /app/answer.txt. " + EXPLANATION + "\n")
    return task


def setup_probe(**fields) -> dict:
    return {"category": "package_oracles", "case": "answer without explanation", "setup_program": SETUP_PROGRAM,
            "location": "/app/explanation.txt", "capture_point": "verification_start",
            "timing": "The requirement applies at verification start.", "program": CHECKER,
            "requirement": {"episode": None, "path": "instruction.md", "excerpt": EXPLANATION},
            "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": SCORING_LINE}, **fields}


VIOLATED = {"claim": {"mechanism": "credit without explanation", "interpretation": "The required file is absent, so no credit is deserved.",
                      "derivation": {"observations": ["exists"], "minimum": "deserved", "maximum": "deserved", "validity": "violated"}}}


ABSENCE = '''import hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs["submission"])
print(json.dumps({"input_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()}, "observations": {"exists": state["exists"]}, "results": {}}))
'''


def test_measured_violation_without_a_deserved_score_does_not_stop_hack_discovery(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """Completion failure alone is not undeserved reward: the category keeps its next attempt."""
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    absent = {"claim": {"mechanism": "credit without explanation", "interpretation": "The required file is absent.",
                        "derivation": {"observations": ["exists"], "validity": "violated"}}}
    requests = inspector_responses(monkeypatch, [{"probes": [setup_probe(program=ABSENCE)], "applicability": package_applicability()},
                                                 absent, {"probes": []}])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1))
    (assessment,) = result.assessments
    assert (assessment.outcome, assessment.validity, assessment.discrepancy) == ("unknown", "violated", "unknown")
    assert len(requests) == 3 and [item.phase for item in result.attempts] == ["broad", "focused"]
    assert result.categories["package_oracles"] == "unknown"


@pytest.mark.parametrize("claim", [
    {"derivation": {"observations": {"exists": False}, "minimum": "deserved", "validity": "violated"}},
    {"derivation": {"observations": "exists", "minimum": "deserved", "validity": "violated"}},
    {"derivation": {"observations": ["exists"], "minimum": {"field": "deserved"}, "validity": "violated"}},
    {"derivation": {"observations": ["exists"], "maximum": {"field": "deserved"}, "validity": "violated"}},
    {"derivation": {"observations": ["exists"], "minimum": "deserved", "maximum": "deserved"}},
    {"validity": "violated", "derivation": {"observations": ["exists"], "minimum": "deserved", "maximum": "deserved"}},
])
def test_invalid_claim_shape_is_model_output_failure_after_a_completed_check(tmp_path, monkeypatch, credentials, claim, unit_sandboxes):
    task = explained_task(tmp_path)
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    inspector_responses(monkeypatch, [
        {"probes": [setup_probe()], "applicability": {"package_oracles": {
            "scope": "package", "status": "applicable", "facts": {"package_copy": True}, "reason": "The Inspector can inspect the copied package."}}},
        {"claim": {**VIOLATED["claim"], **claim}},
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    report = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert report.attempts[0].status == "model_output_failure"
    assert report.status == "partial" and report.assessments == []
    check, = run.record.checks
    assert check.exit_code == 0 and json.loads(check.output)["observations"] == {"exists": 0}
    assert all(sandbox_record(run, name)["cleanup"]["removed"] for name in run.record.sandboxes)




@pytest.mark.parametrize("fields", [{"requirement": {"excerpt": ["not a string"]}}, {"program": 7},
                                    {"timing": []}, {"setup_program": 7},
                                    {"requirement": [setup_probe()["requirement"]]}, {"scoring": [setup_probe()["scoring"]]}])
def test_invalid_probe_fields_start_no_tool_work(tmp_path, monkeypatch, credentials, fields, unit_sandboxes):
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    inspector_responses(monkeypatch, [{"probes": [setup_probe(**fields)], "applicability": package_applicability()}])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert result.attempts[0].status == "model_output_failure"
    assert run.record.episodes == run.record.checks == []
    assert [sandbox_record(run, name)["purpose"] for name in run.record.sandboxes] == ["workspace"]


SCOPE_QUESTION = "Whether the task intends the explanation itself to be graded; the instruction states it, but no test reads it."


@pytest.mark.parametrize("field, note, counted", [
    ("limits", SCOPE_QUESTION, True),
    ("unresolved", SCOPE_QUESTION, False),
    # nudi does not classify free text: a scope note may use a derivation key's word,
    ("limits", "This single case does not show which other answers are deserved.", True),
    # and a necessary condition moved into limits still counts. The prompt and schema are the only guard.
    ("limits", "Whether the cited requirement applies to this submission remains unestablished.", True),
])
def test_scope_note_in_limits_counts_and_a_necessary_condition_in_unresolved_does_not(tmp_path, monkeypatch, credentials, field, note,
                                                                                      counted, unit_sandboxes):
    """The db-wal-recovery assessment 11 shape: a stated requirement never met, full reward, one out-of-scope question."""
    from nudi import report
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    inspector_responses(monkeypatch, [
        {"probes": [setup_probe(category="accepted_invalid")], "applicability": package_applicability("accepted_invalid")},
        {"claim": {**VIOLATED["claim"], field: [note]}},
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_grader(run, [], categories=["accepted_invalid"], focused_attempts=0))
    (assessment,) = result.assessments
    assert (assessment.outcome, assessment.validity, assessment.discrepancy, assessment.reward) == ("accepted_invalid", "violated", "over", 1.0)
    assert getattr(assessment.claim, field) == [note]
    assert checks.evidenced(assessment) is counted
    assert result.categories == {"accepted_invalid": "evidenced_issue" if counted else "unknown"}
    assert report.finding(assessment)["claim"][field] == [note], "a reader sees each scope note beside the finding"
    shown = checks.CLAIM_SCHEMA["properties"]
    assert "unresolved" in shown["limits"]["description"] and "limits" in shown["unresolved"]["description"]
    assert "`limits`" in (Path(checks.__file__).parent / "prompts" / "inspector.md").read_text()


@pytest.mark.parametrize("response,expected", [
    ({"refusal": "These observations do not support the requested measurement."}, "model_inability"),
    ({"claim": {"mechanism": "bad claim", "derivation": {
        "observations": "exists", "minimum": "deserved", "validity": "violated"}}}, "model_output_failure"),
])
def test_attacker_interpretation_keeps_model_output_failures_separate(tmp_path, monkeypatch, credentials, response, expected):
    from test_attack import scripted_episodes
    monkeypatch.setattr(workflow, "run_episode", scripted_episodes)
    inspector_responses(monkeypatch, [{"locations": []}, response])
    run = new_run(tmp_path, monkeypatch, credentials)
    result = asyncio.run(checks.attack(run, maximum_attempts=1))
    assert result.attempts[0].status == result.conditions["none"] == expected
    assert result.status == "partial" and result.assessments == []


@pytest.mark.parametrize("scoring", [{"episode": None, "path": "tests/test.sh", "excerpt": SCORING_LINE}, None, "omitted"])
def test_inspector_receives_nested_output_schemas_and_accepts_valid_references(tmp_path, monkeypatch, credentials, scoring, unit_sandboxes):
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    probe = setup_probe(scoring=scoring)
    if scoring == "omitted":
        del probe["scoring"]
    requests = inspector_responses(monkeypatch, [{"probes": [probe], "applicability": package_applicability()}, VIOLATED])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert len(requests) == 2
    for request in requests:
        system = request["messages"][0]
        assert system["role"] == "system"
        assert json.dumps(checks.CLAIM_SCHEMA) in system["content"]
        assert "`requirement` and optional `scoring` is one Observation object" in system["content"]
    assert checks.CLAIM_SCHEMA["$defs"]["Derivation"]["required"] == ["observations", "validity"]
    assert "validity" not in checks.CLAIM_SCHEMA["properties"], "validity belongs inside derivation"
    assert checks.CLAIM_SCHEMA["$defs"]["Observation"]["required"] == ["episode", "path", "excerpt"]
    assert Observation.model_json_schema()["required"] == ["episode", "path", "excerpt"]
    assert result.attempts[0].status != "model_output_failure"
    check, = run.record.checks
    assert check.exit_code == 0 and check.requirement.episode is None
    assert check.scoring == (Observation.model_validate(scoring) if isinstance(scoring, dict) else None)
    assessment, = result.assessments
    assert assessment.claim.derivation.validity == "violated" and assessment.claim.check == check.id


@pytest.mark.parametrize("location", ["/tests/test.sh", "/logs/verifier/reward.json", "/solution/file",
                                      "/proc/cpuinfo", "relative.txt", "//tests/test.sh", "/app/../tests/test.sh", "/app/*.txt"])
def test_impossible_native_captures_are_rejected_before_episode_admission(tmp_path, monkeypatch, credentials, location):
    started = []

    async def native(*args, **kwargs):
        started.append(True)

    monkeypatch.setattr(workflow, "run_episode", native)
    run = new_run(tmp_path, monkeypatch, credentials)
    with pytest.raises(ValueError, match="capture"):
        asyncio.run(workflow.run_role_episode(run, "simulator", capture_locations=[location]))
    assert started == [] and run.record.episodes == run.record.events == []


@pytest.mark.parametrize("location", ["/tests/test.sh", "/solution/probe.txt", "/logs/verifier/copied.txt"])
def test_package_captures_keep_authorized_access_and_native_exclusions(tmp_path, monkeypatch, credentials, location):
    Sandboxes(monkeypatch, files={"sandbox-0000": {location: b"copied package bytes\n"}})
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    asyncio.run(checks.package_probe(run, "true\n", location, "verification_start"))
    submission, = run.record.submissions
    assert submission.execution_scope == "package" and submission.location == location
    retained = run.config.output_dir / "sandboxes" / submission.content.episode / submission.content.path
    assert base64.b64decode(json.loads(retained.read_text())["base64"]) == b"copied package bytes\n"
    assert run.record.capture_errors == []

    async def no_lookup(*args):
        raise AssertionError("an excluded native capture reached container lookup")

    monkeypatch.setattr(checks, "main_container", no_lookup)
    with pytest.raises(ValueError, match="capture"):
        asyncio.run(checks.protected_capture(None, "ordinary", tmp_path, location))


def package_applicability(category="package_oracles", *, status="applicable", reason="The Inspector can inspect the copied package.", facts=None):
    return {category: {"scope": "package", "status": status,
                       "facts": {"package_copy": True} if facts is None else facts, "reason": reason}}


def test_native_restriction_does_not_suppress_grounded_package_investigation(tmp_path, monkeypatch, credentials, unit_sandboxes):
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    requests = inspector_responses(monkeypatch, [
        {"probes": [], "applicability": {"package_oracles": {
            "scope": "native", "status": "restricted", "facts": {"terminal": True},
            "reason": "Native terminal access does not establish access to copied tests."}}},
        {"probes": [setup_probe()], "applicability": package_applicability()}, VIOLATED,
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=3))
    assert result.categories == {"package_oracles": "evidenced_issue"}
    assert result.assessments[0].execution_scope == "package"
    evidence = result.applicability_evidence["package_oracles"]
    assert evidence["scope"] == "package" and evidence["status"] == "applicable"
    assert evidence["native_access"]["status"] == "unknown"
    assert len(requests) == 3 and run.record.episodes == []


@pytest.mark.parametrize("inability", [False, True])
def test_focused_grounded_applicability_stops_unsupported_retries_and_reports_unknown(tmp_path, monkeypatch, credentials, inability, unit_sandboxes):
    category = "resource_exhaustion"
    focused = {"probes": [], "applicability": package_applicability(
        category, status="unknown", facts={"file_capture": "verification_start"},
        reason="A file snapshot cannot measure original-runtime CPU or memory contention.")}
    if inability:
        focused["refusal"] = "I cannot measure original-runtime resource contention from file snapshots."
    requests = inspector_responses(monkeypatch, [
        {"probes": [], "applicability": package_applicability(category)}, focused,
        {"probes": []}, {"probes": []},
    ])
    run = new_run(tmp_path, monkeypatch, credentials)
    result = asyncio.run(checks.inspect_hacks(run, categories=[category], focused_attempts=3))
    assert len(requests) == 4
    assert result.status == "partial" and result.categories == {category: "unknown"}
    assert "CPU" in result.applicability[category]
    assert result.attempts[1].status == ("model_inability" if inability else "no_evidenced_issue")
    from nudi import report
    warnings = []
    public = report.inspection("hack", result, warnings)
    assert f"hack inspector category {category} is unknown" in warnings and "CPU" in public["applicability"][category]
    if inability:
        assert any("model_inability" in warning for warning in warnings)


@pytest.mark.parametrize("focused,calls,category,executed", [
    ([{"probes": [setup_probe()], "applicability": package_applicability()}, VIOLATED], 3, "evidenced_issue", True),
    ([{"probes": []}, {"probes": []}], 3, "unknown", False),
    ([{"probes": [], "applicability": package_applicability(status="restricted", reason="No tool reaches the copied grader.")}, {"probes": []}],
     3, "unknown", False),
])
def test_failed_broad_request_leaves_applicability_to_focused_attempts(tmp_path, monkeypatch, credentials, focused, calls, category, executed, unit_sandboxes):
    """A transport failure establishes neither applicability nor a restriction; only a focused determination does."""
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    requests = inspector_responses(monkeypatch, [TimeoutError("broad request timed out")] + focused)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=2))
    assert (result.attempts[0].phase, result.attempts[0].status) == ("broad", "inference_failure")
    assert "timed out" in result.attempts[0].error
    assert len(requests) == calls and result.categories == {"package_oracles": category}
    assert any(sandbox_record(run, name)["purpose"] == "probe" for name in run.record.sandboxes) == executed
    assert run.record.episodes == []
    # The broad failure stays in attempts[0]; a later attempt in the category that ends cleanly recovers from it.
    assert result.status == ("complete" if category == "evidenced_issue" else "partial")


def mixed_package_facts(run) -> dict:
    """The db-wal broad response: correct Inspector facts plus native terminal, CPU and memory facts."""
    native = checks.task_context(run)["native_tools"]
    return {"package_copy": True, "copied_grader": True, **{key: native[key] for key in ("terminal", "cpus", "memory_mb")}}


@pytest.mark.parametrize("invalid", ["changed", "missing", "malformed", "invented", "status", "reason", "scope"])
def test_unsupported_applicability_leaves_configured_focused_attempts(tmp_path, monkeypatch, credentials, invalid, unit_sandboxes):
    """Unsupported output is unknown access, not a restriction: remaining attempts stay available."""
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    grounded = package_applicability()["package_oracles"]
    decision = {"changed": {**grounded, "facts": {**mixed_package_facts(run), "copied_grader": "yes"}}, "malformed": "applicable",
                "invented": {**grounded, "facts": {"invented_tool": True}}, "status": {**grounded, "status": "probable"},
                "reason": {**grounded, "reason": " "}, "scope": {**grounded, "scope": "host"}}.get(invalid)
    response = {"probes": []} if invalid == "missing" else {"probes": [], "applicability": {"package_oracles": decision}}
    requests = inspector_responses(monkeypatch, [response] * 3)
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=2))
    assert [(item.phase, item.number) for item in result.attempts] == [("broad", 0), ("focused", 1), ("focused", 2)]
    assert len(requests) == 3 and run.record.episodes == []
    assert all(sandbox_record(run, name)["purpose"] == "workspace" for name in run.record.sandboxes)
    assert result.applicability_evidence.get("package_oracles", {}).get("status", "unknown") == "unknown"
    assert result.categories == {"package_oracles": "unknown"} and result.status == "partial"


@pytest.mark.parametrize("status", ["applicable", "restricted"])
def test_mixed_applicability_keeps_only_tool_facts(tmp_path, monkeypatch, credentials, status, unit_sandboxes):
    """Cited keys that are not tool facts are ignored; the kept tool facts ground the decision, and a non-tool key cannot justify a restriction."""
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    facts = {**mixed_package_facts(run), "allow_internet": False}
    broad = {"probes": [setup_probe()], "applicability": package_applicability(status=status, facts=facts)}
    requests = inspector_responses(monkeypatch, [broad, VIOLATED])
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert len(requests) == 2 and result.categories == {"package_oracles": "evidenced_issue"}
    evidence = result.applicability_evidence["package_oracles"]
    assert evidence["facts"] == {"package_copy": True, "copied_grader": True}
    assert evidence["status"] == ("applicable" if status == "applicable" else "unknown")
    if status == "restricted":
        assert "no actual capability limit" in evidence["reason"]
    assert result.assessments[0].execution_scope == "package" and run.record.episodes == []


def test_prompt_states_the_applicability_fact_format():
    prompt = " ".join((Path(checks.__file__).parent / "prompts/inspector.md").read_text().split())
    assert "`facts` takes only keys of `inspector_tools` or `native_tools`, with their exact values" in prompt
    assert "experiments and other observations go in `reason`" in prompt
    assert "`status` is exactly one of applicable, restricted or unknown" in prompt


def test_inspector_prompt_states_that_a_reference_path_is_relative():
    """The replay's rejected probes cited the task file as /nudi/package/...; the reference rule names the root."""
    prompt = " ".join(checks.InspectorSession(None, "inspector").messages[0]["content"].split())
    assert ("`path` is relative to the task directory for the original task, without /nudi/package/, "
            "or to the episode's output directory, without /nudi/evidence/episodes/<episode>/.") in prompt


@pytest.mark.parametrize("status, settled, inspection", [("applicable", "no_evidenced_issue", "complete"), ("restricted", "unknown", "partial")])
def test_ungrounded_repeat_keeps_a_grounded_applicable_determination(tmp_path, monkeypatch, credentials, status, settled, inspection,
                                                                     unit_sandboxes):
    """The retained runs' pattern: broad grounds applicability, then a focused reply paraphrases a tool value.
    An ungrounded applicable repeat leaves the grounded determination; an ungrounded change of status still leaves it unknown."""
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    repeat = package_applicability(status=status, facts={**mixed_package_facts(run), "python3": "python3"}, reason="experiment-0000 ran in the copied package.")
    inspector_responses(monkeypatch, [{"probes": [], "applicability": package_applicability(), "completed": []},
                                      {"probes": [], "applicability": repeat}])
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1))
    assert result.applicability_evidence["package_oracles"]["status"] == ("applicable" if status == "applicable" else "unknown")
    assert result.categories == {"package_oracles": settled} and result.status == inspection


def test_unsupported_grader_applicability_keeps_interpretation_feedback_reachable(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """The focused grader attempt still receives the unresolved review and may correct its interpretation."""
    from nudi.records import Check
    run = new_run(tmp_path, monkeypatch, credentials)
    (name,) = pool = ordinary_pool(run, 1)

    async def investigate(run, probe, session):
        run.record.checks.append(Check(id="check-0000", content=run.record.submissions[0].content, ids={},
                                       requirement=Observation(**probe["requirement"]), command=["python3"], exit_code=0,
                                       output="x" * 20000))
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"]), outcome="unknown")

    mock_experiments(monkeypatch, investigate)
    requests = inspector_responses(monkeypatch, [
        {"probes": [review_probe(name)], "applicability": package_applicability("accepted_invalid", facts=mixed_package_facts(run))},
        {"probes": []}])
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=1))
    assert len(requests) == 2 and result.categories == {"accepted_invalid": "unknown"}
    initial = json.loads(next(message["content"] for message in requests[0]["messages"] if message["role"] == "user"))
    (shown,) = initial["ordinary_episodes_read_first"]
    assert "trace" not in shown and "ordinary trace" not in json.dumps(initial), "the model reads trace files with its tools"
    assert shown["retained_trace"] == f"/nudi/evidence/episodes/{name}/trace.txt"
    focused = json.loads(requests[1]["messages"][-1]["content"])
    assert "interpret_experiment" in focused["instruction"]
    review = focused["unresolved_ordinary_reviews"][name]
    assert review["checks"] == [{"id": "check-0000", "requirement": review_probe(name)["requirement"], "scoring": None, "exit_code": 0}]
    assert review["reasons"] and "xxxx" not in json.dumps(review)
    assert len(json.dumps(review)) < 2000, "status lists repair identities, not full check dumps"
    assert all(set(item) == {"phase", "category", "status"} for item in focused["attempts"]) and focused["attempts"]
    assert result.ordinary[name].label == "unknown"


def test_claim_schema_shows_coverage_and_basis_without_nudi_identities():
    schema = checks.CLAIM_SCHEMA
    assert {"coverage", "basis", "derivation", "requirement_support"} <= set(schema["properties"])
    assert {"episode", "check"}.isdisjoint(schema["properties"]) and "episode" not in schema["required"]
    assert {"Coverage", "MetricBasis", "DecisionRule", "Observation"} <= set(schema["$defs"])
    assert "episode" in schema["$defs"]["Observation"]["properties"], "nested evidence identities stay"
    assert json.dumps(schema) in checks.OUTPUT_SCHEMAS


def test_malformed_requirement_reading_names_its_field_path(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi.records import Check, Reading, Support
    run = new_run(tmp_path, monkeypatch, credentials)
    (name,) = pool = ordinary_pool(run, 1)

    async def investigate(run, probe, session):
        requirement = Observation(**probe["requirement"])
        run.record.checks.append(Check(id="check-0000", content=run.record.submissions[0].content, ids={},
                                       requirement=requirement, command=["python3"], exit_code=0, output="{}"))
        support = Support(basis="explicit", sources=[requirement])
        readings = [Reading(requirement=requirement, observations=["exists"], validity="supported", interpretation="read",
                            support=support if index == 0 else None) for index in range(2)]
        claim = Claim(mechanism="review", episode=probe["episode"], requirement_support=support, scoring_support=support,
                      derivation=Derivation(observations=["exists"], validity="supported", requirements=readings))
        return Assessment(claim=claim, outcome="unknown")

    mock_experiments(monkeypatch, investigate)
    inspector_responses(monkeypatch, [
        {"probes": [review_probe(name)], "applicability": package_applicability("accepted_invalid", facts=mixed_package_facts(run))}])
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    assert result.attempts[0].status == "model_output_failure"
    assert "claim.derivation.requirements[1].support" in result.attempts[0].error


@pytest.mark.parametrize("interruption,status", [(asyncio.CancelledError(), "cancelled"),
                                                 (workflow.SpendingCapReached("known cost reached the cap"), "spending_exhausted")])
def test_interruption_after_failed_broad_request_stops_focused_attempts(tmp_path, monkeypatch, credentials, interruption, status, unit_sandboxes):
    requests = []
    async def ask(session, context, schema, **kwargs):
        requests.append(context)
        if len(requests) == 1:
            raise checks.InferenceFailure("broad request timed out")
        raise interruption
    monkeypatch.setattr(inspector.Investigation, "ask", ask)
    run = new_run(tmp_path, monkeypatch, credentials)
    with pytest.raises(asyncio.CancelledError) if status == "cancelled" else contextlib.nullcontext():
        asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=2))
    saved = checks.InspectionResult.model_validate_json((run.config.output_dir / "inspection-hack.json").read_text())
    assert len(requests) == 2 and saved.status == status
    assert [(attempt.phase, attempt.status) for attempt in saved.attempts] == [("broad", "inference_failure"), ("focused", status)]


def test_provider_refusal_is_distinct_from_model_declared_inability(tmp_path, monkeypatch, credentials, unit_sandboxes):
    inspector_responses(monkeypatch, [{"refusal": "Measurement is unavailable from these observations."}])
    run = new_run(tmp_path, monkeypatch, credentials)
    model = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert model.attempts[0].status == "model_inability" and model.categories["package_oracles"] == "unknown"

    async def provider(**request):
        return checks.litellm.ModelResponse(choices=[{"index": 0, "finish_reason": "content_filter",
                                                     "message": {"role": "assistant", "content": None}}])

    monkeypatch.setattr(checks.litellm, "acompletion", provider)
    refused = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert refused.attempts[0].status == "refused" and "content_filter" in refused.attempts[0].error


@pytest.mark.parametrize("surface", ["session", "inspection", "attack"])
def test_explicit_provider_policy_exception_keeps_refusal_and_redacted_cause(tmp_path, monkeypatch, credentials, surface, unit_sandboxes):
    from test_attack import scripted_episodes
    run = new_run(tmp_path, monkeypatch, credentials)
    secret = run.keys["inspector"]
    policy = checks.litellm.ContentPolicyViolationError(
        message="explicit policy block " + secret, model="xai/grok-4.7", llm_provider="xai")

    async def provider(**request):
        raise policy

    monkeypatch.setattr(checks.litellm, "acompletion", provider)
    monkeypatch.setattr(workflow, "run_episode", scripted_episodes)
    if surface == "session":
        with pytest.raises(checks.ProviderRefusal) as caught:
            asyncio.run(checks.InspectorSession(run, "policy").ask("inspect"))
        assert caught.value.__cause__ is policy
        assert secret not in str(caught.value) and "[redacted]" in str(caught.value)
    else:
        result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
                             if surface == "inspection" else checks.attack(run, maximum_attempts=1))
        attempt, = result.attempts
        assert attempt.status == "refused" and result.status == "partial"
        assert "explicit policy block" in attempt.error and secret not in attempt.error
        assert secret not in json.dumps(result.model_dump())


@pytest.mark.parametrize("cause,expected", [("response", "refused"), ("exception", "refused"),
                                          ("model", "model_inability")])
def test_capture_selection_distinguishes_refusal_causes_and_keeps_declared_files(tmp_path, monkeypatch, credentials, cause, expected):
    from nudi import report
    from test_simulation import task_with_artifacts
    task = task_with_artifacts(tmp_path, '["/app/answer.txt"]')
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    secret = run.keys["inspector"]

    async def provider(**request):
        if cause == "exception":
            raise checks.litellm.ContentPolicyViolationError(message="policy " + secret,
                                                            model="xai/grok-4.7", llm_provider="xai")
        choice = {"index": 0, "finish_reason": "stop", "message": {"role": "assistant"}}
        if cause == "response":
            choice["finish_reason"] = "content_filter"
        else:
            choice["message"]["content"] = json.dumps({"refusal": "I cannot select additional files."})
        return checks.litellm.ModelResponse(choices=[choice])

    monkeypatch.setattr(checks.litellm, "acompletion", provider)
    selection = asyncio.run(checks.capture_selection(run))
    assert selection.status == report.collection(run.record)["status"] == expected
    assert [(item.source, item.selected) for item in selection.files] == [("/app/answer.txt", True)]
    assert run.record.episodes == run.record.sandboxes == []
    assert secret not in json.dumps(selection.model_dump())


@pytest.mark.parametrize("unavailable", ["later_time", "runtime"])
def test_unchanged_unavailable_measurements_do_not_execute_again_or_become_negative_evidence(tmp_path, monkeypatch, credentials, unavailable, unit_sandboxes):
    pythons = {} if unavailable == "runtime" else {"python3": "3"}
    Sandboxes(monkeypatch, pythons=pythons)
    no_native_actor(monkeypatch)
    candidate = setup_probe(capture_point="grader_read" if unavailable == "later_time" else "verification_start")
    inspector_responses(monkeypatch, [
        {"probes": [], "applicability": package_applicability()},
        {"probes": [candidate]},
        {"probes": [{**candidate, "case": "renamed", "program": CHECKER + "\n# another checker\n"}]},
        {"probes": [candidate]},
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=3))
    assert len([name for name in run.record.sandboxes if sandbox_record(run, name)["purpose"] == "probe"]) == (0 if unavailable == "runtime" else 1)
    assert result.status == "partial" and result.categories == {"package_oracles": "unknown"}
    assert len(result.assessments) == (0 if unavailable == "runtime" else 1)
    assert all(item.outcome in ("unknown", "unavailable") for item in result.assessments)
    assert all(attempt.status == ("tool_failure" if unavailable == "runtime" else "unobservable") for attempt in result.attempts[1:])


def test_unavailable_measurement_does_not_block_a_new_case_in_the_same_focused_history(tmp_path, monkeypatch, credentials, unit_sandboxes):
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    requests = inspector_responses(monkeypatch, [
        {"probes": [], "applicability": package_applicability()},
        {"probes": [setup_probe(capture_point="grader_read")]},
        {"probes": [setup_probe()]}, VIOLATED,
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=3))
    assert result.categories == {"package_oracles": "evidenced_issue"}
    assert [item.number for item in result.attempts[1:]] == [1, 2]
    assert "grader_read" in json.dumps(requests[2]["messages"])
    assert len(run.record.sandboxes) == 5


def test_failed_checker_keeps_a_genuine_focused_retry_available(tmp_path, monkeypatch, credentials, unit_sandboxes):
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    inspector_responses(monkeypatch, [
        {"probes": [], "applicability": package_applicability("accepted_invalid")},
        {"probes": [setup_probe(category="accepted_invalid", program="raise SystemExit(3)\n")]},
        {"probes": [setup_probe(category="accepted_invalid")]}, VIOLATED,
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_grader(run, [], categories=["accepted_invalid"], focused_attempts=2))
    assert result.categories == {"accepted_invalid": "evidenced_issue"}
    # The first focused attempt completed its category after the failed checker, so the failure is a limit.
    assert [attempt.status for attempt in result.attempts[1:]] == ["no_evidenced_issue", "evidenced_issue"]
    assert any("check failed" in limit for limit in result.limits)
    assert [check.exit_code for check in run.record.checks] == [3, 0]


@pytest.mark.parametrize("focused_attempts, last, settled, status", [
    (2, {"probes": []}, "no_evidenced_issue", "complete"),
    # Broad's earlier completion does not recover a later failure; an empty summary completes nothing.
    (2, {"probes": [], "completed": []}, "unknown", "partial"),
    (1, None, "unknown", "partial"),
])
def test_recovered_focused_failure_keeps_its_error_without_forcing_partial(tmp_path, monkeypatch, credentials, focused_attempts, last,
                                                                           settled, status, unit_sandboxes):
    """A failed attempt that a later attempt in the same category recovers from stays in the attempts and warnings only."""
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    inspector_responses(monkeypatch, [
        {"probes": [], "applicability": package_applicability()},
        {"probes": [setup_probe(program=7)]},
        last,
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=focused_attempts))
    assert [attempt.status for attempt in result.attempts] == ["no_evidenced_issue", "model_output_failure", "no_evidenced_issue"][:1 + focused_attempts]
    assert "Invalid probe" in result.attempts[1].error
    assert result.categories == {"package_oracles": settled} and result.status == status
    from nudi import report
    warnings = []
    report.inspection("hack", result, warnings)
    assert any("model_output_failure" in warning and "Invalid probe" in warning for warning in warnings)


@pytest.mark.parametrize("first, repaired, settled, status", [
    ("invalid", True, "no_evidenced_issue", "complete"),
    ("invalid", False, "unknown", "partial"),
    # A valid claim naming an unmeasured observation is inconclusive until the same receipt is repaired.
    ("inconclusive", True, "no_evidenced_issue", "complete"),
    ("inconclusive", False, "unknown", "partial"),
])
def test_pending_interpretation_mark_follows_the_receipt(tmp_path, monkeypatch, credentials, first, repaired, settled, status,
                                                         unit_sandboxes):
    """A receipt left measured or inconclusive leaves its category unsettled until it is interpreted consistently."""
    Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    observations = "exists" if first == "invalid" else ["missing"]
    repair = {"check": "experiment-0000", "claim": {
        "mechanism": "repaired", "interpretation": "The explanation is absent; the copied grader may still award its minimum.",
        "requirement_support": support(setup_probe()["requirement"]), "scoring_support": support(setup_probe()["scoring"]),
        "derivation": {"observations": ["exists"], "minimum": "deserved", "validity": "violated"}}}
    inspector_responses(monkeypatch, [
        {"probes": [setup_probe()], "applicability": package_applicability()},
        {"claim": {"mechanism": first, "derivation": {"observations": observations, "validity": "violated"}}},
        {"probes": [], "reinterpretations": [repair] if repaired else []},
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1))
    assert [attempt.status for attempt in result.attempts] == ["model_output_failure" if first == "invalid" else "no_evidenced_issue",
                                                               "no_evidenced_issue"]
    assert [item["status"] for item in result.experiments] == ["measured" if first == "invalid" and not repaired else "assessed"]
    assert result.categories == {"package_oracles": settled} and result.status == status


def no_native_actor(monkeypatch):
    async def native(config, queue=None, **work):
        raise AssertionError(f"native actor episode dispatched: {config.output_dir.name}")
    monkeypatch.setattr(workflow, "run_episode", native)


def sandbox_record(run, name) -> dict:
    return json.loads((run.config.output_dir / "sandboxes" / name / "sandbox.json").read_text())


@pytest.mark.parametrize("intervention,expected_reward", [("replacement", 0), ("extra_helper", 1), ("reward_precedence", 1)])
def test_original_verifier_upload_overwrites_replacement_and_preserves_overlay_and_reward_precedence(tmp_path, monkeypatch, credentials, intervention, expected_reward):
    """Run Harbor's real verifier against a local file-backed container double and fixture scripts."""
    task = explained_task(tmp_path)
    original_grader = ('#!/bin/sh\ntests=$(dirname "$0")\nif [ -f "$tests/helper.txt" ]; then\n'
                       '  cat "$tests/helper.txt" > "$tests/../logs/verifier/reward.txt"\n'
                       'else\n  cat "$tests/../app/answer.txt" > "$tests/../logs/verifier/reward.txt"\nfi\n'
                       'echo original-grader\n')
    replacement = '#!/bin/sh\ntests=$(dirname "$0")\nlogs="$tests/../logs"\nprintf 1 > "$logs/verifier/reward.txt"\necho replacement-grader\n'
    (task / "tests/test.sh").write_text(original_grader)
    original_digest = tree_digest(task)
    sandboxes = Sandboxes(monkeypatch)

    class FilesystemEnvironment(SandboxEnvironment):
        async def start(self, force_build):
            await super().start(force_build)
            mount = tmp_path / "containers" / self.name / "logs/verifier"
            mount.parent.mkdir(parents=True)
            mount.symlink_to(self.trial_paths.verifier_dir, target_is_directory=True)

        def local(self, path):
            if path == "/logs/verifier":
                return self.trial_paths.verifier_dir
            return tmp_path / "containers" / self.name / path.lstrip("/")

        async def upload_dir(self, source_dir, target_dir):
            await super().upload_dir(source_dir, target_dir)
            destination = self.local(target_dir)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source_dir, destination, dirs_exist_ok=True)
            self.refresh()

        def refresh(self):
            root = tmp_path / "containers" / self.name
            self.owner.files[self.name] = {"/" + str(file.relative_to(root)): file.read_bytes()
                                           for file in root.rglob("*") if file.is_file()}
            self.verifier_outputs = {file.name: file.read_bytes() for file in self.trial_paths.verifier_dir.iterdir() if file.is_file()}

        async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
            args = shlex.split(command)
            if len(args) > 3 and args[1] == sandbox.RUNNER and args[3:] == ["sh", sandbox.SETUP]:
                source = self.uploads[sandbox.SETUP].decode()
            elif "/tests/test.sh" in command:
                source = command
            else:
                return await super().exec(command, cwd, env, timeout_sec, user)
            self.event("exec", command, user, timeout_sec)
            mapping = {path: str(self.local(path)) for path in ("/logs/verifier", "/tests", "/app")}
            for path, local in mapping.items():
                source = source.replace(path, local)
            environment = {**os.environ, **{key: mapping.get(value, value) for key, value in (env or {}).items()}}
            done = subprocess.run(["sh", "-c", source], env=environment, capture_output=True, timeout=5)
            self.refresh()
            return ExecResult(stdout=done.stdout.decode(), stderr=done.stderr.decode(), return_code=done.returncode)

    def create(**config):
        environment = FilesystemEnvironment(sandboxes, **config)
        sandboxes.environments[environment.name] = environment
        return environment

    monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(create))
    no_native_actor(monkeypatch)
    setup = "mkdir -p /app\nprintf 0 > /app/answer.txt\n"
    if intervention == "replacement":
        setup += "cat > /tests/test.sh <<'SH'\n" + replacement + "SH\n"
    elif intervention == "extra_helper":
        setup += "printf 1 > /tests/helper.txt\n"
    else:
        setup += 'printf \'{"reward": 1}\' > /logs/verifier/reward.json\n'
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    name = asyncio.run(checks.package_probe(run, setup, "/tests/test.sh", "verification_start"))
    record, environment = sandbox_record(run, name), sandboxes.environments[name]
    assert record["rewards"] == {"reward": expected_reward}
    assert "original-grader" in record["grader"]["test_stdout"]
    assert environment.local("/tests/test.sh").read_text() == original_grader
    assert environment.local("/app/answer.txt").read_text() == "0", "the submission is still invalid"
    submission, = run.record.submissions
    state = json.loads((run.config.output_dir / "sandboxes" / name / submission.content.path).read_text())
    assert base64.b64decode(state["base64"]).decode() == (replacement if intervention == "replacement" else original_grader)
    if intervention == "extra_helper":
        assert environment.local("/tests/helper.txt").read_text() == "1", "normal upload is an overlay"
    if intervention == "reward_precedence":
        assert environment.verifier_outputs["reward.txt"] == b"0"
        assert json.loads(environment.verifier_outputs["reward.json"]) == {"reward": 1}
    assert tree_digest(task) == original_digest and record["cleanup"]["removed"] is True
    assert run.record.episodes == []


def test_targeted_probe_runs_in_package_sandboxes_and_dispatches_the_copied_grader(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """Setup, independent capture and the copied grader run in one sandbox, closed before a
    fresh checker sandbox starts. No native actor, Trial, agent or actor timer is involved."""
    task = explained_task(tmp_path)
    original = tree_digest(task)
    sandboxes = Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    script = InspectorScript([VIOLATED])

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return run, await checks.investigate(run, setup_probe(), checks.InspectorSession(run, "scoped-interpretation"))

    run, assessment = asyncio.run(main())
    assert run.record.episodes == [] and run.record.probe_episodes == []
    assert run.record.sandboxes == ["sandbox-0000", "sandbox-0001"]
    probe, check = (sandbox_record(run, name) for name in run.record.sandboxes)
    assert (probe["purpose"], check["purpose"]) == ("probe", "check")
    assert probe["execution_scope"] == check["execution_scope"] == "package"
    assert probe["task_digest"] == check["task_digest"] == original == tree_digest(task)

    for name, environment in sandboxes.environments.items():
        config = environment.config
        assert config["type"] == EnvironmentType.DOCKER
        assert not Path(config["environment_dir"]).resolve().is_relative_to(task.resolve())
        assert (config["task_env_config"].cpus, config["task_env_config"].memory_mb) == (1, 512)
        mount, = config["mounts"]
        assert (mount["type"], mount["target"]) == ("bind", "/logs/verifier")
        assert not Path(mount["source"]).resolve().is_relative_to(run.config.output_dir.resolve())
        assert sandbox_record(run, name)["session_id"] == config["session_id"]
    assert len({item.session_id for item in sandboxes.environments.values()}) == 2

    steps = [(event[0], event[1], event[2]) for event in sandboxes.events if event[0] in ("start", "stop", "upload_dir", "upload_file")]
    assert steps == [
        ("start", "sandbox-0000", False), ("upload_dir", "sandbox-0000", sandbox.PACKAGE),
        ("upload_file", "sandbox-0000", sandbox.RUNNER), ("upload_dir", "sandbox-0000", "/tests"),
        ("upload_file", "sandbox-0000", sandbox.SETUP), ("upload_dir", "sandbox-0000", "/tests"), ("stop", "sandbox-0000", True),
        ("start", "sandbox-0001", False), ("upload_dir", "sandbox-0001", sandbox.PACKAGE),
        ("upload_file", "sandbox-0001", sandbox.RUNNER), ("upload_file", "sandbox-0001", sandbox.CHECK_PROGRAM),
        ("upload_file", "sandbox-0001", sandbox.CHECK_INPUTS), ("stop", "sandbox-0001", True)]
    uploads = sandboxes.environments["sandbox-0000"].uploads
    assert uploads[sandbox.SETUP] == SETUP_PROGRAM.encode()
    assert probe["files"][sandbox.SETUP] == hashlib.sha256(SETUP_PROGRAM.encode()).hexdigest()
    order = [event[0] for event in sandboxes.events if event[1] == "sandbox-0000"]
    setup = next(index for index, event in enumerate(sandboxes.events) if event[0] == "exec" and sandbox.SETUP in event[2])
    read = sandboxes.events.index(("read", "sandbox-0000", "/app/explanation.txt"))
    graded = next(index for index, event in enumerate(sandboxes.events) if event[0] == "exec" and "test.sh" in event[2]
                  and not event[2].startswith("chmod"))
    reuploaded = max(index for index, event in enumerate(sandboxes.events)
                     if event[:3] == ("upload_dir", "sandbox-0000", "/tests"))
    assert setup < read < reuploaded < graded, "capture precedes original-test re-upload and copied grading"
    assert "pause" in order and "unpause" in order
    grader = sandboxes.events[graded]
    assert grader[3] is None and grader[4] is None, "the copied grader runs as the verifier user, under no actor timer"
    assert probe["rewards"] == {"reward": 1.0}
    assert probe["grader"]["skip_tests_upload"] is False and probe["grader"]["timeout_sec"] == 60.0
    assert probe["grader"]["test_stdout"] == "graded copy\n"
    assert all(item["removed"] is True for item in (probe["cleanup"], check["cleanup"]))
    assert check["files"][sandbox.CHECK_PROGRAM] == hashlib.sha256(CHECKER.encode()).hexdigest()

    assert assessment.claim.episode == "sandbox-0000" and assessment.execution_scope == "package"
    assert assessment.ids == {"sandbox": "sandbox-0000", "session_id": probe["session_id"]}
    assert assessment.outcome == "accepted_invalid", assessment.reasons
    assert assessment.check.sandbox == "sandbox-0001" and assessment.check.submission.execution_scope == "package"
    assert "trial_id" not in assessment.check.ids
    assert {call.role for call in run.record.calls} == {"inspector"}


def test_native_package_grader_capture_precedes_original_upload(tmp_path, monkeypatch, docker_env):
    """Capture replacement bytes, then execute unchanged host tests in actual Docker."""
    task = explained_task(tmp_path)
    original_grader = ("#!/bin/sh\npython3 - <<'PY'\nimport hashlib,json\nfrom pathlib import Path\n"
                       "print('NUDI_ORIGINAL_GRADER '+json.dumps({'sha256': hashlib.sha256("
                       "Path('/tests/test.sh').read_bytes()).hexdigest(), 'answer': "
                       "Path('/app/answer.txt').read_text()}))\nPY\n"
                       "printf '0\\n' > /logs/verifier/reward.txt\n")
    replacement = "#!/bin/sh\necho NUDI_REPLACEMENT_GRADER\nprintf '1\\n' > /logs/verifier/reward.txt\n"
    (task / "tests/test.sh").write_text(original_grader)
    original_digest = tree_digest(task)
    original_sha256 = hashlib.sha256(original_grader.encode()).hexdigest()
    setup = ("mkdir -p /app\nprintf 0 > /app/answer.txt\n"
             "python3 - <<'PY'\nimport base64\nfrom pathlib import Path\n"
             "print('NUDI_COPIED_GRADER '+base64.b64encode(Path('/tests/test.sh').read_bytes()).decode())\nPY\n"
             "cat > /tests/test.sh <<'SH'\n" + replacement + "SH\n")
    no_native_actor(monkeypatch)

    async def main():
        run = workflow.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run"), frozenset())
        name = await checks.package_probe(run, setup, "/tests/test.sh", "verification_start")
        return run, name

    run, name = asyncio.run(main())
    record = sandbox_record(run, name)
    print("NUDI_GRADER_CAPTURE " + json.dumps({"sandbox": record,
          "submissions": [item.model_dump() for item in run.record.submissions],
          "capture_errors": [item.model_dump() for item in run.record.capture_errors],
          "host_task_sha256": tree_digest(task), "original_grader_sha256": original_sha256,
          "replacement_sha256": hashlib.sha256(replacement.encode()).hexdigest()}, sort_keys=True))
    for kind in ("container", "network"):
        result = subprocess.run(["docker", kind, "ls", "-q", *(["-a"] if kind == "container" else []),
                                 "--filter", f"label=com.docker.compose.project={record['session_id']}"],
                                capture_output=True, text=True, check=True)
        print("NUDI_CLEANUP " + json.dumps({"project": record["session_id"], "kind": kind,
                                               "remaining": result.stdout.split()}))
        assert not result.stdout.strip(), result.stdout
    submission, = run.record.submissions
    retained = run.config.output_dir / "sandboxes" / name / submission.content.path
    state = json.loads(retained.read_text())
    assert base64.b64decode(state["base64"]) == replacement.encode()
    assert hashlib.sha256(retained.read_bytes()).hexdigest() == submission.content.sha256
    assert submission.execution_scope == record["execution_scope"] == "package"
    assert submission.location == state["location"] == "/tests/test.sh"
    assert submission.capture_point == "verification_start" and submission.exit_code == 0
    assert submission.ids == record["ids"] and submission.content.episode == name
    assert submission.path_resolution and submission.observation_windows
    assert record["task_digest"] == record["copy_digest"] == original_digest == tree_digest(task)
    assert record["commands"][-1]["exit_code"] == 0
    assert record["commands"][-1]["output"] == "NUDI_COPIED_GRADER " + base64.b64encode(original_grader.encode()).decode() + "\n"
    assert record["grader"]["skip_tests_upload"] is False and record["rewards"] == {"reward": 0}
    executed = record["grader"]["test_stdout"].strip().removeprefix("NUDI_ORIGINAL_GRADER ")
    assert json.loads(executed) == {"sha256": original_sha256, "answer": "0"}
    assert (task / "tests/test.sh").read_bytes() == original_grader.encode()
    assert record["cleanup"]["removed"] is True and record["errors"] == []
    assert run.record.episodes == run.record.probe_episodes == run.record.calls == run.record.capture_errors == []

    async def no_lookup(*args, **kwargs):
        raise AssertionError("excluded native capture reached container lookup")

    monkeypatch.setattr(checks, "main_container", no_lookup)
    monkeypatch.setattr(checks, "project_container", no_lookup)
    with pytest.raises(ValueError, match="before native episode") as admission:
        asyncio.run(workflow.run_role_episode(run, "simulator", capture_locations=["/tests/test.sh"]))
    with pytest.raises(ValueError, match="capture") as capture:
        asyncio.run(checks.protected_capture(None, "ordinary", tmp_path, "/tests/test.sh"))
    assert run.record.episodes == run.record.events == [] and run.record.sandboxes == [name]
    print("NUDI_NATIVE_REJECTION " + json.dumps({"admission": str(admission.value), "capture": str(capture.value)}))


def test_native_package_probe_large_checker_and_later_service_writes(tmp_path, monkeypatch, docker_env):
    """Real copied grading and a file-uploaded checker outlive a tiny actor timeout."""
    task = explained_task(tmp_path)
    config = task / "task.toml"
    config.write_text(config.read_text().replace("timeout_sec = 20.0", "timeout_sec = 0.001"))
    grader = task / "tests/test.sh"
    grader.write_text("#!/bin/bash\ntouch /app/service-go\n"
                      "for i in $(seq 1 100); do [ -f /app/service-done ] && break; sleep 0.05; done\n"
                      "[ \"$(cat /app/service-done 2>/dev/null)\" = 262144 ] || exit 9\n"
                      "echo later-service-ok\n" + grader.read_text())
    original = tree_digest(task)
    service = ("import os,time; from pathlib import Path; "
               "p=Path('/app/service-go');\nwhile not p.exists(): time.sleep(.02)\n"
               "for i in range(4): os.write(1,b'x'*65536)\n"
               "Path('/app/service-done').write_text('262144')\n")
    setup = ("mkdir -p /app\npython3 - <<'PY'\nimport subprocess,time\nfrom pathlib import Path\n"
             f"subprocess.Popen(['python3','-c',{service!r}])\n"
             "Path('/app/submission.bin').write_bytes(b'A'*350000)\n"
             "Path('/app/answer.txt').write_text('42\\n')\ntime.sleep(.3)\nprint('setup-completed')\nPY\n")
    resources = []
    create = EnvironmentFactory.create_environment

    def observe(**kwargs):
        environment = create(**kwargs)
        execute = environment.exec
        observed = False

        async def execute_observed(*args, **fields):
            nonlocal observed
            if not observed:
                container = await checks.project_container(environment.session_id)
                status, output, error = await trusted_host_command(
                    ["docker", "inspect", "--format", "{{json .HostConfig}}", container])
                assert status == 0, error
                host = json.loads(output)
                assert host["NanoCpus"] == 1000000000 and host["Memory"] == 512 * 1024 * 1024
                resources.append({"project": environment.session_id, "container": container,
                                  "NanoCpus": host["NanoCpus"], "Memory": host["Memory"]})
                observed = True
            return await execute(*args, **fields)

        environment.exec = execute_observed
        return environment

    monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(observe))
    no_native_actor(monkeypatch)

    async def main():
        run = workflow.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run"), frozenset())
        name = await checks.package_probe(run, setup, "/app/submission.bin", "verification_start")
        submission, = run.record.submissions
        check = await checks.check_submission(run, submission,
            Observation(episode=None, path="instruction.md", excerpt=EXPLANATION),
            Observation(episode=None, path="tests/test.sh", excerpt="echo later-service-ok"),
            CHECKER, capture_point="verification_start", timing="Observe this package at verification start.")
        return run, name, submission, check

    run, name, submission, check = asyncio.run(main())
    probe, checker = (sandbox_record(run, item) for item in run.record.sandboxes)
    assert run.record.episodes == run.record.probe_episodes == []
    assert run.record.calls == []
    assert probe["purpose"] == "probe" and checker["purpose"] == "check"
    assert probe["session_id"] != checker["session_id"]
    assert probe["task_digest"] == checker["task_digest"] == original == tree_digest(task)
    assert probe["copy_digest"] == checker["copy_digest"] == original
    assert probe["commands"][-1]["output"] == "setup-completed\n"
    assert probe["commands"][-1]["exit_code"] == 0
    assert probe["rewards"]["reward"] == 1 and "later-service-ok" in probe["grader"]["test_stdout"]
    assert check.exit_code == 0 and check.sandbox == checker["name"]
    from nudi.assessment import Evidence
    evidence = Evidence(run.config.output_dir, name)
    texts = {key: evidence.file(content.episode, content.path).read_text() for key, content in check.inputs.items()}
    encoded = json.dumps(texts).encode()
    assert len(encoded) > 444044
    assert checker["files"][sandbox.CHECK_INPUTS] == hashlib.sha256(encoded).hexdigest()
    assert checker["commands"][-1]["argv"] == ["python3", sandbox.CHECK_PROGRAM]
    assert checker["commands"][-1]["stdin"] == sandbox.CHECK_INPUTS
    assert json.loads(check.output)["input_sha256"] == {key: hashlib.sha256(value.encode()).hexdigest() for key, value in texts.items()}
    assert all(record["execution_scope"] == "package" and record["cleanup"]["removed"] is True for record in (probe, checker))
    for resource in resources:
        for kind in ("container", "network"):
            result = subprocess.run(["docker", kind, "ls", "-q", *(["-a"] if kind == "container" else []),
                                     "--filter", f"label=com.docker.compose.project={resource['project']}"], capture_output=True, text=True, check=True)
            assert not result.stdout.strip(), result.stdout
    print("NUDI_PACKAGE_PROBE " + json.dumps({"input_bytes": len(encoded), "input_sha256": hashlib.sha256(encoded).hexdigest(),
          "resources": resources, "sandboxes": [probe, checker]}, sort_keys=True))


@pytest.mark.parametrize("phase", ["startup", "exec"])
def test_native_sandbox_cancellation_removes_owned_resources(tmp_path, monkeypatch, docker_env, phase):
    """Cancel real Compose startup health waiting or a running generated setup command."""
    task = explained_task(tmp_path)
    if phase == "startup":
        config = task / "task.toml"
        config.write_text(config.read_text().replace('docker_image = "python:3.12-slim"\n', ""))
        (task / "environment").mkdir(exist_ok=True)
        (task / "environment/Dockerfile").write_text(
            "FROM python:3.12-slim\nHEALTHCHECK --interval=1s --timeout=1s --start-period=120s CMD exit 1\n")
    original = tree_digest(task)
    processes, observations, images = [], [], []
    create = EnvironmentFactory.create_environment

    def observe(**kwargs):
        if phase == "startup":
            kwargs["environment_name"] = "nudi-cancel-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8]
        environment = create(**kwargs)
        if phase == "startup":
            images.append(environment._main_image_name)
        collect = environment._collect_buffered_output
        stop = environment.stop

        async def collect_observed(process, **fields):
            processes.append(process)
            return await collect(process, **fields)

        async def stop_observed(*args, **fields):
            assert all(process.returncode is not None for process in processes), "startup/exec CLI child still alive before removal"
            return await stop(*args, **fields)

        environment._collect_buffered_output = collect_observed
        environment.stop = stop_observed
        return environment

    monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(observe))

    async def main():
        run = workflow.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run"), frozenset())
        running = asyncio.create_task(checks.package_probe(
            run, "mkdir -p /app; echo running > /app/exec-started; sleep 120", "/app/answer.txt", "verification_start"))
        try:
            async def wait_for_phase():
                while True:
                    if running.done():
                        pytest.fail(f"package probe ended before {phase}: {running!r}")
                    if run.record.sandboxes:
                        record = sandbox_record(run, run.record.sandboxes[0])
                        status, output, _ = await trusted_host_command(
                            ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={record['session_id']}"])
                        if not status and output.strip():
                            container, = output.split()
                            command = (["docker", "inspect", "--format", "{{.State.Health.Status}}", container]
                                       if phase == "startup" else ["docker", "exec", container, "cat", "/app/exec-started"])
                            status, observed, _ = await trusted_host_command(command)
                            if status == 0 and observed.strip() == ("starting" if phase == "startup" else "running"):
                                assert any(process.returncode is None for process in processes)
                                observations.append({"phase": phase, "container": container, "observed": observed.strip(),
                                                     "live_cli_pids": [p.pid for p in processes if p.returncode is None]})
                                return
                    await asyncio.sleep(.1)
            await asyncio.wait_for(wait_for_phase(), 45)
            assert running.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(running, 20)
        finally:
            if not running.done():
                running.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await running
        record = sandbox_record(run, run.record.sandboxes[0])
        assert record["cancelled"] and record["cleanup"]["removed"] is True
        assert all(process.returncode is not None for process in processes)
        for kind in ("container", "network"):
            status, output, error = await trusted_host_command(["docker", kind, "ls", "-q", *(["-a"] if kind == "container" else []),
                "--filter", f"label=com.docker.compose.project={record['session_id']}"])
            assert status == 0 and not output.strip(), (output, error)
        assert tree_digest(task) == original
        for image in images:
            status, output, error = await trusted_host_command(["docker", "image", "inspect", image])
            assert status != 0 and "No such image" in error, (output, error)
            observations.append({"test_image_absent": image, "error": error.strip()})
        print("NUDI_CANCEL " + json.dumps({"observations": observations, "sandbox": record,
              "cli_children": [{"pid": p.pid, "returncode": p.returncode} for p in processes]}, sort_keys=True))
    asyncio.run(main())


@pytest.mark.parametrize("corruption", ["program", "missing_command", "command", "output", "exit_code"])
def test_retained_native_submission_is_checked_in_a_fresh_sandbox_with_hashed_inputs(tmp_path, monkeypatch, credentials, corruption):
    """A retained ordinary capture is checked without another actor or grader episode, from
    uploaded program and input files; a tampered input or program hash is ungrounded."""
    from nudi.records import Content, EpisodeResult, Submission

    task = explained_task(tmp_path)
    sandboxes = Sandboxes(monkeypatch, pythons={"python3": "2", "python": "3"})
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)
    directory = run.config.output_dir / "episodes" / "0000-simulator"
    (directory / "nudi-evidence").mkdir(parents=True)
    state = json.dumps({"exists": False, "location": "/app/explanation.txt", "observed_end": "end", "observed_start": "start"})
    (directory / "nudi-evidence" / "state.json").write_text(state)
    ids = {"trial_id": "native-trial", "trial_name": "trial", "task_checksum": "sum"}
    content = Content(episode="0000-simulator", path="nudi-evidence/state.json", sha256=hashlib.sha256(state.encode()).hexdigest())
    receipt = json.dumps({"state": state, "sha256": content.sha256, "location": "/app/explanation.txt", "ids": ids})
    submission = Submission(content=content, ids=ids, location="/app/explanation.txt", capture_point="verification_start",
                            command=[sys.executable, "-c", checks.CAPTURE_PROGRAM], program=checks.CAPTURE_PROGRAM,
                            exit_code=0, output=receipt)
    result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(task), task_digest=tree_digest(task),
                           model="ordinary", reasoning_effort=None, versions={}, ids=ids, rewards={"reward": 1.0},
                           artifacts={"nudi_evidence": "nudi-evidence"})
    (directory / "episode.json").write_text(result.model_dump_json())
    run.record.episodes.append("0000-simulator")
    run.record.submissions.append(submission)
    run.save()
    requirement = Observation(episode=None, path="instruction.md", excerpt=EXPLANATION)
    scoring = Observation(episode=None, path="tests/test.sh", excerpt=SCORING_LINE)

    check = asyncio.run(checks.check_submission(run, submission, requirement, scoring, CHECKER,
                                                capture_point="verification_start", timing="It applies at verification start."))
    assert run.record.episodes == ["0000-simulator"] and run.record.sandboxes == ["sandbox-0000"]
    record = sandbox_record(run, "sandbox-0000")
    assert (record["purpose"], record["rewards"]) == ("check", {})
    assert not any("test.sh" in event[2] for event in sandboxes.events if event[0] == "exec"), "no grader runs for a retained check"
    probes = [event[2] for event in sandboxes.events if event[0] == "exec" and checks.VERSION_PROBE in event[2]]
    assert [shlex.split(command)[0] for command in probes] == ["python3", "python"]
    assert check.command == ["python", sandbox.CHECK_PROGRAM] and check.exit_code == 0
    assert check.sandbox == "sandbox-0000" and check.ids == ids
    inputs = sandboxes.environments["sandbox-0000"].uploads[sandbox.CHECK_INPUTS]
    assert json.loads(inputs)["submission"] == state
    assert record["files"][sandbox.CHECK_INPUTS] == hashlib.sha256(inputs).hexdigest()
    claim = Claim(mechanism="omitted explanation", episode="0000-simulator", check=check.id,
                  interpretation="The required file is absent, so no credit is deserved.",
                  derivation=Derivation(observations=["exists"], minimum="deserved", maximum="deserved", validity="violated"))
    assessment = assess(claim, run.config.output_dir)
    assert (assessment.outcome, assessment.execution_scope) == ("accepted_invalid", "native")

    run_path = run.config.output_dir / "run.json"
    sandbox_path = run.config.output_dir / "sandboxes" / "sandbox-0000" / "sandbox.json"
    stored = json.loads(run_path.read_text())
    record = json.loads(sandbox_path.read_text())
    if corruption == "program":
        stored["checks"][0]["program"] = CHECKER + "\n# changed after execution\n"
    elif corruption == "missing_command":
        record["commands"].pop()
    elif corruption == "command":
        stored["checks"][0]["command"] = ["python", "/nudi/check/other.py"]
    elif corruption == "output":
        record["commands"][-1]["output"] = "different retained output"
    elif corruption == "exit_code":
        record["commands"][-1]["exit_code"] = 1
    run_path.write_text(json.dumps(stored))
    sandbox_path.write_text(json.dumps(record))
    tampered = assess(claim, run.config.output_dir)
    assert tampered.outcome == "ungrounded" and "sandbox-0000" in tampered.reasons[0]


def test_sandbox_failure_and_cancellation_stop_it_and_keep_partial_records(tmp_path, monkeypatch, credentials):
    task = explained_task(tmp_path)
    sandboxes = Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task)

    sandboxes.fail[("start", "sandbox-0000")] = RuntimeError("image build failed")
    with pytest.raises(RuntimeError, match="image build failed"):
        asyncio.run(checks.investigate(run, setup_probe(), None))
    failed = sandbox_record(run, "sandbox-0000")
    assert failed["errors"][0]["message"] == "image build failed" and failed["cleanup"]["removed"] is True
    assert ("stop", "sandbox-0000", True) in sandboxes.events

    async def cancel():
        sandboxes.blocked["sandbox-0001"] = asyncio.Event()
        running = asyncio.create_task(checks.investigate(run, setup_probe(), None))
        while not any(event[0] == "exec" and event[1] == "sandbox-0001" for event in sandboxes.events):
            await asyncio.sleep(0.01)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    asyncio.run(cancel())
    cancelled = sandbox_record(run, "sandbox-0001")
    assert cancelled["cancelled"] is True and cancelled["cleanup"]["removed"] is True
    assert cancelled["commands"][-1]["argv"] == ["sh", sandbox.SETUP] and cancelled["commands"][-1]["exit_code"] is None
    assert ("stop", "sandbox-0001", True) in sandboxes.events and sandboxes.running == set()

    sandboxes.remaining.add("sandbox-0002")
    sandboxes.rewards["sandbox-0002"] = None
    asyncio.run(checks.investigate(run, setup_probe(capture_point="grader_read"), None))
    leftover = sandbox_record(run, "sandbox-0002")
    assert leftover["cleanup"]["removed"] is False and leftover["cleanup"]["remaining"]
    assert any("sandbox-0002" in warning and "remain" in warning for warning in run.record.warnings)
    assert leftover["rewards"] == {} and leftover["errors"][0]["type"] == "RewardFileNotFoundError"
    assert run.record.episodes == [] and tree_digest(task) == tree_digest(explained_task(tmp_path / "again"))


def test_spending_cap_starts_no_sandbox_and_instruction_probes_never_execute(tmp_path, monkeypatch, credentials):
    task = explained_task(tmp_path)
    sandboxes = Sandboxes(monkeypatch)
    no_native_actor(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=task, spending_cap=1.0)
    with pytest.raises(checks.ModelOutputFailure, match="setup_program"):
        asyncio.run(checks.investigate(run, {**setup_probe(), "setup_program": None, "instruction": "Act as the task agent."}, None))
    run.record.known_cost = 1.0
    with pytest.raises(workflow.SpendingCapReached):
        asyncio.run(checks.investigate(run, setup_probe(), None))
    assert sandboxes.environments == {} and run.record.sandboxes == [] and run.record.episodes == []


def test_missing_python3_skips_dynamic_setup_and_preserves_evidence_and_native_roles(tmp_path, monkeypatch, credentials, unit_sandboxes):
    sandboxes = Sandboxes(monkeypatch, pythons={"python3": "2", "python": "2"})
    run = new_run(tmp_path, monkeypatch, credentials)
    retained = retained_native_submission(run, "{}")
    original = tree_digest(run.config.task_dir)

    async def static_inspection(*args, **kwargs):
        raise AssertionError("an unsupported workspace must offer no agent tools")

    monkeypatch.setattr(inspector.Investigation, "ask", static_inspection)
    inspection = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    assert inspection.status == "partial" and inspection.attempts[0].status == "tool_failure"
    assert inspection.categories == {"package_oracles": "unknown"} and inspection.assessments == []
    assert "python3" in inspection.attempts[0].error
    name, = run.record.sandboxes
    record = sandbox_record(run, name)
    assert any(error["type"] == "UnsupportedRuntime" for error in record["errors"])
    assert record["grader"] is None and record["rewards"] == {}
    assert not any(sandbox.SETUP in entry["argv"] for entry in record["commands"])
    assert sandbox.SETUP not in sandboxes.environments[name].uploads
    assert record["cleanup"]["removed"] is True
    assert (run.config.output_dir / "episodes" / retained.content.episode / retained.content.path).read_text() == "{}"
    roles = []

    async def native(config, queue, **work):
        roles.append(config.output_dir.name.rsplit("-", 1)[1])
        return SimpleNamespace()

    monkeypatch.setattr(workflow, "run_episode", native)
    asyncio.run(workflow.run_role_episode(run, "simulator"))
    asyncio.run(workflow.run_role_episode(run, "attacker"))
    assert roles == ["simulator", "attacker"] and tree_digest(run.config.task_dir) == original


@pytest.mark.parametrize("next_kind", ["check", "simulator", "attacker"])
def test_unverified_sandbox_cleanup_blocks_later_container_admission(tmp_path, monkeypatch, credentials, next_kind):
    """A sandbox whose containers remain cannot overlap a later checker or native episode."""
    from nudi.records import InfrastructureAbort

    sandboxes = Sandboxes(monkeypatch)
    sandboxes.remaining.add("sandbox-0000")
    run = new_run(tmp_path, monkeypatch, credentials)
    native = []

    async def native_episode(*args, **kwargs):
        native.append(args[0].output_dir.name)
        return SimpleNamespace()

    monkeypatch.setattr(workflow, "run_episode", native_episode)

    async def main():
        async with sandbox.sandbox(run, "probe"):
            pass
        blocked = None
        try:
            if next_kind == "check":
                async with sandbox.sandbox(run, "check"):
                    pass
            else:
                await workflow.run_role_episode(run, next_kind)
        except InfrastructureAbort as error:
            blocked = str(error)
        assert blocked and "sandbox-0000" in blocked, "unverified cleanup admitted another container"

    asyncio.run(main())
    assert sandbox_record(run, "sandbox-0000")["cleanup"]["removed"] is False
    assert run.record.sandboxes == ["sandbox-0000"] and run.record.episodes == []
    assert native == [] and len(sandboxes.environments) == 1


def test_sandbox_runner_stops_excess_output_while_the_command_is_still_running(tmp_path):
    """A producer that never exits must be stopped after the output quota, without a growing log."""
    runner = tmp_path / "runner.sh"
    runner.write_text(sandbox.RUNNER_SCRIPT)
    producer = tmp_path / "producer.py"
    producer.write_text("import os, time\nwhile True:\n os.write(1, b'x' * 4096)\n time.sleep(0.01)\n")
    process = subprocess.Popen([sys.executable, str(runner), "/dev/null", sys.executable, str(producer)],
                               cwd=tmp_path, env={**os.environ, "TMPDIR": str(tmp_path)},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    completed = False
    try:
        output, error = process.communicate(timeout=5)
        completed = True
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, error = process.communicate()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    assert completed, "the output quota did not terminate the command while it was producing output"
    assert len(output) == 65537 and process.returncode == 125, (len(output), process.returncode, error)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["producer.py", "runner.sh"]


@pytest.mark.parametrize(("exit_code", "full_output"), [(0, False), (7, False), (0, True)])
def test_sandbox_runner_finishes_with_an_inherited_writer_and_preserves_later_service_output(tmp_path, exit_code, full_output):
    """Direct setup exit does not wait for a quiet service, and its later writes still have a reader."""
    runner = tmp_path / "runner.sh"
    runner.write_text(sandbox.RUNNER_SCRIPT)
    service = tmp_path / "service.py"
    service.write_text("import os, signal, sys, time\nfrom pathlib import Path\n"
                       "signal.signal(signal.SIGPIPE, signal.SIG_DFL)\nroot = Path(sys.argv[1])\n"
                       "while not (root / 'write-now').exists(): time.sleep(0.01)\n"
                       "for _ in range(32): os.write(1, b'late output' * 1024)\n"
                       "(root / 'written').touch()\ntime.sleep(60)\n")
    setup = tmp_path / "setup.sh"
    foreground = shlex.join([sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"]) if full_output else 'printf "direct output\\n"'
    setup.write_text(f"{shlex.join([sys.executable, str(service), str(tmp_path)])} &\n"
                     'printf "%s\\n" "$!" >service.pid\n' + foreground + "\n"
                     f"touch setup-completed\nexit {exit_code}\n")
    process = subprocess.Popen([sys.executable, str(runner), "/dev/null", "sh", str(setup)], cwd=tmp_path,
                               env={**os.environ, "TMPDIR": str(tmp_path)}, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        try:
            output, error = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            assert (tmp_path / "setup-completed").exists(), "the fixture setup did not finish"
            pytest.fail("setup completion waited for the background service's inherited stdout")
        expected = b"x" * 65536 if full_output else b"direct output\n"
        assert (process.returncode, output) == (exit_code, expected), (process.returncode, output, error)
        service_pid = int((tmp_path / "service.pid").read_text())
        os.kill(service_pid, 0)
        (tmp_path / "write-now").touch()
        until = time.monotonic() + 5
        while not (tmp_path / "written").exists() and time.monotonic() < until:
            time.sleep(0.01)
        assert (tmp_path / "written").exists(), "later service output blocked or received SIGPIPE"
        os.kill(service_pid, 0)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()


@pytest.mark.parametrize("stage", ["compose", "image_inspection"])
@pytest.mark.parametrize("interruption", ["cancel", "build_timeout"])
def test_startup_subprocess_is_joined_before_sandbox_removal(tmp_path, monkeypatch, credentials, interruption, stage):
    """Use Harbor's real buffered collector on a host child, rather than a cancellation-safe fake start."""
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    children, stopped, started = [], [], asyncio.Event()
    child_command = [sys.executable, "-c", "import time; print('linux', flush=True); time.sleep(60)"]
    real_spawn = asyncio.create_subprocess_exec

    async def spawn(*command, **kwargs):
        assert list(command) == child_command, "the startup test must not launch Docker"
        process = await real_spawn(*command, **kwargs)
        children.append(process)
        started.set()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)

    async def host_command(command, **kwargs):
        if command == child_command:
            return await trusted_host_command(command, **kwargs)
        return await sandboxes.docker(command, **kwargs)

    monkeypatch.setattr(checks, "host_command", host_command)

    class StartingEnvironment(SandboxEnvironment):
        _validate_image_os = DockerEnvironment._validate_image_os
        _is_windows_container = False
        logger = SimpleNamespace(debug=lambda *args: None)

        @classmethod
        def _engine_cmd(cls, *command):
            assert command == ("inspect", "--format", "{{.Os}}", "fixture-image")
            return child_command

        async def start(self, force_build):
            self.owner.running.add(self.name)
            if stage == "image_inspection":
                await self._validate_image_os("fixture-image")
            else:
                process = await asyncio.create_subprocess_exec(*child_command, stdout=asyncio.subprocess.PIPE,
                                                               stderr=asyncio.subprocess.PIPE)
                await self._collect_buffered_output(process, timeout_sec=None)

        async def stop(self, delete):
            stopped.append(children[-1].returncode)
            await super().stop(delete)

    def create(**config):
        environment = StartingEnvironment(sandboxes, **config)
        sandboxes.environments[environment.name] = environment
        if interruption == "build_timeout":
            config["task_env_config"].build_timeout_sec = 0.1
        return environment

    monkeypatch.setattr(EnvironmentFactory, "create_environment", staticmethod(create))

    async def main():
        operation = asyncio.create_task(checks.investigate(run, setup_probe(), None))
        try:
            await asyncio.wait_for(started.wait(), 5)
            if interruption == "cancel":
                operation.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await operation
            else:
                with pytest.raises(TimeoutError):
                    await operation
            assert stopped and stopped[0] is not None, "cleanup ran while a startup subprocess could still create containers"
            assert all(child.returncode is not None for child in children)
        finally:
            if not operation.done():
                operation.cancel()
                await asyncio.gather(operation, return_exceptions=True)
            for child in children:
                if child.returncode is None:
                    child.kill()
                await child.communicate()

    asyncio.run(main())
    record = sandbox_record(run, "sandbox-0000")
    assert record["cleanup"]["removed"] is True
    assert record["cancelled"] is (interruption == "cancel")


def test_mounted_grader_fifo_is_explicitly_unavailable_without_blocking(tmp_path):
    """A real FIFO has an emergency writer so a regression cannot leave the reader blocked."""
    fifo = tmp_path / "test-stdout.txt"
    os.mkfifo(fifo)
    results = []
    reader = threading.Thread(target=lambda: results.append(sandbox._bounded(fifo)), daemon=True)
    reader.start()
    try:
        reader.join(timeout=1)
        assert not reader.is_alive(), "opening the grader FIFO blocked the host reader"
    finally:
        if reader.is_alive():
            writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            os.close(writer)
        reader.join(timeout=5)
        assert not reader.is_alive(), "FIFO reader cleanup failed"
    text, error = results[0]
    assert text is None and "regular file" in error


def test_interpretation_inability_is_not_a_tool_or_provider_failure(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi import checks
    # Exercise the real interpretation branch with only the slow native check replaced.
    from nudi.records import Submission, Content, Check, EpisodeResult
    run = new_run(tmp_path, monkeypatch, credentials)
    episode = run.config.output_dir / "episodes" / "ordinary"
    episode.mkdir(parents=True)
    result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir), task_digest=tree_digest(run.config.task_dir), model="ordinary", reasoning_effort=None, versions={}, rewards={"reward": 1})
    (episode / "episode.json").write_text(result.model_dump_json())
    run.record.episodes.append("ordinary")
    state = Submission(content=Content(episode="ordinary", path="state", sha256="hash"), ids={}, location="/app/answer.txt", capture_point="verification_start", command=[], program="capture", output="")
    run.record.submissions.append(state)
    run.save()
    async def checked(*args, **kwargs):
        return Check(id="check", content=state.content, ids={}, requirement=Observation(episode=None, path="instruction.md", excerpt="42"), command=[], exit_code=0, output="actual result")
    monkeypatch.setattr(checks, "check_submission", checked)
    probe = {"category": "package_oracles", "episode": "ordinary", "location": "/app/answer.txt", "capture_point": "verification_start", "timing": "start", "program": CHECKER,
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "42"}}
    script = InspectorScript([{"probes": [probe]}, {"refusal": "declines interpretation"}])
    async def main():
        async with serve(script) as base:
            run.record.models["inspector"].api_base = base
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.attempts[0].status == "model_inability"
    asyncio.run(main())


def ordinary_pool(run, count=2) -> list[str]:
    """Saved ordinary episodes, each with a trace and a verification-start capture record."""
    from nudi.records import Content, EpisodeResult, Submission
    pool = [f"{index:04d}-simulator" for index in range(count)]
    for name in pool:
        directory = run.config.output_dir / "episodes" / name
        directory.mkdir(parents=True)
        (directory / "trace.txt").write_text("ordinary trace")
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir),
                               task_digest=tree_digest(run.config.task_dir), model="ordinary", reasoning_effort=None,
                               versions={}, rewards={"reward": 1.0}, artifacts={"trajectory": "trace.txt"})
        (directory / "episode.json").write_text(result.model_dump_json())
        run.record.episodes.append(name)
        run.record.submissions.append(Submission(content=Content(episode=name, path="state", sha256="hash"), ids={},
                                                 location="/app/answer.txt", capture_point="verification_start",
                                                 command=[], program="capture", output=""))
    run.save()
    return pool


def review_probe(name, **fields) -> dict:
    return {"category": "accepted_invalid", "case": f"answer in {name}", "episode": name, "location": "/app/answer.txt",
            "capture_point": "verification_start", "timing": "The answer applies at verification start.", "program": CHECKER,
            "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"}, **fields}


def reviewed(outcome="unknown", scope="native"):
    async def investigate(run, probe, session):
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"]), outcome=outcome, execution_scope=scope)
    return investigate


def test_grader_review_is_optional_triage_and_omissions_stay_unreviewed_unknown(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """Ordinary episodes are leads, not obligations. An unreviewed one keeps its reason and an unknown label."""
    from nudi import report
    requests = inspector_responses(monkeypatch, [{"probes": [review_probe("0000-simulator")],
                                                  "applicability": package_applicability("accepted_invalid")}])
    mock_experiments(monkeypatch, reviewed())
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    assert result.status == "partial", "an omitted ordinary episode prevents complete review"
    broad = json.loads(requests[0]["messages"][-1]["content"])
    assert broad["unreviewed_ordinary_episodes"] == pool
    assert "each unreviewed ordinary episode" not in broad["instruction"] and "leads" in broad["instruction"]
    prompt = " ".join((Path(checks.__file__).parent / "prompts/inspector.md").read_text().split())
    assert "Propose at least one probe naming each listed" not in prompt and "find leads" in prompt
    assert result.ordinary["0001-simulator"].label == "unknown"
    assert [(review.episode, review.status, review.assessment) for review in result.reviews] == [("0000-simulator", "assessed", 0)]
    assert list(result.unreviewed) == ["0001-simulator"] and "No experiment reviewed" in result.unreviewed["0001-simulator"]
    assert result.categories["accepted_invalid"] == "unknown" and result.status == "partial"
    assert "unreviewed: No experiment reviewed" in " ".join(result.ordinary["0001-simulator"].reasons)
    warnings = []
    labels = report.labels(pool, result, warnings)
    assert labels["review"] == {"attempted": ["0000-simulator"], "unreviewed": result.unreviewed,
                                "unresolved": ["0000-simulator"], "supported": []}
    assert any("1 of 2 ordinary episodes were not reviewed" in warning for warning in warnings)


def test_holistic_inspection_presumes_named_normal_episodes_and_verifies_investigated_ones(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """Default mode: an episode named normal follows the grader, whatever its reward; an investigated one keeps its evidence."""
    from nudi import report
    from nudi.records import EpisodeResult
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 4)
    record = run.config.output_dir / "episodes" / pool[1] / "episode.json"
    record.write_text(EpisodeResult.model_validate_json(record.read_text()).model_copy(update={"rewards": {"reward": 0.0}}).model_dump_json())
    requests = inspector_responses(monkeypatch, [{"probes": [review_probe(pool[2])], "normal_episodes": pool[:3] + ["not-in-pool"],
                                                  "applicability": package_applicability("accepted_invalid")}])
    mock_experiments(monkeypatch, reviewed("accepted_invalid"))
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    broad = json.loads(requests[0]["messages"][-1]["content"])
    assert broad["ordinary_inspection"] == "holistic_inspection" and "normal_episodes" in broad["instruction"]
    assert broad["instruction"].startswith("You are the grader inspector.")
    assert result.ordinary_inspection == "holistic_inspection" and result.normal == pool[:3]
    assert {name: (label.label, label.basis) for name, label in result.ordinary.items()} == {
        pool[0]: ("legitimate", "presumed"), pool[1]: ("legitimate", "presumed"),
        pool[2]: ("accepted_invalid", "verified"), pool[3]: ("unknown", None)}
    assert "presumed: the grader inspector skimmed this episode" in " ".join(result.ordinary[pool[1]].reasons)
    assert result.ordinary[pool[1]].assessments == []
    assert list(result.unreviewed) == [pool[3]], "a skimmed and presumed episode is not unreviewed"
    warnings = []
    labels = report.labels(pool, result, warnings)
    assert labels["mode"] == "holistic_inspection" and labels["basis"] == {"presumed": 2, "verified": 1}
    assert labels["review"]["supported"] == [pool[2]], "a presumed label is not a supported label"
    assert any("2 of 4 ordinary episodes have presumed labels" in warning for warning in warnings)


@pytest.mark.parametrize("doubt", ["unknown_unresolved", "ungrounded", "legitimate_unresolved", "failed_review"])
def test_named_normal_episode_with_an_unresolved_or_failed_review_stays_unknown(tmp_path, monkeypatch, credentials, doubt, unit_sandboxes):
    """A presumption never hides the episode's own unresolved evidence; another episode settles the category."""
    from nudi import report
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 2)
    inspector_responses(monkeypatch, [{"probes": [review_probe(name) for name in pool], "normal_episodes": pool,
                                       "applicability": package_applicability("accepted_invalid")}])

    async def investigate(run, probe, session):
        if probe["episode"] == pool[1]:
            return Assessment(claim=Claim(mechanism="review", episode=pool[1]), outcome="accepted_invalid")
        if doubt == "failed_review":
            raise RuntimeError("checker sandbox failed")
        outcome, unresolved = {"unknown_unresolved": ("unknown", ["whether the answer is required"]), "ungrounded": ("ungrounded", []),
                               "legitimate_unresolved": ("legitimate", ["whether the grader reads this file"])}[doubt]
        return Assessment(claim=Claim(mechanism="review", episode=pool[0], unresolved=unresolved), outcome=outcome)

    mock_experiments(monkeypatch, investigate)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    assert result.categories == {"accepted_invalid": "evidenced_issue"}
    assert (result.ordinary[pool[0]].label, result.ordinary[pool[0]].basis) == ("unknown", None)
    assert (result.ordinary[pool[1]].label, result.ordinary[pool[1]].basis) == ("accepted_invalid", "verified")
    assert result.status == "partial"
    if doubt == "failed_review":
        assert "checker sandbox failed" in " ".join(result.ordinary[pool[0]].reasons)
    assert report.labels(pool, result, [])["review"]["unresolved"] == [pool[0]]


def episode_tools(monkeypatch, behave):
    """Replace each Inspector turn with direct tool calls: `behave(session name, tools, schema)`."""
    async def ask(session, context, schema, *, tools):
        return await behave(session.name, {item.name: item for item in tools}, schema)
    monkeypatch.setattr(inspector.Investigation, "ask", ask)


def test_episode_session_reviews_and_interprets_only_its_own_episode(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi.records import Check
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 2)

    async def checked(run, submission, requirement, scoring, program, *, capture_point, timing):
        run.record.checks.append(Check(id=f"check-{len(run.record.checks):04d}", content=submission.content, ids={},
                                       requirement=requirement, command=["python3"], exit_code=0, output="{}"))
        run.save()
        return run.record.checks[-1]

    monkeypatch.setattr(checks, "check_submission", checked)
    other = {}

    async def behave(name, tools, schema):
        if name == f"grader-episode-{pool[0]}":
            await tools["run_experiment"].ainvoke({"probe": review_probe(pool[0])})
        elif name == f"grader-episode-{pool[1]}":
            other["review"] = await tools["run_experiment"].ainvoke({"probe": review_probe(pool[0], case="another episode")})
            other["receipt"] = await tools["interpret_experiment"].ainvoke({"experiment": "experiment-0000", "claim": {}})
            other["check"] = await tools["interpret_experiment"].ainvoke({"experiment": "check-0000", "claim": {}})
        return schema()

    episode_tools(monkeypatch, behave)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0,
                                               isolated_inspections=True))
    assert all(item["status"] == "skipped" and pool[1] in item["reason"] for item in other.values()), other
    assert [check.id for check in run.record.checks] == ["check-0000"]
    assert [(review.episode, review.attempt) for review in result.reviews] == [(pool[0], 1)]
    assert [item.status for item in result.attempts[1:]] == ["no_evidenced_issue"] * 2, "a rejected call is not a model failure"
    assert list(result.unreviewed) == [pool[1]]


def test_review_interpreted_by_its_check_id_is_assessed_and_an_uninterpreted_one_ends(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """An experiment interpreted by its check id is assessed, without opening a second review that leaves the first
    one running. A review whose session ends before interpretation is ended, not live."""
    from nudi.records import Check
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 2)

    async def checked(run, submission, requirement, scoring, program, *, capture_point, timing):
        run.record.checks.append(Check(id=f"check-{len(run.record.checks):04d}", content=submission.content, ids={},
                                       requirement=requirement, command=["python3"], exit_code=0, output="{}"))
        run.save()
        return run.record.checks[-1]

    monkeypatch.setattr(checks, "check_submission", checked)
    claim = {"mechanism": "review", "requirement_support": support(review_probe(pool[0])["requirement"]),
             "scoring_support": {"basis": "unknown", "sources": [], "rationale": "No scoring source is available.", "uncertainty": []}}

    async def behave(name, tools, schema):
        if name == f"grader-episode-{pool[0]}":
            await tools["run_experiment"].ainvoke({"probe": review_probe(pool[0])})
            await tools["interpret_experiment"].ainvoke({"experiment": "check-0000", "claim": claim})
        elif name == f"grader-episode-{pool[1]}":
            await tools["run_experiment"].ainvoke({"probe": review_probe(pool[1])})
        return schema()

    episode_tools(monkeypatch, behave)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0,
                                               isolated_inspections=True))
    first, second = result.reviews
    assert (first.episode, first.status, first.reinterprets, first.assessment) == (pool[0], "assessed", None, 0)
    assert (second.episode, second.status, second.assessment) == (pool[1], "incomplete", None)
    assert "ended before" in second.error
    assert [item["status"] for item in result.experiments] == ["assessed", "measured"]
    assert "review incomplete after check-0001 exit 0" in " ".join(result.ordinary[pool[1]].reasons)


@pytest.mark.parametrize("then, episode, settled, status", [
    (None, "no_evidenced_issue", "no_evidenced_issue", "partial"),
    # A later failed interpretation of the same receipt is not recovered, so the category stays open.
    ("invalid", "model_output_failure", "unknown", "partial"),
    # A spending cap in the episode session does not undo the category work broad completed.
    ("cap", "spending_exhausted", "no_evidenced_issue", "spending_exhausted"),
])
def test_episode_repair_of_a_broad_receipt_settles_its_category(tmp_path, monkeypatch, credentials, then, episode, settled, status,
                                                                unit_sandboxes):
    """Broad completes the category but leaves its receipt measured; the episode fork interprets it consistently."""
    from nudi.workflow import SpendingCapReached
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 1)

    async def investigate(run, probe, session):
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"]), outcome="legitimate", validity="supported",
                          discrepancy="none")

    mock_experiments(monkeypatch, investigate)
    receipts = []

    async def behave(name, tools, schema):
        if name == "grader-broad":
            receipts.append(await tools["run_experiment"].ainvoke({"probe": review_probe(pool[0])}))
            return schema(applicability=package_applicability("accepted_invalid"), completed=["accepted_invalid"])
        claim = {**receipts[0]["scripted_claim"], "requirement_support": support({"episode": None, "path": "instruction.md", "excerpt": "42"}),
                 "scoring_support": {"basis": "unknown", "sources": [], "rationale": "No scoring source is available.", "uncertainty": []}}
        await tools["interpret_experiment"].ainvoke({"experiment": receipts[0]["id"], "claim": claim})
        if then == "invalid":
            await tools["interpret_experiment"].ainvoke({"experiment": receipts[0]["id"], "claim": {
                **claim, "derivation": {"observations": "exists", "validity": "supported"}}})
        elif then == "cap":
            raise SpendingCapReached("spending cap reached")
        return schema()

    episode_tools(monkeypatch, behave)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0,
                                               isolated_inspections=True))
    assert [item.status for item in result.attempts] == ["no_evidenced_issue", episode]
    assert [item["status"] for item in result.experiments] == ["assessed"]
    assert [review.status for review in result.reviews] == ["model_output_failure" if then == "invalid" else "assessed"]
    assert result.categories == {"accepted_invalid": settled} and result.status == status


@pytest.mark.parametrize("then, episode, status", [
    # A repeated probe is a duplicate attempt; it adds no receipt, does not reopen the category and leaves the verified label.
    ("duplicate", "duplicate_case", "complete"),
    # A category probe in an episode session is skipped; the category work broad completed stands.
    ("skipped", "no_evidenced_issue", "complete"),
])
def test_episode_skip_or_duplicate_keeps_a_settled_category(tmp_path, monkeypatch, credentials, then, episode, status, unit_sandboxes):
    """Broad completes the category and assesses its receipt consistently; a rejected episode probe leaves it settled."""
    from nudi.records import Check, Content, Coverage
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 1)
    requirement = Observation(episode=None, path="instruction.md", excerpt="Write the number 42")
    scoring = Observation(episode=None, path="tests/test.sh", excerpt="reward")
    check = Check(id="scripted-check-0", content=Content(episode=pool[0], path="state", sha256="hash"), ids={},
                  requirement=requirement, scoring=scoring, command=[], exit_code=0, output="")
    coverage = Coverage(requirements=[requirement], scoring=scoring, checks=[check.id],
                        explanation="The answer is the only scored requirement, so the reward 1.0 is deserved.")

    async def investigate(run, probe, session):
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"], coverage=coverage), outcome="legitimate",
                          check=check, validity="supported", discrepancy="none")

    mock_experiments(monkeypatch, investigate)
    rejected = []

    async def behave(name, tools, schema):
        if name == "grader-broad":
            receipt = await tools["run_experiment"].ainvoke({"probe": review_probe(pool[0])})
            claim = {**receipt["scripted_claim"], "requirement_support": support({"episode": None, "path": "instruction.md", "excerpt": "42"}),
                     "scoring_support": {"basis": "unknown", "sources": [], "rationale": "No scoring source is available.", "uncertainty": []}}
            await tools["interpret_experiment"].ainvoke({"experiment": receipt["id"], "claim": claim})
            return schema(applicability=package_applicability("accepted_invalid"), completed=["accepted_invalid"])
        probe = review_probe(pool[0]) if then == "duplicate" else review_probe(pool[0], setup_program="targeted")
        rejected.append(await tools["run_experiment"].ainvoke({"probe": probe}))
        return schema()

    episode_tools(monkeypatch, behave)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0,
                                               isolated_inspections=True))
    assert [item["status"] for item in rejected] == ["duplicate_case" if then == "duplicate" else "skipped"]
    assert [item.status for item in result.attempts] == ["no_evidenced_issue", episode]
    assert [item["status"] for item in result.experiments] == ["assessed"]
    assert (result.ordinary[pool[0]].label, result.ordinary[pool[0]].basis) == ("legitimate", "verified")
    assert result.categories == {"accepted_invalid": "no_evidenced_issue"} and result.status == status


def test_failed_review_a_later_review_recovers_leaves_a_complete_inspection(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """The first review of the episode fails; the focused attempt reviews it again and verifies its label."""
    from nudi.records import Check, Content, Coverage
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 1)
    requirement = Observation(episode=None, path="instruction.md", excerpt="Write the number 42")
    scoring = Observation(episode=None, path="tests/test.sh", excerpt="reward")
    check = Check(id="scripted-check-0", content=Content(episode=pool[0], path="state", sha256="hash"), ids={},
                  requirement=requirement, scoring=scoring, command=[], exit_code=0, output="")
    coverage = Coverage(requirements=[requirement], scoring=scoring, checks=[check.id],
                        explanation="The answer is the only scored requirement, so the reward 1.0 is deserved.")
    calls = []

    async def investigate(run, probe, session):
        calls.append(probe["episode"])
        if len(calls) == 1:
            raise RuntimeError("review sandbox failed")
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"], coverage=coverage), outcome="legitimate",
                          check=check, validity="supported", discrepancy="none")

    mock_experiments(monkeypatch, investigate)

    async def behave(name, tools, schema):
        receipt = await tools["run_experiment"].ainvoke({"probe": review_probe(pool[0])})
        if name == "grader-accepted_invalid":
            claim = {**receipt["scripted_claim"], "requirement_support": support({"episode": None, "path": "instruction.md", "excerpt": "42"}),
                     "scoring_support": {"basis": "unknown", "sources": [], "rationale": "No scoring source is available.", "uncertainty": []}}
            await tools["interpret_experiment"].ainvoke({"experiment": receipt["id"], "claim": claim})
        return schema(applicability=package_applicability("accepted_invalid"), completed=["accepted_invalid"])

    episode_tools(monkeypatch, behave)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=1))
    assert [review.status for review in result.reviews] == ["tool_failure", "assessed"]
    assert [item.status for item in result.attempts] == ["tool_failure", "no_evidenced_issue"]
    assert (result.ordinary[pool[0]].label, result.ordinary[pool[0]].basis) == ("legitimate", "verified")
    assert result.categories == {"accepted_invalid": "no_evidenced_issue"} and result.status == "complete"


@pytest.mark.parametrize("outcome, unresolved, settled, label", [
    ("accepted_invalid", [], "evidenced_issue", "accepted_invalid"),
    ("accepted_invalid", ["whether the answer is required"], "no_evidenced_issue", "unknown"),
    ("unknown", [], "no_evidenced_issue", "unknown"),
])
def test_episode_evidence_settles_its_category_but_episodes_never_change_coverage(tmp_path, monkeypatch, credentials, outcome, unresolved,
                                                                                   settled, label, unit_sandboxes):
    """An evidenced episode finding is an evidenced issue; an unresolved or inconclusive one leaves broad's settled category alone."""
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 2)

    async def investigate(run, probe, session):
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"], unresolved=unresolved), outcome=outcome)

    mock_experiments(monkeypatch, investigate)

    async def behave(name, tools, schema):
        if name == "grader-broad":
            return schema(applicability=package_applicability("accepted_invalid"), completed=["accepted_invalid"])
        receipt = await tools["run_experiment"].ainvoke({"probe": review_probe(name.removeprefix("grader-episode-"))})
        claim = {**receipt["scripted_claim"], "requirement_support": support({"episode": None, "path": "instruction.md", "excerpt": "42"}),
                 "scoring_support": {"basis": "unknown", "sources": [], "rationale": "No scoring source is available.", "uncertainty": []}}
        await tools["interpret_experiment"].ainvoke({"experiment": receipt["id"], "claim": claim})
        # A forged summary from an episode session sets neither applicability nor completion.
        return schema(applicability=package_applicability("accepted_invalid", status="restricted", facts={"package_copy": False}),
                      completed=["accepted_invalid"])

    episode_tools(monkeypatch, behave)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0,
                                               isolated_inspections=True))
    assert result.categories == {"accepted_invalid": settled}
    assert [item.status for item in result.attempts] == ["no_evidenced_issue"] + [
        "evidenced_issue" if settled == "evidenced_issue" else "no_evidenced_issue"] * 2
    assert result.applicability_evidence["accepted_invalid"]["status"] == "applicable"
    assert [assessment.outcome for assessment in result.assessments] == [outcome] * 2
    assert {name: result.ordinary[name].label for name in pool} == dict.fromkeys(pool, label)
    assert result.status == ("complete" if label == "accepted_invalid" else "partial")


def test_inspector_swarm_forks_one_isolated_inspector_per_episode_and_warns(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """On: after broad and focused, each ordinary episode gets its own fork of broad; none sees another's turns."""
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 2)
    requests = inspector_responses(monkeypatch, [{"probes": [], "normal_episodes": pool,
                                                  "applicability": package_applicability("accepted_invalid")},
                                                 {"probes": []}, {"probes": [review_probe(pool[0])]}, {"probes": [review_probe(pool[1])]}])
    mock_experiments(monkeypatch, reviewed("accepted_invalid"))
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=1,
                                               isolated_inspections=True))
    assert any("3 to 7 minutes per episode" in warning and "6 to 14 minutes" in warning for warning in run.record.warnings)
    assert result.ordinary_inspection == "inspector_swarm" and result.normal == [], "no presumed labels in this mode"
    assert [(item.phase, item.category, item.episode) for item in result.attempts] == [
        ("broad", None, None), ("focused", "accepted_invalid", None), ("episode", None, pool[0]), ("episode", None, pool[1])]
    broad, focused, first, second = (request["messages"] for request in requests)
    assert first[:len(broad)] == second[:len(broad)] == broad, "each episode forks broad"
    assert len(second) == len(broad) + 3, "the second episode sees neither the first episode's nor the category's turns"
    for messages, name in ((first, pool[0]), (second, pool[1])):
        request = json.loads(messages[-1]["content"])
        assert (request["phase"], request["episode"], request["categories"]) == ("episode", name, [])
        assert "task" not in request and name in request["instruction"]
    assert [review.episode for review in result.reviews] == pool and result.unreviewed == {}
    assert {name: (label.label, label.basis) for name, label in result.ordinary.items()} == dict.fromkeys(pool, ("accepted_invalid", "verified"))
    assert set(result.sessions) == {"grader-broad", "grader-accepted_invalid", f"grader-episode-{pool[0]}", f"grader-episode-{pool[1]}"}
    prompt = " ".join((Path(checks.__file__).parent / "prompts/inspector.md").read_text().split())
    assert "holistic_inspection" in prompt and "inspector_swarm" in prompt


@pytest.mark.parametrize("status", ["applicable", "restricted"])
def test_category_stop_or_restriction_does_not_discard_ordinary_reviews(tmp_path, monkeypatch, credentials, status, unit_sandboxes):
    """An evidenced first probe or a grounded restriction governs targeted work only."""
    inspector_responses(monkeypatch, [{"probes": [review_probe("0000-simulator"), review_probe("0001-simulator")],
                                       "applicability": package_applicability("accepted_invalid", status=status)}])
    mock_experiments(monkeypatch, reviewed("accepted_invalid"))
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    assert [assessment.claim.episode for assessment in result.assessments] == pool
    assert [(review.episode, review.assessment) for review in result.reviews] == [(pool[0], 0), (pool[1], 1)]
    assert result.unreviewed == {}
    assert {name: label.label for name, label in result.ordinary.items()} == dict.fromkeys(pool, "accepted_invalid")
    assert result.categories["accepted_invalid"] == "evidenced_issue", "restricted-category evidence is retained"


def test_ordinary_finding_outside_the_focused_category_settles_it_without_discarding_reviews(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """First-evidenced-issue stopping: the discovered category gets no later discovery turn."""
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 3)
    applicable = {**package_applicability("accepted_invalid"), **package_applicability("rejected_valid")}
    requests = inspector_responses(monkeypatch, [
        {"probes": [], "applicability": applicable},
        {"probes": [review_probe(pool[0], category="rejected_valid")]},
        {"probes": [review_probe(pool[1]), review_probe(pool[2], category="unrecognized")]},
    ] + [{"probes": []}] * 2)

    async def investigate(run, probe, session):
        outcome = "unknown" if probe["episode"] == pool[1] else "accepted_invalid"
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"]), outcome=outcome)

    mock_experiments(monkeypatch, investigate)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid", "rejected_valid"], focused_attempts=2))
    assert len(requests) == 3, "the evidenced category receives no later discovery turn"
    assert result.categories == {"accepted_invalid": "unknown", "rejected_valid": "evidenced_issue"}
    assert [(item.phase, item.category, item.status) for item in result.attempts] == [
        ("broad", None, "no_evidenced_issue"), ("focused", "accepted_invalid", "no_evidenced_issue"),
        ("focused", "accepted_invalid", "no_evidenced_issue")]
    assert [review.episode for review in result.reviews] == pool and result.unreviewed == {}
    assert result.status == "partial"


def test_unusable_interpretation_keeps_its_successful_check_and_later_ordinary_reviews(tmp_path, monkeypatch, credentials, unit_sandboxes):
    from nudi.records import Check
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run)

    async def checked(run, submission, requirement, scoring, program, *, capture_point, timing):
        run.record.checks.append(Check(id=f"check-{len(run.record.checks):04d}", content=submission.content, ids={},
                                       requirement=requirement, command=["python3"], exit_code=0, output="{}"))
        run.save()
        return run.record.checks[-1]

    monkeypatch.setattr(checks, "check_submission", checked)
    malformed = {"claim": {"mechanism": "unusable", "derivation": {"observations": "exists", "validity": "supported"}}}
    requests = inspector_responses(monkeypatch, [
        {"probes": [review_probe(name) for name in pool], "applicability": package_applicability("accepted_invalid")},
        malformed, VIOLATED])
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    assert [check.exit_code for check in run.record.checks] == [0, 0], "the failure does not discard the later ordinary probe"
    assert [assessment.claim.episode for assessment in result.assessments] == [pool[1]]
    first, second = result.reviews
    assert (first.episode, first.status, first.checks, first.assessment) == (pool[0], "model_output_failure", {"check-0000": 0}, None)
    assert "Invalid Claim" in first.error
    assert (second.episode, second.status, second.checks, second.assessment) == (pool[1], "assessed", {"check-0001": 0}, 0)
    assert result.unreviewed == {} and result.status == "partial"
    reasons = " ".join(result.ordinary[pool[0]].reasons)
    assert "model_output_failure after check-0000 exit 0" in reasons and "Invalid Claim" in reasons
    assert "Invalid Claim" in json.dumps(result.sessions["grader-broad"])
    assert "exact top-level keys" in requests[1]["messages"][0]["content"]


@pytest.mark.parametrize("interruption", ["spending_exhausted", "cancelled", "model_inability"])
def test_interrupted_grader_inspection_keeps_explicit_unreviewed_reasons(tmp_path, monkeypatch, credentials, interruption, unit_sandboxes):
    run = new_run(tmp_path, monkeypatch, credentials, spending_cap=1.0)
    pool = ordinary_pool(run)
    if interruption == "spending_exhausted":
        run.record.known_cost = 1.0
    elif interruption == "model_inability":
        inspector_responses(monkeypatch, [{"refusal": "cannot review these episodes"}])
    else:
        async def cancelled(*args, **kwargs):
            raise asyncio.CancelledError()
        monkeypatch.setattr(inspector.Investigation, "ask", cancelled)
    with pytest.raises(asyncio.CancelledError) if interruption == "cancelled" else contextlib.nullcontext():
        asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    saved = checks.InspectionResult.model_validate_json((run.config.output_dir / "inspection-grader.json").read_text())
    assert saved.reviews == [] and list(saved.unreviewed) == pool and saved.status != "complete"
    assert all(interruption in reason for reason in saved.unreviewed.values()), saved.unreviewed
    assert all("unreviewed: " in " ".join(label.reasons) for label in saved.ordinary.values())


def test_package_probe_naming_an_ordinary_episode_is_not_its_review(tmp_path, monkeypatch, credentials, unit_sandboxes):
    inspector_responses(monkeypatch, [{"probes": [review_probe("0000-simulator", setup_program="true\n")],
                                       "applicability": package_applicability("accepted_invalid")}])
    mock_experiments(monkeypatch, reviewed("accepted_invalid", scope="package"))
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    assert result.reviews == [] and list(result.unreviewed) == pool
    assert result.categories["accepted_invalid"] == "evidenced_issue"
    assert {name: label.label for name, label in result.ordinary.items()} == dict.fromkeys(pool, "unknown")


def failing_targeted_probe(error):
    """A targeted package probe raises `error`; ordinary reviews return an inconclusive assessment."""
    async def investigate(run, probe, session):
        if probe.get("setup_program") is not None:
            raise error
        return Assessment(claim=Claim(mechanism="review", episode=probe["episode"]), outcome="unknown")
    return investigate


def test_nonfatal_targeted_failure_keeps_later_ordinary_reviews(tmp_path, monkeypatch, credentials, unit_sandboxes):
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run)
    requests = inspector_responses(monkeypatch, [{
        "probes": [review_probe(pool[0], setup_program="true\n"), review_probe(pool[0], case="later targeted", setup_program="false\n"),
                   *(review_probe(name) for name in pool)],
        "applicability": package_applicability("accepted_invalid")}])
    investigated = []
    failing = failing_targeted_probe(RuntimeError("sandbox failed"))

    async def investigate(run, probe, session):
        investigated.append(probe.get("setup_program"))
        return await failing(run, probe, session)

    mock_experiments(monkeypatch, investigate)
    result = asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    assert [review.episode for review in result.reviews] == pool, "a targeted failure does not discard ordinary obligations"
    assert investigated == ["true\n", "false\n", None, None], "later tool requests stay independent of a failed setup"
    assert len(requests) == 1 and result.unreviewed == {}
    assert (result.attempts[0].status, result.attempts[0].error) == ("tool_failure", "RuntimeError: sandbox failed")
    assert result.status == "partial"


@pytest.mark.parametrize("interruption, status", [("spending", "spending_exhausted"), ("cancelled", "cancelled"),
                                                  ("infrastructure", "tool_failure: InfrastructureAbort")])
def test_interruption_after_naming_ordinary_episodes_is_distinct_from_omission(tmp_path, monkeypatch, credentials, interruption, status, unit_sandboxes):
    from nudi.records import InfrastructureAbort
    run = new_run(tmp_path, monkeypatch, credentials)
    pool = ordinary_pool(run, 3)
    error = {"spending": workflow.SpendingCapReached("known cost reached the cap"), "cancelled": asyncio.CancelledError(),
             "infrastructure": InfrastructureAbort("container resume failed")}[interruption]
    async def ask(session, context, schema, *, tools):
        measure = next(item for item in tools if item.name == "run_experiment")
        await measure.ainvoke({"probe": review_probe(pool[0], setup_program="true\n")})
        raise AssertionError("fatal tool failure did not propagate")
    monkeypatch.setattr(inspector.Investigation, "ask", ask)
    mock_experiments(monkeypatch, failing_targeted_probe(error))
    with pytest.raises(asyncio.CancelledError if interruption == "cancelled" else InfrastructureAbort) if interruption != "spending" else contextlib.nullcontext():
        asyncio.run(checks.inspect_grader(run, pool, categories=["accepted_invalid"], focused_attempts=0))
    saved = checks.InspectionResult.model_validate_json((run.config.output_dir / "inspection-grader.json").read_text())
    assert saved.reviews == [] and list(saved.unreviewed) == pool and saved.status != "complete"
    assert all(status in reason for reason in saved.unreviewed.values())
    assert all("No experiment reviewed this episode" in reason for reason in saved.unreviewed.values())


# The investigation runtime: the Deep Agents SDK over one held workspace sandbox.


class Finding(BaseModel):
    summary: str


class FollowupFinding(BaseModel):
    summary: str
    verified: bool


def agent_reply(message: dict, finish: str = "stop") -> web.Response:
    usage = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    return web.json_response({"id": "chatcmpl-inspector", "object": "chat.completion", "created": 0, "model": "scripted",
                              "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": usage})


class AgentScript:
    """Scripted chat replies for the Inspector agent. A request offering tools takes the next
    step: a tool call `(name, arguments)`; a list of them, issued together in one reply;
    "overflow", a provider context-length rejection;
    "refusal", a content filter stop; "error", a provider failure; or a callable returning one
    of these. A request without tools is the SDK's summarization call and receives `summary`."""

    def __init__(self, *steps, summary="The investigation so far, condensed."):
        self.steps, self.summary = list(steps), summary
        self.requests: list[tuple[dict, dict]] = []

    async def chat(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.requests.append((dict(request.headers), body))
        if not body.get("tools"):
            return agent_reply({"role": "assistant", "content": self.summary})
        step = self.steps.pop(0)
        if callable(step):
            step = step()
        if step == "overflow":
            error = {"message": "This model's maximum context length is 8 tokens.", "type": "invalid_request_error",
                     "code": "context_length_exceeded"}
            return web.json_response({"error": error}, status=400)
        if step == "refusal":
            return agent_reply({"role": "assistant", "content": ""}, "content_filter")
        if step == "message_refusal":
            return agent_reply({"role": "assistant", "content": "", "refusal": "scripted provider refusal"})
        if step == "error":
            return web.json_response({"error": {"message": "scripted upstream failure", "type": "server_error"}}, status=500)
        calls = [{"id": f"call_{len(self.requests)}" + (f"_{index}" if index else ""), "type": "function",
                  "function": {"name": name, "arguments": json.dumps(arguments)}}
                 for index, (name, arguments) in enumerate(step if isinstance(step, list) else [step])]
        return agent_reply({"role": "assistant", "content": None, "tool_calls": calls}, "tool_calls")

    def tool_results(self) -> list[str]:
        """Each tool result once, in the order the agent received them."""
        results = {}
        for _, body in self.requests:
            for message in body["messages"]:
                if message.get("role") == "tool":
                    results.setdefault(message["tool_call_id"], str(message["content"]))
        return list(results.values())


def transcript(session) -> list[dict]:
    return [json.loads(line) for line in (session.box.directory / "transcript.jsonl").read_text().splitlines()]


def inspector_run(tmp_path, base_url, task=CONTRACT_TASK, **fields):
    """A native Docker run whose Inspector calls reach the scripted endpoint."""
    model = ModelConfig(model="xai/grok-4.7", reasoning_effort="xhigh", api_base=base_url)
    return workflow.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run", models={"inspector": model}, **fields),
                              frozenset({"inspector"}))


GRADER_RULE = "LEADING_ZERO_RULE = 'rejects 042'"
TRACE_MIDDLE = "nudi-trace-middle-evidence"


def test_investigation_reads_omitted_evidence_and_adapts_in_one_workspace(tmp_path, docker_env):
    """The SDK's own tools read past nudi's bounded context and keep files across turns, with
    no credential or host file in reach."""
    from nudi import inspector

    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    (task / "tests" / "oversized_grader.py").write_text("# filler line\n" * 6000 + GRADER_RULE + "\n")
    original = tree_digest(task)
    probe = "print('probe', open('/nudi/package/tests/oversized_grader.py').read().count('LEADING_ZERO_RULE'))\n"
    confined = (f"python3 /nudi/workspace/probe.py; echo provider_key_env=$(env | grep -c {masked(PROVIDER_KEY)}); "
                f"echo host_results=$(find / -path /proc -prune -o -name {masked(SENTINEL)} -print 2>/dev/null | wc -l)")
    script = AgentScript(
        ("read_file", {"file_path": "/nudi/package/tests/oversized_grader.py", "offset": 6000, "limit": 5}),
        ("grep", {"pattern": TRACE_MIDDLE, "path": "/nudi/evidence", "output_mode": "content"}),
        ("write_file", {"file_path": "/nudi/workspace/probe.py", "content": probe}),
        ("execute", {"command": confined}),
        ("Finding", {"summary": "first"}),
        ("edit_file", {"file_path": "/nudi/workspace/probe.py", "old_string": "'probe'", "new_string": "'adapted'"}),
        ("execute", {"command": "python3 /nudi/workspace/probe.py"}),
        ("Finding", {"summary": "second"}))

    async def main():
        async with serve(script) as base_url:
            run = inspector_run(tmp_path, base_url, task)
            trace = run.config.output_dir / "episodes/0000-simulator/trace.json"
            trace.parent.mkdir(parents=True)
            trace.write_text("a" * 50000 + TRACE_MIDDLE + "z" * 50000)
            assert "tests/oversized_grader.py" in checks.task_context(run)["omitted_context_files"]
            assert TRACE_MIDDLE not in checks.trace_excerpt(run, trace)[0]
            evidence = {"0000-simulator/trace.json": trace}
            async with inspector.investigation(run, "grader-broad", "Inspect the copied package.", evidence) as session:
                first = await session.ask("Find the leading-zero rule.", Finding)
                second = await session.ask("Adapt the probe.", Finding)
            return run, session, first, second

    run, session, first, second = asyncio.run(main())
    assert (first.summary, second.summary) == ("first", "second")
    read, found, written, executed, finished, edited, adapted = script.tool_results()
    assert GRADER_RULE in read and TRACE_MIDDLE in found and "/nudi/evidence/0000-simulator/trace.json" in found
    assert "probe 1" in executed and "provider_key_env=0" in executed and "host_results=0" in executed
    assert "adapted 1" in adapted
    # The second turn continues the first turn's history in the same workspace.
    turn_two = next(body for _, body in script.requests if "Adapt the probe." in json.dumps(body["messages"]))
    assert "probe 1" in json.dumps(turn_two["messages"])
    record = sandbox_record(run, session.box.record.name)
    assert record["purpose"] == "workspace" and record["cleanup"]["removed"] is True
    assert (session.box.directory / "workspace/nudi/workspace/probe.py").read_text().startswith("print('adapted'")
    assert {read, found, executed, adapted} <= {str(entry["data"]["content"]) for entry in transcript(session)}
    assert tree_digest(task) == original and files_with_secret(run.config.output_dir) == []


def test_investigation_retains_shell_output_beyond_the_inline_limit(tmp_path, docker_env):
    """Bounding a tool reply must leave its omitted bytes readable and retained."""
    from nudi import inspector

    script = AgentScript(
        ("execute", {"command": "python3 -c \"print('x' * 100000); print('NUDI_OUTPUT_TAIL')\""}),
        ("grep", {"pattern": "NUDI_OUTPUT_TAIL", "path": "/large_tool_results", "output_mode": "content"}),
        ("Finding", {"summary": "retained"}))

    async def main():
        async with serve(script) as base_url:
            run = inspector_run(tmp_path, base_url)
            async with inspector.investigation(run, "long-output", "Inspect the copied package.", {}) as session:
                return session, await session.ask("Run a long-output probe.", Finding)

    session, result = asyncio.run(main())
    assert result.summary == "retained"
    output, recovered = script.tool_results()
    assert len(output) < 100000 and "/large_tool_results/" in output
    assert "NUDI_OUTPUT_TAIL" in recovered
    captured, = (session.box.directory / "workspace/large_tool_results").iterdir()
    assert len(captured.read_bytes()) > sandbox.OUTPUT_LIMIT and captured.read_text().endswith("NUDI_OUTPUT_TAIL\n")


def test_captured_offload_survives_mutation_and_compaction(tmp_path, docker_env):
    """Later shell commands cannot erase bytes already advertised as retained output."""
    from nudi import inspector

    expected = b"x" * 100000 + b"\nIMMUTABLE_OFFLOAD_TAIL\n"
    digest = hashlib.sha256(expected).hexdigest()
    sessions, snapshots_before_mutation = [], []

    def overwrite():
        protected = sessions[0].box.directory / "tool-outputs" / digest
        snapshots_before_mutation.append(protected.is_file() and protected.read_bytes() == expected)
        return "execute", {"command": "printf overwritten > /large_tool_results/call_1"}

    script = AgentScript(
        ("execute", {"command": "python3 -c \"print('x' * 100000); print('IMMUTABLE_OFFLOAD_TAIL')\""}),
        overwrite,
        ("execute", {"command": "rm -f /large_tool_results/call_1"}),
        ("ls", {"path": "/nudi"}),
        "overflow",
        ("grep", {"pattern": "IMMUTABLE_OFFLOAD_TAIL", "path": "/nudi/evidence/tool-results", "output_mode": "content"}),
        ("Finding", {"summary": "recovered"}), summary="The first shell result was overwritten and deleted.")

    async def main():
        async with serve(script) as base_url:
            run = inspector_run(tmp_path, base_url)
            async with inspector.investigation(run, "offload-mutation", "Inspect.", {}) as session:
                sessions.append(session)
                return session, await session.ask("Capture and recover a long result.", Finding)

    session, result = asyncio.run(main())
    assert result.summary == "recovered"
    assert snapshots_before_mutation == [True], "The captured bytes were not protected before the next inference"
    assert (session.box.directory / "tool-outputs" / digest).read_bytes() == expected
    first = next(entry["data"] for entry in transcript(session) if entry["type"] == "tool")
    assert first["artifact"]["retained_output"] == f"tool-outputs/{digest}"
    assert first["artifact"]["sha256"] == digest
    assert "IMMUTABLE_OFFLOAD_TAIL" in script.tool_results()[-1]
    assert not (session.box.directory / "workspace/large_tool_results/call_1").exists()
    assert session.box.record.artifacts["tool_outputs"] == "tool-outputs"


def test_investigation_rejects_host_evidence_and_escaping_evidence_names(tmp_path, monkeypatch, credentials):
    """Only explicitly selected files within this run can enter the workspace."""
    from nudi import inspector

    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)
    scoped = run.config.output_dir / "trace.json"
    scoped.write_text("retained evidence")

    async def main():
        for evidence in ({"credentials.env": credentials}, {"../../outside": scoped}, {"/absolute": scoped}):
            with pytest.raises(ValueError):
                async with inspector.investigation(run, "invalid-evidence", "Inspect.", evidence):
                    pass

    asyncio.run(main())
    assert not sandboxes.running and not run.record.sandboxes


def test_workspace_reports_its_python3_requirement_before_offering_tools(tmp_path, monkeypatch, credentials):
    """The SDK's file helpers require the executable python3, not just a Python 3 runtime."""
    from nudi import inspector

    Sandboxes(monkeypatch, pythons={"python": "3"})
    run = new_run(tmp_path, monkeypatch, credentials)

    async def main():
        with pytest.raises(RuntimeError, match="python3"):
            async with inspector.investigation(run, "unsupported", "Inspect.", {}):
                pass

    asyncio.run(main())
    assert not run.record.calls
    assert sandbox_record(run, "sandbox-0000")["cleanup"]["removed"] is True


def test_workspace_retention_failure_is_explicit_and_cleanup_still_runs(tmp_path, monkeypatch, credentials):
    from nudi import inspector

    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials)

    async def main():
        with pytest.raises(RuntimeError, match="copy failed"):
            async with inspector.investigation(run, "failed-retention", "Inspect.", {}):
                sandboxes.fail["exec", "sandbox-0000"] = RuntimeError("copy failed")

    asyncio.run(main())
    record = sandbox_record(run, "sandbox-0000")
    assert record["cleanup"]["removed"] is True
    assert any(error["type"] == "WorkspaceRetentionError" for error in record["errors"])


def test_forced_compaction_keeps_searchable_history_and_accounts_every_inference(tmp_path, docker_env):
    """A provider context rejection makes the SDK compact. The evicted history is written to
    the workspace and stays searchable there and in the host transcript; the summarization
    call, like every other, has the run's route, credential, effort and cost record."""
    from nudi import inspector

    credentials = tmp_path / "credentials.env"
    credentials.write_text("XAI_API_KEY=nudi-inspector-file-key\n")
    script = AgentScript(
        ("execute", {"command": "python3 -c \"print('EARLY_RESULT_42'); print('context ' * 4000)\""}),
        ("ls", {"path": "/nudi"}),
        ("ls", {"path": "/nudi/package"}),
        ("execute", {"command": "true"}),
        "overflow",
        ("grep", {"pattern": "EARLY_RESULT_42", "path": "/conversation_history", "output_mode": "content"}),
        ("Finding", {"summary": "compacted"}),
        summary="Earlier steps listed the package.")

    async def main():
        async with serve(script) as base_url:
            run = inspector_run(tmp_path, base_url, credentials_file=credentials)
            async with inspector.investigation(run, "hack-broad", "Inspect the copied package.", {}) as session:
                return run, session, await session.ask("Investigate.", Finding)

    run, session, result = asyncio.run(main())
    assert result.summary == "compacted"
    bodies = [body for _, body in script.requests]
    summary, = [body for body in bodies if not body.get("tools")]
    assert "EARLY_RESULT_42" in json.dumps(summary["messages"])
    compacted = json.dumps(bodies[bodies.index(summary) + 1]["messages"])
    assert "EARLY_RESULT_42" not in compacted and "/conversation_history/" in compacted
    assert "EARLY_RESULT_42" in script.tool_results()[-1]
    assert {headers["Authorization"] for headers, _ in script.requests} == {"Bearer nudi-inspector-file-key"}
    assert {(body["model"], body["reasoning_effort"]) for body in bodies} == {("grok-4.7", "xhigh")}
    calls = [call for call in run.record.calls if call.episode == "hack-broad"]
    assert [(call.role, call.error is None) for call in calls] == [("inspector", True)] * 4 + [("inspector", False)] + [("inspector", True)] * 3
    assert all(call.cost is not None for call in calls if call.error is None) and run.record.unknown_cost_calls == 1
    assert run.record.known_cost == pytest.approx(sum(call.cost for call in calls if call.cost is not None))
    history, = (session.box.directory / "workspace/conversation_history").glob("*.md")
    assert "EARLY_RESULT_42" in history.read_text()
    contents = [str(entry["data"]["content"]) for entry in transcript(session)]
    assert any("EARLY_RESULT_42" in text for text in contents) and any("Earlier steps listed the package." in text for text in contents)
    assert sandbox_record(run, session.box.record.name)["cleanup"]["removed"] is True


def test_two_turn_compaction_keeps_sdk_state_and_uses_the_current_schema(tmp_path, docker_env):
    """A later ask continues the compacted SDK conversation instead of replaying its raw input."""
    from nudi import inspector

    continuation = "Continue with the followup schema."
    replayed = []

    class TwoTurnScript(AgentScript):
        async def chat(self, request):
            body = await request.json()
            if body.get("tools") and continuation in json.dumps(body["messages"]) and not replayed:
                replayed.append("FIRST_WINDOW_RESULT_42" in json.dumps(body["messages"]))
                if replayed[-1]:
                    self.steps.insert(0, "overflow")
            return await super().chat(request)

    script = TwoTurnScript(
        ("execute", {"command": "python3 -c \"print('FIRST_WINDOW_RESULT_42'); print('context ' * 4000)\""}),
        ("ls", {"path": "/nudi"}), ("ls", {"path": "/nudi/package"}),
        ("execute", {"command": "true"}), "overflow", ("Finding", {"summary": "first"}),
        ("execute", {"command": "echo SECOND_WINDOW_DONE"}),
        ("FollowupFinding", {"summary": "second", "verified": True}),
        summary="Earlier steps inspected the package.")

    async def main():
        async with serve(script) as base_url:
            run = inspector_run(tmp_path, base_url)
            async with inspector.investigation(run, "two-turn", "Inspect.", {}) as session:
                first = await session.ask("Inspect the first window.", Finding)
                exported = json.loads((session.box.directory / "state.json").read_text())
                first_event, first_id = exported["_summarization_event"], exported["_summarization_session_id"]
                second = await session.ask(continuation, FollowupFinding)
            return run, session, first, second, first_event, first_id

    run, session, first, second, first_event, first_id = asyncio.run(main())
    assert replayed == [False], "The second ask reintroduced the already-compacted raw history"
    assert sum(not body.get("tools") for _, body in script.requests) == 1
    assert first.summary == "first" and isinstance(second, FollowupFinding)
    assert second.summary == "second" and second.verified is True
    assert "SECOND_WINDOW_DONE" in script.tool_results()[-1]
    exported = json.loads((session.box.directory / "state.json").read_text())
    assert exported["_summarization_event"] == first_event
    assert exported["_summarization_session_id"] == first_id
    assert len(list((session.box.directory / "workspace/conversation_history").glob("*.md"))) == 1
    assert sum(entry["type"] == "human" and entry["data"]["content"] == continuation for entry in transcript(session)) == 1
    assert len(run.record.calls) == len(script.requests) == 9
    assert run.record.unknown_cost_calls == 1 and session.box.record.cleanup["removed"] is True


def test_cancelled_investigation_keeps_its_transcript_and_removes_the_workspace(tmp_path, docker_env):
    from nudi import inspector

    script = AgentScript(("execute", {"command": "sleep 120"}))

    async def main():
        async with serve(script) as base_url:
            run = inspector_run(tmp_path, base_url)
            sessions = []

            async def investigate():
                async with inspector.investigation(run, "hack-broad", "Inspect the copied package.", {}) as session:
                    sessions.append(session)
                    await session.ask("Investigate.", Finding)

            running = asyncio.create_task(investigate())

            async def sleeping():
                while not (sessions and any("sleep 120" in entry["argv"][-1] for entry in sessions[0].box.record.commands)):
                    await asyncio.sleep(.1)

            await asyncio.wait_for(sleeping(), 60)
            running.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(running, 60)
            return run, sessions[0]

    run, session = asyncio.run(main())
    record = sandbox_record(run, session.box.record.name)
    assert record["cancelled"] is True and record["cleanup"]["removed"] is True
    sleep, = [entry for entry in record["commands"] if "sleep 120" in entry["argv"][-1]]
    assert sleep["exit_code"] != 0 and sleep["interrupted"] is True
    retained = transcript(session)
    assert any(entry["type"] == "human" and entry["data"]["content"] == "Investigate." for entry in retained)
    assert any(call["args"] == {"command": "sleep 120"} for entry in retained if entry["type"] == "ai"
               for call in entry["data"]["tool_calls"])


def recording_native(monkeypatch) -> list[str]:
    native = []

    async def native_episode(config, queue, **kwargs):
        native.append(config.output_dir.name)
        return SimpleNamespace()

    monkeypatch.setattr(workflow, "run_episode", native_episode)
    return native


@pytest.mark.parametrize("experiment", ["probe", "check", "attacker"])
def test_held_workspace_refuses_another_container_promptly_at_concurrency_one(tmp_path, monkeypatch, credentials, experiment):
    """At concurrency one the held workspace fills the run: a fresh experiment is refused at
    once, never queued behind the workspace, and admitted after the workspace is removed."""
    from nudi import inspector

    Sandboxes(monkeypatch)
    native = recording_native(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(2, 1024))
    assert run.record.capacity.concurrency == 1

    async def start():
        if experiment == "attacker":
            await workflow.run_role_episode(run, "attacker")
        else:
            async with sandbox.sandbox(run, experiment):
                pass

    async def main():
        async with inspector.investigation(run, "hack-broad", "Inspect the copied package.", {}):
            with pytest.raises(workflow.CapacityUnavailable):
                await asyncio.wait_for(start(), 5)
        await start()

    asyncio.run(main())
    workspace, *later = run.record.sandboxes
    assert sandbox_record(run, workspace)["purpose"] == "workspace"
    assert all(sandbox_record(run, name)["cleanup"]["removed"] is True for name in run.record.sandboxes)
    assert (native, later) == ((["0000-attacker"], []) if experiment == "attacker" else ([], ["sandbox-0001"]))


def test_workspace_and_one_experiment_fill_concurrency_two_without_overcommit(tmp_path, monkeypatch, credentials):
    from nudi import inspector

    sandboxes = Sandboxes(monkeypatch)
    native = recording_native(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(3, 1200))
    assert run.record.capacity.concurrency == 2

    async def main():
        async with inspector.investigation(run, "hack-broad", "Inspect the copied package.", {}):
            async with sandbox.sandbox(run, "check"):
                assert len(sandboxes.running) == 2
                with pytest.raises(workflow.CapacityUnavailable):
                    await asyncio.wait_for(workflow.run_role_episode(run, "attacker"), 5)
                with pytest.raises(workflow.CapacityUnavailable):
                    async with sandbox.sandbox(run, "probe"):
                        pass
            async with sandbox.sandbox(run, "probe"):
                assert len(sandboxes.running) == 2

    asyncio.run(main())
    assert native == [] and run.record.episodes == [] and len(run.record.sandboxes) == 3


# The measured exe.dev VM: Docker reports 2 CPUs and 3909 MiB.
MEASURED_VM = (2, 3909)


def resource_task(tmp_path, environment="cpus = 1\nmemory_mb = 2048\n") -> Path:
    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    toml = task / "task.toml"
    toml.write_text(toml.read_text().replace("cpus = 1\nmemory_mb = 512\n", environment))
    return task


def limits(run, name) -> dict:
    environment = sandbox_record(run, name)["environment"]
    return {"cpus": environment["cpus"], "memory_mb": environment["memory_mb"]}


def test_workspace_and_one_full_size_experiment_fit_the_measured_two_cpu_vm(tmp_path, monkeypatch, credentials):
    """A 1-CPU, 2 GiB task gives concurrency one on the measured VM. The held workspace is
    limited to 512 MiB, so one full-size experiment fits beside it within memory headroom
    and the physical CPUs, with a warning that no CPU headroom remains. Any further
    container is refused, and the task's declaration and files stay unchanged."""
    sandboxes = Sandboxes(monkeypatch)
    native = recording_native(monkeypatch)
    task = resource_task(tmp_path)
    digest, declaration = tree_digest(task), (task / "task.toml").read_text()
    run = new_run(tmp_path, monkeypatch, credentials, capacity=MEASURED_VM, task_dir=task)
    assert (run.record.capacity.concurrency, run.record.capacity.workspace_memory_mb) == (1, 512)

    async def main():
        async with inspector.investigation(run, "hack-broad", "Inspect the copied package.", {}):
            async with sandbox.sandbox(run, "check"):
                assert len(sandboxes.running) == 2
                with pytest.raises(workflow.CapacityUnavailable):
                    async with sandbox.sandbox(run, "probe"):
                        pass
                with pytest.raises(workflow.CapacityUnavailable):
                    await asyncio.wait_for(workflow.run_role_episode(run, "attacker"), 5)

    asyncio.run(main())
    assert native == [] and run.record.episodes == []
    workspace, check = run.record.sandboxes
    assert limits(run, workspace) == {"cpus": 1, "memory_mb": 512}
    assert limits(run, check) == {"cpus": 1, "memory_mb": 2048}
    # Harbor's resource override limits the workspace only; the experiment keeps the declaration.
    assert sandboxes.environments[workspace].config["override_memory_mb"] == 512
    assert sandboxes.environments[check].config["override_memory_mb"] is None
    assert len([warning for warning in run.record.warnings if "no CPU headroom" in warning]) == 1
    assert tree_digest(task) == digest and (task / "task.toml").read_text() == declaration
    assert all(sandbox_record(run, name)["copy_digest"] == digest for name in (workspace, check))
    assert all(sandbox_record(run, name)["cleanup"]["removed"] is True for name in (workspace, check))


@pytest.mark.parametrize(("held", "experiment"), [("check", "probe"), ("workspace", "attacker"), ("check", "attacker")])
def test_cpu_exception_admits_only_a_workspace_and_one_fresh_experiment(tmp_path, monkeypatch, credentials, held, experiment):
    Sandboxes(monkeypatch)
    native = recording_native(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=MEASURED_VM, task_dir=resource_task(tmp_path))

    async def main():
        async with sandbox.sandbox(run, held):
            with pytest.raises(workflow.CapacityUnavailable):
                if experiment == "attacker":
                    await asyncio.wait_for(workflow.run_role_episode(run, "attacker"), 5)
                else:
                    async with sandbox.sandbox(run, experiment):
                        pass

    asyncio.run(main())
    assert native == [] and len(run.record.sandboxes) == 1
    assert not any("no CPU headroom" in warning for warning in run.record.warnings)


@pytest.mark.parametrize(("memory_mb", "fits"), [(1024, True), (1600, False), (3518, False)])
def test_explicit_workspace_memory_is_enforced_and_admitted_only_within_memory_headroom(
        tmp_path, monkeypatch, credentials, memory_mb, fits):
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=MEASURED_VM, task_dir=resource_task(tmp_path),
                  workspace_memory_mb=memory_mb)

    async def main():
        async with sandbox.sandbox(run, "workspace"):
            with pytest.raises(workflow.CapacityUnavailable) if not fits else contextlib.nullcontext():
                async with sandbox.sandbox(run, "check"):
                    pass

    asyncio.run(main())
    assert limits(run, "sandbox-0000") == {"cpus": 1, "memory_mb": memory_mb}
    assert sandboxes.environments["sandbox-0000"].config["override_memory_mb"] == memory_mb
    assert len(run.record.sandboxes) == (2 if fits else 1)


@pytest.mark.parametrize("environment", ["cpus = 1\n", "memory_mb = 2048\n", ""])
def test_undeclared_resources_keep_one_container_while_a_workspace_is_held(tmp_path, monkeypatch, credentials, environment):
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(8, 16384), task_dir=resource_task(tmp_path, environment))
    assert run.record.capacity.concurrency == 1

    async def main():
        async with sandbox.sandbox(run, "workspace"):
            with pytest.raises(workflow.CapacityUnavailable):
                async with sandbox.sandbox(run, "check"):
                    pass

    asyncio.run(main())
    assert run.record.sandboxes == ["sandbox-0000"]
    assert sandbox_record(run, "sandbox-0000")["environment"]["memory_mb"] == 512
    assert sandboxes.environments["sandbox-0000"].config["override_memory_mb"] == 512


def test_unverified_workspace_removal_blocks_the_paired_experiment(tmp_path, monkeypatch, credentials):
    from nudi.records import InfrastructureAbort

    sandboxes = Sandboxes(monkeypatch)
    sandboxes.remaining.add("sandbox-0000")
    run = new_run(tmp_path, monkeypatch, credentials, capacity=MEASURED_VM, task_dir=resource_task(tmp_path))

    async def main():
        async with sandbox.sandbox(run, "workspace"):
            pass
        with pytest.raises(InfrastructureAbort, match="sandbox-0000"):
            async with sandbox.sandbox(run, "check"):
                pass

    asyncio.run(main())
    assert run.record.sandboxes == ["sandbox-0000"] and len(sandboxes.environments) == 1


def test_cancelled_workspace_and_experiment_release_both_containers(tmp_path, monkeypatch, credentials):
    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=MEASURED_VM, task_dir=resource_task(tmp_path))

    async def pair(entered=None):
        async with inspector.investigation(run, "hack-broad", "Inspect the copied package.", {}):
            async with sandbox.sandbox(run, "check"):
                if entered is not None:
                    entered.set()
                    await asyncio.Event().wait()

    async def main():
        entered = asyncio.Event()
        running = asyncio.create_task(pair(entered))
        await asyncio.wait([running, asyncio.create_task(entered.wait())], return_when=asyncio.FIRST_COMPLETED)
        assert entered.is_set(), running.exception()
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
        assert sandboxes.running == set()
        await pair()

    asyncio.run(main())
    records = [sandbox_record(run, name) for name in run.record.sandboxes]
    assert [(record["purpose"], record["cancelled"]) for record in records] == [
        ("workspace", True), ("check", True), ("workspace", False), ("check", False)]
    assert all(record["cleanup"]["removed"] is True for record in records)


def test_native_episode_in_flight_refuses_the_workspace_promptly_at_concurrency_one(tmp_path, monkeypatch, credentials):
    from nudi import inspector

    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, capacity=(2, 1024))

    async def main():
        started, release = asyncio.Event(), asyncio.Event()

        async def native_episode(config, queue, **kwargs):
            started.set()
            await release.wait()
            return SimpleNamespace()

        monkeypatch.setattr(workflow, "run_episode", native_episode)

        async def enter():
            async with inspector.investigation(run, "hack-broad", "Inspect the copied package.", {}):
                pass

        running = asyncio.create_task(workflow.run_role_episode(run, "attacker"))
        await started.wait()
        with pytest.raises(workflow.CapacityUnavailable):
            await asyncio.wait_for(enter(), 5)
        release.set()
        await running
        await enter()

    asyncio.run(main())
    assert run.record.episodes == ["0000-attacker"] and len(run.record.sandboxes) == 1 and sandboxes.running == set()


def support(source, *, basis="explicit", rationale="The cited task text states this rule."):
    return {"basis": basis, "sources": [source], "rationale": rationale, "uncertainty": []}


def public_probe(category="rejected_valid", **fields):
    requirement = {"episode": None, "path": "instruction.md", "excerpt": "leading zeros are permitted"}
    return {"category": category, "case": "leading zeros", "location": "/app/answer.txt",
            "capture_point": "verification_start", "timing": "The task explicitly applies at verification start.",
            "requirement": requirement, "scoring": requirement,
            "setup_program": "mkdir -p /app; echo 042 > /app/answer.txt; touch /tmp/probe-marker",
            "program": '''import base64, hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs['submission'])
value = int(base64.b64decode(state['base64']).strip()) if state['exists'] else None
print(json.dumps({'input_sha256': {k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()},
                  'observations': {'answer': value}, 'results': {'deserved': int(value == 42)}}))
''', **fields}


def public_claim(probe, **fields):
    return {"mechanism": probe["category"], "interpretation": "The decimal integer is 42; full credit follows from the task.",
            "derivation": {"observations": ["answer"], "minimum": "deserved", "maximum": "deserved", "validity": "supported"},
            "requirement_support": support(probe["requirement"]), "scoring_support": support(probe["scoring"], basis="inferred"), **fields}


def public_task(tmp_path):
    task = tmp_path / "task"
    shutil.copytree(CONTRACT_TASK, task)
    (task / "instruction.md").write_text("At verification start, /app/answer.txt must contain the decimal integer 42; leading zeros are permitted. Full credit is 1.\n")
    config = task / "task.toml"
    config.write_text('artifacts = ["/app/answer.txt", "/app/explanation.txt"]\n' + config.read_text())
    return task


def test_public_inspector_measures_then_interprets_fresh_experiments_and_retains_history(tmp_path, docker_env):
    """Workspace mutations and earlier setups cannot change a fresh copied grading result."""
    task = public_task(tmp_path)
    digest = tree_digest(task)
    probe = public_probe()
    second = public_probe(category="accepted_invalid", setup_program="test ! -e /tmp/probe-marker || exit 9; mkdir -p /app; echo 42 > /app/answer.txt")
    script = AgentScript(
        ("execute", {"command": "mkdir -p /app; echo 1337 > /app/answer.txt"}),
        ("run_experiment", {"probe": probe}),
        ("interpret_experiment", {"experiment": "experiment-0000", "claim": public_claim(probe)}),
        ("run_experiment", {"probe": second}),
        ("interpret_experiment", {"experiment": "experiment-0001", "claim": public_claim(second)}),
        ("InspectionSummary", {"applicability": {**package_applicability("rejected_valid"), **package_applicability("accepted_invalid")},
                               "completed": ["rejected_valid", "accepted_invalid"]}),
    )

    async def main():
        async with serve(script) as base:
            run = inspector_run(tmp_path, base, task)
            result = await checks.inspect_grader(run, [], categories=["rejected_valid", "accepted_invalid"], focused_attempts=0)
            return run, result

    run, result = asyncio.run(main())
    assert [item.outcome for item in result.assessments] == ["rejected_valid", "legitimate"]
    assert result.categories == {"rejected_valid": "evidenced_issue", "accepted_invalid": "no_evidenced_issue"}
    assert result.status == "complete" and run.record.episodes == []
    measured = [json.loads(item) for item in script.tool_results() if item.startswith('{')]
    assert measured[0]["check"]["exit_code"] == 0 and measured[0]["rewards"]["reward"] == 0
    assert measured[2]["rewards"]["reward"] == 1
    artifacts = result.artifacts["grader-broad"]
    raw = (run.config.output_dir / artifacts["transcript"]).read_text()
    assert "run_experiment" in raw and "interpret_experiment" in raw and "deserved" in raw
    assert all(sandbox_record(run, name)["cleanup"]["removed"] for name in run.record.sandboxes)
    assert tree_digest(task) == digest and files_with_secret(run.config.output_dir) == []


def test_public_tool_duplicates_and_provider_failure_keep_three_focused_attempts_incomplete(tmp_path, docker_env):
    task = public_task(tmp_path)
    probe = public_probe()
    summary = {"applicability": package_applicability("rejected_valid"), "completed": ["rejected_valid"]}
    script = AgentScript(
        ("read_file", {"file_path": "/nudi/package/instruction.md"}), ("InspectionSummary", summary),
        ("execute", {"command": "echo tool-one"}), ("execute", {"command": "echo tool-two"}),
        ("run_experiment", {"probe": probe}), ("run_experiment", {"probe": {**probe, "case": "renamed"}}),
        ("InspectionSummary", summary), "message_refusal",
        ("inspection_status", {}), ("InspectionSummary", summary),
    )

    async def main():
        async with serve(script) as base:
            run = inspector_run(tmp_path, base, task)
            result = await checks.inspect_grader(run, [], categories=["rejected_valid"], focused_attempts=3)
            return run, result

    run, result = asyncio.run(main())
    assert len(result.attempts) == 4 and [item.number for item in result.attempts] == [0, 1, 2, 3]
    assert result.status == "partial" and result.categories["rejected_valid"] == "unknown"
    assert result.attempts[2].status == "refused"
    assert len([name for name in run.record.sandboxes if sandbox_record(run, name)["purpose"] == "probe"]) == 1
    assert "duplicate_case" in json.dumps(script.tool_results())
    assert "refused" in script.tool_results()[-1], "status feedback names the prior failed attempt"
    assert not any("Prior broad grader inspector investigation" in str(body["messages"]) for _, body in script.requests), "focused attempts fork broad"
    assert sum('"task":' in str(item["data"].get("content", "")) for item in map(json.loads,
               (run.config.output_dir / result.artifacts["grader-rejected_valid"]["transcript"]).read_text().splitlines())) == 1


def test_public_inspector_capacity_one_returns_raw_incomplete_feedback(tmp_path, docker_env):
    task = public_task(tmp_path)
    probe = public_probe()
    script = AgentScript(("run_experiment", {"probe": probe}),
                         ("InspectionSummary", {"applicability": package_applicability("rejected_valid"), "completed": ["rejected_valid"]}))

    async def main():
        async with serve(script) as base:
            run = inspector_run(tmp_path, base, task)
            # Admission counts recorded limits: one Docker CPU leaves no room beside the workspace.
            run.record.capacity.concurrency = run.record.capacity.docker_cpus = 1
            run.save()
            result = await asyncio.wait_for(checks.inspect_grader(run, [], categories=["rejected_valid"], focused_attempts=0), 60)
            return run, result

    run, result = asyncio.run(main())
    assert result.status == "partial" and result.categories["rejected_valid"] == "unknown"
    assert "CapacityUnavailable" in json.dumps(script.tool_results())
    assert len(run.record.sandboxes) == 1 and sandbox_record(run, run.record.sandboxes[0])["cleanup"]["removed"]


def test_public_inspector_measures_same_turn_experiments_on_the_measured_vm(tmp_path, monkeypatch, docker_env):
    """Room for the workspace and one 2 GiB experiment suffices for two requested together."""
    monkeypatch.setattr(workflow, "docker_capacity", lambda: MEASURED_VM)
    task = public_task(tmp_path)
    toml = task / "task.toml"
    toml.write_text(toml.read_text().replace("cpus = 1\nmemory_mb = 512\n", "cpus = 1\nmemory_mb = 2048\n"))
    second = public_probe(category="accepted_invalid", setup_program="mkdir -p /app; echo 42 > /app/answer.txt")
    script = AgentScript([("run_experiment", {"probe": public_probe()}), ("run_experiment", {"probe": second})],
                         ("InspectionSummary", {"applicability": {**package_applicability("rejected_valid"), **package_applicability("accepted_invalid")},
                                                "completed": []}))

    async def main():
        async with serve(script) as base:
            run = inspector_run(tmp_path, base, task)
            result = await asyncio.wait_for(checks.inspect_grader(run, [], categories=["rejected_valid", "accepted_invalid"], focused_attempts=0), 300)
            return run, result

    run, result = asyncio.run(main())
    assert run.record.capacity.concurrency == 1 and "CapacityUnavailable" not in json.dumps(script.tool_results())
    assert [item["status"] for item in result.experiments] == ["measured", "measured"]
    measured = [json.loads(item) for item in script.tool_results()]
    assert [(item["check"]["exit_code"], item["rewards"]["reward"]) for item in measured] == [(0, 0), (0, 1)]
    workspace, *experiments = run.record.sandboxes
    # Each experiment uses a setup probe and then a check, both full size.
    assert limits(run, workspace)["memory_mb"] == 512 and [limits(run, name)["memory_mb"] for name in experiments] == [2048] * 4
    assert all(sandbox_record(run, name)["cleanup"]["removed"] for name in run.record.sandboxes)


@pytest.mark.parametrize("setup_failure", ["truncated", "nonzero"])
def test_truncated_setup_output_never_closes_public_coverage(tmp_path, monkeypatch, credentials, unit_sandboxes, setup_failure):
    """A later valid check cannot recover setup output the collector never retained."""
    original = SandboxEnvironment.exec

    async def truncated(environment, command, **kwargs):
        if sandbox.SETUP in command:
            return ExecResult(stdout="RAW_SETUP_FAILURE\n" + ("x" * sandbox.OUTPUT_LIMIT if setup_failure == "truncated" else ""),
                              stderr="", return_code=0 if setup_failure == "truncated" else 7)
        return await original(environment, command, **kwargs)

    monkeypatch.setattr(SandboxEnvironment, "exec", truncated)
    requests = inspector_responses(monkeypatch, [{"probes": [setup_probe()], "applicability": package_applicability()}, VIOLATED])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))
    # A nonzero setup exit the session continued past, with a valid check, is a limit only.
    assert (result.status, result.attempts[0].status) == (("partial", "unobservable") if setup_failure == "truncated" else ("complete", "evidenced_issue"))
    assert result.assessments[0].outcome == "accepted_invalid", "independent measured evidence is still retained"
    assert any("setup" in limit for limit in result.limits)
    raw = (run.config.output_dir / result.artifacts["hack-broad"]["transcript"]).read_text()
    assert "RAW_SETUP_FAILURE" in raw and "truncated" in raw
    assert requests[1]["messages"][-1]["content"], "the same Inspector receives raw measured feedback"


def test_focused_session_can_retrieve_captured_broad_tool_output(tmp_path, docker_env):
    """Broad history references stay usable after its owning workspace is removed."""
    script = AgentScript(
        ("execute", {"command": "python3 -c \"print('x' * 100000); print('BROAD_OUTPUT_TAIL')\""}),
        ("InspectionSummary", {"applicability": package_applicability(), "completed": []}),
        ("grep", {"pattern": "BROAD_OUTPUT_TAIL", "path": "/nudi/evidence/tool-results", "output_mode": "content"}),
        ("InspectionSummary", {"applicability": package_applicability(), "completed": ["package_oracles"]}),
    )

    async def main():
        async with serve(script) as base:
            run = inspector_run(tmp_path, base)
            result = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1)
            return run, result

    run, result = asyncio.run(main())
    assert "BROAD_OUTPUT_TAIL" in script.tool_results()[-1]
    broad = run.config.output_dir / result.artifacts["hack-broad"]["tool_outputs"]
    focused = run.config.output_dir / result.artifacts["hack-package_oracles"]["tool_outputs"]
    source, = broad.iterdir()
    assert (focused / source.name).read_bytes() == source.read_bytes()
    assert source.read_text().endswith("BROAD_OUTPUT_TAIL\n")


def test_real_sdk_tool_infrastructure_abort_stops_before_focused_retry(tmp_path, monkeypatch, credentials):
    from nudi.records import InfrastructureAbort

    Sandboxes(monkeypatch)
    script = AgentScript(("run_experiment", {"probe": setup_probe()}),
                         ("InspectionSummary", {"completed": []}))

    async def abort(run, probe):
        raise InfrastructureAbort("fatal experiment infrastructure")

    monkeypatch.setattr(checks, "measure_experiment", abort)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path),
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            with pytest.raises(InfrastructureAbort, match="fatal experiment infrastructure"):
                await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1)
            return run

    run = asyncio.run(main())
    result = checks.InspectionResult.model_validate_json((run.config.output_dir / "inspection-hack.json").read_text())
    assert len(result.attempts) == len(script.requests) == 1
    assert result.attempts[0].status == "tool_failure" and result.status == "partial"
    assert all(sandbox_record(run, name)["cleanup"]["removed"] for name in run.record.sandboxes)


def test_inspector_searches_wait_120_seconds(monkeypatch):
    """The Inspector's grep and glob get 120 s; a timeout still returns the SDK's error text."""
    from deepagents.backends import sandbox as sdk_sandbox
    from deepagents.middleware import filesystem as sdk_filesystem

    waits, wait_for = [], asyncio.wait_for

    async def short_wait(awaitable, timeout):
        waits.append(timeout)
        return await wait_for(awaitable, .01)

    class Box:
        async def exec(self, *args, **kwargs):
            await asyncio.sleep(.1)

    monkeypatch.setattr(sdk_sandbox.asyncio, "wait_for", short_wait)
    backend = inspector.HarborBackend(Box())

    async def main():
        return await backend.agrep("x", "/"), await backend.aglob("*", "/")

    grep, glob = asyncio.run(main())
    assert waits == [120, 120] and sdk_filesystem.GLOB_TIMEOUT == 120
    assert grep.error.startswith("Error: grep timed out after 120s") and glob.error.startswith("Error: glob timed out after 120s")
    assert len(backend.interrupted) == 2


@pytest.mark.parametrize("outcome", ["completed", "open", "refused"])
def test_tool_error_the_session_recovers_from_is_a_limit(tmp_path, monkeypatch, credentials, outcome):
    """A search timeout followed by a valid response that completes its category fails nothing.
    When the response leaves the category open, the attempt is still a tool failure; a refusal
    keeps its own status, and the grep error stays in the report."""
    from deepagents.backends import sandbox as sdk_sandbox

    Sandboxes(monkeypatch)
    original = SandboxEnvironment.exec

    async def slow(environment, command, **kwargs):
        if "NUDI_SLOW_SEARCH" in command:
            await asyncio.sleep(.5)
        return await original(environment, command, **kwargs)

    monkeypatch.setattr(SandboxEnvironment, "exec", slow)
    monkeypatch.setattr(sdk_sandbox, "ASYNC_GREP_TIMEOUT", .1)
    script = AgentScript(("grep", {"pattern": "NUDI_SLOW_SEARCH", "path": "/"}), ("grep", {"pattern": "42", "path": "/nudi/evidence"}),
                         ("InspectionSummary", {"applicability": package_applicability(), "completed": ["package_oracles"] if outcome == "completed" else [],
                                                "refusal": "cannot finish this inspection" if outcome == "refused" else None}))

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path),
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            return await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)

    result = asyncio.run(main())
    assert "grep timed out" in script.tool_results()[0]
    attempt, = result.attempts
    if outcome == "completed":
        assert (attempt.status, attempt.error) == ("no_evidenced_issue", None)
        assert result.categories == {"package_oracles": "no_evidenced_issue"} and result.status == "complete"
        assert any("hack-broad" in limit and "grep timed out" in limit for limit in result.limits)
    elif outcome == "open":
        assert attempt.status == "tool_failure" and "grep timed out" in attempt.error
        assert result.categories == {"package_oracles": "unknown"} and result.status == "partial"
    else:
        assert (attempt.status, attempt.error) == ("model_inability", "cannot finish this inspection")
        assert result.categories == {"package_oracles": "unknown"} and result.status == "partial"
        from nudi import report
        warnings = []
        public = report.inspection("hack", result, warnings)
        assert any("grep timed out" in text for text in public["limits"] + warnings)


@pytest.mark.parametrize("repeated", [True, False])
def test_truncated_checker_output_stays_unobservable(tmp_path, monkeypatch, credentials, unit_sandboxes, repeated):
    """Truncated checker output fails its category, whether a repeat then evidences the issue
    or the response completes the category."""
    no_native_actor(monkeypatch)
    truncating = setup_probe(category="accepted_invalid", program=f"print('x' * {sandbox.OUTPUT_LIMIT + 1})\n")
    inspector_responses(monkeypatch, [{"probes": [truncating] + [setup_probe(category="accepted_invalid")] * repeated,
                                       "applicability": package_applicability("accepted_invalid")}] + [VIOLATED] * repeated)
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_grader(run, [], categories=["accepted_invalid"], focused_attempts=0))
    assert [check.exit_code for check in run.record.checks] == [125, 0][:1 + repeated]
    assert (result.status, result.attempts[0].status) == ("partial", "unobservable")
    assert result.categories["accepted_invalid"] == ("evidenced_issue" if repeated else "unknown")
    assert any("experiment-0000" in limit and "truncated" in limit for limit in result.limits)


def test_failed_then_repeated_experiment_settles_on_its_evidence(tmp_path, monkeypatch, credentials, unit_sandboxes):
    """A failed checker the same session repeats successfully leaves a limit, not a failure."""
    no_native_actor(monkeypatch)
    inspector_responses(monkeypatch, [
        {"probes": [setup_probe(category="accepted_invalid", program="raise SystemExit(3)\n"), setup_probe(category="accepted_invalid")],
         "applicability": package_applicability("accepted_invalid")}, VIOLATED,
    ])
    run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path))
    result = asyncio.run(checks.inspect_grader(run, [], categories=["accepted_invalid"], focused_attempts=0))
    assert [check.exit_code for check in run.record.checks] == [3, 0]
    assert [(attempt.status, attempt.error) for attempt in result.attempts] == [("evidenced_issue", None)]
    assert result.categories == {"accepted_invalid": "evidenced_issue"} and result.status == "complete"
    assert any("experiment-0000" in limit and "check failed" in limit for limit in result.limits)


@pytest.mark.parametrize("first", ["measured", "failed"])
def test_real_sdk_same_turn_experiments_run_in_turn_beside_other_tools(tmp_path, monkeypatch, credentials, first):
    """On the measured VM the workspace leaves room for one full-size experiment. Experiments
    requested together run one after another, each admitted when it starts, while other
    tools proceed; a recoverable failure releases the next experiment."""
    sandboxes = Sandboxes(monkeypatch)
    release = sandboxes.blocked["sandbox-0001"] = asyncio.Event()
    if first == "failed":
        sandboxes.fail[("start", "sandbox-0001")] = RuntimeError("scripted start failure")
    task = resource_task(tmp_path)
    (task / "instruction.md").write_text("Write the number 42 to /app/answer.txt. " + EXPLANATION + "\n")
    script = AgentScript([("run_experiment", {"probe": setup_probe(case="first")}),
                          ("run_experiment", {"probe": setup_probe(case="second", setup_program=SETUP_PROGRAM + "true\n")}),
                          ("execute", {"command": "echo other-tool"})],
                         ("InspectionSummary", {"completed": []}))

    def executed(name, text):
        return any(event[:2] == ("exec", name) and text in event[2] for event in sandboxes.events)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=MEASURED_VM, task_dir=task,
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            inspecting = asyncio.create_task(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0))

            async def other_tool_ran_while_first_held():
                while not executed("sandbox-0000", "other-tool") or (first == "measured" and not executed("sandbox-0001", sandbox.SETUP)):
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(other_tool_ran_while_first_held(), 20)
            saved = checks.InspectionResult.model_validate_json((run.config.output_dir / "inspection-hack.json").read_text())
            release.set()
            return run, saved.experiments, await asyncio.wait_for(inspecting, 20)

    run, started, result = asyncio.run(main())
    if first == "measured":
        assert [item["case"] for item in started] == ["first"], "the second experiment started while the first held its container"
    running, peak = set(), 0
    for action, name, *_ in sandboxes.events:
        if action in ("start", "stop"):
            (running.add if action == "start" else running.discard)(name)
            peak = max(peak, len(running))
    assert peak == 2, "experiments overlapped beside the workspace"
    assert "CapacityUnavailable" not in json.dumps(script.tool_results())
    assert [item["status"] == "measured" for item in result.experiments] == [first == "measured", True]
    assert all(sandbox_record(run, name)["cleanup"]["removed"] for name in run.record.sandboxes)


@pytest.mark.parametrize("interruption", ["cancelled", "fatal"])
def test_real_sdk_interruption_joins_running_and_waiting_experiments_before_return(tmp_path, monkeypatch, credentials, interruption):
    """Caller cancellation, or a fatal failure of the running experiment, stops the experiment
    waiting its turn before it starts, and joins the running one before the caller returns."""
    from nudi.records import InfrastructureAbort

    sandboxes = Sandboxes(monkeypatch)
    script = AgentScript([("run_experiment", {"probe": setup_probe(case=kind, setup_program=kind)}) for kind in ("running", "waiting")],
                         ("InspectionSummary", {"completed": []}))

    async def main():
        started, release, finished, measured = asyncio.Event(), asyncio.Event(), asyncio.Event(), []

        async def measure(run, probe):
            measured.append(probe["case"])
            try:
                async with sandbox.sandbox(run, "probe"):
                    started.set()
                    if interruption == "fatal":
                        raise InfrastructureAbort("running experiment infrastructure failure")
                    await release.wait()
            finally:
                run.record.warnings.append(f"{probe['case']} experiment finished cleanup")
                run.save()
                finished.set()

        monkeypatch.setattr(checks, "measure_experiment", measure)
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=(4, 4096), task_dir=explained_task(tmp_path),
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            inspecting = asyncio.create_task(checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=1))
            await asyncio.wait_for(started.wait(), 20)
            if interruption == "cancelled":
                inspecting.cancel()
            with pytest.raises(asyncio.CancelledError if interruption == "cancelled" else InfrastructureAbort):
                await asyncio.wait_for(inspecting, 20)
            finished_at_return, running_at_return = finished.is_set(), set(sandboxes.running)
            before = {str(path.relative_to(run.config.output_dir)): path.read_bytes()
                      for path in run.config.output_dir.rglob("*") if path.is_file()}
            release.set()
            await asyncio.sleep(0.05)
            after = {str(path.relative_to(run.config.output_dir)): path.read_bytes()
                     for path in run.config.output_dir.rglob("*") if path.is_file()}
            return run, measured, finished_at_return, running_at_return, before, after

    run, measured, finished_at_return, running_at_return, before, after = asyncio.run(main())
    assert measured == ["running"], "the waiting experiment started after the turn was interrupted"
    assert finished_at_return and not running_at_return, "an admitted experiment survived caller return"
    assert before == after, "owned records changed after caller return"
    assert len(script.requests) == 1 and run.record.sandboxes == ["sandbox-0000", "sandbox-0001"]
    stopped = [event[1] for event in sandboxes.events if event[0] == "stop"]
    assert stopped.index("sandbox-0001") < stopped.index("sandbox-0000"), "experiment cleanup followed workspace teardown"
    assert all(sandbox_record(run, name)["cleanup"]["removed"] for name in run.record.sandboxes)
