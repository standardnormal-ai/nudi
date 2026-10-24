"""Inspector investigations use native episodes and retained state, never model verdicts."""

import asyncio
import base64
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import pytest
from aiohttp import web

from nudi import workflow
from nudi.assessment import assess
from nudi.records import Assessment, Claim, Derivation, ModelConfig, Observation, RunConfig
from test_limits import credentials, new_run
from test_runner import CONTRACT_TASK, TerminusScript, docker_env, serve, tree_digest  # noqa: F401


CHECKER = '''import hashlib, json, sys
inputs = json.load(sys.stdin)
state = json.loads(inputs["submission"])
exists = int(state["exists"])
print(json.dumps({"input_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k,v in inputs.items()}, "observations": {"exists": exists}, "results": {"deserved": exists}}))
'''


def test_native_absence_capture_and_isolated_check_preserve_timing_limit(monkeypatch):
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
            run = workflow.start_run(RunConfig(task_dir=task, output_dir=root / "run", models={"inspector": model}), frozenset({"inspector"}))
            result = await workflow.run_role_episode(run, "inspector", capture_locations=["/app/explanation.txt"])
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
            assert len(run.record.episodes) == 2, "an unsupported capture must not launch a substitute episode"
            assert tree_digest(task) == original
            assert all(call.role == "inspector" for call in run.record.calls)
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
            late_run = workflow.start_run(RunConfig(task_dir=later_task, output_dir=root / "later-run", models={"inspector": model}), frozenset({"inspector"}))
            later = await workflow.run_role_episode(late_run, "inspector", capture_locations=["/app/answer.txt"])
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

    monkeypatch.setenv("XAI_API_KEY", "nudi-local-key")
    with tempfile.TemporaryDirectory(prefix="nudi-native-") as directory:
        asyncio.run(main(Path(directory).resolve()))


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
            run = workflow.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run", models={"inspector": model}), frozenset({"inspector"}))
            await workflow.run_role_episode(run, "inspector", capture_locations=["/app/link/probe.bin", "/app/answer.txt"])
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
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    async def chat(self, request):
        body = await request.json()
        self.requests.append(body)
        response = next(self.responses)
        response = dict(response)
        context = json.loads(body["messages"][-1]["content"])
        if context.get("phase") == "broad" and "applicability" not in response:
            response["applicability"] = {category: {"status": "applicable", "facts": {"terminal": True}, "reason": "Native terminal permits this investigation."} for category in context["categories"]}
        return web.json_response({"id": "inspection", "object": "chat.completion", "created": 0,
                                  "model": body["model"], "choices": [{"index": 0, "finish_reason": "stop",
                                  "message": {"role": "assistant", "content": json.dumps(response)}}],
                                  "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})


def test_broad_then_three_focused_attempts_keep_history_and_new_contexts(tmp_path, monkeypatch, credentials):
    from nudi import checks

    script = InspectorScript([{"probes": []}] * 7)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            result = await checks.inspect_hacks(run, categories=["package_oracles", "fabricated_answers"])
            assert result.status == "complete"
            assert [attempt.phase for attempt in result.attempts] == ["broad"] + ["focused"] * 6
            assert [attempt.category for attempt in result.attempts[1:]] == ["package_oracles"] * 3 + ["fabricated_answers"] * 3
            lengths = [len(request["messages"]) for request in script.requests]
            assert lengths == [2, 2, 4, 6, 2, 4, 6]
            assert "package_oracles" not in script.requests[4]["messages"][-1]["content"]
            assert len(run.record.calls) == 7
            assert run.record.episodes == []

    asyncio.run(main())


def test_candidate_continues_until_evidence_and_only_stops_its_category(tmp_path, monkeypatch, credentials):
    from nudi import checks

    probe = {"category": "package_oracles", "case": "one"}
    script = InspectorScript([{"probes": [probe]}, {"probes": [{**probe, "case": "two"}]}, {"probes": []}])
    outcomes = iter(["unknown", "accepted_invalid"])

    async def investigate(run, candidate, session):
        return Assessment(claim=Claim(mechanism="candidate", episode="case"), outcome=next(outcomes))

    monkeypatch.setattr(checks, "investigate", investigate)

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            result = await checks.inspect_hacks(run, categories=["package_oracles", "fabricated_answers"], focused_attempts=1)
            assert len(result.attempts) == 3
            assert [assessment.outcome for assessment in result.assessments] == ["unknown", "accepted_invalid"]
            assert result.categories["package_oracles"] == "evidenced_issue"
            assert result.categories["fabricated_answers"] == "no_evidenced_issue"

    asyncio.run(main())


def test_grader_reads_existing_traces_and_rejects_repeated_cases(tmp_path, monkeypatch, credentials):
    from nudi import checks
    from nudi.records import EpisodeResult

    script = InspectorScript([{"probes": []}, {"probes": [{"category": "omitted_requirements", "case": "same", "episode": "ordinary"}]},
                              {"probes": [{"category": "omitted_requirements", "case": "same", "episode": "ordinary"}]}])
    investigated = []

    async def investigate(run, probe, session):
        investigated.append(probe)
        return Assessment(claim=Claim(mechanism="candidate", episode="ordinary"), outcome="unknown")

    monkeypatch.setattr(checks, "investigate", investigate)

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
            report = await checks.inspect_grader(run, ["ordinary"], categories=["omitted_requirements"], focused_attempts=2)
            assert "ordinary trajectory omitted the required work" in script.requests[0]["messages"][1]["content"]
            assert len(investigated) == 1
            assert "new case" in script.requests[-1]["messages"][-1]["content"].lower()
            assert report.attempts[-1].status == "duplicate_case"
            assert run.record.episodes == ["ordinary"]

    asyncio.run(main())


@pytest.mark.parametrize(("response", "expected"), [({"refusal": "cannot inspect"}, "refused"), ({"probes": []}, "no_evidenced_issue")])
def test_refusal_is_distinct_from_finished_investigation(tmp_path, monkeypatch, credentials, response, expected):
    from nudi import checks

    async def main():
        async with serve(InspectorScript([response])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.attempts[0].status == expected
    asyncio.run(main())


def test_cap_and_cancellation_preserve_partial_inspection(tmp_path, monkeypatch, credentials):
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
            monkeypatch.setattr(checks.InspectorSession, "ask", cancelled)
            with pytest.raises(asyncio.CancelledError):
                await checks.inspect_hacks(run, categories=["package_oracles"])
            saved = json.loads((run.config.output_dir / "inspection-hack.json").read_text())
            assert saved["status"] == "cancelled"
            assert saved["attempts"][0]["status"] == "cancelled"
    asyncio.run(main())


def test_actual_reset_restriction_prevents_focused_retries(tmp_path, monkeypatch, credentials):
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


def test_inference_and_tool_failures_remain_distinct(tmp_path, monkeypatch, credentials):
    from nudi import checks

    async def main():
        async with serve(InspectorScript([{"probes": [{"category": "package_oracles", "case": "broken"}]}])) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            async def broken_tool(*args):
                raise RuntimeError("native tool failed")
            monkeypatch.setattr(checks, "investigate", broken_tool)
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.status == "partial"
            assert report.attempts[0].status == "tool_failure"
            async def broken_inference(*args, **kwargs):
                raise checks.InferenceFailure("local endpoint failed")
            monkeypatch.setattr(checks.InspectorSession, "ask", broken_inference)
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.attempts[0].status == "inference_failure"
            assert report.status == "partial"
    asyncio.run(main())


def test_tool_exit_and_cancellation_are_host_records_not_task_logs(tmp_path):
    from nudi import checks
    from nudi.checks import RetainedOracle
    from harbor.environments.base import ExecResult

    class Environment:
        session_id = "native-check-instance"
        async def exec(self, *, command):
            if shlex.split(command)[-1] == checks.VERSION_PROBE:
                return ExecResult(stdout="3\n", stderr="", return_code=0)
            assert CHECKER in shlex.split(command)
            return ExecResult(stdout='{"measured": 1}\n', stderr="", return_code=3)

    async def main():
        output = tmp_path / "protected" / "execution.json"
        adapter = RetainedOracle(program=CHECKER, inputs="{}", host_output=str(output), logs_dir=tmp_path / "task-mounted")
        await adapter.run("", Environment(), None)
        record = json.loads(output.read_text())
        assert record["exit_code"] == 3
        assert record["output"] == '{"measured": 1}\n'
        async def cancelled(*args, **kwargs):
            raise asyncio.CancelledError()
        environment = Environment()
        environment.exec = cancelled
        with pytest.raises(asyncio.CancelledError):
            await adapter.run("", environment, None)
        record = json.loads(output.read_text())
        assert record["exit_code"] is None
        assert record["error"] == "CancelledError"
    import shlex
    asyncio.run(main())


@pytest.mark.parametrize(("versions", "selected"), [
    ({"python3": "3"}, "python3"),  # the stopped live run: no python, python3 installed
    ({"python": "3"}, "python"),
    ({"python3": "2", "python": "3"}, "python"),
    ({"python": "2"}, None),
    ({}, None),
])
def test_check_uses_the_instance_python3_or_records_an_unsupported_runtime(tmp_path, versions, selected):
    """Each probe and the check run in the same native instance; Python 2 never runs a check."""
    import shlex
    from harbor.environments.base import ExecResult
    from nudi.checks import CHECK_WRAPPER, PYTHON_CANDIDATES, VERSION_PROBE, RetainedOracle

    class Environment:
        session_id = "native-check-instance"
        commands = []
        async def exec(self, *, command):
            args = shlex.split(command)
            self.commands.append(args)
            if args[0] not in versions:
                return ExecResult(stdout="", stderr=f"bash: {args[0]}: command not found", return_code=127)
            if args[1:] == ["-c", VERSION_PROBE]:
                return ExecResult(stdout=versions[args[0]] + "\n", stderr="", return_code=0)
            return ExecResult(stdout='{"measured": 1}\n', stderr="", return_code=0)

    environment = Environment()
    output = tmp_path / "protected" / "execution.json"
    adapter = RetainedOracle(program=CHECKER, inputs="{}", host_output=str(output), logs_dir=tmp_path / "task-mounted")
    asyncio.run(adapter.run("", environment, None))
    receipt = json.loads(output.read_text())
    probes = receipt["runtime_probes"]
    for probe in probes:
        assert probe["command"] == [probe["command"][0], "-c", VERSION_PROBE]
        assert probe["exit_code"] == (0 if probe["command"][0] in versions else 127)
    if selected:
        assert [probe["command"][0] for probe in probes] == list(PYTHON_CANDIDATES[:PYTHON_CANDIDATES.index(selected) + 1])
        assert receipt["command"] == environment.commands[-1] == [selected, "-c", CHECK_WRAPPER, CHECKER, "{}"]
        assert (receipt["exit_code"], receipt["output"]) == (0, '{"measured": 1}\n')
    else:
        assert [probe["command"][0] for probe in probes] == list(PYTHON_CANDIDATES)
        assert all(CHECKER not in command for command in environment.commands)
        assert (receipt["command"], receipt["exit_code"], receipt["error"]) == ([], None, "unsupported_runtime")
        assert receipt["output"].startswith("unsupported_runtime: no Python 3 executable")


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


def test_prompt_decoder_reads_actual_capture_states_and_rejects_malformed_fields(tmp_path, monkeypatch):
    """The trusted capture program's real state format, read through a stand-in docker CLI,
    decoded by the prompt's example. Malformed fields exit nonzero with no structured result."""
    import subprocess
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

    def check(submission: str):
        inputs = {"submission": submission, "requirement": "Write 42 to /app/answer.txt.", "scoring": "reward = 1"}
        run = subprocess.run([sys.executable, "-c", checks.CHECK_WRAPPER, program, json.dumps(inputs)],
                             capture_output=True, text=True, timeout=30)
        return run.returncode, captured_object(run.stdout), inputs

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


def test_inspector_failure_does_not_retain_credentials(tmp_path, monkeypatch, credentials):
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
    from nudi import checks
    from nudi.records import EpisodeResult

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
    probe = {"category": "omitted_requirements", "case": "later-state", "location": "/app/answer.txt",
             "capture_point": "grader_read", "timing": "This case requires a later read.", "program": CHECKER,
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"},
             "instruction": "Privileged Inspector-only targeted probe."}
    async def main():
        assessment = await checks.investigate(run, probe, None)
        assert assessment.outcome == "unknown"
        assert "grader_read" in assessment.missing[-1]
        await workflow.run_role_episode(run, "simulator")
    asyncio.run(main())
    assert dispatched[0][1]["instruction"] == probe["instruction"]
    assert dispatched[0][1]["capture"] is None
    assert dispatched[1][1] == {}
    assert all(config.native == workflow.ORIGINAL_BEHAVIOR for config, _ in dispatched)
    assert run.record.episodes == ["0000-inspector", "0001-simulator"]
    assert "Privileged" not in (run.config.task_dir / "instruction.md").read_text()


def test_failed_and_provisional_feedback_reaches_same_inspector_retry(tmp_path, monkeypatch, credentials):
    from nudi import checks
    script = InspectorScript([{"probes": []}, {"probes": [{"category": "package_oracles"}]}, {"probes": []}])
    async def investigate(*args):
        return Assessment(claim=Claim(mechanism="candidate", episode="case"), outcome="unknown", missing=["measured retry feedback"])
    monkeypatch.setattr(checks, "investigate", investigate)
    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=2)
            assert "measured retry feedback" in json.dumps(script.requests[2]["messages"])
    asyncio.run(main())


@pytest.mark.parametrize("decision", [{"status": "restricted", "facts": {"terminal": True}, "reason": "No available tool for this case."},
                                      {"status": "applicable", "facts": {"invented_tool": True}, "reason": "Unsupported tool."}])
def test_broad_applicability_controls_focused_coverage(tmp_path, monkeypatch, credentials, decision):
    from nudi import checks
    script = InspectorScript([{"probes": [], "applicability": {"package_oracles": decision}}] + [{"probes": []}] * 3)
    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            report = await checks.inspect_hacks(run, categories=["package_oracles"])
            assert len(script.requests) == 1
            assert report.status == "partial"
            assert report.categories["package_oracles"] in ("restricted", "unknown")
    asyncio.run(main())


def test_capture_failure_is_structured_and_partial(tmp_path, monkeypatch, credentials):
    from nudi import checks
    from nudi.records import EpisodeResult
    from types import SimpleNamespace
    run = new_run(tmp_path, monkeypatch, credentials)
    async def failed_capture(*args):
        raise RuntimeError("archive unavailable")
    monkeypatch.setattr(checks, "protected_capture", failed_capture)
    async def native(config, queue, **work):
        await work["capture"](SimpleNamespace(trial_id="native-id"))
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(config.task_dir), task_digest=tree_digest(config.task_dir),
                               model=config.model, reasoning_effort=None, versions={}, rewards={"reward": 1})
        config.output_dir.mkdir(parents=True)
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result
    monkeypatch.setattr(workflow, "run_episode", native)
    probe = {"category": "package_oracles", "instruction": "targeted", "location": "/app/answer.txt", "capture_point": "verification_start", "timing": "at verification start",
             "requirement": {"episode": None, "path": "instruction.md", "excerpt": "42"}}
    script = InspectorScript([{"probes": [probe]}])
    async def main():
        async with serve(script) as base:
            run.record.models["inspector"].api_base = base
            report = await checks.inspect_hacks(run, categories=["package_oracles"], focused_attempts=0)
            assert report.attempts[0].status == "tool_failure"
            assert report.status == "partial"
            assert run.record.capture_errors[0].location == "/app/answer.txt"
            assert "archive unavailable" in json.dumps(report.sessions)
    asyncio.run(main())


def test_interpretation_refusal_stays_refused(tmp_path, monkeypatch, credentials):
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
            assert report.attempts[0].status == "refused"
    asyncio.run(main())
