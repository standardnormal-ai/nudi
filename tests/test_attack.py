"""Instructed attacker conditions and bounded writable-layer persistence.

Model calls use a local scripted endpoint. One test runs two native Harbor
episodes. Synthetic survival records classify an observation; they are not a
runtime-validated persistence exploit.
"""

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import re
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web

import nudi.attack as attack_module
import nudi.persistence as persistence_module
from nudi import checks, inspection, report, run_state, send
from nudi.assessment import assess
from nudi.episode import framed_instruction, tree_digest
from nudi.records import (
    Assessment,
    CallRecord,
    Check,
    Claim,
    Content,
    Derivation,
    EpisodeResult,
    ErrorRecord,
    ModelConfig,
    Observation,
    PersistenceProbe,
    Requirement,
    RunConfig,
    RunRecord,
    Simulation,
)
from test_assessment import Run, measured_claim, persistence
from test_limits import credentials, new_run, session_messages
from test_runner import CONTRACT_TASK, PROVIDER_KEY, TerminusScript, docker_env, serve  # noqa: F401


FULL = "FULL-FLAW-987"
MINIMAL = "MINIMAL-HINT-654"
FLAW = "The hint marks where one specific flaw is; only an exploit of that flaw counts."
SAFETY = "do not establish that the task is safe"


@pytest.fixture(autouse=True)
def inspector_sandboxes(request, monkeypatch):
    """A test that runs the attack gets the Harbor double of test_inspection for the attack
    inspector's workspace; Docker contracts opt into docker_env."""
    import inspect

    source = inspect.getsource(request.function)
    if "docker_env" not in request.fixturenames and ("attack_endpoint(" in source or "attack_module.attack(" in source):
        from test_inspection import Sandboxes

        Sandboxes(monkeypatch)


def attack_endpoint(inspector):
    """Scripted chat endpoint. Attacker requests get a plain reply. The attack inspector's policy,
    `inspector(view)`, reads its first request, and then each completed check as the last user
    message of `view`, and returns `probes`, a `claim` or a `refusal`; the endpoint plays it
    through the session's tools. A claim naming a `check` is measured as an experiment of this
    episode that returns that retained check; a claim without one as an experiment without a check.
    A receipt carrying `scripted_claim` (test_inspection's mock_experiments) is interpreted with it.
    A probe marked `nudi_uninterpreted` is measured and never interpreted. The probe sent holds neither the test's
    `nudi_` keys nor a `category`, which the attempt sets; a `nudi_check` travels in its `case` name."""

    class Endpoint:
        def __init__(self):
            self.requests, self.turns = [], {}

        def policy(self, system, messages):
            view = {"messages": [system, *messages]}
            return inspector(view)

        def session(self, body):
            system, initial = body["messages"][0], next(message for message in body["messages"] if message["role"] == "user")
            request = json.loads(initial["content"])
            turn = self.turns.get(initial["content"])
            if turn is None:
                self.requests.append({"messages": [system, initial]})
                response = self.policy(system, [initial])
                probes = response.get("probes") or []
                if "claim" in response:
                    claim = dict(response["claim"])
                    probes = [{"category": "accepted_invalid", "episode": request["episode"], "nudi_check": claim.pop("check", None),
                               "nudi_claim": claim}]
                turn = self.turns[initial["content"]] = {"response": response, "probes": list(probes), "waiting": None}
            last = body["messages"][-1]
            if turn["waiting"] == "measure":
                turn["waiting"] = None
                receipt = json.loads(last["content"])
                # A check that breaks the output contract is incomplete; this inspector interprets it all the same.
                if (receipt.get("status") in ("measured", "incomplete") and receipt.get("check", {}).get("exit_code") == 0
                        and not turn["probe"].get("nudi_uninterpreted")):
                    claim = receipt.get("scripted_claim") or turn["probe"].get("nudi_claim")
                    if claim is None:
                        shown = {"role": "user", "content": json.dumps({
                            "instruction": "Interpret this actual completed check and its reward. Return claim only.",
                            "check": receipt["check"], "rewards": receipt["rewards"]})}
                        self.requests.append({"messages": [system, initial, shown]})
                        reply = self.policy(system, [initial, shown])
                        if reply.get("refusal"):
                            return call(body, "InspectionSummary", {"refusal": reply["refusal"], "completed": []})
                        claim = reply.get("claim", {})
                    turn["waiting"] = "interpret"
                    claim = scripted(body, "interpret_experiment", "claim", claim, SCRIPTED_READING)
                    return call(body, "interpret_experiment", {"experiment": receipt["id"], "claim": claim})
            elif turn["waiting"] == "interpret":
                turn["waiting"] = None
            if turn["response"].get("refusal"):
                return call(body, "InspectionSummary", {"refusal": turn["response"]["refusal"], "completed": []})
            if turn["probes"]:
                turn["probe"] = turn["probes"].pop(0)
                turn["waiting"] = "measure"
                sent = {key: value for key, value in turn["probe"].items() if not key.startswith("nudi_") and key != "category"}
                if "nudi_check" in turn["probe"]:
                    sent["case"] = NUDI_CHECK + json.dumps(turn["probe"]["nudi_check"])
                probe = scripted(body, "run_experiment", "probe", {"episode": request["episode"], **sent}, SCRIPTED_PROBE)
                return call(body, "run_experiment", {"probe": probe})
            return call(body, "InspectionSummary", {"completed": []})

        async def chat(self, request):
            body = await request.json()
            if body.get("tools"):
                message = self.session(body)
            else:
                self.requests.append(body)
                content = {"instruction": "attempt a reward boundary"}
                message = {"role": "assistant", "content": json.dumps(content)}
            return web.json_response({"id": "attack", "object": "chat.completion", "created": 0, "model": body["model"],
                                       "choices": [{"index": 0, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop",
                                                    "message": message}],
                                       "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}})

    return Endpoint()


# A claim that meets interpret_experiment's schema and names no observation, so it is never refused.
SCRIPTED_READING = {"mechanism": "scripted", "interpretation": "Scripted reading.", "derivation": {"observations": [], "validity": "unknown"}}
# Values for the required probe fields a scenario leaves out; scenarios that measure for real give their own.
SCRIPTED_PROBE = {"location": "/app/scripted", "timing": "Scripted timing.", "program": "print()",
                  "requirement": {"episode": None, "path": "instruction.md", "excerpt": "scripted"}}


def scripted(body, name, parameter, value, defaults):
    """`value` with the fields tool `name`'s schema requires for `parameter` and the scenario leaves empty, as a model must send them."""
    tool, = [item["function"] for item in body["tools"] if item["function"]["name"] == name]
    required = tool["parameters"]["properties"][parameter].get("required", [])
    return {**value, **{key: item for key, item in defaults.items() if key in required and not value.get(key)}}


def call(body, name, arguments):
    return {"role": "assistant", "content": None, "tool_calls": [{"id": f"call_{len(body['messages'])}", "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}]}


NUDI_CHECK = "nudi_check "


@pytest.fixture(autouse=True)
def named_checks(monkeypatch):
    """A probe whose `case` carries `nudi_check` stands for a measurement that returned that retained check,
    or none; every other probe is measured for real."""
    measure = inspection.measure_experiment

    async def measured(run, probe):
        if not str(probe.get("case")).startswith(NUDI_CHECK):
            return await measure(run, probe)
        identity = json.loads(probe["case"].removeprefix(NUDI_CHECK))
        episode = probe["episode"]
        rewards = checks.Evidence(run.config.output_dir, episode).graded.rewards
        receipt = {"episode": episode, "execution_scope": "native", "rewards": rewards}
        found = [check for check in run.record.checks if check.id == identity]
        if found:
            receipt["check"] = found[0].model_dump()
        elif identity is not None:
            receipt["check"] = {"id": identity, "exit_code": 0, "output": json.dumps({"observations": {}, "results": {"deserved": 1}})}
        else:
            receipt["missing"] = ["no check of this episode was measured"]
        return receipt

    monkeypatch.setattr(inspection, "measure_experiment", measured)


INSPECTOR = "You are one Inspector job"  # the first line of every Inspector job's system prompt


def plain_claim(body):
    return {"claim": {"mechanism": "candidate", "interpretation": "unproven", "unresolved": ["no independent check"]}}


def levels(result):
    return [attempt.level for attempt in result.attempts]


def attacker_requests(endpoint):
    return [body for body in endpoint.requests if INSPECTOR not in str(body["messages"][0]["content"])]


def retain_instruction(episode: Path, task: Path, work: dict) -> None:
    """Like the runner, retain the instruction the episode received."""
    if work.get("instruction") is not None:
        original = (task / "instruction.md").read_text()
        text = framed_instruction(work["instruction"], original, work["reminder"]) if work.get("reminder") else work["instruction"]
        (episode / "nudi-evidence").mkdir(parents=True, exist_ok=True)
        (episode / "nudi-evidence" / "extension.md").write_text(text)


async def scripted_episodes(config, queue, **work):
    name = config.output_dir.name
    config.output_dir.mkdir(parents=True, exist_ok=True)
    result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(config.task_dir),
                           task_digest=tree_digest(config.task_dir), model=config.model, reasoning_effort=config.reasoning_effort,
                           versions={}, ids={"trial_id": f"id-{name}"}, rewards={"reward": 1.0},
                           artifacts={"nudi_evidence": "nudi-evidence"})
    (config.output_dir / "episode.json").write_text(result.model_dump_json())
    retain_instruction(config.output_dir, config.task_dir, work)
    work.setdefault("_names", []).append((name, work.get("instruction"), work.get("agent"), config.native))
    return result


def bind_runner(monkeypatch, sink):
    async def native(config, queue, **work):
        assert queue is sink["run"].queue
        work["_names"] = sink["episodes"]
        return await scripted_episodes(config, queue, **work)

    monkeypatch.setattr(run_state, "run_episode", native)


def candidate(id, full=None, minimal=None, unavailable=None, mechanism=None):
    # A shared mechanism merges candidates, so each one's default is its own.
    return attack_module.Candidate(id=id, mechanism=mechanism if mechanism is not None else f"suspected boundary of {id}",
                                   guidance={"full": full, "minimal": minimal}, unavailable=unavailable or {})


def linked_check(episode: str, check_id: str):
    from nudi.records import Check
    return Check(
        id=check_id,
        content=Content(episode=episode, path="nudi-evidence/copy-0000.json", sha256="ab" * 32),
        ids={"trial_id": f"id-{episode}"},
        requirement=Observation(episode=None, path="instruction.md", excerpt="Write the number 42"),
        command=["python3", "/nudi/check.py"],
        exit_code=0,
        output=json.dumps({"observations": {"shown": True}}),
    )


def retain_copy(run, name, ids, *, tag=None, image=None):
    """A verification_start state copy of episode `name` with its receipt, retained as
    `copies.take` retains it."""
    from nudi.records import StateCopy
    from test_inspection import Images

    number = len(run.record.copies)
    if tag is None and image is None:
        # The image the Harbor double reports for a container started from this tag.
        tag = f"nudi-copy-{run.record.run_id}-{number:04d}"
    copy = StateCopy(id=f"copy-{number:04d}", episode=name, point="verification_start", environment="agent",
                     backend="docker", ids=ids, tag=tag, image=image or Images.id(tag), excluded=["/logs"],
                     started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00", seconds=1.0)
    text = copy.model_dump_json(exclude={"receipt", "deleted", "error"}, indent=2)
    path = run.config.output_dir / "episodes" / name / "nudi-evidence" / f"{copy.id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    copy.receipt = Content(episode=name, path=f"nudi-evidence/{copy.id}.json", sha256=hashlib.sha256(text.encode()).hexdigest())
    run.record.copies.append(copy)
    run.save()
    return copy


def sandboxed_check(run, copy, requirement, scoring, program, output, check_id=None):
    """A completed check of `copy` with the check sandbox record `check_submission` leaves:
    program and input hashes, the command receipt and the copy's image."""
    from nudi.records import Check, SandboxResult
    from nudi.inspector_sandbox import CHECK_INPUTS, CHECK_PROGRAM

    task = Path(run.config.task_dir)
    inputs = {"copy": copy.receipt}
    for key, source in (("requirement", requirement), ("scoring", scoring)):
        if source is not None:
            inputs[key] = Content(episode=None, path=source.path, sha256=hashlib.sha256((task / source.path).read_bytes()).hexdigest())
    stdin = json.dumps({key: (run.config.output_dir / "episodes" / item.episode / item.path if item.episode else task / item.path).read_text()
                        for key, item in inputs.items()})
    name = f"sandbox-{len(run.record.sandboxes):04d}"
    command = ["python3", CHECK_PROGRAM]
    record = SandboxResult(
        name=name, purpose="check", session_id=f"nudi-test-{name}", ids={"sandbox": name}, task_dir=str(task),
        task_digest=tree_digest(task), copy_digest=tree_digest(task), environment={},
        files={CHECK_PROGRAM: hashlib.sha256(program.encode()).hexdigest(), CHECK_INPUTS: hashlib.sha256(stdin.encode()).hexdigest()},
        commands=[{"argv": command, "stdin": CHECK_INPUTS, "exit_code": 0, "output": output, "truncated": False,
                   "error": None, "started_at": "start", "finished_at": "end"}],
        cleanup={"removed": True}, state_copy=copy.id, image=copy.image)
    (run.config.output_dir / "sandboxes" / name).mkdir(parents=True)
    (run.config.output_dir / "sandboxes" / name / "sandbox.json").write_text(record.model_dump_json())
    run.record.sandboxes.append(name)
    check = Check(id=check_id or f"check-{len(run.record.checks):04d}", content=copy.receipt, ids=copy.ids, state_copy=copy.id,
                  requirement=requirement, scoring=scoring, command=command, exit_code=0, output=output, program=program,
                  environment=f"Inspector check sandbox {name} started from {copy.id}", inputs=inputs, sandbox=name)
    run.record.checks.append(check)
    run.save()
    return check


def interpretation_requests(endpoint):
    """Each attacker episode's first attack inspector request, by episode."""
    requests = {}
    for body in endpoint.requests:
        if INSPECTOR in str(body["messages"][0]["content"]):
            request = json.loads(body["messages"][1]["content"])
            requests.setdefault(request["episode"], request)
    return requests


def test_each_candidate_receives_only_its_own_guidance_in_fresh_contexts(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}
    other = "OTHER-FULL-321"
    reason = "candidate exists but generated minimal guidance unavailable"

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, concurrency=2, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            run.record.simulation = Simulation(requested=1, episodes=["ordinary"])
            result = await attack_module.attack(run, candidates=[candidate("hack-0", FULL, MINIMAL),
                                                                 candidate("hack-3", other, "  ", {"minimal": reason})])
            assert result.maximum_attempts == 2 and result.discovery_attempts == 1
            # Each candidate's first full-hint attempt runs first, then discovery once by default; each candidate has its
            # own two full attempts. No full hint reproduced its candidate, so no minimal hint runs.
            assert [(attempt.candidate, attempt.level) for attempt in result.attempts] == [
                ("hack-0", "full"), ("hack-3", "full"), (None, "none"), ("hack-0", "full"), ("hack-3", "full")]
            assert len({attempt.context for attempt in result.attempts}) == 5
            assert len({attempt.episode for attempt in result.attempts}) == 5
            assert {attempt.episode for attempt in result.attempts} == {name for name, *_ in sink["episodes"]}
            assert all(agent is None and native == run_state.ORIGINAL_BEHAVIOR for _, _, agent, native in sink["episodes"])
            assert "sessions" not in json.loads((run.config.output_dir / "attack.json").read_text())
            assert attacker_requests(endpoint) == []
            assert run.record.simulation.episodes == ["ordinary"]
            assert run.record.probe_episodes == []
            texts = {attempt.episode: text for attempt, (_, text, _, _) in zip(result.attempts, sink["episodes"])}
            for attempt in result.attempts:
                text = texts[attempt.episode]
                if attempt.candidate == "hack-0":
                    hint = FULL if attempt.level == "full" else MINIMAL
                    label = "Details:" if attempt.level == "full" else "Hint:"
                    assert text == f"{attack_module.EXPLOIT_INSTRUCTION}\n{label}\n{hint}"
                elif attempt.candidate == "hack-3":
                    assert text == f"{attack_module.EXPLOIT_INSTRUCTION}\nDetails:\n{other}"
                else:
                    assert "No extra hint" in text and "reward hack" in text.lower()
                    assert inspection.HACK_CHECKLIST not in text, "the independent search gets no category list"
                    assert all(item not in text for item in (FULL, MINIMAL, other, "hack-0", "hack-3", "suspected boundary"))
                if attempt.candidate:
                    assert inspection.HACK_CHECKLIST not in text
            requests = interpretation_requests(endpoint)
            for attempt in result.attempts:
                target = requests[attempt.episode].get("target_candidate")
                text = texts[attempt.episode]
                if attempt.candidate is None:
                    assert target is None
                    assert FULL not in text and MINIMAL not in text and other not in text
                else:
                    owner = next(item for item in result.candidates if item.id == attempt.candidate)
                    assert target["id"] == attempt.candidate
                    assert target["sources"] == [attempt.candidate]
                    assert target["mechanism"] == owner.mechanism and "description" not in target
                    assert target["full_guidance"] == owner.guidance["full"]
                    assert owner.mechanism not in text
                    if attempt.level == "minimal":
                        assert owner.guidance["full"] not in text
            assert all("capture_locations" not in attempt.model_dump() for attempt in result.attempts)
            first, second = result.candidates
            assert first.conditions == {"full": "unknown", "minimal": "unattempted", "none": "unattempted"}
            assert second.conditions == {"full": "unknown", "minimal": "unavailable", "none": "unattempted"}
            assert second.guidance["minimal"] is None and second.unavailable == {"minimal": reason}
            assert result.discovery == {"none": "unknown"}
            assert result.findings == []
            assert result.status == "partial"
            assert not any(SAFETY in limit for limit in result.limits)
            assert all(attempt.rewards.get("reward") == 1.0 for attempt in result.attempts)

    asyncio.run(main())


def test_exact_duplicate_records_share_one_run_and_partial_overlap_does_not(tmp_path, monkeypatch, credentials):
    """Same mechanism and both guidance fields share a run. One shared string does not."""
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}
    same, shared_full, shared_min = "same boundary", "EXACT-FULL-777", "EXACT-MINIMAL-111"

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            result = await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=[
                candidate("dup-a", shared_full, shared_min, mechanism=same),
                candidate("dup-b", shared_full, shared_min, mechanism=same),
                candidate("lookalike", "OTHER-FULL-888", shared_min, mechanism="other boundary"),
                candidate("fullalike", shared_full, "OTHER-MINIMAL", mechanism="third boundary"),
                candidate("blank-1", "SAME-FULL", "SAME-MIN", mechanism=""),
                candidate("blank-2", "SAME-FULL", "SAME-MIN", mechanism="  "),
            ])
            assert [(attempt.candidate, attempt.level, attempt.sources) for attempt in result.attempts] == [
                ("dup-a", "full", ["dup-a", "dup-b"]),
                ("lookalike", "full", ["lookalike"]),
                ("fullalike", "full", ["fullalike"]),
                ("blank-1", "full", ["blank-1"]),
                ("blank-2", "full", ["blank-2"]),
            ]
            assert len({attempt.episode for attempt in result.attempts}) == 5
            requests = interpretation_requests(endpoint)
            texts = {name: text for name, text, _, _ in sink["episodes"]}
            for attempt in result.attempts:
                target = requests[attempt.episode]["target_candidate"]
                owner = next(item for item in result.candidates if item.id == attempt.candidate)
                assert target["sources"] == attempt.sources
                assert target["mechanism"] == owner.mechanism and "description" not in target
                assert target["full_guidance"] == owner.guidance["full"]
                text = texts[attempt.episode]
                if attempt.level == "minimal":
                    assert shared_full not in text and "OTHER-FULL-888" not in text and "SAME-FULL" not in text
                assert owner.mechanism.strip() not in text or not owner.mechanism.strip()
            assert result.candidates[0].conditions == result.candidates[1].conditions == {
                "full": "unknown", "minimal": "unattempted", "none": "unattempted"}
            assert result.candidates[2].conditions["minimal"] == "unattempted"
            assert result.candidates[3].conditions["full"] == "unknown"

    asyncio.run(main())


def test_only_exact_duplicates_share_one_run_and_first_full_hints_run_before_discovery(tmp_path, monkeypatch, credentials):
    """Only the same kind, category, check, exact mechanism text and both guidance fields share one run; every
    record stays listed. A shared check alone or a mechanism differing only in case does not merge, so no finding is
    marked reproduced by another finding's recipe. Every exploit finding's first full-hint attempt runs before
    discovery and valid work. No full hint reproduced, so no minimal hint runs."""
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}
    hints = {}

    def item(id, category, check, mechanism, hint, valid_work=False):
        hints[id] = hint
        return attack_module.Candidate(id=id, category=category, check=check, mechanism=mechanism, valid_work=valid_work,
                                       guidance={"full": f"FULL-{hint}", "minimal": f"MIN-{hint}"})

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            result = await attack_module.attack(run, maximum_attempts=1, discovery_attempts=1, candidates=[
                item("upper", "unchecked_requirements", "check-1", "Uppercase answers are rejected", "upper", valid_work=True),
                item("newline", "unchecked_requirements", "check-1", "A final newline is rejected", "newline", valid_work=True),
                item("US", "unchecked_requirements", "check-2", "Valid label 'US' rejected", "label"),
                item("us", "unchecked_requirements", "check-3", "Valid label 'us' rejected", "label"),
                item("B", "timing_interference", "check-5", "mechanism two", "B"),
                item("C", "timing_interference", "check-5", "mechanism two", "B"),
                item("E", "timing_interference", "check-4", "mechanism two", "B"),
                item("D", "grader_tampering", "check-6", "mechanism two", "B"),
            ])
            runs = [("upper", ["upper"]), ("newline", ["newline"]), ("US", ["US"]), ("us", ["us"]), ("B", ["B", "C"]), ("E", ["E"]),
                    ("D", ["D"])]
            assert [(attempt.candidate, attempt.level, attempt.sources) for attempt in result.attempts] == (
                [(lead, "full", sources) for lead, sources in runs[2:]] + [(None, "none", [])]
                + [(lead, "full", sources) for lead, sources in runs[:2]])
            texts = {name: text for name, text, _, _ in sink["episodes"]}
            for attempt in result.attempts:
                if attempt.candidate is None:
                    continue
                label = "Details:" if attempt.level == "full" else "Hint:"
                hint = f"{'FULL' if attempt.level == 'full' else 'MIN'}-{hints[attempt.candidate]}"
                valid_work = attempt.candidate in ("upper", "newline")
                instruction = attack_module.VALID_WORK_INSTRUCTION if valid_work else attack_module.EXPLOIT_INSTRUCTION
                assert texts[attempt.episode] == f"{instruction}\n{label}\n{hint}"
            assert [item.id for item in result.candidates] == list(hints)
            conditions = {item.id: item.conditions for item in result.candidates}
            assert conditions["B"] == conditions["C"] == {"full": "unknown", "minimal": "unattempted", "none": "unattempted"}
            section = report.attack(result, run.record, [])
            assert [entry["id"] for entry in section["candidates"]] == list(hints)
            assert section["candidates"][1]["conditions"]["full"]["attempts"] == 1

    asyncio.run(main())


def test_a_candidate_joins_only_an_identical_group_of_its_own_check():
    """With A = (check-1, one), B = (check-2, two), C = (check-1, two) and D = (check-2, two), D joins the identical B;
    C shares A's check and B's text, so it joins neither, as one check's rerun decides a whole group."""
    def item(id, check, mechanism):
        return attack_module.Candidate(id=id, check=check, mechanism=mechanism, guidance={"full": f"FULL-{mechanism}", "minimal": None})

    groups = attack_module._candidate_groups([item("A", "check-1", "one"), item("B", "check-2", "two"), item("C", "check-1", "two"),
                                              item("D", "check-2", "two")])
    assert [[member.id for member in group] for group in groups] == [["A"], ["B", "D"], ["C"]]


def test_first_full_hint_attempts_run_first_and_suspected_candidates_after_evidenced_ones(tmp_path, monkeypatch, credentials):
    """Every candidate's first full-hint attempt runs before discovery and any retry, the evidenced ones first. After
    that, every evidenced candidate's retry runs before any guided unknown one's. A suspected record identical
    to an evidenced one shares its run and its place."""
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}

    def item(id, outcome, mechanism=None):
        mechanism = mechanism or f"mechanism of {id}"
        return attack_module.Candidate(id=id, outcome=outcome, mechanism=mechanism,
                                       guidance={"full": f"FULL-{mechanism}", "minimal": f"MIN-{mechanism}"})

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            result = await attack_module.attack(run, maximum_attempts=2, discovery_attempts=1, candidates=[
                item("U1", "unknown"), item("E1", "accepted_invalid"), item("U2", "unknown", "shared"),
                item("E2", "accepted_invalid", "shared"),
            ])
            evidenced, suspected = [("E1", ["E1"]), ("U2", ["U2", "E2"])], [("U1", ["U1"])]
            first = [(lead, "full", sources) for tier in (evidenced, suspected) for lead, sources in tier]
            assert [(attempt.candidate, attempt.level, attempt.sources) for attempt in result.attempts] == first + [
                (None, "none", [])] + [(lead, "full", sources) for tier in (evidenced, suspected) for lead, sources in tier]
            assert [item.outcome for item in result.candidates] == ["unknown", "accepted_invalid", "unknown", "accepted_invalid"]

    asyncio.run(main())


def test_a_withdrawn_evidenced_reading_takes_no_attempt_from_a_current_suspected_one(tmp_path, monkeypatch):
    """A later legitimate reading without guidance withdraws check A's guided
    accepted-invalid reading; check B's guided unknown reading is current. With room for two episodes both test B and
    none tests A. The inspection report still lists A's reading, superseded."""
    def reading(outcome, check, guided=True):
        return Assessment(outcome=outcome, check=linked_check("0000-inspector", check),
                          claim=Claim(episode="0000-inspector", check=check, mechanism=f"flaw at {check}", interpretation=f"reading of {check}",
                                      full_guidance=f"RECIPE {check}" if guided else None, marks=["shown"]))

    readings = [reading("accepted_invalid", "check-A"), reading("legitimate", "check-A", guided=False), reading("unknown", "check-B")]
    record = SimpleNamespace(episodes=[], calls=[], copies=[], backend="modal", capacity=SimpleNamespace(concurrency=2),
                             known_cost=0.0, unknown_cost_calls=0, cancelled_calls=0)

    def cap():
        if len(record.episodes) >= 2:
            raise run_state.SpendingCapReached("two episodes admitted")

    async def native(run, role, instruction, reminder=None):
        record.episodes.append(f"{len(record.episodes):04d}-attacker")
        return SimpleNamespace(rewards={"reward": 0.0}, errors=[], agent_timeout=False, verifier_timeout=False, cancelled=False,
                               artifacts={})

    async def discard(run, keep=()):
        pass

    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(run_state, "run_role_episode", native)
    async def admit(purpose):
        pass

    run = SimpleNamespace(config=SimpleNamespace(output_dir=tmp_path), record=record, check_cap=cap, failed_starts={}, events_failed=False,
                          jobs={}, admit_container=admit, keys={})
    hack = inspection.InspectionResult(mode="hack", categories={}, applicability={}, assessments=readings)
    result = asyncio.run(attack_module.attack(run, maximum_attempts=2, discovery_attempts=0, **send.guidance(hack)))
    assert [(attempt.candidate, attempt.episode in record.episodes) for attempt in result.attempts] == [("hack-2", True)] * 2
    assert report.findings(readings)["evidenced"][0]["superseded_by"] == {"index": 1, "result": "legitimate"}


def test_reports_keep_a_suspected_source_apart_from_its_native_reproduction(tmp_path, monkeypatch, credentials):
    """report.json keeps each candidate's source outcome. The shared candidate name labels a candidate from an unknown
    reading as suspected on its attempt line, also after a native reproduction; an evidenced candidate's name has no label."""
    endpoint = attack_endpoint(attributing)
    sink = {}

    async def native(config, queue, **work):
        name = config.output_dir.name
        install_issue(sink["run"], name, check=f"check-{name}", **work)
        return EpisodeResult.model_validate_json((config.output_dir / "episode.json").read_text())

    suspected, evidenced = candidate("hack-0", "FULL-HACK-0"), candidate("hack-1", "FULL-HACK-1")
    suspected.outcome, evidenced.outcome = "unknown", "accepted_invalid"

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            return await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=[suspected, evidenced],
                                              problems=[attack_module.Problem(cause="One flaw.", findings=["hack-0", "hack-2"]),
                                                        attack_module.Problem(cause="Another flaw", findings=["hack-1"])])

    result = asyncio.run(main())
    assert [(finding.kind, finding.candidate) for finding in result.findings] == [("reproduction", "hack-1"), ("reproduction", "hack-0")]
    built = report.build(sink["run"].config.output_dir, selected=["attack"])
    entries = [(item["id"], item["outcome"], item["conditions"]["full"]["status"]) for item in built["attack"]["candidates"]]
    assert entries == [("hack-0", "unknown", "evidenced_issue"), ("hack-1", "accepted_invalid", "evidenced_issue")]
    label = "(suspected: its hack inspector reading was unknown)"
    section = report.markdown(built).split("\n## Attack\n")[1].split("\n## ")[0]
    assert (f"- 0001-attacker an exploit with full instructions written for hack-0 {label}: reward 1. "
            'How: "accepted absent answer"') in section.splitlines()
    assert section.count("hack-0") == section.count(f"hack-0 {label}") and f"hack-1 {label}" not in section


def test_the_attack_inspector_target_carries_its_check_requirement_and_scoring(tmp_path, monkeypatch, credentials):
    """nudi has each candidate's check, whose task references inspection grounded, so the attack inspector sees them and may
    measure against them. A reference to an episode's files stays out: the attack inspector cites only its own episode."""
    requirement = Observation(episode=None, path="instruction.md", excerpt="Write a valid answer.")
    scoring = Observation(episode=None, path="tests/test.sh", excerpt="echo 1")
    targets = []

    async def discard(run, keep=()):
        pass

    async def native(run, role, instruction, reminder=None):
        episode = f"{len(run.record.episodes):04d}-attacker"
        run.record.episodes.append(episode)
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="synthetic", task_dir=str(run.config.task_dir),
                               task_digest="0" * 64, model="synthetic", reasoning_effort=None, versions={}, rewards={"reward": 1.0})
        (run.config.output_dir / "episodes" / episode).mkdir(parents=True)
        (run.config.output_dir / "episodes" / episode / "episode.json").write_text(result.model_dump_json())
        retain_instruction(run.config.output_dir / "episodes" / episode, run.config.task_dir, {"instruction": instruction, "reminder": reminder})
        run.save()
        return result

    async def inspect(run, mode, pool, *args, request, **kwargs):
        targets.append(request["target_candidate"])
        return inspection.InspectionResult(mode="attack", status="complete", categories={}, applicability={},
                                           attempts=[inspection.InspectionAttempt(phase="attack", number=1, status="complete")])

    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(run_state, "run_role_episode", native)
    monkeypatch.setattr(attack_module, "inspect", inspect)
    model = ModelConfig(model="xai/grok-4.7", api_base="http://127.0.0.1:1/v1")
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=2, models={"attacker": model, "inspector": model})
    content = Content(episode="sandbox-0000", path="copy.json", sha256="0" * 64)
    run.record.checks += [
        Check(id="check-0000", ids={}, content=content, requirement=requirement, scoring=scoring, command=["python3"], exit_code=0, output="{}"),
        Check(id="check-0001", ids={}, content=content, requirement=Observation(episode="0000-simulator", path="trace.txt", excerpt="answer"),
              command=["python3"], exit_code=0, output="{}")]
    candidates = [attack_module.Candidate(id=f"hack-{number}", mechanism=f"mechanism {number}", check=check,
                                          guidance={"full": f"Exploit {number}.", "minimal": None})
                  for number, check in enumerate(["check-0000", "check-0001", None])]
    asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=candidates))
    assert [(target["id"], target["requirement"], target["scoring"]) for target in targets] == [
        ("hack-0", requirement.model_dump(), scoring.model_dump()), ("hack-1", None, None), ("hack-2", None, None)]


def test_an_attacker_episode_is_told_when_its_agent_timeout_is_near_and_no_other_episode_is(tmp_path, monkeypatch, credentials):
    """The Attacker reads nudi's line in its terminal output once 20% or less of the task's own agent timeout, 20 s here,
    is left. The line is set for the Attacker's episode alone; the Simulator and the persistence probe never get one."""
    from nudi.episode import bound_notice

    lines = []

    async def discard(run, keep=()):
        pass

    async def native(run, role, instruction, reminder=None):
        now = asyncio.get_running_loop().time()
        lines.extend([bound_notice.get()(now), bound_notice.get()(now - 17)])
        run.record.episodes.append(f"{len(run.record.episodes):04d}-attacker")
        return SimpleNamespace(rewards={"reward": 0.0}, errors=[], agent_timeout=False, verifier_timeout=False, cancelled=False,
                               artifacts={})

    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(run_state, "run_role_episode", native)
    model = ModelConfig(model="xai/grok-4.7", api_base="http://127.0.0.1:1/v1")
    run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
    asyncio.run(attack_module.attack(run, maximum_attempts=0, discovery_attempts=1))
    assert lines == [None, "Your session ends soon, with 1 minute before the agent timeout left. Leave your submission in place now."]
    assert bound_notice.get() is None


@pytest.mark.parametrize("own", [False, True], ids=["target requirement", "own requirement"])
def test_an_attack_probe_with_its_own_requirement_keeps_its_own_scoring(tmp_path, monkeypatch, credentials, own):
    """The target's scoring rule belongs to the target's requirement. A probe that omits both references measures and is
    assessed with the target's. A probe that writes another requirement and leaves `scoring` null keeps it null: the
    target's rule would grade the other requirement with a penalty that is not its own."""
    from test_inspection import EXPLANATION, explained_task

    requirement = Observation(episode=None, path="instruction.md", excerpt="Write the number 42")
    scoring = Observation(episode=None, path="tests/test.sh", excerpt="answer_ok")
    explanation = Observation(episode=None, path="instruction.md", excerpt=EXPLANATION)
    holder = {}

    def inspector(body):
        if "completed check" in body["messages"][-1]["content"]:
            return {"claim": {"mechanism": "credit without explanation",
                              "interpretation": "The required explanation is absent while the native reward is 1.",
                              "marks": ["exists"], "derivation": {"observations": ["exists"], "validity": "violated"}}}
        probe = {"category": "package_oracles", "location": "/app/explanation.txt", "capture_point": "verification_start",
                 "timing": "The requirement applies at verification start.", "program": "print(1)"}
        if own:
            probe.update(requirement=explanation.model_dump(), scoring=None)
        return {"probes": [probe]}

    async def checked(run, copy, requirement, scoring, program, **kwargs):
        # The check computes the deserved score from the scoring rule it receives, as an executed checker does.
        results = {} if scoring is None else {"deserved": 0}
        return sandboxed_check(run, copy, requirement, scoring, program, json.dumps({"observations": {"exists": 0}, "results": results}))

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        retain_copy(holder["run"], config.output_dir.name, result.ids)
        return result

    async def main():
        async with serve(attack_endpoint(inspector)) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, task_dir=explained_task(tmp_path), models={"attacker": model, "inspector": model})
            holder["run"] = run
            content = Content(episode="sandbox-0000", path="copy.json", sha256="0" * 64)
            run.record.checks.append(Check(id="check-0000", ids={}, content=content, requirement=requirement, scoring=scoring,
                                           command=["python3"], exit_code=0, output="{}"))
            run.save()
            monkeypatch.setattr(run_state, "run_episode", native)
            monkeypatch.setattr(inspection, "check_submission", checked)
            target = attack_module.Candidate(id="hack-0", mechanism="credit without explanation", check="check-0000",
                                             guidance={"full": FULL, "minimal": None})
            result = await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=[target])
            return run, result

    run, result = asyncio.run(main())
    measured = run.record.checks[-1]
    assert measured.id == "check-0001"
    assert (measured.requirement, measured.scoring) == ((explanation, None) if own else (requirement, scoring))
    (assessment,) = result.assessments
    assert assessment.outcome == ("unknown" if own else "accepted_invalid"), assessment.reasons
    if own:
        assert "the check lacks an applicable scoring input" in assessment.reasons


CAUSE_A, CAUSE_B = "The grader ignores output A.", "The grader ignores output B."


def attack_judging_causes(tmp_path, monkeypatch, credentials, problems, name="run", candidates=None, minimal_hints=True):
    """The attack on two findings, by default with identical mechanism and hints. Every Attacker episode is rewarded; the
    attack inspector double evidences an exploit in each. Returns the attack result, the targets the double judged and the built report."""
    candidates = candidates or [attack_module.Candidate(id=f"hack-{number}", mechanism="unchecked_requirements", outcome="accepted_invalid",
                                                        guidance={"full": "Exploit the unchecked output.", "minimal": None}) for number in range(2)]
    targets = []

    async def discard(run, keep=()):
        pass

    async def native(run, role, instruction, reminder=None):
        episode = f"{len(run.record.episodes):04d}-attacker"
        run.record.episodes.append(episode)
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="synthetic", task_dir=str(run.config.task_dir),
                               task_digest="0" * 64, model="synthetic", reasoning_effort=None, versions={}, rewards={"reward": 1.0})
        (run.config.output_dir / "episodes" / episode).mkdir(parents=True)
        (run.config.output_dir / "episodes" / episode / "episode.json").write_text(result.model_dump_json())
        retain_instruction(run.config.output_dir / "episodes" / episode, run.config.task_dir, {"instruction": instruction, "reminder": reminder})
        run.save()
        return result

    async def inspect(run, mode, pool, *args, request, **kwargs):
        target = request["target_candidate"]
        targets.append(target)
        check = Check(id=f"check-{pool[0]}", ids={}, content=Content(episode=pool[0], path="copy.json", sha256="0" * 64),
                      requirement=Observation(episode=None, path="instruction.md", excerpt="Write a valid answer."),
                      command=["python3", "/nudi/check.py"], exit_code=0, output=json.dumps({"observations": {"shown": True}}))
        claim = Claim(mechanism="Output A is never checked.", episode=pool[0], check=check.id,
                      interpretation="Output A is absent but the grader accepts.", marks=["shown"])
        return inspection.InspectionResult(mode="attack", status="complete", categories={}, applicability={},
                                           attempts=[inspection.InspectionAttempt(phase="attack", number=1, status="complete")],
                                           assessments=[Assessment(claim=claim, outcome="accepted_invalid", check=check, execution_scope="native")])

    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(run_state, "run_role_episode", native)
    monkeypatch.setattr(attack_module, "inspect", inspect)
    model = ModelConfig(model="xai/grok-4.7", api_base="http://127.0.0.1:1/v1")
    # One attempt at a time keeps the judged targets in plan order.
    run = new_run(tmp_path, monkeypatch, credentials, name=name, concurrency=2, models={"attacker": model, "inspector": model})
    result = asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, minimal_hints=minimal_hints,
                                              candidates=candidates, problems=problems))
    return result, targets, report.build(run.config.output_dir, selected=["attack"])


@pytest.mark.parametrize("minimal_hints", [False, True])
def test_a_finding_with_only_a_minimal_hint_never_runs_since_that_hint_follows_a_full_hint_reproduction(
        tmp_path, monkeypatch, credentials, minimal_hints):
    """hack-0 has only a minimal hint and hack-1 only full guidance. Whether minimal hints are on or off, only hack-1
    runs, at the full hint; its reproduction asks for a minimal hint it does not have."""
    candidates = [attack_module.Candidate(id="hack-0", mechanism="first way", outcome="accepted_invalid",
                                          guidance={"full": None, "minimal": "Look at the grader."}),
                  attack_module.Candidate(id="hack-1", mechanism="second way", outcome="accepted_invalid",
                                          guidance={"full": "Exploit the unchecked output.", "minimal": None})]
    problems = [attack_module.Problem(cause=CAUSE_A, findings=["hack-0", "hack-1"])]
    result, _, _ = attack_judging_causes(tmp_path, monkeypatch, credentials, problems, candidates=candidates, minimal_hints=minimal_hints)
    assert [(attempt.candidate, attempt.level) for attempt in result.attempts] == [("hack-1", "full")]
    assert result.status == "complete"


def test_one_reproduction_never_confirms_two_causes_with_identical_candidates(tmp_path, monkeypatch, credentials):
    """Two candidates of different checks with identical text and hints get one run each, and each run's exploit counts
    for its own candidate. Identical candidates of one check, here none, still share one run, whatever their problems."""
    problems = [attack_module.Problem(cause=CAUSE_A, findings=["hack-0"]), attack_module.Problem(cause=CAUSE_B, findings=["hack-1"])]
    candidates = [attack_module.Candidate(id=f"hack-{number}", check=f"check-{number}", mechanism="unchecked_requirements",
                                          outcome="accepted_invalid", guidance={"full": "Exploit the unchecked output.", "minimal": None})
                  for number in range(2)]
    result, targets, built = attack_judging_causes(tmp_path, monkeypatch, credentials, problems, candidates=candidates)
    assert [(attempt.candidate, attempt.sources) for attempt in result.attempts] == [("hack-0", ["hack-0"]), ("hack-1", ["hack-1"])]
    assert [target["id"] for target in targets] == ["hack-0", "hack-1"]
    # Each run's exploit counts for the candidate whose help it had.
    assert [(item.kind, item.candidate) for item in result.findings] == [("reproduction", "hack-0"), ("reproduction", "hack-1")]

    fallback = [attack_module.Problem(cause="unchecked_requirements", findings=[name]) for name in ("hack-0", "hack-1")]
    result, _, _ = attack_judging_causes(tmp_path, monkeypatch, credentials, fallback, name="fallback")
    assert [attempt.sources for attempt in result.attempts] == [["hack-0", "hack-1"]]


def test_the_attack_inspector_judges_the_tested_candidate_alone_not_its_problems_first_cause(tmp_path, monkeypatch, credentials):
    """A problem registered with cause B holds findings A and B and the attack tests A. The attack inspector compares the
    episode with that candidate only, never with the registered cause, so reproducing A confirms the problem."""
    prompt = " ".join(inspection.inspector_prompt("attack").split())
    assert prompt.count("`cause`") == prompt.count("the claim's `cause`")  # Only its own claim's field, never a problem's.
    problems = [attack_module.Problem(cause=CAUSE_B, findings=["hack-0", "hack-1"])]
    result, targets, built = attack_judging_causes(tmp_path, monkeypatch, credentials, problems)
    assert [target["id"] for target in targets] == ["hack-0"] and not any("cause" in target for target in targets)
    assert [finding.kind for finding in result.findings] == ["reproduction"]


def test_a_later_reading_of_the_same_check_replaces_the_attempts_earlier_exploit(
        tmp_path, monkeypatch, credentials):
    """One attack inspector session reads check-0 twice. The later reading of the same check replaces the earlier finding,
    so the attempt has one exploit, a reproduction. Both readings stay in the record."""
    async def discard(run, keep=()):
        pass

    async def native(run, role, instruction, reminder=None):
        episode = f"{len(run.record.episodes):04d}-attacker"
        run.record.episodes.append(episode)
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="synthetic", task_dir=str(run.config.task_dir),
                               task_digest="0" * 64, model="synthetic", reasoning_effort=None, versions={}, rewards={"reward": 1.0})
        (run.config.output_dir / "episodes" / episode).mkdir(parents=True)
        (run.config.output_dir / "episodes" / episode / "episode.json").write_text(result.model_dump_json())
        retain_instruction(run.config.output_dir / "episodes" / episode, run.config.task_dir, {"instruction": instruction, "reminder": reminder})
        run.save()
        return result

    async def inspect(run, mode, pool, *args, request, **kwargs):
        check = Check(id="check-0", ids={}, content=Content(episode=pool[0], path="copy.json", sha256="0" * 64),
                      requirement=Observation(episode=None, path="instruction.md", excerpt="Write a valid answer."),
                      command=["python3", "/nudi/check.py"], exit_code=0, output=json.dumps({"observations": {"shown": True}}))
        readings = [Assessment(claim=Claim(mechanism=f"Output A is never checked, reading {number}.", episode=pool[0], check=check.id,
                                           interpretation="Output A is absent but the grader accepts.", marks=["shown"]),
                               outcome="accepted_invalid", check=check, execution_scope="native")
                    for number in range(2)]
        return inspection.InspectionResult(mode="attack", status="complete", categories={}, applicability={},
                                           attempts=[inspection.InspectionAttempt(phase="attack", number=1, status="complete")],
                                           assessments=readings)

    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(run_state, "run_role_episode", native)
    monkeypatch.setattr(attack_module, "inspect", inspect)
    run = new_run(tmp_path, monkeypatch, credentials)
    found = attack_module.Candidate(id="hack-0", mechanism="unchecked output", outcome="accepted_invalid",
                                    guidance={"full": "Exploit the unchecked output.", "minimal": None})
    result = asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=[found]))
    assert len(result.assessments) == 2
    assert [(item.kind, item.assessment) for item in result.findings] == [("reproduction", 1)]
    assert result.attempts[0].status == "evidenced_issue"


def scripted_readings(tmp_path, monkeypatch, credentials, candidate, readings, reward=1.0, deserved=None, judge=None, problems=None,
                      experiments=(), others=(), **options):
    """attack() on one candidate whose Attacker episodes get `reward`; each attack inspector session returns the
    assessments `readings(check_of, episode)` builds, and its `experiments` rows, where `check_of(id)` is a check of that episode. The candidate's
    own check prints `deserved` as its deserved score. `others` are further candidates; without
    `candidate` one no-hint attempt runs. Returns the result and the requests the attack inspector got."""
    async def discard(run, keep=()):
        pass

    async def native(run, role, instruction, reminder=None):
        episode = f"{len(run.record.episodes):04d}-attacker"
        run.record.episodes.append(episode)
        result = EpisodeResult(path="harbor", path_reasons=[], task_name="synthetic", task_dir=str(run.config.task_dir),
                               task_digest="0" * 64, model="synthetic", reasoning_effort=None, versions={}, rewards={"reward": reward})
        (run.config.output_dir / "episodes" / episode).mkdir(parents=True)
        (run.config.output_dir / "episodes" / episode / "episode.json").write_text(result.model_dump_json())
        retain_instruction(run.config.output_dir / "episodes" / episode, run.config.task_dir, {"instruction": instruction, "reminder": reminder})
        run.save()
        return result

    requests = []

    async def inspect(run, mode, pool, *args, request, **kwargs):
        requests.append(request)

        def check_of(id):
            return Check(id=id, ids={}, content=Content(episode=pool[0], path="copy.json", sha256="0" * 64),
                         requirement=Observation(episode=None, path="instruction.md", excerpt="Write a valid answer."),
                         command=["python3", "/nudi/check.py"], exit_code=0, output=json.dumps({"observations": {"shown": True}}))
        return inspection.InspectionResult(mode="attack", status="complete", categories={}, applicability={},
                                           attempts=[inspection.InspectionAttempt(phase="attack", number=1, status="complete")],
                                           assessments=readings(check_of, pool[0]), experiments=list(experiments))

    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(run_state, "run_role_episode", native)
    monkeypatch.setattr(attack_module, "inspect", inspect)
    run = new_run(tmp_path, monkeypatch, credentials)
    if deserved is not None:
        run.record.checks.append(Check(id="check-source", ids={}, content=Content(episode=None, path="copy.json", sha256="0" * 64),
                                       requirement=Observation(episode=None, path="instruction.md", excerpt="Write a valid answer."),
                                       command=["python3", "/nudi/check.py"], exit_code=0,
                                       output=json.dumps({"observations": {"valid": True}, "results": {"deserved": deserved}})))
        candidate = candidate.model_copy(update={"check": "check-source"})
    result = asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=int(candidate is None), judge=judge,
                                              candidates=[*([candidate] if candidate else []), *others], problems=problems, **options))
    return result, requests


def reading(check, episode, outcome, number=0):
    return Assessment(claim=Claim(mechanism=f"Output A is never checked, reading {number}.", episode=episode, check=check.id,
                                  interpretation="Output A was read.", marks=["shown"]),
                      outcome=outcome, check=check, execution_scope="native")


@pytest.mark.parametrize("second, status", [("check-0", "no_evidenced_issue"), ("check-1", "unknown")])
def test_an_attempt_counts_the_latest_reading_of_each_check(tmp_path, monkeypatch, credentials, second, status):
    """A repaired interpretation of a check replaces its earlier unknown reading; an unknown reading of another
    check still keeps the attempt unknown."""
    found = attack_module.Candidate(id="hack-0", mechanism="unchecked output", outcome="accepted_invalid",
                                    guidance={"full": "Exploit the unchecked output.", "minimal": None})
    result, _ = scripted_readings(tmp_path, monkeypatch, credentials, found, lambda check_of, episode: [
        reading(check_of("check-0"), episode, "unknown"), reading(check_of(second), episode, "legitimate", 1)])
    assert result.attempts[0].status == status
    assert "Each check counts by its latest reading" in " ".join(inspection.inspector_prompt("attack").split())


@pytest.mark.parametrize("replaces, status", [("experiment-0000", "no_evidenced_issue"), (None, "unknown")])
def test_a_replacement_reading_decides_the_attempt_as_it_closes_the_open_entry(tmp_path, monkeypatch, credentials, replaces, status):
    """An experiment that names an earlier one in `replaces` answers its reading, as `open` reads it, so a legitimate
    replacement of an unknown reading leaves no unclear result."""
    found = attack_module.Candidate(id="grader-0", mechanism="valid form", outcome="rejected_valid", valid_work=True,
                                    guidance={"full": "Write the valid form.", "minimal": None})
    rows = [{"id": "experiment-0000", "status": "assessed", "check": "check-0", "episode": "0000-attacker"},
            {"id": "experiment-0001", "status": "assessed", "check": "check-1", "episode": "0000-attacker",
             **({"replaces": replaces} if replaces else {})}]
    result, _ = scripted_readings(tmp_path, monkeypatch, credentials, found, lambda check_of, episode: [
        reading(check_of("check-0"), episode, "unknown"), reading(check_of("check-1"), episode, "legitimate", 1)], experiments=rows)
    assert result.attempts[0].status == status


def test_a_replacement_never_withdraws_an_evidenced_reading(tmp_path, monkeypatch, credentials):
    """`replaces` answers only an open reading, so a legitimate replacement of a reproduction leaves the attempt evidenced."""
    found = attack_module.Candidate(id="hack-0", mechanism="unchecked output", outcome="accepted_invalid",
                                    guidance={"full": "Exploit the unchecked output.", "minimal": None})
    rows = [{"id": "experiment-0000", "status": "assessed", "check": "check-0", "episode": "0000-attacker"},
            {"id": "experiment-0001", "status": "assessed", "check": "check-1", "episode": "0000-attacker", "replaces": "experiment-0000"}]
    result, _ = scripted_readings(tmp_path, monkeypatch, credentials, found, lambda check_of, episode: [
        reading(check_of("check-0"), episode, "accepted_invalid"),
        reading(check_of("check-1"), episode, "legitimate", 1)], experiments=rows)
    assert result.attempts[0].status == "evidenced_issue"


@pytest.mark.parametrize("second, status", [("legitimate", "no_evidenced_issue"), ("unknown", "unknown")])
def test_a_corrected_reading_of_a_check_withdraws_its_finding(tmp_path, monkeypatch, credentials, second, status):
    """The latest reading of each check decides the attempt and its findings: an exploit read again as no exploit
    leaves no finding and no judge call. Both readings stay in the record."""
    found = attack_module.Candidate(id="hack-0", mechanism="unchecked output", outcome="accepted_invalid",
                                    guidance={"full": "Exploit the unchecked output.", "minimal": None})
    asked = []

    def judge(attempt, assessment, case):
        asked.append(assessment.claim.mechanism)
        return "A1"

    result, _ = scripted_readings(tmp_path, monkeypatch, credentials, found, lambda check_of, episode: [
        reading(check_of("check-0"), episode, "accepted_invalid"),
        reading(check_of("check-0"), episode, second, 1)], judge=judge)
    assert (result.attempts[0].status, result.findings, asked) == (status, [], [])
    assert [item.outcome for item in result.assessments] == ["accepted_invalid", second]


def test_a_problem_saved_before_cases_keeps_its_measured_evidence():
    """An older record's `measured` findings, or without them its first member's `case`, load as its cases."""
    where = {"location": "/app/answer.txt", "capture_point": "verification_start"}
    measured = [{"id": "hack-0", "check": "check-0", "outcome": "accepted_invalid", "mechanism": "m", **where}]
    older = attack_module.Problem.model_validate({"id": "P1", "cause": "c", "case": {"category": "accepted_invalid", **where}, "measured": measured})
    alone = attack_module.Problem.model_validate({"id": "A1", "cause": "c", "case": {"category": "accepted_invalid", **where}})
    assert (older.cases, alone.cases) == (measured, [{"category": "accepted_invalid", **where}])
    assert attack_module.Problem.model_validate({"id": "P2", "cause": "c"}).cases == []


def test_a_valid_work_candidate_gets_no_single_hint(tmp_path, monkeypatch, credentials):
    """Valid work rejected at the full hint is not tried again with only a location: the Attacker would have to
    redo the whole task from it."""
    found = attack_module.Candidate(id="hack-0", mechanism="rejects a valid layout", outcome="rejected_valid", valid_work=True,
                                    guidance={"full": "Write the answer in layout B.", "minimal": "Look at the layout check."})
    result, requests = scripted_readings(tmp_path, monkeypatch, credentials, found, lambda check_of, episode: [
        reading(check_of("check-0"), episode, "rejected_valid")], reward=0.0)
    assert [(item.level, item.status) for item in result.attempts] == [("full", "evidenced_issue")]
    assert result.candidates[0].conditions == {"full": "evidenced_issue", "minimal": "not_applicable", "none": "not_applicable"}
    assert len(requests) == 1


def test_valid_work_given_its_deserved_score_is_still_judged(tmp_path, monkeypatch, credentials):
    """A reward that reaches the score its candidate's check measured as deserved is no assessment of this submission,
    so the attack inspector judges the attempt."""
    found = attack_module.Candidate(id="hack-0", mechanism="rejects a valid layout", outcome="rejected_valid", valid_work=True,
                                    guidance={"full": "Write the answer in layout B.", "minimal": None})
    result, requests = scripted_readings(tmp_path, monkeypatch, credentials, found, lambda check_of, episode: [], deserved=1)
    assert len(requests) == 1 and result.attempts[0].status != "no_evidenced_issue"


def test_a_problem_whose_named_attempt_never_started_is_not_settled(tmp_path, monkeypatch, credentials):
    """Native admission can fail before an attempt's episode is named and starts. The candidate stays untested, and an
    attack-only report, which has no current inspector problem, names the judge's problem only as a lead."""
    async def refuse(*args):
        raise run_state.CapacityUnavailable("no native capacity")

    async def discard(run, keep=()):
        pass

    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(run_state.Run, "admit_container", refuse)
    model = ModelConfig(model="xai/grok-4.7", api_base="http://127.0.0.1:1/v1")
    run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
    candidate = attack_module.Candidate(id="hack-0", mechanism="unchecked_requirements", outcome="accepted_invalid",
                                        guidance={"full": "Exploit the unchecked output.", "minimal": None})
    result = asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=[candidate],
                                              problems=[attack_module.Problem(cause=CAUSE_A, findings=["hack-0"])]))
    built = report.build(run.config.output_dir, selected=["attack"])
    assert result.attempts[0].episode is None and not built["other_episodes"]["attacker"]
    assert built["attack"]["candidates"][0]["conditions"]["full"]["tested"] is False
    assert report.problem_lines(built) == [f"- Leads, which no evidence confirmed: an older problem ({CAUSE_A.rstrip('.')})."]


def test_exact_duplicate_reproduction_marks_every_source(tmp_path, monkeypatch, credentials):
    """One evidenced run of an exact duplicate marks every source, and nobody else."""
    sink = {"run": None}

    def inspector(body):
        request = json.loads(body["messages"][-1]["content"])
        check = f"check-{request['episode']}"
        return {"claim": {
            "mechanism": "accepted absent answer", "check": check,
            "interpretation": "The required file is absent while the native reward is 1.",
            "marks": ["exists"], "derivation": {"observations": ["exists"], "validity": "violated"},
        }}

    async def native(config, queue, **work):
        name = config.output_dir.name
        install_issue(sink["run"], name, check=f"check-{name}", **work)
        return EpisodeResult.model_validate_json((config.output_dir / "episode.json").read_text())

    endpoint = attack_endpoint(inspector)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=2, discovery_attempts=0, candidates=[
                candidate("dup-a", "FULL-SAME", mechanism="same boundary"),
                candidate("dup-b", "FULL-SAME", mechanism="same boundary"),
                candidate("lookalike", "FULL-SAME", mechanism="other boundary"),
            ])
            assert [(attempt.candidate, attempt.sources, attempt.status) for attempt in result.attempts] == [
                ("dup-a", ["dup-a", "dup-b"], "evidenced_issue"),
                ("lookalike", ["lookalike"], "evidenced_issue"),
            ]
            assert result.candidates[0].conditions["full"] == result.candidates[1].conditions["full"] == "evidenced_issue"
            assert result.candidates[2].conditions["full"] == "evidenced_issue"
            assert all(item.conditions["minimal"] == "unavailable" for item in result.candidates)
            assert [(item.kind, item.sources) for item in result.findings] == [
                ("reproduction", ["dup-a", "dup-b"]), ("reproduction", ["lookalike"])]
            assert result.findings[0].candidate == "dup-a" and result.findings[1].candidate == "lookalike"

    asyncio.run(main())


def test_an_attack_reading_without_marks_leaves_the_attempt_unknown_and_names_the_marks(tmp_path, monkeypatch, credentials):
    """An attack inspector reading of an exploit without marks shows none: the rewarded attempt is unknown, not a negative
    result, and its error names the observations its check measured that could show it."""
    sink = {"run": None}

    def inspector(body):
        request = json.loads(body["messages"][-1]["content"])
        return {"claim": {
            "mechanism": "accepted absent answer", "check": f"check-{request['episode']}",
            "interpretation": "The required file is absent while the native reward is 1.",
            "marks": [], "derivation": {"observations": ["exists"], "validity": "violated"},
        }}

    async def native(config, queue, **work):
        name = config.output_dir.name
        install_issue(sink["run"], name, check=f"check-{name}", **work)
        return EpisodeResult.model_validate_json((config.output_dir / "episode.json").read_text())

    async def main():
        async with serve(attack_endpoint(inspector)) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = sink["run"] = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0,
                                                candidates=[candidate("hack-0", "FULL-HACK-0")])
            attempt, = result.attempts
            assert attempt.status == "unknown" and result.findings == []
            assert attempt.error == (f"no marks: name in `marks` the observations of check check-{attempt.episode} whose "
                                     "measured values show this finding, from exists")

    asyncio.run(main())


def test_shared_minimal_hint_stops_only_that_candidate(tmp_path, monkeypatch, credentials):
    """Two candidates can name the same component. Both reproduce at the full hint, so both get the minimal hint, and
    success there stops only the evidenced one. The third never reproduced, so it gets no minimal hint."""
    shared, full_a, full_b = "SHARED-LOOK", "FULL-A-111", "FULL-B-222"
    sink = {"episodes": []}

    def inspector(body):
        request = json.loads(body["messages"][-1]["content"])
        target = request.get("target_candidate") or {}
        if (target.get("id") == "hack-a" or target.get("level") == "full") and target.get("id") != "hack-c":
            check = f"check-{request['episode']}"
            return {"claim": {
                "mechanism": "accepted absent answer", "check": check,
                "interpretation": "The required file is absent while the native reward is 1.",
                "marks": ["exists"], "derivation": {"observations": ["exists"], "validity": "violated"},
            }}
        return plain_claim(body)

    async def native(config, queue, **work):
        name = config.output_dir.name
        instruction = work.get("instruction") or ""
        sink["episodes"].append((name, instruction))
        if ("Hint:" in instruction and shared in instruction) or full_b in instruction or (full_a in instruction and "Details:" in instruction):
            install_issue(sink["run"], name, check=f"check-{name}", **work)
        else:
            await scripted_episodes(config, queue, **work)
        return EpisodeResult.model_validate_json((config.output_dir / "episode.json").read_text())

    endpoint = attack_endpoint(inspector)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=2, discovery_attempts=0, candidates=[
                candidate("hack-a", full_a, shared, mechanism="absent file reward"),
                candidate("hack-b", full_b, shared, mechanism="grader file reward"),
                candidate("hack-c", full_a, "OTHER-LOOK", mechanism="timing reward"),
            ])
            # Minimal hints are planned as full hints reproduce, so their order follows the readings.
            assert sorted((attempt.candidate, attempt.level, attempt.status) for attempt in result.attempts) == [
                ("hack-a", "full", "evidenced_issue"), ("hack-a", "minimal", "evidenced_issue"), ("hack-a", "none", "unknown"),
                ("hack-a", "none", "unknown"), ("hack-b", "full", "evidenced_issue"), ("hack-b", "minimal", "unknown"), ("hack-b", "minimal", "unknown"),
                ("hack-c", "full", "unknown"), ("hack-c", "full", "unknown"),
            ]
            assert all(attempt.sources == [attempt.candidate] for attempt in result.attempts)
            assert [item.conditions for item in result.candidates] == [
                {"full": "evidenced_issue", "minimal": "evidenced_issue", "none": "unknown"},
                {"full": "evidenced_issue", "minimal": "unknown", "none": "unattempted"},
                {"full": "unknown", "minimal": "unattempted", "none": "unattempted"},
            ]
            assert sorted((item.kind, item.candidate) for item in result.findings) == [
                ("reproduction", "hack-a"), ("reproduction", "hack-a"), ("reproduction", "hack-b")]
            requests = interpretation_requests(endpoint)
            texts = dict(sink["episodes"])
            minimal = next(attempt for attempt in result.attempts if attempt.candidate == "hack-a" and attempt.level == "minimal")
            target = requests[minimal.episode]["target_candidate"]
            assert target["mechanism"] == "absent file reward" and target["full_guidance"] == full_a
            assert full_b not in json.dumps(target) and "grader file reward" not in json.dumps(target)
            assert texts[minimal.episode] == f"{attack_module.EXPLOIT_INSTRUCTION}\n{FLAW}\nHint:\n{shared}"
            assert full_a not in texts[minimal.episode] and inspection.HACK_CHECKLIST not in texts[minimal.episode]
            warnings = []
            section = report.attack(result, run.record, warnings)
            assert section["candidates"][0]["conditions"]["minimal"]["evidence"] == "found"
            assert section["candidates"][1]["conditions"]["minimal"]["evidence"] == "not found"
            assert section["candidates"][2]["conditions"]["full"]["attempts"] == 2
            reproduced = next(item for item in section["exploits"]["reproduction"] if item["attempt"] == result.attempts.index(minimal))
            assert reproduced["candidate"] == "hack-a" and reproduced["sources"] == ["hack-a"]

    asyncio.run(main())


@pytest.mark.parametrize("discovery_attempts", [0, 1, 3])
def test_discovery_attempts_are_a_total_that_needs_no_candidate(tmp_path, monkeypatch, credentials, discovery_attempts):
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            options = {} if discovery_attempts == 1 else {"discovery_attempts": discovery_attempts}
            result = await attack_module.attack(run, maximum_attempts=2, **options)
            assert levels(result) == ["none"] * discovery_attempts
            assert len({attempt.context for attempt in result.attempts}) == len({attempt.episode for attempt in result.attempts}) == discovery_attempts
            assert result.candidates == []
            assert result.unavailable == {"full": attack_module.NO_CANDIDATE, "minimal": attack_module.NO_CANDIDATE}
            assert result.discovery_attempts == discovery_attempts
            if discovery_attempts:
                assert result.discovery == {"none": "unknown"} and result.status == "partial"
            else:
                assert result.discovery == {"none": "unattempted"} and result.status == "complete"
                assert any("disabled" in limit for limit in result.limits)

    asyncio.run(main())


def test_each_attacker_episode_and_attack_inspector_session_logs_its_start_and_end(tmp_path, monkeypatch, credentials, caplog):
    caplog.set_level(logging.INFO, logger="nudi")
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"], secret = run, next(iter(run.keys.values()))

            async def native(config, queue, **work):
                # The task names its rewards; a name equal to the run's credential must not reach the log.
                work["_names"] = sink["episodes"]
                result = await scripted_episodes(config, queue, **work)
                result.rewards = {secret: 1.0}
                (config.output_dir / "episode.json").write_text(result.model_dump_json())
                return result

            monkeypatch.setattr(run_state, "run_episode", native)
            caplog.clear()
            return secret, await attack_module.attack(run, maximum_attempts=2)

    secret, result = asyncio.run(main())
    lines = [re.sub(r"after \d+:\d\d:\d\d", "after T", record.getMessage()) for record in caplog.records if record.name == "nudi"]
    assert not any(secret in line for line in lines)
    title = "attack_inspector-attacker-none-none-1"
    assert lines == [
        "Attacker 0000-attacker started",
        "Attacker 0000-attacker finished after T: rewards [1.0]",
        f"attack inspector {title} started",
        f"attack inspector {title} ended after T; searched accepted_invalid",
        "Attacker 0000-attacker result: unclear: no reading decided whether the work is invalid",
    ]
    assert len(result.assessments) == 1
    # Each line is an event of the run's log, after the run's own first one, with the values it is built from.
    logged = [json.loads(line) for line in (tmp_path / "run" / "events.jsonl").read_text().splitlines()][1:]
    assert [re.sub(r"after \d+:\d\d:\d\d", "after T", item["text"].split(" ", 2)[2]) for item in logged] == lines
    assert not any(secret in item["text"] for item in logged)
    for item in logged[1:4:2]:
        assert type(item.pop("elapsed")) is int
    cost = ("known_cost", "unknown_cost_calls", "cancelled_calls")
    assert [{key: value for key, value in item.items() if key not in ("v", "time", "text", *cost)} for item in logged] == [
        {"kind": "attempt_start", "episode": "0000-attacker", "candidate": None, "level": "none", "number": 1},
        {"kind": "attempt_end", "episode": "0000-attacker", "candidate": None, "level": "none", "number": 1, "rewards": [1.0]},
        {"kind": "session_start", "inspector": "attack", "session": title, "category": None, "episode": "0000-attacker"},
        {"kind": "session_end", "inspector": "attack", "session": title, "status": "unobservable", "category": "accepted_invalid",
         "category_status": "pending", "result": "open"},
        {"kind": "attempt_result", "episode": "0000-attacker", "problem": None, "level": "none", "number": 1, "status": "unknown"},
    ]


def test_an_attempt_of_a_problem_names_it_in_its_attempt_and_attack_inspector_events(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=[candidate("hack-0", FULL)],
                                       problems=[attack_module.Problem(id="P1", source="hack", cause="c", findings=["hack-0"])])

    asyncio.run(main())
    logged = [json.loads(line) for line in (tmp_path / "run" / "events.jsonl").read_text().splitlines()]
    assert [(item["kind"], item.get("problem")) for item in logged if "start" in item["kind"] or "attempt" in item["kind"]][1:] == [
        ("attempt_start", "P1"), ("attempt_end", "P1"), ("session_start", "P1"), ("attempt_result", "P1")]


def test_hinted_attempts_can_be_disabled_without_suppressing_discovery(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            result = await attack_module.attack(run, maximum_attempts=0, candidates=[candidate("hack-0", FULL, MINIMAL)])
            assert levels(result) == ["none"]
            assert result.candidates[0].conditions == {"full": "unattempted", "minimal": "unattempted", "none": "unattempted"}
            assert result.discovery == {"none": "unknown"}

    asyncio.run(main())


def test_missing_guidance_is_explicit_and_no_hint_still_runs(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}
    reasons = {"full": "candidate exists but generated full guidance unavailable"}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            result = await attack_module.attack(run, maximum_attempts=2, candidates=[candidate("hack-0", None, "  ", reasons)])
            (item,) = result.candidates
            assert item.conditions == {"full": "unavailable", "minimal": "unavailable", "none": "unattempted"}
            assert item.unavailable["full"] == reasons["full"]
            assert "not supplied" in item.unavailable["minimal"].lower()
            assert result.unavailable == {}
            assert levels(result) == ["none"]
            assert result.discovery == {"none": "unknown"}
            texts = [text or "" for _, text, _, _ in sink["episodes"]]
            assert texts and all("No extra hint" in text and "Details:" not in text and "Hint:" not in text for text in texts)
            assert result.status != "safe"
            assert not any(SAFETY in limit for limit in result.limits)

    asyncio.run(main())


def attributing(body):
    """An evidenced exploit in every attacker episode."""
    request = json.loads(body["messages"][-1]["content"])
    claim = {"mechanism": "accepted absent answer", "check": f"check-{request['episode']}",
             "interpretation": "The required file is absent while the native reward is 1.",
             "marks": ["exists"], "derivation": {"observations": ["exists"], "validity": "violated"}}
    return {"claim": claim}


def evidenced_claim(body):
    text = body["messages"][-1]["content"]
    if "Details:" in text:
        return {"claim": {"mechanism": "accepted invalid reward", "check": "check-full",
                          "interpretation": "The required file is absent while the native reward is 1.",
                          "marks": ["exists"], "derivation": {"observations": ["exists"], "validity": "violated"}}}
    return plain_claim(body)


def install_issue(run, name, check="check-full", **work):
    """A check of this episode's bound copy: absent required state, native reward 1."""
    task = run.config.task_dir
    ids = {"trial_id": f"id-{name}"}
    result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(task), task_digest=tree_digest(task),
                           model="xai/grok-4.7", reasoning_effort=None, versions={}, ids=ids, rewards={"reward": 1.0},
                           artifacts={"nudi_evidence": "nudi-evidence"})
    episode = run.config.output_dir / "episodes" / name
    episode.mkdir(parents=True, exist_ok=True)
    (episode / "episode.json").write_text(result.model_dump_json())
    retain_instruction(episode, task, work)
    copy = retain_copy(run, name, ids)
    sandboxed_check(run, copy, Observation(episode=None, path="instruction.md", excerpt="Write the number 42"),
                    Observation(episode=None, path="tests/test.sh", excerpt="answer_ok"), "print(1)",
                    json.dumps({"observations": {"exists": 0}, "results": {"deserved": 0}}), check_id=check)


def bind_reproducing_runner(monkeypatch, sink):
    """As bind_runner, but a full-hint attempt reproduces with `evidenced_claim`, so its minimal hint follows."""
    async def native(config, queue, **work):
        instruction = work.get("instruction") or ""
        if "Details:" not in instruction:
            work["_names"] = sink["episodes"]
            return await scripted_episodes(config, queue, **work)
        name = config.output_dir.name
        config.output_dir.mkdir(parents=True, exist_ok=True)
        sink["episodes"].append((name, instruction, work.get("agent"), config.native))
        install_issue(sink["run"], name, **work)
        return EpisodeResult.model_validate_json((config.output_dir / "episode.json").read_text())

    monkeypatch.setattr(run_state, "run_episode", native)


def test_first_evidenced_success_stops_only_that_level(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(evidenced_claim)
    sink = {"episodes": []}

    async def native(config, queue, **work):
        assert queue is sink["run"].queue
        name = config.output_dir.name
        config.output_dir.mkdir(parents=True, exist_ok=True)
        instruction = work.get("instruction") or ""
        sink["episodes"].append((name, instruction, work.get("agent"), config.native))
        if "Details:" in instruction:
            install_issue(sink["run"], name, **work)
        else:
            await scripted_episodes(config, queue, **work)
        return EpisodeResult.model_validate_json((config.output_dir / "episode.json").read_text())

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=2, full=FULL, minimal=MINIMAL)
            assert levels(result) == ["full", "none", "minimal", "minimal"]
            assert result.conditions["full"] == "evidenced_issue"
            assert result.conditions["minimal"] == "unknown"
            assert result.conditions["none"] == "unknown"
            matched = [item for item in result.assessments if item.outcome == "accepted_invalid"]
            assert len(matched) == 1 and inspection.evidenced(matched[0])
            assert sum(attempt.status == "evidenced_issue" for attempt in result.attempts) == 1

    asyncio.run(main())


def test_rejected_valid_work_counts_only_for_a_valid_work_candidate(tmp_path, monkeypatch, credentials):
    """A hack inspector's rejected valid work is a valid-work candidate. Its Attacker attempts
    keep a native rejected_valid of their episode; an ordinary attempt's rejected_valid stops nothing."""
    def inspector(body):
        request = json.loads(body["messages"][-1]["content"])
        check = f"check-{request['episode']}"
        return {"claim": {"mechanism": "false rejection", "check": check, "interpretation": "Valid work scored 0."}}

    endpoint = attack_endpoint(inspector)
    sink = {"episodes": []}

    def assessed(claim, directory):
        # Each reading reads the one approved requirement supported, so nudi's decision keeps correct work failed.
        claim = claim.model_copy(update={"marks": ["shown"], "derivation": Derivation(observations=["shown"], validity="supported")})
        return Assessment(claim=claim, execution_scope="native", check=linked_check(claim.episode, claim.check), outcome="rejected_valid",
                          validity="supported")

    valid = candidate("valid-0", "Write the answer in the documented format.", mechanism="the grader rejects the documented format")
    valid.valid_work = True

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            run.record.requirements = [Requirement(text="Write the number 42", observation="shown")]
            bind_runner(monkeypatch, sink)
            monkeypatch.setattr(inspection, "assess", assessed)
            return await attack_module.attack(run, maximum_attempts=2, candidates=[candidate("hack-0", FULL, MINIMAL), valid])

    result = asyncio.run(main())
    built = report.build(sink["run"].config.output_dir, selected=["attack"])
    assert [(item["id"], item["valid_work"]) for item in built["attack"]["candidates"]] == [("hack-0", False), ("valid-0", True)]
    text = report.markdown(built)
    # hack-0's first full-hint attempt runs first, then discovery, so valid-0's full attempt is the third episode.
    assert "- 0002-attacker had work the grader failed with full instructions written for valid-0" in text
    assert "- 0000-attacker tested hack-0 with full instructions: reward 1; no exploit was evidenced" in text
    assert [(attempt.candidate, attempt.level) for attempt in result.attempts] == [
        ("hack-0", "full"), (None, "none"), ("valid-0", "full"), ("hack-0", "full")]
    assert [result.assessments[attempt.assessment].outcome for attempt in result.attempts] == ["rejected_valid"] * 4
    assert [attempt.status for attempt in result.attempts] == ["no_evidenced_issue"] * 2 + ["evidenced_issue", "no_evidenced_issue"]
    assert result.candidates[0].conditions == {"full": "no_evidenced_issue", "minimal": "not_needed", "none": "not_needed"}
    assert result.candidates[1].conditions["full"] == "evidenced_issue" and result.discovery == {"none": "no_evidenced_issue"}
    assert [(finding.kind, finding.candidate) for finding in result.findings] == [("reproduction", "valid-0")]
    texts = {name: text for name, text, _, _ in sink["episodes"]}
    requests = interpretation_requests(endpoint)
    for attempt in result.attempts:
        valid_work = attempt.candidate == "valid-0"
        assert texts[attempt.episode].startswith(attack_module.VALID_WORK_INSTRUCTION if valid_work else attack_module.EXPLOIT_INSTRUCTION)
        assert requests[attempt.episode]["valid_work"] is valid_work
        assert requests[attempt.episode]["categories"] == []


def two_probes(body):
    return {"probes": [
        {"category": "package_oracles", "location": "/app/one"},
        {"category": "package_oracles", "location": "/app/two"},
    ]}


def number(probe) -> int:
    """Which of `two_probes` this is."""
    return {"/app/one": 1, "/app/two": 2}[probe["location"]]


def scripted_investigation(monkeypatch, later, first_outcome, investigated, unresolved=()):
    """The attack inspector's first measured probe returns `first_outcome`; the second fails or
    reaches the spending cap."""
    from test_inspection import mock_experiments

    async def measured(run, probe, session):
        investigated.append((probe["episode"], number(probe)))
        if number(probe) == 2:
            if later == "capped":
                raise run_state.SpendingCapReached("scripted cap")
            raise RuntimeError("later probe failed")
        claim = Claim(mechanism="scripted", episode=probe["episode"], check="check-scripted", unresolved=list(unresolved))
        return Assessment(claim=claim, outcome=first_outcome, check=linked_check(probe["episode"], "check-scripted"))

    mock_experiments(monkeypatch, measured)


# A finding with an open condition stops the attempts like any finding; the Attacker decides nothing more.
@pytest.mark.parametrize("later, unresolved", [("failing", []), ("capped", []), ("failing", ["whether the copied grader is the hosted one"])])
def test_first_evidenced_probe_stops_its_level_before_later_attempts(tmp_path, monkeypatch, credentials, later, unresolved):
    endpoint = attack_endpoint(two_probes)
    investigated = []

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, concurrency=2, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            scripted_investigation(monkeypatch, later, "accepted_invalid", investigated, unresolved)
            result = await attack_module.attack(run, maximum_attempts=2, full=FULL)
            assert levels(result) == ["full", "none"]
            # One attack inspector session measures all its probes; its finding then stops the level's later attempts.
            assert investigated == [(attempt.episode, number) for attempt in result.attempts for number in (1, 2)]
            assert [attempt.status for attempt in result.attempts] == ["evidenced_issue"] * 2
            assert [attempt.assessment for attempt in result.attempts] == [0, 1]
            assert all(inspection.evidenced(assessment) for assessment in result.assessments)
            assert result.conditions == {"full": "evidenced_issue", "minimal": "unavailable", "none": "evidenced_issue"}
            assert result.status == "complete"

    asyncio.run(main())


@pytest.mark.parametrize("later", ["failing", "capped"])
def test_provisional_probe_result_survives_a_later_probe_failure(tmp_path, monkeypatch, credentials, later):
    endpoint = attack_endpoint(two_probes)
    investigated = []

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            scripted_investigation(monkeypatch, later, "unknown", investigated)
            result = await attack_module.attack(run, maximum_attempts=1)
            (attempt,) = result.attempts
            assert investigated == [(attempt.episode, 1), (attempt.episode, 2)]
            assert [assessment.outcome for assessment in result.assessments] == ["unknown"]
            assert attempt.assessment == 0
            saved = json.loads((run.config.output_dir / "attack.json").read_text())
            assert [item["outcome"] for item in saved["assessments"]] == ["unknown"]
            if later == "capped":
                assert attempt.status == result.status == result.conditions["none"] == "spending_exhausted"
            else:
                assert attempt.status == result.conditions["none"] == "tool_failure"
                assert "later probe failed" in attempt.error
                assert result.status == "partial"

    asyncio.run(main())


@pytest.mark.parametrize("repaired", [True, False])
def test_a_check_that_exited_non_zero_leaves_the_attempt_unknown_only_until_it_is_repaired(tmp_path, monkeypatch, credentials, repaired):
    """The failed check's own assessment is no reading of the submission, so a repair that reads it legitimate
    decides the attempt; without one the attempt stays unknown."""
    from test_inspection import mock_experiments
    endpoint = attack_endpoint(two_probes)

    async def measured(run, probe, session):
        failed = number(probe) == 1 or not repaired
        check = linked_check(probe["episode"], f"check-{number(probe)}").model_copy(update={"exit_code": 3 if failed else 0})
        claim = Claim(mechanism="scripted", episode=probe["episode"], check=check.id)
        return Assessment(claim=claim, outcome="unknown" if failed else "legitimate", check=check)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            mock_experiments(monkeypatch, measured)
            result = await attack_module.attack(run, maximum_attempts=1)
            (attempt,) = result.attempts
            assert [assessment.check.exit_code for assessment in result.assessments] == [3, 0 if repaired else 3]
            assert attempt.status == ("no_evidenced_issue" if repaired else "unknown")

    asyncio.run(main())


def test_later_replay_does_not_evidence_the_earlier_attempt(tmp_path, monkeypatch, credentials):
    sink = {"episodes": []}

    def inspector(body):
        return {"claim": {"mechanism": "replayed commands", "check": "check-later", "interpretation": "later output"}}

    endpoint = attack_endpoint(inspector)

    async def native(config, queue, **work):
        sink["episodes"].append(config.output_dir.name)
        return await scripted_episodes(config, queue, **work)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            later = "9000-replay"
            later_dir = run.config.output_dir / "episodes" / later / "nudi-evidence"
            later_dir.mkdir(parents=True)
            (later_dir / "state.json").write_text("later")
            content = Content(episode=later, path="nudi-evidence/state.json", sha256=hashlib.sha256(b"later").hexdigest())
            ids = {"trial_id": "id-later"}
            result = EpisodeResult(path="harbor", path_reasons=[], task_name="task", task_dir=str(run.config.task_dir),
                                   task_digest=tree_digest(run.config.task_dir), model="xai/grok-4.7", reasoning_effort=None,
                                   versions={}, ids=ids, rewards={"reward": 1.0}, artifacts={"nudi_evidence": "nudi-evidence"})
            (later_dir.parent / "episode.json").write_text(result.model_dump_json())
            from nudi.records import Check
            run.record.episodes.append(later)
            run.record.checks.append(Check(id="check-later", content=content, ids=ids,
                                          requirement=Observation(episode=None, path="instruction.md", excerpt="Write the number 42"),
                                          command=["python"], exit_code=0, output="{}"))
            attacker = f"{len(run.record.episodes):04d}-attacker"
            run.save()

            async def native_with_inputs(config, queue, **work):
                name = config.output_dir.name
                config.output_dir.mkdir(parents=True, exist_ok=True)
                (config.output_dir / "nudi-evidence").mkdir(exist_ok=True)
                (config.output_dir / "nudi-evidence" / "commands.txt").write_text("commands")
                sink["episodes"].append(name)
                return await scripted_episodes(config, queue, **work)

            monkeypatch.setattr(run_state, "run_episode", native_with_inputs)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert result.attempts, result.status
            assert result.attempts[0].episode == attacker
            assert result.assessments[0].outcome == "unknown"
            assert "replay" not in result.assessments[0].model_dump()
            assert any("does not establish" in reason for reason in result.assessments[0].reasons)
            assert result.conditions["none"] == "unknown"
            assert not inspection.evidenced(result.assessments[0])

    asyncio.run(main())




def test_unhinted_discovery_enters_the_existing_check_path(tmp_path, monkeypatch, credentials):
    calls = []

    def inspector(body):
        text = body["messages"][-1]["content"]
        if "completed check" in text:
            return {"claim": {"mechanism": "new unhinted boundary", "interpretation": "still unproven", "unresolved": ["bounds"]}}
        return {"probes": [{"category": "package_oracles", "location": "/app/answer.txt", "capture_point": "verification_start",
                            "timing": "The requirement applies at verification start.", "program": "print(1)",
                            "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"},
                            "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": "answer_ok"}}]}

    endpoint = attack_endpoint(inspector)

    async def checked(run, copy, requirement, scoring, program, **kwargs):
        return sandboxed_check(run, copy, requirement, scoring, program, "{}")

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})

            async def native(config, queue, **work):
                result = await scripted_episodes(config, queue, **work)
                retain_copy(run, config.output_dir.name, result.ids)
                return result

            monkeypatch.setattr(run_state, "run_episode", native)
            monkeypatch.setattr(inspection, "check_submission", checked)
            real = inspection.measure_experiment

            async def wrapped(run, probe):
                calls.append(probe.get("episode"))
                assert "instruction" not in probe
                return await real(run, probe)

            monkeypatch.setattr(inspection, "measure_experiment", wrapped)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert result.attempts, result.status
            assert calls == [result.attempts[0].episode]
            assert result.attempts[0].episode.endswith("-attacker")
            assert run.record.checks[-1].id == result.assessments[0].claim.check
            assert result.assessments[0].outcome == "unknown"
            assert result.conditions["none"] == "unknown"
            assert run.record.probe_episodes == []

    asyncio.run(main())


@pytest.mark.parametrize("kind", ["model_inability", "model_output_failure", "tool_failure", "infrastructure_failure", "native_timeout",
                                  "out_of_memory"])
def test_attempt_failures_stay_distinct(tmp_path, monkeypatch, credentials, kind):
    class Raw:
        def __init__(self):
            self.requests = []

        async def chat(self, request):
            body = await request.json()
            self.requests.append(body)
            message = {"role": "assistant", "content": json.dumps({"instruction": "attempt a reward boundary"})}
            if body.get("tools") and kind == "model_inability":
                message = call(body, "InspectionSummary", {"refusal": "declines this condition", "completed": []})
            elif body.get("tools") and kind == "model_output_failure":
                message = {"role": "assistant", "content": "not-json"}
            return web.json_response({"id": "attack", "object": "chat.completion", "created": 0, "model": body["model"],
                                      "choices": [{"index": 0, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop", "message": message}],
                                      "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}})

    endpoint = Raw()
    if kind == "out_of_memory":
        async def ask(*args, **kwargs):
            # How the attack inspector session reports a workspace command that Modal stopped for lack of memory.
            raise inspection.InferenceFailure("ModalFailure: Modal exec failed: sandbox killed, out of memory (exit 137)")
        monkeypatch.setattr("nudi.inspector.Investigation.ask", ask)

    async def native(config, queue, **work):
        if kind == "tool_failure":
            raise RuntimeError("checker crashed")
        result = await scripted_episodes(config, queue, **work)
        if kind == "infrastructure_failure":
            result.errors = [ErrorRecord(type="DockerEnvironmentError", message="daemon unavailable")]
            (config.output_dir / "episode.json").write_text(result.model_dump_json())
        if kind == "native_timeout":
            # Without a reward; a timeout with a reward is interpreted.
            result.agent_timeout, result.rewards = True, {}
            (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert result.attempts, result.status
            assert result.attempts[0].status == kind
            assert result.conditions["none"] == kind
            assert result.status == "partial"
            assert result.conditions["full"] == "unavailable"
            others = {"refused", "model_inability", "model_output_failure", "inference_failure", "tool_failure", "infrastructure_failure", "native_timeout",
                      "out_of_memory", "spending_exhausted", "cancelled"} - {kind}
            assert result.attempts[0].status not in others
            # A failure the attack did not recover from leaves it unfinished, apart from unresolved evidence.
            built = report.build(run.config.output_dir, selected=["attack"])
            assert (built["status"], built["unfinished"], built["unresolved"]) == ("partial", {"attack": "partial"}, [])
            # The line names the agent that failed.
            lost = {"Attacker": "the Attacker failed to run in", "attack inspector": "the attack inspector failed on",
                    None: "an attack attempt failed in"}[result.attempts[0].failed]
            assert built["answer"][0].startswith(f"Finished with gaps: {lost} {result.attempts[0].episode}")

    asyncio.run(main())


def test_native_timeout_with_a_reward_is_interpreted(tmp_path, monkeypatch, credentials):
    """A timed-out attacker episode that still produced a reward is interpreted; the timeout stays a limit."""
    endpoint = attack_endpoint(plain_claim)

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        (config.output_dir / "trace.txt").write_text("attempted the reward boundary")
        result.artifacts["trajectory"] = "trace.txt"
        result.agent_timeout, result.errors = True, [ErrorRecord(type="AgentTimeoutError", message="agent timed out")]
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert [attempt.status for attempt in result.attempts] == ["unknown"]
            assert result.conditions["none"] == "unknown" and result.status == "partial"
            assert any("agent_timeout" in limit and result.attempts[0].episode in limit for limit in result.limits)

    asyncio.run(main())


def test_native_timeout_without_a_trajectory_stays_partial(tmp_path, monkeypatch, credentials):
    """A rewarded timeout is interpreted, but without its trajectory an unproven claim is not a negative result."""
    endpoint = attack_endpoint(plain_claim)

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        result.agent_timeout, result.errors = True, [ErrorRecord(type="AgentTimeoutError", message="agent timed out")]
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=1, candidates=[])
            assert result.attempts[0].episode in interpretation_requests(endpoint)
            assert [attempt.status for attempt in result.attempts] == ["native_timeout"]
            assert result.discovery == {"none": "native_timeout"} and result.status == "partial"
            # A timeout with neither a reward nor an interpretation is an execution failure, so the attack did not run to its end.
            built = report.build(run.config.output_dir, selected=["attack"])
            assert (built["status"], built["unfinished"], built["unresolved"]) == ("partial", {"attack": "partial"}, [])

    asyncio.run(main())


def missing_check_claim(body):
    return {"claim": {**plain_claim(body)["claim"], "check": "check-9999"}}


@pytest.mark.parametrize("reply, rewards, outcomes, status, attack", [
    (plain_claim, {"reward": 1.0}, ["unknown"], "unknown", "partial"),
    (plain_claim, {"reward": 0.0}, [], "no_evidenced_issue", "complete"),  # no reward, so no attack inspector session
    (lambda body: {"probes": []}, {"reward": 1.0}, [], "unknown", "partial"),  # nothing was assessed
    (missing_check_claim, {"reward": 1.0}, ["ungrounded"], "unknown", "partial"),
    (plain_claim, {"score": 1.0}, ["unavailable"], "unknown", "partial"),  # the claim's default reward key is absent
])
def test_rewarded_episode_without_a_judged_submission_stays_unknown(tmp_path, monkeypatch, credentials, reply, rewards, outcomes, status, attack):
    """An unproven, ungrounded or unscored claim, or no assessment, leaves the graded submission unjudged.
    With a positive reward that is not a negative result."""
    endpoint = attack_endpoint(reply)

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        result.rewards = rewards
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=1, candidates=[])
            assert [item.outcome for item in result.assessments] == outcomes
            assert [attempt.status for attempt in result.attempts] == [status]
            assert result.discovery == {"none": status} and result.status == attack

    asyncio.run(main())


def test_attack_inspector_verdict_without_a_check_of_this_episode_is_an_explicit_unknown(tmp_path, monkeypatch, credentials):
    """A claimed verdict with no check is not invented into a probe: it stays unknown with its reason."""
    verdict = {"claim": {"mechanism": "accepted absent answer", "interpretation": "The file looks absent.",
                         "marks": ["exists"], "derivation": {"observations": ["exists"], "validity": "violated"}}}
    endpoint = attack_endpoint(lambda body: verdict)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=1, candidates=[])
            (assessment,) = result.assessments
            assert assessment.outcome == "unknown" and assessment.check is None
            assert "no check has tested the graded submission" in assessment.reasons
            assert [attempt.status for attempt in result.attempts] == ["unknown"], "the rewarded-but-unjudged rule"
            assert run.record.checks == []

    asyncio.run(main())


OPEN = ["open condition 1", "open condition 2"]


@pytest.mark.parametrize("reward, retained, status", [
    (1.0, [("legitimate", OPEN), ("legitimate", OPEN)], "unknown"),  # a legitimate result with an open condition is not clean
    (1.0, [("unknown", []), ("legitimate", [])], "unknown"),  # an earlier assessment stayed unjudged
    (1.0, [("legitimate", [])], "no_evidenced_issue"),
    (0.0, [("legitimate", OPEN), ("legitimate", OPEN)], "no_evidenced_issue"),
])
def test_rewarded_attempt_with_any_unjudged_assessment_stays_unknown(tmp_path, monkeypatch, credentials, reward, retained, status):
    """Every assessment the attempt retained counts, and an open necessary condition leaves it unjudged."""
    from test_inspection import mock_experiments

    endpoint = attack_endpoint(lambda body: {"probes": [{"category": "package_oracles", "location": f"/app/{index}"} for index in range(len(retained))]})
    outcomes = iter(retained)

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        result.rewards = {"reward": reward}
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result

    async def investigate(run, probe, session):
        outcome, unresolved = next(outcomes)
        return Assessment(claim=Claim(mechanism="scripted", episode=probe["episode"], unresolved=unresolved), outcome=outcome)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            mock_experiments(monkeypatch, investigate)
            result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=1, candidates=[])
            # An unrewarded ordinary attempt gets no attack inspector session.
            assert [item.outcome for item in result.assessments] == [outcome for outcome, _ in retained if reward]
            assert [attempt.status for attempt in result.attempts] == [status]
            assert result.discovery == {"none": status}

    asyncio.run(main())


def test_a_measured_experiment_left_uninterpreted_keeps_a_rewarded_attempt_unknown(tmp_path, monkeypatch, credentials):
    """One legitimate interpreted check, then a measured receipt the session never interprets:
    its reading is left unfinished and unknown, so the attempt is not a negative result."""
    from test_inspection import mock_experiments

    endpoint = attack_endpoint(lambda body: {"probes": [{"category": "package_oracles", "location": "/app/0"},
                                                        {"category": "package_oracles", "location": "/app/1", "nudi_uninterpreted": True}]})

    async def investigate(run, probe, session):
        return Assessment(claim=Claim(mechanism="scripted", episode=probe["episode"]), outcome="legitimate")

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            mock_experiments(monkeypatch, investigate)
            result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=1, candidates=[])
            assert [item.outcome for item in result.assessments] == ["legitimate", "unknown"]
            assert result.assessments[1].reasons == [inspection.UNFINISHED] and result.assessments[1].nudi_claim
            assert [attempt.status for attempt in result.attempts] == ["unknown"]
            assert result.discovery == {"none": "unknown"}

    asyncio.run(main())


def test_a_claim_citing_another_episode_is_refused_in_an_attack_inspector_session(tmp_path, monkeypatch, credentials):
    """The attack inspector's claim schema has no citations, so a cited episode is an argument error and nothing is
    assessed from that claim; its draft is left unfinished."""
    from test_inspection import mock_experiments

    endpoint = attack_endpoint(lambda body: {"probes": [{"category": "package_oracles", "location": "/app/answer.txt"}]})

    async def investigate(run, probe, session):
        cited = Observation(episode="0000-simulator", path="trace.txt", excerpt="answer")
        return Assessment(claim=Claim(mechanism="scripted", episode=probe["episode"], citations=[cited]), outcome="legitimate")

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            mock_experiments(monkeypatch, investigate)
            result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=1, candidates=[])
            (attempt,) = result.attempts
            tools = [str(message["content"]) for message in session_messages(run.config.output_dir, f"attack_inspector-{attempt.context}")
                     if message["role"] == "tool"]
            assert any("Error invoking tool 'interpret_experiment'" in text and "citations" in text for text in tools)
            assert [item.reasons for item in result.assessments] == [[inspection.UNFINISHED]] and attempt.status == "unknown"

    asyncio.run(main())


def test_failed_attempt_then_evidenced_exploit_completes_the_attack(tmp_path, monkeypatch, credentials):
    """The first no-hint attempt fails; the second evidences an exploit, which settles the stream."""
    endpoint = attack_endpoint(attributing)
    sink, started = {}, []

    async def native(config, queue, **work):
        name = config.output_dir.name
        started.append(name)
        if len(started) == 1:
            raise RuntimeError("checker crashed")
        install_issue(sink["run"], name, check=f"check-{name}", **work)
        return EpisodeResult.model_validate_json((config.output_dir / "episode.json").read_text())

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=2)
            assert [attempt.status for attempt in result.attempts] == ["tool_failure", "evidenced_issue"]
            assert result.discovery == {"none": "evidenced_issue"} and result.status == "complete"
            # The second attempt recovered from the failed first one, so every step ran.
            assert report.build(run.config.output_dir, selected=["attack"])["unfinished"] == {}

    asyncio.run(main())


def test_spending_cap_and_cancellation_are_separate(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, concurrency=2, spending_cap=1, models={"attacker": model, "inspector": model})
            run.record.known_cost = 1
            result = await attack_module.attack(run, maximum_attempts=2, full=FULL, minimal=MINIMAL)
            assert result.attempts, result.status
            assert result.status == "spending_exhausted"
            assert result.attempts[0].status == "spending_exhausted"
            assert [attempt.level for attempt in result.attempts] == ["full"]
            assert result.candidates[0].conditions == {"full": "spending_exhausted", "minimal": "unattempted", "none": "unattempted"}
            assert endpoint.requests == []
            assert not any(SAFETY in limit for limit in result.limits)

            run.record.known_cost = 0
            async def cancel(config, queue, **work):
                raise asyncio.CancelledError()
            monkeypatch.setattr(run_state, "run_episode", cancel)
            with pytest.raises(asyncio.CancelledError):
                await attack_module.attack(run, maximum_attempts=1)
            saved = json.loads((run.config.output_dir / "attack.json").read_text())
            assert saved["status"] == "cancelled"
            assert saved["attempts"][-1]["status"] == "cancelled"

    asyncio.run(main())


def test_a_task_environment_that_cannot_start_stops_the_attack(tmp_path, monkeypatch, credentials):
    """EnvironmentUnavailable from the attack inspector ends the attack with that status instead of a
    per-attempt tool failure followed by the next Attacker episode."""
    from nudi.records import EnvironmentUnavailable

    run = new_run(tmp_path, monkeypatch, credentials, concurrency=2)  # One attempt at a time.
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)

    async def inspect(*args, **kwargs):
        raise EnvironmentUnavailable("the task's verifier environment failed to start 3 times in a row")

    monkeypatch.setattr(attack_module, "inspect", inspect)
    with pytest.raises(EnvironmentUnavailable):
        asyncio.run(attack_module.attack(run, maximum_attempts=2, discovery_attempts=2, full=FULL, minimal=MINIMAL))
    saved = json.loads((run.config.output_dir / "attack.json").read_text())
    assert saved["status"] == "environment_unavailable"
    assert [(attempt["level"], attempt["status"]) for attempt in saved["attempts"]] == [("full", "environment_unavailable")]


def judged(name, outcome="legitimate"):
    """An attack inspector session's result: one native reading of episode `name`, attributed to its own check, and the
    experiment that measured it."""
    check = f"check-{name}"
    claim = Claim(mechanism="scripted", interpretation="Scripted reading.", episode=name, check=check, marks=["shown"])
    return inspection.InspectionResult(mode="attack", categories={}, applicability={}, status="complete",
                                       experiments=[{"id": "experiment-0000", "category": outcome, "status": "assessed", "check": check,
                                                     "episode": name, "location": "/app/answer.txt", "capture_point": "verification_start"}],
                                       assessments=[Assessment(claim=claim, outcome=outcome, check=linked_check(name, check))],
                                       attempts=[inspection.InspectionAttempt(phase="episode", episode=name, number=1, status="no_evidenced_issue")])


def test_attacker_attempts_run_at_once_keep_running_ones_copies_and_are_saved_in_plan_order(tmp_path, monkeypatch, credentials):
    """Measured runs planned 37 to 53 Attacker episodes and ran 1 to 8 of them. Half the run's concurrency of attempts, each with
    its attack inspector session, run at once. An attempt deletes only its own copies, when it ends. The attempts,
    their readings and findings are saved in plan order, not in the order they ended."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    running, peak, ended, copies = set(), [0], asyncio.Event(), {}

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        copies[config.output_dir.name] = retain_copy(run, config.output_dir.name, result.ids)
        return result

    async def inspect(run, mode, pool, focused_attempts, categories, *, title, workspace, request):
        target = (request["target_candidate"] or {}).get("id")
        running.add(target)
        peak[0] = max(peak[0], len(running))
        await asyncio.sleep(0.01)
        if target == "hack-0":
            # hack-0 ends last. Discovery's attempt started and ended meanwhile, after hack-1's had ended.
            await asyncio.wait_for(ended.wait(), 2)
            assert not workspace.deleted and copies["0001-attacker"].deleted, "only the ended attempt's copy went"
        running.discard(target)
        ended.set() if target is None else None
        return judged(pool[0], "accepted_invalid" if target == "hack-0" else "legitimate")

    monkeypatch.setattr(run_state, "run_episode", native)
    monkeypatch.setattr(attack_module, "inspect", inspect)
    result = asyncio.run(attack_module.attack(run, maximum_attempts=1, candidates=[candidate("hack-0", "FULL-0"), candidate("hack-1", "FULL-1")]))
    assert peak[0] == 2
    assert [(item.candidate, item.episode, item.status) for item in result.attempts] == [
        ("hack-0", "0000-attacker", "evidenced_issue"), ("hack-1", "0001-attacker", "no_evidenced_issue"),
        (None, "0002-attacker", "no_evidenced_issue")]
    assert [result.assessments[item.assessment].claim.episode for item in result.attempts] == [item.episode for item in result.attempts]
    assert [item.claim.episode for item in result.assessments] == [item.episode for item in result.attempts]
    assert [(item.kind, item.candidate, item.attempt, item.assessment) for item in result.findings] == [("reproduction", "hack-0", 0, 0)]
    assert json.loads((run.config.output_dir / "attack.json").read_text()) == json.loads(result.model_dump_json())


def test_a_streams_next_attempt_waits_for_its_last_and_every_first_try_comes_before_any_retry(
        tmp_path, monkeypatch, credentials):
    """A candidate's attempts at one level run one after another, so its evidenced reproduction still skips its retry.
    A freed slot goes to the earliest attempt in plan order whose candidate has none running: a suspected candidate's
    first try before an evidenced candidate's retry, and that retry before the suspected candidate's."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    started, retried = [], asyncio.Event()

    async def inspect(run, mode, pool, focused_attempts, categories, *, title, workspace, request):
        context = title.removeprefix("attack_inspector-attacker-")
        started.append(context)
        retried.set() if context == "E1-full-2" else None
        if context == "E2-full-1":
            await asyncio.wait_for(retried.wait(), 2)
        return judged(pool[0], "accepted_invalid" if context == "E2-full-1" else "legitimate")

    monkeypatch.setattr(attack_module, "inspect", inspect)
    evidenced = [candidate(id, f"FULL-{id}").model_copy(update={"outcome": "accepted_invalid"}) for id in ("E1", "E2")]
    suspected = candidate("U", "FULL-U").model_copy(update={"outcome": "unknown"})
    result = asyncio.run(attack_module.attack(run, maximum_attempts=2, discovery_attempts=0, candidates=[*evidenced, suspected]))
    assert started == ["E1-full-1", "E2-full-1", "U-full-1", "E1-full-2", "U-full-2"]
    assert [item.context.removeprefix("attacker-") for item in result.attempts] == [
        "E1-full-1", "E2-full-1", "U-full-1", "E1-full-2", "U-full-2"]
    assert [item.conditions["full"] for item in result.candidates] == ["no_evidenced_issue", "evidenced_issue", "no_evidenced_issue"]


@pytest.mark.parametrize("left, started", [(10, False), (100, True)])
def test_a_valid_work_attempt_starts_only_when_its_agent_timeout_fits_the_time_left(tmp_path, monkeypatch, credentials, left, started):
    """With a time limit, a valid-work attempt whose agent timeout is longer than the time left does not start and is
    recorded as such; an exploit attempt starts either way. The report says why the valid-work attempt did not start."""
    run = new_run(tmp_path, monkeypatch, credentials)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)

    async def inspect(run, mode, pool, focused_attempts, categories, *, title, workspace, request):
        return judged(pool[0])

    monkeypatch.setattr(attack_module, "inspect", inspect)
    valid = candidate("valid-0", "FULL-V").model_copy(update={"valid_work": True})

    async def main():
        deadline = asyncio.get_running_loop().time() + left
        return await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, deadline=deadline,
                                          candidates=[candidate("hack-0", "FULL-0"), valid])

    # The contract task's agent timeout is 20 seconds.
    result = asyncio.run(main())
    exploit, work = result.attempts
    assert (exploit.candidate, exploit.episode) == ("hack-0", "0000-attacker")
    if started:
        assert work.episode == "0001-attacker" and work.status != "insufficient_time"
        return
    assert (work.candidate, work.episode, work.status) == ("valid-0", None, "insufficient_time")
    assert work.error.startswith("its agent timeout of 20 seconds is longer than the ")
    assert result.candidates[1].conditions["full"] == "insufficient_time" and result.status == "partial"
    run.save()
    text = report.markdown(report.build(run.config.output_dir, selected=["attack"]))
    assert "with full instructions did not start: its agent timeout is longer than the time left before the time limit" in text


@pytest.mark.parametrize("stop", ["environment_unavailable", "spending_exhausted"])
def test_a_stop_in_one_attempt_starts_no_later_one_and_lets_the_running_one_end(tmp_path, monkeypatch, credentials, stop):
    """The failed-start latch's EnvironmentUnavailable, or the spending cap, in one attempt starts no later attempt.
    The other running attempt ends on its own."""
    from nudi.records import EnvironmentUnavailable

    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    raised = asyncio.Event()

    async def inspect(run, mode, pool, focused_attempts, categories, *, title, workspace, request):
        if (request["target_candidate"] or {}).get("id") == "hack-0":
            await asyncio.sleep(0.05)
            raised.set()
            raise EnvironmentUnavailable("failed 3 times") if stop == "environment_unavailable" else run_state.SpendingCapReached("cap")
        await asyncio.wait_for(raised.wait(), 2)
        await asyncio.sleep(0.05)
        return judged(pool[0])

    monkeypatch.setattr(attack_module, "inspect", inspect)
    with pytest.raises(EnvironmentUnavailable) if stop == "environment_unavailable" else contextlib.nullcontext():
        asyncio.run(attack_module.attack(run, maximum_attempts=2, candidates=[candidate("hack-0", "FULL-0"), candidate("hack-1", "FULL-1")]))
    saved = json.loads((run.config.output_dir / "attack.json").read_text())
    assert saved["status"] == stop
    assert [(item["candidate"], item["status"]) for item in saved["attempts"]] == [("hack-0", stop), ("hack-1", "no_evidenced_issue")]


def test_no_native_attacker_episode_starts_after_three_failed_starts_while_their_workspaces_are_removed(
        tmp_path, monkeypatch, credentials):
    """Three attack inspector workspaces fail to start while a fourth is still starting, and their removal is slow, so
    their attempts record no stop yet. The fourth attempt then ends and frees a slot. The next attempt starts no native
    Attacker episode, which would build the same task environment again."""
    from nudi.records import EnvironmentUnavailable
    from test_inspection import Sandboxes, SandboxEnvironment, episode_tools

    sandboxes = Sandboxes(monkeypatch)
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=8, capacity=(32, 32768))
    after_latch, failed, release = [], {"sandbox-0000", "sandbox-0001", "sandbox-0002"}, asyncio.Event()
    for name in failed:
        sandboxes.fail[("start", name)] = RuntimeError("image build failed")
    start, stop = SandboxEnvironment.start, SandboxEnvironment.stop

    async def until(condition):
        async with asyncio.timeout(3):
            while not condition():
                await asyncio.sleep(0.001)

    async def delayed_start(environment, force_build):
        if environment.name in failed:
            await until(lambda: len(run.record.sandboxes) >= 4)
        if environment.name == "sandbox-0003":
            await until(lambda: run.failed_starts.get("environment", 0) >= 3)
        await start(environment, force_build)

    async def delayed_stop(environment, delete):
        if environment.name in failed:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(release.wait(), 0.5)
        await stop(environment, delete)

    async def native(config, queue, **work):
        if run.failed_starts.get("environment", 0) >= 3:
            after_latch.append(config.output_dir.name)
            release.set()
        return await scripted_episodes(config, queue, **work)

    async def behave(name, tools, schema):
        return schema()

    monkeypatch.setattr(SandboxEnvironment, "start", delayed_start)
    monkeypatch.setattr(SandboxEnvironment, "stop", delayed_stop)
    monkeypatch.setattr(run_state, "run_episode", native)
    episode_tools(monkeypatch, behave)
    with pytest.raises(EnvironmentUnavailable):
        asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0,
                                         candidates=[candidate(f"E{number}", f"FULL-{number}") for number in range(7)]))
    assert not after_latch, "no native Attacker episode starts once the latch has tripped"
    assert json.loads((run.config.output_dir / "attack.json").read_text())["status"] == "environment_unavailable"


def test_cancelling_the_attack_cancels_each_running_attempt_and_starts_no_later_one(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    started = []

    async def inspect(run, mode, pool, focused_attempts, categories, *, title, workspace, request):
        started.append(title)
        await asyncio.Event().wait()

    monkeypatch.setattr(attack_module, "inspect", inspect)

    async def main():
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=1, full=FULL))
        for _ in range(200):
            if len(started) == 2 or attacking.done():
                break
            await asyncio.sleep(0.01)
        attacking.cancel()
        with pytest.raises(asyncio.CancelledError):
            await attacking

    asyncio.run(main())
    saved = json.loads((run.config.output_dir / "attack.json").read_text())
    assert saved["status"] == "cancelled"
    assert [(item["level"], item["status"]) for item in saved["attempts"]] == [("full", "cancelled"), ("none", "cancelled")]


def scripted_judge(outcomes):
    """An attack inspector double: each attempt's reading is `outcomes` of the candidate id its attempt aims at, or of None
    for a discovery attempt, and legitimate otherwise. A no-hint attempt has no target, so its title names its aim.
    Records each session's target."""
    targets = []

    async def inspect(run, mode, pool, focused_attempts, categories, *, title, workspace, request):
        target = request["target_candidate"]
        targets.append(target and (target["id"], target["problem"]))
        aimed = title.removeprefix("attack_inspector-attacker-").rsplit("-", 2)[0]
        return judged(pool[0], outcomes.get(target["id"] if target else None if aimed == "none" else aimed, "legitimate"))

    return inspect, targets


def test_a_fed_attack_runs_discovery_at_once_and_a_single_hint_only_after_a_full_hint_reproduction(tmp_path, monkeypatch, credentials):
    """Beside the hack inspector the no-hint attempt starts at once, each fed candidate gets its full hint, and only the one its
    full hint reproduced gets the single hint. Each attempt, its events and its attack inspector name its problem; each
    attempt deletes the copies of its own episode when it ends, and the attack completes."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    discarded = []

    async def discard(run, keep=()):
        discarded.append(keep)

    inspect, targets = scripted_judge({"hack-0": "accepted_invalid"})
    monkeypatch.setattr(attack_module.copies, "discard", discard)
    monkeypatch.setattr(attack_module, "inspect", inspect)
    problems = [attack_module.Problem(id="P1", cause=CAUSE_A, findings=["hack-0"]),
                attack_module.Problem(id="P2", cause=CAUSE_B, findings=["hack-3"])]

    async def main():
        feed = asyncio.Queue()
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=1, discovery_attempts=1, problems=problems,
                                                             feed=feed, gate=run_state.Slots(2)))
        for item in (candidate("hack-0", "FULL-0", "MINIMAL-0"), candidate("hack-3", "FULL-3", "MINIMAL-3"), None):
            feed.put_nowait(item)
        return await attacking

    result = asyncio.run(main())
    assert [(item.context, item.problem) for item in result.attempts] == [
        ("attacker-none-none-1", None), ("attacker-hack-0-full-1", "P1"), ("attacker-hack-3-full-1", "P2"), ("attacker-hack-0-minimal-1", "P1"),
        ("attacker-hack-0-none-1", "P1")]
    assert [item.conditions for item in result.candidates] == [
        {"full": "evidenced_issue", "minimal": "evidenced_issue", "none": "evidenced_issue"},
        {"full": "no_evidenced_issue", "minimal": "not_needed", "none": "not_needed"}]
    assert sorted(filter(None, targets)) == [("hack-0", "P1"), ("hack-0", "P1"), ("hack-3", "P2")]
    events = [json.loads(line) for line in (run.config.output_dir / "events.jsonl").read_text().splitlines()]
    assert sorted((item["kind"], item.get("problem", "")) for item in events if item["kind"] in ("attempt_start", "attempt_end")) == [
        ("attempt_end", ""), ("attempt_end", "P1"), ("attempt_end", "P1"), ("attempt_end", "P1"), ("attempt_end", "P2"),
        ("attempt_start", ""), ("attempt_start", "P1"), ("attempt_start", "P1"), ("attempt_start", "P1"), ("attempt_start", "P2")]
    assert result.status == "complete" and sorted(discarded) == sorted({item.episode} for item in result.attempts)
    saved = json.loads((run.config.output_dir / "attack.json").read_text())
    assert saved == json.loads(result.model_dump_json()) and [item["id"] for item in saved["problems"]] == ["P1", "P2"]


def test_a_candidate_fed_later_gets_its_first_attempt_before_earlier_retries(tmp_path, monkeypatch, credentials):
    """Each exploit candidate's first full-hint attempt goes first, also for a candidate fed after the attack started."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=2)  # one slot
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({})[0])

    async def main():
        feed, gate = asyncio.Queue(), run_state.Slots(1)
        await gate.acquire()  # other work, so both candidates arrive before an attempt ends
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=2, discovery_attempts=0, feed=feed, gate=gate))
        for item in (candidate("hack-0", "FULL-0"), candidate("hack-3", "FULL-3"), None):
            feed.put_nowait(item)
        await asyncio.sleep(0.05)
        gate.release()
        return await attacking

    result = asyncio.run(main())
    started = {item.episode: item.context for item in result.attempts}
    events = [json.loads(line) for line in (run.config.output_dir / "events.jsonl").read_text().splitlines()]
    assert [started[item["episode"]] for item in events if item["kind"] == "attempt_start"] == [
        "attacker-hack-0-full-1", "attacker-hack-3-full-1", "attacker-hack-0-full-2", "attacker-hack-3-full-2"]


def test_an_attacker_on_a_judged_problem_takes_the_next_slot_ahead_of_work_not_started(tmp_path, monkeypatch, credentials):
    """The first Attacker on a judged problem waited behind every hack inspector session not yet started. It takes the
    next free slot ahead of them; running work keeps its slot."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({})[0])
    seen = []

    async def main():
        feed, gate = asyncio.Queue(), run_state.Slots(1)
        await gate.acquire()  # a running hack inspector session

        async def session():
            async with gate:
                seen.append(list(run.record.episodes))

        waiting = asyncio.create_task(session())
        await asyncio.sleep(0)
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, feed=feed, gate=gate))
        for item in (candidate("hack-0", "FULL-0"), None):
            feed.put_nowait(item)
        await asyncio.sleep(0.05)
        gate.release()
        result = await attacking
        await waiting
        return result

    result = asyncio.run(main())
    assert [item.context for item in result.attempts] == ["attacker-hack-0-full-1"]
    assert seen == [[result.attempts[0].episode]], "the waiting session started after the Attacker"


def test_a_waiting_discovery_attempt_leaves_a_judged_problem_free_to_queue_ahead(tmp_path, monkeypatch, credentials):
    """With one slot, the no-hint attempt waits behind a hack inspector session; an Attacker on a judged problem fed
    meanwhile still takes the next free slot ahead of both."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=2)  # one slot
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({})[0])
    seen = []

    async def main():
        feed, gate = asyncio.Queue(), run_state.Slots(1)
        await gate.acquire()  # a running hack inspector session

        async def session():
            async with gate:
                seen.append(list(run.record.episodes))

        waiting = asyncio.create_task(session())
        await asyncio.sleep(0)
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=1, discovery_attempts=1, feed=feed, gate=gate))
        await asyncio.sleep(0.05)  # the no-hint attempt now waits for a slot
        for item in (candidate("hack-0", "FULL-0"), None):
            feed.put_nowait(item)
        await asyncio.sleep(0.05)
        gate.release()
        result = await attacking
        await waiting
        return result

    result = asyncio.run(main())
    started = {item.episode: item.context for item in result.attempts}
    events = [json.loads(line) for line in (run.config.output_dir / "events.jsonl").read_text().splitlines()]
    assert [started[item["episode"]] for item in events if item["kind"] == "attempt_start"] == [
        "attacker-hack-0-full-1", "attacker-none-none-1"]
    assert seen == [[next(item.episode for item in result.attempts if item.context == "attacker-hack-0-full-1")]]


def test_slots_let_work_ahead_first_and_a_cancelled_wait_holds_none():
    async def main():
        slots, order = run_state.Slots(1), []
        await slots.acquire()

        async def take(name, ahead=False):
            async with slots.ahead() if ahead else slots:
                order.append(name)

        session = asyncio.create_task(take("session"))
        gone = asyncio.create_task(take("gone"))
        attacker = asyncio.create_task(take("attacker", ahead=True))
        await asyncio.sleep(0)
        gone.cancel()
        await asyncio.sleep(0)
        slots.release()
        await asyncio.gather(session, attacker)
        return order, slots.free

    assert asyncio.run(main()) == (["attacker", "session"], 1)


def test_a_candidate_fed_before_the_feed_closes_still_runs_and_an_empty_fed_attack_saves_its_record(tmp_path, monkeypatch, credentials):
    """The hack inspector holds the only slot until it ends and the feed closes; the queued candidate still runs afterwards.
    A fed attack that was fed nothing is the run's one attack, so it saves its record too."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({})[0])

    async def main(items):
        feed, gate = asyncio.Queue(), run_state.Slots(1)
        await gate.acquire()
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, feed=feed, gate=gate))
        for item in items:
            feed.put_nowait(item)
        await asyncio.sleep(0.05)
        gate.release()
        return await attacking

    empty = asyncio.run(main([None]))
    assert empty.attempts == [] and empty.status == "complete"
    assert json.loads((run.config.output_dir / "attack.json").read_text())["status"] == "complete"
    result = asyncio.run(main([candidate("hack-0", "FULL-0"), None]))
    assert [(item.context, item.status) for item in result.attempts] == [("attacker-hack-0-full-1", "no_evidenced_issue")]
    assert result.status == "complete"


def test_a_queued_finding_withdrawn_before_its_slot_frees_launches_no_attacker(tmp_path, monkeypatch, credentials):
    """A fed finding waits for a slot; a later reading withdrew it meanwhile, so its Attacker never starts. Its steps say
    so, the event names it, and the attack is complete."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({})[0])
    withdrawn = {"hack-0"}

    async def main():
        feed, gate = asyncio.Queue(), run_state.Slots(1)
        await gate.acquire()
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, feed=feed, gate=gate,
                                                             current=lambda item: None if item.id in withdrawn else item))
        for item in (candidate("hack-0", "FULL-0", "MINIMAL-0"), candidate("hack-1", "FULL-1"), None):
            feed.put_nowait(item)
        await asyncio.sleep(0.05)
        gate.release()
        return await attacking

    result = asyncio.run(main())
    assert [item.context for item in result.attempts] == ["attacker-hack-1-full-1"]
    assert result.candidates[0].conditions == {"full": "withdrawn", "minimal": "withdrawn", "none": "withdrawn"}
    assert result.status == "complete"
    events = [json.loads(line) for line in (run.config.output_dir / "events.jsonl").read_text().splitlines()]
    assert [item["candidate"] for item in events if item["kind"] == "withdrawn"] == ["hack-0"]


@pytest.mark.parametrize("latest", [None, "FULL-1"])
def test_a_queued_finding_runs_the_guidance_of_the_latest_reading_of_its_check(tmp_path, monkeypatch, credentials, latest):
    """hack-0 waits for a slot with full guidance; meanwhile hack-1, a later evidenced reading of its check, replaced it.
    The Attacker runs hack-1's full guidance, never hack-0's. Without it no Attacker starts, the full level is unavailable
    with the reason, and the report counts no full-information attempt."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({})[0])
    replacement = candidate("hack-1", latest)

    async def main():
        feed, gate = asyncio.Queue(), run_state.Slots(1)
        await gate.acquire()
        attacking = asyncio.create_task(attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, feed=feed, gate=gate,
                                                             current=lambda item: replacement))
        for item in (candidate("hack-0", "FULL-0"), None):
            feed.put_nowait(item)
        await asyncio.sleep(0.05)
        gate.release()
        return await attacking

    result = asyncio.run(main())
    told = [(run.config.output_dir / "episodes" / item.episode / "nudi-evidence" / "extension.md").read_text() for item in result.attempts]
    assert not any("FULL-0" in text for text in told)
    (item,) = result.candidates
    built = report.attack(result, run.record, [])
    attempts = sum(condition["attempts"] for entry in built["candidates"] for condition in entry["conditions"].values() if condition)
    if latest:
        assert len(told) == 1 and "FULL-1" in told[0] and item.guidance["full"] == "FULL-1"
    else:
        assert told == [] and attempts == 0
        assert item.conditions["full"] == "unavailable" and item.guidance["full"] is None
        assert item.unavailable["full"] == attack_module.LATER_UNGUIDED.format(level="full")


def test_a_level_skipped_for_missing_guidance_is_decided_by_a_later_attempt_that_ran(tmp_path, monkeypatch, credentials):
    """hack-0's first full attempt finds no guidance on the latest reading and does not start; by the second the guidance
    is back, so that attempt runs and decides the level, which is no longer unavailable."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({})[0])
    replacements = iter([candidate("hack-1"), candidate("hack-1", "FULL-1")])
    result = asyncio.run(attack_module.attack(run, maximum_attempts=2, discovery_attempts=0, candidates=[candidate("hack-0", "FULL-0")],
                                              current=lambda item: next(replacements)))
    (item,) = result.candidates
    assert [attempt.status for attempt in result.attempts] == ["no_evidenced_issue"]
    assert (item.conditions["full"], item.guidance["full"], "full" in item.unavailable) == ("no_evidenced_issue", "FULL-1", False)


def test_a_hint_that_worked_is_followed_by_a_no_hint_attempt_on_the_same_problem(tmp_path, monkeypatch, credentials):
    """hack-0's full hint and then its single hint reproduce it, so a no-hint attempt targets it: the Attacker gets the
    independent attempt's instruction and only its attack inspector is told the target. The single hint says only an
    exploit of its flaw counts. hack-1's full hint does not reproduce it, so neither later step is needed."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    inspect, targets = scripted_judge({"hack-0": "accepted_invalid"})
    monkeypatch.setattr(attack_module, "inspect", inspect)
    result = asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=1, candidates=[
        candidate("hack-0", "FULL-0", "MINIMAL-0"), candidate("hack-1", "FULL-1", "MINIMAL-1")]))
    assert [item.context for item in result.attempts] == ["attacker-hack-0-full-1", "attacker-hack-1-full-1", "attacker-none-none-1",
                                                          "attacker-hack-0-minimal-1", "attacker-hack-0-none-1"]
    assert [item.conditions for item in result.candidates] == [
        {"full": "evidenced_issue", "minimal": "evidenced_issue", "none": "evidenced_issue"},
        {"full": "no_evidenced_issue", "minimal": "not_needed", "none": "not_needed"}]
    told = {item.context: (run.config.output_dir / "episodes" / item.episode / "nudi-evidence" / "extension.md").read_text()
            for item in result.attempts}
    assert told["attacker-hack-0-none-1"] == told["attacker-none-none-1"] and "FULL-0" not in told["attacker-hack-0-none-1"]
    assert "The hint marks where one specific flaw is; only an exploit of that flaw counts." in told["attacker-hack-0-minimal-1"]
    assert targets[-1] is None and result.attempts[-1].status == "evidenced_issue" and result.status == "complete"


def test_a_no_hint_exploit_is_judged_and_its_attempt_names_the_problem(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)
    monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
    monkeypatch.setattr(attack_module, "inspect", scripted_judge({None: "accepted_invalid"})[0])
    asked = []

    def judge(attempt, assessment, case):
        asked.append((attempt.episode, assessment.claim.mechanism, case))
        return "A1"

    result = asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=1, judge=judge))
    # The judge reads the case of the experiment whose check evidenced the exploit, as for an inspector's finding.
    assert asked == [(result.attempts[0].episode, "scripted", {"category": "accepted_invalid", "location": "/app/answer.txt",
                                                               "capture_point": "verification_start"})]
    assert result.attempts[0].problem == "A1" and result.discovery["none"] == "evidenced_issue"
    assert json.loads((run.config.output_dir / "attack.json").read_text())["attempts"][0]["problem"] == "A1"


def test_maximum_attempts_must_be_a_nonnegative_integer(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)
    with pytest.raises(ValueError):
        asyncio.run(attack_module.attack(run, maximum_attempts=False))


def observed_probe(run, *, exists, same_bytes, **overrides):
    planting = run.episode({"artifacts/marker.bin": "nonce-bytes"}, rewards={"reward": 0.0})
    observed = "nonce-bytes" if same_bytes else "other-bytes"
    graded = run.episode({"artifacts/marker.bin": observed}, rewards={"reward": 0.0})
    planted = run.content(planting, "artifacts/marker.bin")
    persisted = run.content(graded, "artifacts/marker.bin")
    values = dict(location="/app/nudi-persistence.bin", marker_sha256=planted.sha256, plant_sha256=planted.sha256,
                  plant_episode=planting, receiver_episode=graded, plant_container_id="a" * 64, receiver_container_id="b" * 64,
                  mount_relationship="writable_layer", mounts=[], container_absent=True, project_empty=True,
                  receiver_capture_point="agent_start", marker_disclosed_to_receiver=False, receiver_exists=exists,
                  receiver_sha256=persisted.sha256 if exists else None, plant_content=planted, receiver_content=persisted,
                  classification="survived")
    values.update(overrides)
    probe = PersistenceProbe(**values)
    run.record.persistence_probes.append(probe)
    run.lifecycle((planting, "started"), (planting, "finished"), (graded, "started"), (graded, "finished"))
    run.save()
    return planted, persisted, graded


def test_absence_and_survival_follow_the_lifecycle_record(tmp_path):
    run = Run(tmp_path)
    planted, persisted, graded = observed_probe(run, exists=False, same_bytes=False)
    absent = assess(Claim(mechanism="persistence", episode=graded, planted=planted, persisted=persisted), run.dir)
    assert absent.persistence == "not_observed"
    assert absent.outcome != "accepted_invalid"
    assert any("Startup code" in item for item in absent.limits)
    assert not any("readback" in item for item in absent.missing)

    (tmp_path / "survived").mkdir()
    survived_run = Run(tmp_path / "survived")
    planted, persisted, graded = observed_probe(survived_run, exists=True, same_bytes=True)
    survived = assess(Claim(mechanism="persistence", episode=graded, planted=planted, persisted=persisted), survived_run.dir)
    assert survived.persistence == "survived"
    assert survived.outcome != "accepted_invalid"
    assert any("not a reward hack" in item for item in survived.limits)


@pytest.mark.parametrize("change", ["same-container", "teardown-error", "project-remains", "wrong-time", "disclosed-marker", "mounted", "no-probe"])
def test_incomplete_lifecycle_does_not_become_absence_or_survival(tmp_path, change):
    if change == "no-probe":
        run, planting, graded, the_claim = persistence(tmp_path)
        run.lifecycle((planting, "started"), (planting, "finished"), (graded, "started"), (graded, "finished"))
        assessment = assess(the_claim, run.dir)
        assert assessment.persistence == "unknown"
        assert any("readback" in item for item in assessment.missing)
        return
    run = Run(tmp_path)
    overrides = {"classification": "not_observed"}
    if change == "same-container":
        overrides["receiver_container_id"] = "a" * 64
    elif change == "teardown-error":
        overrides.update(container_absent=None, teardown_error="permission denied while inspecting the container")
    elif change == "project-remains":
        overrides["project_empty"] = False
    elif change == "wrong-time":
        overrides["receiver_capture_point"] = "verification_start"
    elif change == "disclosed-marker":
        overrides["marker_disclosed_to_receiver"] = True
    elif change == "mounted":
        overrides["mount_relationship"] = "bind"
    planted, persisted, graded = observed_probe(run, exists=False, same_bytes=False, **overrides)
    assessment = assess(Claim(mechanism="persistence", episode=graded, planted=planted, persisted=persisted), run.dir)
    if change == "mounted":
        assert assessment.persistence == "unsupported"
        assert "bind" in " ".join(assessment.persistence_reasons)
    else:
        assert assessment.persistence == "unknown"
    assert assessment.outcome != "accepted_invalid"


def test_unknown_persistence_does_not_erase_a_scoring_finding(tmp_path):
    run, planting, graded, the_claim = persistence(tmp_path)
    check = run.measured_check(run.content(graded))
    run.lifecycle((planting, "started"), (planting, "finished"), (graded, "started"), (graded, "finished"))
    planted = the_claim.planted
    run.record.persistence_probes.append(PersistenceProbe(
        location="/app/cache.txt", marker_sha256=planted.sha256, plant_sha256=planted.sha256, plant_content=planted,
        plant_episode=planting, receiver_episode=graded, plant_container_id="a" * 64, receiver_container_id="b" * 64,
        mount_relationship="writable_layer", container_absent=None, teardown_error="permission denied",
        receiver_capture_point="agent_start", classification="not_observed",
    ))
    run.save()
    assessment = assess(measured_claim(graded, check, planted=planted, persisted=the_claim.persisted), run.dir)
    assert assessment.outcome == "accepted_invalid"
    assert assessment.persistence == "unknown"
    assert any("permission" in reason for reason in assessment.persistence_reasons)


def test_inspector_persistence_request_is_not_an_attack(tmp_path, monkeypatch, credentials):
    """The plant is a native episode, which admission refuses beside a held workspace on the
    measured VM. Nudi runs it after the session that names it releases its workspace."""
    from test_inspection import MEASURED_VM, InspectorScript, Sandboxes, resource_task
    Sandboxes(monkeypatch)
    script = InspectorScript([{"probes": [{"category": "persistence", "case": "a file may survive", "location": "/app/nudi-persistence.bin"}]},
                              {"probes": []}])
    seen = []

    async def fake(run, location):
        await run.admit_container("native")
        seen.append(location)
        return inspection.Assessment(claim=Claim(mechanism="persistence", episode="probe"), outcome="unknown", persistence="not_observed")

    async def main():
        async with serve(script) as base:
            run = new_run(tmp_path, monkeypatch, credentials, capacity=MEASURED_VM, task_dir=resource_task(tmp_path),
                          models={"inspector": ModelConfig(model="xai/grok-4.7", api_base=base)})
            monkeypatch.setattr(inspection, "persistence_assessment", fake)
            report = await inspection.inspect_hacks(run, categories=["persistence", "grader_tampering"])
            assert seen == ["/app/nudi-persistence.bin"]
            assert report.categories["persistence"] == "restricted"
            assert [attempt.category for attempt in report.attempts] == ["grader_tampering", "other"]
            assert report.assessments[0].persistence == "not_observed"
            assert report.categories["persistence"] != "evidenced_issue"
            assert "reset" in report.applicability["persistence"].lower()

    asyncio.run(main())


def test_unsupported_persistence_location_starts_no_episode(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)
    assessment = asyncio.run(persistence_module.persistence_assessment(run, "relative/file"))
    assert assessment.persistence == "unsupported"
    assert run.record.episodes == []
    assert run.record.probe_episodes == []


def test_persistence_plants_through_identified_attacker_probes_outside_hint_conditions(tmp_path, monkeypatch, credentials):
    """The real-reset measurement needs an actor inside the original harness: an Attacker
    probe episode, never a native Inspector. Without an Attacker credential it is unsupported."""
    dispatched = []

    async def native(config, queue, **work):
        dispatched.append((config.output_dir.name, config.model, work.get("instruction") or ""))
        return await scripted_episodes(config, queue)

    monkeypatch.setattr(run_state, "run_episode", native)
    run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": ModelConfig(model="xai/attacker-probe")})
    assessment = asyncio.run(persistence_module.persistence_assessment(run, "/app/nudi-persistence.bin"))
    (name, model, instruction), = dispatched
    assert (name, model) == ("0000-attacker", "xai/attacker-probe") and "NUDI_PLANT_HEX" in instruction
    assert run.record.probe_episodes == ["0000-attacker"] == run.record.episodes
    assert run.record.persistence_probes[0].plant_episode == "0000-attacker"
    assert assessment.persistence != "unsupported" and assessment.outcome != "accepted_invalid"

    monkeypatch.setattr("nudi.run_state.docker_capacity", lambda: (8, 4096, None, "/var/lib/docker"))
    config = RunConfig(task_dir=CONTRACT_TASK, output_dir=tmp_path / "no-attacker", credentials_file=credentials)
    inspection_only = run_state.start_run(config, frozenset({"simulator", "inspector"}))
    assessment = asyncio.run(persistence_module.persistence_assessment(inspection_only, "/app/nudi-persistence.bin"))
    assert assessment.persistence == "unsupported" and "Attacker" in " ".join(assessment.limits)
    assert inspection_only.record.episodes == [] and len(dispatched) == 1
    assert inspection_only.record.persistence_probes[0].classification == "unsupported"


def test_attack_inspector_measures_only_its_episode_and_package_evidence_never_counts(tmp_path, monkeypatch, credentials):
    """Every attempt keeps its native Attacker episode. The attack inspector session refuses a
    probe with a setup_program or naming another episode; a package-scope result of its own
    episode never becomes its success. A reference to another episode's retained file is refused too."""
    from test_inspection import mock_experiments

    def inspector(body):
        return {"probes": [{"category": "package_oracles", "setup_program": "touch /app/oracle", "location": "/app/one"},
                           {"category": "package_oracles", "episode": "0000-simulator", "location": "/app/two"},
                           {"category": "package_oracles", "location": "/app/four",
                            "requirement": {"episode": "0000-simulator", "path": "trace.txt", "excerpt": "answer"}},
                           {"category": "package_oracles", "location": "/app/three"}]}

    endpoint = attack_endpoint(inspector)
    sink = {"episodes": []}
    bound = []

    async def measured(run, probe, session):
        bound.append(dict(probe))
        return Assessment(claim=Claim(mechanism="package oracle", episode=probe["episode"]), outcome="accepted_invalid",
                          execution_scope="package")

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, concurrency=2, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_runner(monkeypatch, sink)
            mock_experiments(monkeypatch, measured)
            return await attack_module.attack(run, maximum_attempts=1, full=FULL, minimal=MINIMAL)

    result = asyncio.run(main())
    assert levels(result) == ["full", "none"]
    assert [name for name, *_ in sink["episodes"]] == [attempt.episode for attempt in result.attempts]
    assert all(name.endswith("-attacker") and agent is None and native == run_state.ORIGINAL_BEHAVIOR
               for name, _, agent, native in sink["episodes"])
    assert [(probe["episode"], probe["location"]) for probe in bound] == [(attempt.episode, "/app/three") for attempt in result.attempts]
    for attempt in result.attempts:
        tools = [str(message["content"]) for message in session_messages(tmp_path / "run", f"attack_inspector-{attempt.context}")
                 if message["role"] == "tool"]
        assert sum(f"This session verifies episode {attempt.episode} only" in text for text in tools) == 3
    assert [attempt.status for attempt in result.attempts] == ["no_evidenced_issue"] * 2
    assert result.conditions == {"full": "no_evidenced_issue", "minimal": "not_needed", "none": "no_evidenced_issue"}


class Planter(TerminusScript):
    """Writes the planted hex on the first turn that contains it, and other bytes afterwards."""

    def __init__(self):
        super().__init__("true", 1.0)

    async def chat(self, request):
        body = await request.json()
        self.requests.append(body)
        self.first_request.set()
        messages = body.get("messages", [])
        first_turn = not any(message.get("role") == "assistant" for message in messages)
        marker = re.search(r"NUDI_PLANT_HEX=([0-9a-f]{32})", json.dumps(body))
        if first_turn and marker:
            token = marker.group(1)
            self.command = "mkdir -p /app; python -c 'open(\"/app/nudi-persistence.bin\",\"wb\").write(bytes.fromhex(\"" + token + "\"))'"
        elif first_turn:
            self.command = "mkdir -p /app; python -c 'open(\"/app/nudi-persistence.bin\",\"wb\").write(b\"receiver-ran\")'"
        commands = [{"keystrokes": f"{self.command}\n", "duration": self.duration}] if first_turn else []
        content = json.dumps({"analysis": "Scripted.", "plan": "Scripted.", "commands": commands, "task_complete": True})
        message = {"role": "assistant", "content": content}
        usage = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
        head = {"id": "chatcmpl-planter", "created": 0, "model": body["model"]}
        if not body.get("stream"):
            return web.json_response({**head, "object": "chat.completion", "choices": [{"index": 0, "message": message, "finish_reason": "stop"}], "usage": usage})
        chunk = {**head, "object": "chat.completion.chunk"}
        events = [{**chunk, "choices": [{"index": 0, "delta": message, "finish_reason": "stop"}]}, {**chunk, "choices": [], "usage": usage}]
        text = "".join(f"data: {json.dumps(event)}\n\n" for event in events)
        return web.Response(text=text + "data: [DONE]\n\n", content_type="text/event-stream")


def test_interpreting_inspector_receives_retained_attack_evidence(tmp_path, monkeypatch, credentials):
    """The attack inspector session starts from the episode's verification_start copy and sees the
    retained task text, the episode's evidence, and the executed instruction."""
    seen = {}
    sink = {"episodes": []}

    def inspector(body):
        text = body["messages"][-1]["content"]
        if "completed check" in text:
            return {"claim": {"mechanism": "new unhinted boundary", "interpretation": "still unproven", "unresolved": ["bounds"]}}
        seen["payload"] = json.loads(text)
        return {"probes": [{"category": "package_oracles", "location": "/app/answer.txt", "capture_point": "verification_start",
                            "timing": "The requirement applies at verification start.", "program": "print(1)",
                            "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"},
                            "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": "answer_ok"}}]}

    endpoint = attack_endpoint(inspector)
    started = []

    async def checked(run, copy, requirement, scoring, program, **kwargs):
        return sandboxed_check(run, copy, requirement, scoring, program, "{}")

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model}, concurrency=2)
            import nudi.inspector as inspector_module
            opened = inspector_module.inspector_sandbox.sandbox

            def recorded(run, purpose, **options):
                started.append((purpose, options.get("copy")))
                return opened(run, purpose, **options)

            monkeypatch.setattr(inspector_module.inspector_sandbox, "sandbox", recorded)

            async def native(config, queue, **work):
                result = await scripted_episodes(config, queue, **work)
                sink["episodes"].append((config.output_dir.name, work.get("instruction")))
                if len(sink["episodes"]) == 1:
                    retain_copy(run, config.output_dir.name, result.ids)
                return result

            monkeypatch.setattr(run_state, "run_episode", native)
            monkeypatch.setattr(inspection, "check_submission", checked)
            result = await attack_module.attack(run, maximum_attempts=1, full=FULL)
            payload = seen["payload"]
            assert payload["mode"] == "attack" and payload["episode"] == result.attempts[-1].episode
            assert "Write the number 42" in payload["task"]["untrusted_task_files"]["instruction.md"]
            (evidence,) = payload["ordinary_episodes_read_first"]
            assert evidence["episode"] == payload["episode"] and evidence["rewards"]["reward"] == 1.0
            # The executed instruction is the whole wrapped prompt: frame, task and reminder.
            task = (run.config.task_dir / "instruction.md").read_text()
            assert payload["executed_instruction"] == framed_instruction(sink["episodes"][-1][1], task, attack_module.EXPLOIT_REMINDER)
            # The last session is discovery's: the full-hint attempt runs first.
            assert payload["valid_work"] is False and payload["target_candidate"] is None
            # Session bookkeeping of the hack and grader inspectors is not the attack inspector's.
            assert not {"phase", "category_status", "applicability", "condition"} & set(payload)
            # The first attempt's workspace starts from its copy; without one it falls back to the task image.
            copy = run.record.copies[0]
            assert [item for item in started if item[0] == "workspace"] == [("workspace", copy), ("workspace", None)]
            assert payload["workspace"] == "task image"
            # Both workspaces get the complete task sources; a copy's check sandbox does not (test_copies).
            records = [json.loads((run.config.output_dir / "sandboxes" / name / "sandbox.json").read_text()) for name in run.record.sandboxes]
            assert [(record["state_copy"], "/nudi/package" in record["files"]) for record in records if record["purpose"] == "workspace"] == [
                (copy.id, True), (None, True)]
            assert result.assessments[0].claim.check and result.assessments[0].claim.episode == result.attempts[0].episode
            none_text = sink["episodes"][-1][1]
            assert "untrusted_task_files" not in none_text
            assert inspection.HACK_CHECKLIST not in none_text
            assert "print(1)" not in none_text
            assert FULL not in none_text

    asyncio.run(main())


def test_simulator_copies_survive_and_each_attempt_deletes_its_own_copy_by_its_tag_when_it_ends(tmp_path, monkeypatch, credentials):
    """The grader inspector may still read the Simulator's copies while attempts run, and no other session reads an
    attempt's copy. So each attempt deletes only its own copy when it ends, after its attack inspector read it, and a
    Simulator copy stays for run-end deletion."""
    states, judged, removed = [], [], []

    def inspector(body):
        judged.append([copy.deleted for copy in holder["run"].record.copies])
        return {"probes": []}

    endpoint = attack_endpoint(inspector)
    holder = {}
    docker = checks.host_command

    async def host(command, **kwargs):
        if command[:3] == ["docker", "image", "rm"]:
            removed.append(command[3:])
        return await docker(command, **kwargs)

    async def native(config, queue, **work):
        states.append([copy.deleted for copy in holder["run"].record.copies])
        result = await scripted_episodes(config, queue, **work)
        retain_copy(holder["run"], config.output_dir.name, result.ids)
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, concurrency=2, models={"attacker": model, "inspector": model})
            holder["run"] = run
            retain_copy(run, "0000-simulator", {"trial_id": "id-0000-simulator"})
            monkeypatch.setattr(run_state, "run_episode", native)
            monkeypatch.setattr(checks, "host_command", host)
            return run, await attack_module.attack(run, maximum_attempts=1, full=FULL)

    run, result = asyncio.run(main())
    assert [attempt.level for attempt in result.attempts] == ["full", "none"]
    assert states == [[None], [None, True]], "the Simulator's copy survives; the ended attempt's copy went"
    assert [state[-1] for state in judged] == [None] * len(judged) and len(judged) >= 2, "an attack inspector reads its own copy"
    assert [copy.deleted for copy in run.record.copies] == [None, True, True]
    assert removed == [[run.record.copies[1].tag], [run.record.copies[2].tag]]


@pytest.mark.parametrize("stop", [asyncio.CancelledError, KeyboardInterrupt])
def test_a_cancel_while_an_attempts_copies_are_deleted_cancels_the_attack(tmp_path, monkeypatch, credentials, stop):
    """An attempt deletes its own copies as it ends, so a cancel there cancels the attack. A second Ctrl-C arrives as
    KeyboardInterrupt, and neither may leave the attack or the attempt "running"."""
    runs = []

    async def cancel(run, keep=()):
        raise stop()

    async def main():
        async with serve(attack_endpoint(plain_claim)) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            runs.append(new_run(tmp_path, monkeypatch, credentials, concurrency=2, models={"attacker": model, "inspector": model}))
            monkeypatch.setattr(attack_module.copies, "discard", cancel)
            await attack_module.attack(runs[0], maximum_attempts=1)

    # The attempt runs in its own task, so a KeyboardInterrupt there leaves the event loop, as asyncio raises it.
    with pytest.raises(stop):
        asyncio.run(main())
    saved = json.loads((runs[0].config.output_dir / "attack.json").read_text())
    assert saved["status"] == "cancelled" and len(saved["attempts"]) == 1 and saved["attempts"][0]["status"] != "running"


def test_inspector_refusal_is_not_completed_negative_coverage(tmp_path, monkeypatch, credentials):
    def inspector(body):
        return {"refusal": "declines this episode"}

    endpoint = attack_endpoint(inspector)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert result.attempts[0].status == "model_inability"
            assert "declines this episode" in result.attempts[0].error
            assert result.conditions["none"] == "model_inability"
            assert result.conditions["none"] != "no_evidenced_issue"
            assert result.status == "partial"
            assert result.status != "complete"

    asyncio.run(main())


def test_check_interpretation_refusal_stays_refused(tmp_path, monkeypatch, credentials):
    def inspector(body):
        text = body["messages"][-1]["content"]
        if "completed check" in text:
            return {"refusal": "declines this check"}
        return {"probes": [{"category": "package_oracles", "location": "/app/answer.txt", "capture_point": "verification_start",
                            "timing": "The requirement applies at verification start.", "program": "print(1)",
                            "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"},
                            "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": "answer_ok"}}]}

    endpoint = attack_endpoint(inspector)
    holder = {}

    async def checked(run, copy, requirement, scoring, program, **kwargs):
        return sandboxed_check(run, copy, requirement, scoring, program, "{}")

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        retain_copy(holder["run"], config.output_dir.name, result.ids)
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            holder["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            monkeypatch.setattr(inspection, "check_submission", checked)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert result.attempts[0].status == "model_inability", result.attempts[0].error
            assert result.attempts[0].status != "tool_failure"
            assert "declines this check" in (result.attempts[0].error or "")
            assert result.conditions["none"] == "model_inability"
            assert result.status == "partial"

    asyncio.run(main())


PROBE = {"location": "/app/answer.txt", "capture_point": "verification_start",
         "timing": "The requirement applies at verification start.", "program": "print(1)",
         "requirement": {"episode": None, "path": "instruction.md", "excerpt": "Write the number 42"},
         "scoring": {"episode": None, "path": "tests/test.sh", "excerpt": "answer_ok"}}
CHECKED_CLAIM = {"mechanism": "candidate", "interpretation": "unproven", "unresolved": ["bounds"]}


def checked_attack(tmp_path, monkeypatch, credentials, inspector):
    """One rewarded discovery attempt whose probes reach a scripted check of its captured submission."""
    from test_inspection import Sandboxes

    Sandboxes(monkeypatch)
    endpoint = attack_endpoint(inspector)
    holder = {}

    async def checked(run, copy, requirement, scoring, program, **kwargs):
        return sandboxed_check(run, copy, requirement, scoring, program, "{}")

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        retain_copy(holder["run"], config.output_dir.name, result.ids)
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = holder["run"] = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            monkeypatch.setattr(inspection, "check_submission", checked)
            return run, await attack_module.attack(run, maximum_attempts=0, discovery_attempts=1, candidates=[])

    return asyncio.run(main())


def test_an_ungrounded_probe_is_returned_to_the_model_and_the_next_probe_runs(tmp_path, monkeypatch, credentials):
    def inspector(body):
        text = body["messages"][-1]["content"]
        if "completed check" in text:
            return {"claim": CHECKED_CLAIM}
        # The first probe cites a task file as a file of the episode.
        cited = {**PROBE["requirement"], "episode": json.loads(text)["episode"]}
        return {"probes": [{**PROBE, "requirement": cited}, PROBE]}

    run, result = checked_attack(tmp_path, monkeypatch, credentials, inspector)
    (attempt,) = result.attempts
    assert [check.content.episode for check in run.record.checks] == [attempt.episode]
    assert [item.outcome for item in result.assessments] == ["unknown"]
    # The invalid probe ran nothing: its reason returns to the model, and the attempt does not fail.
    assert attempt.status != "model_output_failure" and attempt.error is None


def test_unknown_native_cause_is_disclosed(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        result.errors = [ErrorRecord(type="MysteryFault", message="unclassified native failure")]
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert result.attempts[0].status != "infrastructure_failure"
            assert result.attempts[0].status != "no_evidenced_issue"
            assert result.attempts[0].status == "unknown"
            assert "unknown cause" in result.attempts[0].error
            assert "MysteryFault" in result.attempts[0].error
            assert result.conditions["none"] == "unknown"
            assert result.status == "partial"

    asyncio.run(main())


@pytest.mark.parametrize(("error", "called", "status"), [
    (ErrorRecord(type="RuntimeError", message="Failed to start tmux session"), False, "episode_failure"),
    (ErrorRecord(type="RewardFileNotFoundError", message="No reward file found"), True, "no_reward"),
    (None, True, "no_reward")])  # A reward file without a reward records no error.
def test_an_attacker_episode_without_a_reward_failed_to_run_only_without_a_model_call(tmp_path, monkeypatch, credentials, error,
                                                                                      called, status):
    """An episode that left no reward and made no model call, as an agent setup failure, is an Attacker that failed to
    run. One whose Attacker worked and whose grader wrote no reward is no failure of the Attacker and is not judged."""
    holder = {}

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        result.rewards, result.errors = {}, [error] if error else []
        (config.output_dir / "episode.json").write_text(result.model_dump_json())
        if called:
            holder["run"].record.calls.append(CallRecord(role="attacker", episode=config.output_dir.name, model="xai/grok-4.7",
                                                         cost=0.0, cost_source="scripted"))
        return result

    async def main():
        async with serve(attack_endpoint(plain_claim)) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = holder["run"] = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", native)
            return await attack_module.attack(run, maximum_attempts=1)

    attempt = asyncio.run(main()).attempts[0]
    assert attempt.status == status and attempt.status in report.UNASSESSED
    if called:
        assert attempt.failed is None and attempt.status not in report.FAILURES
        reason = f"the grader wrote no reward in {attempt.episode}"
        assert attempt.error == reason if error is None else attempt.error.startswith(f"{reason}: {error.type}")
    else:
        assert attempt.failed == "Attacker" and report.unrecovered(SimpleNamespace(attempts=[attempt]))
        assert attempt.error.startswith("the Attacker failed: the episode ended without a reward: " + error.type)


def test_recorded_call_failure_stays_inference_failure(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)
    holder = {}

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        name = config.output_dir.name
        holder["run"].record.calls.append(CallRecord(role="attacker", episode=name, model="xai/grok-4.7", cost=0.0,
                                                     cost_source="scripted", error="APIConnectionError"))
        holder["run"].save()
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            holder["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=1)
            assert result.attempts[0].status == "inference_failure"
            assert "APIConnectionError" in result.attempts[0].error
            assert result.attempts[0].status != "infrastructure_failure"
            assert result.conditions["none"] == "inference_failure"
            assert result.status == "partial"

    asyncio.run(main())


@pytest.mark.parametrize(("errors", "status"), [
    (["APIConnectionError", None], "unknown"),  # the retry succeeded
    ([None, "APIConnectionError"], "inference_failure"),  # the last request failed
])
def test_recovered_request_error_stays_telemetry(tmp_path, monkeypatch, credentials, errors, status):
    endpoint = attack_endpoint(plain_claim)
    holder = {}

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        for error in errors:
            holder["run"].record.calls.append(CallRecord(role="attacker", episode=config.output_dir.name, model="xai/grok-4.7",
                                                         cost=0.0, cost_source="scripted", error=error))
        holder["run"].save()
        return result

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            holder["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=1)
            (attempt,) = result.attempts
            assert attempt.status == result.conditions["none"] == status
            assert [call.error for call in run.record.calls if call.episode == attempt.episode] == errors
            inspected = (run.config.output_dir / f"inspection-attack_inspector-{attempt.context}.json").exists()
            if status == "unknown":
                assert inspected and attempt.error is None and result.status == "partial"
            else:
                assert not inspected and "APIConnectionError" in attempt.error and result.status == "partial"

    asyncio.run(main())


def test_symlinked_parent_is_not_writable_layer():
    """Lexical mount coverage must not treat an alias into excluded storage as writable."""
    mounts = [{"Destination": "/logs/verifier", "Type": "bind"}]
    assert persistence_module.relate_mount("/app/link/probe.bin", mounts) != "writable_layer"
    resolved = persistence_module.relate_mount("/app/link/probe.bin", mounts, {
        "verified": True,
        "lexical": "/app/link/probe.bin",
        "resolved": "/logs/verifier/probe.bin",
        "parts": [{"path": "/app/link", "is_link": True, "target": "/logs/verifier"}],
    })
    assert resolved == "bind"
    assert persistence_module.relate_mount("/app/probe.bin", [], {"verified": False, "error": "docker exec failed"}) == "unknown"


def test_zero_attempts_report_disabled_coverage(tmp_path, monkeypatch, credentials):
    run = new_run(tmp_path, monkeypatch, credentials)

    async def main():
        result = await attack_module.attack(run, maximum_attempts=0, discovery_attempts=0, full=FULL, minimal=MINIMAL)
        assert result.attempts == []
        # Nothing was requested, so the attack is complete; its limit says no condition was tested.
        assert result.status == "complete"
        assert result.candidates[0].conditions == {"full": "unattempted", "minimal": "unattempted", "none": "unattempted"}
        assert result.discovery == {"none": "unattempted"}
        assert all(status != "no_evidenced_issue" for status in result.candidates[0].conditions.values())
        assert any("disabled" in limit.lower() for limit in result.limits)
        assert not any(SAFETY in limit for limit in result.limits)

    asyncio.run(main())


def test_requested_attempts_without_guidance_are_not_run_with_their_cause(tmp_path, monkeypatch, credentials):
    """Candidates with neither full_guidance nor hint_location get no attempt although some are requested, and the
    limit says why."""
    run = new_run(tmp_path, monkeypatch, credentials)
    unguided = [attack_module.Candidate(id=f"hack-{index}", mechanism="m", guidance={"full": None, "minimal": None},
                                        unavailable={"full": attack_module.FULL_UNAVAILABLE, "minimal": attack_module.MINIMAL_UNAVAILABLE})
                for index in (3, 4)]

    async def main():
        return await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, candidates=unguided)

    result = asyncio.run(main())
    assert result.attempts == [] and result.status == "not run"
    assert attack_module.UNGUIDED_LIMIT in result.limits and attack_module.DISABLED_LIMIT not in result.limits
    assert "full_guidance, which its first attempt needs" in attack_module.UNGUIDED_LIMIT
    run.save()
    built = report.build(run.config.output_dir, selected=["attack"])
    assert built["analyses"] == {"attack": "not run"} and (built["status"], built["unresolved"]) == ("complete", ["attack"])
    assert f"- Limit: {attack_module.UNGUIDED_LIMIT}" in report.markdown(built)


def test_shared_limit_leaves_later_conditions_unattempted(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(plain_claim)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, concurrency=2, spending_cap=1, models={"attacker": model, "inspector": model})
            run.record.known_cost = 1
            result = await attack_module.attack(run, maximum_attempts=2, full=FULL, minimal=MINIMAL)
            assert [attempt.level for attempt in result.attempts] == ["full"]
            assert result.attempts[0].status == "spending_exhausted"
            assert result.discovery["none"] == "unattempted"
            assert result.candidates[0].conditions == {"full": "spending_exhausted", "minimal": "unattempted", "none": "unattempted"}
            assert result.status == "spending_exhausted"
            assert result.status != "complete"
            assert endpoint.requests == []

    asyncio.run(main())


def test_attacker_instruction_is_deterministic(tmp_path, monkeypatch, credentials):
    endpoint = attack_endpoint(evidenced_claim)
    sink = {"episodes": []}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_reproducing_runner(monkeypatch, sink)
            result = await attack_module.attack(run, maximum_attempts=1, full=FULL, minimal=MINIMAL)
            assert attacker_requests(endpoint) == []
            texts = {level: [text for _name, text, _agent, _native in sink["episodes"] if text and (
                (level == "none" and "No extra hint" in text)
                or (level == "full" and "Details:" in text)
                or (level == "minimal" and "Hint:" in text)
            )] for level in ("full", "minimal", "none")}
            assert texts["full"] and texts["minimal"] and texts["none"]
            assert texts["full"][0] == attack_module.EXPLOIT_INSTRUCTION + "\nDetails:\n" + FULL
            assert texts["minimal"][0] == attack_module.EXPLOIT_INSTRUCTION + "\n" + FLAW + "\nHint:\n" + MINIMAL
            assert texts["none"][0].startswith(attack_module.EXPLOIT_INSTRUCTION)
            assert "No extra hint" in texts["none"][0]
            assert "reward hack" in texts["full"][0].lower() and "reward hack" in texts["minimal"][0].lower()
            assert FULL not in texts["none"][0] and MINIMAL not in texts["none"][0]
            assert "untrusted_task_files" not in texts["none"][0]
            assert len({attempt.context for attempt in result.attempts}) == 3
            assert all(agent is None and native == run_state.ORIGINAL_BEHAVIOR for _, _, agent, native in sink["episodes"])

    asyncio.run(main())


def provider_completion(message: dict, finish_reason: str, model: str) -> dict:
    return {"id": "provider", "object": "chat.completion", "created": 0, "model": model,
            "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}


def test_provider_refusal_on_initial_interpretation(tmp_path, monkeypatch, credentials):
    """Empty provider refusal signals are refusals, not inference failures."""

    class Endpoint:
        async def chat(self, request):
            body = await request.json()
            return web.json_response(provider_completion(
                {"role": "assistant", "content": None, "refusal": "declines this episode"},
                "content_filter", body["model"]))

    async def main():
        async with serve(Endpoint()) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            monkeypatch.setattr(run_state, "run_episode", scripted_episodes)
            result = await attack_module.attack(run, maximum_attempts=1)
            error = result.attempts[0].error or ""
            assert result.attempts[0].status == "refused", error
            assert result.attempts[0].status != "inference_failure"
            assert "content_filter" in error
            assert result.conditions["none"] == "refused"
            assert result.status == "partial"
            assert result.status != "complete"

    asyncio.run(main())


def test_provider_refusal_on_check_interpretation(tmp_path, monkeypatch, credentials):
    """A provider refusal while interpreting a generated check stays refused."""

    class Endpoint:
        async def chat(self, request):
            body = await request.json()
            if body["messages"][-1]["role"] == "tool":
                return web.json_response(provider_completion(
                    {"role": "assistant", "content": None, "refusal": "declines this check"},
                    "content_filter", body["model"]))
            episode = json.loads(next(message for message in body["messages"] if message["role"] == "user")["content"])["episode"]
            return web.json_response(provider_completion(call(body, "run_experiment", {"probe": {**PROBE, "episode": episode}}),
                                                         "tool_calls", body["model"]))

    holder = {}

    async def checked(run, copy, requirement, scoring, program, **kwargs):
        return sandboxed_check(run, copy, requirement, scoring, program, "{}")

    async def native(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        retain_copy(holder["run"], config.output_dir.name, result.ids)
        return result

    async def main():
        async with serve(Endpoint()) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            holder["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            monkeypatch.setattr(inspection, "check_submission", checked)
            result = await attack_module.attack(run, maximum_attempts=1)
            error = result.attempts[0].error or ""
            assert result.attempts[0].status == "refused", error
            assert result.attempts[0].status != "inference_failure"
            assert result.attempts[0].status != "tool_failure"
            assert "content_filter" in error
            assert run.record.checks, "the refusal came after the measured check"
            assert result.conditions["none"] == "refused"
            assert result.status == "partial"

    asyncio.run(main())


def test_descriptive_hints_still_require_a_reward_hack(tmp_path, monkeypatch, credentials):
    """Supplied guidance is added to the common exploit instruction, not substituted for it."""
    full_hint = "The grader compares file hashes."
    minimal_hint = "A score file is written at the end."
    endpoint = attack_endpoint(evidenced_claim)
    sink = {"episodes": []}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_reproducing_runner(monkeypatch, sink)
            result = await attack_module.attack(run, maximum_attempts=1, full=full_hint, minimal=minimal_hint)
            assert attacker_requests(endpoint) == []
            texts = {}
            for _name, text, _agent, _native in sink["episodes"]:
                if not text:
                    continue
                if "Details:" in text:
                    texts["full"] = text
                elif "Hint:" in text:
                    texts["minimal"] = text
                elif "No extra hint" in text:
                    texts["none"] = text
            assert set(texts) == {"full", "minimal", "none"}
            for text in texts.values():
                assert "reward hack" in text.lower()
            assert full_hint in texts["full"] and minimal_hint not in texts["full"]
            assert minimal_hint in texts["minimal"] and full_hint not in texts["minimal"]
            assert full_hint not in texts["none"] and minimal_hint not in texts["none"]
            assert "untrusted_task_files" not in texts["none"] and "missing_evidence" not in texts["none"]
            assert len({attempt.context for attempt in result.attempts}) == 3
            assert "sessions" not in json.loads((run.config.output_dir / "attack.json").read_text())

    asyncio.run(main())


GO_DIR = (1 << 31) | 0o755
GO_LINK = (1 << 27) | 0o777
GO_FILE = 0o644
GO_FIFO = (1 << 25) | 0o644


def stat_header(mode: int, link: str = "") -> str:
    body = json.dumps({"name": "n", "size": 1, "mode": mode, "mtime": "2026-01-01T00:00:00Z", "linkTarget": link})
    return base64.b64encode(body.encode()).decode()


class Daemon:
    def __init__(self, stats, *, fail_pause=False, fail_unpause=False, fail_unpause_after=None, hang_stat=False):
        self.stats = stats
        self.fail_pause = fail_pause
        self.fail_unpause = fail_unpause
        self.fail_unpause_after = fail_unpause_after
        self.hang_stat = hang_stat
        self.unpause_count = 0
        self.events = []
        self.stat_started = asyncio.Event()
        self.release_stat = asyncio.Event()
        self.unpaused = asyncio.Event()

    async def handle(self, request):
        self.events.append((request.method, request.path, request.query.get("path")))
        if request.method == "GET" and request.path == "/version":
            return web.json_response({"ApiVersion": "1.44"})
        if request.method == "POST" and request.path.endswith("/pause"):
            if self.fail_pause:
                return web.Response(status=500, text="pause failed")
            return web.Response(status=204)
        if request.method == "POST" and request.path.endswith("/unpause"):
            self.unpause_count += 1
            self.unpaused.set()
            failed = self.fail_unpause or (
                self.fail_unpause_after is not None and self.unpause_count > self.fail_unpause_after
            )
            if failed:
                return web.Response(status=500, text="unpause failed")
            return web.Response(status=204)
        if request.method == "HEAD" and request.path.endswith("/archive"):
            if self.hang_stat:
                self.stat_started.set()
                try:
                    await self.release_stat.wait()
                except asyncio.CancelledError:
                    return web.Response(status=500, text="cancelled")
            spec = self.stats.get(request.query.get("path"), "404")
            if spec == "404":
                return web.Response(status=404, text="missing")
            if spec == "noheader":
                return web.Response(status=200)
            return web.Response(status=200, headers={"X-Docker-Container-Path-Stat": spec})
        return web.Response(status=404, text=request.path)


@contextlib.asynccontextmanager
async def daemon_socket(daemon: Daemon):
    """A short /tmp socket. Pytest's tmp_path exceeds the macOS AF_UNIX limit."""
    directory = Path(tempfile.mkdtemp(prefix="n6-", dir="/tmp"))
    app = web.Application(middlewares=[_daemon_middleware(daemon)])
    app.router.add_route("*", "/{tail:.*}", lambda request: web.Response(status=404))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.UnixSite(runner, str(directory / "d.sock"))
    await site.start()
    try:
        yield directory / "d.sock"
    finally:
        daemon.release_stat.set()
        await runner.cleanup()
        shutil.rmtree(directory, ignore_errors=True)


def _daemon_middleware(daemon: Daemon):
    @web.middleware
    async def middleware(request, handler):
        return await daemon.handle(request)
    return middleware


def use_socket(monkeypatch, sock: Path) -> None:
    monkeypatch.setenv("DOCKER_HOST", f"unix://{sock}")
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)


def lying_exec(location: str) -> str:
    return json.dumps({
        "lexical": location,
        "resolved": location,
        "verified": True,
        "parts": [
            {"path": "/app", "is_link": False, "is_dir": True, "is_file": False, "exists": True},
            {"path": location, "is_link": False, "is_dir": False, "is_file": True, "exists": True, "target": ""},
        ],
    })


def test_container_interpreter_cannot_verify_storage(tmp_path, monkeypatch):
    """A task-controlled interpreter report cannot make excluded storage look writable."""
    location = "/app/link/probe.bin"
    daemon = Daemon({
        "/app": stat_header(GO_DIR),
        "/app/link": stat_header(GO_LINK, "/logs/verifier"),
        "/app/link/probe.bin": stat_header(GO_FILE),
    })
    mounts = [{"Destination": "/logs/verifier", "Type": "bind"}]
    commands = []

    async def host(command, timeout=30):
        commands.append(command)
        if len(command) >= 2 and command[0] == "docker" and command[1] == "exec":
            return 0, lying_exec(location), ""
        return 1, "", "cli unused"

    async def main():
        async with daemon_socket(daemon) as sock:
            use_socket(monkeypatch, sock)
            monkeypatch.setattr(persistence_module, "host_command", host)
            resolution = await persistence_module.path_resolution("cid", location)
            relationship = persistence_module.relate_mount(location, mounts, resolution)
            assert relationship == "bind", resolution
            assert relationship != "writable_layer"
            assert resolution.get("verified") is True
            assert any(part.get("is_link") for part in resolution.get("parts") or [])
            assert str(resolution.get("resolved") or "").startswith("/logs/verifier")
            assert not any(command[1] == "exec" for command in commands if len(command) > 1 and command[0] == "docker")

    asyncio.run(main())


def test_unsafe_parents_and_runtime_paths_stay_unverified(tmp_path, monkeypatch):
    """Symlink or non-directory parents, runtime paths, and missing metadata are not writable-layer coverage."""
    daemon = Daemon({
        "/etc": stat_header(GO_DIR),
        "/etc/hosts": stat_header(GO_FILE),
        "/etc/hostname": stat_header(GO_FILE),
        "/etc/resolv.conf": stat_header(GO_FILE),
        "/proc": stat_header(GO_DIR),
        "/proc/self": stat_header(GO_DIR),
        "/proc/self/status": stat_header(GO_FILE),
        "/sys": stat_header(GO_DIR),
        "/sys/fs": stat_header(GO_DIR),
        "/dev": stat_header(GO_DIR),
        "/dev/null": stat_header(GO_FILE),
        "/app": stat_header(GO_DIR),
        "/app/notdir": stat_header(GO_FILE),
        "/app/notdir/x": stat_header(GO_FILE),
        "/app/missing.bin": "404",
        "/app/fifo": stat_header(GO_FIFO),
        "/app/noheader": "noheader",
    })

    async def host(command, timeout=30):
        if len(command) >= 2 and command[0] == "docker" and command[1] == "exec":
            return 0, lying_exec(command[-1]), ""
        return 1, "", "cli unused"

    async def main():
        async with daemon_socket(daemon) as sock:
            use_socket(monkeypatch, sock)
            monkeypatch.setattr(persistence_module, "host_command", host)
            for location in ("/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/proc/self/status", "/sys/fs", "/dev/null"):
                resolution = await persistence_module.path_resolution("cid", location)
                assert persistence_module.relate_mount(location, [], resolution) != "writable_layer", location
            parent = await persistence_module.path_resolution("cid", "/app/notdir/x")
            assert persistence_module.relate_mount("/app/notdir/x", [], parent) == "unknown", parent
            absent = await persistence_module.path_resolution("cid", "/app/missing.bin")
            assert absent.get("verified") is True and absent.get("exists") is False, absent
            assert persistence_module.relate_mount("/app/missing.bin", [], absent) == "writable_layer"
            missing_parent = await persistence_module.path_resolution("cid", "/gone/file")
            assert missing_parent.get("verified") is not True
            assert missing_parent.get("exists") is not False or missing_parent.get("absent") is not True
            assert persistence_module.relate_mount("/gone/file", [], missing_parent) == "unknown"
            fifo = await persistence_module.path_resolution("cid", "/app/fifo")
            assert persistence_module.relate_mount("/app/fifo", [], fifo) != "writable_layer", fifo
            blank = await persistence_module.path_resolution("cid", "/app/noheader")
            assert blank.get("verified") is not True
            assert persistence_module.relate_mount("/app/noheader", [], blank) == "unknown"
            monkeypatch.setenv("DOCKER_HOST", "ssh://example.test")
            remote = await persistence_module.path_resolution("cid", "/app/missing.bin")
            assert remote.get("verified") is not True
            assert persistence_module.relate_mount("/app/missing.bin", [], remote) == "unknown"
            monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
            tls = await persistence_module.path_resolution("cid", "/app/missing.bin")
            assert persistence_module.relate_mount("/app/missing.bin", [], tls) == "unknown"

    asyncio.run(main())


def test_docker_host_wins_over_context_endpoint(tmp_path, monkeypatch):
    """DOCKER_HOST selects the unix endpoint before DOCKER_CONTEXT, as the Docker CLI does.
    Without DOCKER_HOST the context's endpoint is used."""
    right = Daemon({"/app": stat_header(GO_DIR), "/app/file": stat_header(GO_FILE)})
    wrong = Daemon({})
    commands = []

    async def main():
        right_dir = Path(tempfile.mkdtemp(prefix="n6r-", dir="/tmp"))
        wrong_dir = Path(tempfile.mkdtemp(prefix="n6w-", dir="/tmp"))

        async def host(command, timeout=30):
            commands.append(list(command))
            if list(command[:3]) == ["docker", "context", "inspect"] and "lab" in command:
                return 0, f"unix://{wrong_dir / 'd.sock'}\n", ""
            return 1, "", "unexpected cli"

        app = web.Application(middlewares=[_daemon_middleware(right)])
        app.router.add_route("*", "/{tail:.*}", lambda request: web.Response(status=404))
        runner = web.AppRunner(app)
        await runner.setup()
        await web.UnixSite(runner, str(right_dir / "d.sock")).start()
        other = web.Application(middlewares=[_daemon_middleware(wrong)])
        other.router.add_route("*", "/{tail:.*}", lambda request: web.Response(status=404))
        other_runner = web.AppRunner(other)
        await other_runner.setup()
        await web.UnixSite(other_runner, str(wrong_dir / "d.sock")).start()
        try:
            monkeypatch.setenv("DOCKER_CONTEXT", "lab")
            monkeypatch.setenv("DOCKER_HOST", f"unix://{right_dir / 'd.sock'}")
            monkeypatch.setattr(persistence_module, "host_command", host)
            resolution = await persistence_module.path_resolution("cid", "/app/file")
            assert resolution.get("verified") is True, resolution
            assert persistence_module.relate_mount("/app/file", [], resolution) == "writable_layer"
            assert any(item[1].endswith("/archive") for item in right.events)
            assert not any(item[1].endswith("/archive") for item in wrong.events)
            assert not any("lab" in command for command in commands)
            monkeypatch.delenv("DOCKER_HOST")
            assert await persistence_module.unix_docker_socket() == (str(wrong_dir / "d.sock"), None)
        finally:
            await runner.cleanup()
            await other_runner.cleanup()
            shutil.rmtree(right_dir, ignore_errors=True)
            shutil.rmtree(wrong_dir, ignore_errors=True)

    asyncio.run(main())


def _probe_event(task_dir=None, trials_dir=None):
    config = SimpleNamespace(task=SimpleNamespace(path=task_dir), trials_dir=trials_dir, trial_name="trial")
    return SimpleNamespace(trial_name="trial", trial_id="trial-id", result=SimpleNamespace(task_checksum="sum"), config=config)


def test_failed_pause_or_resume_is_unverified(tmp_path, monkeypatch, credentials):
    """Failed pause leaves storage unknown. Failed resume is an infrastructure failure and stops the probe."""

    async def host(command, timeout=30):
        return 1, "", "interpreter output is not an observation"

    async def identity(event):
        return {"id": "cid", "mounts": [], "project": "proj"}

    captured = []

    async def no_capture(*args, **kwargs):
        captured.append(args)
        raise RuntimeError("content was read without a successful pause")

    async def episode(run, role, **kwargs):
        await kwargs["on_verification"](_probe_event())

    async def main():
        paused = Daemon({"/app": stat_header(GO_DIR), "/app/file": stat_header(GO_FILE)}, fail_pause=True)
        async with daemon_socket(paused) as sock:
            use_socket(monkeypatch, sock)
            monkeypatch.setattr(persistence_module, "host_command", host)
            monkeypatch.setattr(persistence_module, "container_identity", identity)
            monkeypatch.setattr(persistence_module, "read_exact", no_capture)
            monkeypatch.setattr(run_state, "run_role_episode", episode)
            run = new_run(tmp_path / "pause", monkeypatch, credentials)
            await persistence_module.persistence_assessment(run, "/app/file")
            probe = run.record.persistence_probes[-1]
            assert any(item[0] == "POST" and item[1].endswith("/pause") for item in paused.events)
            assert any(item[0] == "POST" and item[1].endswith("/unpause") for item in paused.events)
            assert not any(item[1].endswith("/archive") for item in paused.events)
            assert captured == []
            assert probe.mount_relationship == "unknown"
            assert probe.path_resolution.get("verified") is not True
            assert probe.receiver_episode is None
            assert not any("infrastructure failure" in item for item in probe.limits)
            assert any(item.get("container_id") == "cid" and item.get("pause_error") for item in probe.observation_windows)

        resumed = Daemon({"/app": stat_header(GO_DIR), "/app/file": stat_header(GO_FILE)}, fail_unpause=True)

        async def capture(*args, **kwargs):
            raise RuntimeError("content read is allowed only to prove resume cleanup")

        async with daemon_socket(resumed) as sock:
            use_socket(monkeypatch, sock)
            monkeypatch.setattr(persistence_module, "read_exact", capture)
            run = new_run(tmp_path / "resume-run", monkeypatch, credentials)
            await persistence_module.persistence_assessment(run, "/app/file")
            probe = run.record.persistence_probes[-1]
            assert any(item[1].endswith("/unpause") for item in resumed.events)
            assert probe.mount_relationship == "unknown"
            assert probe.path_resolution.get("verified") is not True
            assert probe.receiver_episode is None
            assert any("infrastructure failure" in item for item in probe.limits)
            window = probe.observation_windows[-1]
            assert window.get("paused") is True and window.get("resume_error")
            assert window.get("container_id") == "cid"

    asyncio.run(main())


def test_cancelled_observation_still_unpauses(tmp_path, monkeypatch, credentials):
    """Cancellation during a paused read still resumes the target container."""
    daemon = Daemon({"/app": stat_header(GO_DIR), "/app/file": stat_header(GO_FILE)}, hang_stat=True)

    async def host(command, timeout=30):
        return 1, "", "interpreter output is not an observation"

    async def identity(event):
        return {"id": "cid", "mounts": [], "project": "proj"}

    async def episode(run, role, **kwargs):
        await kwargs["on_verification"](_probe_event())

    async def main():
        async with daemon_socket(daemon) as sock:
            use_socket(monkeypatch, sock)
            monkeypatch.setattr(persistence_module, "host_command", host)
            monkeypatch.setattr(persistence_module, "container_identity", identity)
            monkeypatch.setattr(run_state, "run_role_episode", episode)
            run = new_run(tmp_path / "run", monkeypatch, credentials)
            task = asyncio.create_task(persistence_module.persistence_assessment(run, "/app/file"))
            try:
                await asyncio.wait_for(daemon.stat_started.wait(), 2)
            except TimeoutError:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
                raise AssertionError("paused read did not reach daemon parent metadata")
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(daemon.unpaused.wait(), 2)
            assert any(item[1].endswith("/pause") for item in daemon.events)
            assert any(item[1].endswith("/unpause") for item in daemon.events)

    asyncio.run(main())


def test_cancellation_while_waiting_for_cleanup_finishes_it_first():
    """Cancellation that arrives during the cleanup wait propagates only after cleanup finishes."""
    order = []

    async def main():
        release = asyncio.Event()

        async def cleanup():
            await release.wait()
            order.append("cleanup finished")

        async def caller():
            try:
                await checks.finish_cleanup(asyncio.create_task(cleanup()))
            except asyncio.CancelledError:
                order.append("cancelled")
                raise

        task = asyncio.create_task(caller())
        await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()

    asyncio.run(main())
    assert order == ["cleanup finished", "cancelled"]


@pytest.mark.parametrize("phase", ["unpause", "close"])
@pytest.mark.parametrize("resume_fails", [False, True])
def test_late_observation_cancellation_keeps_annotations_and_resume_failure(monkeypatch, phase, resume_fails):
    async def main():
        entered, release = asyncio.Event(), asyncio.Event()
        order, windows = [], []
        probe = PersistenceProbe(location="/app/file", mount_relationship="writable_layer",
                                 path_resolution={"verified": True}, receiver_exists=True,
                                 receiver_sha256="observed", receiver_capture_point="agent_start")

        async def block(stage):
            if phase == stage:
                entered.set()
                await release.wait()

        class Client:
            async def aclose(self):
                await block("close")
                order.append("closed")

        async def socket():
            return "/test/docker.sock", None

        async def client(sock):
            return Client(), "1.44"

        async def action(client, api, container, action):
            if action == "unpause":
                await block("unpause")
                if resume_fails:
                    raise RuntimeError("resume unavailable")
                order.append("resumed")

        monkeypatch.setattr(persistence_module, "unix_docker_socket", socket)
        monkeypatch.setattr(persistence_module, "docker_client", client)
        monkeypatch.setattr(persistence_module, "docker_action", action)

        async def observe():
            async with persistence_module.protected_read("cid", windows, probe) as paused:
                assert paused

        task = asyncio.create_task(observe())
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done(), "cancellation must await observation cleanup"
        release.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert order[-1] == "closed" and task.cancelled()
        assert persistence_module.TIMING_LIMIT in probe.limits
        window, = windows
        assert window["read_finished_at"] and window["cancelled"]
        if resume_fails:
            assert "resume unavailable" in window["resume_error"]
            assert probe.receiver_exists is None and probe.receiver_capture_point is None
            assert probe.path_resolution["verified"] is False and probe.mount_relationship == "unknown"
            assert any("resume failed" in limit for limit in probe.limits)
            assert isinstance(caught.value.__cause__, persistence_module.InfrastructureAbort)
        else:
            assert window["resumed_at"] and probe.receiver_exists is True

    asyncio.run(main())


def test_cleanup_cancellation_retains_a_simultaneous_cleanup_exception():
    async def main():
        entered, release = asyncio.Event(), asyncio.Event()

        async def cleanup():
            entered.set()
            await release.wait()
            raise RuntimeError("cleanup failed")

        task = asyncio.create_task(checks.finish_cleanup(asyncio.create_task(cleanup())))
        await entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert isinstance(caught.value.__cause__, RuntimeError)
        assert str(caught.value.__cause__) == "cleanup failed"

    asyncio.run(main())


def test_double_slash_roots_are_not_writable_layer(monkeypatch):
    """A leading double slash is rejected. Collapsed metadata must not bypass an exclusion."""
    daemon = Daemon({
        "/etc": stat_header(GO_DIR),
        "/etc/hosts": stat_header(GO_FILE),
        "/logs": stat_header(GO_DIR),
        "/logs/verifier": stat_header(GO_DIR),
        "/logs/verifier/file": stat_header(GO_FILE),
    })

    async def host(command, timeout=30):
        return 1, "", "cli unused"

    async def main():
        async with daemon_socket(daemon) as sock:
            use_socket(monkeypatch, sock)
            monkeypatch.setattr(persistence_module, "host_command", host)
            hosts = await persistence_module.path_resolution("cid", "//etc/hosts")
            assert hosts.get("verified") is not True, hosts
            assert persistence_module.relate_mount("//etc/hosts", [], hosts) != "writable_layer", hosts
            planted = await persistence_module.path_resolution("cid", "//logs/verifier/file")
            mounts = [{"Destination": "/logs/verifier", "Type": "bind"}]
            assert planted.get("verified") is not True, planted
            assert persistence_module.relate_mount("//logs/verifier/file", mounts, planted) != "writable_layer", planted

    asyncio.run(main())


def test_failed_resume_stops_plant_grader_and_receiver_agent(tmp_path, monkeypatch, credentials):
    """Failed resume stops the plant grader and the receiver agent. Cleanup still runs.

    The stub follows Harbor's order: the agent body runs only after the agent-start hook
    returns, and the grader runs only after the verification hook returns. Cleanup always runs.
    """
    from nudi.episode import capture_at_agent_start, capture_at_trial_end, capture_at_verification

    async def host(command, timeout=30):
        state = json.dumps({"exists": False, "base64": "", "observed_end": "2026-01-01T00:00:00Z"})
        receipt = json.dumps({"state": state, "sha256": hashlib.sha256(state.encode()).hexdigest()})
        return 0, receipt, ""

    async def identity(event):
        return {"id": "cid", "mounts": [], "project": "proj"}

    async def teardown(container_id, project):
        return {"absent": True, "empty": True, "error": None, "reasons": []}

    read_exact = persistence_module.read_exact

    async def capture(container, location, directory, filename):
        """The plant read finds the marker; the receiver's read goes through `host`."""
        if filename != "plant.json":
            return await read_exact(container, location, directory, filename)
        text = (directory / "extension.md").read_text()
        marker = bytes.fromhex(re.search(r"NUDI_PLANT_HEX=([0-9a-f]+)", text).group(1))
        state = json.dumps({"exists": True, "base64": base64.b64encode(marker).decode(), "location": location})
        directory.mkdir(parents=True, exist_ok=True)
        (directory / filename).write_text(state)
        return {"state": json.loads(state), "file_sha": hashlib.sha256(state.encode()).hexdigest(),
                "path": f"nudi-evidence/{filename}", "raw_sha": hashlib.sha256(marker).hexdigest()}

    def harbor(steps):
        async def fake(config, task_dir, result, queue, agent=None):
            name = config.output_dir.name
            try:
                await capture_at_agent_start(_probe_event())
                steps.append((name, "agent"))
                await capture_at_verification(_probe_event(task_dir, config.output_dir / "harbor"))
                steps.append((name, "grader"))
            except Exception as exc:
                if type(exc).__name__ != "InfrastructureAbort":
                    raise
                result.errors.append(ErrorRecord(type=type(exc).__name__, message=str(exc)))
            finally:
                steps.append((name, "cleanup"))
                await capture_at_trial_end(_probe_event())

        return fake

    async def drive(name, daemon):
        steps = []
        monkeypatch.setattr("nudi.episode.run_harbor", harbor(steps))
        async with daemon_socket(daemon) as sock:
            use_socket(monkeypatch, sock)
            monkeypatch.setattr(persistence_module, "host_command", host)
            monkeypatch.setattr(persistence_module, "container_identity", identity)
            monkeypatch.setattr(persistence_module, "teardown_observation", teardown)
            monkeypatch.setattr(persistence_module, "read_exact", capture)
            run = new_run(tmp_path / name, monkeypatch, credentials)
            await persistence_module.persistence_assessment(run, "/app/file")
            return run, steps

    async def main():
        plant = Daemon({"/app": stat_header(GO_DIR)}, fail_unpause=True)
        plant_run, plant_steps = await drive("plant-abort", plant)
        plant_probe = plant_run.record.persistence_probes[-1]
        plant_episode = (plant_run.config.output_dir / "episodes" / "0000-attacker" / "episode.json").read_text()
        receiver = Daemon({"/app": stat_header(GO_DIR)}, fail_unpause_after=1)
        receiver_run, receiver_steps = await drive("receiver-abort", receiver)
        receiver_probe = receiver_run.record.persistence_probes[-1]
        receiver_episode = (receiver_run.config.output_dir / "episodes" / "0001-attacker" / "episode.json").read_text()
        problems = []
        if ("0000-attacker", "grader") in plant_steps:
            problems.append("plant grader ran after failed resume")
        if ("0000-attacker", "cleanup") not in plant_steps:
            problems.append("plant cleanup did not run")
        if not any(item[1].endswith("/unpause") for item in plant.events):
            problems.append("plant unpause was not attempted")
        if not any(item.startswith("infrastructure failure: container resume failed:") for item in plant_probe.limits):
            problems.append(f"plant infrastructure cause missing: {plant_probe.limits}")
        if "InfrastructureAbort" not in plant_episode:
            problems.append("plant episode did not retain InfrastructureAbort")
        if ("0001-attacker", "agent") in receiver_steps:
            problems.append("receiver agent ran after failed resume")
        if ("0001-attacker", "cleanup") not in receiver_steps:
            problems.append("receiver cleanup did not run")
        if receiver.unpause_count < 2:
            problems.append(f"receiver resume was not attempted: {receiver.unpause_count}")
        if not any(item.startswith("infrastructure failure: container resume failed:") for item in receiver_probe.limits):
            problems.append(f"receiver infrastructure cause missing: {receiver_probe.limits}")
        if "InfrastructureAbort" not in receiver_episode:
            problems.append("receiver episode did not retain InfrastructureAbort")
        assert problems == [], problems

    asyncio.run(main())


class AliasPlanter(Planter):
    """Plants through a symlink into Harbor's verifier mount. The archive member is still a regular file."""

    async def chat(self, request):
        body = await request.json()
        self.requests.append(body)
        self.first_request.set()
        messages = body.get("messages", [])
        first_turn = not any(message.get("role") == "assistant" for message in messages)
        marker = re.search(r"NUDI_PLANT_HEX=([0-9a-f]{32})", json.dumps(body))
        if first_turn and marker:
            token = marker.group(1)
            self.command = (
                "mkdir -p /app; ln -sfn /logs/verifier /app/link; "
                "python -c 'open(\"/app/link/probe.bin\",\"wb\").write(bytes.fromhex(\"" + token + "\"))'"
            )
        elif first_turn:
            self.command = "mkdir -p /app; python -c 'open(\"/app/link/probe.bin\",\"wb\").write(b\"receiver-ran\")'"
        commands = [{"keystrokes": f"{self.command}\n", "duration": self.duration}] if first_turn else []
        content = json.dumps({"analysis": "Scripted.", "plan": "Scripted.", "commands": commands, "task_complete": True})
        message = {"role": "assistant", "content": content}
        usage = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
        head = {"id": "chatcmpl-alias", "created": 0, "model": body["model"]}
        if not body.get("stream"):
            return web.json_response({**head, "object": "chat.completion", "choices": [{"index": 0, "message": message, "finish_reason": "stop"}], "usage": usage})
        chunk = {**head, "object": "chat.completion.chunk"}
        events = [{**chunk, "choices": [{"index": 0, "delta": message, "finish_reason": "stop"}]}, {**chunk, "choices": [], "usage": usage}]
        text = "".join(f"data: {json.dumps(event)}\n\n" for event in events)
        return web.Response(text=text + "data: [DONE]\n\n", content_type="text/event-stream")


def test_native_symlink_parent_is_excluded_storage(tmp_path, monkeypatch, docker_env):
    """A regular archive member reached through a symlink into /logs/verifier is excluded storage."""

    async def main():
        task = tmp_path / "task"
        shutil.copytree(CONTRACT_TASK, task)
        script = AliasPlanter()
        async with serve(script) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base, reasoning_effort="high")
            run = run_state.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run", models={"attacker": model}), frozenset({"attacker"}))
            assessment = await persistence_module.persistence_assessment(run, "/app/link/probe.bin")
        probe = run.record.persistence_probes[-1]
        assert probe.path_resolution.get("verified") is True
        assert any(part.get("is_link") for part in probe.path_resolution.get("parts") or [])
        assert str(probe.path_resolution.get("resolved", "")).startswith("/logs/verifier")
        assert probe.mount_relationship in persistence_module.EXCLUDED_MOUNT_TYPES
        assert probe.mount_relationship != "writable_layer"
        planted = json.loads((run.config.output_dir / "episodes" / probe.plant_content.episode / probe.plant_content.path).read_text())
        assert planted.get("exists") is True
        assert assessment.persistence == "unsupported"
        assert assessment.persistence != "not_observed"
        assert probe.receiver_episode is None

    monkeypatch.setenv("XAI_API_KEY", PROVIDER_KEY)
    asyncio.run(main())


def test_native_planting_readback_teardown_and_fresh_instance(tmp_path, monkeypatch, docker_env):
    """Original-harness planting on a benign task. The receiver is not given the marker."""

    async def main():
        task = tmp_path / "task"
        shutil.copytree(CONTRACT_TASK, task)
        script = Planter()
        async with serve(script) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base, reasoning_effort="high")
            run = run_state.start_run(RunConfig(task_dir=task, output_dir=tmp_path / "run", models={"attacker": model}), frozenset({"attacker"}))
            run.record.simulation = Simulation(requested=1, episodes=["ordinary"])
            assessment = await persistence_module.persistence_assessment(run, "/app/nudi-persistence.bin")
        assert assessment.persistence == "not_observed", assessment.persistence_reasons
        probe = run.record.persistence_probes[-1]
        plant_text = (run.config.output_dir / "episodes" / probe.plant_episode / "nudi-evidence" / "extension.md").read_text()
        receiver_text = (run.config.output_dir / "episodes" / probe.receiver_episode / "nudi-evidence" / "extension.md").read_text()
        marker = re.search(r"NUDI_PLANT_HEX=([0-9a-f]{32})", plant_text).group(1)
        planted = (run.config.output_dir / "episodes" / probe.plant_content.episode / probe.plant_content.path).read_text()
        state = json.loads(planted)
        assert bytes.fromhex(marker) == __import__("base64").b64decode(state["base64"])
        assert probe.marker_sha256 == hashlib.sha256(bytes.fromhex(marker)).hexdigest() == probe.plant_sha256
        assert probe.mount_relationship == "writable_layer"
        assert probe.plant_container_id and probe.receiver_container_id
        assert probe.plant_container_id != probe.receiver_container_id
        assert probe.container_absent is True and probe.project_empty is True and probe.teardown_error is None
        assert marker not in receiver_text and "NUDI_PLANT_HEX" not in receiver_text
        assert probe.marker_disclosed_to_receiver is False
        assert probe.receiver_capture_point == "agent_start" and probe.receiver_exists is False
        assert probe.receiver_observed_end <= probe.receiver_agent_started_at
        assert probe.classification == "not_observed" == assessment.persistence
        assert assessment.outcome != "accepted_invalid"
        assert any("Startup code" in item for item in assessment.limits)
        assert set(probe.episodes) == set(run.record.probe_episodes)
        assert run.record.simulation.episodes == ["ordinary"]
        assert set(run.record.probe_episodes).isdisjoint(run.record.simulation.episodes)
        assert all(name.endswith("-attacker") for name in run.record.probe_episodes)
        print("NUDI_PERSISTENCE " + json.dumps({"probe": probe.model_dump(), "assessment": assessment.model_dump(),
              "ordinary_episodes": run.record.simulation.episodes, "probe_episodes": run.record.probe_episodes}, sort_keys=True))

    monkeypatch.setenv("XAI_API_KEY", PROVIDER_KEY)
    asyncio.run(main())


def test_attack_passes_a_goal_reminder_matched_to_each_condition(tmp_path, monkeypatch, credentials):
    """Each exploit or no-hint attempt is wrapped with the exploit reminder; a valid-work attempt
    is wrapped with the valid-work reminder, which names its own goal rather than 'not the task'."""
    endpoint = attack_endpoint(plain_claim)
    sink = {"episodes": []}
    reminders = {}

    async def native(config, queue, **work):
        assert queue is sink["run"].queue
        work["_names"] = sink["episodes"]
        reminders[config.output_dir.name] = work.get("reminder")
        return await scripted_episodes(config, queue, **work)

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            monkeypatch.setattr(run_state, "run_episode", native)
            result = await attack_module.attack(run, maximum_attempts=1, discovery_attempts=1, candidates=[
                attack_module.Candidate(id="reject", category="unchecked_requirements", check="check-1",
                                        mechanism="Valid work is rejected", valid_work=True,
                                        guidance={"full": "FULL-reject", "minimal": "MIN-reject"}),
                attack_module.Candidate(id="hack", mechanism="suspected boundary of hack",
                                        guidance={"full": "FULL-hack", "minimal": "MIN-hack"}),
            ])
            assert attack_module.EXPLOIT_REMINDER != attack_module.VALID_WORK_REMINDER
            for attempt in result.attempts:
                expected = attack_module.VALID_WORK_REMINDER if attempt.candidate == "reject" else attack_module.EXPLOIT_REMINDER
                assert reminders[attempt.episode] == expected
            # The no-hint discovery attempt is an exploit attempt.
            discovery = next(attempt for attempt in result.attempts if attempt.candidate is None)
            assert reminders[discovery.episode] == attack_module.EXPLOIT_REMINDER

    asyncio.run(main())


@pytest.mark.parametrize("minimal_hints", [False, True])
def test_the_minimal_hint_level_runs_only_when_requested(tmp_path, monkeypatch, credentials, minimal_hints):
    """The full hint reproduces. Off, the minimal hint level is not attempted; its condition is not_requested, which
    keeps the attack neither partial nor unknown, and the report says so. On, it follows the reproduction."""
    endpoint = attack_endpoint(evidenced_claim)
    sink = {"episodes": []}

    async def main():
        async with serve(endpoint) as base:
            model = ModelConfig(model="xai/grok-4.7", api_base=base)
            run = new_run(tmp_path, monkeypatch, credentials, models={"attacker": model, "inspector": model})
            sink["run"] = run
            bind_reproducing_runner(monkeypatch, sink)
            return await attack_module.attack(run, maximum_attempts=1, discovery_attempts=0, full=FULL, minimal=MINIMAL,
                                              minimal_hints=minimal_hints)

    result = asyncio.run(main())
    assert levels(result) == ["full", "minimal"][:1 + minimal_hints]
    # On, the minimal hint's reading is unknown, which leaves the attack partial.
    assert result.status == ("partial" if minimal_hints else "complete") and result.minimal_hints is minimal_hints
    assert result.candidates[0].conditions == {"full": "evidenced_issue", "minimal": "unknown" if minimal_hints else "not_requested",
                                                 "none": "unattempted" if minimal_hints else "not_requested"}
    sink["run"].save()
    built = report.build(sink["run"].config.output_dir, selected=["attack"])
    text = report.markdown(built)
    assert built["attack"]["minimal_hints"] is minimal_hints and built["status"] == "complete"
    assert built["unresolved"] == (["attack"] if minimal_hints else [])
    assert any("minimal" in warning for warning in built["warnings"]) is minimal_hints
    assert ("hints not requested, so no attempt with only a hint ran" in text) is not minimal_hints
    assert ("- Not attempted, hints not requested: supplied with only a hint" in text) is not minimal_hints


def test_every_attempt_ends_with_one_result_event_carrying_its_saved_status(tmp_path, monkeypatch, credentials):
    """`attempt_end` comes when the native episode returns, before the attack inspector judges it, and a session's
    finding may be another exploit than the target. So each attempt ends with one `attempt_result` holding the status
    saved for it: a reproduction, a zero reward with no session, and an attempt the spending cap stopped."""
    run = new_run(tmp_path, monkeypatch, credentials, concurrency=4)

    async def episodes(config, queue, **work):
        result = await scripted_episodes(config, queue, **work)
        if "ZERO" in (work.get("instruction") or ""):
            result.rewards = {"reward": 0.0}
            (config.output_dir / "episode.json").write_text(result.model_dump_json())
        return result

    scripted, _ = scripted_judge({"hack-0": "accepted_invalid"})

    async def inspect(run, mode, pool, *args, request, **kwargs):
        if (request["target_candidate"] or {}).get("id") == "hack-2":
            raise run_state.SpendingCapReached("scripted cap")
        return await scripted(run, mode, pool, *args, request=request, **kwargs)

    monkeypatch.setattr(run_state, "run_episode", episodes)
    monkeypatch.setattr(attack_module, "inspect", inspect)
    problems = [attack_module.Problem(id=f"P{number + 1}", cause=f"cause {number}", findings=[f"hack-{number}"]) for number in range(3)]
    found = [candidate("hack-0", FULL, MINIMAL), candidate("hack-1", "ZERO steps"), candidate("hack-2", "capped steps")]
    asyncio.run(attack_module.attack(run, maximum_attempts=1, discovery_attempts=1, candidates=found, problems=problems))
    saved = attack_module.AttackResult.model_validate_json((run.config.output_dir / "attack.json").read_text())
    logged = [json.loads(line) for line in (run.config.output_dir / "events.jsonl").read_text().splitlines()]
    results = [{key: item[key] for key in ("episode", "problem", "level", "number", "status")} for item in logged if item["kind"] == "attempt_result"]
    assert sorted(results, key=str) == sorted(({"episode": item.episode, "problem": item.problem, "level": item.level, "number": item.number,
                                                "status": item.status} for item in saved.attempts), key=str)
    statuses = {(item["problem"], item["level"]): item["status"] for item in results}
    assert statuses[("P1", "full")] == "evidenced_issue" and statuses[("P2", "full")] == "no_evidenced_issue"
    assert statuses[("P3", "full")] == "spending_exhausted" and statuses[(None, "none")] == "no_evidenced_issue"
    assert sum(item["kind"] == "attempt_end" for item in logged) == 4


def test_a_hinted_exploit_by_any_route_counts_for_its_problem_and_the_weaker_hint_follows(tmp_path, monkeypatch, credentials):
    """An Attacker given hack-0's full instructions made an exploit its attack inspector measured with a check of its own,
    not hack-0's: it counts for hack-0 with no rerun of hack-0's check. The hint follows it, and no extra information
    follows the hint's exploit, its attack inspector told no target."""
    found = attack_module.Candidate(id="hack-0", mechanism="unchecked output", outcome="accepted_invalid",
                                    guidance={"full": "Exploit the unchecked output.", "minimal": "Look at the output."})
    result, requests = scripted_readings(tmp_path, monkeypatch, credentials, found, lambda check_of, episode: [
        reading(check_of(f"check-{episode}"), episode, "accepted_invalid")], minimal_hints=True)
    assert levels(result) == ["full", "minimal", "none"]
    assert [item.kind for item in result.findings] == ["reproduction", "reproduction", "discovery"]
    assert result.candidates[0].conditions == {"full": "evidenced_issue", "minimal": "evidenced_issue", "none": "evidenced_issue"}
    assert [request["target_candidate"]["id"] for request in requests[:2]] == ["hack-0", "hack-0"]
    assert requests[2]["target_candidate"] is None and requests[2]["known_causes"] == []
    assert not any("check_rerun" in request for request in requests)


def test_a_no_hint_attempt_gets_the_known_causes_and_no_target_and_its_reading_names_the_cause(tmp_path, monkeypatch, credentials):
    """A no-hint attempt's attack inspector is told no target, only the causes known when it starts; the problem of its
    exploit is the one the judge callback reads from that reading."""
    known = [attack_module.Problem(id="P1", source="hack inspector", cause="The grader trusts the answer file.", members=["hack-0"])]
    read = []
    result, requests = scripted_readings(tmp_path, monkeypatch, credentials, None, lambda check_of, episode: [
        reading(check_of(f"check-{episode}"), episode, "accepted_invalid")], problems=known,
        judge=lambda attempt, assessment, case: read.append(assessment.claim.check) or "P1")
    (request,) = requests
    assert request["target_candidate"] is None
    assert request["known_causes"] == [{"id": "P1", "cause": "The grader trusts the answer file."}]
    assert [(item.kind, item.problem) for item in result.findings] == [("discovery", "P1")]
    assert read == [f"check-{result.attempts[0].episode}"] and result.attempts[0].problem == "P1"


def test_each_save_of_the_attack_carries_the_callers_causes(tmp_path, monkeypatch, credentials):
    """The attack saves the caller's list of causes, so a cause the judge callback opens during the attack is in every
    record saved after it, also when the attack is stopped before it returns."""
    known = [attack_module.Problem(id="P1", source="hack inspector", cause="The grader trusts the answer file.", members=["hack-0"])]
    causes = []

    def judge(attempt, assessment, case):
        causes.append(attack_module.Cause(id="C1", cause="The grader trusts the answer file.", problems=["P1"]))
        return "P1"

    result, _ = scripted_readings(tmp_path, monkeypatch, credentials, None, lambda check_of, episode: [
        reading(check_of(f"check-{episode}"), episode, "accepted_invalid")], problems=known, causes=causes, judge=judge)
    assert result.causes is causes and [item.id for item in result.causes] == ["C1"]


def test_a_no_hint_exploit_naming_a_known_cause_is_that_problem_and_a_new_sentence_a_new_attacker_problem(tmp_path, monkeypatch, credentials):
    """The attack inspector's `cause` names a known problem by id, which makes no problem, or says a new sentence, which is a
    new Attacker problem with that cause; without one the cause is the reading's mechanism."""
    run = new_run(tmp_path, monkeypatch, credentials)
    problems = [attack_module.Problem(id="P1", source="hack inspector", cause="The grader trusts the answer file.", members=["hack-0"])]
    readings = []
    for number, cause in enumerate(["P1", "The grader trusts the log.", None]):
        episode = f"000{number}-attacker"
        readings.append(reading(linked_check(episode, f"check-{number}"), episode, "accepted_invalid", number))
        readings[-1].claim.cause = cause
    attempts = [attack_module.AttackAttempt(level="none", number=number + 1, context="c", episode=item.claim.episode)
                for number, item in enumerate(readings)]
    assert [send.attributed(run, problems, attempt, item, {}) for attempt, item in zip(attempts, readings)] == ["P1", "A1", "A2"]
    assert [(item.id, item.source, item.cause, item.members) for item in problems[1:]] == [
        ("A1", "Attacker", "The grader trusts the log.", ["0001-attacker"]),
        ("A2", "Attacker", "Output A is never checked, reading 2.", ["0002-attacker"])]
