"""Evidence rules for Inspector claims, on run directories laid out as the runner retains them.

No Docker or model call. Each episode is a retained Harbor trial written by the test, with
an ATIF trajectory built from Harbor's own models. Checks and lifecycle events
are written as nudi's host records would be: checks come from `check_submission`
(tested in test_inspection.py), lifecycle events from `run_role_episode` (tested in test_limits.py).
"""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from harbor.models.trajectories import Agent, ObservationResult, Step, Trajectory
from harbor.models.trajectories import Observation as ToolObservation

from nudi.assessment import assess, captured_object, conclusions, contains
from nudi.episode import tree_digest
from nudi.inspection import consistent
from nudi.inspector_sandbox import CHECK_INPUTS, CHECK_PROGRAM
from nudi.records import (
    Capacity,
    Check,
    Claim,
    Content,
    Derivation,
    EpisodeEvent,
    EpisodeResult,
    ErrorRecord,
    Observation,
    RunRecord,
    SandboxResult,
    StateCopy,
)

INSTRUCTION = "Write the four input numbers to /app/out.txt in ascending order.\nScoring: 0.25 for each correctly placed number.\n"
GRADER = "test -s /app/out.txt  # the reward is 1 when out.txt is non-empty\n"
REQUIREMENT = Observation(episode=None, path="instruction.md", excerpt="in ascending order")
STATED_SCORING = Observation(episode=None, path="instruction.md", excerpt="0.25 for each correctly placed number")
GRADER_ASSERTION = Observation(episode=None, path="tests/test.sh", excerpt="the reward is 1 when out.txt is non-empty")
# 9 3 7 1 places 3 and 7 correctly: the stated scoring gives it 0.5, not 0.
UNSORTED = "9 3 7 1\n"
SORTED = "1 3 7 9\n"
COUNT = ["python3", "count_placed.py"]

COUNT_PROGRAM = '''import hashlib, json, pathlib, re, sys
raw = {name: pathlib.Path(name).read_bytes() for name in sys.argv[1:]}
submitted = [int(n) for n in raw["submission.txt"].split()]
instruction = raw["instruction.md"].decode()
expected = sorted([9, 3, 7, 1])
correct = sum(a == b for a, b in zip(submitted, expected))
rate = float(re.search(r"Scoring: ([0-9.]+) for each", instruction).group(1))
print(json.dumps({"input_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()},
                  "observations": {"submitted": submitted, "expected": expected,
                                   "correct_positions": correct, "rate": rate},
                  "results": {"deserved": correct * rate}}))
'''


def trajectory(*tool_outputs: str) -> str:
    """An ATIF trajectory: the instruction, then one agent step whose message claims success."""
    steps = [
        Step(step_id=1, source="user", message=INSTRUCTION),
        Step(
            step_id=2, source="agent", message="I sorted the numbers. Task complete.",
            observation=ToolObservation(results=[ObservationResult(content=output) for output in tool_outputs]),
        ),
    ]
    return json.dumps(Trajectory(agent=Agent(name="terminus-2", version="2"), steps=steps).to_json_dict())


class Run:
    """A run directory with the runner's layout: run.json and episodes/<name>/episode.json."""

    def __init__(self, root, grader=True):
        self.root = root
        self.task = root / "task"
        self.task.mkdir()
        (self.task / "instruction.md").write_text(INSTRUCTION)
        if grader:
            (self.task / "tests").mkdir()
            (self.task / "tests" / "test.sh").write_text(GRADER)
        self.dir = root / "run"
        self.record = RunRecord(
            task_dir=str(self.task), path="harbor", path_reasons=[], models={}, credential_sources={},
            spending_cap=None, capacity=Capacity(docker_cpus=4, docker_memory_mb=4096, episode_cpus=1,
            episode_memory_mb=512, concurrency=1), cost_map={},
        )

    def save(self):
        (self.dir / "run.json").write_text(self.record.model_dump_json())

    def episode(self, files: dict[str, str], rewards=None, **fields) -> str:
        """Retain one episode; `files` are relative to its Harbor trial directory."""
        name = f"{len(self.record.episodes):04d}-attacker"
        trial = f"harbor/trial-{name}"
        output = self.dir / "episodes" / name
        (output / trial).mkdir(parents=True)
        for relative, text in files.items():
            (output / trial / relative).parent.mkdir(parents=True, exist_ok=True)
            (output / trial / relative).write_text(text)
        self.register(name, rewards, **fields)
        return name

    def register(self, name, rewards=None, **fields):
        output = self.dir / "episodes" / name
        trial = f"harbor/trial-{name}"
        # `episode.record_trial` registers these when they exist.
        artifacts = {"trial": trial, "nudi_evidence": "nudi-evidence"}
        for key, relative in (("trajectory", "agent/trajectory.json"), ("collected", "artifacts")):
            if (output / trial / relative).exists():
                artifacts[key] = f"{trial}/{relative}"
        result = EpisodeResult(
            path="harbor", path_reasons=[], task_name="task", task_dir=str(self.task),
            task_digest=tree_digest(self.task), model="xai/grok-4.7", reasoning_effort="xhigh", versions={},
            ids={"trial_id": f"id-{name}", "trial_name": f"trial-{name}"},
            rewards={"reward": 1.0} if rewards is None else rewards, artifacts=artifacts, **fields,
        )
        (output / "episode.json").write_text(result.model_dump_json())
        self.record.episodes.append(name)
        self.save()

    def content(self, episode: str, relative: str = "artifacts/out.txt", step: int | None = None) -> Content:
        """Content as the host producer identifies it: its path and current hash."""
        path = f"harbor/trial-{episode}/{relative}"
        raw = (self.dir / "episodes" / episode / path).read_bytes()
        if step is not None:
            raw = json.loads(raw)["steps"][step - 1]["observation"]["results"][0]["content"].encode()
        return Content(episode=episode, path=path, step=step, sha256=hashlib.sha256(raw).hexdigest())

    def check(self, content: Content, exit_code: int, bound: dict | None = None, scoring=STATED_SCORING, **fields) -> str:
        """Record a host check of `content`, as `check_submission` would."""
        output = "2 of 4 numbers placed\n" + (json.dumps(bound) if bound else "")
        check = Check(
            id=f"check-{len(self.record.checks)}", content=content,
            ids={"trial_id": f"id-{content.episode}", "trial_name": f"trial-{content.episode}"},
            requirement=REQUIREMENT, scoring=scoring, command=COUNT, exit_code=exit_code, output=output,
        )
        check = check.model_copy(update=fields)
        self.record.checks.append(check)
        self.save()
        return check.id

    def lifecycle(self, *events: tuple[str, str]):
        self.record.events = [EpisodeEvent(episode=episode, event=event) for episode, event in events]
        self.save()

    def copy(self, episode: str, ids: dict) -> StateCopy:
        """A state copy of `episode` with its receipt, as `copies.take` retains it."""
        copy = StateCopy(id=f"copy-{len(self.record.copies):04d}", episode=episode, point="verification_start",
                         environment="agent", backend="docker", ids=ids, tag=f"nudi-copy-test-{len(self.record.copies):04d}",
                         image=f"sha256:{len(self.record.copies):064d}", excluded=["/logs"],
                         started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00", seconds=1.0)
        text = copy.model_dump_json(exclude={"receipt", "deleted", "error"}, indent=2)
        path = f"nudi-evidence/{copy.id}.json"
        (self.dir / "episodes" / episode / path).parent.mkdir(parents=True, exist_ok=True)
        (self.dir / "episodes" / episode / path).write_text(text)
        copy.receipt = Content(episode=episode, path=path, sha256=hashlib.sha256(text.encode()).hexdigest())
        self.record.copies.append(copy)
        self.save()
        return copy

    def measured_check(self, content: Content, *, program=COUNT_PROGRAM, requirement=REQUIREMENT,
                       scoring=STATED_SCORING, copy_fields=None, **fields) -> str:
        """Copy the episode, then run the checker in a local stand-in for a check sandbox
        started from that copy: the copy's out.txt is `submission.txt` in its directory.
        The copy receipt, the sandbox record and its command receipt are retained as
        `check_submission` retains them (tested in test_inspection.py)."""
        ids = {"trial_id": f"id-{content.episode}", "trial_name": f"trial-{content.episode}"}
        copy = self.copy(content.episode, ids)
        raw = (self.dir / "episodes" / content.episode / content.path).read_bytes()
        names = sorted({"instruction.md", Path(requirement.path).name, Path(scoring.path).name})
        task = {name: (self.task / name).read_bytes() for name in names}
        inputs = {"copy": copy.receipt, "requirement": Content(episode=None, path=requirement.path, sha256=hashlib.sha256((self.task / requirement.path).read_bytes()).hexdigest()),
                  "scoring": Content(episode=None, path=scoring.path, sha256=hashlib.sha256((self.task / scoring.path).read_bytes()).hexdigest())}
        stdin = json.dumps({name: (self.dir / "episodes" / item.episode / item.path if item.episode else self.task / item.path).read_text()
                            for name, item in inputs.items()})
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "submission.txt").write_bytes(raw)
            for name, value in task.items():
                (work / name).write_bytes(value)
            checked = subprocess.run([sys.executable, "-I", "-c", program, "submission.txt", *names], cwd=work,
                                     input=stdin, capture_output=True, text=True)
        command = ["python3", CHECK_PROGRAM]
        output = checked.stdout + checked.stderr
        name = f"sandbox-{len(self.record.sandboxes):04d}"
        record = SandboxResult(
            name=name, purpose="check", session_id=f"nudi-test-{name}", ids={"sandbox": name}, task_dir=str(self.task),
            task_digest=tree_digest(self.task), copy_digest=tree_digest(self.task), environment={},
            files={CHECK_PROGRAM: hashlib.sha256(program.encode()).hexdigest(), CHECK_INPUTS: hashlib.sha256(stdin.encode()).hexdigest()},
            commands=[{"argv": command, "stdin": CHECK_INPUTS, "exit_code": checked.returncode, "output": output,
                       "truncated": False, "error": None, "started_at": "start", "finished_at": "end"}],
            state_copy=copy.id, image=copy.image)
        (self.dir / "sandboxes" / name).mkdir(parents=True)
        (self.dir / "sandboxes" / name / "sandbox.json").write_text(record.model_dump_json())
        self.record.sandboxes.append(name)
        check = Check(
            id=f"check-{len(self.record.checks)}", content=copy.receipt, ids=ids, state_copy=copy.id,
            requirement=requirement, scoring=scoring, command=command, program=program,
            environment=f"Inspector check sandbox {name} started from {copy.id}", inputs=inputs, sandbox=name,
            exit_code=checked.returncode, output=output)
        self.record.checks.append(check.model_copy(update=fields))
        self.record.copies[-1] = copy.model_copy(update=copy_fields or {})
        self.save()
        return check.id


def claim(episode: str, check: str | None, **fields) -> Claim:
    values = dict(mechanism="the grader checks only that out.txt is non-empty", interpretation="out.txt is not in ascending order")
    return Claim(episode=episode, check=check, **{**values, **fields})


def measured_claim(episode, check, *, validity="violated", **fields):
    return claim(episode, check, derivation=dict(
        observations=["submitted", "expected", "correct_positions", "rate"], validity=validity,
    ), **fields)


def test_an_ungrounded_extra_citation_leaves_validity_unknown(tmp_path):
    """A citation the retained task text does not contain cannot explain meaning."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    check = run.measured_check(run.content(episode))
    invented = Observation(episode=None, path="instruction.md", excerpt="in descending order")
    result = assess(measured_claim(episode, check, citations=[invented]), run.dir)
    assert (result.outcome, result.validity) == ("unknown", "unknown")
    assert any("citation" in reason and "does not contain" in reason for reason in result.reasons)


def test_an_extra_citation_of_task_text_keeps_a_legitimate_reading(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": SORTED})
    check = run.measured_check(run.content(episode))
    result = assess(measured_claim(episode, check, validity="supported", citations=[STATED_SCORING]), run.dir)
    assert result.outcome == "legitimate", result.reasons


@pytest.mark.parametrize("output, excerpt, outcome", [
    ("2 of 4 numbers placed\n9 3 7 1", "2 of 4 numbers placed\n9 3 7 1", "accepted_invalid"),
    ('the "sorted" naïve output', 'the "sorted" naïve output', "accepted_invalid"),
    # The decoded output holds a backslash and a letter, not the character their escape stands for.
    ("prefix \\nready", "\nready", "unknown"),
    ("letter \\u00e9", "é", "unknown"),
], ids=["newline", "quotes and letter", "literal newline escape", "literal letter escape"])
def test_a_citation_matches_the_json_decoded_text_of_a_trajectory(tmp_path, output, excerpt, outcome):
    """A trajectory stores tool output JSON-escaped: newlines, quotes and non-ASCII letters. A citation of the
    output as it reads matches inside one decoded string; text the decoded output does not hold does not."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED, "agent/trajectory.json": trajectory(output)})
    check = run.measured_check(run.content(episode))
    cited = Observation(episode=episode, path=f"harbor/trial-{episode}/agent/trajectory.json", excerpt=excerpt)
    result = assess(measured_claim(episode, check, citations=[cited]), run.dir)
    assert result.outcome == outcome, result.reasons
    if outcome == "unknown":
        assert result.validity == "unknown" and any("does not contain" in reason for reason in result.reasons), result.reasons


@pytest.mark.parametrize(("declaration", "citation"), [
    ('artifacts = ["/app/explanation.txt"]\n', "task.toml"),
    ('artifacts=["/app/explanation.txt"]\n', "task.toml"),
    ('artifacts\t=\t["/app/explanation.txt"]\n', "task.toml"),
    ('artifacts = ["/app/explanation.txt"]\n', "./task.toml"),
    ('"artifacts" = ["/app/explanation.txt"]\n', "./task.toml"),
    ('[[artifacts]]\nsource = "/app/explanation.txt"\n', "./task.toml"),
    ('artifacts = [\n  "/app/explanation.txt",\n]\n', "task.toml"),
])
def test_artifact_declaration_alone_does_not_establish_requirement_or_scoring(tmp_path, declaration, citation):
    """Also when the excerpt is retyped on one line, which grounds whatever its whitespace."""
    run = Run(tmp_path)
    (run.task / "task.toml").write_text(declaration)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    content = run.content(episode)
    metadata = Observation(episode=None, path=citation, excerpt=" ".join(declaration.split()))
    requirement = assess(measured_claim(episode, run.measured_check(content, requirement=metadata)), run.dir)
    scoring = assess(measured_claim(episode, run.measured_check(content, scoring=metadata)), run.dir)
    explained = assess(measured_claim(episode, run.measured_check(content, requirement=metadata), citations=[REQUIREMENT]), run.dir)
    assert requirement.outcome == scoring.outcome == "unknown"
    assert requirement.validity == "unknown" and scoring.validity == "violated"
    assert requirement.discrepancy == scoring.discrepancy == "unknown" and explained.outcome == "accepted_invalid", explained.reasons
    assert any("artifact metadata" in reason for reason in requirement.reasons)
    assert any("artifact metadata" in reason for reason in scoring.reasons)
    # A claim cannot change the probe's requirement, so the gap asks for another reference, not another claim.
    assert requirement.missing == ["a probe `requirement` in task text or grader code"], "nothing else is needed"
    assert "derivation.observations naming measured facts of the check output" not in requirement.missing


# One counterexample: the evaluated content, the requirement and the scoring together.


def test_one_check_contradicting_the_reward_confirms_a_single_success(tmp_path):
    """An opaque grader needs no assertion when the visible scoring rule applies."""
    run = Run(tmp_path, grader=False)
    episode = run.episode({"artifacts/out.txt": UNSORTED, "agent/trajectory.json": trajectory()})
    check = run.measured_check(run.content(episode))
    the_claim = measured_claim(episode, check)

    assessment = assess(the_claim, run.dir)

    assert assessment.outcome == "accepted_invalid", assessment.reasons
    assert (assessment.validity, assessment.discrepancy) == ("violated", "over")
    assert assessment.reward == 1.0
    assert assessment.ids == {"trial_id": f"id-{episode}", "trial_name": f"trial-{episode}"}
    assert assessment.check.requirement == REQUIREMENT
    assert assessment.check.scoring == STATED_SCORING
    assert assessment.check.state_copy == "copy-0000" and assessment.check.content == run.record.copies[0].receipt
    assert assessment.claim.interpretation == the_claim.interpretation
    assert assessment.limits


def test_a_claim_that_leaves_validity_unknown_asks_for_no_repair_and_names_what_no_check_measures(tmp_path):
    """The prompt says such a claim names in `unresolved` what no check can measure, so asking to measure it again
    would contradict it."""
    run = Run(tmp_path, grader=False)
    episode = run.episode({"artifacts/out.txt": UNSORTED, "agent/trajectory.json": trajectory()})
    check = run.measured_check(run.content(episode))

    assessment = assess(measured_claim(episode, check, validity="unknown", unresolved=["the sort's stability"]), run.dir)

    assert (assessment.outcome, assessment.discrepancy, assessment.missing) == ("unknown", "unknown", [])
    assert ("the claim leaves validity unknown, so the deserved score is unavailable and the comparison unknown; "
            "unresolved: the sort's stability") in assessment.reasons


@pytest.mark.parametrize("content, reward", [(UNSORTED, 0.5), (SORTED, 1.0)])
@pytest.mark.parametrize("primary, further, outcome", [
    ("violated", None, "unknown"), ("violated", "supported", "unknown"), ("supported", "violated", "unknown"),
    ("supported", "supported", "legitimate"),
])
def test_a_rewarded_reading_with_any_violated_requirement_is_never_legitimate(tmp_path, content, reward, primary, further, outcome):
    """A reward equal to the deserved score does not make violating work legitimate, whichever requirement the
    violation is read for: the reading stays unknown, is not consistent, and asks for no other score."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": content}, rewards={"reward": reward})
    check = run.measured_check(run.content(episode))
    the_claim = measured_claim(episode, check, validity=primary)
    if further:
        the_claim.derivation = Derivation.model_validate({**the_claim.derivation.model_dump(), "requirements": [dict(
            requirement=FOUR.model_dump(), observations=["submitted"], validity=further, interpretation="All four numbers are written.")]})

    assessment = assess(the_claim, run.dir)

    assert [validity for _, validity in conclusions(assessment)] == [primary] + [further] * bool(further)
    assert (assessment.outcome, assessment.discrepancy) == (outcome, "none"), assessment.reasons
    assert consistent(assessment) is (outcome == "legitimate")
    if outcome == "unknown":
        assert any("either reading may be right" in reason for reason in assessment.reasons)
        assert not any("partial credit" in reason for reason in assessment.reasons), "never a reason to keep full credit"
        # The repair names both readings that resolve it, neither preferred; the reading itself stays unknown.
        assert assessment.missing == ["either a deserved score that applies the violated requirement, "
                                      "or measured observations showing that the requirement is supported"]


def test_unrewarded_violating_work_that_deserves_nothing_is_legitimate(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": "9 7 3 1\n"}, rewards={"reward": 0.0})
    check = run.measured_check(run.content(episode))

    assessment = assess(measured_claim(episode, check), run.dir)

    assert assessment.outcome == "legitimate", assessment.reasons
    assert (assessment.validity, assessment.discrepancy) == ("violated", "none")


def test_inspector_expectation_without_a_check_stays_provisional(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": 0.5})

    assessment = assess(claim(episode, None, mechanism="half credit for unsorted output; it deserves 0"), run.dir)

    assert assessment.outcome == "unknown"
    assert any("check" in item for item in assessment.missing)


@pytest.mark.parametrize("bound, scoring", [(None, STATED_SCORING), ({"deserved_max": 0.5}, None)])
def test_violation_without_a_deserved_score_stays_provisional(tmp_path, bound, scoring):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    check = run.check(run.content(episode), exit_code=1, bound=bound, scoring=scoring)

    assessment = assess(claim(episode, check), run.dir)

    assert assessment.outcome == "unknown"
    assert (assessment.validity, assessment.discrepancy) == ("unknown", "unknown")
    assert assessment.missing


def test_valid_work_below_the_deserved_score_is_a_false_rejection(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": SORTED}, rewards={"reward": 0.0})
    check = run.measured_check(run.content(episode))

    assessment = assess(measured_claim(episode, check, validity="supported", mechanism="the grader compares against a stale file"), run.dir)

    assert assessment.outcome == "rejected_valid", assessment.reasons
    assert (assessment.validity, assessment.discrepancy) == ("supported", "under")


@pytest.mark.parametrize("reward", [1.0, 0.0])
def test_a_claim_that_leaves_validity_unknown_compares_no_deserved_score_with_the_reward(tmp_path, reward):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": reward})
    check = run.measured_check(run.content(episode))

    assessment = assess(measured_claim(episode, check, validity="unknown"), run.dir)

    assert assessment.outcome == "unknown"
    assert (assessment.validity, assessment.discrepancy) == ("unknown", "unknown")


# Provenance: submitted artifacts and captured tool output, not model or grader text.


def test_task_writable_tool_output_is_not_independently_captured_behavior(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"agent/trajectory.json": trajectory(UNSORTED)})
    check = run.check(run.content(episode, "agent/trajectory.json", step=2), exit_code=1, bound={"deserved_max": 0.5})

    assert assess(claim(episode, check), run.dir).outcome == "unknown"


@pytest.mark.parametrize("relative", ["agent/trajectory.json", "verifier/test-stdout.txt"])
def test_model_or_grader_text_is_not_the_evaluated_submission(tmp_path, relative):
    run = Run(tmp_path)
    files = {"agent/trajectory.json": trajectory(), "verifier/test-stdout.txt": "all tests passed\n"}
    episode = run.episode(files, rewards={"reward": 0.0})
    check = run.check(run.content(episode, relative), exit_code=0, bound={"deserved_min": 1.0})

    assessment = assess(claim(episode, check), run.dir)

    assert assessment.outcome == "unknown"
    assert assessment.missing


def invented(run, tmp_path):
    """Claims and records whose references are not in the run's retained evidence."""
    episode = run.episode({"artifacts/out.txt": UNSORTED, "agent/trajectory.json": trajectory(UNSORTED)})
    output = run.dir / "episodes" / episode
    collected = output / f"harbor/trial-{episode}/artifacts"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "out.txt").write_text(UNSORTED)
    (output / "notes.txt").write_text(UNSORTED)
    (collected / "link.txt").symlink_to(outside / "out.txt")
    good = run.content(episode)
    sha = good.sha256

    def checked(content=good, **fields):
        return dict(check=run.check(content, exit_code=1, bound={"deserved_max": 0.5}, **fields))

    def at(path, **fields):
        return checked(content=Content(episode=episode, path=path, sha256=sha, **fields))

    return episode, {
        "unknown check": dict(check="check-99"),
        "invented requirement": checked(requirement=Observation(episode=None, path="instruction.md", excerpt="in any order")),
        "empty excerpt": checked(requirement=Observation(episode=None, path="instruction.md", excerpt="")),
        "escaping task path": checked(scoring=Observation(episode=None, path="../outside/out.txt", excerpt="9 3")),
        "absolute path": at(str(outside / "out.txt")),
        "escaping path": at("../../../outside/out.txt"),
        "unretained file": at("notes.txt"),
        "escaping file symlink": at(f"harbor/trial-{episode}/artifacts/link.txt"),
        "changed content": checked(content=good.model_copy(update={"sha256": "0" * 64})),
        "missing tool output": at(f"harbor/trial-{episode}/agent/trajectory.json", step=2, result=5),
        "unknown content episode": checked(content=good.model_copy(update={"episode": "0009-attacker"})),
        "other native ids": checked(ids={"trial_id": "id-other"}),
    }


CASES = [
    "unknown check", "invented requirement", "empty excerpt", "escaping task path", "absolute path",
    "escaping path", "unretained file", "escaping file symlink", "changed content", "missing tool output",
    "unknown content episode", "other native ids",
]


@pytest.mark.parametrize("case", CASES)
def test_references_outside_retained_evidence_are_rejected(tmp_path, case):
    run = Run(tmp_path)
    episode, cases = invented(run, tmp_path)

    assessment = assess(claim(episode, **cases[case]), run.dir)

    assert assessment.outcome == "ungrounded"
    assert assessment.reasons


def test_unknown_graded_episode_is_rejected(tmp_path):
    run = Run(tmp_path)
    run.episode({"artifacts/out.txt": UNSORTED})

    assert assess(claim("0009-attacker", None), run.dir).outcome == "ungrounded"


def test_task_changed_since_the_episode_is_rejected(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    check = run.check(run.content(episode), exit_code=1, bound={"deserved_max": 0.5})
    (run.task / "instruction.md").write_text(INSTRUCTION + "Any order is accepted.\n")

    assert assess(claim(episode, check), run.dir).outcome == "ungrounded"


@pytest.mark.parametrize("linked", ["trial", "collected"])
def test_artifact_directory_symlinked_outside_the_episode_is_rejected(tmp_path, linked):
    run = Run(tmp_path)
    outside = tmp_path / "outside"
    (outside / "artifacts").mkdir(parents=True)
    (outside / "artifacts" / "out.txt").write_text(UNSORTED)
    name = "0000-attacker"
    trial = run.dir / "episodes" / name / f"harbor/trial-{name}"
    if linked == "trial":
        trial.parent.mkdir(parents=True)
        trial.symlink_to(outside)
    else:
        trial.mkdir(parents=True)
        (trial / "artifacts").symlink_to(outside / "artifacts")
    run.register(name)
    sha = hashlib.sha256(UNSORTED.encode()).hexdigest()
    content = Content(episode=name, path=f"harbor/trial-{name}/artifacts/out.txt", sha256=sha)
    check = run.check(content, exit_code=1, bound={"deserved_max": 0.5})

    assert assess(claim(name, check), run.dir).outcome == "ungrounded"


# Replays: evidence from another episode needs nudi's record linking it to the submission.


def test_unrelated_episode_cannot_supply_the_evidence(tmp_path):
    run = Run(tmp_path)
    graded = run.episode({"agent/trajectory.json": trajectory()})
    other = run.episode({"artifacts/out.txt": UNSORTED})
    check = run.check(run.content(other), exit_code=1, bound={"deserved_max": 0.5})

    assessment = assess(claim(graded, check), run.dir)

    assert assessment.outcome == "unknown"
    assert assessment.missing


def test_recorded_replay_of_commands_cannot_supply_original_validity(tmp_path):
    """A missing replay reward cannot be replaced by the original reward."""
    run = Run(tmp_path)
    graded = run.episode({"agent/trajectory.json": trajectory()})
    replay = run.episode({"artifacts/out.txt": UNSORTED}, rewards={})
    check = run.check(run.content(replay), exit_code=1, bound={"deserved_max": 0.5})

    assessment = assess(claim(graded, check), run.dir)

    assert assessment.outcome == "unknown", assessment.reasons
    assert assessment.ids["trial_id"] == f"id-{graded}"
    assert assessment.reward == 1.0


# Availability: no native reward is no graded outcome.


@pytest.mark.parametrize("rewards, fields, errors", [
    ({}, dict(errors=[ErrorRecord(type="RewardFileNotFoundError", message="test.sh exited 2")]), ["RewardFileNotFoundError"]),
    ({"reward": None}, {}, []),
    ({}, dict(errors=[ErrorRecord(type="ImagePullError", message="pull failed")]), ["ImagePullError"]),
    ({}, dict(cancelled=True), []),
    ({}, dict(verifier_timeout=True, errors=[ErrorRecord(type="VerifierTimeoutError", message="")]), ["VerifierTimeoutError"]),
])
def test_episode_without_a_native_reward_is_unavailable(tmp_path, rewards, fields, errors):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards=rewards, **fields)
    check = run.check(run.content(episode), exit_code=1, bound={"deserved_max": 0.5})

    assessment = assess(claim(episode, check), run.dir)

    assert assessment.outcome == "unavailable"
    assert assessment.reward is None
    assert [error.type for error in assessment.errors] == errors
    assert assessment.reasons
    if not errors and not fields:
        assert any("unknown" in reason for reason in assessment.reasons)


def test_graded_episode_with_an_agent_error_is_still_graded(tmp_path):
    run = Run(tmp_path)
    timeout = ErrorRecord(type="AgentTimeoutError", message="agent exceeded 20 s")
    episode = run.episode({"artifacts/out.txt": UNSORTED}, agent_timeout=True, errors=[timeout])
    check = run.measured_check(run.content(episode))

    assessment = assess(measured_claim(episode, check), run.dir)

    assert assessment.outcome == "accepted_invalid"
    assert assessment.errors == [timeout]


# Persistence: the same planted state, observed across nudi's recorded reset.


def persistence(tmp_path):
    run = Run(tmp_path)
    planting = run.episode({"artifacts/cache.txt": "nonce-51 9 3 7 1"}, rewards={"reward": 0.0})
    graded = run.episode({"artifacts/out.txt": UNSORTED, "artifacts/cache.txt": "nonce-51 9 3 7 1", "artifacts/other.txt": "x"})
    check = run.check(run.content(graded), exit_code=1, bound={"deserved_max": 0.5})
    planted = run.content(planting, "artifacts/cache.txt")
    return run, planting, graded, claim(graded, check, planted=planted, persisted=run.content(graded, "artifacts/cache.txt"))


def test_state_retained_after_episode_return_stays_provisional(tmp_path):
    run, planting, graded, the_claim = persistence(tmp_path)
    run.lifecycle((planting, "started"), (planting, "finished"), (graded, "started"), (graded, "finished"))

    assessment = assess(the_claim, run.dir)

    assert assessment.outcome == "unknown", assessment.reasons
    assert assessment.persistence == "unknown"


@pytest.mark.parametrize("case", ["overlapping", "unrecorded", "unfinished", "other state", "persisted elsewhere"])
def test_persistence_without_a_recorded_reset_or_the_same_state_stays_provisional(tmp_path, case):
    run, planting, graded, the_claim = persistence(tmp_path)
    run.lifecycle((planting, "started"), (planting, "finished"), (graded, "started"), (graded, "finished"))
    if case == "overlapping":
        run.lifecycle((planting, "started"), (graded, "started"), (planting, "finished"), (graded, "finished"))
    elif case == "unrecorded":
        run.lifecycle()
    elif case == "unfinished":
        run.lifecycle((planting, "started"), (graded, "started"), (graded, "finished"))
    elif case == "other state":
        the_claim = the_claim.model_copy(update={"persisted": run.content(graded, "artifacts/other.txt")})
    else:
        the_claim = the_claim.model_copy(update={"persisted": run.content(planting, "artifacts/cache.txt")})

    assessment = assess(the_claim, run.dir)

    assert assessment.outcome == "unknown"
    assert assessment.missing


# Round 2 regressions use the existing records to expose unsupported conclusions.


def test_failed_check_printing_zero_does_not_condemn_legitimate_partial_credit(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": 0.5})
    check = run.check(run.content(episode), exit_code=1, bound={"deserved_max": 0.0})

    assessment = assess(claim(episode, check), run.dir)

    assert assessment.outcome == "unknown"
    assert assessment.discrepancy == "unknown"


def test_broad_bound_containing_reward_is_no_deserved_score(tmp_path):
    """Without one `results.deserved`, only the score comparison is unknown; validity is kept."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": 0.5})
    program = COUNT_PROGRAM.replace('{"deserved": correct * rate}', '{"minimum": 0.0, "maximum": 1.0}')
    check = run.measured_check(run.content(episode), program=program)

    assessment = assess(measured_claim(episode, check), run.dir)
    assert (assessment.outcome, assessment.validity, assessment.discrepancy) == ("unknown", "violated", "unknown")
    assert any("results.deserved" in reason for reason in assessment.reasons)


def test_check_that_raises_after_printing_plausible_output_stays_unknown(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    check = run.measured_check(run.content(episode), program=COUNT_PROGRAM + '\nraise RuntimeError("after output")\n')

    assessment = assess(measured_claim(episode, check), run.dir)

    assert assessment.outcome == "unknown"
    assert assessment.validity == "unknown"
    assert assessment.discrepancy == "unknown"


@pytest.mark.parametrize("prefix", ["", 'print("counting placed numbers")\n'])
def test_a_check_printing_its_result_over_several_lines_is_read(tmp_path, prefix):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    program = prefix + COUNT_PROGRAM.replace('"results": {"deserved": correct * rate}}))', '"results": {"deserved": correct * rate}}, indent=2))')
    check = run.measured_check(run.content(episode), program=program)

    assessment = assess(measured_claim(episode, check), run.dir)

    assert assessment.outcome == "accepted_invalid", assessment.reasons


@pytest.mark.parametrize("output, expected", [
    ('{"a": 1}', {"a": 1}),
    ('log\n{"a": 1}\n', {"a": 1}),
    ('{"a": 1}\n{"b": 2}', {"b": 2}),
    ('{\n  "a": {\n    "b": [1, 2]\n  }\n}', {"a": {"b": [1, 2]}}),
    ('progress\n{\n  "a": 1\n}', {"a": 1}),
    ('{"a": 1}\n{\n  "b": 2\n}', {"b": 2}),
    ('{\n  "a": 1\n}\ndone', None),
    ('{"a": {"b": 1}', None),
    ('[1, 2]', None),
    ('', None),
    ('{"a": 1} trailing', None),
])
def test_captured_object_is_the_last_complete_json_object(output, expected):
    assert captured_object(output) == expected


@pytest.mark.parametrize("value", [False, True, float("nan"), -float("inf"), float("inf"), "0.5", None])
def test_invalid_deserved_score_leaves_only_the_comparison_unknown(tmp_path, value):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": 0.5})
    program = COUNT_PROGRAM.replace('{"deserved": correct * rate}', f"json.loads({json.dumps({'deserved': value})!r})")
    check = run.measured_check(run.content(episode), program=program)

    assessment = assess(measured_claim(episode, check), run.dir)

    assert (assessment.outcome, assessment.validity, assessment.discrepancy) == ("unknown", "violated", "unknown")


@pytest.mark.parametrize("computed_reward", ["10 ** 400", "-(10 ** 400)"], ids=["positive", "negative"])
def test_deserved_scores_outside_finite_float_range_stay_provisional(tmp_path, computed_reward):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": 0.5})
    program = COUNT_PROGRAM.replace('{"deserved": correct * rate}', '{"deserved": ' + computed_reward + '}')
    check = run.measured_check(run.content(episode), program=program)

    assessment = assess(measured_claim(episode, check), run.dir)

    assert assessment.outcome == "unknown"
    assert assessment.discrepancy == "unknown"
    assert assessment.missing


def test_unrelated_echo_cannot_condemn_the_actual_sorted_submission(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": SORTED, "agent/trajectory.json": trajectory(UNSORTED)})
    check = run.check(run.content(episode, "agent/trajectory.json", step=2), exit_code=1, bound={"deserved_max": 0.5})

    assert assess(claim(episode, check), run.dir).outcome == "unknown"


def test_replayed_commands_with_new_output_cannot_condemn_original_submission(tmp_path):
    run = Run(tmp_path)
    original = run.episode({"artifacts/out.txt": SORTED, "agent/trajectory.json": trajectory(SORTED)})
    replay = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": 0.0})
    check = run.check(run.content(replay), exit_code=1, bound={"deserved_max": 0.5})

    assessment = assess(claim(original, check), run.dir)

    assert assessment.outcome == "unknown"
    assert assessment.reward == 1.0


def test_equal_disclosed_marker_after_episode_return_does_not_prove_persistence(tmp_path):
    run, planting, graded, the_claim = persistence(tmp_path)
    run.lifecycle((planting, "started"), (planting, "finished"), (graded, "started"), (graded, "finished"))

    assessment = assess(the_claim, run.dir)

    assert assessment.model_dump().get("persistence") == "unknown"
    assert any("reset" in reason or "readback" in reason for reason in assessment.missing)


@pytest.mark.parametrize("reward, validity, output, outcome", [
    (1.0, "violated", UNSORTED, "accepted_invalid"),
    (1.0, "supported", SORTED, "legitimate"),
    (0.0, "supported", SORTED, "rejected_valid"),
])
def test_measured_scoring_of_the_actual_submission_supports_one_outcome(tmp_path, reward, validity, output, outcome):
    run = Run(tmp_path, grader=False)
    episode = run.episode({"artifacts/out.txt": output}, rewards={"reward": reward})
    check = run.measured_check(run.content(episode))

    assessment = assess(measured_claim(episode, check, validity=validity), run.dir)

    assert assessment.outcome == outcome, assessment.reasons
    assert assessment.reward == reward
    assert assessment.ids["trial_id"] == f"id-{episode}"
    assert assessment.claim.interpretation
    assert assessment.limits


def test_supported_scoring_mismatch_survives_provisional_persistence(tmp_path):
    run, planting, graded, the_claim = persistence(tmp_path)
    check = run.measured_check(run.content(graded))
    run.lifecycle((planting, "started"), (planting, "finished"), (graded, "started"), (graded, "finished"))

    assessment = assess(measured_claim(graded, check, planted=the_claim.planted, persisted=the_claim.persisted), run.dir)

    assert assessment.outcome == "accepted_invalid"
    assert assessment.model_dump().get("persistence") == "unknown"
    assert any("reset" in missing or "readback" in missing for missing in assessment.missing)


@pytest.mark.parametrize("observations, program, validity, expected", [
    (["deserved"], COUNT_PROGRAM, "unknown", ["names ['deserved']: keys of `results`, not `observations`"]),
    (["not_returned"], COUNT_PROGRAM, "unknown", ["names ['not_returned']: absent from both `observations` and `results`"]),
    (["submitted"], COUNT_PROGRAM.replace('"deserved": correct', '"reward": correct'), "supported", ["no finite `results.deserved`"]),
], ids=["result_as_observation", "absent_name", "omitted_deserved"])
def test_reference_defects_stay_unknown_with_their_specific_cause(tmp_path, observations, program, validity, expected):
    """A successful check stays usable evidence; a wrong section, absent name or omitted deserved score is named, never repaired.
    A missing deserved score leaves the score comparison unknown, not the measured validity."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": SORTED})
    assert assess(measured_claim(episode, run.measured_check(run.content(episode)), validity="supported"), run.dir).outcome == "legitimate"
    check = run.measured_check(run.content(episode), program=program)
    defective = measured_claim(episode, check, validity="supported")
    defective.derivation.observations = observations

    assessment = assess(defective, run.dir)

    assert assessment.check.exit_code == 0
    assert (assessment.outcome, assessment.validity, assessment.discrepancy) == ("unknown", validity, "unknown")
    reasons = " ".join(assessment.reasons)
    assert all(item in reasons for item in expected), reasons
    assert defective.derivation.observations == observations


FACT_PROGRAM = '''import hashlib, json, pathlib, sys
raw = {name: pathlib.Path(name).read_bytes() for name in sys.argv[1:]}
submitted = [int(n) for n in raw["submission.txt"].split()]
print(json.dumps({"input_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()},
                  "observations": {"ascending": submitted == sorted(submitted), "note": "looks complete"},
                  "results": {}}))
'''
FOUR = Observation(episode=None, path="instruction.md", excerpt="Write the four input numbers to /app/out.txt")


def test_measured_boolean_observation_resolves_validity_while_the_score_stays_unknown(tmp_path):
    """A measured Boolean is a fact like a number. Copied text is not, whatever validity is asserted."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    check = run.measured_check(run.content(episode), program=FACT_PROGRAM)

    assessment = assess(claim(episode, check, derivation=dict(observations=["ascending"], validity="violated")), run.dir)

    assert (assessment.outcome, assessment.validity, assessment.discrepancy) == ("unknown", "violated", "unknown")
    assert any("results.deserved" in reason for reason in assessment.reasons)
    asserted = assess(claim(episode, check, derivation=dict(observations=["note"], validity="supported")), run.dir)
    assert (asserted.outcome, asserted.validity) == ("unknown", "unknown")
    assert any("measured" in reason for reason in asserted.reasons)


@pytest.mark.parametrize("missing", ["reward", "scoring"])
def test_missing_reward_or_scoring_keeps_independently_measured_validity(tmp_path, missing):
    run = Run(tmp_path)
    timeout = dict(rewards={}, verifier_timeout=True, errors=[ErrorRecord(type="VerifierTimeoutError", message="")])
    episode = run.episode({"artifacts/out.txt": UNSORTED}, **(timeout if missing == "reward" else {}))
    check = run.measured_check(run.content(episode))
    if missing == "scoring":
        run.record.checks[-1].scoring = None
        run.save()

    assessment = assess(measured_claim(episode, check), run.dir)

    assert (assessment.validity, assessment.discrepancy) == ("violated", "unknown")
    if missing == "reward":
        assert (assessment.outcome, assessment.reward) == ("unavailable", None)
        assert "VerifierTimeoutError" in assessment.reasons[0]
    else:
        assert assessment.outcome == "unknown" and any("scoring input" in reason for reason in assessment.reasons)


def test_one_check_keeps_independent_requirement_conclusions(tmp_path):
    """One execution supports one requirement and violates another; each reading is verified alone."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED}, rewards={"reward": 0.5})
    check = run.measured_check(run.content(episode))
    invented = Observation(episode=None, path="instruction.md", excerpt="in any order")

    def reading(requirement, observations, validity, interpretation="All four numbers are written."):
        return dict(requirement=requirement.model_dump(), observations=observations, validity=validity, interpretation=interpretation)

    the_claim = measured_claim(episode, check)
    the_claim.derivation = Derivation.model_validate({**the_claim.derivation.model_dump(), "requirements": [
        reading(FOUR, ["submitted"], "supported"), reading(invented, ["submitted"], "supported"),
        reading(GRADER_ASSERTION, ["submitted"], "violated"), reading(FOUR, ["deserved"], "violated"),
        reading(FOUR, ["submitted"], "violated", interpretation=" "),
    ]})

    assessment = assess(the_claim, run.dir)

    assert (assessment.outcome, assessment.validity) == ("unknown", "violated")
    assert conclusions(assessment) == [(REQUIREMENT, "violated"), (FOUR, "supported"), (invented, "unknown"),
                                       (GRADER_ASSERTION, "unknown"), (FOUR, "unknown"), (FOUR, "unknown")]
    reasons = [" ".join(item.reasons) for item in assessment.conclusions]
    assert reasons[0] == "" and "does not contain" in reasons[1] and "not among the check's inputs" in reasons[2]
    assert "keys of `results`" in reasons[3] and "interpretation" in reasons[4]


@pytest.mark.parametrize("change", ["failed copy", "other episode", "other ids", "forged receipt", "no sandbox", "other image"])
def test_a_check_not_bound_to_a_good_copy_of_its_episode_stays_provisional(tmp_path, change):
    """A copy that failed, names another episode or other IDs, a receipt that differs from the
    retained one, or a check not run in a sandbox started from the copy, links nothing."""
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    other = run.episode({"artifacts/out.txt": SORTED})
    copy_fields = {"failed copy": {"error": "RuntimeError: docker commit failed"},
                   "other episode": {"episode": other}, "other ids": {"ids": {"trial_id": "id-other"}}}.get(change)
    check = run.measured_check(run.content(episode), copy_fields=copy_fields)
    if change == "forged receipt":
        receipt = run.record.copies[-1].receipt
        (run.dir / "episodes" / episode / receipt.path).write_text("{}")
    elif change == "no sandbox":
        run.record.checks[-1].sandbox = None
    elif change == "other image":
        run.record.copies[-1].image = "sha256:" + "f" * 64
    run.save()

    assessment = assess(measured_claim(episode, check), run.dir)

    assert assessment.outcome in ("unknown", "ungrounded") and assessment.validity == "unknown", change
    assert assessment.reasons


def test_a_bound_copy_check_reports_the_copy_limits(tmp_path):
    run = Run(tmp_path)
    episode = run.episode({"artifacts/out.txt": UNSORTED})
    check = run.measured_check(run.content(episode))

    assessment = assess(measured_claim(episode, check), run.dir)

    assert assessment.outcome == "accepted_invalid", assessment.reasons
    assert "the check ran with the episode's own interpreter, so code the episode planted could change its output" in assessment.limits
    assert "the copy omits /logs; nothing under them was checked" in assessment.limits
    assert "processes were paused for 1.0 s before grading" in assessment.limits


@pytest.mark.parametrize("text, excerpt, found", [
    ("Write the answer\n    to /app/answer.txt.", "Write the answer to /app/answer.txt.", True),
    ("Write the answer to\t/app/answer.txt.", "Write  the answer\nto /app/answer.txt.", True),
    ('{"output": "two\\n  lines"}', "two lines", True),
    ("Write the answer", "Writethe answer", False),
    ("prefix \\nready", "\nready", False),
], ids=["line break", "spaces and tab", "json string", "missing space", "literal escape"])
def test_an_excerpt_matches_its_source_whatever_its_whitespace(text, excerpt, found):
    """Retyped text often differs from its source in line breaks and indentation only; a missing space still differs."""
    assert contains(text, excerpt) is found
