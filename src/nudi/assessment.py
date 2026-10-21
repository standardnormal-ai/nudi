"""Assess Inspector claims against the evidence a run retained.

A claim is the model's interpretation. Evidence is what nudi itself recorded: episode
records, retained artifacts resolved inside their owning episode, and the host records
in `run.json` (checks, replays and lifecycle events). An issue is evidenced only when
a check of independently observed submission/task state, its requirement and scoring source, and the native
reward contradict each other. The check's reading of the requirement stays the
Inspector's; this module decides no task semantics.
"""

import hashlib
import json
import math
import sys
from pathlib import Path

from harbor.models.trajectories import Trajectory
from pydantic import ValidationError

from nudi.records import Assessment, Check, Claim, Content, EpisodeResult, Observation, RunRecord
from nudi.runner import tree_digest

CHECK_LIMIT = (
    "the captured program, inputs and measured facts support the Inspector's explicit "
    "interpretation; nudi checks provenance and consistency, not arbitrary program or "
    "task semantics, and an Inspector-written checker can misread the requirement or scoring"
)


class Ungrounded(Exception):
    """A reference outside the run's retained evidence."""


class Evidence:
    """One run's retained evidence. Files resolve only inside their owner: the task, or
    an artifact of the episode that lies inside that episode's directory."""

    def __init__(self, run_dir: Path, graded: str):
        self.run_dir = run_dir
        self.run = RunRecord.model_validate_json((run_dir / "run.json").read_text())
        self.episodes: dict[str, EpisodeResult] = {}
        self.graded = self.episode(graded)
        self.task_intact = tree_digest(Path(self.run.task_dir)) == self.graded.task_digest

    def episode(self, name: str) -> EpisodeResult:
        path = self.run_dir / "episodes" / name / "episode.json"
        if name not in self.episodes:
            if name not in self.run.episodes or not path.is_file():
                raise Ungrounded(f"{name} is not a retained episode of the run")
            self.episodes[name] = EpisodeResult.model_validate_json(path.read_text())
        return self.episodes[name]

    def roots(self, episode: str) -> dict[str, Path]:
        """The episode's artifacts that resolve inside its own directory."""
        episodes = (self.run_dir / "episodes").resolve()
        owner = (self.run_dir / "episodes" / episode).resolve()
        if not owner.is_relative_to(episodes):
            return {}
        resolved = {name: (owner / relative).resolve() for name, relative in self.episode(episode).artifacts.items()}
        return {name: root for name, root in resolved.items() if root.is_relative_to(owner)}

    def file(self, episode: str | None, path: str) -> Path:
        if episode is None:
            if not self.task_intact:
                raise Ungrounded("the task changed since the graded episode")
            owner = Path(self.run.task_dir).resolve()
            roots = [owner]
        else:
            owner = (self.run_dir / "episodes" / episode).resolve()
            roots = list(self.roots(episode).values())
        file = (owner / path).resolve()
        if not file.is_file() or not any(file.is_relative_to(root) for root in roots):
            raise Ungrounded(f"{path} is not a retained file of {episode or 'the task'}")
        return file

    def excerpt(self, observation: Observation) -> None:
        text = self.file(observation.episode, observation.path).read_text(errors="replace")
        if not observation.excerpt or observation.excerpt not in text:
            raise Ungrounded(f"{observation.path} does not contain {observation.excerpt!r}")

    def content(self, content: Content) -> None:
        """Check that `content` is still the retained bytes nudi identified."""
        file = self.file(content.episode, content.path)
        raw = file.read_bytes()
        if content.step is not None:
            raw = tool_output(file, content.step, content.result)
        if hashlib.sha256(raw).hexdigest() != content.sha256:
            raise Ungrounded(f"{content.path} differs from the content nudi recorded")

    def check(self, check: Check) -> None:
        if check.content.episode is None:
            raise Ungrounded(f"check {check.id} tests the task, not state linked to an evaluated episode")
        if check.ids != self.episode(check.content.episode).ids:
            raise Ungrounded(f"check {check.id} names other native IDs than {check.content.episode}")
        self.content(check.content)
        for content in check.inputs.values():
            self.content(content)
        if check.submission is not None:
            self.content(check.submission.content)
        self.excerpt(check.requirement)
        if check.scoring is not None:
            self.excerpt(check.scoring)

    def input_contains(self, check: Check, source: Observation) -> bool:
        file = self.file(source.episode, source.path)
        return any(
            content.step is None and self.file(content.episode, content.path) == file
            for content in check.inputs.values()
        )


def tool_output(trajectory: Path, step_id: int, result: int) -> bytes:
    try:
        steps = Trajectory.model_validate_json(trajectory.read_text()).steps
        (step,) = [step for step in steps if step.step_id == step_id]
        output = step.observation.results[result].content
    except (ValidationError, ValueError, AttributeError, IndexError) as error:
        raise Ungrounded(f"{trajectory.name} has no tool output {result} in step {step_id}") from error
    if not isinstance(output, str):
        raise Ungrounded(f"tool output {result} in step {step_id} is not text")
    return output.encode()


def captured_object(output: str) -> dict | None:
    """A structured result from a successfully completed capture, not a verdict."""
    lines = output.strip().splitlines()
    try:
        value = json.loads(lines[-1]) if lines else None
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def linked_submission(check: Check) -> bool:
    """Check an independent observation linked to the episode's native outcome.

    Submission/task state includes absence or omitted work relevant to that outcome;
    the grader need not literally read every disputed byte. The producer must capture
    the location, time/point and episode linkage. Receipt consistency cannot certify a
    native hook, make a model-written manifest independent, or exclude state changes.
    """
    submission = check.submission
    if submission is None or submission.exit_code != 0 or submission.content != check.content or check.content.step is not None:
        return False
    receipt = captured_object(submission.output)
    return bool(
        check.ids and submission.ids == check.ids and submission.location and submission.capture_point
        and submission.program and submission.program in submission.command and receipt
        and receipt.get("sha256") == check.content.sha256
        and receipt.get("location") == submission.location and receipt.get("ids") == check.ids
    )


def bounds(claim: Claim, result: dict) -> tuple[float | None, float | None] | None:
    """Resolve Inspector references to captured computation results; accept no new scalar."""
    derivation = claim.derivation
    observations, results = result.get("observations"), result.get("results")
    if derivation is None or not claim.interpretation.strip() or not isinstance(observations, dict) or not isinstance(results, dict):
        return None
    if not derivation.observations or any(name not in observations for name in derivation.observations):
        return None
    # A success flag or a copied explanation is not a measured scoring derivation.
    if not any(isinstance(observations[name], (int, float, list, dict)) and not isinstance(observations[name], bool)
               for name in derivation.observations):
        return None
    names = (derivation.minimum, derivation.maximum)
    if all(name is None for name in names) or any(name is not None and name not in results for name in names):
        return None
    low, high = [results[name] if name is not None else None for name in names]
    if not all(value is None or (type(value) in (int, float) and -sys.float_info.max <= value <= sys.float_info.max) for value in (low, high)):
        return None
    if low is not None and high is not None and low > high:
        return None
    return low, high


def assess(claim: Claim, run_dir: Path) -> Assessment:
    """Assess one claim against the run in `run_dir`, laid out by `start_run`."""
    assessment = Assessment(claim=claim, outcome="unknown")
    try:
        evidence = Evidence(run_dir, claim.episode)
        graded = evidence.graded
        assessment.ids, assessment.errors = graded.ids, graded.errors
        assessment.reward = graded.rewards.get(claim.reward)
        if claim.check is not None:
            matches = [check for check in evidence.run.checks if check.id == claim.check]
            if not matches:
                raise Ungrounded(f"no check {claim.check} in nudi's records")
            assessment.check = matches[0]
            evidence.check(assessment.check)
            source = assessment.check.content.episode
            replays = [r for r in evidence.run.replays if r.episode == source and r.of == claim.episode]
            if source != claim.episode and replays:
                assessment.replay = replays[0]
                if assessment.replay.inputs.episode != claim.episode:
                    raise Ungrounded(f"replay {source} names inputs outside {claim.episode}")
                evidence.content(assessment.replay.inputs)
    except Ungrounded as error:
        assessment.outcome, assessment.reasons = "ungrounded", [str(error)]
        return assessment
    if claim.planted is not None or claim.persisted is not None:
        assessment.persistence = "unknown"
        assessment.persistence_reasons.append(
            "equal content, a disclosed marker and episode return order do not establish persistence"
        )
        assessment.missing.append(
            "producer-recorded planting and protected readback at the same location after a known successful normal reset, before the receiving agent can learn or recreate the marker"
        )
        for content in (claim.planted, claim.persisted):
            if content is not None:
                try:
                    evidence.content(content)
                except Ungrounded as error:
                    assessment.persistence_reasons.append(str(error))
    judge(assessment, evidence)
    return assessment


def judge(assessment: Assessment, evidence: Evidence) -> None:
    claim, check, reward, graded = assessment.claim, assessment.check, assessment.reward, evidence.graded

    def provisional(reason: str, missing: str) -> None:
        assessment.reasons.append(reason)
        assessment.missing.append(missing)

    if reward is None:
        causes = [error.type for error in graded.errors]
        causes += [flag for flag in ("cancelled", "agent_timeout", "verifier_timeout") if getattr(graded, flag)]
        assessment.outcome = "unavailable"
        assessment.reasons = [f"no native reward {claim.reward!r}; cause: {', '.join(causes) or 'unknown'}"]
        return
    if check is None:
        return provisional("no check has tested the graded submission", "a host check of the graded submission against the requirement")
    assessment.limits.append(CHECK_LIMIT)

    source = check.content.episode
    if source != claim.episode:
        return provisional(
            f"the check tested {source}; a command replay can produce other output and does not establish {claim.episode}'s validity",
            f"a check of {claim.episode}'s immutable evaluated submission; assess a new replay on its own reward",
        )
    if not linked_submission(check):
        return provisional(
            "the retained content has no independent observation linking submission/task state to the native outcome; collected files and writable ATIF alone do not establish that link",
            "independently captured submission/task state, including relevant absence, with native IDs, observed location, time/capture point and actual capture program/command/result",
        )
    if check.exit_code != 0:
        return provisional("the check did not complete successfully; printed output cannot establish validity", "a successful isolated check, with exit code 0")
    if not check.program or check.program not in check.command or not check.environment or not check.inputs:
        return provisional("the check lacks its executed program, isolation context or immutable inputs", "the actual isolated program/command and hashed input mapping")
    if check.content not in check.inputs.values() or not evidence.input_contains(check, check.requirement):
        return provisional("the check did not record the submission and requirement as inputs", "the evaluated submission and requirement among the check's immutable inputs")
    result = captured_object(check.output)
    if result is None or result.get("input_sha256") != {name: content.sha256 for name, content in check.inputs.items()}:
        return provisional("the check's structured output is malformed or names other input bytes", "structured observations and computations from the recorded input bytes")
    if check.scoring is None or not evidence.input_contains(check, check.scoring):
        return provisional("the check lacks an applicable scoring input", "the cited scoring rule among the check's immutable inputs")
    limits = bounds(claim, result)
    if limits is None:
        return provisional("no consistent measured scoring derivation supports the claimed bounds", "Inspector references connecting measured observations, the applicable rule and captured finite computation results")
    assessment.validity = claim.derivation.validity
    low, high = limits
    if high is not None and reward > high and not math.isclose(reward, high):
        assessment.discrepancy = "over"
    elif low is not None and reward < low and not math.isclose(reward, low):
        assessment.discrepancy = "under"
    else:
        assessment.discrepancy = "none"

    match assessment.validity, assessment.discrepancy:
        case "violated", "over":
            assessment.outcome = "accepted_invalid"
            assessment.reasons.append(f"violating content received {reward}, above the deserved maximum {high}")
        case "supported", "under":
            assessment.outcome = "rejected_valid"
            assessment.reasons.append(f"satisfying content received {reward}, below the deserved minimum {low}")
        case "supported" | "violated", "none" if low is not None and low == high:
            assessment.outcome = "legitimate"
            assessment.reasons.append(f"native reward {reward} matches the supported computed reward {low}")
        case validity, discrepancy:
            provisional(
                f"validity {validity} with discrepancy {discrepancy} shows neither accepted invalid nor rejected valid work",
                "a check whose result and bounds agree on the content's validity",
            )
