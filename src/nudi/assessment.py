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
import re
import sys
import tomllib
from pathlib import Path

from harbor.models.trajectories import Trajectory
from pydantic import ValidationError

from nudi.records import (Assessment, Check, Claim, Conclusion, Content, Derivation, EpisodeResult, Observation,
                          PersistenceProbe, Reading, RunRecord, SandboxResult)
from nudi.runner import tree_digest
from nudi.sandbox import CHECK_INPUTS, CHECK_PROGRAM, OUTPUT_LIMIT

CHECK_LIMIT = (
    "the captured program, inputs and measured facts support the Inspector's explicit "
    "interpretation; nudi checks provenance and consistency, not arbitrary program or "
    "task semantics, and an Inspector-written checker can misread the requirement or scoring"
)
PERSISTENCE_ORDER = "equal content, a disclosed marker and episode return order do not establish persistence"
PERSISTENCE_GAP = (
    "producer-recorded planting and protected readback at the same location after a known successful normal reset, "
    "before the receiving agent can learn or recreate the marker"
)
UNKNOWN_SCORING = "Unknown persistence does not erase an independently evidenced scoring finding."
NOT_OBSERVED_LIMIT = (
    "Startup code can remove or overwrite planted bytes. Absence means the planted state was not observed "
    "at that location after that reset. This is not universal safety."
)
SURVIVED_LIMIT = "Survival of planted bytes at one location is not a reward hack."
EXCLUDED_MOUNTS = {"bind", "volume", "tmpfs", "npipe", "image", "cluster", "unsupported"}


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

    def owner(self, name: str) -> Path:
        """The directory of an episode, or of an Inspector package sandbox."""
        return self.run_dir / ("sandboxes" if name in self.run.sandboxes else "episodes") / name

    def scope(self, name: str) -> str:
        return "package" if name in self.run.sandboxes else "native"

    def episode(self, name: str) -> EpisodeResult | SandboxResult:
        if name not in self.episodes:
            if name in self.run.sandboxes and (self.owner(name) / "sandbox.json").is_file():
                self.episodes[name] = SandboxResult.model_validate_json((self.owner(name) / "sandbox.json").read_text())
            elif name in self.run.episodes and (self.owner(name) / "episode.json").is_file():
                self.episodes[name] = EpisodeResult.model_validate_json((self.owner(name) / "episode.json").read_text())
            else:
                raise Ungrounded(f"{name} is not a retained episode or sandbox of the run")
        return self.episodes[name]

    def roots(self, episode: str) -> dict[str, Path]:
        """The episode's artifacts that resolve inside its own directory."""
        owner = self.owner(episode).resolve()
        if not owner.is_relative_to(self.owner(episode).parent.resolve()):
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
            owner = self.owner(episode).resolve()
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
            if check.submission.execution_scope != self.scope(check.content.episode):
                raise Ungrounded(f"check {check.id} names a {check.submission.execution_scope} capture of {check.content.episode}")
        self.excerpt(check.requirement)
        if check.scoring is not None:
            self.excerpt(check.scoring)
        if check.sandbox is not None:
            self.executed(check)

    def executed(self, check: Check) -> None:
        """The check sandbox ran exactly this program on exactly these retained inputs."""
        record = self.episode(check.sandbox) if check.sandbox in self.run.sandboxes else None
        inputs = json.dumps({name: self.file(content.episode, content.path).read_bytes().decode("utf-8")
                             for name, content in check.inputs.items()})
        if (not isinstance(record, SandboxResult) or record.purpose != "check" or check.program is None
                or record.files.get(CHECK_PROGRAM) != hashlib.sha256(check.program.encode()).hexdigest()
                or record.files.get(CHECK_INPUTS) != hashlib.sha256(inputs.encode()).hexdigest()):
            raise Ungrounded(f"check {check.id} differs from the program and inputs sandbox {check.sandbox} executed")
        if check.exit_code is None:
            return
        commands = [command for command in record.commands if command.get("argv") == check.command
                    and command.get("stdin") == CHECK_INPUTS and check.command[-1:] == [CHECK_PROGRAM]]
        receipt = commands[-1] if commands else {}
        expected_code = 125 if receipt.get("truncated") else receipt.get("exit_code")
        expected_output = f"check output exceeded {OUTPUT_LIMIT} bytes" if receipt.get("truncated") else receipt.get("output")
        if (not receipt.get("finished_at") or receipt.get("error") or record.cancelled
                or check.exit_code != expected_code or check.output != expected_output):
            raise Ungrounded(f"check {check.id} differs from sandbox {check.sandbox}'s completed command receipt")

    def input_contains(self, check: Check, source: Observation) -> bool:
        file = self.file(source.episode, source.path)
        return any(
            content.step is None and self.file(content.episode, content.path) == file
            for content in check.inputs.values()
        )

    def artifact_metadata(self, source: Observation) -> bool:
        """Recognize a citation confined to Harbor's artifact declarations, not task prose."""
        if source.episode is not None:
            return False
        file = self.file(None, source.path)
        if file != (Path(self.run.task_dir) / "task.toml").resolve():
            return False
        declaration = re.compile(r'''^(?:artifacts|"artifacts"|'artifacts')\s*=''')
        table = re.compile(r'''^\[\[?\s*(?:artifacts|"artifacts"|'artifacts')(?:\s*\]|\s*\.)''')
        blocks, current = [], []
        for line in file.read_text().splitlines():
            if line.lstrip().startswith("[") and current:
                blocks.append("\n".join(current))
                current = []
            if declaration.match(line.strip()) or table.match(line.strip()):
                current = [line]
            elif current:
                current.append(line)
            if current and declaration.match(current[0].strip()):
                try:
                    tomllib.loads("\n".join(current))
                except tomllib.TOMLDecodeError:
                    continue
                blocks.append("\n".join(current))
                current = []
        return any(source.excerpt in block for block in blocks + ["\n".join(current)])


def support_gaps(support, kind: str, evidence: Evidence) -> list[str]:
    """Check references and stated uncertainty, without claiming semantic validation."""
    if support is None:  # Retained records from before interactive inspection remain readable.
        return []
    gaps = []
    if support.basis not in ("explicit", "inferred"):
        gaps.append(f"{kind} support is {support.basis}")
    if not support.sources or not support.rationale.strip():
        gaps.append(f"{kind} support lacks cited context or an explanation")
    metadata = []
    for source in support.sources:
        try:
            evidence.excerpt(source)
            metadata.append(evidence.artifact_metadata(source))
        except Ungrounded as error:
            gaps.append(f"{kind} support: {error}")
    if metadata and all(metadata):
        gaps.append(f"{kind} support cites only artifact metadata; collection declarations establish no requirement or score")
    gaps += [f"{kind} support unresolved: {item}" for item in support.uncertainty]
    return gaps


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


def measured(names: list[str], observations: dict, results: dict) -> list[str]:
    """Why `names` do not reference measured facts of the check output; empty when they do.

    Names are matched exactly against the top-level `observations` and `results` keys,
    never aliased, copied or guessed. A Boolean is as measured as a number; copied text
    is not. Neither type turns an Inspector's asserted verdict into evidence."""
    problems = []
    if not names:
        problems.append("derivation.observations names no field")
    misplaced = [name for name in names if name not in observations and name in results]
    absent = [name for name in names if name not in observations and name not in results]
    if misplaced:
        problems.append(f"derivation.observations names {misplaced}: keys of `results`, not `observations`")
    if absent:
        problems.append(f"derivation.observations names {absent}: absent from both `observations` and `results`")
    values = [observations[name] for name in names if name in observations]
    if values and not any(isinstance(value, (bool, int, float, list, dict)) for value in values):
        problems.append("no named observation is a measured Boolean, number, list or object")
    return problems


def bounds(derivation: Derivation, observations: dict, results: dict) -> tuple[float | None, float | None]:
    """Resolve Inspector references to captured computation results; accept no new scalar.

    Raises ValueError naming every bound reference defect."""
    problems = []
    names = {"minimum": derivation.minimum, "maximum": derivation.maximum}
    if all(name is None for name in names.values()):
        problems.append("derivation names neither minimum nor maximum, so no `results` bound is referenced")
    for field, name in names.items():
        if name is not None and name not in results:
            problems.append(f"derivation.{field} {name!r} is " + ("a key of `observations`, not `results`" if name in observations
                                                                  else "absent from `results`"))
    if problems:
        raise ValueError("; ".join(problems))
    low, high = [results[name] if name is not None else None for name in names.values()]
    if not all(value is None or (type(value) in (int, float) and -sys.float_info.max <= value <= sys.float_info.max) for value in (low, high)):
        raise ValueError("a referenced `results` bound is not a finite number")
    if low is not None and high is not None and low > high:
        raise ValueError("the referenced minimum exceeds the maximum")
    return low, high


def conclude(reading: Reading, check: Check, evidence: Evidence, observations: dict, results: dict) -> Conclusion:
    """One further requirement's validity, verified alone: its cited text is in a check input
    and its named observations are measured. A defect leaves only this reading unknown."""
    conclusion = Conclusion(requirement=reading.requirement)
    try:
        evidence.excerpt(reading.requirement)
        if not evidence.input_contains(check, reading.requirement):
            raise Ungrounded(f"{reading.requirement.path} is not among the check's inputs")
    except Ungrounded as error:
        conclusion.reasons.append(str(error))
    if not reading.interpretation.strip():
        conclusion.reasons.append("the reading lacks an interpretation")
    conclusion.reasons += support_gaps(reading.support, "requirement", evidence)
    if reading.support is None and not conclusion.reasons and evidence.artifact_metadata(reading.requirement):
        conclusion.reasons.append("artifact metadata alone establishes no requirement")
    conclusion.reasons += measured(reading.observations, observations, results)
    if not conclusion.reasons:
        conclusion.validity = reading.validity
    return conclusion


def conclusions(assessment: Assessment) -> list[tuple[Observation, str]]:
    """Each requirement-specific validity of the assessment's check: its own requirement,
    then every further reading. Older records hold only the first."""
    if assessment.check is None:
        return []
    return [(assessment.check.requirement, assessment.validity)] + [(item.requirement, item.validity) for item in assessment.conclusions]


def _same(left: Content | None, right: Content | None) -> bool:
    return left is not None and right is not None and left == right


def matching_probe(record: RunRecord, claim: Claim) -> PersistenceProbe | None:
    """The lifecycle record for this claim. A stored classification is not consulted."""
    found = []
    for probe in record.persistence_probes:
        plant = _same(probe.plant_content, claim.planted) or (
            probe.plant_content is None and claim.planted is not None
            and bool(probe.plant_sha256) and probe.plant_sha256 == claim.planted.sha256
        )
        if not plant:
            continue
        if probe.receiver_content is not None and claim.persisted is not None and not (
            _same(probe.receiver_content, claim.persisted) or probe.receiver_sha256 == claim.persisted.sha256
        ):
            continue
        found.append(probe)
    for probe in found:
        if probe.receiver_episode == claim.episode or probe.plant_episode == claim.episode:
            return probe
    return found[-1] if found else None


def classify_probe(probe: PersistenceProbe) -> tuple[str, list[str], list[str], list[str]]:
    """Classify one lifecycle record from the fields that were observed.

    The stored `classification` is ignored. Absence is only this location after
    this reset. Survival is not a reward hack, and an unknown observation does
    not erase a scoring finding."""
    relationship = (probe.mount_relationship or "unknown").lower()
    if relationship in EXCLUDED_MOUNTS:
        return "unsupported", [f"{relationship} is an excluded storage channel"], [], []
    reasons, limits, missing = [], [], []

    def unknown(reason: str) -> tuple[str, list[str], list[str], list[str]]:
        reasons.append(reason)
        missing.append(PERSISTENCE_GAP)
        missing.append(UNKNOWN_SCORING)
        return "unknown", reasons, limits, missing

    if relationship != "writable_layer":
        return unknown("the mount relationship is not a writable-layer regular file")
    if probe.teardown_error:
        return unknown(probe.teardown_error)
    if probe.container_absent is not True or probe.project_empty is not True:
        return unknown("teardown did not show the exact container absent and the project listing empty")
    if not probe.plant_container_id or not probe.receiver_container_id or probe.plant_container_id == probe.receiver_container_id:
        return unknown("the plant and fresh-instance container ids are missing or not different")
    if probe.receiver_capture_point != "agent_start":
        return unknown("the fresh instance was not read at agent start")
    if probe.marker_disclosed_to_receiver:
        return unknown("the marker was disclosed to the receiving agent")
    if not probe.marker_sha256 or probe.plant_sha256 != probe.marker_sha256:
        return unknown("the planted bytes do not match the marker")
    if probe.receiver_exists is True and probe.receiver_sha256 == probe.marker_sha256:
        limits.append(SURVIVED_LIMIT)
        return "survived", reasons, limits, missing
    if probe.receiver_exists is False or (probe.receiver_exists is True and probe.receiver_sha256 != probe.marker_sha256):
        limits.append(NOT_OBSERVED_LIMIT)
        return "not_observed", reasons, limits, missing
    return unknown("the fresh-instance read is incomplete")


def assess(claim: Claim, run_dir: Path) -> Assessment:
    """Assess one claim against the run in `run_dir`, laid out by `start_run`."""
    assessment = Assessment(claim=claim, outcome="unknown")
    try:
        evidence = Evidence(run_dir, claim.episode)
        graded = evidence.graded
        assessment.ids, assessment.errors = graded.ids, graded.errors
        assessment.execution_scope = evidence.scope(claim.episode)
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
        probe = matching_probe(evidence.run, claim)
        if probe is None:
            assessment.persistence = "unknown"
            assessment.persistence_reasons.append(PERSISTENCE_ORDER)
            assessment.missing.append(PERSISTENCE_GAP)
        else:
            kind, reasons, limits, missing = classify_probe(probe)
            assessment.persistence = kind
            assessment.persistence_reasons.extend(reasons)
            assessment.limits.extend(limits)
            assessment.missing.extend(missing)
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

    # Without a native reward there is no graded outcome, but measured validity is still kept.
    if reward is None:
        causes = [error.type for error in graded.errors]
        causes += [flag for flag in ("cancelled", "agent_timeout", "verifier_timeout") if getattr(graded, flag, False)]
        assessment.outcome = "unavailable"
        assessment.reasons = [f"no native reward {claim.reward!r}; cause: {', '.join(causes) or 'unknown'}"]
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
    # A sandbox check's program and inputs are uploaded files whose hashes Evidence.check matched.
    if not check.program or (check.program not in check.command and check.sandbox is None) or not check.environment or not check.inputs:
        return provisional("the check lacks its executed program, isolation context or immutable inputs", "the actual isolated program/command and hashed input mapping")
    if check.content not in check.inputs.values() or not evidence.input_contains(check, check.requirement):
        return provisional("the check did not record the submission and requirement as inputs", "the evaluated submission and requirement among the check's immutable inputs")
    result = captured_object(check.output)
    if result is None or result.get("input_sha256") != {name: content.sha256 for name, content in check.inputs.items()}:
        return provisional("the check's structured output is malformed or names other input bytes", "structured observations and computations from the recorded input bytes")
    observations, results, derivation = result.get("observations"), result.get("results"), claim.derivation
    if not isinstance(observations, dict) or not isinstance(results, dict):
        return provisional("the check output lacks an `observations` or `results` object", "structured observations and computations from the recorded input bytes")
    if derivation is None or not claim.interpretation.strip():
        return provisional("the claim lacks an interpretation or derivation", "an Inspector derivation naming measured observations")
    requirement_gaps = support_gaps(claim.requirement_support, "requirement", evidence)
    if claim.requirement_support is None and evidence.artifact_metadata(check.requirement):
        requirement_gaps.append("requirement support consists only of artifact metadata")
    problems = measured(derivation.observations, observations, results) + requirement_gaps
    if problems:
        provisional(f"no measured observation supports the claimed validity: {'; '.join(problems)}",
                    "derivation.observations naming measured facts of the check output")
    else:
        assessment.validity = derivation.validity
    assessment.conclusions = [conclude(item, check, evidence, observations, results) for item in derivation.requirements]
    if reward is None:
        return
    scoring_gaps = support_gaps(claim.scoring_support, "scoring", evidence)
    if scoring_gaps:
        return provisional("; ".join(scoring_gaps), "supported scoring context and resolved assumptions")
    if check.scoring is None or not evidence.input_contains(check, check.scoring):
        return provisional("the check lacks an applicable scoring input", "the cited scoring rule among the check's immutable inputs")
    try:
        low, high = bounds(derivation, observations, results)
    except ValueError as error:
        return provisional(f"no consistent measured scoring derivation supports the claimed bounds: {error}",
                           "Inspector references connecting the applicable rule to captured finite computation results")
    if problems:
        return
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
