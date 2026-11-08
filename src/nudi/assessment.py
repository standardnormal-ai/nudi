"""Assess Inspector claims against the evidence a run retained.

A claim is the model's interpretation. Evidence is what nudi itself recorded: episode
records, retained artifacts resolved inside their owning episode, and the host records
in `run.json` (checks and lifecycle events). An issue is evidenced only when
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

from nudi.episode import tree_digest
from nudi.inspector_sandbox import CHECK_INPUTS, CHECK_PROGRAM, OUTPUT_LIMIT
from nudi.records import (Assessment, Check, Claim, Conclusion, Content, EpisodeResult, Observation,
                          PersistenceProbe, Reading, RunRecord, SandboxResult, StateCopy)

CHECK_LIMIT = (
    "the captured program, inputs and measured facts support the Inspector's explicit "
    "interpretation; nudi checks provenance and consistency, not arbitrary program or "
    "task semantics, and an Inspector-written checker can misread the requirement or scoring"
)
COPY_INTERPRETER = "the check ran with the episode's own interpreter, so code the episode planted could change its output"
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
            sandbox = name in self.run.sandboxes
            record = self.owner(name) / ("sandbox.json" if sandbox else "episode.json")
            if not (sandbox or name in self.run.episodes) or not record.is_file():
                raise Ungrounded(f"{name} is not a retained episode or sandbox of the run")
            # Like its other files, the record must lie inside its own directory.
            if not record.resolve().is_relative_to(self.owner(name).resolve()):
                raise Ungrounded(f"{name}'s {record.name} links outside its directory")
            self.episodes[name] = (SandboxResult if sandbox else EpisodeResult).model_validate_json(record.read_text())
        return self.episodes[name]

    def roots(self, episode: str) -> dict[str, Path]:
        """The episode's artifacts that resolve inside its own directory."""
        owner = self.owner(episode).resolve()
        if not owner.is_relative_to(self.owner(episode).parent.resolve()):
            return {}
        resolved = {name: (owner / relative).resolve() for name, relative in self.episode(episode).artifacts.items()}
        return {name: root for name, root in resolved.items() if root.is_relative_to(owner)}

    def files(self, episode: str) -> dict[str, Path]:
        """The episode's retained files by their paths in its directory, and its record. A file is given only when it
        resolves inside a declared artifact, as `file` requires of a citation, and a linked file keeps its declared
        name. A folder link is not followed: a file inside a declared artifact is given at its own path anyway, one
        outside could not be cited, and a link loop cannot recurse."""
        home, roots = self.owner(episode), self.roots(episode)
        found = {}
        for name in roots:
            declared = home / self.episode(episode).artifacts[name]
            for source in [declared] if declared.is_file() else sorted(declared.rglob("*")):
                if source.is_file() and any(source.resolve().is_relative_to(root) for root in roots.values()):
                    found[str(source.relative_to(home))] = source
        found["episode.json"] = home / "episode.json"
        return found

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
        if not observation.excerpt or not contains(text, observation.excerpt):
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
        copy = self.copy(check)
        if check.state_copy is not None and (copy is None or record.state_copy != copy.id or record.image != copy.image):
            raise Ungrounded(f"check {check.id}'s sandbox {check.sandbox} did not start from {check.state_copy}'s image")
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

    def copy(self, check: Check) -> StateCopy | None:
        return next((copy for copy in self.run.copies if copy.id == check.state_copy), None)

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
        return any(contains(block, source.excerpt) for block in blocks + ["\n".join(current)])


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


def spaced(text: str) -> str:
    """`text` with each run of whitespace read as one space, kept at its ends."""
    return re.sub(r"\s+", " ", text)


def contains(text: str, excerpt: str) -> bool:
    """Whether `text` holds `excerpt` or, for a JSON file such as a trajectory, one decoded string does, whatever the
    whitespace between their words: retyped text often differs from its source in line breaks and indentation only."""
    excerpt = spaced(excerpt)
    if excerpt in spaced(text):
        return True
    try:
        stack = [json.loads(text)]
    except (ValueError, RecursionError):
        return False
    while stack:
        item = stack.pop()
        if isinstance(item, str) and excerpt in spaced(item):
            return True
        stack.extend(item.values() if isinstance(item, dict) else item if isinstance(item, list) else [])
    return False


def captured_object(output: str) -> dict | None:
    """A structured result from a successfully completed capture, not a verdict: the JSON object on the last line,
    or else the last one printed over several lines that starts a line and ends the output."""
    text = output.strip()
    lines = text.splitlines()
    try:
        value = json.loads(lines[-1]) if lines else None
    except json.JSONDecodeError:
        value = None
        for start in reversed([match.start() for match in re.finditer(r"^\{", text, re.MULTILINE)]):
            try:
                found, end = json.JSONDecoder().raw_decode(text, start)
            except json.JSONDecodeError:
                continue
            if end == len(text):
                value = found
                break
    return value if isinstance(value, dict) else None


def linked_submission(check: Check, evidence: Evidence) -> StateCopy | None:
    """The state copy that links the checked state to the episode's native outcome, or None.

    nudi took the copy without error, the check's content is its receipt, it names the
    check's episode and native IDs, and a sandbox started from it ran the check
    (`Evidence.executed`). Submission/task state includes absence or omitted work; the
    grader need not literally read every disputed byte. A copy cannot exclude state
    changes outside its point or under its excluded paths.
    """
    copy = evidence.copy(check)
    if (copy is None or copy.error is not None or copy.receipt != check.content or copy.episode != check.content.episode
            or not check.ids or copy.ids != check.ids or check.sandbox is None):
        return None
    return copy


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


def deserved(results: dict) -> float | None:
    """The check's computed `results.deserved` when it is a finite number; never a default."""
    value = results.get("deserved")
    finite = type(value) in (int, float) and -sys.float_info.max <= value <= sys.float_info.max
    return value if finite else None


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
    if not conclusion.reasons and evidence.artifact_metadata(reading.requirement):
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


EQUAL_REWARD = ("either a deserved score that applies the violated requirement, "
                "or measured observations showing that the requirement is supported")


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
    copy = linked_submission(check, evidence)
    if copy is None:
        return provisional(
            "the retained content has no state copy linking submission/task state to the native outcome; collected files and writable ATIF alone do not establish that link",
            "a state copy nudi took of the episode, with its native IDs and point, checked in a sandbox started from it",
        )
    assessment.limits.append(COPY_INTERPRETER)
    assessment.limits.append(f"the copy omits {', '.join(copy.excluded)}; nothing under them was checked")
    if copy.backend == "docker" and copy.point == "verification_start":
        assessment.limits.append(f"processes were paused for {copy.seconds:.1f} s before grading")
    if check.exit_code != 0:
        return provisional("the check did not complete successfully; printed output cannot establish validity", "a successful isolated check, with exit code 0")
    # The check sandbox's program and inputs are uploaded files whose hashes Evidence.check matched.
    if not check.program or not check.environment or not check.inputs:
        return provisional("the check lacks its executed program, isolation context or immutable inputs", "the actual isolated program/command and hashed input mapping")
    if check.content not in check.inputs.values() or not evidence.input_contains(check, check.requirement):
        return provisional("the check did not record the submission and requirement as inputs", "the evaluated submission and requirement among the check's immutable inputs")
    result = captured_object(check.output)
    # The sandbox receipt binds the output to the uploaded program and input bytes.
    if result is None:
        return provisional("the check's structured output is malformed", "structured observations and computations from the recorded input bytes")
    observations, results, derivation = result.get("observations"), result.get("results"), claim.derivation
    if not isinstance(observations, dict) or not isinstance(results, dict):
        return provisional("the check output lacks an `observations` or `results` object", "structured observations and computations from the recorded input bytes")
    if derivation is None or not claim.interpretation.strip():
        return provisional("the claim lacks an interpretation or derivation", "an Inspector derivation naming measured observations")
    citation_gaps = []
    for citation in claim.citations:
        try:
            evidence.excerpt(citation)
        except Ungrounded as error:
            citation_gaps.append(f"citation: {error}")

    def metadata_alone(source: Observation) -> bool:
        return all(evidence.artifact_metadata(item) for item in [source, *claim.citations])

    problems = measured(derivation.observations, observations, results) + citation_gaps
    # A claim cannot change the probe's requirement, so this gap asks for another reference, not another claim.
    metadata = not citation_gaps and metadata_alone(check.requirement)
    if problems:
        provisional(f"no measured observation supports the claimed validity: {'; '.join(problems)}",
                    "derivation.observations naming measured facts of the check output")
    if metadata:
        provisional("artifact metadata alone establishes no requirement", "a probe `requirement` in task text or grader code")
    if not problems and not metadata:
        assessment.validity = derivation.validity
    assessment.conclusions = [conclude(item, check, evidence, observations, results) for item in derivation.requirements]
    if reward is None:
        return
    if check.scoring is None or not evidence.input_contains(check, check.scoring):
        return provisional("the check lacks an applicable scoring input", "the cited scoring rule among the check's immutable inputs")
    if not citation_gaps and metadata_alone(check.scoring):
        return provisional("artifact metadata alone establishes no score", "a scoring rule in task text or grader code")
    # The claim says no check can measure what it names in `unresolved`, so no repair is asked for, and the deserved
    # score is unavailable: the comparison stays unknown and the printed `results.deserved` is not read.
    if derivation.validity == "unknown":
        return assessment.reasons.append("the claim leaves validity unknown, so the deserved score is unavailable and the comparison unknown"
                                         + "".join(f"; unresolved: {item}" for item in claim.unresolved))
    score = deserved(results)
    if score is None:
        return provisional("the check output has no finite `results.deserved`, so the score comparison is unknown",
                           "a check computing the deserved score as a finite `results.deserved`")
    if problems or metadata:
        return
    if math.isclose(reward, score):
        assessment.discrepancy = "none"
    else:
        assessment.discrepancy = "over" if reward > score else "under"

    violated = "violated" in [validity for _, validity in conclusions(assessment)]
    match assessment.validity, assessment.discrepancy:
        case "violated", "over":
            assessment.outcome = "accepted_invalid"
            assessment.reasons.append(f"violating content received {reward}, above the deserved score {score}")
        case "supported", "under":
            assessment.outcome = "rejected_valid"
            assessment.reasons.append(f"satisfying content received {reward}, below the deserved score {score}")
        case "supported" | "violated", "none" if violated and reward > 0:
            # The repair names both readings that resolve it, neither preferred; nothing here changes the outcome.
            provisional(f"content with a violated requirement received {reward}, equal to the deserved score {score}; "
                        "either reading may be right", EQUAL_REWARD)
        case "supported" | "violated", "none":
            assessment.outcome = "legitimate"
            assessment.reasons.append(f"native reward {reward} matches the deserved score {score}")
        case validity, discrepancy:
            provisional(
                f"validity {validity} with discrepancy {discrepancy} shows neither accepted invalid nor rejected valid work",
                "a check whose result and deserved score agree on the content's validity",
            )
