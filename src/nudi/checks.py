"""Inspector investigations and native, independently retained observations.

Generated checks reuse Harbor's Oracle harness in a disposable episode. The small
Oracle adapter retains the native exec result outside all task-mounted directories.
"""

import asyncio
import hashlib
import json
import re
import shlex
import sys
import os
import signal
from pathlib import Path, PurePosixPath

from harbor.agents.oracle import OracleAgent
from harbor.agents.base import BaseAgent
from harbor.constants import MAIN_SERVICE_NAME
from harbor.models.task.artifacts import effective_artifact_service, normalize_artifact_entries
from harbor.models.trial.config import AgentConfig
from harbor.models.trial.paths import EnvironmentPaths
from harbor.models.task.task import Task
from pydantic import BaseModel
import litellm

from nudi.assessment import Evidence, assess
from nudi.records import ArtifactSelection, Assessment, Check, Claim, Content, Observation, Outcome, Submission


# Trusted host code. No model source is evaluated here. Docker's archive API reads
# state independently of commands, interpreters or manifests inside the task.
CAPTURE_PROGRAM = '''import datetime, hashlib, io, json, subprocess, sys, tarfile
container, location, ids = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
proc = subprocess.Popen(["docker", "cp", container + ":" + location, "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    raw = proc.stdout.read(2097153)
    if len(raw) > 2097152:
        raise ValueError("capture exceeds 2 MiB archive limit")
    error = proc.stderr.read(8192).decode(errors="replace")
    status = proc.wait(timeout=10)
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait()
if status:
    if "Could not find the file" not in error:
        raise RuntimeError(error)
    alive = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", container], capture_output=True, text=True, timeout=10, check=True)
    if alive.stdout.strip() != "true":
        raise RuntimeError("task container is no longer running")
    state = {"location": location, "exists": False}
else:
    import base64
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        members = archive.getmembers()
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("only individual regular files and absence are supported")
        state = {"location": location, "exists": True, "base64": base64.b64encode(archive.extractfile(members[0]).read()).decode()}
state.update(observed_start=start, observed_end=datetime.datetime.now(datetime.timezone.utc).isoformat())
text = json.dumps(state, sort_keys=True)
print(json.dumps({"state": text, "sha256": hashlib.sha256(text.encode()).hexdigest(), "location": location, "ids": ids}))
'''


# The wrapper bounds generated stdout before it reaches Harbor's host-side
# buffering. Native agent timeouts, user, network and resource limits still apply.
CHECK_WRAPPER = '''import subprocess, sys
child = subprocess.Popen([sys.executable, "-c", sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
child.stdin.write(sys.argv[2].encode()); child.stdin.close()
try:
    output = child.stdout.read(65537)
    if len(output) > 65536:
        child.kill(); child.wait()
        print("check output exceeded 65536 bytes")
        sys.exit(125)
    sys.stdout.buffer.write(output); sys.stdout.buffer.flush()
    sys.exit(child.wait())
finally:
    if child.poll() is None:
        child.kill(); child.wait()
'''


class RetainedOracle(OracleAgent):
    """Only generated checks use this Oracle adapter; it retains direct ExecResult."""

    def __init__(self, *, program: str, inputs: str, host_output: str, **kwargs):
        # Harbor injects task_dir/trial_paths only for its registered oracle name.
        # This adapter needs neither: its program and host receipt are explicit.
        BaseAgent.__init__(self, **kwargs)
        self.program, self.inputs, self.host_output = program, inputs, Path(host_output)

    async def run(self, instruction, environment, context):
        command = ["python", "-c", CHECK_WRAPPER, self.program, self.inputs]
        receipt = {"command": command, "environment": f"native Harbor {environment.session_id}",
                   "exit_code": None, "output": ""}
        try:
            result = await environment.exec(command=shlex.join(command))
            receipt.update(exit_code=result.return_code, output=result.stdout or "", stderr=result.stderr)
        except BaseException as error:
            receipt["error"] = type(error).__name__
            raise
        finally:
            self.host_output.parent.mkdir(parents=True, exist_ok=True)
            self.host_output.write_text(json.dumps(receipt))


async def host_command(command: list[str], *, timeout: float = 30) -> tuple[int, str, str]:
    """Run trusted capture tools only, with bounded output generated by the fixed reader."""
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        return process.returncode, stdout.decode(), stderr.decode(errors="replace")
    finally:
        if process.returncode is None:
            os.killpg(process.pid, signal.SIGKILL)
            await process.wait()


async def capture_submission(event, episode: str, output_dir: Path, location: str) -> Submission:
    """Observe one file or its absence during the awaited verification-start hook.

    It observes an interval, not an atomic snapshot, agent return or later grader read.
    The Docker project/service mapping belongs to the pinned Harbor Docker backend.
    """
    path = PurePosixPath(location)
    if not path.is_absolute() or ".." in path.parts or "\x00" in location:
        raise ValueError("capture location must be an absolute task path without '..'")
    project = re.sub(r"[^a-z0-9_-]", "-", (event.trial_name + "__env").lower())
    if not project[0].isalnum():
        project = "0" + project
    status, output, error = await host_command([
        "docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={project}",
        "--filter", "label=com.docker.compose.service=main",
    ])
    containers = output.split()
    if status or len(containers) != 1:
        raise RuntimeError(f"native task container unavailable: {error or containers}")
    ids = {"trial_id": str(event.trial_id), "trial_name": event.trial_name, "task_checksum": event.result.task_checksum}
    command = [sys.executable, "-c", CAPTURE_PROGRAM, containers[0], location, json.dumps(ids)]
    status, output, error = await host_command(command)
    if status:
        raise RuntimeError(error)
    receipt = json.loads(output)
    name = hashlib.sha256(location.encode()).hexdigest()[:16] + ".json"
    retained = output_dir / "nudi-evidence" / name
    retained.parent.mkdir(parents=True, exist_ok=True)
    retained.write_text(receipt["state"])
    return Submission(content=Content(episode=episode, path=f"nudi-evidence/{name}", sha256=receipt["sha256"]),
                      ids=ids, location=location, capture_point="verification_start", command=command,
                      program=CAPTURE_PROGRAM, exit_code=status, output=output)


async def check_submission(run, submission: Submission, requirement, scoring, program: str, *, capture_point: str, timing: str) -> Check:
    """Check retained bytes through native Harbor; unavailable timing never substitutes.

    `timing` is Inspector interpretation of the requirement, not a new observation.
    """
    from nudi.workflow import run_role_episode

    run.check_cap()
    check = Check(id=f"check-{len(run.record.checks):04d}", content=submission.content, ids=submission.ids,
                  requirement=requirement, scoring=scoring, command=[], exit_code=None, output="", program=program, timing=timing)
    run.record.checks.append(check)
    run.save()
    if capture_point != "verification_start" or not timing.strip():
        check.output = f"Requested task time {capture_point!r} is not observed; no substitute capture was used. Inspector interpretation: {timing}"
        run.save()
        return check
    evidence = Evidence(run.config.output_dir, submission.content.episode)
    evidence.content(submission.content)
    evidence.excerpt(requirement)
    inputs = {"submission": submission.content}
    for name, source in (("requirement", requirement), ("scoring", scoring)):
        if source is not None:
            evidence.excerpt(source)
            file = evidence.file(source.episode, source.path)
            inputs[name] = Content(episode=source.episode, path=source.path, sha256=hashlib.sha256(file.read_bytes()).hexdigest())
    text = {name: evidence.file(content.episode, content.path).read_bytes().decode("utf-8") for name, content in inputs.items()}
    check.inputs, check.submission = inputs, submission
    name = f"{len(run.record.episodes):04d}-inspector"
    execution = run.config.output_dir / "episodes" / name / "nudi-evidence" / "execution.json"
    agent = AgentConfig(import_path="nudi.checks:RetainedOracle", kwargs={
        "program": program, "inputs": json.dumps(text), "host_output": str(execution.resolve()),
    })
    try:
        result = await run_role_episode(run, "inspector", agent=agent)
        if execution.is_file():
            receipt = json.loads(execution.read_text())
            check.command, check.environment, check.output = receipt["command"], receipt["environment"], receipt["output"]
            if not result.cancelled and not result.agent_timeout:
                check.exit_code = receipt["exit_code"]
    finally:
        run.save()
    return check


HACK_CATEGORIES = ("leakage_metadata", "package_oracles", "grader_tampering", "fabricated_answers",
                   "malformed_rewards", "timing_interference", "resource_exhaustion", "online_lookup", "persistence")
GRADER_CATEGORIES = ("accepted_invalid", "rejected_valid", "omitted_requirements", "partial_credit")


class InspectionAttempt(BaseModel):
    phase: str
    category: str | None = None
    number: int
    status: str = "running"
    error: str | None = None


class EpisodeLabel(BaseModel):
    label: Outcome
    reasons: list[str] = []
    assessments: list[int] = []
    """Indices into `InspectionResult.assessments` of this episode's assessments."""


class InspectionResult(BaseModel):
    mode: str
    status: str = "running"
    categories: dict[str, str]
    applicability: dict[str, str]
    applicability_evidence: dict[str, dict] = {}
    attempts: list[InspectionAttempt] = []
    assessments: list[Assessment] = []
    sessions: dict[str, list[dict]] = {}
    ordinary: dict[str, EpisodeLabel] = {}
    """Grader mode: a label for every ordinary episode, from its own assessments only.
    Targeted probe episodes are outside the pool; their assessments never label it."""


def select_artifacts(task_dir: Path) -> list[ArtifactSelection]:
    """Choose the task's declared artifacts that ordinary episodes capture at verification start.

    Only main-service container sources are captured, never host destinations. Directories,
    helper services and grader files/outputs are skipped with their reason. A source that
    is a directory without a trailing slash fails at capture and is recorded per episode.
    """
    grader = (EnvironmentPaths.verifier_dir, EnvironmentPaths.tests_dir, EnvironmentPaths.solution_dir)
    selection = []
    for index, entry in enumerate(normalize_artifact_entries(Task(task_dir).config.artifacts)):
        path, selected = PurePosixPath(entry.source), False
        if effective_artifact_service(entry) != MAIN_SERVICE_NAME:
            reason = "a helper service's path; only the main task container is captured"
        elif not path.is_absolute():
            reason = "not an absolute container path"
        elif entry.source.endswith("/") or entry.exclude or path == EnvironmentPaths.artifacts_dir:
            reason = "a directory; only individual regular files or their absence are captured"
        elif any(path == root or root in path.parents for root in grader):
            reason = "a grader file or grader-created output, not submission state at verification start"
        else:
            selected, reason = True, "a declared main-service file, captured at verification start"
        selection.append(ArtifactSelection(declaration=index, source=entry.source, service=entry.service,
                                           destination=entry.destination, selected=selected, reason=reason))
    return selection


class InferenceFailure(RuntimeError):
    pass


class InspectorRefusal(RuntimeError):
    pass


def redacted(run, text: str) -> str:
    for secret in run.keys.values():
        text = text.replace(secret, "[redacted]")
    return text


class InspectorSession:
    """One Inspector context. Only focused retries share its history."""

    def __init__(self, run, name: str):
        self.run, self.name = run, name
        prompt = (Path(__file__).parent / "prompts" / "inspector.md").read_text()
        self.messages = [{"role": "system", "content": prompt}]

    async def ask(self, context: str) -> dict:
        from nudi.workflow import SpendingCapReached, model_calls

        self.run.check_cap()
        self.messages.append({"role": "user", "content": context})
        model = self.run.record.models["inspector"]
        request = {"model": model.model, "messages": self.messages, "api_base": model.api_base}
        if model.reasoning_effort is not None:
            request["reasoning_effort"] = model.reasoning_effort
        if model.model.startswith("xiaomi_mimo/") and model.reasoning_effort not in (None, "none"):
            request["extra_body"] = {"thinking": {"type": "enabled"}}
        try:
            with model_calls(self.run, "inspector", self.name):
                response = await litellm.acompletion(**request)
            message = response.choices[0].message
            content = message.content or ""
            self.messages.append({"role": "assistant", "content": content})
            if getattr(message, "refusal", None):
                return {"refusal": message.refusal}
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ValueError("Inspector response must be a JSON object")
            return result
        except (asyncio.CancelledError, SpendingCapReached):
            raise
        except Exception as error:
            message = f"{type(error).__name__}: {error}"
            for secret in self.run.keys.values():
                message = message.replace(secret, "[redacted]")
            raise InferenceFailure(message) from error


def task_context(run) -> dict:
    """Scoped source text only; credentials and host run files are never included."""
    root = run.config.task_dir.resolve()
    files, remaining, omitted = {}, 262144, []
    for file in sorted(root.rglob("*")):
        if not file.is_file() or not file.resolve().is_relative_to(root):
            continue
        name = str(file.relative_to(root))
        if file.stat().st_size > min(65536, remaining):
            omitted.append(name)
            continue
        try:
            text = file.read_text(encoding="utf-8")
        except UnicodeError:
            omitted.append(name)
            continue
        files[name] = text
        remaining -= file.stat().st_size
    task = Task(root)
    return {"untrusted_task_files": files, "omitted_context_files": omitted,
            "native_tools": {"terminal": True, "network": str(task.config.agent.network_mode or task.config.environment.network_mode),
                             "agent_user": task.config.agent.user, "verifier_mode": task.config.verifier.environment_mode,
                             "cpus": task.config.environment.cpus, "memory_mb": task.config.environment.memory_mb},
            "capture_capabilities": ["verification_start file bytes or absence during recorded interval"],
            "capture_limits": "No atomic snapshot, state at agent return/later grader read, continuity or protected normal-reset readback."}


def ordinary_context(run, pool: list[str]) -> list[dict]:
    episodes = []
    for name in pool:
        evidence = Evidence(run.config.output_dir, name)
        if not evidence.task_intact:
            raise ValueError("ordinary episode task differs from the current task")
        result = evidence.graded
        trace = None
        if "trajectory" in result.artifacts:
            path = evidence.file(name, result.artifacts["trajectory"])
            with path.open(encoding="utf-8", errors="replace") as file:
                trace = file.read(65537)
        episodes.append({"episode": name, "rewards": result.rewards, "errors": [error.model_dump() for error in result.errors],
                         "agent_timeout": result.agent_timeout, "verifier_timeout": result.verifier_timeout,
                         "cancelled": result.cancelled, "trace": trace[:65536] if trace else None,
                         "trace_truncated": bool(trace and len(trace) > 65536), "artifacts": result.artifacts,
                         "captured": [{"location": state.location, "capture_point": state.capture_point}
                                      for state in run.record.submissions if state.content.episode == name],
                         "capture_failures": [failure.model_dump() for failure in run.record.capture_errors if failure.episode == name]})
    return episodes


SUPPORTED_LABELS = ("accepted_invalid", "rejected_valid", "legitimate")


def label_ordinary(run, pool: list[str], report: InspectionResult) -> dict[str, EpisodeLabel]:
    """A supported label only from one agreeing set of the episode's own assessments;
    otherwise unknown with every reason, or unavailable without a native reward."""
    labels = {}
    for name in pool:
        indices = [index for index, assessment in enumerate(report.assessments) if assessment.claim.episode == name]
        own = [report.assessments[index] for index in indices]
        reasons = [reason for assessment in own for reason in assessment.reasons + assessment.missing]
        graded = Evidence(run.config.output_dir, name).graded
        if graded.rewards.get("reward") is None:
            causes = [error.type for error in graded.errors]
            causes += [flag for flag in ("cancelled", "agent_timeout", "verifier_timeout") if getattr(graded, flag)]
            labels[name] = EpisodeLabel(label="unavailable", reasons=[f"no native reward 'reward'; cause: {', '.join(causes) or 'unknown'}"],
                                        assessments=indices)
            continue
        supported = sorted({assessment.outcome for assessment in own} & set(SUPPORTED_LABELS))
        if len(supported) == 1:
            labels[name] = EpisodeLabel(label=supported[0], reasons=reasons, assessments=indices)
            continue
        if supported:
            reasons.append(f"its assessments disagree: {', '.join(supported)}")
        if not own:
            reasons.append("no investigation assessed this episode; finding no mismatch does not establish legitimacy")
        if not any(state.content.episode == name for state in run.record.submissions):
            reasons.append("no independent capture of this episode's state exists; uncaptured work is not evidence of absence")
        reasons += [f"capture of {failure.location} failed: {failure.error.type}: {failure.error.message}"
                    for failure in run.record.capture_errors if failure.episode == name]
        if report.status != "complete":
            reasons.append(f"grader inspection ended with status {report.status}, so its coverage is incomplete")
        labels[name] = EpisodeLabel(label="unknown", reasons=reasons, assessments=indices)
    return labels


async def investigate(run, probe: dict, session: InspectorSession) -> Assessment:
    """Execute a proposed investigation, then ask that same Inspector to interpret it."""
    from nudi.workflow import run_role_episode

    requirement = Observation.model_validate(probe["requirement"])
    scoring = Observation.model_validate(probe["scoring"]) if probe.get("scoring") else None
    capture_point, timing = probe["capture_point"], probe["timing"]
    if probe.get("instruction"):
        name = f"{len(run.record.episodes):04d}-inspector"
        await run_role_episode(run, "inspector", instruction=probe["instruction"],
                               capture_locations=[probe["location"]] if capture_point == "verification_start" else [])
    else:
        name = probe["episode"]
        Evidence(run.config.output_dir, name)
    claim = Claim(mechanism=probe["category"], episode=name)
    failures = [failure for failure in run.record.capture_errors if failure.episode == name and failure.location == probe["location"]]
    if capture_point == "verification_start" and failures:
        raise RuntimeError("Native capture failed: " + failures[-1].model_dump_json())
    submissions = [state for state in run.record.submissions if state.content.episode == name and state.location == probe["location"]]
    if capture_point != "verification_start" or not submissions:
        assessment = assess(claim, run.config.output_dir)
        assessment.missing.append(f"independent state at requested time {capture_point!r}; no substitute observation was used")
        return assessment
    check = await check_submission(run, submissions[-1], requirement, scoring, probe["program"], capture_point=capture_point, timing=timing)
    if check.exit_code != 0:
        claim.check = check.id
        return assess(claim, run.config.output_dir)
    result = Evidence(run.config.output_dir, name).graded
    response = await session.ask(json.dumps({"instruction": "Interpret this actual completed check and native reward. Return claim only; no new probes.",
                                             "requested_time": capture_point, "timing_interpretation": timing,
                                             "check": check.model_dump(), "rewards": result.rewards}))
    if response.get("refusal"):
        raise InspectorRefusal(str(response["refusal"]))
    interpretation = response["claim"]
    # Identity is supplied by nudi, never by a model's receipt or success flag.
    claim = Claim.model_validate({**interpretation, "episode": name, "check": check.id})
    return assess(claim, run.config.output_dir)


async def inspect_hacks(run, *, focused_attempts: int = 3, categories=None) -> InspectionResult:
    return await inspect(run, "hack", [], focused_attempts, list(categories or HACK_CATEGORIES))


async def inspect_grader(run, ordinary_pool: list[str], *, focused_attempts: int = 3, categories=None) -> InspectionResult:
    return await inspect(run, "grader", ordinary_pool, focused_attempts, list(categories or GRADER_CATEGORIES))


async def inspect(run, mode: str, pool: list[str], focused_attempts: int, categories: list[str]) -> InspectionResult:
    from nudi.workflow import MissingCredential, SpendingCapReached

    if type(focused_attempts) is not int or focused_attempts < 0:
        raise ValueError("focused_attempts counts total attempts and must be a nonnegative integer")
    allowed = HACK_CATEGORIES if mode == "hack" else GRADER_CATEGORIES
    if not categories or len(set(categories)) != len(categories) or any(category not in allowed for category in categories):
        raise ValueError("categories must be distinct approved inspection categories")
    if "inspector" not in run.keys:
        raise MissingCredential("Inspector credential was not resolved for this run")
    context = task_context(run)
    ordinary = ordinary_context(run, pool) if mode == "grader" else []
    simulation = run.record.simulation
    inventory = [item.model_dump() for item in simulation.selection] if mode == "grader" and simulation else []
    applicability = {category: "Applicability has not been determined from actual tools/access." for category in categories}
    restricted = set()
    if "persistence" in categories:
        restricted.add("persistence")
        applicability["persistence"] = "Protected state readback after a known successful normal reset is unavailable; persistence remains provisional."
    if "online_lookup" in categories and context["native_tools"]["network"].lower().endswith("none"):
        restricted.add("online_lookup")
        applicability["online_lookup"] = "The declared task network policy disallows online lookup."
    report = InspectionResult(mode=mode, categories={category: "restricted" if category in restricted else "pending" for category in categories}, applicability=applicability)
    destination = run.config.output_dir / f"inspection-{mode}.json"
    seen = set()

    def save():
        destination.write_text(report.model_dump_json(indent=2))

    async def attempt(session, phase, category, number):
        record = InspectionAttempt(phase=phase, category=category, number=number)
        report.attempts.append(record)
        report.sessions[session.name] = session.messages
        save()
        try:
            requested = [category] if category else categories
            payload = {"mode": mode, "phase": phase, "categories": requested, "applicability": {key: applicability[key] for key in requested},
                       "task": context, "ordinary_episodes_read_first": ordinary, "capture_inventory": inventory,
                       "instruction": "Investigate a new case." if mode == "grader" and number > 1 else "Inspect the supplied evidence and propose bounded probes."}
            response = await session.ask(json.dumps(payload, default=str))
            if response.get("refusal"):
                record.status, record.error = "refused", redacted(run, str(response["refusal"]))
                return
            if phase == "broad":
                decisions = response.get("applicability", {})
                for target in categories:
                    if target in restricted:
                        continue
                    decision = decisions.get(target, {}) if isinstance(decisions, dict) else {}
                    facts = decision.get("facts", {}) if isinstance(decision, dict) else {}
                    grounded = isinstance(facts, dict) and bool(facts) and all(
                        key in context["native_tools"] and type(value) is type(context["native_tools"][key]) and value == context["native_tools"][key]
                        for key, value in facts.items())
                    status = decision.get("status") if isinstance(decision, dict) else None
                    reason = decision.get("reason") if isinstance(decision, dict) else None
                    if not grounded or not isinstance(reason, str) or not reason.strip() or status not in ("applicable", "restricted", "unknown"):
                        status, reason = "unknown", "No supported applicability determination from actual tools/access."
                    report.applicability_evidence[target] = {"status": status, "facts": facts, "reason": reason}
                    applicability[target] = reason
                    if status != "applicable":
                        report.categories[target] = status
                        restricted.add(target)
            probes = response.get("probes", [])
            if not isinstance(probes, list):
                raise InferenceFailure("probes must be a list")
            record.status = "no_evidenced_issue"
            for probe in probes:
                target = probe.get("category")
                if target not in requested or target in restricted or report.categories[target] == "evidenced_issue":
                    continue
                # A renamed label cannot turn an identical episode/probe into a new case.
                identity = json.dumps({key: probe.get(key) for key in ("episode", "instruction", "requirement", "location")}, sort_keys=True)
                if mode == "grader" and identity in seen:
                    record.status = "duplicate_case"
                    continue
                seen.add(identity)
                assessment = await investigate(run, probe, session)
                report.assessments.append(assessment)
                session.messages.append({"role": "user", "content": redacted(run, json.dumps({"investigation_result": assessment.model_dump()}))})
                if assessment.outcome in ("accepted_invalid", "rejected_valid"):
                    report.categories[target] = "evidenced_issue"
                    record.status = "evidenced_issue"
                elif assessment.check is not None and assessment.check.exit_code != 0:
                    record.status = "tool_failure"
                save()
        except SpendingCapReached:
            record.status = report.status = "spending_exhausted"
            raise
        except asyncio.CancelledError:
            record.status = report.status = "cancelled"
            raise
        except InferenceFailure as error:
            record.status, record.error = "inference_failure", str(error)
        except InspectorRefusal as error:
            record.status, record.error = "refused", redacted(run, str(error))
        except Exception as error:
            record.status, record.error = "tool_failure", redacted(run, f"{type(error).__name__}: {error}")
        finally:
            if record.error is not None:
                session.messages.append({"role": "user", "content": json.dumps({"investigation_status": record.status, "error": record.error})})
            save()

    try:
        await attempt(InspectorSession(run, f"{mode}-broad"), "broad", None, 0)
        for category in categories:
            if category not in report.applicability_evidence and category not in restricted:
                report.categories[category] = "unknown"
                restricted.add(category)
            if category in restricted or report.categories[category] == "evidenced_issue":
                continue
            session = InspectorSession(run, f"{mode}-{category}")
            for number in range(1, focused_attempts + 1):
                await attempt(session, "focused", category, number)
                if report.categories[category] == "evidenced_issue":
                    break
            if report.categories[category] == "pending":
                report.categories[category] = "no_evidenced_issue"
        report.status = "partial" if restricted or any(item.status in ("tool_failure", "inference_failure", "refused") for item in report.attempts) else "complete"
    except SpendingCapReached:
        pass
    finally:
        if mode == "grader":
            report.ordinary = label_ordinary(run, pool, report)
        save()
    return report
