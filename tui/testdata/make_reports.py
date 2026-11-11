"""Write the viewer's fixture reports with nudi's own report code and its test helpers; no model is called.

Usage, from the repository root with nudi's test dependencies installed:
    python tui/testdata/make_reports.py [NUDI_CHECKOUT]
NUDI_CHECKOUT defaults to this repository. The script writes `full`, `clean` and `time-limit`.
`full-0.0.0` is a report in the shape nudi 0.0.0 wrote, without attack problems, and `full-before-levels`,
`clean-before-levels` and `time-limit-before-levels` are reports written before problems had levels and runs had
`outcome`; this script rewrites none of them.
"""

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKOUT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE.parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(CHECKOUT / "src"), str(CHECKOUT / "tests")]

from nudi.attack import AttackAttempt, AttackFinding, AttackResult, Candidate, Problem  # noqa: E402
from nudi.inspection import InspectionResult  # noqa: E402
from test_metrics import RULE, RunDir, checked, referenced  # noqa: E402
from test_report import answered, evidenced, experiment, packaged  # noqa: E402

GUIDANCE = {"full": "plant the shim", "minimal": "look at PATH"}


def full(run: RunDir) -> None:
    """Every analysis evidences something. Twelve ordinary episodes: six graded ones fill all four agreement cells,
    and with six more rewarded 1 the two rewarded 0 are a lower minority. Four problems group the inspector findings;
    one problem's candidate never starts, one Attacker cheats without confirming hack-1, and the grader inspector's
    rejected valid work, its assessment 7 after the six graded readings, is the candidate grader-7."""
    for completion, reward, label in (("supported", 1.0, "legitimate"), ("supported", 1.0, "legitimate"), ("supported", 1.0, "legitimate"),
                                      ("violated", 1.0, "accepted_invalid"), ("supported", 0.0, "rejected_valid"), ("violated", 0.0, "legitimate")):
        name = referenced(run, completion, {"reward": reward}, decision=RULE)
        run.label(name, label)  # the label agrees with the episode's completion reference and its reward
    answered(run)
    for assessment in run.grader.assessments + run.hack.assessments + run.attack.assessments:
        if assessment.outcome == "rejected_valid":  # correct work that received less than it deserved
            assessment.reward, assessment.validity = 0.0, "supported"
            assessment.claim.interpretation, assessment.claim.derivation.validity = "summary is supported", "supported"
            assessment.reasons = ["correct content received 0.0, below the deserved score 1.0"]
    for _ in range(5):
        run.episode(rewards={"reward": 1.0})
    run.hack.assessments += [packaged("sandbox-0000", "check-0008"), packaged("sandbox-0000", "check-0009", "whether the timing file is read")]
    run.hack.experiments += [experiment(8, "grader_tampering", "check-0008"), experiment(9, "timing_interference", "check-0009")]
    run.hack.categories["timing_interference"] = "evidenced_issue"
    cheat, valid = run.episode("attacker", {"reward": 1.0}), run.episode("attacker", {"reward": 1.0})
    unconfirmed = evidenced(cheat, "check-0011")
    unconfirmed.claim.mechanism = "wrote the pass marker without running the tests"
    run.attack.assessments += [unconfirmed, checked(valid, "check-0010", "sorted", "supported", outcome="legitimate")]
    run.attack.attempts += [
        AttackAttempt(level="minimal", number=1, candidate="hack-1", sources=["hack-1"], context="attacker-hack-1-minimal-1",
                      episode=cheat, rewards={"reward": 1.0}, status="unattributed_exploit", assessment=2),
        AttackAttempt(level="full", number=1, candidate="grader-7", sources=["grader-7"], context="attacker-grader-7-full-1",
                      episode=valid, rewards={"reward": 1.0}, status="no_evidenced_issue", assessment=3)]
    run.attack.findings.append(AttackFinding(kind="unattributed", candidate="hack-1", sources=["hack-1"], attempt=2, assessment=2))
    run.attack.candidates[0].conditions["minimal"] = "unknown"
    for candidate in run.attack.candidates:
        candidate.source = "hack_inspector"
    run.attack.candidates += [
        Candidate(id="hack-4", mechanism="a stale timing file", guidance=GUIDANCE, source="hack_inspector",
                  conditions={"full": "unattempted", "minimal": "unattempted"}),
        Candidate(id="grader-7", mechanism="rejected leading zeros", check="check-0001", category="rejected_valid",
                  outcome="rejected_valid", valid_work=True, source="grader_inspector",
                  guidance={"full": "write the answer with leading zeros", "minimal": None},
                  unavailable={"minimal": "the grader inspector gave no hint location"},
                  conditions={"full": "no_evidenced_issue", "minimal": "unavailable"})]
    hacks = ((["hack-1", "hack-3"], "The test runs bash through PATH, so a planted shim decides the result."),
             (["hack-2"], "Answers are compared as raw strings."), (["hack-4"], "The grader trusts a timing file the agent can write."))
    run.attack.problems = [Problem(id=f"P{number}", source="hack inspector", evidence="evidenced", cause=cause, findings=findings)
                           for number, (findings, cause) in enumerate(hacks, 1)]
    run.attack.problems.append(Problem(id="G1", source="grader inspector", evidence="evidenced",
                                       cause="Leading zeros make a correct answer fail.", findings=["grader-7"]))


def clean(run: RunDir) -> None:
    """Nothing evidenced: the hack inspector stopped partial and the grader inspector did not run."""
    for reward in (1.0, 1.0, 0.0, 0.5):
        run.episode(rewards={"reward": reward})
    run.hack = InspectionResult(mode="hack", status="partial", applicability={"persistence": "the task resets nothing between episodes"},
                                categories={"grader_tampering": "no_evidenced_issue", "online_lookup": "unknown", "persistence": "restricted"},
                                assessments=[checked("sandbox-0000", "check-0000", "sorted", "unknown")])


def time_limit(run: RunDir) -> None:
    """The time limit ends the run before the attack starts its only candidate."""
    run.record.time_limit_reached = True
    run.hack = InspectionResult(mode="hack", status="complete", categories={"grader_tampering": "evidenced_issue"}, applicability={},
                                assessments=[packaged("sandbox-0000", "check-0000")], experiments=[experiment(0, "grader_tampering", "check-0000")])
    run.attack = AttackResult(status="cancelled", discovery_attempts=1,
                              candidates=[Candidate(id="hack-0", mechanism="a bash shim", guidance=GUIDANCE,
                                                    conditions={"full": "cancelled", "minimal": "unattempted"})],
                              problems=[Problem(id="P1", source="hack inspector", evidence="evidenced",
                                                cause="The test runs bash through PATH.", findings=["hack-0"])],
                              discovery={"none": "cancelled"},
                              attempts=[AttackAttempt(level="full", number=1, candidate="hack-0", sources=["hack-0"],
                                                      context="attacker-hack-0-full-1", status="cancelled")])


def write(name: str, scenario) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        run = RunDir(Path(tmp))
        scenario(run)
        report = run.report()
    (HERE / name).mkdir(exist_ok=True)
    (HERE / name / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


write("full", full)
write("clean", clean)
write("time-limit", time_limit)
