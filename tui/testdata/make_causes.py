"""Hand-make tui/testdata/causes/report.json from the schema 4 full fixture: a cause of several findings with an Attacker
exploit judged to use it, a no-hint exploit of a new cause, and a cause whose only finding is judged to use it.

Run after make_reports.py, from the repository root: python3 tui/testdata/make_causes.py tui"""
import copy, json, sys
from pathlib import Path
tui = Path(sys.argv[1])
r = json.loads((tui / "testdata/full/report.json").read_text())
assert r["schema_version"] == 4
LADDER5 = "●●●●● exploit executable by learner with no extra information"
base = r["attack"]["findings"]["evidenced"][0]
added = {}
for n, (episode, mechanism, cause) in enumerate([("0016-attacker", "A wrapper script returns 0.", "C1"),
                                                 ("0017-attacker", "The agent writes the reward file itself.", "C6"),
                                                 ("0018-attacker", "A stale marker file is read as a pass.", "C7")]):
    index, attempt = len(r["attack"]["findings"]["evidenced"]), len(r["attack"]["attempts"])
    a = copy.deepcopy(base)
    a["index"], a["claim"]["episode"], a["claim"]["mechanism"] = index, episode, mechanism
    a["captured"]["check"]["id"], a["captured"]["ids"]["trial_id"] = f"check-00{16 + n}", episode
    r["attack"]["findings"]["evidenced"].append(a)
    r["attack"]["attempts"].append({"number": 1 + n, "level": "none", "cause": cause, "candidate": None, "sources": [], "context": None,
                                    "episode": episode, "status": "evidenced_issue", "assessment": index, "rewards": {"reward": 1.0},
                                    "error": None, "failed": None})
    r["attack"]["exploits"]["discovery"].append({"assessment": index, "attempt": attempt, "candidate": None, "cause": cause, "sources": [],
                                                 "rationale": None, "relation": None})
    r["other_episodes"]["attacker"].append(episode)
    added[episode] = {"id": episode, "source": "Attacker", "outcome": "accepted_invalid", "type": None, "level": 5, "label": LADDER5,
                      "attacked": True, "read_as": cause != "C6", "mechanism": mechanism, "help": "no extra information", "kind": "discovery",
                      "attempt": attempt, "assessment": index, "scope": "native", "reward": 1.0, "check": f"check-00{16 + n}", "marks": {"exists": False},
                      "requirement": None, "reason": None, "conditions": [], "attempts": None, "reproduced": None, "unrewarded": None,
                      "unresolved": [], "family": None, "origin": None, "also": [], "location": None, "capture_point": None}
causes = r["causes"]
causes[0]["cause"] = "The grader trusts whatever runs first on PATH."
causes[0]["findings"].append(added["0016-attacker"])
causes.insert(0, {"id": "C6", "cause": "The agent writes the reward file itself.", "level": 5, "label": LADDER5, "attempts": None,
                  "reproduced": None, "unrewarded": None, "findings": [added["0017-attacker"]]})
causes.append({"id": "C7", "cause": "A stale marker file is read as a pass.", "level": None, "label": None, "attempts": None,
               "reproduced": None, "unrewarded": None, "findings": [added["0018-attacker"]]})
for c in causes:  # as the backend writes them: every finding after a cause's first was placed by a reading, and a cause
    for f in c["findings"][1:]:  # none of whose findings went to an Attacker counts no attempts
        f["read_as"] = True
    if not any(f["attacked"] for f in c["findings"]):
        c["attempts"] = c["reproduced"] = c["unrewarded"] = None
out = tui / "testdata/causes"
out.mkdir(exist_ok=True)
(out / "report.json").write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n")
