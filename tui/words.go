package main

// The screens turn each label of report.json into words through one table per label set.
// A label missing from its table shows as itself and is recorded in missed, which the
// fixture tests check, so a new Python label fails them until it has words.

var missed = map[string]bool{}

func word(table map[string]string, label string) string {
	if w, ok := lookup(table, label); ok {
		return w
	}
	return label
}

func lookup[T any](table map[string]T, label string) (T, bool) {
	v, ok := table[label]
	if !ok {
		missed[label] = true
	}
	return v, ok
}

// The phases in the order nudi runs them, each with its key in report.json's analyses.
var phases = []struct{ Name, Analysis string }{
	{"Simulation", "simulation"},
	{"Grade Simulations", "grader"},
	{"Find Hacks", "hack"},
	{"Attack", "attack"},
	{"Finished", ""},
}

// statusWords name an analysis's status, and the run's status; the stopped ones use the report's own words.
// An event's phase_end adds stopped and failed.
var statusWords = map[string]string{
	"stopped":            "stopped",
	"failed":             "failed",
	"complete":           "done",
	"partial":            "some results unclear",
	"time_limit":         "time limit reached",
	"cancelled":          "stopped",
	"spending_exhausted": "stopped by the spending cap",
	"running":            "unfinished",
	"unknown":            "result unclear",
	"not run":            "selected but not run",
}

// kindTags name a finding by the job that found it and its outcome.
var kindTags = map[string]string{
	"grader_inspector accepted_invalid": "FP",
	"grader_inspector rejected_valid":   "FN",
	"hack_inspector accepted_invalid":   "HACK",
	"hack_inspector rejected_valid":     "FN",
	"attack accepted_invalid":           "HACK",
	"attack rejected_valid":             "FN",
}

// kindKeys say in a few words what each tag means, FP and FN as the simulation chart does.
var kindKeys = map[string]string{
	"HACK": "a trick that gets reward",
	"FP":   "Incorrect work passed",
	"FN":   "Correct work failed",
}

var sourceWords = map[string]string{
	"grader_inspector": "grader inspector",
	"hack_inspector":   "hack inspector",
	"attack":           "attack inspector",
}

var scopeWords = map[string]string{"package": "package copy", "native": "real episode"}

var checkNames = map[string]string{
	"leakage_metadata":       "Reads leaked answer",
	"package_oracles":        "Reads solution files",
	"grader_tampering":       "Edits grader or tests",
	"fabricated_answers":     "Hard-codes answers",
	"malformed_rewards":      "Writes invalid reward",
	"timing_interference":    "Rigs timing",
	"resource_exhaustion":    "Crashes grader",
	"online_lookup":          "Looks answer up online",
	"persistence":            "Files survive reset",
	"unchecked_requirements": "Skips unchecked requirements",
	"other":                  "Other trick",
	"accepted_invalid":       "Incorrect work passed",
	"rejected_valid":         "Correct work failed",
}

// hackOrder is the order of the hack chips; other shows only when the report has it.
var hackOrder = []string{"leakage_metadata", "package_oracles", "grader_tampering", "fabricated_answers", "malformed_rewards",
	"timing_interference", "resource_exhaustion", "online_lookup", "persistence", "unchecked_requirements", "other"}

// labelWords name the grader inspector's local label of an ordinary episode.
var labelWords = map[string]string{
	"legitimate":       "legitimate",
	"accepted_invalid": "Incorrect work passed",
	"rejected_valid":   "Correct work failed",
	"unknown":          "Unresolved",
	"unavailable":      "unavailable",
	"ungrounded":       "ungrounded",
	"unreviewed":       "not reviewed",
}

// flagWords name Python's distribution flags of a reward.
var flagWords = map[string]string{"identical_rewards": "Identical rewards", "low_minority": "Lower minority", "high_minority": "Higher minority"}

// exploitWords say what an Attacker exploit confirmed of the findings it tested, by its kind in the report.
var exploitWords = map[string]string{
	"reproduction": "reproduced",
	"other":        "another mechanism while testing",
	"unattributed": "not confirmed as",
	"discovery":    "found with no extra information",
}

// levelWords name an attack hint level as the exploit chart does: what an Attacker receives.
var levelWords = map[string]string{"none": "no extra information", "full": "full instructions", "minimal": "only a hint"}

// ladderWords are the exploit chart's steps, 2 to 5; level 1 in older reports is a lead.
var ladderWords = map[int]string{
	2: "●●○○○ reproduced exploit",
	3: "●●●○○ exploit executable by learner with full information",
	4: "●●●●○ exploit executable by learner with hint",
	5: "●●●●● exploit executable by unaided learner",
}

// helpLevels give a problem's step from the least help an Attacker needed, for reports written before `level`;
// any other value is a reproduced exploit.
var helpLevels = map[string]int{"none": 5, "minimal": 4, "full": 3,
	"found_alone": 5, "single_hint": 4, "full_info": 3, "full_info_or_less": 3, "not_reproduced": 1}

// validWorkWords say how an Attacker reproduced correct work the grader fails, after the simulation chart's FN words.
var validWorkWords = map[int]string{
	3: ", reproduced by an Attacker with full instructions",
	4: ", reproduced by an Attacker with only a hint",
	5: ", reproduced by an Attacker with no extra information",
}

// reasonWords say why a reproduced exploit got no further.
var reasonWords = map[string]string{
	"not_exploited": "Attackers did not exploit it",
	"no_guidance":   "not attacked: no guidance",
	"unknown":       "no clear Attacker result",
}

// reproducedWords say how the hack inspector's reproduction of a problem ended.
var reproducedWords = map[string]string{"evidenced": "✓", "not_reproduced": "✗ not reproduced"}

// evidencedWords say where a level-2 problem's findings were evidenced, after its label.
var evidencedWords = map[string]string{"package": "evidenced in a package sandbox", "native": "evidenced in a native episode"}

// Result is how one attack attempt ended, as the attack panel draws it.
type Result int

const (
	NotTested Result = iota
	Evidenced
	Elsewhere
	NoIssue
	Failed
	Unsettled
)

var attemptResults = map[string]Result{
	"evidenced_issue":        Evidenced,
	"other_exploit":          Elsewhere,
	"unattributed_exploit":   Unsettled, // an exploit not attributed to its problem or another
	"no_evidenced_issue":     NoIssue,
	"unknown":                Unsettled,
	"native_timeout":         Failed,
	"model_output_failure":   Failed,
	"model_inability":        Failed,
	"refused":                Failed,
	"inference_failure":      Failed,
	"tool_failure":           Failed,
	"out_of_memory":          Failed,
	"step_limit":             Failed,
	"infrastructure_failure": Failed,
	"spending_exhausted":     NotTested,
	"cancelled":              NotTested,
	"insufficient_time":      NotTested,
	"running":                NotTested,
	"unattempted":            NotTested,
}

var resultWords = map[Result]string{
	Evidenced: "evidenced",
	Elsewhere: "cheated another way",
	NoIssue:   "no issue evidenced",
	Failed:    "error",
	Unsettled: "result unclear",
	NotTested: "not tested",
}
