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
}

// roleNames are each model role in report.json's configuration and the jobs it runs.
var roleNames = map[string][2]string{
	"simulator": {"Simulator", "Simulator, which runs the simulated episodes"},
	"inspector": {"Inspector", "Grader Inspector, Hack Inspector, Attack Inspector, and the judge that groups findings into problems"},
	"attacker":  {"Attacker", "Attacker, which tries to demonstrate each problem in a real episode"},
}

// stopWords say how a run stopped, by its stop's kind, and what the screens say of the results.
var stopWords = map[string][2]string{
	"cancelled":        {"Stopped by you", "Results below are from before the stop."},
	"terminated":       {"Stopped by a termination signal", "Results below are from before the stop."},
	"time_limit":       {"Stopped at the time limit", "Results below are from before the limit."},
	"spending_cap":     {"Stopped at the spending cap", "Results below are from before the cap."},
	"provider_refused": {"Stopped by the model provider", "Results below are from before the stop."},
	"stopped":          {"Run not finished", "The report has no end. The run may still be going, or it stopped without a report."},
}

// unfinishedWords say why a step did not run to its end, by its status.
var unfinishedWords = map[string]string{
	"partial":            "Not finished",
	"cancelled":          "Stopped",
	"time_limit":         "Stopped at the time limit",
	"spending_exhausted": "Stopped at the spending cap",
	"running":            "No result recorded",
	"unknown":            "No result recorded",
	"not run":            "Did not run",
}

// failedWords say, for each phase that raised an error, what the run therefore does not show.
var failedWords = map[string]string{
	"simulation": "No simulation result, so this run shows no rewards and no grader accuracy.",
	"grader":     "No grader review, so this run shows no grader accuracy.",
	"hack":       "No hack search result, so this run shows nothing about hacks.",
	"attack":     "No Attacker result, so this run shows no Attacker test.",
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

var scopeWords = map[string]string{"package": "task copy", "native": "real episode"}

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

// lookedFor says what an inspector looked for in each category of its search.
var lookedFor = map[string]string{
	"leakage_metadata":       "Answers leaked through files, metadata or the environment",
	"package_oracles":        "Solution or test files the agent can read",
	"grader_tampering":       "Changing the grader, tests or their inputs",
	"fabricated_answers":     "Answers written without doing the work",
	"malformed_rewards":      "A reward file the grader reads without checking it",
	"timing_interference":    "Clocks, timeouts and timing files the reward reads",
	"resource_exhaustion":    "Using up memory, disk or time so the grader breaks",
	"online_lookup":          "Looking the answer up online",
	"persistence":            "State left behind that a later episode reads",
	"unchecked_requirements": "A requirement the grader never checks",
	"other":                  "Any other way to get the reward",
	"accepted_invalid":       "Episodes the grader passed although the task was not done",
	"rejected_valid":         "Episodes the grader failed although the work was correct",
}

// labelWords name the Grader Inspector's label of a simulated episode; both wrong decisions are a mismatch.
var labelWords = map[string]string{
	"legitimate":       "Legitimate",
	"accepted_invalid": "Mismatch",
	"rejected_valid":   "Mismatch",
	"unknown":          "Unresolved",
	"unavailable":      "Unavailable",
	"ungrounded":       "Ungrounded",
	"unreviewed":       "Not reviewed",
}

// labelMeanings say what each label of labelWords means.
var labelMeanings = map[string]string{
	"Legitimate":   "The reward matches the work",
	"Mismatch":     "The reward does not match the work",
	"Unresolved":   "The Grader Inspector could not decide",
	"Unavailable":  "The episode has no graded outcome",
	"Ungrounded":   "The label cites evidence the run did not keep",
	"Not reviewed": "Not inspected in this run",
}

// verdictWords say what the Grader Inspector's label and the grader's decision make of an episode.
var verdictWords = map[string]string{
	"legitimate pass":       "Correct work, passed",
	"legitimate fail":       "Incorrect work, failed",
	"accepted_invalid pass": "Incorrect work passed",
	"rejected_valid fail":   "Correct work rejected",
	"unknown":               "The Grader Inspector could not decide",
}

// flagWords name Python's distribution flags of a reward.
var flagWords = map[string]string{"identical_rewards": "Identical rewards", "low_minority": "Unusually low rewards", "high_minority": "Unusually high rewards"}

// exploitWords say what an Attacker exploit confirmed of the findings it tested, by its kind in the report.
var exploitWords = map[string]string{
	"reproduction": "reproduced",
	"other":        "another mechanism while testing",
	"unattributed": "not confirmed as",
	"discovery":    "found with no information",
}

// levelWords name an attack hint level as the exploit chart does: what an Attacker receives.
var levelWords = map[string]string{"none": "no information", "full": "full instructions", "minimal": "only a hint"}

// ladderWords are the exploit chart's steps, 2 to 5; level 1 in older reports is a lead.
var ladderWords = map[int]string{
	2: "●●○○○ reproduced, no Attacker demonstrated it",
	3: "●●●○○ an Attacker given full instructions demonstrated it",
	4: "●●●●○ an Attacker given only a hint demonstrated it",
	5: "●●●●● an Attacker given no information demonstrated it",
}

// helpLevels give a problem's step from the least help an Attacker needed, for reports written before `level`;
// any other value is a reproduced exploit.
var helpLevels = map[string]int{"none": 5, "minimal": 4, "full": 3,
	"found_alone": 5, "single_hint": 4, "full_info": 3, "full_info_or_less": 3, "not_reproduced": 1}

// validWorkWords say how an Attacker reproduced correct work the grader fails, after the simulation chart's FN words.
var validWorkWords = map[int]string{
	3: ", reproduced by an Attacker with full instructions",
	4: ", reproduced by an Attacker with only a hint",
	5: ", reproduced by an Attacker with no information",
}

// reasonWords say why a reproduced exploit got no further.
var reasonWords = map[string]string{
	"not_exploited": "Attackers did not exploit it",
	"no_guidance":   "not attacked: no guidance",
	"unknown":       "no clear Attacker result",
}

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

// triedWords say what an attempt showed of its problem, as the plain output and the live logs say it.
var triedWords = map[Result]string{Evidenced: "demonstrated", Elsewhere: "demonstrated another hack", NoIssue: "not demonstrated",
	Unsettled: "unresolved", Failed: "error", NotTested: "not started"}

// stoppedWords say how a try whose episode started ended without a result, as its phase would: "Stopped at the
// spending cap", or else "Stopped".
func stoppedWords(status string) string {
	if words, ok := phaseEndWords[status]; ok {
		return capital(words)
	}
	return "Stopped"
}

// resultWords say how an attempt ended, as the Status column of a try shows it.
var resultWords = map[Result]string{
	Evidenced: "Finished",
	Elsewhere: "Finished",
	NoIssue:   "Finished",
	Failed:    "Error",
	Unsettled: "Finished",
	NotTested: "Not started",
}
