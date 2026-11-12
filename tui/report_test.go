package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are written by testdata/make_reports.py with nudi's own report code, except full-0.0.0,
// a report in the shape nudi 0.0.0 wrote, and pipeline-full, written by hand with problems formed during the run.
var fixtures = []string{"full", "full-0.0.0", "clean", "time-limit", "pipeline-full", "full-before-levels", "clean-before-levels",
	"time-limit-before-levels"}

func fixture(t *testing.T, name string) Report {
	t.Helper()
	r, err := load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func writeReport(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadRefusesWhatItCannotRead(t *testing.T) {
	for body, want := range map[string]string{
		"":                                    "has no report.json",
		`{"status": "complete"}`:              "older than 0.0.0",
		`{"status": "complete", "answer": 3}`: "cannot unmarshal",
		`{"status"`:                           "unexpected end",
		`{"answer": []}`:                      "has no answer lines",
		`{"answer": ["x"], "metrics": {"confusion": [{"false_discovery_rate": {"value": 0.5, "numerator": null, "denominator": 2}}]}}`: "a rate without its counts",
		`{"answer": ["x"], "metrics": {"confusion": [{"false_negative_rate": {"value": 0.5, "numerator": 1}}]}}`:                       "a rate without its counts",
		`{"answer": ["x"], "metrics": {"confusion": [{"pass_rate": {"value": 0.5, "denominator": 2}}]}}`:                               "a rate without its counts",
	} {
		dir := t.TempDir()
		if body != "" {
			dir = writeReport(t, body)
		}
		if _, err := load(dir); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
}

// Python writes null for a statistic it cannot give; those reports still load.
func TestLoadKeepsLegitimateNulls(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "configuration": {"known_cost": null, "spending_cap": null, "modal_cost": null},
		"metrics": {"confusion": [{"status": "unavailable", "rule": null, "tp": null, "fp": null, "fn": null, "tn": null,
		"false_discovery_rate": {"value": null, "numerator": null, "denominator": null, "unavailable": "no rule"},
		"false_negative_rate": {"value": null, "numerator": null, "denominator": null, "unavailable": "no rule"}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := plainReport(r, 100); strings.Contains(s, "$0.00") || !strings.Contains(oneLine(s), "Model cost unavailable") {
		t.Fatalf("an absent cost is shown as a number:\n%s", s)
	}
	if s := header(r, false, 100); strings.Contains(s, "$0.00") {
		t.Fatalf("header: %q", s)
	}
}

// A call cancelled in flight is counted apart from one without a price.
func TestCostCountsCancelledCallsApart(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "configuration": {"known_cost": 1.5, "unknown_cost_calls": 2, "cancelled_calls": 1}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := oneLine(plainText(strings.Join(costRows(r, 100, true), "\n")))
	if !strings.Contains(s, "Calls without a price 2 Not counted in model cost") || !strings.Contains(s, "Calls cancelled in flight 1") {
		t.Fatalf("cost rows:\n%s", s)
	}
}

// The Modal estimate names each figure and where the bill comes from.
func TestCostNamesEachModalFigure(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "configuration": {"known_cost": 1.5, "modal_cost": {"at_requests": 0.37, "at_limits": 6.69}}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := oneLine(plainText(strings.Join(costRows(r, 300, true), "\n")))
	for _, want := range []string{"Modal sandbox estimate $0.37 to $6.69", "At requested CPU and memory, then at their limits", "separate from the cap", "Run nudi cost " + r.Dir} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
}

func TestLoadStaysInRunFolder(t *testing.T) {
	outside := writeReport(t, `{"answer": ["outside"]}`)
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "report.json"), filepath.Join(dir, "report.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := load(dir); err == nil {
		t.Fatal("a report.json linked from outside the run folder was read")
	}
	if code, out, _ := run(dir); code != 2 || strings.Contains(out, "outside") {
		t.Fatalf("exit %d: %q", code, out)
	}
}

// The folder name comes from the command line, so what is shown of it is cleaned as report text is.
func TestFolderNameIsCleaned(t *testing.T) {
	body, err := os.ReadFile("testdata/full/report.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "run-\u0007\u202e")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(dir)
	if code != 0 || strings.ContainsAny(out, "\u0007\u202e") || !strings.Contains(out, "run- P1") {
		t.Fatalf("exit %d:\n%q", code, out)
	}
	code, _, errs := run(dir+"-none", "1")
	if code != 2 || strings.ContainsAny(errs, "\u0007\u202e") || !strings.Contains(errs, "run--none has no report.json") {
		t.Fatalf("exit %d: %q", code, errs)
	}
}

func TestLoadDropsControlCharacters(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["ok\u001b[2J\u0007 then\ttab"], "configuration": {"task_dir": "a\rb"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Answer[0] != "ok[2J then\ttab" || r.task() != "ab" {
		t.Fatalf("%q %q", r.Answer[0], r.task())
	}
}

// Model-written text can sit in a map key, such as a category, as well as in a value.
func TestLoadCleansKeysAndValues(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["a\u202eb\u001b]0;title\u0007c"], "analyses": {"hack": "complete"},
		"inspections": {"hack_inspector": {"categories": {"x\u001b[31my\u202ez": "evidenced_issue"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	categories := r.Inspections["hack_inspector"].Categories
	if r.Answer[0] != "ab]0;titlec" || categories["x[31myz"] != "evidenced_issue" || len(categories) != 1 {
		t.Fatalf("%q %q", r.Answer[0], categories)
	}
	for _, s := range []string{plainReport(r, 100), drawTab(r, 2, 100)} {
		if strings.ContainsAny(s, "\u202e\u0007") || strings.Contains(s, "\x1b]") || strings.Contains(s, "x\x1b[31my") {
			t.Fatalf("%q", s)
		}
	}
}

func TestFindingsAreCurrentEvidencedInSourceOrder(t *testing.T) {
	var got []string
	for _, f := range fixture(t, "full").findings() {
		got = append(got, f.Source+" "+f.ID)
	}
	want := "grader_inspector grader-12,grader_inspector grader-13,hack_inspector hack-1,hack_inspector hack-2," +
		"hack_inspector hack-3,hack_inspector hack-4,attack check-0005,attack check-0006,attack check-0011"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %s", strings.Join(got, ","))
	}
}

// How the run ended, its time, cost and capacity come as data; a report written before a field reads it as not recorded.
func TestLoadReadsRunFactsAndOlderReportsLackThem(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "unfinished": {"hack": "cancelled"}, "unresolved": ["grader"], "elapsed": 760.5,
		"stop": {"kind": "time_limit", "phase": "hack", "minutes": 30, "reason": null}, "phase_errors": {"attack": "RuntimeError: boom"},
		"ungrouped": ["grader-1"], "configuration": {"capacity": {"concurrency": 12}, "unknown_reasons": {"no price": 3},
		"modal_cost": {"at_requests": 0.31, "at_limits": 0.41, "sandboxes": 5, "without_limits": 1, "still_running": 2}}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := r.Configuration
	if r.Unfinished["hack"] != "cancelled" || r.Unresolved[0] != "grader" || *r.Elapsed != 760.5 || r.PhaseErrors["attack"] != "RuntimeError: boom" ||
		r.Ungrouped[0] != "grader-1" || c.Capacity.Concurrency != 12 || c.UnknownReasons["no price"] != 3 ||
		c.ModalCost.Sandboxes != 5 || c.ModalCost.WithoutLimits != 1 || c.ModalCost.StillRunning != 2 {
		t.Fatalf("%+v", r)
	}
	if s := r.Stop; s.Kind != "time_limit" || s.Phase != "hack" || *s.Minutes != 30 || s.Reason != "" {
		t.Fatalf("stop: %+v", s)
	}
	old := fixture(t, "full-0.0.0")
	if old.Elapsed != nil || old.Stop != nil || old.PhaseErrors != nil || old.Ungrouped != nil {
		t.Fatalf("an older report reads fields it lacks as recorded: %+v", old)
	}
	if s := fixture(t, "time-limit").Stop; s == nil || s.Kind != "time_limit" || s.Minutes != nil {
		t.Fatalf("time-limit stop: %+v", s)
	}
}

// The screens' tables read Python's facts: problem outcomes, condition counts, flag rules, per-episode rewards and
// labels, open questions, the no-hint search and each attempt's reward.
func TestLoadReadsTheFactsTheScreensTabulate(t *testing.T) {
	r := fixture(t, "full")
	ps := r.Attack.Problems
	if r.SchemaVersion != 3 || ps[0].ID != "P1" || ps[0].Finding != "hack-1" || ps[0].Outcome != "accepted_invalid" || ps[0].Type != nil ||
		ps[1].ID != "P2" || ps[1].Outcome != "rejected_valid" || ps[1].Reason == nil || ps[0].Conditions[0].Attempts != 1 || ps[0].Conditions[0].Status == "" {
		t.Fatalf("problems: %+v", ps)
	}
	if at := r.Attack.Attempts; at[0].Status != "evidenced_issue" || *at[0].Assessment != 0 || at[3].Status != "no_evidenced_issue" {
		t.Fatalf("attempts: %+v", at)
	}
	if strings.Join(r.Ungrouped, ",") != "hack-3,grader-12,grader-13" {
		t.Fatalf("ungrouped: %v", r.Ungrouped)
	}
	group := r.Ordinary.Groups[0]
	flag := group.Rewards["reward"].Flags[0]
	if *flag.Flag != "low_minority" || len(flag.Quartiles) != 2 || *flag.Fence != 1 || *flag.Minimum != 10 || len(flag.Recorded) != 2 ||
		len(flag.Episodes) != 2 || flag.Recorded[flag.Episodes[0]].Errors == nil {
		t.Fatalf("flag: %+v", flag)
	}
	if len(group.Episodes) != 12 || len(group.EpisodeRewards) != 12 || *group.EpisodeRewards[group.Episodes[0]]["reward"] != 1 {
		t.Fatalf("episodes: %+v", group)
	}
	if r.Labels.Episodes[group.Episodes[0]].Label == "" || r.Labels.Review.Attempted == nil || r.Metrics.Coverage.Eligible != 6 ||
		r.Metrics.Coverage.Ordinary != 12 || r.Metrics.Episodes[group.Episodes[0]].Completion == "" {
		t.Fatalf("labels %+v metrics %+v", r.Labels, r.Metrics.Coverage)
	}
	hack := r.Inspections["hack_inspector"]
	if hack.Open == nil || hack.Experiments[0].ID == "" || hack.Experiments[0].Status == "" {
		t.Fatalf("hack inspection: %+v", hack)
	}
	a := r.Attack
	if a.Discovery == nil || a.Discovery.Status == "" || a.Attempts[0].Number != 1 || *a.Attempts[0].Rewards["reward"] != 1 ||
		a.Exploits["reproduction"][0].Attempt == nil {
		t.Fatalf("attack: %+v", a)
	}
}
