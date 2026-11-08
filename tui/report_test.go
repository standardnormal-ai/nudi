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
	if s := card(r, 100, false); strings.Contains(s, "$0.00") || !strings.Contains(s, "known model cost unavailable") {
		t.Fatalf("an absent cost is shown as a number:\n%s", s)
	}
	if s := header(r, 100); strings.Contains(s, "$0.00") {
		t.Fatalf("header: %q", s)
	}
}

// A call cancelled in flight is counted apart from one without a price.
func TestCostLineCountsCancelledCallsApart(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "configuration": {"known_cost": 1.5, "unknown_cost_calls": 2, "cancelled_calls": 1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := costLine(r); !strings.Contains(s, "2 calls without a price · 1 call cancelled in flight") {
		t.Fatalf("cost line: %q", s)
	}
}

// The Modal estimate names each figure and where the bill comes from.
func TestCostLineNamesEachModalFigure(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "configuration": {"known_cost": 1.5, "modal_cost": {"at_requests": 0.37, "at_limits": 6.69}}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "Modal sandboxes about $0.37 at requested CPU and memory, $6.69 if all used their limits; outside the cap; bill: nudi cost " + r.Dir
	if s := costLine(r); !strings.Contains(s, want) {
		t.Fatalf("cost line: %q", s)
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
	for _, s := range []string{card(r, 100, true), renderPhase(r, nil, 2, 100)} {
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
	want := "grader_inspector grader-6,grader_inspector grader-7,hack_inspector hack-1,hack_inspector hack-2," +
		"hack_inspector hack-3,hack_inspector hack-4,attack check-0005,attack check-0006,attack check-0011"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %s", strings.Join(got, ","))
	}
}

// A level the run did not request does not hide that a finding has no guidance for the requested ones.
func TestUntestedCountsFindingsWithoutGuidanceForRequestedLevels(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "attack": {"attempts": [], "candidates": [
		{"id": "hack-0", "conditions": {"full": {"status": "unavailable"}, "minimal": {"status": "not_requested"}}},
		{"id": "hack-1", "conditions": {"full": {"status": "unattempted"}, "minimal": {"status": "not_requested"}}},
		{"id": "hack-2", "conditions": {"full": {"status": "unavailable"}, "minimal": {"status": "unavailable"}}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := untested(r); s != "3 findings not tested, 2 of them without guidance" {
		t.Fatalf("untested: %q", s)
	}
}
