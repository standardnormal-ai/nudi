package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// causeIDs are each cause's id with its findings' ids, as "C1: P1 P3 A1".
func causeIDs(r Report) []string {
	var out []string
	for _, c := range r.Causes {
		ids := []string{}
		for _, f := range c.Findings {
			ids = append(ids, f.ID)
		}
		out = append(out, c.ID+": "+strings.Join(ids, " "))
	}
	return out
}

// A schema 4 report's causes hold their findings, in the order Results lists them and numbered so: by the heading of
// their type, best level first under each. Attacker findings get short refs, and a finding read as its cause stays out
// of the findings whose tries count.
func TestCausesLoad(t *testing.T) {
	r := fixture(t, "causes")
	want := []string{"C6: A1", "C1: hack-1 hack-3 A2", "C3: hack-4", "C4: grader-12", "C7: A3", "C2: hack-2", "C5: grader-13"}
	if got := causeIDs(r); !slices.Equal(got, want) {
		t.Fatalf("causes %v, want %v", got, want)
	}
	for i, c := range r.Causes {
		if c.N != i+1 || c.name() != fmt.Sprintf("Cause %d", i+1) {
			t.Errorf("cause %s numbered %d", c.ID, c.N)
		}
	}
	if slices.ContainsFunc(r.Attack.Problems, Problem.judged) || len(r.Attack.Problems) != 7 || r.Causes[4].Level != 0 {
		t.Errorf("findings whose tries count: %d", len(r.Attack.Problems))
	}
	if f := r.Causes[1].Findings[2]; !f.ReadAs || f.Finding != "0016-attacker" || f.CauseID != "C1" {
		t.Errorf("read as: %+v", f)
	}
}

// Older reports convert in one place: each problem is a cause of its own under its id, and a schema 3 cause row groups
// its problems, with its no-hint readings as findings read as it and its unattacked problems marked.
func TestOldReportsBecomeCauses(t *testing.T) {
	r := fixture(t, "full-schema3")
	want := []string{"P1: P1", "hack-3: hack-3", "P3: P3", "grader-12: grader-12", "P2: P2", "grader-13: grader-13"}
	if got := causeIDs(r); !slices.Equal(got, want) {
		t.Errorf("schema 3 without rows: %v", got)
	}
	if c := r.Causes[3]; c.N != 4 || strings.Contains(c.Cause, "unchecked") || c.Cause == "" {
		t.Errorf("an older cause named by a generic mechanism: %+v", c)
	}
	b := strings.Replace(readFixture(t, "full-schema3"), `"causes": []`, `"causes": [{"id": "C1", "cause": "The grader trusts PATH.", "level": 5,
		"label": "●●●●● exploit", "problems": ["P1", "P3"], "readings": ["0008-attacker"], "not_attacked": ["P3"]}]`, 1)
	r = loadBody(t, b)
	if got := causeIDs(r); got[0] != "C1: P1 P3 A1" || len(got) != 5 {
		t.Fatalf("schema 3 rows: %v", got)
	}
	c := r.Causes[0]
	if f := c.Findings[1]; !f.notAttackedAlone() || c.Findings[0].ReadAs {
		t.Errorf("not attacked: %+v", f)
	}
	if f := c.Findings[2]; !f.judged() || f.Level != 5 || f.Cause == "" {
		t.Errorf("reading: %+v", f)
	}
	if r := fixture(t, "full-0.0.0"); r.Causes != nil {
		t.Errorf("a report without problems has causes: %v", causeIDs(r))
	}
}

// Results lists the causes under the headings of their type, one row per cause numbered 1 to the count; Enter on a
// cause of one finding opens it, and a cause of several expands into its findings, each by its short name and no id:
// the cause counts those not attacked on their own, and one read as the cause keeps its own level. A cause with only a
// finding judged to use it has no level of its own.
func TestCauseRows(t *testing.T) {
	r := fixture(t, "causes")
	s := plainTab(r, results, "none")
	c2 := oneLine(rowsAfter(s, "2  The grader trusts whatever", 3))
	if !strings.Contains(oneLine(row(s, "Incorrect Work Passed (5)")), "e expand Hint Full") || !strings.Contains(oneLine(row(s, "Correct Work Failed (2)")), "Hint Full") ||
		strings.Contains(s, "Causes (") || strings.Contains(s[:strings.Index(s, "Abandoned")], "Type") || strings.Contains(s[:strings.Index(s, "Abandoned")], "work passed") ||
		!strings.Contains(c2, "●●●●○") || !strings.Contains(c2, "3 findings, 1 not attacked on its own") || strings.Contains(s, "No info") {
		t.Errorf("rows:\n%s", s)
	}
	for _, id := range []string{"C1", "C6", "hack-", "A1"} {
		if strings.Contains(s[:strings.Index(s, "Abandoned")], id) {
			t.Errorf("a cause row shows the code %s:\n%s", id, s)
		}
	}
	if strings.Index(s, "5  A stale marker") > strings.Index(s, "Correct Work Failed") || strings.Index(s, "6  Answers") < strings.Index(s, "Correct Work Failed") {
		t.Errorf("groups:\n%s", s)
	}
	if strings.Contains(oneLine(rowsAfter(s, "6  ", 1)), "findings") || strings.Contains(s, "Inspector  ") {
		t.Errorf("a cause of one finding:\n%s", s)
	}
	m := newModel(r, 0, false)
	m.page()
	c3 := slices.IndexFunc(m.items, func(it item) bool { return it.n > 0 }) + 2 // after causes 1 and 2
	if m.items[c3].key != "" || evidenceOf(m.found, r.Causes[2].Findings[0]) != m.items[c3].n {
		t.Errorf("a cause of one finding opens it: %+v", m.items)
	}
	if strings.Count(s, "not attacked") != 1 {
		t.Errorf("unattacked count:\n%s", s)
	}
	if c5 := oneLine(rowsAfter(s, "5  A stale", 4)); strings.Contains(c5, "●") || !strings.Contains(c5, "No level of its own, only findings associated to it") {
		t.Errorf("no level:\n%s", s)
	}
	open := plainTab(r, results, "cause C1")
	rows := open[:strings.Index(open, "Abandoned")]
	if h1 := oneLine(rowsAfter(rows, "Edits grader or tests", 1)); h1 != "Edits grader or tests ✓ ✓ ●●●●○" {
		t.Errorf("finding row %q:\n%s", h1, open)
	}
	if h3 := oneLine(rowsAfter(second(rows, "Edits grader or tests"), "Edits grader or tests", 2)); h3 != "Edits grader or tests - - ●●○○○ not attacked on its own" {
		t.Errorf("not attacked on its own %q:\n%s", h3, open)
	}
	if a2 := oneLine(rowsAfter(rows, "A wrapper script", 2)); a2 != "A wrapper script returns 0. ●●●●● associated to this cause" || strings.Contains(rows, "Attacker,") {
		t.Errorf("read as %q:\n%s", a2, open)
	}
	if strings.Contains(rows, "hack-") || strings.Contains(rows, "A2") {
		t.Errorf("a finding row shows its code:\n%s", open)
	}
	if tally(r, r.findings()) == "" || !strings.Contains(plainText(tally(r, r.findings())), "7 causes") {
		t.Errorf("tally: %s", tally(r, r.findings()))
	}
}

// second is s from the line after the first that holds sub.
func second(s, sub string) string {
	i := strings.Index(s, sub)
	return s[i+strings.Index(s[i:], "\n")+1:]
}

// A run without Attacker tries attacked no finding, so no row says one was not attacked on its own.
func TestCauseRowsWithoutTries(t *testing.T) {
	_, r := edited(t, "causes", func(raw map[string]any) { raw["attack"].(map[string]any)["attempts"] = []any{} })
	if open := plainTab(r, results, "cause C1"); strings.Contains(open, "not attacked") || strings.Count(open, "Edits grader or tests") != 2 {
		t.Errorf("no tries:\n%s", open)
	}
}

// A finding row names its type only when it differs from its cause's.
func TestCauseFindingType(t *testing.T) {
	_, r := edited(t, "causes", func(raw map[string]any) { findingIn(raw, "hack-3")["outcome"] = "rejected_valid" })
	open := plainTab(r, results, "cause C1")
	if h3 := oneLine(rowsAfter(second(open, "Edits grader or tests"), "Edits grader or tests", 2)); !strings.Contains(h3, "not attacked on its own, Correct work failed") ||
		strings.Contains(oneLine(rowsAfter(open, "Edits grader or tests", 2)), "passed") {
		t.Errorf("type:\n%s", open)
	}
	if !strings.Contains(open, "Incorrect Work Passed (5)") {
		t.Errorf("a finding read as the cause sets its type:\n%s", open)
	}
}

// nudi-view RUN cause N opens cause N as Results numbers it, in any case and with or without the space; a plain N
// keeps opening finding N. The ids still work: C1 opens a cause of several findings, a cause of one finding or a
// finding id opens that finding.
func TestCauseArgument(t *testing.T) {
	r := fixture(t, "causes")
	found := r.findings()
	if n, cause, err := findingNumber(r, found, "C1"); n != 0 || cause != "C1" || err != nil {
		t.Errorf("C1: %d %q %v", n, cause, err)
	}
	c2 := r.Causes[slices.IndexFunc(r.Causes, func(c Cause) bool { return c.ID == "C2" })]
	if n, _, _ := findingNumber(r, found, "C2"); n == 0 || n != evidenceOf(found, c2.Findings[0]) {
		t.Errorf("C2 opens %d", n)
	}
	if n, _, _ := findingNumber(r, found, "A2"); n == 0 || found[n-1].Claim.Episode != "0016-attacker" {
		t.Errorf("A2 opens %d", n)
	}
	if _, _, err := findingNumber(r, found, "C9"); err == nil || err.Error() != "run has no cause or finding C9" {
		t.Errorf("C9: %v", err)
	}
	for _, words := range [][]string{{"cause", "2"}, {"Cause", "2"}, {"cause2"}, {"CAUSE 2"}} {
		if id, err := causeNumber(r, words); id != "C1" || err != nil {
			t.Errorf("%v: %q %v", words, id, err)
		}
	}
	// A plain number is a cause's number too, as Results shows it; rows show no finding numbers.
	if id, err := causeNumber(r, []string{"2"}); id != "C1" || err != nil {
		t.Errorf("a plain number is a cause number: %q %v", id, err)
	}
	if id, err := causeNumber(fixture(t, "clean"), []string{"1"}); id != "1" || err != nil {
		t.Errorf("a report without causes keeps finding numbers: %q %v", id, err)
	}
	if _, err := causeNumber(r, []string{"cause", "8"}); err == nil || err.Error() != "run has 7 causes; N must be 1 to 7" {
		t.Errorf("cause 8: %v", err)
	}
	if _, err := causeNumber(r, []string{"cases", "2"}); err == nil {
		t.Error("two words that are not cause N")
	}
	_, out, _ := run("testdata/causes", "C1")
	if !strings.HasPrefix(out, "  Cause 2  The grader trusts") || !strings.Contains(oneLine(out), "A wrapper script returns 0.") || strings.Contains(out, "CAUSES") || strings.Contains(out, "hack-1") {
		t.Errorf("piped C1:\n%s", out)
	}
	for _, words := range [][]string{{"cause", "2"}, {"2"}} {
		if _, by, _ := run(append([]string{"testdata/causes"}, words...)...); by != out {
			t.Errorf("piped %v:\n%s", words, by)
		}
	}
	if _, one, _ := run("testdata/causes", "1"); !strings.Contains(one, "Results › Cause 1 ›") {
		t.Errorf("piped 1, a cause of one finding, opens that finding:\n%s", one)
	}
	if _, id, _ := run("testdata/causes", "hack-1"); !strings.Contains(id, "REFERENCES") {
		t.Errorf("piped hack-1 opens that finding:\n%s", id)
	}
	if code, _, errOut := run("testdata/causes", "cause", "0"); code != 2 || !strings.Contains(errOut, "N must be 1 to 7") {
		t.Errorf("cause 0: %d %s", code, errOut)
	}
	m := newModel(r, 0, false).openCause("C1")
	if !m.open["4cause C1"] || m.items[m.sel[results]].key != "cause C1" {
		t.Errorf("opened cause: %v", m.open)
	}
}

// Piped cause output gives each finding the timeline of its screen, one step per fact that exists, in order: who found
// it, what it breaks, its reward, nudi's check, its cause, the Attacker's result at each help it was given, its level.
func TestCauseTimeline(t *testing.T) {
	_, out, _ := run("testdata/causes", "cause", "2")
	first := out[strings.Index(out, "Edits grader or tests"):strings.Index(out, "level")]
	var steps []string
	for _, l := range strings.Split(first, "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[0] == "◆" {
			steps = append(steps, f[1])
		}
	}
	if !slices.Equal(steps, []string{"issue", "requires", "reward", "nudi", "cause", "hint", "full"}) {
		t.Errorf("steps %v:\n%s", steps, out)
	}
	for _, want := range []string{"◆ issue Hack Inspector, task copy", "◆ cause associated to cause 2", "◆ hint Attacker demonstrated it, reward 1 Try 14",
		"◆ full Attacker demonstrated it, reward 1 Try 7", "◆ level 4 of 5", "◆ attacker not attacked on its own", "◆ cause associated to cause 2",
		"◆ no info Attacker demonstrated it, reward 1 Try 16"} {
		if !strings.Contains(oneLine(out), want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	for _, gone := range []string{"Found by", "Evidence ", "Attacker  ", "0007-attacker", "Help "} {
		if strings.Contains(out, gone) {
			t.Errorf("the timeline repeats %q:\n%s", gone, out)
		}
	}
	if strings.Count(out, "not attacked on its own") != 1 {
		t.Errorf("not attacked said more than once:\n%s", out)
	}
}

// The Attack tab groups tries by cause, numbered as on Results; each try is named by its number, and the no-hint try
// read as a cause names it.
func TestAttackByCause(t *testing.T) {
	r := fixture(t, "causes")
	s := plainTab(r, 3, "none")
	if strings.Contains(oneLine(row(s, "Cause ")), "Ref") || !strings.Contains(oneLine(rowsAfter(s, "2  The grader trusts whatever", 1)), "▸ 2 The grader trusts whatever") || strings.Contains(s, "C1") {
		t.Errorf("rows:\n%s", s)
	}
	if !strings.Contains(oneLine(rowsAfter(s, "16 ", 1)), "✓ ✗ Cause 2") {
		t.Errorf("no-hint try read as cause 2:\n%s", s)
	}
	open := plainTab(r, 3, "tries C1 "+r.Causes[1].Cause)
	tries := rowsAfter(open, "2  The grader trusts whatever", 4)
	if !strings.Contains(oneLine(tries), "Try Help") || !strings.Contains(oneLine(tries), "7 Full ✓ Finished 1") || !strings.Contains(oneLine(tries), "14 Hint ✓") ||
		strings.Contains(open, "-attacker") || strings.Contains(tries, "16 ") {
		t.Errorf("cause 2's tries:\n%s", open)
	}
}

// The plain output lists causes by number with their findings beneath, each by its short name and its timeline; an
// older report's problems are numbered the same way.
func TestPlainCauses(t *testing.T) {
	s := plainReport(fixture(t, "causes"), plainW)
	if !strings.Contains(s, "CAUSES\n  An agent grouped the findings into causes; it can make mistakes.\n\n  Cause 1") || !strings.Contains(s, "\n  Cause 1  The agent writes") ||
		!strings.Contains(s, "\n      Edits grader or tests\n          Mechanism         The grader runs the task's copy") || !strings.Contains(s, "not attacked on its own") ||
		!strings.Contains(s, "◆ cause      associated to cause 2") || strings.Contains(s, "\nPROBLEMS") || !strings.Contains(s, "  Cause 6  Answers are compared as raw strings.\n      Mechanism ") ||
		strings.Contains(s[:strings.Index(s, "EVIDENCE")], "hack-") {
		t.Errorf("plain:\n%s", s)
	}
	if s := plainReport(fixture(t, "full-schema3"), plainW); !strings.Contains(s, "CAUSES\n  Cause 1  The test runs bash") || strings.Contains(s, "Finding     ") || strings.Contains(s, "unchecked requirement") {
		t.Errorf("older plain:\n%s", s)
	}
}

// The judge's cause event is a log line in words.
func TestLiveCauseEvent(t *testing.T) {
	l := &Live{}
	l.apply(Event{Kind: "cause", Text: "nudi: 10:00:00 the judge read P2's cause as C1, so no Attacker attacks P2 on its own"})
	if len(l.Recent) != 1 || !strings.Contains(plainText(l.logRow(l.Recent[0], 120)), "novelty_judge") ||
		!strings.Contains(plainText(l.logRow(l.Recent[0], 120)), "no Attacker attacks P2 on its own") {
		t.Errorf("cause event: %v", l.Recent)
	}
}

// rowsAfter is the line of s that contains prefix after its first non-space, with the n-1 lines after it.
func rowsAfter(s, prefix string, n int) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimLeft(l, " ›▸▾"), prefix) {
			return strings.Join(lines[i:min(len(lines), i+n)], "\n")
		}
	}
	return ""
}

// edited is fixture name loaded after edit changed its JSON, with the folder it is written to.
func edited(t *testing.T, name string, edit func(raw map[string]any)) (string, Report) {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal([]byte(readFixture(t, name)), &raw); err != nil {
		t.Fatal(err)
	}
	edit(raw)
	b, _ := json.Marshal(raw)
	dir := writeReport(t, string(b))
	r, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, r
}

// findingIn is the finding id under the causes of raw.
func findingIn(raw map[string]any, id string) map[string]any {
	for _, c := range raw["causes"].([]any) {
		for _, f := range c.(map[string]any)["findings"].([]any) {
			if f.(map[string]any)["id"] == id {
				return f.(map[string]any)
			}
		}
	}
	panic("no finding " + id)
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func loadBody(t *testing.T, body string) Report {
	t.Helper()
	r, err := load(writeReport(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A try given no information keeps the candidate of the slot it ran in, which it was not told: neither its row nor its
// exploit names that finding. A null attempt cause is no cause.
func TestNoInformationTryNamesNoSlotFinding(t *testing.T) {
	_, r := edited(t, "causes", func(raw map[string]any) {
		at := raw["attack"].(map[string]any)["attempts"].([]any)[4].(map[string]any)
		at["candidate"], at["sources"], at["cause"] = "hack-2", []any{"hack-2"}, "C2"
		raw["attack"].(map[string]any)["attempts"].([]any)[5].(map[string]any)["cause"] = nil
		e := raw["attack"].(map[string]any)["exploits"].(map[string]any)["discovery"].([]any)[0].(map[string]any)
		e["candidate"], e["sources"] = "hack-2", []any{"hack-2"}
	})
	for _, row := range attemptRows(r, 120) {
		if strings.HasPrefix(strings.TrimSpace(row), "0016-attacker") && strings.Contains(row, "hack-2") {
			t.Errorf("slot finding named: %s", row)
		}
	}
	i := slices.IndexFunc(r.findings(), func(f Finding) bool { return ref(f) == "0016-attacker" })
	if i < 0 {
		t.Fatal("no 0016-attacker evidence")
	}
	if got := r.findings()[i].Confirms; got != "found with no information" {
		t.Errorf("confirms %q", got)
	}
}

// A folded cause row shows its sentence on one line, cut with "…" on a word boundary; opening the cause shows it in
// full. The Attack tab's cause rows do the same, and the plain report keeps the sentence whole.
func TestFoldedCauseSentenceIsOneLine(t *testing.T) {
	long := "The grader trusts whatever runs first on PATH, so a planted git binary in the writable conda environment rewrites the graded test patch before pytest reads it."
	_, r := edited(t, "causes", func(raw map[string]any) {
		for _, c := range raw["causes"].([]any) {
			if c := c.(map[string]any); c["id"] == "C1" {
				c["cause"] = long
			}
		}
	})
	for _, w := range []int{60, 80, 120} {
		for _, tab := range []struct {
			s    int
			open string
		}{{results, "cause C1"}, {3, "tries C1 " + long}} {
			shut := plainText(drawTab(r, tab.s, w, "none"))
			line := row(shut, "▸ 2  The grader trusts whatever")
			i := strings.Index(shut, line)
			next := strings.TrimSpace(strings.SplitN(shut[i+len(line)+1:], "\n", 2)[0])
			if !strings.Contains(line, "…") || strings.Contains(line, "pytest reads it.") || strings.HasPrefix(next, "conda") || strings.HasPrefix(next, "environment") {
				t.Errorf("tab %d at %d, folded row %q, next %q", tab.s, w, line, next)
			}
			before, _, _ := strings.Cut(line, "…")
			words := strings.Fields(before)
			if strings.HasSuffix(before, " ") || !slices.ContainsFunc(strings.Fields(long), func(w string) bool { return strings.TrimRight(w, ",.") == words[len(words)-1] }) {
				t.Errorf("tab %d at %d, cut not at a word end: %q", tab.s, w, line)
			}
			open := plainText(drawTab(r, tab.s, w, tab.open))
			if first := row(open, "▾"); strings.Contains(first, "…") || !strings.Contains(oneLine(open), "before pytest reads it.") {
				t.Errorf("tab %d at %d, open row not in full", tab.s, w)
			}
		}
	}
	if !strings.Contains(oneLine(plainReport(r, 80)), long) {
		t.Error("plain report cut the sentence")
	}
}

// clip keeps a ref whole: it ends at the space before one rather than inside it.
func TestClipNeverInsideARef(t *testing.T) {
	for _, c := range []struct {
		s    string
		w    int
		want string
	}{
		{"abc hack-17 defgh", 10, "abc…"},
		{"aaaaaa bbbbbbbbbbbbb", 10, "aaaaaa…"},
		{"abcdefghijklmnop", 10, "abcdefghi…"},
		{"short", 10, "short"},
		{"abcdef gh ij", 10, "abcdef gh…"},
		{"one two, C4 three", 10, "one two…"},
	} {
		if got := clip(c.s, c.w); got != c.want {
			t.Errorf("clip(%q, %d) = %q, want %q", c.s, c.w, got, c.want)
		}
	}
}

// A finding is named by its own sentence; an older report's generic mechanism, a category name, reads as that
// category's label. A try is named by its session's number.
func TestNames(t *testing.T) {
	grader := "grader_tampering"
	for _, c := range []struct {
		mechanism string
		category  *string
		want      string
	}{
		{"unchecked requirement", nil, "Skips a requirement the grader never checks"},
		{"unchecked requirement", &grader, "Edits grader or tests"},
		{"grader_tampering", nil, "Edits grader or tests"},
		{"some_new_category", nil, "Some new category"},
		{"The grader trusts  PATH.", &grader, "The grader trusts PATH."},
		{"sorted", nil, "sorted"},
	} {
		if got := mechanismName(c.mechanism, c.category); got != c.want {
			t.Errorf("mechanismName(%q) = %q, want %q", c.mechanism, got, c.want)
		}
	}
	if !generic("unchecked requirement") || generic("The grader trusts PATH.") {
		t.Error("generic")
	}
	for ref, want := range map[string]string{"0007-attacker": "Try 7", "0016-attacker": "Try 16", "sandbox-0000": "sandbox-0000", "0004-simulator": "0004-simulator"} {
		if got := sessionName(ref); got != want {
			t.Errorf("sessionName(%q) = %q", ref, got)
		}
	}
}

// Abandoned Findings names each by its own sentence on one line, cut with "…", or an older report's by its category's
// label; the Ref column shows only for rows that do not open, and a row that opens has no ref.
func TestAbandonedNames(t *testing.T) {
	for _, w := range []int{60, 80, 120} {
		s := plainText(drawTab(fixture(t, "full"), results, w, "o"))
		rows := s[strings.Index(s, "Abandoned Findings"):strings.Index(s, "Suspected findings")]
		if !strings.Contains(rows, "Ref") || !strings.Contains(rows, "The rewar") || !strings.Contains(rows, "grader-0") || strings.Contains(rows, "unchecked") {
			t.Errorf("at %d:\n%s", w, rows)
		}
		if w < 120 && !strings.Contains(rows, "…") {
			t.Errorf("no sentence cut at %d:\n%s", w, rows)
		}
	}
	old := plainTab(fixture(t, "full-schema3"), results, "o")
	if strings.Contains(old, "unchecked requirement") || !strings.Contains(old, "Skips a requirement the grader never checks") {
		t.Errorf("older names:\n%s", old)
	}
	r := fixture(t, "causes")
	r.Inspections, r.Attack.Leads = nil, nil
	delete(r.Attack.Findings, "legitimate")
	s := plainTab(r, results, "o")
	rows := s[strings.Index(s, "Abandoned Findings"):strings.Index(s, "Suspected findings")]
	if strings.Contains(rows, "Ref") || !strings.Contains(rows, "A wrapper script returns 0.") || strings.Contains(rows, "-attacker") {
		t.Errorf("rows that all open:\n%s", rows)
	}
}

// The finding screen gives the timeline the pipe gives, without the rows it would repeat; the help explains its marker,
// and nothing the viewer writes says "reading".
func TestFindingTimeline(t *testing.T) {
	r := fixture(t, "causes")
	found := r.findings()
	n := evidenceOf(found, r.Causes[1].Findings[0])
	s := plainShow(r, found, n, 100)
	evidence := s[strings.Index(s, "EVIDENCE"):strings.Index(s, "LIMITATIONS")]
	for _, want := range []string{"◆ issue Hack Inspector, task copy", "◆ cause associated to cause 2", "◆ hint Attacker demonstrated it, reward 1 Try 14", "◆ level 4 of 5"} {
		if !strings.Contains(oneLine(evidence), want) {
			t.Errorf("no %q:\n%s", want, s)
		}
	}
	head := s[:strings.Index(s, "EVIDENCE")]
	for _, gone := range []string{"Found by", "Evidence from", "Attacker result", "Help ", "Cause  ", "hack-1", "C1"} {
		if strings.Contains(head, gone) {
			t.Errorf("the head repeats %q:\n%s", gone, head)
		}
	}
	if !strings.Contains(head, "Results › Cause 2 › The grader trusts whatever runs first on PATH.") {
		t.Errorf("crumb:\n%s", head)
	}
	_, help, _ := run("--help")
	if !strings.Contains(plainText(helpPanel(100, false)), "A step in a finding's timeline") || strings.Contains(help+plainText(helpPanel(100, false)), "reading") {
		t.Errorf("help:\n%s", help)
	}
}
