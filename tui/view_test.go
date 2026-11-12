package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// renderAll draws every screen of r at two widths, with every row and section expanded, and checks that no line
// is wider than the window.
func renderAll(t *testing.T, r Report) {
	t.Helper()
	found := r.findings()
	for _, w := range []int{80, 120} {
		screens := []string{plainReport(r, w), modelsPanel(r, w), costPanel(r, w), helpPanel(w, false), helpPanel(w, true), drawTab(r, 0, w, "episodes")}
		for s := 0; s <= results; s++ {
			screens = append(screens, drawTab(r, s, w))
		}
		for n := range found {
			for tab := range 3 {
				screens = append(screens, renderShow(r, found, n+1, tab, "Results", w))
			}
		}
		for _, s := range screens {
			for _, line := range splitLines(s) {
				if width(line) > w {
					t.Errorf("%d columns at width %d: %q", width(line), w, ansi.Strip(line))
				}
			}
		}
	}
}

func TestEveryLabelHasWords(t *testing.T) {
	clear(missed)
	for _, name := range fixtures {
		renderAll(t, fixture(t, name))
	}
	if len(missed) > 0 {
		t.Fatalf("labels without words: %v", missed)
	}
}

// TestRealReports renders the run folders listed in NUDI_REPORTS, separated by the path list separator.
func TestRealReports(t *testing.T) {
	dirs := filepath.SplitList(os.Getenv("NUDI_REPORTS"))
	if len(dirs) == 0 {
		t.Skip("NUDI_REPORTS lists no run folders")
	}
	clear(missed)
	for _, dir := range dirs {
		r, err := load(dir)
		if err != nil {
			t.Fatal(err)
		}
		renderAll(t, r)
	}
	if len(missed) > 0 {
		t.Fatalf("labels without words: %v", missed)
	}
}

// drawTab draws tab s of r w columns wide with nothing selected and every row and section expanded, or only the ones
// named when open names some.
func drawTab(r Report, s, w int, open ...string) string {
	m := newModel(r, 0, false)
	m.w, m.screen = w, s
	if open == nil {
		open = []string{"o", "i", "s", "x", "e", "?", "p", "a"}
		m.page()
		for _, it := range m.items {
			open = append(open, it.key)
		}
	}
	for _, k := range open {
		m.open[fmt.Sprint(s)+k] = true
	}
	return m.tabPage(-1).String()
}

func plainTab(r Report, s int, open ...string) string {
	return plainText(drawTab(r, s, wideAt-1, open...))
}

func TestReportWithoutProblems(t *testing.T) {
	r := fixture(t, "full-0.0.0")
	if r.Attack.Problems != nil || r.problemOf("hack-1") != -1 {
		t.Fatalf("problems: %v", r.Attack.Problems)
	}
	for _, s := range []string{plainTab(r, 2), plainTab(r, 3), plainTab(r, results), plainReport(r, 120), plainShow(r, r.findings(), 3, 120)} {
		if strings.Contains(s, "\nPROBLEMS\n") || strings.Contains(s, "PROBLEMS (") || strings.Contains(s, "Problems (") || strings.Contains(s, "Who demonstrated it") {
			t.Errorf("a report without problems shows some:\n%s", s)
		}
	}
	if s := plainTab(r, 3); !strings.Contains(s, "Tries (2)") || !strings.Contains(s, "hack-1") || !strings.Contains(plainTab(r, results), "Findings (") {
		t.Errorf("attempts or findings are missing:\n%s", s)
	}
}

// A run stopped before the attack reached its candidate says so; nothing in it failed.
func TestStoppedRunSaysNotTested(t *testing.T) {
	r := fixture(t, "time-limit-before-levels")
	attack := plainTab(r, 3)
	for _, want := range []string{"Not started", "Not tested: stopped."} {
		if !strings.Contains(attack, want) {
			t.Errorf("attack panel lacks %q:\n%s", want, attack)
		}
	}
	for _, s := range []string{attack, plainReport(r, 120), plainShow(r, r.findings(), 1, 120)} {
		// The exploit chart's "reproduced, no Attacker demonstrated it" is the Hack Inspector's reproduction, which the
		// run did finish.
		s = strings.ReplaceAll(strings.ToLower(s), "reproduced, no attacker demonstrated it", "")
		for _, bad := range []string{"fail", "error", " reproduced", " attempted"} { // Python's warnings say "unattempted"
			if strings.Contains(s, bad) {
				t.Errorf("%q in:\n%s", bad, s)
			}
		}
	}
	if exitCode(r) != 1 || exitCode(fixture(t, "time-limit")) != 1 || exitCode(fixture(t, "full")) != 0 || exitCode(fixture(t, "clean-before-levels")) != 1 {
		t.Error("exit codes differ from Python's")
	}
}

func TestAgreementTable(t *testing.T) {
	grader := plainTab(fixture(t, "full"), 1)
	for _, want := range []string{
		"Type             Grader   Work was     Episodes",
		"True positive    Pass     Correct      ███████████████ 3",
		"False positive   Pass     Incorrect    █████ 1",
		"Counts as passed       reward ≥ 0.5",
		"False discovery rate   25%          1/4        Incorrect work among passed work",
		"False negative rate    25%          1/4        Rejected work among correct work",
		"Incorrect work passed     Episodes the grader passed although the task was not done   1",
	} {
		if !strings.Contains(grader, want) {
			t.Errorf("grader tab lacks %q:\n%s", want, grader)
		}
	}
}

// The grounded native pass rate stands with its 95% Wilson interval on the card and the Grade Simulations tab; a missing
// or unavailable rate reads unavailable with its reason, and an older one without its interval shows none.
func TestNativePassRate(t *testing.T) {
	r := fixture(t, "full")
	if s := oneLine(plainReport(r, 120)); !strings.Contains(s, "Pass rate 83%, 10/12, passed among scored episodes") || !strings.Contains(s, "95% interval 55% to 95%, Wilson interval") {
		t.Errorf("plain report:\n%s", s)
	}
	if s := oneLine(plainTab(r, 1)); !strings.Contains(s, "Pass rate 83% 10/12") || !strings.Contains(s, "95% interval 55% to 95% Wilson interval") {
		t.Errorf("grader tab:\n%s", s)
	}
	for rate, want := range map[string][2]string{
		``: {"Pass rate unavailable", "Pass rate unavailable"},
		`, "pass_rate": {"value": null, "numerator": null, "denominator": null, "unavailable": "native pass rate is unavailable: no source-grounded native decision rule", "interval": null}`: {
			"Pass rate unavailable native pass rate is unavailable: no source-", "Pass rate unavailable: native pass rate is unavailable: no source-grounded"},
		`, "pass_rate": {"value": 0.5, "numerator": 1, "denominator": 2}`: {"Pass rate 50% 1/2", "Pass rate 50%, 1/2"},
	} {
		r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"grader": "complete"},
			"metrics": {"confusion": [{"status": "unsupported", "reasons": ["r"]`+rate+`}]}}`))
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range []string{oneLine(plainTab(r, 1)), oneLine(plainReport(r, 100))} {
			if !strings.Contains(s, want[i]) || strings.Contains(s, "Wilson") {
				t.Errorf("%q: lacks %q:\n%s", rate, want[i], s)
			}
		}
	}
}

// Without grader agreement the pass rate still names its rule; a group without a rule names none.
func TestPassRateKeepsItsRuleWithoutAgreement(t *testing.T) {
	for _, status := range []string{"unsupported", "unavailable"} {
		for rule, want := range map[string]string{
			`, "rule": {"comparison": ">=", "threshold": 0.5, "pass_values": []}`: "Counts as passed reward ≥ 0.5",
			``: "Counts as passed no native decision rule",
		} {
			r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"grader": "complete"},
				"metrics": {"confusion": [{"reward": "reward", "status": "`+status+`", "reasons": ["r"]`+rule+`,
					"pass_rate": {"value": 0.6667, "numerator": 2, "denominator": 3}}]}}`))
			if err != nil {
				t.Fatal(err)
			}
			if s := oneLine(plainTab(r, 1)); !strings.Contains(s, want) || !strings.Contains(s, "Pass rate 67% 2/3") || !strings.Contains(s, "Not available: r") {
				t.Errorf("%s %q: lacks %q:\n%s", status, rule, want, s)
			}
		}
	}
}

func TestCategoriesShowOnlyWhatWasSearched(t *testing.T) {
	r, err := load(writeReport(t, `{"answer":["x"], "analyses":{"hack":"complete"}, "inspections":{"hack_inspector":{
        "categories":{"grader_tampering":"no_evidenced_issue","online_lookup":"unknown","persistence":"restricted"},
        "applicability":{"persistence":"the task resets nothing between episodes"},
        "attempts":[{"phase":"focused","number":1,"category":"grader_tampering","status":"no_evidenced_issue"}],
        "limits":["Search stopped at the spending cap."]}},
        "warnings":["hack inspector category online_lookup is unknown: network access ended before the probe"]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, 2, "s")
	for _, want := range []string{"Edits grader or tests     Changing the grader, tests or their inputs", "Not searched: Looks answer up online: no search attempt recorded",
		"Not searched: Files survive reset: the task resets nothing between episodes", "focused 1     Edits grader or tests         completed",
		"Search stopped at the spending cap."} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	if got := strings.Join(r.Warnings, " "); !strings.Contains(got, "network access ended before the probe") || strings.Contains(got, "is unknown") {
		t.Errorf("lost legacy reason or kept verdict: %s", got)
	}
	for _, verdict := range []string{"no_evidenced_issue", "is unknown", "restricted"} {
		if strings.Contains(s, verdict) {
			t.Errorf("shows %q: %s", verdict, s)
		}
	}
	legacy := fixture(t, "clean-before-levels")
	if !strings.Contains(strings.Join(legacy.Warnings, " "), "the task resets nothing between episodes") {
		t.Error("lost legacy exclusion")
	}
}

func TestOldReportsRenderWithoutCategoryVerdicts(t *testing.T) {
	for _, name := range fixtures {
		r := fixture(t, name)
		screens := []string{plainReport(r, 120), plainReport(r, 120)}
		for s := 0; s <= results; s++ {
			screens = append(screens, plainTab(r, s))
		}
		for _, s := range screens {
			for _, unwanted := range []string{"grader is safe", "inspector category ", "inspector categories ", "nothing found", "could not tell ·", " skipped"} {
				if strings.Contains(s, unwanted) {
					t.Errorf("%s shows %q:\n%s", name, unwanted, s)
				}
			}
		}
	}
}

func run(args ...string) (int, string, string) {
	var out, errs bytes.Buffer
	code := view(args, &out, &errs)
	return code, out.String(), errs.String()
}

func TestPipe(t *testing.T) {
	code, out, _ := run("testdata/full")
	if code != 0 || out != plainReport(fixture(t, "full"), plainW)+"\n" || strings.Contains(out, "\x1b") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "NEXT\n  nudi-view testdata/full P1\n") {
		t.Error("the plain report does not say what to run next")
	}
	code, out, _ = run("testdata/full", "6")
	// Finding 6 belongs to P3: the problem's cause names it, and its own mechanism stays on a line of its own.
	for _, want := range []string{"Results › The grader trusts a timing file the agent can write.", "Mechanism", "unchecked requirement", "Hack: the reward was earned without doing the task", "hack-4",
		"◆ open", "whether the timing file is read", "LIMITATIONS 3", "REFERENCES"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("exit %d, lacks %q:\n%s", code, want, out)
		}
	}
	if code, _, _ := run("testdata/clean-before-levels"); code != 1 {
		t.Errorf("partial run exits %d", code)
	}
	// Evidence left unresolved is a result: the run still ran every step.
	if code, _, _ := run("testdata/clean"); code != 0 {
		t.Errorf("complete run with unresolved evidence exits %d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	for args, want := range map[string]string{
		"testdata/none":    "testdata/none has no report.json",
		"testdata/full 10": "run has 9 findings; N must be 1 to 9",
		"testdata/full x":  "run has 9 findings; N must be 1 to 9",
		"testdata/clean 1": "run has no evidenced findings",
		"testdata/full P9": "run has no problem P9",
		"a b c":            "accepts between 1 and 2 arg(s)",
	} {
		code, out, errs := run(strings.Fields(args)...)
		if code != 2 || out != "" || !strings.Contains(errs, "nudi-view: "+want) {
			t.Errorf("%s: exit %d, %q %q", args, code, out, errs)
		}
	}
}

func press(m model, keys ...string) model {
	for _, k := range keys {
		next, _ := m.Update(keyMsg(k))
		m = next.(model)
	}
	return m
}

// keyMsg is the key press named k: a letter, or a named key such as enter or shift+tab.
func keyMsg(k string) tea.KeyPressMsg {
	codes := map[string]rune{"enter": tea.KeyEnter, "esc": tea.KeyEscape, "tab": tea.KeyTab, "left": tea.KeyLeft,
		"right": tea.KeyRight, "up": tea.KeyUp, "down": tea.KeyDown}
	if k == "shift+tab" {
		return tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	}
	if c, ok := codes[k]; ok {
		return tea.KeyPressMsg{Code: c}
	}
	return tea.KeyPressMsg{Text: k}
}

func TestKeys(t *testing.T) {
	m := newModel(fixture(t, "full"), 0, true)
	if m = press(m, "x"); m.intro != nil {
		t.Fatal("a key does not skip the intro")
	}
	if m.screen != results || !strings.Contains(m.View().Content, "gave reward the checks show the work did not earn") {
		t.Fatal("the viewer does not open on Results")
	}
	// Enter expands the first problem, P1; Down and Enter open its first evidence record, hack-1.
	m = press(m, "enter", "down", "enter")
	n := m.n
	if n < 1 || m.found[n-1].ID != "hack-1" || !strings.Contains(ansi.Strip(m.View().Content), "Results › "+detailName(m.r, m.found[n-1])) {
		t.Fatalf("finding %d", m.n)
	}
	m = press(m, "right", "right", "tab")
	if m.n != n+2 || m.tab != 1 || !strings.Contains(ansi.Strip(m.View().Content), "Results › "+detailName(m.r, m.found[n+1])) {
		t.Fatalf("finding %d tab %d", m.n, m.tab)
	}
	m = press(m, "esc", "tab", "tab", "tab")
	if m.n != 0 || m.screen != 2 || !strings.Contains(ansi.Strip(m.View().Content), "Find Hacks  ✓") {
		t.Fatalf("finding %d screen %d", m.n, m.screen)
	}
	for _, k := range []string{"m", "c", "?"} {
		if m = press(m, k); m.overlay != k {
			t.Fatalf("%s opens no panel", k)
		}
		if m = press(m, "esc"); m.overlay != "" {
			t.Fatalf("Esc does not close panel %s", k)
		}
	}
	if m = press(m, "s"); !strings.Contains(ansi.Strip(m.View().Content), "▾ Search Scope") {
		t.Fatal("s does not expand the search scope")
	}
	if m = press(m, "q"); !m.exited || m.View().Content != "" {
		t.Fatal("q does not quit")
	}
	if m := newModel(fixture(t, "full"), 6, false); !strings.Contains(ansi.Strip(m.View().Content), detailName(m.r, m.found[5])) {
		t.Fatal("N does not open on finding N")
	}
}

// oneLine joins wrapped text back into one line, so a test can look for a whole sentence.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// The rewards show Python's summaries and its flags, on the card and the Simulation screen; Python's reason as written
// is in the plain output.
func TestRewardSummariesAndFlags(t *testing.T) {
	r := fixture(t, "full")
	if s := oneLine(plainReport(r, 120)); !strings.Contains(s, "0.8333") || !strings.Contains(s, "2 episodes received 0; the other 10 received 1.") ||
		!strings.Contains(s, "2 of 12 usable 'reward' rewards are below the rest by the quartile rule") {
		t.Errorf("plain report:\n%s", s)
	}
	s := plainTab(r, 0, "?", "p")
	for _, want := range []string{
		"12/12                12          0.8333       1            0.3892       -2.055",
		"Reason for warning: A few rewards far below the rest",
		"A reward is unusually low when it is below Q1 - 3 x IQR.",
		"Q1 is 1 and Q3 is 1, so the fence is 1.",
		"0004-simulator   Correct work rejected",
		"No error, timeout or refusal in these episodes.",
		"nudi checks this only with 10 or more usable rewards.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("simulation tab lacks %q:\n%s", want, s)
		}
	}
	if s := oneLine(plainTab(fixture(t, "clean"), 0)); !strings.Contains(s, "Distribution flags are not evaluated for 'reward': 4 usable rewards, fewer than 10.") {
		t.Errorf("the reason flags were not evaluated is missing:\n%s", s)
	}
}

// A statistic Python could not give, or that an older report lacks, is unavailable, never zero.
func TestMissingRewardStatisticsAreUnavailable(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"simulation": "complete"}, "ordinary": {"requested": 1, "attempted": 1,
		"groups": [{"configuration": {"model": "m"}, "rewards": {"reward": {"attempted": 1, "usable": 1, "mean": 1.0, "sd": null,
		"median": null, "distribution": [[1.0, 1]]}}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, 0)
	if !strings.Contains(oneLine(s), "1/1 1 1 unavailable unavailable unavailable") || strings.Contains(s, " 0 ") {
		t.Errorf("rewards:\n%s", s)
	}
}

// A grader-N candidate is the grader inspector's finding with index N, as Python names it, so the attack names that finding's number.
func TestGraderCandidateNamesItsFinding(t *testing.T) {
	r := fixture(t, "full-before-levels")
	if show := plainShow(r, r.findings(), 2, 120); !strings.Contains(show, "grader-7") || !strings.Contains(show, "Problem 4 of 4") || !strings.Contains(show, "Attacker try 1, full instructions") {
		t.Errorf("finding 2:\n%s", show)
	}
}

// A pipe gets the report at most 100 columns wide: long text breaks at spaces with every word kept, and a path too
// long for its column moves whole to a line of its own, so the commands under NEXT can be copied.
func TestPlainCardKeepsItsWidth(t *testing.T) {
	long := strings.TrimSpace(strings.Repeat("the grader reads a file the agent can write ", 6))
	r, err := load(writeReport(t, `{"answer": ["x"], "warnings": ["`+long+`"], "attack": {"findings": {"evidenced": [
		{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "`+long+`"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Dir = "runs/" + strings.Repeat("x", 80)
	s := plainReport(r, plainW)
	for _, line := range splitLines(s) {
		if width(line) > plainW {
			t.Errorf("%d columns: %q", width(line), line)
		}
	}
	for _, want := range []string{"  Run directory\n      " + r.Dir + "\n", "\nNEXT\n  nudi-view " + r.Dir + " 1\n", "\n\nCOST\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\n\n\n") {
		t.Errorf("two blank lines in a row:\n%s", s)
	}
	flat := oneLine(s)
	for _, want := range []string{"1 " + long, "Run " + capital(long), "Evidence from Not recorded"} {
		if !strings.Contains(flat, want) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
}

// Each warning becomes a Work left row that says where, what and why, in Python's words; a warning about an attack
// candidate is dropped, since the problem's own row already says it. Control and format characters never reach the pipe.
func TestWarningsBecomeWorkLeftRows(t *testing.T) {
	s := plainReport(fixture(t, "full"), 120)
	for _, want := range []string{
		"  Grade Simulations   5 of 12 ordinary episodes\n                      Have no supported local label (unreviewed 5)",
		"  Attack              P2 Answers are compared as raw strings.\n                      With only a hint: no Attacker attempt recorded",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "warning") || strings.Contains(s, "attack candidate") {
		t.Errorf("a warning line is left over:\n%s", s)
	}
	if s := plainReport(fixture(t, "clean-before-levels"), 120); !strings.Contains(s, "  Find Hacks          Search limitation (persistence)\n                      The task resets nothing between episodes") {
		t.Errorf("clean report:\n%s", s)
	}
	r, err := load(writeReport(t, `{"answer": ["x"], "warnings": ["a\u001b[2Jb\u202ec ok", "two"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := plainReport(r, 100); !strings.Contains(s, "  Run                 A[2Jbc ok\n  Run                 Two\n") || strings.ContainsAny(s, "\u202e\u001b") {
		t.Errorf("warnings:\n%q", s)
	}
}

// An attack finding keeps what Python's exploits say it confirmed, on its screen and in the pipe.
func TestAttackTagsKeepWhatTheyConfirmed(t *testing.T) {
	r := fixture(t, "full-before-levels")
	c := oneLine(plainReport(r, 120))
	for _, want := range []string{
		"7 planted a bash shim that prints the pass marker Type Hack",
		"Attacker exploit Reproduced hack-1 (finding 3)",
		"Attacker exploit Reproduced hack-2 (finding 4)",
		"Attacker exploit Not confirmed as hack-1 (finding 3)",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("report lacks %q:\n%s", want, c)
		}
	}
	if s := plainShow(r, r.findings(), 9, 120); !strings.Contains(s, "\n Attacker exploit  Not confirmed as hack-1 (finding 3)\n") {
		t.Errorf("finding 9:\n%s", s)
	}
	attack := func(exploits string) string {
		return `{"answer": ["x"], "attack": {` + exploits + `"findings": {"evidenced": [
			{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m0"}},
			{"index": 1, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m1"}}]}}}`
	}
	for body, want := range map[string]string{
		attack(`"exploits": {"discovery": [{"assessment": 0, "candidate": null, "sources": []}]}, `): "m0 Type Hack: the reward was earned without doing the task Found by Attacker Evidence from Not recorded Reference no check Attacker exploit Found with no information 2 m1 Type Hack: the reward was earned without doing the task Found by Attacker Evidence from Not recorded Reference no check Attacker exploit Confirms no tested finding",
		attack(""): "Reference no check SIMULATION",
	} {
		r, err := load(writeReport(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if s := oneLine(plainReport(r, 100)); !strings.Contains(s, want) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
}

// A missing or null index, on a finding or an exploit entry, attributes nothing; an explicit index 0 is a real index.
func TestMissingReferencesAttributeNothing(t *testing.T) {
	attack := func(index0, exploits string) string {
		return `{"answer": ["x"], "attack": {"exploits": {"reproduction": [` + exploits + `]}, "findings": {"evidenced": [
			{` + index0 + `"assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m0"}},
			{"index": 1, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m1"}}]}}}`
	}
	unavailable := [2]string{"Confirmation unavailable", "Confirmation unavailable"}
	for body, want := range map[string][2]string{
		attack(`"index": 0, `, `{"assessment": 0, "sources": ["hack-5"]}`):    {"Reproduced hack-5", "Confirms no tested finding"},
		attack(`"index": 0, `, `{"assessment": 1, "sources": ["hack-5"]}`):    {"Confirms no tested finding", "Reproduced hack-5"},
		attack(`"index": 0, `, `{"sources": ["hack-5"]}`):                     unavailable,
		attack(`"index": 0, `, `{"assessment": null, "sources": ["hack-5"]}`): unavailable,
		attack(`"index": 0, `, `null`):                                        unavailable,
		attack(``, `{"assessment": 0, "sources": ["hack-5"]}`):                {"Confirmation unavailable", "Confirms no tested finding"},
		attack(`"index": null, `, `{"assessment": 0, "sources": ["hack-5"]}`): {"Confirmation unavailable", "Confirms no tested finding"},
	} {
		r, err := load(writeReport(t, body))
		if err != nil {
			t.Fatal(err)
		}
		for i, w := range want {
			if !strings.Contains(oneLine(plainShow(r, r.findings(), i+1, 100)), "Attacker exploit "+w) {
				t.Errorf("finding %d lacks %q:\n%s", i+1, w, plainShow(r, r.findings(), i+1, 100))
			}
		}
	}
	grader := func(index string) Report {
		r, err := load(writeReport(t, `{"answer": ["x"], "inspections": {"grader_inspector": {"findings": {"evidenced": [
			{`+index+`"assessment": {"outcome": "rejected_valid"}, "claim": {"mechanism": "g"}}]}}},
			"attack": {"candidates": [{"id": "grader-0", "valid_work": true}], "problems": [{"cause": "c", "findings": ["grader-0"], "candidate": "grader-0"}]}}`))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := grader(`"index": 0, `); r.findings()[0].ID != "grader-0" || r.problemOf("grader-0") != 0 {
		t.Errorf("index 0 is named %q", r.findings()[0].ID)
	}
	for _, index := range []string{``, `"index": null, `} {
		r := grader(index)
		found := r.findings()
		if found[0].ID != "grader index unavailable" || r.problemOf(found[0].ID) != -1 {
			t.Errorf("%q: named %q", index, found[0].ID)
		}
		if s := plainShow(r, found, 1, 100); strings.Contains(s, "grader-0") || strings.Contains(s, "Problem 1 of 1") {
			t.Errorf("%q: finding 1 is linked:\n%s", index, s)
		}
	}
}

// Absent or null flags, a null flag entry, or one without its name or reason read as unavailable, never as blank.
func TestMissingFlagDetailsAreUnavailable(t *testing.T) {
	rewards := func(flags string) string {
		return `{"answer": ["x"], "analyses": {"simulation": "complete"}, "ordinary": {"requested": 1, "attempted": 1, "groups": [{"configuration": {"model": "m"},
			"rewards": {"reward": {"attempted": 1, "usable": 1, "mean": 1.0, "distribution": [[1.0, 1]]` + flags + `}}}]}}`
	}
	for flags, want := range map[string]string{
		``:                                      "Pattern details unavailable.",
		`, "flags": null`:                       "Pattern details unavailable.",
		`, "flags": [null]`:                     "Pattern details unavailable.",
		`, "flags": [{"text": "t"}]`:            "Pattern details unavailable.",
		`, "flags": [{"flag": "low_minority"}]`: "Pattern details unavailable.",
		`, "flags": [{"flag": null, "text": "t"}]`: "Pattern details unavailable.",
		`, "flags": []`: "No pattern flagged.",
	} {
		r, err := load(writeReport(t, rewards(flags)))
		if err != nil {
			t.Fatal(err)
		}
		s := plainTab(r, 0)
		if !strings.Contains(s, want) || want == "No pattern flagged." && strings.Contains(s, "details unavailable") {
			t.Errorf("%q:\n%s", flags, s)
		}
	}
}

// An attempt not started for lack of time is not tested; one whose workspace ran out of memory, whose attack inspector ran out of steps,
// or whose episode ended without a reward, failed.
func TestAttackStopsHaveWords(t *testing.T) {
	for status, want := range map[string]Result{"insufficient_time": NotTested, "out_of_memory": Failed, "step_limit": Failed, "episode_failure": Failed} {
		clear(missed)
		if res, _ := lookup(attemptResults, status); res != want || missed[status] {
			t.Errorf("%s shows as %v", status, res)
		}
	}
}

func TestBroadSearchExcludesRestrictionsButKeepsMeasuredWork(t *testing.T) {
	r, err := load(writeReport(t, `{"answer":["x"],"analyses":{"hack":"complete"},"inspections":{"hack_inspector":{
        "categories":{"online_lookup":"unknown","persistence":"restricted"},
        "attempts":[{"phase":"broad","status":"no_evidenced_issue"}],
        "limits":["stopped before sessions ended, so they are unknown"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	in := r.Inspections["hack_inspector"]
	s := plainTab(r, 2, "s")
	if !strings.Contains(s, "Looks answer up online    Looking the answer up online") || strings.Contains(s, "Not searched: Looks answer up online") ||
		!strings.Contains(s, "Not searched: Files survive reset") || strings.Contains(s, "so they are unknown") {
		t.Fatal(s)
	}
	in.Experiments = append(in.Experiments, Experiment{Category: "persistence"})
	if s := plainTab(r, 2, "s"); strings.Contains(s, "Not searched") {
		t.Fatal(s)
	}
}

// A problem id opens the finding that shows it, and the finding's screen names its problem by that id.
func TestViewOpensAProblemById(t *testing.T) {
	code, out, _ := run("testdata/pipeline-full", "P2")
	if code != 0 || !strings.Contains(out, "hack-2") || !strings.Contains(out, " Problem           P2 ") || !strings.Contains(out, "Attacker result    Reproduced with full instructions\n") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if code, _, errs := run("testdata/pipeline-full", "P9"); code != 2 || !strings.Contains(errs, "run has no problem P9") {
		t.Errorf("exit %d, %q", code, errs)
	}
}

// Each Attacker finding belongs to the problem its own exploit entry names, also when one session holds exploits of
// two problems and so is a member of both.
func TestAttackFindingsFollowTheirOwnExploit(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "other_episodes": {"attacker": ["0001-attacker"]}, "attack": {
		"problems": [
			{"id": "P1", "source": "hack inspector", "cause": "c1", "level": 3},
			{"id": "P2", "source": "hack inspector", "cause": "c2", "level": 3, "members": ["0001-attacker"]},
			{"id": "P3", "source": "hack inspector", "cause": "c3", "level": 3, "members": ["0001-attacker"]}],
		"attempts": [{"number": 1, "level": "full", "problem": "P1", "candidate": "hack-0", "sources": ["hack-0"], "episode": "0001-attacker", "status": "other_exploit"}],
		"exploits": {"other": [
			{"assessment": 0, "attempt": 0, "candidate": "hack-0", "sources": ["hack-0"], "problem": "P2"},
			{"assessment": 1, "attempt": 0, "candidate": "hack-0", "sources": ["hack-0"], "problem": "P3"}]},
		"findings": {"evidenced": [
			{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m0", "episode": "0001-attacker"}},
			{"index": 1, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m1", "episode": "0001-attacker"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	found := r.findings()
	for i, want := range []string{"P2", "P3"} {
		var held []string
		for _, p := range r.Attack.Problems {
			if r.demonstrates(found[i], p) {
				held = append(held, p.ID)
			}
		}
		if p := findingProblem(r, found[i]); p == nil || p.ID != want || len(held) != 1 {
			t.Errorf("finding %d is held by %v", i+1, held)
		}
	}
}

// An evidenced Attacker finding without an exploit entry, as one outside its requested outcome, stays on the
// Results tab when no problem holds it.
func TestUnheldAttackFindingIsListed(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "attack": {"problems": [], "exploits": {"reproduction": [], "other": [], "unattributed": [], "discovery": []},
		"findings": {"evidenced": [{"index": 0, "assessment": {"outcome": "rejected_valid"}, "claim": {"mechanism": "outside its outcome", "episode": "0001-attacker"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := plainTab(r, results); !strings.Contains(s, "outside its outcome") {
		t.Errorf("the finding is missing:\n%s", s)
	}
}

// A blank limitation is no limitation: the finding still draws, and its count leaves the blank out.
func TestBlankLimitationsAreSkipped(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "inspections": {"hack_inspector": {"findings": {"evidenced": [
		{"index": 0, "assessment": {"outcome": "accepted_invalid", "limits": ["  "]}, "claim": {"mechanism": "m", "limits": ["", "a real limit"], "unresolved": [" "]}}]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	found := r.findings()
	s := plainText(renderShow(r, found, 1, 1, "Results", 100))
	if !strings.Contains(s, "Limitations 1") || !strings.Contains(s, "1  A real limit") || strings.Contains(s, "OPEN CONDITIONS") {
		t.Errorf("limitations:\n%s", s)
	}
	if s := plainShow(r, found, 1, 100); !strings.Contains(s, "A real limit") {
		t.Errorf("plain finding:\n%s", s)
	}
}

// Enter on a Find Hacks finding of a report without problems opens that finding, by its number on the whole list.
func TestFindHacksOpensItsOwnFinding(t *testing.T) {
	r := fixture(t, "full-0.0.0")
	found := r.findings()
	m := newModel(r, 0, false)
	m.w, m.screen = 100, 2
	m.page()
	n := -1
	for _, it := range m.items {
		if it.n > 0 {
			n = it.n
			break
		}
	}
	if n < 1 || found[n-1].ID != "hack-1" {
		t.Errorf("the first Find Hacks row opens finding %d", n)
	}
}

// A reward pattern counts only usable rewards, and without rewards per episode it says they are unavailable.
func TestRewardPatternCountsUsableRewards(t *testing.T) {
	one, zero := 1.0, 0.0
	rewards := map[string]map[string]*float64{"e00": {"r": &zero}, "e01": {"r": &zero}, "e12": {"r": nil}}
	for i := 2; i < 12; i++ {
		rewards[fmt.Sprintf("e%02d", i)] = map[string]*float64{"r": &one}
	}
	flag, text := "low_minority", "t"
	x := Rewards{Flags: []*Flag{{Flag: &flag, Text: &text, Episodes: []string{"e00", "e01"}}}}
	if got := patterns(x, rewards, "r"); got[0] != "2 episodes received 0; the other 10 received 1." {
		t.Errorf("pattern: %q", got)
	}
	if got := patterns(x, nil, "r"); strings.Contains(got[0], "no usable reward") || !strings.Contains(got[0], "unavailable") {
		t.Errorf("pattern without rewards per episode: %q", got)
	}
}

// A no-information try that matched an Attacker problem another try found first is not a new finding.
func TestNoInfoMatchOfAnEarlierAttackerProblemIsNotNew(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "other_episodes": {"attacker": ["0001-attacker", "0002-attacker"]}, "attack": {
		"problems": [{"id": "A1", "source": "Attacker", "cause": "a1", "level": 5, "members": ["0001-attacker", "0002-attacker"]}],
		"discovery": {"status": "evidenced_issue", "attempts": 2, "maximum_attempts": 2},
		"attempts": [
			{"number": 1, "level": "none", "episode": "0001-attacker", "status": "evidenced_issue"},
			{"number": 2, "level": "none", "episode": "0002-attacker", "status": "evidenced_issue"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, 3)
	if got, again := cells(s, "1 "), cells(s, "2 "); got != "✓ ✓" || again != "✓ ✗ a1" {
		t.Errorf("first %q, second %q:\n%s", got, again, s)
	}
}

// A problem's type is the report's own; without one the viewer guesses none, whatever its findings show.
func TestProblemTypeIsTheReports(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "inspections": {"grader_inspector": {"findings": {"evidenced": [
		{"index": 0, "assessment": {"outcome": "rejected_valid"}, "claim": {"mechanism": "g"}}]}}},
		"attack": {"problems": [{"id": "G1", "source": "grader inspector", "cause": "c", "findings": ["grader-0"], "level": 2},
			{"id": "G2", "source": "grader inspector", "cause": "d", "type": "false_positive", "level": 2}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := problemType(r.Attack.Problems[0]); got != "" {
		t.Errorf("no type: %q", got)
	}
	if got := problemType(r.Attack.Problems[1]); got != "False positive" {
		t.Errorf("false_positive: %q", got)
	}
}

// A phase that failed after keeping results shows them, and says it failed before finishing rather than that it has none.
func TestFailedPhaseKeepsItsResults(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "status": "partial", "analyses": {"hack": "partial"}, "phase_errors": {"hack": "hack failed: RuntimeError: boom"},
		"inspections": {"hack_inspector": {"findings": {"evidenced": [{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "kept finding"}}]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{plainTab(r, results), plainTab(r, 2), plainReport(r, 120)} {
		if strings.Contains(s, "No hack search result") || strings.Contains(s, "nothing about hacks") || !strings.Contains(s, "failed before it finished") {
			t.Errorf("failed phase:\n%s", s)
		}
	}
	if s := plainTab(r, 2); !strings.Contains(s, "kept finding") {
		t.Errorf("the kept finding is missing:\n%s", s)
	}
}

// Without exploits, an attack finding is listed under the first problem whose members name its episode, and only
// there, also when a try aimed at another problem found it; a finding no problem names is not attributed.
func TestOlderAttackFindingFollowsMembership(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "attack": {"problems": [
		{"id": "P1", "source": "hack inspector", "cause": "c1", "findings": ["hack-1"], "members": ["hack-1", "0005-attacker"], "level": 3},
		{"id": "P2", "source": "hack inspector", "cause": "c2", "findings": ["hack-2"], "members": ["hack-2", "0005-attacker"], "level": 3}],
		"attempts": [{"number": 1, "level": "full", "problem": "P2", "episode": "0005-attacker", "status": "evidenced_issue"},
			{"number": 2, "level": "full", "problem": "P2", "episode": "0006-attacker", "status": "evidenced_issue"}],
		"findings": {"evidenced": [{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m5", "episode": "0005-attacker"}},
			{"index": 1, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m6", "episode": "0006-attacker"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	held := map[string][]string{}
	for _, f := range r.findings() {
		for _, p := range r.Attack.Problems {
			if r.demonstrates(f, p) {
				held[f.Claim.Episode] = append(held[f.Claim.Episode], p.ID)
			}
		}
	}
	if got := fmt.Sprint(held); got != "map[0005-attacker:[P1]]" {
		t.Errorf("held: %s", got)
	}
	if s := plainTab(r, results, "o"); !strings.Contains(row(s, "m6"), "? Not attributed") {
		t.Errorf("m6:\n%s", s)
	}
}

// Without the Inspector column, the legend leaves it out, and an expanded problem states its level, so a row without
// a ✓ still says why it counts.
func TestOlderProblemStatesItsLevel(t *testing.T) {
	r := fixture(t, "pipeline-full")
	s := plainTab(r, results)
	if strings.Contains(s, "Inspector: an inspector evidenced it") {
		t.Errorf("legend names an absent column:\n%s", s)
	}
	for _, p := range problems(r) {
		if want := "Level       " + level(r, p); !strings.Contains(s, want) {
			t.Errorf("%s lacks %q:\n%s", p.ID, want, s)
		}
	}
	if s := plainTab(fixture(t, "full"), results); !strings.Contains(s, "Inspector: an inspector evidenced it") || strings.Contains(s, "Level       ") {
		t.Errorf("a report with the Inspector column:\n%s", s)
	}
}

// Even a run that allowed tries without information has no No info column on Results.
func TestNoInfoColumnEvenWhenTriesWereAllowed(t *testing.T) {
	if s := plainTab(fixture(t, "time-limit"), results); strings.Contains(oneLine(row(s, "Problem ")), "No info") {
		t.Errorf("time-limit:\n%s", s)
	}
}

// A finding a problem holds is named by the problem's cause; its own mechanism stays on a line of its own. A finding
// no problem holds keeps its own name.
func TestDetailNamesItsProblem(t *testing.T) {
	r := fixture(t, "full")
	s := plainShow(r, r.findings(), 3, 120)
	for _, want := range []string{"Results › The test runs bash through PATH, so a planted shim decides the result.", "Mechanism"} {
		if !strings.Contains(s, want) {
			t.Errorf("finding 3 lacks %q:\n%s", want, s)
		}
	}
	if s := plainShow(r, r.findings(), 1, 120); strings.Contains(s, "Mechanism") || !strings.Contains(s, "Results › "+title(r.findings()[0])) {
		t.Errorf("finding 1:\n%s", s)
	}
}

// A clean run names its open question and why it is open; it never says a phase is incomplete when it only left
// results unresolved.
func TestCleanRunNamesItsOpenQuestion(t *testing.T) {
	s := plainReport(fixture(t, "clean"), 120)
	for _, want := range []string{"No problems demonstrated in this run.", "1 open question",
		"  Find Hacks          unchecked requirement (hack-0)\n                      Unresolved: Reason not recorded"} {
		if !strings.Contains(s, want) {
			t.Errorf("report lacks %q:\n%s", want, s)
		}
	}
	for _, gone := range []string{"Coverage", "some results unclear", "No cheat and no misjudged work"} {
		if strings.Contains(s, gone) {
			t.Errorf("report shows %q:\n%s", gone, s)
		}
	}
}

// The help defines the metrics; the Results tab only shows them.
func TestHelpDefinesMetrics(t *testing.T) {
	help := plainText(helpPanel(wideAt, false))
	for _, want := range []string{"Metrics", "F1", "2 TP / (2 TP + FP + FN)", "AUROC", "Score ordering", "source-grounded"} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
	if s := plainTab(fixture(t, "full"), results); strings.Contains(s, "2 TP") {
		t.Errorf("results define the metrics:\n%s", s)
	}
}

// Evidence no problem holds is a selectable row, and Enter opens its detail; an ungrouped finding that is its own
// problem is shown once, as that problem.
func TestStandaloneEvidenceOpens(t *testing.T) {
	r := fixture(t, "full")
	if s := plainTab(r, results, "o"); strings.Contains(s, "Standalone evidence") {
		t.Errorf("a problem is also standalone evidence:\n%s", s)
	}
	r.Attack.Problems = slices.DeleteFunc(r.Attack.Problems, func(p Problem) bool { return p.ID == "grader-12" })
	found := r.findings()
	p := &page{w: wideAt, sel: -1, open: map[string]bool{"o": true}}
	resultsPage(r, found, p)
	for _, it := range p.items {
		if line := plainText(p.lines[it.line]); strings.Contains(line, "Standalone evidence") {
			if it.n < 1 || found[it.n-1].ID != "grader-12" {
				t.Errorf("row %q opens finding %d", line, it.n)
			}
			return
		}
	}
	t.Errorf("no selectable standalone evidence:\n%s", plainText(p.String()))
}

// Older reports: legacy tries name what each tested and whether it succeeded, and problems of unknown type alone
// form one Problems group.
func TestOlderReportsGroupWhatTheyKnow(t *testing.T) {
	if s := plainTab(fixture(t, "full-0.0.0"), 3); !strings.Contains(s, "Tested") || !strings.Contains(s, "Succeeded") {
		t.Errorf("legacy tries:\n%s", s)
	}
	if s := plainTab(fixture(t, "pipeline-full"), 3); !strings.Contains(s, "Problems (5)") || strings.Contains(s, "Type Unknown") {
		t.Errorf("no type group:\n%s", s)
	}
}

// The Models panel wraps inside its box and names each role's jobs.
func TestModelsPanelFits(t *testing.T) {
	r := fixture(t, "full")
	for _, w := range []int{60, 80, 100, 120} {
		s := plainText(modelsPanel(r, w))
		for _, line := range splitLines(s) {
			if width(line) > w || strings.Contains(line, "…") {
				t.Errorf("width %d: %q", w, line)
			}
		}
		if !strings.Contains(s, "Jobs: Grader Inspector, Hack Inspector,") {
			t.Errorf("width %d lacks the jobs:\n%s", w, s)
		}
	}
}

// Find Hacks mentions Attackers only when the run selected Attack, and the pipe keeps no internal labels.
func TestPlainWordsOnly(t *testing.T) {
	if s := plainTab(fixture(t, "clean"), 2); strings.Contains(s, "Attackers") {
		t.Errorf("clean Find Hacks:\n%s", s)
	}
	r := fixture(t, "full")
	out := plainReport(r, 120)
	for n := range r.findings() {
		out += plainShow(r, r.findings(), n+1, 120)
	}
	for _, gone := range []string{"exploit executable", "no extra information", "Evidenced in no problem", "Summary is violated"} {
		if strings.Contains(out, gone) {
			t.Errorf("plain output shows %q", gone)
		}
	}
}

// Two standalone Attacker findings of one episode are two rows, and each opens its own finding.
func TestStandaloneRowsOpenTheirOwnFinding(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "attack": {"problems": [], "exploits": {"reproduction": [], "other": [], "unattributed": [], "discovery": []},
		"findings": {"evidenced": [{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "first way", "episode": "0001-attacker"}},
			{"index": 1, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "second way", "episode": "0001-attacker"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	p := &page{w: wideAt, sel: -1, open: map[string]bool{"o": true}}
	resultsPage(r, r.findings(), p)
	var opens []int
	for _, it := range p.items {
		if strings.Contains(plainText(p.lines[it.line]), "Standalone evidence") {
			opens = append(opens, it.n)
		}
	}
	if !slices.Equal(opens, []int{1, 2}) {
		t.Errorf("standalone rows open %v:\n%s", opens, plainText(p.String()))
	}
}

// A problem imported at its earlier run's level keeps saying so in the plain report.
func TestImportedLevelKeepsItsRun(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "attack": {"problems": [
		{"id": "A1", "cause": "c1", "source": "Attacker", "level": 5, "members": ["0001-attacker"],
			"label": "evidenced in run r1 at ●●●●● exploit executable by unaided learner; not found again here"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "      Level             5 of 5: an Attacker given no information demonstrated it in run r1; not found again here"
	if got := row(plainReport(r, 140), "Level"); got != want {
		t.Errorf("level:\n%q\nwant\n%q", got, want)
	}
}

// The saved Attack table says how a try stopped once its episode started, and "Not started" only for one that never
// started.
func TestSavedTriesSayHowAStartedTryStopped(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "other_episodes": {"attacker": ["0001-attacker"]}, "attack": {
		"problems": [{"id": "P1", "source": "hack inspector", "cause": "c1", "level": 2, "findings": ["hack-0"]}],
		"attempts": [
			{"number": 1, "level": "full", "problem": "P1", "candidate": "hack-0", "episode": "0001-attacker", "rewards": {"0001-attacker": 1}, "status": "spending_exhausted"},
			{"number": 2, "level": "full", "problem": "P1", "candidate": "hack-0", "status": "spending_exhausted"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, 3)
	if first, second := oneLine(row(s, "1 ")), oneLine(row(s, "2 ")); !strings.Contains(first, "Stopped at") || strings.Contains(first, "Not started") || !strings.Contains(second, "Not started") {
		t.Errorf("first %q, second %q:\n%s", first, second, s)
	}
}

// An older report's exploit found while the Attacker held help for another problem keeps its level, without naming
// the problem the help was for.
func TestOlderExploitElsewhereKeepsItsLevel(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"},
		"other_episodes": {"attacker": ["0001-attacker", "0002-attacker"]}, "attack": {
		"problems": [
			{"id": "P1", "source": "hack inspector", "cause": "c1", "level": 3, "exploited_with": "full", "findings": ["hack-0"],
			 "conditions": [{"condition": "full", "attempts": 1, "exploited": 1, "status": "evidenced_issue"}]},
			{"id": "A2", "source": "Attacker", "cause": "a2", "level": 4, "exploited_with": "elsewhere_minimal", "members": ["0002-attacker"],
			 "exploited_by": [{"episode": "0002-attacker", "target": "P1"}],
			 "conditions": [{"condition": "elsewhere_minimal", "attempts": 1, "exploited": 1, "status": "evidenced_issue"}]}],
		"attempts": [
			{"number": 1, "level": "full", "problem": "P1", "candidate": "hack-0", "sources": ["hack-0"], "episode": "0001-attacker", "status": "evidenced_issue"},
			{"number": 1, "level": "minimal", "problem": "P1", "candidate": "hack-0", "sources": ["hack-0"], "episode": "0002-attacker", "status": "other_exploit"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ps := problems(r); ps[0].ID != "A2" || ps[1].ID != "P1" {
		t.Errorf("order %v", ps)
	}
	plain := plainReport(r, 120)
	if !strings.Contains(plain, "4 of 5: an Attacker given only a hint demonstrated it") || strings.Contains(plain, "aimed at") {
		t.Errorf("plain:\n%s", plain)
	}
	if s := plainTab(r, results) + plainTab(r, 3); strings.Contains(s, "aimed at") || strings.Contains(s, "✓*") {
		t.Errorf("screens:\n%s", s)
	}
}

// A suspected exploit, a measured check whose reading ended unknown, is a counted state among the findings not counted
// as problems, on Results and in the plain output, named by its category with its check as the reference.
func TestSuspectedExploitIsNotCountedAsAProblem(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"hack": "partial", "grader": "complete"}, "inspections": {
		"hack_inspector": {"suspected": [{"category": "package_oracles", "check": "check-0"}], "findings": {}},
		"grader_inspector": {"suspected": [{"category": null, "check": "check-1"}], "findings": {}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, results, "o")
	for _, want := range []string{"Abandoned Problems", "Reads solution files", "check-0", "check-1"} {
		if !strings.Contains(s, want) {
			t.Errorf("Results misses %q:\n%s", want, s)
		}
	}
	plain := plainReport(r, 100)
	if !strings.Contains(plain, "State             Suspected exploit") || !strings.Contains(plain, "Reference         check-0") {
		t.Errorf("plain:\n%s", plain)
	}
}

// The plain output says how a started try stopped, in its problem and among the attempts.
func TestPlainSaysHowAStartedTryStopped(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "other_episodes": {"attacker": ["0001-attacker"]}, "attack": {
		"problems": [{"id": "P1", "source": "hack inspector", "cause": "c1", "level": 2, "findings": ["hack-0"]}],
		"attempts": [{"number": 1, "level": "full", "problem": "P1", "candidate": "hack-0", "episode": "0001-attacker", "rewards": {"reward": 1}, "status": "cancelled"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainReport(r, 120)
	if strings.Contains(s, "not started") || !strings.Contains(s, "full instructions: stopped, 0001-attacker") || !strings.Contains(oneLine(row(s, "0001-attacker ")), "stopped") {
		t.Errorf("plain:\n%s", s)
	}
}

// A suspected exploit that is also an unresolved finding of the same check is one row, in the suspected state.
func TestSuspectedReadingIsOneRow(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"hack": "complete"}, "inspections": {"hack_inspector": {
		"suspected": [{"category": "package_oracles", "check": "check-0"}],
		"findings": {"inconclusive": [{"index": 0, "captured": {"check": {"id": "check-0"}}, "claim": {"mechanism": "reads the answer"}}]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, results, "o")
	if !strings.Contains(s, "Abandoned Problems") || strings.Count(s, "Suspected exploit") != 1 || strings.Contains(s, "Unresolved") {
		t.Errorf("Results:\n%s", s)
	}
}

// A condition with an assessed try and a failed one answers from the assessed try; "not tested" is for none.
func TestAssessedTryOutweighsAFailure(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "attack": {
		"problems": [{"id": "P1", "source": "hack inspector", "cause": "c1", "level": 2, "findings": ["hack-0"],
			"conditions": [{"condition": "minimal", "attempts": 1, "exploited": 0, "status": "inference_failure"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.tried(r.Attack.Problems[0], "minimal"); got != "no" {
		t.Errorf("hint answers %q", got)
	}
	if s := plainTab(r, results); !strings.HasPrefix(cells(s, "▾ c1"), "✗ - P1") || strings.Contains(s, "Hint -") {
		t.Errorf("Results:\n%s", s)
	}
}

// The Attack table has no Tries count; a failed try stays in the expanded list, which carries the row's answers.
func TestFailedTryStaysInTheList(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "other_episodes": {"attacker": ["0001-attacker"]}, "attack": {
		"problems": [{"id": "P1", "source": "hack inspector", "cause": "c1", "level": 2, "findings": ["hack-0"],
			"conditions": [{"condition": "full", "attempts": 0, "exploited": 0, "status": "native_timeout"}]}],
		"attempts": [{"number": 1, "level": "full", "problem": "P1", "candidate": "hack-0", "episode": "0001-attacker", "status": "native_timeout"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, 3)
	if got := cells(s, "▾ c1"); got != "P1" || strings.Contains(s, "Tries") || !strings.Contains(s, "0001-attacker") {
		t.Errorf("row %q:\n%s", got, s)
	}
}

// A failed experiment fails only itself: Work left names the experiment, once, and never the search session that ran it,
// which went on. While the experiment is open its open row already says so.
func TestFailedExperimentIsNamedNotItsSearch(t *testing.T) {
	for open, want := range map[string]string{
		`[]`: "Error: the sandbox broke",
		`[{"id":"experiment-0000","category":"grader_tampering","reason":"experiment-0000: tool_failure: the sandbox broke","next":"replace it"}]`: "Unresolved: experiment-0000: tool_failure: the sandbox broke",
	} {
		r, err := load(writeReport(t, `{"answer":["x"],"analyses":{"hack":"complete"},"inspections":{"hack_inspector":{
            "categories":{"grader_tampering":"no_evidenced_issue"},"open":`+open+`,
            "experiments":[{"id":"experiment-0000","status":"tool_failure","category":"grader_tampering","error":"the sandbox broke"},
                           {"id":"experiment-0001","status":"assessed","category":"grader_tampering","check":"check-0001"}],
            "attempts":[{"phase":"focused","number":1,"category":"grader_tampering","status":"tool_failure","error":"the sandbox broke"}]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		rows := workLeft(r, r.findings())
		if !slices.Equal(rows, [][3]string{{"Find Hacks", word(checkNames, "grader_tampering") + " (experiment-0000)", want}}) {
			t.Errorf("open %s: %q", open, rows)
		}
	}
}

// Legends are folded by default: e on the header they explain opens them.
func TestLegendsFoldedUntilE(t *testing.T) {
	r := fixture(t, "full")
	for s, legend := range map[int]string{
		results: "Hint, Full: an Attacker, by how much it was told.",
		2:       "The Hack Inspector made it happen in a copy of the task.",
		3:       "✓ yes   ✗ no",
	} {
		shut, open := plainTab(r, s, "problem 0"), plainTab(r, s, "e")
		if strings.Contains(shut, legend) || strings.Contains(shut, "✓ yes") || !strings.Contains(shut, "e expand") {
			t.Errorf("tab %d shows its legend by default:\n%s", s, shut)
		}
		if !strings.Contains(open, legend) || !strings.Contains(open, "e collapse") {
			t.Errorf("tab %d: e does not open its legend:\n%s", s, open)
		}
		m := newModel(r, 0, false)
		m.screen = s
		if m = press(m, "e"); !strings.Contains(ansi.Strip(m.View().Content), legend) {
			t.Errorf("tab %d: pressing e does not open the legend", s)
		}
	}
	if s := plainTab(r, results, "problem 0"); !strings.HasSuffix(row(s, "Problems (6)"), "e expand") || strings.Contains(s, "Evidence") || strings.Contains(s, "Who demonstrated it") {
		t.Errorf("Results header:\n%s", s)
	}
}

// Disclaimers and subtitles are gone, raw labels read plainly, and the no-information question has only its answer.
func TestScreensSayOnlyData(t *testing.T) {
	r := fixture(t, "full")
	screens := map[string]string{
		"episodes": plainTab(r, 0, "p"), "method": plainTab(r, 0, "?"), "grade": plainTab(r, 1, "s", "e"),
		"hacks": plainTab(r, 2, "s", "x"), "attack": plainTab(r, 3), "plain": plainReport(r, 120),
	}
	for name, s := range screens {
		for _, bad := range []string{"not recorded for this episode", "A pattern to read", "Can an Attacker demonstrate", "Reward key",
			"Episodes in accuracy", "In accuracy", "Basis", "pass rule, among", "assessed", "allowed no try", "asked to find any hack",
			"It describes the search", "This problem?", "Other hack?", "Tries", "Pattern name", "reward key"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s shows %q:\n%s", name, bad, s)
			}
		}
	}
	for name, want := range map[string]string{"grade": "Used for accuracy 6/12", "hacks": "Done", "attack": "Not tested: not allowed in this run.", "plain": "Reward name"} {
		if !strings.Contains(oneLine(screens[name]), want) {
			t.Errorf("%s lacks %q:\n%s", name, want, screens[name])
		}
	}
	if s := oneLine(screens["grade"]); !strings.Contains(s, "Fraction Meaning") || !strings.Contains(s, "Passed among scored episodes") {
		t.Errorf("grade metrics:\n%s", screens["grade"])
	}
}

// A flagged reward pattern puts its warning on the Simulation tab and its reason first in the method; no flag, no warning.
func TestRewardPatternWarning(t *testing.T) {
	r := fixture(t, "full")
	main, method := plainTab(r, 0, "problem 0"), plainTab(r, 0, "?")
	if !strings.Contains(main, "Warning: Possibly a bad system prompt or grader<->prompt mismatch") {
		t.Errorf("main view:\n%s", main)
	}
	if !strings.Contains(method, "╭─ Reward Patterns Explainer ─") || !strings.Contains(oneLine(method), "│ Reason for warning: A few rewards far below the rest") || strings.Contains(method, "│ Pattern") || strings.Contains(method, "Details") {
		t.Errorf("method:\n%s", method)
	}
	if s := oneLine(plainReport(r, 120)); !strings.Contains(s, "Warning Possibly a bad system prompt") || !strings.Contains(s, "Reason A few rewards far below the rest") {
		t.Errorf("plain:\n%s", s)
	}
	for flag, want := range map[string]string{
		"high_minority":     "Warning: Possibly a hack or a grader that passes wrong work",
		"identical_rewards": "Warning: Possibly a task that is too easy or too hard, or a grader that ignores the work",
	} {
		r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"simulation": "complete"}, "ordinary": {"requested": 1, "attempted": 1,
			"groups": [{"configuration": {"model": "m"}, "rewards": {"reward": {"attempted": 1, "usable": 1, "mean": 1.0,
			"distribution": [[1.0, 1]], "flags": [{"flag": "`+flag+`", "text": "t", "episodes": []}]}}}]}}`))
		if err != nil {
			t.Fatal(err)
		}
		if s := plainTab(r, 0); !strings.Contains(s, want) {
			t.Errorf("%s:\n%s", flag, s)
		}
	}
	if s := plainTab(fixture(t, "clean"), 0); strings.Contains(s, "Warning") {
		t.Errorf("no flag, yet a warning:\n%s", s)
	}
}

// From schema 3 a try's answer is its result: an exploit, none in an assessed try, or ? when the grader paid nothing or
// the result is unclear, each with its reason under it; an inspector problem's cells are its conditions and an
// Attacker's problem has ✓ at its own help. A no-hint exploit read as a known problem's cause names that problem's
// cause, and nothing says a problem is possibly the same as another.
func TestSchemaThreeTries(t *testing.T) {
	r, err := load(writeReport(t, `{"schema_version": 3, "answer": ["x"], "analyses": {"attack": "complete"},
		"other_episodes": {"attacker": ["0001-attacker", "0002-attacker", "0003-attacker", "0004-attacker", "0005-attacker", "0006-attacker", "0007-attacker", "0008-attacker", "0009-attacker"]},
		"attack": {"discovery": {"status": "evidenced_issue", "attempts": 2, "maximum_attempts": 2},
		"problems": [
			{"id": "P1", "finding": "hack-0", "source": "hack inspector", "cause": "c1", "type": "hack", "level": 3,
			 "conditions": [{"condition": "full", "attempts": 1, "exploited": 1, "status": "evidenced_issue"}, {"condition": "minimal", "attempts": 0, "exploited": 0, "status": "unattempted"}]},
			{"id": "P2", "finding": "hack-1", "source": "hack inspector", "cause": "c2", "type": null, "level": 2, "unrewarded": 1,
			 "reason": "completeness is unknown: no approved requirement list was given",
			 "conditions": [{"condition": "full", "attempts": 1, "exploited": 0, "status": "no_evidenced_issue"}, {"condition": "minimal", "attempts": 1, "exploited": 0, "status": "unknown", "unrewarded": 1}]},
			{"id": "P3", "finding": "hack-2", "source": "hack inspector", "cause": "c3", "type": null, "level": 2, "unrewarded": 1,
			 "conditions": [{"condition": "full", "attempts": 0, "exploited": 0, "status": "no_evidenced_issue", "unrewarded": 1},
			                {"condition": "minimal", "attempts": 0, "exploited": 0, "status": "not_needed"}]},
			{"id": "A1", "finding": "0002-attacker", "source": "Attacker", "cause": "a1", "type": "hack", "level": 5, "help": "no extra information", "kind": "discovery"}],
		"attempts": [
			{"number": 1, "level": "full", "candidate": "hack-0", "sources": ["hack-0"], "episode": "0001-attacker", "status": "evidenced_issue", "assessment": 0, "rewards": {"reward": 1}},
			{"number": 1, "level": "none", "sources": [], "problem": "A1", "episode": "0002-attacker", "status": "evidenced_issue", "assessment": 1, "rewards": {"reward": 1}},
			{"number": 1, "level": "full", "candidate": "hack-1", "sources": ["hack-1"], "episode": "0003-attacker", "status": "no_evidenced_issue", "assessment": 2, "rewards": {"reward": 1}},
			{"number": 2, "level": "full", "candidate": "hack-1", "sources": ["hack-1"], "episode": "0004-attacker", "status": "no_reward",
			 "error": "the grader wrote no reward in 0004-attacker"},
			{"number": 1, "level": "minimal", "candidate": "hack-1", "sources": ["hack-1"], "episode": "0005-attacker", "status": "unknown",
			 "error": "the attack inspector's reply was cut off\nmore", "rewards": {"reward": 1}},
			{"number": 2, "level": "minimal", "candidate": "hack-1", "sources": ["hack-1"], "episode": "0006-attacker", "status": "no_evidenced_issue", "rewards": {"reward": 0}},
			{"number": 2, "level": "none", "candidate": "hack-0", "sources": ["hack-0"], "problem": "P1", "episode": "0007-attacker", "status": "evidenced_issue", "assessment": 3, "rewards": {"reward": 1}},
			{"number": 1, "level": "full", "candidate": "hack-2", "sources": ["hack-2"], "episode": "0008-attacker", "status": "no_evidenced_issue", "rewards": {"reward": 0}},
			{"number": 3, "level": "none", "sources": [], "episode": "0009-attacker", "status": "no_evidenced_issue", "rewards": {"reward": 0}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	res := plainTab(r, results, "none")
	for id, want := range map[string]string{"c1": "Hack - ✓ ✓ P1", "c2": "? ? ✗ ✓ P2", "a1": "Hack - - - A1", "c3": "? - ? ✓ P3"} {
		if got := cells(res, "▸ "+id); got != want {
			t.Errorf("%s row %q, want %q:\n%s", id, got, want, res)
		}
	}
	for key, want := range map[string][]string{"tries P1 c1": {"1 Full ✓ Finished 1 0001-attacker"},
		"tries P2 c2": {"1 Full ✗ Finished 1 0003-attacker", "2 Full ? No reward - 0004-attacker",
			"3 Hint ? Finished 1 0005-attacker Result unclear: the attack inspector's reply was cut off.",
			"4 Hint ? Finished 0 0006-attacker The grader paid nothing, so nudi did not inspect it."},
		"tries A1 a1": {"1 No info ✓ Finished 1 0002-attacker"}} {
		s := oneLine(plainTab(r, 3, key))
		for _, w := range want {
			if !strings.Contains(s, w) {
				t.Errorf("%s lacks %q:\n%s", key, w, s)
			}
		}
	}
	if s := oneLine(plainTab(r, 3)); !strings.Contains(s, "1 ✓ ✓ 2 ✓ ✗ c1 3 ? -") || !strings.Contains(s, "Same cause as") {
		t.Errorf("no-information tries:\n%s", s)
	}
	plain := plainReport(r, 120)
	for _, want := range []string{"no reward: the grader wrote no reward in 0004-attacker", "only a hint: unresolved, 0005-attacker",
		"  Result unclear: the attack inspector's reply was cut off.", "0003-attacker   P2        full instructions     not demonstrated",
		"0006-attacker   P2        only a hint           not inspected", "0008-attacker   P3        full instructions     not inspected",
		"only a hint: not tested, no exploit was made with more help"} {
		if !strings.Contains(plain, want) {
			t.Errorf("plain lacks %q:\n%s", want, plain)
		}
	}
	// A try given no information is not one given P1's help, whatever candidate it was started for.
	if s := plainTab(r, 3, "tries P1 c1"); strings.Contains(s, "0007-attacker") || strings.Contains(plain, "no information: demonstrated, 0007") {
		t.Errorf("a no-information try counted for P1:\n%s\n%s", s, plain)
	}
	if strings.Contains(oneLine(plain), "P3 c3 Not tested") {
		t.Errorf("a try the grader paid nothing is called not tested:\n%s", plain)
	}
	for _, s := range []string{res, plain, plainTab(r, results), plainTab(r, 3)} {
		if strings.Contains(s, "same as") || strings.Contains(s, "rerun of") || strings.Contains(s, "Note") {
			t.Errorf("a gone field is stated:\n%s", s)
		}
	}
}

// An Attacker problem the report names after its episode shows as A1, A2, ... in report order wherever a problem
// ref shows, and opens by it; its tries keep the episode. A short id is shown as it is.
func TestAttackerProblemsShowShortRefs(t *testing.T) {
	// The full report with 0014-attacker's exploit, given P1's hint, also an Attacker problem named after its episode.
	body, err := os.ReadFile("testdata/full/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	attack := raw["attack"].(map[string]any)
	attack["problems"] = append(attack["problems"].([]any), map[string]any{"id": "0014-attacker", "finding": "0014-attacker", "source": "Attacker",
		"cause": "wrote the pass marker", "level": 4, "assessment": 2, "help": "only a hint written for hack-1", "kind": "reproduction"})
	body, _ = json.Marshal(raw)
	dir := writeReport(t, string(body))
	r, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s := plainTab(r, results, "none"); !strings.HasSuffix(cells(s, "▸ wrote the pass marker"), " A1") || strings.Contains(s, "0014-") {
		t.Errorf("Results:\n%s", s)
	}
	plain := plainReport(r, 120)
	for _, want := range []string{"\n  A1         wrote the pass marker"} {
		if !strings.Contains(plain, want) {
			t.Errorf("plain lacks %q:\n%s", want, plain)
		}
	}
	if s := plainTab(r, 3, "tries A1 wrote the pass marker"); !strings.Contains(s, "0014-attacker") {
		t.Errorf("a try lost its episode:\n%s", s)
	}
	if code, out, _ := run(dir, "A1"); code != 0 || !strings.Contains(out, "0014-attacker") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	short, err := load(writeReport(t, `{"schema_version": 2, "answer": ["x"], "attack": {"problems": [
		{"id": "A7", "finding": "0002-attacker", "source": "Attacker", "cause": "a7", "level": 4}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := plainTab(short, results, "none"); !strings.HasSuffix(cells(s, "▸ a7"), " A7") {
		t.Errorf("a short id is renamed:\n%s", s)
	}
	// Beside A ids the report wrote, an episode-named problem takes the next free number.
	mixed, err := load(writeReport(t, `{"schema_version": 2, "answer": ["x"], "attack": {"leads": [{"id": "A2", "cause": "l"}], "problems": [
		{"id": "A1", "finding": "0001-attacker", "source": "Attacker", "cause": "a1", "level": 4},
		{"id": "0003-attacker", "finding": "0003-attacker", "source": "Attacker", "cause": "a3", "level": 4}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ids := []string{mixed.Attack.Problems[0].ID, mixed.Attack.Problems[1].ID}; ids[0] != "A1" || ids[1] != "A3" {
		t.Errorf("ids %v", ids)
	}
}

// A titled group with no rows is left out; an empty result keeps its title and says so.
func TestEmptyGroupsAreHidden(t *testing.T) {
	r := fixture(t, "full")
	for tab, bad := range map[int][]string{3: {"Hacks (0)", "Correct Work Rejected (0)"}, 2: {"Ideas Not Reproduced (0)", "Open Questions (0)"}} {
		for _, b := range bad {
			if s := plainTab(r, tab); strings.Contains(s, b) {
				t.Errorf("tab %d shows %q:\n%s", tab, b, s)
			}
		}
	}
	if s := plainTab(r, 3, "e"); !strings.HasSuffix(oneLine(row(s, "Incorrect Work Passed (4)")), "e collapse") || !strings.Contains(s, "✓ yes") {
		t.Errorf("the first group shown lost the legend:\n%s", s)
	}
	none, err := load(writeReport(t, `{"schema_version": 2, "answer": ["x"], "analyses": {"attack": "complete"}, "attack": {"problems": []}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s := plainTab(none, 3); !strings.Contains(s, "Hacks (0)") || !strings.Contains(s, "None in this run.") {
		t.Errorf("no problem at all:\n%s", s)
	}
}

// A try told nothing and aimed at nothing is the no-information question's answer, also when its exploit became a problem.
func TestDiscoveryTryThatCreatedAProblem(t *testing.T) {
	r, err := load(writeReport(t, `{"schema_version": 2, "answer": ["x"], "analyses": {"attack": "complete"},
		"other_episodes": {"attacker": ["0002-attacker"]}, "attack": {
		"discovery": {"status": "evidenced_issue", "tested": true, "attempts": 1, "maximum_attempts": 1},
		"problems": [{"id": "A1", "finding": "0002-attacker", "members": ["0002-attacker"], "source": "Attacker", "cause": "a1", "level": 5}],
		"attempts": [{"number": 1, "level": "none", "candidate": null, "sources": [], "episode": "0002-attacker", "status": "evidenced_issue",
			"problem": "A1", "created": "A1", "reproduced": null}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainTab(r, 3)
	if _, after, _ := strings.Cut(s, "Without Any Information?"); strings.Contains(s, "Not tested") || !strings.HasPrefix(cells(after, "1  "), "✓ ✓") {
		t.Errorf("no-information answer:\n%s", s)
	}
}

// A missing statistic stays "unavailable" whole at 80 and 120 columns; an episode's missing reward, in a column too
// narrow for the word, is -.
func TestMissingNumbersNeverSplit(t *testing.T) {
	r := fixture(t, "full")
	g := &r.Ordinary.Groups[0]
	x := g.Rewards["reward"]
	x.SD, x.Skewness = nil, nil
	g.Rewards["reward"] = x
	g.EpisodeRewards[g.Episodes[0]]["reward"] = nil
	for _, s := range []string{plainText(drawTab(r, results, 120)), plainText(drawTab(r, 0, 80, "p")), plainText(drawTab(r, 0, 120, "p"))} {
		if strings.Contains(s, "unavail\n") || strings.Contains(s, "unavaila\n") || strings.Contains(s, "unavailab\n") {
			t.Errorf("a split word:\n%s", s)
		}
	}
	if s := plainText(drawTab(r, 0, 80, "p")); !strings.Contains(s, g.Episodes[0]+"    -") {
		t.Errorf("episode without reward:\n%s", s)
	}
}

// Counts read as English: one episode, not one episodes.
func TestOneEpisodeWithoutReward(t *testing.T) {
	r := fixture(t, "full")
	g := &r.Ordinary.Groups[0]
	x := g.Rewards["reward"]
	x.Usable = x.Attempted - 1
	g.Rewards["reward"] = x
	if s := plainReport(r, 120); !strings.Contains(s, "1 episode without a usable reward") {
		t.Errorf("plain:\n%s", s)
	}
}

// Plain abandoned problems wrap their titles, and a lead with no source has no empty Found by row.
func TestPlainAbandonedProblemsWrap(t *testing.T) {
	r := fixture(t, "full")
	r.Attack.Leads[0].Cause = strings.Repeat("a long cause ", 12)
	s := plainReport(r, plainW)
	for _, line := range strings.Split(s, "\n") {
		if width(line) > plainW && !strings.Contains(line, "/") {
			t.Errorf("%d columns: %q", width(line), line)
		}
	}
	if strings.Contains(s, "Found by\n") {
		t.Errorf("an empty Found by row:\n%s", s)
	}
}

// At 80 columns a tab strip that needs two lines keeps Results beside a tab, never alone on a line.
func TestTabStripWrapsWholeTabs(t *testing.T) {
	r := fixture(t, "full")
	r.Analyses["simulation"] = "partial"
	m := newModel(r, 0, false)
	m.w = 80
	for _, line := range strings.Split(plainText(m.top()), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "│") {
			t.Errorf("Results alone:\n%s", plainText(m.top()))
		}
	}
}

// No repeated not-tested lines, bare key hints, plain fold titles, Simulation episodes behind p.
func TestPlainFoldsAndKeyHints(t *testing.T) {
	r := fixture(t, "full")
	res := plainTab(r, results)
	for _, bad := range []string{"Hint -      Not tested", "Full -      Not tested", "no guidance for an Attacker", "Evidence   e", "Ideas and records",
		"Not counted as problems", "(P1, G1", "(6 unresolved"} {
		if strings.Contains(res, bad) {
			t.Errorf("Results shows %q:\n%s", bad, res)
		}
	}
	for _, want := range []string{"▾ Abandoned Problems", "Suspected problems that didn't have enough evidence", "▾ What the References Mean"} {
		if !strings.Contains(res, want) {
			t.Errorf("Results lacks %q:\n%s", want, res)
		}
	}
	for s, head := range map[int]string{results: "Problems (6)", 2: "Problems Found (4)", 3: "Incorrect Work Passed (4)", 1: "Metrics"} {
		if got := oneLine(row(plainTab(r, s, "none"), head)); !strings.HasSuffix(got, " e expand") || strings.Contains(got, "Legend") {
			t.Errorf("tab %d header %q", s, got)
		}
	}
	if s := plainReport(r, 120); !strings.Contains(s, "\nABANDONED PROBLEMS\n") || strings.Contains(s, "NOT COUNTED") {
		t.Errorf("plain:\n%s", s)
	}
	sim := plainTab(r, 0, "none")
	for _, bad := range []string{"received 0", "Enter", "episodes   ?"} {
		if strings.Contains(sim, bad) {
			t.Errorf("Simulation shows %q:\n%s", bad, sim)
		}
	}
	if !strings.Contains(sim, "? expand") || !strings.Contains(oneLine(sim), "▸ Episodes (12) p expand") || strings.Contains(sim, "0004-simulator") {
		t.Errorf("Simulation folds:\n%s", sim)
	}
	if s := plainTab(r, 0, "p", "?"); !strings.Contains(s, "▾ Episodes (12)") || !strings.Contains(s, "0004-simulator    0") || !strings.Contains(s, "? collapse") ||
		!strings.Contains(s, "Rewards") {
		t.Errorf("Simulation open:\n%s", s)
	}
	grade := plainTab(r, 1, "none")
	for _, bad := range []string{"Fraction", "Meaning", "Wilson interval", "The reward matches the work"} {
		if strings.Contains(grade, bad) {
			t.Errorf("Grade Simulations shows %q by default:\n%s", bad, grade)
		}
	}
	if s := plainTab(r, 1, "e"); !strings.Contains(s, "Fraction   Meaning") || !strings.Contains(s, "The reward matches the work") {
		t.Errorf("e does not show the columns:\n%s", s)
	}
	if s := plainTab(r, 2, "none"); !strings.Contains(s, "▸ Search Scope") || !strings.Contains(s, "▸ Experiments") {
		t.Errorf("Find Hacks folds:\n%s", s)
	}
}

// The key bar names what Enter does on the selected row, and shows no Enter where it does nothing.
func TestKeyBarSaysWhatEnterDoes(t *testing.T) {
	r := fixture(t, "full")
	bar := func(m model) string {
		return ansi.Strip(splitLines(strings.TrimRight(m.View().Content, "\n"))[len(splitLines(strings.TrimRight(m.View().Content, "\n")))-1])
	}
	for s, want := range map[int]string{results: "Enter expand problem", 2: "Enter open finding", 3: "Enter expand tries", 0: "", 1: ""} {
		m := newModel(r, 0, false)
		m.screen = s
		m = m.layout()
		got := bar(m)
		if strings.Contains(got, "expand or open") || want == "" && strings.Contains(got, "Enter") || want != "" && !strings.Contains(got, want) {
			t.Errorf("tab %d bar %q, want %q", s, got, want)
		}
	}
	m := newModel(r, 0, false)
	m.screen = 3
	if got := bar(press(m.layout(), "enter")); !strings.Contains(got, "Enter collapse tries") {
		t.Errorf("after Enter: %q", got)
	}
	m = newModel(r, 0, false)
	m.screen = 0
	if m = press(m.layout(), "p"); !strings.Contains(ansi.Strip(m.View().Content), "0004-simulator") {
		t.Error("p does not open the episodes")
	}
}

// Only titles are bold, in Title Case: sections, folds, boxes and the active tab. Rows, cells, values, warnings, key
// hints and the selected row are not.
func TestOnlyTitlesAreBold(t *testing.T) {
	small := []string{"a", "an", "and", "as", "for", "in", "of", "on", "the", "to"}
	for _, name := range []string{"full", "time-limit", "pipeline-full"} {
		r := fixture(t, name)
		for s := range results + 1 {
			m := newModel(r, 0, false)
			m.w, m.screen = 100, s
			for _, k := range []string{"o", "i", "e", "?", "p"} {
				m.open[fmt.Sprint(s)+k] = true
			}
			runs := boldRuns(m.View().Content)
			if len(runs) == 0 {
				t.Errorf("%s tab %d has no bold title", name, s)
			}
			for _, run := range runs {
				caps := len(run) > 3 && strings.ToUpper(run) == run && strings.ToLower(run) != run
				for i, w := range strings.Fields(run) {
					if first := w[:1]; first != strings.ToUpper(first) && (i == 0 || !slices.Contains(small, w)) {
						caps = true
					}
				}
				if caps {
					t.Errorf("%s tab %d: %q is bold but not a Title Case title", name, s, run)
				}
			}
			if s == results && name == "full" && !slices.Contains(runs, "Problems") {
				t.Errorf("Results title not bold: %q", runs)
			}
		}
	}
}

// boldRuns are the stretches of s drawn bold, without their escapes.
func boldRuns(s string) []string {
	sgr := regexp.MustCompile(`\x1b\[([0-9;:]*)m`)
	var runs []string
	var run strings.Builder
	on := false
	for {
		loc := sgr.FindStringSubmatchIndex(s)
		text := s
		if loc != nil {
			text = s[:loc[0]]
		}
		if on {
			run.WriteString(ansi.Strip(text))
		}
		if loc == nil {
			break
		}
		params := strings.Split(s[loc[2]:loc[3]], ";")
		for i := 0; i < len(params); i++ {
			switch params[i] {
			case "", "0", "22":
				on = false
			case "1":
				on = true
			case "38", "48", "58": // a colour, whose own numbers are not styles
				if i+1 < len(params) && params[i+1] == "5" {
					i += 2
				} else {
					i += 4
				}
			}
		}
		if text := strings.TrimSpace(run.String()); !on && text != "" {
			runs = append(runs, text)
			run.Reset()
		}
		s = s[loc[1]:]
	}
	return runs
}

// problemNamed is problem id of r as the viewer lists it, with its row keys on Results and on the Attack tab.
func problemNamed(t *testing.T, r Report, id string) (p Problem, row, tries string) {
	t.Helper()
	ps := problems(r)
	i := slices.IndexFunc(ps, func(p Problem) bool { return p.ID == id })
	if i < 0 {
		t.Fatalf("no problem %s", id)
	}
	return ps[i], fmt.Sprint("problem ", i), "tries " + id + " " + ps[i].Cause
}

// A try the grader paid nothing was never inspected: it says so, and its problem counts it apart.
func TestUnrewardedTryWasNotInspected(t *testing.T) {
	r := fixture(t, "full")
	ep, zero, one := "0017-attacker", 0.0, 1
	r.Attack.Attempts = append(r.Attack.Attempts, Attempt{Number: 1, Level: "minimal", Sources: []string{"hack-2"}, Episode: &ep,
		Status: "no_evidenced_issue", Rewards: map[string]*float64{"reward": &zero}})
	r.OtherEpisodes.Attacker = append(r.OtherEpisodes.Attacker, ep)
	for i := range r.Attack.Problems {
		if r.Attack.Problems[i].ID == "P2" {
			r.Attack.Problems[i].Unrewarded = &one
		}
	}
	_, open, tries := problemNamed(t, r, "P2")
	s := plainTab(r, 3, tries)
	if !strings.Contains(s, "The grader paid nothing, so nudi did not inspect it.") {
		t.Errorf("tries of P2:\n%s", s)
	}
	for _, s := range []string{plainTab(r, results, open), plainReport(r, plainW)} {
		if !strings.Contains(s, "1 attempt got reward 0, so nudi did not inspect it.") {
			t.Errorf("P2 does not count its unrewarded try:\n%s", s)
		}
	}
}

// An Attacker problem is one reading of its attempt: a further reading of that episode is neither its evidence nor
// standalone evidence.
func TestAttackerProblemIsOneReading(t *testing.T) {
	r := fixture(t, "full")
	index, further := 2, 9
	r.Attack.Problems = append(r.Attack.Problems, Problem{ID: "0014-attacker", Finding: "0014-attacker", Source: "Attacker", Cause: "a1", Level: 4, Assessment: &index})
	shortRefs(&r)
	f := r.Attack.Findings["evidenced"][2]
	f.Index, f.Claim.Mechanism = &further, "a further reading of the same episode"
	r.Attack.Findings["evidenced"] = append(r.Attack.Findings["evidenced"], f)
	_, open, _ := problemNamed(t, r, "A1")
	if s := plainTab(r, results, open); strings.Count(s, "0014-attacker") != 1 {
		t.Errorf("A1 on Results:\n%s", s)
	}
	if s := plainTab(r, results, "o"); strings.Contains(s, "a further reading") {
		t.Errorf("the further reading is listed apart:\n%s", s)
	}
}

// Without a problem of known type or outcome the Type column and the type groups would say nothing: Results has no
// Type column and the Attack tab one Problems group, with each problem's reference.
func TestNoTypeWithoutTypedProblems(t *testing.T) {
	r := fixture(t, "full")
	for i := range r.Attack.Problems {
		r.Attack.Problems[i].Outcome = ""
	}
	if s := plainTab(r, results); strings.Contains(oneLine(row(s, "Problem ")), "Type") {
		t.Errorf("Results has a Type column:\n%s", s)
	}
	s := plainTab(r, 3)
	if !strings.Contains(s, "Problems (6)") || strings.Contains(s, "Type Unknown") || !strings.Contains(oneLine(row(s, "Problem ")), "Ref") || !strings.Contains(s, "P1") {
		t.Errorf("Attack tab:\n%s", s)
	}
	hack := "hack"
	r.Attack.Problems[0].Type = &hack
	if s := plainTab(r, results); !strings.Contains(oneLine(row(s, "Problem ")), "Type") {
		t.Errorf("a typed problem lost the Type column:\n%s", s)
	}
	if s := plainTab(r, 3); !strings.Contains(s, "Hacks (1)") || !strings.Contains(s, "Type Unknown (5)") {
		t.Errorf("typed groups:\n%s", s)
	}
}

// An episode without a reward says when it ended and why, once, and the simulation is not called 12 of 12 episodes
// not finished.
func TestEpisodeWithoutRewardSaysWhen(t *testing.T) {
	r := fixture(t, "full")
	phase := "agent work"
	r.Ordinary.NoReward = map[string]Unrewarded{"0000-simulator": {ModelCalls: 12, Phase: &phase}}
	r.Ordinary.Failures = map[string][]string{"0000-simulator": {"ModalFailure: the sandbox ran out of memory"}}
	g := &r.Ordinary.Groups[0]
	x := g.Rewards["reward"]
	x.Usable = x.Attempted - 1
	g.Rewards["reward"] = x
	r.Unfinished = map[string]string{"simulation": "partial"}
	s := plainTab(r, results)
	if !strings.Contains(oneLine(s), "simulator ended during agent work: ModalFailure: the sandbox ran out of memory") || strings.Contains(s, "12 of 12 episodes") {
		t.Errorf("work left:\n%s", s)
	}
}

// The Answer's causes show as Python wrote them under the verdict, a problem's line under its cause keeping its indent
// as it wraps; the Answer's other problem lines stay in the problems table.
func TestCauseLinesAsWritten(t *testing.T) {
	r := fixture(t, "full")
	r.Answer = append(r.Answer[:2:2], "Causes, each one thing the grader trusts: a reading.",
		"C1: The test runs bash through PATH; ●●●●○ exploit executable by learner with hint.",
		"  - P1: reward 1; exists = false measured by check check-0003; ●●●●○ exploit executable by learner with hint; 2 of 2 assessed attempts with its help were exploits.",
		"  - P3: reward 1; exists = false measured by check check-0009; ●●○○○ reproduced exploit; not attacked on its own.",
		"P2: reward 0; a line the table says.")
	s := plainTab(r, results, "a")
	if !strings.Contains(s, "\n   C1: The test runs bash through PATH;") || !strings.Contains(s, "\n     - P1: reward 1;") || !strings.Contains(s, "\n       ") ||
		!strings.Contains(oneLine(s), "not attacked on its own.") || strings.Contains(s, "a line the table says") {
		t.Errorf("Results:\n%s", s)
	}
	if !slices.ContainsFunc(splitLines(s), func(l string) bool { return strings.HasPrefix(l, "       ") && strings.Contains(l, "were exploits.") }) {
		t.Errorf("a wrapped problem line lost its indent:\n%s", s)
	}
	p := plainReport(r, plainW)
	if !strings.Contains(p, "\n                      - P1: reward 1;") ||
		!slices.ContainsFunc(splitLines(p), func(l string) bool { return strings.HasPrefix(l, strings.Repeat(" ", 24)+"exploits.") }) {
		t.Errorf("plain:\n%s", p)
	}
}

// A problem table has no No info column: a try given no information is aimed at no problem. Its tries keep it.
func TestProblemTablesWithoutNoInfo(t *testing.T) {
	r := fixture(t, "full")
	for _, s := range []string{plainTab(r, results, "e"), plainTab(r, 3, "e")} {
		head := splitLines(s)[slices.IndexFunc(splitLines(s), func(l string) bool { return strings.Contains(l, "Problem ") && strings.Contains(l, "Hint") })]
		if strings.Contains(head, "No info") || strings.Contains(s, "No info, Hint") {
			t.Errorf("a No info column or legend:\n%s", s)
		}
	}
	if s := plainTab(r, results, "e"); !strings.Contains(s, "Hint, Full: an Attacker, by how much it was told.") {
		t.Errorf("legend:\n%s", s)
	}
}

// A problem's type is the report's type when it has one, else its measured outcome; an Attacker's exploit is
// incorrect work passed.
func TestProblemResultType(t *testing.T) {
	r := fixture(t, "full")
	hack := "hack"
	r.Attack.Problems[0].Type = &hack
	r.Attack.Problems = append(r.Attack.Problems, Problem{ID: "A1", Source: "Attacker", Cause: "an unaided exploit", Level: 5, Finding: "0016-attacker"})
	s := plainTab(r, results, "none")
	for _, want := range []string{"Type", "Hack", "Incorrect work passed", "Correct work failed"} {
		if !strings.Contains(s, want) {
			t.Errorf("Results lacks %q:\n%s", want, s)
		}
	}
	if rowOf(s, "an unaided exploit") == "" || !strings.Contains(rowOf(s, "an unaided exploit"), "Incorrect work passed") {
		t.Errorf("an Attacker problem's type:\n%s", s)
	}
	if a := plainTab(r, 3, "none"); !strings.Contains(a, "Hacks (1)") || !strings.Contains(a, "Incorrect Work Passed (") || !strings.Contains(a, "Correct Work Failed (2)") || strings.Contains(a, "Type Unknown") {
		t.Errorf("Attack groups:\n%s", a)
	}
	p := plainReport(r, plainW)
	if !regexp.MustCompile(`Type +Correct work failed`).MatchString(p) || !regexp.MustCompile(`Type +Hack: the reward`).MatchString(p) {
		t.Errorf("plain types:\n%s", p)
	}
}

// rowOf is the first line of s that contains text.
func rowOf(s, text string) string {
	for _, l := range splitLines(s) {
		if strings.Contains(l, text) {
			return l
		}
	}
	return ""
}

// The Answer's causes fold under one line on Results, a opens them; the verdict stays; the plain report keeps them.
func TestCausesFolded(t *testing.T) {
	r := fixture(t, "full")
	r.Answer = append(r.Answer[:2:2], "Causes, each one thing the grader trusts: a reading.",
		"C1: The test runs bash through PATH.", "  - P1: reward 1.", "C2: The grader trusts a timing file.", "  - P3: reward 1.")
	s := plainTab(r, results, "none")
	if !strings.Contains(s, r.Answer[1][:30]) || !strings.Contains(s, "▸ Causes (2)") || !strings.Contains(s, "a expand") || strings.Contains(s, "C1: The test") {
		t.Errorf("folded:\n%s", s)
	}
	m := press(newModel(r, 0, false), "a")
	if o := plainText(m.tabPage(-1).String()); !strings.Contains(o, "▾ Causes (2)") || !strings.Contains(o, "C1: The test runs bash") || !strings.Contains(o, "- P3: reward 1.") {
		t.Errorf("opened:\n%s", o)
	}
	if p := plainReport(r, plainW); !strings.Contains(p, "C2: The grader trusts a timing file.") {
		t.Errorf("plain:\n%s", p)
	}
	if s := plainTab(fixture(t, "full"), results, "none"); strings.Contains(s, "Causes (") {
		t.Errorf("a fold without causes:\n%s", s)
	}
}

// The category and pass rule labels read as plain words.
func TestPlainLabels(t *testing.T) {
	r := fixture(t, "full")
	for _, s := range []string{plainTab(r, 1), plainReport(r, plainW)} {
		if !strings.Contains(s, "Counts as passed") || !strings.Contains(s, "reward ≥ 0.5") || strings.Contains(s, "Pass rule") {
			t.Errorf("pass rule:\n%s", s)
		}
	}
	if word(checkNames, "unchecked_requirements") != "Skips a requirement the grader never checks" {
		t.Errorf("category: %s", word(checkNames, "unchecked_requirements"))
	}
}
