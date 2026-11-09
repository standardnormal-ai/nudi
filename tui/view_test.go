package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// renderAll draws every screen of r at two widths and checks that no line is wider than the window.
func renderAll(t *testing.T, r Report) {
	t.Helper()
	found := r.findings()
	for _, w := range []int{80, 120} {
		screens := []string{card(r, w, true), card(r, w, false)}
		for p := range phases {
			screens = append(screens, renderPhase(r, found, p, w))
		}
		for n := range found {
			screens = append(screens, renderShow(r, found, n+1, 0, w), renderShow(r, found, n+1, 1, w), plainShow(r, found, n+1, w))
		}
		for i, s := range screens[2:] {
			if i >= len(phases) && (i-len(phases))%3 == 2 {
				continue // a pipe gets whole lines
			}
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

func plainPhase(r Report, phase int) string {
	return plainText(renderPhase(r, r.findings(), phase, wideAt-1))
}

// Only a problem's candidate is attacked, so only it is marked; the other members stay listed unmarked.
func TestProblemMarksOnlyTheCandidate(t *testing.T) {
	r := fixture(t, "full-before-levels")
	attack := plainPhase(r, 3)
	for _, want := range []string{
		"#3 hack-1 (selected · attempted · reproduced)   #5 hack-3\n",
		"#4 hack-2 (selected · attempted · reproduced)\n",
		"#6 hack-4 (selected · not tested)\n",
		"1 finding not tested",
	} {
		if !strings.Contains(attack, want) {
			t.Errorf("attack panel lacks %q:\n%s", want, attack)
		}
	}
	if n := strings.Count(attack, "· reproduced)"); n != 2 {
		t.Errorf("%d reproduced marks, want 2", n)
	}
	found := r.findings()
	for n, want := range map[int]string{
		3: "problem 1 of 4 · this finding (selected · attempted · reproduced)",
		5: "problem 1 of 4 · the attack tests #3 hack-1 for it",
		6: "problem 3 of 4 · this finding (selected · not tested)",
		1: "",
	} {
		show := ansi.Strip(renderShow(r, found, n, 0, 120))
		if want == "" && strings.Contains(show, "problem") || !strings.Contains(show, want) {
			t.Errorf("finding %d lacks %q:\n%s", n, want, show)
		}
	}
	// Python's answer counts the problems; the card adds no count of its own, and the hack panel keeps one.
	if s := card(r, 120, false); strings.Count(s, "problems from") != 1 || !strings.Contains(s, "4 problems from 4 hack inspector findings and 1 grader inspector finding; the attack selects") {
		t.Errorf("card counts the problems other than once, in Python's words:\n%s", s)
	}
	if !strings.Contains(plainPhase(r, 2), "4 problems from 4 hack inspector findings and 1 grader inspector finding") {
		t.Error("the hack panel does not count the problems")
	}
}

// A finding is marked reproduced only when reproduced_findings names it; a report without that field
// marks the candidate of a reproduced problem, as before.
func TestReproducedFindingsMarkOnlyThose(t *testing.T) {
	report := func(field string) Report {
		r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "other_episodes": {"attacker": ["e"]},
			"inspections": {"hack_inspector": {"findings": {"evidenced": [
				{"index": 1, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m1"}},
				{"index": 2, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m2"}}]}}},
			"attack": {"candidates": [{"id": "hack-1"}],
				"attempts": [{"level": "full", "candidate": "hack-1", "sources": ["hack-1", "hack-2"], "episode": "e", "status": "evidenced_issue"}],
				"problems": [{"cause": "c", "findings": ["hack-1", "hack-2"], "candidate": "hack-1", "reproduced": true`+field+`}]}}`))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for field, want := range map[string][3]string{
		``: {"#1 hack-1 (selected · attempted · reproduced)   #2 hack-2\n",
			"this finding (selected · attempted · reproduced)\n", "the attack tests #1 hack-1 for it\n"},
		`, "reproduced_findings": ["hack-2"]`: {"#1 hack-1 (selected · attempted)   #2 hack-2 (reproduced)\n",
			"this finding (selected · attempted)\n", "the attack tests #1 hack-1 for it (reproduced)\n"},
		`, "reproduced_findings": ["hack-1", "hack-2"]`: {"#1 hack-1 (selected · attempted · reproduced)   #2 hack-2 (reproduced)\n",
			"this finding (selected · attempted · reproduced)\n", "the attack tests #1 hack-1 for it (reproduced)\n"},
		`, "reproduced_findings": []`: {"#1 hack-1 (selected · attempted)   #2 hack-2\n",
			"this finding (selected · attempted)\n", "the attack tests #1 hack-1 for it\n"},
	} {
		r := report(field)
		found := r.findings()
		for i, s := range []string{plainPhase(r, 3), plainShow(r, found, 1, 100), plainShow(r, found, 2, 100)} {
			if !strings.Contains(s, want[i]) {
				t.Errorf("%q: lacks %q:\n%s", field, want[i], s)
			}
		}
	}
}

func TestReportWithoutProblems(t *testing.T) {
	r := fixture(t, "full-0.0.0")
	if r.Attack.Problems != nil || r.problemOf("hack-1") != -1 {
		t.Fatalf("problems: %v", r.Attack.Problems)
	}
	for _, s := range []string{plainPhase(r, 2), plainPhase(r, 3), card(r, 120, false), plainShow(r, r.findings(), 3, 120)} {
		if strings.Contains(s, "problem") || strings.Contains(s, "PROBLEMS") {
			t.Errorf("a report without problems shows some:\n%s", s)
		}
	}
	if !strings.Contains(plainPhase(r, 3), "#3 hack-1          full instructions") {
		t.Error("attempts are missing")
	}
}

// A run stopped before the attack reached its candidate says so; nothing in it failed.
func TestStoppedRunSaysNotTested(t *testing.T) {
	r := fixture(t, "time-limit-before-levels")
	attack := plainPhase(r, 3)
	for _, want := range []string{"ATTACK  stopped", "#1 hack-0 (selected · not tested)", "·· not tested", "1 finding not tested"} {
		if !strings.Contains(attack, want) {
			t.Errorf("attack panel lacks %q:\n%s", want, attack)
		}
	}
	for _, s := range []string{attack, card(r, 120, false), plainShow(r, r.findings(), 1, 120)} {
		for _, bad := range []string{"fail", "error", "reproduced", " attempted"} { // Python's warnings say "unattempted"
			if strings.Contains(strings.ToLower(s), bad) {
				t.Errorf("%q in:\n%s", bad, s)
			}
		}
	}
	if exitCode(r) != 1 || exitCode(fixture(t, "time-limit")) != 1 || exitCode(fixture(t, "full")) != 0 || exitCode(fixture(t, "clean-before-levels")) != 1 {
		t.Error("exit codes differ from Python's")
	}
}

func TestAgreementTable(t *testing.T) {
	grader := plainPhase(fixture(t, "full"), 1)
	for _, want := range []string{
		"Type │ Meaning               │ Episodes",
		"TP   │ Correct work passed   │ ███████████████ 3",
		"FP   │ Incorrect work passed │ █████ 1",
		"pass means reward >= 0.5",
		"FDR (Of accepted work, how much was incorrect?)  FP / (TP + FP)  1/4  25%",
		"FNR (Of correct work, how much was rejected?)    FN / (TP + FN)  1/4  25%",
		"Searched: Incorrect work passed; Correct work failed",
	} {
		if !strings.Contains(grader, want) {
			t.Errorf("grader panel lacks %q:\n%s", want, grader)
		}
	}
}

// The grounded native pass rate stands with its 95% Wilson interval, as report.md words it, on the card and the
// Grade Simulations screen; a missing or unavailable rate reads unavailable, and an older one without its interval shows none.
func TestNativePassRate(t *testing.T) {
	r := fixture(t, "full")
	for _, s := range []string{plainPhase(r, 1), card(r, 120, false)} {
		if want := "native pass rate 83% (10/12), 95% Wilson interval 0.55 to 0.95"; !strings.Contains(oneLine(s), want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	for rate, want := range map[string][2]string{
		``: {"native pass rate unavailable", "native pass rate unavailable"},
		`, "pass_rate": {"value": null, "numerator": null, "denominator": null, "unavailable": "native pass rate is unavailable: no source-grounded native decision rule", "interval": null}`: {
			"native pass rate is unavailable: no source-grounded native decision rule", "native pass rate unavailable"},
		`, "pass_rate": {"value": 0.5, "numerator": 1, "denominator": 2}`: {"native pass rate 50% (1/2)", "native pass rate 50% (1/2)"},
	} {
		r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"grader": "complete"},
			"metrics": {"confusion": [{"status": "unsupported", "reasons": ["r"]`+rate+`}]}}`))
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range []string{oneLine(plainPhase(r, 1)), oneLine(card(r, 100, false))} {
			if !strings.Contains(s, want[i]) || strings.Contains(s, "Wilson") {
				t.Errorf("%q: lacks %q:\n%s", rate, want[i], s)
			}
		}
	}
}

// Without grader agreement the pass rate still names its rule, as report.md does; a group without a rule names none.
func TestPassRateKeepsItsRuleWithoutAgreement(t *testing.T) {
	for _, status := range []string{"unsupported", "unavailable"} {
		for rule, want := range map[string]string{
			`, "rule": {"comparison": ">=", "threshold": 0.5, "pass_values": []}`: "pass means reward >= 0.5 native pass rate 67% (2/3)",
			``: "r native pass rate 67% (2/3)",
		} {
			r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"grader": "complete"},
				"metrics": {"confusion": [{"reward": "reward", "status": "`+status+`", "reasons": ["r"]`+rule+`,
					"pass_rate": {"value": 0.6667, "numerator": 2, "denominator": 3}}]}}`))
			if err != nil {
				t.Fatal(err)
			}
			if s := oneLine(plainPhase(r, 1)); !strings.Contains(s, want) {
				t.Errorf("%s %q: lacks %q:\n%s", status, rule, want, s)
			}
		}
	}
}

func TestCategoriesShowOnlyWhatWasSearched(t *testing.T) {
	r, err := load(writeReport(t, `{"answer":["x"], "inspections":{"hack_inspector":{
        "categories":{"grader_tampering":"no_evidenced_issue","online_lookup":"unknown","persistence":"restricted"},
        "applicability":{"persistence":"the task resets nothing between episodes"},
        "attempts":[{"phase":"focused","number":1,"category":"grader_tampering","status":"no_evidenced_issue"}],
        "limits":["Search stopped at the spending cap."]}},
        "warnings":["hack inspector category online_lookup is unknown: network access ended before the probe"]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainText(hackPanel(r, 160))
	for _, want := range []string{"Searched: Edits grader or tests\n", "Looks answer up online: no search attempt recorded",
		"Files survive reset: the task resets nothing between episodes", "focused attempt 1 (Edits grader or tests): completed",
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
		screens := []string{card(r, 120, false), card(r, 120, true)}
		for p := range phases {
			screens = append(screens, plainPhase(r, p))
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
	if code != 0 || out != card(fixture(t, "full"), plainW, false)+"\n" || strings.Contains(out, "\x1b") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "next › nudi-view testdata/full P1") {
		t.Error("the card does not say what to run next")
	}
	code, out, _ = run("testdata/full", "6")
	for _, want := range []string{"finding 6 of 9", "HACK", "hack-4", "◆ open", "whether the timing file is read", "Limitations 2"} {
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
		msg := tea.KeyPressMsg{Text: k}
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		case "left":
			msg = tea.KeyPressMsg{Code: tea.KeyLeft}
		}
		next, _ := m.Update(msg)
		m = next.(model)
	}
	return m
}

func TestKeys(t *testing.T) {
	m := newModel(fixture(t, "full"), 0, true)
	if m = press(m, "x"); m.intro != nil {
		t.Fatal("a key does not skip the intro")
	}
	if m.phase != len(phases)-1 || !strings.Contains(m.View().Content, "The grader can be cheated") {
		t.Fatal("the viewer does not open on the card")
	}
	// Enter opens the card's next finding, the one that shows problem P1, finding 3.
	m = press(m, "enter", "l", "l", "tab")
	if m.n != 5 || m.tab != 1 || !strings.Contains(ansi.Strip(m.View().Content), "finding 5 of 9") {
		t.Fatalf("finding %d tab %d", m.n, m.tab)
	}
	m = press(m, "esc", "left", "h")
	if m.n != 0 || m.phase != 2 || !strings.Contains(ansi.Strip(m.View().Content), "FIND HACKS  done") {
		t.Fatalf("finding %d phase %d", m.n, m.phase)
	}
	if m = press(m, "q"); !m.exited || m.View().Content != "" {
		t.Fatal("q does not quit")
	}
	if m := newModel(fixture(t, "full"), 6, false); !strings.Contains(ansi.Strip(m.View().Content), "finding 6 of 9") {
		t.Fatal("N does not open on finding N")
	}
}

// oneLine joins wrapped text back into one line, so a test can look for a whole sentence.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// The rewards show Python's summaries and its flags with their reasons as written, on the card and the Simulation screen.
func TestRewardSummariesAndFlags(t *testing.T) {
	r := fixture(t, "full")
	for _, s := range []string{plainPhase(r, 0), card(r, 120, false)} {
		for _, want := range []string{
			"mean 0.8333 · median 1 · sample SD 0.3892 · skewness -2.055",
			"▲ Lower minority",
			"2 of 12 usable 'reward' rewards are below the rest by the quartile rule (0004-simulator 0, 0005-simulator 0; median 1, lower fence 1).",
			"Every named episode has a presumed or unsupported label, so grader inspection did not examine this pattern.",
		} {
			if !strings.Contains(oneLine(s), want) {
				t.Errorf("lacks %q:\n%s", want, s)
			}
		}
	}
	if s := oneLine(plainPhase(fixture(t, "clean"), 0)); !strings.Contains(s, "Distribution flags are not evaluated for 'reward': 4 usable rewards, fewer than 10.") {
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
	s := plainPhase(r, 0)
	if !strings.Contains(s, "mean 1 · median unavailable · sample SD unavailable · skewness unavailable") || strings.Contains(s, " 0 ") {
		t.Errorf("rewards:\n%s", s)
	}
}

// A grader-N candidate is the grader inspector's finding with index N, as Python names it, so the attack names that finding's number.
func TestGraderCandidateNamesItsFinding(t *testing.T) {
	r := fixture(t, "full-before-levels")
	attack := plainPhase(r, 3)
	for _, want := range []string{"#2 grader-7 (selected · attempted)\n", "#2 grader-7        full instructions valid work"} {
		if !strings.Contains(attack, want) {
			t.Errorf("attack panel lacks %q:\n%s", want, attack)
		}
	}
	if show := plainShow(r, r.findings(), 2, 120); !strings.Contains(show, "grader-7") || !strings.Contains(show, "problem 4 of 4 · this finding (selected · attempted)") {
		t.Errorf("finding 2:\n%s", show)
	}
}

// A pipe gets the card at most 100 columns wide: a long finding or warning line breaks at spaces, a
// finding continuing under its mechanism, every word kept; the next command moves whole to its own line.
func TestPlainCardKeepsItsWidth(t *testing.T) {
	long := strings.TrimSpace(strings.Repeat("the grader reads a file the agent can write ", 6))
	r, err := load(writeReport(t, `{"answer": ["x"], "warnings": ["`+long+`"], "attack": {"findings": {"evidenced": [
		{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "`+long+`"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Dir = "runs/" + strings.Repeat("x", 80)
	s := card(r, plainW, false)
	lines := splitLines(s)
	for i, line := range lines {
		if width(line) > plainW {
			t.Errorf("%d columns: %q", width(line), line)
		}
		if strings.HasPrefix(line, "  1  HACK") {
			if next := lines[i+1]; len(next) <= 21 || strings.TrimLeft(next, " ") != next[21:] {
				t.Errorf("finding continues as %q", next)
			}
		}
	}
	if !strings.HasSuffix(s, "\n next ›\n   nudi-view "+r.Dir+" 1") {
		t.Errorf("the next command is not whole on its own line:\n%s", s)
	}
	flat := oneLine(s)
	for _, want := range []string{"HACK " + long, "warning in " + r.Dir + "/report.md " + long, "next › nudi-view " + r.Dir + " 1"} {
		if !strings.Contains(flat, want) {
			t.Errorf("card lacks %q:\n%s", want, s)
		}
	}
}

// The card lists the first warnings in Python's words, each by its first line, and counts the rest.
func TestCardListsWarnings(t *testing.T) {
	s := card(fixture(t, "full"), 120, false)
	want := " ▲ 5 warnings in testdata/full/report.md\n" +
		"   attack candidate hack-1 minimal is unknown\n" +
		"   attack candidates hack-2 minimal, hack-4 full and minimal are unattempted\n" +
		"   11 of 12 ordinary episodes have no supported local label (unknown 6, unreviewed 5); they are excluded, not counted as\n" +
		"   correct\n" +
		"   and 2 more\n"
	if !strings.Contains(s, want) {
		t.Errorf("card lacks %q:\n%s", want, s)
	}
	if s := card(fixture(t, "clean-before-levels"), 120, false); !strings.Contains(s, "2 warnings") || !strings.Contains(s, "hack partial: its coverage is incomplete") ||
		!strings.Contains(s, "the task resets nothing between episodes") {
		t.Errorf("clean card:\n%s", s)
	}
	r, err := load(writeReport(t, `{"answer": ["x"], "warnings": ["a\u001b[2Jb\u202ec\tok\nits second line", "two", "three", "four"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{card(r, 100, false), card(r, 100, true)} {
		if !strings.Contains(s, "a[2Jbc ok") || strings.Contains(s, "second line") || strings.ContainsAny(s, "\u202e\t") || !strings.Contains(ansi.Strip(s), "and 1 more") {
			t.Errorf("warnings:\n%q", s)
		}
	}
}

// An attack finding keeps what Python's exploits say it confirmed beside its tag, wherever the tag is drawn.
func TestAttackTagsKeepWhatTheyConfirmed(t *testing.T) {
	r := fixture(t, "full-before-levels")
	c := card(r, 120, false)
	for _, want := range []string{
		" 7  HACK            reproduced #3 hack-1 · planted a bash shim that prints the pass marker\n",
		" 8  FN              reproduced #4 hack-2 · wrote the answer with leading zeros\n",
		" 9  HACK            not confirmed as #3 hack-1 · wrote the pass marker without running the tests\n",
		" 3  HACK            unchecked requirement\n",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("card lacks %q:\n%s", want, c)
		}
	}
	if s := plainShow(r, r.findings(), 9, 120); !strings.Contains(s, "\n not confirmed as #3 hack-1\n") {
		t.Errorf("finding 9:\n%s", s)
	}
	if s := plainPhase(r, 3); !strings.Contains(s, "#9 HACK check-0011") || !strings.Contains(s, "not confirmed as #3 hack-1") {
		t.Errorf("found panel:\n%s", s)
	}
	attack := func(exploits string) string {
		return `{"answer": ["x"], "attack": {` + exploits + `"findings": {"evidenced": [
			{"index": 0, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m0"}},
			{"index": 1, "assessment": {"outcome": "accepted_invalid"}, "claim": {"mechanism": "m1"}}]}}}`
	}
	for body, want := range map[string][]string{
		attack(`"exploits": {"discovery": [{"assessment": 0, "candidate": null, "sources": []}]}, `): {
			"HACK            found with no extra information · m0\n", "HACK            confirms no tested finding · m1"},
		attack(""): {"HACK            m0\n", "HACK            m1"},
	} {
		r, err := load(writeReport(t, body))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if s := card(r, 100, false); !strings.Contains(s, w) {
				t.Errorf("card lacks %q:\n%s", w, s)
			}
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
	unavailable := []string{"HACK            confirmation unavailable · m0\n", "HACK            confirmation unavailable · m1"}
	for body, want := range map[string][]string{
		attack(`"index": 0, `, `{"assessment": 0, "sources": ["hack-5"]}`):    {"HACK            reproduced hack-5 · m0\n", "HACK            confirms no tested finding · m1"},
		attack(`"index": 0, `, `{"assessment": 1, "sources": ["hack-5"]}`):    {"HACK            confirms no tested finding · m0\n", "HACK            reproduced hack-5 · m1"},
		attack(`"index": 0, `, `{"sources": ["hack-5"]}`):                     unavailable,
		attack(`"index": 0, `, `{"assessment": null, "sources": ["hack-5"]}`): unavailable,
		attack(`"index": 0, `, `null`):                                        unavailable,
		attack(``, `{"assessment": 0, "sources": ["hack-5"]}`):                {"HACK            confirmation unavailable · m0\n", "HACK            confirms no tested finding · m1"},
		attack(`"index": null, `, `{"assessment": 0, "sources": ["hack-5"]}`): {"HACK            confirmation unavailable · m0\n", "HACK            confirms no tested finding · m1"},
	} {
		r, err := load(writeReport(t, body))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if s := card(r, 100, false); !strings.Contains(s, w) {
				t.Errorf("card lacks %q:\n%s", w, s)
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
		if s := plainShow(r, found, 1, 100); strings.Contains(s, "grader-0") || strings.Contains(s, "problem 1 of 1") {
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
		``:                                      "\n flag details unavailable",
		`, "flags": null`:                       "\n flag details unavailable",
		`, "flags": [null]`:                     "\n ▲ flag details unavailable",
		`, "flags": [{"text": "t"}]`:            "\n ▲ flag details unavailable",
		`, "flags": [{"flag": "low_minority"}]`: "\n ▲ flag details unavailable",
		`, "flags": [{"flag": null, "text": "t"}]`: "\n ▲ flag details unavailable",
		`, "flags": []`: "",
	} {
		r, err := load(writeReport(t, rewards(flags)))
		if err != nil {
			t.Fatal(err)
		}
		s := plainPhase(r, 0)
		if want == "" && strings.Contains(s, "flag details") || want != "" && !strings.Contains(s, want) {
			t.Errorf("%q:\n%s", flags, s)
		}
	}
}

// An attempt not started for lack of time is not tested; one whose workspace ran out of memory, or whose attack inspector ran out of steps, failed.
func TestAttackStopsHaveWords(t *testing.T) {
	for status, want := range map[string]Result{"insufficient_time": NotTested, "out_of_memory": Failed, "step_limit": Failed} {
		clear(missed)
		if res, _ := lookup(attemptResults, status); res != want || missed[status] {
			t.Errorf("%s shows as %v", status, res)
		}
	}
}

func TestBroadSearchExcludesRestrictionsButKeepsMeasuredWork(t *testing.T) {
	r, err := load(writeReport(t, `{"answer":["x"],"inspections":{"hack_inspector":{
        "categories":{"online_lookup":"unknown","persistence":"restricted"},
        "attempts":[{"phase":"broad","status":"no_evidenced_issue"}],
        "limits":["stopped before sessions ended, so they are unknown"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	in := r.Inspections["hack_inspector"]
	s := plainText(hackPanel(r, 160))
	if !strings.Contains(s, "Searched: Looks answer up online\n") || strings.Contains(s, "so they are unknown") {
		t.Fatal(s)
	}
	in.Experiments = append(in.Experiments, struct {
		Category string `json:"category"`
	}{Category: "persistence"})
	if s := plainText(hackPanel(r, 160)); !strings.Contains(s, "Searched: Looks answer up online; Files survive reset\n") {
		t.Fatal(s)
	}
}

// A problem id opens the finding that shows it, and the finding's screen names its problem by that id.
func TestViewOpensAProblemById(t *testing.T) {
	code, out, _ := run("testdata/pipeline-full", "P2")
	if code != 0 || !strings.Contains(out, "hack-2") || !strings.Contains(out, "P2 · this finding") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if code, _, errs := run("testdata/pipeline-full", "P9"); code != 2 || !strings.Contains(errs, "run has no problem P9") {
		t.Errorf("exit %d, %q", code, errs)
	}
}
