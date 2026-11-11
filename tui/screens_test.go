package main

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var screenFixtures = []string{"full", "clean", "full-0.0.0", "time-limit", "pipeline-full"}

// Every tab of each fixture at 100 columns, as it opens: Results first, then the four phases with nothing expanded.
func TestScreens(t *testing.T) {
	for _, name := range screenFixtures {
		r := fixture(t, name)
		var out []string
		for _, s := range []int{results, 0, 1, 2, 3} {
			m := newModel(r, 0, false)
			m.screen = s
			out = append(out, fmt.Sprintf("=== tab %d", s), plainText(m.top()+"\n\n"+m.page()))
		}
		golden(t, name, "screens.txt", strings.Join(out, "\n"))
	}
}

// golden checks that a screen says nothing a reader cannot use, then compares it with its saved copy.
func golden(t *testing.T, name, file, s string) {
	t.Helper()
	for _, banned := range []string{"synthetic", "fixture", "\u2014", " · ", "▲", "▼"} {
		if strings.Contains(s, banned) {
			t.Errorf("%s %s shows %q", name, file, banned)
		}
	}
	snapshot(t, name, file, s)
}

// Every finding of each fixture at 100 columns, under each of its tabs: Evidence, Limitations and References.
func TestDetailScreens(t *testing.T) {
	for _, name := range screenFixtures {
		r := fixture(t, name)
		found := r.findings()
		if len(found) == 0 {
			continue
		}
		var out []string
		for n := range found {
			for tab := range showTabs(found[n]) {
				out = append(out, fmt.Sprintf("=== finding %d tab %d", n+1, tab), plainText(renderShow(r, found, n+1, tab, "Results", 100)))
			}
		}
		golden(t, name, "detail.txt", strings.Join(out, "\n"))
	}
}

// The report a pipe gets for each fixture: its sections in the order of the Results tab, full ids and no colour.
func TestPlainScreens(t *testing.T) {
	for _, name := range screenFixtures {
		s := plainReport(fixture(t, name), plainW)
		if strings.Contains(s, "\x1b") || strings.Contains(s, "…") {
			t.Errorf("%s: the pipe gets colour or a cut value", name)
		}
		golden(t, name, "plain.txt", s)
	}
}

func TestHelpScreen(t *testing.T) {
	code, out, _ := run("--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	golden(t, ".", "help.txt", strings.TrimSuffix(out, "\n"))
}

// Each way a run can end has its own Results banner.
func TestEndings(t *testing.T) {
	for body, want := range map[string]string{
		`"status": "complete", "answer": ["Finished", "No hack found."]`:                                         "✓ Finished",
		`"status": "partial", "answer": ["Finished", "x"]`:                                                       "Partly finished",
		`"answer": ["Stopped", "x"], "stop": {"kind": "cancelled"}`:                                              "Stopped by you",
		`"answer": ["Stopped", "x"], "stop": {"kind": "terminated"}`:                                             "Stopped by a termination signal",
		`"answer": ["Stopped", "x"], "stop": {"kind": "time_limit", "minutes": 5}, "elapsed": 300`:               "Stopped at the time limit  5:00 of 5:00",
		`"answer": ["Stopped", "x"], "stop": {"kind": "spending_cap"}`:                                           "Stopped at the spending cap",
		`"answer": ["Stopped", "x"], "stop": {"kind": "stopped", "reason": "no run_end event"}`:                  "Run not finished",
		`"answer": ["Stopped", "x"], "stop": {"kind": "provider_refused", "reason": "the provider refused it"}`:  "Stopped by the model provider",
		`"answer": ["Stopped", "x"], "stop": {"kind": "provider_refused", "reason": "the provider refused it."}`: "The provider refused it.\n",
		`"answer": ["Could not start: no task.toml"]`:                                                            "no task.toml",
		`"answer": ["Finished", "x"], "analyses": {"hack": "partial"}, "phase_errors": {"hack": "boom\nmore"}`:   "Find Hacks failed",
	} {
		r, err := load(writeReport(t, "{"+body+"}"))
		if err != nil {
			t.Fatal(err)
		}
		if s := plainText(strings.Join(ending(r, r.findings(), 100), "\n")); !strings.Contains(s, want) {
			t.Errorf("%s: lacks %q:\n%s", body, want, s)
		}
	}
}

// A phase the run left out says so on its tab and on Results; one that was selected but never started says that.
func TestPhasesNotRun(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["Stopped", "x"], "analyses": {"simulation": "complete", "grader": "not run"}, "stop": {"kind": "cancelled"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for s, want := range map[int]string{
		1:       "Selected, but it did not start before the run stopped.",
		2:       "FIND HACKS  not selected for this run",
		results: "Not available: Grade Simulations",
	} {
		if got := plainTab(r, s); !strings.Contains(got, want) {
			t.Errorf("tab %d lacks %q:\n%s", s, want, got)
		}
	}
}

// At 60, 80, 100 and 120 columns and 24 rows, every tab and panel, expanded or not, and every finding's tab fits the window.
func TestWidthSweep(t *testing.T) {
	for _, name := range screenFixtures {
		r := fixture(t, name)
		for _, w := range []int{60, 80, 100, 120} {
			for n := 1; n <= len(r.findings()); n++ {
				for tab := range 3 {
					var tm tea.Model = newModel(r, n, false)
					tm, _ = tm.Update(tea.WindowSizeMsg{Width: w, Height: 24})
					m := tm.(model)
					m.tab = tab
					v := m.layout().View().Content
					if h := lipgloss.Height(v); h > 24 {
						t.Errorf("%s at %d: finding %d tab %d is %d rows", name, w, n, tab, h)
					}
					for _, l := range splitLines(v) {
						if width(l) > w {
							t.Errorf("%s at %d: finding %d tab %d has a line %d wide: %s", name, w, n, tab, width(l), plainText(l))
							break
						}
					}
				}
			}
			for s := 0; s <= results; s++ {
				for _, overlay := range []string{"", "m", "c", "?"} {
					for _, all := range []bool{false, true} {
						var tm tea.Model = newModel(r, 0, false)
						tm, _ = tm.Update(tea.WindowSizeMsg{Width: w, Height: 24})
						m := tm.(model)
						m.screen, m.overlay = s, overlay
						if all {
							open := []string{"o", "i", "s", "x", "?", "episodes"}
							m.page()
							for _, it := range m.items {
								open = append(open, it.key)
							}
							for _, k := range open {
								m.open[fmt.Sprint(s)+k] = true
							}
						}
						m = m.layout()
						v := m.View().Content
						if h := lipgloss.Height(v); h > 24 {
							t.Errorf("%s at %d: tab %d %q is %d rows", name, w, s, overlay, h)
						}
						for _, l := range splitLines(v) {
							if width(l) > w {
								t.Errorf("%s at %d: tab %d %q has a line %d wide: %s", name, w, s, overlay, width(l), plainText(l))
								break
							}
						}
					}
				}
			}
		}
	}
}
