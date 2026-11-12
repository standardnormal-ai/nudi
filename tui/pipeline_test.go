package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the snapshots of the pipeline fixtures")

// pipelineLive reads a fixture's whole event log, and the time of its last event, at which its snapshot is drawn.
func pipelineLive(t *testing.T, name string) *Live {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	l := &Live{Dir: "testdata/" + name}
	for _, e := range readAll(t, string(b)) {
		l.apply(e)
	}
	return l
}

// snapshot compares s with the fixture's snapshot file, or rewrites it with -update.
func snapshot(t *testing.T, name, file, s string) {
	t.Helper()
	path := filepath.Join("testdata", name, file)
	if *update {
		if err := os.WriteFile(path, []byte(s+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != s+"\n" {
		t.Errorf("%s differs; go test -run %s -update rewrites it:\n%s", path, t.Name(), s)
	}
}

// checkWidths draws l at 120, 100, 80 and 60 columns, also 24 rows high, where liveScreen checks the lines fit.
func checkWidths(t *testing.T, l *Live) {
	t.Helper()
	for _, w := range []int{120, 100, 80, 60} {
		liveScreen(t, l, l.Last.at(), w, 0)
		liveScreen(t, l, l.Last.at(), w, 24)
	}
}

// row is the first plain line of s that starts, after its indent, with prefix.
func row(s, prefix string) string {
	for _, line := range splitLines(s) {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return line
		}
	}
	return ""
}

// Problems form as the judge names them: the same ones fold under their problem, the reproduction settles each.
// cells are the words of the first row of s that starts with prefix, after it.
func cells(s, prefix string) string {
	return strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, prefix)), prefix)), " ")
}

func TestPipelineLanesFromEvents(t *testing.T) {
	l := pipelineLive(t, "pipeline-hacks")
	var got []string
	for _, n := range l.Lanes {
		got = append(got, n.ID+" "+n.Reproduced+" "+strings.Join(n.Members, ","))
	}
	if s := strings.Join(got, "; "); s != "P1 evidenced experiment-0002,experiment-0005; P2 evidenced ; P3  ; P4 not_reproduced " {
		t.Fatalf("lanes: %s", s)
	}
	if l.Slots == nil || *l.Slots != 6 || l.ZeroJudged != nil {
		t.Fatalf("slots %v, zero judged %v", l.Slots, l.ZeroJudged)
	}
	g := pipelineLive(t, "pipeline-grader")
	if n := g.lane("P1"); !n.Alone || strings.Join(n.Members, ",") != "experiment-0002,experiment-0005,0000-attacker" {
		t.Fatalf("P1 %+v", n)
	}
	if last := g.Lanes[len(g.Lanes)-1]; last.ID != "grader-6" || last.Same != "P4" || g.lane("G1") == nil {
		t.Fatalf("grader lanes %+v", g.Lanes)
	}
	if p, x := g.hackCounts(); p != 4 || x != 2 {
		t.Fatalf("%d problems, %d exploited", p, x)
	}
}

func TestPipelineHacksScreen(t *testing.T) {
	l := pipelineLive(t, "pipeline-hacks")
	checkWidths(t, l)
	s := liveScreen(t, l, l.Last.at(), 100, 0)
	snapshot(t, "pipeline-hacks", "screen.txt", s)
	for _, want := range []string{
		"Find Hacks  ⣾", "Find Hacks  ⣾ ── Attack ⣾", "Simulation ── Grade Simulations ──", "Agents  5 running",
		"General search", "Focused search", "Edits grader or tests", "No information", "Skips the test file", "Full instructions, try 1",
		"Checks try 1, hint", "Findings So Far (4)", "Finding", "New?", "Inspector?", "Full instr.?", "Hint?",
		"Related Observations (2)", "Can an Attacker Succeed Without Any Information?",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	for prefix, want := range map[string]string{
		"Reward reads stdout":    "✓ ✓ ✓ ⣾ 2:04",
		"Skips the test file":    "✓ ✓ ⣾ 3:20 -",
		"Writes expected output": "✓ ⣾ 3:10 - -",
		"Timeout counts as pass": "✓ ✗ - -",
		"1     ⣾ 8:49":           "",
	} {
		if got := cells(s, prefix); got != want || row(s, prefix) == "" {
			t.Errorf("%s row: %q", prefix, row(s, prefix))
		}
	}
	for _, gone := range []string{"experiment-", "·", "same as P1", "✓ another way", "✗ not reproduced", "(grader)", "judge:"} {
		if strings.Contains(s, gone) {
			t.Errorf("shows %q:\n%s", gone, s)
		}
	}
	open := liveKeys(t, l, l.Last.at(), 100, 0, "o")
	if got := cells(open, "experiment-0002"); got != "Hack Inspector ✗ Reward reads stdout" {
		t.Errorf("related observation: %q\n%s", got, open)
	}
}

// In 24 rows the agents keep one row of tiles with the others a key away, and the findings keep the rows that fit.
func TestPipelineHacksShortScreen(t *testing.T) {
	l := pipelineLive(t, "pipeline-hacks")
	s := liveScreen(t, l, l.Last.at(), 100, 24)
	snapshot(t, "pipeline-hacks", "screen-24.txt", s)
	if !strings.Contains(s, "Agents 1-3 of 5  ←/→ more") || strings.Contains(s, "Skips the test file\n") {
		t.Errorf("agents:\n%s", s)
	}
	if s := liveKeys(t, l, l.Last.at(), 100, 24, "right", "right"); !strings.Contains(s, "Agents 4-5 of 5") || !strings.Contains(s, "Checks try 1, hint") {
		t.Errorf("the next agents:\n%s", s)
	}
	if s := liveKeys(t, l, l.Last.at(), 100, 24, "down", "down", "down"); strings.Contains(s, "Agents 1-3 of 5") {
		t.Errorf("scrolled:\n%s", s)
	}
	if s := liveKeys(t, l, l.Last.at(), 100, 24, "f"); !strings.Contains(s, "Timeout counts as pass") || strings.Contains(s, "Agents 1-3 of 5") {
		t.Errorf("all findings:\n%s", s)
	}
}

// At any size the findings show a header only over rows: the rows that fit, at least two, or one line that f opens.
func TestLiveFindingsNeverShowAnEmptyHeader(t *testing.T) {
	for _, name := range []string{"pipeline-hacks", "pipeline-grader"} {
		l := pipelineLive(t, name)
		for _, w := range []int{60, 80, 100, 120} {
			for h := 20; h <= 40; h++ {
				lines := splitLines(liveScreen(t, l, l.Last.at(), w, h))
				for i, line := range lines {
					if strings.HasPrefix(line, " Finding ") && (i+1 == len(lines) || strings.TrimSpace(lines[i+1]) == "" || strings.Contains(lines[i+1], "more ↓")) {
						t.Errorf("%s at %dx%d: a header without rows:\n%s", name, w, h, strings.Join(lines, "\n"))
					}
				}
			}
		}
	}
}

func TestPipelineGraderScreen(t *testing.T) {
	l := pipelineLive(t, "pipeline-grader")
	checkWidths(t, l)
	s := liveScreen(t, l, l.Last.at(), 100, 0)
	snapshot(t, "pipeline-grader", "screen.txt", s)
	snapshot(t, "pipeline-grader", "screen-24.txt", liveScreen(t, l, l.Last.at(), 100, 24))
	for _, want := range []string{
		"Find Hacks ✓", "Grade Simulations  ⣾", "Grader Inspector", "Agents  1 running", "General review",
		"novelty_judge     Same as an earlier finding: timeout counts as pass", "Related Observations (5)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	for prefix, want := range map[string]string{
		"Reward reads stdout":    "✓ ✓ ✓ ✗",
		"Skips the test file":    "✓ ✓ ✓ ✗",
		"Writes expected output": "✓ ✓ ✗ -",
		"Accepts empty answer":   "✓ ✓ - -",
		"Timeout counts as pass": "✓ ✓ - -",
		"1     Finished":         "✓ ✗ Reward reads stdout",
	} {
		if got := cells(s, prefix); got != want {
			t.Errorf("%s row: %q", prefix, row(s, prefix))
		}
	}
	if strings.Index(s, "Timeout counts") > strings.Index(s, "Accepts empty") {
		t.Errorf("grader rows come before the hacks':\n%s", s)
	}
	open := liveKeys(t, l, l.Last.at(), 100, 0, "o")
	for prefix, want := range map[string]string{
		"grader-6":      "Grader Inspector ✗ Timeout counts as pass",
		"0000-attacker": "Attacker ✗ Reward reads stdout",
	} {
		if got := cells(open, prefix); got != want {
			t.Errorf("%s: %q", prefix, got)
		}
	}
}

// A zero-info Attacker's exploit judged new is a problem of its own, in the no-information block: it has no
// finding to hint from.
func TestPipelineAttackerProblem(t *testing.T) {
	l := liveFrom(t, ev("00:00", "run_start", `, "backend": "docker"`)+
		ev("00:00", "phase_start", `, "phase": "hack"`)+
		ev("00:01", "attempt_start", `, "episode": "0000-attacker", "level": "none", "number": 1`)+
		ev("00:02", "judged", `, "inspector": "hack", "finding": "hack-1", "problem": "P1", "new": true, "cause": "c1"`)+
		ev("03:00", "attempt_end", `, "episode": "0000-attacker", "rewards": [1.0]`)+
		ev("03:00", "session_start", `, "inspector": "attack", "session": "s0", "episode": "0000-attacker"`)+
		ev("03:30", "session_end", `, "inspector": "attack", "session": "s0", "status": "evidenced_issue"`)+
		ev("03:31", "judged", `, "inspector": "attack", "finding": "0000-attacker", "problem": "A1", "new": true, "cause": "prints the marker early"`)+
		ev("03:31", "attempt_result", `, "episode": "0000-attacker", "problem": "A1", "level": "none", "status": "evidenced_issue"`)+
		ev("04:00", "reproduced", `, "problem": "P1", "result": "not_reproduced"`)+
		ev("04:00", "phase_end", `, "phase": "hack", "status": "complete", "elapsed": 240`))
	if s := liveScreen(t, l, at9("04:00"), 100, 0); !strings.Contains(s, "Find Hacks  ✓") || !strings.Contains(s, "phase time 4:00") {
		t.Errorf("screen:\n%s", s)
	}
	s := liveKeys(t, l, at9("04:00"), 100, 0, "shift+tab", "shift+tab", "shift+tab")
	if got := cells(s, "1     Finished"); got != "✓ ✓ Prints the marker early" {
		t.Errorf("no-information row: %q\n%s", got, s)
	}
	if got := cells(s, "C1"); got != "✓ ✗ - -" || !strings.Contains(s, "Problems (1)") {
		t.Errorf("Results:\n%s", s)
	}
	if !strings.Contains(s, "2 problems so far") {
		t.Errorf("Results does not count the Attacker's problem")
	}
	if p, x := l.hackCounts(); p != 2 || x != 1 {
		t.Errorf("%d problems, %d exploited", p, x)
	}
}

// An attempt settles only at its attempt_result: an attack inspector's finding can be another exploit, and zero reward needs no session.
func TestPipelineFinalResult(t *testing.T) {
	log := ev("00:00", "run_start", `, "backend": "docker"`) +
		ev("00:00", "phase_start", `, "phase": "hack"`) +
		ev("00:01", "judged", `, "inspector": "hack", "finding": "experiment-0000", "problem": "P1", "new": true, "cause": "c1"`) +
		ev("00:02", "reproduced", `, "problem": "P1", "result": "evidenced"`) +
		ev("00:03", "judged", `, "inspector": "hack", "finding": "experiment-0001", "problem": "P2", "new": true, "cause": "c2"`) +
		ev("00:04", "reproduced", `, "problem": "P2", "result": "evidenced"`) +
		ev("00:05", "attempt_start", `, "episode": "0001-attacker", "level": "full", "number": 1, "problem": "P1"`) +
		ev("00:06", "attempt_start", `, "episode": "0002-attacker", "level": "full", "number": 1, "problem": "P2"`) +
		ev("03:00", "attempt_end", `, "episode": "0001-attacker", "level": "full", "number": 1, "problem": "P1", "rewards": [1.0]`) +
		ev("03:00", "session_start", `, "inspector": "attack", "session": "s1", "episode": "0001-attacker", "problem": "P1"`) +
		ev("03:30", "session_end", `, "inspector": "attack", "session": "s1", "status": "evidenced_issue"`) +
		ev("04:00", "attempt_end", `, "episode": "0002-attacker", "level": "full", "number": 1, "problem": "P2", "rewards": [0.0]`)
	at := func(l *Live, prefix string) string { return cells(liveScreen(t, l, at9("05:00"), 100, 0), prefix) }
	l := liveFrom(t, log)
	if got := at(l, "C1"); got != "✓ ✓ ⣾ 4:55 -" {
		t.Errorf("before its result P1 reads %q", got)
	}
	if got := at(l, "C2"); got != "✓ ✓ ⣾ 4:54 -" {
		t.Errorf("before its result P2 reads %q", got)
	}
	l = liveFrom(t, log+
		ev("03:31", "attempt_result", `, "episode": "0001-attacker", "problem": "P1", "level": "full", "status": "other_exploit"`)+
		ev("04:00", "attempt_result", `, "episode": "0002-attacker", "problem": "P2", "level": "full", "status": "no_evidenced_issue"`))
	if got := at(l, "C1"); got != "✓ ✓ ✗ -" {
		t.Errorf("P1 reads %q", got)
	}
	if got := at(l, "C2"); got != "✓ ✓ ✗ -" {
		t.Errorf("P2 reads %q", got)
	}
	if p, x := l.hackCounts(); p != 2 || x != 0 {
		t.Errorf("%d problems, %d exploited", p, x)
	}
}

// An exploit nudi could not attribute is not settled: only other_exploit names another mechanism.
func TestPipelineUnattributedIsNotSettled(t *testing.T) {
	log := ev("00:00", "run_start", `, "backend": "docker"`) +
		ev("00:00", "phase_start", `, "phase": "hack"`) +
		ev("00:01", "judged", `, "inspector": "hack", "finding": "experiment-0000", "problem": "P1", "new": true, "cause": "c1"`) +
		ev("00:02", "reproduced", `, "problem": "P1", "result": "evidenced"`) +
		ev("00:03", "attempt_start", `, "episode": "0001-attacker", "level": "full", "number": 1, "problem": "P1"`) +
		ev("03:00", "attempt_result", `, "episode": "0001-attacker", "problem": "P1", "level": "full", "number": 1, "status": "unattributed_exploit"`)
	if got := cells(liveScreen(t, liveFrom(t, log), at9("04:00"), 100, 0), "C1"); got != "✓ ✓ ? -" {
		t.Errorf("P1 row: %q", got)
	}
	if res, _ := lookup(attemptResults, "other_exploit"); res != Elsewhere {
		t.Errorf("other_exploit reads %v", res)
	}
}

// A rerun's log repeats the earlier run's problems: they make rows that never turn, an earlier finding with no
// information among them, and only this run's attempts find anything with no information.
func TestPipelineReplayedProblems(t *testing.T) {
	replay := ev("00:00", "run_start", `, "backend": "docker", "analyses": ["attack"]`) +
		ev("00:00", "phase_start", `, "phase": "attack"`) +
		ev("00:01", "judged", `, "inspector": "hack", "finding": "experiment-0000", "problem": "P1", "new": true, "cause": "c1", "replayed": true`) +
		ev("00:01", "reproduced", `, "problem": "P1", "result": "evidenced", "replayed": true`) +
		ev("00:01", "judged", `, "inspector": "hack", "finding": "experiment-0001", "problem": "P2", "new": true, "cause": "c4", "replayed": true`) +
		ev("00:01", "judged", `, "inspector": "attack", "finding": "0000-attacker", "problem": "A1", "new": true, "cause": "c2", "replayed": true`)
	l := liveFrom(t, replay)
	if log := plainText(l.logRow(l.Recent[2], 100)); l.ZeroJudged != nil || l.lane("A1").Alone || strings.TrimSpace(log) != "novelty_judge     nudi: judged" {
		t.Errorf("replayed judgements: zero judged %v, A1 %+v, log %q", l.ZeroJudged, l.lane("A1"), log)
	}
	s := liveScreen(t, liveFrom(t, replay+
		ev("00:02", "attempt_start", `, "episode": "0001-attacker", "level": "none", "number": 1`)+
		ev("03:00", "attempt_end", `, "episode": "0001-attacker", "level": "none", "number": 1, "rewards": [0.0]`)+
		ev("03:00", "attempt_result", `, "episode": "0001-attacker", "problem": null, "level": "none", "number": 1, "status": "no_evidenced_issue"`)), at9("04:00"), 100, 0)
	for prefix, want := range map[string]string{
		"1     Finished": "✗",
		"C2":             "✓ - - -",
		"C1":             "✓ ✓ - -",
		"C4":             "✓ - - -",
		"Simulation":     "── Grade Simulations ── Find Hacks ── ATTACK ⣾ │ [ Results ]",
	} {
		if got := cells(s, prefix); got != want && prefix != "Simulation" {
			t.Errorf("%s row: %q", prefix, got)
		}
	}
	if strings.Contains(s, "Simulation waiting") || !strings.Contains(s, "Attack  ⣾") {
		t.Errorf("a phase the rerun left out shows as waiting:\n%s", s)
	}
	// A fresh zero-info exploit is new once its attempt_result says so.
	fresh := replay +
		ev("00:02", "attempt_start", `, "episode": "0001-attacker", "level": "none", "number": 1`) +
		ev("03:01", "judged", `, "inspector": "attack", "finding": "0001-attacker", "problem": "A2", "new": true, "cause": "c3"`)
	if got := cells(liveScreen(t, liveFrom(t, fresh), at9("04:00"), 100, 0), "1     ⣾ 3:58"); got != "" {
		t.Errorf("A2 before its result: %q", got)
	}
	l = liveFrom(t, fresh+ev("03:01", "attempt_result", `, "episode": "0001-attacker", "problem": "A2", "level": "none", "number": 1, "status": "evidenced_issue"`))
	if got := cells(liveScreen(t, l, at9("04:00"), 100, 0), "1     Finished"); got != "✓ ✓ C3" {
		t.Errorf("after the result: %q", got)
	}
}

// A result for an attempt the spending cap stopped before its episode started is that attempt, ended, with no tile.
func TestPipelineResultWithoutStart(t *testing.T) {
	log := ev("00:00", "run_start", `, "backend": "docker"`) +
		ev("00:00", "phase_start", `, "phase": "hack"`)
	for _, p := range []string{"P1", "P2"} {
		log += ev("00:01", "judged", `, "inspector": "hack", "finding": "experiment-000`+p[1:]+`", "problem": "`+p+`", "new": true, "cause": "c`+p[1:]+`"`) +
			ev("00:02", "reproduced", `, "problem": "`+p+`", "result": "evidenced"`)
	}
	for _, p := range []string{"P1", "P2"} {
		log += ev("00:03", "attempt_result", `, "episode": null, "problem": "`+p+`", "level": "full", "number": 1, "status": "spending_exhausted"`)
	}
	l := liveFrom(t, log)
	s := liveScreen(t, l, at9("01:00"), 100, 0)
	for _, prefix := range []string{"C1", "C2"} {
		if got := cells(s, prefix); got != "✓ ✓ - -" {
			t.Errorf("%s row: %q", prefix, got)
		}
	}
	if len(l.Agents) != 0 || len(l.Tries) != 2 || l.Tries[1].Start.Number != 1 {
		t.Errorf("agents %+v, tries %d", l.Agents, len(l.Tries))
	}
}

// The phases a run selected wait from its start until they start; the others are off.
func TestLiveTabsShowSelectedPhases(t *testing.T) {
	start := func(analyses string) string {
		return ev("00:00", "run_start", `, "backend": "docker", "analyses": `+analyses)
	}
	screen := func(log string) string { return liveScreen(t, liveFrom(t, log), at9("00:30"), 120, 0) }
	full := start(`["hack", "simulation", "grader", "attack"]`)
	if s := screen(full); !strings.Contains(s, "Grade Simulations waiting") || !strings.Contains(s, "Find Hacks waiting") || !strings.Contains(s, "Attack waiting") {
		t.Errorf("before the hacks:\n%s", s)
	}
	s := screen(full + ev("00:01", "phase_start", `, "phase": "hack", "slots": 6`))
	if !strings.Contains(s, "Find Hacks  ⣾") || !strings.Contains(s, "phase time 0:29") || !strings.Contains(s, "Simulation waiting") {
		t.Errorf("during the hacks:\n%s", s)
	}
	if s := screen(start(`["hack", "attack"]`)); strings.Contains(s, "Simulation waiting") || !strings.Contains(s, "Attack waiting") {
		t.Errorf("a hacks run:\n%s", s)
	}
}

// A failed phase says Error on its tab and why under it, and the run's end once it came.
func TestLiveFailedPhase(t *testing.T) {
	l := liveFrom(t, ev("00:00", "run_start", `, "backend": "modal", "concurrency": 4`)+
		ev("00:00", "phase_start", `, "phase": "hack"`)+
		ev("00:04", "session_start", `, "inspector": "hack", "session": "hack-broad"`)+
		ev("01:00", "phase_end", `, "phase": "hack", "status": "failed", "elapsed": 60, "error": "hack failed: RuntimeError: out of memory"`)+
		ev("02:10", "run_end", `, "status": "failed", "report": "report.json"`))
	s := screenLines(t, l, at9("02:10"))
	for _, want := range []string{"Find Hacks  Error", "Find Hacks  Error", "Error  hack failed: RuntimeError: out of memory",
		"The run ended at 2:10. Its report keeps the results so far.", "Agents  none running", "Simulation -"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	if s := liveKeys(t, l, at9("02:10"), 100, 0, "tab", "tab"); !strings.Contains(s, "None before the error.") {
		t.Errorf("Results:\n%s", s)
	}
}

// The one attack runs on after the hack inspection ends, so the hacks' counts follow it: a later exploit of a problem of
// the hacks, and an Attacker's problem judged later, count.
func TestPipelineHackCountsFollowTheAttack(t *testing.T) {
	l := liveFrom(t, ev("00:00", "run_start", `, "backend": "docker", "analyses": ["hack", "simulation", "grader", "attack"]`)+
		ev("00:00", "phase_start", `, "phase": "hack", "slots": 6`)+
		ev("00:01", "judged", `, "inspector": "hack", "finding": "experiment-0000", "problem": "P1", "new": true, "cause": "c1"`)+
		ev("00:02", "reproduced", `, "problem": "P1", "result": "not_reproduced"`)+
		ev("01:00", "phase_end", `, "phase": "hack", "status": "complete", "elapsed": 60`)+
		ev("01:01", "phase_start", `, "phase": "grader"`)+
		ev("01:02", "judged", `, "inspector": "grader", "finding": "grader-0", "problem": "P1", "new": false, "cause": "c1"`)+
		ev("01:03", "reproduced", `, "problem": "P1", "result": "evidenced"`)+
		ev("02:00", "phase_end", `, "phase": "grader", "status": "complete", "elapsed": 59`)+
		ev("02:01", "phase_start", `, "phase": "attack"`)+
		ev("02:02", "attempt_start", `, "episode": "0000-attacker", "level": "none", "number": 1`)+
		ev("02:02", "attempt_start", `, "episode": "0001-attacker", "level": "full", "number": 1, "problem": "P1"`)+
		ev("03:00", "attempt_result", `, "episode": "0001-attacker", "problem": "P1", "level": "full", "status": "evidenced_issue"`)+
		ev("03:30", "judged", `, "inspector": "attack", "finding": "0000-attacker", "problem": "A1", "new": true, "cause": "c2"`)+
		ev("03:30", "attempt_result", `, "episode": "0000-attacker", "problem": "A1", "level": "none", "status": "evidenced_issue"`))
	if p, x := l.hackCounts(); p != 2 || x != 2 {
		t.Errorf("hacks counts: %d problems, %d exploited", p, x)
	}
	s := liveKeys(t, l, at9("04:00"), 100, 0, "o")
	if got := cells(s, "grader-0"); got != "Grader Inspector ✗ C1" {
		t.Errorf("grader-0 row: %q", got)
	}
	if got := cells(s, "C1"); got != "✓ ✓ ✓ -" {
		t.Errorf("P1 row: %q", got)
	}
}

// The plain report lists the problems by their step on the exploit chart, highest first, from `level`, or from the
// help an Attacker needed in older reports, where an unknown value is an evidenced exploit; leads, problems no
// evidence confirmed, are not counted as problems.
func TestProblemsByHelpNeeded(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "attack": {"problems": [
		{"id": "P1", "cause": "c1", "source": "hack inspector", "help_needed": "not_reproduced"},
		{"id": "P2", "cause": "c2", "source": "hack inspector", "help_needed": "later_value", "findings": ["hack-2"]},
		{"id": "G1", "cause": "c3", "source": "grader inspector", "help_needed": "unknown", "findings": ["grader-3"]},
		{"id": "A1", "cause": "c4", "source": "Attacker", "help_needed": "found_alone"},
		{"id": "P3", "cause": "c5", "source": "hack inspector", "help_needed": "full_info"},
		{"id": "P4", "cause": "c6", "source": "hack inspector", "help_needed": "found_alone"},
		{"id": "P5", "cause": "c7", "source": "hack inspector", "help_needed": "single_hint"},
		{"id": "P6", "cause": "c8", "source": "hack inspector", "help_needed": "not_exploited", "findings": ["hack-6"]},
		{"id": "P7", "cause": "c9", "source": "hack inspector", "help_needed": "full_info_or_less"},
		{"id": "P8", "cause": "c10", "source": "hack inspector", "help_needed": "unknown", "level": 4}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	plain := plainReport(r, 100)
	levels := map[string]string{"A1": "5 of 5: an Attacker given no information demonstrated it", "P4": "5 of 5", "P5": "4 of 5: an Attacker given only a hint demonstrated it",
		"P8": "4 of 5", "P3": "3 of 5: an Attacker given full instructions demonstrated it", "P7": "3 of 5", "P2": "2 of 5: reproduced, no Attacker demonstrated it", "G1": "2 of 5", "P6": "2 of 5"}
	at := -1
	for _, id := range []string{"A1", "P4", "P5", "P8", "P3", "P7", "P2", "G1", "P6"} {
		i := strings.Index(plain, "\n  "+id+"  ")
		if i < at || !strings.HasPrefix(row(plain[i+1:], "Level"), "      Level             "+levels[id]) {
			t.Fatalf("%s out of order or at the wrong level:\n%s", id, plain)
		}
		at = i
	}
	if !strings.Contains(plain, "Count             9 problems") || strings.Contains(plain, "  P1  c1") || !strings.Contains(plain, "State             Suspected only") {
		t.Errorf("the lead:\n%s", plain)
	}
	// Results lists the same problems in the same order, and the lead among the other findings.
	s := plainTab(r, results, "o")
	at = -1
	for _, id := range []string{"A1", "P4", "P5", "P8", "P3", "P7", "P2", "G1", "P6"} {
		i := strings.Index(s, "  "+id+"\n")
		if i < at {
			t.Fatalf("%s out of order:\n%s", id, s)
		}
		at = i
	}
	if !strings.Contains(s, "c1                                  Suspected only              Hack Inspector    P1") {
		t.Errorf("lead missing:\n%s", s)
	}
}

// A problem of correct work the grader fails is named with the simulation chart's FN words, never an exploit step;
// an older problem without findings or levels is a lead.
func TestPlainNamesCorrectWorkFailedAndCountsOlderPendingProblemsAsLeads(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "attack": {
		"candidates": [{"id": "grader-0", "valid_work": true}],
		"problems": [{"id": "G1", "cause": "rejects zeros", "source": "grader inspector", "findings": ["grader-0"], "help_needed": "full_info"},
		             {"id": "P1", "cause": "pending", "source": "hack inspector", "help_needed": "unknown"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := plainReport(r, 120)
	if !strings.Contains(s, "False negative: correct work was rejected") || !strings.Contains(s, "Level             Reproduced by an Attacker with full instructions") ||
		strings.Contains(s, "exploit executable") {
		t.Errorf("correct work failed:\n%s", s)
	}
	if !strings.Contains(s, "Count             1 problem\n") || strings.Contains(s, "  P1  pending") {
		t.Errorf("older pending problem:\n%s", s)
	}
}

func TestPipelineFullPlain(t *testing.T) {
	r := fixture(t, "pipeline-full")
	if a := plainTab(r, 3); strings.Contains(a, "selected") || strings.Contains(plainTab(r, 2), "problems from") {
		t.Errorf("attack tab:\n%s", a)
	}
}

// A guided try that finds another mechanism, judged a new Attacker problem, shows that problem on the phase tab and on
// Results; a later no-information try that matches it is not new.
func TestLiveAttackerProblemFromAGuidedTry(t *testing.T) {
	l := liveFrom(t, ev("00:00", "run_start", `, "backend": "docker"`)+
		ev("00:00", "phase_start", `, "phase": "hack"`)+
		ev("00:01", "judged", `, "inspector": "hack", "finding": "hack-1", "problem": "P1", "new": true, "cause": "c1"`)+
		ev("00:02", "attempt_start", `, "episode": "0000-attacker", "level": "full", "number": 1, "problem": "P1", "candidate": "hack-1"`)+
		ev("03:00", "attempt_end", `, "episode": "0000-attacker", "rewards": [1.0]`)+
		ev("03:31", "judged", `, "inspector": "attack", "finding": "0000-attacker", "problem": "A1", "new": true, "cause": "prints the marker early"`)+
		ev("03:31", "attempt_result", `, "episode": "0000-attacker", "problem": "P1", "level": "full", "status": "other_exploit"`)+
		ev("03:32", "attempt_start", `, "episode": "0001-attacker", "level": "none", "number": 1`)+
		ev("05:00", "attempt_end", `, "episode": "0001-attacker", "rewards": [1.0]`)+
		ev("05:01", "judged", `, "inspector": "attack", "finding": "0001-attacker", "problem": "A1", "new": false, "cause": "prints the marker early"`)+
		ev("05:01", "attempt_result", `, "episode": "0001-attacker", "problem": "A1", "level": "none", "status": "evidenced_issue"`))
	s := liveScreen(t, l, at9("05:01"), 100, 0)
	if got := cells(s, "Prints the marker early"); !strings.HasPrefix(got, "✓ - ✓") {
		t.Errorf("A1 row: %q\n%s", got, s)
	}
	if got := cells(s, "1     Finished"); got != "✓ ✗ Prints the marker early" {
		t.Errorf("no-information row: %q\n%s", got, s)
	}
	if r := liveKeys(t, l, at9("05:01"), 100, 0, "tab", "tab"); !strings.Contains(r, "2 problems so far") || !strings.Contains(row(r, "Prints the marker early"), "✓") {
		t.Errorf("Results:\n%s", r)
	}
}

// A phase that ended partial may have left an attempt that failed to run, so its tab says partly, not done.
func TestLivePartialPhaseIsPartly(t *testing.T) {
	l := liveFrom(t, ev("00:00", "run_start", `, "backend": "docker"`)+
		ev("00:00", "phase_start", `, "phase": "hack"`)+
		ev("01:00", "phase_end", `, "phase": "hack", "status": "partial", "elapsed": 60`))
	if s := screenLines(t, l, at9("01:00")); !strings.Contains(s, "Find Hacks  partly") || strings.Contains(s, "✓") {
		t.Errorf("partial phase:\n%s", s)
	}
}

// A failed phase's tab keeps its whole error and leaves the findings to Results.
func TestLiveLongErrorLeavesFindingsToResults(t *testing.T) {
	l := liveFrom(t, ev("00:00", "run_start", `, "backend": "docker"`)+
		ev("00:00", "phase_start", `, "phase": "hack"`)+
		ev("00:01", "judged", `, "inspector": "hack", "finding": "hack-1", "problem": "P1", "new": true, "cause": "c1"`)+
		ev("00:02", "judged", `, "inspector": "hack", "finding": "hack-2", "problem": "P2", "new": true, "cause": "c2"`)+
		ev("01:00", "phase_end", `, "phase": "hack", "status": "failed", "elapsed": 60, "error": "hack failed: one\ntwo\nthree\nfour\nfive\nsix\nseven"`))
	if s := liveScreen(t, l, at9("01:00"), 100, 24); !strings.Contains(s, "seven") || strings.Contains(s, "Findings So Far") {
		t.Errorf("failed tab:\n%s", s)
	}
	if s := liveKeys(t, l, at9("01:00"), 100, 0, "tab", "tab"); !strings.Contains(s, "Problems (2)") || !strings.Contains(s, "C2") {
		t.Errorf("Results:\n%s", s)
	}
}
