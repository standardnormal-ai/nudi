package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
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

// checkWidths draws l at 100, 80 and 60 columns and checks that no line is wider than the window.
func checkWidths(t *testing.T, l *Live) {
	t.Helper()
	for _, w := range []int{100, 80, 60} {
		for _, line := range splitLines(renderLive(l, l.Last.at(), w, 0)) {
			if width(line) > w {
				t.Errorf("%d columns at width %d: %q", width(line), w, ansi.Strip(line))
			}
		}
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
	s := plainText(renderLive(l, l.Last.at(), 100, 0))
	snapshot(t, "pipeline-hacks", "screen.txt", s)
	for _, want := range []string{
		"HACKS ⣾ 8:50", "hack inspector + Attackers", "AGENTS  5 of 6 slots",
		"hack-broad", "hack-grader_tamperi…", "no extra informatio…", "P2 full instructions", "0002-attacker, try 1", "P1 only a hint",
		"FINDINGS", "judge", "reproduce", "full instructions", "only a hint",
		"+ experiment-0002, experiment-0005 same as P1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	for prefix, cells := range map[string][]string{
		"no extra information":      {"·", "·", "try 1 ⣾ 8m"},
		"P1 reward reads stdout":    {"new", "✓", "✓ exploited", "⣾ 2m"},
		"P2 skips the test file":    {"new", "✓", "⣾ 3m", "·"},
		"P3 writes expected output": {"new", "⣾ 3m", "·", "·"},
		"P4 timeout counts as pass": {"new", "✗ not reproduced"},
	} {
		r := row(s, prefix)
		if got := strings.Fields(strings.TrimPrefix(strings.TrimSpace(r), prefix)); strings.Join(got, " ") != strings.Join(cells, " ") {
			t.Errorf("%s row: %q", prefix, r)
		}
	}
	if strings.Index(s, "no extra information  ") > strings.Index(s, "P1 reward") || strings.Contains(s, "GRADER") || strings.Contains(s, "FOUND") {
		t.Errorf("layout:\n%s", s)
	}
	if narrow := plainText(renderLive(l, l.Last.at(), 80, 0)); strings.Contains(narrow, "judge") || !strings.Contains(row(narrow, "P4"), "✗ not reproduced") {
		t.Errorf("at 80 columns:\n%s", narrow)
	}
}

func TestPipelineGraderScreen(t *testing.T) {
	l := pipelineLive(t, "pipeline-grader")
	checkWidths(t, l)
	s := plainText(renderLive(l, l.Last.at(), 100, 0))
	snapshot(t, "pipeline-grader", "screen.txt", s)
	for _, want := range []string{
		"HACKS ✓ 18:00  4 problems, 2 exploited", "GRADER ⣾ 6:59", "Simulate · Inspect · Attack",
		"AGENTS  1 running", "grader-broad",
		"judge: grader-6 is the same as P4 (timeout counts as pass)",
		"+ experiment-0002, experiment-0005, 0000-attacker same as P1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	for prefix, cells := range map[string]string{
		"no extra information":            "same as P1 · try 1 ✓ exploited",
		"P1 reward reads stdout":          "new ✓ ✓ exploited ✓ another way",
		"P2 skips the test file":          "new ✓ ✓ exploited ✗ not exploited",
		"P3 writes expected output":       "new ✓ ✗ not exploited –",
		"G1 accepts empty answer":         "new ✓ (grader) · ·",
		"grader-5 reward reads stdout":    "same as P1, attacked in hacks",
		"grader-6 timeout counts as pass": "same as P4",
		"P4 timeout counts as pass":       "new ✓ · ·",
	} {
		r := row(s, prefix)
		if got := strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(r), prefix)), " "); got != cells {
			t.Errorf("%s row: %q", prefix, r)
		}
	}
	if strings.Index(s, "P4 timeout") > strings.Index(s, "G1 accepts") {
		t.Errorf("grader rows come before the hacks':\n%s", s)
	}
}

// A zero-info Attacker's exploit judged new is a problem of its own, an A row after the P rows: it has no finding to hint from.
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
	s := plainText(renderLive(l, at9("04:00"), 100, 0))
	for prefix, cells := range map[string]string{
		"no extra information":       "new A1 · try 1 ✓ exploited",
		"A1 prints the marker early": "new ✓ (Attacker) found with no extra information",
	} {
		if got := strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, prefix)), prefix)), " "); got != cells {
			t.Errorf("%s row: %q", prefix, row(s, prefix))
		}
	}
	if !strings.Contains(s, "HACKS ✓ 4:00  2 problems, 1 exploited") || strings.Index(s, "P1 c1") > strings.Index(s, "A1 prints") {
		t.Errorf("screen:\n%s", s)
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
	cells := func(l *Live, prefix string) string {
		s := plainText(renderLive(l, at9("05:00"), 100, 0))
		return strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, prefix)), prefix)), " ")
	}
	l := liveFrom(t, log)
	if got := cells(l, "P1 c1"); got != "new ✓ ⣾ 4m ·" {
		t.Errorf("before its result P1 reads %q", got)
	}
	if got := cells(l, "P2 c2"); got != "new ✓ ⣾ 4m ·" {
		t.Errorf("before its result P2 reads %q", got)
	}
	l = liveFrom(t, log+
		ev("03:31", "attempt_result", `, "episode": "0001-attacker", "problem": "P1", "level": "full", "status": "other_exploit"`)+
		ev("04:00", "attempt_result", `, "episode": "0002-attacker", "problem": "P2", "level": "full", "status": "no_evidenced_issue"`))
	if got := cells(l, "P1 c1"); got != "new ✓ ✓ another way –" {
		t.Errorf("P1 reads %q", got)
	}
	if got := cells(l, "P2 c2"); got != "new ✓ ✗ not exploited –" {
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
	s := plainText(renderLive(liveFrom(t, log), at9("04:00"), 100, 0))
	if got := strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, "P1 c1")), "P1 c1")), " "); got != "new ✓ ? result unclear –" {
		t.Errorf("P1 row: %q", got)
	}
	if res, _ := lookup(attemptResults, "other_exploit"); res != Elsewhere {
		t.Errorf("other_exploit reads %v", res)
	}
}

// A rerun's log repeats the earlier run's problems: they make rows, but only this run's attempts find anything with zero info.
func TestPipelineReplayedProblems(t *testing.T) {
	replay := ev("00:00", "run_start", `, "backend": "docker", "analyses": ["attack"]`) +
		ev("00:00", "phase_start", `, "phase": "attack"`) +
		ev("00:01", "judged", `, "inspector": "hack", "finding": "experiment-0000", "problem": "P1", "new": true, "cause": "c1", "replayed": true`) +
		ev("00:01", "reproduced", `, "problem": "P1", "result": "evidenced", "replayed": true`) +
		ev("00:01", "judged", `, "inspector": "attack", "finding": "0000-attacker", "problem": "A1", "new": true, "cause": "c2", "replayed": true`)
	l := liveFrom(t, replay)
	if l.ZeroJudged != nil || l.lane("A1").Alone || strings.Contains(strings.Join(l.Recent, "\n"), "judge:") {
		t.Errorf("replayed judgements: zero judged %v, A1 %+v, recent %q", l.ZeroJudged, l.lane("A1"), l.Recent)
	}
	cells := func(s, prefix string) string {
		return strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, prefix)), prefix)), " ")
	}
	s := plainText(renderLive(liveFrom(t, replay+
		ev("00:02", "attempt_start", `, "episode": "0001-attacker", "level": "none", "number": 1`)+
		ev("03:00", "attempt_end", `, "episode": "0001-attacker", "level": "none", "number": 1, "rewards": [0.0]`)+
		ev("03:00", "attempt_result", `, "episode": "0001-attacker", "problem": null, "level": "none", "number": 1, "status": "no_evidenced_issue"`)), at9("04:00"), 100, 0))
	for prefix, want := range map[string]string{
		"no extra information": "· · try 1 ✗ not exploited",
		"A1 c2":                "new kept from the earlier run",
		"P1 c1":                "new ✓ · ·",
	} {
		if got := cells(s, prefix); got != want {
			t.Errorf("%s row: %q", prefix, got)
		}
	}
	// A fresh zero-info exploit is found alone once its attempt_result says so, not at its judge call.
	fresh := replay +
		ev("00:02", "attempt_start", `, "episode": "0001-attacker", "level": "none", "number": 1`) +
		ev("03:01", "judged", `, "inspector": "attack", "finding": "0001-attacker", "problem": "A2", "new": true, "cause": "c3"`)
	if got := cells(plainText(renderLive(liveFrom(t, fresh), at9("04:00"), 100, 0)), "A2 c3"); strings.Contains(got, "zero info") {
		t.Errorf("A2 before its result: %q", got)
	}
	l = liveFrom(t, fresh+ev("03:01", "attempt_result", `, "episode": "0001-attacker", "problem": "A2", "level": "none", "number": 1, "status": "evidenced_issue"`))
	s = plainText(renderLive(l, at9("04:00"), 100, 0))
	if got := cells(s, "A2 c3"); got != "new ✓ (Attacker) found with no extra information" || cells(s, "no extra information") != "new A2 · try 1 ✓ exploited" || cells(s, "A1 c2") != "new kept from the earlier run" {
		t.Errorf("after the result:\n%s", s)
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
	s := plainText(renderLive(l, at9("01:00"), 100, 0))
	for _, prefix := range []string{"P1 c1", "P2 c2"} {
		if got := strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, prefix)), prefix)), " "); got != "new ✓ · not tested –" {
			t.Errorf("%s row: %q", prefix, got)
		}
	}
	if len(l.Agents) != 0 || len(l.Tries) != 2 || l.Tries[1].Start.Number != 1 {
		t.Errorf("agents %+v, tries %d", l.Agents, len(l.Tries))
	}
}

// The pieces a run selected show from its start, pending until their phases start; an attack alone has no grader piece.
func TestPipelinePendingPieces(t *testing.T) {
	start := func(analyses string) string {
		return ev("00:00", "run_start", `, "backend": "docker", "analyses": `+analyses)
	}
	screen := func(log string) string { return plainText(renderLive(liveFrom(t, log), at9("00:30"), 100, 0)) }
	full := start(`["hack", "simulation", "grader", "attack"]`)
	if s := screen(full); !strings.Contains(s, "HACKS ○") || !strings.Contains(s, "GRADER ○") || !strings.Contains(s, "Simulate · Inspect · Attack") {
		t.Errorf("before the hacks:\n%s", s)
	}
	s := screen(full + ev("00:01", "phase_start", `, "phase": "hack", "slots": 6`))
	if !strings.Contains(s, "HACKS ⣾ 0:29") || !strings.Contains(s, "GRADER ○") || strings.Contains(s, "problems") {
		t.Errorf("during the hacks:\n%s", s)
	}
	for _, analyses := range []string{`["hack", "attack"]`, `["attack"]`} {
		if s := screen(start(analyses)); strings.Contains(s, "GRADER") {
			t.Errorf("%s shows the grader piece:\n%s", analyses, s)
		}
	}
	if s := screen(start(`["grader"]`)); strings.Contains(s, "HACKS") || !strings.Contains(s, "GRADER ○") {
		t.Errorf("a grader run:\n%s", s)
	}
}

// The hacks' counts are those of their own end: later attacks, and an Attacker's problem judged later, belong to the grader piece.
func TestPipelineHackCountsFreeze(t *testing.T) {
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
	s := plainText(renderLive(l, at9("04:00"), 100, 0))
	if !strings.Contains(s, "HACKS ✓ 1:00  1 problem, 0 exploited") {
		t.Errorf("hacks counts changed:\n%s", s)
	}
	if got := strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, "grader-0 c1")), "grader-0 c1")), " "); got != "same as P1" {
		t.Errorf("grader-0 row: %q", got)
	}
	if got := strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(row(s, "P1 c1")), "P1 c1")), " "); got != "new ✓ ✓ exploited ·" {
		t.Errorf("P1 row: %q", got)
	}
}

// The card lists the problems by their step on the exploit chart, highest first, from `level`, or from the help an
// Attacker needed in older reports, where an unknown value is an evidenced exploit; leads, problems no evidence
// confirmed, are counted after them.
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
	// A full-hint reproduction whose single hint did not settle is at full information.
	want := " PROBLEMS  level\n" +
		" A1 c4     ●●●●● exploit executable by unaided learner\n   from Attacker\n" +
		" P4 c6     ●●●●● exploit executable by unaided learner\n   from hack inspector + independent attacker\n" +
		" P5 c7     ●●●●○ exploit executable by learner with hint\n   from hack inspector\n" +
		" P8 c10    ●●●●○ exploit executable by learner with hint\n   from hack inspector\n" +
		" P3 c5     ●●●○○ exploit executable by learner with full information\n   from hack inspector\n" +
		" P7 c9     ●●●○○ exploit executable by learner with full information\n   from hack inspector\n" +
		" P2 c2     ●●○○○ reproduced exploit\n   from hack inspector\n" +
		" G1 c3     ●●○○○ reproduced exploit, no clear Attacker result\n   from grader inspector\n" +
		" P6 c8     ●●○○○ reproduced exploit, Attackers did not exploit it\n   from hack inspector\n" +
		" 1 lead, which no evidence confirmed\n"
	for _, s := range []string{card(r, 100, false), plainPhase(r, 3)} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks\n%s\nin:\n%s", want, s)
		}
	}
	if s := card(r, 60, true); strings.Contains(s, "\n\n\n") {
		t.Errorf("at 60 columns:\n%s", s)
	}
}

// A problem exploited only by a no-hint attempt aimed at it or at another problem names no independent attacker; one
// the independent no-hint search exploited does. Without an exploit, the scope of its evidence and `exploited_with`
// follow the label.
func TestOnlyAnUnaimedNoHintExploitNamesTheIndependentAttacker(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "attack": {"problems": [
		{"id": "P1", "cause": "c1", "source": "hack inspector", "exploited_with": "none", "level": 5, "label": "●●●●● exploit executable by unaided learner",
		 "conditions": [{"condition": "none", "exploited": 1}, {"condition": "independent", "exploited": 0}]},
		{"id": "P2", "cause": "c2", "source": "hack inspector", "exploited_with": "none", "level": 5, "label": "●●●●● exploit executable by unaided learner",
		 "conditions": [{"condition": "independent", "exploited": 1}]},
		{"id": "P3", "cause": "c3", "source": "hack inspector", "exploited_with": "not_exploited", "level": 2, "label": "●●○○○ reproduced exploit",
		 "scope": "native", "findings": ["hack-3"], "conditions": []},
		{"id": "P4", "cause": "c4", "source": "hack inspector", "exploited_with": "none", "level": 5, "label": "●●●●● exploit executable by unaided learner",
		 "conditions": [{"condition": "elsewhere_none", "exploited": 1}, {"condition": "independent", "exploited": 0}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := card(r, 100, false)
	for _, want := range []string{" P1 c1     ●●●●● exploit executable by unaided learner\n   from hack inspector\n",
		" P2 c2     ●●●●● exploit executable by unaided learner\n   from hack inspector + independent attacker\n",
		" P3 c3     ●●○○○ reproduced exploit, evidenced in a native episode, Attackers did not exploit it\n",
		" P4 c4     ●●●●● exploit executable by unaided learner\n   from hack inspector\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q in:\n%s", want, s)
		}
	}
}

// Reports whose problems lack the help needed render as before: no PROBLEMS block on the card.
func TestOldReportsHaveNoProblemsBlock(t *testing.T) {
	for _, name := range []string{"full-before-levels", "full-0.0.0", "clean", "time-limit-before-levels"} {
		if s := card(fixture(t, name), 100, false); strings.Contains(s, "PROBLEMS") || strings.Contains(s, "help an Attacker needed") {
			t.Errorf("%s card:\n%s", name, s)
		}
	}
}

// With problems, the card shows them after the answer and no list of findings: each finding is still on its own screen.
func TestCardProblemsFollowTheAnswer(t *testing.T) {
	s := card(fixture(t, "pipeline-full"), plainW, false)
	// Every source of a problem is named: P1 holds a grader inspector finding and an exploit with no extra information too.
	if !strings.Contains(s, " ●●●●● exploit executable by unaided learner\n   from hack inspector + grader inspector + independent attacker\n") {
		t.Errorf("sources:\n%s", s)
	}
	// A problem whose finding gave no guidance was not attacked, and says so.
	if !strings.Contains(s, "  ●●○○○ reproduced exploit, not attacked: no guidance\n   from grader inspector\n") {
		t.Errorf("no guidance:\n%s", s)
	}
	// A problem no evidence confirmed is a lead, counted, not listed.
	if !strings.Contains(s, "\n 1 lead, which no evidence confirmed\n") || strings.Contains(s, "P4 timeout") {
		t.Errorf("leads:\n%s", s)
	}
	if !strings.Contains(s, "See report.md for the evidence and limits.\n\n PROBLEMS") || strings.Contains(s, "FP  ") ||
		strings.Contains(s, "HACK ") || strings.Contains(s, "inconclusive") || !strings.Contains(s, "next › nudi-view testdata/pipeline-full P1") {
		t.Errorf("card:\n%s", s)
	}
	if old := card(fixture(t, "full-before-levels"), plainW, false); !strings.Contains(old, "  1  ") {
		t.Errorf("a report without problems keeps its list of findings:\n%s", old)
	}
}

// The terminal card clips each line at its width, so a long cause gives way to the level; every source is named on
// the line under it, wrapped when it does not fit.
func TestCardShowsEverySourceAtTerminalWidth(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "attack": {"problems": [
		{"id": "P1", "cause": "`+strings.Repeat("Write the expected digest into the reward file. ", 4)+`", "source": "hack inspector",
		 "members": ["experiment-0000", "grader-1"], "help_needed": "found_alone"},
		{"id": "G1", "cause": "c2", "source": "grader inspector", "members": ["grader-2"], "help_needed": "full_info_or_less"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []int{100, 60} {
		s := card(r, w, true)
		for _, line := range splitLines(s) {
			if width(line) > w {
				t.Errorf("%d columns at width %d: %q", width(line), w, ansi.Strip(line))
			}
		}
		if plain := ansi.Strip(s); !strings.Contains(plain, " P1 Write") || !strings.Contains(plain, "●●●●● exploit") ||
			!strings.Contains(plain, "hack inspector +") || !strings.Contains(plain, "grader inspector +") ||
			!strings.Contains(plain, "independent") || !strings.Contains(plain, "●●●○○ exploit") {
			t.Errorf("at %d columns:\n%s", w, plain)
		}
	}
}

// A problem of correct work the grader fails is named with the simulation chart's FN words, never an exploit step;
// an older problem without findings or levels is a lead.
func TestCardNamesCorrectWorkFailedAndCountsOlderPendingProblemsAsLeads(t *testing.T) {
	r, err := load(writeReport(t, `{"answer": ["x"], "analyses": {"attack": "complete"}, "attack": {
		"candidates": [{"id": "grader-0", "valid_work": true}],
		"problems": [{"id": "G1", "cause": "rejects zeros", "source": "grader inspector", "findings": ["grader-0"], "help_needed": "full_info"},
		             {"id": "P1", "cause": "pending", "source": "hack inspector", "help_needed": "unknown"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := ansi.Strip(card(r, 120, true))
	if !strings.Contains(s, "Correct work failed, reproduced by an Attacker with full instructions") || strings.Contains(s, "●●●○○") {
		t.Errorf("correct work failed:\n%s", s)
	}
	if !strings.Contains(s, " 1 lead, which no evidence confirmed") || strings.Contains(s, "pending") {
		t.Errorf("older pending problem:\n%s", s)
	}
}

func TestPipelineFullCard(t *testing.T) {
	r := fixture(t, "pipeline-full")
	s := card(r, plainW, false)
	snapshot(t, "pipeline-full", "card.txt", s)
	for _, w := range []int{100, 80, 60} {
		for _, line := range splitLines(card(r, w, true)) {
			if width(line) > w {
				t.Errorf("%d columns at width %d: %q", width(line), w, ansi.Strip(line))
			}
		}
	}
	if a := plainPhase(r, 3); !strings.Contains(a, "P1                 no extra information") || !strings.Contains(a, "G1                 only a hint") ||
		strings.Contains(a, "selected") || strings.Contains(plainPhase(r, 2), "problems from") {
		t.Errorf("attack panel:\n%s", a)
	}
}

// The headline says how the run ended, so it stays neutral; red marks only the count of problems found, after it.
func TestBannerKeepsTheHeadlineNeutralAndMarksOnlyTheProblemCountRed(t *testing.T) {
	const redBackground, greyBackground = "48;2;255;95;109", "48;2;110;118;129"
	top := splitLines(card(fixture(t, "pipeline-full"), 120, true))[0]
	headline, count := strings.Index(top, "Finished. Every step ran."), strings.Index(top, redBackground)
	if !strings.HasPrefix(top[:headline], "\x1b") || !strings.Contains(top[:headline], greyBackground) || count < headline ||
		!strings.HasSuffix(strings.TrimRight(ansi.Strip(top), " "), "5 problems") {
		t.Errorf("banner %q", top)
	}
	r, err := load(writeReport(t, `{"answer": ["Finished. Every step ran."], "analyses": {"attack": "complete"}, "attack": {"problems": []}}`))
	if err != nil {
		t.Fatal(err)
	}
	if top := splitLines(card(r, 120, true))[0]; strings.Contains(top, redBackground) || strings.Contains(ansi.Strip(top), "problem") {
		t.Errorf("a run without problems has no red: %q", top)
	}
}
