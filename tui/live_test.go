package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func liveFrom(t *testing.T, log string) *Live {
	t.Helper()
	l := &Live{Dir: "runs/x"}
	for _, e := range readAll(t, log) {
		l.apply(e)
	}
	return l
}

// at9 is 09:MM:SS UTC on the day the test events are written.
func at9(ms string) time.Time {
	t, _ := time.Parse(time.RFC3339, "2026-11-07T09:"+ms+"Z")
	return t
}

// liveScreen is the live screen of l at time now, w columns wide and h rows high, 0 for no limit, as plain text. It
// checks that no line is wider than the window.
func liveScreen(t *testing.T, l *Live, now time.Time, w, h int) string {
	t.Helper()
	return liveKeys(t, l, now, w, h)
}

// liveKeys is liveScreen after the keys were pressed.
func liveKeys(t *testing.T, l *Live, now time.Time, w, h int, keys ...string) string {
	t.Helper()
	var m tea.Model = liveModel{l: *l, w: w, h: h}
	for _, k := range keys {
		m, _ = m.Update(keyMsg(k))
	}
	s := m.(liveModel).render(now)
	for _, line := range splitLines(s) {
		if width(line) > w {
			t.Errorf("%d columns at width %d: %q", width(line), w, ansi.Strip(line))
		}
	}
	// View adds a blank row above and the cursor's row below.
	if h > 0 && lipgloss.Height(s)+2 > h {
		t.Errorf("%d rows at height %d:\n%s", lipgloss.Height(s)+2, h, ansi.Strip(s))
	}
	return plainText(s)
}

// screenLines draws l at 60, 80 and 120 columns, also 24 rows high, and returns the screen at 100 columns.
func screenLines(t *testing.T, l *Live, now time.Time) string {
	t.Helper()
	for _, w := range []int{60, 80, 120} {
		liveScreen(t, l, now, w, 0)
		liveScreen(t, l, now, w, 24)
	}
	return liveScreen(t, l, now, 100, 0)
}

// An attack in progress: two attempts still run, others returned, one is read by its attack inspector.
var attackLog = ev("00:00", "run_start", `, "backend": "modal", "spending_cap": 4, "concurrency": 8, "concurrency_setting": 8, "known_cost": 0`) +
	ev("00:00", "phase_start", `, "phase": "hack"`) +
	ev("00:30", "evidenced", `, "inspector": "hack", "outcome": "accepted_invalid", "category": "grader_tampering", "id": "check-0001", "index": 0`) +
	ev("02:00", "phase_end", `, "phase": "hack", "status": "partial"`) +
	ev("02:00", "phase_start", `, "phase": "attack"`) +
	ev("02:01", "attempt_start", `, "episode": "0000-attacker", "candidate": "hack-0", "level": "full", "number": 1`) +
	ev("02:01", "attempt_start", `, "episode": "0001-attacker", "candidate": null, "level": "none", "number": 1`) +
	ev("02:02", "attempt_start", `, "episode": "0002-attacker", "candidate": "hack-0", "level": "full", "number": 2`) +
	ev("02:03", "attempt_start", `, "episode": "0003-attacker", "candidate": "hack-0", "level": "minimal", "number": 1`) +
	ev("02:04", "attempt_start", `, "episode": "0004-attacker", "candidate": "hack-0", "level": "minimal", "number": 2`) +
	ev("03:00", "attempt_end", `, "episode": "0000-attacker", "rewards": [1.0]`) +
	ev("03:00", "session_start", `, "inspector": "attack", "session": "attack_inspector-attacker-hack-0-full-1", "episode": "0000-attacker"`) +
	ev("03:30", "evidenced", `, "inspector": "attack", "outcome": "accepted_invalid", "category": "accepted_invalid", "id": "check-0002", "index": 0, "episode": "0000-attacker"`) +
	ev("03:40", "attempt_end", `, "episode": "0002-attacker", "rewards": [0.0]`) +
	ev("03:41", "attempt_end", `, "episode": "0003-attacker", "rewards": [1.0]`) +
	ev("03:41", "session_start", `, "inspector": "attack", "session": "s3", "episode": "0003-attacker"`) +
	ev("03:50", "session_end", `, "inspector": "attack", "session": "s3", "status": "duplicate_case"`) +
	ev("03:55", "attempt_end", `, "episode": "0004-attacker", "rewards": [1.0]`) +
	ev("03:55", "session_start", `, "inspector": "attack", "session": "s4", "episode": "0004-attacker"`) +
	ev("03:58", "session_end", `, "inspector": "attack", "session": "s4", "status": "no_evidenced_issue", "known_cost": 0.62, "unknown_cost_calls": 2`)

func TestLiveScreen(t *testing.T) {
	s := screenLines(t, liveFrom(t, attackLog), at9("04:00"))
	for _, want := range []string{
		"nudi  runs/x   following live", "Modal     Elapsed 4:00     Concurrency 8", "Model cost $0.62 of $4.00",
		"Simulation waiting", "Find Hacks partly", "Attack  ⣾",
		"Agents  2 running", "Attacker", "No information", "Looking for any hack", "Try 1",
		"Attack Inspector", "Checks try 1, full",
		"Findings So Far (0)", "None yet.",
		"Can an Attacker Succeed Without Any Information?", "Try   Status        Hack demonstrated?  New finding?  Problem",
		"Logs", "l expand", "Attack Inspector  Ended, no evidence found: check of try 2 with only a hint",
		"Attacker          Episode returned, reward 1: try 2 with only a hint",
		"? Help   Tab next tab   Up/Down scroll   l logs   q Stop following",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	// Attempts from before problems formed during the run name no problem, so only the no-information block shows them.
	for _, gone := range []string{"·", "▲", "duplicate_case", "m Models", "0000-attacker"} {
		if strings.Contains(s, gone) {
			t.Errorf("shows %q:\n%s", gone, s)
		}
	}
}

// Before nudi writes the log, the screen says what it waits for.
func TestLiveScreenWaitsForTheLog(t *testing.T) {
	if s := screenLines(t, &Live{Dir: "runs/x"}, at9("00:00")); !strings.Contains(s, "Waiting for runs/x/events.jsonl") {
		t.Fatal(s)
	}
}

func TestLiveScreenNotesLimitAndCost(t *testing.T) {
	l := liveFrom(t, ev("00:00", "run_start", `, "backend": "docker", "spending_cap": null, "concurrency": 2, "concurrency_setting": 4`)+
		ev("00:00", "phase_start", `, "phase": "simulation"`)+
		ev("00:01", "warning", `, "message": "w"`)+
		ev("05:00", "time_limit", `, "phase": "simulation", "minutes": 5, "known_cost": 1.5, "cancelled_calls": 1`))
	s := screenLines(t, l, at9("05:00"))
	for _, want := range []string{"Docker     Elapsed 5:00     Concurrency 2", "Model cost $1.50", "Simulation  ⣾",
		"Limit  The run reached its time limit of 5 minutes. Its report keeps the results so far.", "Agents  none running"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "1 warning") || strings.Contains(s, "Can an Attacker") {
		t.Errorf("an orphan count or an empty block:\n%s", s)
	}
	if c := liveKeys(t, l, at9("05:00"), 100, 0, "c"); !strings.Contains(c, "Calls cancelled in") {
		t.Errorf("cost panel:\n%s", c)
	}
}

func TestLiveScreenShowsCleanedText(t *testing.T) {
	s := liveModel{l: *liveFrom(t, ev("00:00", "run_start", `, "backend": "docker"`)+ev("00:00", "phase_start", `, "phase": "grader"`)+
		ev("00:01", "session_start", `, "inspector": "grader", "session": "s", "episode": "a\u001b[2J\u0007b"`)), w: 120}.render(at9("00:02"))
	if strings.Contains(s, "\x1b[2J") || strings.Contains(s, "\a") || !strings.Contains(ansi.Strip(s), "a[2Jb") {
		t.Fatalf("%q", s)
	}
}

func copyReport(t *testing.T, from, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(from, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

var runEnd = ev("05:00", "phase_end", `, "phase": "attack", "status": "complete"`) + ev("05:01", "run_end", `, "status": "complete", "report": "report.json"`)

// In a pipe, --follow prints each event's line as nudi writes it, then the plain report once it is whole.
func TestFollowPipe(t *testing.T) {
	dir := t.TempDir()
	addLog(t, dir, attackLog+runEnd)
	copyReport(t, "testdata/full", dir)
	code, out, errs := run("--follow", dir)
	r, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Count(attackLog+runEnd, "\n")
	if code != 0 || errs != "" || !strings.HasPrefix(out, "nudi: run_start\nnudi: phase_start\nnudi: evidenced\n") ||
		strings.Count(out, "nudi: ") != lines || !strings.HasSuffix(out, "nudi: run_end\n"+plainReport(r, plainW)+"\n") {
		t.Fatalf("exit %d %q:\n%s", code, errs, out)
	}
}

func TestFollowRefuses(t *testing.T) {
	stopped := ev("00:00", "run_start", "") + ev("00:01", "run_end", `, "status": "stopped", "report": null`)
	for _, c := range []struct{ log, report, arg, want string }{
		{stopped, "", "", "the run ended with status stopped and nudi wrote no report.json"},
		{ev("00:00", "run_start", "") + ev("00:01", "run_end", `, "status": "complete", "report": "report.json"`), `{"status": "complete"}`, "", "older than 0.0.0"},
		{ev("00:00", "run_start", "") + `{"v": 2, "kind": "run_start"}` + "\n", "", "", "line 2 has format version 2; this viewer reads version 1"},
		{stopped, "", "1", "--follow takes a run folder and no finding number"},
	} {
		dir := t.TempDir()
		addLog(t, dir, c.log)
		if c.report != "" {
			if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte(c.report), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		args := []string{"--follow", dir}
		if c.arg != "" {
			args = append(args, c.arg)
		}
		if code, out, errs := run(args...); code != 2 || !strings.Contains(errs, c.want) || c.arg == "" && !strings.HasPrefix(out, "nudi: run_start\n") {
			t.Errorf("%q: exit %d, %q %q", c.want, code, out, errs)
		}
	}
	if code, _, errs := run("--follow", filepath.Join(t.TempDir(), "none")); code != 2 || !strings.Contains(errs, "no such file") {
		t.Errorf("a missing folder: exit %d %q", code, errs)
	}
}

// A follow ends when the run's process on this host is gone without run_end, or when no log begins in time.
func TestFollowEndsForARunThatIsGone(t *testing.T) {
	ended := exec.Command("true")
	if err := ended.Run(); err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	start := func(pid int, host string) string {
		return ev("00:00", "run_start", fmt.Sprintf(`, "pid": %d, "host": %q`, pid, host))
	}
	dir := t.TempDir()
	addLog(t, dir, start(ended.ProcessState.Pid(), host))
	want := fmt.Sprintf("nudi (pid %d) is no longer running and wrote no run_end; nudi report ", ended.ProcessState.Pid())
	if code, out, errs := run("--follow", dir); code != 2 || out != "nudi: run_start\n" || !strings.Contains(errs, want) {
		t.Errorf("exit %d, %q %q", code, out, errs)
	}
	// A process still running, or one on another host, which cannot be checked, keeps the follow going.
	for _, log := range []string{start(os.Getpid(), host), start(ended.ProcessState.Pid(), "another-host"), ev("00:00", "run_start", "")} {
		dir := t.TempDir()
		addLog(t, dir, log)
		f, l := &follower{dir: dir}, &Live{Dir: dir}
		for range 2 {
			if _, r, err := f.poll(l); r != nil || err != nil {
				t.Errorf("%s: %v", log, err)
			}
		}
	}
	empty := t.TempDir()
	if _, _, err := (&follower{dir: empty}).poll(&Live{Dir: empty}); err != nil {
		t.Errorf("a new folder: %v", err)
	}
	late := &follower{dir: empty, begun: time.Now().Add(-startWait - time.Second)}
	if _, _, err := late.poll(&Live{Dir: empty}); err == nil || !strings.Contains(err.Error(), "no nudi run began its events.jsonl there within 2 minutes") {
		t.Errorf("an empty folder: %v", err)
	}
}

// In a terminal the live screen reads the log once a second and gives way to the viewer once the report is whole.
func TestFollowScreenGivesWayToTheViewer(t *testing.T) {
	dir := t.TempDir()
	addLog(t, dir, attackLog)
	m, _ := newLive(dir).Update(liveTick{})
	if s := ansi.Strip(m.View().Content); !strings.Contains(s, "Agents  2 running") || !strings.Contains(s, "q Stop following") {
		t.Fatalf("live screen:\n%s", s)
	}
	addLog(t, dir, runEnd)
	copyReport(t, "testdata/full", dir)
	for range 9 {
		if m, _ = m.Update(liveTick{}); len(m.(liveModel).l.Phases) != 2 || m.(liveModel).l.End != nil {
			t.Fatal("the log was read before a second passed")
		}
	}
	m, _ = m.Update(liveTick{})
	v, ok := m.(model)
	if !ok || !strings.Contains(v.View().Content, "The grader can be cheated") {
		t.Fatalf("%T does not show the viewer", m)
	}
}

func TestFollowScreenQuits(t *testing.T) {
	dir := t.TempDir()
	addLog(t, dir, attackLog)
	m, cmd := newLive(dir).Update(tea.KeyPressMsg{Text: "q"})
	if _, ok := m.(liveModel); !ok || cmd == nil || cmd() != tea.Quit() {
		t.Fatal("q does not quit the live screen")
	}
	addLog(t, dir, `{"v": 2}`+"\n")
	m, cmd = newLive(dir).Update(liveTick{})
	if m.(liveModel).err == nil || cmd == nil || cmd() != tea.Quit() {
		t.Fatal("an unknown version does not stop the live screen")
	}
}

// A replay of a whole recorded run log, written half a line at a time, through the same reader and screen as a live run.
// The log in testdata/live holds ids, statuses and counts only.
func TestReplayRecordedLog(t *testing.T) {
	b, err := os.ReadFile("testdata/live/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(strings.TrimSuffix(string(b), "\n"))
	dir := t.TempDir()
	f, l := &follower{dir: dir}, &Live{Dir: "runs/demo"}
	var seen strings.Builder
	read := 0
	for i, line := range lines {
		half := len(line) / 2
		for j, part := range []string{line[:half], line[half:] + "\n"} {
			if i == len(lines)-1 && j == 1 {
				copyReport(t, "testdata/full", dir)
			}
			addLog(t, dir, part)
			events, r, err := f.poll(l)
			if err != nil {
				t.Fatal(err)
			}
			if read += len(events); read != i+j {
				t.Fatalf("line %d half %d: %d events read in all", i+1, j+1, read)
			}
			if r != nil != (read == len(lines)) {
				t.Fatalf("line %d half %d: report %v", i+1, j+1, r != nil)
			}
			now := time.Time{}
			if l.Last != nil {
				now = l.Last.at()
			}
			seen.WriteString(screenLines(t, l, now))
		}
	}
	s := seen.String()
	for _, want := range []string{
		"Agents  4 running", "General search", "Focused search", "Reads leaked answer", "Episode review", "Only a hint, try",
		"Find Hacks  ⣾", "Grade Simulations  ⣾", "Attack  ⣾", "Can an Attacker Succeed Without Any Information?", "Hack Inspector    Started: general search of all categories",
		"Elapsed 59:21", "Model cost $1.20 of $3.00", "Docker", "Concurrency 4",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("no screen shows %q", want)
		}
	}
}

// The live logs and findings name jobs, targets, help and outcomes in words: no session ids, no outcome labels and
// no problem ids as names. Related observations are listed by their reference.
func TestLiveWordsOnly(t *testing.T) {
	ids := regexp.MustCompile(`\bP\d+\b`)
	for _, name := range []string{"pipeline-hacks", "pipeline-grader"} {
		l := pipelineLive(t, name)
		for _, s := range []string{liveKeys(t, l, l.Last.at(), 100, 0, "l"), liveKeys(t, l, l.Last.at(), 100, 0, "tab", "l")} {
			for _, gone := range []string{"attack_inspector-attacker", "accepted_invalid", "rejected_valid", "nudi: "} {
				if strings.Contains(s, gone) {
					t.Errorf("%s shows %q:\n%s", name, gone, s)
				}
			}
			if id := ids.FindString(s); id != "" {
				t.Errorf("%s names %s:\n%s", name, id, s)
			}
		}
	}
	if s := liveKeys(t, pipelineLive(t, "pipeline-hacks"), time.Time{}, 100, 0, "o"); !strings.Contains(s, "Reference") || strings.Contains(s, "Observation ") {
		t.Errorf("related observations:\n%s", s)
	}
}

// The live Help lists only what works while the run goes on, says what partly means and what the references are.
func TestLiveHelp(t *testing.T) {
	s := plainText(helpPanel(wideAt, true))
	for _, want := range []string{"partly", "unresolved", "References", "Findings So Far"} {
		if !strings.Contains(s, want) {
			t.Errorf("live help lacks %q:\n%s", want, s)
		}
	}
	for _, gone := range []string{"i lists", "Work left", "◆", "›"} {
		if strings.Contains(s, gone) {
			t.Errorf("live help shows %q:\n%s", gone, s)
		}
	}
}

// Log lines say only what the events record: a reproduction has no scope, an attempt stopped after its episode
// started was started, a session's evidence is its result, and a grader session's end reviewed what its start named.
func TestLiveLogSaysWhatEventsRecord(t *testing.T) {
	l := liveFrom(t, ev("00:01", "judged", `, "inspector": "grader", "problem": "P4", "finding": "grader-1", "new": true, "cause": "c4"`)+
		ev("00:02", "reproduced", `, "problem": "P4", "result": "evidenced"`)+
		ev("00:03", "attempt_start", `, "episode": "0001-attacker", "level": "full", "number": 1, "problem": "P4"`)+
		ev("00:04", "attempt_end", `, "episode": "0001-attacker", "rewards": [1.0]`)+
		ev("00:05", "attempt_result", `, "episode": "0001-attacker", "level": "full", "number": 1, "problem": "P4", "status": "spending_exhausted"`)+
		ev("00:06", "attempt_result", `, "episode": "0002-attacker", "level": "full", "number": 2, "problem": "P4", "status": "spending_exhausted"`)+
		ev("00:07", "session_start", `, "inspector": "hack", "session": "hack-other", "category": "other"`)+
		ev("00:08", "session_end", `, "inspector": "hack", "session": "hack-other", "category": "other", "elapsed": 60, "status": "no_evidenced_issue", "result": "evidenced_issue"`)+
		ev("00:09", "session_start", `, "inspector": "grader", "session": "grader-episode-0005-simulator", "episode": "0005-simulator"`)+
		ev("00:10", "session_end", `, "inspector": "grader", "session": "grader-episode-0005-simulator", "elapsed": 60, "status": "evidenced_issue"`)+
		ev("00:11", "session_end", `, "inspector": "grader", "session": "grader-episode-0006-simulator", "elapsed": 60, "status": "evidenced_issue"`))
	want := map[int]string{
		1:  "Reproduced: c4",
		4:  "Stopped at the spending cap: try 1 with full instructions",
		5:  "Not started: try 2 with full instructions",
		7:  "Ended after 1:00, evidence found: focused search for",
		9:  "Ended after 1:00, evidence found: review of episode 0005-simulator",
		10: "",
	}
	for i, w := range want {
		if got := plainText(l.logWords(l.Recent[i])); !strings.HasPrefix(got, w) || w == "" && got != "" {
			t.Errorf("event %d says %q, want %q", i, got, w)
		}
	}
}

// The live no-information table says how a try stopped once its episode started, and "Not started" only for one
// that never started.
func TestLiveNoInfoSaysHowAStartedTryStopped(t *testing.T) {
	l := liveFrom(t, ev("00:01", "attempt_start", `, "episode": "0001-attacker", "level": "none", "number": 1`)+
		ev("00:02", "attempt_end", `, "episode": "0001-attacker", "rewards": [1.0]`)+
		ev("00:03", "attempt_result", `, "episode": "0001-attacker", "level": "none", "number": 1, "status": "spending_exhausted"`)+
		ev("00:04", "attempt_result", `, "episode": null, "level": "none", "number": 2, "status": "spending_exhausted"`))
	s := strings.Join(l.noInfo(at9("00:05"), "", 100), "\n")
	if first, second := row(plainText(s), "1 "), row(plainText(s), "2 "); !strings.Contains(first, "Stopped at") || strings.Contains(first, "Not started") || !strings.Contains(second, "Not started") {
		t.Errorf("first %q, second %q:\n%s", first, second, plainText(s))
	}
}

// The attack runs on after the hack inspection ends, so the hacks count what Attackers exploit after its end too.
func TestTheHacksCountUpdatesAfterTheHackPhaseEnd(t *testing.T) {
	log := ev("00:00", "run_start", `, "backend": "docker", "analyses": ["hack", "attack"]`) +
		ev("00:00", "phase_start", `, "phase": "hack"`) +
		ev("00:00", "phase_start", `, "phase": "attack"`) +
		ev("00:10", "judged", `, "inspector": "hack", "finding": "hack-0", "problem": "P1", "new": true, "cause": "forge"`) +
		ev("01:00", "phase_end", `, "phase": "hack", "status": "complete", "elapsed": 60`)
	l := liveFrom(t, log)
	if p, x := l.hackCounts(); p != 1 || x != 0 {
		t.Fatalf("at the hack phase end: %d problems, %d exploited", p, x)
	}
	for _, e := range readAll(t, ev("01:10", "attempt_start", `, "episode": "0000-attacker", "problem": "P1", "level": "full", "number": 1`)+
		ev("02:00", "attempt_end", `, "episode": "0000-attacker", "problem": "P1", "level": "full", "number": 1`)+
		ev("02:30", "attempt_result", `, "episode": "0000-attacker", "problem": "P1", "level": "full", "number": 1, "status": "evidenced_issue"`)+
		ev("02:40", "judged", `, "inspector": "grader", "finding": "grader-0", "problem": "P2", "new": true, "cause": "skip"`)) {
		l.apply(e)
	}
	if p, x := l.hackCounts(); p != 2 || x != 1 {
		t.Fatalf("after the hack phase end: %d problems, %d exploited", p, x)
	}
}

// A finding a later reading withdrew, and a reading that revises an earlier one, are logged in words, without outcome
// labels or check ids.
func TestLiveLogSaysWithdrawnAndRevisedInWords(t *testing.T) {
	l := liveFrom(t, ev("00:01", "judged", `, "inspector": "hack", "problem": "P1", "finding": "hack-0", "new": true, "cause": "c1"`)+
		ev("00:02", "revised", `, "inspector": "hack", "id": "check-7", "index": 1, "before": "accepted_invalid", "after": "legitimate"`)+
		ev("00:03", "withdrawn", `, "candidate": "hack-0", "problem": "P1", "level": "full"`))
	for i, want := range map[int]string{1: "Read a check again: its earlier finding is withdrawn or corrected",
		2: "Not started, a later reading withdrew the finding: with full instructions, for c1"} {
		if got := plainText(l.logWords(l.Recent[i])); got != want {
			t.Errorf("event %d says %q, want %q", i, got, want)
		}
	}
}

// A try that exploited another problem than its target demonstrated a hack: the no-information table names the problem
// the judge put it in, and a guided try the judge put in an existing problem marks that problem.
func TestLiveTriesAnswerFromJudgeMembership(t *testing.T) {
	l := liveFrom(t, ev("00:01", "judged", `, "inspector": "hack", "problem": "P1", "finding": "hack-1", "new": true, "cause": "c1"`)+
		ev("00:02", "judged", `, "inspector": "hack", "problem": "P2", "finding": "hack-2", "new": true, "cause": "c2"`)+
		ev("00:03", "attempt_start", `, "episode": "0001-attacker", "level": "none", "number": 1, "problem": "P1"`)+
		ev("00:04", "judged", `, "inspector": "attack", "problem": "A1", "finding": "0001-attacker", "new": true, "cause": "reads answer"`)+
		ev("00:05", "attempt_result", `, "episode": "0001-attacker", "level": "none", "number": 1, "problem": "P1", "status": "other_exploit"`)+
		ev("00:06", "attempt_start", `, "episode": "0002-attacker", "level": "full", "number": 1, "problem": "P1"`)+
		ev("00:07", "judged", `, "inspector": "attack", "problem": "P2", "finding": "0002-attacker", "new": false, "cause": "c2"`)+
		ev("00:08", "attempt_result", `, "episode": "0002-attacker", "level": "full", "number": 1, "problem": "P1", "status": "other_exploit"`))
	s := plainText(strings.Join(l.noInfo(at9("00:09"), "", 100), "\n"))
	if got := cells(s, "1 "); got != "Finished ✓ ✓ Reads answer" {
		t.Errorf("no-information row %q:\n%s", got, s)
	}
	if got := plainText(l.mark(l.lane("P2"), "full", at9("00:09"), "")); got != plainText(glyph("yes")) {
		t.Errorf("P2 full instructions %q", got)
	}
}

// A problem a later reading withdrew says so on its row and leaves the count, unless an Attacker demonstrated it.
func TestLiveWithdrawnProblemLeavesTheCount(t *testing.T) {
	log := ev("00:00", "run_start", `, "backend": "docker"`) +
		ev("00:01", "judged", `, "inspector": "hack", "problem": "P1", "finding": "hack-0", "new": true, "cause": "c1"`) +
		ev("00:02", "reproduced", `, "problem": "P1", "result": "evidenced"`) +
		ev("00:03", "revised", `, "inspector": "hack", "id": "check-0", "index": 1, "before": "accepted_invalid", "after": "legitimate"`) +
		ev("00:04", "withdrawn", `, "candidate": "hack-0", "problem": "P1", "level": "full"`)
	s := plainText(liveFrom(t, log).resultsBody(Report{}, at9("00:05"), "", 100))
	if !strings.Contains(s, "0 problems so far") || cells(s, "C1") != "✓ ✗ - -" {
		t.Errorf("withdrawn P1 row %q:\n%s", cells(s, "C1"), s)
	}
	s = plainText(liveFrom(t, log+ev("00:05", "attempt_result", `, "episode": null, "problem": "P1", "level": "none", "number": 1, "status": "evidenced_issue"`)).
		resultsBody(Report{}, at9("00:06"), "", 100))
	if !strings.Contains(s, "1 problem so far") {
		t.Errorf("an Attacker's exploit keeps it:\n%s", s)
	}
}

// A phase tab that is not running shows only its phase and its own agents. The findings so far, the Attacker given no
// information, the related observations and the logs show on the running phase's tab and on Results.
func TestIdlePhaseTabShowsOnlyItsPhaseAndAgents(t *testing.T) {
	l := pipelineLive(t, "pipeline-grader")
	shared := []string{"Findings So Far", "Can an Attacker", "Related Observations", "Logs"}
	for name, keys := range map[string][]string{"Simulation  ✓": {"shift+tab"}, "Find Hacks  ✓": {"tab"}, "Attack  waiting": {"tab", "tab"}} {
		s := liveKeys(t, l, l.Last.at(), 100, 0, keys...)
		if !strings.Contains(s, name) || !strings.Contains(s, "Agents  none running") {
			t.Errorf("%s tab:\n%s", name, s)
		}
		for _, gone := range append(shared, "General review") {
			if strings.Contains(s, gone) {
				t.Errorf("%s tab shows %q:\n%s", name, gone, s)
			}
		}
	}
	for _, s := range []string{liveScreen(t, l, l.Last.at(), 100, 0), liveKeys(t, l, l.Last.at(), 100, 0, "tab", "tab", "tab")} {
		if !strings.Contains(s, "Can an Attacker") || !strings.Contains(s, "Reward reads stdout") {
			t.Errorf("the running tab or Results lacks the findings:\n%s", s)
		}
	}
}

// Results keeps the finished sections while the run goes on; those the events do not fill say when they come.
func TestLiveResultsKeepsTheFinishedSections(t *testing.T) {
	l := pipelineLive(t, "pipeline-grader")
	s := liveKeys(t, l, l.Last.at(), 100, 0, "tab", "tab", "tab")
	at := -1
	for _, h := range []string{"Problems (5)", "Abandoned Problems", "Simulation Rewards", "Grader Accuracy", "Work Left", "\n Cost"} {
		i := strings.Index(s, h)
		if i < at {
			t.Fatalf("%s missing or out of order:\n%s", h, s)
		}
		at = i
	}
	if n := strings.Count(s, "Available when the run ends."); n != 4 || strings.Contains(s, "Findings So Far") {
		t.Errorf("%d sections wait for the end:\n%s", n, s)
	}
}
