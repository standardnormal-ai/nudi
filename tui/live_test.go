package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
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

// screenLines draws l at both widths, checks that no line is wider than the window, and returns the wide screen as plain text.
func screenLines(t *testing.T, l *Live, now time.Time) string {
	t.Helper()
	for _, w := range []int{80, 120} {
		for _, line := range splitLines(renderLive(l, now, w, 0)) {
			if width(line) > w {
				t.Errorf("%d columns at width %d: %q", width(line), w, ansi.Strip(line))
			}
		}
	}
	return ansi.Strip(renderLive(l, now, 120, 0))
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
		"nudi  runs/x", "⏱ 0:04:00", "$0.62", "$4", "modal",
		"concurrency 8 of 8 · 2 calls without a price",
		"HACKS ▲ some results unclear  0 problems, 0 exploited", "GRADER ⣾ 2:00", "Simulate · Inspect · Attack",
		"AGENTS  2 running", "Attacker", "0001-attacker", "1m 59s", "no extra informatio…",
		"attack inspector", "attack_inspector-at…", "1m 00s", "evidenced check-0002",
		"FINDINGS", "no extra information", "try 1 ⣾ 1m",
		" nudi: attempt_end\n nudi: session_start\n nudi: session_end",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	// Attempts from before problems formed during the run name no problem, so only the no extra information row shows them.
	for _, gone := range []string{"FOUND", "ATTACK ", "hack-0  ", "duplicate_case"} {
		if strings.Contains(s, gone) {
			t.Errorf("shows %q:\n%s", gone, s)
		}
	}
}

// Before nudi writes the log, the screen says what it waits for.
func TestLiveScreenWaitsForTheLog(t *testing.T) {
	if s := screenLines(t, &Live{Dir: "runs/x"}, at9("00:00")); !strings.Contains(s, "waiting for runs/x/events.jsonl") {
		t.Fatal(s)
	}
}

func TestLiveScreenNotesLimitCostAndWarnings(t *testing.T) {
	s := screenLines(t, liveFrom(t, ev("00:00", "run_start", `, "backend": "docker", "spending_cap": null, "concurrency": 2, "concurrency_setting": 4`)+
		ev("00:00", "phase_start", `, "phase": "simulation"`)+
		ev("00:01", "warning", `, "message": "w"`)+
		ev("05:00", "time_limit", `, "phase": "simulation", "minutes": 5, "known_cost": 1.5, "cancelled_calls": 1`)), at9("05:00"))
	for _, want := range []string{"$1.50   docker", "concurrency 2 of 4 · 1 call cancelled in flight · time limit of 5 minutes reached · 1 warning", "AGENTS  none running", "GRADER ⣾ 5:00"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "FINDINGS") || strings.Contains(s, "HACKS") {
		t.Errorf("a findings pipeline before any attempt or problem:\n%s", s)
	}
}

func TestLiveScreenShowsCleanedText(t *testing.T) {
	s := renderLive(liveFrom(t, ev("00:00", "run_start", `, "backend": "docker"`)+
		ev("00:01", "session_start", `, "inspector": "hack", "session": "a\u001b[2J\u0007b"`)), at9("00:02"), 120, 0)
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

// In a pipe, --follow prints each event's line as nudi writes it, then the card once the report is whole.
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
		strings.Count(out, "nudi: ") != lines || !strings.HasSuffix(out, "nudi: run_end\n"+card(r, plainW, false)+"\n") {
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
func TestFollowScreenGivesWayToTheCard(t *testing.T) {
	dir := t.TempDir()
	addLog(t, dir, attackLog)
	m, _ := newLive(dir).Update(liveTick{})
	if s := ansi.Strip(m.View().Content); !strings.Contains(s, "AGENTS  2 running") || !strings.Contains(s, "q quit") {
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
		t.Fatalf("%T does not show the card", m)
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
		"AGENTS  4 running", "hack-broad", "hack-leakage_metada…", "grader-episode-0004…", "Attacker", "only a hint",
		"evidenced check-0031", "HACKS", "GRADER", "Simulate · Inspect · Attack", "no extra information",
		"⏱ 0:59:21", "$1.20", "$3", "docker", "concurrency 4 of 4",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("no screen shows %q", want)
		}
	}
}
