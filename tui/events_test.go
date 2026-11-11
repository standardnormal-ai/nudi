package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ev is one event line of format version 1, written at 09:MM:SS UTC on the day of the test runs.
func ev(at, kind, fields string) string {
	return `{"v": 1, "time": "2026-11-07T09:` + at + `.000000+00:00", "kind": "` + kind + `", "text": "nudi: ` + kind + `"` + fields + "}\n"
}

func addLog(t *testing.T, dir, body string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
}

func kinds(events []Event) string {
	var out []string
	for _, e := range events {
		out = append(out, e.Kind)
	}
	return strings.Join(out, " ")
}

// nudi may be writing the last line, so only lines that end in a newline are read.
func TestFollowReadsWholeLinesOnly(t *testing.T) {
	dir := t.TempDir()
	f := &follower{dir: dir}
	if events, err := f.next(); err != nil || len(events) != 0 {
		t.Fatalf("before nudi writes the log: %v %v", events, err)
	}
	start, phase := ev("00:00", "run_start", `, "backend": "docker"`), ev("00:01", "phase_start", `, "phase": "hack"`)
	addLog(t, dir, start+phase[:20])
	if events, err := f.next(); err != nil || kinds(events) != "run_start" || events[0].Backend != "docker" {
		t.Fatalf("%v %v", events, err)
	}
	addLog(t, dir, phase[20:])
	if events, err := f.next(); err != nil || kinds(events) != "phase_start" || events[0].Phase != "hack" {
		t.Fatalf("%v %v", events, err)
	}
	if events, err := f.next(); err != nil || len(events) != 0 {
		t.Fatalf("read twice: %v %v", events, err)
	}
}

func TestFollowRefusesWhatItCannotRead(t *testing.T) {
	ok := ev("00:00", "run_start", "")
	for body, want := range map[string]string{
		`{"v": 2, "kind": "run_start"}` + "\n": "events.jsonl line 1 has format version 2; this viewer reads version 1",
		ok + `{"kind": "run_start"}` + "\n":    "events.jsonl line 2 has format version null",
		`{"v": 1` + "\n":                       "events.jsonl line 1: unexpected end",
		"[1]\n":                                "events.jsonl line 1 is not a JSON object",
		ok + `{"v": 1, "kind": "x", "number": "two"}` + "\n": "events.jsonl line 2: json: cannot unmarshal",
	} {
		dir := t.TempDir()
		addLog(t, dir, body)
		if _, err := (&follower{dir: dir}).next(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
	if _, err := (&follower{dir: filepath.Join(t.TempDir(), "none")}).next(); err == nil {
		t.Error("a missing run folder is followed")
	}
}

func TestFollowStaysInRunFolder(t *testing.T) {
	outside := t.TempDir()
	addLog(t, outside, ev("00:00", "run_start", ""))
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "events.jsonl"), filepath.Join(dir, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	if events, err := (&follower{dir: dir}).next(); err == nil {
		t.Fatalf("an events.jsonl linked from outside the run folder was read: %v", events)
	}
}

// Event strings can hold model or task text, so they are cleaned as the report is, map keys included.
func TestFollowCleansEventStrings(t *testing.T) {
	dir := t.TempDir()
	addLog(t, dir, `{"v": 1, "kind": "session_start", "inspector": "hack", "session": "a\u001b[2J\u0007b‮c", "text": "x\u001b]0;t\u0007y", "k\u001bey": 1}`+"\n")
	events, err := (&follower{dir: dir}).next()
	if err != nil || len(events) != 1 {
		t.Fatalf("%v %v", events, err)
	}
	if e := events[0]; e.Session != "a[2Jbc" || e.Text != "x]0;ty" {
		t.Fatalf("%q %q", e.Session, e.Text)
	}
}

// The live state holds what is running now: a session or an Attacker attempt from its start to its end.
func TestLiveTracksWhatRuns(t *testing.T) {
	log := ev("00:00", "run_start", `, "backend": "modal", "spending_cap": 4, "concurrency": 8, "concurrency_setting": 8`) +
		ev("00:00", "phase_start", `, "phase": "hack"`) +
		ev("00:01", "session_start", `, "inspector": "hack", "session": "hack-broad"`) +
		ev("00:30", "evidenced", `, "inspector": "hack", "outcome": "accepted_invalid", "category": "grader_tampering", "id": "check-0001", "index": 0`) +
		ev("01:00", "session_end", `, "inspector": "hack", "session": "hack-broad", "elapsed": 59, "status": "evidenced_issue"`) +
		ev("01:00", "session_start", `, "inspector": "hack", "session": "hack-persistence", "category": "persistence"`) +
		ev("01:00", "session_start", `, "inspector": "hack", "session": "hack-online_lookup", "category": "online_lookup"`)
	var l Live
	for _, e := range readAll(t, log) {
		l.apply(e)
	}
	if len(l.Agents) != 2 || l.Agents[0].Name != "hack-persistence" || l.Agents[1].Name != "hack-online_lookup" {
		t.Fatalf("%+v", l)
	}
	for _, e := range readAll(t, ev("02:00", "phase_end", `, "phase": "hack", "status": "complete", "elapsed": 120`)+
		ev("02:00", "phase_start", `, "phase": "attack"`)+
		ev("02:01", "attempt_start", `, "episode": "0000-attacker", "candidate": "hack-0", "level": "full", "number": 1`)+
		ev("02:01", "attempt_start", `, "episode": "0001-attacker", "candidate": null, "level": "none", "number": 1`)+
		ev("03:00", "attempt_end", `, "episode": "0000-attacker", "candidate": "hack-0", "level": "full", "number": 1, "elapsed": 59, "rewards": [1.0]`)+
		ev("03:00", "session_start", `, "inspector": "attack", "session": "attack_inspector-attacker-hack-0-full-1", "episode": "0000-attacker"`)+
		ev("03:30", "evidenced", `, "inspector": "attack", "outcome": "accepted_invalid", "id": "check-0002", "index": 0, "episode": "0000-attacker"`)) {
		l.apply(e)
	}
	if l.Phases[0].Status != "complete" || l.Phases[1].Kind != "phase_start" {
		t.Fatalf("phases %+v", l.Phases)
	}
	var running []string
	for _, a := range l.Agents {
		running = append(running, a.Who+" "+a.Name+" "+a.Last)
	}
	if got := strings.Join(running, ", "); got != "attacker 0001-attacker no information, try 1, attack attack_inspector-attacker-hack-0-full-1 evidenced check-0002" {
		t.Fatalf("running: %s", got)
	}
	if len(l.Tries) != 2 || l.Tries[0].Returned == nil || !l.Tries[0].Inspecting || l.Tries[1].Returned != nil {
		t.Fatalf("tries %+v", l.Tries)
	}
	for _, e := range readAll(t, ev("04:00", "session_end", `, "inspector": "attack", "session": "attack_inspector-attacker-hack-0-full-1", "status": "evidenced_issue"`)+
		ev("04:00", "attempt_result", `, "episode": "0000-attacker", "level": "full", "status": "evidenced_issue"`)+
		ev("05:00", "time_limit", `, "phase": "attack", "minutes": 5`)+
		ev("05:01", "run_end", `, "status": "time_limit", "report": "report.json"`)) {
		l.apply(e)
	}
	if len(l.Agents) != 0 || l.Tries[0].Inspecting || l.Tries[0].Status != "evidenced_issue" || l.Tries[1].Status != "" || l.Limit == nil || l.End == nil {
		t.Fatalf("after the end: %+v", l)
	}
}

func readAll(t *testing.T, log string) []Event {
	t.Helper()
	dir := t.TempDir()
	addLog(t, dir, log)
	events, err := (&follower{dir: dir}).next()
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// nudi writes each text after its clock time, and in a batch after the environment's name too; both stay.
func TestLegacySessionEndTextInFollowAndLive(t *testing.T) {
	body, err := os.ReadFile("testdata/clean/report.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, lead := range []string{"", "nudi: 09:00:01 ", "nudi: 09:00:01 sort-task: "} {
		for _, tc := range []struct{ status, category, state, suffix string }{
			{"no_evidenced_issue", "online_lookup", "unknown", "; searched online_lookup"},
			{"evidenced_issue", "online_lookup", "evidenced_issue", "; searched online_lookup"},
			{"unknown", "online_lookup", "pending", "; searched online_lookup"},
			{"tool_failure", "online_lookup", "unknown", ": attempt tool_failure; searched online_lookup"},
			{"cancelled", "online_lookup", "restricted", ": attempt cancelled; searched online_lookup"},
			{"no_evidenced_issue", "", "", ""},
		} {
			t.Run(lead+tc.status+tc.state, func(t *testing.T) {
				dir := writeReport(t, string(body))
				prefix := lead + "hack inspector hack-online_lookup ended after 0:00:01"
				line := prefix + ": attempt " + tc.status
				if tc.category != "" {
					line += "; category " + tc.category + " " + tc.state
				}
				raw := map[string]any{"v": 1, "kind": "session_end", "text": line, "inspector": "hack",
					"session": "hack-online_lookup", "status": tc.status, "category": tc.category, "category_status": tc.state}
				encoded, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				addLog(t, dir, string(encoded)+"\n")
				var out bytes.Buffer
				if _, err := followPlain(dir, &out); err != nil {
					t.Fatal(err)
				}
				want := prefix + tc.suffix
				if out.String() != want+"\n" {
					t.Errorf("follow: %q, want %q", out.String(), want)
				}
				var live Live
				events, _, err := (&follower{dir: dir}).poll(&live)
				if err != nil {
					t.Fatal(err)
				}
				if len(live.Recent) != 1 || live.Recent[0].Text != want {
					t.Errorf("recent: %v", live.Recent)
				}
				if len(events) != 1 || events[0].Status != tc.status || text(events[0].Category) != tc.category {
					t.Errorf("changed structured fields: %+v", events)
				}
				retained, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
				if err != nil || string(retained) != string(encoded)+"\n" {
					t.Fatal("changed retained event")
				}
			})
		}
	}
}

func TestEventNormalizationLeavesOtherTextAlone(t *testing.T) {
	for _, tc := range []struct{ kind, text string }{
		{"session_end", "hack inspector hack-online_lookup ended after 0:00:01; searched online_lookup"},
		{"warning", "hack inspector hack-online_lookup ended after 0:00:01: attempt unknown; category online_lookup unknown"},
		{"session_end", "custom explanation: attempt unknown; category online_lookup unknown"},
		{"session_end", "nudi: 09:00:01 custom explanation: attempt unknown; category online_lookup unknown"},
	} {
		raw, err := json.Marshal(map[string]any{"v": 1, "kind": tc.kind, "text": tc.text})
		if err != nil {
			t.Fatal(err)
		}
		e, err := parseEvent(raw)
		if err != nil || e.Text != tc.text {
			t.Fatalf("%+v %v", e, err)
		}
	}
}

// Analyses overlap, so a phase's end takes only its own sessions and attempts off the tiles.
func TestAPhaseEndKeepsTheOtherAnalysesAgents(t *testing.T) {
	log := ev("00:00", "phase_start", `, "phase": "hack", "slots": 2`) +
		ev("00:00", "phase_start", `, "phase": "simulation"`) +
		ev("00:00", "phase_start", `, "phase": "attack"`) +
		ev("00:01", "attempt_start", `, "episode": "0000-attacker", "candidate": null, "level": "none", "number": 1`) +
		ev("00:01", "session_start", `, "inspector": "hack", "session": "hack-broad"`) +
		ev("01:00", "phase_end", `, "phase": "simulation", "status": "complete", "elapsed": 60`) +
		ev("01:00", "phase_start", `, "phase": "grader"`) +
		ev("01:01", "session_start", `, "inspector": "grader", "session": "grader-broad"`) +
		ev("02:00", "phase_end", `, "phase": "hack", "status": "complete", "elapsed": 120`)
	var l Live
	running := func() string {
		var names []string
		for _, a := range l.Agents {
			names = append(names, a.Who+" "+a.Name)
		}
		return strings.Join(names, ", ")
	}
	for _, e := range readAll(t, log) {
		l.apply(e)
	}
	if got := running(); got != "attacker 0000-attacker, grader grader-broad" {
		t.Fatalf("after the hack inspector: %s", got)
	}
	for _, e := range readAll(t, ev("03:00", "phase_end", `, "phase": "grader", "status": "complete", "elapsed": 119`)) {
		l.apply(e)
	}
	if got := running(); got != "attacker 0000-attacker" {
		t.Fatalf("after the grader inspector: %s", got)
	}
	for _, e := range readAll(t, ev("04:00", "phase_end", `, "phase": "attack", "status": "complete", "elapsed": 240, "attempts": 1`)) {
		l.apply(e)
	}
	if got := running(); got != "" {
		t.Fatalf("after the attack: %s", got)
	}
}

// While the run goes, nudi rewrites report.json after each confirmation with status running; only the final one ends
// the follow, and after run_end a report still running is no final report.
func TestFollowKeepsFollowingARunningReport(t *testing.T) {
	body, err := os.ReadFile("testdata/clean/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	raw["status"] = "running"
	running, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := writeReport(t, string(running))
	addLog(t, dir, ev("00:00", "run_start", `, "pid": `+strconv.Itoa(os.Getpid())))
	f, l := &follower{dir: dir}, &Live{Dir: dir}
	if _, r, err := f.poll(l); r != nil || err != nil {
		t.Fatalf("a running report ended the follow: %v %v", r, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, r, err := f.poll(l); r == nil || err != nil || r.Status == "running" {
		t.Fatalf("the final report did not end the follow: %v %v", r, err)
	}

	dir = writeReport(t, string(running))
	addLog(t, dir, ev("00:00", "run_start", `, "pid": `+strconv.Itoa(os.Getpid()))+ev("00:01", "run_end", `, "status": "stopped", "report": "report.json"`))
	_, r, err := (&follower{dir: dir}).poll(&Live{Dir: dir})
	if r != nil || err == nil || !strings.Contains(err.Error(), "written while it ran; nudi report") {
		t.Fatalf("after run_end: %v %v", r, err)
	}
}
