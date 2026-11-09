package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// eventsVersion is the format version of events.jsonl this viewer reads.
const eventsVersion = 1

// Event holds the fields of one events.jsonl line that the live screen reads. docs/viewer.md lists them.
type Event struct {
	Time             string   `json:"time"`
	Kind             string   `json:"kind"`
	Text             string   `json:"text"`
	KnownCost        *float64 `json:"known_cost"`
	UnknownCostCalls int      `json:"unknown_cost_calls"`
	CancelledCalls   int      `json:"cancelled_calls"`

	Backend            string   `json:"backend"`
	SpendingCap        *float64 `json:"spending_cap"`
	Concurrency        *int     `json:"concurrency"`
	ConcurrencySetting *int     `json:"concurrency_setting"`

	Phase     string     `json:"phase"`
	Status    string     `json:"status"`
	Inspector string     `json:"inspector"` // grader, hack or attack
	Session   string     `json:"session"`
	Category  *string    `json:"category"`
	Episode   *string    `json:"episode"`
	Outcome   string     `json:"outcome"`
	ID        string     `json:"id"`
	Index     *int       `json:"index"`
	Candidate *string    `json:"candidate"`
	Level     string     `json:"level"`
	Number    int        `json:"number"`
	Rewards   []*float64 `json:"rewards"`
	Minutes   *float64   `json:"minutes"`
	Report    *string    `json:"report"`
	Elapsed   *float64   `json:"elapsed"`

	Slots    *int     `json:"slots"`    // the shared pool of the hacks, in the hack phase_start
	Analyses []string `json:"analyses"` // the phases a run_start selected
	Pid      int      `json:"pid"`      // nudi's process, in run_start
	Host     string   `json:"host"`     // the host nudi runs on, in run_start; older logs have none
	Problem  string   `json:"problem"`  // P1, G1 or A1: what a judged, reproduced, attempt or attack inspector event is about
	Finding  string   `json:"finding"`  // the probe, finding or attempt the judge judged
	New      bool     `json:"new"`      // the judge found no known problem it is the same as
	Cause    string   `json:"cause"`
	Result   string   `json:"result"`   // evidenced; older logs also have not_reproduced
	Replayed bool     `json:"replayed"` // a judged or reproduced event a rerun repeats from the earlier run
}

// at is when nudi wrote the event, or the zero time when the event has no readable time.
func (e Event) at() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, e.Time)
	return t
}

func text(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// follower reads RUN/events.jsonl as nudi appends to it, never through a link that leads out of RUN.
type follower struct {
	dir   string
	read  int64     // bytes of whole lines read so far
	line  int       // lines read so far
	begun time.Time // when the follow began
}

// next returns the events nudi appended since the last call. A last line without its newline waits for
// the next call, since nudi may still be writing it. No log yet means the run has not started. A line it
// cannot read ends the follow, with the events before it.
func (f *follower) next() ([]Event, error) {
	root, err := os.OpenRoot(f.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open("events.jsonl")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Seek(f.read, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var out []Event
	for {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return out, nil
		}
		f.read += int64(i + 1)
		f.line++
		e, err := parseEvent(b[:i])
		if err != nil {
			return out, fmt.Errorf("%s line %d%w", clean(filepath.Join(f.dir, "events.jsonl")), f.line, err)
		}
		out = append(out, e)
		b = b[i+1:]
	}
}

// legacySessionEnd matches the text after nudi's clock time and, in a batch, the environment's name, which stay.
var legacySessionEnd = regexp.MustCompile(`^((?:nudi: \d\d:\d\d:\d\d (?:[^:]+: )?)?(?:hack|grader|attack) inspector \S+ ended after [^;]+): attempt (\w+)(?:; category (\S+) (?:evidenced_issue|no_evidenced_issue|unknown|restricted|pending))?$`)

// parseEvent reads one line, after dropping the characters a terminal would obey or reorder from every
// string in it, map keys included. A line of another format version is refused, since its fields may mean other things.
func parseEvent(line []byte) (Event, error) {
	var raw any
	if err := json.Unmarshal(line, &raw); err != nil {
		return Event{}, fmt.Errorf(": %w", err)
	}
	m, ok := clean(raw).(map[string]any)
	if !ok {
		return Event{}, errors.New(" is not a JSON object")
	}
	if m["v"] != float64(eventsVersion) {
		v, _ := json.Marshal(m["v"])
		return Event{}, fmt.Errorf(" has format version %s; this viewer reads version %d", v, eventsVersion)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return Event{}, fmt.Errorf(": %w", err)
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		return Event{}, fmt.Errorf(": %w", err)
	}
	// Normalize only nudi's generated legacy session summary, before either display reads it.
	if e.Kind == "session_end" {
		if match := legacySessionEnd.FindStringSubmatch(e.Text); match != nil {
			e.Text = match[1]
			if !slices.Contains([]string{"evidenced_issue", "no_evidenced_issue", "unknown"}, match[2]) {
				e.Text += ": attempt " + match[2]
			}
			if match[3] != "" {
				e.Text += "; searched " + match[3]
			}
		}
	}
	return e, nil
}

// Live is what a run's events say so far. Python wrote every word and number in it; the live screen lays them out.
type Live struct {
	Dir                     string
	Start, Last, Limit, End *Event  // run_start, the latest event, time_limit and run_end
	Phases                  []Event // each phase's latest event: its phase_start while it runs, then its phase_end
	Agents                  []Agent // the sessions and Attacker attempts running now, in the order they started
	Tries                   []*Try  // every Attacker attempt so far
	Lanes                   []*Lane // the rows of the findings pipeline, in the order the judge named them
	ZeroJudged              *Event  // the latest judge call on the exploit of an Attacker with no extra information
	Slots                   *int
	Hacked                  []int // the problems of the hacks and how many an Attacker exploited, as the hack phase ended
	Warnings                int
	Recent                  []string // the last events, in nudi's words or the judge's result in the viewer's
}

// Lane is one row of the findings pipeline: a problem the judge named new, or a grader finding it found the
// same as a problem of the hacks, which the grader piece does not attack again.
type Lane struct {
	ID, Cause  string    // P1, G1 or A1; for a grader finding the same as a problem of the hacks, the finding's id
	Same       string    // that problem
	Judged     time.Time // when the judge named it new, so when its reproduction started
	Reproduced string    // the hack inspector's result, once it is settled
	Members    []string  // the findings the judge found the same as it, folded under it
	Alone      bool      // an Attacker with no extra information of this run exploited it, by its attempt_result
	Replayed   bool      // a rerun repeated it from the earlier run
}

// Agent is a running inspector session or Attacker attempt.
type Agent struct {
	Who     string // grader, hack or attack for an inspector session, attacker for an Attacker attempt
	Name    string // the session's name or the Attacker's episode
	Title   string // what the tile names: the problem and its level when the event has one, otherwise Name
	Episode string // the episode an attack inspector session reads
	Since   time.Time
	Last    string // the last event that names it, in words
}

// Try is one Attacker attempt: its start, its end once the episode returned, and its saved status once nudi settled it.
type Try struct {
	Start      Event
	Hacks      bool // it started while the hacks ran
	Returned   *Event
	Inspecting bool   // its attack inspector session runs
	Status     string // the attempt's status from attempt_result; a session's own status is not the attempt's
}

// recent is how many event lines the live screen shows.
const recent = 3

// apply adds one event, in the order nudi wrote them.
func (l *Live) apply(e Event) {
	l.Last = &e
	line := e.Text
	if e.Kind == "judged" && !e.Replayed { // a replayed one keeps nudi's words, which say it is from the earlier run
		line = judgedWords(e)
	}
	l.Recent = append(l.Recent, line)
	l.Recent = l.Recent[max(0, len(l.Recent)-recent):]
	if e.Slots != nil && e.Kind == "phase_start" && e.Phase == "hack" {
		l.Slots = e.Slots
	}
	switch e.Kind {
	case "run_start":
		l.Start = &e
	case "phase_start":
		l.Phases = append(l.Phases, e)
	case "phase_end":
		for i := range l.Phases {
			if l.Phases[i].Phase == e.Phase {
				l.Phases[i] = e
			}
		}
		l.Agents = nil // an analysis ends after its sessions and attempts
		if e.Phase == "hack" {
			problems, exploited := l.hackCounts()
			l.Hacked = []int{problems, exploited}
		}
	case "session_start":
		a := Agent{Who: e.Inspector, Name: e.Session, Title: e.Session, Episode: text(e.Episode), Since: e.at(), Last: "started"}
		if t := l.try(text(e.Episode)); e.Inspector == "attack" && t != nil {
			t.Inspecting = true
			if e.Problem != "" {
				a.Title = e.Problem + " " + word(levelWords, t.Start.Level)
			}
		}
		l.Agents = append(l.Agents, a)
	case "session_end":
		// session_end names no episode, so an attack inspector's attempt is the one its session_start named.
		for _, a := range l.Agents {
			if t := l.try(a.Episode); t != nil && a.Who == "attack" && e.Inspector == "attack" && a.Name == e.Session {
				t.Inspecting = false
			}
		}
		l.stop(e.Inspector, e.Session)
	case "evidenced":
		// Only the attack inspector's evidenced events name what it reads, an Attacker episode.
		for i, a := range l.Agents {
			if e.Inspector == "attack" && a.Who == "attack" && a.Episode == text(e.Episode) {
				l.Agents[i].Last = "evidenced " + e.ID
			}
		}
	case "attempt_start":
		a := Agent{Who: "attacker", Name: text(e.Episode), Title: text(e.Episode), Since: e.at(), Last: tryName(e)}
		if e.Problem != "" {
			a.Title, a.Last = e.Problem+" "+word(levelWords, e.Level), fmt.Sprintf("%s, try %d", text(e.Episode), e.Number)
		}
		l.Agents = append(l.Agents, a)
		l.Tries = append(l.Tries, &Try{Start: e, Hacks: l.running("hack")})
	case "attempt_end":
		l.stop("attacker", text(e.Episode))
		if t := l.try(text(e.Episode)); t != nil {
			t.Returned = &e
		}
	case "attempt_result":
		t := l.try(text(e.Episode))
		if t == nil { // stopped before its episode started, as by the spending cap: the result is the whole attempt
			t = &Try{Start: e, Hacks: l.running("hack")}
			l.Tries = append(l.Tries, t)
		}
		t.Status = e.Status
		if t.Start.Problem == "" {
			t.Start.Problem = e.Problem // a no-extra-information attempt's problem is known once it is judged
		}
		if n := l.lane(e.Problem); n != nil && e.Level == "none" && e.Status == "evidenced_issue" {
			n.Alone = true
		}
	case "judged":
		if e.Inspector == "attack" && !e.Replayed {
			l.ZeroJudged = &e
		}
		switch n := l.lane(e.Problem); {
		case e.New:
			l.Lanes = append(l.Lanes, &Lane{ID: e.Problem, Cause: e.Cause, Judged: e.at(), Replayed: e.Replayed})
		case e.Inspector == "grader" && !strings.HasPrefix(e.Problem, "G"):
			l.Lanes = append(l.Lanes, &Lane{ID: e.Finding, Cause: e.Cause, Same: e.Problem})
		case n != nil:
			n.Members = append(n.Members, e.Finding)
		}
	case "reproduced":
		if n := l.lane(e.Problem); n != nil {
			n.Reproduced = e.Result
		}
	case "warning":
		l.Warnings++
	case "time_limit":
		l.Limit = &e
	case "run_end":
		l.End = &e
		l.Agents = nil
	}
}

// judgedWords say what the judge decided, with the problem's cause.
func judgedWords(e Event) string {
	if e.New {
		return fmt.Sprintf("judge: %s is new, %s (%s)", e.Finding, e.Problem, e.Cause)
	}
	return fmt.Sprintf("judge: %s is the same as %s (%s)", e.Finding, e.Problem, e.Cause)
}

// lane is the problem with id id, or nil.
func (l *Live) lane(id string) *Lane {
	for _, n := range l.Lanes {
		if n.ID == id && n.Same == "" {
			return n
		}
	}
	return nil
}

// stop removes the running agent who named name.
func (l *Live) stop(who, name string) {
	l.Agents = slices.DeleteFunc(l.Agents, func(a Agent) bool { return a.Who == who && a.Name == name })
}

// try is the Attacker attempt of episode, or nil, also for no episode.
func (l *Live) try(episode string) *Try {
	if episode == "" {
		return nil
	}
	for _, t := range l.Tries {
		if text(t.Start.Episode) == episode {
			return t
		}
	}
	return nil
}

// tryName is what an attempt tested and how, such as "hack-1 full instructions, try 2", or "no extra information, try 1".
func tryName(e Event) string {
	s := word(levelWords, e.Level) + fmt.Sprintf(", try %d", e.Number)
	if e.Candidate != nil {
		s = *e.Candidate + " " + s
	}
	return s
}
