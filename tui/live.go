package main

import (
	"cmp"
	"fmt"
	"image/color"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// The live screen of a run that is still going: the frame of the finished viewer over what the events say so far.

const tileW = 32 // width of one agent tile

// spin is the Dot spinner without its trailing space.
var spin = func() []string {
	var out []string
	for _, f := range spinner.Dot.Frames {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}()

// agentJobs name who runs a tile or wrote a log line: an inspector session by its inspector, or an Attacker attempt.
var agentJobs = map[string]string{"grader": "Grader Inspector", "hack": "Hack Inspector", "attack": "Attack Inspector", "attacker": "Attacker"}

var agentColors = map[string]color.Color{"grader": blue, "hack": violet, "attack": blue, "attacker": coral}

// phaseJobs say who works in each phase, in the order of phases.
var phaseJobs = []string{"Simulator", "Grader Inspector", "Hack Inspector", "Attackers + Attack Inspector"}

// shortLevels name a hint level as the Help panel does.
var shortLevels = map[string]string{"none": "no info", "minimal": "hint", "full": "full"}

// liveUI is what the viewer of a live run chose: the tab on view once a key chose it, the sections expanded, the
// panel on view, the scroll offset and the page of agent tiles.
type liveUI struct {
	screen  int
	chosen  bool
	open    map[string]bool // o related observations, l logs, f all findings
	overlay string          // ? or c
	offset  int
	agents  int
}

// press handles a key on the live screen.
func (m liveModel) press(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	u, k := &m.ui, msg.String()
	if u.open == nil {
		u.open = map[string]bool{}
	}
	switch {
	case key.Matches(msg, keys.quit):
		return m, tea.Quit
	case u.overlay != "":
		if k == u.overlay || k == "esc" {
			u.overlay = ""
		}
	case k == "tab" || k == "shift+tab":
		step := 1
		if k == "shift+tab" {
			step = results
		}
		u.screen, u.chosen, u.offset = (m.view()+step)%(results+1), true, 0
	case k == "left":
		u.agents = max(0, u.agents-1)
	case k == "right":
		fit := tilesPerRow(m.w)
		u.agents = min(u.agents+1, max(0, (len(m.l.Agents)-1)/fit))
	case k == "o" || k == "l" || k == "f":
		u.open[k] = !u.open[k]
	case k == "esc":
		u.open["f"] = false
	case k == "up" || k == "k":
		u.offset = max(0, u.offset-1)
	case k == "down" || k == "j":
		top, body := m.parts(time.Now())
		if room := m.room(top); room > 0 && u.offset+room < len(splitLines(body)) {
			u.offset++
		}
	case k == "?" || k == "c":
		u.overlay, u.offset = k, 0
	}
	return m, nil
}

// view is the tab on view: the one a key chose, or else the phase that started last.
func (m liveModel) view() int {
	if m.ui.chosen || len(m.l.Phases) == 0 {
		return m.ui.screen
	}
	last := m.l.Phases[len(m.l.Phases)-1].Phase
	return max(0, slices.IndexFunc(phases, func(p struct{ Name, Analysis string }) bool { return p.Analysis == last }))
}

// room is how many rows of the body fit under top, or 0 before the terminal reports its size.
func (m liveModel) room(top string) int {
	if m.h == 0 {
		return 0
	}
	return max(3, m.h-lipgloss.Height(top)-chrome)
}

// render is the whole live screen at time now: the frame, the body scrolled to the offset, then the key help.
func (m liveModel) render(now time.Time) string {
	top, body := m.parts(now)
	lines := splitLines(body)
	if room := m.room(top); room > 0 && len(lines) > room {
		off := min(m.ui.offset, len(lines)-room)
		lines = lines[off : off+room]
	}
	var help []string
	for _, k := range [][2]string{{"?", "Help"}, {"Tab", "next tab"}, {"Up/Down", "scroll"}, {"l", "logs"}, {"q", "Stop following"}} {
		help = append(help, bold(k[0])+" "+dim(k[1]))
	}
	// A narrow window drops keys from the middle; Help lists them all.
	for len(help) > 2 && width(strings.Join(help, "   ")) > m.w-2 {
		help = slices.Delete(help, len(help)-2, len(help)-1)
	}
	return top + "\n\n" + strings.Join(lines, "\n") + "\n\n " + strings.Join(help, "   ")
}

// parts are the header with the tab strip, and the body of the tab or panel on view.
func (m liveModel) parts(now time.Time) (top, body string) {
	l, w, sp := &m.l, m.w, spin[m.frame%len(spin)]
	r := l.report(now)
	if l.Start == nil {
		return cut(header(r, true, w), w), cut(" "+dim("Waiting for "+l.Dir+"/events.jsonl. nudi writes it when the run starts."), w)
	}
	top = cut(header(r, true, w)+"\n\n"+tabStrip(func(i int) (string, bool) { return l.stage(i, sp) }, m.view(), w), w)
	switch {
	case m.ui.overlay == "?":
		body = helpPanel(w, true)
	case m.ui.overlay == "c":
		body = costPanel(r, w)
	case m.ui.open["f"]:
		body = strings.Join(l.findings(now, sp, w, -1), "\n")
	case m.view() == results:
		body = l.resultsBody(r, now, sp, w)
	default:
		body = m.stageBody(now, sp, m.room(top))
	}
	return top, cut(body, w)
}

// report holds what the frame reads of a run that has no report yet.
func (l *Live) report(now time.Time) Report {
	r := Report{Dir: l.Dir}
	c := &r.Configuration
	c.TaskDir = l.Dir
	if l.Start == nil {
		return r
	}
	c.Backend, c.SpendingCap, c.KnownCost = l.Start.Backend, l.Start.SpendingCap, l.Last.KnownCost
	c.UnknownCostCalls, c.CancelledCalls = l.Last.UnknownCostCalls, l.Last.CancelledCalls
	if n := l.Start.Concurrency; n != nil {
		c.Capacity.Concurrency = *n
	}
	s := l.ran(now).Seconds()
	r.Elapsed = &s
	return r
}

// ran is how long the run has run, or ran until its end.
func (l *Live) ran(now time.Time) time.Duration {
	if l.End != nil {
		now = l.End.at()
	}
	return since(l.Start.at(), now)
}

// since is the time from t to now, never negative, since the clock of nudi's host can be set back.
func since(t, now time.Time) time.Duration { return max(0, now.Sub(t)).Truncate(time.Second) }

// running is a spinner in colour c with the time it has turned.
func running(c color.Color, sp string, d time.Duration) string {
	return fg(c, sp) + " " + elapsed(d.Seconds())
}

// stage is the mark of phase i on its tab: a spinner while it runs, waiting before it starts, then how it ended.
// The Attack tab also turns while Attackers work during Find Hacks. A phase the run left out is off.
func (l *Live) stage(i int, sp string) (string, bool) {
	name := phases[i].Analysis
	p := l.phase(name)
	attacking := slices.ContainsFunc(l.Agents, func(a Agent) bool { return a.Who == "attacker" || a.Who == "attack" })
	switch {
	case p == nil && len(l.Start.Analyses) > 0 && !slices.Contains(l.Start.Analyses, name):
		return "", true
	case p == nil && name == "attack" && attacking, p != nil && p.Kind == "phase_start":
		return fg(phaseColors[i], sp), false
	case p == nil && l.End != nil, p != nil && p.Status == "not run":
		return dim("-"), false
	case p == nil:
		return dim("waiting"), false
	case p.Status == "failed":
		return redStyle.Bold(true).Render("Error"), false
	case p.Status == "complete":
		return greenStyle.Render("✓"), false
	case p.Status == "partial": // the events do not say whether every attempt ran, so partial is never done
		return amber("partly"), false
	}
	return amber("stopped"), false
}

// phaseLine names phase i with its mark and time, then who works in it.
func (l *Live) phaseLine(i int, now time.Time, sp string) string {
	mark, off := l.stage(i, sp)
	name := lipgloss.NewStyle().Bold(true).Foreground(phaseColors[i]).Render(strings.ToUpper(phases[i].Name))
	if off {
		return " " + name + "  " + dim("Not part of this run")
	}
	t := ""
	if p := l.phase(phases[i].Analysis); p != nil && p.Kind == "phase_start" {
		t = " " + elapsed(since(p.at(), now).Seconds())
	} else if p != nil && p.Elapsed != nil {
		t = " " + elapsed(*p.Elapsed)
	}
	return " " + name + " " + mark + t + "     " + dim(phaseJobs[i])
}

// stageBody is a phase tab: the phase, why it failed, the agents, the findings so far, the related observations,
// the Attacker with no information and the logs. When it does not fit in room rows, one row of agent tiles shows
// and the findings keep the rows left, at least two, or else a line that f opens.
func (m liveModel) stageBody(now time.Time, sp string, room int) string {
	l, w, i := &m.l, m.w, m.view()
	head := []string{l.phaseLine(i, now, sp)}
	if p := l.phase(phases[i].Analysis); p != nil && p.Error != "" {
		note := p.Error
		if l.End != nil {
			note += "\nThe run ended at " + elapsed(l.ran(now).Seconds()) + ". Its report keeps the results so far."
		}
		head = append(head, "", cols(w, " ", []int{7}, redStyle.Bold(true).Render("Error"), note))
	}
	if l.Limit != nil && l.Limit.Minutes != nil {
		head = append(head, "", cols(w, " ", []int{7}, amber("Limit"),
			"The run reached its time limit of "+strconv.FormatFloat(*l.Limit.Minutes, 'f', -1, 64)+" minutes. Its report keeps the results so far."))
	}
	head = append(head, "")
	rest := l.rest(now, sp, w, m.ui.open)
	join := func(agents, findings []string) string {
		return strings.Join(slices.Concat(head, agents, []string{""}, findings, rest), "\n")
	}
	agents := l.agentsBlock(now, sp, w, -1)
	findings := l.findings(now, sp, w, -1)
	if s := join(agents, findings); room == 0 || len(splitLines(s)) <= room {
		return s
	}
	agents = l.agentsBlock(now, sp, w, m.ui.agents)
	return join(agents, l.findings(now, sp, w, max(0, room-len(splitLines(strings.Join(head, "\n")))-len(agents)-1)))
}

// rest is what follows the findings on a phase tab: the related observations, the Attacker with no information
// and the logs.
func (l *Live) rest(now time.Time, sp string, w int, open map[string]bool) []string {
	p := &page{w: w, sel: -1, open: open}
	if rel := l.related(); len(rel) > 0 {
		p.add("")
		if p.toggle("o", "Related observations", fmt.Sprintf("(%d)", len(rel))) {
			widths := []int{20, 18, 14}
			p.add(cols(w, "   ", widths, dim("Reference"), dim("Found by"), dim("New finding?"), dim("Same as")))
			for _, r := range rel {
				p.add(cols(w, "   ", widths, r[0], r[1], under("New finding?", glyph("no")), r[2]))
			}
		}
	}
	if block := l.noInfo(now, sp, w); len(block) > 0 {
		p.add("")
		p.add(block...)
	}
	p.add("", spread(" "+bold("LOGS"), bold("l")+" "+dim(map[bool]string{false: "expand", true: "collapse"}[open["l"]]), w))
	logs := l.Recent
	if !open["l"] {
		logs = logs[max(0, len(logs)-4):]
	}
	for _, e := range logs {
		p.add(l.logRow(e, w))
	}
	return p.lines
}

// tilesPerRow is how many agent tiles fit side by side in w columns.
func tilesPerRow(w int) int { return max(1, (w-1)/(tileW+1)) }

// agentsBlock is one tile per running session and Attacker attempt, in rows as wide as the screen; with a page from
// 0, only that page's row, with the range it shows.
func (l *Live) agentsBlock(now time.Time, sp string, w, page int) []string {
	n, fit := len(l.Agents), tilesPerRow(w)
	if n == 0 {
		return []string{heading("AGENTS", "none running")}
	}
	title, shown := heading("AGENTS", fmt.Sprintf("%d running", n)), l.Agents
	if page >= 0 && n > fit {
		a := min(page, (n-1)/fit) * fit
		b := min(n, a+fit)
		shown = l.Agents[a:b]
		which := fmt.Sprintf("Agents %d-%d of %d", a+1, b, n)
		if a+1 == b {
			which = fmt.Sprintf("Agent %d of %d", b, n)
		}
		title = spread(title, dim(which)+"  "+bold("←/→")+" "+dim("more"), w)
	}
	out := []string{title}
	for i := 0; i < len(shown); i += fit {
		var tiles [][]string
		for _, a := range shown[i:min(i+fit, len(shown))] {
			tiles = append(tiles, l.tile(a, now, sp))
		}
		for row := range tiles[0] {
			line := ""
			for _, t := range tiles {
				line += " " + t[row]
			}
			out = append(out, line)
		}
	}
	return out
}

// tile is one agent: who it is and how long it has run in the top edge, then what it works on.
func (l *Live) tile(a Agent, now time.Time, sp string) []string {
	c, ok := agentColors[a.Who]
	if !ok {
		c = grey
	}
	job, t, inner := word(agentJobs, a.Who), running(c, sp, since(a.Since, now)), tileW-4
	out := []string{dim("╭─ ") + bold(job) + " " + dim(strings.Repeat("─", max(1, tileW-8-width(job)-width(t)))) + " " + t + dim(" ─╮")}
	body := append(l.target(a), "", "", "")
	for _, s := range body[:3] {
		out = append(out, dim("│")+" "+pad(truncate(s, inner), inner)+" "+dim("│"))
	}
	return append(out, dim("╰"+strings.Repeat("─", tileW-2)+"╯"))
}

// target is what an agent works on, in words. An Attacker attempt from a log without problems names only its help.
func (l *Live) target(a Agent) []string {
	switch a.Who {
	case "hack":
		if a.Category == "" {
			return []string{"General search", "All categories"}
		}
		return []string{"Focused search", word(checkNames, a.Category)}
	case "grader":
		if a.Episode == "" {
			return []string{"General review", "All simulated episodes"}
		}
		return []string{"Episode review", a.Episode}
	case "attacker":
		if t := l.try(a.Name); t != nil && t.Start.Level == "none" {
			return []string{"No information", "Looking for any hack", fmt.Sprintf("Try %d", t.Start.Number)}
		} else if t != nil {
			return append(l.cause(t.Start.Problem, 2), capital(word(levelWords, t.Start.Level))+fmt.Sprintf(", try %d", t.Start.Number))
		}
	case "attack":
		if t := l.try(a.Episode); t != nil {
			return append([]string{fmt.Sprintf("Checks try %d, %s", t.Start.Number, word(shortLevels, t.Start.Level))}, l.cause(t.Start.Problem, 2)...)
		}
	}
	return nil
}

// cause is the cause of problem id in at most n lines of a tile, or nothing for an unknown problem.
func (l *Live) cause(id string, n int) []string {
	lane := l.lane(id)
	if lane == nil {
		return nil
	}
	lines := breakLines(capital(lane.Cause), tileW-4)
	if len(lines) > n {
		lines = append(lines[:n-1], truncate(strings.Join(lines[n-1:], " "), tileW-4))
	}
	return lines
}

// problemLanes are the problems the inspectors found, the hacks' first, then the grader's, then those an Attacker
// found while aimed at another problem or in the earlier run of a rerun, whose help the events do not give. The
// no-information block holds the problems of this run's Attackers given no information.
func (l *Live) problemLanes() []*Lane {
	var out []*Lane
	for _, prefix := range []string{"P", "G", "A"} {
		for _, n := range l.Lanes {
			if t := l.try(n.From); n.Same == "" && strings.HasPrefix(n.ID, prefix) && (prefix != "A" || t == nil || t.Start.Level != "none") {
				out = append(out, n)
			}
		}
	}
	return out
}

// findings is the FINDINGS SO FAR section: one row per problem in problemLanes, with whether the novelty_judge
// named it new, the inspector reproduced it and an Attacker demonstrated it with full instructions and with a hint.
// With room from 0 it keeps to that many rows: the rows that fit, at least two, then how many more; else one line.
func (l *Live) findings(now time.Time, sp string, w, room int) []string {
	lanes := l.problemLanes()
	title := titled("FINDINGS SO FAR", len(lanes))
	if len(lanes) == 0 {
		none := "None yet."
		if slices.ContainsFunc(l.Phases, func(p Event) bool { return p.Error != "" }) {
			none = "None before the error."
		}
		return []string{title, " " + dim(none)}
	}
	fw := min(46, w-42)
	widths := []int{fw, 7, 12, 14}
	out := []string{title, cols(w, " ", widths, dim("Finding"), dim("New?"), dim("Inspector?"), dim("Full instr.?"), dim("Hint?"))}
	var rows [][]string
	for _, n := range lanes {
		rows = append(rows, splitLines(cols(w, " ", widths, capital(n.Cause), under("New?", "✓"), under("Inspector?", l.inspected(n, now, sp)),
			under("Full instr.?", l.mark(n, "full", now, sp)), under("Hint?", l.mark(n, "minimal", now, sp)))))
	}
	if all := slices.Concat(rows...); room < 0 || len(out)+len(all) <= room {
		return append(out, all...)
	}
	k, used := 0, len(out)+1
	for k < len(rows) && used+len(rows[k]) <= room {
		used += len(rows[k])
		k++
	}
	open := bold("f") + " " + dim("open")
	if k < 2 {
		return []string{title + "   " + open}
	}
	return append(append(out, slices.Concat(rows[:k]...)...), " "+dim(fmt.Sprintf("+%d more ↓", len(rows)-k))+"   "+open)
}

// mark is whether an Attacker told as much as level demonstrated problem n: its latest try aimed at n, or for an
// Attacker's problem the try that found it.
func (l *Live) mark(n *Lane, level string, now time.Time, sp string) string {
	if t := l.try(n.From); strings.HasPrefix(n.ID, "A") && t != nil && t.Start.Level == level {
		return glyph("yes")
	}
	return tryMark(l.latest(n.ID, level), now, sp)
}

// inspected says whether the inspector reproduced problem n: a grader finding is its own reproduction, an Attacker's
// problem has no inspector, and a problem a rerun repeats from the earlier run does not turn.
func (l *Live) inspected(n *Lane, now time.Time, sp string) string {
	switch {
	case strings.HasPrefix(n.ID, "A"):
		return glyph("")
	case strings.HasPrefix(n.ID, "G"), n.Reproduced == "evidenced":
		return glyph("yes")
	case n.Reproduced == "not_reproduced":
		return glyph("no")
	case n.Reproduced != "":
		return glyph("?")
	case n.Replayed:
		return glyph("")
	}
	return running(violet, sp, since(n.Judged, now))
}

// tryMark is whether attempt t demonstrated its problem: turning until nudi settles it, blue while its Attack
// Inspector runs, then yes, no, unresolved, or not tested for an attempt that failed or did not start.
func tryMark(t *Try, now time.Time, sp string) string {
	switch {
	case t == nil:
		return glyph("")
	case t.Status == "" && t.Inspecting:
		return running(blue, sp, since(t.Start.at(), now))
	case t.Status == "":
		return running(coral, sp, since(t.Start.at(), now))
	}
	return glyph(answer(t))
}

// answer is a settled attempt's answer to whether it demonstrated its problem, as glyph takes it.
func answer(t *Try) string {
	res, known := lookup(attemptResults, t.Status)
	switch {
	case !known, res == Unsettled:
		return "?"
	case res == Evidenced:
		return "yes"
	case res == NoIssue, res == Elsewhere:
		return "no"
	}
	return ""
}

// related are the findings the novelty_judge found the same as a problem: each with who found it and that
// problem's cause.
func (l *Live) related() [][3]string {
	var out [][3]string
	for _, n := range l.Lanes {
		if n.Same != "" {
			cause := n.Cause
			if p := l.lane(n.Same); p != nil {
				cause = p.Cause
			}
			out = append(out, [3]string{n.ID, foundBy(n.ID), capital(cause)})
		}
		for _, id := range n.Members {
			out = append(out, [3]string{id, foundBy(id), capital(n.Cause)})
		}
	}
	return out
}

// foundBy names who found a finding from its id: an Attacker's episode, a grader finding, or else the Hack Inspector's.
func foundBy(id string) string {
	switch {
	case strings.HasSuffix(id, "-attacker"):
		return "Attacker"
	case strings.HasPrefix(id, "grader"):
		return "Grader Inspector"
	}
	return "Hack Inspector"
}

// noInfo is the block of the Attackers given no information: each try, whether it demonstrated a hack, and whether
// the novelty_judge named it a new problem.
func (l *Live) noInfo(now time.Time, sp string, w int) []string {
	widths := []int{6, 14, 20, 14}
	var rows []string
	for _, t := range l.Tries {
		if t.Start.Level != "none" {
			continue
		}
		status, shown, isNew, cause := "", "", "", ""
		if t.Status == "" {
			c := coral
			if t.Inspecting {
				c = blue
			}
			status = running(c, sp, since(t.Start.at(), now))
		} else {
			res, _ := lookup(attemptResults, t.Status)
			status, shown = resultWords[res], under("Hack demonstrated?", glyph(answer(t)))
			if res == NotTested && t.Start.Kind == "attempt_start" {
				status = stoppedWords(t.Status)
			}
		}
		if p := t.Start.Problem; p != "" {
			n := l.lane(p)
			isNew = under("New finding?", map[bool]string{true: "✓", false: glyph("no")}[n != nil && n.From == text(t.Start.Episode)])
			if n != nil {
				cause = capital(n.Cause)
			}
		}
		rows = append(rows, cols(w, "   ", widths, strconv.Itoa(t.Start.Number), status, shown, isNew, cause))
	}
	if len(rows) == 0 {
		return nil
	}
	return append([]string{" " + bold("CAN AN ATTACKER SUCCEED WITHOUT ANY INFORMATION?"),
		cols(w, "   ", widths, dim("Try"), dim("Status"), dim("Hack demonstrated?"), dim("New finding?"), dim("Problem"))}, rows...)
}

// logClock splits nudi's line into its clock time and its message.
var logClock = regexp.MustCompile(`^nudi: (\d\d:\d\d:\d\d) (.*)$`)

// logRow is one event as a log line: its time, who it is from, and what it did in the viewer's words, or nudi's
// words for an event whose fields say nothing more. A judgement a rerun repeats keeps nudi's words, which say it is
// from the earlier run.
func (l *Live) logRow(e Event, w int) string {
	at, text := "", e.Text
	if m := logClock.FindStringSubmatch(e.Text); m != nil {
		at, text = m[1], m[2]
	}
	job := "nudi"
	switch {
	case e.Kind == "judged":
		job = "novelty_judge"
	case strings.HasPrefix(e.Kind, "attempt_"):
		job = "Attacker"
	case agentJobs[e.Inspector] != "":
		job = agentJobs[e.Inspector]
	}
	return cols(w, " ", []int{10, 18}, dim(at), job, cmp.Or(l.logWords(e), text))
}

// logWords say what event e did from its fields: what its job aimed at, with how much help, and how it ended; empty
// when the fields say nothing nudi's own words do not.
func (l *Live) logWords(e Event) string {
	took := ""
	if e.Elapsed != nil {
		took = " after " + elapsed(*e.Elapsed)
	}
	switch e.Kind {
	case "judged":
		if e.Replayed {
			return ""
		}
		if e.New {
			return "New finding: " + e.Cause
		}
		return "Same as an earlier finding: " + e.Cause
	case "phase_start", "phase_end":
		i := slices.IndexFunc(phases, func(p struct{ Name, Analysis string }) bool { return p.Analysis == e.Phase })
		if i < 0 {
			return ""
		}
		if e.Kind == "phase_end" {
			return phases[i].Name + " ended" + took + ": " + cmp.Or(phaseEndWords[e.Status], strings.ReplaceAll(e.Status, "_", " "))
		}
		if e.Slots != nil {
			return fmt.Sprintf("%s started, %d agents at a time", phases[i].Name, *e.Slots)
		}
		return phases[i].Name + " started"
	case "session_start", "session_end":
		episode := text(e.Episode)
		if e.Kind == "session_end" && e.Inspector != "hack" { // session_end names no episode; its session_start does
			i := slices.IndexFunc(l.Recent, func(s Event) bool { return s.Kind == "session_start" && s.Session == e.Session })
			if i < 0 {
				return "" // its start has left the log, so nudi's words say what it worked on
			}
			episode = text(l.Recent[i].Episode)
		}
		aim := l.aim(e.Inspector, text(e.Category), episode)
		if aim == "" {
			return ""
		}
		if e.Kind == "session_start" {
			return "Started: " + aim
		}
		end := e.Status
		if e.Result != "" && slices.Contains([]string{"evidenced_issue", "no_evidenced_issue", "unknown"}, e.Status) {
			end = e.Result // the status says how the session ran; its result says what evidence it left
		}
		return "Ended" + took + ", " + cmp.Or(sessionWords[end], strings.ReplaceAll(end, "_", " ")) + ": " + aim
	case "reproduced":
		if n := l.lane(e.Problem); n != nil && e.Result == "evidenced" {
			return "Reproduced: " + n.Cause // the event records no scope, so no task copy or native episode
		} else if n != nil && e.Result == "not_reproduced" {
			return "Not reproduced: " + n.Cause
		}
	case "evidenced":
		kind := map[string]string{"HACK": "a hack", "FP": "incorrect work passed", "FN": "correct work rejected"}[kindTags[jobKeys[e.Inspector]+" "+e.Outcome]]
		if kind == "" {
			return ""
		}
		out := "Evidence confirmed: " + kind
		if c := text(e.Category); c != "" && c != e.Outcome {
			out += ", " + word(checkNames, c)
		}
		if t := l.try(text(e.Episode)); t != nil {
			out += fmt.Sprintf(", in try %d", t.Start.Number)
		}
		return out
	case "attempt_start", "attempt_end", "attempt_result":
		aim := l.tryAim(e)
		switch e.Kind {
		case "attempt_start":
			return "Started: " + aim
		case "attempt_end":
			var rewards []string
			for _, x := range e.Rewards {
				rewards = append(rewards, num(x))
			}
			return "Episode returned" + took + ", reward " + cmp.Or(strings.Join(rewards, ", "), "none") + ": " + aim
		}
		res, known := attemptResults[e.Status]
		if !known {
			return ""
		}
		if t := l.try(text(e.Episode)); res == NotTested && t != nil && t.Start.Kind == "attempt_start" {
			return stoppedWords(e.Status) + ": " + aim // its episode started
		}
		return capital(triedWords[res]) + ": " + aim
	case "withdrawn":
		if n := l.lane(e.Problem); n != nil {
			return "Not started, a later reading withdrew the finding: with " + word(levelWords, e.Level) + ", for " + n.Cause
		}
	case "revised":
		return "Read a check again: its earlier finding is withdrawn or corrected"
	}
	return ""
}

// jobKeys turn an event's inspector into the job keys of kindTags.
var jobKeys = map[string]string{"grader": "grader_inspector", "hack": "hack_inspector", "attack": "attack"}

// phaseEndWords say how a phase ended, by its phase_end status.
var phaseEndWords = map[string]string{"complete": "complete", "partial": "partly", "failed": "failed", "stopped": "stopped",
	"cancelled": "stopped", "time_limit": "stopped at the time limit", "spending_exhausted": "stopped at the spending cap"}

// sessionWords say how an inspector session ended, by its session_end status.
var sessionWords = map[string]string{"evidenced_issue": "evidence found", "no_evidenced_issue": "no evidence found", "complete": "complete",
	"unknown": "unresolved", "open": "unresolved", "duplicate_case": "the same case as an earlier one"}

// aim is what an inspector session works on, in words: its search, its review or the Attacker try it checks.
func (l *Live) aim(who, category, episode string) string {
	switch who {
	case "hack":
		if category == "" {
			return "general search of all categories"
		}
		return "focused search for " + word(checkNames, category)
	case "grader":
		if episode == "" {
			return "general review of all simulated episodes"
		}
		return "review of episode " + episode
	case "attack":
		if t := l.try(episode); t != nil {
			return "check of " + l.tryAim(t.Start)
		}
	}
	return ""
}

// tryAim names an Attacker attempt by its try and its help, and what it aims at: the problem's cause, or any hack
// for one given no information.
func (l *Live) tryAim(e Event) string {
	if t := l.try(text(e.Episode)); t != nil {
		e.Level, e.Number, e.Problem = t.Start.Level, t.Start.Number, cmp.Or(t.Start.Problem, e.Problem)
	}
	out := fmt.Sprintf("try %d with %s", e.Number, word(levelWords, e.Level))
	if e.Level == "none" {
		return out + ", for any hack"
	}
	if n := l.lane(e.Problem); n != nil {
		return out + ", for " + n.Cause
	}
	return out
}

// resultsBody is the Results tab while the run goes on: the findings so far, the Attacker with no information and
// the cost.
func (l *Live) resultsBody(r Report, now time.Time, sp string, w int) string {
	n := 0
	for _, lane := range l.Lanes {
		n += boolInt(lane.Same == "")
	}
	out := []string{
		spread(" "+bold("Run not finished")+"  "+dim("running for "+elapsed(l.ran(now).Seconds())), dim(fmt.Sprintf("%d problem%s so far", n, plural(n))), w),
		" " + dim("Findings so far. The result is final when the run ends."), "",
	}
	out = append(out, l.findings(now, sp, w, -1)...)
	if block := l.noInfo(now, sp, w); len(block) > 0 {
		out = append(append(out, ""), block...)
	}
	out = append(append(out, "", heading("COST", "")), costRows(r, w, false)...)
	return strings.Join(out, "\n")
}

// phase is the latest event of phase name, or nil before it started.
func (l *Live) phase(name string) *Event {
	for i := range l.Phases {
		if l.Phases[i].Phase == name {
			return &l.Phases[i]
		}
	}
	return nil
}

func (l *Live) running(name string) bool {
	p := l.phase(name)
	return p != nil && p.Kind == "phase_start"
}

// hackCounts are the problems so far, the P and A rows, and how many of them an Attacker exploited at any level.
func (l *Live) hackCounts() (problems, exploited int) {
	for _, n := range l.Lanes {
		if n.Same != "" || !strings.HasPrefix(n.ID, "P") && !strings.HasPrefix(n.ID, "A") {
			continue
		}
		problems++
		if n.Alone || slices.ContainsFunc(l.Tries, func(t *Try) bool { return t.Start.Problem == n.ID && t.result() == Evidenced }) {
			exploited++
		}
	}
	return problems, exploited
}

func sum(xs []int) int {
	n := 0
	for _, x := range xs {
		n += x
	}
	return n
}

// latest is the latest Attacker attempt on problem id at level, or nil.
func (l *Live) latest(id, level string) *Try {
	var out *Try
	for _, t := range l.Tries {
		if t.Start.Problem == id && t.Start.Level == level {
			out = t
		}
	}
	return out
}

// result is how nudi settled the attempt, NotTested until its attempt_result.
func (t *Try) result() Result {
	if t.Status == "" {
		return NotTested
	}
	res, _ := lookup(attemptResults, t.Status)
	return res
}
