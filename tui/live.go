package main

import (
	"fmt"
	"image/color"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/lipgloss/v2"
)

const tileW = 24 // width of one agent tile

// spin is the Dot spinner without its trailing space.
var spin = func() []string {
	var out []string
	for _, f := range spinner.Dot.Frames {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}()

// agentWords name who runs a tile: an inspector session by its inspector, or an Attacker attempt.
var agentWords = map[string]string{"grader": "grader inspector", "hack": "hack inspector", "attack": "attack inspector", "attacker": "Attacker"}

var agentColors = map[string]color.Color{"grader": blue, "hack": violet, "attack": blue, "attacker": coral}

// renderLive draws the live screen at time now: the header, the two pieces, the running agents, the findings
// pipeline, then the latest event lines. frame turns the spinners.
func renderLive(l *Live, now time.Time, w, frame int) string {
	sp := spin[frame%len(spin)]
	top := liveHeader(l, now, w)
	if l.Start == nil {
		return cut(top+"\n\n "+dim("waiting for "+l.Dir+"/events.jsonl; nudi writes it once the run starts"), w)
	}
	out := []string{top, dim(" " + liveNotes(l)), "", liveStepper(l, now, sp), "", agentsPanel(l, now, w, sp)}
	if table := findingsPanel(l, now, w, sp); table != "" {
		out = append(out, "", table)
	}
	out = append(out, "")
	for _, t := range l.Recent {
		out = append(out, " "+dim(t))
	}
	return cut(strings.Join(out, "\n"), w)
}

// since is the time from t to now, never negative, since the clock of nudi's host can be set back.
func since(t, now time.Time) time.Duration { return max(0, now.Sub(t)).Truncate(time.Second) }

// clock prints a duration as Python prints one, H:MM:SS.
func clock(d time.Duration) string {
	s := int(d / time.Second)
	return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
}

func minutes(d time.Duration) string {
	s := int(d / time.Second)
	return fmt.Sprintf("%dm %02ds", s/60, s%60)
}

// liveHeader names the run folder, then the run's elapsed time, its known cost against the spending cap and the backend.
func liveHeader(l *Live, now time.Time, w int) string {
	left := " " + logo + "  " + bold(l.Dir)
	if l.Start == nil {
		return left
	}
	right := dim("⏱ ") + bold(clock(since(l.Start.at(), now))) + "   "
	if c := l.Last.KnownCost; c == nil {
		right += dim("cost unavailable")
	} else {
		right += fmt.Sprintf("$%.2f", *c)
		if limit := l.Start.SpendingCap; limit != nil && *limit > 0 {
			right += " " + bar(white, 12, *c / *limit) + dim(" $"+strconv.FormatFloat(*limit, 'f', -1, 64))
		}
	}
	right += "   " + dim(l.Start.Backend)
	return left + strings.Repeat(" ", max(2, w-width(left)-width(right)-1)) + right
}

// liveNotes are the run's concurrency, the calls without a known cost, the time limit once reached, and the warnings.
func liveNotes(l *Live) string {
	var parts []string
	if c, of := l.Start.Concurrency, l.Start.ConcurrencySetting; c != nil && of != nil {
		parts = append(parts, fmt.Sprintf("concurrency %d of %d", *c, *of))
	}
	if n := l.Last.UnknownCostCalls; n > 0 {
		parts = append(parts, fmt.Sprintf("%d call%s without a price", n, plural(n)))
	}
	if n := l.Last.CancelledCalls; n > 0 {
		parts = append(parts, fmt.Sprintf("%d call%s cancelled in flight", n, plural(n)))
	}
	if l.Limit != nil && l.Limit.Minutes != nil {
		parts = append(parts, "time limit of "+strconv.FormatFloat(*l.Limit.Minutes, 'f', -1, 64)+" minutes reached")
	}
	if l.Warnings > 0 {
		parts = append(parts, fmt.Sprintf("%d warning%s", l.Warnings, plural(l.Warnings)))
	}
	return strings.Join(parts, " · ")
}

// liveStepper shows the run's two pieces: HACKS, the hack phase, and GRADER, the simulation, grader and attack phases
// as three steps lit one by one. A piece shows once one of its phases started, or pending from the start when run_start
// selected it: the hacks with the hack phase, the grader with the simulation or the grader phase. A piece turns while a
// phase of it runs, then is marked complete or with its status; the finished hacks count their problems and how many an
// Attacker exploited.
func liveStepper(l *Live, now time.Time, sp string) string {
	var heads, notes []string
	hacks, grader := l.piece("HACKS", violet, []string{"hack"}, now, sp), l.piece("GRADER", blue, graderSteps, now, sp)
	if hacks == "" && l.selected("hack") {
		hacks = dim("HACKS ○")
	}
	if grader == "" && l.selected("simulation", "grader") {
		grader = dim("GRADER ○")
	}
	if hacks != "" {
		if l.Hacked != nil {
			hacks += fmt.Sprintf("  %d problem%s, %d exploited", l.Hacked[0], plural(l.Hacked[0]), l.Hacked[1])
		}
		heads, notes = append(heads, hacks), append(notes, dim("hack inspector + Attackers"))
	}
	if grader != "" {
		var steps []string
		for i, name := range graderSteps {
			switch p := l.phase(name); {
			case p == nil:
				steps = append(steps, dim(stepWords[i]))
			case p.Kind == "phase_start":
				steps = append(steps, lipgloss.NewStyle().Bold(true).Foreground(stepColors[i]).Render(stepWords[i]))
			case p.Status == "complete":
				steps = append(steps, greenStyle.Render(stepWords[i]))
			default:
				steps = append(steps, yellowStyle.Render(stepWords[i]))
			}
		}
		heads, notes = append(heads, grader), append(notes, strings.Join(steps, dim(" · ")))
	}
	if len(heads) < 2 {
		return " " + strings.Join(heads, "") + "\n " + strings.Join(notes, "")
	}
	room := max(pieceW, width(heads[0])+3, width(notes[0])+3)
	return " " + pad(heads[0], room) + heads[1] + "\n " + pad(notes[0], room) + notes[1]
}

// pieceW is where the grader piece starts on the stepper.
const pieceW = 41

var (
	graderSteps = []string{"simulation", "grader", "attack"}
	stepWords   = []string{"Simulate", "Inspect", "Attack"}
	stepColors  = []color.Color{teal, blue, coral}
)

// piece is one piece's name and mark with its time so far: the time of its finished phases and that of its running
// one, left out when a phase_end lacks its elapsed. It is empty before any of its phases started.
func (l *Live) piece(name string, c color.Color, names []string, now time.Time, sp string) string {
	started, running, timed, status := false, false, true, "complete"
	var took time.Duration
	for _, p := range l.Phases {
		if !slices.Contains(names, p.Phase) {
			continue
		}
		started = true
		switch {
		case p.Kind == "phase_start":
			running = true
			took += since(p.at(), now)
		case p.Elapsed != nil:
			took += time.Duration(*p.Elapsed) * time.Second
		default:
			timed = false
		}
		if p.Kind == "phase_end" && status == "complete" {
			status = p.Status
		}
	}
	s, t := int(took/time.Second), ""
	if timed {
		t = fmt.Sprintf(" %d:%02d", s/60, s%60)
	}
	switch {
	case !started:
		return ""
	case running:
		return lipgloss.NewStyle().Bold(true).Foreground(c).Render(name) + " " + fg(c, sp) + t
	case status == "complete":
		return bold(name) + " " + greenStyle.Render("✓") + t
	}
	return bold(name) + " " + yellowStyle.Render("▲") + t + " " + dim(word(statusWords, status))
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

// selected says whether run_start selected one of the phases names.
func (l *Live) selected(names ...string) bool {
	return l.Start != nil && slices.ContainsFunc(l.Start.Analyses, func(a string) bool { return slices.Contains(names, a) })
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

// agentsPanel draws one tile per running session and Attacker attempt, in rows as wide as the panel. While the hacks
// run, the heading counts them against the shared pool of slots.
func agentsPanel(l *Live, now time.Time, w int, sp string) string {
	note := fmt.Sprintf("%d running", len(l.Agents))
	switch {
	case l.Slots != nil && l.running("hack"):
		note = fmt.Sprintf("%d of %d slots", len(l.Agents), *l.Slots)
	case len(l.Agents) == 0:
		return heading("AGENTS", "none running")
	}
	fit := max(1, (w-1)/tileW)
	rows := []string{heading("AGENTS", note)}
	for i := 0; i < len(l.Agents); i += fit {
		tiles := []string{" "}
		for _, a := range l.Agents[i:min(i+fit, len(l.Agents))] {
			tiles = append(tiles, agentTile(a, now, sp))
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, tiles...))
	}
	return strings.Join(rows, "\n")
}

// agentTile names who runs and what, how long it has run, and the last event that names it.
func agentTile(a Agent, now time.Time, sp string) string {
	c, ok := agentColors[a.Who]
	if !ok {
		c = grey
	}
	inner := tileW - 4
	body := fg(c, sp) + " " + bold(truncate(word(agentWords, a.Who), inner-2)) + "\n" +
		truncate(a.Title, inner) + "\n" +
		minutes(since(a.Since, now)) + "\n" +
		dim(truncate(a.Last, inner))
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(grey).Padding(0, 1).Width(tileW).Render(body)
}

// The findings pipeline's columns after the label, with the width of each but the last.
var (
	pipeHeads  = []string{"judge", "reproduce", "full instructions", "only a hint"}
	pipeWidths = []int{12, 13, 19}
)

// pipeRow is one line of the findings pipeline: its label, its cells from the judge on, the last of which runs on
// to the end of the line, and the findings folded under it.
type pipeRow struct {
	label string
	cells []string
	fold  string
}

// findingsPanel lays out the problems as the judge names them, one row each moving left to right: the judge, the
// hack inspector's reproduction, then the Attacker with full instructions and with only a hint. A no extra information row comes first,
// as its attempts have no finding; the findings the judge found the same as a problem fold under it. A grader
// finding the same as a problem of the hacks has its own row, since the grader piece does not attack it again.
// Under 100 columns the judge column goes.
func findingsPanel(l *Live, now time.Time, w int, sp string) string {
	rows := l.pipeRows(now, sp)
	if len(rows) == 0 {
		return ""
	}
	widths := pipeWidths
	if w < wideAt {
		widths = widths[1:]
	}
	labelW := min(34, max(8, w-14-sum(widths)))
	line := func(label string, cells []string) string {
		if w < wideAt && len(cells) > 1 {
			cells = cells[1:]
		}
		s := " " + pad(label, labelW)
		for i, c := range cells {
			if i < len(cells)-1 {
				c = pad(c, widths[i])
			}
			s += c
		}
		return s
	}
	var head []string
	for _, h := range pipeHeads {
		head = append(head, dim(h))
	}
	out := []string{line(bold("FINDINGS"), head)}
	for _, r := range rows {
		out = append(out, line(truncate(r.label, labelW-1), r.cells))
		if r.fold != "" {
			out = append(out, "    "+dim(r.fold))
		}
	}
	return strings.Join(out, "\n")
}

// pipeRows are the no extra information row, then the problems of the hacks, those found by an Attacker alone, and the grader's.
func (l *Live) pipeRows(now time.Time, sp string) []pipeRow {
	var rows []pipeRow
	var zero []string
	for _, t := range l.Tries {
		if t.Start.Level == "none" {
			zero = append(zero, fmt.Sprintf("try %d ", t.Start.Number)+tryCell(t, now, sp))
		}
	}
	if len(zero) > 0 {
		judge := dim("·")
		if e := l.ZeroJudged; e != nil && e.New {
			judge = "new " + e.Problem
		} else if e != nil {
			judge = "same as " + e.Problem
		}
		rows = append(rows, pipeRow{label: "no extra information", cells: []string{judge, dim("·"), strings.Join(zero, "   ")}})
	}
	lanes := slices.Clone(l.Lanes)
	rank := func(n *Lane) int {
		switch {
		case n.Same == "" && strings.HasPrefix(n.ID, "P"):
			return 0
		case n.Same == "" && strings.HasPrefix(n.ID, "A"):
			return 1
		}
		return 2
	}
	slices.SortStableFunc(lanes, func(a, b *Lane) int { return rank(a) - rank(b) })
	for _, n := range lanes {
		r := pipeRow{label: n.ID + " " + n.Cause}
		full, hint := l.latest(n.ID, "full"), l.latest(n.ID, "minimal")
		attack := []string{tryCell(full, now, sp), tryCell(hint, now, sp)}
		if hint == nil && full != nil && full.Status != "" && full.result() != Evidenced {
			attack[1] = dim("–") // only a hint follows only an exploit with full instructions
		}
		switch {
		case n.Same != "":
			same := "same as " + n.Same
			if slices.ContainsFunc(l.Tries, func(t *Try) bool { return t.Hacks && t.Start.Problem == n.Same }) {
				same += ", attacked in hacks"
			}
			r.cells = []string{dim(same)}
		case strings.HasPrefix(n.ID, "A") && n.Alone:
			r.cells = []string{"new", "✓ (Attacker)", dim("found with no extra information")}
		case strings.HasPrefix(n.ID, "A") && n.Replayed:
			r.cells = []string{"new", dim("kept from the earlier run")}
		case strings.HasPrefix(n.ID, "A"):
			r.cells = []string{"new", fg(violet, sp) + " " + mins(since(n.Judged, now))}
		case strings.HasPrefix(n.ID, "G"):
			r.cells = append([]string{"new", "✓ (grader)"}, attack...)
		case n.Reproduced == "":
			r.cells = append([]string{"new", fg(violet, sp) + " " + mins(since(n.Judged, now))}, attack...)
		case n.Reproduced == "not_reproduced":
			r.cells = []string{"new", dim(reproducedWords[n.Reproduced])}
		default:
			r.cells = append([]string{"new", word(reproducedWords, n.Reproduced)}, attack...)
		}
		if len(n.Members) > 0 {
			r.fold = "+ " + strings.Join(n.Members, ", ") + " same as " + n.ID
		}
		rows = append(rows, r)
	}
	return rows
}

func sum(xs []int) int {
	n := 0
	for _, x := range xs {
		n += x
	}
	return n
}

func mins(d time.Duration) string { return fmt.Sprintf("%dm", int(d/time.Minute)) }

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

// pipeWords name how an attack inspector session settled an attempt, in the pipeline's cells.
var pipeWords = map[Result]string{
	Evidenced: "✓ exploited",
	Elsewhere: "✓ another way",
	NoIssue:   "✗ not exploited",
	Failed:    "✗ error",
	Unsettled: "? result unclear",
	NotTested: "· not tested",
}

// tryCell is one attempt in the pipeline: waiting, turning with its minutes until nudi settles it, blue while its
// attack inspector runs, then its result. A status the viewer has no words for is shown as written.
func tryCell(t *Try, now time.Time, sp string) string {
	switch {
	case t == nil:
		return dim("·")
	case t.Status == "" && t.Inspecting:
		return fg(blue, sp) + " " + mins(since(t.Start.at(), now))
	case t.Status == "":
		return fg(coral, sp) + " " + mins(since(t.Start.at(), now))
	}
	res, known := lookup(attemptResults, t.Status)
	switch {
	case !known:
		return "? " + t.Status
	case res == Evidenced:
		return redStyle.Render(pipeWords[res])
	}
	return dim(pipeWords[res])
}
