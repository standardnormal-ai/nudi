package main

import (
	"fmt"
	"image/color"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

const (
	wideAt = 100 // columns from which FOUND sits beside the phase panel
	foundW = 44  // width of the FOUND column
	maxW   = 120 // widest the screens grow; a wider terminal leaves the rest empty
	chrome = 9   // rows around the scrolling body: blank lines, header, models, stepper and key help
)

type keyMap struct {
	prev, next, open, back, tab, quit key.Binding
	finding                           bool
}

func (k keyMap) ShortHelp() []key.Binding {
	if k.finding {
		return []key.Binding{k.prev, k.next, k.tab, k.back, k.quit}
	}
	return []key.Binding{k.prev, k.next, k.open, k.quit}
}

func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

var keys = keyMap{
	prev: key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←", "previous")),
	next: key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→", "next")),
	open: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "evidence")),
	back: key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("esc", "back")),
	tab:  key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "evidence or limitations")),
	quit: key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

// model is the viewer: the phases of one finished run, its card, and the evidence of each finding.
type model struct {
	r      Report
	found  []Finding
	intro  *intro
	phase  int // index into phases; the viewer opens on Finished
	n      int // the finding on screen, from 1; 0 shows the phases
	tab    int // 0 Evidence, 1 Limitations
	w, h   int // h is 0 until the terminal reports its size
	body   viewport.Model
	help   help.Model
	exited bool
}

type frameMsg struct{}

func newModel(r Report, n int, withIntro bool) model {
	m := model{r: r, found: r.findings(), phase: len(phases) - 1, n: n, w: 100, help: help.New(), body: viewport.New()}
	m.body.KeyMap.Left.SetEnabled(false)
	m.body.KeyMap.Right.SetEnabled(false)
	if withIntro {
		m.intro = newIntro()
	}
	return m.layout()
}

func (m model) Init() tea.Cmd {
	if m.intro == nil {
		return nil
	}
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second/introFPS, func(time.Time) tea.Msg { return frameMsg{} })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.exited {
		return m, nil
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = min(msg.Width, maxW), msg.Height
		m.help.SetWidth(m.w)
		if m.w < 32 || m.h < 10 {
			m.intro = nil
		}
	case frameMsg:
		if m.intro != nil && m.intro.step() {
			return m, tick()
		}
		m.intro = nil
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, keys.quit):
			m.exited = true
			m.intro = nil
			return m, tea.Quit
		case m.intro != nil:
			m.intro = nil
		case m.n > 0:
			switch {
			case key.Matches(msg, keys.prev):
				m.n = max(1, m.n-1)
			case key.Matches(msg, keys.next):
				m.n = min(len(m.found), m.n+1)
			case key.Matches(msg, keys.tab):
				m.tab = 1 - m.tab
			case key.Matches(msg, keys.back):
				m.n = 0
			default:
				var cmd tea.Cmd
				m.body, cmd = m.body.Update(msg)
				return m, cmd
			}
			m.body.GotoTop()
		default:
			switch {
			case key.Matches(msg, keys.prev):
				m.phase = max(0, m.phase-1)
			case key.Matches(msg, keys.next):
				m.phase = min(len(phases)-1, m.phase+1)
			case key.Matches(msg, keys.open) && len(m.found) > 0:
				_, m.n = m.r.topProblem(m.found)
				m.tab = 0
			default:
				var cmd tea.Cmd
				m.body, cmd = m.body.Update(msg)
				return m, cmd
			}
			m.body.GotoTop()
		}
	}
	return m.layout(), nil
}

// layout puts the current screen into the scrolling body, as tall as it needs and no taller than the window.
func (m model) layout() model {
	var s string
	if m.n > 0 {
		s = renderShow(m.r, m.found, m.n, m.tab, m.w)
	} else {
		s = renderPhase(m.r, m.found, m.phase, m.w)
	}
	m.body.SetWidth(m.w)
	m.body.SetContent(s)
	h := lipgloss.Height(s)
	if m.h > 0 {
		h = min(h, max(3, m.h-chrome))
	}
	m.body.SetHeight(h)
	return m
}

// View draws inline, under the command line, cut to the window's height so that no row is left
// behind on a redraw. The intro takes the screen's rows first. Once the viewer quits, main prints the card.
func (m model) View() tea.View {
	var v tea.View
	v.WindowTitle = "nudi " + m.r.task()
	if m.exited {
		return v
	}
	top := header(m.r, m.w) + "\n" + truncate(modelsLine(m.r), m.w) + "\n\n" + stepper(m.r, m.phase, m.n > 0, m.w)
	content := top + "\n\n" + m.body.View()
	if m.intro != nil {
		h := lipgloss.Height(content)
		if m.h > 0 {
			h = min(h, max(1, m.h-4))
		}
		content = lipgloss.NewStyle().PaddingLeft(1).Height(h).Render(m.intro.view(m.w-2, h))
		v.SetContent("\n" + content + "\n\n " + dim(truncate("any key skip · q quit", m.w-2)) + "\n")
		return v
	}
	k := keys
	k.finding = m.n > 0
	k.open.SetEnabled(len(m.found) > 0)
	v.SetContent("\n" + content + "\n\n " + m.help.View(k) + "\n")
	return v
}

// renderPhase draws the panel of one phase with FOUND beside it, or the card for Finished.
func renderPhase(r Report, found []Finding, phase, w int) string {
	if phase == len(phases)-1 {
		return card(r, w, true)
	}
	leftW := w
	if w >= wideAt {
		leftW = w - foundW - 2
	}
	left := phasePanel(r, found, phase, leftW)
	right := foundPanel(found, min(w, foundW))
	if w < wideAt {
		return cut(left+"\n\n"+right, w)
	}
	return cut(lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(leftW).Render(left), "  ", right), w)
}

func cut(s string, w int) string {
	lines := splitLines(s)
	for i, l := range lines {
		lines[i] = truncate(l, w)
	}
	return strings.Join(lines, "\n")
}

func phasePanel(r Report, found []Finding, phase, w int) string {
	name, analysis := phases[phase].Name, phases[phase].Analysis
	status, selected := r.Analyses[analysis]
	if !selected {
		return heading(strings.ToUpper(name), "not selected for this run")
	}
	head := heading(strings.ToUpper(name), word(statusWords, status))
	if status == "not run" {
		return head
	}
	switch phase {
	case 0:
		return head + "\n" + rewardsChart(r, w)
	case 1:
		return head + "\n" + graderPanel(r, w)
	case 2:
		return head + "\n" + hackPanel(r, w)
	}
	return head + "\n" + attackPanel(r, found, w)
}

func bar(c color.Color, w int, pct float64) string {
	p := progress.New(progress.WithColors(c), progress.WithFillCharacters('━', '━'), progress.WithoutPercentage(), progress.WithWidth(w))
	p.EmptyColor = grey
	return p.ViewAs(pct)
}

func header(r Report, w int) string {
	left := " " + logo + "  " + bold(r.task())
	c := r.Configuration
	right := dim("cost unavailable")
	if c.KnownCost != nil {
		right = fmt.Sprintf("$%.2f", *c.KnownCost)
	}
	if c.KnownCost != nil && c.SpendingCap != nil && *c.SpendingCap > 0 {
		right += " " + bar(white, 12, *c.KnownCost / *c.SpendingCap) + dim(" $"+strconv.FormatFloat(*c.SpendingCap, 'f', -1, 64))
	}
	right += "   " + dim(c.Backend)
	if m := c.ModalCost; m != nil {
		right += dim(fmt.Sprintf(" ~$%.2f–%.2f", m.AtRequests, m.AtLimits))
	}
	return left + strings.Repeat(" ", max(2, w-width(left)-width(right)-1)) + right
}

// modelsLine names each role's model, without its provider, and its reasoning effort.
func modelsLine(r Report) string {
	var parts []string
	for _, role := range slices.Sorted(maps.Keys(r.Configuration.Models)) {
		m := r.Configuration.Models[role]
		parts = append(parts, strings.TrimSpace(role+" "+path.Base(m.Model)+" "+m.ReasoningEffort))
	}
	return dim(" " + strings.Join(parts, " · "))
}

// stepper names the phases with each one's status: a check when complete, a triangle when it stopped
// early or was not run, a circle when the run did not select it. The phase on screen is bold.
func stepper(r Report, phase int, finding bool, w int) string {
	var parts []string
	for i, p := range phases {
		mark, style := "■", boldStyle
		if p.Analysis != "" {
			status, selected := r.Analyses[p.Analysis]
			switch {
			case !selected:
				mark, style = "○", dimStyle
			case status == "complete":
				mark, style = "✓", greenStyle
			default:
				mark, style = "▲", yellowStyle
			}
		}
		name := p.Name
		if i == phase && !finding {
			name = lipgloss.NewStyle().Bold(true).Underline(true).Foreground(phaseColors[i]).Render(name)
		} else {
			name = style.Render(name)
		}
		parts = append(parts, style.Render(mark)+" "+name)
	}
	return truncate(" "+strings.Join(parts, dim(" ── ")), w)
}

func heading(s, note string) string { return " " + bold(s) + "  " + dim(note) }

// rewardsChart charts the Simulator's rewards per configuration: one bar per reward value, with
// Python's summaries and its flags, each with its reason as written. Every attempted episode at one
// value makes a bar 40 cells long.
func rewardsChart(r Report, w int) string {
	o := r.Ordinary
	if o == nil || len(o.Groups) == 0 {
		return ""
	}
	out := []string{heading("REWARDS", fmt.Sprintf("%d of %d episodes", o.Attempted, o.Requested))}
	for _, g := range o.Groups {
		if len(o.Groups) > 1 {
			out = append(out, " "+dim(path.Base(g.Configuration.Model)))
		}
		for _, name := range slices.Sorted(maps.Keys(g.Rewards)) {
			x := g.Rewards[name]
			if len(g.Rewards) > 1 {
				out = append(out, " "+dim(name))
			}
			for _, d := range x.Distribution {
				style := redStyle
				if d[0] > 0 {
					style = greenStyle
				}
				cells := int(40 * d[1] / float64(max(1, x.Attempted)))
				out = append(out, fmt.Sprintf(" %s %s %d", dim(pad(rewardText(d[0]), 4)), style.Render(strings.Repeat("█", max(1, cells))), int(d[1])))
			}
			line := "mean " + num(x.Mean) + " · median " + num(x.Median) + " · sample SD " + num(x.SD) + " · skewness " + num(x.Skewness)
			if left := x.Attempted - x.Usable; left > 0 {
				line += fmt.Sprintf(" · %d without a usable reward, not counted", left)
			}
			out = append(out, wrap(line, w, " ", dim))
			if x.Flags == nil {
				out = append(out, wrap("flag details unavailable", w, " ", dim))
			}
			for _, f := range x.Flags {
				if f == nil || f.Flag == nil || f.Text == nil {
					out = append(out, " "+yellowStyle.Render("▲ flag details unavailable"))
					continue
				}
				out = append(out, " "+yellowStyle.Render("▲ "+word(flagWords, *f.Flag)), wrap(*f.Text, w, "   ", plain))
			}
			if x.FlagsNotEvaluated != nil {
				out = append(out, wrap(*x.FlagsNotEvaluated, w, " ", dim))
			}
		}
	}
	return strings.Join(out, "\n")
}

func rewardText(x float64) string {
	s := strconv.FormatFloat(x, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

func graderPanel(r Report, w int) string {
	var out []string
	if in := r.Inspections["grader_inspector"]; in != nil {
		out = append(out, chips(in, []string{"accepted_invalid", "rejected_valid"}, w))
	}
	if r.Labels != nil {
		var parts []string
		for _, label := range slices.Sorted(maps.Keys(r.Labels.Counts)) {
			parts = append(parts, fmt.Sprintf("%s %d", word(labelWords, label), r.Labels.Counts[label]))
		}
		out = append(out, " "+dim("episode labels  "+strings.Join(parts, " · ")))
	}
	if r.Metrics != nil {
		for _, a := range r.Metrics.Confusion {
			out = append(out, agreementPanel(a, w))
		}
	}
	return strings.Join(out, "\n\n")
}

var agreementWords = map[string]string{"supported": "supported", "unsupported": "not supported", "unavailable": "unavailable"}

// agreementPanel tabulates one confusion group: the grader's native decision against the grader
// inspector's reference, with the two rates exactly as the report gives them. The native pass rate
// stands apart from agreement, so it is shown whatever the agreement status, after its rule.
func agreementPanel(a Agreement, w int) string {
	head := heading("GRADER ACCURACY", path.Base(a.Configuration.Model)+" · "+a.Reward)
	pass := wrap(passRateText(a.PassRate), w, " ", plain)
	if a.PassRate.Unavailable != nil {
		pass = wrap(*a.PassRate.Unavailable, w, " ", dim)
	}
	if a.Status != "supported" {
		if a.Rule != nil {
			pass = " " + dim(ruleText(a)) + "\n" + pass
		}
		return head + "\n " + dim("grader agreement "+word(agreementWords, a.Status)) + "\n" + wrap(strings.Join(a.Reasons, " "), w, " ", dim) + "\n" + pass
	}
	cells := []*int{a.TP, a.FP, a.FN, a.TN}
	total := 0
	for _, c := range cells {
		if c != nil {
			total += *c
		}
	}
	episodes := func(i int, style lipgloss.Style) string {
		if cells[i] == nil {
			return "–"
		}
		n := *cells[i]
		if k := 30 * n / max(1, total); k > 0 {
			return style.Render(strings.Repeat("█", k)) + " " + strconv.Itoa(n)
		}
		return strconv.Itoa(n)
	}
	t := table.New().Border(lipgloss.NormalBorder()).BorderStyle(dimStyle).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		StyleFunc(func(row, _ int) lipgloss.Style {
			if row == table.HeaderRow {
				return boldStyle.Padding(0, 1)
			}
			return lipgloss.NewStyle().Padding(0, 1)
		}).
		Headers("Type", "Meaning", "Episodes").
		Row("TP", "Correct work passed", episodes(0, greenStyle)).
		Row("FP", "Incorrect work passed", episodes(1, redStyle)).
		Row("FN", "Correct work failed", episodes(2, redStyle)).
		Row("TN", "Incorrect work failed", episodes(3, greenStyle))
	rate := func(name, formula string, x Rate) string {
		s := "\n " + pad(name, 47) + "  " + dim(formula) + "  "
		switch {
		case x.Unavailable != nil:
			return "\n" + wrap(*x.Unavailable, w, " ", dim)
		case x.Value == nil:
			return s + dim("unavailable")
		}
		at := ""
		if x.LowerBound {
			at = "at least "
		}
		return s + fmt.Sprintf("%d/%d  %s%.0f%%", *x.Numerator, *x.Denominator, at, 100**x.Value)
	}
	return head + "\n " + strings.ReplaceAll(t.String(), "\n", "\n ") + "\n " + dim(ruleText(a)) + "\n" + pass + "\n" +
		rate("FDR (Of accepted work, how much was incorrect?)", "FP / (TP + FP)", a.FalseDiscoveryRate) +
		rate("FNR (Of correct work, how much was rejected?)", "FN / (TP + FN)", a.FalseNegativeRate)
}

// ruleText is the grader's native decision rule that pass and fail stand for.
func ruleText(a Agreement) string {
	switch rule := a.Rule; {
	case rule == nil:
		return "no native decision rule"
	case len(rule.PassValues) > 0:
		var values []string
		for _, v := range rule.PassValues {
			values = append(values, rewardText(v))
		}
		return "pass means " + a.Reward + " " + strings.Join(values, " or ")
	case rule.Comparison != nil && rule.Threshold != nil:
		return "pass means " + a.Reward + " " + *rule.Comparison + " " + rewardText(*rule.Threshold)
	}
	return "no native decision rule"
}

func hackPanel(r Report, w int) string {
	in := r.Inspections["hack_inspector"]
	if in == nil {
		return ""
	}
	out := chips(in, hackOrder, w)
	if line := problemCount(r); line != "" {
		out += "\n\n" + wrap(line, w, " ", dim)
	}
	return out
}

// chips lists the searched categories, including names introduced by newer reports.
func chips(in *Inspection, order []string, w int) string {
	codes := slices.Clone(order)
	for _, code := range slices.Sorted(maps.Keys(in.Categories)) {
		if !slices.Contains(codes, code) {
			codes = append(codes, code)
		}
	}
	searched := map[string]bool{}
	for _, at := range in.Attempts {
		searched[at.Category] = true
		if at.Phase == "broad" {
			for code, state := range in.Categories {
				if state != "restricted" {
					searched[code] = true
				}
			}
		}
	}
	for _, ex := range in.Experiments {
		searched[ex.Category] = true
	}
	for _, group := range in.Findings {
		for _, finding := range group {
			searched[text(finding.Category)] = true
		}
	}
	var names, details []string
	for _, code := range codes {
		state, ok := in.Categories[code]
		if !ok {
			continue
		}
		name := word(checkNames, code)
		if searched[code] {
			names = append(names, name)
		}
		if state == "restricted" && in.Applicability[code] != "" {
			details = append(details, name+": "+in.Applicability[code])
		} else if !searched[code] {
			details = append(details, name+": no search attempt recorded")
		}
	}
	for _, at := range in.Attempts {
		target := word(checkNames, at.Category)
		if target == "" {
			target = at.Episode
		}
		if target == "" {
			target = "all categories"
		}
		status := at.Status
		switch status {
		case "evidenced_issue", "no_evidenced_issue":
			status = "completed"
		case "unknown":
			status = "ended"
		}
		line := fmt.Sprintf("%s attempt %d (%s): %s", at.Phase, at.Number, target, status)
		if at.Error != "" {
			line += ": " + strings.SplitN(at.Error, "\n", 2)[0]
		}
		details = append(details, line)
	}
	details = append(details, in.Limits...)
	scope := strings.Join(names, "; ")
	if scope == "" {
		scope = "none recorded"
	}
	out := wrap("Searched: "+scope, w, " ", plain)
	for _, detail := range details {
		out += "\n" + wrap(strings.TrimSuffix(detail, ", so they are unknown"), w, " ", dim)
	}
	return out
}

// attackPanel lists the problems the hack findings come from, then every attempt by the findings
// it tested and its hint level, the attempts without a hint first.
func attackPanel(r Report, found []Finding, w int) string {
	a := r.Attack
	if a == nil {
		return ""
	}
	out := []string{" " + dim(fmt.Sprintf("at most %d attempt%s per finding and hint level", a.MaximumAttempts, plural(a.MaximumAttempts)))}
	if lines := problemLines(r, w); lines != nil {
		out = append(append(out, ""), lines...)
	} else if len(a.Problems) > 0 {
		out = append(out, "", heading("PROBLEMS", "the attack tests one finding of each"))
		for i, p := range a.Problems {
			out = append(out, truncate(fmt.Sprintf(" %2d %s", i+1, p.Cause), w), "    "+problemMembers(r, found, p))
		}
	}
	type row struct {
		label string
		cells []Attempt
	}
	var rows []row
	index := map[string]int{}
	columns := 0
	for _, level := range []string{"none", "full", "minimal"} {
		for _, at := range a.Attempts {
			if at.Level != level {
				continue
			}
			what := strings.Join(names(found, tested(at)), " and ")
			if at.Problem != "" {
				what = at.Problem
			}
			label := pad(what, 18) + " " + word(levelWords, at.Level)
			if validWork(a, tested(at)) {
				label += " " + fg(coral, "valid work")
			}
			if _, ok := index[label]; !ok {
				index[label] = len(rows)
				rows = append(rows, row{label: label})
			}
			rows[index[label]].cells = append(rows[index[label]].cells, at)
			columns = max(columns, len(rows[index[label]].cells))
		}
	}
	if len(rows) == 0 {
		out = append(out, "", " "+dim("No attempt was recorded."))
	} else {
		labelW := 0
		for _, rw := range rows {
			labelW = max(labelW, width(rw.label))
		}
		var head []string
		for n := range columns {
			head = append(head, fmt.Sprintf("try %d", n+1))
		}
		out = append(out, "", " "+strings.Repeat(" ", labelW+1)+dim(strings.Join(head, "   ")))
		used, raw := map[Result]bool{}, map[string]bool{}
		for _, rw := range rows {
			line := " " + pad(dim(rw.label), labelW) + " "
			for _, at := range rw.cells {
				res, known := lookup(attemptResults, at.Status)
				if !r.started(at) {
					res, known = NotTested, true
				}
				if !known {
					raw[at.Status] = true
					res = Unsettled
				}
				used[res] = true
				line += cell(res) + "  "
			}
			out = append(out, truncate(line, w))
		}
		var legend []string
		for _, res := range []Result{Evidenced, Elsewhere, NoIssue, Failed, Unsettled, NotTested} {
			if used[res] {
				legend = append(legend, swatch(res)+" "+dim(resultWords[res]))
			}
		}
		for _, status := range slices.Sorted(maps.Keys(raw)) {
			legend = append(legend, dim(status))
		}
		out = append(out, "", truncate(" "+strings.Join(legend, "   "), w))
	}
	if line := untested(r); line != "" {
		out = append(out, " "+dim(line))
	}
	return strings.Join(out, "\n")
}

// tested are the candidates an attempt tested; an attempt without a hint tests none.
func tested(a Attempt) []string {
	if len(a.Sources) > 0 {
		return a.Sources
	}
	if a.Candidate != nil {
		return []string{*a.Candidate}
	}
	return nil
}

// names gives each report id its finding number in the viewer, such as "#4 hack-1".
func names(found []Finding, ids []string) []string {
	var out []string
	for _, id := range ids {
		if n := number(found, id); n > 0 {
			id = fmt.Sprintf("#%d %s", n, id)
		}
		out = append(out, id)
	}
	return out
}

func validWork(a *Attack, ids []string) bool {
	for _, c := range a.Candidates {
		if c.ValidWork && slices.Contains(ids, c.ID) {
			return true
		}
	}
	return false
}

// problemMembers names a problem's findings. The attack selects only its candidate, so only the candidate
// is marked selected, then attempted or not tested; any finding the report names reproduced is marked so.
func problemMembers(r Report, found []Finding, p Problem) string {
	var parts []string
	for i, id := range p.Findings {
		name := names(found, []string{id})[0]
		if p.Candidate == nil || *p.Candidate != id {
			part := dim(name)
			if marks := problemMarks(r, p, id); marks != "" {
				part += " " + marks
			}
			parts = append(parts, part)
			continue
		}
		parts = append(parts, bold(name)+" "+problemMarks(r, p, id))
		parts[0], parts[i] = parts[i], parts[0]
	}
	if p.Candidate == nil {
		parts = append(parts, dim("no finding selected, not tested"))
	}
	return strings.Join(parts, "   ")
}

// problemMarks marks finding id of problem p: the candidate is selected, then attempted or not tested, and an attempted
// finding is reproduced when the report says so. A finding with neither has no marks.
func problemMarks(r Report, p Problem, id string) string {
	var marks []string
	if p.Candidate != nil && *p.Candidate == id {
		tested := "attempted"
		if !r.attempted(id) {
			tested = "not tested"
		}
		marks = append(marks, "selected", tested)
	}
	if reproduced(p, id) && r.attempted(id) {
		marks = append(marks, redStyle.Render("reproduced"))
	}
	if len(marks) == 0 {
		return ""
	}
	return dim("(") + strings.Join(marks, dim(" · ")) + dim(")")
}

// untested counts the candidates no attempt tested, those without guidance apart.
func untested(r Report) string {
	none, noGuidance := 0, 0
	for _, c := range r.Attack.Candidates {
		if r.attempted(c.ID) {
			continue
		}
		none++
		// Without guidance: every condition the run requested is unavailable.
		requested, unavailable := 0, true
		for _, cond := range c.Conditions {
			if cond.Status != "not_requested" {
				requested++
				unavailable = unavailable && cond.Status == "unavailable"
			}
		}
		if requested > 0 && unavailable {
			noGuidance++
		}
	}
	if none == 0 {
		return ""
	}
	s := fmt.Sprintf("%d finding%s not tested", none, plural(none))
	if noGuidance > 0 {
		s += fmt.Sprintf(", %d of them without guidance", noGuidance)
	}
	return s
}

func cell(res Result) string {
	switch res {
	case Evidenced:
		return redStyle.Render("██████")
	case Elsewhere:
		return yellowStyle.Render("██████")
	case NoIssue:
		return dim("██████")
	case Failed:
		return redStyle.Render("  ✗   ")
	case Unsettled:
		return "  ?   "
	}
	return dim("  ··  ")
}

func swatch(res Result) string {
	switch res {
	case Evidenced:
		return redStyle.Render("██")
	case Elsewhere:
		return yellowStyle.Render("██")
	case NoIssue:
		return dim("██")
	case Failed:
		return redStyle.Render("✗")
	case Unsettled:
		return "?"
	}
	return dim("··")
}

func foundPanel(found []Finding, w int) string {
	border := grey
	if len(found) > 0 {
		border = red
	}
	inner := w - 4
	var body []string
	kinds := map[string]bool{}
	for i, f := range found {
		kinds[kind(f)] = true
		head := fmt.Sprintf("#%d ", i+1) + redStyle.Bold(true).Render(kind(f)) + " " + open(f)
		head += dim(truncate(f.ID, inner-width(head)))
		if f.Confirms != "" {
			head += "\n" + dim(truncate(f.Confirms, inner))
		}
		body = append(body, head+"\n"+truncate(title(f), inner))
	}
	if len(body) == 0 {
		body = []string{dim("Nothing evidenced.")}
	}
	if legend := tagLegend(kinds); legend != "" {
		body = append(body, legend)
	}
	title := bold("FOUND  0")
	if len(found) > 0 {
		title = redStyle.Bold(true).Render(fmt.Sprintf("FOUND  %d", len(found)))
	}
	return " " + title + "\n" + lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).Padding(0, 1).Width(w).
		Render(strings.Join(body, "\n\n"))
}

// tagLegend is the key under the findings: what each tag on screen means.
func tagLegend(kinds map[string]bool) string {
	var legend []string
	for _, k := range []string{"HACK", "FP", "FN"} {
		if kinds[k] {
			legend = append(legend, dim(pad(k, 16)+kindKeys[k]))
		}
	}
	return strings.Join(legend, "\n")
}
