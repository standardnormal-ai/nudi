package main

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"
)

// The frame every finished screen shares: the header, the tab strip, the key help and the panels that m, c and ? open.

var dark = lipgloss.Color("#0d1117")

type keyMap struct {
	sel, open, tab, help, quit, section, other, back key.Binding
	finding                                          bool
}

func (k keyMap) ShortHelp() []key.Binding {
	if k.finding {
		return []key.Binding{k.section, k.other, k.back, k.help, k.quit}
	}
	return []key.Binding{k.sel, k.open, k.tab, k.help, k.quit}
}

func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

var keys = keyMap{
	sel:     key.NewBinding(key.WithKeys("up", "down", "k", "j"), key.WithHelp("Up/Down", "select")),
	open:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("Enter", "")),
	tab:     key.NewBinding(key.WithKeys("tab", "shift+tab"), key.WithHelp("Tab", "next tab")),
	help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "Help")),
	quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "Quit")),
	section: key.NewBinding(key.WithKeys("tab"), key.WithHelp("Tab", "next section")),
	other:   key.NewBinding(key.WithKeys("left", "right", "h", "l"), key.WithHelp("Left/Right", "other finding")),
	back:    key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("Esc", "back")),
}

// header is two quiet rows: the task, where it ran, how long and how many episodes at once; then the model cost
// against the spending cap, the Modal sandbox estimate, and the keys of the models and cost panels.
// A live run is following live and has no models panel.
func header(r Report, live bool, w int) string {
	c := r.Configuration
	var right []string
	if c.Backend != "" {
		right = append(right, dim(strings.ToUpper(c.Backend[:1])+c.Backend[1:]))
	}
	if r.Elapsed != nil {
		right = append(right, dim("Elapsed")+" "+elapsed(*r.Elapsed))
	}
	if n := c.Capacity.Concurrency; n > 0 {
		right = append(right, dim("Concurrency")+" "+strconv.Itoa(n))
	}
	cost := []string{dim("Model cost unavailable")}
	if c.KnownCost != nil {
		cost[0] = dim("Model cost") + " " + dollars(*c.KnownCost)
		if c.SpendingCap != nil && *c.SpendingCap > 0 {
			cost[0] += dim(" of ") + dollars(*c.SpendingCap) + "  " + costBar(c, 12)
		}
	}
	if m := c.ModalCost; m != nil {
		cost = append(cost, dim("Sandbox estimate")+fmt.Sprintf(" $%.2f to $%.2f", m.AtRequests, m.AtLimits))
	}
	cost = append(cost, keyText("c")+" "+dim("Cost"))
	left, models := " "+logo+"  "+keyText(r.task()), " "+keyText("m")+" "+dim("Models")
	if live {
		left = left + "   " + dim("following live")
	}
	if len(r.Configuration.Models) == 0 {
		models = ""
	}
	return spread(left, strings.Join(right, "     "), w) + "\n" + spread(models, strings.Join(cost, "     "), w)
}

// costBar fills with the share of the spending cap the model cost used, amber once it reached the cap.
func costBar(c Configuration, w int) string {
	share := *c.KnownCost / *c.SpendingCap
	if share >= 1 {
		return bar(yellow, w, 1)
	}
	return bar(teal, w, share)
}

// stage is the mark of phase i on its tab: a check once it finished, a word when it did not, and off when the run left it out.
// A phase that ran to its end with questions left open finished; Work left lists the questions.
func (r Report) stage(i int) (mark string, off bool) {
	a := phases[i].Analysis
	status, ok := r.Analyses[a]
	switch {
	case !ok:
		return "", true
	case r.PhaseErrors[a] != "":
		return redStyle.Render("Error"), false
	case status == "complete", status == "partial" && r.Unfinished[a] == "" && slices.Contains(r.Unresolved, a):
		return greenStyle.Render("✓"), false
	case status == "not run":
		return dim("-"), false
	case status == "partial":
		return yellowStyle.Render("partly"), false
	case status == "cancelled", status == "time_limit", status == "spending_exhausted":
		return yellowStyle.Render("stopped"), false
	}
	return yellowStyle.Render("not finished"), false
}

// tabStrip joins the four phases in their order on the left, each with the mark stage gives it, and puts Results
// alone on the right. The tab on screen is drawn inverse. A narrow window joins them closer, then wraps them.
func tabStrip(stage func(int) (string, bool), screen, w int) string {
	var parts []string
	for i, p := range phases {
		mark, off := stage(i)
		name := p.Name
		switch {
		case i == screen:
			name = lipgloss.NewStyle().Bold(true).Foreground(dark).Background(phaseColors[i]).Render(" " + name + " ")
		case off:
			name = dim(name)
		}
		if mark != "" {
			name += " " + mark
		}
		parts = append(parts, name)
	}
	tab := dim("[ ") + "Results" + dim(" ]")
	if screen == results {
		tab = lipgloss.NewStyle().Bold(true).Foreground(dark).Background(white).Render(" Results ")
	}
	right := dim("│") + "   " + tab
	rule := "\n " + dim(strings.Repeat("─", max(0, w-2)))
	for _, join := range []string{" ── ", " ─ "} {
		if left := " " + strings.Join(parts, dim(join)); width(left)+width(right)+3 <= w {
			return spread(left, right, w) + rule
		}
	}
	lines := []string{" " + parts[0]}
	for i, p := range parts[1:] {
		need := width(p)
		if i == len(parts)-2 {
			need += width(right) + 3 // the last tab keeps Results beside it
		}
		if last := lines[len(lines)-1]; width(last)+3+need < w {
			lines[len(lines)-1] = last + dim(" ─ ") + p
		} else {
			lines = append(lines, " "+p)
		}
	}
	lines[len(lines)-1] = spread(lines[len(lines)-1], right, w)
	return strings.Join(lines, "\n") + rule
}

// modelsPanel is one row per model role: its model, without its provider, and its reasoning effort, with the jobs
// the role runs wrapped below it inside the box.
func modelsPanel(r Report, w int) string {
	widths, inner := []int{12, 28}, w-5
	rows := []string{cols(inner, "", widths, dim("Role"), dim("Model"), dim("Reasoning"))}
	for _, role := range slices.Sorted(maps.Keys(r.Configuration.Models)) {
		m := r.Configuration.Models[role]
		name, ok := lookup(roleNames, role)
		if !ok {
			name = [2]string{role, ""}
		}
		effort := m.ReasoningEffort
		if effort == "" {
			effort = "-"
		}
		rows = append(rows, cols(inner, "", widths, name[0], path.Base(m.Model), effort))
		if name[1] != "" {
			rows = append(rows, wrap("Jobs: "+name[1], inner, strings.Repeat(" ", 12), dim))
		}
	}
	if len(rows) == 1 {
		rows = []string{dim("No model recorded.")}
	}
	return "\n" + box("Models", keyText("m")+" "+dim("close"), w-1, rows...)
}

// costRows are the cost section of Results, and with all the cost panel and the plain output: model cost against the
// cap, with a bar on Results only, the calls without a price, the Modal sandbox estimate and the Modal bill, which only
// `nudi cost` fetches.
func costRows(r Report, w int, all bool) []string {
	c, widths := r.Configuration, []int{28, 22}
	row := func(name, value, note string) string { return cols(w, " ", widths, dim(name), value, dim(note)) }
	model := "unavailable"
	share := ""
	if c.KnownCost != nil {
		model = dollars(*c.KnownCost)
		if c.SpendingCap != nil && *c.SpendingCap > 0 {
			model += dim(" of ") + dollars(*c.SpendingCap) + dim(" cap")
			if !all {
				share = costBar(c, 16)
			}
		}
	}
	out := []string{cols(w, " ", widths, dim("Model cost"), model, share)}
	if all && c.SpendingCap != nil {
		out = append(out, row("Spending cap", dollars(*c.SpendingCap), "Covers model cost only"))
	}
	if n := c.UnknownCostCalls; n > 0 {
		out = append(out, row("Calls without a price", strconv.Itoa(n), "Not counted in model cost"))
		if all {
			for _, reason := range slices.Sorted(maps.Keys(c.UnknownReasons)) {
				out = append(out, row("", strconv.Itoa(c.UnknownReasons[reason]), reason))
			}
		}
	}
	if n := c.CancelledCalls; n > 0 {
		out = append(out, row("Calls cancelled in flight", strconv.Itoa(n), "Stopped before they returned"))
	}
	if m := c.ModalCost; m != nil {
		out = append(out, row("Modal sandbox estimate", fmt.Sprintf("$%.2f to $%.2f", m.AtRequests, m.AtLimits), "At requested CPU and memory, then at their limits"))
		if all {
			out = append(out, row("Sandboxes", strconv.Itoa(m.Sandboxes), fmt.Sprintf("%d without limits, %d still running", m.WithoutLimits, m.StillRunning)),
				row("", "", "The estimate leaves out the machine running nudi and is separate from the cap"))
		}
		out = append(out, row("Modal bill", "not fetched", "Run nudi cost "+r.Dir))
	}
	return out
}

func costPanel(r Report, w int) string {
	return "\n" + box("Cost", keyText("c")+" "+dim("close"), w-1, costRows(r, w-4, true)...)
}

// helpPanel explains every symbol, colour and word the screens use; live adds those of a run still going.
func helpPanel(w int, live bool) string {
	row := func(a, b string) string { return cols(w, " ", []int{20}, a, dim(b)) }
	// The live screen has no Work left, no row cursor and no Enter; its rows say so in their own words.
	untested, unfinished, toggle := "Not tested. Work left on Results says why.", "A phase that did not finish. Work left on Results says what is left.",
		"A collapsed or expanded section or row. Press the key shown beside it, or Enter."
	if live {
		untested, toggle = "Not tested yet.", "A collapsed or expanded section. Press the key shown beside it."
		unfinished = "partly: the phase ended with some results unresolved or some work not finished; the report says which. stopped: it ended before its work was done."
	}
	out := []string{spread(" "+fg(teal, bold("Help")), keyText("?")+" "+dim("or")+" "+keyText("Esc")+" "+dim("close"), w), "", heading("Symbols", ""),
		row(greenStyle.Render("✓")+" "+redStyle.Render("✓"), "Yes. Green beside a phase that finished; red for a demonstrated problem."),
		row(dim("✗"), "No. Not shown in the tests that ran."),
		row(dim("-"), untested),
		row(yellowStyle.Render("?"), "Unresolved. The evidence did not decide it."),
		row(redStyle.Render("Error"), "The step failed to run. The reason is on the same screen."),
		row(yellowStyle.Render("partly")+" "+yellowStyle.Render("stopped"), unfinished),
		row(dim("▸ ▾"), toggle),
	}
	if !live {
		out = append(out, row(fg(teal, "›"), "The selected row. Enter opens it."), row(fg(violet, "◆")+" "+dim("│"), "A step in an evidence timeline."))
	}
	out = append(out, row(dim("──"), "Joins the four phase tabs on the left, in the order they run."),
		row(dim("[ ")+"Results"+dim(" ]"), "The Results tab, alone on the right. Tab moves between tabs."))
	if live {
		out = append(out, row(fg(teal, spin[0])+" 2:10", "Running, for the time beside it."),
			row(dim("waiting"), "A phase that has not started yet."),
			row(dim("↓"), "More rows below. f opens them all."))
	}
	out = append(out, "", heading("Colours", ""),
		row(redStyle.Render("red"), "A demonstrated problem, or a wrong grader decision."),
		row(greenStyle.Render("green"), "A finished phase, or a correct grader decision."),
		row(yellowStyle.Render("amber"), "Work that needs attention: stopped, partly finished, not tested."),
		row(dim("grey"), "Background information."),
		"", heading("Words", ""),
		row("Real episode", "A normal run of the task by an agent, scored by the task's own grader."),
		row("Task copy", "A copy of the task package that an inspector ran on its own."),
		row("Full instructions", "The Attacker was told the problem and how to use it. Full in short."),
		row("Only a hint", "The Attacker was told only where to look. Hint in short."),
		row("No information", "The Attacker got the task and was asked to find any hack. No info in short."))
	if !live {
		out = append(out, row("P1, G1, hack-1", "References. On Results, i lists every kind."),
			"", heading("Metrics", ""),
			row("F1", "How well the grader's passes match the work the Grader Inspector found correct: 2 TP / (2 TP + FP + FN), from 0 to 1."),
			row("AUROC", "How often the reward ranks correct work above incorrect work: 1 always, 0.5 by chance."),
			row("Score ordering", "AUROC needs a score whose order the grader's own code sets (source-grounded). Reward values alone do not give one."))
	}
	if live {
		out = append(out, "", heading("References", ""))
		for _, x := range references {
			out = append(out, row(x[0], x[1]+", as "+x[2]+"."))
		}
		out = append(out, "", heading("Findings So Far", ""))
	}
	if live {
		out = append(out, row("New?", "The novelty_judge found no earlier finding with the same cause."),
			row("Inspector?", "The Hack Inspector reproduced the finding in a task copy. A Grader Inspector finding is its own evidence."),
			row("Full instr.?", "An Attacker given full instructions demonstrated it in a real episode."),
			row("Hint?", "An Attacker given only a hint demonstrated it in a real episode."),
			row("novelty_judge", "Compares each finding with the earlier ones and names it new or the same as one."),
			row("Related observations", "Findings with the same cause as a finding above."))
	}
	if live {
		out = append(out, "", heading("Keys", ""), row("Tab, Shift+Tab", "Move between tabs."))
		return strings.Join(append(out,
			row("Up/Down", "Scroll."),
			row("Left/Right", "Show more agent tiles."),
			row("o", "Expand or collapse the related observations."),
			row("l", "Expand or collapse the logs."),
			row("f", "Open or close all findings so far."),
			row("m", "The models of this run."),
			row("c", "The cost of this run so far."),
			row("q", "Stop following. The run goes on.")), "\n")
	}
	return strings.Join(append(out, "", heading("Keys", ""), row("Tab, Left/Right", "Move between tabs."),
		row("m", "The models of this run."), row("c", "The cost of this run.")), "\n")
}
