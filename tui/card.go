package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// shownWarnings is how many warnings the card lists before it counts the rest.
const shownWarnings = 3

// card is the finished run in one screen: Python's answer, the problems or else the findings, the rewards and the cost.
// The viewer opens on it, prints it into the scrollback on quit, and a pipe gets it as plain text.
func card(r Report, w int, color bool) string {
	found := r.findings()
	var b strings.Builder
	// line adds one line of the card; a pipe gets it at most w wide, each continuation after hang spaces.
	line := func(s string, hang int) {
		if !color {
			s = fold(ansi.Strip(s), w, strings.Repeat(" ", hang))
		}
		b.WriteString(s + "\n")
	}
	b.WriteString(banner(r, len(found), w) + "\n")
	for _, line := range r.Answer[1:] {
		b.WriteString(wrap(line, w, " ", plain) + "\n")
	}
	b.WriteString("\n")
	// With problems the card lists them instead of the findings, which keep their own screens.
	if problems := problemLines(r, w); problems != nil {
		b.WriteString(strings.Join(problems, "\n") + "\n\n")
	} else {
		for i, f := range found {
			line(fmt.Sprintf(" %2d  %s", i+1, findingLine(f)), 21) // under the mechanism
		}
		counts := findingCounts(r, found)
		if counts != "" {
			b.WriteString(" " + dim(counts) + "\n")
		}
		if len(found) > 0 || counts != "" {
			b.WriteString("\n")
		}
	}
	if chart := rewardsChart(r, w); chart != "" {
		b.WriteString(chart + "\n\n")
	}
	b.WriteString(wrap(strings.Join(stats(r), " · "), w, " ", dim) + "\n")
	b.WriteString(wrap(costLine(r), w, " ", dim) + "\n")
	if n := len(r.Warnings); n > 0 {
		line(" "+yellowStyle.Render(fmt.Sprintf("▲ %d warning%s", n, plural(n)))+dim(" in "+r.Dir+"/report.md"), 3)
		// Each warning on one line, its first, as report.md shows it.
		for _, warning := range r.Warnings[:min(n, shownWarnings)] {
			line("   "+strings.Join(strings.Fields(strings.SplitN(warning, "\n", 2)[0]), " "), 3)
		}
		if n > shownWarnings {
			b.WriteString("   " + dim(fmt.Sprintf("and %d more", n-shownWarnings)) + "\n")
		}
	}
	next := r.Dir + "/report.md"
	if p, n := r.topProblem(found); p != nil {
		next = "nudi-view " + r.Dir + " " + p.ID
	} else if len(found) > 0 {
		next = "nudi-view " + r.Dir + " " + strconv.Itoa(n)
	}
	b.WriteString("\n " + dim("next ›"))
	if !color && width(" next › "+next) > w {
		b.WriteString("\n  ") // the command stays whole, on a line of its own
	}
	b.WriteString(" " + next)
	if !color {
		return plainText(b.String()) // a pipe gets whole lines
	}
	return cut(b.String(), w)
}

// banner shows the first answer line, how the run ended, on a neutral bar; a report from before headlines has its
// verdict there. Red marks only the count after it: the problems listed, or a report without them its evidenced findings.
func banner(r Report, found, w int) string {
	n, noun := found, "evidenced finding"
	if r.helpNeeded() {
		n, noun = len(slices.DeleteFunc(slices.Clone(r.Attack.Problems), Problem.lead)), "problem"
	}
	bar := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0d1117")).Background(grey).Padding(0, 1)
	if n == 0 {
		return bar.Width(w).Render(r.Answer[0])
	}
	if n > 1 {
		noun += "s"
	}
	count := bar.Background(red).Render(fmt.Sprintf("%d %s", n, noun))
	return lipgloss.JoinHorizontal(lipgloss.Top, bar.Width(w-lipgloss.Width(count)).Render(r.Answer[0]), count)
}

// problemLines list the problems by their step on the exploit chart, highest first, each with its source. Leads, the
// problems no evidence confirmed, are counted on one line. Reports whose problems lack `exploited_with` and
// `help_needed` have none.
func problemLines(r Report, w int) []string {
	if !r.helpNeeded() {
		return nil
	}
	ps := slices.DeleteFunc(slices.Clone(r.Attack.Problems), Problem.lead)
	leads := len(r.Attack.Leads) + len(r.Attack.Problems) - len(ps)
	slices.SortStableFunc(ps, func(a, b Problem) int { return b.ladder() - a.ladder() })
	name := func(p Problem) string {
		return strings.TrimSpace(p.ID + " " + strings.Join(strings.Fields(p.Cause), " "))
	}
	// The report's label, or in reports before `label` the chart's words, and at level 2 where it was evidenced and the reason.
	label := func(p Problem) string {
		l, text := p.ladder(), p.Label
		if text == "" && r.validWork(p) {
			text = "Correct work failed" + validWorkWords[l]
		} else if text == "" {
			text = ladderWords[l]
		}
		reason := reasonWords[p.why()]
		if r.validWork(p) && p.why() == "not_exploited" {
			reason = "Attackers did not reproduce it"
		}
		if l == 2 {
			return strings.Join(slices.DeleteFunc([]string{text, evidencedWords[p.Scope], reason}, func(s string) bool { return s == "" }), ", ")
		}
		return text
	}
	// Every inspector whose finding the judge placed in the problem, then an Attacker with no extra information.
	sources := func(p Problem) []string {
		out := []string{p.Source}
		for _, m := range p.Members {
			s := map[string]string{"hack": "hack inspector", "experiment": "hack inspector", "grader": "grader inspector"}[strings.SplitN(m, "-", 2)[0]]
			if s != "" && !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
		if p.independent() && p.Source != "Attacker" {
			out = append(out, "independent attacker")
		}
		return slices.DeleteFunc(out, func(s string) bool { return s == "" })
	}
	// Each problem's sources go on the line under it, so the cause keeps its room beside the long chart label.
	labelW, helpW := 8, 0
	for _, p := range ps {
		labelW, helpW = max(labelW, width(name(p))), max(helpW, width(label(p)))
	}
	labelW = min(labelW, max(10, w-3-helpW))
	out := []string{" " + pad(bold("PROBLEMS"), labelW) + "  " + dim("level")}
	for _, p := range ps {
		help := dim(label(p))
		if p.ladder() >= 3 {
			help = redStyle.Render(label(p))
		}
		out = append(out, " "+pad(truncate(name(p), labelW), labelW)+"  "+help)
		if names := sources(p); len(names) > 0 {
			out = append(out, wrap("from "+strings.Join(names, " + "), w, "   ", dim))
		}
	}
	if leads > 0 {
		out = append(out, " "+dim(fmt.Sprintf("%d lead%s, which no evidence confirmed", leads, strings.Repeat("s", min(1, leads-1)))))
	}
	return out
}

// problemCount says how many problems the inspector findings come from, for the hack panel; reports before nudi 0.0.1 have none.
func problemCount(r Report) string {
	if r.Attack == nil || len(r.Attack.Problems) == 0 || r.helpNeeded() {
		return ""
	}
	n := map[string]int{}
	for _, p := range r.Attack.Problems {
		for _, id := range p.Findings {
			n[strings.SplitN(id, "-", 2)[0]]++
		}
	}
	var from []string
	for _, prefix := range []string{"hack", "grader"} {
		if n[prefix] > 0 {
			from = append(from, fmt.Sprintf("%d %s inspector finding%s", n[prefix], prefix, plural(n[prefix])))
		}
	}
	ps := len(r.Attack.Problems)
	return fmt.Sprintf("%d problem%s from %s; the attack tests one finding of each", ps, plural(ps), strings.Join(from, " and "))
}

func findingCounts(r Report, found []Finding) string {
	var parts []string
	open := 0
	for _, f := range found {
		if len(f.Claim.Unresolved) > 0 {
			open++
		}
	}
	if open > 0 {
		parts = append(parts, fmt.Sprintf("▲ %d with open conditions", open))
	}
	for _, bucket := range []string{"inconclusive", "legitimate"} {
		if n := r.count(bucket); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, bucket))
		}
	}
	return strings.Join(parts, " · ")
}

func stats(r Report) []string {
	var out []string
	if o := r.Ordinary; o != nil {
		out = append(out, fmt.Sprintf("%d of %d episodes", o.Attempted, o.Requested))
	}
	if r.Metrics != nil {
		for _, a := range r.Metrics.Confusion {
			out = append(out, passRateText(a.PassRate))
			if a.Status == "supported" {
				out = append(out, rateText("FDR (Of accepted work, how much was incorrect?)", a.FalseDiscoveryRate),
					rateText("FNR (Of correct work, how much was rejected?)", a.FalseNegativeRate))
			}
		}
	}
	if r.Attack != nil {
		n := 0
		for _, a := range r.Attack.Attempts {
			if r.started(a) {
				n++
			}
		}
		out = append(out, fmt.Sprintf("%d attack attempt%s", n, plural(n)))
	}
	return out
}

// rateText is a rate beside its counts, marked when presumed labels make it a lower bound.
func rateText(name string, x Rate) string {
	if x.Unavailable != nil || x.Value == nil {
		return name + " unavailable"
	}
	at := ""
	if x.LowerBound {
		at = "at least "
	}
	return fmt.Sprintf("%s %s%.0f%% (%d/%d)", name, at, 100**x.Value, *x.Numerator, *x.Denominator)
}

// passRateText is the share of usable rewards that the grounded native decision rule passes, with its 95% Wilson
// interval when the report gives one, as report.md words it.
func passRateText(x Rate) string {
	s := rateText("native pass rate", x)
	if len(x.Interval) == 2 {
		s += fmt.Sprintf(", 95%% Wilson interval %.2f to %.2f", x.Interval[0], x.Interval[1])
	}
	return s
}

func costLine(r Report) string {
	c := r.Configuration
	known := "known model cost unavailable"
	if c.KnownCost != nil {
		known = fmt.Sprintf("$%.2f known model cost", *c.KnownCost)
	}
	if c.SpendingCap != nil {
		known += ", spending cap $" + strconv.FormatFloat(*c.SpendingCap, 'f', -1, 64)
	}
	parts := []string{known}
	if c.UnknownCostCalls > 0 {
		parts = append(parts, fmt.Sprintf("%d call%s without a price", c.UnknownCostCalls, plural(c.UnknownCostCalls)))
	}
	if c.CancelledCalls > 0 {
		parts = append(parts, fmt.Sprintf("%d call%s cancelled in flight", c.CancelledCalls, plural(c.CancelledCalls)))
	}
	if m := c.ModalCost; m != nil {
		parts = append(parts, fmt.Sprintf("Modal sandboxes about $%.2f at requested CPU and memory, $%.2f if all used their limits; "+
			"outside the cap; bill: nudi cost %s", m.AtRequests, m.AtLimits, r.Dir))
	}
	if c.Backend != "" {
		parts = append(parts, c.Backend)
	}
	return strings.Join(parts, " · ")
}

// exitCode is Python's: 0 for a complete run, 1 for any other, also one that reached its time limit.
func exitCode(r Report) int {
	if r.Status == "complete" {
		return 0
	}
	return 1
}

// plainText is s for a pipe: no colour and no spaces at the ends of lines.
func plainText(s string) string {
	lines := splitLines(ansi.Strip(s))
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}

// fold breaks a plain line wider than w at its last space within w, again for each rest, which
// continues after indent; a word longer than the room keeps a line of its own.
func fold(s string, w int, indent string) string {
	var out []string
	for width(s) > w {
		lead := len(s) - len(strings.TrimLeft(s, " "))
		at := strings.LastIndexByte(ansi.Truncate(s, w+1, ""), ' ')
		if at <= lead {
			if at = strings.IndexByte(s[lead:], ' '); at < 0 {
				break
			}
			at += lead
		}
		out = append(out, strings.TrimRight(s[:at], " "))
		s = indent + strings.TrimLeft(s[at:], " ")
	}
	return strings.Join(append(out, s), "\n")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
