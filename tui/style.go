package main

import (
	"fmt"
	"image/color"
	"slices"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Colour marks the phase in progress and red marks a finding. Everything else is plain or dim.
var (
	teal   = lipgloss.Color("#5fd4c4")
	violet = lipgloss.Color("#b18cff")
	coral  = lipgloss.Color("#ff8a65")
	blue   = lipgloss.Color("#7fb0ff")
	red    = lipgloss.Color("#ff5f6d")
	green  = lipgloss.Color("#7ee787")
	yellow = lipgloss.Color("#e3b341")
	grey   = lipgloss.Color("#6e7681")
	white  = lipgloss.Color("#e6edf3")

	phaseColors = [...]color.Color{teal, blue, violet, coral}

	dimStyle    = lipgloss.NewStyle().Foreground(grey)
	boldStyle   = lipgloss.NewStyle().Foreground(white).Bold(true)
	redStyle    = lipgloss.NewStyle().Foreground(red)
	greenStyle  = lipgloss.NewStyle().Foreground(green)
	yellowStyle = lipgloss.NewStyle().Foreground(yellow)
	logo        = lipgloss.NewStyle().Foreground(teal).Bold(true).Render("nudi")
)

func dim(s string) string  { return dimStyle.Render(s) }
func bold(s string) string { return boldStyle.Render(s) }

func fg(c color.Color, s string) string { return lipgloss.NewStyle().Foreground(c).Render(s) }

func width(s string) int { return lipgloss.Width(s) }

func truncate(s string, w int) string { return ansi.Truncate(s, w, "…") }

func pad(s string, w int) string { return s + strings.Repeat(" ", max(0, w-width(s))) }

func kind(f Finding) string { return word(kindTags, f.Source+" "+f.Assessment.Outcome) }

// title is the finding's mechanism, in the Inspector's words, on one line.
func title(f Finding) string { return strings.Join(strings.Fields(f.Claim.Mechanism), " ") }

// num prints a number from the report as Python's number() does, with up to four significant digits.
func num(x *float64) string {
	if x == nil {
		return "unavailable"
	}
	return strconv.FormatFloat(*x, 'g', 4, 64)
}

// breakLines breaks s at spaces into lines at most w columns wide; a longer word keeps a line of its own.
func breakLines(s string, w int) []string {
	var out []string
	for _, word := range strings.Fields(s) {
		if n := len(out); n > 0 && width(out[n-1])+1+width(word) <= w {
			out[n-1] += " " + word
		} else {
			out = append(out, word)
		}
	}
	return out
}

// wrap is s in lines at most w columns wide, each one drawn by style after indent.
func wrap(s string, w int, indent string, style func(string) string) string {
	lines := breakLines(s, w-width(indent))
	for i, l := range lines {
		lines[i] = indent + style(l)
	}
	return strings.Join(lines, "\n")
}

func plain(s string) string { return s }

func heading(s, note string) string { return " " + bold(s) + "  " + dim(note) }

// titled is a section's title with its count, as in PROBLEMS (3).
func titled(name string, n int) string { return " " + bold(name) + " " + dim("("+strconv.Itoa(n)+")") }

// spread puts left and right on one line w wide, or right on the next line when they do not fit.
func spread(left, right string, w int) string {
	if gap := w - width(left) - width(right) - 1; gap >= 2 {
		return left + strings.Repeat(" ", gap) + right
	}
	if right == "" {
		return left
	}
	return left + "\n " + right
}

// cols lays cells out as one table row after indent, each in its column of widths and the last in the rest of w;
// a cell too long for its column wraps inside it. A narrow window first shrinks the widest columns, then puts the
// first cell on a line of its own above the others.
func cols(w int, indent string, widths []int, cells ...string) string {
	ws := slices.Clone(widths[:len(cells)-1])
	room := w - width(indent) - 8
	for len(ws) > 0 && sum(ws) > room {
		i := slices.Index(ws, slices.Max(ws))
		if ws[i] <= 12 {
			break
		}
		ws[i]--
	}
	if sum(ws) > room && len(cells) > 2 {
		return cols(w, indent, nil, cells[0]) + "\n" + cols(w, strings.Repeat(" ", width(indent)+2), widths[1:], cells[1:]...)
	}
	blocks := []string{indent}
	for i, c := range cells {
		cw, pad := w-sum(ws)-width(indent), 0
		if i < len(ws) {
			cw, pad = ws[i], min(2, ws[i]-1)
		}
		blocks = append(blocks, lipgloss.NewStyle().Width(max(1, cw)).PaddingRight(pad).Render(c))
	}
	lines := splitLines(lipgloss.JoinHorizontal(lipgloss.Top, blocks...))
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}

// box draws lines in a rounded frame w wide with its title in the top edge and foot, when given, in the bottom one.
func box(title, foot string, w int, lines ...string) string {
	edge := func(left, text, right string) string {
		if text == "" {
			return " " + dim(left+strings.Repeat("─", w-2)+right)
		}
		return " " + dim(left+"─ ") + text + " " + dim(strings.Repeat("─", max(0, w-5-width(text)))+right)
	}
	out := []string{edge("╭", bold(title), "╮")}
	for _, l := range splitLines(strings.Join(lines, "\n")) {
		out = append(out, " "+dim("│")+" "+pad(truncate(l, w-4), w-4)+" "+dim("│"))
	}
	return strings.Join(append(out, edge("╰", foot, "╯")), "\n")
}

// glyph is a table cell's answer: yes, no, not tested or unresolved. A yes is red where it is a demonstrated problem.
func glyph(s string) string {
	switch s {
	case "yes":
		return redStyle.Render("✓")
	case "no":
		return dim("✗")
	case "?":
		return yellowStyle.Render("?")
	}
	return dim("-")
}

// under centres a one-column cell under its column's header.
func under(head, cell string) string { return strings.Repeat(" ", (width(head)-1)/2) + cell }

// elapsed prints seconds as M:SS, or H:MM:SS from an hour.
func elapsed(seconds float64) string {
	s := int(seconds)
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

func dollars(x float64) string { return fmt.Sprintf("$%.2f", x) }

func amber(s string) string { return yellowStyle.Render(s) }

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

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func rewardText(x float64) string {
	s := strconv.FormatFloat(x, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}
