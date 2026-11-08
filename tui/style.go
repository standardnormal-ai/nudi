package main

import (
	"image/color"
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

	phaseColors = [...]color.Color{teal, blue, violet, coral, green}

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

func tag(f Finding) string { return redStyle.Bold(true).Render(pad(kind(f), 14)) }

// title is the finding's mechanism, in the Inspector's words, on one line.
func title(f Finding) string { return strings.Join(strings.Fields(f.Claim.Mechanism), " ") }

// open marks a finding that has open conditions; it is still evidenced.
func open(f Finding) string {
	if len(f.Claim.Unresolved) > 0 {
		return yellowStyle.Render("▲") + " "
	}
	return ""
}

// findingLine is the finding's tag, then what an attack finding confirmed, then its mechanism.
func findingLine(f Finding) string {
	confirms := ""
	if f.Confirms != "" {
		confirms = dim(f.Confirms + " · ")
	}
	return tag(f) + "  " + open(f) + confirms + title(f)
}

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
