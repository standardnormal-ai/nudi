package main

import (
	"fmt"
	"image/color"
	"slices"
	"strings"
)

// renderShow draws finding n of found with its Evidence tab (0) or Limitations tab (1).
func renderShow(r Report, found []Finding, n, tab, w int) string {
	f := found[n-1]
	body := evidence(f, w)
	if tab == 1 {
		body = limitations(f, w)
	}
	return cut(showHead(r, found, n, w)+"\n\n "+tabs(f, tab)+"\n\n"+body, w)
}

// plainShow is finding n for a pipe: both tabs one after the other, without colour.
func plainShow(r Report, found []Finding, n, w int) string {
	f := found[n-1]
	return plainText(showHead(r, found, n, w) + "\n\n Evidence\n\n" + evidence(f, w) +
		fmt.Sprintf("\n\n Limitations %d\n\n", len(limits(f))) + limitations(f, w))
}

// showHead names the finding: its tag, the job that found it, its id, its mechanism and its check.
// A hack finding also says which problem it belongs to and whether the attack tested it.
func showHead(r Report, found []Finding, n, w int) string {
	f := found[n-1]
	out := []string{
		" " + logo + dim(" › "+r.task()+" › ") + fmt.Sprintf("finding %d of %d", n, len(found)),
		"",
		" " + tag(f) + "  " + open(f) + dim(word(sourceWords, f.Source)+" · "+word(scopeWords, f.ExecutionScope)+" · "+f.ID),
		wrap(title(f), w, " ", bold),
	}
	check := f.check()
	if f.Category != nil {
		check = word(checkNames, *f.Category) + " · " + check
	}
	out = append(out, " "+dim(check))
	if f.Confirms != "" {
		out = append(out, " "+dim(f.Confirms))
	}
	if i := r.problemOf(f.ID); i >= 0 {
		p := r.Attack.Problems[i]
		line := dim(fmt.Sprintf("problem %d of %d · ", i+1, len(r.Attack.Problems)))
		if p.ID != "" {
			line = bold(p.ID) + dim(" · ")
		}
		switch {
		case p.Candidate == nil:
			line += dim("no finding selected, not tested")
		case *p.Candidate == f.ID:
			line += dim("this finding ") + problemMarks(r, p, f.ID)
		default:
			line += dim("the attack tests " + names(found, []string{*p.Candidate})[0] + " for it")
			if marks := problemMarks(r, p, f.ID); marks != "" {
				line += " " + marks
			}
		}
		out = append(out, " "+line, wrap(p.Cause, w, " ", dim))
	}
	return strings.Join(out, "\n")
}

func tabs(f Finding, tab int) string {
	names := []string{"Evidence", fmt.Sprintf("Limitations %d", len(limits(f)))}
	for i, name := range names {
		if i == tab {
			names[i] = boldStyle.Underline(true).Render(name)
		} else {
			names[i] = dim(name)
		}
	}
	return strings.Join(names, "    ")
}

// evidence is what happened, one marker per step and red where nudi says the grader went wrong,
// then the Inspector's interpretation and its citations.
func evidence(f Finding, w int) string {
	var steps [][]string
	if f.Claim.Episode != "" {
		steps = append(steps, step(violet, "episode", f.Claim.Episode, word(scopeWords, f.ExecutionScope), w))
	}
	if c := f.Captured.Check; c != nil && c.Requirement != nil {
		steps = append(steps, step(violet, "requires", c.Requirement.Excerpt, c.Requirement.Path, w))
	}
	source := "native grader"
	if f.ExecutionScope == "package" {
		source = "copied grader"
	}
	steps = append(steps, step(violet, "reward", num(f.reward())+" from the "+source, "", w))
	for _, reason := range f.Assessment.Reasons {
		steps = append(steps, step(red, "nudi", reason, "", w))
	}
	for _, condition := range f.Claim.Unresolved {
		steps = append(steps, step(yellow, "open", condition, "", w))
	}
	var out []string
	for i, s := range steps {
		if i > 0 {
			out = append(out, " "+dim("│"))
		}
		out = append(out, s...)
	}
	if text := f.Interpretation.Interpretation; text != "" {
		out = append(out, "", " "+bold("Interpretation"), wrap(text, w, "   ", plain))
	}
	if len(f.Interpretation.Citations) > 0 {
		out = append(out, "", " "+bold("Citations"))
		for _, c := range f.Interpretation.Citations {
			out = append(out, wrap(c.Excerpt, w, "   ", plain), "   "+dim(c.Path))
		}
	}
	return strings.Join(out, "\n")
}

// step is one line of the timeline, wrapped, with where it happened at the right edge.
func step(c color.Color, what, text, where string, w int) []string {
	room := max(20, w-15-width(where))
	lines := breakLines(text, room)
	if len(lines) == 0 {
		lines = []string{""}
	}
	out := []string{" " + fg(c, "◆") + " " + dim(pad(what, 10)) + " " + lines[0]}
	if where != "" {
		out[0] = pad(out[0], w-width(where)-1) + dim(where)
	}
	for _, l := range lines[1:] {
		out = append(out, strings.Repeat(" ", 14)+l)
	}
	return out
}

// limits are nudi's limits on the finding, then the Inspector's, each once.
func limits(f Finding) []string {
	var out []string
	for _, l := range append(slices.Clone(f.Assessment.Limits), f.Claim.Limits...) {
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out
}

func limitations(f Finding, w int) string {
	var out []string
	for _, l := range limits(f) {
		out = append(out, " "+yellowStyle.Render("▲")+" "+strings.Join(breakLines(l, w-4), "\n   "))
	}
	if len(out) == 0 {
		return " " + dim("No limitation recorded.")
	}
	return strings.Join(out, "\n\n")
}
