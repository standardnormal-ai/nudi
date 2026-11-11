package main

import (
	"cmp"
	"fmt"
	"image/color"
	"slices"
	"strconv"
	"strings"
)

// showTabs name the tabs of a finding: its evidence, its limitations with their count, and its references.
func showTabs(f Finding) []string {
	return []string{"Evidence", fmt.Sprintf("Limitations %d", len(filled(f.Claim.Unresolved))+len(limits(f))), "References"}
}

// renderShow draws finding n of found under the tab it was opened from, with its tab on view: 0 Evidence,
// 1 Limitations or 2 References.
func renderShow(r Report, found []Finding, n, tab int, from string, w int) string {
	return cut(showHead(r, found, n, from, w)+"\n\n"+tabs(found[n-1], tab, w)+"\n\n"+showTab(r, found, n, tab, w), w)
}

// plainShow is finding n for a pipe: its head, then each tab under its name, without colour.
func plainShow(r Report, found []Finding, n, w int) string {
	out := showHead(r, found, n, "Results", w)
	for i, name := range showTabs(found[n-1]) {
		out += "\n\n " + strings.ToUpper(name) + "\n\n" + showTab(r, found, n, i, w)
	}
	return plainText(out)
}

func showTab(r Report, found []Finding, n, tab, w int) string {
	switch tab {
	case 1:
		return limitations(found[n-1], w)
	case 2:
		return referencesTab(r, found, n, w)
	}
	return evidence(found[n-1], w)
}

// showHead names the finding after the tab it was opened from, with its problem's reference on the right, then its
// full type and who found it, its problem, where its evidence comes from and what an Attacker made of it.
func showHead(r Report, found []Finding, n int, from string, w int) string {
	f := found[n-1]
	p := findingProblem(r, f)
	right := ref(f)
	problem := "None"
	if p != nil {
		right, problem = p.ID, p.ID
		if p.ID == "" {
			right, problem = ref(f), fmt.Sprintf("Problem %d of %d", slices.IndexFunc(r.Attack.Problems, func(x Problem) bool { return x.Cause == p.Cause })+1, len(r.Attack.Problems))
		}
	}
	name := detailName(r, f)
	crumb := " " + dim(from+" › ")
	var out []string
	if one := crumb + bold(name); width(one)+width(right)+3 <= w {
		out = append(out, spread(one, dim(right), w))
	} else {
		out = append(out, spread(crumb, dim(right), w), wrap(name, w, " ", bold))
	}
	out = append(out, wrap(typeNames[findingType(f)], w, " ", func(s string) string { return redStyle.Render(s) }), "")
	where := cmp.Or(strings.TrimSpace(capital(word(scopeWords, f.ExecutionScope))+" "+f.Claim.Episode), "Not recorded")
	pairs := [][2]string{{"Found by", jobNames[f.Source]}, {"Problem", problem}, {"Evidence from", where}, {"Attacker result", attackerResult(r, p)}}
	if w >= 100 {
		widths := []int{18, 24, 19}
		out = append(out, cols(w, " ", widths, dim(pairs[0][0]), pairs[0][1], dim(pairs[2][0]), pairs[2][1]),
			cols(w, " ", widths, dim(pairs[1][0]), pairs[1][1], dim(pairs[3][0]), pairs[3][1]))
	} else {
		for _, kv := range pairs {
			out = append(out, cols(w, " ", []int{18}, dim(kv[0]), kv[1]))
		}
	}
	if name != title(f) && title(f) != "" {
		out = append(out, cols(w, " ", []int{18}, dim("Mechanism"), title(f)))
	}
	if f.Confirms != "" {
		out = append(out, cols(w, " ", []int{18}, dim("Attacker exploit"), capital(f.Confirms)))
	}
	return strings.Join(out, "\n")
}

// detailName names a finding in its detail: the cause of the problem that holds it, else its own mechanism, which
// the detail then shows on a line of its own.
func detailName(r Report, f Finding) string {
	if p := findingProblem(r, f); p != nil && strings.TrimSpace(p.Cause) != "" {
		return strings.Join(strings.Fields(p.Cause), " ")
	}
	return title(f)
}

// typeNames give each kind of wrong grader decision its full name.
var typeNames = map[string]string{
	"False positive": "False positive: incorrect work passed",
	"False negative": "False negative: correct work was rejected",
	"Hack":           "Hack: the reward was earned without doing the task",
	"Unavailable":    "Unavailable: the report records no outcome for it",
}

// findingProblem is the problem that holds finding f, or that an Attacker's finding demonstrated; nil for none.
func findingProblem(r Report, f Finding) *Problem {
	if r.Attack == nil {
		return nil
	}
	for i, p := range r.Attack.Problems {
		if f.Source != "attack" && slices.Contains(p.Findings, f.ID) || f.Source == "attack" && r.demonstrates(f, p) {
			return &r.Attack.Problems[i]
		}
	}
	return nil
}

// attackerResult is the least an Attacker was told when it reproduced problem p, else what its tries settled.
func attackerResult(r Report, p *Problem) string {
	if p == nil {
		return "Not tested"
	}
	for _, level := range []string{"none", "minimal", "full"} {
		if r.tried(*p, level) == "yes" {
			return strings.TrimSuffix("Reproduced with "+levelWords[level]+" while aimed at "+r.aimedElsewhere(*p), " while aimed at ")
		}
	}
	switch best(r.tried(*p, "none"), r.tried(*p, "minimal"), r.tried(*p, "full")) {
	case "no":
		return "Not reproduced"
	case "?":
		return "Unresolved"
	}
	return "Not tested"
}

// tabs is the finding's tab strip, the tab on view underlined, over a rule.
func tabs(f Finding, tab, w int) string {
	names := showTabs(f)
	for i, name := range names {
		if i == tab {
			names[i] = boldStyle.Underline(true).Render(name)
		} else {
			names[i] = dim(name)
		}
	}
	return " " + strings.Join(names, "    ") + "\n " + dim(strings.Repeat("─", max(0, w-2)))
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
		out = append(out, "", heading("INTERPRETATION", ""), wrap(cmp.Or(writers[f.Source], "The Inspector")+" wrote: \""+text+"\"", w, " ", plain))
	}
	if len(f.Interpretation.Citations) > 0 {
		out = append(out, "", heading("CITATIONS", ""))
		for _, c := range f.Interpretation.Citations {
			out = append(out, wrap(c.Excerpt, w, " ", plain), " "+dim(c.Path))
		}
	}
	return strings.Join(out, "\n")
}

// writers name who wrote a finding's interpretation, by its source.
var writers = map[string]string{"grader_inspector": "The Grader Inspector", "hack_inspector": "The Hack Inspector", "attack": "The Attack Inspector"}

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
	for _, l := range filled(append(slices.Clone(f.Assessment.Limits), f.Claim.Limits...)) {
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out
}

// filled are the entries of xs that are not blank.
func filled(xs []string) []string {
	return slices.DeleteFunc(slices.Clone(xs), func(s string) bool { return strings.TrimSpace(s) == "" })
}

// limitations are the finding's open conditions, then its scope limits, numbered on through both, each under a
// short heading.
func limitations(f Finding, w int) string {
	var out []string
	n := 0
	for _, part := range []struct {
		name  string
		items []string
	}{{"OPEN CONDITIONS", filled(f.Claim.Unresolved)}, {"SCOPE LIMITS", limits(f)}} {
		if len(part.items) == 0 {
			continue
		}
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, titled(part.name, len(part.items)))
		for _, l := range part.items {
			n++
			head, body := limitHeading(l)
			lines := splitLines(wrap(head, w, "    ", bold))
			lines[0] = " " + pad(strconv.Itoa(n), 3) + lines[0][4:]
			out = append(out, lines...)
			if body != "" {
				out = append(out, wrap(body, w, "    ", plain))
			}
		}
	}
	if len(out) == 0 {
		return " " + dim("No limitation recorded.")
	}
	return strings.Join(out, "\n")
}

// limitHeadings name the limits nudi writes, by how their text starts.
var limitHeadings = [][2]string{
	{"the captured program, inputs and measured facts", "nudi checks the evidence, not the task's intent"},
	{"the check ran with the episode's own interpreter", "The check used the episode's own interpreter"},
	{"the copy omits", "Part of the episode was not copied"},
	{"processes were paused", "The episode was paused before grading"},
	{"Startup code can remove", "The planted state was not seen again"},
	{"Survival of planted bytes", "Surviving files alone are not a hack"},
}

// limitHeading splits a limit into a short heading and the rest: a known limit's heading over its whole text, the
// words before a colon over the words after it, or the limit alone.
func limitHeading(l string) (head, body string) {
	for _, h := range limitHeadings {
		if strings.HasPrefix(l, h[0]) {
			return h[1], capital(l)
		}
	}
	if i := strings.Index(l, ": "); i > 0 && i <= 40 {
		return capital(l[:i]), capital(l[i+2:])
	}
	return capital(l), ""
}

// referencesTab names every reference of the finding with what it is, and the command that opens it again.
func referencesTab(r Report, found []Finding, n, w int) string {
	f := found[n-1]
	widths := []int{18, 36}
	row := func(a, b, c string) string { return cols(w, " ", widths, a, b, dim(c)) }
	out := []string{row(dim("Reference"), dim("Value"), "What it is")}
	again := strconv.Itoa(n)
	if p := findingProblem(r, f); p != nil && p.ID != "" {
		what := "A problem: the findings that share one cause"
		if i := strings.Index("PGA", p.ID[:1]); i >= 0 {
			what = references[i][1]
		}
		out = append(out, row("Problem", p.ID, what))
		if evidenceOf(found, *p) == n {
			again = p.ID
		}
	}
	if f.Source != "attack" {
		out = append(out, row("Finding", f.ID, "The "+jobNames[f.Source]+"'s evidence record"))
	}
	if f.Experiment != "" {
		out = append(out, row("Experiment", f.Experiment, "The idea the "+jobNames[f.Source]+" tested"))
	}
	if c := f.Captured.Check; c != nil {
		out = append(out, row("Check", c.ID, "nudi's rerun of the evidence"))
	}
	if e := f.Claim.Episode; e != "" {
		what := "Inspector sandbox that ran a copy of the task"
		switch {
		case strings.HasSuffix(e, "-simulator"):
			what = "Simulator episode where it appeared"
		case strings.HasSuffix(e, "-attacker"):
			what = "Attacker session that showed it"
		}
		out = append(out, row("Episode", e, what))
	}
	if p := findingProblem(r, f); p != nil {
		for _, at := range r.aimed(*p) {
			if at.Episode != nil && *at.Episode != f.Claim.Episode {
				out = append(out, row("Attempt", *at.Episode, fmt.Sprintf("Attacker try %d, %s", at.Number, levelWords[at.Level])))
			}
		}
	}
	return strings.Join(append(out, "", cols(w, " ", widths, dim("Open it again"), "nudi-view "+r.Dir+" "+again)), "\n")
}
