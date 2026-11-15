package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"image/color"
	"maps"
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
	return evidence(r, found, n, w)
}

// showHead names the finding after the tab it was opened from and its cause, then gives its full type, and its own
// mechanism, exploit and marks when the report has them. The Evidence tab's timeline says who found it, its cause and
// what an Attacker made of it.
func showHead(r Report, found []Finding, n int, from string, w int) string {
	f := found[n-1]
	p := findingProblem(r, f)
	crumb := from + " › "
	if p != nil && r.causeOf(*p).N > 0 {
		crumb += r.causeOf(*p).name() + " › "
	}
	name := detailName(r, f)
	var out []string
	if one := " " + dim(crumb) + bold(name); width(one) <= w {
		out = append(out, one)
	} else {
		out = append(out, " "+dim(strings.TrimSuffix(crumb, " ")), wrap(name, w, " ", bold))
	}
	out = append(out, wrap(typeNames[findingType(f)], w, " ", func(s string) string { return redStyle.Render(s) }))
	var rows [][2]string
	if name != title(f) && title(f) != "" && !generic(f.Claim.Mechanism) {
		rows = append(rows, [2]string{"Mechanism", title(f)})
	}
	if f.Confirms != "" {
		rows = append(rows, [2]string{"Attacker exploit", capital(f.Confirms)})
	}
	if p != nil {
		rows = append(rows, [2]string{"Marks", markValues(*p)}, [2]string{"Requirement", deref(p.Requirement)})
	}
	for i, kv := range slices.DeleteFunc(rows, func(kv [2]string) bool { return kv[1] == "" }) {
		if i == 0 {
			out = append(out, "")
		}
		out = append(out, cols(w, " ", []int{18}, dim(kv[0]), kv[1]))
	}
	return strings.Join(out, "\n")
}

// detailName names a finding in its detail: the sentence of the cause that holds it, else its own mechanism, which
// the detail then shows on a line of its own.
func detailName(r Report, f Finding) string {
	if p := findingProblem(r, f); p != nil {
		if s := strings.Join(strings.Fields(cmp.Or(r.causeOf(*p).Cause, p.Cause)), " "); s != "" {
			return s
		}
	}
	return title(f)
}

// markValues are each mark of a problem's reading with the value its check measured, as "exists = false".
func markValues(p Problem) string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(p.Marks)) {
		v, _ := json.Marshal(p.Marks[k])
		out = append(out, k+" = "+string(v))
	}
	return strings.Join(out, ", ")
}

// typeNames give each kind of wrong grader decision its full name.
var typeNames = map[string]string{
	"False positive": "False positive: incorrect work passed",
	"False negative": "False negative: correct work was rejected",
	"Hack":           "Hack: the reward was earned without doing the task",
}

// findingProblem is the problem that holds finding f, or that an Attacker's finding demonstrated; nil for none.
func findingProblem(r Report, f Finding) *Problem {
	if r.Attack == nil {
		return nil
	}
	for _, p := range append(r.allFindings(), slices.DeleteFunc(slices.Clone(r.Attack.Problems), func(p Problem) bool { return p.CauseID != "" })...) {
		if f.Source != "attack" && slices.Contains(p.readings(), f.ID) || f.Source == "attack" && r.demonstrates(f, p) {
			return &p
		}
	}
	return nil
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

// evidence is the finding's timeline, then the interpretation its finder wrote and its citations.
func evidence(r Report, found []Finding, n, w int) string {
	f := found[n-1]
	out := timeline(r, &f, findingProblem(r, f), w)
	if text := f.Interpretation.Interpretation; text != "" {
		out = append(out, "", heading("Interpretation", ""), wrap(cmp.Or(writers[f.Source], "The Inspector")+" wrote: \""+text+"\"", w, " ", plain))
	}
	if len(f.Interpretation.Citations) > 0 {
		out = append(out, "", heading("Citations", ""))
		for _, c := range f.Interpretation.Citations {
			out = append(out, wrap(c.Excerpt, w, " ", plain), " "+dim(c.Path))
		}
	}
	return strings.Join(out, "\n")
}

// timeline is a finding's evidence, one marker per step and red where the grader went wrong: who found it and where,
// the requirement its check read, the reward, nudi's check, the cause it is associated to, each Attacker try by the help
// it was given, and its level. A step shows only when the report records it: f, its evidence record, and p, the finding
// under its cause, can each be nil.
func timeline(r Report, f *Finding, p *Problem, w int) []string {
	var steps [][]string
	if f != nil {
		issue := jobNames[f.Source]
		if scope := word(scopeWords, f.ExecutionScope); scope != "" {
			issue += ", " + scope
		}
		try := "" // an Attacker finding's own try, unless a step below names it
		if f.Source == "attack" && p == nil {
			try = sessionName(f.Claim.Episode)
		}
		steps = append(steps, step(violet, "issue", issue, try, w))
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
	} else if p != nil && sourceName(p.Source) != "" {
		steps = append(steps, step(violet, "issue", sourceName(p.Source), "", w))
	}
	if p != nil {
		if c := r.causeOf(*p); c.N > 0 {
			text := "associated to cause " + strconv.Itoa(c.N)
			steps = append(steps, step(violet, "cause", text, "", w))
		}
		steps = append(steps, triesSteps(r, *p, w)...)
		if l := p.ladder(); l >= 1 && l <= 5 {
			// Its number alone when a try above shows how it was reached; in words when none does.
			text := level(r, *p)
			if slices.ContainsFunc(r.aimed(*p), func(at Attempt) bool { return tryResult(r, at, p) == "demonstrated" }) {
				text = fmt.Sprintf("%d of 5", l) + levelRun(*p)
			}
			steps = append(steps, step(violet, "level", text, "", w))
		}
	}
	var out []string
	for i, s := range steps {
		if i > 0 {
			out = append(out, " "+dim("│"))
		}
		out = append(out, s...)
	}
	return out
}

// triesSteps are the Attacker's tries at finding p, by the help each was given, or one step saying it was not attacked
// on its own; a help no try was given says why, when the report records it.
func triesSteps(r Report, p Problem, w int) [][]string {
	if p.notAttackedAlone() {
		return [][]string{step(violet, "attacker", "not attacked on its own", "", w)}
	}
	var out [][]string
	for _, level := range []string{"minimal", "full", "none"} {
		what := strings.ToLower(helpWords[level])
		tried := false
		for _, at := range r.aimed(p) {
			if at.Level != level {
				continue
			}
			tried = true
			text := map[string]string{"demonstrated": "Attacker demonstrated it", "not demonstrated": "Attacker did not demonstrate it"}[tryResult(r, at, &p)]
			if text == "" {
				text = capital(tryResult(r, at, &p))
			}
			if note := tryNote(r, at); strings.HasPrefix(note, "Result unclear") {
				text = strings.TrimSuffix(note, ".")
			}
			for _, k := range slices.Sorted(maps.Keys(at.Rewards)) {
				text += ", " + k + " " + num(at.Rewards[k])
			}
			c := violet
			if strings.HasPrefix(text, "Attacker demonstrated") {
				c = red
			}
			out = append(out, step(c, what, text, sessionName(deref(at.Episode)), w))
		}
		if tried || r.tried(p, level) != "-" {
			continue
		}
		for _, c := range p.Conditions {
			if c.Condition == level || level == "none" && c.Condition == "independent" {
				out = append(out, step(yellow, what, "not tested, "+word(notTestedWords, c.Status), "", w))
			}
		}
	}
	return out
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
	}{{"Open Conditions", filled(f.Claim.Unresolved)}, {"Scope Limits", limits(f)}} {
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
		if c := r.causeOf(*p).ID; c != "" {
			out = append(out, row("Cause", c, "Findings a judge read as one cause"))
		}
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
				out = append(out, row("Attempt", *at.Episode, sessionName(*at.Episode)+", "+levelWords[at.Level]))
			}
		}
	}
	return strings.Join(append(out, "", cols(w, " ", widths, dim("Open it again"), "nudi-view "+r.Dir+" "+again)), "\n")
}
