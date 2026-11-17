package main

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
)

// page collects one screen's lines and its selectable rows, so the viewer can move a cursor over them.
type page struct {
	w     int
	sel   int             // the selected row, or -1 for none
	open  map[string]bool // the rows and sections expanded
	lines []string
	items []item
}

// item is one selectable row: Enter opens finding n, or else expands key.
type item struct {
	line int
	n    int
	key  string
}

func (p *page) add(s ...string) {
	for _, x := range s {
		p.lines = append(p.lines, splitLines(x)...)
	}
}

// pick adds a selectable row, drawn after its mark: a cursor when it is the selected row.
func (p *page) pick(n int, key string, draw func(mark string, on bool) string) {
	on := len(p.items) == p.sel
	mark := "   "
	if on {
		mark = " " + fg(teal, "›") + " "
	}
	p.items = append(p.items, item{len(p.lines), n, key})
	p.add(draw(mark, on))
}

// toggle is the line of a collapsed section: its title, its count and the key that expands it.
func (p *page) toggle(key, name, note string) bool {
	arrow := map[bool]string{true: "▾", false: "▸"}[p.open[key]]
	head, right := " "+dim(arrow)+" "+bold(name), p.fold(key)
	if note == "" {
		p.add(spread(head, right, p.w))
	} else if width(head)+1+width(note)+width(right)+3 <= p.w {
		p.add(spread(head+" "+dim(note), right, p.w))
	} else {
		p.add(spread(head, right, p.w), wrap(note, p.w, "   ", dim))
	}
	return p.open[key]
}

// fold is the key hint on a header that opens what explains it.
func (p *page) fold(key string) string {
	return keyText(key) + " " + dim(map[bool]string{true: "collapse", false: "expand"}[p.open[key]])
}

// symbols is the legend of the answer cells.
var symbols = " " + dim("✓ yes   ✗ no   - not tested   ? unresolved")

func (p *page) String() string { return strings.Join(p.lines, "\n") }

// resultsPage is the Results tab: how the run ended, the problems, the other findings, what the references mean,
// the rewards beside grader accuracy, the work left and the cost.
func resultsPage(r Report, found []Finding, p *page) {
	p.add(ending(r, found, p.w)...)
	p.add("")
	if r.Attack != nil && r.Attack.Problems != nil {
		causesTable(r, found, p)
	} else {
		findingsTable(found, "", p)
	}
	p.add("")
	if others, opens := otherFindings(r); len(others) > 0 && p.toggle("o", "Abandoned Findings", "") {
		// An evidenced finding on the list opens with Enter, and its references are on its screen; a row with no detail
		// keeps its reference, in a Ref column only when there is such a row.
		heads := []string{dim("Finding"), dim("State"), dim("Found by"), dim("Ref")}
		if !slices.Contains(opens, 0) {
			heads = heads[:3]
		}
		state, by := 21, 18
		if p.w < 80 {
			state, by = 18, 18
		}
		widths := []int{max(12, p.w-3-state-by-10*boolInt(len(heads) == 4)), state, by}
		name := fit(p.w, "   ", widths[:len(heads)-1])[0] - 2
		p.add(cols(p.w, "   ", widths, heads...))
		for i, o := range others {
			row := []string{clip(o[0], name), o[1], o[2], dim(sessionName(o[3]))}
			if n := opens[i]; n > 0 {
				row[3] = ""
				p.pick(n, "", func(mark string, _ bool) string { return cols(p.w, mark, widths, row[:len(heads)]...) })
			} else {
				p.add(cols(p.w, "   ", widths, row[:len(heads)]...))
			}
		}
		p.add(wrap("Suspected findings that didn't have enough evidence", p.w, "   ", dim))
	}
	if p.toggle("i", "What the References Mean", "") {
		widths := []int{17, 62}
		p.add(cols(p.w, "   ", widths, dim("Reference"), dim("What it names"), dim("Example")))
		for _, x := range references {
			p.add(cols(p.w, "   ", widths, fg(teal, x[0]), x[1], dim(x[2])))
		}
		p.add(wrap("A cause groups the findings a judge model read as sharing one. References never change between views.", p.w, "   ", dim))
	}
	p.add("")
	left, right := rewardsSummary(r, p.w), accuracySummary(r, p.w)
	if p.w >= 100 {
		p.add(lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(49).Render(left), right))
	} else {
		p.add(left, "", right)
	}
	p.add("")
	rows := workLeft(r, found)
	p.add(titled("Work Left", len(rows)))
	if len(rows) == 0 {
		p.add(" " + dim("None recorded."))
	} else {
		widths := []int{19, 38}
		p.add(cols(p.w, " ", widths, dim("Where"), dim("What"), dim("Why")))
		for _, row := range rows {
			p.add(cols(p.w, " ", widths, row[0], row[1], yellowStyle.Render(row[2])))
		}
	}
	p.add("", heading("Cost", ""))
	p.add(costRows(r, p.w, false)...)
}

// references say what each kind of reference on the screens names, with an example.
var references = [][3]string{
	{"C", "Cause: the findings a judge model read as sharing one", "C1"},
	{"P", "Cause of an older report, found by the Hack Inspector's search", "P1"},
	{"G", "Cause of an older report, found by the Grader Inspector in the simulations", "G1"},
	{"A", "Finding of an Attacker alone", "A1"},
	{"hack-N", "Finding: an evidence record of the Hack Inspector", "hack-1"},
	{"grader-N", "Finding: an evidence record of the Grader Inspector", "grader-7"},
	{"experiment-N", "One idea the Hack Inspector tested", "experiment-0002"},
	{"check-N", "nudi's rerun that confirmed a finding", "check-0003"},
	{"NNNN-attacker", "One Attacker session", "0007-attacker"},
	{"NNNN-simulator", "One Simulator episode", "0004-simulator"},
}

// errorLine is an error's first line up to any structured payload a provider appended, such as " - {...}", which
// stays in report.json.
func errorLine(s string) string {
	s = strings.SplitN(s, "\n", 2)[0]
	if i := strings.Index(s, " - {"); i >= 0 {
		s = s[:i]
	}
	return s
}

// ending is how the run ended, with its time or cost, the count of problems on the right, and the verdict under it
// as Python wrote it. A failed phase names its error; a stop says that the results come from before it.
func ending(r Report, found []Finding, w int) []string {
	head, notes := endingParts(r)
	right := tally(r, found)
	out := []string{spread(" "+head, right, w)}
	// A finished run that lost some of its work warns of it beside the count, or on a line of its own when that does
	// not fit; Work Left says what was lost.
	if lost := lostWork(r); lost != "" {
		warn := yellowStyle.Render("! " + lost)
		if width(head)+width(warn)+width(right)+7 <= w {
			out[0] = spread(" "+head, warn+strings.Repeat(" ", 3*boolInt(right != ""))+right, w)
		} else {
			out = append(out, wrap("! "+lost, w, " ", amber))
		}
	}
	for _, note := range notes {
		out = append(out, wrap(note, w, " ", plain))
	}
	return out
}

// endingParts are the ending's headline, with its time or cost beside it, and the lines under it.
func endingParts(r Report) (string, []string) {
	clock := ""
	if r.Elapsed != nil {
		clock = elapsed(*r.Elapsed)
	}
	var head, beside string
	var notes []string
	failed := slices.DeleteFunc(slices.Clone(phases), func(p struct{ Name, Analysis string }) bool { return r.PhaseErrors[p.Analysis] == "" })
	amber, verdict := yellowStyle, r.verdict()
	var errs []string
	for _, p := range failed {
		errs = append(errs, redStyle.Render("Error")+"  "+errorLine(r.PhaseErrors[p.Analysis]), failedNote(r, p.Name, p.Analysis))
	}
	switch {
	case r.Stop != nil: // a stop ends the run even after a phase failed; the failure stays a note
		words, _ := lookup(stopWords, r.Stop.Kind)
		head, notes = amber.Render(words[0]), append(errs, verdict, words[1])
		switch c := r.Configuration; r.Stop.Kind {
		case "time_limit":
			beside = clock
			if r.Stop.Minutes != nil && clock != "" {
				beside += " of " + elapsed(*r.Stop.Minutes*60)
			}
		case "spending_cap":
			if c.KnownCost != nil && c.SpendingCap != nil {
				beside = dollars(*c.KnownCost) + " of " + dollars(*c.SpendingCap)
			}
		case "stopped":
			notes = append(append([]string{words[1], r.Stop.Reason}, errs...), verdict, dim("If it is still going:")+"  nudi-view --follow "+r.Dir)
		case "provider_refused":
			notes = append([]string{capital(strings.TrimSuffix(r.Stop.Reason, ".")) + "."}, notes...)
			fallthrough
		default:
			if clock != "" {
				beside = "at " + clock
			}
		}
	case len(failed) > 0:
		head, notes = redStyle.Render(failed[0].Name+" failed"), append(errs, verdict)
	case strings.HasPrefix(r.Answer[0], "Could not start"):
		head, notes = amber.Render("Could not start"), []string{strings.TrimPrefix(r.Answer[0], "Could not start: ")}
	case lostWork(r) != "": // its work ended, but some was lost: the warning beside it says what
		head, notes = greenStyle.Render("Finished"), []string{verdict}
		if clock != "" {
			beside = "after " + clock
		}
	case r.Status == "complete":
		head, notes = greenStyle.Render("✓ Finished"), []string{verdict}
		if clock != "" {
			beside = "after " + clock
		}
	case r.Status == "time_limit":
		head, notes = amber.Render("Stopped at the time limit"), []string{verdict, stopWords["time_limit"][1]}
	default:
		head, notes = amber.Render("Stopped"), []string{verdict}
	}
	if beside != "" {
		head += "  " + dim(beside)
	}
	return head, slices.DeleteFunc(notes, func(s string) bool { return s == "" })
}

// lostWork says what failed, and where, in a finished run whose Answer says work was lost or in an unfinished run, whose
// work ended with some of it lost, as "Find Hacks: 1 search failed"; "" for any other run. It counts the failures the Answer's first line names: an inspector session that failed with
// its experiment's error is that experiment's search, and an evidence copy belongs to no phase.
func lostWork(r Report) string {
	failed := slices.ContainsFunc(slices.Collect(maps.Values(r.PhaseErrors)), func(e string) bool { return e != "" })
	if r.Stop != nil || failed || strings.HasPrefix(r.Answer[0], "Could not start") ||
		r.Status != "unfinished" && !(r.Status == "complete" && strings.HasPrefix(r.Answer[0], "Finished, but ")) {
		return ""
	}
	var out []string
	count := func(where string, n int, one, many string) {
		if n > 0 {
			out = append(out, fmt.Sprintf("%s: %d %s", where, n, map[bool]string{true: one, false: many}[n == 1]))
		}
	}
	if o := r.Ordinary; o != nil {
		count(phases[0].Name, len(o.NoReward), "episode without a reward", "episodes without a reward")
	}
	for i, source := range []string{"grader_inspector", "hack_inspector"} {
		in := r.Inspections[source]
		if in == nil {
			continue
		}
		searches, lost := 0, map[string]bool{}
		for _, ex := range in.Experiments {
			if attemptResults[ex.Status] == Failed {
				searches, lost[ex.Error] = searches+1, true
			}
		}
		for _, at := range in.Attempts {
			if attemptResults[at.Status] == Failed && !lost[at.Error] {
				searches++
			}
		}
		count(phases[i+1].Name, searches, "search failed", "searches failed")
	}
	if r.Attack != nil {
		n := 0
		for _, at := range r.Attack.Attempts {
			n += boolInt(attemptResults[at.Status] == Failed)
		}
		count(phases[3].Name, n, "try failed", "tries failed")
	}
	copies := 0
	for _, c := range r.Copies {
		copies += boolInt(c.Error != nil)
	}
	if copies > 0 {
		out = append(out, fmt.Sprintf("%d evidence %s failed", copies, map[bool]string{true: "copy", false: "copies"}[copies == 1]))
	}
	if len(out) == 0 { // the Answer names lost work that no listed record shows
		return "Some work was lost"
	}
	return strings.Join(out, "; ")
}

// causeWords are the Answer's sentence over its causes, which says what kind of claim a cause is, or "": the line before
// the first that starts with a cause's id, after the verdict. The cause lines repeat the cause rows, so no screen shows them.
func (r Report) causeWords() string {
	i := slices.IndexFunc(r.Answer, func(s string) bool {
		return slices.ContainsFunc(r.Causes, func(c Cause) bool {
			return c.ID != "" && (strings.HasPrefix(s, c.ID+": ") || strings.HasPrefix(s, c.ID+", "))
		})
	})
	if i < 3 || r.Answer[i-1] == r.verdict() {
		return ""
	}
	return r.Answer[i-1]
}

// verdict is Python's verdict line: the answer's second line after a headline, or its first in reports from before headlines.
// Python's line for a run that evidenced nothing reads as the plan's words.
func (r Report) verdict() string {
	line := r.Answer[0]
	for _, prefix := range []string{"Finished", "Stopped", "Could not start"} {
		if strings.HasPrefix(r.Answer[0], prefix) {
			line = ""
			if len(r.Answer) > 1 {
				line = r.Answer[1]
			}
		}
	}
	if line == "No cheat and no misjudged work was evidenced." {
		return "No cause demonstrated in this run."
	}
	return line
}

// tally is the count on the right of the ending: the causes, or the evidenced findings of a report without
// problems, else the open questions.
func tally(r Report, found []Finding) string {
	n, noun := len(found), "evidenced finding"
	if r.Attack != nil && r.Attack.Problems != nil {
		n, noun = len(r.Causes), "cause"
	}
	if n > 0 {
		return redStyle.Render(fmt.Sprintf("%d %s%s", n, noun, plural(n)))
	}
	if q := len(openQuestions(r, "grader_inspector")) + len(openQuestions(r, "hack_inspector")); q > 0 {
		return yellowStyle.Render(fmt.Sprintf("%d open question%s", q, plural(q)))
	}
	return ""
}

// problems are the report's problems that are no lead, highest on the exploit chart first.
func problems(r Report) []Problem {
	ps := slices.DeleteFunc(slices.Clone(r.Attack.Problems), Problem.lead)
	slices.SortStableFunc(ps, byRung)
	return ps
}

// problemType is the kind of wrong grader decision the report records for a problem, or "" when it records none.
func problemType(p Problem) string { return typeWords[deref(p.Type)] }

var typeWords = map[string]string{"hack": "Hack", "false_positive": "False positive", "false_negative": "False negative"}

// resultType is what a problem's reading measured the grader do: the report's type when it records one, else its
// outcome, an Attacker's exploit being incorrect work passed; "" when neither is recorded.
func resultType(p Problem) string {
	switch {
	case problemType(p) != "":
		return problemType(p)
	case p.Outcome == "rejected_valid":
		return "Correct work failed"
	case p.Outcome == "accepted_invalid" || p.Source == "Attacker":
		return "Incorrect work passed"
	}
	return ""
}

// findingType is the kind of wrong grader decision a finding shows, by its tag.
func findingType(f Finding) string {
	return map[string]string{"HACK": "Hack", "FP": "False positive", "FN": "False negative"}[kind(f)]
}

var jobNames = map[string]string{"grader_inspector": "Grader Inspector", "hack_inspector": "Hack Inspector", "attack": "Attacker"}

// sessionName is how the screens name an Attacker session, as Try 7 for 0007-attacker; any other reference is kept.
func sessionName(ref string) string {
	if n, ok := strings.CutSuffix(ref, "-attacker"); ok {
		if i, err := strconv.Atoi(n); err == nil {
			return "Try " + strconv.Itoa(i)
		}
	}
	return ref
}

// ref is how the screens refer to a finding: its id, or for an Attacker's finding its session.
func ref(f Finding) string {
	if f.Source == "attack" && f.Claim.Episode != "" {
		return f.Claim.Episode
	}
	return f.ID
}

// conditionNames are the conditions of each column of the problems table: told nothing, a hint, or everything.
var conditionNames = map[string][]string{"none": {"none", "independent"}, "minimal": {"minimal"}, "full": {"full"}}

// tried is whether an Attacker demonstrated p when told as much as level says: yes when one exploited it, no when
// one tried and did not, ? when its tries settled nothing, and - when none was tried. An inspector problem answers
// from its conditions, Python's counts of the attempts given its help; an Attacker problem of schema 2 on, or one
// without conditions, from its attempts.
func (r Report) tried(p Problem, level string) string {
	answer := "-"
	if r.SchemaVersion >= 2 && (p.Source == "Attacker" || p.Conditions == nil) { // any exploit, else any assessed none, else no result
		seen := map[string]bool{}
		for _, at := range r.aimed(p) {
			if at.Level == level && r.started(at) {
				seen[r.succeeded(at, p)] = true
			}
		}
		for _, answer := range []string{"yes", "no", "?"} {
			if seen[answer] {
				return answer
			}
		}
		return "-"
	}
	if p.Conditions != nil {
		for _, c := range p.Conditions {
			switch {
			case !slices.Contains(conditionNames[level], c.Condition):
			case c.Attempts == 0 && c.Unrewarded > 0: // tried, but nudi did not inspect a try the grader paid nothing
				answer = best(answer, "?")
			case c.Attempts == 0:
			case c.Exploited > 0:
				answer = "yes"
			default:
				res, _ := lookup(attemptResults, c.Status)
				// A failed try beside the assessed ones leaves their answer: none of them exploited it.
				answer = best(answer, cmp.Or(answers[res], "no"))
			}
		}
		return answer
	}
	for _, at := range r.aimed(p) {
		if at.Level == level && r.started(at) {
			res, _ := lookup(attemptResults, at.Status)
			answer = best(answer, answers[res])
		}
	}
	return answer
}

// answers are what an attempt that ended so says of its problem; an error or a try not started says nothing.
var answers = map[Result]string{Evidenced: "yes", NoIssue: "no", Unsettled: "?"}

// succeeded is what a started attempt aimed at problem p says of it from schema 2 on: yes for an Attacker problem's
// own attempt or an exploit, no for an assessed attempt without one, ? otherwise, as for an attempt the grader paid
// nothing, which nudi did not inspect, or one whose result is unclear.
func (r Report) succeeded(at Attempt, p Problem) string {
	switch {
	case p.Source == "Attacker", at.Status == "evidenced_issue":
		return "yes"
	case at.Status == "no_evidenced_issue" && at.Assessment != nil:
		return "no"
	}
	return "?"
}

// exploitOf is the attempt of the exploit that attack finding f's reading is, if it is one: an attempt's further
// readings are none.
func (r Report) exploitOf(f Finding) (Attempt, bool) {
	for _, kind := range r.Attack.Exploits {
		for _, e := range kind {
			if e != nil && e.Assessment != nil && f.Index != nil && *e.Assessment == *f.Index && e.Attempt != nil && *e.Attempt >= 0 && *e.Attempt < len(r.Attack.Attempts) {
				return r.Attack.Attempts[*e.Attempt], true
			}
		}
	}
	return Attempt{}, false
}

// best is the strongest of the answers: yes, then unresolved, then no, then not tested.
func best(answers ...string) string {
	rank := map[string]int{"no": 1, "?": 2, "yes": 3}
	out := "-"
	for _, a := range answers {
		if rank[a] > rank[out] {
			out = a
		}
	}
	return out
}

// aimed are the attempts aimed at problem p. From schema 2 on those given its finding's help, or for an Attacker
// problem the attempt of its episode; in older reports those aimed at it by its id, or at one of its findings.
func (r Report) aimed(p Problem) []Attempt {
	if r.Attack == nil {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(r.Attack.Attempts), func(at Attempt) bool { return !r.aimedAt(at, p) })
}

func (r Report) aimedAt(at Attempt, p Problem) bool {
	switch {
	case r.SchemaVersion >= 2 && p.Source == "Attacker":
		return at.Episode != nil && *at.Episode == p.Finding
	case r.SchemaVersion < 2 && p.ID != "" && at.Problem != "":
		return at.Problem == p.ID
	case r.SchemaVersion >= 3 && at.Level == "none": // given no information, so not the problem's help
		return false
	}
	return slices.ContainsFunc(tested(at), func(id string) bool { return slices.Contains(p.readings(), id) })
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

// causeGroups are the causes under the headings of their type, each group in the causes' order: Hacks (Hack or False
// positive), Incorrect Work Passed, Correct Work Rejected (False negative), Correct Work Failed, then Type Unknown for
// a cause whose type is not known or whose findings' types differ. An empty group is left out; with no cause at all,
// the empty Hacks group is the result, and when no cause's type is known the one group is Causes.
func causeGroups(r Report) ([]string, map[string][]Cause) {
	groups := map[string][]Cause{}
	for _, c := range r.Causes {
		name := cmp.Or(map[string]string{"Hack": "Hacks", "False positive": "Hacks", "False negative": "Correct Work Rejected",
			"Incorrect work passed": "Incorrect Work Passed", "Correct work failed": "Correct Work Failed"}[causeType(c.Findings)], "Type Unknown")
		groups[name] = append(groups[name], c)
	}
	names := slices.DeleteFunc([]string{"Hacks", "Incorrect Work Passed", "Correct Work Rejected", "Correct Work Failed", "Type Unknown"},
		func(n string) bool { return len(groups[n]) == 0 })
	switch {
	case len(names) == 0:
		names = []string{"Hacks"}
	case len(names) == 1 && names[0] == "Type Unknown":
		names, groups["Causes"] = []string{"Causes"}, groups["Type Unknown"]
	}
	return names, groups
}

// causesTable lists the causes under the headings of their type, best level first, with the legend of its cells behind
// e. A cause of one finding is that finding's row, which Enter opens; Enter expands a cause of several into its
// findings, and opens a finding.
func causesTable(r Report, found []Finding, p *page) {
	if len(r.Causes) == 0 {
		p.add(titled("Causes", 0), " None demonstrated in this run.")
		return
	}
	// The columns of how much an Attacker was told. A try given no information is aimed at no finding, so none of
	// them is No info; a cause's level says when an Attacker told nothing made it.
	var levels []string
	if len(r.Attack.Attempts) > 0 || slices.ContainsFunc(r.Attack.Problems, func(p Problem) bool { return p.Conditions != nil }) {
		levels = []string{"minimal", "full"}
	}
	refW := width(strconv.Itoa(len(r.Causes))) + 2 // each cause's number
	// The cause sentence takes what the other columns leave.
	widths := []int{refW, max(12, p.w-5-refW-6*len(levels)-7)}
	for range levels {
		widths = append(widths, 6)
	}
	widths = append(widths, 7)
	// cells are a cause's or a finding's text, its Hint and Full and its level.
	cells := func(text string, fs []Problem, level int) []string {
		out := []string{text}
		for _, l := range levels {
			out = append(out, under(helpWords[l], glyph(r.causeTried(fs, l))))
		}
		return append(out, dots(level))
	}
	names, groups := causeGroups(r)
	for i, name := range names {
		// The heading names the type and heads the columns; the first also has the key of the legend.
		heads := []string{titled(name, len(groups[name]))}
		if i == 0 {
			heads[0] += "  " + p.fold("e")
		}
		for _, l := range levels {
			heads = append(heads, dim(helpWords[l]))
		}
		head := cols(p.w, "", append([]int{5 + widths[0] + widths[1]}, widths[2:len(widths)-1]...), append(heads, "")...)
		if i > 0 {
			p.add("", head)
		} else {
			p.add(head)
			if p.open["e"] {
				p.add(symbols)
				if len(levels) > 0 {
					p.add(wrap("Hint, Full: an Attacker, by how much it was told, for the findings attacked on their own.", p.w, " ", dim))
				}
				if words := r.causeWords(); words != "" {
					p.add(wrap(words, p.w, " ", dim))
				}
				p.add("")
			}
		}
		for _, c := range groups[name] {
			causeRows(r, found, c, widths, cells, p)
		}
	}
}

// causeRows are cause c's row under its number, and when it is open its findings, indented: each by its short name on
// one line, with on a dim line why its cells are empty or dim, and its type when it differs from the cause's.
func causeRows(r Report, found []Finding, c Cause, widths []int, cells func(string, []Problem, int) []string, p *page) {
	// Under its sentence, how many findings it has, and why it has no level or how many of them no Attacker attacked on
	// their own; a run without Attacker tries attacked none.
	var notes []string
	if len(c.Findings) > 1 {
		notes = append(notes, fmt.Sprintf("%d findings", len(c.Findings)))
	}
	alone := len(slices.DeleteFunc(slices.Clone(c.Findings), func(f Problem) bool { return !f.notAttackedAlone() }))
	switch {
	case c.Level == 0 && !slices.ContainsFunc(c.Findings, func(f Problem) bool { return !f.ReadAs }):
		notes = append(notes, "no level of its own, only findings associated to it")
	case alone > 0 && len(r.Attack.Attempts) > 0:
		notes = append(notes, fmt.Sprintf("%d not attacked on %s own", alone, map[bool]string{true: "its", false: "their"}[alone == 1]))
	}
	// A folded row keeps its sentence to one line; opening the cause, or for one finding the finding, shows it whole.
	key := "cause " + c.ID
	name := func(indent string) string {
		out := strings.Join(strings.Fields(c.Cause), " ")
		if !p.open[key] || len(c.Findings) == 1 {
			out = clip(out, fit(p.w, indent, widths[:len(widths)-1])[1]-2)
		}
		if len(notes) > 0 {
			out += "\n" + dim(capital(strings.Join(notes, ", ")))
		}
		return out
	}
	if len(c.Findings) == 1 {
		p.pick(evidenceOf(found, c.Findings[0]), "", func(mark string, _ bool) string {
			return cols(p.w, mark+"  ", widths, append([]string{fg(teal, strconv.Itoa(c.N))}, cells(name(mark+"  "), c.Findings, c.Level)...)...)
		})
		return
	}
	p.pick(0, key, func(mark string, _ bool) string {
		arrow := map[bool]string{true: "▾", false: "▸"}[p.open[key]]
		return cols(p.w, mark+dim(arrow)+" ", widths, append([]string{fg(teal, strconv.Itoa(c.N))}, cells(name(mark+dim(arrow)+" "), c.Findings, c.Level)...)...)
	})
	if !p.open[key] {
		return
	}
	inner := append([]int{widths[0], widths[1] - 2}, widths[2:]...)
	room := fit(p.w, "       ", inner[:len(inner)-1])[1] - 2
	for _, f := range c.Findings {
		var why []string
		switch {
		case f.judged():
			why = append(why, "associated to this cause")
		case f.notAttackedAlone() && len(r.Attack.Attempts) > 0: // a run without Attacker tries attacked none
			why = append(why, "not attacked on its own")
		}
		if t := resultType(f); t != "" && t != causeType(c.Findings) {
			why = append(why, t)
		}
		text := clip(shortName(found, f), room)
		if len(why) > 0 {
			text += "\n" + dim(strings.Join(why, ", "))
		}
		row := cells(text, []Problem{f}, f.ladder())
		switch {
		case f.judged(): // its own exploit, made with no information, is its level
			row = append(append([]string{row[0]}, slices.Repeat([]string{""}, len(row)-2)...), dots(5))
		case f.notAttackedAlone(): // its cause's line counts it
			for i := range row {
				row[i] = dim(plainText(row[i]))
			}
		}
		p.pick(evidenceOf(found, f), "", func(mark string, _ bool) string {
			return cols(p.w, "  "+mark+"  ", inner, append([]string{""}, row...)...)
		})
	}
}

// shortName is a finding's name on its row: the label of the category its evidence was found in, else its mechanism.
// A grader category's label only repeats the type heading above it, so the mechanism names such a finding.
func shortName(found []Finding, f Problem) string {
	var category *string
	if n := evidenceOf(found, f); n > 0 {
		if c := deref(found[n-1].Category); c != "accepted_invalid" && c != "rejected_valid" && checkNames[c] != "" {
			return checkNames[c]
		}
		category = found[n-1].Category
	}
	return mechanismName(f.Cause, category)
}

// findingName names finding p by its cause and its short name, as "Cause 3, Hard-codes answers"; a finding no cause
// holds, by its short name alone.
func (r Report) findingName(found []Finding, p Problem) string {
	if c := r.causeOf(p); c.N > 0 {
		return c.name() + ", " + shortName(found, p)
	}
	return shortName(found, p)
}

// generic is whether mechanism only names a category, as older reports wrote it, and is no sentence.
func generic(mechanism string) bool {
	m := strings.Join(strings.Fields(mechanism), " ")
	return mechanismName(m, nil) != m
}

// mechanismName names a finding by its mechanism, the sentence an agent wrote. Older reports can hold only a category
// name there, such as grader_tampering; the label of the finding's category, or of that name, stands in for it.
func mechanismName(mechanism string, category *string) string {
	m := strings.Join(strings.Fields(mechanism), " ")
	key := strings.ReplaceAll(m, " ", "_")
	_, known := checkNames[key]
	_, plural := checkNames[key+"s"]
	if !known && !plural && (strings.Contains(m, " ") || !strings.Contains(m, "_")) {
		return m
	}
	for _, k := range []string{deref(category), key, key + "s"} {
		if checkNames[k] != "" {
			return checkNames[k]
		}
	}
	return capital(strings.ReplaceAll(m, "_", " "))
}

// measured are the findings whose tries say what a cause's cells say: those attacked on their own, not those read as it.
func measured(fs []Problem) []Problem {
	return slices.DeleteFunc(slices.Clone(fs), func(f Problem) bool { return f.judged() || f.notAttackedAlone() })
}

// causeTried is the best answer of the measured findings fs when an Attacker was told as much as level says.
func (r Report) causeTried(fs []Problem, level string) string {
	out := "-"
	for _, f := range measured(fs) {
		out = best(out, r.tried(f, level))
	}
	return out
}

// causeType is what the findings fs show the grader do, each kind once, or "" when none is recorded.
func causeType(fs []Problem) string {
	var types []string
	for _, f := range fs {
		if t := resultType(f); t != "" && !f.ReadAs && !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	if len(types) == 0 && len(fs) == 1 {
		return resultType(fs[0])
	}
	return strings.Join(types, ", ")
}

// dots is a level, 1 to 5, as the list draws it; "" without one.
func dots(level int) string {
	if level < 1 || level > 5 {
		return ""
	}
	return strings.Repeat("●", level) + strings.Repeat("○", 5-level)
}

// unrewarded counts the attempts at a problem that the grader paid nothing, which nudi did not inspect, or "".
func unrewarded(p Problem) string {
	if p.Unrewarded == nil || *p.Unrewarded == 0 {
		return ""
	}
	n := *p.Unrewarded
	return fmt.Sprintf("%d attempt%s got reward 0, so nudi did not inspect %s.", n, plural(n), map[bool]string{true: "it", false: "them"}[n == 1])
}

// demonstrates says whether Attacker finding f demonstrated problem pr, by its own exploit entry: the problem the judge
// named for another mechanism, else the problem its attempt aimed at or was judged to find, else one of the problem's
// findings it reproduced. A finding without an entry, or not attributed, demonstrates none. In reports without exploits,
// it demonstrates only the first problem whose members name its session.
func (r Report) demonstrates(f Finding, pr Problem) bool {
	if r.SchemaVersion >= 2 { // its reading is the exploit of an attempt that counts for pr
		counts := func(at Attempt) bool { return r.aimedAt(at, pr) && r.succeeded(at, pr) == "yes" }
		if at, ok := r.exploitOf(f); ok || r.Attack.Exploits != nil {
			return ok && counts(at)
		}
		return f.Claim.Episode != "" && slices.ContainsFunc(r.Attack.Attempts, func(at Attempt) bool {
			return deref(at.Episode) == f.Claim.Episode && counts(at)
		})
	}
	if r.Attack.Exploits == nil {
		i := slices.IndexFunc(r.Attack.Problems, func(p Problem) bool { return slices.Contains(p.Members, f.Claim.Episode) })
		return f.Claim.Episode != "" && i >= 0 && r.Attack.Problems[i].ID == pr.ID && r.Attack.Problems[i].Cause == pr.Cause
	}
	for kind, exploits := range r.Attack.Exploits {
		for _, e := range exploits {
			if e == nil || e.Assessment == nil || f.Index == nil || *e.Assessment != *f.Index {
				continue
			}
			var at Attempt
			if e.Attempt != nil && *e.Attempt >= 0 && *e.Attempt < len(r.Attack.Attempts) {
				at = r.Attack.Attempts[*e.Attempt]
			}
			switch {
			case kind == "unattributed":
				return false
			case kind == "other":
				return pr.ID != "" && deref(e.Problem) == pr.ID
			case pr.ID != "" && at.Problem != "":
				return at.Problem == pr.ID
			}
			ids := append(slices.Clone(e.Sources), deref(e.Candidate))
			return slices.ContainsFunc(ids, func(id string) bool { return id != "" && slices.Contains(pr.readings(), id) })
		}
	}
	return false
}

// findingsTable lists the evidenced findings of a report without problems, those of source alone when it names one;
// Enter opens one by its number on the whole list.
func findingsTable(found []Finding, source string, p *page) {
	n := 0
	for _, f := range found {
		n += boolInt(source == "" || f.Source == source)
	}
	p.add(titled("Findings", n))
	if n == 0 {
		p.add(" None evidenced in this run.")
		return
	}
	widths := []int{44, 16} // every row opens with Enter, so its reference waits on its screen
	p.add(cols(p.w, "   ", widths, dim("Finding"), dim("Type"), dim("Found by")))
	for i, f := range found {
		if source != "" && f.Source != source {
			continue
		}
		p.pick(i+1, "", func(mark string, on bool) string {
			return cols(p.w, mark, widths, title(f), redStyle.Render(findingType(f)), jobNames[f.Source])
		})
	}
}

// otherFindings are the findings no problem counts: ideas not reproduced, unresolved ones, evidenced findings
// that no problem holds (standalone evidence), suspected exploits, Attacker findings not attributed, and leads. opens gives each row's
// finding number in r.findings(), the one Enter opens, or 0 for a row with no detail.
func otherFindings(r Report) (out [][4]string, opens []int) {
	states := [][2]string{{"legitimate", dim("✗") + " Not reproduced"}, {"inconclusive", yellowStyle.Render("?") + " Unresolved"}}
	read := map[string]bool{} // the inspector and check of each unresolved finding that is also a suspected exploit
	for _, state := range states {
		for _, source := range sources {
			for _, f := range r.section(source)[state[0]] {
				if f.SupersededBy == nil {
					f.Source = source
					if f.Index != nil && source != "attack" {
						f.ID = fmt.Sprintf("%s-%d", strings.TrimSuffix(source, "_inspector"), *f.Index)
					}
					shown := state[1]
					if in := r.Inspections[source]; in != nil && state[0] == "inconclusive" && slices.ContainsFunc(in.Suspected, func(x Suspected) bool { return x.Check == f.check() }) {
						shown, read[source+" "+f.check()] = "Suspected exploit", true
					}
					out, opens = append(out, [4]string{title(f), shown, jobNames[source], ref(f)}), append(opens, 0)
				}
			}
		}
	}
	for _, source := range sources[:2] {
		if in := r.Inspections[source]; in != nil {
			for _, x := range in.Suspected {
				if read[source+" "+x.Check] {
					continue
				}
				name := cmp.Or(checkNames[deref(x.Category)], deref(x.Category), "No category")
				out, opens = append(out, [4]string{name, "Suspected exploit", jobNames[source], x.Check}), append(opens, 0)
			}
		}
	}
	if r.Attack == nil || r.Attack.Problems == nil {
		return out, opens
	}
	found := r.findings()
	for i, f := range found {
		if f.Source != "attack" && slices.Contains(r.Ungrouped, f.ID) && !slices.ContainsFunc(r.Attack.Problems, func(p Problem) bool { return p.ID == f.ID }) {
			out, opens = append(out, [4]string{title(f), "Standalone evidence", jobNames[f.Source], f.ID}), append(opens, i+1)
		}
	}
	held := problems(r)
	for i, f := range found {
		if f.Source != "attack" || slices.ContainsFunc(held, func(p Problem) bool { return r.demonstrates(f, p) }) {
			continue
		}
		if _, ok := r.exploitOf(f); r.SchemaVersion >= 2 && r.Attack.Exploits != nil && !ok {
			continue // a further reading of an attempt, which the report counts nowhere
		}
		state := "Standalone evidence"
		// Without exploits, a finding no problem names has no attribution at all.
		if r.Attack.Exploits == nil || slices.ContainsFunc(r.Attack.Exploits["unattributed"], func(e *Exploit) bool {
			return e != nil && e.Assessment != nil && f.Index != nil && *f.Index == *e.Assessment
		}) {
			state = yellowStyle.Render("?") + " Not attributed"
		}
		out, opens = append(out, [4]string{title(f), state, "Attacker", ref(f)}), append(opens, i+1)
	}
	for _, p := range append(slices.Clone(r.Attack.Leads), slices.DeleteFunc(slices.Clone(r.Attack.Problems), func(p Problem) bool { return !p.lead() })...) {
		out, opens = append(out, [4]string{strings.Join(strings.Fields(p.Cause), " "), "Suspected only", sourceName(p.Source), p.ID}), append(opens, 0)
	}
	return out, opens
}

// stateCounts says how many rows of otherFindings are in each state, as in "6 unresolved, 2 not reproduced".
func stateCounts(rows [][4]string) string {
	var states []string
	counts := map[string]int{}
	for _, row := range rows {
		state := strings.ToLower(strings.TrimLeft(plainText(row[1]), "✗? "))
		if counts[state]++; counts[state] == 1 {
			states = append(states, state)
		}
	}
	slices.SortStableFunc(states, func(a, b string) int { return counts[b] - counts[a] })
	for i, state := range states {
		if counts[state] > 1 && strings.HasSuffix(state, "exploit") {
			states[i] = fmt.Sprintf("%d %ss", counts[state], state)
			continue
		}
		states[i] = fmt.Sprintf("%d %s", counts[state], state)
	}
	return strings.Join(states, ", ")
}

// sourceName is a problem's source in title case, as the screens name jobs.
func sourceName(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

// rewardsSummary is the Simulator's rewards: a bar per reward value, then the episodes and the summaries.
func rewardsSummary(r Report, w int) string {
	out := []string{heading("Simulation Rewards", "")}
	if r.Ordinary == nil || len(r.Ordinary.Groups) == 0 {
		return strings.Join(append(out, " "+yellowStyle.Render("Not available: "+r.missing(0))), "\n")
	}
	o := r.Ordinary
	widths := []int{10, 13, 13} // with 48 columns, each statistic keeps room for "unavailable"
	for _, g := range o.Groups {
		for _, name := range slices.Sorted(maps.Keys(g.Rewards)) {
			x := g.Rewards[name]
			if len(o.Groups) > 1 || len(g.Rewards) > 1 {
				out = append(out, " "+dim(group(g.Configuration.Model, name)))
			}
			out = append(out, rewardBars(x, 2, min(w, 48))...)
			out = append(out, "", cols(48, " ", widths, dim("Episodes"), dim("Mean"), dim("Median"), dim("SD")),
				cols(48, " ", widths, fmt.Sprintf("%d/%d", x.Usable, o.Requested), num(x.Mean), num(x.Median), num(x.SD)))
		}
	}
	return strings.Join(out, "\n")
}

// rewardBars draw a bar of unit cells per episode at each reward value, narrowed to fit w.
func rewardBars(x Rewards, unit, w int) []string {
	most := 1.0
	for _, d := range x.Distribution {
		most = max(most, d[1])
	}
	scale := min(float64(unit), float64(w-16)/most)
	out := []string{cols(w, " ", []int{9}, dim("Reward"), dim("Episodes"))}
	for _, d := range x.Distribution {
		cells := max(1, int(d[1]*scale+0.5))
		out = append(out, cols(w, " ", []int{9}, strconv.FormatFloat(d[0], 'g', 4, 64), fg(teal, strings.Repeat("█", cells))+" "+strconv.Itoa(int(d[1]))))
	}
	return out
}

// accuracySummary is the grader's decisions against the Grader Inspector's reference, and the two rates of its mistakes.
func accuracySummary(r Report, w int) string {
	out := []string{heading("Grader Accuracy", "")}
	if r.Metrics == nil || len(r.Metrics.Confusion) == 0 {
		return strings.Join(append(out, " "+yellowStyle.Render("Not available: "+r.missing(1))), "\n")
	}
	w = min(w, 52)
	for _, a := range r.Metrics.Confusion {
		if len(r.Metrics.Confusion) > 1 {
			out = append(out, " "+dim(group(a.Configuration.Model, a.Reward)))
		}
		if a.Status != "supported" {
			out = append(out, wrap("Not available: "+strings.Join(a.Reasons, " "), w, " ", amber))
			continue
		}
		out = append(out, cols(w, " ", []int{17}, dim("Type"), dim("Episodes")))
		for _, c := range confusionRows(a) {
			out = append(out, cols(w, " ", []int{17}, c.style.Render(c.name), c.style.Render(c.bar(a, 9))))
		}
		out = append(out, "", cols(w, " ", []int{26}, dim("Incorrect among passed"), rateCells(a.FalseDiscoveryRate)),
			cols(w, " ", []int{26}, dim("Rejected among correct"), rateCells(a.FalseNegativeRate)))
	}
	return strings.Join(out, "\n")
}

// missing says why phase i left no result to show.
func (r Report) missing(i int) string {
	a := phases[i].Analysis
	status, ok := r.Analyses[a]
	switch {
	case !ok:
		return phases[i].Name + " not selected"
	case r.PhaseErrors[a] != "":
		return phases[i].Name + " failed"
	case status == "not run":
		return phases[i].Name + " did not run"
	case status == "complete":
		return "no result recorded"
	}
	mark, _ := r.stage(i)
	return phases[i].Name + " " + plainText(mark)
}

type confusion struct {
	name, decision, work string
	n                    *int
	style                lipgloss.Style
}

func confusionRows(a Agreement) []confusion {
	return []confusion{
		{"True positive", "Pass", "Correct", a.TP, greenStyle},
		{"False positive", "Pass", "Incorrect", a.FP, redStyle},
		{"False negative", "Fail", "Correct", a.FN, redStyle},
		{"True negative", "Fail", "Incorrect", a.TN, greenStyle},
	}
}

// bar is the row's episodes as a bar, as long as unit cells for the largest share of the four.
func (c confusion) bar(a Agreement, unit int) string {
	if c.n == nil {
		return "unavailable"
	}
	most := 1
	for _, x := range []*int{a.TP, a.FP, a.FN, a.TN} {
		if x != nil {
			most = max(most, *x)
		}
	}
	return strings.Repeat("█", max(1, unit**c.n/most)) + " " + strconv.Itoa(*c.n)
}

// rateCells is a rate as a percentage and its fraction, at least the percentage when presumed labels make it a lower bound.
func rateCells(x Rate) string {
	if x.Unavailable != nil || x.Value == nil {
		return "unavailable"
	}
	return percent(x) + "   " + fmt.Sprintf("%d/%d", *x.Numerator, *x.Denominator)
}

func percent(x Rate) string {
	at := ""
	if x.LowerBound {
		at = "at least "
	}
	return fmt.Sprintf("%s%.0f%%", at, 100**x.Value)
}

// openQuestions are what kept an inspector's search open when it ended, each as where, what and why: its open items,
// and its unresolved findings when the run says the phase's evidence stayed unresolved.
func openQuestions(r Report, source string) [][3]string {
	in := r.Inspections[source]
	if in == nil {
		return nil
	}
	i := map[string]int{"grader_inspector": 1, "hack_inspector": 2}[source]
	qs := openItems(in)
	if slices.Contains(r.Unresolved, phases[i].Analysis) {
		qs = append(qs, unresolvedFindings(in, source)...)
	}
	var out [][3]string
	for _, q := range qs {
		out = append(out, [3]string{phases[i].Name, q[0], "Unresolved: " + q[1]})
	}
	return out
}

// openItems are an inspector's open items, each as what and why.
func openItems(in *Inspection) [][2]string {
	var out [][2]string
	for _, o := range in.Open {
		what := o.ID
		if o.Category != nil {
			what = word(checkNames, *o.Category) + " (" + o.ID + ")"
		}
		out = append(out, [2]string{what, cmp.Or(strings.TrimSpace(o.Reason), "Reason not recorded")})
	}
	return out
}

// unresolvedFindings are an inspector's current unresolved findings, each as its mechanism with its reference, and why.
func unresolvedFindings(in *Inspection, source string) [][2]string {
	var out [][2]string
	for _, f := range in.Findings["inconclusive"] {
		if f.SupersededBy != nil {
			continue
		}
		why := strings.Join(filled(f.Claim.Unresolved), "; ")
		if why == "" && len(f.Assessment.Reasons) > 0 {
			why = f.Assessment.Reasons[0]
		}
		what := title(f)
		if f.Index != nil {
			what += fmt.Sprintf(" (%s-%d)", strings.TrimSuffix(source, "_inspector"), *f.Index)
		}
		out = append(out, [2]string{what, cmp.Or(strings.TrimSpace(why), "Reason not recorded")})
	}
	return out
}

// notTestedWords say why an Attacker condition, or the search without information, was not tried.
var notTestedWords = map[string]string{
	"unavailable":        "no guidance for an Attacker",
	"no_guidance":        "no guidance for an Attacker",
	"unattempted":        "no Attacker attempt recorded",
	"unknown":            "no Attacker attempt recorded",
	"not_requested":      "not requested",
	"cancelled":          "stopped",
	"spending_exhausted": "spending cap",
	"insufficient_time":  "not enough time left",
	"running":            "no result recorded",
	"withdrawn":          "the inspector that found it later withdrew it",
	"not_needed":         "no exploit was made with more help",
}

// workLeft is every piece of work the run did not finish, as where, what and why.
func workLeft(r Report, found []Finding) [][3]string {
	var out [][3]string
	unfinished := r.Unfinished
	if unfinished == nil { // older reports: every analysis that did not complete
		unfinished = map[string]string{}
		for a, status := range r.Analyses {
			if status != "complete" {
				unfinished[a] = status
			}
		}
	}
	for i, p := range phases {
		a := p.Analysis
		switch status, ok := unfinished[a]; {
		case r.PhaseErrors[a] != "":
			out = append(out, [3]string{p.Name, "The whole phase", "Error: " + errorLine(r.PhaseErrors[a])})
		case ok && !slices.Contains(r.Unresolved, a):
			what := "Remaining work"
			if o := r.Ordinary; i == 0 && o != nil {
				if o.Attempted == o.Requested && len(o.NoReward) > 0 {
					continue // every episode ran; the ones without a reward say what did not finish
				}
				what = fmt.Sprintf("%d of %d episodes", o.Attempted, o.Requested)
			}
			out = append(out, [3]string{p.Name, what, word(unfinishedWords, status)})
		}
	}
	if o := r.Ordinary; o != nil {
		if _, ok := unfinished["simulation"]; !ok && o.Attempted < o.Requested {
			out = append(out, [3]string{"Simulation", fmt.Sprintf("%d of %d episodes", o.Requested-o.Attempted, o.Requested), "Not run"})
		}
		for _, g := range o.Groups {
			for _, name := range slices.Sorted(maps.Keys(g.Rewards)) {
				if x := g.Rewards[name]; x.Attempted > x.Usable {
					out = append(out, [3]string{"Simulation", fmt.Sprintf("%d episode%s without a usable %s", x.Attempted-x.Usable, plural(x.Attempted-x.Usable), name),
						strings.Join(append([]string{"Not counted in the rewards."}, o.unrewarded(g.Episodes)...), " ")})
				}
			}
		}
	}
	for _, source := range []string{"grader_inspector", "hack_inspector"} {
		out = append(out, openQuestions(r, source)...)
		if in := r.Inspections[source]; in != nil {
			name := phases[map[string]int{"grader_inspector": 1, "hack_inspector": 2}[source]].Name
			// A failed experiment fails only itself, not the search that ran it and went on; its session keeps its error.
			lost := map[string]bool{}
			for _, ex := range in.Experiments {
				if attemptResults[ex.Status] != Failed || ex.Error == "" {
					continue
				}
				lost[ex.Error] = true
				if !slices.ContainsFunc(in.Open, func(o Open) bool { return o.ID == ex.ID }) { // an open one has its open row
					out = append(out, [3]string{name, word(checkNames, ex.Category) + " (" + ex.ID + ")", "Error: " + errorLine(ex.Error)})
				}
			}
			for _, at := range in.Attempts {
				why := errorLine(at.Error)
				if why == "" && slices.Contains(searchFailures, at.Status) {
					why = strings.ReplaceAll(at.Status, "_", " ")
				}
				if why != "" && !lost[at.Error] {
					out = append(out, [3]string{name, "Search: " + searchTarget(at), "Not finished: " + why})
				}
			}
		}
	}
	if r.Attack == nil {
		return append(out, warningRows(r, out)...)
	}
	if r.Attack.Problems != nil {
		for _, p := range problems(r) {
			if best(r.tried(p, "none"), r.tried(p, "minimal"), r.tried(p, "full")) != "-" || p.notAttackedAlone() {
				continue
			}
			why := p.why()
			for _, c := range p.Conditions {
				if c.Condition == "full" || c.Condition == "minimal" || c.Condition == "none" {
					why = c.Status
					break
				}
			}
			reason, ok := notTestedWords[why]
			if !ok {
				reason = "no Attacker attempt recorded"
			}
			out = append(out, [3]string{"Attack", r.findingName(found, p), "Not tested: " + reason})
		}
	}
	for _, at := range r.Attack.Attempts {
		if res, _ := lookup(attemptResults, at.Status); res == Failed {
			what := "Try " + strconv.Itoa(at.Number)
			if at.Episode != nil {
				what = sessionName(*at.Episode)
			}
			why := strings.ReplaceAll(at.Status, "_", " ")
			if at.Error != nil {
				why = errorLine(*at.Error)
			}
			out = append(out, [3]string{"Attack", what, "Error: " + why})
		}
	}
	out = append(out, untriedLevels(r, found, out)...)
	if d := r.Attack.Discovery; d != nil && d.MaximumAttempts > 0 && d.Attempts == 0 {
		out = append(out, [3]string{"Attack", "Search with no information", "Not tested: " + word(notTestedWords, d.Status)})
	}
	return append(out, warningRows(r, out)...)
}

// searchFailures are the statuses of an inspector's search attempt that Python warns of even without an error message.
var searchFailures = []string{"refused", "model_inability", "model_output_failure", "unobservable", "inference_failure", "tool_failure", "out_of_memory", "step_limit"}

// settled are the statuses of an Attacker condition that leave no work: tried to a result, or never possible.
var settled = []string{"evidenced_issue", "no_evidenced_issue", "unavailable", "not_requested", "not_needed", "not_applicable"}

// untriedLevels are the Attacker conditions of each candidate without a result, as Python warns of them, for each
// candidate whose problem is not already a Work left row.
func untriedLevels(r Report, found []Finding, rows [][3]string) [][3]string {
	var out [][3]string
	for _, c := range r.Attack.Candidates {
		what := c.ID
		if i := slices.IndexFunc(r.Attack.Problems, func(p Problem) bool { return deref(p.Candidate) == c.ID || p.Finding == c.ID }); i >= 0 {
			what = r.findingName(found, r.Attack.Problems[i])
		}
		if slices.ContainsFunc(rows, func(row [3]string) bool { return row[1] == what }) {
			continue
		}
		for _, level := range []string{"full", "minimal", "none"} {
			cond, ok := c.Conditions[level]
			if !ok || slices.Contains(settled, cond.Status) {
				continue
			}
			why := "With " + levelWords[level] + ": " + word(notTestedWords, cond.Status)
			if cond.Status == "unknown" {
				why = "With " + levelWords[level] + ": " + reasonWords["unknown"]
			}
			out = append(out, [3]string{"Attack", what, why})
		}
	}
	return out
}

// warningRows are the report's warnings that no Work left row says yet, each split into where, what and why.
func warningRows(r Report, rows [][3]string) [][3]string {
	has := func(where, what string) bool {
		return slices.ContainsFunc(rows, func(row [3]string) bool { return row[0] == where && strings.HasPrefix(row[1], what) })
	}
	var out [][3]string
	for _, w := range r.Warnings {
		where := "Run"
		w = strings.TrimPrefix(w, "run: ")
		for _, p := range phases {
			if rest, ok := strings.CutPrefix(w, p.Analysis+" "); ok {
				where, w = p.Name, rest
			}
		}
		switch {
		case strings.HasPrefix(w, "inspector "), strings.HasPrefix(w, "persistence probe "):
			if where == "Run" {
				where = phases[2].Name
			}
			w = strings.TrimPrefix(w, "inspector ")
		case strings.Contains(w, " ordinary episodes "), strings.HasPrefix(w, "F1 "), strings.HasPrefix(w, "AUROC "):
			if where == "Run" {
				where = phases[1].Name
			}
		case strings.Contains(w, "model calls"):
			where = "Cost"
		}
		status, coverage := strings.CutSuffix(w, ": its coverage is incomplete")
		switch {
		case strings.HasPrefix(w, "candidate"), searchWarning.MatchString(w):
			continue // untriedLevels and the search rows say these
		case coverage, strings.HasSuffix(w, "was selected but not run"), strings.HasPrefix(w, "attempted "):
			// The open questions name what stayed unresolved; without one the reason is not recorded.
			if !has(where, "") && status == "unresolved" {
				out = append(out, [3]string{where, "Some results", "Unresolved: Reason not recorded"})
			} else if !has(where, "") {
				out = append(out, [3]string{where, "Coverage", "Incomplete: " + word(statusWords, status)})
			}
			continue
		case strings.HasPrefix(w, "no-hint discovery is "):
			if !has(where, "Search with no information") {
				out = append(out, [3]string{where, "Search with no information", capital(strings.TrimPrefix(w, "no-hint discovery is "))})
			}
			continue
		}
		what, why := w, ""
		if i := strings.IndexAny(w, ":;"); i > 0 {
			what, why = w[:i], strings.TrimSpace(w[i+1:])
		}
		for _, verb := range []string{" is ", " are ", " uses ", " have ", " has ", " were "} {
			if i := strings.Index(what, verb); i > 0 {
				what, why = what[:i], strings.TrimSpace(what[i+len(verb):]+": "+why)
				if verb != " is " && verb != " are " {
					why = verb[1:] + why
				}
				break
			}
		}
		if !strings.Contains(what, "/") { // a model id or a path keeps its spelling
			what = capital(what)
		}
		out = append(out, [3]string{where, what, capital(strings.TrimSuffix(why, ": "))})
	}
	return out
}

var searchWarning = regexp.MustCompile(`^\S+ attempt \d+ \(`)

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// searchTarget is what one search attempt looked at: its category, its episode, or every category.
func searchTarget(at SearchAttempt) string {
	switch {
	case at.Category != "":
		return word(checkNames, at.Category)
	case at.Episode != "":
		return at.Episode
	}
	return "all categories"
}
