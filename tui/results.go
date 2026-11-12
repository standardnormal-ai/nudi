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
	// The Answer's causes fold under one line, which a opens.
	if causes := r.causeLines(); len(causes) > 0 {
		n := len(slices.DeleteFunc(slices.Clone(causes), func(s string) bool { return !causeLine.MatchString(s) }))
		if p.toggle("a", "Causes", "("+strconv.Itoa(n)+")") {
			for _, line := range causes {
				p.add(hang(line, p.w, "   "))
			}
		}
	}
	p.add("")
	if r.Attack != nil && r.Attack.Problems != nil {
		problemsTable(r, found, p)
	} else {
		findingsTable(found, "", p)
	}
	p.add("")
	if others, opens := otherFindings(r); len(others) > 0 && p.toggle("o", "Abandoned Problems", "") {
		widths := []int{36, 28, 18}
		p.add(cols(p.w, "   ", widths, dim("Finding"), dim("State"), dim("Found by"), dim("Ref")))
		for i, o := range others {
			// An evidenced finding on the list opens with Enter; the other rows have no detail.
			if n := opens[i]; n > 0 {
				p.pick(n, "", func(mark string, _ bool) string { return cols(p.w, mark, widths, o[0], o[1], o[2], dim(o[3])) })
			} else {
				p.add(cols(p.w, "   ", widths, o[0], o[1], o[2], dim(o[3])))
			}
		}
		p.add(wrap("Suspected problems that didn't have enough evidence", p.w, "   ", dim))
	}
	if p.toggle("i", "What the References Mean", "") {
		widths := []int{17, 62}
		p.add(cols(p.w, "   ", widths, dim("Reference"), dim("What it names"), dim("Example")))
		for _, x := range references {
			p.add(cols(p.w, "   ", widths, fg(teal, x[0]), x[1], dim(x[2])))
		}
		p.add(wrap("A problem groups the findings that share one cause. References never change between views.", p.w, "   ", dim))
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
	{"P", "Problem found by the Hack Inspector's search", "P1"},
	{"G", "Problem found by the Grader Inspector in the simulations", "G1"},
	{"A", "Problem found only by an Attacker", "A1"},
	{"hack-N", "Finding: an evidence record of the Hack Inspector", "hack-1"},
	{"grader-N", "Finding: an evidence record of the Grader Inspector", "grader-7"},
	{"experiment-N", "One idea the Hack Inspector tested", "experiment-0002"},
	{"check-N", "nudi's rerun that confirmed a finding", "check-0003"},
	{"NNNN-attacker", "One Attacker session", "0007-attacker"},
	{"NNNN-simulator", "One Simulator episode", "0004-simulator"},
}

// ending is how the run ended, with its time or cost, the count of problems on the right, and the verdict under it
// as Python wrote it. A failed phase names its error; a stop says that the results come from before it.
func ending(r Report, found []Finding, w int) []string {
	head, notes := endingParts(r, false)
	out := []string{spread(" "+head, tally(r, found), w)}
	for _, note := range notes {
		out = append(out, hang(note, w, " "))
	}
	return out
}

// endingParts are the ending's headline, with its time or cost beside it, and the lines under it.
// The Answer's causes follow the verdict when causes is set.
func endingParts(r Report, causes bool) (string, []string) {
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
		errs = append(errs, redStyle.Render("Error")+"  "+strings.SplitN(r.PhaseErrors[p.Analysis], "\n", 2)[0], failedNote(r, p.Name, p.Analysis))
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
	case r.Status == "complete":
		head, notes = greenStyle.Render("✓ Finished"), []string{verdict}
		if clock != "" {
			beside = "after " + clock
		}
	case r.Status == "time_limit":
		head, notes = amber.Render("Stopped at the time limit"), []string{verdict, stopWords["time_limit"][1]}
	case r.Status == "partial":
		head, notes = amber.Render("Partly finished"), []string{verdict, "Work left says what did not finish."}
	default:
		head, notes = amber.Render("Stopped"), []string{verdict}
	}
	if beside != "" {
		head += "  " + dim(beside)
	}
	if i := slices.Index(notes, verdict); i >= 0 && verdict != "" && causes {
		notes = slices.Insert(notes, i+1, r.causeLines()...)
	}
	return head, slices.DeleteFunc(notes, func(s string) bool { return s == "" })
}

// causeLines are the Answer's causes as Python wrote them: the paragraph over them, then each cause with its problems'
// lines under it, which start "  - ". Empty when the Answer has none.
func (r Report) causeLines() []string {
	i := slices.IndexFunc(r.Answer, func(s string) bool { return strings.HasPrefix(s, "Causes, ") })
	if i < 0 {
		return nil
	}
	j := i + 1
	for j < len(r.Answer) && (strings.HasPrefix(r.Answer[j], "  - ") || causeLine.MatchString(r.Answer[j])) {
		j++
	}
	return r.Answer[i:j]
}

var causeLine = regexp.MustCompile(`^C\d+: `)

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
		return "No problems demonstrated in this run."
	}
	return line
}

// tally is the count on the right of the ending: the problems, or the evidenced findings of a report without
// problems, else the open questions.
func tally(r Report, found []Finding) string {
	n, noun := len(found), "evidenced finding"
	if r.Attack != nil && r.Attack.Problems != nil {
		n, noun = len(problems(r)), "problem"
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

// problemsTable lists the problems, each with its evidence and, behind e, the legend of its cells; Enter expands a problem into its evidence records,
// and Enter on a record opens it.
func problemsTable(r Report, found []Finding, p *page) {
	ps := problems(r)
	if len(ps) == 0 {
		p.add(titled("Problems", 0), " None demonstrated in this run.")
		return
	}
	p.add(spread(titled("Problems", len(ps)), p.fold("e"), p.w))
	attacked := len(r.Attack.Attempts) > 0 || slices.ContainsFunc(ps, func(p Problem) bool { return p.Conditions != nil })
	inspected := r.SchemaVersion >= 2 || slices.ContainsFunc(ps, func(p Problem) bool { return p.EvidencedByInspector != nil })
	// The columns of how much an Attacker was told. A try given no information is aimed at no problem, so none of
	// them is No info; an Attacker problem's level says when an Attacker told nothing made it.
	var levels []string
	if attacked {
		levels = []string{"minimal", "full"}
	}
	// Without a problem of known type a column of ? would say nothing.
	typed := slices.ContainsFunc(ps, func(p Problem) bool { return resultType(p) != "" })
	heads, widths := []string{"Problem"}, []int{44}
	if typed { // the Problem column gives way first, so that a nine-letter Ref still fits at 100 columns
		heads, widths = []string{"Problem", "Type"}, []int{39, 23}
	}
	for _, level := range levels {
		heads, widths = append(heads, helpWords[level]), append(widths, 6)
	}
	if inspected {
		heads, widths = append(heads, "Inspector"), append(widths, 11)
	}
	heads = append(heads, "Ref")
	if p.open["e"] {
		var legend, told []string
		for _, level := range levels {
			told = append(told, helpWords[level])
		}
		if len(told) > 0 {
			legend = append(legend, strings.Join(told, ", ")+": an Attacker, by how much it was told.")
		}
		if inspected {
			legend = append(legend, "Inspector: an inspector evidenced it.")
		}
		p.add(symbols)
		if len(legend) > 0 {
			p.add(wrap(strings.Join(legend, " "), p.w, " ", dim))
		}
		p.add("")
	}
	var cells []string
	for _, h := range heads {
		cells = append(cells, dim(h))
	}
	p.add(cols(p.w, "     ", widths, cells...))
	for i, pr := range ps {
		key := "problem " + strconv.Itoa(i)
		p.pick(0, key, func(mark string, on bool) string {
			arrow := dim("▸") + " "
			if p.open[key] {
				arrow = dim("▾") + " "
			}
			name := strings.Join(strings.Fields(pr.Cause), " ")
			cells := []string{name}
			if typed && resultType(pr) == "" {
				cells = append(cells, under("Type", glyph("?")))
			} else if typed {
				cells = append(cells, redStyle.Render(resultType(pr)))
			}
			for _, level := range levels {
				cells = append(cells, under(helpWords[level], glyph(r.tried(pr, level))))
			}
			if inspected {
				answer := "-"
				if e := pr.EvidencedByInspector; e != nil {
					answer = map[bool]string{true: "yes", false: "no"}[*e]
				} else if r.SchemaVersion >= 2 && pr.Source != "Attacker" {
					answer = "yes" // an inspector problem is an evidenced reading
				}
				cells = append(cells, under("Inspector", glyph(answer)))
			}
			return cols(p.w, mark+arrow, widths, append(cells, dim(pr.ID))...)
		})
		if p.open[key] {
			evidenceRows(r, found, pr, p)
			levelRows(r, pr, inspected, p)
		}
	}
	if p.lines[len(p.lines)-1] == "" { // an expanded last problem already ends in a blank line
		p.lines = p.lines[:len(p.lines)-1]
	}
}

// evidenceRows are a problem's evidence records: its inspector findings, then the Attacker findings that demonstrated it.
func evidenceRows(r Report, found []Finding, pr Problem, p *page) {
	before := len(p.items)
	for i, f := range found {
		if f.Source != "attack" && slices.Contains(pr.readings(), f.ID) || f.Source == "attack" && r.demonstrates(f, pr) {
			p.pick(i+1, "", func(mark string, _ bool) string {
				return cols(p.w, "     "+mark, []int{44, 18}, title(f), jobNames[f.Source], dim(ref(f)))
			})
		}
	}
	if len(p.items) == before {
		p.add("       " + dim("No evidence record on the list."))
	}
}

// levelRows are, under an expanded problem's evidence records, what its cells do not say: without the Inspector column,
// the problem's level; the report's reason when it records no type; and its note. Work left says why a cell is not
// tested.
func levelRows(r Report, pr Problem, inspected bool, p *page) {
	if !inspected {
		p.add(cols(p.w, "       ", []int{12}, dim("Level"), dim(level(r, pr))))
	}
	if pr.Help != nil {
		p.add(cols(p.w, "       ", []int{12}, dim("Help"), dim(*pr.Help)))
	}
	if pr.Reason != nil && problemType(pr) == "" {
		p.add(wrap(capital(*pr.Reason), p.w, "       ", dim))
	}
	if n := unrewarded(pr); n != "" {
		p.add(wrap(n, p.w, "       ", dim))
	}
	p.add("")
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
	widths := []int{44, 16, 18}
	p.add(cols(p.w, "   ", widths, dim("Finding"), dim("Type"), dim("Found by"), dim("Ref")))
	for i, f := range found {
		if source != "" && f.Source != source {
			continue
		}
		p.pick(i+1, "", func(mark string, on bool) string {
			name := title(f)
			return cols(p.w, mark, widths, name, redStyle.Render(findingType(f)), jobNames[f.Source], dim(ref(f)))
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
	"withdrawn":          "a later reading withdrew the finding",
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
			out = append(out, [3]string{p.Name, "The whole phase", "Error: " + strings.SplitN(r.PhaseErrors[a], "\n", 2)[0]})
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
					out = append(out, [3]string{name, word(checkNames, ex.Category) + " (" + ex.ID + ")", "Error: " + strings.SplitN(ex.Error, "\n", 2)[0]})
				}
			}
			for _, at := range in.Attempts {
				why := strings.SplitN(at.Error, "\n", 2)[0]
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
			if best(r.tried(p, "none"), r.tried(p, "minimal"), r.tried(p, "full")) != "-" {
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
			out = append(out, [3]string{"Attack", strings.TrimSpace(p.ID + " " + strings.Join(strings.Fields(p.Cause), " ")), "Not tested: " + reason})
		}
	}
	for _, at := range r.Attack.Attempts {
		if res, _ := lookup(attemptResults, at.Status); res == Failed {
			what := "Try " + strconv.Itoa(at.Number)
			if at.Episode != nil {
				what = *at.Episode
			}
			why := strings.ReplaceAll(at.Status, "_", " ")
			if at.Error != nil {
				why = strings.SplitN(*at.Error, "\n", 2)[0]
			}
			out = append(out, [3]string{"Attack", what, "Error: " + why})
		}
	}
	out = append(out, untriedLevels(r, out)...)
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
func untriedLevels(r Report, rows [][3]string) [][3]string {
	var out [][3]string
	for _, c := range r.Attack.Candidates {
		what := c.ID
		if i := slices.IndexFunc(r.Attack.Problems, func(p Problem) bool { return deref(p.Candidate) == c.ID || p.Finding == c.ID }); i >= 0 {
			p := r.Attack.Problems[i]
			what = strings.TrimSpace(p.ID + " " + strings.Join(strings.Fields(p.Cause), " "))
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
			if !has(where, "") && status == "partial" {
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
		out = append(out, [3]string{where, capital(what), capital(strings.TrimSuffix(why, ": "))})
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
