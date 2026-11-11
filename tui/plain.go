package main

import (
	"cmp"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

// The plain output for a pipe: the Results tab and every phase tab as sections in capitals, one labelled field per
// line, every hidden table expanded. Values wrap in their column and are never cut.

// field is one labelled line of a section, after indent; a long value wraps under itself. A word too long for the
// value's column, such as a path, moves whole to a line of its own below the name, so it is never split.
func field(w int, indent, name, value string) string {
	for _, word := range strings.Fields(value) {
		if width(word) > w-width(indent)-18 {
			return indent + name + "\n" + indent + "    " + value
		}
	}
	return cols(w, indent, []int{18}, name, value)
}

// plainReport is the whole run for a pipe, in the order of the Results tab.
func plainReport(r Report, w int) string {
	found := r.findings()
	var out []string
	section := func(name string, lines ...string) {
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, name)
		out = append(out, lines...)
	}
	section("RUN", runFields(r, w)...)
	section("RESULT", resultFields(r, found, w)...)
	if r.Attack != nil && r.Attack.Problems != nil {
		section("PROBLEMS", problemFields(r, found, w)...)
	}
	section("EVIDENCE", evidenceFields(r, found, w)...)
	if others, _ := otherFindings(r); len(others) > 0 {
		lines := []string{field(w, "  ", "Count", stateCounts(others))}
		for _, o := range others {
			lines = append(lines, "", "  "+o[0], field(w, "      ", "State", strings.TrimLeft(plainText(o[1]), "✗? ")),
				field(w, "      ", "Found by", o[2]), field(w, "      ", "Reference", o[3]))
		}
		section("NOT COUNTED AS PROBLEMS", lines...)
	}
	section("SIMULATION", simulationFields(r, found, w)...)
	section("GRADER ACCURACY", accuracyFields(r, w)...)
	if r.Attack != nil {
		section("ATTACK ATTEMPTS", attemptRows(r, w)...)
	}
	var left []string
	for _, row := range workLeft(r, found) {
		left = append(left, cols(w, "  ", []int{20}, row[0], strings.TrimSpace(row[1]+"\n"+row[2])))
	}
	if len(left) == 0 {
		left = []string{"  None recorded."}
	}
	section("WORK LEFT", left...)
	var cost []string
	for _, row := range costRows(r, w-1, true) {
		cost = append(cost, " "+strings.ReplaceAll(row, "\n", "\n "))
	}
	section("COST", cost...)
	var next []string
	if p, _ := r.topProblem(found); p != nil && p.ID != "" {
		next = append(next, "  nudi-view "+r.Dir+" "+p.ID, "      Open problem "+p.ID+" with its evidence")
	} else if len(found) > 0 {
		next = append(next, "  nudi-view "+r.Dir+" 1", "      Open finding 1 with its evidence")
	}
	section("NEXT", append(next, "  "+r.Dir+"/report.json", "      The full report, for programs")...)
	return plainText(strings.Join(out, "\n"))
}

func runFields(r Report, w int) []string {
	c := r.Configuration
	out := []string{field(w, "  ", "Task", r.task()), field(w, "  ", "Run directory", r.Dir)}
	if c.Backend != "" {
		out = append(out, field(w, "  ", "Backend", capital(c.Backend)))
	}
	if c.Capacity.Concurrency > 0 {
		out = append(out, field(w, "  ", "Concurrency", strconv.Itoa(c.Capacity.Concurrency)))
	}
	if r.Elapsed != nil {
		out = append(out, field(w, "  ", "Elapsed", elapsed(*r.Elapsed)))
	}
	for _, role := range slices.Sorted(maps.Keys(c.Models)) {
		m := c.Models[role]
		name := role
		if n, ok := lookup(roleNames, role); ok {
			name = n[0]
		}
		model := path.Base(m.Model)
		if m.ReasoningEffort != "" {
			model += ", reasoning " + m.ReasoningEffort
		}
		out = append(out, field(w, "  ", name+" model", model))
	}
	return out
}

func resultFields(r Report, found []Finding, w int) []string {
	head, notes := endingParts(r)
	out := []string{field(w, "  ", "Ending", strings.TrimPrefix(plainText(head), "✓ "))}
	for i, note := range notes {
		name := ""
		if i == 0 {
			name = "Summary"
		}
		out = append(out, field(w, "  ", name, note))
	}
	if t := plainText(tally(r, found)); t != "" {
		out = append(out, field(w, "  ", "Count", t))
	}
	left := "None"
	if n := len(workLeft(r, found)); n > 0 {
		left = fmt.Sprintf("%d item%s, listed under WORK LEFT", n, plural(n))
	}
	return append(out, field(w, "  ", "Work left", left))
}

// level is a problem's step on the exploit chart in words. Correct work the grader fails is no exploit, so it has no
// step and says how an Attacker reproduced it. A rerun's problem its Attackers did not find again keeps the earlier
// run's level, and says so.
func level(r Report, p Problem) string {
	again := ""
	if run, ok := strings.CutPrefix(p.Label, "evidenced in run "); ok && strings.HasSuffix(p.Label, "; not found again here") {
		run, _, _ = strings.Cut(run, " at ")
		again = " in run " + run + "; not found again here"
	}
	if problemType(r, p) == "False negative" {
		return cmp.Or(capital(strings.TrimPrefix(validWorkWords[p.ladder()], ", ")), "Not reproduced by an Attacker") + again
	}
	elsewhere := strings.TrimSuffix(", while aimed at "+r.aimedElsewhere(p), ", while aimed at ")
	return fmt.Sprintf("%d of 5: %s", p.ladder(), strings.TrimLeft(cmp.Or(ladderWords[p.ladder()], p.Label), "●○ ")) + elsewhere + again
}

// problemFields are the problems, highest level first, each with its type, level, evidence records and Attacker tries.
func problemFields(r Report, found []Finding, w int) []string {
	ps := problems(r)
	if len(ps) == 0 {
		return []string{"  None demonstrated in this run."}
	}
	var out []string
	for i, p := range ps {
		if i > 0 {
			out = append(out, "")
		}
		out = append(out, cols(w, "  ", []int{4}, p.ID, strings.Join(strings.Fields(p.Cause), " ")))
		kv := func(name, value string) {
			if value != "" {
				out = append(out, field(w, "      ", name, value))
			}
		}
		kv("Type", typeNames[problemType(r, p)])
		kv("Level", level(r, p))
		kv("Found by", sourceName(p.Source))
		var evidence []string
		for _, f := range found {
			if f.Source != "attack" && slices.Contains(p.Findings, f.ID) || f.Source == "attack" && r.demonstrates(f, p) {
				evidence = append(evidence, ref(f)+", "+jobNames[f.Source]+", "+word(scopeWords, f.ExecutionScope)+", reward "+num(f.reward()))
			}
		}
		if len(evidence) == 0 {
			evidence = []string{"No evidence record on the list"}
		}
		kv("Evidence", strings.Join(evidence, "\n"))
		if len(p.Members) > 0 {
			kv("Related", strings.Join(p.Members, ", ")+": novelty_judge matched them to "+cmp.Or(p.ID, "this problem"))
		}
		var tries []string
		for _, level := range []string{"none", "minimal", "full"} {
			for _, at := range r.aimed(p) {
				if at.Level == level {
					tries = append(tries, levelWords[level]+": "+tryWords(r, at))
				}
			}
			// Tries aimed at another problem that exploited this one, as the judge named it.
			for _, by := range p.ExploitedBy {
				if i := slices.IndexFunc(r.Attack.Attempts, func(at Attempt) bool { return at.Episode != nil && *at.Episode == by.Episode }); i >= 0 && r.Attack.Attempts[i].Level == level {
					at := r.Attack.Attempts[i]
					tries = append(tries, levelWords[level]+": demonstrated while aimed at "+cmp.Or(deref(by.Target), "another problem")+strings.TrimPrefix(tryWords(r, at), tryResult(r, at)))
				}
			}
			if r.tried(p, level) == "-" && !slices.ContainsFunc(r.aimed(p), func(at Attempt) bool { return at.Level == level }) {
				for _, c := range p.Conditions {
					if c.Condition == level || level == "none" && c.Condition == "independent" {
						tries = append(tries, levelWords[level]+": not tested, "+word(notTestedWords, c.Status))
					}
				}
			}
		}
		if len(tries) == 0 {
			tries = []string{"Not tested"}
		}
		kv("Attacker", strings.Join(tries, "\n"))
	}
	return out
}

// tryWords say how an Attacker's try ended, with its session and reward.
func tryWords(r Report, at Attempt) string {
	out := tryResult(r, at)
	if at.Episode != nil {
		out += ", " + *at.Episode
	}
	for _, k := range slices.Sorted(maps.Keys(at.Rewards)) {
		out += ", " + k + " " + num(at.Rewards[k])
	}
	return out
}

// tryResult says how an Attacker's try ended, with the error of one that failed.
func tryResult(r Report, at Attempt) string {
	res, _ := lookup(attemptResults, at.Status)
	if !r.started(at) {
		res = NotTested
	}
	out := triedWords[res]
	if res == NotTested && r.started(at) {
		out = strings.ToLower(stoppedWords(at.Status)) // its episode started
	}
	if at.Error != nil && res == Failed {
		out += ": " + strings.SplitN(*at.Error, "\n", 2)[0]
	}
	return out
}

// evidenceFields are the evidenced findings, numbered as nudi-view RUN N opens them.
func evidenceFields(r Report, found []Finding, w int) []string {
	if len(found) == 0 {
		return []string{"  None evidenced in this run."}
	}
	var out []string
	for i, f := range found {
		if i > 0 {
			out = append(out, "")
		}
		out = append(out, cols(w, "  ", []int{4}, strconv.Itoa(i+1), title(f)))
		kv := func(name, value string) { out = append(out, field(w, "      ", name, value)) }
		kv("Type", typeNames[findingType(f)])
		kv("Found by", jobNames[f.Source])
		if p := findingProblem(r, f); p != nil {
			kv("Problem", cmp.Or(p.ID, strings.Join(strings.Fields(p.Cause), " ")))
		}
		kv("Evidence from", cmp.Or(strings.TrimSpace(capital(word(scopeWords, f.ExecutionScope))+" "+f.Claim.Episode), "Not recorded"))
		kv("Reference", ref(f))
		if f.Confirms != "" {
			kv("Attacker exploit", capital(f.Confirms))
		}
		if n := len(filled(f.Claim.Unresolved)) + len(limits(f)); n > 0 {
			kv("Limitations", fmt.Sprintf("%d, shown by nudi-view %s %d", n, r.Dir, i+1))
		}
	}
	return out
}

func simulationFields(r Report, found []Finding, w int) []string {
	o := r.Ordinary
	if o == nil || len(o.Groups) == 0 {
		return []string{field(w, "  ", "Not available", r.missing(0))}
	}
	var out []string
	for _, g := range o.Groups {
		for _, name := range slices.Sorted(maps.Keys(g.Rewards)) {
			x := g.Rewards[name]
			if len(out) > 0 {
				out = append(out, "")
			}
			out = append(out, field(w, "  ", "Model", path.Base(g.Configuration.Model)), field(w, "  ", "Reward name", name),
				field(w, "  ", "Episodes", fmt.Sprintf("%d usable, %d attempted, %d requested", x.Usable, x.Attempted, o.Requested)))
			var values []string
			for _, d := range x.Distribution {
				values = append(values, fmt.Sprintf("%s: %d episode%s", strconv.FormatFloat(d[0], 'g', 4, 64), int(d[1]), plural(int(d[1]))))
			}
			out = append(out, field(w, "  ", "Rewards", strings.Join(values, "\n")), field(w, "  ", "Mean", num(x.Mean)),
				field(w, "  ", "Median", num(x.Median)), field(w, "  ", "Sample SD", num(x.SD)), field(w, "  ", "Skewness", num(x.Skewness)),
				field(w, "  ", "Reward pattern", strings.Join(patterns(x, g.EpisodeRewards, name), "\n")))
			if x.FlagsNotEvaluated != nil {
				out = append(out, field(w, "  ", "", *x.FlagsNotEvaluated))
			}
			for i, line := range warnings(x) {
				out = append(out, field(w, "  ", map[bool]string{true: "Warning", false: ""}[i == 0], strings.TrimPrefix(line, "Warning: ")))
			}
			// The method panel's rows, which the screen opens with ?, with Python's details as well.
			for _, kv := range methodRows(r, found, x) {
				out = append(out, field(w, "  ", strings.Replace(kv[0], "Episodes", "Flagged episodes", 1), kv[1]))
			}
		}
	}
	return out
}

func accuracyFields(r Report, w int) []string {
	if r.Metrics == nil || len(r.Metrics.Confusion) == 0 {
		return []string{field(w, "  ", "Not available", r.missing(1))}
	}
	m := r.Metrics
	out := []string{field(w, "  ", "Accuracy uses", fmt.Sprintf("%d of %d episodes", m.Coverage.Eligible, m.Coverage.Ordinary))}
	for _, a := range m.Confusion {
		if a.Configuration.Model != "" {
			out = append(out, field(w, "  ", "Model", path.Base(a.Configuration.Model)+", reward name "+a.Reward))
		}
		out = append(out, field(w, "  ", "Pass rule", ruleText(a)))
		if a.Status != "supported" {
			out = append(out, field(w, "  ", "Not available", cmp.Or(strings.Join(a.Reasons, " "), "No reason recorded")))
		} else {
			for _, c := range confusionRows(a) {
				n := "unavailable"
				if c.n != nil {
					n = strconv.Itoa(*c.n)
				}
				out = append(out, field(w, "  ", c.name, fmt.Sprintf("%s: grader %s, work %s", n, strings.ToLower(c.decision), strings.ToLower(c.work))))
			}
		}
		rate := func(name string, x Rate, what string) {
			value := "unavailable"
			if x.Unavailable != nil {
				value += ": " + *x.Unavailable
			} else if x.Value != nil {
				value = fmt.Sprintf("%s, %d/%d", percent(x), *x.Numerator, *x.Denominator)
			}
			if x.Value != nil {
				value += ", " + what
			}
			out = append(out, field(w, "  ", name, value))
		}
		rate("Pass rate", a.PassRate, "passed among scored episodes")
		if x := a.PassRate.Interval; len(x) == 2 {
			out = append(out, field(w, "  ", "95% interval", fmt.Sprintf("%.0f%% to %.0f%%, Wilson interval for the pass rate", 100*x[0], 100*x[1])))
		}
		if a.Status == "supported" {
			rate("False discovery", a.FalseDiscoveryRate, "incorrect work among passed work")
			rate("False negative", a.FalseNegativeRate, "rejected work among correct work")
		}
	}
	return out
}

// attemptRows are every Attacker try: its session, the problem it aimed at, how much it was told and how it ended.
func attemptRows(r Report, w int) []string {
	widths := []int{16, 10, 22, 30}
	out := []string{cols(w, "  ", widths, "Attempt", "Problem", "Help", "Result", "Reward")}
	for _, at := range r.Attack.Attempts {
		episode, problem := "-", cmp.Or(at.Problem, strings.Join(tested(at), ", "), "none")
		if at.Episode != nil {
			episode = *at.Episode
		}
		for _, p := range r.Attack.Problems {
			if at.Problem == "" && p.ID != "" && slices.ContainsFunc(tested(at), func(id string) bool { return slices.Contains(p.Findings, id) }) {
				problem = p.ID
			}
		}
		var rewards []string
		for _, k := range slices.Sorted(maps.Keys(at.Rewards)) {
			rewards = append(rewards, strings.TrimPrefix(k+" ", "reward ")+num(at.Rewards[k]))
		}
		out = append(out, cols(w, "  ", widths, episode, problem, cmp.Or(levelWords[at.Level], "-"), tryResult(r, at), cmp.Or(strings.Join(rewards, ", "), "-")))
	}
	if len(r.Attack.Attempts) == 0 {
		return []string{"  No try recorded."}
	}
	return out
}
