package main

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// The four phase tabs: Simulation, Grade Simulations, Find Hacks and Attack.

// stageHead says whether phase i has results to show. The tab is the page title and carries the mark, so a phase
// the run left out, did not run or that failed says only why.
func stageHead(r Report, i int, p *page) bool {
	a := phases[i].Analysis
	if _, off := r.stage(i); off {
		p.add(wrap(leftOut(r), p.w, " ", plain))
		return false
	}
	switch {
	case r.PhaseErrors[a] != "":
		p.add(wrap(redStyle.Render("Error")+"  "+r.PhaseErrors[a], p.w, " ", plain), wrap(failedNote(r, phases[i].Name, a), p.w, " ", plain))
		if !kept(r, a) {
			return false
		}
		p.add("")
	case r.Analyses[a] == "not run":
		why := "Selected, but it did not start."
		if r.Stop != nil {
			why = "Selected, but it did not start before the run stopped."
		}
		p.add(wrap(why, p.w, " ", plain))
		return false
	}
	return true
}

// kept says whether phase a left results in the report, as one that failed may have before its error.
func kept(r Report, a string) bool {
	switch a {
	case "simulation":
		return r.Ordinary != nil && len(r.Ordinary.Groups) > 0
	case "attack":
		return r.Attack != nil
	}
	return r.Inspections[a+"_inspector"] != nil
}

// failedNote says what a phase that raised an error leaves: the results it kept before the error, or what the run
// therefore does not show.
func failedNote(r Report, name, a string) string {
	if kept(r, a) {
		return name + " failed before it finished. Its results here are from before the error."
	}
	return failedWords[a]
}

// leftOut says which choice of analyses left a phase out.
func leftOut(r Report) string {
	selected := slices.Sorted(maps.Keys(r.Analyses))
	switch {
	case slices.Equal(selected, []string{"grader", "simulation"}):
		return "This run used --analysis simulation, which leaves out the hack search and the Attack."
	case slices.Equal(selected, []string{"attack", "hack"}):
		return "This run used --analysis hacking, which leaves out the Simulation and Grade Simulations."
	}
	return "The run did not select this phase."
}

// simulationPage is the Simulator's rewards: a chart, the statistics and the reward pattern, whose method ? explains;
// p lists the episodes.
func simulationPage(r Report, found []Finding, p *page) {
	o := r.Ordinary
	if !stageHead(r, 0, p) {
		return
	}
	if o == nil || len(o.Groups) == 0 {
		p.add(" " + dim("No simulation result recorded."))
		return
	}
	for _, g := range o.Groups {
		for _, name := range slices.Sorted(maps.Keys(g.Rewards)) {
			x := g.Rewards[name]
			if len(o.Groups) > 1 || len(g.Rewards) > 1 {
				p.add(" "+dim(group(g.Configuration.Model, name)), "")
			}
			widths := []int{21, 12, 13, 13, 13}
			p.add(heading("Rewards", ""))
			p.add(rewardBars(x, 5, p.w)...)
			p.add("", heading("Statistics", ""),
				cols(p.w, " ", widths, dim("Usable / attempted"), dim("Requested"), dim("Mean"), dim("Median"), dim("Sample SD"), dim("Skewness")),
				cols(p.w, " ", widths, fmt.Sprintf("%d/%d", x.Usable, x.Attempted), strconv.Itoa(o.Requested), num(x.Mean), num(x.Median), num(x.SD), num(x.Skewness)))
			p.add("", spread(heading("Reward Pattern", ""), p.fold("?"), p.w))
			for _, line := range warnings(x) {
				p.add(wrap(line, p.w, " ", amber))
			}
			// The flagged episodes and their rewards are in the method and the episodes; only what has no warning stays.
			for _, line := range patterns(x, g.EpisodeRewards, name) {
				if line == unavailable || line == "No pattern flagged." {
					p.add(wrap(line, p.w, " ", plain))
				}
			}
			if x.FlagsNotEvaluated != nil {
				p.add(wrap(*x.FlagsNotEvaluated, p.w, " ", dim))
			}
			if p.open["?"] {
				p.add("", method(r, found, x, p.w))
			}
		}
	}
	if n := len(o.Groups[0].EpisodeRewards); n > 0 {
		p.add("")
		if p.toggle("p", "Episodes", fmt.Sprintf("(%d)", n)) {
			episodesTable(r, found, p)
		}
	}
}

// unavailable is the reward pattern of a report whose flags lack their details.
const unavailable = "Pattern details unavailable."

// patterns say each flagged reward pattern in one line: how many episodes received what, against the others. The
// pattern's name is in the method panel.
func patterns(x Rewards, rewards map[string]map[string]*float64, key string) []string {
	if x.Flags == nil {
		return []string{unavailable}
	}
	var out []string
	for _, f := range x.Flags {
		if f == nil || f.Flag == nil || f.Text == nil {
			out = append(out, unavailable)
			continue
		}
		if rewards == nil { // reports written before rewards per episode
			out = append(out, fmt.Sprintf("%d episode%s flagged; rewards per episode unavailable.", len(f.Episodes), plural(len(f.Episodes))))
			continue
		}
		var named, rest []*float64
		for _, e := range slices.Sorted(maps.Keys(rewards)) {
			if slices.Contains(f.Episodes, e) {
				named = append(named, rewards[e][key])
			} else if v := rewards[e][key]; v != nil {
				rest = append(rest, v) // the others' usable rewards only
			}
		}
		line := fmt.Sprintf("%d episode%s received %s", len(f.Episodes), plural(len(f.Episodes)), values(named))
		if len(rest) > 0 {
			line += fmt.Sprintf("; the other %d received %s", len(rest), values(rest))
		}
		out = append(out, line+".")
	}
	if len(out) == 0 && x.FlagsNotEvaluated == nil {
		out = append(out, "No pattern flagged.")
	}
	return out
}

// flagWarnings are what each reward pattern may point to, and flagReasons why nudi flagged it.
var (
	flagWarnings = map[string]string{
		"low_minority":      "Possibly a bad system prompt or grader<->prompt mismatch",
		"high_minority":     "Possibly a hack or a grader that passes wrong work",
		"identical_rewards": "Possibly a task that is too easy or too hard, or a grader that ignores the work",
	}
	flagReasons = map[string]string{
		"low_minority":      "A few rewards far below the rest",
		"high_minority":     "A few rewards far above the rest",
		"identical_rewards": "Every usable reward is the same",
	}
)

// warnings are one line for each kind of reward pattern flagged; none when nothing is flagged.
func warnings(x Rewards) []string {
	var out []string
	for _, f := range x.Flags {
		if f == nil || f.Flag == nil || f.Text == nil {
			continue
		}
		if w, ok := lookup(flagWarnings, *f.Flag); ok && !slices.Contains(out, "Warning: "+w) {
			out = append(out, "Warning: "+w)
		}
	}
	return out
}

// values is the range of the rewards given, or one reward when they are all the same.
func values(xs []*float64) string {
	var known []float64
	for _, x := range xs {
		if x != nil {
			known = append(known, *x)
		}
	}
	if len(known) == 0 {
		return "no usable reward"
	}
	lo, hi := slices.Min(known), slices.Max(known)
	if lo == hi {
		return strconv.FormatFloat(lo, 'g', 4, 64)
	}
	return strconv.FormatFloat(lo, 'g', 4, 64) + " to " + strconv.FormatFloat(hi, 'g', 4, 64)
}

// method explains how nudi reads the first flagged pattern, its reason first, with this run's numbers and its episodes.
// Python's text, which repeats the rows and the warning, is left to the plain output.
func method(r Report, found []Finding, x Rewards, w int) string {
	var rows []string
	for _, kv := range methodRows(r, found, x) {
		switch kv[0] {
		case "Reason":
			rows = append(rows, wrap("Reason for warning: "+kv[1], w-4, "", plain), "")
		case "Details":
		default:
			rows = append(rows, cols(w-4, "", []int{11}, dim(kv[0]), kv[1]))
		}
	}
	if rows == nil {
		rows = []string{dim("No pattern to explain.")}
	}
	return box("Reward Patterns Explainer", keyText("?")+" "+dim("collapse"), w-1, rows...)
}

// methodRows are the method's rows, each a name and its text; none without a flagged pattern.
func methodRows(r Report, found []Finding, x Rewards) [][2]string {
	var f *Flag
	for _, g := range x.Flags {
		if g != nil && g.Flag != nil && g.Text != nil {
			f = g
			break
		}
	}
	if f == nil {
		return nil
	}
	rules := map[string]string{
		"low_minority":      "A reward is unusually low when it is below Q1 - 3 x IQR.",
		"high_minority":     "A reward is unusually high when it is above Q3 + 3 x IQR.",
		"identical_rewards": "Every usable reward has the same value.",
	}
	rows := [][2]string{{"Reason", word(flagReasons, *f.Flag)}, {"Rule", rules[*f.Flag]}}
	if len(f.Quartiles) == 2 && f.Fence != nil {
		rows = append(rows, [2]string{"Terms", "Q1 is the first quartile and Q3 the third. IQR is Q3 - Q1, the spread of the middle half."},
			[2]string{"This run", fmt.Sprintf("Q1 is %s and Q3 is %s, so the fence is %s.", num(&f.Quartiles[0]), num(&f.Quartiles[1]), num(f.Fence))})
	}
	for i, e := range f.Episodes {
		name := ""
		if i == 0 {
			name = "Episodes"
		}
		rows = append(rows, [2]string{name, pad(e, 17) + reading(r, found, e)})
	}
	recorded := "No error, timeout or refusal in these episodes."
	for _, e := range f.Episodes {
		rec, ok := f.Recorded[e]
		if !ok {
			recorded = "Not recorded."
			break
		}
		if rec.AgentTimeout || rec.VerifierTimeout || len(rec.Errors) > 0 || len(rec.Refusals) > 0 {
			recorded = "At least one episode recorded an error, timeout or refusal."
		}
	}
	rows = append(rows, [2]string{"Recorded", recorded}, [2]string{"Details", *f.Text})
	if f.Minimum != nil {
		rows = append(rows, [2]string{"Minimum", fmt.Sprintf("nudi checks this only with %d or more usable rewards.", *f.Minimum)})
	}
	return rows
}

// reading is what the Grader Inspector's label and the grader's decision make of episode e, with its problem.
func reading(r Report, found []Finding, e string) string {
	label, decision := "", ""
	if r.Labels != nil {
		label = r.Labels.Episodes[e].Label
	}
	if r.Metrics != nil {
		decision = deref(r.Metrics.Episodes[e].Decision)
	}
	s, ok := verdictWords[label+" "+decision]
	if !ok {
		s = verdictWords[label]
	}
	if id := episodeProblem(r, found, e); id != "" {
		s = strings.TrimPrefix(s+", problem "+id, ", ")
	}
	return s
}

// episodeProblem is the problem an episode belongs to, by its sessions or its findings' episodes.
func episodeProblem(r Report, found []Finding, e string) string {
	if r.Attack == nil {
		return ""
	}
	for _, p := range r.Attack.Problems {
		if slices.Contains(p.Members, e) || slices.ContainsFunc(found, func(f Finding) bool { return f.Claim.Episode == e && slices.Contains(p.Findings, f.ID) }) {
			return p.ID
		}
	}
	return ""
}

// episodesTable lists the simulated episodes, lowest reward first, with what the Grader Inspector made of each.
func episodesTable(r Report, found []Finding, p *page) {
	g := r.Ordinary.Groups[0]
	key := slices.Sorted(maps.Keys(g.Rewards))
	episodes := slices.Sorted(maps.Keys(g.EpisodeRewards))
	reward := func(e string) *float64 {
		if len(key) == 0 {
			return nil
		}
		return g.EpisodeRewards[e][key[0]]
	}
	slices.SortStableFunc(episodes, func(a, b string) int {
		x, y := reward(a), reward(b)
		switch {
		case x == nil || y == nil:
			return cmp.Compare(boolInt(x == nil), boolInt(y == nil))
		}
		return cmp.Compare(*x, *y)
	})
	widths := []int{18, 9, 15, 40}
	p.add(cols(p.w, "   ", widths, dim("Episode"), dim("Reward"), dim("Label"), dim("Grader Inspector"), dim("Ref")))
	for _, e := range episodes {
		label := "-"
		if r.Labels != nil {
			if l, ok := r.Labels.Episodes[e]; ok {
				label = word(labelWords, l.Label)
			}
		}
		switch label {
		case "Mismatch":
			label = redStyle.Render(label)
		case "Legitimate", "-":
		default:
			label = dim(label)
		}
		what := reading(r, found, e)
		problem := episodeProblem(r, found, e)
		what = strings.TrimSuffix(strings.TrimSuffix(what, "problem "+problem), ", ")
		if what == "" {
			what = dim("-")
		}
		p.add(cols(p.w, "   ", widths, e, num(reward(e)), label, what, dim(problem)))
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// gradePage is the grader's accuracy against the Grader Inspector's reference: the four kinds of decision, the
// metrics, the episode labels, and, behind s, what the Grader Inspector looked for. e shows the metrics' fractions and
// the meanings of metrics and labels.
func gradePage(r Report, p *page) {
	if !stageHead(r, 1, p) {
		return
	}
	if r.Metrics == nil || len(r.Metrics.Confusion) == 0 {
		p.add(" " + yellowStyle.Render("No grader accuracy recorded."))
	}
	if m := r.Metrics; m != nil {
		used := ""
		if m.Coverage.Ordinary > 0 {
			used = dim("Used for accuracy ") + fmt.Sprintf("%d/%d", m.Coverage.Eligible, m.Coverage.Ordinary)
		}
		for i, a := range m.Confusion {
			agreement(a, len(m.Confusion) > 1, used, p)
			if i == 0 {
				used = ""
			}
		}
	}
	if l := r.Labels; l != nil && len(l.Counts) > 0 {
		p.add(spread(heading("Episode Labels", ""), p.fold("e"), p.w))
		widths := []int{17, 11, 44}
		labelRow := func(cells ...string) string {
			if !p.open["e"] {
				cells = slices.Delete(cells, 2, 3)
			}
			return cols(p.w, " ", widths, cells...)
		}
		p.add(labelRow(dim("Label"), dim("Episodes"), dim("Meaning"), dim("Used for accuracy")))
		var excluded []string
		if r.Metrics != nil {
			for _, es := range r.Metrics.Coverage.Excluded {
				excluded = append(excluded, es...)
			}
		}
		counts, in := map[string]int{}, map[string]int{}
		for label, n := range l.Counts {
			counts[word(labelWords, label)] += n
		}
		for e, x := range l.Episodes {
			if !slices.Contains(excluded, e) {
				in[word(labelWords, x.Label)]++
			}
		}
		for _, name := range []string{"Legitimate", "Mismatch", "Unresolved", "Unavailable", "Ungrounded", "Not reviewed"} {
			if counts[name] == 0 {
				continue
			}
			meaning := labelMeanings[name]
			if refs := graderProblems(r); name == "Mismatch" && refs != "" {
				meaning += ": " + refs
			}
			answer := map[bool]string{true: greenStyle.Render("✓"), false: dim("✗")}[in[name] > 0]
			if in[name] > 0 && in[name] < counts[name] {
				answer = fmt.Sprintf("%d/%d", in[name], counts[name])
			}
			if r.Metrics == nil {
				answer = dim("-")
			}
			p.add(labelRow(name, strconv.Itoa(counts[name]), meaning, answer))
		}
		p.add("")
	}
	if in := r.Inspections["grader_inspector"]; in != nil {
		scope(r, in, "Grader Inspector", "s", p)
	}
}

// graderProblems are the ids of the problems the Grader Inspector found.
func graderProblems(r Report) string {
	if r.Attack == nil {
		return ""
	}
	var ids []string
	for _, p := range r.Attack.Problems {
		if strings.HasPrefix(p.ID, "G") && !p.lead() {
			ids = append(ids, p.ID)
		}
	}
	return strings.Join(ids, ", ")
}

// agreement draws one confusion group: the four kinds of decision, then the metrics. Without grader agreement it
// says why, and the pass rate still stands with its rule.
// With several groups, each names its Simulator model and reward.
// used, how many simulated episodes the accuracy uses, goes on the right of the header.
func agreement(a Agreement, several bool, used string, p *page) {
	note := ""
	if several {
		note = group(a.Configuration.Model, a.Reward)
	}
	p.add(spread(heading("Grader Accuracy", note), used, p.w))
	if a.Status == "supported" {
		widths := []int{17, 9, 13}
		p.add(cols(p.w, " ", widths, dim("Type"), dim("Grader"), dim("Work was"), dim("Episodes")))
		for _, c := range confusionRows(a) {
			p.add(c.style.Render(cols(p.w, " ", widths, c.name, c.decision, c.work, c.bar(a, 15))))
		}
	} else {
		p.add(wrap("Not available: "+strings.Join(a.Reasons, " "), p.w, " ", amber))
	}
	widths := []int{23, 13, 11}
	row := func(cells ...string) string {
		if !p.open["e"] && len(cells) > 2 {
			cells = cells[:2]
		}
		return cols(p.w, " ", widths, cells...)
	}
	p.add("", spread(heading("Metrics", ""), p.fold("e"), p.w), row(dim("Metric"), dim("Value"), dim("Fraction"), dim("Meaning")))
	metric := func(name string, x Rate, basis string) {
		value, fraction := "unavailable", ""
		if x.Unavailable != nil {
			basis = *x.Unavailable
		} else if x.Value != nil {
			value, fraction = percent(x), fmt.Sprintf("%d/%d", *x.Numerator, *x.Denominator)
		}
		p.add(row(name, value, fraction, dim(basis)))
	}
	metric("Pass rate", a.PassRate, "Passed among scored episodes")
	if x := a.PassRate.Interval; len(x) == 2 {
		p.add(row("95% interval", fmt.Sprintf("%.0f%% to %.0f%%", 100*x[0], 100*x[1]), "", dim("Wilson interval for the pass rate")))
	}
	if a.Status == "supported" {
		metric("False discovery rate", a.FalseDiscoveryRate, "Incorrect work among passed work")
		metric("False negative rate", a.FalseNegativeRate, "Rejected work among correct work")
	}
	p.add(row("Pass rule", ruleText(a)), "")
}

// ruleText is the grader's native decision rule that pass and fail stand for.
func ruleText(a Agreement) string {
	switch rule := a.Rule; {
	case rule == nil:
		return "no native decision rule"
	case len(rule.PassValues) > 0:
		var values []string
		for _, v := range rule.PassValues {
			values = append(values, rewardText(v))
		}
		return a.Reward + " " + strings.Join(values, " or ")
	case rule.Comparison != nil && rule.Threshold != nil:
		return a.Reward + " " + *rule.Comparison + " " + rewardText(*rule.Threshold)
	}
	return "no native decision rule"
}

// searched are the categories an inspector's search covered: each one an attempt, experiment or finding names, and
// for a broad attempt every category that is not restricted.
func searched(in *Inspection) map[string]bool {
	out := map[string]bool{}
	for _, at := range in.Attempts {
		out[at.Category] = true
		if at.Phase == "broad" {
			for code, state := range in.Categories {
				if state != "restricted" {
					out[code] = true
				}
			}
		}
	}
	for _, ex := range in.Experiments {
		out[ex.Category] = true
	}
	for _, group := range in.Findings {
		for _, f := range group {
			out[text(f.Category)] = true
		}
	}
	return out
}

// scope is an inspector's search behind key: what it looked for in each category it searched, how many findings
// it evidenced there, the categories it did not search and why, its search attempts and its limits.
func scope(r Report, in *Inspection, job, key string, p *page) {
	codes := slices.Sorted(maps.Keys(in.Categories))
	if !p.toggle(key, "Search Scope", fmt.Sprintf("(%d categor%s)", len(codes), map[bool]string{true: "y", false: "ies"}[len(codes) == 1])) {
		return
	}
	done := searched(in)
	widths := []int{26, 60}
	var skipped []string
	if len(codes) > 0 {
		p.add(cols(p.w, "   ", widths, dim("Category"), dim("Looked for"), dim("Found")))
	}
	for _, code := range codes {
		found := "-"
		if done[code] {
			n := 0
			for _, f := range in.Findings["evidenced"] {
				if f.SupersededBy == nil && text(f.Category) == code {
					n++
				}
			}
			found = strconv.Itoa(n)
		} else {
			why := in.Applicability[code]
			if why == "" || in.Categories[code] != "restricted" {
				why = "no search attempt recorded"
			}
			skipped = append(skipped, word(checkNames, code)+": "+why)
		}
		looked, _ := lookup(lookedFor, code)
		p.add(cols(p.w, "   ", widths, word(checkNames, code), looked, found))
	}
	for _, s := range skipped {
		p.add(wrap("Not searched: "+s, p.w, "   ", dim))
	}
	if len(in.Attempts) > 0 {
		p.add("", cols(p.w, "   ", []int{14, 30}, dim("Search"), dim("Target"), dim("Ended")))
		for _, at := range in.Attempts {
			status := map[string]string{"evidenced_issue": "completed", "no_evidenced_issue": "completed", "unknown": "ended"}[at.Status]
			if status == "" {
				status = strings.ReplaceAll(at.Status, "_", " ")
			}
			if at.Error != "" {
				status += ": " + strings.SplitN(at.Error, "\n", 2)[0]
			}
			p.add(cols(p.w, "   ", []int{14, 30}, fmt.Sprintf("%s %d", at.Phase, at.Number), searchTarget(at), status))
		}
	}
	for _, l := range in.Limits {
		p.add(wrap(strings.TrimSuffix(l, ", so they are unknown"), p.w, "   ", dim))
	}
}

// hacksPage is the Hack Inspector's search: the problems it found and whether an Attacker demonstrated them, the
// ideas it did not reproduce, its open questions, and behind s and x its search and its experiments.
func hacksPage(r Report, found []Finding, p *page) {
	if !stageHead(r, 2, p) {
		return
	}
	var ps []Problem
	if r.Attack != nil && r.Attack.Problems != nil {
		ps = slices.DeleteFunc(problems(r), func(p Problem) bool {
			return strings.HasPrefix(p.ID, "G") || p.Source == "grader inspector" || p.Source == "Attacker"
		})
		widths := []int{46, 14, 12}
		if len(ps) == 0 {
			p.add(titled("Problems Found", 0), " None found in this run.")
		} else {
			p.add(spread(titled("Problems Found", len(ps)), p.fold("e"), p.w))
			if p.open["e"] {
				p.add(cols(p.w, "   ", []int{15}, dim("Reproduced?"), dim("The Hack Inspector made it happen in a copy of the task.")),
					cols(p.w, "   ", []int{15}, dim("Attacker?"), dim("An Attacker made it happen in a real episode. The Attack tab shows how.")), "")
			}
			p.add(cols(p.w, "   ", widths, dim("Problem"), dim("Reproduced?"), dim("Attacker?"), dim("Ref")))
		}
		for _, pr := range ps {
			p.pick(evidenceOf(found, pr), "", func(mark string, on bool) string {
				name := strings.Join(strings.Fields(pr.Cause), " ")
				reproduced := map[bool]string{true: "yes", false: "-"}[len(pr.Findings) > 0]
				if e := pr.EvidencedByInspector; e != nil {
					reproduced = map[bool]string{true: "yes", false: "no"}[*e]
				}
				attacker := best(r.tried(pr, "none"), r.tried(pr, "minimal"), r.tried(pr, "full"))
				return cols(p.w, mark, widths, name, under("Reproduced?", glyph(reproduced)), under("Attacker?", glyph(attacker)), dim(pr.ID))
			})
		}
		p.add("")
	}
	in := r.Inspections["hack_inspector"]
	if in == nil {
		p.add(" " + dim("No hack search result recorded."))
		return
	}
	if ps == nil {
		findingsTable(found, "hack_inspector", p)
		p.add("")
	}
	var ideas []Finding
	for _, f := range in.Findings["legitimate"] {
		if f.SupersededBy == nil {
			ideas = append(ideas, f)
		}
	}
	p.add(titled("Ideas Not Reproduced", len(ideas)))
	if len(ideas) == 0 {
		p.add(" None recorded.")
	} else {
		widths := []int{46, 14}
		p.add(cols(p.w, "   ", widths, dim("Idea"), dim("Reproduced?"), dim("What happened")))
		for _, f := range ideas {
			what := ""
			if len(f.Assessment.Reasons) > 0 {
				what = f.Assessment.Reasons[0]
			}
			p.add(cols(p.w, "   ", widths, title(f), under("Reproduced?", glyph("no")), what))
		}
	}
	questions := append(openItems(in), unresolvedFindings(in, "hack_inspector")...)
	p.add("", titled("Open Questions", len(questions)))
	if len(questions) == 0 {
		p.add(" None recorded.")
	} else {
		p.add(cols(p.w, "   ", []int{46}, dim("Question"), dim("Why it is open")))
		for _, q := range questions {
			p.add(cols(p.w, "   ", []int{46}, q[0], q[1]))
		}
	}
	p.add("")
	scope(r, in, "Hack Inspector", "s", p)
	if len(in.Experiments) > 0 && p.toggle("x", "Experiments", fmt.Sprintf("(%d)", len(in.Experiments))) {
		widths := []int{18, 26, 16}
		p.add(cols(p.w, "   ", widths, dim("Experiment"), dim("Category"), dim("Status"), dim("Episode")))
		for _, ex := range in.Experiments {
			p.add(cols(p.w, "   ", widths, ex.ID, word(checkNames, ex.Category), experimentEnd(ex.Status), ex.Episode))
		}
	}
}

// experimentWords say how an inspector's experiment ended, when it did not fail or stop.
var experimentWords = map[string]string{"assessed": "Done", "measured": "Ran, not read", "unfinished": "Ran, not read",
	"incomplete": "Check broken", "known_problem": "Known problem", "running": "Not finished"}

// experimentEnd is how an experiment ended: its words, else an error, whose cause Work left names, else stopped.
func experimentEnd(status string) string {
	if w, ok := experimentWords[status]; ok {
		return w
	}
	if res, _ := lookup(attemptResults, status); res == Failed {
		return "Error"
	}
	return "Stopped"
}

// helpWords name an attempt's hint level as the tables' columns do.
var helpWords = map[string]string{"none": "No info", "minimal": "Hint", "full": "Full"}

// attackPage is the Attack: for each hack, each rejection of correct work and each problem whose type the report does
// not record, whether an Attacker demonstrated it, by how much it was told, with its tries behind Enter; then whether
// an Attacker told nothing succeeded.
func attackPage(r Report, found []Finding, p *page) {
	a := r.Attack
	if !stageHead(r, 3, p) {
		return
	}
	if a == nil {
		p.add(" " + dim("No Attacker result recorded."))
		return
	}
	if a.Problems == nil {
		triesTable(r, found, a.Attempts, true, p)
	} else {
		var hacks, rejected, unknown []Problem
		for _, pr := range problems(r) {
			switch problemType(r, pr) {
			case "False negative":
				rejected = append(rejected, pr)
			case "Unavailable":
				unknown = append(unknown, pr)
			default:
				hacks = append(hacks, pr)
			}
		}
		attackTable(r, found, "Hacks", hacks, true, p)
		attackTable(r, found, "Correct Work Rejected", rejected, false, p)
		if len(unknown) > 0 {
			attackTable(r, found, "Type Not Recorded", unknown, false, p)
		}
	}
	p.add(heading("Can an Attacker Succeed Without Any Information?", ""))
	var alone []Attempt
	for _, at := range a.Attempts {
		if len(tested(at)) == 0 && at.Problem == "" {
			alone = append(alone, at)
		}
	}
	switch d := a.Discovery; {
	case len(alone) > 0:
		widths := []int{6, 21, 15}
		p.add(cols(p.w, "   ", widths, dim("Try"), dim("Hack demonstrated?"), dim("New finding?"), dim("Same as")))
		for i, at := range alone {
			demonstrated, fresh, same := "-", "-", ""
			if r.started(at) {
				res, _ := lookup(attemptResults, at.Status)
				demonstrated = map[Result]string{Evidenced: "yes", NoIssue: "no", Elsewhere: "yes", Unsettled: "?"}[res]
				if demonstrated == "" {
					demonstrated = "-"
				}
			}
			for _, pr := range a.Problems {
				if at.Episode != nil && slices.Contains(pr.Members, *at.Episode) {
					demonstrated = "yes"
					// An Attacker problem is new for the try the judge first placed in it.
					if pr.Source == "Attacker" && pr.Members[0] == *at.Episode {
						fresh = "yes"
					} else {
						fresh, same = "no", strings.Join(strings.Fields(pr.Cause), " ")
					}
				}
			}
			p.add(cols(p.w, "   ", widths, strconv.Itoa(i+1), under("Hack demonstrated?", glyph(demonstrated)), under("New finding?", glyph(fresh)), same))
		}
	case d == nil:
		p.add(" No try recorded.")
	case d.MaximumAttempts == 0:
		p.add(" Not tested: not allowed in this run.")
	default:
		p.add(" Not tested: " + word(notTestedWords, d.Status) + ".")
	}
}

// attackTable lists problems with the answer under each hint level; Enter expands a row into its tries, which then
// carry its answers.
func attackTable(r Report, found []Finding, name string, ps []Problem, first bool, p *page) {
	if first {
		attackHead(titled(name, len(ps)), p)
	} else {
		p.add(titled(name, len(ps)))
	}
	if len(ps) == 0 {
		p.add(" None in this run.", "")
		return
	}
	widths := []int{44, 9, 6}
	p.add(cols(p.w, "     ", widths, dim("Problem"), dim("No info"), dim("Hint"), dim("Full")))
	for _, pr := range ps {
		key := "tries " + pr.ID + " " + pr.Cause
		aimed := r.aimed(pr)
		p.pick(0, key, func(mark string, on bool) string {
			arrow := dim("▸") + " "
			if p.open[key] {
				arrow = dim("▾") + " "
			}
			cause := strings.Join(strings.Fields(pr.Cause), " ")
			if p.open[key] {
				return cols(p.w, mark+arrow, widths, cause, "")
			}
			return cols(p.w, mark+arrow, widths, cause, under("No info", glyph(r.tried(pr, "none"))), under("Hint", glyph(r.tried(pr, "minimal"))),
				under("Full", glyph(r.tried(pr, "full"))))
		})
		if p.open[key] {
			triesTable(r, found, aimed, false, p)
		}
	}
	p.add("")
}

// attackHead is the first title on the Attack tab. It carries the e hint, and the legend opens under it.
func attackHead(title string, p *page) {
	p.add(spread(title, p.fold("e"), p.w))
	if p.open["e"] {
		p.add(symbols, wrap("✓* The Attacker got the reward with a different hack than the one it was told about.", p.w, " ", dim), "")
	}
}

// triesTable lists attempts: their hint level, whether each succeeded, with * for another hack than its own, how it ended,
// its reward and its session; Enter opens an attempt's finding. Reports without problems also name what it tested.
func triesTable(r Report, found []Finding, attempts []Attempt, flat bool, p *page) {
	indent := "       "
	if flat {
		indent = "   "
		attackHead(titled("Tries", len(attempts)), p)
	}
	if len(attempts) == 0 {
		p.add(indent+dim("No try recorded."), "")
		return
	}
	widths := []int{5, 9, 12, 13, 8}
	heads := []string{"Try", "Help", "Succeeded", "Status", "Reward", "Attempt"}
	if flat {
		widths = []int{5, 12, 9, 12, 13, 8}
		heads = slices.Insert(heads, 1, "Tested")
	}
	var cells []string
	for _, h := range heads {
		cells = append(cells, dim(h))
	}
	p.add(cols(p.w, indent, widths, cells...))
	for i, at := range attempts {
		res, _ := lookup(attemptResults, at.Status)
		succeeded, status := glyph("-"), resultWords[res]
		if r.started(at) {
			if res == NotTested {
				status = stoppedWords(at.Status) // its episode started
			}
			succeeded = glyph(answers[res])
			if res == Elsewhere {
				succeeded = glyph("yes") + dim("*")
			}
		} else {
			status = resultWords[NotTested]
		}
		reward := "-"
		for _, k := range slices.Sorted(maps.Keys(at.Rewards)) {
			reward = num(at.Rewards[k])
			break
		}
		episode := "-"
		n := 0
		if at.Episode != nil {
			episode = *at.Episode
			n = slices.IndexFunc(found, func(f Finding) bool { return f.Source == "attack" && f.Claim.Episode == episode }) + 1
		}
		help := helpWords[at.Level]
		if help == "" {
			help = "-"
		}
		row := []string{strconv.Itoa(i + 1), help, under("Succeeded", succeeded), status, reward, dim(episode)}
		if flat {
			row = slices.Insert(row, 1, strings.Join(tested(at), ", "))
		}
		p.pick(n, "", func(mark string, _ bool) string { return cols(p.w, indent[:len(indent)-3]+mark, widths, row...) })
	}
	p.add("")
}
