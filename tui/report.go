package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Report holds the fields of a run folder's report.json that the viewer reads. Python writes every
// word, status and number in it; the viewer only lays them out. docs/viewer.md lists the fields.
type Report struct {
	Dir           string                 `json:"-"`
	Status        string                 `json:"status"`
	Answer        []string               `json:"answer"`
	Analyses      map[string]string      `json:"analyses"`
	Configuration Configuration          `json:"configuration"`
	Ordinary      *Ordinary              `json:"ordinary"`
	Labels        *Labels                `json:"labels"`
	Metrics       *Metrics               `json:"metrics"`
	Inspections   map[string]*Inspection `json:"inspections"`
	Attack        *Attack                `json:"attack"`
	OtherEpisodes struct {
		Attacker []string `json:"attacker"`
	} `json:"other_episodes"`
	Warnings []string `json:"warnings"`
}

type Configuration struct {
	TaskDir          string           `json:"task_dir"`
	Models           map[string]Model `json:"models"`
	SpendingCap      *float64         `json:"spending_cap"`
	KnownCost        *float64         `json:"known_cost"`
	UnknownCostCalls int              `json:"unknown_cost_calls"`
	CancelledCalls   int              `json:"cancelled_calls"`
	Backend          string           `json:"backend"`
	ModalCost        *struct {
		AtRequests float64 `json:"at_requests"`
		AtLimits   float64 `json:"at_limits"`
	} `json:"modal_cost"`
}

type Model struct {
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
}

// Ordinary is the Simulator's pool: rewards per configuration of task, model and versions.
type Ordinary struct {
	Requested int `json:"requested"`
	Attempted int `json:"attempted"`
	Groups    []struct {
		Configuration struct {
			Model string `json:"model"`
		} `json:"configuration"`
		Rewards map[string]Rewards `json:"rewards"`
	} `json:"groups"`
}

type Rewards struct {
	Attempted         int          `json:"attempted"`
	Usable            int          `json:"usable"`
	Mean              *float64     `json:"mean"`
	Median            *float64     `json:"median"`
	SD                *float64     `json:"sd"`
	Skewness          *float64     `json:"skewness"`
	Distribution      [][2]float64 `json:"distribution"` // [reward, episodes]
	Flags             []*Flag      `json:"flags"`        // nil when absent or null, empty when Python raised none
	FlagsNotEvaluated *string      `json:"flags_not_evaluated"`
}

// Flag is a reward pattern Python names, with its reason; it is never a finding.
type Flag struct {
	Flag *string `json:"flag"`
	Text *string `json:"text"`
}

type Labels struct {
	Counts map[string]int `json:"counts"`
}

type Metrics struct {
	Confusion []Agreement `json:"confusion"`
}

// Agreement is one confusion group: the grader's native decision against the grader inspector's reference.
type Agreement struct {
	Configuration struct {
		Model string `json:"model"`
	} `json:"configuration"`
	Reward  string   `json:"reward"`
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
	Rule    *struct {
		Comparison *string   `json:"comparison"`
		Threshold  *float64  `json:"threshold"`
		PassValues []float64 `json:"pass_values"`
	} `json:"rule"`
	TP                 *int `json:"tp"`
	FP                 *int `json:"fp"`
	FN                 *int `json:"fn"`
	TN                 *int `json:"tn"`
	FalseDiscoveryRate Rate `json:"false_discovery_rate"`
	FalseNegativeRate  Rate `json:"false_negative_rate"`
	PassRate           Rate `json:"pass_rate"` // the grounded native rule's, apart from agreement
}

type Rate struct {
	Value       *float64  `json:"value"`
	Numerator   *int      `json:"numerator"`
	Denominator *int      `json:"denominator"`
	LowerBound  bool      `json:"lower_bound"`
	Unavailable *string   `json:"unavailable"`
	Interval    []float64 `json:"interval"` // the pass rate's 95% Wilson interval, lower and upper
}

type SearchAttempt struct {
	Phase    string `json:"phase"`
	Category string `json:"category"`
	Episode  string `json:"episode"`
	Number   int    `json:"number"`
	Status   string `json:"status"`
	Error    string `json:"error"`
}

type Inspection struct {
	Applicability map[string]string `json:"applicability"`
	Attempts      []SearchAttempt   `json:"attempts"`
	Experiments   []struct {
		Category string `json:"category"`
	} `json:"experiments"`
	Limits     []string             `json:"limits"`
	Status     string               `json:"status"`
	Categories map[string]string    `json:"categories"`
	Findings   map[string][]Finding `json:"findings"` // evidenced, inconclusive, legitimate
}

type Finding struct {
	Index          *int      `json:"index"`
	SupersededBy   *struct{} `json:"superseded_by"`
	ExecutionScope string    `json:"execution_scope"`
	Category       *string   `json:"category"`
	Claim          struct {
		Mechanism  string   `json:"mechanism"`
		Episode    string   `json:"episode"`
		Unresolved []string `json:"unresolved"`
		Limits     []string `json:"limits"`
	} `json:"claim"`
	Captured struct {
		NativeReward *float64 `json:"native_reward"`
		CopiedReward *float64 `json:"copied_grader_reward"`
		Check        *struct {
			ID          string `json:"id"`
			Requirement *struct {
				Excerpt string `json:"excerpt"`
				Path    string `json:"path"`
			} `json:"requirement"`
		} `json:"check"`
	} `json:"captured"`
	Interpretation struct {
		Interpretation string `json:"interpretation"`
		Citations      []struct {
			Excerpt string `json:"excerpt"`
			Path    string `json:"path"`
		} `json:"citations"`
	} `json:"interpretation"`
	Assessment struct {
		Outcome string   `json:"outcome"`
		Reasons []string `json:"reasons"`
		Limits  []string `json:"limits"`
	} `json:"assessment"`

	// Set by the viewer: which job found it, its id in the report, such as hack-3 for the hack inspector's assessment 3,
	// and for an attack finding what Python's exploits say it confirmed.
	Source, ID, Confirms string `json:"-"`
}

type Attack struct {
	Status          string                `json:"status"`
	MaximumAttempts int                   `json:"maximum_attempts"`
	Candidates      []Candidate           `json:"candidates"`
	Problems        []Problem             `json:"problems"` // absent before nudi 0.0.1
	Leads           []Problem             `json:"leads"`    // an older record's problems no evidence confirmed, with id and cause
	Attempts        []Attempt             `json:"attempts"`
	Findings        map[string][]Finding  `json:"findings"`
	Exploits        map[string][]*Exploit `json:"exploits"` // by kind; absent from pooled attack records
}

// Exploit is an attack finding that Python counts as an Attacker exploit, by its assessment index.
type Exploit struct {
	Assessment *int     `json:"assessment"`
	Candidate  *string  `json:"candidate"`
	Sources    []string `json:"sources"`
}

type Candidate struct {
	ID         string `json:"id"`
	ValidWork  bool   `json:"valid_work"`
	Conditions map[string]struct {
		Status string `json:"status"`
	} `json:"conditions"`
}

type Problem struct {
	Cause      string   `json:"cause"`
	Findings   []string `json:"findings"`
	Candidate  *string  `json:"candidate"`
	Reproduced bool     `json:"reproduced"`
	// The findings a reproduction tested; nil in reports written before the field.
	ReproducedFindings []string `json:"reproduced_findings"`

	// Problems formed as findings arrive carry these; older reports lack them.
	ID         string   `json:"id"`          // P1, G1 or A1
	Source     string   `json:"source"`      // hack inspector, grader inspector or Attacker
	Members    []string `json:"members"`     // the finding ids the judge found the same
	HelpNeeded string   `json:"help_needed"` // in older reports, the least help an Attacker needed
	Level      int      `json:"level"`       // the problem's place in the list, 1 to 5; 0 in older reports
	Label      string   `json:"label"`       // that place's text
	Scope      string   `json:"scope"`       // where its findings were evidenced, package or native; absent in older reports
	// The least information under which an Attacker exploit was observed, or why none was; absent in older reports.
	ExploitedWith string      `json:"exploited_with"`
	Conditions    []Condition `json:"conditions"` // nil in older reports
}

// Condition is one condition an Attacker tried a problem under.
type Condition struct {
	Condition string `json:"condition"` // full, minimal, none (aimed at the problem), elsewhere_LEVEL (aimed at another) or independent
	Exploited int    `json:"exploited"` // how many of its attempts exploited the problem
}

// why is the problem's `exploited_with`, or in older reports its `help_needed`.
func (p Problem) why() string {
	if p.ExploitedWith != "" {
		return p.ExploitedWith
	}
	return p.HelpNeeded
}

// independent says whether a no-hint Attacker not aimed at the problem exploited it; in older reports, level 5 says so.
func (p Problem) independent() bool {
	if p.Conditions == nil {
		return p.ladder() == 5
	}
	return slices.ContainsFunc(p.Conditions, func(c Condition) bool { return c.Condition == "independent" && c.Exploited > 0 })
}

// lead says whether a problem is a lead, one no evidence confirmed: level 1 in reports written before leads.
func (p Problem) lead() bool {
	return p.ladder() == 1
}

// ladder is the problem's place in the list, from `help_needed` in reports written before `level`.
func (p Problem) ladder() int {
	if p.Level > 0 {
		return p.Level
	}
	if l, ok := helpLevels[p.why()]; ok {
		return l
	}
	if p.why() == "no_guidance" || len(p.Findings) > 0 {
		return 2
	}
	return 1
}

// validWork says whether a problem's findings are correct work the grader fails, so it is no exploit.
func (r Report) validWork(p Problem) bool {
	return r.Attack != nil && slices.ContainsFunc(r.Attack.Candidates, func(c Candidate) bool { return c.ValidWork && slices.Contains(p.Findings, c.ID) })
}

type Attempt struct {
	Level     string   `json:"level"`   // none, full or minimal
	Problem   string   `json:"problem"` // the problem it attacked; absent before problems formed during the run
	Candidate *string  `json:"candidate"`
	Sources   []string `json:"sources"`
	Episode   *string  `json:"episode"`
	Status    string   `json:"status"`
}

// load reads DIR/report.json, never through a link that leads out of DIR. A report without an answer
// comes from a nudi older than 0.0.0 and is refused, as is one whose answer or rates are incomplete.
var legacyCategoryWarning = regexp.MustCompile(`(?s)^((?:hack|grader) inspector) categor(?:y|ies) (.+?) (?:is|are) \w+(?:: (.*))?$`)

func load(dir string) (Report, error) {
	path := filepath.Join(dir, "report.json")
	root, err := os.OpenRoot(dir)
	var b []byte
	if err == nil {
		b, err = root.ReadFile("report.json")
		root.Close()
	}
	if errors.Is(err, fs.ErrNotExist) {
		return Report{}, fmt.Errorf("%s has no report.json; nudi writes it when a run ends", dir)
	}
	if err != nil {
		return Report{}, fmt.Errorf("%s: %w", path, err)
	}
	// Report text comes from models, so characters that a terminal would obey or reorder are dropped first.
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return Report{}, fmt.Errorf("%s: %w", path, err)
	}
	if b, err = json.Marshal(clean(raw)); err != nil {
		return Report{}, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return Report{}, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case r.Answer == nil:
		return Report{}, fmt.Errorf("%s comes from a nudi older than 0.0.0, which wrote no answer; this viewer reads reports from nudi 0.0.0 on", path)
	case len(r.Answer) == 0:
		return Report{}, fmt.Errorf("%s has no answer lines", path)
	}
	if r.Metrics != nil {
		for _, a := range r.Metrics.Confusion {
			for _, x := range []Rate{a.FalseDiscoveryRate, a.FalseNegativeRate, a.PassRate} {
				if x.Value != nil && (x.Numerator == nil || x.Denominator == nil) {
					return Report{}, fmt.Errorf("%s has a rate without its counts", path)
				}
			}
		}
	}
	// Older reports keep generated category verdicts in their warnings and safety prose in their answer.
	var warnings []string
	for _, warning := range r.Warnings {
		if match := legacyCategoryWarning.FindStringSubmatch(warning); match != nil {
			if match[3] == "" {
				continue
			}
			warning = match[1] + " search limitation (" + match[2] + "): " + match[3]
		}
		warnings = append(warnings, warning)
	}
	r.Warnings = warnings
	for i, line := range r.Answer {
		r.Answer[i] = strings.TrimSuffix(line, " That does not show that the grader is safe.")
	}
	r.Dir = shown(dir)
	return r, nil
}

// shown is the run folder's name for display only, cleaned as report text is; files are read through the name as given.
func shown(dir string) string { return clean(filepath.Clean(dir)).(string) }

// clean drops control characters, except newline and tab, and format characters such as bidi
// overrides from every string in v, map keys included.
func clean(v any) any {
	switch v := v.(type) {
	case string:
		return strings.Map(func(c rune) rune {
			if unicode.IsControl(c) && c != '\n' && c != '\t' || unicode.Is(unicode.Cf, c) {
				return -1
			}
			return c
		}, v)
	case []any:
		for i := range v {
			v[i] = clean(v[i])
		}
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[clean(k).(string)] = clean(x)
		}
		return out
	}
	return v
}

func (r Report) task() string { return r.Configuration.TaskDir }

// sources are the jobs whose evidenced findings the viewer lists, in the report's order.
var sources = []string{"grader_inspector", "hack_inspector", "attack"}

func (r Report) section(source string) map[string][]Finding {
	if source == "attack" {
		if r.Attack == nil {
			return nil
		}
		return r.Attack.Findings
	}
	if in := r.Inspections[source]; in != nil {
		return in.Findings
	}
	return nil
}

// findings are the evidenced findings that are their check's latest reading, numbered from 1 in this order.
// An inspector's finding is named as Python names its attack candidate: hack-N or grader-N is that inspector's assessment N.
// Without its index it links to no candidate.
func (r Report) findings() []Finding {
	var out []Finding
	for _, source := range sources {
		for _, f := range r.section(source)["evidenced"] {
			if f.SupersededBy != nil {
				continue
			}
			f.Source, f.ID = source, f.check()
			if prefix, ok := strings.CutSuffix(source, "_inspector"); ok {
				f.ID = prefix + " index unavailable"
				if f.Index != nil {
					f.ID = fmt.Sprintf("%s-%d", prefix, *f.Index)
				}
			}
			out = append(out, f)
		}
	}
	for i, f := range out {
		if f.Source == "attack" && r.Attack.Exploits != nil {
			out[i].Confirms = r.confirms(out, f.Index)
		}
	}
	return out
}

// confirms says what the attack finding with assessment index confirmed, from its exploit entry: a finding
// that is no exploit confirms no tested finding. A missing index, on the finding or on any entry, attributes nothing.
func (r Report) confirms(found []Finding, index *int) string {
	known := index != nil
	for _, kind := range slices.Sorted(maps.Keys(r.Attack.Exploits)) {
		for _, e := range r.Attack.Exploits[kind] {
			if e == nil || e.Assessment == nil {
				known = false
				continue
			}
			if index == nil || *e.Assessment != *index {
				continue
			}
			ids := e.Sources
			if len(ids) == 0 && e.Candidate != nil {
				ids = []string{*e.Candidate}
			}
			return strings.TrimSpace(word(exploitWords, kind) + " " + strings.Join(names(found, ids), " and "))
		}
	}
	if !known {
		return "confirmation unavailable"
	}
	return "confirms no tested finding"
}

// count is the number of findings in a result bucket, every reading included, as the report lists them.
func (r Report) count(bucket string) int {
	n := 0
	for _, source := range sources {
		n += len(r.section(source)[bucket])
	}
	return n
}

func (f Finding) check() string {
	if f.Captured.Check == nil {
		return "no check"
	}
	return f.Captured.Check.ID
}

func (f Finding) reward() *float64 {
	if f.ExecutionScope == "package" {
		return f.Captured.CopiedReward
	}
	return f.Captured.NativeReward
}

// number is the viewer's number of the finding with report id id, or 0 when it is not listed.
func number(found []Finding, id string) int {
	for i, f := range found {
		if f.ID == id {
			return i + 1
		}
	}
	return 0
}

// started says whether an attempt's episode ran; an entry the spending cap or a stop blocked never started.
func (r Report) started(a Attempt) bool {
	if a.Episode == nil {
		return false
	}
	for _, e := range r.OtherEpisodes.Attacker {
		if e == *a.Episode {
			return true
		}
	}
	return false
}

// attempted says whether any started attempt tested candidate id.
func (r Report) attempted(id string) bool {
	for _, a := range r.Attack.Attempts {
		if r.started(a) && (slices.Contains(a.Sources, id) || a.Candidate != nil && *a.Candidate == id) {
			return true
		}
	}
	return false
}

// reproduced says whether the attack reproduced finding id of p. A report without reproduced_findings
// has only the problem's flag, which stands for its candidate.
func reproduced(p Problem, id string) bool {
	if p.ReproducedFindings == nil {
		return p.Reproduced && p.Candidate != nil && *p.Candidate == id
	}
	return slices.Contains(p.ReproducedFindings, id)
}

// problemOf is the problem whose findings include id, or -1.
func (r Report) problemOf(id string) int {
	if r.Attack == nil {
		return -1
	}
	for i, p := range r.Attack.Problems {
		if slices.Contains(p.Findings, id) {
			return i
		}
	}
	return -1
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// evidenceOf is the number of the finding that shows problem p, or 0: its candidate, else its first finding on the
// list, else for a problem an Attacker found the attack finding of one of its episodes.
func evidenceOf(found []Finding, p Problem) int {
	for _, id := range append(slices.DeleteFunc([]string{deref(p.Candidate)}, func(s string) bool { return s == "" }), p.Findings...) {
		if i := slices.IndexFunc(found, func(f Finding) bool { return f.ID == id }); i >= 0 {
			return i + 1
		}
	}
	return slices.IndexFunc(found, func(f Finding) bool { return f.Source == "attack" && slices.Contains(p.Members, f.Claim.Episode) }) + 1
}

// topProblem is the problem highest on the list whose evidence is on the list of findings, and that evidence's number;
// nil and 1 without one, as in reports whose problems lack exploited_with and help_needed.
func (r Report) topProblem(found []Finding) (*Problem, int) {
	if !r.helpNeeded() {
		return nil, 1
	}
	ps := slices.DeleteFunc(slices.Clone(r.Attack.Problems), Problem.lead)
	slices.SortStableFunc(ps, func(a, b Problem) int { return b.ladder() - a.ladder() })
	for _, p := range ps {
		if n := evidenceOf(found, p); n > 0 && p.ID != "" {
			return &p, n
		}
	}
	return nil, 1
}

// helpNeeded says whether the report's problems carry `exploited_with`, or `help_needed` in older reports, as problems
// formed during the run do.
func (r Report) helpNeeded() bool {
	return r.Attack != nil && slices.ContainsFunc(r.Attack.Problems, func(p Problem) bool { return p.why() != "" })
}
