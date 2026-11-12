package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Report holds the fields of a run folder's report.json that the viewer reads. Python writes every
// word, status and number in it; the viewer only lays them out. docs/viewer.md lists the fields.
type Report struct {
	Dir           string                 `json:"-"`
	SchemaVersion int                    `json:"schema_version"` // 2 when each problem is one reading with its own level, 3 when levels come from the help given; 0 before the field
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

	// Absent in reports written before them, which leaves these nil: not recorded, never none.
	Unfinished  map[string]string `json:"unfinished"`   // each step that did not run to its end, by its status
	Unresolved  []string          `json:"unresolved"`   // each step that ran to its end with evidence left unresolved
	Elapsed     *float64          `json:"elapsed"`      // the run's seconds, also null when a time was not recorded
	Stop        *Stop             `json:"stop"`         // nil for a run that ended on its own; a report without PhaseErrors predates it
	PhaseErrors map[string]string `json:"phase_errors"` // the error each analysis raised
	Ungrouped   []string          `json:"ungrouped"`    // evidenced inspector findings no problem holds
}

// Stop is why a run stopped before its end.
type Stop struct {
	Kind    string   `json:"kind"`    // cancelled, terminated, time_limit, spending_cap, provider_refused or stopped
	Phase   string   `json:"phase"`   // the analysis it stopped, when known
	Minutes *float64 `json:"minutes"` // the time limit, when known
	Reason  string   `json:"reason"`  // why nudi report wrote the report of a run that did not close out, or the provider's refusal
}

type Configuration struct {
	TaskDir          string           `json:"task_dir"`
	Models           map[string]Model `json:"models"`
	SpendingCap      *float64         `json:"spending_cap"`
	KnownCost        *float64         `json:"known_cost"`
	UnknownCostCalls int              `json:"unknown_cost_calls"`
	CancelledCalls   int              `json:"cancelled_calls"`
	UnknownReasons   map[string]int   `json:"unknown_reasons"`
	Capacity         struct {
		Concurrency int `json:"concurrency"`
	} `json:"capacity"`
	Backend   string `json:"backend"`
	ModalCost *struct {
		AtRequests    float64 `json:"at_requests"`
		AtLimits      float64 `json:"at_limits"`
		Sandboxes     int     `json:"sandboxes"`
		WithoutLimits int     `json:"without_limits"`
		StillRunning  int     `json:"still_running"`
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
		Rewards        map[string]Rewards             `json:"rewards"`
		Episodes       []string                       `json:"episodes"`
		EpisodeRewards map[string]map[string]*float64 `json:"episode_rewards"` // null for a value that is not a finite number
	} `json:"groups"`
	NoReward map[string]Unrewarded `json:"no_reward"` // each episode without a finite reward
	Failures map[string][]string   `json:"failures"`  // each episode's failures
}

// unrewarded say when each of episodes that has no reward ended, and its first failure.
func (o Ordinary) unrewarded(episodes []string) []string {
	var out []string
	for _, e := range slices.Sorted(maps.Keys(o.NoReward)) {
		if len(episodes) > 0 && !slices.Contains(episodes, e) {
			continue
		}
		line := e + " ended"
		if ph := o.NoReward[e].Phase; ph != nil {
			line += " during " + *ph
		} else {
			line += " before its first model call"
		}
		if f := o.Failures[e]; len(f) > 0 {
			line += ": " + strings.SplitN(f[0], "\n", 2)[0]
		}
		out = append(out, line+".")
	}
	return out
}

// Unrewarded is an episode that ended without a reward: its model calls and when it ended, agent work or grading.
type Unrewarded struct {
	ModelCalls int     `json:"model_calls"`
	Phase      *string `json:"phase"`
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
	Flag      *string             `json:"flag"`
	Text      *string             `json:"text"`
	Episodes  []string            `json:"episodes"`
	Quartiles []float64           `json:"quartiles"` // Q1 and Q3 of a minority flag
	Fence     *float64            `json:"fence"`     // the outer fence a minority flag's rewards lie beyond
	Minimum   *int                `json:"minimum"`   // the usable rewards a flag needs
	Recorded  map[string]Recorded `json:"recorded"`  // what each of its episodes recorded
}

type Recorded struct {
	AgentTimeout    bool     `json:"agent_timeout"`
	VerifierTimeout bool     `json:"verifier_timeout"`
	Errors          []string `json:"errors"`   // error types
	Refusals        []string `json:"refusals"` // refusal signals
}

type Labels struct {
	Counts   map[string]int `json:"counts"`
	Episodes map[string]struct {
		Label string  `json:"label"`
		Basis *string `json:"basis"`
	} `json:"episodes"`
	Review struct {
		Attempted  []string          `json:"attempted"`
		Unresolved []string          `json:"unresolved"`
		Supported  []string          `json:"supported"`
		Unreviewed map[string]string `json:"unreviewed"`
	} `json:"review"`
}

type Metrics struct {
	Confusion []Agreement `json:"confusion"`
	Episodes  map[string]struct {
		Completion string  `json:"completion"` // complete, incomplete or unknown
		Decision   *string `json:"decision"`   // pass or fail
	} `json:"episodes"`
	Coverage struct {
		Ordinary int                 `json:"ordinary"`
		Resolved int                 `json:"resolved"`
		Eligible int                 `json:"eligible"` // the episodes in grader agreement
		Excluded map[string][]string `json:"excluded"` // the others, by why
	} `json:"coverage"`
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
	Applicability map[string]string    `json:"applicability"`
	Attempts      []SearchAttempt      `json:"attempts"`
	Experiments   []Experiment         `json:"experiments"`
	Open          []Open               `json:"open"`      // nil in older reports: not recorded
	Suspected     []Suspected          `json:"suspected"` // absent in older reports
	Limits        []string             `json:"limits"`
	Status        string               `json:"status"`
	Categories    map[string]string    `json:"categories"`
	Findings      map[string][]Finding `json:"findings"` // evidenced, inconclusive, legitimate
}

// Suspected is a suspected exploit: a measured check whose reading ended unknown, never a problem.
type Suspected struct {
	Category *string `json:"category"`
	Check    string  `json:"check"`
}

// Experiment is one idea an inspector tested.
type Experiment struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Category string `json:"category"`
	Check    string `json:"check"`
	Episode  string `json:"episode"`
	Error    string `json:"error"` // why it failed to run, for a failed experiment
}

// Open is what kept a category, or a grader inspector's ordinary episode, open when the inspection ended.
type Open struct {
	ID       string  `json:"id"` // an experiment, episode or category
	Category *string `json:"category"`
	Reason   string  `json:"reason"`
	Next     string  `json:"next"`
}

type Finding struct {
	Index          *int      `json:"index"`
	SupersededBy   *struct{} `json:"superseded_by"`
	ExecutionScope string    `json:"execution_scope"`
	Category       *string   `json:"category"`
	Experiment     string    `json:"experiment"` // the inspector's experiment that tested it
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
	Discovery       *struct {
		Status          string `json:"status"`
		Attempts        int    `json:"attempts"`
		MaximumAttempts int    `json:"maximum_attempts"`
	} `json:"discovery"` // the no-hint search; absent from pooled attack records
}

// Exploit is an attack finding that Python counts as an Attacker exploit, by its assessment index.
type Exploit struct {
	Assessment *int     `json:"assessment"`
	Candidate  *string  `json:"candidate"`
	Sources    []string `json:"sources"`
	Attempt    *int     `json:"attempt"` // its index in the attack's attempts
	Problem    *string  `json:"problem"` // for `other`, the problem the judge named
}

type Candidate struct {
	ID         string `json:"id"`
	ValidWork  bool   `json:"valid_work"`
	Conditions map[string]struct {
		Status string `json:"status"`
	} `json:"conditions"`
}

type Problem struct {
	Cause     string   `json:"cause"`
	Findings  []string `json:"findings"`
	Candidate *string  `json:"candidate"`

	// Problems formed as findings arrive carry these; older reports lack them.
	ID         string   `json:"id"`          // P1, G1, A1, or a finding id or Attacker episode the judge numbered no problem for
	Source     string   `json:"source"`      // hack inspector, grader inspector or Attacker
	Members    []string `json:"members"`     // the finding ids the judge found the same
	HelpNeeded string   `json:"help_needed"` // in older reports, the least help an Attacker needed
	Level      int      `json:"level"`       // the problem's place in the list, 1 to 5; 0 in older reports and for a reading without marks
	Label      string   `json:"label"`       // that place's text
	Scope      string   `json:"scope"`       // where its findings were evidenced, package or native; absent in older reports
	// The least information under which an Attacker exploit was observed, or why none was; absent in older reports.
	ExploitedWith        string      `json:"exploited_with"`
	Conditions           []Condition `json:"conditions"`             // nil in older reports
	Outcome              string      `json:"outcome"`                // accepted_invalid or rejected_valid; empty when not recorded or mixed
	EvidencedByInspector *bool       `json:"evidenced_by_inspector"` // nil when not recorded or without the inspections

	// Reports from schema 2 on carry these.
	Finding     string         `json:"finding"`     // the finding or Attacker episode the problem comes from
	Type        *string        `json:"type"`        // hack, false_positive or false_negative, only when an approved requirement list confirms it
	Reason      *string        `json:"reason"`      // why nudi makes no claim, or why completeness is unknown
	Text        string         `json:"text"`        // for a reading without marks, what its check measured
	Marks       map[string]any `json:"marks"`       // each mark of its reading and the value its check measured
	Requirement *string        `json:"requirement"` // the approved requirement its reading reads violated
	Help        *string        `json:"help"`        // the help an Attacker had and the problem it was written for
	Unrewarded  *int           `json:"unrewarded"`  // attempts the grader paid nothing, which nudi did not inspect
	Assessment  *int           `json:"assessment"`  // for an Attacker problem, the attack reading it comes from
}

// Condition is one condition an Attacker tried a problem under.
type Condition struct {
	Condition string `json:"condition"` // full, minimal, none (aimed at the problem), elsewhere_LEVEL (aimed at another) or independent
	Exploited int    `json:"exploited"` // how many of its attempts exploited the problem
	Attempts  int    `json:"attempts"`  // its started attempts; from schema 3 on, its assessed ones
	Status    string `json:"status"`
	// From schema 3 on, the attempts the grader paid nothing, which nudi did not inspect.
	Unrewarded int `json:"unrewarded"`
}

// why is the problem's `exploited_with`, or in older reports its `help_needed`.
func (p Problem) why() string {
	if p.ExploitedWith != "" {
		return p.ExploitedWith
	}
	return p.HelpNeeded
}

// byRung orders problems highest on the exploit chart first.
func byRung(a, b Problem) int { return b.ladder() - a.ladder() }

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
	if p.why() == "no_guidance" || len(p.Findings) > 0 && p.Text == "" {
		return 2
	}
	return 1
}

// readings are the inspector findings a problem holds: from schema 2 on, only the reading it comes from.
func (p Problem) readings() []string {
	if p.Finding != "" {
		return []string{p.Finding}
	}
	return p.Findings
}

type Attempt struct {
	Number    int                 `json:"number"`
	Rewards   map[string]*float64 `json:"rewards"`
	Error     *string             `json:"error"`
	Level     string              `json:"level"`   // none, full or minimal
	Problem   string              `json:"problem"` // the problem it attacked; absent before problems formed during the run
	Candidate *string             `json:"candidate"`
	Sources   []string            `json:"sources"`
	Episode   *string             `json:"episode"`
	Status    string              `json:"status"`

	// Reports from schema 2 on carry this.
	Assessment *int `json:"assessment"` // the attack inspector's reading of it; null when none was asked for, as for reward 0
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
	// A problem the judge gave no cause is named by its reading's mechanism, or a reading without marks by what its
	// check measured.
	if r.Attack != nil {
		found := r.findings()
		for i, p := range r.Attack.Problems {
			if strings.TrimSpace(p.Cause) == "" {
				if j := slices.IndexFunc(found, func(f Finding) bool { return f.ID == p.Finding || f.Source == "attack" && f.Claim.Episode == p.Finding }); j >= 0 {
					p.Cause = found[j].Claim.Mechanism
				}
				r.Attack.Problems[i].Cause = cmp.Or(p.Cause, p.Text)
			}
		}
	}
	shortRefs(&r)
	r.Dir = shown(dir)
	return r, nil
}

// shortRef is a problem id as P1 or A2, not an episode name.
var shortRef = regexp.MustCompile(`^[A-Z]\d+$`)

// shortRefs names each Attacker problem the report names after its episode A1, A2, ... in report order, after the A
// ids the report already wrote, and renames every reference to it. Tries keep the episode, which links to the attempt.
func shortRefs(r *Report) {
	if r.Attack == nil {
		return
	}
	n := 0
	for _, p := range append(slices.Clone(r.Attack.Problems), r.Attack.Leads...) {
		if shortRef.MatchString(p.ID) && p.ID[0] == 'A' {
			k, _ := strconv.Atoi(p.ID[1:])
			n = max(n, k)
		}
	}
	names := map[string]string{}
	for i, p := range r.Attack.Problems {
		if p.Source == "Attacker" && !shortRef.MatchString(p.ID) {
			n++
			names[p.ID] = fmt.Sprintf("A%d", n)
			r.Attack.Problems[i].ID = names[p.ID]
		}
	}
	rename := func(id *string) {
		if id != nil && names[*id] != "" {
			*id = names[*id]
		}
	}
	for i := range r.Attack.Attempts {
		rename(&r.Attack.Attempts[i].Problem)
	}
	for _, kind := range r.Attack.Exploits {
		for _, e := range kind {
			if e != nil {
				rename(e.Problem)
			}
		}
	}
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

// problemOf is the problem whose findings include id, or -1.
func (r Report) problemOf(id string) int {
	if r.Attack == nil {
		return -1
	}
	for i, p := range r.Attack.Problems {
		if slices.Contains(p.readings(), id) {
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
	for _, id := range append(slices.DeleteFunc([]string{deref(p.Candidate)}, func(s string) bool { return s == "" }), p.readings()...) {
		if i := slices.IndexFunc(found, func(f Finding) bool { return f.ID == id }); i >= 0 {
			return i + 1
		}
	}
	if i := slices.IndexFunc(found, func(f Finding) bool {
		return f.Source == "attack" && p.Assessment != nil && f.Index != nil && *f.Index == *p.Assessment
	}); i >= 0 {
		return i + 1
	}
	return slices.IndexFunc(found, func(f Finding) bool {
		return f.Source == "attack" && (slices.Contains(p.Members, f.Claim.Episode) || slices.Contains(p.readings(), f.Claim.Episode))
	}) + 1
}

// topProblem is the problem highest on the list whose evidence is on the list of findings, and that evidence's number;
// nil and 1 without one, as in reports whose problems lack exploited_with and help_needed.
func (r Report) topProblem(found []Finding) (*Problem, int) {
	if !r.helpNeeded() {
		return nil, 1
	}
	ps := slices.DeleteFunc(slices.Clone(r.Attack.Problems), Problem.lead)
	slices.SortStableFunc(ps, byRung)
	for _, p := range ps {
		if n := evidenceOf(found, p); n > 0 && p.ID != "" {
			return &p, n
		}
	}
	return nil, 1
}

// helpNeeded says whether the report's problems were formed during the run: every problem of schema 2, or one carrying
// `exploited_with`, or `help_needed` in older reports.
func (r Report) helpNeeded() bool {
	return r.Attack != nil && (r.SchemaVersion >= 2 || slices.ContainsFunc(r.Attack.Problems, func(p Problem) bool { return p.why() != "" }))
}
