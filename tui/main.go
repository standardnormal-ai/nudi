package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

// plainW is the width used when stdout is not a terminal.
const plainW = 100

func main() { os.Exit(view(os.Args[1:], os.Stdout, os.Stderr)) }

// view runs one command line and returns its exit code: Python's for the run, 0 when it is complete
// or reached its time limit and 1 when it is partial, or 2 when the folder or the arguments are wrong.
func view(args []string, stdout, stderr io.Writer) int {
	code := 0
	noIntro, follow := false, false
	root := &cobra.Command{
		Use:     "nudi-view RUN [N | cause N | REF]",
		Short:   "open a nudi run in the terminal",
		Version: version(),
		Args:    cobra.RangeArgs(1, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			// finish prints the header and Results tab of a viewer that quit into the scrollback; a live screen quits without a report.
			finish := func(m tea.Model, err error) error {
				if err != nil {
					return err
				}
				switch m := m.(type) {
				case liveModel:
					if m.err != nil {
						return m.err
					}
					return fmt.Errorf("stopped following %s before nudi wrote its report.json", m.l.Dir)
				case model:
					lipgloss.Fprintln(out, "\n"+m.final()+"\n")
					code = exitCode(m.r)
				}
				return nil
			}
			if follow {
				if len(args) > 1 {
					return errors.New("--follow takes a run folder and no finding or cause")
				}
				if isTerminal(out) {
					return finish(tea.NewProgram(newLive(args[0])).Run())
				}
				r, err := followPlain(args[0], out)
				if err != nil {
					return err
				}
				fmt.Fprintln(out, plainReport(r, plainW))
				code = exitCode(r)
				return nil
			}
			r, err := load(args[0])
			if err != nil {
				return err
			}
			found := r.findings()
			n, cause := 0, ""
			if len(args) > 1 {
				ref, err := causeNumber(r, args[1:])
				if err != nil {
					return err
				}
				if n, cause, err = findingNumber(r, found, ref); err != nil {
					return err
				}
			}
			if !isTerminal(out) {
				if n > 0 {
					fmt.Fprintln(out, plainShow(r, found, n, plainW))
				} else if cause != "" {
					fmt.Fprintln(out, plainText(strings.Join(causeBlock(r, found, cause, plainW), "\n")))
				} else {
					fmt.Fprintln(out, plainReport(r, plainW))
				}
				code = exitCode(r)
				return nil
			}
			m := newModel(r, n, !noIntro && os.Getenv("CI") == "")
			if cause != "" {
				m = m.openCause(cause)
			}
			return finish(tea.NewProgram(m).Run())
		},
	}
	root.Flags().BoolVar(&noIntro, "no-intro", false, "open without the intro animation")
	root.Flags().BoolVar(&follow, "follow", false, "follow a run that is still going, from its events.jsonl, until nudi writes its report")
	root.Flags().BoolP("version", "v", false, "show the version and exit")
	root.SetHelpFunc(func(c *cobra.Command, _ []string) {
		if c != root {
			fmt.Fprint(c.OutOrStdout(), c.UsageString())
			return
		}
		fmt.Fprint(c.OutOrStdout(), helpText)
	})
	root.SetVersionTemplate("nudi-view {{.Version}}\n")
	root.SilenceUsage, root.SilenceErrors = true, true
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(stderr, clean("nudi-view: "+err.Error())) // an error can quote the folder name
		return 2
	}
	return code
}

// helpText is nudi-view --help, laid out as nudi --help is.
const helpText = `usage: nudi-view [-h] [-v] [--follow] [--no-intro] RUN [N | cause N | REF]

open a nudi run in the terminal; in a pipe, print the whole report as plain text

positional arguments:
  RUN                   a run directory that nudi send-nudis wrote
  N, cause N            open cause N, numbered as Results numbers them
  REF                   open a cause or finding by its id in report.json, such as C1, hack-6 or A2

options:
  -h, --help            show this help message and exit
  -v, --version         show the version and exit
  --follow              follow a run that is still going, from its events.jsonl, until nudi writes
                        its report
  --no-intro            open without the intro animation

commands:
  completion SHELL      print a shell completion script

examples:
  nudi-view runs/git-multibranch            open the run
  nudi-view runs/git-multibranch 1          open cause 1 with its findings
  nudi-view runs/git-multibranch hack-6     open finding hack-6 with its evidence
  nudi-view --follow runs/git-multibranch   follow a run that is still going

in a pipe:
  nudi-view RUN prints every section of the report as plain text, nudi-view RUN N one cause and
  nudi-view RUN REF one cause or finding; with --follow it prints each event's line, then the report

related commands:
  nudi send-nudis TASK  run nudi on one or more Harbor tasks and write their reports
  nudi report RUN       write a run's report again from its records
  nudi cost RUN         print Modal's bill for a run's sandboxes
`

// version is the module version of a built binary, or says it was built from source.
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Sum != "" {
		return info.Main.Version
	}
	return "unknown (built from source)"
}

// causeNumber reads the words after RUN: N or "cause N", also as one word or in capitals, is the id of cause N, numbered
// as Results numbers them; anything else is one report id, passed on, as is N for an older report without causes.
func causeNumber(r Report, words []string) (string, error) {
	m := causeWords.FindStringSubmatch(strings.Join(words, " "))
	if m == nil {
		if len(words) > 1 {
			return "", fmt.Errorf("expected N, cause N or an id after the run folder, not %q", strings.Join(words, " "))
		}
		return words[0], nil
	}
	n, _ := strconv.Atoi(m[2])
	if len(r.Causes) == 0 {
		if m[1] == "" { // an older report without causes numbers its findings
			return words[0], nil
		}
		return "", errors.New("run has no causes")
	}
	if n < 1 || n > len(r.Causes) {
		return "", fmt.Errorf("run has %d cause%s; N must be 1 to %d", len(r.Causes), plural(len(r.Causes)), len(r.Causes))
	}
	return r.Causes[n-1].ID, nil
}

var causeWords = regexp.MustCompile(`^(?i)(cause ?)?(\d+)$`)

// findingNumber parses a reference, or the finding N of an older report without causes: a finding id such as P2 opens the finding that
// shows it, as does a cause of one finding; a cause of several, such as C1, is named back to be opened as a cause.
func findingNumber(r Report, found []Finding, arg string) (int, string, error) {
	if c := slices.IndexFunc(r.Causes, func(c Cause) bool { return c.ID == arg }); c >= 0 && len(r.Causes[c].Findings) > 1 {
		return 0, arg, nil
	}
	if len(found) == 0 {
		return 0, "", errors.New("run has no evidenced findings")
	}
	if _, err := strconv.Atoi(arg); err != nil {
		fs := r.allFindings()
		i := slices.IndexFunc(fs, func(p Problem) bool { return p.ID == arg })
		if c := slices.IndexFunc(r.Causes, func(c Cause) bool { return c.ID == arg }); i < 0 && c >= 0 {
			fs, i = r.Causes[c].Findings, 0
		}
		if i < 0 {
			return 0, "", fmt.Errorf("run has no cause or finding %s", arg)
		}
		if n := evidenceOf(found, fs[i]); n > 0 {
			return n, "", nil
		}
		return 0, "", fmt.Errorf("%s has no evidenced finding to open", arg)
	}
	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > len(found) {
		return 0, "", fmt.Errorf("run has %d finding%s; N must be 1 to %d", len(found), plural(len(found)), len(found))
	}
	return n, "", nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}
