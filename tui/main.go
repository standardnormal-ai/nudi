package main

import (
	"errors"
	"fmt"
	"io"
	"os"
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
		Use:     "nudi-view RUN [N | PROBLEM]",
		Short:   "open a nudi run in the terminal",
		Version: version(),
		Args:    cobra.RangeArgs(1, 2),
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
				if len(args) == 2 {
					return errors.New("--follow takes a run folder and no finding number")
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
			n := 0
			if len(args) == 2 {
				if n, err = findingNumber(r, found, args[1]); err != nil {
					return err
				}
			}
			if !isTerminal(out) {
				if n > 0 {
					fmt.Fprintln(out, plainShow(r, found, n, plainW))
				} else {
					fmt.Fprintln(out, plainReport(r, plainW))
				}
				code = exitCode(r)
				return nil
			}
			return finish(tea.NewProgram(newModel(r, n, !noIntro && os.Getenv("CI") == "")).Run())
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
const helpText = `usage: nudi-view [-h] [-v] [--follow] [--no-intro] RUN [N | PROBLEM]

open a nudi run in the terminal; in a pipe, print the whole report as plain text

positional arguments:
  RUN                   a run directory that nudi send-nudis wrote
  N | PROBLEM           open finding N, or the evidence of problem PROBLEM such as P1

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
  nudi-view runs/git-multibranch P1         open problem P1 with its evidence
  nudi-view runs/git-multibranch 1          open finding 1 with its evidence
  nudi-view --follow runs/git-multibranch   follow a run that is still going

in a pipe:
  nudi-view RUN prints every section of the report as plain text, nudi-view RUN N one finding;
  with --follow it prints each event's line, then the report

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

// findingNumber parses the N of `nudi-view RUN N`, or a problem id such as P2, which opens the finding that shows it.
func findingNumber(r Report, found []Finding, arg string) (int, error) {
	if len(found) == 0 {
		return 0, errors.New("run has no evidenced findings")
	}
	if _, err := strconv.Atoi(strings.TrimLeft(arg, "PGA")); err == nil && len(arg) > 1 && strings.ContainsRune("PGA", rune(arg[0])) {
		i := -1
		if r.Attack != nil {
			i = slices.IndexFunc(r.Attack.Problems, func(p Problem) bool { return p.ID == arg })
		}
		if i < 0 {
			return 0, fmt.Errorf("run has no problem %s", arg)
		}
		if n := evidenceOf(found, r.Attack.Problems[i]); n > 0 {
			return n, nil
		}
		return 0, fmt.Errorf("problem %s has no evidenced finding to open", arg)
	}
	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > len(found) {
		return 0, fmt.Errorf("run has %d finding%s; N must be 1 to %d", len(found), plural(len(found)), len(found))
	}
	return n, nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}
