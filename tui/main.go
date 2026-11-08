package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/fang/v2"
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
		Use:   "nudi-view RUN [N | PROBLEM]",
		Short: "View a nudi run, or the evidence for its finding N or problem PROBLEM",
		Long: "View a finished nudi run from its report.json. In a terminal it opens the run's screens; in a pipe it prints the run's card, or finding N, as plain text.\n" +
			"With --follow it follows a run that is still going from its events.jsonl and shows the card once nudi has written the report; in a pipe it prints each event's line, then the card.",
		Example: "nudi-view runs/git-multibranch\nnudi-view runs/git-multibranch P1\nnudi-view runs/git-multibranch 1\nnudi-view --follow runs/git-multibranch",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			// finish prints the card of a viewer that quit into the scrollback; a live screen quits without a report.
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
					lipgloss.Fprintln(out, "\n"+card(m.r, m.w, true)+"\n")
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
				fmt.Fprintln(out, card(r, plainW, false))
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
					fmt.Fprintln(out, card(r, plainW, false))
				}
				code = exitCode(r)
				return nil
			}
			return finish(tea.NewProgram(newModel(r, n, !noIntro && os.Getenv("CI") == "")).Run())
		},
	}
	root.Flags().BoolVar(&noIntro, "no-intro", false, "open without the intro animation")
	root.Flags().BoolVar(&follow, "follow", false, "follow a run that is still going, from its events.jsonl, until nudi writes its report")
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := fang.Execute(context.Background(), root, fang.WithErrorHandler(func(w io.Writer, _ fang.Styles, err error) {
		fmt.Fprintln(w, clean("nudi-view: "+err.Error())) // an error can quote the folder name
	}))
	if err != nil {
		return 2
	}
	return code
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
