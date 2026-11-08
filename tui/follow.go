package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// startWait is how long a follow waits for nudi to begin the run's log.
const startWait = 2 * time.Minute

// poll adds the events nudi appended since the last poll to l and returns them, with the report once nudi
// has written it whole. After run_end the report is final, so one that cannot be read, or none, ends the follow.
// So does a run whose process has ended without run_end, and a folder whose log has not begun within startWait.
func (f *follower) poll(l *Live) ([]Event, *Report, error) {
	if f.begun.IsZero() {
		f.begun = time.Now()
	}
	// Checked before the read, so a run_end written before the process ended is read first.
	ended := l.Start != nil && gone(*l.Start)
	events, err := f.next()
	for _, e := range events {
		l.apply(e)
	}
	if err != nil {
		return events, nil, err
	}
	r, err := load(f.dir)
	switch {
	case err == nil:
		return events, &r, nil
	case l.End == nil && ended:
		return events, nil, fmt.Errorf("%s: nudi (pid %d) is no longer running and wrote no run_end; nudi report %s writes its report",
			l.Dir, l.Start.Pid, l.Dir)
	case l.Start == nil && time.Since(f.begun) > startWait:
		return events, nil, fmt.Errorf("%s: no nudi run began its events.jsonl there within %.0f minutes", l.Dir, startWait.Minutes())
	case l.End == nil:
		return events, nil, nil // nudi has not written it yet, or is writing it
	case l.End.Report == nil:
		return events, nil, fmt.Errorf("%s: the run ended with status %s and nudi wrote no report.json", l.Dir, l.End.Status)
	}
	return events, nil, err
}

// followPlain prints each event's line as nudi writes it, for a pipe, and returns the report once nudi has written it.
func followPlain(dir string, out io.Writer) (Report, error) {
	f, l := &follower{dir: dir}, &Live{Dir: shown(dir)}
	for {
		events, r, err := f.poll(l)
		for _, e := range events {
			fmt.Fprintln(out, e.Text)
		}
		if err != nil {
			return Report{}, err
		}
		if r != nil {
			return *r, nil
		}
		time.Sleep(time.Second)
	}
}

// liveModel is the live screen of a run that is still going. Once nudi has written the report, it gives way to the viewer.
type liveModel struct {
	f     *follower
	l     Live
	frame int
	w, h  int // h is 0 until the terminal reports its size
	err   error
	help  help.Model
}

type liveTick struct{}

func newLive(dir string) liveModel {
	return liveModel{f: &follower{dir: dir}, l: Live{Dir: shown(dir)}, w: 100, help: help.New()}
}

// Init reads the log at once.
func (m liveModel) Init() tea.Cmd { return func() tea.Msg { return liveTick{} } }

// The spinners turn ten times a second, and the log is read on every tenth turn.
func (m liveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = min(msg.Width, maxW), msg.Height
		m.help.SetWidth(m.w)
	case tea.KeyPressMsg:
		if key.Matches(msg, keys.quit) {
			return m, tea.Quit
		}
	case liveTick:
		if m.frame%10 == 0 {
			_, r, err := m.f.poll(&m.l)
			if err != nil {
				m.err = err
				return m, tea.Quit
			}
			if r != nil {
				v := newModel(*r, 0, false)
				v.w, v.h = m.w, m.h
				v.help.SetWidth(m.w)
				return v.layout(), nil
			}
		}
		m.frame++
		return m, tea.Tick(time.Second/10, func(time.Time) tea.Msg { return liveTick{} })
	}
	return m, nil
}

// View draws inline, cut to the window's height so that no row is left behind on a redraw.
func (m liveModel) View() tea.View {
	var v tea.View
	v.WindowTitle = "nudi " + m.l.Dir
	s := renderLive(&m.l, time.Now(), m.w, m.frame)
	if m.h > 0 {
		s = lipgloss.NewStyle().MaxHeight(max(3, m.h-4)).Render(s)
	}
	v.SetContent("\n" + s + "\n\n " + m.help.ShortHelpView([]key.Binding{keys.quit}) + "\n")
	return v
}

// gone says whether the process of the run that start began has ended. Only a process on this host can be checked,
// so a run from another host, or one whose run_start has no pid, never counts as gone.
func gone(start Event) bool {
	if host, err := os.Hostname(); start.Pid <= 0 || start.Host != "" && (err != nil || start.Host != host) {
		return false
	}
	p, err := os.FindProcess(start.Pid)
	return err != nil || errors.Is(p.Signal(syscall.Signal(0)), os.ErrProcessDone)
}
