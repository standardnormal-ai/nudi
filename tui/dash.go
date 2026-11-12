package main

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	wideAt  = 100 // columns of a wide terminal
	maxW    = 120 // widest the screens grow; a wider terminal leaves the rest empty
	results = 4   // the Results tab, after the four phase tabs
	chrome  = 5   // rows around the top and the scrolling body: blank lines and the key help
)

// model is the viewer of one finished run: four phase tabs and Results, the panels m, c and ? open, and the
// evidence of each finding.
type model struct {
	r       Report
	found   []Finding
	intro   *intro
	screen  int // 0 to 3 a phase tab, or results
	n       int // the finding on screen, from 1; 0 shows the tabs
	tab     int // 0 Evidence, 1 Limitations, 2 References
	sel     [results + 1]int
	open    map[string]bool // the rows and sections expanded, by tab
	overlay string          // the panel on screen: m, c or ?; empty for none
	items   []item          // the selectable rows of the tab on screen
	w, h    int             // h is 0 until the terminal reports its size
	body    viewport.Model
	help    help.Model
	exited  bool
}

type frameMsg struct{}

func newModel(r Report, n int, withIntro bool) model {
	m := model{r: r, found: r.findings(), screen: results, n: n, w: 100, open: map[string]bool{}, help: help.New(), body: viewport.New()}
	m.help.ShortSeparator = "   "
	m.help.Styles.ShortKey, m.help.Styles.ShortDesc, m.help.Styles.ShortSeparator = keyStyle, dimStyle, dimStyle
	m.body.KeyMap.Left.SetEnabled(false)
	m.body.KeyMap.Right.SetEnabled(false)
	if withIntro {
		m.intro = newIntro()
	}
	return m.layout()
}

func (m model) Init() tea.Cmd {
	if m.intro == nil {
		return nil
	}
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second/introFPS, func(time.Time) tea.Msg { return frameMsg{} })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.exited {
		return m, nil
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = min(msg.Width, maxW), msg.Height
		m.help.SetWidth(m.w)
		if m.w < 32 || m.h < 10 {
			m.intro = nil
		}
	case frameMsg:
		if m.intro != nil && m.intro.step() {
			return m, tick()
		}
		m.intro = nil
	case tea.KeyPressMsg:
		switch k := msg.String(); {
		case key.Matches(msg, keys.quit):
			m.exited = true
			m.intro = nil
			return m, tea.Quit
		case m.intro != nil:
			m.intro = nil
		case m.overlay != "":
			if k != m.overlay && k != "esc" {
				return m.scroll(msg)
			}
			m.overlay = ""
		case m.n > 0:
			switch {
			case k == "left" || k == "h":
				m.n = max(1, m.n-1)
			case k == "right" || k == "l":
				m.n = min(len(m.found), m.n+1)
			case k == "tab":
				m.tab = (m.tab + 1) % 3
			case k == "shift+tab":
				m.tab = (m.tab + 2) % 3
			case key.Matches(msg, keys.back):
				m.n = 0
			case k == "?":
				m.overlay = k
			default:
				return m.scroll(msg)
			}
			m.body.GotoTop()
		default:
			return m.browse(msg)
		}
	}
	return m.layout(), nil
}

// browse handles a key on a tab: Tab and Left/Right move between tabs, Up/Down move the cursor, Enter opens or
// expands the row under it, and each section's key expands it.
func (m model) browse(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	sel, k, prefix := &m.sel[m.screen], msg.String(), fmt.Sprint(m.screen)
	toggle := func(key string) { m.open[prefix+key] = !m.open[prefix+key] }
	switch {
	case k == "tab" || k == "right" || k == "l":
		m.screen = (m.screen + 1) % (results + 1)
		m.body.GotoTop()
	case k == "shift+tab" || k == "left" || k == "h":
		m.screen = (m.screen + results) % (results + 1)
		m.body.GotoTop()
	case (k == "up" || k == "k") && *sel > 0:
		*sel--
		return m.reveal(), nil
	case (k == "down" || k == "j") && *sel < len(m.items)-1:
		*sel++
		return m.reveal(), nil
	case k == "enter" && len(m.items) > 0:
		switch it := m.items[*sel]; {
		case it.n > 0:
			m.n, m.tab = it.n, 0
			m.body.GotoTop()
		case it.key != "":
			toggle(it.key)
		}
	case k == "esc" && len(m.items) > 0:
		m.open[prefix+m.items[*sel].key] = false
	case k == "?" && m.screen == 0:
		toggle("?")
	case k == "m" || k == "c" || k == "?":
		m.overlay = k
		m.body.GotoTop()
	case m.screen == results && (k == "o" || k == "i" || k == "e"), m.screen == 0 && k == "p", m.screen == 1 && (k == "s" || k == "e"),
		m.screen == 2 && (k == "s" || k == "x" || k == "e"), m.screen == 3 && k == "e":
		toggle(k)
	default:
		return m.scroll(msg)
	}
	m = m.layout()
	m.sel[m.screen] = min(m.sel[m.screen], max(0, len(m.items)-1))
	return m.layout(), nil
}

func (m model) scroll(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.body, cmd = m.body.Update(msg)
	return m, cmd
}

// reveal scrolls the body so that the selected row shows.
func (m model) reveal() model {
	m = m.layout()
	if s := m.sel[m.screen]; s < len(m.items) {
		m.body.EnsureVisible(m.items[s].line, 0, 0)
	}
	return m
}

// layout puts the current screen into the scrolling body, as tall as it needs and no taller than the window.
func (m model) layout() model {
	s := m.page()
	m.body.SetWidth(m.w)
	m.body.SetContent(s)
	h := lipgloss.Height(s)
	if m.h > 0 {
		h = min(h, max(3, m.h-lipgloss.Height(m.top())-chrome))
	}
	m.body.SetHeight(h)
	return m
}

// page draws the screen on view and keeps its selectable rows in m.items.
func (m *model) page() string {
	m.items = nil
	switch {
	case m.overlay == "m":
		return cut(modelsPanel(m.r, m.w), m.w)
	case m.overlay == "c":
		return cut(costPanel(m.r, m.w), m.w)
	case m.overlay == "?":
		return cut(helpPanel(m.w, false), m.w)
	case m.n > 0:
		from := "Results"
		if m.screen < results {
			from = phases[m.screen].Name
		}
		return renderShow(m.r, m.found, m.n, m.tab, from, m.w)
	}
	p := m.tabPage(m.sel[m.screen])
	m.items = p.items
	return cut(p.String(), m.w)
}

// tabPage draws the tab on view with row sel selected; -1 selects none.
func (m model) tabPage(sel int) *page {
	open := map[string]bool{}
	for k, v := range m.open {
		if after, ok := strings.CutPrefix(k, fmt.Sprint(m.screen)); ok {
			open[after] = v
		}
	}
	p := &page{w: m.w, sel: sel, open: open}
	switch m.screen {
	case 0:
		simulationPage(m.r, m.found, p)
	case 1:
		gradePage(m.r, p)
	case 2:
		hacksPage(m.r, m.found, p)
	case 3:
		attackPage(m.r, m.found, p)
	default:
		resultsPage(m.r, m.found, p)
	}
	return p
}

// top is the header and the tab strip.
func (m model) top() string {
	return cut(header(m.r, false, m.w)+"\n\n"+tabStrip(m.r.stage, m.screen, m.w), m.w)
}

// final is what the viewer leaves in the scrollback on quit: the header and the Results tab, nothing selected.
func (m model) final() string {
	m.screen, m.open = results, map[string]bool{}
	return cut(header(m.r, false, m.w), m.w) + "\n\n" + cut(m.tabPage(-1).String(), m.w)
}

// View draws inline, under the command line, cut to the window's height so that no row is left
// behind on a redraw. The intro takes the screen's rows first. Once the viewer quits, main prints the final screen.
func (m model) View() tea.View {
	var v tea.View
	v.WindowTitle = "nudi " + m.r.task()
	if m.exited {
		return v
	}
	content := m.top() + "\n\n" + m.body.View()
	if m.intro != nil {
		h := lipgloss.Height(content)
		if m.h > 0 {
			h = min(h, max(1, m.h-4))
		}
		content = lipgloss.NewStyle().PaddingLeft(1).Height(h).Render(m.intro.view(m.w-2, h))
		v.SetContent("\n" + content + "\n\n " + dim(truncate("any key skip   q quit", m.w-2)) + "\n")
		return v
	}
	k := keys
	k.finding = m.n > 0
	if m.screen == 0 && m.n == 0 {
		k.help.SetHelp("?", "method")
	}
	if len(m.items) == 0 {
		k.sel.SetHelp("Up/Down", "scroll")
	}
	k.open.SetHelp("Enter", m.enter())
	k.open.SetEnabled(m.enter() != "")
	v.SetContent("\n" + content + "\n\n " + truncate(m.help.View(k), m.w-1) + "\n")
	return v
}

// enter says what Enter does on the selected row: open its finding, or expand or collapse its rows; empty for nothing.
func (m model) enter() string {
	s := m.sel[m.screen]
	if m.n > 0 || m.overlay != "" || s >= len(m.items) {
		return ""
	}
	switch it := m.items[s]; {
	case it.n > 0:
		return "open finding"
	case it.key != "":
		return map[bool]string{true: "collapse ", false: "expand "}[m.open[fmt.Sprint(m.screen)+it.key]] + strings.Fields(it.key)[0]
	}
	return ""
}

func cut(s string, w int) string {
	lines := splitLines(s)
	for i, l := range lines {
		lines[i] = truncate(l, w)
	}
	return strings.Join(lines, "\n")
}

func bar(c color.Color, w int, pct float64) string {
	p := progress.New(progress.WithColors(c), progress.WithFillCharacters('━', '━'), progress.WithoutPercentage(), progress.WithWidth(w))
	p.EmptyColor = grey
	return p.ViewAs(pct)
}

// names gives each report id its finding number in the viewer, such as "hack-1 (finding 4)".
func names(found []Finding, ids []string) []string {
	var out []string
	for _, id := range ids {
		if n := number(found, id); n > 0 {
			id = fmt.Sprintf("%s (finding %d)", id, n)
		}
		out = append(out, id)
	}
	return out
}
