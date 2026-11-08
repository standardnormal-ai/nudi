package main

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func introAt(frame int) *intro {
	in := newIntro()
	for range frame {
		in.step()
	}
	return in
}

func marks(s string) (dots, contours int) {
	for _, r := range ansi.Strip(s) {
		if r == '•' || r == '·' {
			dots++
		}
		if r > 0x2800 && r <= 0x28ff {
			contours++
		}
	}
	return
}

func TestIntroGathersThenSwimsAsHybrid(t *testing.T) {
	entrance := introAt(0).view(88, 26)
	if dots, contours := marks(entrance); dots < 40 || contours != 0 {
		t.Fatalf("entrance has %d dots and %d contour cells", dots, contours)
	}
	settling := introAt(42).view(88, 26)
	settled := introAt(66).view(88, 26)
	for name, view := range map[string]string{"settling": settling, "settled": settled} {
		if dots, contours := marks(view); dots < 5 || contours < 100 {
			t.Errorf("%s loses the hybrid: %d dots, %d contour cells", name, dots, contours)
		}
	}
	if ansi.Strip(entrance) == ansi.Strip(settling) || ansi.Strip(settling) == ansi.Strip(settled) || ansi.Strip(settled) == ansi.Strip(introAt(84).view(88, 26)) {
		t.Fatal("assembly or settled swimming is static")
	}
	if settled != introAt(66).view(88, 26) {
		t.Fatal("the same animation time is not deterministic")
	}
	for name, view := range map[string]string{"entrance": entrance, "settled": settled} {
		if !strings.Contains(ansi.Strip(view), "nudi initializing…") || strings.Contains(ansi.Strip(view), "hack") {
			t.Errorf("%s lacks the initialization status", name)
		}
	}
}

func TestIntroCompletionLeavesTimeToSwim(t *testing.T) {
	in := newIntro()
	for frame := 1; frame < 96; frame++ {
		if !in.step() {
			t.Fatalf("intro ended at frame %d before four seconds of animation", frame)
		}
	}
	if in.step() || in.step() {
		t.Fatal("the intro continues after four seconds")
	}
}

func TestIntroFitsAvailableArea(t *testing.T) {
	for _, size := range [][2]int{{88, 26}, {78, 18}, {46, 10}, {30, 7}, {1, 1}, {0, 0}, {-1, -1}} {
		for _, frame := range []int{0, 42, 66, 84} {
			view := introAt(frame).view(size[0], size[1])
			if size[0] <= 0 || size[1] <= 0 {
				if view != "" {
					t.Errorf("%v: empty area contains output", size)
				}
				continue
			}
			if height := len(splitLines(view)); height > size[1] {
				t.Errorf("%v frame %d: %d rows", size, frame, height)
			}
			for _, line := range splitLines(view) {
				if width(line) > size[0] {
					t.Errorf("%v frame %d: %d columns", size, frame, width(line))
				}
			}
		}
	}
}

func TestIntroFitsViewerOnResize(t *testing.T) {
	m := newModel(fixture(t, "full"), 0, true)
	for _, size := range [][2]int{{80, 24}, {120, 40}, {48, 16}, {80, 24}} {
		next, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = next.(model)
		if m.intro == nil {
			t.Fatalf("intro skipped at usable size %v", size)
		}
		view := m.View().Content
		if height := len(splitLines(view)); height > size[1] {
			t.Errorf("%v: viewer intro spills %d rows", size, height)
		}
		for _, line := range splitLines(view) {
			if width(line) > size[0] {
				t.Errorf("%v: viewer intro spills %d columns", size, width(line))
			}
		}
	}
	next, _ := m.Update(tea.WindowSizeMsg{Width: 20, Height: 6})
	if next.(model).intro != nil {
		t.Fatal("unusable windows should skip the intro")
	}
}

func TestIntroSkipQuitAndLateTick(t *testing.T) {
	for _, frame := range []int{0, 70} {
		m := newModel(fixture(t, "full"), 6, true)
		m.intro = introAt(frame)
		if m.Init() == nil {
			t.Fatal("intro did not schedule its first frame")
		}
		next, cmd := m.Update(tea.KeyPressMsg{Text: "x"})
		m = next.(model)
		if m.intro != nil || cmd != nil || m.n != 6 || !strings.Contains(ansi.Strip(m.View().Content), "finding 6 of 9") {
			t.Fatal("skip did not immediately open the requested finding")
		}
		next, cmd = m.Update(frameMsg{})
		if next.(model).intro != nil || cmd != nil {
			t.Fatal("a queued frame restarted the skipped intro")
		}
		for _, key := range []tea.KeyPressMsg{{Text: "q"}, {Code: 'c', Mod: tea.ModCtrl}} {
			m = newModel(fixture(t, "full"), 0, true)
			m.intro = introAt(frame)
			next, cmd = m.Update(key)
			m = next.(model)
			if !m.exited || m.intro != nil || cmd == nil || m.View().Content != "" {
				t.Fatal("quit must immediately stop the intro and clear its view")
			}
			if _, cmd = m.Update(frameMsg{}); cmd != nil {
				t.Fatal("a queued frame scheduled work after quit")
			}
		}
	}
	m := newModel(fixture(t, "full"), 0, false)
	if m.intro != nil || m.Init() != nil {
		t.Fatal("suppressed intro schedules animation work")
	}
}

func TestIntroAutomaticHandoff(t *testing.T) {
	m := newModel(fixture(t, "full"), 0, true)
	for range 96 {
		next, _ := m.Update(frameMsg{})
		m = next.(model)
	}
	if m.intro != nil || !strings.Contains(m.View().Content, "The grader can be cheated") {
		t.Fatal("the intro did not hand off to the card")
	}
	if _, cmd := m.Update(frameMsg{}); cmd != nil {
		t.Fatal("completed intro schedules another frame")
	}
}

func TestIntroTickIsBounded(t *testing.T) {
	start := time.Now()
	if _, ok := tick()().(frameMsg); !ok {
		t.Fatal("tick did not produce an animation frame")
	}
	if elapsed := time.Since(start); elapsed < time.Second/24-time.Millisecond {
		t.Fatalf("animation ticks faster than 24 fps: %s", elapsed)
	}
}

func BenchmarkIntroView(b *testing.B) {
	in := introAt(66)
	b.ReportAllocs()
	for b.Loop() {
		in.view(88, 26)
	}
}
