package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"image/color"
	"io"
	"math"
	"strings"
	"sync"

	"charm.land/lipgloss/v2"
)

const (
	introFPS    = 24
	introFrames = 96
	dragonW     = 176
	dragonH     = 96
	dragonPlane = dragonW * dragonH
)

// The selected Canvas drawing and regeneration instructions live beside this asset.
// Rasters contain only palette indices, with solid and contour planes per frame.
//
//go:embed assets/dragon.bin.gz
var dragonCompressed []byte

// Plain output and suppressed intros never decode the artwork. Limit the one-time
// decode to the known size; a damaged asset degrades to opening the viewer.
var dragonRasters = sync.OnceValue(func() []byte {
	z, err := gzip.NewReader(bytes.NewReader(dragonCompressed))
	if err != nil {
		return nil
	}
	defer z.Close()
	const size = introFrames * 2 * dragonPlane
	data, err := io.ReadAll(io.LimitReader(z, size+1))
	if err != nil || len(data) != size {
		return nil
	}
	return data
})

var (
	introStatus = logo + " " + dim("initializing…")
	brailleBit  = [4][2]rune{{1, 8}, {2, 16}, {4, 32}, {64, 128}}
	introInk    = func() [6][17]lipgloss.Style {
		palette := [6][3]byte{{60, 96, 139}, {103, 154, 196}, {195, 228, 243}, {136, 201, 226}, {71, 123, 209}, {52, 69, 116}}
		var styles [6][17]lipgloss.Style
		for i, rgb := range palette {
			for alpha := range 17 {
				blend := func(c, bg byte) byte { return byte((int(c)*alpha + int(bg)*(16-alpha)) / 16) }
				styles[i][alpha] = lipgloss.NewStyle().Foreground(color.RGBA{R: blend(rgb[0], 8), G: blend(rgb[1], 13), B: blend(rgb[2], 16), A: 255})
			}
		}
		return styles
	}()
)

type intro struct{ frame int }

func newIntro() *intro {
	if dragonRasters() == nil {
		return nil
	}
	return &intro{}
}

// step advances a bounded 24 fps sequence, including swimming after formation.
func (in *intro) step() bool {
	if in.frame < introFrames {
		in.frame++
	}
	return in.frame < introFrames
}

type introCell struct {
	char    rune
	palette byte
	alpha   float64
}

type introRaster struct {
	pixels []byte
	w, h   int
}

func (r introRaster) at(x, y int) byte {
	if x < 0 || y < 0 || x >= r.w || y >= r.h {
		return 0
	}
	return r.pixels[y*r.w+x]
}

// Downsampling keeps every occupied source pixel, so fine fingers survive in a
// compact window. Both axes use the same scale before rounding to whole cells.
func fitRaster(pixels []byte, w, h int) introRaster {
	if w == dragonW && h == dragonH {
		return introRaster{pixels, w, h}
	}
	out := make([]byte, w*h)
	for y := range dragonH {
		for x := range dragonW {
			i := (y*h/dragonH)*w + x*w/dragonW
			out[i] = max(out[i], pixels[y*dragonW+x])
		}
	}
	return introRaster{out, w, h}
}

func introNoise(n int) float64 {
	x := math.Sin(float64(n)*127.1+311.7) * 43758.5453
	return x - math.Floor(x)
}

func (in *intro) view(w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	if w < 24 || h < 5 {
		return truncate(logo, w)
	}
	scale := min(1.0, float64(w)/88, float64(h-2)/24)
	cols, rows := max(1, int(88*scale)), max(1, int(24*scale))
	data := dragonRasters()
	if data == nil {
		return truncate(logo, w)
	}
	frame := min(in.frame, introFrames-1)
	offset := frame * 2 * dragonPlane
	solid := fitRaster(data[offset:offset+dragonPlane], cols*2, rows*4)
	edge := fitRaster(data[offset+dragonPlane:offset+2*dragonPlane], cols*2, rows*4)
	grid := make([]introCell, cols*rows)
	s := float64(frame) / introFPS
	clamp := func(x float64) float64 { return min(1, max(0, x)) }

	// The approved hybrid first gathers coarse dots, then retains a sparse
	// interior while its fine contours emerge. Motion is already in the rasters.
	for y := range rows {
		for x := range cols {
			n, count, col := y*cols+x, 0, byte(0)
			for yy := range 4 {
				for xx := range 2 {
					if c := solid.at(x*2+xx, y*4+yy); c != 0 {
						count++
						col = max(col, c)
					}
				}
			}
			if count == 0 {
				continue
			}
			fade := 1.0
			if introNoise(n+71) >= .70 && col != 4 {
				fade = 1 - clamp((s-1.8)/1.1)
			}
			if fade == 0 {
				continue
			}
			u := max(0, s-introNoise(n)*.6)
			left := math.Exp(-u*2.8) * math.Cos(u*3.4)
			px := int(math.Round(float64(x) + (introNoise(n+10)-.5)*90*float64(cols)/88*left))
			py := int(math.Round(float64(y) + (introNoise(n+20)-.5)*36*float64(rows)/24*left))
			if px < 0 || px >= cols || py < 0 || py >= rows {
				continue
			}
			char, alpha := '·', .64
			if count > 3 {
				char = '•'
			}
			if col == 4 {
				alpha = .95
			}
			grid[py*cols+px] = introCell{char, col, fade * alpha}
		}
	}
	for y := range rows {
		for x := range cols {
			mask, col := rune(0), byte(0)
			for yy := range 4 {
				for xx := range 2 {
					if c := edge.at(x*2+xx, y*4+yy); c != 0 {
						mask |= brailleBit[yy][xx]
						col = max(col, c)
					}
				}
			}
			n := y*cols + x
			alpha := clamp((s - 1.15 - introNoise(n+91)*.9) / .55)
			if mask == 0 || alpha <= .04 {
				continue
			}
			inside := solid.at(x*2-1, y*4+2) != 0 && solid.at(x*2+2, y*4+2) != 0 && solid.at(x*2+1, y*4-1) != 0 && solid.at(x*2+1, y*4+4) != 0
			if dot := &grid[n]; inside && dot.char != 0 && col != 4 && introNoise(n+121) < .6 {
				dot.alpha = max(dot.alpha, alpha*.75)
			} else {
				grid[n] = introCell{0x2800 + mask, col, alpha}
			}
		}
	}

	lines := make([]string, rows)
	for y := range rows {
		var line, run strings.Builder
		lastColor := -1
		flush := func() {
			if lastColor >= 0 {
				line.WriteString(introInk[lastColor/17][lastColor%17].Render(run.String()))
			} else {
				line.WriteString(run.String())
			}
			run.Reset()
		}
		for _, cell := range grid[y*cols : (y+1)*cols] {
			char, ink := cell.char, -1
			if char == 0 {
				char = ' '
			} else {
				ink = (int(cell.palette)-1)*17 + int(math.Round(cell.alpha*16))
			}
			if ink != lastColor {
				flush()
				lastColor = ink
			}
			run.WriteRune(char)
		}
		flush()
		lines[y] = lipgloss.PlaceHorizontal(w, lipgloss.Center, line.String())
	}
	under := lipgloss.PlaceHorizontal(w, lipgloss.Center, truncate(introStatus, w))
	return strings.Join(lines, "\n") + "\n\n" + under
}

func splitLines(s string) []string { return strings.Split(s, "\n") }
