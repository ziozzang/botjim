package tui

// Braille sparkline: each terminal cell encodes 2×4 dots, so a rolling
// throughput window renders as a compact smooth line (btop-style).

// Spark holds a rolling window of samples in [0,1].
type Spark struct {
	width int
	vals  []float64
	max   float64 // autoscale ceiling
}

// NewSpark builds a sparkline that keeps the last width cells worth of data.
func NewSpark(width int) *Spark {
	if width < 1 {
		width = 1
	}
	return &Spark{width: width}
}

// Push appends a sample (absolute value; autoscaled).
func (s *Spark) Push(v float64) {
	s.vals = append(s.vals, v)
	if len(s.vals) > s.width*2 {
		s.vals = s.vals[len(s.vals)-s.width*2:]
	}
	if v > s.max {
		s.max = v
	}
	if s.max > 0 {
		s.max *= 0.999 // slow decay so old peaks don't pin the scale forever
	}
}

// Render draws the sparkline into exactly width cells.
func (s *Spark) Render(width int) string {
	if width < 1 {
		return ""
	}
	n := s.width * 2 // data points per full line
	vals := s.vals
	if len(vals) > n {
		vals = vals[len(vals)-n:]
	}
	max := s.max
	if max <= 0 {
		max = 1
	}
	out := make([]rune, 0, s.width)
	for cell := 0; cell < s.width; cell++ {
		// newest data on the right: map cell index to value window position
		idx := len(vals) - (s.width-cell)*2
		if idx < 0 {
			out = append(out, ' ')
			continue
		}
		pair := vals[idx:min(idx+2, len(vals))]
		bits := 0
		// braille dot layout per cell (Unicode U+2800 base):
		//  dots: col0 {1,2,3,7} col1 {4,5,6,8} — rows top→bottom 0..3
		for c := 0; c < 2 && c < len(pair); c++ {
			v := pair[c] / max
			if v > 1 {
				v = 1
			}
			h := int(v * 3.999) // 0..3
			for row := 0; row <= h; row++ {
				bits |= brailleDot(c, row)
			}
		}
		out = append(out, rune(0x2800+bits))
	}
	return string(out[len(out)-min(width, len(out)):])
}

func brailleDot(col, row int) int {
	// row0..3 of column 0: bits 0x01,0x02,0x04,0x40
	// row0..3 of column 1: bits 0x08,0x10,0x20,0x80
	if col == 0 {
		return []int{0x01, 0x02, 0x04, 0x40}[row]
	}
	return []int{0x08, 0x10, 0x20, 0x80}[row]
}

// Max reports the current autoscale ceiling.
func (s *Spark) Max() float64 { return s.max }
