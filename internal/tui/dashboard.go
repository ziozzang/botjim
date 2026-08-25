package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ziozzang/botjim/internal/progress"
)

// Dashboard palette.
var (
	dBrand = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213"))
	dRate  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("82"))
	dDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	dPath  = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	dErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	dOk    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	dEta   = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
)

// DashboardSource is everything the server dashboard needs to render; the
// session.Server satisfies it.
type DashboardSource interface {
	Regs() []*progress.Registry
	Logs() []string
	Conns() int
}

type dashModel struct {
	lastTrack map[*progress.Registry]connView
	ctx       context.Context
	src       DashboardSource
	total     *Spark
	rates     map[*progress.Registry]*Spark
	lastTot   map[*progress.Registry]uint64
	snap      []connView
	logs      []string
	conns     int
	started   time.Time
	quitting  bool
	lastRate  float64
}

type connView struct {
	snap  progress.Snapshot
	spark *Spark
	label string
	// per-file speed state (delta between refreshes)
	track map[uint32]int64
	at    time.Time
	rates map[uint32]float64
}

type dashTick time.Time

func dashTickCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return dashTick(t) })
}

// RunDashboard runs the btop-style server dashboard until the user quits
// (q / Ctrl-C) or the context dies.
func RunDashboard(ctx context.Context, src DashboardSource) error {
	m := &dashModel{
		lastTrack: map[*progress.Registry]connView{},
		ctx:       ctx,
		src:       src,
		total:     NewSpark(100),
		rates:     map[*progress.Registry]*Spark{},
		lastTot:   map[*progress.Registry]uint64{},
		started:   time.Now(),
	}
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithAltScreen())
	go func() {
		<-ctx.Done()
		p.Send(dashTick(time.Now())) // wake the loop so it notices shutdown
	}()
	_, err := p.Run()
	return err
}

func (m *dashModel) Init() tea.Cmd { return dashTickCmd() }

func (m *dashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case dashTick:
		if m.ctx.Err() != nil {
			m.quitting = true
			return m, tea.Quit
		}
		m.refresh()
		return m, dashTickCmd()
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.quitting = true
			return m, tea.Quit
		}
		switch msg.String() {
		case "q", "Q":
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *dashModel) refresh() {
	regs := m.src.Regs()
	m.conns = m.src.Conns()
	m.logs = m.src.Logs()
	now := time.Now()
	_ = now

	seen := map[*progress.Registry]bool{}
	var views []connView
	var totalRate float64
	for i, r := range regs {
		seen[r] = true
		s := r.Snapshot()
		sp, ok := m.rates[r]
		if !ok {
			sp = NewSpark(60)
			m.rates[r] = sp
			m.lastTot[r] = s.SentBytes
		}
		delta := s.SentBytes - m.lastTot[r]
		m.lastTot[r] = s.SentBytes
		rate := float64(delta) / 0.25
		sp.Push(rate)
		totalRate += rate
		label := fmt.Sprintf("conn %d", i+1)
		if len(s.Files) > 0 {
			label = fmt.Sprintf("conn %d · %s", i+1, truncMid(s.Files[0].Path, 30))
		}
		cv := connView{snap: s, spark: sp, label: label, track: map[uint32]int64{}, rates: map[uint32]float64{}}
		if old, ok := m.lastTrack[r]; ok {
			cv.track, cv.at, cv.rates = old.track, old.at, old.rates
		} else {
			cv.at = now
		}
		if dt := now.Sub(cv.at).Seconds(); dt > 0.05 {
			for _, f := range s.Files {
				rate := float64(f.Done-cv.track[f.ID]) / dt
				if old, ok := cv.rates[f.ID]; ok && rate > 0 {
					rate = 0.6*old + 0.4*rate
				}
				cv.rates[f.ID] = rate
			}
			cv.track = map[uint32]int64{}
			for _, f := range s.Files {
				cv.track[f.ID] = f.Done
			}
			cv.at = now
		}
		views = append(views, cv)
		m.lastTrack[r] = cv
	}
	for r := range m.rates {
		if !seen[r] {
			delete(m.rates, r)
			delete(m.lastTot, r)
		}
	}
	m.snap = views
	m.lastRate = totalRate
	m.total.Push(totalRate)
}

func (m *dashModel) View() string {
	var b strings.Builder
	b.WriteString(dBrand.Render(" botjim ") + "server — live dashboard\n\n")
	b.WriteString(fmt.Sprintf("connections %d · uptime %s\n\n", m.conns, fmtDuration(time.Since(m.started))))

	// aggregate throughput
	rateTag := dRate.Render(fmt.Sprintf("%s/s", humanBytes(uint64(m.lastRate))))
	b.WriteString(dDim.Render("throughput  ") + m.total.Render(72) + "  " + rateTag + "\n\n")

	if len(m.snap) == 0 {
		b.WriteString(dDim.Render("waiting for clients…") + "\n\n")
	} else {
		for _, v := range m.snap {
			b.WriteString(dPath.Render(v.label) + "\n")
			eta := fmtDuration(v.snap.ETA)
			if v.snap.ETA <= 0 {
				eta = "--"
			}
			if v.snap.TotalBytes > 0 {
				frac := float64(v.snap.SentBytes+v.snap.SkippedBytes) / float64(v.snap.TotalBytes)
				b.WriteString(fmt.Sprintf("  [%-30s] %5.1f%%  %s/%s  eta %s\n",
					barText(frac, 30), frac*100,
					humanBytes(v.snap.SentBytes+v.snap.SkippedBytes), humanBytes(v.snap.TotalBytes),
					dEta.Render(eta)))
			}
			b.WriteString("  " + v.spark.Render(34) + fmt.Sprintf("  files %d/%d  errors %d\n",
				v.snap.DoneFiles, v.snap.TotalFiles, v.snap.ErrFiles))
			for i, f := range v.snap.Files {
				if i >= 4 {
					b.WriteString(fmt.Sprintf("    %s\n", dDim.Render(fmt.Sprintf("… %d more", len(v.snap.Files)-4))))
					break
				}
				frac := 1.0
				if f.Size > 0 {
					frac = float64(f.Done) / float64(f.Size)
				}
				feta := "--"
				if rate := v.rates[f.ID]; rate > 1 && f.Done < f.Size {
					feta = fmtDuration(time.Duration(float64(f.Size-f.Done)/rate) * time.Second)
				}
				b.WriteString(fmt.Sprintf("    %-36s %s %5.1f%% %8s/s %8s\n",
					dPath.Render(truncMid(f.Path, 36)), stateTag(f.State, f.Err), frac*100,
					humanBytes(uint64(v.rates[f.ID])), dDim.Render(feta)))
			}
			b.WriteString("\n")
		}
	}

	if len(m.logs) > 0 {
		b.WriteString("log\n")
		for _, l := range m.logs[max(0, len(m.logs)-6):] {
			b.WriteString("  " + truncEnd(l, 74) + "\n")
		}
	}
	b.WriteString("\n" + dDim.Render("[q] quit · plain V1 — trusted networks only") + "\n")
	if m.quitting {
		b.WriteString("shutting down…\n")
	}
	return b.String()
}

func barText(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	full := int(frac * float64(width))
	return strings.Repeat("=", full) + strings.Repeat("·", width-full)
}
