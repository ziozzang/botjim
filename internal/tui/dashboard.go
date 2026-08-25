package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ziozzang/botjim/internal/progress"
)

// DashboardSource is everything the server dashboard needs to render; the
// session.Server satisfies it.
type DashboardSource interface {
	Regs() []*progress.Registry
	Logs() []string
	Conns() int
}

type dashModel struct {
	ctx      context.Context
	src      DashboardSource
	total    *Spark
	rates    map[*progress.Registry]*Spark
	lastTot  map[*progress.Registry]uint64
	snap     []connView
	logs     []string
	conns    int
	started  time.Time
	quitting bool
	lastRate float64
}

type connView struct {
	snap  progress.Snapshot
	spark *Spark
	label string
}

type dashTick time.Time

func dashTickCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return dashTick(t) })
}

// RunDashboard runs the btop-style server dashboard until the user quits
// (q / Ctrl-C) or the context dies.
func RunDashboard(ctx context.Context, src DashboardSource) error {
	m := &dashModel{
		ctx:     ctx,
		src:     src,
		total:   NewSpark(100),
		rates:   map[*progress.Registry]*Spark{},
		lastTot: map[*progress.Registry]uint64{},
		started: time.Now(),
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
		views = append(views, connView{snap: s, spark: sp, label: label})
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
	b.WriteString("botjim server — live dashboard\n\n")
	b.WriteString(fmt.Sprintf("connections %d · uptime %s\n\n", m.conns, fmtDuration(time.Since(m.started))))

	// aggregate throughput
	rateTag := fmt.Sprintf("%s/s", humanBytes(uint64(m.lastRate)))
	b.WriteString("throughput  " + m.total.Render(72) + "  " + rateTag + "\n\n")

	if len(m.snap) == 0 {
		b.WriteString("waiting for clients…\n\n")
	} else {
		for _, v := range m.snap {
			b.WriteString(v.label + "\n")
			if v.snap.TotalBytes > 0 {
				frac := float64(v.snap.SentBytes+v.snap.SkippedBytes) / float64(v.snap.TotalBytes)
				b.WriteString(fmt.Sprintf("  [%-30s] %5.1f%%  %s/%s  eta %s\n",
					barText(frac, 30), frac*100,
					humanBytes(v.snap.SentBytes+v.snap.SkippedBytes), humanBytes(v.snap.TotalBytes),
					fmtDuration(v.snap.ETA)))
			}
			b.WriteString("  " + v.spark.Render(34) + fmt.Sprintf("  files %d/%d  errors %d\n",
				v.snap.DoneFiles, v.snap.TotalFiles, v.snap.ErrFiles))
			for i, f := range v.snap.Files {
				if i >= 4 {
					b.WriteString(fmt.Sprintf("    … %d more\n", len(v.snap.Files)-4))
					break
				}
				frac := 1.0
				if f.Size > 0 {
					frac = float64(f.Done) / float64(f.Size)
				}
				b.WriteString(fmt.Sprintf("    %-40s %5.1f%% %s\n", truncMid(f.Path, 40), frac*100, stateTag(f.State, f.Err)))
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
	b.WriteString("\n[q] quit · plain V1 — trusted networks only\n")
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
