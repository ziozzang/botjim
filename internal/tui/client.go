package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	bprogress "github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ziozzang/botjim/internal/progress"
)

// Client palette.
var (
	cBrand    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213"))
	cDir      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("75"))
	cRate     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("82"))
	cEta      = lipgloss.NewStyle().Foreground(lipgloss.Color("222"))
	cDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	cErr      = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	cOk       = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	cWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	cPathSt   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	cFileRate = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
)

// perFileTrack remembers the previous snapshot's per-file progress so the
// view can show a live per-file speed and remaining time.
type perFileTrack struct {
	at   time.Time
	done map[uint32]int64
}

// clientModel is the push/pull progress view: aggregate bar, live rate,
// ETA, per-file speed and remaining time, plus a rolling transfer log.
type clientModel struct {
	reg     *progress.Registry
	pull    bool
	bar     bprogress.Model
	snap    progress.Snapshot
	events  []string
	done    bool
	err     error
	track   perFileTrack
	rates   map[uint32]float64 // per-file bytes/s from the last interval
	logRows int
}

type tickMsg time.Time

type doneMsg struct{ err error }

func clientTick() tea.Cmd {
	return tea.Tick(150*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// RunClientProgress runs the full-screen client progress UI until the
// transfer context finishes. Returns when the UI exits.
func RunClientProgress(ctx context.Context, reg *progress.Registry, pull bool, done <-chan error) error {
	bar := bprogress.New(bprogress.WithScaledGradient("#3fb950", "#58a6ff"))
	m := &clientModel{
		reg: reg, pull: pull, bar: bar,
		track:   perFileTrack{at: time.Now(), done: map[uint32]int64{}},
		rates:   map[uint32]float64{},
		logRows: 8,
	}
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithAltScreen())

	watch := make(chan doneMsg, 1)
	go func() {
		select {
		case err := <-done:
			watch <- doneMsg{err}
		case <-ctx.Done():
			watch <- doneMsg{ctx.Err()}
		}
	}()
	go func() {
		for {
			select {
			case msg := <-watch:
				p.Send(msg)
				return
			case e := <-reg.Events:
				line := time.Now().Format("15:04:05 ")
				var styled string
				switch e.Kind {
				case "file-done":
					styled = cOk.Render("✔") + " " + cPathSt.Render(e.Path)
				case "file-skip":
					styled = cDim.Render("⤼") + " " + cPathSt.Render(e.Path) + cDim.Render("  "+e.Msg)
				case "file-error":
					styled = cErr.Render("✖") + " " + cPathSt.Render(e.Path) + " " + cErr.Render(e.Msg)
				case "warn":
					styled = cWarn.Render("!") + " " + cWarn.Render(e.Path+" "+e.Msg)
				default:
					styled = cDim.Render("·") + " " + cDim.Render(e.Path+" "+e.Msg)
				}
				p.Send(eventMsg(line + styled))
			case <-ctx.Done():
				return
			}
		}
	}()
	_, err := p.Run()
	return err
}

type eventMsg string

func (m *clientModel) Init() tea.Cmd { return clientTick() }

func (m *clientModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		m.refresh()
		if !m.done {
			return m, clientTick()
		}
		return m, nil
	case eventMsg:
		m.events = append(m.events, string(msg))
		if len(m.events) > m.logRows {
			m.events = m.events[len(m.events)-m.logRows:]
		}
		return m, nil
	case doneMsg:
		m.done = true
		m.err = msg.err
		m.refresh()
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		// adjust the log depth to the terminal
		if rows := msg.Height / 3; rows > 3 && rows < 12 {
			m.logRows = rows
		}
	}
	return m, nil
}

// refresh snapshots progress and derives per-file speeds from the delta
// since the previous tick.
func (m *clientModel) refresh() {
	m.snap = m.reg.Snapshot()
	now := time.Now()
	dt := now.Sub(m.track.at).Seconds()
	newDone := make(map[uint32]int64, len(m.snap.Files))
	for _, f := range m.snap.Files {
		newDone[f.ID] = f.Done
		if dt > 0.05 {
			rate := float64(f.Done-m.track.done[f.ID]) / dt
			// light smoothing so a single slow interval doesn't zero out
			if old, ok := m.rates[f.ID]; ok && rate > 0 {
				rate = 0.6*old + 0.4*rate
			}
			m.rates[f.ID] = rate
		}
	}
	if dt > 0.05 {
		m.track = perFileTrack{at: now, done: newDone}
	}
}

func (m *clientModel) View() string {
	var b strings.Builder
	s := m.snap
	direction := cDir.Render("push ↑")
	if m.pull {
		direction = cDir.Render("pull ↓")
	}
	title := fmt.Sprintf("%s %s — %s / %s",
		cBrand.Render("botjim"), direction,
		humanBytes(s.SentBytes+s.SkippedBytes), humanBytes(s.TotalBytes))
	if s.Scanning {
		title += cDim.Render(fmt.Sprintf("  (scanning… %d entries)", s.TotalFiles))
	}
	b.WriteString(title + "\n\n")

	if s.TotalBytes > 0 {
		frac := float64(s.SentBytes+s.SkippedBytes) / float64(s.TotalBytes)
		b.WriteString(m.bar.ViewAs(frac) + "\n\n")
	} else {
		b.WriteString(cDim.Render("waiting…") + "\n\n")
	}

	eta := fmtDuration(s.ETA)
	if s.ETA <= 0 {
		eta = "--"
	}
	b.WriteString(fmt.Sprintf("  속도 %s/s   남은시간 %s   경과 %s\n",
		cRate.Render(humanBytes(uint64(s.RateBps))), cEta.Render(eta), cDim.Render(fmtDuration(s.Elapsed))))
	b.WriteString(fmt.Sprintf("  파일 %d/%d 완료 · 오류 %s · 생략 %s\n\n",
		s.DoneFiles+s.SkipFiles, s.TotalFiles, cErrIf(s.ErrFiles), humanBytes(s.SkippedBytes)))

	if len(s.Files) > 0 {
		b.WriteString(cDim.Render(fmt.Sprintf("  진행 중인 파일 %d", len(s.Files))) + "\n")
		rows := min(len(s.Files), 8)
		for i, f := range s.Files {
			if i >= rows {
				b.WriteString(cDim.Render(fmt.Sprintf("  … %d more\n", len(s.Files)-rows)))
				break
			}
			frac := 1.0
			if f.Size > 0 {
				frac = float64(f.Done) / float64(f.Size)
			}
			rate := m.rates[f.ID]
			feta := "--"
			if rate > 1 && f.Done < f.Size {
				feta = fmtDuration(time.Duration(float64(f.Size-f.Done)/rate) * time.Second)
			}
			tag := stateTag(f.State, f.Err)
			b.WriteString(fmt.Sprintf("  %-46s %s %6.1f%% %8s/s %8s\n",
				cPathSt.Render(truncMid(f.Path, 46)), tag,
				frac*100, cFileRate.Render(humanBytes(uint64(rate))), cDim.Render(feta)))
		}
		b.WriteString("\n")
	}

	if len(m.events) > 0 {
		b.WriteString(cDim.Render("  전송 로그") + "\n")
		for _, e := range m.events {
			b.WriteString("  " + e + "\n")
		}
	}
	if m.done {
		verdict := cOk.Render("전송 완료 — 종료합니다")
		if m.err != nil {
			verdict = cErr.Render("중단: " + m.err.Error())
		}
		b.WriteString("\n" + verdict + "\n")
	}
	return b.String()
}

func cErrIf(n uint64) string {
	if n > 0 {
		return cErr.Render(fmt.Sprint(n))
	}
	return fmt.Sprint(n)
}

func stateTag(state, errMsg string) string {
	switch state {
	case "done":
		return cOk.Render("✔")
	case "error":
		return cErr.Render("✖ " + truncEnd(errMsg, 30))
	case "skipped":
		return cDim.Render("⤼")
	case "active":
		return cFileRate.Render("▸")
	}
	return state
}

func truncEnd(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func truncMid(s string, n int) string {
	if len(s) <= n {
		return s
	}
	h := (n - 1) / 2
	return s[:h] + "…" + s[len(s)-(n-1-h):]
}

func fmtDuration(d time.Duration) string {
	if d <= 0 {
		return "--"
	}
	if d > time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	if d > time.Minute {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
