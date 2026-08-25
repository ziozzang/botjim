package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	bprogress "github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ziozzang/botjim/internal/progress"
)

// clientModel is the push/pull progress view: one aggregate bar, live rate,
// ETA and the busiest files, plus a rolling event tail.
type clientModel struct {
	reg     *progress.Registry
	pull    bool
	bar     bprogress.Model
	snap    progress.Snapshot
	events  []string
	done    bool
	err     error
	lastEvt time.Time
}

type tickMsg time.Time

type doneMsg struct{ err error }

func clientTick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// RunClientProgress runs the full-screen client progress UI until the
// transfer context finishes. Returns when the UI exits.
func RunClientProgress(ctx context.Context, reg *progress.Registry, pull bool, done <-chan error) error {
	bar := bprogress.New(bprogress.WithScaledGradient("#3fb950", "#58a6ff"))
	m := &clientModel{reg: reg, pull: pull, bar: bar}
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
				line := time.Now().Format("15:04:05 ") + e.Kind
				if e.Path != "" {
					line += " " + e.Path
				}
				if e.Msg != "" {
					line += ": " + e.Msg
				}
				p.Send(eventMsg(line))
			case <-ctx.Done():
				// ctx death is reported through the watch goroutine above
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
		m.snap = m.reg.Snapshot()
		if !m.done {
			return m, clientTick()
		}
		return m, nil
	case eventMsg:
		m.events = append(m.events, string(msg))
		if len(m.events) > 8 {
			m.events = m.events[len(m.events)-8:]
		}
		return m, nil
	case doneMsg:
		m.done = true
		m.err = msg.err
		m.snap = m.reg.Snapshot()
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *clientModel) View() string {
	var b strings.Builder
	s := m.snap
	direction := "push ↑"
	if m.pull {
		direction = "pull ↓"
	}
	b.WriteString(fmt.Sprintf("botjim %s — %s\n\n", direction, humanBytes(s.SentBytes+s.SkippedBytes)))
	if s.TotalBytes > 0 {
		frac := float64(s.SentBytes+s.SkippedBytes) / float64(s.TotalBytes)
		b.WriteString(m.bar.ViewAs(frac) + "\n\n")
	} else if s.Scanning {
		b.WriteString("scanning… " + fmt.Sprint(s.TotalFiles) + " entries\n\n")
	} else {
		b.WriteString("waiting…\n\n")
	}
	b.WriteString(fmt.Sprintf("rate %s/s   eta %s   elapsed %s\n",
		humanBytes(uint64(s.RateBps)), fmtDuration(s.ETA), fmtDuration(s.Elapsed)))
	b.WriteString(fmt.Sprintf("files %d done / %d total   errors %d   skipped %s\n\n",
		s.DoneFiles+s.SkipFiles, s.TotalFiles, s.ErrFiles, humanBytes(s.SkippedBytes)))
	if len(s.Files) > 0 {
		b.WriteString("active files\n")
		for i, f := range s.Files {
			if i >= 8 {
				b.WriteString(fmt.Sprintf("  … %d more\n", len(s.Files)-8))
				break
			}
			frac := 1.0
			if f.Size > 0 {
				frac = float64(f.Done) / float64(f.Size)
			}
			b.WriteString(fmt.Sprintf("  %s %5.1f%% %s\n", truncMid(f.Path, 44), frac*100, stateTag(f.State, f.Err)))
		}
		b.WriteString("\n")
	}
	if len(m.events) > 0 {
		b.WriteString("events\n")
		for _, e := range m.events {
			b.WriteString("  " + truncEnd(e, 72) + "\n")
		}
	}
	if m.done {
		b.WriteString("\ntransfer finished — exiting\n")
	}
	return b.String()
}

func stateTag(state, errMsg string) string {
	switch state {
	case "done":
		return "✔"
	case "error":
		return "✖ " + truncEnd(errMsg, 40)
	case "skipped":
		return "⤼ skipped"
	case "active":
		return "…"
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
