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
	cLogBox   = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).
			BorderForeground(lipgloss.Color("238"))
)

const logHistoryCap = 1000

// perFileTrack remembers the previous snapshot's per-file progress so the
// view can show a live per-file speed and remaining time.
type perFileTrack struct {
	at   time.Time
	done map[uint32]int64
}

// clientModel is the push/pull progress view: aggregate bar, live rate,
// ETA, per-file speed and remaining time, and a scrolling transfer log.
type clientModel struct {
	reg     *progress.Registry
	pull    bool
	bar     bprogress.Model
	snap    progress.Snapshot
	events  []string // full log history (capped)
	logOff  int      // scroll offset into events; tail when follow
	follow  bool     // stick to the tail of the log
	done    bool
	err     error
	waitKey bool // after completion, wait for a key (browser flow)
	help    bool // '?' overlay
	track   perFileTrack
	rates   map[uint32]float64
	width   int
	height  int
}

type tickMsg time.Time

type doneMsg struct{ err error }

func clientTick() tea.Cmd {
	return tea.Tick(150*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// RunClientProgress runs the full-screen client progress UI until the
// transfer finishes; with waitKey it then waits for one more keypress
// (the browser flow returns to the picker afterwards).
func RunClientProgress(ctx context.Context, reg *progress.Registry, pull bool, done <-chan error, waitKey bool) error {
	bar := bprogress.New(bprogress.WithScaledGradient("#3fb950", "#58a6ff"))
	m := &clientModel{
		reg: reg, pull: pull, bar: bar,
		track:   perFileTrack{at: time.Now(), done: map[uint32]int64{}},
		rates:   map[uint32]float64{},
		follow:  true,
		waitKey: waitKey,
		width:   80, height: 24,
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
				p.Send(eventMsg(formatEvent(e)))
			case <-ctx.Done():
				return
			}
		}
	}()
	_, err := p.Run()
	return err
}

func formatEvent(e progress.Event) string {
	line := e.At.Format("15:04:05 ")
	switch e.Kind {
	case "file-done":
		line += cOk.Render("✔") + " " + cPathSt.Render(e.Path)
	case "file-skip":
		line += cDim.Render("⤼") + " " + cPathSt.Render(e.Path) + cDim.Render("  "+e.Msg)
	case "file-error":
		line += cErr.Render("✖") + " " + cPathSt.Render(e.Path) + " " + cErr.Render(e.Msg)
	case "warn":
		line += cWarn.Render("!") + " " + cWarn.Render(e.Path+" "+e.Msg)
	default:
		line += cDim.Render("·") + " " + cDim.Render(e.Path+" "+e.Msg)
	}
	return line
}

type eventMsg string

func (m *clientModel) Init() tea.Cmd { return clientTick() }

func (m *clientModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		m.refresh()
		if !m.done {
			return m, clientTick()
		}
		return m, nil
	case eventMsg:
		m.events = append(m.events, string(msg))
		if len(m.events) > logHistoryCap {
			m.events = m.events[len(m.events)-logHistoryCap:]
		}
		return m, nil
	case doneMsg:
		m.done = true
		m.err = msg.err
		m.refresh()
		if m.waitKey {
			return m, nil // show the final frame until a key
		}
		return m, tea.Quit
	case tea.KeyMsg:
		if m.help {
			m.help = false
			return m, nil
		}
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
		if msg.String() == "?" {
			m.help = true
			return m, nil
		}
		if m.done && m.waitKey {
			return m, tea.Quit
		}
		// log scrolling
		rows := m.logRows()
		switch msg.Type {
		case tea.KeyUp:
			m.scrollLog(-1)
		case tea.KeyDown:
			m.scrollLog(1)
		case tea.KeyPgUp:
			m.scrollLog(-rows)
		case tea.KeyPgDown:
			m.scrollLog(rows)
		case tea.KeyEnd:
			m.follow = true
		case tea.KeyHome:
			m.logOff = 0
			m.follow = false
		}
	}
	return m, nil
}

func (m *clientModel) scrollLog(delta int) {
	m.follow = false
	m.logOff += delta
	if m.logOff < 0 {
		m.logOff = 0
	}
	if max := len(m.events) - m.logRows(); max >= 0 && m.logOff > max {
		m.logOff = max
	}
	if m.logOff >= len(m.events)-m.logRows() {
		m.follow = true
	}
}

// logRows is how many log lines fit under the header, bar and file table.
func (m *clientModel) logRows() int {
	n := m.height - 12 // header(2)+bar(2)+stats(2)+files(4)+title(1)+footer(1)
	if n < 3 {
		n = 3
	}
	return n
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
	if m.help {
		return m.helpView()
	}
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
	b.WriteString(title + "\n")

	if s.TotalBytes > 0 {
		frac := float64(s.SentBytes+s.SkippedBytes) / float64(s.TotalBytes)
		b.WriteString(m.bar.ViewAs(frac) + "\n")
	} else {
		b.WriteString(cDim.Render("waiting…") + "\n")
	}

	eta := fmtDuration(s.ETA)
	if s.ETA <= 0 {
		eta = "--"
	}
	b.WriteString(fmt.Sprintf("rate %s/s   eta %s   elapsed %s   files %d/%d done · errors %s · skipped %s\n",
		cRate.Render(humanBytes(uint64(s.RateBps))), cEta.Render(eta), cDim.Render(fmtDuration(s.Elapsed)),
		s.DoneFiles+s.SkipFiles, s.TotalFiles, cErrIf(s.ErrFiles), humanBytes(s.SkippedBytes)))

	if len(s.Files) > 0 {
		rows := min(len(s.Files), 4)
		for i, f := range s.Files {
			if i >= rows {
				b.WriteString(cDim.Render(fmt.Sprintf("  … %d more in flight\n", len(s.Files)-rows)))
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
			b.WriteString(fmt.Sprintf("  %-46s %s %6.1f%% %8s/s %8s\n",
				cPathSt.Render(truncMid(f.Path, 46)), stateTag(f.State, f.Err),
				frac*100, cFileRate.Render(humanBytes(uint64(rate))), cDim.Render(feta)))
		}
	} else if !m.done {
		b.WriteString(cDim.Render("  …") + "\n")
	}

	// scrolling transfer log (tail-following; ↑↓ to scroll back)
	logRows := m.logRows()
	start := 0
	end := len(m.events)
	if m.follow {
		start = max(0, end-logRows)
	} else {
		start = m.logOff
		end = min(len(m.events), start+logRows)
	}
	hdr := "  transfer log"
	if !m.follow {
		hdr += cDim.Render(fmt.Sprintf("  (scrolled up %d, End = latest)", len(m.events)-end))
	}
	if end-start < logRows { // pad to keep the layout stable
		hdr += strings.Repeat(" ", 0)
	}
	b.WriteString(cLogBox.Render(hdr) + "\n")
	for _, e := range m.events[start:end] {
		b.WriteString("  " + e + "\n")
	}
	for i := end - start; i < logRows; i++ {
		b.WriteString("\n")
	}

	footer := cDim.Render("  [?] help · [↑↓/PgUp/PgDn] scroll log · [Ctrl-C] abort")
	if m.done && m.waitKey {
		if m.err != nil {
			footer = cErr.Render("  aborted: ") + cDim.Render(m.err.Error()) + cDim.Render(" — press any key to return to the picker")
		} else {
			footer = cOk.Render("  transfer complete") + cDim.Render(" — press any key to return to the picker")
		}
	} else if m.done {
		footer = cOk.Render("  transfer complete")
	}
	b.WriteString(footer + "\n")
	return b.String()
}

func (m *clientModel) helpView() string {
	var b strings.Builder
	b.WriteString(cBrand.Render(" botjim ") + "진행 화면 도움말\n\n")
	b.WriteString(`  파일 표가 위로, 전송 로그가 아래로 스크롤됩니다.

  ` + cOk.Render("✔") + ` 파일 전송 완료     ` + cDim.Render("⤼") + ` 이미 있어 생략     ` + cErr.Render("✖") + ` 오류
  속도/남은시간: 전체 전송 기준 (최근 4초 이동 평균)
  파일 행: 진행률 · 파일별 속도 · 파일별 남은 시간

  키:
    ↑ / ↓ / PgUp / PgDn   로그 스크롤 (위로 올리면 자동 추적 멈춤)
    Home / End            로그 처음 / 최신(자동 추적 재개)
    ?                     이 도움말
    Ctrl-C                전송 중단 (재실행 시 이어받기)

  브라우저에서 시작한 전송이 끝나면 아무 키나 눌러 선택 화면으로
  돌아갑니다. 로그는 파일로도 기록됩니다 (요약에 경로 표시).
`)
	b.WriteString("\n" + cDim.Render("아무 키나 누르면 돌아갑니다") + "\n")
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
