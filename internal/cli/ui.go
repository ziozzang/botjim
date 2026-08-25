package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/progress"
	"github.com/ziozzang/botjim/internal/session"
	"github.com/ziozzang/botjim/internal/tui"
)

// clientUI is the progress front-end for a client run: the full TUI on a
// terminal, a single refresh line under --no-tui, nothing under -q. It owns
// the main goroutine for the TUI case (the engine runs underneath).
type clientUI struct {
	reg     *progress.Registry
	pull    bool
	f       *flags
	line    *lineUI
	waitKey bool // after completion, hold the final screen for a keypress
}

func newClientUI(f *flags, reg *progress.Registry, pull bool) *clientUI {
	return &clientUI{reg: reg, pull: pull, f: f}
}

// Run drives the UI while call runs in a goroutine; it returns when call
// finishes or (TUI only) the user quits early — in that case the context is
// cancelled so call unwinds.
func (u *clientUI) Run(ctx context.Context, cancel context.CancelFunc, call func() session.ClientResult) session.ClientResult {
	if u.f.quiet {
		return call()
	}
	if !stderrIsTerminal() || u.f.noTUI {
		lu := newLineUI(u)
		lu.Run(ctx)
		res := call()
		lu.Close()
		return res
	}
	// The result is shared state guarded by resDone: the done-forwarder
	// must not consume it out from under the return path (that deadlock
	// held every browser-flow transfer open after its final keypress).
	var res session.ClientResult
	resDone := make(chan struct{})
	go func() {
		res = call()
		close(resDone)
	}()
	done := make(chan error, 1)
	go func() {
		<-resDone
		done <- res.Err
	}()
	_ = tui.RunClientProgress(ctx, u.reg, u.pull, done, u.waitKey)
	// if the TUI exited before the transfer finished, the user quit: abort
	select {
	case <-resDone:
	default:
		cancel()
		<-resDone
	}
	return res
}

// lineUI is the --no-tui single-line progress renderer.
type lineUI struct {
	u        *clientUI
	ticker   *time.Ticker
	stop     chan struct{}
	done     chan struct{}
	lastLen  int
	finished bool
}

func newLineUI(u *clientUI) *lineUI {
	return &lineUI{u: u, stop: make(chan struct{}), done: make(chan struct{})}
}

func (l *lineUI) Run(ctx context.Context) {
	if !stderrIsTerminal() {
		close(l.done)
		return
	}
	l.ticker = time.NewTicker(250 * time.Millisecond)
	go func() {
		defer close(l.done)
		defer l.ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-l.stop:
				return
			case <-l.ticker.C:
				l.render()
			}
		}
	}()
}

func (l *lineUI) render() {
	s := l.u.reg.Snapshot()
	direction := "↑"
	if l.u.pull {
		direction = "↓"
	}
	var b strings.Builder
	pct := 0.0
	if s.TotalBytes > 0 {
		pct = float64(s.SentBytes+s.SkippedBytes) / float64(s.TotalBytes) * 100
	}
	b.WriteString(fmt.Sprintf("\r%s %5.1f%% %s/%s %s/s eta %s files %d/%d",
		direction, pct, humanBytes(s.SentBytes+s.SkippedBytes), humanBytes(s.TotalBytes),
		humanBytes(uint64(s.RateBps)), fmtETA(s.ETA), s.DoneFiles+s.SkipFiles, s.TotalFiles))
	if s.Scanning {
		b.WriteString(" (scanning…)")
	}
	if n := len(b.String()); n < l.lastLen {
		b.WriteString(strings.Repeat(" ", l.lastLen-n))
	} else {
		l.lastLen = n
	}
	fmt.Fprint(os.Stderr, b.String())
}

func (l *lineUI) Close() {
	if l.ticker != nil {
		l.ticker.Stop()
	}
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
	<-l.done
	if l.lastLen > 0 {
		fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", l.lastLen)+"\r")
	}
}

func fmtETA(d time.Duration) string {
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

// serverUI is the server front-end: the btop dashboard on a terminal, plain
// lines otherwise. It owns the main goroutine when active.
type serverUI struct {
	srv *session.Server
	f   *flags
}

func newServerUI(srv *session.Server, f *flags) *serverUI {
	return &serverUI{srv: srv, f: f}
}

// Run blocks until the server should stop (user quit or context death).
func (u *serverUI) Run(ctx context.Context) {
	if u.f.quiet || !stderrIsTerminal() || u.f.noTUI {
		<-ctx.Done()
		return
	}
	_ = tui.RunDashboard(ctx, u.srv)
}

func osName() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

func archName() string {
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}
