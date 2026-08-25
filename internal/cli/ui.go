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
)

// clientUI is the progress front-end for a client run. The TUI replaces the
// renderer when stderr is a terminal and --no-tui is absent; otherwise a
// single refresh line does the job (pipes get one summary line at the end).
type clientUI struct {
	reg     *progress.Registry
	pull    bool
	f       *flags
	ticker  *time.Ticker
	stop    chan struct{}
	done    chan struct{}
	lastLen int
}

func newClientUI(f *flags, reg *progress.Registry, pull bool) *clientUI {
	return &clientUI{reg: reg, pull: pull, f: f, stop: make(chan struct{}), done: make(chan struct{})}
}

func (u *clientUI) Run(ctx context.Context) {
	interval := 250 * time.Millisecond
	if u.f.quiet || !stderrIsTerminal() || u.f.noTUI {
		if u.f.quiet {
			close(u.done)
			return
		}
	}
	u.ticker = time.NewTicker(interval)
	go func() {
		defer close(u.done)
		defer u.ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-u.stop:
				return
			case <-u.ticker.C:
				u.render()
			}
		}
	}()
}

func (u *clientUI) render() {
	s := u.reg.Snapshot()
	direction := "↑ push"
	if u.pull {
		direction = "↓ pull"
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
	if n := len(b.String()); n < u.lastLen {
		b.WriteString(strings.Repeat(" ", u.lastLen-n))
	} else {
		u.lastLen = n
	}
	fmt.Fprint(os.Stderr, b.String())
}

func (u *clientUI) Close() {
	if u.ticker != nil {
		u.ticker.Stop()
	}
	select {
	case <-u.stop:
	default:
		close(u.stop)
	}
	<-u.done
	if u.lastLen > 0 {
		fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", u.lastLen)+"\r")
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

// serverUI is the server-side front-end: plain log lines for now; the btop
// dashboard takes over on terminals.
type serverUI struct {
	srv  *session.Server
	f    *flags
	stop chan struct{}
	done chan struct{}
}

func newServerUI(srv *session.Server, f *flags) *serverUI {
	return &serverUI{srv: srv, f: f, stop: make(chan struct{}), done: make(chan struct{})}
}

func (u *serverUI) Run(ctx context.Context) {
	if u.f.quiet || !stderrIsTerminal() || u.f.noTUI {
		close(u.done)
		return
	}
	u.renderStatic()
	go func() {
		defer close(u.done)
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-u.stop:
				return
			case <-t.C:
			}
		}
	}()
}

func (u *serverUI) renderStatic() {
	fmt.Fprint(os.Stderr, "press Ctrl-C to stop\n")
}

func (u *serverUI) Close() {
	select {
	case <-u.stop:
	default:
		close(u.stop)
	}
	<-u.done
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
