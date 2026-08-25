package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/session"
)

// browserModel is the midnight-commander-style picker: one pane, space to
// mark, enter to descend, `s` to send the marked set, `u` to go up.
type browserModel struct {
	cfg      BrowserConfig
	entries  []protocol.ListEntry
	cursor   int
	marked   map[string]bool
	cwd      string // display path (remote-relative or local)
	cwdLocal string // local absolute base for push mode
	err      string
	quitting bool
	result   []string
	loading  bool
}

type listLoadedMsg struct {
	dir     string
	entries []protocol.ListEntry
	err     error
}

// RunBrowser opens the picker and returns the chosen paths (empty when the
// user quits without marking anything).
func RunBrowser(ctx context.Context, cfg BrowserConfig) ([]string, error) {
	m := &browserModel{cfg: cfg, marked: map[string]bool{}}
	if cfg.Pull {
		m.cwd = ""
	} else {
		abs, err := filepath.Abs(".")
		if err != nil {
			return nil, err
		}
		m.cwdLocal = abs
		m.cwd = abs
	}
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return nil, err
	}
	return m.result, nil
}

func listLocalDir(dir string) ([]protocol.ListEntry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []protocol.ListEntry
	for _, de := range des {
		le := protocol.ListEntry{Name: de.Name(), IsDir: de.IsDir()}
		if fi, err := de.Info(); err == nil {
			le.Size = uint64(fi.Size())
			le.MtimeMS = fi.ModTime().UnixMilli()
			le.Mode = uint16(fi.Mode().Perm())
		}
		out = append(out, le)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// listRemoteOnce lists a remote directory over a short-lived connection.
func listRemoteOnce(addr, dir string) ([]protocol.ListEntry, error) {
	resp, err := session.ListRemote(context.Background(), addr, dir, 0, 4096)
	if err != nil {
		return nil, err
	}
	out := append([]protocol.ListEntry(nil), resp.Entries...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func (m *browserModel) Init() tea.Cmd { return m.reload() }

func (m *browserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case listLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		if msg.dir == m.cwd {
			m.entries = msg.entries
			m.cursor = 0
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			m.quitting = true
			return m, tea.Quit
		case tea.KeyUp:
			if m.cursor > 0 {
				m.cursor--
			}
		case tea.KeyDown:
			if m.cursor < len(m.entries)-1 {
				m.cursor++
			}
		case tea.KeyEnter:
			if e, ok := m.atCursor(); ok && e.IsDir {
				m.enter(e.Name)
				return m, m.reload()
			}
		case tea.KeySpace:
			if e, ok := m.atCursor(); ok {
				m.toggle(e)
				if m.cursor < len(m.entries)-1 {
					m.cursor++
				}
			}
		case tea.KeyCtrlU, tea.KeyBackspace:
			m.up()
			return m, m.reload()
		}
		switch msg.String() {
		case "j":
			if m.cursor < len(m.entries)-1 {
				m.cursor++
			}
		case "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "u":
			m.up()
			return m, m.reload()
		case "a":
			for _, e := range m.entries {
				if !e.IsDir {
					m.marked[m.join(e.Name)] = true
				}
			}
		case "c":
			m.marked = map[string]bool{}
		case "s":
			m.send()
			return m, tea.Quit
		case "q", "Q", "esc":
			m.quitting = true
			return m, tea.Quit
		case "r":
			return m, m.reload()
		}
	}
	return m, nil
}

// reload returns a Cmd that fetches the current directory's listing.
func (m *browserModel) reload() tea.Cmd {
	m.loading = true
	m.err = ""
	m.entries = nil
	cwd := m.cwd
	cwdLocal := m.cwdLocal
	addr := m.cfg.Addr
	pull := m.cfg.Pull
	return func() tea.Msg {
		if pull {
			entries, err := listRemoteOnce(addr, cwd)
			return listLoadedMsg{dir: cwd, entries: entries, err: err}
		}
		entries, err := listLocalDir(cwdLocal)
		return listLoadedMsg{dir: cwd, entries: entries, err: err}
	}
}

func (m *browserModel) atCursor() (protocol.ListEntry, bool) {
	if m.cursor < 0 || m.cursor >= len(m.entries) {
		return protocol.ListEntry{}, false
	}
	return m.entries[m.cursor], true
}

func (m *browserModel) join(name string) string {
	if m.cwd == "" || m.cwd == "." {
		return name
	}
	return m.cwd + "/" + name
}

func (m *browserModel) enter(name string) {
	if m.cfg.Pull {
		m.cwd = m.join(name)
	} else {
		m.cwdLocal = filepath.Join(m.cwdLocal, name)
		m.cwd = m.cwdLocal
	}
}

func (m *browserModel) up() {
	if m.cfg.Pull {
		if m.cwd == "" {
			return
		}
		i := strings.LastIndexByte(m.cwd, '/')
		if i < 0 {
			m.cwd = ""
		} else {
			m.cwd = m.cwd[:i]
		}
	} else {
		parent := filepath.Dir(m.cwdLocal)
		if parent == m.cwdLocal {
			return
		}
		m.cwdLocal = parent
		m.cwd = parent
	}
}

func (m *browserModel) toggle(e protocol.ListEntry) {
	if e.IsDir {
		return // mark files; whole-dir marking via descending + 'a'
	}
	key := m.join(e.Name)
	if m.marked[key] {
		delete(m.marked, key)
	} else {
		m.marked[key] = true
	}
}

func (m *browserModel) send() {
	var out []string
	for p := range m.marked {
		out = append(out, p)
	}
	sort.Strings(out)
	m.result = out
}

func (m *browserModel) View() string {
	var b strings.Builder
	mode := "push local"
	if m.cfg.Pull {
		mode = "pull remote"
	}
	where := m.cwd
	if where == "" {
		where = "/"
	}
	b.WriteString(fmt.Sprintf("botjim browser — %s — %s\n\n", mode, where))
	if m.err != "" {
		b.WriteString("error: " + m.err + "\n\n")
	}
	if m.loading {
		b.WriteString("loading…\n")
	}
	for i, e := range m.entries {
		cursor := " "
		if i == m.cursor {
			cursor = ">"
		}
		mark := " "
		if m.marked[m.join(e.Name)] {
			mark = "*"
		}
		kind := " "
		if e.IsDir {
			kind = "d"
		}
		b.WriteString(fmt.Sprintf("%s%s %s %-44s %10s\n",
			cursor, mark, kind, truncEnd(e.Name, 44), sizeOrDir(e)))
	}
	b.WriteString(fmt.Sprintf("\nmarked %d\n", len(m.marked)))
	b.WriteString("\n↑↓/jk move · space mark · enter open · u parent · a mark-all-files · c clear · s send · q quit\n")
	return b.String()
}

func sizeOrDir(e protocol.ListEntry) string {
	if e.IsDir {
		return "<dir>"
	}
	return humanBytes(e.Size)
}
