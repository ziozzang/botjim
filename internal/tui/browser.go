package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/session"
)

// Browser palette (256-color, degrades gracefully).
var (
	stBrand    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213"))
	stMode     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("75"))
	stPath     = lipgloss.NewStyle().Foreground(lipgloss.Color("222"))
	stDir      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	stSymlink  = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	stExec     = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	stPlain    = lipgloss.NewStyle()
	stMarkOn   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("82"))
	stMarkOff  = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	stSize     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	stCursorG  = "▌"
	stStatus   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	stStatusHi = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("82"))
	stFooter   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	stKey      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
	stError    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	stPrompt   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	stMatch    = lipgloss.NewStyle().Bold(true).Underline(true)
	stRowSel   = lipgloss.NewStyle().Reverse(true)
)

// symlinkModeBit marks a symlink in protocol.ListEntry.Mode (shared with
// the server's listing).
const symlinkModeBit = uint16(1 << 15)

// browserModel is the midnight-commander-style picker: one pane, space to
// mark, enter to descend, '/' to regex-filter, `s` to send the marked set.
type browserModel struct {
	cfg      BrowserConfig
	entries  []protocol.ListEntry // full listing
	view     []protocol.ListEntry // entries visible under the filter
	cursor   int                  // index into view
	offset   int                  // first rendered row of view (scrolling)
	marked   map[string]bool
	cwd      string // display path (remote-relative or local)
	cwdLocal string // local absolute base for push mode
	err      string
	quitting bool
	result   []string
	loading  bool

	searching bool   // '/' input active
	pattern   string // raw input
	filter    *regexp.Regexp
	filterErr string

	width  int
	height int
}

type listLoadedMsg struct {
	dir     string
	entries []protocol.ListEntry
	err     error
}

// RunBrowser opens the picker and returns the chosen paths (empty when the
// user quits without marking anything).
func RunBrowser(ctx context.Context, cfg BrowserConfig) ([]string, error) {
	m := &browserModel{cfg: cfg, marked: map[string]bool{}, width: 80, height: 24}
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
			if fi.Mode()&os.ModeSymlink != 0 {
				le.Mode |= symlinkModeBit
			}
		}
		out = append(out, le)
	}
	sortEntries(out)
	return out, nil
}

// listRemoteOnce lists a remote directory over a short-lived connection.
func listRemoteOnce(addr, dir string) ([]protocol.ListEntry, error) {
	resp, err := session.ListRemote(context.Background(), addr, dir, 0, 4096)
	if err != nil {
		return nil, err
	}
	out := append([]protocol.ListEntry(nil), resp.Entries...)
	sortEntries(out)
	return out, nil
}

func sortEntries(out []protocol.ListEntry) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
}

func (m *browserModel) Init() tea.Cmd { return m.reload() }

// visibleRows is how many listing rows fit under the chrome.
func (m *browserModel) visibleRows() int {
	n := m.height - 5 // title, blank, status, blank, footer
	if n < 1 {
		n = 1
	}
	return n
}

func (m *browserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clamp()
		return m, nil
	case listLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		if msg.dir == m.cwd {
			m.entries = msg.entries
			m.applyFilter()
			m.cursor = 0
			m.offset = 0
		}
		return m, nil
	case tea.KeyMsg:
		if m.searching {
			m.updateSearch(msg)
			return m, nil
		}
		switch msg.Type {
		case tea.KeyCtrlC:
			m.quitting = true
			return m, tea.Quit
		case tea.KeyUp:
			m.moveCursor(-1)
		case tea.KeyDown:
			m.moveCursor(1)
		case tea.KeyPgUp:
			m.moveCursor(-m.visibleRows())
		case tea.KeyPgDown:
			m.moveCursor(m.visibleRows())
		case tea.KeyHome:
			m.moveCursor(-len(m.view))
		case tea.KeyEnd:
			m.moveCursor(len(m.view))
		case tea.KeyEnter:
			if e, ok := m.atCursor(); ok && e.IsDir {
				m.enter(e.Name)
				return m, m.reload()
			}
		case tea.KeySpace:
			if e, ok := m.atCursor(); ok {
				m.toggle(e)
				m.moveCursor(1)
			}
		case tea.KeyCtrlU, tea.KeyBackspace:
			m.up()
			return m, m.reload()
		}
		switch msg.String() {
		case "j":
			m.moveCursor(1)
		case "k":
			m.moveCursor(-1)
		case "g":
			m.moveCursor(-len(m.view))
		case "G":
			m.moveCursor(len(m.view))
		case "u":
			m.up()
			return m, m.reload()
		case "/":
			m.searching = true
			m.pattern = ""
			m.filterErr = ""
		case "a":
			for _, e := range m.view {
				if !e.IsDir {
					m.marked[m.join(e.Name)] = true
				}
			}
		case "c":
			m.marked = map[string]bool{}
		case "x":
			m.clearFilter()
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

// moveCursor moves by delta rows and keeps the cursor inside both the
// listing and the scrolled window.
func (m *browserModel) moveCursor(delta int) {
	if len(m.view) == 0 {
		m.cursor = 0
		return
	}
	m.cursor += delta
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor > len(m.view)-1 {
		m.cursor = len(m.view) - 1
	}
	m.clamp()
}

// clamp scrolls the window so the cursor row is always rendered.
func (m *browserModel) clamp() {
	rows := m.visibleRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
	if maxOff := len(m.view) - rows; m.offset > maxOff {
		if maxOff < 0 {
			maxOff = 0
		}
		m.offset = maxOff
	}
}

// updateSearch handles keys while the '/' prompt is open.
func (m *browserModel) updateSearch(msg tea.KeyMsg) {
	switch msg.Type {
	case tea.KeyEnter:
		m.searching = false // keep the filter active
	case tea.KeyEsc:
		m.searching = false
		m.clearFilter()
	case tea.KeyBackspace:
		if n := len(m.pattern); n > 0 {
			r := []rune(m.pattern)
			m.pattern = string(r[:len(r)-1])
		}
		m.compileFilter()
	case tea.KeyCtrlC, tea.KeyCtrlU:
		m.pattern = ""
		m.compileFilter()
	default:
		if msg.Runes != nil && msg.Type == tea.KeyRunes {
			m.pattern += string(msg.Runes)
			m.compileFilter()
		}
	}
}

func (m *browserModel) compileFilter() {
	m.filterErr = ""
	if m.pattern == "" {
		m.clearFilter()
		return
	}
	re, err := regexp.Compile(`(?i)` + m.pattern)
	if err != nil {
		m.filterErr = err.Error()
		return
	}
	m.filter = re
	m.applyFilter()
}

func (m *browserModel) clearFilter() {
	m.pattern = ""
	m.filter = nil
	m.filterErr = ""
	m.applyFilter()
}

func (m *browserModel) applyFilter() {
	m.view = m.view[:0]
	for _, e := range m.entries {
		if m.filter == nil || m.filter.MatchString(e.Name) {
			m.view = append(m.view, e)
		}
	}
	if m.cursor > len(m.view)-1 {
		m.cursor = max(0, len(m.view)-1)
	}
	m.clamp()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// reload returns a Cmd that fetches the current directory's listing.
func (m *browserModel) reload() tea.Cmd {
	m.loading = true
	m.err = ""
	m.entries = nil
	m.view = nil
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
	if m.cursor < 0 || m.cursor >= len(m.view) {
		return protocol.ListEntry{}, false
	}
	return m.view[m.cursor], true
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
	b.WriteString(stBrand.Render(" botjim ") + stMode.Render(mode) +
		stPath.Render(" "+truncEnd(where, max(10, m.width-24))) + "\n\n")

	rows := m.visibleRows()
	start := m.offset
	end := min(start+rows, len(m.view))
	for i := start; i < end; i++ {
		b.WriteString(m.renderRow(i) + "\n")
	}
	// pad short listings so the chrome stays put
	for i := end - start; i < rows; i++ {
		b.WriteString("\n")
	}

	// status line
	b.WriteString("\n")
	if m.searching || m.pattern != "" {
		label := stPrompt.Render("  /" + m.pattern)
		if m.searching {
			label += stPrompt.Render("▏")
		}
		info := fmt.Sprintf("  %d/%d", len(m.view), len(m.entries))
		if m.filterErr != "" {
			info += "  " + stError.Render(truncEnd(m.filterErr, 40))
		}
		b.WriteString(label + stStatus.Render(info) + "\n")
	} else {
		pos := fmt.Sprintf("%d/%d", m.cursor+1, len(m.view))
		b.WriteString("  " + stStatusHi.Render(fmt.Sprintf("marked %d", len(m.marked))) +
			stStatus.Render("  "+pos+scrollHint(m)) + "\n")
	}

	keys := stKey.Render("↑↓/jk") + " move · " + stKey.Render("space") + " mark · " +
		stKey.Render("enter") + " open · " + stKey.Render("/") + " find · " +
		stKey.Render("u") + " parent · " + stKey.Render("a") + " all · " +
		stKey.Render("c") + " clear · " + stKey.Render("s") + " send · " + stKey.Render("q") + " quit"
	b.WriteString(truncANSI(keys, m.width) + "\n")
	return b.String()
}

// renderRow draws one listing row: cursor, mark, kind, name (with match
// highlight), size — full width so the cursor row inverts cleanly.
func (m *browserModel) renderRow(i int) string {
	e := m.view[i]
	cursorCol := " "
	if i == m.cursor {
		cursorCol = stCursorG
	}
	var mark string
	if m.marked[m.join(e.Name)] {
		mark = stMarkOn.Render("✔")
	} else {
		mark = stMarkOff.Render("·")
	}
	kind, nameStyle := "-", stPlain
	switch {
	case e.IsDir:
		kind, nameStyle = "d", stDir
	case e.Mode&symlinkModeBit != 0:
		kind, nameStyle = "~", stSymlink
	case e.Mode&0o111 != 0:
		kind, nameStyle = "*", stExec
	}
	name := m.renderName(e.Name, nameStyle)

	sizeW := 10
	nameW := m.width - 6 - (sizeW + 2) // "▌ · - " prefix (6 cols), size + gap
	if nameW < 12 {
		nameW = 12
	}
	row := cursorCol + " " + mark + " " + kind + " " + padDisplay(name, nameW) +
		"  " + padLeft(stSize.Render(sizeOrDir(e)), sizeW)
	if i == m.cursor {
		row = stRowSel.Render(padDisplay(row, m.width))
	}
	return row
}

// renderName styles a filename, underlining the regex match when a filter
// is active.
func (m *browserModel) renderName(name string, style lipgloss.Style) string {
	if m.filter == nil {
		return style.Render(truncEnd(name, 60))
	}
	loc := m.filter.FindStringIndex(name)
	if loc == nil {
		return style.Render(truncEnd(name, 60))
	}
	pre := style.Render(name[:loc[0]])
	mid := stMatch.Render(name[loc[0]:loc[1]])
	post := style.Render(name[loc[1]:])
	return pre + mid + post
}

func scrollHint(m *browserModel) string {
	rows := m.visibleRows()
	total := len(m.view)
	switch {
	case total <= rows:
		return ""
	case m.offset > 0 && m.offset+rows < total:
		return "  ↕ more"
	case m.offset > 0:
		return "  ↑ more"
	case m.offset+rows < total:
		return "  ↓ more"
	}
	return ""
}

// padDisplay pads s with spaces to display width w (ANSI-aware).
func padDisplay(s string, w int) string {
	dw := lipgloss.Width(s)
	if dw >= w {
		return s
	}
	return s + strings.Repeat(" ", w-dw)
}

func padLeft(s string, w int) string {
	dw := lipgloss.Width(s)
	if dw >= w {
		return s
	}
	return strings.Repeat(" ", w-dw) + s
}

// truncANSI trims a styled string to a display width, dropping whole
// escape sequences intact.
func truncANSI(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	var b strings.Builder
	width := 0
	inEsc := false
	for _, r := range s {
		if inEsc {
			b.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		if r == 0x1b {
			inEsc = true
			b.WriteRune(r)
			continue
		}
		rw := lipgloss.Width(string(r))
		if width+rw > w-1 {
			break
		}
		width += rw
		b.WriteRune(r)
	}
	b.WriteString("…")
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sizeOrDir(e protocol.ListEntry) string {
	if e.IsDir {
		return "<dir>"
	}
	return humanBytes(e.Size)
}
