// Package tui holds botjim's terminal front-ends: the btop-style server
// dashboard, the client progress view and the midnight-commander-style file
// picker. Everything renders through bubbletea and polls progress
// registries; no engine code prints to the terminal by itself.
package tui

// BrowserConfig configures the picker.
type BrowserConfig struct {
	Addr     string
	Pull     bool // browse the remote (true) or the local cwd (false)
	Dest     string
	StartDir string // push: directory to open first (sticky across sends)
}
