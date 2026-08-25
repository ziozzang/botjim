// Package tui holds botjim's terminal front-ends: the btop-style server
// dashboard, the client progress view and the midnight-commander-style file
// picker. Everything renders through bubbletea and polls progress
// registries; no engine code prints to the terminal by itself.
package tui

import (
	"context"
	"errors"
)

// BrowserConfig configures the picker.
type BrowserConfig struct {
	Addr string
	Pull bool // browse the remote (true) or the local cwd (false)
	Dest string
}

// Selection is the picker's outcome.
type Selection struct {
	Paths []string
}

// RunBrowser opens the picker and returns the chosen paths. Empty selection
// means the user quit without choosing.
func RunBrowser(ctx context.Context, cfg BrowserConfig) ([]string, error) {
	return nil, errors.New("browser TUI not wired yet")
}
