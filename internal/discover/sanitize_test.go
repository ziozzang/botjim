package discover

import "testing"

// TestHasControl: beacon fields with terminal-injection sequences must be
// flagged (they are printed to the terminal by `botjim peers`).
func TestHasControl(t *testing.T) {
	clean := []string{"lab1", "botjim 0.10.0", "/srv/data", "host-name_2"}
	dirty := []string{
		"\x1b[2J",          // ANSI clear screen
		"a\rb",             // carriage return overwrite
		"x\x07y",           // bell
		"\x1b]0;title\x07", // OSC title set
		"tab\tsep",         // tab
		"null\x00byte",
	}
	for _, s := range clean {
		if hasControl(s) {
			t.Errorf("clean %q flagged", s)
		}
	}
	for _, s := range dirty {
		if !hasControl(s) {
			t.Errorf("control string %q not flagged", s)
		}
	}
}
