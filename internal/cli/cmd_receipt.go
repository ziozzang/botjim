package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ziozzang/botjim/internal/session"
)

// receipt is the standalone proof-of-transfer document.
type receipt struct {
	TS        string `json:"ts"`
	Direction string `json:"direction"`
	Peer      string `json:"peer"`
	Files     uint64 `json:"files"`
	Bytes     uint64 `json:"bytes"`
	Skipped   uint64 `json:"skipped"`
	Errors    int    `json:"errors"`
	Manifest  string `json:"manifest_sha256,omitempty"`
	OK        bool   `json:"ok"`
}

// writeReceipt stores the receipt at path (or the default directory with
// a timestamped name when path is "default").
func writeReceipt(path, peer string, pull bool, res session.ClientResult) string {
	r := receipt{
		TS:        time.Now().Format(time.RFC3339Nano),
		Direction: "push",
		Peer:      peer,
		Files:     res.Report.Files,
		Bytes:     res.Report.Bytes,
		Skipped:   res.Report.SkippedBytes,
		Errors:    len(res.Report.Errors),
		Manifest:  res.ManifestDigest,
		OK:        res.Err == nil && len(res.Report.Errors) == 0,
	}
	if pull {
		r.Direction = "pull"
	}
	p := path
	if p == "default" || p == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(dir, "botjim", "receipts")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return ""
		}
		p = filepath.Join(dir, time.Now().Format("20060102-150405.000")+".json")
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return ""
	}
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		return ""
	}
	return p
}
