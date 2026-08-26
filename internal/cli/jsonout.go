package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/ziozzang/botjim/internal/progress"
)

// jsonSink writes transfer events as NDJSON lines to stdout — the
// machine-readable stream for scripts and CI.
type jsonSink struct {
	mu  sync.Mutex
	out *os.File
}

func (j *jsonSink) emit(e progress.Event) {
	b, err := json.Marshal(map[string]string{
		"ts":   e.At.Format("2006-01-02T15:04:05.000Z07:00"),
		"type": e.Kind,
		"path": e.Path,
		"msg":  e.Msg,
	})
	if err != nil {
		return
	}
	j.mu.Lock()
	j.out.Write(append(b, '\n'))
	j.mu.Unlock()
}

// attachJSON wires the registry's structured sink to stdout (or fd 3 when
// stderr carries the human progress).
func attachJSON(reg *progress.Registry) {
	s := &jsonSink{out: os.Stdout}
	reg.SetEventSink(s.emit)
	fmt.Fprintln(os.Stderr, "json events: stdout")
}
