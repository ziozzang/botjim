// Package metrics renders botjim's server counters in the Prometheus
// text exposition format. Stdlib only — no client library needed for
// counters and gauges.
package metrics

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ziozzang/botjim/internal/session"
	"github.com/ziozzang/botjim/internal/version"
)

// Serve binds the metrics endpoint on addr until ctx ends. Scrapes hit
// /metrics (Prometheus text format); anything else gets a tiny index.
func Serve(done <-chan struct{}, addr string, srv *session.Server, started time.Time) error {
	mux := http.NewServeMux()
	var scrapes atomic.Int64
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		scrapes.Add(1)
		st := srv.Stats()
		var sb strings.Builder
		writeMetric(&sb, "botjim_sessions_total", "counter", "Client sessions accepted since start.", st.Sessions)
		writeMetric(&sb, "botjim_files_total", "counter", "Files transferred (both directions) since start.", st.Files)
		writeMetric(&sb, "botjim_bytes_total", "counter", "Bytes transferred (on the wire payload) since start.", st.Bytes)
		writeMetric(&sb, "botjim_errors_total", "counter", "Failed transfers and per-file errors since start.", st.Errors)
		writeMetric(&sb, "botjim_active_sessions", "gauge", "Currently connected clients.", int64(st.Active))
		writeMetric(&sb, "botjim_metrics_scrapes_total", "counter", "Scrapes of this endpoint.", scrapes.Load())
		writeMetric(&sb, "botjim_uptime_seconds", "gauge", "Seconds since server start.", int64(time.Since(started).Seconds()))
		fmt.Fprintf(&sb, "# HELP botjim_version_info botjim build information.\n# TYPE botjim_version_info gauge\nbotjim_version_info{version=\"%s\"} 1\n", version.Version)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(sb.String()))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "botjim %s — metrics at /metrics\n", version.Version)
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-done
		_ = ln.Close()
	}()
	srvHTTP := &http.Server{Handler: mux}
	err = srvHTTP.Serve(ln)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil // listener closed on shutdown
}

func writeMetric(sb *strings.Builder, name, typ, help string, v int64) {
	fmt.Fprintf(sb, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, typ, name, v)
}
