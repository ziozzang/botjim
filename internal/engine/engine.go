// Package engine implements the direction-agnostic transfer cores: Sender
// (manifest walker + chunk scheduler + N data-stream workers) and Receiver
// (manifest processor + part assembler + finalizer). Which side of a
// connection runs which core is decided by the session layer; the cores
// themselves never know whether they are the client or the server.
package engine

import (
	"github.com/ziozzang/botjim/internal/attrs"
)

// Options is the per-transfer configuration both cores share. It mirrors the
// negotiated InitTransfer on the wire.
type Options struct {
	Direction   uint8 // protocol.DirPush / DirPull
	Compression uint8 // compress.AlgNone / AlgZstd / AlgLz4
	ZstdLevel   int
	ChunkPolicy int64 // 0 = auto ladder
	Preserve    uint16
	Parallel    int
	Resume      uint8 // 0 strict (size+mtime), 1 size-only, 2 fresh
	KeepGoing   bool
	Fsync       bool
	OwnerPolicy attrs.OwnerPolicy
	Nonce       string   // session nonce hex — suffix for new part files
	RelHome     string   // sender side: root that maps to manifest "."
	Exclude     []string // walker exclusions
	Include     []string // walker inclusions
	LimitBPS    int64    // send-rate cap (0 = unlimited)
	DryRun      bool     // plan only
}

// FileError is one failed file in the report.
type FileError struct {
	Path string
	Code uint16
	Msg  string
}

// Report summarizes one transfer run.
type Report struct {
	Files        uint64
	Bytes        uint64 // payload bytes that hit the wire (post-decision, pre-compression)
	SkippedBytes uint64 // bytes never sent because already present
	Errors       []FileError
	Warnings     []string
	Cancelled    bool
}

// Error codes shared by FileResult.
const (
	CodeOK            uint16 = 0
	CodeIO            uint16 = 1
	CodeNoSpace       uint16 = 2
	CodeInvalidPath   uint16 = 3
	CodeSourceChanged uint16 = 4
	CodePerm          uint16 = 5
	CodeExists        uint16 = 6
	CodeProtocol      uint16 = 7
	Codecanceled      uint16 = 8
)
