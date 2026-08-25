# botjim

**Files, ferried intact.** — the ergonomics of `tar | netcat`, with attributes preserved, chunk-parallel streams and crash-safe resume.

botjim is a CLI file transfer tool for Linux and macOS. A server waits; clients push or pull. It moves modes, ownership, timestamps, xattrs, symlinks, hardlinks and sparse holes verbatim, parallelizes a single large file across N streams over one TCP port, and resumes where it left off when re-run after an interruption.

```
$ botjim -s                                    # server: waits, btop-style dashboard
$ botjim -c 1.2.3.4 foo*                       # client: push foo* to the server
$ botjim -c 1.2.3.4 --pull 'data/*'            # pull from the server
$ botjim -c 1.2.3.4                            # no paths: MC-style picker TUI
```

## Features

- **Full attribute preservation** — mode (incl. setuid/setgid/sticky), uid/gid (`--map-owners`), mtime/atime (nanosecond), xattrs, symlinks, hardlinks (data sent once), sparse files (zero chunks never touch the wire), fifo/device nodes (`--devices`, root only). Only ctime is impossible — the kernel forbids it.
- **Chunk-parallel** — a single file is split into 4/8/16MiB chunks fanned out over N streams (`--parallel`, default 8) multiplexed on one TCP connection (yamux).
- **Resume** — the receiver keeps `<name>.fs-part-<nonce>` plus a sidecar (per-chunk hash bitmap); a re-run re-hashes what's on disk and only fetches the gaps. Verified by a kill -9 suite; a completed file costs 0 bytes on re-run.
- **Compression** — per-chunk zstd (default) / lz4 / none, with automatic raw fallback for incompressible data.
- **TUI** — btop-style server dashboard (braille sparkline throughput, per-connection progress, log tail) and a client progress view (bar, rate, ETA); single-line fallback in pipes.
- **MC-style browser** — run with no paths to pick files with space/enter midnight-commander-style; pull mode browses the server's directories remotely.
- **Self-update** — `botjim update` replaces the binary from GitHub Releases after SHA256SUMS verification.

## Install

Grab a static binary for your platform from [Releases](https://github.com/ziozzang/botjim/releases), or build from source:

```
go build -o botjim ./cmd/botjim
```

## Usage

```
botjim -s [flags]                        # server (default port 4761)
botjim -c HOST[:PORT] [PATH...]          # push
botjim -c HOST[:PORT] --pull [RPATH...]  # pull
botjim update [--check|--force]          # self-update
```

The server jails everything inside `--root`: pushes land there, pulls read there, and `..`/absolute paths/symlink escapes are refused. See [README_KO.md](README_KO.md) for the full flag table (Korean).

Glob arguments already expanded by the shell are taken as-is; quoted patterns are expanded internally (with `**` recursion). A literal path containing `*` wins over the pattern if it exists.

## Performance (loopback tmpfs, 16 cores)

| workload | botjim | `tar \| nc` (with extraction) |
|---|---|---|
| 5GiB single file (none, p=8) | **1397 MiB/s** | 1054 MiB/s |
| 5GiB single (zstd-3) | 1159 MiB/s | — |
| 20k × 64KiB small files | 348 MiB/s | 437 MiB/s |
| 1GiB random (zstd, raw fallback) | 1163 MiB/s | 390 MiB/s |
| 1GiB zeros (sparse) | 0.09s (holes are not transmitted) | — |

## Protocol sketch

One TCP connection: a 36-byte handshake (magic `FSY1`, feature bits, crc32c) → yamux multiplexing → one control stream (manifest, HaveBitmaps, FileResults) + N data streams (chunk frames). Chunk identity is `SHA-256(path‖index‖data)` — intact data written at the wrong offset fails verification. Encryption (V1 is plaintext) drops into the reserved `transport.CipherFunc` hook as an X25519+ChaCha20-Poly1305 record layer without frame changes.

## Security note

V1 is **plaintext**. Use it on trusted networks, VPNs or ssh tunnels. The server refuses anything outside its root, but anyone who can reach the port can push — an auth token is planned for V1.1.

## Development

```
make test        # unit + integration (push/pull × compression × parallel matrix, resume)
make race        # -race, twice
make harnesses   # attribute harness + kill -9 suite + docker container E2E
make bench       # benchmarks vs tar|nc
```

## License

MIT — see [LICENSE](LICENSE)
