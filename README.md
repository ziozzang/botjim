# botjim

**Files, ferried intact.** — the ergonomics of `tar | netcat`, with attributes preserved, chunk-parallel streams, crash-safe resume, and end-to-end-encrypted relay transfers for machines that cannot reach each other.

botjim is a CLI file transfer tool for Linux and macOS. A server waits; clients push or pull. It moves modes, ownership, timestamps, xattrs, symlinks, hardlinks and sparse holes verbatim, parallelizes a single large file across N streams over one TCP port, and resumes where it left off when re-run after an interruption. When neither side can accept connections, a relay brokers the transfer — and still cannot read a byte of it.

```
$ botjim server                                # server: waits, btop-style dashboard
$ botjim send 1.2.3.4 foo*                     # push foo* to the server
$ botjim pull 1.2.3.4 'data/*'                 # pull from the server
$ botjim send 1.2.3.4                          # no paths: MC-style picker TUI

$ botjim relay                                 # relay broker (pairing + spooling)
$ botjim send --via relay.example.com data/    # push through a relay (prints a code)
$ botjim recv --via relay.example.com --code CODE   # receive on the other machine
```

## Features

- **Full attribute preservation** — mode (incl. setuid/setgid/sticky), uid/gid (`--map-owners`), mtime/atime (nanosecond), xattrs, symlinks, hardlinks (data sent once), sparse files (zero chunks never touch the wire), fifo/device nodes (`--devices`, root only). Only ctime is impossible — the kernel forbids it.
- **Chunk-parallel** — a single file is split into 4/8/16MiB chunks fanned out over N streams (`--parallel`, default 8) multiplexed on one TCP connection (yamux).
- **Resume** — the receiver keeps `<name>.fs-part-<nonce>` plus a sidecar (per-chunk hash bitmap); a re-run re-hashes what's on disk and only fetches the gaps. Verified by a kill -9 suite; a completed file costs 0 bytes on re-run.
- **Compression** — per-chunk zstd (default) / lz4 / none, with automatic raw fallback for incompressible data.
- **Relay mode** — for machines behind NAT: both peers connect out to a broker, pair on a 125-bit code, and transfer end-to-end encrypted (X25519 + ChaCha20-Poly1305); the relay shuffles ciphertext only. The broker can buffer up to `--spool-max` (default 2GiB, memory-first then disk) so a fast sender can run ahead of a slow receiver.
- **TUI** — btop-style server dashboard (braille sparkline throughput, per-connection and per-file rate/ETA, log tail); client progress view (bar, live rate, global and per-file ETA, scrolling transfer log); `?` help everywhere; single-line fallback in pipes.
- **MC-style browser** — run `send` with no paths to pick files midnight-commander-style: space marks (files AND directories — a marked directory sends its subtree), `/` regex-filters with match highlighting, PgUp/PgDn scrolling, `?` help; pull mode browses the server remotely.
- **Self-update** — `botjim update` replaces the binary from GitHub Releases after SHA256SUMS verification.

## Install

Grab a static binary for your platform from [Releases](https://github.com/ziozzang/botjim/releases), or build from source:

```
go build -o botjim ./cmd/botjim
```

## Commands

Every command takes `--help` for its full option list. (`-s` / `-c` from earlier releases still work as aliases.)

| command | purpose |
|---|---|
| `botjim server [flags]` | wait for transfers (default port 4761); `--root` is the jail |
| `botjim send HOST[:port] [PATH...]` | push; no paths opens the picker |
| `botjim pull HOST[:port] [RPATH...]` | pull into `--dest` |
| `botjim relay [flags]` | pairing broker (default port 4762) |
| `botjim send --via RELAY PATH...` | push through a relay; prints a one-shot pairing code |
| `botjim recv --via RELAY --code CODE` | receive a relay push into `--dest` |
| `botjim update [--check\|--force]` | self-update |
| `botjim version` / `botjim help [cmd]` | |

The server jails everything inside `--root`: pushes land there, pulls read there, and `..`/absolute paths/symlink escapes are refused. See [README_KO.md](README_KO.md) for the Korean edition, [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Relay walkthrough

```
machine C (anywhere)      $ botjim relay --spool-max 2G

machine A (NAT'd)         $ botjim send --via C.example.com photos/
                         code:  4CSQG-2622A-NA9ZR-PQBMF-1ZT28
                         (share it with B out-of-band — chat, phone, whatever)

machine B (NAT'd)         $ botjim recv --via C.example.com \
                                 --code 4CSQG-2622A-NA9ZR-PQBMF-1ZT28
```

The relay matches peers on `SHA-256(code)` only; it never sees the code itself, and after pairing every byte — including botjim's own protocol handshake — is inside the AEAD record layer. Codes are one-shot (first taker wins) and expire after `--wait` minutes. See [ARCHITECTURE.md](ARCHITECTURE.md#relay-mode) for the threat model.

## Performance (loopback tmpfs, 16 cores)

| workload | botjim | `tar \| nc` (with extraction) |
|---|---|---|
| 5GiB single file (none, p=8) | **1397 MiB/s** | 1054 MiB/s |
| 5GiB single (zstd-3) | 1159 MiB/s | — |
| 20k × 64KiB small files | 348 MiB/s | 437 MiB/s |
| 1GiB random (zstd, raw fallback) | 1163 MiB/s | 390 MiB/s |
| 1GiB zeros (sparse) | 0.09s (holes are not transmitted) | — |

## Security

Direct mode (server/send/pull) is **plaintext** — use it on trusted networks, VPNs or ssh tunnels; an auth token is planned. Relay mode is end-to-end encrypted by construction: the broker holds only ciphertext, cannot decrypt, and tampering is detected. A malicious relay can refuse service or observe timing/sizes, nothing more.

## Development

```
make test        # unit + integration (push/pull × compression × parallel matrix, resume, jail, relay)
make race        # -race
make harnesses   # attribute harness + kill -9 suite + docker container E2E
make bench       # benchmarks vs tar|nc
```

## License

MIT — see [LICENSE](LICENSE)
