# botjim

**Files, ferried intact.** — the ergonomics of `tar | netcat`, with attributes preserved, chunk-parallel streams, crash-safe resume, delta updates, token/pass/cloak hardening, end-to-end-encrypted relay transfers, and token-joined swarms for very large immutable artifacts.

botjim is a CLI file transfer tool for Linux and macOS. A server waits; clients push or pull. It moves modes, ownership, timestamps, xattrs, symlinks, hardlinks and sparse holes verbatim, parallelizes a single large file across N streams over one TCP port, resumes where it left off when re-run after an interruption, and re-sends only the chunks that actually changed. When neither side can accept connections, a relay brokers the transfer — and still cannot read a byte of it.

```
$ botjim server --token s3cret                # server: waits, btop-style dashboard
$ botjim send 1.2.3.4 foo*                    # push foo* to the server
$ botjim pull 1.2.3.4 'data/*'                # pull from the server
$ botjim send 1.2.3.4                         # no paths: MC-style picker TUI

$ botjim sync push lab                        # one-shot mirror (policy from config)
$ tar c dir | botjim pipe send --stdin d.tgz 1.2.3.4   # tar | nc drop-in

$ botjim relay                                # relay broker (pairing + spooling)
$ botjim send --via relay.example.com data/   # push through a relay (prints a code)
$ botjim recv --via relay.example.com --code CODE     # receive on the other machine
```

## Features

- **Full attribute preservation** — mode (incl. setuid/setgid/sticky), uid/gid (`--map-owners`), mtime/atime (nanosecond), xattrs, symlinks, hardlinks (data sent once), sparse files (zero chunks never touch the wire), fifo/device nodes (`--devices`, root only). Only ctime is impossible — the kernel forbids it.
- **Chunk-parallel** — a single file is split into 4/8/16MiB chunks fanned out over N streams (`--parallel`, default 8) multiplexed on one TCP connection (yamux).
- **Resume** — the receiver keeps `<name>.fs-part-<nonce>` plus a sidecar (per-chunk hash bitmap); a re-run re-hashes what's on disk and only fetches the gaps. Verified by a kill -9 suite; a completed file costs 0 bytes on re-run. `--retries` auto-reconnects mid-transfer (exponential backoff, each attempt resumes where the last died).
- **Delta updates** — a changed file is re-sent chunk-by-chunk: the receiver claims which chunks it has (untrusted — the sender re-verifies every claim against its own bytes), and only differing chunks travel. Every adopted file is full-hash verified before commit.
- **Compression** — per-chunk zstd (default) / lz4 / none, with automatic raw fallback for incompressible data.
- **Auth & encryption (direct mode)** — `--token` (HMAC proof, constant-time compare), `--pass` (X25519 + ChaCha20-Poly1305 record layer — everything including the handshake is ciphertext), `--cloak PATH` (the whole session rides a WebSocket upgrade on an HTTP-looking path; plain GETs get a decoy page). Without any of these, direct mode is plaintext — use on trusted networks.
- **Relay mode** — for machines behind NAT: both peers connect out to a broker, pair on a 125-bit code, and transfer end-to-end encrypted; the relay shuffles ciphertext only. The broker can buffer up to `--spool-max` (default 2GiB, memory-first then disk) so a fast sender can run ahead of a slow receiver.
- **Swarm mode** — token-joined, chunk-level distribution for immutable artifacts (LLM weights, datasets): `swarm seed` hashes the tree into a spec (`.swarm.json`, per-file SHA-256 + a v2 per-chunk SHA catalog, optionally ed25519-signed), serves chunks and announces to a tracker; `swarm join` assembles from *any* peer — seed, other joiners (verified data only is re-served), or `--http` static hosting via Range requests — rarest-first, resumable. Every fetched chunk is verified against the catalog as it lands; a peer that serves bytes failing it is banned for the session. The token derives the tracker room and keys every peer link.
- **Filters & pacing** — `--exclude`/`--include` globs (bare names match any component, `**` recurses), `--limit 100M` bandwidth cap, `--dry-run` plan without sending, `--delete` mirror mode (destination entries missing from the manifest are removed, jail-scoped).
- **Named endpoints & sync** — `~/.botjim/config.json` stores endpoints (`{"lab1": {"addr": "10.0.0.5:4761", "token": "…"}}`) and per-target autosync policy (include/exclude/delete/dest); `botjim sync push lab1` / `sync pull lab1` mirror with that policy. Plain `send lab1` resolves the name too. `sync push --watch` keeps mirroring as the source changes (debounced; each re-push is a delta).
- **Mesh config propagation** — edit the endpoint list on one node, every node converges: `botjim config publish` wraps the endpoints in an ed25519-signed, versioned envelope (`.botjim-mesh.json`); a receiving server with the mesh key pinned validates the signature and a strictly increasing version, then merges it into its own config automatically. No new protocol — the envelope rides an ordinary sync push.
- **Pipe mode** — `tar c x | botjim pipe send --stdin x.tgz HOST` and `botjim pipe cat HOST PATH > file`: the familiar pipes, but engine-backed (spooled, verified, resumable).
- **Audit & receipts** — `--audit` appends every transfer to a tamper-evident hash-chained journal (`botjim audit verify|tail`); `--receipt` writes a JSON receipt with the manifest digest — proof of what moved.
- **TUI** — btop-style server dashboard (braille sparkline throughput, per-connection and per-file rate/ETA, log tail); client progress view (bar, live rate, global and per-file ETA, scrolling transfer log); `?` help everywhere; single-line fallback in pipes.
- **MC-style browser** — run `send` with no paths to pick files midnight-commander-style: space marks (files AND directories — a marked directory sends its subtree), `/` regex-filters with match highlighting, PgUp/PgDn scrolling, `?` help; pull mode browses the server remotely.
- **LAN discovery** — `botjim server --discover` beacons on a multicast group (opt-in); `botjim peers` lists servers on the network with name/address/version/root.
- **HTTP bridge & metrics** — `botjim serve [DIR]`: plain HTTP with Range support, so browsers/curl/HF-style downloaders can consume any local tree; `botjim server --metrics :9090` exposes Prometheus counters (sessions, files, bytes, errors, active).
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
| `botjim server [flags]` | wait for transfers (default port 4761); `--root` is the jail; `--discover` announces on the LAN |
| `botjim send HOST\|NAME [PATH...]` | push; no paths opens the picker; names resolve via config endpoints |
| `botjim pull HOST\|NAME [RPATH...]` | pull into `--dest` |
| `botjim sync push\|pull NAME` | one-shot mirror with the target's autosync policy; `push --watch` keeps mirroring |
| `botjim config publish` | sign endpoints as a mesh envelope for automatic propagation |
| `botjim pipe send --stdin NAME HOST` | stdin → remote file (`tar \| nc` drop-in) |
| `botjim pipe cat HOST PATH` | remote file → stdout |
| `botjim peers` | discover `--discover` servers on the LAN |
| `botjim relay [flags]` | pairing broker (default port 4762) |
| `botjim send --via RELAY PATH...` | push through a relay; prints a one-shot pairing code |
| `botjim recv --via RELAY --code CODE` | receive a relay push into `--dest` |
| `botjim swarm seed\|join\|track\|verify\|keygen` | token-joined swarm distribution |
| `botjim serve [DIR]` | HTTP+Range bridge for any downloader |
| `botjim endpoints` / `botjim config show` | inspect the config |
| `botjim audit verify\|tail FILE` | hash-chain journal reader |
| `botjim update [--check\|--force]` | self-update |
| `botjim completion bash\|zsh\|fish` / `botjim man` | shell completions / man page |
| `botjim version` / `botjim help [cmd]` | |

The server jails everything inside `--root`: pushes land there, pulls read there, and `..`/absolute paths/symlink escapes are refused. A pre-transfer disk-space check refuses files that cannot fit. See [README_KO.md](README_KO.md) for the Korean edition, [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Config

`~/.botjim/config.json` (or `$BOTJIM_CONFIG`) supplies default flag values and named endpoints:

```json
{
  "token": "s3cret",
  "compress": "zstd",
  "endpoints": {
    "lab1": {"addr": "10.0.0.5:4761", "token": "lab-token"}
  },
  "autosync": {
    "lab1": {"exclude": ["*.tmp"], "delete": true, "dest": "~/mirror/lab1"}
  }
}
```

`botjim send lab1 ...` and `botjim sync push lab1` resolve `lab1` automatically; explicit flags always win over the config.

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

## Swarm walkthrough

```
$ botjim swarm keygen                                   # once: ed25519 spec-signing key
$ botjim swarm seed --tracker t.example.com model/      # prints code + swarm id, signs spec
$ botjim swarm track                                    # on some host (or reuse one)
$ botjim swarm join --tracker t.example.com --code CODE \
                     --spec model.swarm.json --dest . --serve
```

Every joiner is also a source once its data is verified, so the swarm ramps as it fills; rarest chunks are fetched first, and `--verify-key` (the signer's public key) refuses a swapped or tampered spec.

## Performance (loopback tmpfs, 16 cores)

| workload | botjim | `tar \| nc` (with extraction) |
|---|---|---|
| 5GiB single file (none, p=8) | **1397 MiB/s** | 1054 MiB/s |
| 5GiB single (zstd-3) | 1159 MiB/s | — |
| 20k × 64KiB small files | 348 MiB/s | 437 MiB/s |
| 1GiB random (zstd, raw fallback) | 1163 MiB/s | 390 MiB/s |
| 1GiB zeros (sparse) | 0.09s (holes are not transmitted) | — |

## Security

Direct mode is plaintext unless you opt in: `--token` (shared-secret proof), `--pass` (record-layer encryption), `--cloak` (traffic shaping as WebSocket). Relay and swarm links are end-to-end encrypted by construction: brokers and trackers see only ciphertext and metadata. A malicious relay can refuse service or observe timing/sizes, nothing more. Audit journals are tamper-evident; receipts carry the manifest digest.

## Development

```
make test        # unit + integration (push/pull × compression × parallel matrix, resume, jail, relay)
make race        # -race
make harnesses   # attribute harness + kill -9 suite + docker container E2E
make bench       # benchmarks vs tar|nc
```

## License

MIT — see [LICENSE](LICENSE)
