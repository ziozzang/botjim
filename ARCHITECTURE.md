# botjim architecture

This document describes how botjim is put together: the wire protocol, the
transfer engines, resume, the relay mode and its threat model, and the
testing regime. The source of truth is the code; this is the map.

```
┌─────────────────────────────  one TCP connection  ─────────────────────────────┐
│                                                                                │
│  [FSY1 handshake] → [e2ee record layer: relay mode only] → yamux multiplexing   │
│                                          │                                     │
│                      ┌───────────────────┴──────────────────┐                  │
│                control stream                        N data streams           │
│        (manifest, HaveBitmaps, FileResults)         (chunk frames)             │
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘
     sender core (walker + scheduler + workers)  ⇄  receiver core (assembler + finalizer)
```

## Layers

| package | responsibility |
|---|---|
| `internal/protocol` | pure codecs: handshake, control frames, manifest entries, chunk frames |
| `internal/transport` | TCP, handshake exchange, yamux session; `CipherFunc` hook, sec-token proof |
| `internal/manifest` | deterministic walker (hardlink grouping, LCA relative paths) |
| `internal/chunking` | the chunk grid ladder + chunk identity hash |
| `internal/engine` | sender (scheduler/workers) and receiver (assembler/finalizer) — direction-agnostic |
| `internal/sidecar` | resume metadata (chunk hashes, have-bitmap) |
| `internal/attrs` | attribute application in the protocol order |
| `internal/relay` | broker, pairing codes, e2ee handshake + record layer, spool, swarm (tracker/spec/joiner/spec signing) |
| `internal/cloak` | WebSocket disguise: sniff, decoy page, upgrade, RFC 6455 framing |
| `internal/audit` | hash-chained transfer journal (tamper-evident) |
| `internal/discover` | LAN presence beacons (UDP multicast, opt-in) |
| `internal/session` | connection lifecycle: who runs which engine; browser RPC; retry wrapper |
| `internal/cli` / `internal/tui` | command surface, config/endpoints/sync policy, terminals |

**Direction-agnostic engines.** `server`/`client` only decide who dials and
who listens. Push: client = sender. Pull: client = receiver. The engines
never know which side of the connection they are on.

## Wire protocol (v1)

Handshake (36 bytes): magic `FSY1`, major/minor, cipher id (0 = plaintext),
feature bits, 16-byte nonce, crc32c. Major mismatch or nonzero cipher id
refuses the session (downgrade guard). After the handshake both sides start
yamux on the same TCP connection (16MiB stream windows, tuned socket
buffers).

Control messages: `InitTransfer → TransferAck → ManifestBatch* →
ManifestEnd`, per-file `HaveBitmap` (what the receiver already has) and
`FileResult` (outcomes), `ChunkRetry`, listing RPC for the browser, and
session lifecycle (`Cancel`/`Abort`/`Done`/`Goodbye`). Manifest batches are
zstd-compressed above 4KiB.

Data streams: each sender worker owns one stream; frames are
`type | fileID | chunkIdx | flags | len | payload`. Chunk identity is
`SHA-256(path ‖ index ‖ data)` computed independently by both sides — a
chunk written at the wrong offset fails verification even if its bytes are
intact. Zero chunks (sparse holes) travel as a flag with no payload; raw
fallback skips compression for incompressible chunks; decompression is
bounded by the expected chunk length from the manifest (bomb-proofing).

## Transfer flow

1. **Walk** the roots into a deterministic manifest (per-directory name
   order; hardlinks detected by (dev,ino), data sent once). Streaming with
   a 2048-file pending credit so million-file trees stay bounded.
2. **Prepare** (receiver): jail checks, create directories/symlinks/nodes,
   open part files, load sidecars, re-hash what's claimed present. The
   bitmap is a hint; on-disk data is the authority.
3. **Schedule** (sender): HaveBitmaps gate which chunks to send; a ready
   queue feeds N workers (no positive acks — yamux provides reliability;
   the receiver only speaks up on failure via `ChunkRetry`).
4. **Finalize** (receiver): when a file's last chunk lands — fsync, apply
   attributes (chown → chmod → xattr → utimes; order matters: chown clears
   setuid), atomic rename, prune leftovers.
5. **Post-pass**: hardlinks, then directory attributes deepest-first.

## Resume invariants

- The chunk grid is a pure function of file size — never changed, so old
  partials stay valid forever.
- A sidecar records per-chunk hashes; on re-run every claimed chunk is
  re-hashed against it. A part without a sidecar is fully re-hashed and
  rebuilt; zero chunks in that path are re-requested (unverifiable without
  the original hash).
- Part files carry an exclusive flock: a live session's partial can never
  be adopted out from under it. Locks are released deterministically at
  session end.
- A completed transfer costs 0 bytes on re-run (size+mtime shortcut).

## Relay mode

For peers that cannot accept inbound connections. Three parties:

- **broker** (`botjim relay`): pairs peers and shuffles bytes. Never holds
  protocol state.
- **sender** (`botjim send --via RELAY`): parks an offer under a code hash.
- **receiver** (`botjim recv --via RELAY --code`): claims the slot; the
  broker pipes the two connections.

**Pairing.** The code is 25 Crockford-base32 characters (125 bits),
generated by the sender. The broker matches on `SHA-256(code)` — it never
sees the code. At this entropy, offline brute-force of the hash is
infeasible, which is why a PAKE is unnecessary (it earns its keep only
when codes are weak human secrets). Codes are one-shot; the first taker
wins; slots expire after `--wait`.

**End-to-end encryption.** After pairing, both peers run an X25519
exchange whose HKDF schedule folds the code in as a PSK, with both sides
verifying confirmation MACs over the transcript (wrong code → clean
failure, no oracle). Everything after — including botjim's own FSY1
handshake — travels in a ChaCha20-Poly1305 record layer with per-direction
derived nonce prefixes and strictly increasing counters (replay/reorder
rejected). This is the reserved `transport.CipherFunc` hook in action —
the same hook direct mode's `--pass` uses (see below).

**Spooling.** Each direction of a paired session runs through a bounded
spool: memory up to `--spool-mem` (default 256MiB), then an unlinked spill
file in `--spool-dir`, never more than `--spool-max` (default 2GiB) held.
A fast sender can run ahead of a slow receiver within the budget; beyond
it the broker applies TCP backpressure. The spool holds only ciphertext.
Drained directions half-close (TCP `CloseWrite`) so EOF propagates without
killing the reverse path.

**Threat model.** A malicious broker can: refuse service, learn IP
addresses, observe timing and approximate sizes, and attempt to replay or
tamper (detected — AEAD). It cannot: read content, decrypt later, forge a
peer, or reuse a code. A code shared over a compromised channel loses
confidentiality to that eavesdropper — share it out-of-band.

## Direct-mode security (v0.3+)

The relay's record layer was generalized into hooks the plain path can
use; direct mode now has three opt-in layers, each independent:

- **`--token`** — after the FSY1 handshake the client proves knowledge of
  the shared secret with an HMAC over a transcript binding both nonces
  and the role; comparison is constant-time. A passive listener without
  the token cannot progress past the proof.
- **`--pass`** — X25519 with an HKDF schedule that stretches the
  passphrase (scrypt) as a PSK; both sides verify confirmation MACs
  before any protocol byte. From then on the session — including the
  token proof — rides the ChaCha20-Poly1305 record layer.
- **`--cloak PATH`** — the TCP stream is shaped as HTTP: a plain GET to
  any other path gets a plausible decoy page; the right path upgrades to
  a WebSocket (101 + `Sec-WebSocket-Accept` verified) and the real
  session travels in RFC 6455 binary frames. The server demuxes on the
  first bytes (FSY1 vs HTTP) on one port, so plain and cloaked clients
  coexist.

## Delta & resume interplay (v0.3+)

A same-size destination file is adopted as a resume part; the receiver's
chunk claims are **untrusted hints** — the sender re-hashes every claimed
chunk against its own bytes before skipping it, and `MsgCommit` makes a
file final only after the receiver has verified the full content hash.
The chunk grid stays a pure function of size, so partials and deltas
from any earlier release remain valid.

## Swarm mode (v0.5+)

Token-joined chunk distribution for immutable artifacts. The seed hashes
the tree into a `SwarmSpec` (per-file SHA-256 + size) and writes the
portable descriptor (`.swarm.json`). The token does double duty: the
tracker room is keyed by `SHA-256(token)` (the tracker never sees the
token), and every peer↔peer link runs the e2ee record layer keyed from
it — a peer without the token cannot even handshake. Joiners fetch
chunks rarest-first from any peer (seed or joiner; joiners only serve
files they have verified), verify per-file hashes, and resume on re-run.
Descriptors can be **ed25519-signed** (`swarm keygen`); joiners pin the
signer with `--verify-key` so a swapped or tampered spec fails closed.

## Audit journal (v0.6+)

`--audit` appends one line per transfer event to a hash chain: each
entry embeds `SHA-256(prev ‖ entry)`. `botjim audit verify` walks the
chain and reports the first break — editing or deleting any line
invalidates everything after it. The journal records endpoints, sizes
and outcomes, never content.

## Config, endpoints, sync (v0.6–v0.8)

`~/.botjim/config.json` carries default flag values (explicit flags
win), **named endpoints** (addr/token/pass/cloak) and per-target
**autosync** policy (include/exclude/delete/dest). `botjim sync push|pull
NAME` is a one-shot mirror driven by that policy through the same engine
(delta, resume, verification, `--delete` mirror semantics — chdir to the
source, send `.`, so the mirror lands at the jail root).

## Receipts & pipe (v0.8)

`--receipt` writes a JSON proof-of-transfer (files, bytes, errors,
`manifest_sha256` — a running SHA-256 over the manifest entries, so the
same tree always yields the same digest). `botjim pipe` is the
`tar | nc` drop-in: stdin is spooled to a temp file and pushed through
the full engine (`pipe send`), or one remote file is pulled and streamed
to stdout (`pipe cat`) — the familiar pipes, but verified.

## LAN discovery (v0.8)

`botjim server --discover` beacons a small JSON datagram (name, port,
root, version) on `239.255.47.61:4762` every 3s; `botjim peers` listens
for a few seconds and lists what it heard. The beacon carries the *port*
only — the listener pairs it with the datagram's source IP, so
multi-homed hosts are announced with the address that is actually
reachable per interface. Discovery is opt-in and unauthenticated by
design: it is a convenience layer, and every real transfer still needs
the engine's token/encryption.

## Testing

- unit: codecs roundtrip + truncation rejection, chunk grid boundaries,
  jail glob, sidecar lifecycle, spool FIFO/backpressure, code entropy
- integration (`internal/session`): push/pull × compression × parallelism
  matrix with content verification; cancel-and-resume; symlink-jail
  regression suite (dir-over-symlink, empty-file truncation, pull-through-
  symlink, hardlink-to-empty)
- relay (`internal/relay`): pairing through a real broker, wrong-code
  refusal, tamper detection, pipe integrity
- swarm: seed/join through a real tracker, joiner serving, spec signing
  (tamper/wrong-key rejection), delta-claim verification
- config/sync: endpoint resolution, policy application, mirror `--delete`
  semantics (stale removal), redirected-run regression (`2>/dev/null`
  must not launch the TUI)
- harnesses: attribute preservation vs a `tar` snapshot, kill -9 resume
  suite (random interruption points × N), docker container E2E
- `-race` across all packages; benchmarks against `tar | nc`

## Versioning

Semver. The wire protocol major (`FSY1` → `FSY2`) changes only
incompatibly; feature bits negotiate everything else. Sidecars and part
files embed the format version.
