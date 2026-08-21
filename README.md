# CHIMERA PGC — Protocol Genome Compiler (PoC)

CHIMERA's first step: **instead of imitating any known protocol, deterministically compile a brand-new, structurally valid, executable protocol species from a 256-bit seed.**

The idea comes from [UPGen](https://www.usenix.org/biblio/fake-title-653) (Unidentified Protocol Generation, USENIX Security 2025). UPGen's core insight: rather than disguising traffic as TLS/QUIC — which always leaves imitation artifacts — generate a protocol that *looks like a legitimate encrypted protocol nobody has ever seen*. A censor that blocks it by category also breaks crypto wallets, IoT, games, and countless private enterprise protocols.

This repository is a runnable prototype of that route, grown into a cross-platform monorepo.

**Documentation for developers**:
[Handoff](docs/HANDOFF.md) · [Architecture](docs/ARCHITECTURE.md) · [Protocol](docs/PROTOCOL.md) · [Build](docs/BUILD.md) · [Deploy](docs/DEPLOY.md) · [Roadmap](docs/ROADMAP.md) · [Security](docs/SECURITY.md)

- **Linux server**: `cmd/chimerad` (TUN + generated protocol; `-no-tun` echo mode for self-tests only)
- **Linux CLI client**: `cmd/chimerac` (`-check` probe / TUN VPN + optional default-route takeover)
- **Windows GUI client**: `apps/windows` (Wails + Wintun data plane + default-route takeover)
- **Android client**: `apps/android` (Kotlin VpnService + gomobile AAR)
- **Shared kernel**: `core/` (every platform calls the same Go core), `bind/` (gomobile entry point)
- **Protocol compiler**: `internal/{drbg,genome,compiler}`, transports in `internal/tunnel`
- **Evaluation tooling**: `cmd/chimera-eval`, `scripts/eval-capture.sh`

---

## What exists today

Given `(seed, generation)`, the compiler deterministically produces:

1. **Handshake pattern**: 6 variants (`c_s`, `c_s_c`, `c_s_c_s`, `c_c_s`, `s_c`, `s_c_s`)
2. **Per-message field layouts**:
   - Plaintext field pool: `version / type / nonce / reserved`
   - Length fields: width (u8/u16/u24/u32), endianness, semantics (ciphertext length vs record length), standalone segmentation
   - Encrypted field pool: `key_material / certificate / extra / pad_length`
   - Field order and fixed/prefix encoding are sampled randomly
3. **Padding policy**: `none / uniform / burst`
4. **Cipher suites**: AES-128/192/256-GCM (Go standard library), ChaCha20-Poly1305 via explicit config
5. **Executable codec**:
   - Serializes fields to wire bytes per the genome
   - AEAD encryption, sequence-number replay protection, tamper detection
   - Splits the length field into its own transport segment when `LengthAlone`
   - Streaming `ReadFrame` supporting arbitrary length-field positions and both length semantics
6. **Executable handshake state machine**:
   - PSK derives bootstrap keys
   - Both sides exchange X25519 ephemerals
   - Session keys derive from ECDH + PSK + handshake transcript (forward secrecy)
7. **Automated verification**: 120 random seeds run end-to-end handshakes, full message round trips, tamper rejection, stream framing, and pattern diversity.

```text
seed ──▶ HMAC-DRBG ──▶ protocol genome JSON
                          │
                          ▼
                  Compile(genome, PSK)
                          │
              ┌───────────┴───────────┐
              │ handshake codec table │
              │ X25519 state machine  │
              │ app-record codecs     │
              └───────────┬───────────┘
                          ▼
              a runnable end-to-end protocol
```

### Transport layer

The same compiled datagrams ride over multiple underlays:

- **udp** (default): raw datagrams keep every shaping/jitter property.
- **tcp**: 2-byte big-endian length framing for networks that QoS-throttle UDP.
- **websocket / wss**: same framing over WebSocket binary messages; the upgrade path is derived from seed+generation, everything else gets an ordinary 404 so scanners cannot tell the listener apart from a normal web service. `wss` uses standard TLS ≥ 1.2.
- **http / https**: paired POST upload + GET download legs carrying the same frames.
- TCP listeners apply configurable unauthenticated-first-frame probe defense: `close`, `silent` (default), or `tls` (standard fatal alert for TLS-looking probes), with timeout and concurrency caps.
- **Send-side noise mask**: after every N real writes the session emits one cryptographically random decoy frame (rate-capped). Receivers drop decoys via AEAD failure — no shared state.
- **Port hopping**: the server binds the base port plus HMAC(seed, generation)-derived ports (count 1–16); clients probe the same sequence with a shortened 3s timeout. Works identically for UDP and TCP.
- Per-genome shape ladders (five padding ladders selected by fingerprint), randomized keepalive intervals (75–125%), larger UDP socket buffers, zeroed ToS/DSCP.

---

## Running

```bash
cd /home/joy/chimera
go test ./...
go build ./...
bash scripts/selftest.sh          # no root needed; handshake + address assignment + data-plane echo

# Fixed seed (32 bytes = 64 hex chars)
go run ./cmd/gencompiler \
  -seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# Protocol mutation: same seed, different generation -> completely different protocol
go run ./cmd/gencompiler \
  -seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -gen 1

# Full genome JSON (for deployment or analysis)
go run ./cmd/gencompiler \
  -seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -json /tmp/chimera-genome.json
```

Sample output:

```text
protocol fingerprint: 329f3b93f59e27ab...
est. design entropy : 119.3 bits
handshake pattern   : c_s

  M0_client  plain=nonce(fixed_bytes) reserved[00] length(u24,big,ciphertext)
             enc=extra(prefixed_u8) key_material(x963) pad_length(u16)
             payload=true pad=uniform[18,253] cipher=aes-192-gcm
  ...
-- handshake demo --
handshake OK over generated pattern "c_s"
app record c2s  : "hello chimera, this is an app record" (round trip OK)
app record s2c  : "payload from the other direction" (round trip OK)
```

---

## Key design decisions

| Decision | Why |
|---|---|
| Protocol spec is seed-determined | Client/server never negotiate "what the protocol looks like" online; no negotiation fields = no fingerprint to grab |
| One seed per server, one mutation per generation | Identifying a captured protocol only burns one server's one generation |
| Length-field width derived from worst-case frame size | Avoids invalid genotypes where "the protocol was generated but cannot encode legal messages" |
| Length field may sit at any plaintext position | The first bytes carry no fixed structure, raising classifier cost |
| Nonce = (message index, sequence number) | No nonce reuse when the bootstrap key spans multiple handshake messages |
| Bootstrap PSK + ephemeral X25519 | Handshake is encrypted from the first frame while session keys stay forward-secret |
| Standard library only (crypto) | Auditable cryptography, simple builds |

---

## Current boundaries (important)

This is **not** a complete anti-censorship system for high-risk environments, but the data plane and daemon are hardened for production self-hosted VPN operation:

- Implemented: protocol generation, AES-GCM / ChaCha20-Poly1305, UDP handshake (retransmit / decoys / silent drop), **UDP/TCP/WebSocket/WSS/HTTP(S) multi-transport**, multi-client multiplexing, automatic address assignment, Linux TUN bridging, Linux CLI client (probe + TUN), Windows route takeover, **LAN/private-network split tunneling** (Windows bypass routes + Android public-range whitelist), packet-mode ACK/SKIP, NAT keepalive, session quotas and rate limiting, packet-length shaping, send-side timing jitter, server generation window, per-session fault isolation in chimerad, printable handshake covers (gfw.report FEP Ex2/Ex4), server-first authenticated knock, handshake first-packet replay table, UDP socket buffer/ToS tuning, TCP first-frame probe defense (silent/tls mimicry + concurrency caps), **send-side noise mask**, **port hopping**, roaming session reclamation on the server, configurable tunnel DNS on Linux, restrictive ACL on the Windows config file.
- Not implemented: on-device Android acceptance testing, lane B/C (CDN broadcast / real-application parasitism), full traffic morphing.
- `EstimatedEntropyBits` is the generator's own bookkeeping approximation, not a security proof.

---

## Next steps (suggested order)

1. **On-device testing**: Android `protect(fd)` + VpnService against real networks.
2. **Lane B**: publish ciphertext fragments via CDN/object storage; clients fetch with human-like browsing behavior.
3. **Adversarial evaluation**: `cmd/chimera-eval` scores tcpdump pcaps against gfw.report / Wu 2023 first-packet heuristics plus length/IAT statistics. This is the paper-inferred detector, not proof of evading the live GFW; real claims need observation points inside censored networks.

## Directory layout

```text
cmd/gencompiler/      CLI: generate, summarize, end-to-end demo
cmd/chimerad/         Server daemon (TUN, sessions, routing)
cmd/chimerac/         Linux CLI client (probe, TUN, routes, DNS)
cmd/chimera-eval/     pcap scoring against published heuristics
internal/drbg/        HMAC-DRBG deterministic randomness
internal/genome/      Protocol genome types and generator
internal/compiler/    Codec, handshake state machine, sessions
internal/tunnel/      UDP/TCP/WebSocket/HTTP transports, mux, shaping
core/                 Shared client/server core (transports, port hop, TLS)
bind/                 gomobile API for Android
apps/windows/         Wails GUI client (Go + JS frontend)
apps/android/         Kotlin VpnService client
```

---

## Platform status

| Platform | Directory | Status |
|---|---|---|
| Linux server | `cmd/chimerad` | Done: multi-client UDP handshake multiplexing + TUN bridging; needs root/CAP_NET_ADMIN + NAT script; `-no-tun` is self-test only |
| Linux CLI | `cmd/chimerac` | `-check` probe; TUN + half-default route takeover (best-effort IPv6 `::/1`+`8000::/1`) |
| Windows GUI | `apps/windows` | Wails GUI + Wintun packet pump + default-route takeover |
| Android | `apps/android` | VpnService + gomobile AAR; `protect(fd)` loop prevention |

## Running the Linux server

```bash
# 1. Generate the local key pair
go run ./cmd/chimera-init -dir ./local -server YOUR.PUBLIC.IP:4789

# 2. Build and install
CGO_ENABLED=0 go build -o /usr/local/bin/chimerad ./cmd/chimerad
CGO_ENABLED=0 go build -o /usr/local/bin/chimerac ./cmd/chimerac
install -m 644 deploy/chimerad.service /etc/systemd/system/

# 3. Enable forwarding and NAT (replace eth0 with your egress interface)
sudo ./scripts/setup-nat.sh eth0

# 4. Start
sudo systemctl start chimerad
journalctl -u chimerad -f
```

**Multi-client and auto-assignment**: the server hands each client a unique TUN address from `client_cidr` (e.g. `10.99.0.0/24`; `.1` is reserved for the gateway, assignment starts at `.2`, addresses are reused after release). Right after the handshake the server pushes an encrypted control packet; Android requests the address before creating its TUN. The "local TUN address" field in the clients is the fallback used when the server has no `client_cidr` configured.

## Mobile builds

GitHub Actions uploads:

- `Chimera-linux-amd64` — `ubuntu-latest`: `chimerad` + `chimerac` + `chimera-init`
- `ChimeraClient-windows-amd64` — `windows-latest`: Wails GUI + `wintun.dll`
- `ChimeraClient-android-debug` — `ubuntu-latest`: gomobile AAR + `assembleDebug`

```bash
# Android: generate app/libs/bind.aar (needs ANDROID_HOME + NDK)
./build/build-mobile-core.sh   # or apps/android/build-android-core.sh
```

The `bind` package exposes a minimal gomobile surface (`Start / Stop / Send / Receive`, plus the transport/hop variants); each platform shell is responsible for bridging its system TUN data flow to the Go core.
