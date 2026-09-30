# edup protocol v5

Protocol v5 replaces v4's password-keyed XOR obfuscation with authenticated
encryption, per-packet replay protection, and session keys established by a
one-round-trip handshake. Client and server must both run v5.

## Goals and threat model

The attacker can observe, drop, delay, reorder, replay, modify and inject
tunnel datagrams, and can send from any address. v5 provides:

- **Confidentiality and integrity:** every packet is ChaCha20-Poly1305
  (RFC 8439). The server verifies the tag before it changes any state.
- **Replay protection:** every session packet carries a unique 48-bit counter.
  The receiver accepts each counter at most once and refuses counters that fell
  behind its window.
- **Fresh sessions:** traffic recorded in an earlier session, before a client
  restart or before a server reload, is never accepted again.
- **Return-path integrity:** only authenticated, never-seen packets that are
  the newest of their session move the learned endpoint. Forged, replayed or
  delayed packets cannot redirect a user's return traffic.
- **User isolation:** each user has an independent key; one user's key cannot
  speak for another user ID.

Out of scope:

- **Forward secrecy.** Session keys derive from the long-term user key. Anyone
  who later learns a password and recorded the traffic can decrypt it,
  handshakes included.
- **Password guessing.** The user key is BLAKE2s of the password, not a slow
  KDF. A captured INIT allows offline guessing, so use generated credentials
  (`edup-client credentials`, 256 bits).
- **Identity hiding and traffic analysis.** The user ID, packet type, key
  phase, counter, sizes and timing are visible.
- **Denial of service.** An on-path attacker can drop traffic. Anyone who knows
  a user ID can make the server verify tags, which costs server CPU.

## Datagram layout

All fields are big-endian unless noted.

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 8 | user ID | signed 64-bit, public routing ID |
| 8 | 1 | type | 0 IPv4 data, 1 KEEPALIVE, 2 IPv6 data, 3 INIT, 4 RESPONSE |
| 9 | 1 | flags | bit 0: key phase; other bits must be zero |
| 10 | 6 | counter | 48-bit packet counter |
| 16 | 16 | tag | Poly1305 tag |
| 32 | … | body | ciphertext (data), empty (KEEPALIVE), or a 16-byte nonce (handshake) |

Bytes 0..16 are the AEAD associated data. Overhead is 50 bytes over IPv4 and
62 bytes over IPv6, after the compact encoding (below) saves 10/18 bytes.
With a 1500-byte outer MTU, the client MTU is 1450 (IPv4) or 1438 (IPv6).

### Data packets and KEEPALIVE

- Key: the session key.
- Nonce (96 bits): the direction as a little-endian 32-bit word (0 client to
  server, 1 server to client), then the counter as a little-endian 64-bit word.
- Construction: RFC 8439 AEAD with the 16-byte header as associated data and
  the compact IP packet as plaintext.

Both sides start counting at 1. Counter 0 of the server direction sealed the
RESPONSE. A KEEPALIVE has an empty body. The server answers each KEEPALIVE
with its own, freshly sealed KEEPALIVE.

The compact body is unchanged from v4. IPv4 keeps the peer address, ID,
flags/option count, TOS, TTL and protocol (10 bytes instead of 20). IPv6 keeps
the peer address, traffic class/flow label, next header and hop limit (22
bytes instead of 40). The local address is omitted in both directions and
transport checksums assume it is zero. The largest body is 1536 bytes.

### Handshake

The long-term user key `K` is BLAKE2s-256 of `"edup v5 user key\0" ‖ password`.

1. **INIT** (client to server): type 3, flags 0, counter 0, body = random
   16-byte client nonce `c`.
   - `K1 = HChaCha20(K, c)`.
   - Tag = ChaCha20-Poly1305 under `K1` with nonce (0, 0), associated data
     `header ‖ c`, and an empty message.
2. **RESPONSE** (server to client): type 4, flags = the key phase of the new
   session, counter 0, body = server nonce `s`.
   - `s` = a random 64-bit salt chosen at every server load, then a per-user
     handshake count (both little-endian).
   - Session key `S = HChaCha20(K1, s)`.
   - Tag under `S` with nonce (1, 0), associated data `header ‖ s`, empty
     message.
3. The client installs `S` and immediately sends a KEEPALIVE with it.

The server keeps two session slots per user, indexed by key phase. An INIT
always fills the inactive slot and marks it pending. A pending session becomes
active when the first packet sealed with it authenticates. The previously
active slot is then retired: its packets are rejected.

Properties:

- **Replayed INIT:** INIT is replayable, but a replay only produces a new
  pending session whose key the attacker cannot derive. The active session,
  the learned endpoint and the replay windows are untouched.
- **Old sessions:** the server nonce is unique per handshake and per load, so a
  session from before a client restart or server reload can never be derived
  again.
- **Mutual proof:** RESPONSE proves the server knows `K` and saw this INIT.
  The first session packet proves the client knows `S`.

The client retransmits INIT every second until it gets a RESPONSE. It starts a
new handshake when a KEEPALIVE stays unanswered for 5 seconds, for example
after a server reload. It keeps sealing with the old session until the new one
is established, and keeps accepting the previous session's packets (by key
phase) so in-flight packets survive a rekey.

### Replay windows

A counter is checked only after its packet authenticated. A window is a ring
of 64-bit slots:

- The high 48 bits of a slot name a block of 16 consecutive counters.
- The low 16 bits mark the counters seen in that block.
- A slot only ever moves to newer blocks.
- The server updates a slot with one compare-and-swap, so concurrent CPUs
  never accept a counter twice.

The server uses 64 slots (about 1024 packets of reordering), the client 256.
The server also tracks the newest counter per session. Only a packet that
raises it may change the learned endpoint. An older-but-new packet is still
delivered, and a KEEPALIVE of that kind is answered at the learned endpoint,
not at its source.

## XDP implementation

The server has no userspace process on the data path, so ChaCha20, HChaCha20
and Poly1305 run inside XDP. `edup_common::crypto` compiles unchanged for BPF
and userspace. It uses only 32-bit add/rotate/xor and 32×32→64-bit
multiplication, with Poly1305 in five 26-bit limbs.

Two kernel limits shaped the program graph:

- **Verifier cost.** A 1500-byte packet needs 24 ChaCha20 blocks.
  `edup_crypt` (one packet), `edup_block` (one 64-byte block) and
  `edup_keystream` are BTF global functions, which the verifier checks once
  instead of along every path.
- **512-byte stack.** The frame of the NAT data path leaves too little room
  for the cryptography, so sealing and opening run in their own tail-called
  programs, and pass state in a per-CPU map entry.

| Slot | Program | Role |
|-----:|---------|------|
| 0/1 | `edup_ipv4` / `edup_ipv6` | parse, user and session lookup; Internet → NAT → seal |
| 2/3 | `edup_handshake_ipv4/ipv6` | INIT → RESPONSE |
| 4 | `edup_open` | decrypt and verify, then continue in 6/7 |
| 5 | `edup_seal` | encrypt, outer UDP checksum, transmit |
| 6/7 | `edup_accept_ipv4/ipv6` | replay check, session confirmation, endpoint, NAT |

The dispatcher `edup` selects slot 0 or 1 by EtherType. New drop counters:
`drop_auth`, `drop_replay`, `drop_no_session`; `handshake` counts RESPONSEs.
