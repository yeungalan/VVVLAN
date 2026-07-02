# VVVLAN architecture

This document describes the protocols and internals. For an overview and
usage, see the [README](../README.md).

## Components

| Package | Responsibility |
|---|---|
| `internal/identity` | Static Curve25519 keypair per node. `NodeID = SHA-256(pubkey)[:16]`, so an ID commits to a key. |
| `internal/noise` | Handshake + transport crypto (below). |
| `internal/proto` | Wire framing for the UDP data plane and JSON types for the control plane. |
| `internal/control` | Control server: networks, join tokens, membership, IPAM, netmap distribution, punch signaling. State is a JSON file. |
| `internal/relay` | Relay/bridge: verified node↔address bindings, opaque frame forwarding, endpoint reflection. |
| `internal/engine` | Node data plane: TUN↔UDP pump, session management, path discovery, exit-node logic. |
| `internal/tunio` | Cross-platform TUN device (wireguard-go driver) + in-memory device for tests. |
| `internal/netcfg` | OS commands for addresses, routes, exit routes, and gateway NAT (Linux/macOS/Windows). |

## Identity and trust

- Every node generates a Curve25519 keypair on first run
  (`identity.json`, 0600).
- The **node ID** is the truncated hash of the public key. The control
  server accepts a registration only with a valid join token and stores the
  key; peers later authenticate each other end-to-end by these keys (from
  the netmap), so the control server is trusted for *membership*
  (who is in the network) but never sees traffic.
- Registration returns a random **session token** used to authenticate the
  control WebSocket and relay bindings. It rotates on every re-join.

## Control plane

HTTP + WebSocket, JSON.

- `POST /api/register` `{token, public_key, name, hostname, os}` →
  `{node_id, virtual_ip, cidr, session_token, relay_addr, ...}`.
  The virtual IP is leased from the network CIDR by the IPAM
  (lowest-free; `.0`, `.1` and broadcast reserved; released on node
  removal; re-registration keeps the address).
- `GET /ws?node_id=&session_token=` — long-lived WebSocket:
  - server → client: `netmap` (full network view: peers with public keys,
    virtual IPs, endpoint candidates, online flags, gateway designation,
    relay address), `punch` (a peer asks you to probe it).
  - client → server: `endpoints` (candidate endpoints), `punch_ask`
    (ask a peer to probe me), `path_report` (telemetry for the UI).
  - Netmaps are re-broadcast to all connected members on any relevant
    change (join/leave/connect/disconnect/endpoints/gateway).
- Admin API (`Authorization: Bearer <admin key>`): networks CRUD, token
  minting (TTL + max uses), node listing/removal, gateway selection. The
  embedded web UI is a static page speaking this API.

## Data plane

One UDP socket per node. Every datagram starts with a type byte:

```
0x01 handshake initiation   0x10 relay bind (node id + session token)
0x02 handshake response     0x11 relay bind OK
0x03 transport packet       0x12 relay send   [dst node id][inner]
0x04 disco probe            0x13 relay recv   [src node id][inner]
                            0x14 relay bind error
                            0x20 who-am-i     0x21 who-am-i response
```

### Handshake and transport (`internal/noise`)

Noise IK, following WireGuard's construction with SHA-256/HKDF and
ChaCha20-Poly1305 (no cookies/mac1/mac2, no PSK):

```
initiation: sender_index ‖ e_i ‖ AEAD(static_i) ‖ AEAD(timestamp)
response:   sender_index ‖ receiver_index ‖ e_r ‖ AEAD(ε)
transport:  receiver_index ‖ counter ‖ AEAD(ip packet)
```

- The initiator must already know the responder's static key (from the
  netmap) — unknown/foreign initiators fail at the first DH.
- The encrypted timestamp defends against replayed initiations: a responder
  remembers the newest timestamp per initiator key and rejects older ones.
- Transport packets use the send counter as the AEAD nonce; receivers keep a
  64-packet sliding replay window per session.
- Random 32-bit session indices map incoming packets to sessions without
  revealing identities on the wire.
- Initiators re-handshake every 10 minutes (new keys); superseded sessions
  are pruned.

### Disco (path discovery)

Small probes encrypted with a **pair key** = `H(X25519(static_a, static_b))`
using XChaCha20-Poly1305 (random nonce), framed as
`0x04 ‖ sender node id ‖ sealed{ping|pong, txid, observed-addr}`.
The cleartext sender ID only selects which pair key to try; authenticity
comes from the AEAD.

Establishing a direct path to peer P:

1. Send disco pings to all of P's candidate endpoints (netmap): LAN
   addresses and P's reflector-observed public endpoint. Endpoints inside
   the overlay CIDR are excluded everywhere — probing them would tunnel the
   tunnel.
2. Simultaneously send `punch_ask` via control; the server tells P to probe
   our endpoints, opening P's NAT mapping outward (simultaneous hole punch).
3. A node that receives a direct ping pongs back (echoing where the ping
   came from) and, if it has no direct path itself, immediately probes back
   to that source address.
4. The first direct pong sets the peer's direct endpoint; all traffic
   switches from the relay to it.
5. Keepalive pings run every 15 s on direct paths; ~35 s of silence drops
   the path back to the relay and restarts discovery. Any authenticated
   transport packet also counts as liveness.

### Relay

The relay keeps `node id → source address` bindings, created only with a
valid session token (checked against the control store — same process) and
refreshed every 25 s. A bound client sends `0x12 ‖ dst ‖ inner`; the relay
looks up both parties and delivers `0x13 ‖ src ‖ inner`, stamping the
*verified* source ID. Inner frames are the same handshake/transport/disco
packets used directly — the relay cannot read or forge them. The same
socket answers `who-am-i` with the observed public `ip:port` (STUN-lite),
which is how nodes learn their public endpoints.

## Routing and anti-spoofing

Outbound (TUN → UDP): destination virtual IP → peer lookup → seal → best
path. Packets to addresses outside the overlay CIDR are forwarded to the
gateway peer when exit mode is on. First packet to a peer queues (≤16) while
the handshake runs.

Inbound (UDP → TUN), after decryption:

- source must equal the sending peer's virtual IP — **except** when the peer
  is the designated gateway (NAT return traffic legitimately carries
  external sources);
- destination must be this node's virtual IP — **except** on the gateway,
  which accepts internet-bound packets and writes them to its TUN for the
  OS to forward/NAT.

## Internet passthrough (exit node)

Gateway side (automatic when the netmap designates this node): enable IP
forwarding and NAT from the overlay CIDR out the default-route interface
(Linux: sysctl + iptables MASQUERADE; Windows: `New-NetNat`; macOS: manual
`pfctl` rule, instructions are printed).

Client side (`vvvland exit on`): install `0.0.0.0/1` + `128.0.0.0/1` routes
onto the TUN (they outrank the physical default route without deleting it),
and pin `/32` host routes via the original physical gateway for the control
server, the relay, and every direct peer endpoint — including ones
discovered later — so tunnel transport never routes into the tunnel.
Everything is rolled back on `exit off` or shutdown.

## Testing

- `internal/noise`, `internal/ipam`, `internal/proto`, `internal/control`:
  unit tests (handshake vectors, replay, tampering, IPAM lifecycle, token
  limits, persistence).
- `internal/engine`: in-process end-to-end tests — a real control server
  (httptest), real relay, two engines on in-memory TUN devices; asserts
  relay delivery, upgrade to direct, continued flow, and that spoofed
  source addresses are dropped.
- `scripts/smoke-netns.sh` (root, Linux): the full stack with real TUN
  devices in network namespaces — direct P2P, relay fallback behind a
  firewall, and internet passthrough through a gateway node.

## Known limitations

- IPv4-only overlay (IPv6 packets are ignored at the TUN).
- The relay is a single instance colocated with the control server; there is
  no relay mesh/geo selection.
- Netmaps are sent as full snapshots, which is fine for small/medium
  networks but not incremental.
- macOS gateway NAT requires one manual pf rule.
- No MFA/SSO on the admin API — front it with TLS and keep the admin key
  secret.
