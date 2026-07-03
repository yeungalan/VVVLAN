# VVVLAN

A self-hosted virtual networking system in the spirit of ZeroTier, Tailscale
and Hamachi: it emulates a network interface on each machine and connects the
machines into a private virtual LAN over the internet, with end-to-end
encrypted tunnels, direct peer-to-peer connectivity where possible, and
automatic relay fallback where not.

Everything lives in this monorepo and builds into two static binaries:

| Binary | Role |
|---|---|
| `vvvlan-server` | Control server (auth, membership, IP assignment, coordination) + relay/bridge server + admin web UI, in one process |
| `vvvland` | Node agent: creates the virtual NIC, maintains encrypted peer tunnels, exposes a local CLI |

Supported platforms: **Linux**, **macOS**, and **Windows** (the virtual
interface uses `/dev/net/tun`, `utun`, and [Wintun](https://www.wintun.net)
respectively, via the wireguard-go TUN driver).

## Features

- **Virtual network interface** — a TUN adapter per node; the overlay is a
  plain IPv4 subnet, so anything that speaks IP (SSH, game servers, file
  shares, ping) works unmodified.
- **DHCP-style addressing** — the control server leases each joining node a
  virtual IP out of the network's CIDR automatically; addresses survive
  re-joins and are recycled when nodes are removed.
- **End-to-end encryption** — a Noise-IK handshake (Curve25519 +
  ChaCha20-Poly1305 + HKDF, modeled on WireGuard's construction) between
  every pair of peers. Neither the control server nor the relay can read
  traffic.
- **P2P with NAT traversal** — nodes discover their public endpoints via the
  relay's built-in reflector (STUN-lite) and hole-punch toward each other,
  coordinated by the control server. Paths are probed continuously and
  upgraded/downgraded live.
- **Relay fallback** — when a direct path can't be established (restrictive
  NATs, firewalls), traffic transparently falls back to the bridge/relay
  server, still end-to-end encrypted.
- **Internet passthrough (exit node)** — any node can be designated the
  network's gateway; other nodes can then route *all* their internet traffic
  through the encrypted overlay (`vvvland exit on`).
- **Easy onboarding** — create a network in the web UI, click "Generate join
  token", paste one command on the new machine.
- **Web UI** — create networks, mint join tokens, watch which nodes are
  online, see per-pair connectivity (direct vs relayed, latency), pick the
  gateway node, remove nodes.

## Quick start

### 1. Run the server (one public host)

```sh
go build ./cmd/vvvlan-server
./vvvlan-server --listen :8080 --relay-listen :41641
```

The admin key is printed at startup (and stored in `vvvlan-server.json`).
Open `http://<server>:8080/`, sign in with the admin key, create a network,
and generate a join token. The UDP relay port (default `41641`) must be
reachable by all nodes; put the HTTP side behind TLS (e.g. a reverse proxy)
for production use.

### 2. Join machines

On each machine (the UI shows this exact command with the token filled in):

```sh
vvvland join --server http://<server>:8080 --token <join-token>
sudo vvvland up
```

`vvvland up` creates the virtual interface, so it needs root/admin:
- **Linux**: `sudo` (or `CAP_NET_ADMIN`)
- **macOS**: `sudo`
- **Windows**: an Administrator prompt, with `wintun.dll` next to
  `vvvland.exe` (download from [wintun.net](https://www.wintun.net))

That's it — the machines can now reach each other at their virtual IPs:

```sh
vvvland status
# PEER    VIRTUAL IP   STATE    PATH     DETAIL
# beta    10.99.0.3    online   direct   203.0.113.7:41641 (12ms)
ping 10.99.0.3
```

### 3. Optional: internet passthrough

Pick a gateway node in the web UI ("Set gateway"), then on any other node:

```sh
vvvland exit on    # route all internet traffic via the gateway
vvvland exit off
```

The gateway node NATs overlay traffic to the internet. On Linux this uses
kernel NAT (iptables MASQUERADE). On **Windows and macOS** the gateway uses
**userspace NAT**: gateway traffic is terminated by an in-process TCP/IP
stack (gVisor netstack, the same approach Tailscale uses) and re-dialed as
ordinary sockets, with zero OS configuration — WinNAT and pf are not
touched, so it works on every Windows edition including Home. Userspace
mode forwards TCP and UDP; ICMP ping does not traverse it, so verify
passthrough with a browser or `curl`, not `ping`. Pass `--userspace-nat`
to `vvvland up` to force userspace mode on Linux too.
Clients keep their tunnel/control traffic pinned to the physical route, so
there is no routing loop.

## CLI reference

```
vvvland join --server <url> --token <tok> [--name <name>] [--state <dir>]
vvvland up   [--port <udp>] [--tun <name>] [--exit] [--userspace-nat] [--debug]
vvvland status [--json]
vvvland exit on|off

vvvlan-server --listen :8080 --relay-listen :41641
              [--relay-public-addr host:port] [--state <file>] [--debug]
```

`--relay-public-addr` is needed when the relay is reachable at a different
host than the control server URL (by default clients assume the same host).

## How it works

```
                 ┌───────────────────────────────┐
                 │         vvvlan-server         │
                 │  control (HTTP/WS) │  relay   │
                 │  - auth, netmaps   │  (UDP)   │
                 │  - IPAM, punching  │  - STUN  │
                 └─────────▲──────────┴────▲─────┘
             netmap, punch │               │ encrypted frames
                 (WSS)     │               │ (fallback path)
        ┌──────────────────┴───┐       ┌───┴──────────────────┐
        │      vvvland A       │◄─────►│      vvvland B       │
        │ TUN 10.99.0.2        │  P2P  │ TUN 10.99.0.3        │
        │ noise-IK sessions    │ (UDP) │ noise-IK sessions    │
        └──────────────────────┘       └──────────────────────┘
```

- Each node has a static Curve25519 identity; its node ID is derived from
  the public key, so IDs can't be spoofed.
- Nodes redeem a join token over HTTPS and get a virtual IP + session token,
  then hold a WebSocket to the control server, which pushes **netmaps**
  (peers, keys, virtual IPs, endpoint candidates, gateway designation).
- IP packets from the TUN are looked up by destination virtual IP, encrypted
  to the peer's key, and sent over a single UDP socket — directly if a path
  has been probed alive, otherwise wrapped in a relay frame.
- Path discovery sends encrypted probes to all candidate endpoints of a peer
  while the control server tells the peer to probe back (simultaneous hole
  punch); the first working address pair becomes the direct path, with
  keepalives and automatic fallback to the relay when it dies.
- Receivers enforce source-address anti-spoofing: a peer may only originate
  packets from its own virtual IP (the gateway, which forwards NAT return
  traffic, is the deliberate exception).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the wire protocol and
crypto details.

## Development

```sh
go test ./...                 # unit + in-memory end-to-end tests
go test -race ./...
sudo bash scripts/smoke-netns.sh   # Linux: full-stack test in network
                                   # namespaces: real TUN, direct P2P,
                                   # firewalled relay fallback, and internet
                                   # passthrough (kernel + userspace NAT)
```

Cross-compile:

```sh
GOOS=windows GOARCH=amd64 go build ./cmd/...
GOOS=darwin  GOARCH=arm64 go build ./cmd/...
```

Repository layout:

```
cmd/vvvland          node agent + CLI
cmd/vvvlan-server    control + relay + UI server
internal/identity    node keys and IDs
internal/noise       handshake + transport encryption
internal/proto       wire protocol and API types
internal/ipam        virtual IP allocation
internal/control     control server (state, REST, WebSocket)
internal/controlclient  node-side control client
internal/relay       relay/bridge + endpoint reflector
internal/engine      data plane: routing, sessions, NAT traversal
internal/tunio       cross-platform TUN abstraction
internal/netcfg      per-OS address/route/NAT configuration
internal/usernat     userspace NAT (gVisor netstack) for gateways
internal/ui          embedded admin web UI
```

## Troubleshooting

**Peers can't reach each other and `vvvland status` shows `relay (bound: false)`**

The relay UDP port (default `41641`) is not reachable from the nodes. The
agent also logs `relay server is not responding` after ~30 s. Direct P2P may
still work between machines on the same LAN, but anything that needs the
relay or hole-punch coordination will not. Fix the path to the relay:

- Windows server: allow inbound UDP through the firewall:

  ```
  netsh advfirewall firewall add rule name="vvvlan relay" dir=in action=allow protocol=UDP localport=41641
  ```

- Linux server: `sudo ufw allow 41641/udp` (or the equivalent for your
  firewall).
- Server behind a home router: forward UDP `41641` to the server, and make
  sure nodes join using the router's public address (or run the server on a
  host with a public IP).

**Nodes always show `relay`, never `direct`**

Hole punching works through most NATs, but a local firewall that blocks all
inbound UDP on the *node* prevents probes from landing. Run the agent on a
fixed port and allow it:

```
vvvland up --port 41642
# Windows:
netsh advfirewall firewall add rule name="vvvland" dir=in action=allow protocol=UDP localport=41642
```

**Internet passthrough doesn't work after `vvvland exit on`**

Check the gateway first: `vvvland status` on the gateway shows
`role internet gateway ... (userspace NAT)` plus flow counters
(`nat flows tcp=… udp=… dial_errors=…`). If the flow counters stay at zero
while a client browses, traffic is not reaching the gateway (check the
client's `vvvland status` shows a tunnel to the gateway). If `dial_errors`
climbs, the gateway host itself cannot reach the internet or an outbound
firewall is blocking it — the log names the destinations that failed.
Remember ICMP does not traverse userspace NAT: test with a browser or
`curl`, not `ping`. Windows/macOS gateways always use userspace NAT
(TCP/UDP); Linux gateways use kernel NAT and forward ICMP too.

**A node shows `—` under Connectivity in the UI**

No tunnel to any peer has been established yet (paths appear after the
first traffic or probe exchange). Ping the peer's virtual IP and re-check;
if it stays `—`, check the relay reachability above.

## Security notes

- All peer traffic is end-to-end encrypted with per-pair sessions and replay
  protection; the relay forwards ciphertext only.
- Join tokens expire (24h default) and can be use-limited; session tokens
  rotate on re-join; the admin API requires the admin key.
- The overlay is IPv4-only by design; IPv6 packets never enter the tunnel.
- This is a young project and has not been externally audited — prefer
  running the control server behind TLS and treat it accordingly.
