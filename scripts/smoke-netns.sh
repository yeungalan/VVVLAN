#!/usr/bin/env bash
# Full-stack smoke test on Linux using network namespaces. Requires root.
#
# Topology:
#   host          runs vvvlan-server (control + relay + UI) and acts as the
#                 "internet" (198.51.100.1 on lo) for the passthrough test
#   netns ns1     runs vvvland agent "alpha" (10.200.1.2, veth to host)
#   netns ns2     runs vvvland agent "beta"  (10.200.2.2, veth to host)
#
# Scenarios:
#   1. direct      overlay ping with an expected direct P2P path
#   2. relay-only  direct traffic between the namespaces is firewalled,
#                  so the overlay must fall back to the relay
#   3. passthrough beta becomes the network gateway; alpha routes its
#                  internet traffic through the overlay to reach 198.51.100.1
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"

cd "$(dirname "$0")/.."
WORK=$(mktemp -d)
HTTP_PORT=18080
SERVER_PID="" A1_PID="" A2_PID=""
trap cleanup EXIT

cleanup() {
  set +e
  kill "$SERVER_PID" "$A1_PID" "$A2_PID" 2>/dev/null
  wait 2>/dev/null
  ip netns del ns1 2>/dev/null
  ip netns del ns2 2>/dev/null
  iptables -D FORWARD -s 10.200.1.0/24 -d 10.200.2.0/24 -j DROP 2>/dev/null
  iptables -D FORWARD -s 10.200.2.0/24 -d 10.200.1.0/24 -j DROP 2>/dev/null
  ip addr del 198.51.100.1/32 dev lo 2>/dev/null
  rm -rf "$WORK"
}

fail() {
  echo "FAIL: $1"
  for f in server ns1 ns2; do
    echo "--- $f log ---"; tail -25 "$WORK/$f.log" 2>/dev/null
  done
  exit 1
}

api() {
  local method=$1 path=$2 body=${3:-}
  curl -fsS -X "$method" "http://127.0.0.1:$HTTP_PORT$path" \
    -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
    ${body:+-d "$body"}
}

jsonget() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

start_agents() {
  ip netns exec ns1 "$WORK/bin/vvvland" up --state "$WORK/ns1" --debug >"$WORK/ns1.log" 2>&1 &
  A1_PID=$!
  ip netns exec ns2 "$WORK/bin/vvvland" up --state "$WORK/ns2" --debug >"$WORK/ns2.log" 2>&1 &
  A2_PID=$!
}

stop_agents() {
  kill "$A1_PID" "$A2_PID" 2>/dev/null || true
  wait "$A1_PID" "$A2_PID" 2>/dev/null || true
}

wait_ping() { # ns, target, tries
  for _ in $(seq 1 "${3:-30}"); do
    if ip netns exec "$1" ping -c1 -W1 "$2" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

peer_direct() { # ns -> "True"/"False"
  ip netns exec "$1" "$WORK/bin/vvvland" status --json | jsonget "['peers'][0]['direct']"
}

echo "==> building"
go build -o "$WORK/bin/" ./cmd/...

echo "==> creating namespaces"
for i in 1 2; do
  ip netns add ns$i
  ip link add veth$i type veth peer name eth0 netns ns$i
  ip addr add 10.200.$i.1/24 dev veth$i
  ip link set veth$i up
  ip netns exec ns$i ip addr add 10.200.$i.2/24 dev eth0
  ip netns exec ns$i ip link set eth0 up
  ip netns exec ns$i ip link set lo up
  ip netns exec ns$i ip route add default via 10.200.$i.1
done
sysctl -qw net.ipv4.ip_forward=1
ip addr add 198.51.100.1/32 dev lo   # pretend internet host

echo "==> starting vvvlan-server"
"$WORK/bin/vvvlan-server" --listen ":$HTTP_PORT" --relay-listen ":41641" \
  --state "$WORK/server.json" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
ADMIN_KEY=$(jsonget "['admin_key']" <"$WORK/server.json")

echo "==> creating network + join token"
NET_ID=$(api POST /api/networks '{"name":"smoketest","cidr":"10.99.0.0/24"}' | jsonget "['id']")
TOKEN=$(api POST "/api/networks/$NET_ID/tokens" '{}' | jsonget "['token']")

echo "==> joining nodes"
ip netns exec ns1 "$WORK/bin/vvvland" join --server "http://10.200.1.1:$HTTP_PORT" \
  --token "$TOKEN" --name alpha --state "$WORK/ns1" >/dev/null
ip netns exec ns2 "$WORK/bin/vvvland" join --server "http://10.200.2.1:$HTTP_PORT" \
  --token "$TOKEN" --name beta --state "$WORK/ns2" >/dev/null
VIP1=$(jsonget "['virtual_ip']" <"$WORK/ns1/config.json")
VIP2=$(jsonget "['virtual_ip']" <"$WORK/ns2/config.json")
BETA_ID=$(jsonget "['node_id']" <"$WORK/ns2/config.json")
echo "    alpha=$VIP1 beta=$VIP2"

echo
echo "=== scenario 1: direct P2P ==="
start_agents
wait_ping ns1 "$VIP2" || fail "overlay ping (direct scenario)"
sleep 2
[ "$(peer_direct ns1)" = "True" ] || fail "expected a direct path in scenario 1"
echo "    ping OK, path=direct"
stop_agents

echo
echo "=== scenario 2: relay fallback (P2P firewalled) ==="
iptables -I FORWARD -s 10.200.1.0/24 -d 10.200.2.0/24 -j DROP
iptables -I FORWARD -s 10.200.2.0/24 -d 10.200.1.0/24 -j DROP
start_agents
wait_ping ns1 "$VIP2" || fail "overlay ping (relay scenario)"
sleep 2
[ "$(peer_direct ns1)" = "False" ] || fail "expected relayed path in scenario 2"
# The admin API must show the relayed path too (UI connectivity column).
api GET "/api/networks/$NET_ID/nodes" | python3 -c "
import sys, json
nodes = json.load(sys.stdin)
paths = [p for n in nodes for p in (n.get('paths') or [])]
assert paths, 'no path reports reached the control server'
assert all(not p['direct'] for p in paths), paths
" || fail "relay path not reported to the admin API"
echo "    ping OK, path=relay (reported to UI)"
stop_agents
iptables -D FORWARD -s 10.200.1.0/24 -d 10.200.2.0/24 -j DROP
iptables -D FORWARD -s 10.200.2.0/24 -d 10.200.1.0/24 -j DROP

echo
echo "=== scenario 3: internet passthrough via gateway ==="
api POST "/api/networks/$NET_ID/gateway" "{\"node_id\":\"$BETA_ID\"}" >/dev/null
start_agents
wait_ping ns1 "$VIP2" || fail "overlay ping (passthrough scenario)"
# Enable exit mode on alpha and reach the "internet" through beta.
for _ in $(seq 1 10); do
  if ip netns exec ns1 "$WORK/bin/vvvland" exit on >/dev/null 2>&1; then break; fi
  sleep 1
done
wait_ping ns1 198.51.100.1 15 || fail "internet ping via gateway"
SRC=$(ip netns exec ns1 ip route get 198.51.100.1 | head -1)
echo "    internet reachable via overlay ($SRC)"
ip netns exec ns1 "$WORK/bin/vvvland" exit off >/dev/null
stop_agents

echo
echo "ALL SMOKE SCENARIOS PASSED"
