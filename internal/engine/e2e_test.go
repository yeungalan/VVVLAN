package engine_test

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yeungalan/vvvlan/internal/control"
	"github.com/yeungalan/vvvlan/internal/controlclient"
	"github.com/yeungalan/vvvlan/internal/engine"
	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/relay"
	"github.com/yeungalan/vvvlan/internal/tunio"
)

// testNode is one emulated VVVLAN node: engine + control WebSocket + fake TUN.
type testNode struct {
	name string
	id   *identity.Identity
	dev  *tunio.MemDevice
	eng  *engine.Engine
	vip  netip.Addr
}

// startInfra brings up a control server and relay sharing one store, and
// returns the HTTP base URL and a join token.
func startInfra(t *testing.T) (serverURL, token string) {
	t.Helper()
	log := testLogger(t)

	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	rly, err := relay.New("127.0.0.1:0", func(node identity.NodeID, tok string) bool {
		return store.ValidateSession(node.String(), tok)
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	go rly.Serve()
	t.Cleanup(func() { rly.Close() })

	ctrl := control.New(control.Config{
		Store:     store,
		Log:       log,
		RelayAddr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(rly.LocalPort())).String(),
	})
	ts := httptest.NewServer(ctrl.Handler())
	t.Cleanup(ts.Close)

	nw, err := store.CreateNetwork("testnet", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := store.CreateToken(nw.ID, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ts.URL, tok.Token
}

func testLogger(t *testing.T) *slog.Logger {
	level := slog.LevelWarn
	if os.Getenv("VVVLAN_TEST_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// buildIPv4 builds a minimal IPv4 packet with an opaque payload.
func buildIPv4(src, dst netip.Addr, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // v4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64   // TTL
	pkt[9] = 0xFD // experimental protocol number
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	copy(pkt[20:], payload)
	return pkt
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverURL, token := startInfra(t)

	nodes := make([]*testNode, 2)
	for i, name := range []string{"alpha", "beta"} {
		n := &testNode{name: name}
		var err error
		n.id, err = identity.New()
		if err != nil {
			t.Fatal(err)
		}
		resp, err := controlclient.Register(ctx, serverURL, token, name, name+"-host", "test", n.id)
		if err != nil {
			t.Fatal(err)
		}
		n.vip = netip.MustParseAddr(resp.VirtualIP)
		n.dev = tunio.NewMemDevice()

		log := testLogger(t).With("node", name)
		var ws *controlclient.WS
		eng, err := engine.New(engine.Config{
			Identity:     n.id,
			Device:       n.dev,
			SessionToken: resp.SessionToken,
			Log:          log,
			AskPunch:     func(target string) { ws.AskPunch(target) },
			ReportEndpoints: func(eps []string) {
				ws.SendEndpoints(eps)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		n.eng = eng
		ws = controlclient.NewWS(serverURL, resp.NodeID, resp.SessionToken, controlclient.Callbacks{
			OnNetMap: eng.UpdateNetMap,
			OnPunch:  eng.HandlePunch,
		}, log)
		go ws.Run(ctx)
		go eng.Run(ctx)
		nodes[i] = n
	}
	alpha, beta := nodes[0], nodes[1]

	// Wait until both nodes are bound to the relay and see each other.
	waitFor(t, 15*time.Second, "nodes ready", func() bool {
		sa, sb := alpha.eng.Snapshot(), beta.eng.Snapshot()
		return sa.RelayBound && sb.RelayBound && len(sa.Peers) == 1 && len(sb.Peers) == 1
	})

	// alpha -> beta through the overlay (initially via the relay, since no
	// direct path is established yet).
	sent := buildIPv4(alpha.vip, beta.vip, []byte("ping-payload-1"))
	alpha.dev.In <- sent
	expectPacket(t, beta.dev, sent, 15*time.Second)

	// beta -> alpha reply.
	reply := buildIPv4(beta.vip, alpha.vip, []byte("pong-payload-1"))
	beta.dev.In <- reply
	expectPacket(t, alpha.dev, reply, 15*time.Second)

	// Both engines should upgrade to a direct P2P path (both are on
	// localhost, so hole punching trivially succeeds).
	waitFor(t, 30*time.Second, "direct path", func() bool {
		sa, sb := alpha.eng.Snapshot(), beta.eng.Snapshot()
		return len(sa.Peers) == 1 && sa.Peers[0].Direct &&
			len(sb.Peers) == 1 && sb.Peers[0].Direct
	})

	// Traffic still flows after the upgrade.
	sent2 := buildIPv4(alpha.vip, beta.vip, []byte("ping-payload-2"))
	alpha.dev.In <- sent2
	expectPacket(t, beta.dev, sent2, 10*time.Second)
}

func TestSpoofedSourceIsDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverURL, token := startInfra(t)
	nodes := make([]*testNode, 2)
	for i, name := range []string{"mallory", "victim"} {
		n := &testNode{name: name}
		var err error
		n.id, err = identity.New()
		if err != nil {
			t.Fatal(err)
		}
		resp, err := controlclient.Register(ctx, serverURL, token, name, name+"-host", "test", n.id)
		if err != nil {
			t.Fatal(err)
		}
		n.vip = netip.MustParseAddr(resp.VirtualIP)
		n.dev = tunio.NewMemDevice()
		log := testLogger(t).With("node", name)
		var ws *controlclient.WS
		eng, err := engine.New(engine.Config{
			Identity:        n.id,
			Device:          n.dev,
			SessionToken:    resp.SessionToken,
			Log:             log,
			AskPunch:        func(target string) { ws.AskPunch(target) },
			ReportEndpoints: func(eps []string) { ws.SendEndpoints(eps) },
		})
		if err != nil {
			t.Fatal(err)
		}
		n.eng = eng
		ws = controlclient.NewWS(serverURL, resp.NodeID, resp.SessionToken, controlclient.Callbacks{
			OnNetMap: eng.UpdateNetMap,
			OnPunch:  eng.HandlePunch,
		}, log)
		go ws.Run(ctx)
		go eng.Run(ctx)
		nodes[i] = n
	}
	mallory, victim := nodes[0], nodes[1]

	waitFor(t, 15*time.Second, "nodes ready", func() bool {
		sa, sb := mallory.eng.Snapshot(), victim.eng.Snapshot()
		return sa.RelayBound && sb.RelayBound && len(sa.Peers) == 1 && len(sb.Peers) == 1
	})

	// A legitimate packet establishes the tunnel.
	legit := buildIPv4(mallory.vip, victim.vip, []byte("legit"))
	mallory.dev.In <- legit
	expectPacket(t, victim.dev, legit, 15*time.Second)

	// A packet with a forged source (someone else's virtual IP) must be
	// dropped by the victim even though the tunnel itself authenticates.
	forged := buildIPv4(netip.MustParseAddr("10.77.0.200"), victim.vip, []byte("forged"))
	mallory.dev.In <- forged
	select {
	case pkt := <-victim.dev.Out:
		if string(pkt[20:]) == "forged" {
			t.Fatal("spoofed packet was delivered")
		}
	case <-time.After(3 * time.Second):
		// expected: nothing delivered
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func expectPacket(t *testing.T, dev *tunio.MemDevice, want []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case got := <-dev.Out:
			if string(got) == string(want) {
				return
			}
			// Ignore unrelated packets (e.g. duplicates from retries).
		case <-deadline:
			t.Fatalf("timed out waiting for packet (%d bytes)", len(want))
		}
	}
}
