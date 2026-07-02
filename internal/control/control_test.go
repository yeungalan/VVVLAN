package control

import (
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestJoinFlowAndIPAM(t *testing.T) {
	s, path := testStore(t)
	nw, err := s.CreateNetwork("home", "10.42.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.CreateToken(nw.ID, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}

	n1, _, err := s.RegisterNode(tok.Token, "aaaa", "pubA", "alpha", "host-a", "linux")
	if err != nil {
		t.Fatal(err)
	}
	n2, _, err := s.RegisterNode(tok.Token, "bbbb", "pubB", "beta", "host-b", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if n1.VirtualIP != "10.42.0.2" || n2.VirtualIP != "10.42.0.3" {
		t.Fatalf("unexpected IPs: %s %s", n1.VirtualIP, n2.VirtualIP)
	}

	// Re-registering the same node keeps its IP but rotates the session.
	n1b, _, err := s.RegisterNode(tok.Token, "aaaa", "pubA", "alpha2", "host-a", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if n1b.VirtualIP != n1.VirtualIP {
		t.Fatalf("re-register changed IP: %s -> %s", n1.VirtualIP, n1b.VirtualIP)
	}
	if n1b.SessionToken == n1.SessionToken {
		t.Fatal("session token was not rotated")
	}
	if !s.ValidateSession("aaaa", n1b.SessionToken) || s.ValidateSession("aaaa", n1.SessionToken) {
		t.Fatal("session validation wrong after rotation")
	}

	// Removing a node releases its IP for the next joiner.
	if err := s.DeleteNode("aaaa"); err != nil {
		t.Fatal(err)
	}
	n3, _, err := s.RegisterNode(tok.Token, "cccc", "pubC", "gamma", "host-c", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if n3.VirtualIP != "10.42.0.2" {
		t.Fatalf("released IP not reused: got %s", n3.VirtualIP)
	}

	// Reload from disk: allocations must survive.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := s2.CreateToken(nw.ID, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	n4, _, err := s2.RegisterNode(tok2.Token, "dddd", "pubD", "delta", "host-d", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if n4.VirtualIP != "10.42.0.4" {
		t.Fatalf("after reload got %s, want 10.42.0.4", n4.VirtualIP)
	}
}

func TestTokenLimits(t *testing.T) {
	s, _ := testStore(t)
	nw, _ := s.CreateNetwork("n", "10.9.0.0/24")

	one, _ := s.CreateToken(nw.ID, time.Hour, 1)
	if _, _, err := s.RegisterNode(one.Token, "a1", "p1", "x", "h", "linux"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RegisterNode(one.Token, "a2", "p2", "y", "h", "linux"); err == nil {
		t.Fatal("exhausted token accepted")
	}

	expired, _ := s.CreateToken(nw.ID, -time.Minute, 0)
	if _, _, err := s.RegisterNode(expired.Token, "a3", "p3", "z", "h", "linux"); err == nil {
		t.Fatal("expired token accepted")
	}

	if _, _, err := s.RegisterNode("no-such-token", "a4", "p4", "w", "h", "linux"); err == nil {
		t.Fatal("bogus token accepted")
	}
}

func TestGatewaySelection(t *testing.T) {
	s, _ := testStore(t)
	nw, _ := s.CreateNetwork("n", "10.8.0.0/24")
	tok, _ := s.CreateToken(nw.ID, time.Hour, 0)
	s.RegisterNode(tok.Token, "g1", "p1", "gw", "h", "linux")

	if err := s.SetGateway(nw.ID, "nope"); err == nil {
		t.Fatal("accepted non-member gateway")
	}
	if err := s.SetGateway(nw.ID, "g1"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Network(nw.ID)
	if got.GatewayNodeID != "g1" {
		t.Fatal("gateway not set")
	}
	// Deleting the gateway node clears the gateway.
	s.DeleteNode("g1")
	got, _ = s.Network(nw.ID)
	if got.GatewayNodeID != "" {
		t.Fatal("gateway not cleared after node removal")
	}
}

func TestDeleteNetworkCascades(t *testing.T) {
	s, _ := testStore(t)
	nw, _ := s.CreateNetwork("n", "10.7.0.0/24")
	tok, _ := s.CreateToken(nw.ID, time.Hour, 0)
	s.RegisterNode(tok.Token, "x1", "p1", "n1", "h", "linux")
	if err := s.DeleteNetwork(nw.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Node("x1"); err != ErrNotFound {
		t.Fatal("node survived network deletion")
	}
	if len(s.Tokens(nw.ID)) != 0 {
		t.Fatal("tokens survived network deletion")
	}
}
