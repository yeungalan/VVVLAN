package proto

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/yeungalan/vvvlan/internal/identity"
)

func TestAddrPortRoundTrip(t *testing.T) {
	for _, s := range []string{"1.2.3.4:80", "255.255.255.255:65535", "[2001:db8::1]:443"} {
		ap := netip.MustParseAddrPort(s)
		enc := AppendAddrPort(nil, ap)
		got, rest, err := ConsumeAddrPort(enc)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if len(rest) != 0 || got != ap {
			t.Fatalf("%s: got %v rest=%d", s, got, len(rest))
		}
	}
	if _, _, err := ConsumeAddrPort([]byte{9, 1, 2}); err == nil {
		t.Fatal("accepted bad family")
	}
}

func TestRelayFraming(t *testing.T) {
	var dst identity.NodeID
	copy(dst[:], bytes.Repeat([]byte{7}, 16))
	inner := []byte{TypeTransport, 1, 2, 3}
	framed := EncodeRelaySend(dst, inner)
	if framed[0] != TypeRelaySend {
		t.Fatal("wrong type byte")
	}
	gotDst, gotInner, err := DecodeRelaySend(framed[1:])
	if err != nil || gotDst != dst || !bytes.Equal(gotInner, inner) {
		t.Fatalf("relay send round trip failed: %v", err)
	}
	back := EncodeRelayRecv(dst, inner)
	gotSrc, gotInner2, err := DecodeRelayRecv(back[1:])
	if err != nil || gotSrc != dst || !bytes.Equal(gotInner2, inner) {
		t.Fatalf("relay recv round trip failed: %v", err)
	}
}

func TestRelayBindRoundTrip(t *testing.T) {
	var id identity.NodeID
	copy(id[:], bytes.Repeat([]byte{3}, 16))
	b := RelayBind{NodeID: id, SessionToken: "tok-123"}
	enc := b.Marshal()
	if enc[0] != TypeRelayBind {
		t.Fatal("wrong type byte")
	}
	got, err := UnmarshalRelayBind(enc[1:])
	if err != nil || got.NodeID != id || got.SessionToken != "tok-123" {
		t.Fatalf("bind round trip failed: %+v %v", got, err)
	}
}

func TestWhoAmIRoundTrip(t *testing.T) {
	req := EncodeWhoAmI(0xDEADBEEF)
	if req[0] != TypeWhoAmI || len(req) != 9 {
		t.Fatal("bad whoami encoding")
	}
	ap := netip.MustParseAddrPort("203.0.113.9:4567")
	resp := EncodeWhoAmIResp(42, ap)
	txid, got, err := DecodeWhoAmIResp(resp[1:])
	if err != nil || txid != 42 || got != ap {
		t.Fatalf("whoami resp round trip: %v %v %v", txid, got, err)
	}
}

func TestDiscoRoundTrip(t *testing.T) {
	var id identity.NodeID
	copy(id[:], bytes.Repeat([]byte{5}, 16))
	ping := &DiscoMessage{Kind: DiscoPing, Sender: id, TxID: 99}
	got, err := UnmarshalDisco(ping.Marshal())
	if err != nil || got.Kind != DiscoPing || got.Sender != id || got.TxID != 99 {
		t.Fatalf("ping round trip: %+v %v", got, err)
	}
	pong := &DiscoMessage{Kind: DiscoPong, Sender: id, TxID: 99, Observed: netip.MustParseAddrPort("9.8.7.6:1000")}
	got, err = UnmarshalDisco(pong.Marshal())
	if err != nil || got.Observed != pong.Observed {
		t.Fatalf("pong round trip: %+v %v", got, err)
	}
}
