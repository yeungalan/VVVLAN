package noise

import (
	"bytes"
	"testing"

	"github.com/yeungalan/vvvlan/internal/identity"
)

func newIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// handshake runs a full IK handshake between two identities, going through
// the wire encoding, and returns both transport sessions.
func handshake(t *testing.T, initiator, responder *identity.Identity) (*Session, *Session) {
	t.Helper()
	initMsg, hs, err := NewInitiation(initiator, responder.PublicKey, NewIndex())
	if err != nil {
		t.Fatal(err)
	}
	parsedInit, err := UnmarshalInitiation(initMsg.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	remoteStatic, _, rhs, err := ConsumeInitiation(responder, parsedInit)
	if err != nil {
		t.Fatal(err)
	}
	if remoteStatic != initiator.PublicKey {
		t.Fatal("responder derived wrong initiator static key")
	}
	respMsg, respSess, err := rhs.CreateResponse(NewIndex())
	if err != nil {
		t.Fatal(err)
	}
	parsedResp, err := UnmarshalResponse(respMsg.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	initSess, err := hs.ConsumeResponse(parsedResp)
	if err != nil {
		t.Fatal(err)
	}
	return initSess, respSess
}

func TestHandshakeAndTransport(t *testing.T) {
	alice, bob := newIdentity(t), newIdentity(t)
	as, bs := handshake(t, alice, bob)

	if as.RemoteIndex != bs.LocalIndex || bs.RemoteIndex != as.LocalIndex {
		t.Fatal("session indices not exchanged correctly")
	}

	// Both directions.
	for i, msg := range [][]byte{[]byte("hello from alice"), {}, bytes.Repeat([]byte{0xAB}, 1400)} {
		sealed := as.Seal(msg)
		got, err := bs.Open(sealed)
		if err != nil {
			t.Fatalf("msg %d: bob open: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("msg %d: round trip mismatch", i)
		}
	}
	sealed := bs.Seal([]byte("hi alice"))
	if _, err := as.Open(sealed); err != nil {
		t.Fatalf("alice open: %v", err)
	}
}

func TestTransportRejectsTamperAndReplay(t *testing.T) {
	alice, bob := newIdentity(t), newIdentity(t)
	as, bs := handshake(t, alice, bob)

	sealed := as.Seal([]byte("payload"))
	if _, err := bs.Open(sealed); err != nil {
		t.Fatal(err)
	}
	// Replay of the exact same packet must fail.
	if _, err := bs.Open(sealed); err != ErrReplay {
		t.Fatalf("replay: got %v, want ErrReplay", err)
	}
	// Tampered ciphertext must fail.
	sealed2 := as.Seal([]byte("payload2"))
	sealed2[len(sealed2)-1] ^= 1
	if _, err := bs.Open(sealed2); err != ErrDecrypt {
		t.Fatalf("tamper: got %v, want ErrDecrypt", err)
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	// In-order.
	for i := uint64(1); i <= 10; i++ {
		if err := w.check(i); err != nil {
			t.Fatalf("counter %d: %v", i, err)
		}
	}
	// Out of order within window is fine once.
	if err := w.check(20); err != nil {
		t.Fatal(err)
	}
	if err := w.check(15); err != nil {
		t.Fatal(err)
	}
	if err := w.check(15); err != ErrReplay {
		t.Fatalf("duplicate 15: got %v", err)
	}
	// Too far behind.
	if err := w.check(100); err != nil {
		t.Fatal(err)
	}
	if err := w.check(20); err != ErrReplay {
		t.Fatalf("stale counter: got %v", err)
	}
}

func TestInitiationRejectsWrongResponder(t *testing.T) {
	alice, bob, carol := newIdentity(t), newIdentity(t), newIdentity(t)
	msg, _, err := NewInitiation(alice, bob.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Carol must not be able to consume an initiation addressed to Bob.
	if _, _, _, err := ConsumeInitiation(carol, msg); err == nil {
		t.Fatal("carol consumed an initiation addressed to bob")
	}
}

func TestSessionKeysDifferPerHandshake(t *testing.T) {
	alice, bob := newIdentity(t), newIdentity(t)
	as1, _ := handshake(t, alice, bob)
	as2, bs2 := handshake(t, alice, bob)
	sealed := as1.Seal([]byte("x"))
	if _, err := bs2.Open(sealed); err == nil {
		t.Fatal("session 2 decrypted traffic from session 1")
	}
	_ = as2
}

func TestTimestampOrdering(t *testing.T) {
	a := NowTimestamp()
	b := NowTimestamp()
	if a.After(a) {
		t.Fatal("timestamp After itself")
	}
	if a.After(b) && b.After(a) {
		t.Fatal("inconsistent ordering")
	}
}

func TestDiscoSealOpen(t *testing.T) {
	alice, bob := newIdentity(t), newIdentity(t)
	ka, err := PairKey(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := PairKey(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ka != kb {
		t.Fatal("pair keys do not match")
	}
	sealed, err := SealDisco(&ka, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenDisco(&kb, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatal("disco round trip mismatch")
	}
	// A third party's pair key must not decrypt it.
	carol := newIdentity(t)
	kc, _ := PairKey(carol.PrivateKey, bob.PublicKey)
	if _, err := OpenDisco(&kc, sealed); err == nil {
		t.Fatal("wrong pair key decrypted disco message")
	}
}
