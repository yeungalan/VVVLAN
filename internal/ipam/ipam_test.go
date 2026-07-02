package ipam

import (
	"net/netip"
	"testing"
)

func TestAllocateReleaseCycle(t *testing.T) {
	p, err := New(netip.MustParsePrefix("10.60.0.0/29")) // hosts .1-.6, .1 reserved
	if err != nil {
		t.Fatal(err)
	}
	var got []netip.Addr
	for {
		a, err := p.Allocate()
		if err == ErrPoolExhausted {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, a)
	}
	want := []string{"10.60.0.2", "10.60.0.3", "10.60.0.4", "10.60.0.5", "10.60.0.6"}
	if len(got) != len(want) {
		t.Fatalf("allocated %d addrs, want %d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("alloc %d = %v, want %v", i, got[i], w)
		}
	}
	// Release one and reallocate: lowest free comes back.
	p.Release(netip.MustParseAddr("10.60.0.3"))
	a, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != "10.60.0.3" {
		t.Fatalf("reallocated %v, want 10.60.0.3", a)
	}
}

func TestMarkUsedRebuild(t *testing.T) {
	p, err := New(netip.MustParsePrefix("10.1.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	p.MarkUsed(netip.MustParseAddr("10.1.0.2"))
	p.MarkUsed(netip.MustParseAddr("10.1.0.3"))
	p.MarkUsed(netip.MustParseAddr("192.168.0.1")) // outside prefix: ignored
	a, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != "10.1.0.4" {
		t.Fatalf("got %v, want 10.1.0.4", a)
	}
}

func TestRejectsBadPrefixes(t *testing.T) {
	if _, err := New(netip.MustParsePrefix("10.0.0.0/31")); err == nil {
		t.Fatal("accepted /31")
	}
	if _, err := New(netip.MustParsePrefix("fd00::/64")); err == nil {
		t.Fatal("accepted IPv6 prefix")
	}
}
