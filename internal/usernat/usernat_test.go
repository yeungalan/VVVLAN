package usernat

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// newClientStack builds a second, ordinary netstack that plays the role of
// an overlay client (10.99.0.2) whose traffic is piped into the NAT under
// test — the same packets a real peer would send through the tunnel.
func newClientStack(t *testing.T, nat *NAT, fromNAT <-chan []byte) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		// The test "internet" lives on 127.0.0.1, so loopback addresses
		// must be allowed end to end.
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(64, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("client NIC: %v", err)
	}
	addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(net.ParseIP("10.99.0.2").To4()),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("client addr: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// client -> NAT
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			buf := pkt.ToBuffer()
			nat.InjectInbound(buf.Flatten())
			buf.Release()
			pkt.DecRef()
		}
	}()
	// NAT -> client
	go func() {
		for {
			select {
			case pkt, ok := <-fromNAT:
				if !ok {
					return
				}
				pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(pkt),
				})
				ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
				pkb.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
	return s
}

func setup(t *testing.T) *stack.Stack {
	t.Helper()
	fromNAT := make(chan []byte, 64)
	nat, err := newNAT(1280, func(pkt []byte) {
		cp := append([]byte(nil), pkt...)
		select {
		case fromNAT <- cp:
		default:
		}
	}, slog.Default(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nat.Close)
	return newClientStack(t, nat, fromNAT)
}

func TestTCPThroughNAT(t *testing.T) {
	// Real TCP server on the host: the "internet".
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				fmt.Fprintf(c, "echo:%s", buf[:n])
			}(c)
		}
	}()

	client := setup(t)
	serverAddr := ln.Addr().(*net.TCPAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(serverAddr.IP.To4()),
		Port: uint16(serverAddr.Port),
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dialing through NAT: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if string(buf[:n]) != "echo:hello" {
		t.Fatalf("got %q, want %q", buf[:n], "echo:hello")
	}
}

func TestUDPThroughNAT(t *testing.T) {
	// Real UDP echo server on the host.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()

	client := setup(t)
	serverAddr := pc.LocalAddr().(*net.UDPAddr)

	conn, err := gonet.DialUDP(client, nil, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(serverAddr.IP.To4()),
		Port: uint16(serverAddr.Port),
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dialing UDP through NAT: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Fatalf("got %q, want %q", buf[:n], "echo:ping")
	}
}
