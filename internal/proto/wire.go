// Package proto defines the VVVLAN wire protocol: the UDP data-plane packet
// framing shared by clients and the relay server, the encrypted discovery
// (path probing) payloads, and the JSON types of the control-plane API.
package proto

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/yeungalan/vvvlan/internal/identity"
)

// Packet type bytes. Every UDP datagram starts with one of these.
const (
	// Data plane, exchanged between peers (directly or via relay).
	TypeInitiation byte = 0x01 // noise handshake initiation
	TypeResponse   byte = 0x02 // noise handshake response
	TypeTransport  byte = 0x03 // encrypted IP packet
	TypeDisco      byte = 0x04 // encrypted path discovery message

	// Relay control, exchanged between a client and the relay server.
	TypeRelayBind    byte = 0x10 // client -> relay: register/keepalive mapping
	TypeRelayBindOK  byte = 0x11 // relay -> client: bind accepted
	TypeRelaySend    byte = 0x12 // client -> relay: forward inner packet to dst
	TypeRelayRecv    byte = 0x13 // relay -> client: inner packet from src
	TypeRelayBindErr byte = 0x14 // relay -> client: bind rejected

	// Endpoint reflection (STUN-lite), served by the relay socket.
	TypeWhoAmI     byte = 0x20 // client -> relay: what is my public endpoint?
	TypeWhoAmIResp byte = 0x21 // relay -> client: observed address
)

const nodeIDSize = 16

var ErrMalformed = errors.New("proto: malformed packet")

// AppendAddrPort encodes an address as [family byte][ip][port u16].
func AppendAddrPort(dst []byte, ap netip.AddrPort) []byte {
	addr := ap.Addr().Unmap()
	if addr.Is4() {
		dst = append(dst, 4)
		b := addr.As4()
		dst = append(dst, b[:]...)
	} else {
		dst = append(dst, 6)
		b := addr.As16()
		dst = append(dst, b[:]...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], ap.Port())
	return append(dst, p[:]...)
}

// ConsumeAddrPort decodes an address encoded by AppendAddrPort and returns
// the remainder of the buffer.
func ConsumeAddrPort(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, nil, ErrMalformed
	}
	var ipLen int
	switch b[0] {
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return netip.AddrPort{}, nil, ErrMalformed
	}
	if len(b) < 1+ipLen+2 {
		return netip.AddrPort{}, nil, ErrMalformed
	}
	addr, ok := netip.AddrFromSlice(b[1 : 1+ipLen])
	if !ok {
		return netip.AddrPort{}, nil, ErrMalformed
	}
	port := binary.BigEndian.Uint16(b[1+ipLen : 1+ipLen+2])
	return netip.AddrPortFrom(addr, port), b[1+ipLen+2:], nil
}

// RelayBind is sent by a client to the relay to establish (and keep alive)
// the mapping from its node ID to its current source address. The session
// token was issued by the control server at registration and is verified by
// the relay.
type RelayBind struct {
	NodeID       identity.NodeID
	SessionToken string
}

func (m *RelayBind) Marshal() []byte {
	out := make([]byte, 0, 1+nodeIDSize+len(m.SessionToken))
	out = append(out, TypeRelayBind)
	out = append(out, m.NodeID[:]...)
	out = append(out, m.SessionToken...)
	return out
}

func UnmarshalRelayBind(b []byte) (*RelayBind, error) {
	// b excludes the type byte.
	if len(b) < nodeIDSize {
		return nil, ErrMalformed
	}
	m := &RelayBind{}
	copy(m.NodeID[:], b[:nodeIDSize])
	m.SessionToken = string(b[nodeIDSize:])
	return m, nil
}

// EncodeRelaySend frames an inner data-plane packet for forwarding to dst:
// [TypeRelaySend][dst node id][inner packet].
func EncodeRelaySend(dst identity.NodeID, inner []byte) []byte {
	out := make([]byte, 0, 1+nodeIDSize+len(inner))
	out = append(out, TypeRelaySend)
	out = append(out, dst[:]...)
	return append(out, inner...)
}

// DecodeRelaySend splits a TypeRelaySend payload (excluding the type byte).
func DecodeRelaySend(b []byte) (dst identity.NodeID, inner []byte, err error) {
	if len(b) < nodeIDSize+1 {
		return dst, nil, ErrMalformed
	}
	copy(dst[:], b[:nodeIDSize])
	return dst, b[nodeIDSize:], nil
}

// EncodeRelayRecv frames an inner packet delivered from src:
// [TypeRelayRecv][src node id][inner packet]. The src ID is stamped by the
// relay from the verified bind, so receivers can trust it.
func EncodeRelayRecv(src identity.NodeID, inner []byte) []byte {
	out := make([]byte, 0, 1+nodeIDSize+len(inner))
	out = append(out, TypeRelayRecv)
	out = append(out, src[:]...)
	return append(out, inner...)
}

// DecodeRelayRecv splits a TypeRelayRecv payload (excluding the type byte).
func DecodeRelayRecv(b []byte) (src identity.NodeID, inner []byte, err error) {
	if len(b) < nodeIDSize+1 {
		return src, nil, ErrMalformed
	}
	copy(src[:], b[:nodeIDSize])
	return src, b[nodeIDSize:], nil
}

// EncodeWhoAmI builds an endpoint reflection request with a transaction ID.
func EncodeWhoAmI(txid uint64) []byte {
	out := make([]byte, 9)
	out[0] = TypeWhoAmI
	binary.BigEndian.PutUint64(out[1:], txid)
	return out
}

// EncodeWhoAmIResp builds the reflection response echoing txid and the
// observed source address of the request.
func EncodeWhoAmIResp(txid uint64, observed netip.AddrPort) []byte {
	out := make([]byte, 9, 9+19)
	out[0] = TypeWhoAmIResp
	binary.BigEndian.PutUint64(out[1:], txid)
	return AppendAddrPort(out, observed)
}

// DecodeWhoAmIResp parses a TypeWhoAmIResp payload (excluding the type byte).
func DecodeWhoAmIResp(b []byte) (txid uint64, observed netip.AddrPort, err error) {
	if len(b) < 8 {
		return 0, netip.AddrPort{}, ErrMalformed
	}
	txid = binary.BigEndian.Uint64(b[:8])
	observed, _, err = ConsumeAddrPort(b[8:])
	return txid, observed, err
}

// Disco message kinds (inside the encrypted TypeDisco payload).
const (
	DiscoPing byte = 1
	DiscoPong byte = 2
)

// DiscoMessage is a path probe. Pings are sent to candidate endpoints of a
// peer; a pong echoes the transaction ID and tells the sender which remote
// address the ping arrived from, proving the path works in both directions.
type DiscoMessage struct {
	Kind   byte
	Sender identity.NodeID
	TxID   uint64
	// Observed is set in pongs: the source address the corresponding ping
	// was received from, as seen by the pong sender.
	Observed netip.AddrPort
}

func (m *DiscoMessage) Marshal() []byte {
	out := make([]byte, 0, 1+nodeIDSize+8+19)
	out = append(out, m.Kind)
	out = append(out, m.Sender[:]...)
	var tx [8]byte
	binary.BigEndian.PutUint64(tx[:], m.TxID)
	out = append(out, tx[:]...)
	if m.Kind == DiscoPong {
		out = AppendAddrPort(out, m.Observed)
	}
	return out
}

func UnmarshalDisco(b []byte) (*DiscoMessage, error) {
	if len(b) < 1+nodeIDSize+8 {
		return nil, ErrMalformed
	}
	m := &DiscoMessage{Kind: b[0]}
	copy(m.Sender[:], b[1:1+nodeIDSize])
	m.TxID = binary.BigEndian.Uint64(b[1+nodeIDSize : 1+nodeIDSize+8])
	if m.Kind == DiscoPong {
		var err error
		m.Observed, _, err = ConsumeAddrPort(b[1+nodeIDSize+8:])
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}
