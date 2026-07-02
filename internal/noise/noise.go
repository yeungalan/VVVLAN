// Package noise implements the VVVLAN tunnel handshake and transport
// encryption. The design follows the Noise IK pattern as used by WireGuard:
// the initiator knows the responder's static Curve25519 key ahead of time
// (distributed by the control server), a 1-RTT handshake authenticates both
// sides and derives ChaCha20-Poly1305 transport keys, and transport packets
// carry a 64-bit counter used as the AEAD nonce with a sliding replay window
// on the receiver.
package noise

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yeungalan/vvvlan/internal/identity"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	construction = "VVVLAN v1 Noise_IK Curve25519 ChaCha20Poly1305 SHA256"

	hashSize  = 32
	keySize   = 32
	tagSize   = 16
	tsSize    = 12
	IndexSize = 4

	// InitiationSize is the wire size of a handshake initiation message
	// (excluding the packet-type byte added by the proto package).
	InitiationSize = IndexSize + keySize + (keySize + tagSize) + (tsSize + tagSize)
	// ResponseSize is the wire size of a handshake response message.
	ResponseSize = IndexSize + IndexSize + keySize + tagSize
	// TransportOverhead is the per-packet overhead of a transport message:
	// receiver index, counter, and AEAD tag.
	TransportOverhead = IndexSize + 8 + tagSize
)

var (
	ErrDecrypt      = errors.New("noise: decryption failed")
	ErrReplay       = errors.New("noise: replayed packet")
	ErrShortMessage = errors.New("noise: message too short")
)

func hashOf(parts ...[]byte) [hashSize]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [hashSize]byte
	h.Sum(out[:0])
	return out
}

func hmacOf(key, data []byte) [hashSize]byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	var out [hashSize]byte
	m.Sum(out[:0])
	return out
}

// kdfN implements the HKDF-based key derivation from the Noise spec.
func kdf1(ck *[hashSize]byte, input []byte) (t0 [hashSize]byte) {
	prk := hmacOf(ck[:], input)
	t0 = hmacOf(prk[:], []byte{0x1})
	return t0
}

func kdf2(ck *[hashSize]byte, input []byte) (t0, t1 [hashSize]byte) {
	prk := hmacOf(ck[:], input)
	t0 = hmacOf(prk[:], []byte{0x1})
	t1 = hmacOf(prk[:], append(t0[:], 0x2))
	return t0, t1
}

func kdf3(ck *[hashSize]byte, input []byte) (t0, t1, t2 [hashSize]byte) {
	prk := hmacOf(ck[:], input)
	t0 = hmacOf(prk[:], []byte{0x1})
	t1 = hmacOf(prk[:], append(t0[:], 0x2))
	t2 = hmacOf(prk[:], append(t1[:], 0x3))
	return t0, t1, t2
}

func mixHash(h *[hashSize]byte, data []byte) {
	*h = hashOf(h[:], data)
}

func aeadSeal(key *[keySize]byte, counter uint64, plaintext, ad []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return aead.Seal(nil, nonce[:], plaintext, ad)
}

func aeadOpen(key *[keySize]byte, counter uint64, ciphertext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	pt, err := aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Timestamp is a 12-byte monotonic-enough timestamp (unix nanoseconds,
// big endian, zero padded) included in initiation messages so responders can
// reject replayed initiations.
type Timestamp [tsSize]byte

func NowTimestamp() Timestamp {
	var ts Timestamp
	binary.BigEndian.PutUint64(ts[:8], uint64(time.Now().UnixNano()))
	return ts
}

// After reports whether ts is strictly newer than other.
func (ts Timestamp) After(other Timestamp) bool {
	for i := 0; i < tsSize; i++ {
		if ts[i] != other[i] {
			return ts[i] > other[i]
		}
	}
	return false
}

// HandshakeState carries the intermediate state between the two handshake
// messages.
type HandshakeState struct {
	ck           [hashSize]byte
	h            [hashSize]byte
	localEphPriv identity.PrivateKey
	localEphPub  identity.PublicKey
	remoteEphPub identity.PublicKey
	remoteStatic identity.PublicKey
	localStatic  *identity.Identity
	localIndex   uint32
	remoteIndex  uint32
	initiator    bool
}

// Initiation is a parsed handshake initiation message.
type Initiation struct {
	SenderIndex  uint32
	Ephemeral    identity.PublicKey
	EncStatic    [keySize + tagSize]byte
	EncTimestamp [tsSize + tagSize]byte
}

// Response is a parsed handshake response message.
type Response struct {
	SenderIndex   uint32
	ReceiverIndex uint32
	Ephemeral     identity.PublicKey
	EncEmpty      [tagSize]byte
}

func (m *Initiation) Marshal() []byte {
	out := make([]byte, InitiationSize)
	binary.BigEndian.PutUint32(out[0:4], m.SenderIndex)
	copy(out[4:36], m.Ephemeral[:])
	copy(out[36:36+keySize+tagSize], m.EncStatic[:])
	copy(out[36+keySize+tagSize:], m.EncTimestamp[:])
	return out
}

func UnmarshalInitiation(b []byte) (*Initiation, error) {
	if len(b) != InitiationSize {
		return nil, ErrShortMessage
	}
	m := &Initiation{}
	m.SenderIndex = binary.BigEndian.Uint32(b[0:4])
	copy(m.Ephemeral[:], b[4:36])
	copy(m.EncStatic[:], b[36:36+keySize+tagSize])
	copy(m.EncTimestamp[:], b[36+keySize+tagSize:])
	return m, nil
}

func (m *Response) Marshal() []byte {
	out := make([]byte, ResponseSize)
	binary.BigEndian.PutUint32(out[0:4], m.SenderIndex)
	binary.BigEndian.PutUint32(out[4:8], m.ReceiverIndex)
	copy(out[8:40], m.Ephemeral[:])
	copy(out[40:], m.EncEmpty[:])
	return out
}

func UnmarshalResponse(b []byte) (*Response, error) {
	if len(b) != ResponseSize {
		return nil, ErrShortMessage
	}
	m := &Response{}
	m.SenderIndex = binary.BigEndian.Uint32(b[0:4])
	m.ReceiverIndex = binary.BigEndian.Uint32(b[4:8])
	copy(m.Ephemeral[:], b[8:40])
	copy(m.EncEmpty[:], b[40:])
	return m, nil
}

func newEphemeral() (identity.PrivateKey, identity.PublicKey, error) {
	priv, err := identity.NewPrivateKey()
	if err != nil {
		return identity.PrivateKey{}, identity.PublicKey{}, err
	}
	return priv, priv.Public(), nil
}

func dh(priv identity.PrivateKey, pub identity.PublicKey) ([]byte, error) {
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return nil, fmt.Errorf("noise: bad DH: %w", err)
	}
	// Reject all-zero shared secrets (low order points).
	var zero [32]byte
	if subtle.ConstantTimeCompare(shared, zero[:]) == 1 {
		return nil, errors.New("noise: zero shared secret")
	}
	return shared, nil
}

// NewInitiation builds a handshake initiation for the given peer.
// localIndex is the session index the caller allocated for this handshake.
func NewInitiation(local *identity.Identity, remoteStatic identity.PublicKey, localIndex uint32) (*Initiation, *HandshakeState, error) {
	hs := &HandshakeState{
		localStatic:  local,
		remoteStatic: remoteStatic,
		localIndex:   localIndex,
		initiator:    true,
	}
	hs.ck = hashOf([]byte(construction))
	hs.h = hashOf(hs.ck[:], remoteStatic[:])

	var err error
	hs.localEphPriv, hs.localEphPub, err = newEphemeral()
	if err != nil {
		return nil, nil, err
	}

	msg := &Initiation{SenderIndex: localIndex, Ephemeral: hs.localEphPub}
	hs.ck = kdf1(&hs.ck, hs.localEphPub[:])
	mixHash(&hs.h, hs.localEphPub[:])

	es, err := dh(hs.localEphPriv, remoteStatic)
	if err != nil {
		return nil, nil, err
	}
	var k [keySize]byte
	hs.ck, k = kdf2(&hs.ck, es)
	encStatic := aeadSeal(&k, 0, local.PublicKey[:], hs.h[:])
	copy(msg.EncStatic[:], encStatic)
	mixHash(&hs.h, encStatic)

	ss, err := dh(local.PrivateKey, remoteStatic)
	if err != nil {
		return nil, nil, err
	}
	hs.ck, k = kdf2(&hs.ck, ss)
	ts := NowTimestamp()
	encTs := aeadSeal(&k, 0, ts[:], hs.h[:])
	copy(msg.EncTimestamp[:], encTs)
	mixHash(&hs.h, encTs)

	return msg, hs, nil
}

// ConsumeInitiation processes a received initiation. It returns the
// initiator's static public key, the timestamp from the message (for replay
// checks against the last accepted timestamp for that key), and the handshake
// state needed to create a response.
func ConsumeInitiation(local *identity.Identity, msg *Initiation) (identity.PublicKey, Timestamp, *HandshakeState, error) {
	hs := &HandshakeState{
		localStatic: local,
		remoteIndex: msg.SenderIndex,
		initiator:   false,
	}
	hs.ck = hashOf([]byte(construction))
	hs.h = hashOf(hs.ck[:], local.PublicKey[:])

	hs.remoteEphPub = msg.Ephemeral
	hs.ck = kdf1(&hs.ck, msg.Ephemeral[:])
	mixHash(&hs.h, msg.Ephemeral[:])

	es, err := dh(local.PrivateKey, msg.Ephemeral)
	if err != nil {
		return identity.PublicKey{}, Timestamp{}, nil, err
	}
	var k [keySize]byte
	hs.ck, k = kdf2(&hs.ck, es)
	staticPlain, err := aeadOpen(&k, 0, msg.EncStatic[:], hs.h[:])
	if err != nil {
		return identity.PublicKey{}, Timestamp{}, nil, err
	}
	copy(hs.remoteStatic[:], staticPlain)
	mixHash(&hs.h, msg.EncStatic[:])

	ss, err := dh(local.PrivateKey, hs.remoteStatic)
	if err != nil {
		return identity.PublicKey{}, Timestamp{}, nil, err
	}
	hs.ck, k = kdf2(&hs.ck, ss)
	tsPlain, err := aeadOpen(&k, 0, msg.EncTimestamp[:], hs.h[:])
	if err != nil {
		return identity.PublicKey{}, Timestamp{}, nil, err
	}
	var ts Timestamp
	copy(ts[:], tsPlain)
	mixHash(&hs.h, msg.EncTimestamp[:])

	return hs.remoteStatic, ts, hs, nil
}

// CreateResponse builds the handshake response and the responder's transport
// session. localIndex is the session index the responder allocated.
func (hs *HandshakeState) CreateResponse(localIndex uint32) (*Response, *Session, error) {
	if hs.initiator {
		return nil, nil, errors.New("noise: CreateResponse called on initiator state")
	}
	hs.localIndex = localIndex

	var err error
	hs.localEphPriv, hs.localEphPub, err = newEphemeral()
	if err != nil {
		return nil, nil, err
	}
	msg := &Response{
		SenderIndex:   localIndex,
		ReceiverIndex: hs.remoteIndex,
		Ephemeral:     hs.localEphPub,
	}
	hs.ck = kdf1(&hs.ck, hs.localEphPub[:])
	mixHash(&hs.h, hs.localEphPub[:])

	ee, err := dh(hs.localEphPriv, hs.remoteEphPub)
	if err != nil {
		return nil, nil, err
	}
	hs.ck = kdf1(&hs.ck, ee)

	se, err := dh(hs.localEphPriv, hs.remoteStatic)
	if err != nil {
		return nil, nil, err
	}
	hs.ck = kdf1(&hs.ck, se)

	var zeroPSK [keySize]byte
	var tau, k [hashSize]byte
	hs.ck, tau, k = kdf3(&hs.ck, zeroPSK[:])
	mixHash(&hs.h, tau[:])

	encEmpty := aeadSeal(&k, 0, nil, hs.h[:])
	copy(msg.EncEmpty[:], encEmpty)
	mixHash(&hs.h, encEmpty)

	sess := hs.deriveSession()
	return msg, sess, nil
}

// ConsumeResponse processes the handshake response on the initiator and
// returns the initiator's transport session.
func (hs *HandshakeState) ConsumeResponse(msg *Response) (*Session, error) {
	if !hs.initiator {
		return nil, errors.New("noise: ConsumeResponse called on responder state")
	}
	if msg.ReceiverIndex != hs.localIndex {
		return nil, errors.New("noise: response for unknown handshake")
	}
	hs.remoteIndex = msg.SenderIndex
	hs.remoteEphPub = msg.Ephemeral

	hs.ck = kdf1(&hs.ck, msg.Ephemeral[:])
	mixHash(&hs.h, msg.Ephemeral[:])

	ee, err := dh(hs.localEphPriv, msg.Ephemeral)
	if err != nil {
		return nil, err
	}
	hs.ck = kdf1(&hs.ck, ee)

	se, err := dh(hs.localStatic.PrivateKey, msg.Ephemeral)
	if err != nil {
		return nil, err
	}
	hs.ck = kdf1(&hs.ck, se)

	var zeroPSK [keySize]byte
	var tau, k [hashSize]byte
	hs.ck, tau, k = kdf3(&hs.ck, zeroPSK[:])
	mixHash(&hs.h, tau[:])

	if _, err := aeadOpen(&k, 0, msg.EncEmpty[:], hs.h[:]); err != nil {
		return nil, err
	}
	mixHash(&hs.h, msg.EncEmpty[:])

	return hs.deriveSession(), nil
}

// RemoteStatic returns the peer's static key once known.
func (hs *HandshakeState) RemoteStatic() identity.PublicKey { return hs.remoteStatic }

func (hs *HandshakeState) deriveSession() *Session {
	sendKey, recvKey := kdf2(&hs.ck, nil)
	if !hs.initiator {
		sendKey, recvKey = recvKey, sendKey
	}
	s := &Session{
		LocalIndex:  hs.localIndex,
		RemoteIndex: hs.remoteIndex,
		Initiator:   hs.initiator,
		Created:     time.Now(),
	}
	copy(s.sendKey[:], sendKey[:])
	copy(s.recvKey[:], recvKey[:])
	return s
}

// replayWindow is a sliding bitmap replay filter for 64 packets behind the
// highest counter seen.
type replayWindow struct {
	highest uint64
	bitmap  uint64
}

func (w *replayWindow) check(counter uint64) error {
	switch {
	case counter > w.highest:
		shift := counter - w.highest
		if shift >= 64 {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = counter
		return nil
	case w.highest-counter >= 64:
		return ErrReplay
	default:
		bit := uint64(1) << (w.highest - counter)
		if w.bitmap&bit != 0 {
			return ErrReplay
		}
		w.bitmap |= bit
		return nil
	}
}

// Session is an established transport session.
type Session struct {
	LocalIndex  uint32
	RemoteIndex uint32
	Initiator   bool
	Created     time.Time

	sendKey [keySize]byte
	recvKey [keySize]byte

	mu      sync.Mutex
	sendCtr uint64
	replay  replayWindow
}

// Seal encrypts payload into a transport message:
// [remoteIndex u32][counter u64][ciphertext+tag].
func (s *Session) Seal(payload []byte) []byte {
	s.mu.Lock()
	s.sendCtr++
	ctr := s.sendCtr
	s.mu.Unlock()

	out := make([]byte, IndexSize+8, IndexSize+8+len(payload)+tagSize)
	binary.BigEndian.PutUint32(out[0:4], s.RemoteIndex)
	binary.BigEndian.PutUint64(out[4:12], ctr)
	ct := aeadSeal(&s.sendKey, ctr, payload, nil)
	return append(out, ct...)
}

// ReceiverIndex extracts the receiver session index from a transport message
// without decrypting it.
func ReceiverIndex(b []byte) (uint32, error) {
	if len(b) < IndexSize {
		return 0, ErrShortMessage
	}
	return binary.BigEndian.Uint32(b[0:4]), nil
}

// Open decrypts a transport message produced by Seal and enforces the replay
// window.
func (s *Session) Open(b []byte) ([]byte, error) {
	if len(b) < TransportOverhead {
		return nil, ErrShortMessage
	}
	ctr := binary.BigEndian.Uint64(b[4:12])
	pt, err := aeadOpen(&s.recvKey, ctr, b[12:], nil)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	err = s.replay.check(ctr)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// Age returns how long ago the session was established.
func (s *Session) Age() time.Duration { return time.Since(s.Created) }

// NewIndex returns a random session index.
func NewIndex() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(b[:])
}

// PairKey derives a stable symmetric key for a pair of nodes from the X25519
// shared secret of their static keys. It is used to authenticate and encrypt
// lightweight discovery (path probing) messages without a full session.
func PairKey(local identity.PrivateKey, remote identity.PublicKey) ([keySize]byte, error) {
	var key [keySize]byte
	shared, err := curve25519.X25519(local[:], remote[:])
	if err != nil {
		return key, err
	}
	sum := hashOf([]byte("VVVLAN disco v1"), shared)
	copy(key[:], sum[:])
	return key, nil
}

// SealDisco encrypts a small discovery payload with the pair key using
// XChaCha20-Poly1305 and a random nonce: [nonce 24][ciphertext+tag].
func SealDisco(key *[keySize]byte, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, payload, nil), nil
}

// OpenDisco decrypts a discovery payload sealed with SealDisco.
func OpenDisco(key *[keySize]byte, b []byte) ([]byte, error) {
	if len(b) < chacha20poly1305.NonceSizeX+tagSize {
		return nil, ErrShortMessage
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, b[:chacha20poly1305.NonceSizeX], b[chacha20poly1305.NonceSizeX:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
