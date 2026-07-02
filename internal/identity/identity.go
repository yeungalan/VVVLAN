// Package identity implements node identity: a static Curve25519 keypair
// and the node ID derived from the public key.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of Curve25519 keys in bytes.
const KeySize = 32

// PublicKey is a Curve25519 public key.
type PublicKey [KeySize]byte

// PrivateKey is a Curve25519 private key.
type PrivateKey [KeySize]byte

// NodeID identifies a node. It is the SHA-256 hash of the node's static
// public key truncated to 16 bytes, so possession of the private key proves
// ownership of the ID.
type NodeID [16]byte

func (k PublicKey) String() string  { return base64.StdEncoding.EncodeToString(k[:]) }
func (k PublicKey) IsZero() bool    { return k == PublicKey{} }
func (id NodeID) String() string    { return fmt.Sprintf("%x", id[:]) }
func (id NodeID) IsZero() bool      { return id == NodeID{} }
func (k PrivateKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// ParsePublicKey parses a base64-encoded public key.
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("invalid public key: %w", err)
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("invalid public key length %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// ParsePrivateKey parses a base64-encoded private key.
func ParsePrivateKey(s string) (PrivateKey, error) {
	var k PrivateKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("invalid private key: %w", err)
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("invalid private key length %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// ParseNodeID parses a hex-encoded node ID.
func ParseNodeID(s string) (NodeID, error) {
	var id NodeID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("invalid node id: %w", err)
	}
	if len(b) != len(id) {
		return id, fmt.Errorf("invalid node id length %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}

// NewPrivateKey generates a new clamped Curve25519 private key.
func NewPrivateKey() (PrivateKey, error) {
	var k PrivateKey
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	// Clamp per Curve25519 convention.
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// Public returns the public key for a private key.
func (k PrivateKey) Public() PublicKey {
	var pub PublicKey
	pubBytes, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// Only possible for a low-order point; cannot happen with the
		// standard basepoint.
		panic(err)
	}
	copy(pub[:], pubBytes)
	return pub
}

// SharedSecret computes the X25519 shared secret with a peer public key.
func (k PrivateKey) SharedSecret(peer PublicKey) ([]byte, error) {
	return curve25519.X25519(k[:], peer[:])
}

// ID derives the NodeID for a public key.
func (k PublicKey) ID() NodeID {
	h := sha256.Sum256(k[:])
	var id NodeID
	copy(id[:], h[:16])
	return id
}

// Identity is a node's persistent identity.
type Identity struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
	NodeID     NodeID
}

// New generates a fresh identity.
func New() (*Identity, error) {
	priv, err := NewPrivateKey()
	if err != nil {
		return nil, err
	}
	pub := priv.Public()
	return &Identity{PrivateKey: priv, PublicKey: pub, NodeID: pub.ID()}, nil
}

type identityFile struct {
	PrivateKey string `json:"private_key"`
}

// LoadOrCreate loads the identity stored at path, creating and persisting a
// new one if the file does not exist.
func LoadOrCreate(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var f identityFile
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		priv, err := ParsePrivateKey(f.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		pub := priv.Public()
		return &Identity{PrivateKey: priv, PublicKey: pub, NodeID: pub.ID()}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := New()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	data, err = json.MarshalIndent(identityFile{PrivateKey: id.PrivateKey.String()}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}
