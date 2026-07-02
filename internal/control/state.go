package control

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yeungalan/vvvlan/internal/ipam"
)

// Network is a virtual network managed by the control server.
type Network struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	CIDR          string    `json:"cidr"`
	GatewayNodeID string    `json:"gateway_node_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Node is a registered member of a network.
type Node struct {
	ID           string    `json:"id"` // hex NodeID derived from the public key
	NetworkID    string    `json:"network_id"`
	PublicKey    string    `json:"public_key"` // base64
	Name         string    `json:"name"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	VirtualIP    string    `json:"virtual_ip"`
	SessionToken string    `json:"session_token"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeen     time.Time `json:"last_seen"`
	Endpoints    []string  `json:"endpoints,omitempty"`
}

// Token is a join token for a network.
type Token struct {
	Token     string    `json:"token"`
	NetworkID string    `json:"network_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	Uses      int       `json:"uses"`
}

// state is the persisted control-server state.
type state struct {
	AdminKey string              `json:"admin_key"`
	Networks map[string]*Network `json:"networks"`
	Nodes    map[string]*Node    `json:"nodes"`
	Tokens   map[string]*Token   `json:"tokens"`
}

// Store holds control-server state, persisted as JSON at path.
type Store struct {
	mu    sync.Mutex
	path  string
	st    state
	pools map[string]*ipam.Pool // networkID -> allocator, rebuilt from state
}

// OpenStore loads (or initializes) the store at path. An admin key is
// generated on first run.
func OpenStore(path string) (*Store, error) {
	s := &Store{
		path: path,
		st: state{
			Networks: map[string]*Network{},
			Nodes:    map[string]*Node{},
			Tokens:   map[string]*Token{},
		},
		pools: map[string]*ipam.Pool{},
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &s.st); err != nil {
			return nil, fmt.Errorf("parsing state %s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		// fresh state
	default:
		return nil, err
	}
	if s.st.AdminKey == "" {
		s.st.AdminKey = randomToken(24)
	}
	// Rebuild IPAM pools from persisted assignments.
	for id, nw := range s.st.Networks {
		prefix, err := netip.ParsePrefix(nw.CIDR)
		if err != nil {
			return nil, fmt.Errorf("network %s has bad CIDR %q: %w", id, nw.CIDR, err)
		}
		pool, err := ipam.New(prefix)
		if err != nil {
			return nil, err
		}
		s.pools[id] = pool
	}
	for _, n := range s.st.Nodes {
		if pool, ok := s.pools[n.NetworkID]; ok {
			if addr, err := netip.ParseAddr(n.VirtualIP); err == nil {
				pool.MarkUsed(addr)
			}
		}
	}
	if err := s.save(); err != nil {
		return nil, err
	}
	return s, nil
}

// save persists state; callers must hold s.mu.
func (s *Store) save() error {
	data, err := json.MarshalIndent(&s.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// AdminKey returns the admin API key.
func (s *Store) AdminKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.AdminKey
}

// CreateNetwork creates a network with the given name and CIDR (default
// 100.<rand>.0.0/16 from the CGNAT-style private pool when empty).
func (s *Store) CreateNetwork(name, cidr string) (*Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		return nil, errors.New("network name is required")
	}
	if cidr == "" {
		cidr = fmt.Sprintf("10.%d.%d.0/24", 100+randByte()%100, randByte())
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	pool, err := ipam.New(prefix)
	if err != nil {
		return nil, err
	}
	nw := &Network{
		ID:        randomToken(8),
		Name:      name,
		CIDR:      prefix.Masked().String(),
		CreatedAt: time.Now().UTC(),
	}
	s.st.Networks[nw.ID] = nw
	s.pools[nw.ID] = pool
	return nw, s.save()
}

// DeleteNetwork removes a network, its nodes and tokens.
func (s *Store) DeleteNetwork(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.Networks[id]; !ok {
		return ErrNotFound
	}
	delete(s.st.Networks, id)
	delete(s.pools, id)
	for nid, n := range s.st.Nodes {
		if n.NetworkID == id {
			delete(s.st.Nodes, nid)
		}
	}
	for t, tok := range s.st.Tokens {
		if tok.NetworkID == id {
			delete(s.st.Tokens, t)
		}
	}
	return s.save()
}

// ErrNotFound is returned for lookups of unknown IDs.
var ErrNotFound = errors.New("not found")

// Networks lists all networks.
func (s *Store) Networks() []*Network {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Network, 0, len(s.st.Networks))
	for _, nw := range s.st.Networks {
		cp := *nw
		out = append(out, &cp)
	}
	return out
}

// Network returns a network by ID.
func (s *Store) Network(id string) (*Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nw, ok := s.st.Networks[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *nw
	return &cp, nil
}

// CreateToken mints a join token for a network.
func (s *Store) CreateToken(networkID string, ttl time.Duration, maxUses int) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.Networks[networkID]; !ok {
		return nil, ErrNotFound
	}
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	tok := &Token{
		Token:     randomToken(16),
		NetworkID: networkID,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(ttl),
		MaxUses:   maxUses,
	}
	s.st.Tokens[tok.Token] = tok
	return tok, s.save()
}

// Tokens lists tokens for a network.
func (s *Store) Tokens(networkID string) []*Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Token
	for _, t := range s.st.Tokens {
		if t.NetworkID == networkID {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out
}

// RegisterNode redeems a join token and adds (or re-registers) the node with
// public key pub, assigning a virtual IP. Re-registration with the same key
// keeps the existing IP.
func (s *Store) RegisterNode(token, nodeID, pub, name, hostname, osName string) (*Node, *Network, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.st.Tokens[token]
	if !ok {
		return nil, nil, errors.New("invalid join token")
	}
	if time.Now().After(tok.ExpiresAt) {
		return nil, nil, errors.New("join token expired")
	}
	if tok.MaxUses > 0 && tok.Uses >= tok.MaxUses {
		return nil, nil, errors.New("join token exhausted")
	}
	nw, ok := s.st.Networks[tok.NetworkID]
	if !ok {
		return nil, nil, errors.New("network no longer exists")
	}

	if existing, ok := s.st.Nodes[nodeID]; ok && existing.NetworkID == nw.ID {
		// Same identity rejoining: refresh metadata and session token.
		existing.Name = name
		existing.Hostname = hostname
		existing.OS = osName
		existing.SessionToken = randomToken(24)
		existing.LastSeen = time.Now().UTC()
		cpN, cpW := *existing, *nw
		return &cpN, &cpW, s.save()
	}

	pool := s.pools[nw.ID]
	addr, err := pool.Allocate()
	if err != nil {
		return nil, nil, err
	}
	node := &Node{
		ID:           nodeID,
		NetworkID:    nw.ID,
		PublicKey:    pub,
		Name:         name,
		Hostname:     hostname,
		OS:           osName,
		VirtualIP:    addr.String(),
		SessionToken: randomToken(24),
		CreatedAt:    time.Now().UTC(),
		LastSeen:     time.Now().UTC(),
	}
	s.st.Nodes[node.ID] = node
	tok.Uses++
	cpN, cpW := *node, *nw
	return &cpN, &cpW, s.save()
}

// Node returns a node by ID.
func (s *Store) Node(id string) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *n
	return &cp, nil
}

// DeleteNode removes a node and releases its address.
func (s *Store) DeleteNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[id]
	if !ok {
		return ErrNotFound
	}
	if pool, ok := s.pools[n.NetworkID]; ok {
		if addr, err := netip.ParseAddr(n.VirtualIP); err == nil {
			pool.Release(addr)
		}
	}
	if nw, ok := s.st.Networks[n.NetworkID]; ok && nw.GatewayNodeID == id {
		nw.GatewayNodeID = ""
	}
	delete(s.st.Nodes, id)
	return s.save()
}

// NetworkNodes lists the members of a network.
func (s *Store) NetworkNodes(networkID string) []*Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Node
	for _, n := range s.st.Nodes {
		if n.NetworkID == networkID {
			cp := *n
			out = append(out, &cp)
		}
	}
	return out
}

// ValidateSession reports whether sessionToken is the current token for node
// id. Used by the relay and the WebSocket endpoint.
func (s *Store) ValidateSession(id, sessionToken string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[id]
	return ok && sessionToken != "" && constEq(n.SessionToken, sessionToken)
}

// SetEndpoints stores a node's latest candidate endpoints and bumps LastSeen.
func (s *Store) SetEndpoints(id string, endpoints []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[id]
	if !ok {
		return ErrNotFound
	}
	n.Endpoints = endpoints
	n.LastSeen = time.Now().UTC()
	return s.save()
}

// TouchNode updates a node's LastSeen without persisting to disk (called on
// every WS message; persisted opportunistically by other mutations).
func (s *Store) TouchNode(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.st.Nodes[id]; ok {
		n.LastSeen = time.Now().UTC()
	}
}

// SetGateway designates nodeID (which must be a member, or empty to clear)
// as the network's internet-passthrough gateway.
func (s *Store) SetGateway(networkID, nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	nw, ok := s.st.Networks[networkID]
	if !ok {
		return ErrNotFound
	}
	if nodeID != "" {
		n, ok := s.st.Nodes[nodeID]
		if !ok || n.NetworkID != networkID {
			return errors.New("node is not a member of this network")
		}
	}
	nw.GatewayNodeID = nodeID
	return s.save()
}

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randByte() int {
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0])
}

func constEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
