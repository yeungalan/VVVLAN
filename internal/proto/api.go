package proto

import (
	"encoding/json"
	"time"
)

// RegisterRequest is sent by a node to join a network using a join token.
type RegisterRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"` // base64 static Curve25519 key
	Name      string `json:"name"`       // human-friendly node name
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
}

// RegisterResponse confirms membership and carries the node's credentials.
type RegisterResponse struct {
	NodeID       string `json:"node_id"`
	NetworkID    string `json:"network_id"`
	NetworkName  string `json:"network_name"`
	VirtualIP    string `json:"virtual_ip"` // assigned by the control server's IPAM
	CIDR         string `json:"cidr"`
	SessionToken string `json:"session_token"` // authenticates WS + relay binds
	RelayAddr    string `json:"relay_addr"`    // host:port of the relay UDP socket
}

// Peer describes another member of the network as distributed in the netmap.
type Peer struct {
	NodeID    string   `json:"node_id"`
	PublicKey string   `json:"public_key"`
	Name      string   `json:"name"`
	VirtualIP string   `json:"virtual_ip"`
	Endpoints []string `json:"endpoints"` // candidate ip:port endpoints for P2P
	Online    bool     `json:"online"`
	IsGateway bool     `json:"is_gateway"` // node offers internet passthrough
}

// NetMap is the full network view pushed to a node over the control WebSocket.
type NetMap struct {
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name"`
	CIDR        string `json:"cidr"`
	Self        Peer   `json:"self"`
	Peers       []Peer `json:"peers"`
	RelayAddr   string `json:"relay_addr"`
	// GatewayNodeID is the node providing internet passthrough, if any.
	GatewayNodeID string `json:"gateway_node_id,omitempty"`
}

// WSMessage is the envelope for all control WebSocket messages.
type WSMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// WS message types.
const (
	// Server -> client.
	WSNetMap = "netmap" // Data: NetMap
	WSPunch  = "punch"  // Data: PunchRequest (peer wants to hole punch to you)

	// Client -> server.
	WSEndpoints  = "endpoints"   // Data: EndpointUpdate
	WSPunchAsk   = "punch_ask"   // Data: PunchAsk (please tell peer to punch me)
	WSPathReport = "path_report" // Data: PathReport (telemetry for the UI)
)

// EndpointUpdate is a node reporting its candidate endpoints (local interface
// addresses plus the reflector-observed public endpoint).
type EndpointUpdate struct {
	Endpoints []string `json:"endpoints"`
}

// PunchAsk asks the control server to signal the target node to start
// probing back toward the asker, opening its NAT mapping.
type PunchAsk struct {
	TargetNodeID string `json:"target_node_id"`
}

// PunchRequest tells a node that a peer is trying to establish a direct path
// and it should immediately probe the peer's endpoints.
type PunchRequest struct {
	FromNodeID string   `json:"from_node_id"`
	Endpoints  []string `json:"endpoints"`
}

// PathReport is best-effort telemetry about connectivity to a peer, shown in
// the admin UI.
type PathReport struct {
	PeerNodeID string `json:"peer_node_id"`
	Direct     bool   `json:"direct"`
	Endpoint   string `json:"endpoint,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
}

// ---- Admin API (UI / CLI) types ----

// NetworkInfo summarizes a network for the admin API.
type NetworkInfo struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	CIDR          string    `json:"cidr"`
	GatewayNodeID string    `json:"gateway_node_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	NodeCount     int       `json:"node_count"`
}

// NodeInfo summarizes a member node for the admin API.
type NodeInfo struct {
	NodeID    string       `json:"node_id"`
	Name      string       `json:"name"`
	Hostname  string       `json:"hostname"`
	OS        string       `json:"os"`
	VirtualIP string       `json:"virtual_ip"`
	Online    bool         `json:"online"`
	LastSeen  time.Time    `json:"last_seen"`
	IsGateway bool         `json:"is_gateway"`
	Endpoints []string     `json:"endpoints"`
	Paths     []PathReport `json:"paths,omitempty"` // last reported peer paths
}

// TokenInfo describes a join token.
type TokenInfo struct {
	Token     string    `json:"token"`
	NetworkID string    `json:"network_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"` // 0 = unlimited
	Uses      int       `json:"uses"`
}

// CreateNetworkRequest creates a new virtual network.
type CreateNetworkRequest struct {
	Name string `json:"name"`
	CIDR string `json:"cidr,omitempty"` // default 100.100.0.0/16-style pool if empty
}

// CreateTokenRequest mints a join token for a network.
type CreateTokenRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"` // default 24h
	MaxUses    int `json:"max_uses,omitempty"`    // 0 = unlimited
}

// SetGatewayRequest designates (or clears) the internet-passthrough node.
type SetGatewayRequest struct {
	NodeID string `json:"node_id"` // empty clears the gateway
}
