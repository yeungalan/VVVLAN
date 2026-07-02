// Package control implements the VVVLAN control server: authentication of
// nodes via join tokens, network membership, DHCP-style IP assignment,
// distribution of netmaps over WebSocket, and hole-punch signaling between
// peers. It also serves the admin REST API used by the web UI and CLI.
package control

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/proto"
)

// Config configures the control server.
type Config struct {
	Store *Store
	Log   *slog.Logger
	// RelayAddr is the relay endpoint advertised to nodes, e.g.
	// "vpn.example.com:41641". If it starts with ":" the client substitutes
	// the control server's host.
	RelayAddr string
	// UI, when non-nil, is served at / (the embedded admin web UI).
	UI http.Handler
}

// Server is the control server.
type Server struct {
	cfg Config
	log *slog.Logger

	mu    sync.Mutex
	conns map[string]*wsConn                     // nodeID -> live WebSocket
	paths map[string]map[string]proto.PathReport // nodeID -> peerID -> last report
}

type wsConn struct {
	nodeID    string
	networkID string
	send      chan proto.WSMessage
}

// New creates the control server.
func New(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Server{
		cfg:   cfg,
		log:   cfg.Log,
		conns: map[string]*wsConn{},
		paths: map[string]map[string]proto.PathReport{},
	}
}

// Handler returns the HTTP handler for the control server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Node-facing endpoints.
	mux.HandleFunc("POST /api/register", s.handleRegister)
	mux.HandleFunc("GET /ws", s.handleWS)

	// Admin endpoints (web UI + CLI).
	mux.Handle("GET /api/networks", s.admin(s.handleListNetworks))
	mux.Handle("POST /api/networks", s.admin(s.handleCreateNetwork))
	mux.Handle("DELETE /api/networks/{id}", s.admin(s.handleDeleteNetwork))
	mux.Handle("GET /api/networks/{id}/nodes", s.admin(s.handleListNodes))
	mux.Handle("POST /api/networks/{id}/tokens", s.admin(s.handleCreateToken))
	mux.Handle("GET /api/networks/{id}/tokens", s.admin(s.handleListTokens))
	mux.Handle("POST /api/networks/{id}/gateway", s.admin(s.handleSetGateway))
	mux.Handle("DELETE /api/nodes/{id}", s.admin(s.handleDeleteNode))
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	if s.cfg.UI != nil {
		mux.Handle("/", s.cfg.UI)
	}
	return mux
}

func (s *Server) admin(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		if len(key) > 7 && key[:7] == "Bearer " {
			key = key[7:]
		}
		if !constEq(key, s.cfg.Store.AdminKey()) {
			httpErr(w, http.StatusUnauthorized, "invalid admin key")
			return
		}
		h(w, r)
	})
}

// ---- Node registration ----

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req proto.RegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	pub, err := identity.ParsePublicKey(req.PublicKey)
	if err != nil {
		httpErr(w, http.StatusBadRequest, "bad public key")
		return
	}
	nodeID := pub.ID().String()
	name := req.Name
	if name == "" {
		name = req.Hostname
	}
	node, nw, err := s.cfg.Store.RegisterNode(req.Token, nodeID, req.PublicKey, name, req.Hostname, req.OS)
	if err != nil {
		httpErr(w, http.StatusForbidden, err.Error())
		return
	}
	s.log.Info("node registered", "node", node.ID, "name", node.Name, "network", nw.Name, "ip", node.VirtualIP)
	s.broadcastNetMap(nw.ID)
	writeJSON(w, proto.RegisterResponse{
		NodeID:       node.ID,
		NetworkID:    nw.ID,
		NetworkName:  nw.Name,
		VirtualIP:    node.VirtualIP,
		CIDR:         nw.CIDR,
		SessionToken: node.SessionToken,
		RelayAddr:    s.cfg.RelayAddr,
	})
}

// ---- WebSocket: netmap distribution + signaling ----

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Nodes authenticate with their session token; browser origin checks
	// don't apply to this endpoint.
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	sessionToken := r.URL.Query().Get("session_token")
	if !s.cfg.Store.ValidateSession(nodeID, sessionToken) {
		httpErr(w, http.StatusUnauthorized, "invalid node session")
		return
	}
	node, err := s.cfg.Store.Node(nodeID)
	if err != nil {
		httpErr(w, http.StatusUnauthorized, "unknown node")
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn := &wsConn{
		nodeID:    nodeID,
		networkID: node.NetworkID,
		send:      make(chan proto.WSMessage, 32),
	}

	s.mu.Lock()
	if old, ok := s.conns[nodeID]; ok {
		close(old.send)
	}
	s.conns[nodeID] = conn
	s.mu.Unlock()

	s.log.Info("node connected", "node", nodeID, "name", node.Name)
	s.broadcastNetMap(node.NetworkID)

	// Writer.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ping := time.NewTicker(30 * time.Second)
		defer ping.Stop()
		for {
			select {
			case msg, ok := <-conn.send:
				if !ok {
					ws.WriteControl(websocket.CloseMessage, nil, time.Now().Add(time.Second))
					return
				}
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := ws.WriteJSON(msg); err != nil {
					return
				}
			case <-ping.C:
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	// Reader.
	ws.SetReadLimit(1 << 16)
	ws.SetReadDeadline(time.Now().Add(90 * time.Second))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(90 * time.Second))
		s.cfg.Store.TouchNode(nodeID)
		return nil
	})
	for {
		var msg proto.WSMessage
		if err := ws.ReadJSON(&msg); err != nil {
			break
		}
		ws.SetReadDeadline(time.Now().Add(90 * time.Second))
		s.cfg.Store.TouchNode(nodeID)
		s.handleWSMessage(conn, msg)
	}

	ws.Close()
	<-done
	s.mu.Lock()
	if s.conns[nodeID] == conn {
		delete(s.conns, nodeID)
	}
	s.mu.Unlock()
	s.log.Info("node disconnected", "node", nodeID)
	s.broadcastNetMap(node.NetworkID)
}

func (s *Server) handleWSMessage(conn *wsConn, msg proto.WSMessage) {
	switch msg.Type {
	case proto.WSEndpoints:
		var upd proto.EndpointUpdate
		if err := json.Unmarshal(msg.Data, &upd); err != nil {
			return
		}
		if len(upd.Endpoints) > 16 {
			upd.Endpoints = upd.Endpoints[:16]
		}
		if err := s.cfg.Store.SetEndpoints(conn.nodeID, upd.Endpoints); err == nil {
			s.broadcastNetMap(conn.networkID)
		}

	case proto.WSPunchAsk:
		var ask proto.PunchAsk
		if err := json.Unmarshal(msg.Data, &ask); err != nil {
			return
		}
		target, err := s.cfg.Store.Node(ask.TargetNodeID)
		if err != nil || target.NetworkID != conn.networkID {
			return
		}
		asker, err := s.cfg.Store.Node(conn.nodeID)
		if err != nil {
			return
		}
		req := proto.PunchRequest{FromNodeID: asker.ID, Endpoints: asker.Endpoints}
		data, _ := json.Marshal(req)
		s.sendTo(target.ID, proto.WSMessage{Type: proto.WSPunch, Data: data})

	case proto.WSPathReport:
		var rep proto.PathReport
		if err := json.Unmarshal(msg.Data, &rep); err != nil {
			return
		}
		s.mu.Lock()
		if s.paths[conn.nodeID] == nil {
			s.paths[conn.nodeID] = map[string]proto.PathReport{}
		}
		s.paths[conn.nodeID][rep.PeerNodeID] = rep
		s.mu.Unlock()
	}
}

func (s *Server) sendTo(nodeID string, msg proto.WSMessage) {
	s.mu.Lock()
	conn := s.conns[nodeID]
	s.mu.Unlock()
	if conn == nil {
		return
	}
	select {
	case conn.send <- msg:
	default: // slow consumer; drop rather than block the server
	}
}

// buildNetMap assembles the netmap for one node.
func (s *Server) buildNetMap(nodeID string) (*proto.NetMap, error) {
	node, err := s.cfg.Store.Node(nodeID)
	if err != nil {
		return nil, err
	}
	nw, err := s.cfg.Store.Network(node.NetworkID)
	if err != nil {
		return nil, err
	}
	members := s.cfg.Store.NetworkNodes(nw.ID)
	s.mu.Lock()
	online := make(map[string]bool, len(s.conns))
	for id := range s.conns {
		online[id] = true
	}
	s.mu.Unlock()

	nm := &proto.NetMap{
		NetworkID:     nw.ID,
		NetworkName:   nw.Name,
		CIDR:          nw.CIDR,
		RelayAddr:     s.cfg.RelayAddr,
		GatewayNodeID: nw.GatewayNodeID,
	}
	for _, m := range members {
		p := proto.Peer{
			NodeID:    m.ID,
			PublicKey: m.PublicKey,
			Name:      m.Name,
			VirtualIP: m.VirtualIP,
			Endpoints: m.Endpoints,
			Online:    online[m.ID],
			IsGateway: m.ID == nw.GatewayNodeID,
		}
		if m.ID == nodeID {
			nm.Self = p
		} else {
			nm.Peers = append(nm.Peers, p)
		}
	}
	sort.Slice(nm.Peers, func(i, j int) bool { return nm.Peers[i].NodeID < nm.Peers[j].NodeID })
	return nm, nil
}

// broadcastNetMap pushes fresh netmaps to every connected member of a network.
func (s *Server) broadcastNetMap(networkID string) {
	s.mu.Lock()
	var targets []*wsConn
	for _, c := range s.conns {
		if c.networkID == networkID {
			targets = append(targets, c)
		}
	}
	s.mu.Unlock()
	for _, c := range targets {
		nm, err := s.buildNetMap(c.nodeID)
		if err != nil {
			continue
		}
		data, _ := json.Marshal(nm)
		s.sendTo(c.nodeID, proto.WSMessage{Type: proto.WSNetMap, Data: data})
	}
}

// ValidateSession implements the relay's TokenValidator.
func (s *Server) ValidateSession(node identity.NodeID, sessionToken string) bool {
	return s.cfg.Store.ValidateSession(node.String(), sessionToken)
}

// ---- Admin handlers ----

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	nws := s.cfg.Store.Networks()
	out := make([]proto.NetworkInfo, 0, len(nws))
	for _, nw := range nws {
		out = append(out, proto.NetworkInfo{
			ID:            nw.ID,
			Name:          nw.Name,
			CIDR:          nw.CIDR,
			GatewayNodeID: nw.GatewayNodeID,
			CreatedAt:     nw.CreatedAt,
			NodeCount:     len(s.cfg.Store.NetworkNodes(nw.ID)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, out)
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req proto.CreateNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	nw, err := s.cfg.Store.CreateNetwork(req.Name, req.CIDR)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, proto.NetworkInfo{
		ID: nw.ID, Name: nw.Name, CIDR: nw.CIDR, CreatedAt: nw.CreatedAt,
	})
}

func (s *Server) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Store.DeleteNetwork(r.PathValue("id")); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "deleted"})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	networkID := r.PathValue("id")
	if _, err := s.cfg.Store.Network(networkID); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	nodes := s.cfg.Store.NetworkNodes(networkID)
	s.mu.Lock()
	out := make([]proto.NodeInfo, 0, len(nodes))
	for _, n := range nodes {
		info := proto.NodeInfo{
			NodeID:    n.ID,
			Name:      n.Name,
			Hostname:  n.Hostname,
			OS:        n.OS,
			VirtualIP: n.VirtualIP,
			Online:    s.conns[n.ID] != nil,
			LastSeen:  n.LastSeen,
			Endpoints: n.Endpoints,
		}
		for _, rep := range s.paths[n.ID] {
			info.Paths = append(info.Paths, rep)
		}
		sort.Slice(info.Paths, func(i, j int) bool {
			return info.Paths[i].PeerNodeID < info.Paths[j].PeerNodeID
		})
		out = append(out, info)
	}
	s.mu.Unlock()
	if nw, err := s.cfg.Store.Network(networkID); err == nil {
		for i := range out {
			out[i].IsGateway = out[i].NodeID == nw.GatewayNodeID
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VirtualIP < out[j].VirtualIP })
	writeJSON(w, out)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req proto.CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	tok, err := s.cfg.Store.CreateToken(r.PathValue("id"), time.Duration(req.TTLSeconds)*time.Second, req.MaxUses)
	if err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	writeJSON(w, tokenInfo(tok))
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if _, err := s.cfg.Store.Network(r.PathValue("id")); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	toks := s.cfg.Store.Tokens(r.PathValue("id"))
	out := make([]proto.TokenInfo, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenInfo(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeJSON(w, out)
}

func (s *Server) handleSetGateway(w http.ResponseWriter, r *http.Request) {
	var req proto.SetGatewayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	networkID := r.PathValue("id")
	if err := s.cfg.Store.SetGateway(networkID, req.NodeID); err != nil {
		if errors.Is(err, ErrNotFound) {
			httpErr(w, http.StatusNotFound, "not found")
		} else {
			httpErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	s.broadcastNetMap(networkID)
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := s.cfg.Store.Node(id)
	if err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	if err := s.cfg.Store.DeleteNode(id); err != nil {
		httpNotFoundOr500(w, err)
		return
	}
	s.mu.Lock()
	if c, ok := s.conns[id]; ok {
		close(c.send)
		delete(s.conns, id)
	}
	delete(s.paths, id)
	s.mu.Unlock()
	s.broadcastNetMap(node.NetworkID)
	writeJSON(w, map[string]string{"status": "deleted"})
}

func tokenInfo(t *Token) proto.TokenInfo {
	return proto.TokenInfo{
		Token:     t.Token,
		NetworkID: t.NetworkID,
		CreatedAt: t.CreatedAt,
		ExpiresAt: t.ExpiresAt,
		MaxUses:   t.MaxUses,
		Uses:      t.Uses,
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func httpNotFoundOr500(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		httpErr(w, http.StatusNotFound, "not found")
	} else {
		httpErr(w, http.StatusInternalServerError, err.Error())
	}
}
