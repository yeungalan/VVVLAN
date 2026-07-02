// Package controlclient is the node-side client of the control server:
// registration via join token, and a self-reconnecting WebSocket that
// receives netmaps and hole-punch signals and reports endpoints.
package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/proto"
)

// Register redeems a join token with the control server.
func Register(ctx context.Context, serverURL, token, name, hostname, osName string, id *identity.Identity) (*proto.RegisterResponse, error) {
	req := proto.RegisterRequest{
		Token:     token,
		PublicKey: id.PublicKey.String(),
		Name:      name,
		Hostname:  hostname,
		OS:        osName,
	}
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(serverURL, "/")+"/api/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("contacting control server: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("registration rejected: %s", e.Error)
		}
		return nil, fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}
	var out proto.RegisterResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("bad registration response: %w", err)
	}
	return &out, nil
}

// ResolveRelayAddr expands a relay address advertised as ":port" using the
// control server's hostname.
func ResolveRelayAddr(serverURL, relayAddr string) (string, error) {
	if !strings.HasPrefix(relayAddr, ":") {
		return relayAddr, nil
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("bad server URL: %w", err)
	}
	return u.Hostname() + relayAddr, nil
}

// Callbacks are invoked from the WebSocket read loop.
type Callbacks struct {
	OnNetMap func(nm *proto.NetMap)
	OnPunch  func(req *proto.PunchRequest)
}

// WS maintains the control WebSocket connection with automatic reconnect.
type WS struct {
	serverURL    string
	nodeID       string
	sessionToken string
	cb           Callbacks
	log          *slog.Logger

	out chan proto.WSMessage
}

// NewWS creates the WebSocket client (call Run to start it).
func NewWS(serverURL, nodeID, sessionToken string, cb Callbacks, log *slog.Logger) *WS {
	return &WS{
		serverURL:    serverURL,
		nodeID:       nodeID,
		sessionToken: sessionToken,
		cb:           cb,
		log:          log,
		out:          make(chan proto.WSMessage, 64),
	}
}

func (c *WS) wsURL() (string, error) {
	u, err := url.Parse(c.serverURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported server URL scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/ws"
	q := u.Query()
	q.Set("node_id", c.nodeID)
	q.Set("session_token", c.sessionToken)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Run connects and reconnects until ctx is canceled.
func (c *WS) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		c.log.Warn("control connection lost, reconnecting", "err", err, "backoff", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *WS) runOnce(ctx context.Context) error {
	wsURL, err := c.wsURL()
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, _, err := websocket.DefaultDialer.DialContext(dialCtx, wsURL, nil)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	c.log.Info("connected to control server")

	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

	// Writer.
	go func() {
		for {
			select {
			case msg := <-c.out:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteJSON(msg); err != nil {
					cancelConn()
					return
				}
			case <-connCtx.Done():
				conn.Close() // unblock the reader
				return
			}
		}
	}()

	conn.SetReadLimit(1 << 20)
	conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPingHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(10*time.Second))
		return nil
	})
	for {
		var msg proto.WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		switch msg.Type {
		case proto.WSNetMap:
			var nm proto.NetMap
			if err := json.Unmarshal(msg.Data, &nm); err == nil && c.cb.OnNetMap != nil {
				// The server may advertise the relay as ":port"; expand it
				// with the control server's host before handing it out.
				if addr, err := ResolveRelayAddr(c.serverURL, nm.RelayAddr); err == nil {
					nm.RelayAddr = addr
				}
				c.cb.OnNetMap(&nm)
			}
		case proto.WSPunch:
			var req proto.PunchRequest
			if err := json.Unmarshal(msg.Data, &req); err == nil && c.cb.OnPunch != nil {
				c.cb.OnPunch(&req)
			}
		}
	}
}

func (c *WS) send(typ string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	msg := proto.WSMessage{Type: typ, Data: data}
	select {
	case c.out <- msg:
	default: // drop rather than block the data plane
	}
}

// SendEndpoints reports this node's candidate endpoints.
func (c *WS) SendEndpoints(endpoints []string) {
	c.send(proto.WSEndpoints, proto.EndpointUpdate{Endpoints: endpoints})
}

// AskPunch asks the server to signal target to probe back toward us.
func (c *WS) AskPunch(targetNodeID string) {
	c.send(proto.WSPunchAsk, proto.PunchAsk{TargetNodeID: targetNodeID})
}

// SendPathReport reports the current path to a peer (UI telemetry).
func (c *WS) SendPathReport(rep proto.PathReport) {
	c.send(proto.WSPathReport, rep)
}
