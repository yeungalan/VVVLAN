package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yeungalan/vvvlan/internal/engine"
)

// serveLocalAPI exposes the running agent to the CLI on localhost:
//
//	GET  /status      -> engine.Status
//	POST /exit        -> {"on": bool}
func serveLocalAPI(ctx context.Context, addr string, eng *engine.Engine, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(eng.Snapshot())
	})
	mux.HandleFunc("POST /exit", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			On bool `json:"on"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := eng.SetExit(req.On); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Warn("local API unavailable", "addr", addr, "err", err)
	}
}

func localAPIGet(addr, path string, out any) error {
	resp, err := http.Get("http://" + addr + path)
	if err != nil {
		return errors.New("cannot reach the vvvland agent — is it running? (`sudo vvvland up`)")
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func localAPIPost(addr, path string, body any) error {
	data, _ := json.Marshal(body)
	resp, err := http.Post("http://"+addr+path, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return errors.New("cannot reach the vvvland agent — is it running? (`sudo vvvland up`)")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("agent returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	localAPI := fs.String("localapi", "127.0.0.1:4646", "local API address")
	asJSON := fs.Bool("json", false, "print raw JSON")
	fs.Parse(args)

	var st engine.Status
	if err := localAPIGet(*localAPI, "/status", &st); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	fmt.Printf("node        %s\n", st.NodeID)
	fmt.Printf("virtual ip  %s (%s)\n", st.VirtualIP, st.CIDR)
	if st.PublicAddr != "" {
		fmt.Printf("public addr %s\n", st.PublicAddr)
	}
	fmt.Printf("relay       %s (bound: %v)\n", st.RelayAddr, st.RelayBound)
	if st.IsGateway {
		mode := st.NATMode
		if mode == "" {
			mode = "starting"
		}
		fmt.Printf("role        internet gateway for this network (%s NAT)\n", mode)
		if st.NATStats != nil {
			fmt.Printf("nat flows   tcp=%d udp=%d dial_errors=%d\n",
				st.NATStats.TCPFlows, st.NATStats.UDPFlows, st.NATStats.DialErrors)
		}
	}
	if st.ExitEnabled {
		fmt.Println("passthrough internet traffic routed via gateway")
	}
	if len(st.Peers) == 0 {
		fmt.Println("\nno peers in this network yet")
		return nil
	}
	fmt.Printf("\n%-18s %-15s %-8s %-10s %s\n", "PEER", "VIRTUAL IP", "STATE", "PATH", "DETAIL")
	for _, p := range st.Peers {
		state := "offline"
		if p.Online {
			state = "online"
		}
		path, detail := "-", ""
		if p.Direct {
			path = "direct"
			detail = fmt.Sprintf("%s (%.0fms)", p.Endpoint, float64(p.RTT.Microseconds())/1000)
		} else if p.HasTunnel {
			path = "relay"
		}
		name := p.Name
		if p.IsGateway {
			name += " [gw]"
		}
		fmt.Printf("%-18s %-15s %-8s %-10s %s\n", name, p.VirtualIP, state, path, detail)
	}
	return nil
}

func cmdExit(args []string) error {
	fs := flag.NewFlagSet("exit", flag.ExitOnError)
	localAPI := fs.String("localapi", "127.0.0.1:4646", "local API address")
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off") {
		return errors.New("usage: vvvland exit on|off")
	}
	on := rest[0] == "on"
	if err := localAPIPost(*localAPI, "/exit", map[string]bool{"on": on}); err != nil {
		return err
	}
	if on {
		fmt.Println("internet passthrough enabled — traffic now routes via the network gateway")
	} else {
		fmt.Println("internet passthrough disabled")
	}
	return nil
}
