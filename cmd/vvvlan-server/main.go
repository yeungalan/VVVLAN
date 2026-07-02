// Command vvvlan-server runs the VVVLAN control server, the relay/bridge
// server, and the admin web UI in a single process.
//
// Usage:
//
//	vvvlan-server --listen :8080 --relay-listen :41641 --state ./vvvlan-server.json
//
// The admin key for the web UI and API is printed at startup (and persisted
// in the state file).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/yeungalan/vvvlan/internal/control"
	"github.com/yeungalan/vvvlan/internal/relay"
	"github.com/yeungalan/vvvlan/internal/ui"
)

func main() {
	var (
		listen      = flag.String("listen", ":8080", "HTTP listen address (control API + web UI)")
		relayListen = flag.String("relay-listen", ":41641", "UDP listen address for the relay/reflector")
		relayPublic = flag.String("relay-public-addr", "", "relay address advertised to nodes (host:port); defaults to \":<relay port>\", which clients resolve against the control server's hostname")
		statePath   = flag.String("state", "vvvlan-server.json", "path of the persistent state file")
		debug       = flag.Bool("debug", false, "verbose logging")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	store, err := control.OpenStore(*statePath)
	if err != nil {
		log.Error("opening state store", "err", err)
		os.Exit(1)
	}

	ctrl := control.New(control.Config{
		Store:     store,
		Log:       log,
		RelayAddr: advertisedRelayAddr(*relayPublic, *relayListen),
		UI:        ui.Handler(),
	})

	rly, err := relay.New(*relayListen, ctrl.ValidateSession, log)
	if err != nil {
		log.Error("starting relay", "err", err)
		os.Exit(1)
	}
	go func() {
		if err := rly.Serve(); err != nil {
			log.Error("relay stopped", "err", err)
			os.Exit(1)
		}
	}()

	fmt.Fprintf(os.Stderr, "\n  VVVLAN control server\n")
	fmt.Fprintf(os.Stderr, "  web UI:    http://localhost%s/\n", normalizePort(*listen))
	fmt.Fprintf(os.Stderr, "  admin key: %s\n", store.AdminKey())
	fmt.Fprintf(os.Stderr, "  relay UDP: %s\n\n", *relayListen)

	log.Info("control server listening", "http", *listen, "relay", *relayListen)
	if err := http.ListenAndServe(*listen, ctrl.Handler()); err != nil {
		log.Error("http server stopped", "err", err)
		os.Exit(1)
	}
}

// advertisedRelayAddr picks what to tell nodes about the relay location.
func advertisedRelayAddr(public, listen string) string {
	if public != "" {
		return public
	}
	// Advertise just the port; clients substitute the control server host.
	_, port, ok := splitHostPort(listen)
	if !ok {
		return listen
	}
	return ":" + port
}

func normalizePort(listen string) string {
	if _, port, ok := splitHostPort(listen); ok {
		return ":" + port
	}
	return listen
}

func splitHostPort(s string) (host, port string, ok bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
