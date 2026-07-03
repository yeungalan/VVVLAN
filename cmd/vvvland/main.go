// Command vvvland is the VVVLAN node agent. It manages the node identity,
// joins networks via the control server, runs the virtual interface and the
// encrypted data plane, and exposes a local API for the CLI.
//
// Typical usage:
//
//	vvvland join --server https://vvvlan.example.com --token <join-token>
//	sudo vvvland up
//	vvvland status
//	vvvland exit on      # route internet traffic via the network gateway
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"log/slog"

	"github.com/yeungalan/vvvlan/internal/controlclient"
	"github.com/yeungalan/vvvlan/internal/engine"
	"github.com/yeungalan/vvvlan/internal/identity"
	"github.com/yeungalan/vvvlan/internal/netcfg"
	"github.com/yeungalan/vvvlan/internal/proto"
	"github.com/yeungalan/vvvlan/internal/tunio"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "join":
		err = cmdJoin(os.Args[2:])
	case "up":
		err = cmdUp(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "exit":
		err = cmdExit(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vvvland — VVVLAN node agent

commands:
  join --server <url> --token <join-token> [--name <name>]
        register this machine with a network
  up    [--port <udp-port>] [--tun <name>] [--exit]
        run the agent (needs root/admin to create the TUN interface)
  status
        show connection state and peers
  exit on|off
        toggle internet passthrough via the network's gateway node

common flags:
  --state <dir>       state directory (default: <os config dir>/vvvlan)
  --localapi <addr>   local API address (default 127.0.0.1:4646)
`)
}

// config is the node's persisted membership.
type config struct {
	ServerURL    string `json:"server_url"`
	NodeID       string `json:"node_id"`
	SessionToken string `json:"session_token"`
	NetworkName  string `json:"network_name"`
	VirtualIP    string `json:"virtual_ip"`
	CIDR         string `json:"cidr"`
	RelayAddr    string `json:"relay_addr"`
	Name         string `json:"name"`
}

func defaultStateDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "vvvlan")
}

func loadConfig(stateDir string) (*config, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, "config.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("this machine has not joined a network yet — run `vvvland join` first")
		}
		return nil, err
	}
	var c config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveConfig(stateDir string, c *config) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(stateDir, "config.json"), data, 0o600)
}

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	server := fs.String("server", "", "control server URL, e.g. https://vvvlan.example.com")
	token := fs.String("token", "", "join token from the admin UI")
	name := fs.String("name", "", "node name shown in the UI (default: hostname)")
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	fs.Parse(args)
	if *server == "" || *token == "" {
		return errors.New("--server and --token are required")
	}
	if _, err := url.Parse(*server); err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	id, err := identity.LoadOrCreate(filepath.Join(*stateDir, "identity.json"))
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	resp, err := controlclient.Register(context.Background(), *server, *token, *name, hostname, runtime.GOOS, id)
	if err != nil {
		return err
	}
	c := &config{
		ServerURL:    *server,
		NodeID:       resp.NodeID,
		SessionToken: resp.SessionToken,
		NetworkName:  resp.NetworkName,
		VirtualIP:    resp.VirtualIP,
		CIDR:         resp.CIDR,
		RelayAddr:    resp.RelayAddr,
		Name:         *name,
	}
	if err := saveConfig(*stateDir, c); err != nil {
		return err
	}
	fmt.Printf("joined network %q\n  virtual IP: %s (%s)\n  node id:    %s\n\nstart the agent with:  sudo vvvland up\n",
		resp.NetworkName, resp.VirtualIP, resp.CIDR, resp.NodeID)
	if runtime.GOOS == "windows" {
		fmt.Println("(on Windows run `vvvland up` from an Administrator prompt; wintun.dll must be next to vvvland.exe — see https://www.wintun.net)")
	}
	return nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	port := fs.Int("port", 0, "UDP port for tunnel traffic (0 = automatic)")
	tunName := fs.String("tun", defaultTunName(), "TUN interface name")
	localAPI := fs.String("localapi", "127.0.0.1:4646", "local API listen address")
	exit := fs.Bool("exit", false, "enable internet passthrough via the gateway at startup")
	usrNAT := fs.Bool("userspace-nat", false, "when acting as gateway, always NAT in userspace (netstack) instead of configuring the OS")
	debug := fs.Bool("debug", false, "verbose logging")
	fs.Parse(args)

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	id, err := identity.LoadOrCreate(filepath.Join(*stateDir, "identity.json"))
	if err != nil {
		return err
	}
	cfg, err := loadConfig(*stateDir)
	if err != nil {
		return err
	}

	dev, err := tunio.CreateTUN(*tunName, tunio.DefaultMTU)
	if err != nil {
		return err
	}
	log.Info("virtual interface created", "name", dev.Name())
	mgr := netcfg.NewManager(dev.Name(), log)

	// The engine and the control WebSocket reference each other: the engine
	// pushes endpoints/punch-asks up, the WebSocket pushes netmaps/punch
	// requests down. Late-bind the ws through a variable assigned before any
	// engine loop starts.
	var ws *controlclient.WS
	eng, err := engine.New(engine.Config{
		Identity:     id,
		Device:       dev,
		SessionToken: cfg.SessionToken,
		UDPPort:      *port,
		Log:          log,
		NetCfg:       mgr,
		AskPunch: func(target string) {
			ws.AskPunch(target)
		},
		ReportEndpoints: func(eps []string) {
			ws.SendEndpoints(eps)
		},
		ReportPath: func(rep proto.PathReport) {
			ws.SendPathReport(rep)
		},
		UserspaceNAT: *usrNAT,
	})
	if err != nil {
		dev.Close()
		return err
	}
	ws = controlclient.NewWS(cfg.ServerURL, cfg.NodeID, cfg.SessionToken, controlclient.Callbacks{
		OnNetMap: eng.UpdateNetMap,
		OnPunch:  eng.HandlePunch,
	}, log)
	return runAgent(cfg, dev, mgr, eng, ws, *localAPI, *exit, log)
}

func defaultTunName() string {
	switch runtime.GOOS {
	case "darwin":
		// macOS TUN names must be utun[0-9]*; plain "utun" asks the kernel
		// to pick the next free number.
		return "utun"
	default:
		return "vvvlan0"
	}
}

// controlHostIPs resolves the control server's host so exit mode can pin it
// to the physical route.
func controlHostIPs(serverURL string) []netip.Addr {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok {
			out = append(out, a)
		}
	}
	return out
}

func runAgent(cfg *config, dev tunio.Device, mgr *netcfg.Manager,
	eng *engine.Engine, ws *controlclient.WS, localAPI string, exit bool, log *slog.Logger) error {

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	eng.SetControlIPs(controlHostIPs(cfg.ServerURL))

	go ws.Run(ctx)
	go serveLocalAPI(ctx, localAPI, eng, log)

	if exit {
		go func() {
			// Exit routes need the first netmap; retry via the local flag.
			if err := eng.SetExit(true); err != nil {
				log.Warn("could not enable internet passthrough yet", "err", err)
			}
		}()
	}

	log.Info("vvvland running",
		"network", cfg.NetworkName, "ip", cfg.VirtualIP, "node", cfg.NodeID, "udp_port", eng.LocalPort())
	err := eng.Run(ctx)
	mgr.Cleanup()
	if errors.Is(err, context.Canceled) {
		log.Info("shut down")
		return nil
	}
	return err
}
