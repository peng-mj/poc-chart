package main

import (
	"fmt"
	"os"

	"github.com/mj/pqc-chart-tool/pkg/transport"
	"github.com/spf13/pflag"
)

// CLIConfig holds the command line configuration.
type CLIConfig struct {
	generate      bool
	showID        bool
	connectTarget string
	peerIDHash    string
	message       string
	port          int
	acceptAny     bool
}

// parseFlags parses command line flags and returns the configuration.
func parseFlags() *CLIConfig {
	cfg := &CLIConfig{}

	fs := pflag.NewFlagSet("pqc-client", pflag.ExitOnError)

	fs.BoolVarP(&cfg.generate, "generate", "g", false, "Generate a new ML-DSA identity keypair")
	fs.BoolVarP(&cfg.showID, "show-id", "i", false, "Display your ID hash for sharing")
	fs.StringVarP(&cfg.connectTarget, "connect", "c", "", "Connection target (for client mode): ip:port")
	fs.StringVarP(&cfg.peerIDHash, "peer", "p", "", "Peer address (ip:port for client mode) or server address (for server mode)")
	fs.StringVarP(&cfg.message, "message", "m", "", "Send a single message and exit (client mode)")
	fs.IntVarP(&cfg.port, "port", "P", transport.DefaultPort, "Listening port (for server mode)")
	fs.BoolVarP(&cfg.acceptAny, "accept", "a", false, "Accept connections from any peer (for server mode)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	return cfg
}

// runConnect handles the connect mode.
func runConnect(cfg *CLIConfig) {
	if cfg.connectTarget == "" {
		fmt.Println("Error: --connect is required for connect mode")
		fmt.Println("Use 'pqc-client -h' for help")
		os.Exit(1)
	}

	connectToPeer(cfg.connectTarget, cfg.peerIDHash, cfg.message)
}

// runServer handles the server mode.
func runServer(cfg *CLIConfig) {
	startServer(cfg.peerIDHash, cfg.port, cfg.acceptAny)
}

// runConnectAsClient handles the connect mode when only peer is specified.
func runConnectAsClient(peer string, message string) {
	connectToPeer(peer, "", message)
}