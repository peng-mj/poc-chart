package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mj/pqc-chart-tool/internal/logging"
)

func main() {
	logging.Setup(slog.LevelInfo)

	cfg := parseFlags()

	switch {
	case cfg.generate:
		generateIdentity()
	case cfg.showID:
		showIdentity()
	case cfg.connectTarget != "" && cfg.peerIDHash != "":
		runConnect(cfg)
	case cfg.connectTarget == "" && cfg.peerIDHash != "":
		runConnectAsClient(cfg.peerIDHash, cfg.message)
	case cfg.connectTarget == "" && cfg.peerIDHash == "":
		runServer(cfg)
	default:
		fmt.Println("Error: invalid combination of options")
		os.Exit(1)
	}
}