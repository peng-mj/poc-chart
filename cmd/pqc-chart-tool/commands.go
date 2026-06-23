package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"strings"

	"github.com/mj/pqc-chart-tool/internal/logging"
	"github.com/mj/pqc-chart-tool/pkg/client"
	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/identity"
	"github.com/mj/pqc-chart-tool/pkg/interactive"
	"github.com/mj/pqc-chart-tool/pkg/transport"
)

// autoGenerateIdentity generates a new ML-DSA identity keypair if one doesn't exist.
func autoGenerateIdentity() (*crypto.MLDSAKeyPair, *identity.KeyStore) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logging.Fatal("failed to get home directory", "error", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)

	store, err := identity.NewKeyStore(storePath, nil)
	if err != nil {
		logging.Fatal("failed to open keystore", "error", err)
	}

	if store.HasKeypair("default") {
		store.Close()
		return nil, nil
	}
	store.Close()

	fmt.Println("No identity found. Generating ML-DSA-65 keypair...")

	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		logging.Fatal("failed to generate keypair", "error", err)
	}

	masterPassword := interactive.ReadPassword("Enter master password for key storage: ")

	store, err = identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		logging.Fatal("failed to create keystore", "error", err)
	}

	if err := store.SaveDSAKeypair("default", keypair.Public, keypair.Private); err != nil {
		logging.Fatal("failed to save keypair", "error", err)
	}

	idHash := identity.ComputeIDHash(keypair.Public)
	fmt.Printf("\nIdentity generated successfully!\n")
	fmt.Printf("Your ID Hash: %s\n", identity.FormatIDHash(idHash))

	return keypair, store
}

// loadIdentity loads the existing identity or auto-generates one.
func loadIdentity() (*crypto.MLDSAKeyPair, *identity.KeyStore, []byte) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logging.Fatal("failed to get home directory", "error", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)
	store, err := identity.NewKeyStore(storePath, nil)
	if err != nil {
		logging.Fatal("failed to open keystore", "error", err)
	}

	if !store.HasKeypair("default") {
		store.Close()
		keypair, newStore := autoGenerateIdentity()
		idHash := identity.ComputeIDHash(keypair.Public)
		return keypair, newStore, idHash
	}

	store.Close()

	masterPassword := interactive.ReadPassword("Enter master password: ")

	store, err = identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		logging.Fatal("failed to open keystore", "error", err)
	}

	publicKey, privateKey, err := store.LoadDSAKeypair("default")
	if err != nil {
		logging.Fatal("failed to load keypair", "error", err)
	}

	keypair := &crypto.MLDSAKeyPair{
		Public:  publicKey,
		Private: privateKey,
	}

	idHash := identity.ComputeIDHash(publicKey)

	return keypair, store, idHash
}

// generateIdentity generates a new ML-DSA identity keypair.
func generateIdentity() {
	fmt.Println("Generating ML-DSA-65 keypair...")

	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		logging.Fatal("failed to generate keypair", "error", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logging.Fatal("failed to get home directory", "error", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)
	masterPassword := interactive.ReadPassword("Enter master password for key storage: ")

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		logging.Fatal("failed to create keystore", "error", err)
	}
	defer store.Close()

	if err := store.SaveDSAKeypair("default", keypair.Public, keypair.Private); err != nil {
		logging.Fatal("failed to save keypair", "error", err)
	}

	idHash := identity.ComputeIDHash(keypair.Public)
	fmt.Printf("\nIdentity generated successfully!\n")
	fmt.Printf("Your ID Hash: %s\n", identity.FormatIDHash(idHash))
	fmt.Println("\nShare this ID hash with peers you want to connect with.")
	fmt.Println("Use 'pqc-client -i' to display it again.")

	crypto.SecureClear(keypair.Private)
}

// showIdentity displays the user's ID hash.
func showIdentity() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logging.Fatal("failed to get home directory", "error", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)
	masterPassword := interactive.ReadPassword("Enter master password: ")

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		logging.Fatal("failed to open keystore", "error", err)
	}
	defer store.Close()

	if !store.HasKeypair("default") {
		fmt.Println("No identity found. Run 'pqc-client -g' first.")
		os.Exit(1)
	}

	publicKey, _, err := store.LoadDSAKeypair("default")
	if err != nil {
		logging.Fatal("failed to load keypair", "error", err)
	}

	idHash := identity.ComputeIDHash(publicKey)
	fmt.Printf("Your ID Hash: %s\n", identity.FormatIDHash(idHash))
}

// connectToPeer connects to a peer and starts interactive chat or sends a single message.
func connectToPeer(target, peerIDHashStr, message string) {
	keypair, store, _ := loadIdentity()
	defer store.Close()
	defer crypto.SecureClear(keypair.Private)

	var peerIDHash []byte
	var err error

	if peerIDHashStr != "" {
		peerIDHash, err = identity.ParseIDHash(peerIDHashStr)
		if err != nil {
			logging.Fatal("invalid peer ID hash", "error", err)
		}
	}

	if !strings.Contains(target, ":") {
		target = fmt.Sprintf("%s:%d", target, transport.DefaultPort)
	}
	pqcClient := client.NewPQCClientDirect(keypair, target, false)
	fmt.Printf("Connecting to %s...\n", target)

	if peerIDHash == nil {
		peerIDHash = make([]byte, 32)
	}

	channel, err := pqcClient.Connect(peerIDHash)
	if err != nil {
		logging.Fatal("connection failed", "error", err)
	}
	defer channel.Close()

	fmt.Println("Connected securely!")

	if message != "" {
		if err := channel.Send([]byte(message)); err != nil {
			logging.Fatal("failed to send message", "error", err)
		}
		fmt.Println("Message sent successfully")

		response, err := channel.Recv()
		if err != nil {
			logging.Fatal("failed to receive response", "error", err)
		}
		fmt.Printf("Response: %s\n", string(response))
	} else {
		interactive.InteractiveChat(channel)
	}
}

// startServer starts the server mode for direct connections.
func startServer(peerIDHashStr string, port int, acceptAny bool) {
	var peerIDHash []byte
	var err error
	if peerIDHashStr != "" {
		peerIDHash, err = identity.ParseIDHash(peerIDHashStr)
		if err != nil {
			logging.Fatal("invalid peer ID hash", "error", err)
		}
	}

	keypair, store, _ := loadIdentity()
	defer store.Close()
	defer crypto.SecureClear(keypair.Private)

	pqcClient := client.NewPQCClientDirect(keypair, "", acceptAny)

	server := transport.NewDirectServer()
	addr := fmt.Sprintf("0.0.0.0:%d", port)

	server.OnConnect = func(conn net.Conn) {
		slog.Info("incoming connection", "remote_addr", conn.RemoteAddr())

		tcpConn := transport.NewDirectConn(conn)

		if peerIDHash == nil {
			peerIDHash = make([]byte, 32)
		}

		channel, err := pqcClient.Accept(tcpConn, peerIDHash, acceptAny)
		if err != nil {
			slog.Error("handshake failed", "remote_addr", conn.RemoteAddr(), "error", err)
			conn.Close()
			return
		}
		defer channel.Close()

		fmt.Println("\nPeer connected securely!")
		interactive.InteractiveChat(channel)
	}

	if err := server.Start(addr); err != nil {
		logging.Fatal("failed to start server", "error", err)
	}

	myIDHash := identity.ComputeIDHash(keypair.Public)
	fmt.Printf("Server listening on %s\n", addr)
	fmt.Printf("Your ID Hash: %s\n", identity.FormatIDHash(myIDHash))
	fmt.Println("\nWaiting for incoming connections...")
	fmt.Println("Press Ctrl+C to stop the server")

	slog.Info("server started, ready to accept connections")
	setupSignalHandler(server)
}

// setupSignalHandler handles graceful shutdown on SIGINT/SIGTERM
func setupSignalHandler(server *transport.DirectServer) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	fmt.Println("\n\nShutting down server...")
	server.Stop()
	fmt.Println("Server stopped")
	os.Exit(0)
}