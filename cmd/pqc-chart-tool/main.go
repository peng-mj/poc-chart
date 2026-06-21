// Package main implements the PQC Chart Tool application.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/identity"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
	"github.com/mj/pqc-chart-tool/pkg/transport"
	"github.com/spf13/pflag"
)

// PQCClient represents a PQC client.
type PQCClient struct {
	identityKeypair *crypto.MLDSAKeyPair
	myIDHash        []byte
	relayURL        string
	directAddr      string
	fragmentBuffer  *protocol.FragmentBuffer
}

// NewPQCClient creates a new PQC client.
func NewPQCClient(identityKeypair *crypto.MLDSAKeyPair, relayURL string) *PQCClient {
	myIDHash := identity.ComputeIDHash(identityKeypair.Public)
	return &PQCClient{
		identityKeypair: identityKeypair,
		relayURL:        relayURL,
		myIDHash:        myIDHash,
		fragmentBuffer:  protocol.NewFragmentBuffer(5 * time.Minute),
	}
}

// NewPQCClientDirect creates a new PQC client for direct connections.
func NewPQCClientDirect(identityKeypair *crypto.MLDSAKeyPair, directAddr string) *PQCClient {
	myIDHash := identity.ComputeIDHash(identityKeypair.Public)
	return &PQCClient{
		identityKeypair: identityKeypair,
		directAddr:      directAddr,
		myIDHash:        myIDHash,
		fragmentBuffer:  protocol.NewFragmentBuffer(5 * time.Minute),
	}
}

// Connect initiates a connection to a peer.
func (c *PQCClient) Connect(targetIDHash []byte) (*SecureChannel, error) {
	var conn protocol.Transport

	if c.directAddr != "" {
		ws, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("ws://%s", c.directAddr), nil)
		if err != nil {
			return nil, fmt.Errorf("dial direct: %w", err)
		}
		conn = transport.NewDirectConn(ws)
	} else if c.relayURL != "" {
		ws, _, err := websocket.DefaultDialer.Dial(c.relayURL, nil)
		if err != nil {
			return nil, fmt.Errorf("dial relay: %w", err)
		}
		conn = transport.NewWebSocketConn(ws)
	} else {
		return nil, errors.New("no connection address specified")
	}

	channel, err := c.performHandshake(conn, targetIDHash)
	if err != nil {
		if closer, ok := conn.(interface{ Close() error }); ok {
			closer.Close()
		}
		return nil, err
	}
	return channel, nil
}

// Accept handles an incoming connection.
func (c *PQCClient) Accept(ws *websocket.Conn, targetIDHash []byte) (*SecureChannel, error) {
	conn := transport.NewDirectConn(ws)
	channel, err := c.performHandshakeResponder(conn, targetIDHash)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return channel, nil
}

// performHandshake performs the handshake as initiator.
func (c *PQCClient) performHandshake(conn protocol.Transport, targetIDHash []byte) (*SecureChannel, error) {
	// Phase 1: KEM Handshake
	handshake := protocol.NewKEMHandshake(true)
	request, err := handshake.Initiate()
	if err != nil {
		return nil, err
	}

	log.Println("[init] sending handshake request")
	if err := protocol.SendFragmented(conn, request, protocol.MsgHandshakeRequest, 1400); err != nil {
		return nil, err
	}

	// Receive agree
	log.Println("[init] waiting for handshake agree")
	flag, agreeData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgHandshakeAgree {
		return nil, errors.New("unexpected message type")
	}

	log.Println("[init] received agree, computing finish")
	finishData, err := handshake.HandleAgree(agreeData)
	if err != nil {
		return nil, err
	}

	log.Println("[init] sending finish")
	if err := protocol.SendFragmented(conn, finishData, protocol.MsgHandshakeFinish, 1400); err != nil {
		return nil, err
	}

	log.Println("[init] deriving session key")
	// Derive session key
	sessionKey, err := handshake.DeriveSessionKey()
	if err != nil {
		return nil, err
	}

	// Channel binding
	channelBinding := append(handshake.MyKEMPublicKey(), handshake.PeerPubkey()...)

	// Phase 2: Identity Verification
	idExchange := identity.NewIdentityExchange(sessionKey, c.identityKeypair, targetIDHash)

	// Send identity
	if err := idExchange.SendIdentity(conn); err != nil {
		return nil, err
	}

	// Receive challenge, send signature
	flag, challengeEnc, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgChallenge {
		return nil, errors.New("unexpected message type")
	}

	sessionID := sessionKey
	sigResponse, err := idExchange.HandleChallenge(challengeEnc, channelBinding, sessionID)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, sigResponse, protocol.MsgSignatureResponse, 1400); err != nil {
		return nil, err
	}

	// Receive peer identity
	flag, peerIdentity, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgIdentityMessage {
		return nil, errors.New("unexpected message type")
	}

	peerChallenge, err := idExchange.HandlePeerIdentity(peerIdentity)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, peerChallenge, protocol.MsgChallenge, 1400); err != nil {
		return nil, err
	}

	// Receive peer signature
	flag, peerSig, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgSignatureResponse {
		return nil, errors.New("unexpected message type")
	}

	verified, err := idExchange.VerifyResponse(peerSig, peerChallenge, channelBinding, sessionID)
	if err != nil {
		return nil, err
	}

	if !verified {
		return nil, errors.New("identity verification failed")
	}

	log.Println("双向验证通过！管道已建立")
	return NewSecureChannel(conn, sessionKey), nil
}

// performHandshakeResponder performs the handshake as responder.
func (c *PQCClient) performHandshakeResponder(conn protocol.Transport, targetIDHash []byte) (*SecureChannel, error) {
	// Phase 1: KEM Handshake
	handshake := protocol.NewKEMHandshake(false)

	// Receive request
	log.Println("[resp] waiting for handshake request")
	flag, requestData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgHandshakeRequest {
		return nil, errors.New("unexpected message type")
	}

	log.Println("[resp] received request, computing agree")
	agreeData, err := handshake.HandleRequest(requestData)
	if err != nil {
		return nil, err
	}

	log.Println("[resp] sending agree")
	if err := protocol.SendFragmented(conn, agreeData, protocol.MsgHandshakeAgree, 1400); err != nil {
		return nil, err
	}

	// Receive finish
	log.Println("[resp] waiting for finish")
	flag, finishData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgHandshakeFinish {
		return nil, errors.New("unexpected message type")
	}

	if err := handshake.HandleFinish(finishData); err != nil {
		return nil, err
	}

	// Derive session key
	sessionKey, err := handshake.DeriveSessionKey()
	if err != nil {
		return nil, err
	}

	// Channel binding
	channelBinding := append(handshake.MyKEMPublicKey(), handshake.PeerPubkey()...)

	// Phase 2: Identity Verification
	idExchange := identity.NewIdentityExchange(sessionKey, c.identityKeypair, targetIDHash)

	// Receive peer identity, send challenge
	flag, peerIdentity, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgIdentityMessage {
		return nil, errors.New("unexpected message type")
	}

	peerChallenge, err := idExchange.HandlePeerIdentity(peerIdentity)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, peerChallenge, protocol.MsgChallenge, 1400); err != nil {
		return nil, err
	}

	// Receive signature
	flag, sigResponse, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgSignatureResponse {
		return nil, errors.New("unexpected message type")
	}

	verified, err := idExchange.VerifyResponse(sigResponse, peerChallenge, channelBinding, sessionKey)
	if err != nil {
		return nil, err
	}

	if !verified {
		return nil, errors.New("identity verification failed")
	}

	// Send our identity
	if err := idExchange.SendIdentity(conn); err != nil {
		return nil, err
	}

	// Receive challenge
	flag, challengeEnc, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgChallenge {
		return nil, errors.New("unexpected message type")
	}

	sigData, err := idExchange.HandleChallenge(challengeEnc, channelBinding, sessionKey)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, sigData, protocol.MsgSignatureResponse, 1400); err != nil {
		return nil, err
	}

	log.Println("双向验证通过！管道已建立")
	return NewSecureChannel(conn, sessionKey), nil
}

// IDHash returns the client's ID hash.
func (c *PQCClient) IDHash() []byte {
	return c.myIDHash
}

// SecureChannel represents an encrypted channel.
type SecureChannel struct {
	transport  protocol.Transport
	sessionKey []byte
}

// NewSecureChannel creates a new secure channel.
func NewSecureChannel(transport protocol.Transport, sessionKey []byte) *SecureChannel {
	return &SecureChannel{
		transport:  transport,
		sessionKey: sessionKey,
	}
}

// Send sends an encrypted message.
func (sc *SecureChannel) Send(data []byte) error {
	encrypted, err := crypto.AESGCMEncrypt(sc.sessionKey, data)
	if err != nil {
		return err
	}
	return sc.transport.Send(encrypted)
}

// Recv receives and decrypts a message.
func (sc *SecureChannel) Recv() ([]byte, error) {
	data, err := sc.transport.Recv()
	if err != nil {
		return nil, err
	}
	return crypto.AESGCMDecrypt(sc.sessionKey, data)
}

// Close closes the secure channel.
func (sc *SecureChannel) Close() error {
	if closer, ok := sc.transport.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "generate":
		generateIdentity()
	case "show-id":
		showIdentity()
	case "connect":
		runConnect()
	case "server":
		runServer()
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runConnect() {
	var showHelp bool
	fs := pflag.NewFlagSet("connect", pflag.ExitOnError)
	fs.BoolVarP(&showHelp, "help", "h", false, "Show help for connect command")
	fs.Usage = func() {
		fmt.Println("Connect to a peer")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  pqc-client connect <target> <peer-id-hash>")
		fmt.Println()
		fmt.Println("Arguments:")
		fmt.Println("  target         Connection target:")
		fmt.Println("                   - ws://relay-url (relay mode)")
		fmt.Println("                   - ip:port (direct mode, default port: 18080)")
		fmt.Println("  peer-id-hash   The peer's ID hash to connect to")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  pqc-client connect ws://relay.example.com:8080 a1b2c3...")
		fmt.Println("  pqc-client connect 192.168.1.100:18080 a1b2c3...")
		fmt.Println("  pqc-client connect 192.168.1.100 a1b2c3...")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}

	if showHelp {
		fs.Usage()
		os.Exit(0)
	}

	args := fs.Args()
	if len(args) < 2 {
		fs.Usage()
		os.Exit(1)
	}

	target := args[0]
	peerIDHash := args[1]

	connectToPeer(target, peerIDHash)
}

func runServer() {
	var port int
	var showHelp bool
	fs := pflag.NewFlagSet("server", pflag.ExitOnError)
	fs.IntVarP(&port, "port", "p", transport.DefaultPort, "Listening port (default: 18080)")
	fs.BoolVarP(&showHelp, "help", "h", false, "Show help for server command")
	fs.Usage = func() {
		fmt.Println("Start server mode for direct connections")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  pqc-client server <peer-id-hash> [options]")
		fmt.Println()
		fmt.Println("Arguments:")
		fmt.Println("  peer-id-hash   The ID hash of the peer you expect to connect")
		fmt.Println()
		fmt.Println("Options:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  pqc-client server d4e5f6a1b2c3...")
		fmt.Println("  pqc-client server d4e5f6a1b2c3... -p 19090")
		fmt.Println("  pqc-client server d4e5f6a1b2c3... --port 19090")
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(1)
	}

	if showHelp {
		fs.Usage()
		os.Exit(0)
	}

	args := fs.Args()
	if len(args) < 1 {
		fs.Usage()
		os.Exit(1)
	}

	peerIDHashStr := args[0]

	startServer(peerIDHashStr, port)
}

func generateIdentity() {
	fmt.Println("Generating ML-DSA-65 keypair...")

	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}

	// Save to keystore
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)
	masterPassword := readPassword("Enter master password for key storage: ")

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		log.Fatalf("Failed to create keystore: %v", err)
	}
	defer store.Close()

	if err := store.SaveDSAKeypair("default", keypair.Public, keypair.Private); err != nil {
		log.Fatalf("Failed to save keypair: %v", err)
	}

	idHash := identity.ComputeIDHash(keypair.Public)
	fmt.Printf("\nIdentity generated successfully!\n")
	fmt.Printf("Your ID Hash: %s\n", identity.FormatIDHash(idHash))
	fmt.Println("\nShare this ID hash with peers you want to connect with.")
	fmt.Println("Use 'pqc-client show-id' to display it again.")

	// Securely clear the private key from memory
	crypto.SecureClear(keypair.Private)
}

func showIdentity() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)
	masterPassword := readPassword("Enter master password: ")

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		log.Fatalf("Failed to open keystore: %v", err)
	}
	defer store.Close()

	if !store.HasKeypair("default") {
		fmt.Println("No identity found. Run 'pqc-client generate' first.")
		os.Exit(1)
	}

	publicKey, _, err := store.LoadDSAKeypair("default")
	if err != nil {
		log.Fatalf("Failed to load keypair: %v", err)
	}

	idHash := identity.ComputeIDHash(publicKey)
	fmt.Printf("Your ID Hash: %s\n", identity.FormatIDHash(idHash))
}

func connectToPeer(target, peerIDHashStr string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)
	masterPassword := readPassword("Enter master password: ")

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		log.Fatalf("Failed to open keystore: %v", err)
	}
	defer store.Close()

	if !store.HasKeypair("default") {
		fmt.Println("No identity found. Run 'pqc-client generate' first.")
		os.Exit(1)
	}

	_, privateKey, err := store.LoadDSAKeypair("default")
	if err != nil {
		log.Fatalf("Failed to load keypair: %v", err)
	}
	defer crypto.SecureClear(privateKey)

	publicKey, _, _ := store.LoadDSAKeypair("default")

	keypair := &crypto.MLDSAKeyPair{
		Public:  publicKey,
		Private: privateKey,
	}

	peerIDHash, err := identity.ParseIDHash(peerIDHashStr)
	if err != nil {
		log.Fatalf("Invalid peer ID hash: %v", err)
	}

	var client *PQCClient

	if strings.HasPrefix(target, "ws://") || strings.HasPrefix(target, "wss://") {
		client = NewPQCClient(keypair, target)
		fmt.Printf("Connecting to relay %s...\n", target)
	} else {
		if !strings.Contains(target, ":") {
			target = fmt.Sprintf("%s:%d", target, transport.DefaultPort)
		}
		client = NewPQCClientDirect(keypair, target)
		fmt.Printf("Connecting directly to %s...\n", target)
	}

	channel, err := client.Connect(peerIDHash)
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer channel.Close()

	fmt.Println("Connected securely!")

	interactiveChat(channel)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	var password string
	fmt.Scanln(&password)
	return password
}

func interactiveChat(channel *SecureChannel) {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("> ")
		for scanner.Scan() {
			text := scanner.Text()
			if strings.ToLower(text) == "quit" {
				channel.Close()
				os.Exit(0)
			}
			if err := channel.Send([]byte(text)); err != nil {
				log.Printf("Send error: %v", err)
				return
			}
			fmt.Print("> ")
		}
	}()

	for {
		data, err := channel.Recv()
		if err != nil {
			log.Printf("Receive error: %v", err)
			return
		}
		fmt.Printf("\rPeer: %s\n> ", string(data))
	}
}

func startServer(peerIDHashStr string, port int) {
	peerIDHash, err := identity.ParseIDHash(peerIDHashStr)
	if err != nil {
		log.Fatalf("Invalid peer ID hash: %v", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}

	storePath := fmt.Sprintf("%s/.pqc-client", homeDir)
	masterPassword := readPassword("Enter master password: ")

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		log.Fatalf("Failed to open keystore: %v", err)
	}
	defer store.Close()

	if !store.HasKeypair("default") {
		fmt.Println("No identity found. Run 'pqc-client generate' first.")
		os.Exit(1)
	}

	_, privateKey, err := store.LoadDSAKeypair("default")
	if err != nil {
		log.Fatalf("Failed to load keypair: %v", err)
	}
	defer crypto.SecureClear(privateKey)

	publicKey, _, _ := store.LoadDSAKeypair("default")

	keypair := &crypto.MLDSAKeyPair{
		Public:  publicKey,
		Private: privateKey,
	}

	client := NewPQCClientDirect(keypair, "")

	server := transport.NewDirectServer()
	addr := fmt.Sprintf("0.0.0.0:%d", port)

	server.OnConnect = func(ws *websocket.Conn) {
		log.Printf("Incoming connection from %s", ws.RemoteAddr())

		channel, err := client.Accept(ws, peerIDHash)
		if err != nil {
			log.Printf("Handshake failed with %s: %v", ws.RemoteAddr(), err)
			return
		}
		defer channel.Close()

		fmt.Println("\nPeer connected securely!")
		interactiveChat(channel)
	}

	if err := server.Start(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	myIDHash := identity.ComputeIDHash(keypair.Public)
	fmt.Printf("Server listening on %s\n", addr)
	fmt.Printf("Your ID Hash: %s\n", identity.FormatIDHash(myIDHash))
	fmt.Println("\nWaiting for incoming connections...")
	fmt.Println("Use 'pqc-client connect <server-ip> <peer-id-hash>' from another terminal to connect.")

	log.Println("Server started, ready to accept connections")
	select {}
}

func printHelp() {
	fmt.Println("PQC Client - Post-Quantum Cryptography Secure Communication")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  pqc-client <command> [arguments]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  generate         Generate a new ML-DSA identity keypair")
	fmt.Println("  show-id          Display your ID hash for sharing")
	fmt.Println("  connect          Connect to a peer (run 'pqc-client connect -h' for details)")
	fmt.Println("  server           Start server mode for direct connections (run 'pqc-client server -h' for details)")
	fmt.Println("  help, -h, --help Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Generate identity")
	fmt.Println("  pqc-client generate")
	fmt.Println()
	fmt.Println("  # Show ID hash")
	fmt.Println("  pqc-client show-id")
	fmt.Println()
	fmt.Println("  # Connect via relay")
	fmt.Println("  pqc-client connect ws://localhost:8080 abc123...")
	fmt.Println()
	fmt.Println("  # Start server mode (listening on 0.0.0.0:18080)")
	fmt.Println("  pqc-client server d4e5f6a1b2c3...")
	fmt.Println()
	fmt.Println("  # Start server mode on custom port (using short flag)")
	fmt.Println("  pqc-client server d4e5f6a1b2c3... -p 19090")
	fmt.Println()
	fmt.Println("  # Start server mode on custom port (using long flag)")
	fmt.Println("  pqc-client server d4e5f6a1b2c3... --port 19090")
	fmt.Println()
	fmt.Println("  # Connect directly to peer")
	fmt.Println("  pqc-client connect 192.168.1.100:18080 abc123...")
	fmt.Println("  pqc-client connect 192.168.1.100 abc123...")
	fmt.Println()
	fmt.Println("Use 'pqc-client <command> -h' for more information about a specific command.")
}

func printUsage() {
	fmt.Println("PQC Client - Post-Quantum Cryptography Secure Communication")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  pqc-client <command> [arguments]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  generate         Generate a new ML-DSA identity keypair")
	fmt.Println("  show-id          Display your ID hash for sharing")
	fmt.Println("  connect          Connect to a peer")
	fmt.Println("  server           Start server mode for direct connections")
	fmt.Println("  help, -h, --help Show this help message")
	fmt.Println()
	fmt.Println("Use 'pqc-client help' or 'pqc-client <command> -h' for more information.")
}
