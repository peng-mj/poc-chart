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
)

// PQCClient represents a PQC client.
type PQCClient struct {
	identityKeypair *crypto.MLDSAKeyPair
	myIDHash       []byte
	relayURL        string
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

// Connect initiates a connection to a peer.
func (c *PQCClient) Connect(targetIDHash []byte) (*SecureChannel, error) {
	// Connect to relay
	ws, _, err := websocket.DefaultDialer.Dial(c.relayURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial relay: %w", err)
	}

	conn := transport.NewWebSocketConn(ws)

	// Phase 1: KEM Handshake
	handshake := protocol.NewKEMHandshake(true)
	request, err := handshake.Initiate()
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := protocol.SendFragmented(conn, request, protocol.MsgHandshakeRequest, 1400); err != nil {
		conn.Close()
		return nil, err
	}

	// Receive agree
	flag, agreeData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if flag != protocol.MsgHandshakeAgree {
		conn.Close()
		return nil, errors.New("unexpected message type")
	}

	finishData, err := handshake.HandleAgree(agreeData)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := protocol.SendFragmented(conn, finishData, protocol.MsgHandshakeFinish, 1400); err != nil {
		conn.Close()
		return nil, err
	}

	// Derive session key
	sessionKey, err := handshake.DeriveSessionKey()
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Channel binding
	channelBinding := append(handshake.MyKEMPublicKey(), handshake.PeerPubkey()...)

	// Phase 2: Identity Verification
	idExchange := identity.NewIdentityExchange(sessionKey, c.identityKeypair, targetIDHash)

	// Send identity
	if err := idExchange.SendIdentity(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Receive challenge, send signature
	flag, challengeEnc, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if flag != protocol.MsgChallenge {
		conn.Close()
		return nil, errors.New("unexpected message type")
	}

	sessionID := sessionKey // Use session key as session ID
	sigResponse, err := idExchange.HandleChallenge(challengeEnc, channelBinding, sessionID)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := protocol.SendFragmented(conn, sigResponse, protocol.MsgSignatureResponse, 1400); err != nil {
		conn.Close()
		return nil, err
	}

	// Receive peer identity
	flag, peerIdentity, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if flag != protocol.MsgIdentityMessage {
		conn.Close()
		return nil, errors.New("unexpected message type")
	}

	peerChallenge, err := idExchange.HandlePeerIdentity(peerIdentity)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := protocol.SendFragmented(conn, peerChallenge, protocol.MsgChallenge, 1400); err != nil {
		conn.Close()
		return nil, err
	}

	// Receive peer signature
	flag, peerSig, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if flag != protocol.MsgSignatureResponse {
		conn.Close()
		return nil, errors.New("unexpected message type")
	}

	verified, err := idExchange.VerifyResponse(peerSig, peerChallenge, channelBinding, sessionID)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !verified {
		conn.Close()
		return nil, errors.New("identity verification failed")
	}

	log.Println("双向验证通过！管道已建立")
	return NewSecureChannel(ws, sessionKey), nil
}

// IDHash returns the client's ID hash.
func (c *PQCClient) IDHash() []byte {
	return c.myIDHash
}

// SecureChannel represents an encrypted channel.
type SecureChannel struct {
	conn       *websocket.Conn
	sessionKey []byte
}

// NewSecureChannel creates a new secure channel.
func NewSecureChannel(conn *websocket.Conn, sessionKey []byte) *SecureChannel {
	return &SecureChannel{
		conn:       conn,
		sessionKey: sessionKey,
	}
}

// Send sends an encrypted message.
func (sc *SecureChannel) Send(data []byte) error {
	encrypted, err := crypto.AESGCMEncrypt(sc.sessionKey, data)
	if err != nil {
		return err
	}
	return sc.conn.WriteMessage(websocket.BinaryMessage, encrypted)
}

// Recv receives and decrypts a message.
func (sc *SecureChannel) Recv() ([]byte, error) {
	_, data, err := sc.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	return crypto.AESGCMDecrypt(sc.sessionKey, data)
}

// Close closes the secure channel.
func (sc *SecureChannel) Close() error {
	return sc.conn.Close()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: pqc-client <command>")
		fmt.Println("Commands:")
		fmt.Println("  generate    Generate a new identity keypair")
		fmt.Println("  show-id     Show your ID hash for sharing")
		fmt.Println("  connect     Connect to a peer")
		fmt.Println("  help        Show this help message")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "generate":
		generateIdentity()
	case "show-id":
		showIdentity()
	case "connect":
		if len(os.Args) < 4 {
			fmt.Println("Usage: pqc-client connect <relay-url> <peer-id-hash>")
			os.Exit(1)
		}
		relayURL := os.Args[2]
		peerIDHash := os.Args[3]
		connectToPeer(relayURL, peerIDHash)
	case "help":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
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

func connectToPeer(relayURL, peerIDHashStr string) {
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

	// Reload to get both keys properly
	publicKey, _, _ := store.LoadDSAKeypair("default")

	keypair := &crypto.MLDSAKeyPair{
		Public:  publicKey,
		Private: privateKey,
	}

	peerIDHash, err := identity.ParseIDHash(peerIDHashStr)
	if err != nil {
		log.Fatalf("Invalid peer ID hash: %v", err)
	}

	client := NewPQCClient(keypair, relayURL)

	fmt.Printf("Connecting to peer %s...\n", peerIDHashStr)
	channel, err := client.Connect(peerIDHash)
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer channel.Close()

	fmt.Println("Connected securely!")

	// Simple interactive mode
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

func readPassword(prompt string) string {
	fmt.Print(prompt)
	var password string
	fmt.Scanln(&password)
	return password
}

func printHelp() {
	fmt.Println("PQC Client - Post-Quantum Cryptography Secure Communication")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  generate              Generate a new ML-DSA identity keypair")
	fmt.Println("  show-id               Display your ID hash for sharing")
	fmt.Println("  connect <url> <hash>  Connect to a peer via relay")
	fmt.Println("  help                  Show this help message")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  pqc-client generate")
	fmt.Println("  pqc-client show-id")
	fmt.Println("  pqc-client connect ws://localhost:8080 abc123...")
}
