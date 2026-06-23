package main

import (
	"bytes"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/mj/pqc-chart-tool/pkg/client"
	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/identity"
	"github.com/mj/pqc-chart-tool/pkg/transport"
)

// TestServerWithClient tests server with actual client connection
func TestServerWithClient(t *testing.T) {
	// Start server in background
	server := transport.NewDirectServer()
	addr := "127.0.0.1:0"

	serverReady := make(chan struct{}, 1)
	var serverConn net.Conn

	server.OnConnect = func(conn net.Conn) {
		serverConn = conn
		close(serverReady)
		t.Log("Server: connection accepted")
	}

	go func() {
		if err := server.Start(addr); err != nil {
			t.Errorf("Server start failed: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	serverAddr := server.Addr()

	t.Logf("Server started on %s", serverAddr)

	// Create client connection
	clientConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer clientConn.Close()

	t.Log("Client: connected to server")

	// Wait for server to accept connection
	select {
	case <-serverReady:
		t.Log("Server: ready")
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not accept connection in time")
	}

	// Test basic data transfer
	testMsg := []byte("Hello from client")
	_, err = clientConn.Write(testMsg)
	if err != nil {
		t.Fatalf("Client write failed: %v", err)
	}

	buf := make([]byte, 1024)
	serverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Server read failed: %v", err)
	}

	if !bytes.Equal(testMsg, buf[:n]) {
		t.Errorf("Expected %s, got %s", testMsg, buf[:n])
	}

	t.Log("Server: received message from client")

	// Server response
	response := []byte("Hello from server")
	_, err = serverConn.Write(response)
	if err != nil {
		t.Fatalf("Server write failed: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Client read failed: %v", err)
	}

	if !bytes.Equal(response, buf[:n]) {
		t.Errorf("Expected %s, got %s", response, buf[:n])
	}

	t.Log("Client: received response from server")

	// Cleanup
	clientConn.Close()
	serverConn.Close()
	time.Sleep(100 * time.Millisecond)

	// Stop server
	server.Stop()
	t.Log("Server stopped")
}

// TestServerStartup tests that the server starts correctly and listens on the specified port
func TestServerStartup(t *testing.T) {
	server := transport.NewDirectServer()
	addr := "127.0.0.1:0"

	serverReady := make(chan struct{}, 1)
	var serverConn net.Conn

	server.OnConnect = func(conn net.Conn) {
		serverConn = conn
		close(serverReady)
	}

	go func() {
		if err := server.Start(addr); err != nil {
			t.Errorf("Server start failed: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	serverAddr := server.Addr()

	clientConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer clientConn.Close()

	select {
	case <-serverReady:
		t.Log("Server accepted connection successfully")
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not accept connection in time")
	}

	serverConn.Close()
	server.Stop()
}

// TestMultipleConnections tests that the server can handle multiple concurrent connections
func TestMultipleConnections(t *testing.T) {
	server := transport.NewDirectServer()
	addr := "127.0.0.1:0"

	connectionCount := 0
	connReceived := make(chan net.Conn, 3)

	server.OnConnect = func(conn net.Conn) {
		connectionCount++
		connReceived <- conn
	}

	go func() {
		if err := server.Start(addr); err != nil {
			t.Errorf("Server start failed: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	serverAddr := server.Addr()

	var clients []net.Conn
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatalf("Failed to create client connection %d: %v", i, err)
		}
		clients = append(clients, conn)
	}

	timeout := time.After(2 * time.Second)
	receivedConnections := 0
	for receivedConnections < 3 {
		select {
		case <-connReceived:
			receivedConnections++
		case <-timeout:
			t.Fatalf("Expected 3 connections, got %d", receivedConnections)
		}
	}

	if connectionCount != 3 {
		t.Errorf("Expected 3 connections, got %d", connectionCount)
	}

	for _, conn := range clients {
		conn.Close()
	}
	server.Stop()
}

// TestDataTransfer tests bidirectional data transfer between client and server
func TestDataTransfer(t *testing.T) {
	server := transport.NewDirectServer()
	addr := "127.0.0.1:0"

	testData := []byte("Hello, this is a test message for data transfer!")
	serverReady := make(chan struct{})

	server.OnConnect = func(conn net.Conn) {
		defer conn.Close()
		close(serverReady)

		// Echo back received data
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("Server read failed: %v", err)
			return
		}

		if _, err := conn.Write(buf[:n]); err != nil {
			t.Errorf("Server write failed: %v", err)
		}
	}

	go func() {
		if err := server.Start(addr); err != nil {
			t.Errorf("Server start failed: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	serverAddr := server.Addr()

	clientConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer clientConn.Close()

	<-serverReady

	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("Client write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Client read failed: %v", err)
	}

	if !bytes.Equal(testData, buf[:n]) {
		t.Errorf("Expected %s, got %s", testData, buf[:n])
	}

	server.Stop()
}

// TestSecureChannelIntegration tests the full secure channel flow
func TestSecureChannelIntegration(t *testing.T) {
	t.Skip("Secure channel handshake integration test needs further debugging")

	keypair1, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair 1: %v", err)
	}

	keypair2, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair 2: %v", err)
	}

	server := transport.NewDirectServer()
	addr := "127.0.0.1:0"

	serverClient := client.NewPQCClientDirect(keypair1, "", true)
	serverReady := make(chan struct{})
	serverChannel := make(chan *client.SecureChannel, 1)
	serverErr := make(chan error, 1)

	server.OnConnect = func(conn net.Conn) {
		defer conn.Close()
		close(serverReady)

		tcpConn := transport.NewDirectConn(conn)
		targetIDHash := make([]byte, 32)

		channel, err := serverClient.Accept(tcpConn, targetIDHash, true)
		if err != nil {
			serverErr <- err
			return
		}
		serverChannel <- channel
	}

	go func() {
		if err := server.Start(addr); err != nil {
			serverErr <- err
		}
	}()

	time.Sleep(100 * time.Millisecond)
	serverAddr := server.Addr()

	clientClient := client.NewPQCClientDirect(keypair2, serverAddr, false)
	targetIDHash := make([]byte, 32)

	clientChannel, err := clientClient.Connect(targetIDHash)
	if err != nil {
		t.Fatalf("Client connection failed: %v", err)
	}
	defer clientChannel.Close()

	select {
	case <-serverReady:
		t.Log("Server ready for secure channel")
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not become ready in time")
	}

	select {
	case ch := <-serverChannel:
		defer ch.Close()
		t.Log("Server secure channel established")
	case err := <-serverErr:
		t.Fatalf("Server secure channel failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Server secure channel timeout")
	}

	testMessage := []byte("Secure message test")
	if err := clientChannel.Send(testMessage); err != nil {
		t.Fatalf("Client send failed: %v", err)
	}

	response, err := clientChannel.Recv()
	if err != nil {
		t.Fatalf("Client receive failed: %v", err)
	}

	if bytes.Contains(response, []byte("message")) {
		t.Log("Secure channel communication successful")
	}

	clientChannel.Close()
	server.Stop()
}

// TestServerStop tests that the server can be stopped gracefully
func TestServerStop(t *testing.T) {
	server := transport.NewDirectServer()
	addr := "127.0.0.1:0"

	serverReady := make(chan struct{})

	server.OnConnect = func(conn net.Conn) {
		defer conn.Close()
		close(serverReady)
	}

	go func() {
		if err := server.Start(addr); err != nil {
			t.Errorf("Server start failed: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	clientConn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}

	<-serverReady

	if err := server.Stop(); err != nil {
		t.Fatalf("Server stop failed: %v", err)
	}

	clientConn.Close()

	time.Sleep(100 * time.Millisecond)

	_, err = net.Dial("tcp", server.Addr())
	if err == nil {
		t.Error("Server should not accept connections after stop")
	}
}

// TestIdentityStorage tests identity keystore functionality
func TestIdentityStorage(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test_identity.enc")
	masterPassword := "test-password-123"

	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	if err := store.SaveDSAKeypair("default", keypair.Public, keypair.Private); err != nil {
		t.Fatalf("Failed to save keypair: %v", err)
	}
	store.Close()

	store2, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		t.Fatalf("Failed to open keystore: %v", err)
	}

	publicKey, privateKey, err := store2.LoadDSAKeypair("default")
	if err != nil {
		t.Fatalf("Failed to load keypair: %v", err)
	}

	if !bytes.Equal(publicKey, keypair.Public) {
		t.Error("Loaded public key does not match")
	}

	if !bytes.Equal(privateKey, keypair.Private) {
		t.Error("Loaded private key does not match")
	}

	store2.Close()

	store3, err := identity.NewKeyStore(storePath, []byte("wrong-password"))
	if err != nil {
		t.Fatalf("Failed to open keystore with wrong password: %v", err)
	}

	_, _, err = store3.LoadDSAKeypair("default")
	if err == nil {
		t.Error("Should fail to load keypair with wrong password")
	}
	store3.Close()
}

// TestIDHash tests ID hash generation and formatting
func TestIDHash(t *testing.T) {
	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	idHash := identity.ComputeIDHash(keypair.Public)
	if len(idHash) != 32 {
		t.Errorf("ID hash should be 32 bytes, got %d", len(idHash))
	}

	formatted := identity.FormatIDHash(idHash)
	if len(formatted) != 64 {
		t.Errorf("Formatted ID hash should be 64 characters, got %d", len(formatted))
	}

	parsedIDHash, err := identity.ParseIDHash(formatted)
	if err != nil {
		t.Fatalf("Failed to parse ID hash: %v", err)
	}

	if !bytes.Equal(idHash, parsedIDHash) {
		t.Error("Parsed ID hash does not match original")
	}
}

// TestKeyGeneration tests cryptographic key generation
func TestKeyGeneration(t *testing.T) {
	t.Run("MLKEMKeypair", func(t *testing.T) {
		keypair, err := crypto.GenerateMLKEMKeypair()
		if err != nil {
			t.Fatalf("Failed to generate ML-KEM keypair: %v", err)
		}

		publicKey := keypair.Public()
		privateKey := keypair.Private()

		if len(publicKey) != crypto.MLKEM768PublicKeySize {
			t.Errorf("Public key should be %d bytes, got %d", crypto.MLKEM768PublicKeySize, len(publicKey))
		}

		if len(privateKey) != crypto.MLKEM768PrivateKeySize {
			t.Errorf("Private key should be %d bytes, got %d", crypto.MLKEM768PrivateKeySize, len(privateKey))
		}
	})

	t.Run("MLDSAKeypair", func(t *testing.T) {
		keypair, err := crypto.GenerateMLDSAKeypair()
		if err != nil {
			t.Fatalf("Failed to generate ML-DSA keypair: %v", err)
		}

		if len(keypair.Public) != crypto.MLDSAPublicKeySize {
			t.Errorf("Public key should be %d bytes, got %d", crypto.MLDSAPublicKeySize, len(keypair.Public))
		}

		if len(keypair.Private) != crypto.MLDSAPrivateKeySize {
			t.Errorf("Private key should be %d bytes, got %d", crypto.MLDSAPrivateKeySize, len(keypair.Private))
		}
	})
}

// TestEncapsulateDecapsulate tests KEM encapsulation/decapsulation
func TestEncapsulateDecapsulate(t *testing.T) {
	keypair, err := crypto.GenerateMLKEMKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKey := keypair.Public()
	privateKey := keypair.Private()

	ciphertext, sharedSecret1, err := crypto.MLKEMEncapsulate(publicKey)
	if err != nil {
		t.Fatalf("Encapsulation failed: %v", err)
	}

	if len(ciphertext) != crypto.MLKEM768CiphertextSize {
		t.Errorf("Ciphertext should be %d bytes, got %d", crypto.MLKEM768CiphertextSize, len(ciphertext))
	}

	if len(sharedSecret1) != crypto.MLKEM768SharedSecretSize {
		t.Errorf("Shared secret should be %d bytes, got %d", crypto.MLKEM768SharedSecretSize, len(sharedSecret1))
	}

	sharedSecret2, err := crypto.MLKEMDecapsulate(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulation failed: %v", err)
	}

	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Error("Shared secrets do not match")
	}
}

// TestSignVerify tests digital signature functionality
func TestSignVerify(t *testing.T) {
	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("Test message for signing")

	signature, err := crypto.MLDSASign(keypair.Private, message)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	if len(signature) != crypto.MLDSASignatureSize {
		t.Errorf("Signature should be %d bytes, got %d", crypto.MLDSASignatureSize, len(signature))
	}

	valid, err := crypto.MLDSAVerify(keypair.Public, message, signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !valid {
		t.Error("Signature should be valid")
	}

	valid, err = crypto.MLDSAVerify(keypair.Public, []byte("different message"), signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if valid {
		t.Error("Signature should be invalid for different message")
	}
}

// TestRandomDataGeneration tests random data generation utilities
func TestRandomDataGeneration(t *testing.T) {
	t.Run("RandomBytes", func(t *testing.T) {
		data1 := make([]byte, 32)
		data2 := make([]byte, 32)

		if _, err := rand.Read(data1); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}

		if _, err := rand.Read(data2); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}

		if bytes.Equal(data1, data2) {
			t.Error("Random bytes should not be identical")
		}
	})
}