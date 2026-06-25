package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// 32-byte key valid for AES-256-GCM.
var testSessionKey = make([]byte, 32)

func TestSessionStoreCreateConsume(t *testing.T) {
	store := NewSessionStore(5 * time.Second)

	key := []byte("test-session-key-32-bytes-long!!")
	token, err := store.Create(key)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}
	if store.Len() != 1 {
		t.Fatalf("store should have 1 entry, got %d", store.Len())
	}

	got, err := store.Consume(token)
	if err != nil {
		t.Fatalf("Consume failed: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("got %q, want %q", string(got), string(key))
	}
	if store.Len() != 0 {
		t.Fatalf("store should be empty after consume, got %d", store.Len())
	}
}

func TestSessionStoreOneTimeUse(t *testing.T) {
	store := NewSessionStore(5 * time.Second)

	token, _ := store.Create([]byte("key"))

	if _, err := store.Consume(token); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}

	_, err := store.Consume(token)
	if err == nil {
		t.Fatal("second consume should fail")
	}
}

func TestSessionStoreUnknownToken(t *testing.T) {
	store := NewSessionStore(5 * time.Second)

	_, err := store.Consume("nonexistent")
	if err == nil {
		t.Fatal("consume of unknown token should fail")
	}
}

func TestSessionStoreExpired(t *testing.T) {
	store := NewSessionStore(50 * time.Millisecond)

	token, _ := store.Create([]byte("key"))

	time.Sleep(100 * time.Millisecond)

	_, err := store.Consume(token)
	if err == nil {
		t.Fatal("consume of expired token should fail")
	}
}

func TestWSServerFullFlow(t *testing.T) {
	addr := freeAddr(t)
	server := NewWSServer()

	handshakePayload := []byte("handshake-data")

	// HandshakeHandler: receive data, echo it, return known session key
	server.HandshakeHandler = func(tr protocol.Transport) ([]byte, error) {
		data, err := tr.Recv()
		if err != nil {
			return nil, err
		}
		if string(data) != string(handshakePayload) {
			t.Errorf("handshake got %q, want %q", string(data), string(handshakePayload))
		}
		if err := tr.Send(data); err != nil {
			return nil, err
		}
		return testSessionKey, nil
	}

	msgReceived := make(chan []byte, 1)

	server.OnSecureChannel = func(tr protocol.Transport, sessionKey []byte) {
		if string(sessionKey) != string(testSessionKey) {
			t.Errorf("got session key mismatch")
		}
		data, err := tr.Recv()
		if err != nil {
			t.Errorf("message WS recv: %v", err)
			return
		}
		msgReceived <- data
	}

	go func() {
		_ = server.Start(addr)
	}()
	defer server.Stop()
	time.Sleep(200 * time.Millisecond)

	ctx := context.Background()
	wsURL := "ws://" + addr

	// --- Phase 1: Handshake WS ---
	handshakeTr, err := WSDial(ctx, wsURL+HandshakeWSEndpoint)
	if err != nil {
		t.Fatalf("dial handshake: %v", err)
	}

	if err := handshakeTr.Send(handshakePayload); err != nil {
		t.Fatalf("send handshake data: %v", err)
	}

	echoed, err := handshakeTr.Recv()
	if err != nil {
		t.Fatalf("recv echo: %v", err)
	}
	if string(echoed) != string(handshakePayload) {
		t.Fatalf("echo mismatch: got %q", string(echoed))
	}

	// Receive the encrypted session token
	flag, tokenRaw, err := protocol.NewFragmentBuffer(30*time.Second).ReceiveFragmented(handshakeTr)
	if err != nil {
		t.Fatalf("recv token: %v", err)
	}
	if flag != protocol.MsgSessionToken {
		t.Fatalf("got flag %d, want %d", flag, protocol.MsgSessionToken)
	}
	tokenMsg, err := protocol.DeserializeSessionTokenMsg(tokenRaw)
	if err != nil {
		t.Fatalf("deserialize token msg: %v", err)
	}

	// Decrypt with the known session key
	tokenBytes, err := crypto.AESGCMDecrypt(testSessionKey, tokenMsg.EncryptedToken)
	if err != nil {
		t.Fatalf("decrypt token: %v", err)
	}
	token := string(tokenBytes)

	_ = handshakeTr.Close()

	// --- Phase 2: Message WS ---
	msgTr, err := WSDial(ctx, wsURL+MessageWSEndpoint+"?session="+token)
	if err != nil {
		t.Fatalf("dial message: %v", err)
	}
	defer msgTr.Close()

	testMsg := []byte("secure-message")
	if err := msgTr.Send(testMsg); err != nil {
		t.Fatalf("send message: %v", err)
	}

	select {
	case got := <-msgReceived:
		if string(got) != string(testMsg) {
			t.Fatalf("got %q, want %q", string(got), string(testMsg))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message WS")
	}
}

func TestWSServerInvalidToken(t *testing.T) {
	addr := freeAddr(t)

	server := NewWSServer()
	server.HandshakeHandler = func(tr protocol.Transport) ([]byte, error) {
		return testSessionKey, nil
	}
	server.OnSecureChannel = func(tr protocol.Transport, sessionKey []byte) {}

	go func() {
		_ = server.Start(addr)
	}()
	defer server.Stop()
	time.Sleep(200 * time.Millisecond)

	ctx := context.Background()
	_, err := WSDial(ctx, "ws://"+addr+MessageWSEndpoint+"?session=bogus")
	if err == nil {
		t.Fatal("dial with bogus token should fail")
	}
}
