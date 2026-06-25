package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mj/pqc-chart-tool/pkg/client"
	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
	"github.com/mj/pqc-chart-tool/pkg/transport"
)

// TestWSFullHandshake tests the complete two-phase WebSocket flow:
// handshake WS (KEM + identity) → token → message WS → encrypted chat.
func TestWSFullHandshake(t *testing.T) {
	kp1, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	serverClient := client.NewPQCClient(kp1)
	server := transport.NewWSServer()

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)

	server.HandshakeHandler = func(conn protocol.Transport) ([]byte, error) {
		return serverClient.HandshakeResponder(conn, nil, true)
	}

	server.OnSecureChannel = func(tr protocol.Transport, sessionKey []byte) {
		defer wg.Done()
		ch := client.NewSecureChannel(tr, sessionKey)
		// Echo: receive a message, send it back
		msg, err := ch.Recv()
		if err != nil {
			serverErr = fmt.Errorf("server recv: %w", err)
			return
		}
		if err := ch.Send(msg); err != nil {
			serverErr = fmt.Errorf("server send: %w", err)
			return
		}
		_ = ch.Close()
	}

	go func() {
		_ = server.Start(addr)
	}()
	defer server.Stop()
	time.Sleep(200 * time.Millisecond)

	clientClient := client.NewPQCClient(kp2)
	wsURL := fmt.Sprintf("ws://%s", addr)

	ch, err := clientClient.Connect(wsURL, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer ch.Close()

	testMsg := []byte("hello-over-ws")
	if err := ch.Send(testMsg); err != nil {
		t.Fatalf("client send: %v", err)
	}

	resp, err := ch.Recv()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}

	if string(resp) != string(testMsg) {
		t.Fatalf("got %q, want %q", string(resp), string(testMsg))
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatal(serverErr)
	}
}
