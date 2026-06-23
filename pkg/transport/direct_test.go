// Package transport provides TCP transport tests
package transport

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDirectServer tests the direct TCP server functionality
func TestDirectServer(t *testing.T) {
	server := NewDirectServer()
	addr := "127.0.0.1:0"

	var serverErr error
	serverReady := make(chan struct{})
	var serverConn net.Conn

	// Set up server to accept one connection
	server.OnConnect = func(conn net.Conn) {
		serverConn = conn
		close(serverReady)
	}

	// Start server in goroutine
	go func() {
		serverErr = server.Start(addr)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, serverErr, "Server should start without error")

	// Get actual server address
	serverAddr := server.listener.Addr().String()

	// Connect client
	clientConn, err := net.Dial("tcp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Wait for server to accept connection
	select {
	case <-serverReady:
		t.Log("Server accepted connection")
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not accept connection in time")
	}

	// Test sending data from client to server
	testMessage := []byte("Hello from client")
	_, err = clientConn.Write(testMessage)
	require.NoError(t, err)

	// Test receiving data on server
	buf := make([]byte, 1024)
	n, err := serverConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testMessage, buf[:n], "Server should receive correct message")

	// Test sending data from server to client
	serverResponse := []byte("Hello from server")
	_, err = serverConn.Write(serverResponse)
	require.NoError(t, err)

	// Test receiving data on client
	clientBuf := make([]byte, 1024)
	n, err = clientConn.Read(clientBuf)
	require.NoError(t, err)
	assert.Equal(t, serverResponse, clientBuf[:n], "Client should receive correct response")

	// Clean up
	serverConn.Close()
	server.Stop()
}

// TestDirectConn tests the direct connection wrapper
func TestDirectConn(t *testing.T) {
	// Create a simple echo server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()
	serverReady := make(chan struct{})

	go func() {
		conn, err := listener.Accept()
		require.NoError(t, err)
		defer conn.Close()
		close(serverReady)

		// Echo back received data
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, err = conn.Write(buf[:n])
				require.NoError(t, err)
			}
		}
	}()

	// Connect client
	tcpConn, err := net.Dial("tcp", serverAddr)
	require.NoError(t, err)

	directConn := NewDirectConn(tcpConn)
	defer directConn.Close()

	// Wait for server to be ready
	<-serverReady

	// Test Send and Recv
	testMessage := []byte("Test message for DirectConn")
	err = directConn.Send(testMessage)
	require.NoError(t, err)

	received, err := directConn.Recv()
	require.NoError(t, err)
	assert.Equal(t, testMessage, received, "Should receive echoed message")

	// Test Close
	err = directConn.Close()
	require.NoError(t, err)
	assert.True(t, directConn.IsClosed(), "Connection should be closed")

	// Test Send on closed connection
	err = directConn.Send([]byte("Should fail"))
	assert.Error(t, err, "Send on closed connection should fail")

	// Test Recv on closed connection
	_, err = directConn.Recv()
	assert.Error(t, err, "Recv on closed connection should fail")
}

// TestDirectConnRemoteAddr tests RemoteAddr method
func TestDirectConnRemoteAddr(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().String()
	serverReady := make(chan struct{})

	go func() {
		conn, err := listener.Accept()
		require.NoError(t, err)
		defer conn.Close()
		close(serverReady)

		// Keep connection alive
		time.Sleep(100 * time.Millisecond)
	}()

	// Connect client
	tcpConn, err := net.Dial("tcp", serverAddr)
	require.NoError(t, err)

	directConn := NewDirectConn(tcpConn)
	defer directConn.Close()

	<-serverReady

	remoteAddr := directConn.RemoteAddr()
	assert.NotEmpty(t, remoteAddr, "RemoteAddr should not be empty")
	assert.Contains(t, remoteAddr, "127.0.0.1", "RemoteAddr should contain client IP")

	directConn.Close()
	remoteAddrAfterClose := directConn.RemoteAddr()
	assert.Empty(t, remoteAddrAfterClose, "RemoteAddr should be empty after close")
}

// TestMultipleConnections tests server handling multiple connections
func TestMultipleConnections(t *testing.T) {
	server := NewDirectServer()
	addr := "127.0.0.1:0"

	connectionCount := 0
	connReceived := make(chan net.Conn, 3)

	server.OnConnect = func(conn net.Conn) {
		connectionCount++
		connReceived <- conn
	}

	go func() {
		_ = server.Start(addr)
	}()

	time.Sleep(100 * time.Millisecond)
	serverAddr := server.listener.Addr().String()

	// Create multiple client connections
	var clients []net.Conn
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", serverAddr)
		require.NoError(t, err)
		clients = append(clients, conn)
	}

	// Wait for all connections to be accepted
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

	assert.Equal(t, 3, connectionCount, "Should have accepted 3 connections")

	// Clean up
	for _, conn := range clients {
		conn.Close()
	}
	server.Stop()
}