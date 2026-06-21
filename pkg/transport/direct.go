// Package transport provides direct TCP transport for PQC communication.
package transport

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// DefaultPort is the default port for direct connections.
const DefaultPort = 18080

// DirectServer is a TCP server for direct peer connections.
type DirectServer struct {
	listener  net.Listener
	upgrader  websocket.Upgrader
	OnConnect func(*websocket.Conn)
}

// NewDirectServer creates a new direct server.
func NewDirectServer() *DirectServer {
	return &DirectServer{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

// Start starts the server on the specified address.
func (s *DirectServer) Start(addr string) error {
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Printf("Direct server listening on %s", addr)

	go s.acceptConnections()
	return nil
}

// StartTLS starts the server with TLS.
func (s *DirectServer) StartTLS(addr string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	var ln net.Listener
	ln, err = tls.Listen("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = ln
	log.Printf("Direct TLS server listening on %s", addr)

	go s.acceptConnections()
	return nil
}

// acceptConnections accepts incoming connections.
func (s *DirectServer) acceptConnections() {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handleWebSocket(w, r)
		}),
	}

	if err := httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
		log.Printf("Server error: %v", err)
	}
}

// handleWebSocket handles WebSocket upgrade.
func (s *DirectServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	wsConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	remoteAddr := wsConn.RemoteAddr().String()
	log.Printf("Peer connected from %s", remoteAddr)

	if s.OnConnect != nil {
		s.OnConnect(wsConn)
	} else {
		wsConn.Close()
	}
}

// Stop stops the server.
func (s *DirectServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// DirectConn is a direct connection transport.
type DirectConn struct {
	wsConn *websocket.Conn
	mu     sync.Mutex
	closed bool
}

// NewDirectConn creates a new direct connection.
func NewDirectConn(wsConn *websocket.Conn) *DirectConn {
	return &DirectConn{
		wsConn: wsConn,
	}
}

// Send sends a message through the connection.
func (dc *DirectConn) Send(data []byte) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.closed || dc.wsConn == nil {
		return fmt.Errorf("connection closed")
	}

	return dc.wsConn.WriteMessage(websocket.BinaryMessage, data)
}

// Recv receives a message from the connection.
func (dc *DirectConn) Recv() ([]byte, error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.closed || dc.wsConn == nil {
		return nil, fmt.Errorf("connection closed")
	}

	dc.wsConn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	msgType, data, err := dc.wsConn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if msgType != websocket.BinaryMessage {
		return nil, fmt.Errorf("unexpected message type: %d", msgType)
	}

	return data, nil
}

// Close closes the connection.
func (dc *DirectConn) Close() error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.closed {
		return nil
	}

	dc.closed = true
	if dc.wsConn != nil {
		return dc.wsConn.Close()
	}
	return nil
}

// IsClosed returns whether the connection is closed.
func (dc *DirectConn) IsClosed() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.closed
}

// RemoteAddr returns the remote address.
func (dc *DirectConn) RemoteAddr() string {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.wsConn != nil {
		return dc.wsConn.RemoteAddr().String()
	}
	return ""
}
