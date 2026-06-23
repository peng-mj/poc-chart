// Package transport provides direct TCP transport for PQC communication.
package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DefaultPort is the default port for direct connections.
const DefaultPort = 18080

// DirectServer is a TCP server for direct peer connections.
type DirectServer struct {
	listener  net.Listener
	OnConnect func(net.Conn)
}

// Addr returns the server's listening address
func (s *DirectServer) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// NewDirectServer creates a new direct server.
func NewDirectServer() *DirectServer {
	return &DirectServer{}
}

// Start starts the server on the specified address.
func (s *DirectServer) Start(addr string) error {
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	slog.Info("direct server listening", "addr", addr)

	go s.acceptConnections()
	return nil
}

// acceptConnections accepts incoming connections.
func (s *DirectServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("accept error", "error", err)
			}
			return
		}

		remoteAddr := conn.RemoteAddr().String()
		slog.Info("peer connected", "remote_addr", remoteAddr)

		if s.OnConnect != nil {
			s.OnConnect(conn)
		} else {
			conn.Close()
		}
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
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

// NewDirectConn creates a new direct connection.
func NewDirectConn(conn net.Conn) *DirectConn {
	return &DirectConn{
		conn: conn,
	}
}

// Send sends a message through the connection.
func (dc *DirectConn) Send(data []byte) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.closed || dc.conn == nil {
		return errors.New("connection closed")
	}

	_, err := dc.conn.Write(data)
	return err
}

// Recv receives a message from the connection.
func (dc *DirectConn) Recv() ([]byte, error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.closed || dc.conn == nil {
		return nil, errors.New("connection closed")
	}

	dc.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, 8192)
	n, err := dc.conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// Close closes the connection.
func (dc *DirectConn) Close() error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.closed {
		return nil
	}

	dc.closed = true
	if dc.conn != nil {
		return dc.conn.Close()
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

	if dc.conn != nil && !dc.closed {
		return dc.conn.RemoteAddr().String()
	}
	return ""
}
