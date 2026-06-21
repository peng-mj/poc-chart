// Package transport provides WebSocket transport for PQC communication.
package transport

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConn implements the Transport interface using gorilla/websocket.
type WebSocketConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// NewWebSocketConn creates a new WebSocket transport.
func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{conn: conn}
}

// Send sends a message through the WebSocket.
func (ws *WebSocketConn) Send(data []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.conn == nil {
		return errors.New("connection closed")
	}

	return ws.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Recv receives a message from the WebSocket.
func (ws *WebSocketConn) Recv() ([]byte, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.conn == nil {
		return nil, errors.New("connection closed")
	}

	// Set read deadline for timeout handling
	ws.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	msgType, data, err := ws.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if msgType != websocket.BinaryMessage {
		return nil, fmt.Errorf("unexpected message type: %d", msgType)
	}

	return data, nil
}

// Close closes the WebSocket connection.
func (ws *WebSocketConn) Close() error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.conn == nil {
		return nil
	}

	err := ws.conn.Close()
	ws.conn = nil
	return err
}

// IsClosed returns whether the connection is closed.
func (ws *WebSocketConn) IsClosed() bool {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.conn == nil
}
