// Package transport provides WebSocket transport for PQC communication.
//
// This file implements the two-phase WebSocket architecture:
//   - Phase 1 (/ws/handshake): a long-lived WebSocket for KEM key exchange
//     and identity verification. After the handshake completes the server
//     issues a one-time, TTL-bound session token.
//   - Phase 2 (/ws/message): a fresh WebSocket opened with the session token
//     for encrypted message exchange.
package transport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
)

const (
	// DefaultWSPort is the default port for WebSocket connections.
	DefaultWSPort = 18080

	// HandshakeWSEndpoint is the WebSocket endpoint for the handshake phase.
	HandshakeWSEndpoint = "/ws/handshake"

	// MessageWSEndpoint is the WebSocket endpoint for the message phase.
	MessageWSEndpoint = "/ws/message"

	// SessionTokenSize is the number of random bytes in a session token.
	SessionTokenSize = 32

	// DefaultTokenTTL is how long a session token remains valid.
	DefaultTokenTTL = 30 * time.Second
)

// readWriteTimeout is used for individual WS read/write operations.
const readWriteTimeout = 5 * time.Minute

// -----------------------------------------------------------------------
// WSTransport — implements protocol.Transport over a WebSocket connection
// -----------------------------------------------------------------------

// WSTransport wraps a websocket.Conn to satisfy the protocol.Transport
// interface. Each Send transmits one binary WS message; each Recv reads
// one complete binary WS message.
type WSTransport struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	closed bool
}

// NewWSTransport wraps an existing websocket.Conn.
func NewWSTransport(conn *websocket.Conn) *WSTransport {
	return &WSTransport{conn: conn}
}

// Send writes data as a single binary WebSocket message.
func (t *WSTransport) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("transport closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), readWriteTimeout)
	defer cancel()

	return t.conn.Write(ctx, websocket.MessageBinary, data)
}

// Recv reads a single binary WebSocket message.
func (t *WSTransport) Recv() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, errors.New("transport closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), readWriteTimeout)
	defer cancel()

	_, data, err := t.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Close cleanly closes the underlying WebSocket connection.
func (t *WSTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	return t.conn.Close(websocket.StatusNormalClosure, "")
}

// -----------------------------------------------------------------------
// SessionStore — one-time, TTL-bound token → sessionKey mapping
// -----------------------------------------------------------------------

// SessionStore holds session tokens created during the handshake phase,
// mapping each to the derived session key. Tokens are consumed exactly
// once and expire after a configurable TTL.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*pendingSession
	ttl      time.Duration
}

type pendingSession struct {
	sessionKey []byte
	expiry     time.Time
}

// NewSessionStore creates a SessionStore with the given token TTL.
func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*pendingSession),
		ttl:      ttl,
	}
}

// Create generates a new session token, stores the mapping, and returns
// the hex-encoded token string.
func (s *SessionStore) Create(sessionKey []byte) (string, error) {
	raw := make([]byte, SessionTokenSize)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	token := hex.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[token] = &pendingSession{
		sessionKey: sessionKey,
		expiry:     time.Now().Add(s.ttl),
	}
	return token, nil
}

// Consume validates the token (exists, not expired) and removes it
// atomically. Returns the associated session key. A second call with
// the same token always fails (one-time use).
func (s *SessionStore) Consume(token string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ps, ok := s.sessions[token]
	if !ok {
		return nil, errors.New("invalid or unknown session token")
	}

	delete(s.sessions, token)

	if time.Now().After(ps.expiry) {
		return nil, errors.New("session token expired")
	}

	return ps.sessionKey, nil
}

// cleanup removes expired entries. Caller must hold the mutex.
func (s *SessionStore) cleanup() {
	now := time.Now()
	for token, ps := range s.sessions {
		if now.After(ps.expiry) {
			delete(s.sessions, token)
		}
	}
}

// Len returns the number of pending sessions (for diagnostics / testing).
func (s *SessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// -----------------------------------------------------------------------
// WSServer — WebSocket server with handshake + message endpoints
// -----------------------------------------------------------------------

// HandshakeHandlerFunc is called when a handshake WebSocket connects.
// It must run the KEM + identity-verification handshake over the given
// transport and return the derived session key.
type HandshakeHandlerFunc func(protocol.Transport) ([]byte, error)

// SecureChannelFunc is called when a message WebSocket connects after
// successful token validation. It receives a fresh transport bound to
// the derived session key.
type SecureChannelFunc func(transport protocol.Transport, sessionKey []byte)

// WSServer is a WebSocket server exposing two endpoints:
//
//   /ws/handshake — upgraded to WS, handed to HandshakeHandler, then the
//     server sends an encrypted session token and closes the connection.
//
//   /ws/message?session=<token> — validates and consumes the token, then
//     upgrades to WS and calls OnSecureChannel with the new transport.
type WSServer struct {
	server          *http.Server
	sessions        *SessionStore
	HandshakeHandler HandshakeHandlerFunc
	OnSecureChannel  SecureChannelFunc
}

// NewWSServer creates a WSServer with the default token TTL.
func NewWSServer() *WSServer {
	return &WSServer{
		sessions: NewSessionStore(DefaultTokenTTL),
	}
}

// Start begins serving WebSocket connections on the given address.
func (s *WSServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc(HandshakeWSEndpoint, s.handleHandshakeWS)
	mux.HandleFunc(MessageWSEndpoint, s.handleMessageWS)

	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	slog.Info("WebSocket server listening", "addr", addr)
	return s.server.ListenAndServe()
}

// Stop gracefully shuts down the server.
func (s *WSServer) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// Addr returns the server's configured address.
func (s *WSServer) Addr() string {
	if s.server != nil {
		return s.server.Addr
	}
	return ""
}

// acceptWS upgrades an HTTP request to a WebSocket connection.
func acceptWS(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	return websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // CLI tool, not browser-origin restricted
	})
}

// handleHandshakeWS processes Phase 1: the handshake WebSocket.
func (s *WSServer) handleHandshakeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := acceptWS(w, r)
	if err != nil {
		slog.Error("handshake WS accept failed", "error", err)
		return
	}

	transport := NewWSTransport(conn)

	sessionKey, err := s.HandshakeHandler(transport)
	if err != nil {
		slog.Error("handshake handler failed", "error", err)
		_ = conn.Close(websocket.StatusInternalError, "handshake failed")
		return
	}

	token, err := s.sessions.Create(sessionKey)
	if err != nil {
		slog.Error("failed to create session token", "error", err)
		_ = conn.Close(websocket.StatusInternalError, "token creation failed")
		return
	}

	encToken, err := crypto.AESGCMEncrypt(sessionKey, []byte(token))
	if err != nil {
		slog.Error("failed to encrypt token", "error", err)
		_ = conn.Close(websocket.StatusInternalError, "encryption failed")
		return
	}

	msg := &protocol.SessionTokenMsg{EncryptedToken: encToken}
	if err := protocol.SendFragmented(transport, msg.Serialize(), protocol.MsgSessionToken, 1400); err != nil {
		slog.Error("failed to send session token", "error", err)
		_ = conn.Close(websocket.StatusInternalError, "send failed")
		return
	}

	_ = transport.Close()
	slog.Info("handshake completed, session token issued")
}

// handleMessageWS processes Phase 2: the message WebSocket.
func (s *WSServer) handleMessageWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("session")
	if token == "" {
		http.Error(w, "session token required", http.StatusUnauthorized)
		return
	}

	sessionKey, err := s.sessions.Consume(token)
	if err != nil {
		slog.Warn("message WS token validation failed", "error", err)
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return
	}

	conn, err := acceptWS(w, r)
	if err != nil {
		slog.Error("message WS accept failed", "error", err)
		return
	}

	transport := NewWSTransport(conn)

	slog.Info("message WS established")
	if s.OnSecureChannel != nil {
		s.OnSecureChannel(transport, sessionKey)
	}
}

// -----------------------------------------------------------------------
// WSDial — client-side dial helper
// -----------------------------------------------------------------------

// WSDial opens a WebSocket connection to the given URL and returns a
// WSTransport wrapping it.
func WSDial(ctx context.Context, url string) (*WSTransport, error) {
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		// CLI tool — no origin restrictions.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", url, err)
	}

	return NewWSTransport(conn), nil
}
