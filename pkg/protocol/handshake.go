// Package protocol implements the handshake and identity verification protocol.
// This file implements the KEM handshake state machine.
package protocol

import (
	"errors"
	"sync"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
)

// HandshakeState represents the current state of the handshake.
type HandshakeState int

const (
	StateInit        HandshakeState = iota
	StateWaitAgree
	StateWaitFinish
	StateEstablished
	StateFailed
)

// String returns the string representation of the state.
func (s HandshakeState) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateWaitAgree:
		return "WAIT_AGREE"
	case StateWaitFinish:
		return "WAIT_FINISH"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// KEMHandshake implements the bidirectional ML-KEM handshake.
type KEMHandshake struct {
	state          HandshakeState
	isInitiator    bool
	myKEMKeypair   *crypto.MLKEMKeyPair
	myKEMPublicKey []byte // cached public key (survives keypair clearing)
	peerPubkey     []byte
	sharedSecrets  map[string][]byte
	mu             sync.Mutex
}

// NewKEMHandshake creates a new KEM handshake instance.
func NewKEMHandshake(isInitiator bool) *KEMHandshake {
	return &KEMHandshake{
		state:         StateInit,
		isInitiator:   isInitiator,
		sharedSecrets: make(map[string][]byte),
	}
}

// Initiate starts the handshake as the initiator.
func (h *KEMHandshake) Initiate() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var err error
	h.myKEMKeypair, err = crypto.GenerateMLKEMKeypair()
	if err != nil {
		return nil, err
	}
	h.myKEMPublicKey = h.myKEMKeypair.Public()

	msg := &HandshakeRequest{
		KEMPublicKey:    h.myKEMKeypair.Public(),
		AlgorithmSuite: "ML-KEM-768_AES-GCM",
	}

	h.state = StateWaitAgree
	return msg.Serialize(), nil
}

// HandleRequest handles a handshake request (responder).
func (h *KEMHandshake) HandleRequest(request []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	req, err := DeserializeHandshakeRequest(request)
	if err != nil {
		return nil, err
	}

	// Generate our temporary keypair
	h.myKEMKeypair, err = crypto.GenerateMLKEMKeypair()
	if err != nil {
		return nil, err
	}
	h.myKEMPublicKey = h.myKEMKeypair.Public()

	h.peerPubkey = req.KEMPublicKey

	// Encapsulate using peer's public key
	ciphertext, ssB2A, err := crypto.MLKEMEncapsulate(req.KEMPublicKey)
	if err != nil {
		return nil, err
	}
	h.sharedSecrets["ss_B2A"] = ssB2A

	msg := &HandshakeAgree{
		KEMPublicKey:   h.myKEMKeypair.Public(),
		PeerCiphertext: ciphertext,
		AlgorithmSuite: "ML-KEM-768_AES-GCM",
	}

	h.state = StateWaitFinish
	return msg.Serialize(), nil
}

// HandleAgree handles the agree message (initiator).
func (h *KEMHandshake) HandleAgree(agree []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != StateWaitAgree {
		return nil, errors.New("invalid state for HandleAgree")
	}

	agr, err := DeserializeHandshakeAgree(agree)
	if err != nil {
		return nil, err
	}

	// Encapsulate ctA
	ssB2A, err := crypto.MLKEMDecapsulate(h.myKEMKeypair.Private(), agr.PeerCiphertext)
	if err != nil {
		return nil, err
	}
	h.sharedSecrets["ss_B2A"] = ssB2A

	// Save peer's public key
	h.peerPubkey = agr.KEMPublicKey

	// Encapsulate using peer's public key
	ciphertext, ssA2B, err := crypto.MLKEMEncapsulate(agr.KEMPublicKey)
	if err != nil {
		return nil, err
	}
	h.sharedSecrets["ss_A2B"] = ssA2B

	msg := &HandshakeFinish{Ciphertext: ciphertext}
	h.state = StateEstablished
	return msg.Serialize(), nil
}

// HandleFinish handles the finish message (responder).
func (h *KEMHandshake) HandleFinish(finish []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != StateWaitFinish {
		return errors.New("invalid state for HandleFinish")
	}

	fin, err := DeserializeHandshakeFinish(finish)
	if err != nil {
		return err
	}

	// Decapsulate ctB
	ssA2B, err := crypto.MLKEMDecapsulate(h.myKEMKeypair.Private(), fin.Ciphertext)
	if err != nil {
		return err
	}
	h.sharedSecrets["ss_A2B"] = ssA2B

	h.state = StateEstablished

	// Securely clear the private key
	privateKey := h.myKEMKeypair.Private()
	crypto.SecureClear(privateKey)
	// Clear the reference to the keypair (the decapsulation key is internal to mlkem package)
	h.myKEMKeypair = nil

	return nil
}

// DeriveSessionKey derives the session key from shared secrets.
func (h *KEMHandshake) DeriveSessionKey() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != StateEstablished {
		return nil, errors.New("handshake not established")
	}

	ssB2A, ok1 := h.sharedSecrets["ss_B2A"]
	ssA2B, ok2 := h.sharedSecrets["ss_A2B"]
	if !ok1 || !ok2 {
		return nil, errors.New("shared secrets not available")
	}

	// Combine shared secrets
	master := append(ssB2A, ssA2B...)

	// Derive session key using HKDF
	info := []byte("ML-KEM-768-session-key-v1")
	return crypto.HKDF(master, nil, info, 32)
}

// State returns the current handshake state.
func (h *KEMHandshake) State() HandshakeState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// MyKEMPublicKey returns our temporary KEM public key.
func (h *KEMHandshake) MyKEMPublicKey() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.myKEMPublicKey
}

// ChannelBinding returns a canonical binding of both KEM public keys
// (initiator's key first, responder's key second). Both sides compute
// the identical value regardless of role.
func (h *KEMHandshake) ChannelBinding() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.isInitiator {
		return append(h.myKEMPublicKey, h.peerPubkey...)
	}
	return append(h.peerPubkey, h.myKEMPublicKey...)
}

// PeerPubkey returns the peer's temporary KEM public key.
func (h *KEMHandshake) PeerPubkey() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.peerPubkey
}

// SetState sets the handshake state (for testing).
func (h *KEMHandshake) SetState(state HandshakeState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = state
}
