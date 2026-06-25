// Package identity handles key storage and identity management.
// This file provides identity verification utilities.
package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
)

// IDHashSize is the size of the ID hash in bytes.
const IDHashSize = 32

// ComputeIDHash computes the SHAKE-256 hash of a public key for use as an ID.
func ComputeIDHash(publicKey []byte) []byte {
	return crypto.SHAKE256(publicKey, IDHashSize)
}

// FormatIDHash formats an ID hash as a hexadecimal string.
func FormatIDHash(hash []byte) string {
	return hex.EncodeToString(hash)
}

// ParseIDHash parses a hexadecimal ID hash string.
func ParseIDHash(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// IdentityExchange handles the identity verification phase.
type IdentityExchange struct {
	sessionKey     []byte
	myDSAKeypair   *crypto.MLDSAKeyPair
	peerIDHash     []byte
	peerDSAPubkey  []byte
	challengeNonce []byte // plaintext nonce we issued (for VerifyResponse)
	isVerified     bool
	mu             sync.Mutex
}

// NewIdentityExchange creates a new identity exchange instance.
func NewIdentityExchange(sessionKey []byte, myDSAKeypair *crypto.MLDSAKeyPair, peerIDHash []byte) *IdentityExchange {
	return &IdentityExchange{
		sessionKey:    sessionKey,
		myDSAKeypair:  myDSAKeypair,
		peerIDHash:    peerIDHash,
	}
}

// SendIdentity sends our ML-DSA public key (encrypted).
func (e *IdentityExchange) SendIdentity(transport protocol.Transport) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	encrypted, err := crypto.AESGCMEncrypt(e.sessionKey, e.myDSAKeypair.Public)
	if err != nil {
		return err
	}

	msg := &protocol.IdentityMsg{PublicKeyEncrypted: encrypted}
	return protocol.SendFragmented(transport, msg.Serialize(), protocol.MsgIdentityMessage, 1400)
}

// HandlePeerIdentity handles the peer's public key and returns a challenge.
func (e *IdentityExchange) HandlePeerIdentity(encryptedPub []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	pubBytes, err := crypto.AESGCMDecrypt(e.sessionKey, encryptedPub)
	if err != nil {
		return nil, err
	}

	// Verify the hash matches the expected peer ID hash (if specified)
	if e.peerIDHash != nil {
		computedHash := ComputeIDHash(pubBytes)
		if subtle.ConstantTimeCompare(computedHash, e.peerIDHash) != 1 {
			return nil, errors.New("peer ID hash mismatch")
		}
	}

	e.peerDSAPubkey = pubBytes

	// Generate a challenge nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	e.challengeNonce = nonce

	encrypted, err := crypto.AESGCMEncrypt(e.sessionKey, nonce)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// HandleChallenge handles a challenge nonce and returns a signature.
func (e *IdentityExchange) HandleChallenge(encryptedNonce []byte, channelBinding []byte, sessionID []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	nonce, err := crypto.AESGCMDecrypt(e.sessionKey, encryptedNonce)
	if err != nil {
		return nil, err
	}

	// Sign: nonce + channel_binding + session_id
	message := append(nonce, channelBinding...)
	message = append(message, sessionID...)

	signature, err := crypto.MLDSASign(e.myDSAKeypair.Private, message)
	if err != nil {
		return nil, err
	}

	encrypted, err := crypto.AESGCMEncrypt(e.sessionKey, signature)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// VerifyResponse verifies the signature response from the peer.
// It uses the challenge nonce stored from HandlePeerIdentity.
func (e *IdentityExchange) VerifyResponse(encryptedSig []byte, channelBinding []byte, sessionID []byte) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	sig, err := crypto.AESGCMDecrypt(e.sessionKey, encryptedSig)
	if err != nil {
		return false, err
	}

	// Reconstruct the signed message using the plaintext nonce
	message := append(e.challengeNonce, channelBinding...)
	message = append(message, sessionID...)

	valid, err := crypto.MLDSAVerify(e.peerDSAPubkey, message, sig)
	if err != nil {
		return false, err
	}

	if valid {
		e.isVerified = true
	}

	return valid, nil
}

// IsVerified returns whether the peer's identity has been verified.
func (e *IdentityExchange) IsVerified() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isVerified
}

// NonceCache prevents replay attacks on nonce challenges.
type NonceCache struct {
	cache map[string]time.Time
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewNonceCache creates a new nonce cache.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{
		cache: make(map[string]time.Time),
		ttl:   ttl,
	}
}

// CheckAndAdd checks if a nonce has been used and adds it if not.
func (nc *NonceCache) CheckAndAdd(peerIDHash, nonce []byte) bool {
	key := string(append(peerIDHash, nonce...))
	now := time.Now()

	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Clean up expired entries periodically
	if len(nc.cache) > 1000 {
		for k, t := range nc.cache {
			if now.Sub(t) > nc.ttl {
				delete(nc.cache, k)
			}
		}
	}

	if _, exists := nc.cache[key]; exists {
		return false // Replay detected
	}

	nc.cache[key] = now
	return true
}
