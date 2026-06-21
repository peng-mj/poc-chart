// Package crypto provides post-quantum cryptography primitives.
// This file encapsulates signature operations using Ed25519.
// NOTE: Ed25519 is used as a temporary replacement for ML-DSA (FIPS 204).
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

// Ed25519KeyPair represents an Ed25519 key pair.
// This is used as a replacement for ML-DSA until the Go stdlib exposes ML-DSA publicly.
type Ed25519KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// Ed25519 constants (matching the standard ed25519 sizes)
const (
	Ed25519SeedSize      = 32
	Ed25519PublicKeySize = 32
	Ed25519PrivateKeySize = 64 // seed + public key
	Ed25519SignatureSize = 64
)

// GenerateEd25519Keypair generates a new Ed25519 key pair.
func GenerateEd25519Keypair() (*Ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Ed25519KeyPair{
		Public:  publicKey,
		Private: privateKey,
	}, nil
}

// Ed25519Sign signs the given message using the private key.
func Ed25519Sign(privateKey, message []byte) (signature []byte, err error) {
	if len(privateKey) < Ed25519PrivateKeySize {
		return nil, errors.New("invalid private key size: expected 64 bytes")
	}

	sig := ed25519.Sign(privateKey, message)
	return sig, nil
}

// Ed25519Verify verifies the signature of the message using the public key.
func Ed25519Verify(publicKey, message, signature []byte) (bool, error) {
	if len(publicKey) < Ed25519PublicKeySize {
		return false, errors.New("invalid public key size: expected 32 bytes")
	}

	if len(signature) < Ed25519SignatureSize {
		return false, errors.New("invalid signature size: expected 64 bytes")
	}

	valid := ed25519.Verify(publicKey, message, signature)
	return valid, nil
}

// Legacy aliases for compatibility with existing code.
// These will be removed once ML-DSA is available in Go stdlib.

// MLDSAKeyPair is an alias for Ed25519KeyPair.
type MLDSAKeyPair = Ed25519KeyPair

// MLDSA constants (aliased from Ed25519)
const (
	MLDSASeedSize      = Ed25519SeedSize
	MLDSAPublicKeySize  = Ed25519PublicKeySize
	MLDSAPrivateKeySize = Ed25519PrivateKeySize
	MLDSASignatureSize = Ed25519SignatureSize
)

// GenerateMLDSAKeypair is an alias for GenerateEd25519Keypair.
func GenerateMLDSAKeypair() (*MLDSAKeyPair, error) {
	return GenerateEd25519Keypair()
}

// MLDSASign is an alias for Ed25519Sign.
func MLDSASign(privateKey, message []byte) (signature []byte, err error) {
	return Ed25519Sign(privateKey, message)
}

// MLDSAVerify is an alias for Ed25519Verify.
func MLDSAVerify(publicKey, message, signature []byte) (bool, error) {
	return Ed25519Verify(publicKey, message, signature)
}
