// Package identity handles key storage and identity management.
package identity

import (
	"os"
	"path/filepath"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
)

// KeyStore manages persistent key storage with encrypted private keys.
type KeyStore struct {
	storePath string
	encKey    []byte
}

// NewKeyStore creates a new key store with the given path and master password.
func NewKeyStore(storePath string, masterPassword []byte) (*KeyStore, error) {
	// Derive encryption key from master password
	encKey, err := crypto.HKDF(masterPassword, nil, []byte("KeyStore-v1"), 32)
	if err != nil {
		return nil, err
	}

	// Ensure directory exists
	if err := os.MkdirAll(storePath, 0700); err != nil {
		return nil, err
	}

	return &KeyStore{
		storePath: storePath,
		encKey:    encKey,
	}, nil
}

// SaveDSAKeypair saves an ML-DSA keypair to the store.
func (ks *KeyStore) SaveDSAKeypair(keyID string, publicKey, privateKey []byte) error {
	// Save public key in plaintext (for sharing)
	pubPath := filepath.Join(ks.storePath, keyID+".pub")
	if err := os.WriteFile(pubPath, publicKey, 0644); err != nil {
		return err
	}

	// Encrypt and save private key
	encPriv, err := crypto.AESGCMEncrypt(ks.encKey, privateKey)
	if err != nil {
		return err
	}

	privPath := filepath.Join(ks.storePath, keyID+".priv")
	return os.WriteFile(privPath, encPriv, 0600)
}

// LoadDSAKeypair loads an ML-DSA keypair from the store.
func (ks *KeyStore) LoadDSAKeypair(keyID string) (publicKey, privateKey []byte, err error) {
	pubPath := filepath.Join(ks.storePath, keyID+".pub")
	privPath := filepath.Join(ks.storePath, keyID+".priv")

	publicKey, err = os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, err
	}

	encPriv, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err = crypto.AESGCMDecrypt(ks.encKey, encPriv)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

// HasKeypair checks if a keypair exists in the store.
func (ks *KeyStore) HasKeypair(keyID string) bool {
	pubPath := filepath.Join(ks.storePath, keyID+".pub")
	_, err := os.ReadFile(pubPath)
	return err == nil
}

// DeleteKeypair removes a keypair from the store.
func (ks *KeyStore) DeleteKeypair(keyID string) error {
	pubPath := filepath.Join(ks.storePath, keyID+".pub")
	privPath := filepath.Join(ks.storePath, keyID+".priv")

	// Remove private key first
	if err := os.Remove(privPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Remove public key
	if err := os.Remove(pubPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// ListKeypairs returns all key IDs in the store.
func (ks *KeyStore) ListKeypairs() ([]string, error) {
	entries, err := os.ReadDir(ks.storePath)
	if err != nil {
		return nil, err
	}

	var keyIDs []string
	seen := make(map[string]bool)

	for _, entry := range entries {
		name := entry.Name()
		// Only process .pub files
		if filepath.Ext(name) == ".pub" {
			keyID := name[:len(name)-4]
			if !seen[keyID] {
				keyIDs = append(keyIDs, keyID)
				seen[keyID] = true
			}
		}
	}

	return keyIDs, nil
}

// Close clears the encryption key from memory.
func (ks *KeyStore) Close() {
	crypto.SecureClear(ks.encKey)
	ks.encKey = nil
}
