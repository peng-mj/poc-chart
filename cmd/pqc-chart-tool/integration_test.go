package main

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/identity"
)

// TestIdentityStorage tests identity keystore functionality
func TestIdentityStorage(t *testing.T) {
	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "test_identity.enc")
	masterPassword := "test-password-123"

	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	store, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	if err := store.SaveDSAKeypair("default", keypair.Public, keypair.Private); err != nil {
		t.Fatalf("Failed to save keypair: %v", err)
	}
	store.Close()

	store2, err := identity.NewKeyStore(storePath, []byte(masterPassword))
	if err != nil {
		t.Fatalf("Failed to open keystore: %v", err)
	}

	publicKey, privateKey, err := store2.LoadDSAKeypair("default")
	if err != nil {
		t.Fatalf("Failed to load keypair: %v", err)
	}

	if !bytes.Equal(publicKey, keypair.Public) {
		t.Error("Loaded public key does not match")
	}

	if !bytes.Equal(privateKey, keypair.Private) {
		t.Error("Loaded private key does not match")
	}

	store2.Close()

	store3, err := identity.NewKeyStore(storePath, []byte("wrong-password"))
	if err != nil {
		t.Fatalf("Failed to open keystore with wrong password: %v", err)
	}

	_, _, err = store3.LoadDSAKeypair("default")
	if err == nil {
		t.Error("Should fail to load keypair with wrong password")
	}
	store3.Close()
}

// TestIDHash tests ID hash generation and formatting
func TestIDHash(t *testing.T) {
	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	idHash := identity.ComputeIDHash(keypair.Public)
	if len(idHash) != 32 {
		t.Errorf("ID hash should be 32 bytes, got %d", len(idHash))
	}

	formatted := identity.FormatIDHash(idHash)
	if len(formatted) != 64 {
		t.Errorf("Formatted ID hash should be 64 characters, got %d", len(formatted))
	}

	parsedIDHash, err := identity.ParseIDHash(formatted)
	if err != nil {
		t.Fatalf("Failed to parse ID hash: %v", err)
	}

	if !bytes.Equal(idHash, parsedIDHash) {
		t.Error("Parsed ID hash does not match original")
	}
}

// TestKeyGeneration tests cryptographic key generation
func TestKeyGeneration(t *testing.T) {
	t.Run("MLKEMKeypair", func(t *testing.T) {
		keypair, err := crypto.GenerateMLKEMKeypair()
		if err != nil {
			t.Fatalf("Failed to generate ML-KEM keypair: %v", err)
		}

		publicKey := keypair.Public()
		privateKey := keypair.Private()

		if len(publicKey) != crypto.MLKEM768PublicKeySize {
			t.Errorf("Public key should be %d bytes, got %d", crypto.MLKEM768PublicKeySize, len(publicKey))
		}

		if len(privateKey) != crypto.MLKEM768PrivateKeySize {
			t.Errorf("Private key should be %d bytes, got %d", crypto.MLKEM768PrivateKeySize, len(privateKey))
		}
	})

	t.Run("MLDSAKeypair", func(t *testing.T) {
		keypair, err := crypto.GenerateMLDSAKeypair()
		if err != nil {
			t.Fatalf("Failed to generate ML-DSA keypair: %v", err)
		}

		if len(keypair.Public) != crypto.MLDSAPublicKeySize {
			t.Errorf("Public key should be %d bytes, got %d", crypto.MLDSAPublicKeySize, len(keypair.Public))
		}

		if len(keypair.Private) != crypto.MLDSAPrivateKeySize {
			t.Errorf("Private key should be %d bytes, got %d", crypto.MLDSAPrivateKeySize, len(keypair.Private))
		}
	})
}

// TestEncapsulateDecapsulate tests KEM encapsulation/decapsulation
func TestEncapsulateDecapsulate(t *testing.T) {
	keypair, err := crypto.GenerateMLKEMKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKey := keypair.Public()
	privateKey := keypair.Private()

	ciphertext, sharedSecret1, err := crypto.MLKEMEncapsulate(publicKey)
	if err != nil {
		t.Fatalf("Encapsulation failed: %v", err)
	}

	if len(ciphertext) != crypto.MLKEM768CiphertextSize {
		t.Errorf("Ciphertext should be %d bytes, got %d", crypto.MLKEM768CiphertextSize, len(ciphertext))
	}

	if len(sharedSecret1) != crypto.MLKEM768SharedSecretSize {
		t.Errorf("Shared secret should be %d bytes, got %d", crypto.MLKEM768SharedSecretSize, len(sharedSecret1))
	}

	sharedSecret2, err := crypto.MLKEMDecapsulate(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulation failed: %v", err)
	}

	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Error("Shared secrets do not match")
	}
}

// TestSignVerify tests digital signature functionality
func TestSignVerify(t *testing.T) {
	keypair, err := crypto.GenerateMLDSAKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("Test message for signing")

	signature, err := crypto.MLDSASign(keypair.Private, message)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	if len(signature) != crypto.MLDSASignatureSize {
		t.Errorf("Signature should be %d bytes, got %d", crypto.MLDSASignatureSize, len(signature))
	}

	valid, err := crypto.MLDSAVerify(keypair.Public, message, signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !valid {
		t.Error("Signature should be valid")
	}

	valid, err = crypto.MLDSAVerify(keypair.Public, []byte("different message"), signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if valid {
		t.Error("Signature should be invalid for different message")
	}
}

// TestRandomDataGeneration tests random data generation utilities
func TestRandomDataGeneration(t *testing.T) {
	t.Run("RandomBytes", func(t *testing.T) {
		data1 := make([]byte, 32)
		data2 := make([]byte, 32)

		if _, err := rand.Read(data1); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}

		if _, err := rand.Read(data2); err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}

		if bytes.Equal(data1, data2) {
			t.Error("Random bytes should not be identical")
		}
	})
}
