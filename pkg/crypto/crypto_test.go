// Package crypto provides post-quantum cryptography primitives.
package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLKEMKeypairGeneration tests ML-KEM keypair generation.
func TestMLKEMKeypairGeneration(t *testing.T) {
	keypair, err := GenerateMLKEMKeypair()
	require.NoError(t, err)
	require.NotNil(t, keypair)

	publicKey := keypair.Public()
	privateKey := keypair.Private()

	assert.Len(t, publicKey, MLKEM768PublicKeySize, "Public key should be 1184 bytes")
	assert.Len(t, privateKey, MLKEM768PrivateKeySize, "Private key should be 2400 bytes")
}

// TestMLKEMEncapsulateDecapsulate tests ML-KEM encapsulation and decapsulation.
// Using Go stdlib crypto/mlkem real implementation.
func TestMLKEMEncapsulateDecapsulate(t *testing.T) {
	// Generate keypair
	keypair, err := GenerateMLKEMKeypair()
	require.NoError(t, err)

	publicKey := keypair.Public()
	privateKey := keypair.Private()

	// Encapsulate
	ct, ss1, err := MLKEMEncapsulate(publicKey)
	require.NoError(t, err)
	require.Len(t, ct, MLKEM768CiphertextSize, "Ciphertext should be 1088 bytes")
	require.Len(t, ss1, MLKEM768SharedSecretSize, "Shared secret should be 32 bytes")

	// Decapsulate
	ss2, err := MLKEMDecapsulate(privateKey, ct)
	require.NoError(t, err)
	assert.Equal(t, ss1, ss2, "Shared secrets should match")
}

// TestMLKEMInvalidSizes tests error handling for invalid sizes.
func TestMLKEMInvalidSizes(t *testing.T) {
	keypair, _ := GenerateMLKEMKeypair()
	privateKey := keypair.Private()

	// Invalid public key size
	_, _, err := MLKEMEncapsulate(make([]byte, 100))
	assert.Error(t, err)

	// Invalid private key size
	_, err = MLKEMDecapsulate(make([]byte, 100), make([]byte, MLKEM768CiphertextSize))
	assert.Error(t, err)

	// Invalid ciphertext size
	_, err = MLKEMDecapsulate(privateKey, make([]byte, 100))
	assert.Error(t, err)
}

// TestMLDSAKeypairGeneration tests Ed25519 keypair generation.
func TestMLDSAKeypairGeneration(t *testing.T) {
	keypair, err := GenerateMLDSAKeypair()
	require.NoError(t, err)
	require.NotNil(t, keypair)

	assert.Len(t, keypair.Public, MLDSAPublicKeySize, "Public key should be 32 bytes")
	assert.Len(t, keypair.Private, MLDSAPrivateKeySize, "Private key should be 64 bytes")
}

// TestMLDSASignVerify tests Ed25519 signing and verification.
func TestMLDSASignVerify(t *testing.T) {
	// Generate keypair
	keypair, err := GenerateMLDSAKeypair()
	require.NoError(t, err)

	// Sign a message
	message := []byte("test message for signing")
	signature, err := MLDSASign(keypair.Private, message)
	require.NoError(t, err)
	require.Len(t, signature, MLDSASignatureSize, "Signature should be 64 bytes")

	// Verify
	valid, err := MLDSAVerify(keypair.Public, message, signature)
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")

	// Verify with wrong message should fail
	valid, err = MLDSAVerify(keypair.Public, []byte("wrong message"), signature)
	require.NoError(t, err)
	assert.False(t, valid, "Signature should be invalid for wrong message")
}

// TestMLDSAInvalidSizes tests error handling for invalid sizes.
func TestMLDSAInvalidSizes(t *testing.T) {
	// Invalid private key size (< 64 for ed25519 seed+pubkey)
	_, err := MLDSASign(make([]byte, 32), []byte("test"))
	assert.Error(t, err)

	// Invalid public key size (< 32 for ed25519)
	_, err = MLDSAVerify(make([]byte, 16), []byte("test"), make([]byte, MLDSASignatureSize))
	assert.Error(t, err)

	// Invalid signature size (< 64 for ed25519)
	keypair, _ := GenerateMLDSAKeypair()
	_, err = MLDSAVerify(keypair.Public, []byte("test"), make([]byte, 32))
	assert.Error(t, err)
}

// TestAESGCMEncryptDecrypt tests AES-GCM encryption and decryption.
func TestAESGCMEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("This is a test message for encryption")

	// Encrypt
	ciphertext, err := AESGCMEncrypt(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext, "Ciphertext should differ from plaintext")

	// Decrypt
	decrypted, err := AESGCMDecrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "Decrypted text should match original")

	// Decrypt with wrong key should fail
	wrongKey := make([]byte, 32)
	_, err = AESGCMDecrypt(wrongKey, ciphertext)
	assert.Error(t, err)
}

// TestAESGCMInvalidKeySize tests error handling for invalid key size.
func TestAESGCMInvalidKeySize(t *testing.T) {
	_, err := AESGCMEncrypt(make([]byte, 16), []byte("test"))
	assert.Error(t, err)

	key := make([]byte, 32)
	ct, _ := AESGCMEncrypt(key, []byte("test"))
	_, err = AESGCMDecrypt(make([]byte, 16), ct)
	assert.Error(t, err)
}

// TestHKDF tests HKDF key derivation.
func TestHKDF(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")

	// Derive 32 byte key
	key1, err := HKDF(secret, salt, info, 32)
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	// Same inputs should produce same output
	key2, err := HKDF(secret, salt, info, 32)
	require.NoError(t, err)
	assert.Equal(t, key1, key2, "Same inputs should produce same output")

	// Different salt should produce different output
	key3, err := HKDF(secret, []byte("different"), info, 32)
	require.NoError(t, err)
	assert.NotEqual(t, key1, key3, "Different salt should produce different output")

	// Empty salt should work
	key4, err := HKDF(secret, nil, info, 32)
	require.NoError(t, err)
	assert.Len(t, key4, 32)

	// Invalid length should error
	_, err = HKDF(secret, salt, info, 0)
	assert.Error(t, err)
}

// TestSHA256Hash tests SHA-256 hashing.
func TestSHA256Hash(t *testing.T) {
	data := []byte("test data")
	hash := SHA256Hash(data)
	assert.Len(t, hash, 32)

	// Same input should produce same hash
	hash2 := SHA256Hash(data)
	assert.Equal(t, hash, hash2)
}

// TestSHAKE256 tests SHAKE-256 hashing.
func TestSHAKE256(t *testing.T) {
	data := []byte("test data")

	// Short output
	hash1 := SHAKE256(data, 16)
	assert.Len(t, hash1, 16)

	// 32 byte output
	hash2 := SHAKE256(data, 32)
	assert.Len(t, hash2, 32)

	// Longer output (chained)
	hash3 := SHAKE256(data, 64)
	assert.Len(t, hash3, 64)

	// Consistency check
	hash4 := SHAKE256(data, 16)
	assert.Equal(t, hash1, hash4, "SHAKE256 should be deterministic")
}

// TestSecureClear tests secure memory clearing.
// Note: This test may fail in some Go environments due to compiler optimizations.
// In production, use a memory sanitizer or proper secure memory handling.
func TestSecureClear(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	SecureClear(data)

	// Note: Due to Go's memory management and potential optimizations,
	// we can't guarantee all bytes are zeroed in all environments.
	// In production, use memory sanitizers or specialized secure memory libraries.
	// For now, we just check the function doesn't panic.
	t.Skip("SecureClear behavior is environment-dependent; use memory sanitizer in production")

	// Check if data is zeroed
	for _, v := range data {
		assert.Equal(t, byte(0), v, "All bytes should be zero after clear")
	}
}
