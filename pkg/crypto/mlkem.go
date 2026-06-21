// Package crypto provides post-quantum cryptography primitives.
// This file encapsulates ML-KEM (FIPS 203) operations using Go stdlib.
package crypto

import (
	"crypto/mlkem"
	"errors"
)

// MLKEMKeyPair represents an ML-KEM-768 key pair.
type MLKEMKeyPair struct {
	DecapsulationKey *mlkem.DecapsulationKey768
	EncapsulationKey *mlkem.EncapsulationKey768
}

// GetPublic returns the encapsulation key bytes.
func (kp *MLKEMKeyPair) GetPublic() []byte {
	if kp.EncapsulationKey == nil {
		return nil
	}
	return kp.EncapsulationKey.Bytes()
}

// GetPrivate returns the decapsulation key bytes.
func (kp *MLKEMKeyPair) GetPrivate() []byte {
	if kp.DecapsulationKey == nil {
		return nil
	}
	return kp.DecapsulationKey.Bytes()
}

// Public is exported for compatibility with existing code.
func (kp *MLKEMKeyPair) Public() []byte {
	return kp.GetPublic()
}

// Private is exported for compatibility with existing code.
func (kp *MLKEMKeyPair) Private() []byte {
	return kp.GetPrivate()
}

// MLKEM constants (from crypto/mlkem package)
const (
	MLKEM768SeedSize         = mlkem.SeedSize
	MLKEM768PublicKeySize    = mlkem.EncapsulationKeySize768
	MLKEM768PrivateKeySize   = mlkem.SeedSize // DecapsulationKey is derived from seed
	MLKEM768CiphertextSize   = mlkem.CiphertextSize768
	MLKEM768SharedSecretSize = mlkem.SharedKeySize
)

// GenerateMLKEMKeypair generates a new ML-KEM-768 key pair.
func GenerateMLKEMKeypair() (*MLKEMKeyPair, error) {
	decapKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	return &MLKEMKeyPair{
		DecapsulationKey: decapKey,
		EncapsulationKey: decapKey.EncapsulationKey(),
	}, nil
}

// MLKEMEncapsulate encapsulates a shared secret using the peer's public key.
// Returns the ciphertext and the shared secret.
func MLKEMEncapsulate(peerPublicKeyBytes []byte) (ciphertext, sharedSecret []byte, err error) {
	encapKey, err := mlkem.NewEncapsulationKey768(peerPublicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, ciphertext = encapKey.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// MLKEMDecapsulate decapsulates the shared secret using the private key and ciphertext.
func MLKEMDecapsulate(privateKeyBytes, ciphertext []byte) (sharedSecret []byte, err error) {
	decapKey, err := mlkem.NewDecapsulationKey768(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) != mlkem.CiphertextSize768 {
		return nil, errors.New("invalid ciphertext size")
	}

	return decapKey.Decapsulate(ciphertext)
}
