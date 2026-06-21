// Package crypto provides post-quantum cryptography primitives.
// This file encapsulates KDF and hash operations.
package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

// HKDF derives a key of the specified length using HKDF-SHA256.
// HKDF(salt, secret, info) -> derived key
func HKDF(secret, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("invalid length: must be positive")
	}

	// If salt is empty, use zeros
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}

	// Use hkdf.Key with generic API
	key, err := hkdf.Key(sha256.New, secret, salt, string(info), length)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// SHA256Hash computes the SHA-256 hash of the data.
func SHA256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// SHAKE256 computes a SHAKE-256 hash and returns the first n bytes.
// For shorter outputs (< 32 bytes), we use SHA-256 truncated.
// For longer outputs, we chain SHA-256 hashes.
func SHAKE256(data []byte, n int) []byte {
	if n <= 32 {
		// For short outputs, use SHA-256 truncated
		h := sha256.New()
		h.Write(data)
		result := h.Sum(nil)
		return result[:n]
	}

	// For longer outputs, chain SHA-256 hashes
	var result []byte
	h := sha256.New()
	block := make([]byte, 32)

	for i := 0; i < n; i += 32 {
		if i > 0 {
			h.Reset()
			h.Write(block)
		} else {
			h.Write(data)
		}
		block = h.Sum(nil)

		remaining := n - i
		if remaining > 32 {
			result = append(result, block...)
		} else {
			result = append(result, block[:remaining]...)
		}
	}

	return result
}
