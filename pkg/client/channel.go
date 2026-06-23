package client

import (
	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
)

// SecureChannel represents an encrypted channel.
type SecureChannel struct {
	transport  protocol.Transport
	sessionKey []byte
}

// NewSecureChannel creates a new secure channel.
func NewSecureChannel(transport protocol.Transport, sessionKey []byte) *SecureChannel {
	return &SecureChannel{
		transport:  transport,
		sessionKey: sessionKey,
	}
}

// Send sends an encrypted message.
func (sc *SecureChannel) Send(data []byte) error {
	encrypted, err := crypto.AESGCMEncrypt(sc.sessionKey, data)
	if err != nil {
		return err
	}
	return sc.transport.Send(encrypted)
}

// Recv receives and decrypts a message.
func (sc *SecureChannel) Recv() ([]byte, error) {
	data, err := sc.transport.Recv()
	if err != nil {
		return nil, err
	}
	return crypto.AESGCMDecrypt(sc.sessionKey, data)
}

// Close closes the secure channel.
func (sc *SecureChannel) Close() error {
	if closer, ok := sc.transport.(interface{ Close() error }); ok {
		return closer.Close()
	}
	crypto.SecureClear(sc.sessionKey)
	return nil
}