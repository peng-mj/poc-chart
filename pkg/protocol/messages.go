// Package protocol implements the handshake and identity verification protocol.
package protocol

import (
	"encoding/binary"
	"errors"
)

// MessageFlag represents the type of message.
type MessageFlag byte

const (
	MsgHandshakeRequest   MessageFlag = 0x01
	MsgHandshakeAgree     MessageFlag = 0x02
	MsgHandshakeFinish    MessageFlag = 0x03
	MsgIdentityMessage    MessageFlag = 0x10
	MsgChallenge          MessageFlag = 0x11
	MsgSignatureResponse  MessageFlag = 0x12
)

// HandshakeRequest is the initial message sent by the initiator.
// Format: | flag (1B) | kem_pub_len (2B) | kem_pub (1184B) | suite_len (2B) | suite |
type HandshakeRequest struct {
	KEMPublicKey    []byte // ML-KEM-768 public key (1184 bytes)
	AlgorithmSuite string  // Algorithm suite identifier
}

// Serialize encodes the HandshakeRequest to bytes.
func (m *HandshakeRequest) Serialize() []byte {
	suiteBytes := []byte(m.AlgorithmSuite)
	totalLen := 1 + 2 + len(m.KEMPublicKey) + 2 + len(suiteBytes)
	buf := make([]byte, 0, totalLen)

	buf = append(buf, byte(MsgHandshakeRequest))
	binary.BigEndian.PutUint16(buf[len(buf):len(buf)+2], uint16(len(m.KEMPublicKey)))
	buf = append(buf, make([]byte, 2)...)
	buf = append(buf, m.KEMPublicKey...)

	binary.BigEndian.PutUint16(buf[len(buf):len(buf)+2], uint16(len(suiteBytes)))
	buf = append(buf, make([]byte, 2)...)
	buf = append(buf, suiteBytes...)

	// Fix the length fields
	offset := 1
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(m.KEMPublicKey)))
	offset += 2 + len(m.KEMPublicKey)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(suiteBytes)))

	return buf
}

// DeserializeHandshakeRequest decodes bytes to a HandshakeRequest.
func DeserializeHandshakeRequest(data []byte) (*HandshakeRequest, error) {
	if len(data) < 1+2 {
		return nil, errors.New("data too short")
	}

	if MessageFlag(data[0]) != MsgHandshakeRequest {
		return nil, errors.New("invalid message flag")
	}

	offset := 1
	kemPubLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(kemPubLen)+2 {
		return nil, errors.New("data too short for public key")
	}

	kemPub := data[offset : offset+int(kemPubLen)]
	offset += int(kemPubLen)

	suiteLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(suiteLen) {
		return nil, errors.New("data too short for suite")
	}

	suite := string(data[offset : offset+int(suiteLen)])

	return &HandshakeRequest{
		KEMPublicKey:    kemPub,
		AlgorithmSuite: suite,
	}, nil
}

// HandshakeAgree is sent by the responder in response to HandshakeRequest.
// Format: | flag (1B) | kem_pub_len (2B) | kem_pub (1184B) | ct_len (2B) | ct (1088B) | suite_len (2B) | suite |
type HandshakeAgree struct {
	KEMPublicKey    []byte // ML-KEM-768 public key (1184 bytes)
	PeerCiphertext  []byte // Encapsulation ciphertext (1088 bytes)
	AlgorithmSuite  string
}

// Serialize encodes the HandshakeAgree to bytes.
func (m *HandshakeAgree) Serialize() []byte {
	suiteBytes := []byte(m.AlgorithmSuite)
	buf := make([]byte, 0, 1+2+len(m.KEMPublicKey)+2+len(m.PeerCiphertext)+2+len(suiteBytes))

	buf = append(buf, byte(MsgHandshakeAgree))
	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(m.KEMPublicKey)))
	buf = append(buf, m.KEMPublicKey...)

	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(m.PeerCiphertext)))
	buf = append(buf, m.PeerCiphertext...)

	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(suiteBytes)))
	buf = append(buf, suiteBytes...)

	return buf
}

// DeserializeHandshakeAgree decodes bytes to a HandshakeAgree.
func DeserializeHandshakeAgree(data []byte) (*HandshakeAgree, error) {
	if len(data) < 1+2 {
		return nil, errors.New("data too short")
	}

	if MessageFlag(data[0]) != MsgHandshakeAgree {
		return nil, errors.New("invalid message flag")
	}

	offset := 1
	kemPubLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(kemPubLen)+2 {
		return nil, errors.New("data too short for public key")
	}

	kemPub := data[offset : offset+int(kemPubLen)]
	offset += int(kemPubLen)

	ctLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(ctLen)+2 {
		return nil, errors.New("data too short for ciphertext")
	}

	ciphertext := data[offset : offset+int(ctLen)]
	offset += int(ctLen)

	suiteLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(suiteLen) {
		return nil, errors.New("data too short for suite")
	}

	suite := string(data[offset : offset+int(suiteLen)])

	return &HandshakeAgree{
		KEMPublicKey:   kemPub,
		PeerCiphertext: ciphertext,
		AlgorithmSuite: suite,
	}, nil
}

// HandshakeFinish is sent by the initiator to complete the KEM handshake.
// Format: | flag (1B) | ct_len (2B) | ct (1088B) |
type HandshakeFinish struct {
	Ciphertext []byte // Encapsulation ciphertext (1088 bytes)
}

// Serialize encodes the HandshakeFinish to bytes.
func (m *HandshakeFinish) Serialize() []byte {
	buf := make([]byte, 0, 1+2+len(m.Ciphertext))

	buf = append(buf, byte(MsgHandshakeFinish))
	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(m.Ciphertext)))
	buf = append(buf, m.Ciphertext...)

	return buf
}

// DeserializeHandshakeFinish decodes bytes to a HandshakeFinish.
func DeserializeHandshakeFinish(data []byte) (*HandshakeFinish, error) {
	if len(data) < 1+2 {
		return nil, errors.New("data too short")
	}

	if MessageFlag(data[0]) != MsgHandshakeFinish {
		return nil, errors.New("invalid message flag")
	}

	offset := 1
	ctLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(ctLen) {
		return nil, errors.New("data too short for ciphertext")
	}

	ciphertext := data[offset : offset+int(ctLen)]

	return &HandshakeFinish{Ciphertext: ciphertext}, nil
}

// IdentityMsg carries the encrypted ML-DSA public key.
// Format: | flag (1B) | pub_len (2B) | pub (~1312B) |
type IdentityMsg struct {
	PublicKeyEncrypted []byte
}

// Serialize encodes the IdentityMsg to bytes.
func (m *IdentityMsg) Serialize() []byte {
	buf := make([]byte, 0, 1+2+len(m.PublicKeyEncrypted))

	buf = append(buf, byte(MsgIdentityMessage))
	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(m.PublicKeyEncrypted)))
	buf = append(buf, m.PublicKeyEncrypted...)

	return buf
}

// DeserializeIdentityMsg decodes bytes to an IdentityMsg.
func DeserializeIdentityMsg(data []byte) (*IdentityMsg, error) {
	if len(data) < 1+2 {
		return nil, errors.New("data too short")
	}

	if MessageFlag(data[0]) != MsgIdentityMessage {
		return nil, errors.New("invalid message flag")
	}

	offset := 1
	pubLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(pubLen) {
		return nil, errors.New("data too short for public key")
	}

	pub := data[offset : offset+int(pubLen)]

	return &IdentityMsg{PublicKeyEncrypted: pub}, nil
}

// Challenge carries an encrypted nonce for signing.
// Format: | flag (1B) | nonce_len (2B) | nonce (32B) | tag (16B) |
// Note: The tag is included in the encrypted payload from AES-GCM
type Challenge struct {
	EncryptedNonce []byte
}

// Serialize encodes the Challenge to bytes.
func (m *Challenge) Serialize() []byte {
	buf := make([]byte, 0, 1+2+len(m.EncryptedNonce))

	buf = append(buf, byte(MsgChallenge))
	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(m.EncryptedNonce)))
	buf = append(buf, m.EncryptedNonce...)

	return buf
}

// DeserializeChallenge decodes bytes to a Challenge.
func DeserializeChallenge(data []byte) (*Challenge, error) {
	if len(data) < 1+2 {
		return nil, errors.New("data too short")
	}

	if MessageFlag(data[0]) != MsgChallenge {
		return nil, errors.New("invalid message flag")
	}

	offset := 1
	nonceLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(nonceLen) {
		return nil, errors.New("data too short for nonce")
	}

	nonce := data[offset : offset+int(nonceLen)]

	return &Challenge{EncryptedNonce: nonce}, nil
}

// SignatureResponse carries an encrypted ML-DSA signature.
// Format: | flag (1B) | sig_len (2B) | sig (~2420B) |
type SignatureResponse struct {
	EncryptedSignature []byte
}

// Serialize encodes the SignatureResponse to bytes.
func (m *SignatureResponse) Serialize() []byte {
	buf := make([]byte, 0, 1+2+len(m.EncryptedSignature))

	buf = append(buf, byte(MsgSignatureResponse))
	buf = append(buf, make([]byte, 2)...)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(m.EncryptedSignature)))
	buf = append(buf, m.EncryptedSignature...)

	return buf
}

// DeserializeSignatureResponse decodes bytes to a SignatureResponse.
func DeserializeSignatureResponse(data []byte) (*SignatureResponse, error) {
	if len(data) < 1+2 {
		return nil, errors.New("data too short")
	}

	if MessageFlag(data[0]) != MsgSignatureResponse {
		return nil, errors.New("invalid message flag")
	}

	offset := 1
	sigLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if len(data) < offset+int(sigLen) {
		return nil, errors.New("data too short for signature")
	}

	sig := data[offset : offset+int(sigLen)]

	return &SignatureResponse{EncryptedSignature: sig}, nil
}
