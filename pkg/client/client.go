package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/identity"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
	"github.com/mj/pqc-chart-tool/pkg/transport"
)

// PQCClient represents a PQC client capable of initiating and accepting
// handshakes over WebSocket.
type PQCClient struct {
	identityKeypair *crypto.MLDSAKeyPair
	myIDHash        []byte
	fragmentBuffer  *protocol.FragmentBuffer
}

// NewPQCClient creates a new PQC client with the given identity keypair.
func NewPQCClient(identityKeypair *crypto.MLDSAKeyPair) *PQCClient {
	myIDHash := identity.ComputeIDHash(identityKeypair.Public)
	return &PQCClient{
		identityKeypair: identityKeypair,
		myIDHash:        myIDHash,
		fragmentBuffer:  protocol.NewFragmentBuffer(5 * time.Minute),
	}
}

// dialTimeout is the maximum time to wait when dialing a WebSocket.
const dialTimeout = 10 * time.Second

// Connect initiates a WebSocket connection to a peer.
//
// The method performs two phases:
//  1. Opens a handshake WebSocket, runs the KEM + identity-verification
//     handshake, receives a session token, then closes the handshake WS.
//  2. Opens a fresh message WebSocket using the session token.
//
// The returned SecureChannel wraps the message WebSocket transport.
func (c *PQCClient) Connect(wsURL string, targetIDHash []byte) (*SecureChannel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	// ---- Phase 1: Handshake WebSocket ----
	handshakeURL := wsURL + transport.HandshakeWSEndpoint
	handshakeTr, err := transport.WSDial(ctx, handshakeURL)
	if err != nil {
		return nil, fmt.Errorf("dial handshake WS: %w", err)
	}

	sessionKey, err := c.runHandshakeInitiator(handshakeTr, targetIDHash)
	if err != nil {
		_ = handshakeTr.Close()
		return nil, err
	}

	token, err := c.receiveSessionToken(handshakeTr, sessionKey)
	if err != nil {
		_ = handshakeTr.Close()
		return nil, err
	}

	_ = handshakeTr.Close()

	// ---- Phase 2: Message WebSocket ----
	messageURL := fmt.Sprintf("%s%s?session=%s", wsURL, transport.MessageWSEndpoint, token)
	messageTr, err := transport.WSDial(ctx, messageURL)
	if err != nil {
		return nil, fmt.Errorf("dial message WS: %w", err)
	}

	return NewSecureChannel(messageTr, sessionKey), nil
}

// receiveSessionToken reads the encrypted session token from the handshake
// transport, decrypts it with the session key, and returns the raw token.
func (c *PQCClient) receiveSessionToken(tr protocol.Transport, sessionKey []byte) (string, error) {
	flag, tokenData, err := c.fragmentBuffer.ReceiveFragmented(tr)
	if err != nil {
		return "", fmt.Errorf("receive session token: %w", err)
	}
	if flag != protocol.MsgSessionToken {
		return "", fmt.Errorf("unexpected message type %d, want session token", flag)
	}

	tokenMsg, err := protocol.DeserializeSessionTokenMsg(tokenData)
	if err != nil {
		return "", fmt.Errorf("deserialize session token: %w", err)
	}

	tokenBytes, err := crypto.AESGCMDecrypt(sessionKey, tokenMsg.EncryptedToken)
	if err != nil {
		return "", fmt.Errorf("decrypt session token: %w", err)
	}

	return string(tokenBytes), nil
}

// runHandshakeInitiator performs the full handshake as the initiator
// (KEM key exchange + bidirectional identity verification) and returns
// the derived session key.
func (c *PQCClient) runHandshakeInitiator(conn protocol.Transport, targetIDHash []byte) ([]byte, error) {
	handshake := protocol.NewKEMHandshake(true)
	request, err := handshake.Initiate()
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, request, protocol.MsgHandshakeRequest, 1400); err != nil {
		return nil, err
	}

	flag, agreeData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgHandshakeAgree {
		return nil, errors.New("unexpected message type")
	}

	finishData, err := handshake.HandleAgree(agreeData)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, finishData, protocol.MsgHandshakeFinish, 1400); err != nil {
		return nil, err
	}

	sessionKey, err := handshake.DeriveSessionKey()
	if err != nil {
		return nil, err
	}

	channelBinding := handshake.ChannelBinding()
	idExchange := identity.NewIdentityExchange(sessionKey, c.identityKeypair, targetIDHash)

	// Phase 1: Initiator proves identity to responder
	if err := idExchange.SendIdentity(conn); err != nil {
		return nil, err
	}

	flag, challengeEnc, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgChallenge {
		return nil, errors.New("unexpected message type")
	}

	sigData, err := idExchange.HandleChallenge(challengeEnc, channelBinding, sessionKey)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, sigData, protocol.MsgSignatureResponse, 1400); err != nil {
		return nil, err
	}

	// Phase 2: Responder proves identity to initiator
	flag, peerIdentityData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgIdentityMessage {
		return nil, errors.New("unexpected message type")
	}

	peerIdentityMsg, err := protocol.DeserializeIdentityMsg(peerIdentityData)
	if err != nil {
		return nil, err
	}

	peerChallenge, err := idExchange.HandlePeerIdentity(peerIdentityMsg.PublicKeyEncrypted)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, peerChallenge, protocol.MsgChallenge, 1400); err != nil {
		return nil, err
	}

	flag, peerSig, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgSignatureResponse {
		return nil, errors.New("unexpected message type")
	}

	verified, err := idExchange.VerifyResponse(peerSig, channelBinding, sessionKey)
	if err != nil {
		return nil, err
	}

	if !verified {
		return nil, errors.New("identity verification failed")
	}

	return sessionKey, nil
}

// HandshakeResponder performs the full handshake as the responder
// (KEM key exchange + bidirectional identity verification) and returns
// the derived session key. This is called by the server's handshake
// handler for each incoming handshake WebSocket.
func (c *PQCClient) HandshakeResponder(conn protocol.Transport, targetIDHash []byte, acceptAny bool) ([]byte, error) {
	handshake := protocol.NewKEMHandshake(false)

	flag, requestData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgHandshakeRequest {
		return nil, errors.New("unexpected message type")
	}

	agreeData, err := handshake.HandleRequest(requestData)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, agreeData, protocol.MsgHandshakeAgree, 1400); err != nil {
		return nil, err
	}

	flag, finishData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgHandshakeFinish {
		return nil, errors.New("unexpected message type")
	}

	if err := handshake.HandleFinish(finishData); err != nil {
		return nil, err
	}

	sessionKey, err := handshake.DeriveSessionKey()
	if err != nil {
		return nil, err
	}

	channelBinding := handshake.ChannelBinding()

	var peerIDHash []byte
	if !acceptAny {
		peerIDHash = targetIDHash
	}
	idExchange := identity.NewIdentityExchange(sessionKey, c.identityKeypair, peerIDHash)

	flag, peerIdentityData, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgIdentityMessage {
		return nil, errors.New("unexpected message type")
	}

	peerIdentityMsg, err := protocol.DeserializeIdentityMsg(peerIdentityData)
	if err != nil {
		return nil, err
	}

	peerChallenge, err := idExchange.HandlePeerIdentity(peerIdentityMsg.PublicKeyEncrypted)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, peerChallenge, protocol.MsgChallenge, 1400); err != nil {
		return nil, err
	}

	flag, sigResponse, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgSignatureResponse {
		return nil, errors.New("unexpected message type")
	}

	verified, err := idExchange.VerifyResponse(sigResponse, channelBinding, sessionKey)
	if err != nil {
		return nil, err
	}

	if !verified {
		return nil, errors.New("identity verification failed")
	}

	if err := idExchange.SendIdentity(conn); err != nil {
		return nil, err
	}

	flag, challengeEnc, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgChallenge {
		return nil, errors.New("unexpected message type")
	}

	sigData, err := idExchange.HandleChallenge(challengeEnc, channelBinding, sessionKey)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, sigData, protocol.MsgSignatureResponse, 1400); err != nil {
		return nil, err
	}

	return sessionKey, nil
}

// IDHash returns the client's ID hash.
func (c *PQCClient) IDHash() []byte {
	return c.myIDHash
}
