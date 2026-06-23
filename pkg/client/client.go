package client

import (
	"errors"
	"fmt"
	"net"

	"github.com/mj/pqc-chart-tool/pkg/crypto"
	"github.com/mj/pqc-chart-tool/pkg/identity"
	"github.com/mj/pqc-chart-tool/pkg/protocol"
	"github.com/mj/pqc-chart-tool/pkg/transport"
)

// PQCClient represents a PQC client.
type PQCClient struct {
	identityKeypair *crypto.MLDSAKeyPair
	myIDHash        []byte
	directAddr      string
	fragmentBuffer  *protocol.FragmentBuffer
	acceptAny       bool
}

// NewPQCClientDirect creates a new PQC client for direct TCP connections.
func NewPQCClientDirect(identityKeypair *crypto.MLDSAKeyPair, directAddr string, acceptAny bool) *PQCClient {
	myIDHash := identity.ComputeIDHash(identityKeypair.Public)
	return &PQCClient{
		identityKeypair: identityKeypair,
		directAddr:      directAddr,
		myIDHash:        myIDHash,
		fragmentBuffer:  protocol.NewFragmentBuffer(5 * 60 * 1000000000),
		acceptAny:       acceptAny,
	}
}

// Connect initiates a TCP connection to a peer.
func (c *PQCClient) Connect(targetIDHash []byte) (*SecureChannel, error) {
	var conn protocol.Transport

	if c.directAddr != "" {
		tcpConn, err := net.Dial("tcp", c.directAddr)
		if err != nil {
			return nil, fmt.Errorf("dial TCP: %w", err)
		}
		conn = transport.NewDirectConn(tcpConn)
	} else {
		return nil, errors.New("no connection address specified")
	}

	channel, err := c.performHandshake(conn, targetIDHash)
	if err != nil {
		if closer, ok := conn.(interface{ Close() error }); ok {
			closer.Close()
		}
		return nil, err
	}
	return channel, nil
}

// Accept handles an incoming TCP connection.
func (c *PQCClient) Accept(conn protocol.Transport, targetIDHash []byte, acceptAny bool) (*SecureChannel, error) {
	channel, err := c.performHandshakeResponder(conn, targetIDHash, acceptAny)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return channel, nil
}

// performHandshake performs the handshake as initiator.
func (c *PQCClient) performHandshake(conn protocol.Transport, targetIDHash []byte) (*SecureChannel, error) {
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

	channelBinding := append(handshake.MyKEMPublicKey(), handshake.PeerPubkey()...)
	idExchange := identity.NewIdentityExchange(sessionKey, c.identityKeypair, targetIDHash)

	if err := idExchange.SendIdentity(conn); err != nil {
		return nil, err
	}

	flag, peerIdentity, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgIdentityMessage {
		return nil, errors.New("unexpected message type")
	}

	peerChallenge, err := idExchange.HandlePeerIdentity(peerIdentity)
	if err != nil {
		return nil, err
	}

	if err := protocol.SendFragmented(conn, peerChallenge, protocol.MsgChallenge, 1400); err != nil {
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

	flag, peerSig, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgSignatureResponse {
		return nil, errors.New("unexpected message type")
	}

	verified, err := idExchange.VerifyResponse(peerSig, peerChallenge, channelBinding, sessionKey)
	if err != nil {
		return nil, err
	}

	if !verified {
		return nil, errors.New("identity verification failed")
	}

	return NewSecureChannel(conn, sessionKey), nil
}

// performHandshakeResponder performs the handshake as responder.
func (c *PQCClient) performHandshakeResponder(conn protocol.Transport, targetIDHash []byte, acceptAny bool) (*SecureChannel, error) {
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

	channelBinding := append(handshake.MyKEMPublicKey(), handshake.PeerPubkey()...)

	var peerIDHash []byte
	if !acceptAny {
		peerIDHash = targetIDHash
	}
	idExchange := identity.NewIdentityExchange(sessionKey, c.identityKeypair, peerIDHash)

	flag, peerIdentity, err := c.fragmentBuffer.ReceiveFragmented(conn)
	if err != nil {
		return nil, err
	}
	if flag != protocol.MsgIdentityMessage {
		return nil, errors.New("unexpected message type")
	}

	peerChallenge, err := idExchange.HandlePeerIdentity(peerIdentity)
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

	verified, err := idExchange.VerifyResponse(sigResponse, peerChallenge, channelBinding, sessionKey)
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

	return NewSecureChannel(conn, sessionKey), nil
}

// IDHash returns the client's ID hash.
func (c *PQCClient) IDHash() []byte {
	return c.myIDHash
}