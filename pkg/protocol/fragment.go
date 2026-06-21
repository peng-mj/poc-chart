// Package protocol implements the handshake and identity verification protocol.
// This file handles message fragmentation for large messages.
package protocol

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"time"
)

// FragmentHeader is the header for fragmented messages (13 bytes).
type FragmentHeader struct {
	Flag   MessageFlag
	Index  uint16 // Fragment index (0-based)
	Total  uint16 // Total number of fragments
	MsgLen uint32 // Complete message length
	MsgID  uint32 // Message ID for reassembly
}

// MarshalBinary encodes the fragment header to bytes.
func (h *FragmentHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 13)
	buf[0] = byte(h.Flag)
	binary.BigEndian.PutUint16(buf[1:3], h.Index)
	binary.BigEndian.PutUint16(buf[3:5], h.Total)
	binary.BigEndian.PutUint32(buf[5:9], h.MsgLen)
	binary.BigEndian.PutUint32(buf[9:13], h.MsgID)
	return buf, nil
}

// UnmarshalBinary decodes bytes to a fragment header.
func (h *FragmentHeader) UnmarshalBinary(data []byte) error {
	if len(data) < 13 {
		return errors.New("invalid fragment header size")
	}
	h.Flag = MessageFlag(data[0])
	h.Index = binary.BigEndian.Uint16(data[1:3])
	h.Total = binary.BigEndian.Uint16(data[3:5])
	h.MsgLen = binary.BigEndian.Uint32(data[5:9])
	h.MsgID = binary.BigEndian.Uint32(data[9:13])
	return nil
}

// Transport is the interface for sending and receiving messages.
type Transport interface {
	Send(data []byte) error
	Recv() ([]byte, error)
}

// SendFragmented sends a message, fragmenting if necessary.
func SendFragmented(transport Transport, data []byte, flag MessageFlag, maxFragmentSize int) error {
	if maxFragmentSize < 100 {
		return errors.New("max fragment size too small")
	}

	// Generate message ID
	msgID := uint32(rand.Uint32())
	if msgID == 0 {
		msgID = uint32(time.Now().UnixNano())
	}

	// If message fits in one fragment, send directly
	if len(data) <= maxFragmentSize {
		header := &FragmentHeader{
			Flag:   flag,
			Index:  0,
			Total:  1,
			MsgLen: uint32(len(data)),
			MsgID:  msgID,
		}
		hb, err := header.MarshalBinary()
		if err != nil {
			return err
		}
		return transport.Send(append(hb, data...))
	}

	// Fragment the message
	total := uint16((len(data) + maxFragmentSize - 1) / maxFragmentSize)
	for i := uint16(0); i < total; i++ {
		offset := int(i) * maxFragmentSize
		end := offset + maxFragmentSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]

		header := &FragmentHeader{
			Flag:   flag,
			Index:  i,
			Total:  total,
			MsgLen: uint32(len(data)),
			MsgID:  msgID,
		}
		hb, err := header.MarshalBinary()
		if err != nil {
			return err
		}

		if err := transport.Send(append(hb, chunk...)); err != nil {
			return err
		}
	}

	return nil
}

// FragmentBuffer reassembles fragmented messages.
type FragmentBuffer struct {
	fragments map[uint32]map[uint16][]byte // msgID -> index -> data
	mu        sync.RWMutex
	timeout   time.Duration
	lastClean time.Time
}

// NewFragmentBuffer creates a new fragment buffer.
func NewFragmentBuffer(timeout time.Duration) *FragmentBuffer {
	return &FragmentBuffer{
		fragments: make(map[uint32]map[uint16][]byte),
		timeout:   timeout,
		lastClean: time.Now(),
	}
}

// ReceiveFragmented receives and reassembles fragmented messages.
func (fb *FragmentBuffer) ReceiveFragmented(transport Transport) (MessageFlag, []byte, error) {
	for {
		packet, err := transport.Recv()
		if err != nil {
			return 0, nil, err
		}

		if len(packet) < 13 {
			return 0, nil, errors.New("packet too short for fragment header")
		}

		header := &FragmentHeader{}
		if err := header.UnmarshalBinary(packet[:13]); err != nil {
			return 0, nil, err
		}

		payload := packet[13:]

		// Single fragment message
		if header.Total == 1 {
			return header.Flag, payload, nil
		}

		// Multi-fragment message
		fb.mu.Lock()

		// Periodic cleanup
		if time.Since(fb.lastClean) > fb.timeout {
			fb.cleanup()
			fb.lastClean = time.Now()
		}

		// Initialize fragment map for this message ID
		if _, exists := fb.fragments[header.MsgID]; !exists {
			fb.fragments[header.MsgID] = make(map[uint16][]byte)
		}

		// Store fragment
		fb.fragments[header.MsgID][header.Index] = payload

		// Check if all fragments received
		if uint16(len(fb.fragments[header.MsgID])) == header.Total {
			// Reassemble message
			result := make([]byte, 0, header.MsgLen)
			for i := uint16(0); i < header.Total; i++ {
				result = append(result, fb.fragments[header.MsgID][i]...)
			}

			// Clean up
			delete(fb.fragments, header.MsgID)
			fb.mu.Unlock()

			return header.Flag, result, nil
		}

		fb.mu.Unlock()
	}
}

// cleanup removes stale fragments.
func (fb *FragmentBuffer) cleanup() {
	// Simple cleanup: remove all fragments
	// In production, you might want to track timestamps
	if len(fb.fragments) > 100 {
		for msgID := range fb.fragments {
			delete(fb.fragments, msgID)
			if len(fb.fragments) < 50 {
				break
			}
		}
	}
}
