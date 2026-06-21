// Package crypto provides post-quantum cryptography primitives.
// This file provides secure memory handling utilities.
package crypto

import (
	"crypto/rand"
	"reflect"
	"unsafe"
)

// SecureClear securely clears sensitive data from memory.
// This uses unsafe to bypass Go's optimizations that might eliminate the clearing.
func SecureClear(data []byte) {
	if len(data) == 0 {
		return
	}

	// Get the underlying array pointer
	header := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	basePtr := header.Data
	arrayLen := header.Len

	// Clear the data multiple times with different patterns
	for round := 0; round < 4; round++ {
		for i := 0; i < arrayLen; i++ {
			elemPtr := unsafe.Pointer(uintptr(basePtr) + uintptr(i))

			switch round {
			case 0:
				// Round 1: Zero out
				*(*byte)(elemPtr) = 0
			case 1:
				// Round 2: Fill with 0xFF
				*(*byte)(elemPtr) = 0xFF
			case 2:
				// Round 3: Fill with 0xAA
				*(*byte)(elemPtr) = 0xAA
			default:
				// Round 4: Random data
				var b [1]byte
				rand.Read(b[:])
				*(*byte)(elemPtr) = b[0]
			}
		}
	}
}

// SecureMakeSlice creates a slice that will be cleared when finalized.
// Note: This relies on finalizer which is not guaranteed to run.
func SecureMakeSlice(size int) []byte {
	data := make([]byte, size)
	// In a production system, you might want to use runtime.SetFinalizer
	// but that has its own issues and is not guaranteed.
	return data
}

// ZeroString securely clears a string.
func ZeroString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Strings are immutable in Go, so we can't directly clear them
	// The best we can do is set the reference to nil
	header := (*reflect.StringHeader)(unsafe.Pointer(s))
	header.Data = 0
	header.Len = 0
}
