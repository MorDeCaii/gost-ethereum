package gost34112012

import "io"

type GostHash interface {
	// Write (via the embedded io.Writer interface) adds more data to the running hash.
	// It never returns an error.
	io.Writer

	// Sum appends the current hash to b and returns the resulting slice.
	// It does not change the underlying hash state.
	Sum(b []byte) []byte

	// Reset resets the Hash to its initial state.
	Reset()

	// Size returns the number of bytes Sum will return.
	Size() int

	// BlockSize returns the hash's underlying block size.
	// The Write method must be able to accept any amount
	// of data, but it may operate more efficiently if all writes
	// are a multiple of the block size.
	BlockSize() int

	// Compares current hash with h
	Equal(h GostHash) bool
}

// Hash32 is the common interface implemented by all 32-bit hash functions.
type GostHash32 interface {
	GostHash
	Sum32() uint32
}

// Hash64 is the common interface implemented by all 64-bit hash functions.
type GostHash64 interface {
	GostHash
	Sum64() uint64
}
