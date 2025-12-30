// Copyright (c) 2025 complex (complex@ft.hn)
// See LICENSE for licensing information

package internal

import (
	"encoding/binary"
)

const (
	storageHeader = "POLYSEED"
	headerSize    = 8
	extraByte     = 0xFF
	storageFooter = 0x7000

	SecretSize = 19
	secretBits = 150
	clearBits  = (SecretSize * 8) - secretBits
	ClearMask  = ^uint8(((1 << clearBits) - 1) << (8 - clearBits))
)

// store16 stores a 16-bit value in little-endian format
func store16(p []byte, u uint16) {
	binary.LittleEndian.PutUint16(p, u)
}

// load16 loads a 16-bit value from little-endian format
func load16(p []byte) uint16 {
	return binary.LittleEndian.Uint16(p)
}

// StatusErrFormat indicates invalid seed format
var StatusErrFormat = &storageError{msg: "invalid seed format"}

type storageError struct {
	msg string
}

func (e *storageError) Error() string {
	return e.msg
}

// DataStore serializes seed data into storage format
func DataStore(d *Data, storage *[32]byte) {
	pos := 0

	// Header
	copy(storage[pos:], storageHeader)
	pos += headerSize

	// Features and birthday
	store16(storage[pos:], uint16(d.Features)<<DateBits|uint16(d.Birthday))
	pos += 2

	// Secret
	copy(storage[pos:], d.Secret[:SecretSize])
	pos += SecretSize

	// Extra byte
	storage[pos] = extraByte
	pos++

	// Footer and checksum
	store16(storage[pos:], storageFooter|d.Checksum)
}

// DataLoad deserializes seed data from storage format
func DataLoad(storage *[32]byte, d *Data) error {
	pos := 0

	// Check header
	if string(storage[pos:pos+headerSize]) != storageHeader {
		return StatusErrFormat
	}
	pos += headerSize

	// Load features and birthday
	v1 := load16(storage[pos:])
	d.Birthday = uint16(v1 & DateMask)
	v1 >>= DateBits
	if v1 > FeatureMask {
		return StatusErrFormat
	}
	d.Features = uint8(v1)
	pos += 2

	// Load secret
	for i := range d.Secret {
		d.Secret[i] = 0
	}
	copy(d.Secret[:], storage[pos:pos+SecretSize])
	if d.Secret[SecretSize-1]&^ClearMask != 0 {
		return StatusErrFormat
	}
	pos += SecretSize

	// Check extra byte
	if storage[pos] != extraByte {
		return StatusErrFormat
	}
	pos++

	// Check footer and load checksum
	v2 := load16(storage[pos:])
	d.Checksum = uint16(v2 & GfMask)
	v2 &^= GfMask
	if v2 != storageFooter {
		return StatusErrFormat
	}

	return nil
}

