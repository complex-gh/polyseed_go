// Copyright (c) 2025 complex (complex@ft.hn)
// See LICENSE for licensing information

package polyseed

import (
	"encoding/binary"
)

const (
	storageHeader = "POLYSEED"
	headerSize    = 8
	extraByte     = 0xFF
	storageFooter = 0x7000

	secretSize = 19
	secretBits = 150
	clearBits  = (secretSize * 8) - secretBits
	clearMask  = ^uint8(((1 << clearBits) - 1) << (8 - clearBits))
)

// store16 stores a 16-bit value in little-endian format
func store16(p []byte, u uint16) {
	binary.LittleEndian.PutUint16(p, u)
}

// load16 loads a 16-bit value from little-endian format
func load16(p []byte) uint16 {
	return binary.LittleEndian.Uint16(p)
}

// dataStore serializes seed data into storage format
func dataStore(d *data, storage *Storage) {
	pos := 0

	// Header
	copy(storage[pos:], storageHeader)
	pos += headerSize

	// Features and birthday
	store16(storage[pos:], uint16(d.features)<<dateBits|uint16(d.birthday))
	pos += 2

	// Secret
	copy(storage[pos:], d.secret[:secretSize])
	pos += secretSize

	// Extra byte
	storage[pos] = extraByte
	pos++

	// Footer and checksum
	store16(storage[pos:], storageFooter|d.checksum)
}

// dataLoad deserializes seed data from storage format
func dataLoad(storage *Storage, d *data) error {
	pos := 0

	// Check header
	if string(storage[pos:pos+headerSize]) != storageHeader {
		return StatusErrFormat
	}
	pos += headerSize

	// Load features and birthday
	v1 := load16(storage[pos:])
	d.birthday = uint16(v1 & dateMask)
	v1 >>= dateBits
	if v1 > featureMask {
		return StatusErrFormat
	}
	d.features = uint8(v1)
	pos += 2

	// Load secret
	for i := range d.secret {
		d.secret[i] = 0
	}
	copy(d.secret[:], storage[pos:pos+secretSize])
	if d.secret[secretSize-1]&^clearMask != 0 {
		return StatusErrFormat
	}
	pos += secretSize

	// Check extra byte
	if storage[pos] != extraByte {
		return StatusErrFormat
	}
	pos++

	// Check footer and load checksum
	v2 := load16(storage[pos:])
	d.checksum = uint16(v2 & gfMask)
	v2 &^= gfMask
	if v2 != storageFooter {
		return StatusErrFormat
	}

	return nil
}

// Store serializes the seed data in a platform-independent way
func (s *Seed) Store(storage *Storage) {
	d := s.toData()
	dataStore(d, storage)
	memzero(d.secret[:])
}

// Load deserializes a seed from storage format
func Load(storage *Storage) (*Seed, error) {
	d := &data{}
	if err := dataLoad(storage, d); err != nil {
		return nil, err
	}

	// Verify checksum
	p := &gfPoly{}
	p.coeff[0] = gfElem(d.checksum)
	dataToPoly(d, p)
	if !p.check() {
		memzero(d.secret[:])
		return nil, StatusErrChecksum
	}

	// Check features
	if !featuresSupported(d.features) {
		memzero(d.secret[:])
		return nil, StatusErrUnsupported
	}

	seed := &Seed{
		birthday: d.birthday,
		features: d.features,
		secret:   d.secret,
		checksum: d.checksum,
	}

	return seed, nil
}

// toData converts a Seed to internal data format
func (s *Seed) toData() *data {
	return &data{
		birthday: s.birthday,
		features: s.features,
		secret:   s.secret,
		checksum: s.checksum,
	}
}

// fromData creates a Seed from internal data format
func seedFromData(d *data) *Seed {
	return &Seed{
		birthday: d.birthday,
		features: d.features,
		secret:   d.secret,
		checksum: d.checksum,
	}
}

