// Copyright (c) 2025 complex (complex@ft.hn)
// See LICENSE for licensing information

package internal

const (
	// GfBits is the number of bits in a Galois Field element
	GfBits = 11

	// GfSize is the size of the Galois Field (2^11 = 2048)
	GfSize = 1 << GfBits

	// GfMask is the mask for GF elements
	GfMask = GfSize - 1

	// PolyNumCheckDigits is the number of check digits in the polynomial
	PolyNumCheckDigits = 1

	// shareBits is the number of bits of the secret per word
	shareBits = 10

	// NumWords is the number of words in the mnemonic phrase
	NumWords = 16

	// dataWords is the number of data words (excluding checksum)
	dataWords = NumWords - PolyNumCheckDigits
)

// Data represents the internal seed data structure
type Data struct {
	Birthday uint16
	Features uint8
	Secret   [32]byte
	Checksum uint16
}

// Constants for date and feature bits
const (
	DateBits  = 10
	DateMask  = (1 << DateBits) - 1
	FeatureBits = 5
	FeatureMask = (1 << FeatureBits) - 1
)

// gfElem represents an element in GF(2048)
type GfElem uint16

// mul2Table is the multiplication by 2 table for GF(2048)
var mul2Table = [8]GfElem{5, 7, 1, 3, 13, 15, 9, 11}

// GfPoly represents a polynomial over GF(2048)
type GfPoly struct {
	Coeff [NumWords]GfElem
}

// mul2 multiplies a GF element by 2
func (x GfElem) mul2() GfElem {
	if x < 1024 {
		return 2 * x
	}
	return mul2Table[x%8] + 16*((x-1024)/8)
}

// Eval evaluates the polynomial at x = 2 using Horner's method
func (p *GfPoly) Eval() GfElem {
	result := p.Coeff[NumWords-1]
	for i := NumWords - 2; i >= 0; i-- {
		result = result.mul2() ^ p.Coeff[i]
	}
	return result
}

// Encode calculates the checksum and stores it in coeff[0]
func (p *GfPoly) Encode() {
	p.Coeff[0] = p.Eval()
}

// Check verifies the polynomial checksum
func (p *GfPoly) Check() bool {
	return p.Eval() == 0
}

// DataToPoly converts seed data to a polynomial
func DataToPoly(d *Data, p *GfPoly) {
	extraVal := (uint32(d.Features) << DateBits) | uint32(d.Birthday)
	extraBits := FeatureBits + DateBits

	wordBits := 0
	wordVal := uint32(0)

	secretIdx := 0
	secretVal := uint32(d.Secret[secretIdx])
	secretBits := 8
	const charBits = 8
	const secretBitsTotal = 150
	seedRemBits := secretBitsTotal - secretBits

	for i := 0; i < dataWords; i++ {
		for wordBits < shareBits {
			if secretBits == 0 {
				secretIdx++
				if seedRemBits < charBits {
					secretBits = seedRemBits
				} else {
					secretBits = charBits
				}
				secretVal = uint32(d.Secret[secretIdx])
				seedRemBits -= secretBits
			}
			chunkBits := shareBits - wordBits
			if chunkBits > secretBits {
				chunkBits = secretBits
			}
			secretBits -= chunkBits
			wordBits += chunkBits
			wordVal <<= chunkBits
			wordVal |= (secretVal >> secretBits) & ((1 << chunkBits) - 1)
		}
		wordVal <<= 1
		extraBits--
		wordVal |= (extraVal >> extraBits) & 1
		p.Coeff[PolyNumCheckDigits+i] = GfElem(wordVal)
		wordVal = 0
		wordBits = 0
	}
}

// PolyToData converts a polynomial to seed data
func PolyToData(p *GfPoly, d *Data) {
	d.Birthday = 0
	d.Features = 0
	for i := range d.Secret {
		d.Secret[i] = 0
	}
	d.Checksum = uint16(p.Coeff[0])

	extraVal := uint32(0)
	extraBits := 0

	wordBits := 0
	wordVal := uint32(0)

	secretIdx := 0
	secretBits := 0
	seedBits := 0

	const charBits = 8
	const secretBitsTotal = 150

	for i := PolyNumCheckDigits; i < NumWords; i++ {
		wordVal = uint32(p.Coeff[i])

		extraVal <<= 1
		extraVal |= wordVal & 1
		wordVal >>= 1
		wordBits = GfBits - 1
		extraBits++

		for wordBits > 0 {
			if secretBits == charBits {
				secretIdx++
				seedBits += secretBits
				secretBits = 0
			}
			chunkBits := wordBits
			if chunkBits > charBits-secretBits {
				chunkBits = charBits - secretBits
			}
			wordBits -= chunkBits
			chunkMask := uint32((1 << chunkBits) - 1)
			if chunkBits < charBits {
				d.Secret[secretIdx] <<= chunkBits
			}
			d.Secret[secretIdx] |= byte((wordVal >> wordBits) & chunkMask)
			secretBits += chunkBits
		}
	}

	seedBits += secretBits

	d.Birthday = uint16(extraVal & DateMask)
	d.Features = uint8(extraVal >> DateBits)
}

