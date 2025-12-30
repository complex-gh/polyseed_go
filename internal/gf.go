// Copyright (c) 2025 complex (complex@ft.hn)
// See LICENSE for licensing information

package polyseed

const (
	// gfBits is the number of bits in a Galois Field element
	gfBits = 11

	// gfSize is the size of the Galois Field (2^11 = 2048)
	gfSize = 1 << gfBits

	// gfMask is the mask for GF elements
	gfMask = gfSize - 1

	// polyNumCheckDigits is the number of check digits in the polynomial
	polyNumCheckDigits = 1

	// shareBits is the number of bits of the secret per word
	shareBits = 10

	// dataWords is the number of data words (excluding checksum)
	dataWords = NumWords - polyNumCheckDigits
)

// gfElem represents an element in GF(2048)
type gfElem uint16

// mul2Table is the multiplication by 2 table for GF(2048)
var mul2Table = [8]gfElem{5, 7, 1, 3, 13, 15, 9, 11}

// gfPoly represents a polynomial over GF(2048)
type gfPoly struct {
	coeff [NumWords]gfElem
}

// mul2 multiplies a GF element by 2
func (x gfElem) mul2() gfElem {
	if x < 1024 {
		return 2 * x
	}
	return mul2Table[x%8] + 16*((x-1024)/8)
}

// eval evaluates the polynomial at x = 2 using Horner's method
func (p *gfPoly) eval() gfElem {
	result := p.coeff[NumWords-1]
	for i := NumWords - 2; i >= 0; i-- {
		result = result.mul2() ^ p.coeff[i]
	}
	return result
}

// encode calculates the checksum and stores it in coeff[0]
func (p *gfPoly) encode() {
	p.coeff[0] = p.eval()
}

// check verifies the polynomial checksum
func (p *gfPoly) check() bool {
	return p.eval() == 0
}

// dataToPoly converts seed data to a polynomial
func dataToPoly(d *data, p *gfPoly) {
	extraVal := (uint32(d.features) << dateBits) | uint32(d.birthday)
	extraBits := featureBits + dateBits

	wordBits := 0
	wordVal := uint32(0)

	secretIdx := 0
	secretVal := uint32(d.secret[secretIdx])
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
				secretVal = uint32(d.secret[secretIdx])
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
		p.coeff[polyNumCheckDigits+i] = gfElem(wordVal)
		wordVal = 0
		wordBits = 0
	}
}

// polyToData converts a polynomial to seed data
func polyToData(p *gfPoly, d *data) {
	d.birthday = 0
	d.features = 0
	for i := range d.secret {
		d.secret[i] = 0
	}
	d.checksum = uint16(p.coeff[0])

	extraVal := uint32(0)
	extraBits := 0

	wordBits := 0
	wordVal := uint32(0)

	secretIdx := 0
	secretBits := 0
	seedBits := 0

	const charBits = 8
	const secretBitsTotal = 150

	for i := polyNumCheckDigits; i < NumWords; i++ {
		wordVal = uint32(p.coeff[i])

		extraVal <<= 1
		extraVal |= wordVal & 1
		wordVal >>= 1
		wordBits = gfBits - 1
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
				d.secret[secretIdx] <<= chunkBits
			}
			d.secret[secretIdx] |= byte((wordVal >> wordBits) & chunkMask)
			secretBits += chunkBits
		}
	}

	seedBits += secretBits

	d.birthday = uint16(extraVal & dateMask)
	d.features = uint8(extraVal >> dateBits)
}

