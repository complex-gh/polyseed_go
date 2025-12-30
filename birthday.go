// Copyright (c) 2025 complex (complex@ft.hn)
// See LICENSE for licensing information

package polyseed

const (
	// epoch is the base timestamp: 1st November 2021 12:00 UTC
	epoch = uint64(1635768000)

	// timeStep is 30.436875 days = 1/12 of the Gregorian year
	timeStep = uint64(2629746)

	// DateBits is the number of bits used for the birthday
	DateBits = 10

	// dateBits is the number of bits used for the birthday (internal alias)
	dateBits = DateBits

	// DateMask is the mask for date bits
	DateMask = (1 << DateBits) - 1

	// dateMask is the mask for date bits (internal alias)
	dateMask = DateMask
)

// birthdayEncode converts a Unix timestamp to a birthday value
func birthdayEncode(timestamp uint64) uint16 {
	// Handle broken time() implementations
	if timestamp == ^uint64(0) || timestamp < epoch {
		return 0
	}
	return uint16(((timestamp - epoch) / timeStep) & dateMask)
}

// birthdayDecode converts a birthday value to a Unix timestamp
func birthdayDecode(birthday uint16) uint64 {
	return epoch + uint64(birthday)*timeStep
}

