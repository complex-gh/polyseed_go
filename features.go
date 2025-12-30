// Copyright (c) 2025 complex (complex@ft.hn)
// See LICENSE for licensing information

package polyseed

const (
	// featureBits is the total number of feature bits
	featureBits = 5

	// featureMask is the mask for all feature bits
	featureMask = (1 << featureBits) - 1

	// internalFeatures is the number of internal feature bits
	internalFeatures = 2

	// userFeatures is the number of user-accessible feature bits
	userFeatures = 3

	// userFeaturesMask is the mask for user feature bits
	userFeaturesMask = (1 << userFeatures) - 1

	// encryptedMask indicates the seed is encrypted by a passphrase
	encryptedMask = 16
)

// makeFeatures creates a feature value from user features
func makeFeatures(userFeatures uint8) uint8 {
	return userFeatures & userFeaturesMask
}

// getFeatures extracts feature bits using a mask
func getFeatures(features uint8, mask uint8) uint8 {
	return features & (mask & userFeaturesMask)
}

// isEncrypted checks if the seed is encrypted
func isEncrypted(features uint8) bool {
	return (features & encryptedMask) != 0
}

// featuresSupported checks if the given features are supported
func featuresSupported(features uint8) bool {
	return (features & reservedFeatures) == 0
}

// EnableFeatures enables the optional seed features. Up to 3 different boolean flags are
// supported. By default, all 3 features are disabled.
//
// mask is a bitmask of the enabled features. Only the least significant 3 bits are used.
//
// Returns the number of features that were enabled (0, 1, 2 or 3).
func EnableFeatures(mask uint8) int {
	numEnabled := 0
	reservedFeatures = featureMask ^ encryptedMask
	for i := 0; i < userFeatures; i++ {
		fmask := uint8(1 << i)
		if mask&fmask != 0 {
			reservedFeatures ^= fmask
			numEnabled++
		}
	}
	return numEnabled
}

