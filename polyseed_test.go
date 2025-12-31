// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

package polyseed

import (
	"testing"

	"polyseed/internal"
	"polyseed/lang"
)

func TestRoundtripAllLanguages(t *testing.T) {
	// Create a seed
	seed, err := Create(0)
	if err != nil {
		t.Fatalf("Failed to create seed: %v", err)
	}
	defer seed.Free()

	// Test roundtrip for all languages
	numLangs := GetNumLangs()
	for i := 0; i < numLangs; i++ {
		lang := GetLang(i)
		if lang == nil {
			t.Errorf("Language at index %d is nil", i)
			continue
		}

		langName := lang.GetLangNameEn()
		t.Run(langName, func(t *testing.T) {
			// Encode seed to mnemonic phrase
			phrase := seed.Encode(lang, CoinMonero)

			if len(phrase) == 0 {
				t.Fatal("Encoded phrase is empty")
			}

			// Decode phrase back to seed
			decodedSeed, decodedLang, err := Decode(phrase, CoinMonero)
			if err != nil {
				t.Fatalf("Failed to decode phrase: %v", err)
			}
			defer decodedSeed.Free()

			// Verify language matches
			if decodedLang != lang {
				t.Errorf("Language mismatch: expected %v, got %v", lang, decodedLang)
			}

			// Verify features (should be all false for seed created with 0)
			if decodedSeed.GetFeature(1) != 0 ||
				decodedSeed.GetFeature(2) != 0 ||
				decodedSeed.GetFeature(4) != 0 {
				t.Error("Features should all be false")
			}

			// Verify key generation works (this validates the seed is correct)
			key := decodedSeed.Keygen(CoinMonero, 32)
			if len(key) != 32 {
				t.Errorf("Expected key length 32, got %d", len(key))
			}
		})
	}
}

const (
	// Specific timestamps used in tests
	seedTime1 = uint64(1638446400) // Dec 2021
	seedTime2 = uint64(3118651200) // Oct 2068
	seedTime3 = uint64(4305268800) // Jun 2106

	// Expected English phrase for seed1 (with specific random bytes)
	expectedPhraseEn1 = "raven tail swear infant grief assist regular lamp " +
		"duck valid someone little harsh puppy airport language"

	// Expected English phrase with 4-char prefixes
	expectedPhraseEn2 = "rave tail swea infan grie assi regul lamp " +
		"duck vali some litt hars pupp airp langua"

	// Expected Spanish phrase for seed2
	expectedPhraseEs1 = "eje fin parte célebre tabú pestaña lienzo puma " +
		"prisión hora regalo lengua existir lápiz lote sonoro"

	// Expected Spanish phrase without accents
	expectedPhraseEs2 = "eje fin parte celebre tabu pestana lienzo puma " +
		"prision hora regalo lengua existir lapiz lote sonoro"

	// Expected Spanish phrase with 4-char prefixes
	expectedPhraseEs3 = "eje fin part cele tabu pest lien puma " +
		"pris hora rega leng exis lapi lote sono"
)

// Specific random bytes that generate known seeds (from tests.c)
var (
	// Random bytes for seed1 - generates expectedPhraseEn1
	randBytes1 = []byte{
		0xdd, 0x76, 0xe7, 0x35, 0x9a, 0x0d, 0xed, 0x37,
		0xcd, 0x0f, 0xf0, 0xf3, 0xc8, 0x29, 0xa5, 0xae,
		0x01, 0x67, 0xf3,
	}

	// Random bytes for seed2 - generates expectedPhraseEs1
	randBytes2 = []byte{
		0x5a, 0x2b, 0x02, 0xdf, 0x7d, 0xb2, 0x1f, 0xcb,
		0xe6, 0xec, 0x6d, 0xf1, 0x37, 0xd5, 0x4c, 0x7b,
		0x20, 0xfd, 0x2b,
	}
)

// Helper function to get language by English name
func getLangByName(name string) *lang.Language {
	numLangs := GetNumLangs()
	for i := 0; i < numLangs; i++ {
		l := GetLang(i)
		if l != nil && l.GetLangNameEn() == name {
			return l
		}
	}
	return nil
}

// createSeedWithValues creates a seed with specific secret bytes, birthday timestamp, and features
// This is a test helper function that allows deterministic seed creation
func createSeedWithValues(secretBytes []byte, birthdayTimestamp uint64, features uint8) (*Seed, error) {
	// Check features
	seedFeatures := makeFeatures(features)
	if !featuresSupported(seedFeatures) {
		return nil, StatusErrUnsupported
	}

	// Create seed
	seed := &Seed{
		birthday: birthdayEncode(birthdayTimestamp),
		features: seedFeatures,
	}

	// Copy secret bytes
	if len(secretBytes) != internal.SecretSize {
		return nil, StatusErrFormat
	}
	copy(seed.secret[:internal.SecretSize], secretBytes)
	seed.secret[internal.SecretSize-1] &= internal.ClearMask

	// Encode polynomial
	d := seed.toData()
	p := &internal.GfPoly{}
	internal.DataToPoly(d, p)

	// Calculate checksum
	p.Encode()
	seed.checksum = uint16(p.Coeff[0])

	memzero(d.Secret[:])

	return seed, nil
}

// TestSeedPhraseGenerationWithSpecificValues tests seed phrase generation
// with specific deterministic values to verify correctness
func TestSeedPhraseGenerationWithSpecificValues(t *testing.T) {
	// This test verifies both directions:
	// 1. Decoding a known phrase and verifying its properties
	// 2. Creating a seed with specific random bytes and verifying it produces the expected phrase

	langEn := getLangByName("English")
	if langEn == nil {
		t.Fatal("English language not found")
	}

	// Test 1: Decode the known English phrase and verify it matches Test Case 1
	// This verifies that a seed created with:
	// - Random bytes: randBytes1
	// - Time: seedTime1 (1638446400, Dec 2021)
	// - Features: 0
	// - Coin: CoinMonero (0)
	// - Language: English
	// Produces: expectedPhraseEn1
	t.Run("DecodeKnownEnglishPhrase", func(t *testing.T) {
		seed, lang, err := Decode(expectedPhraseEn1, CoinMonero)
		if err != nil {
			t.Fatalf("Failed to decode known phrase: %v", err)
		}
		defer seed.Free()

		// Verify language
		if lang != langEn {
			t.Errorf("Expected English language, got %s", lang.GetLangNameEn())
		}

		// Verify birthday matches seedTime1 (Dec 2021)
		// Note: Birthday is quantized to time steps, so we check the decoded value
		// which represents the start of the time step containing seedTime1
		birthday := seed.GetBirthday()
		// Calculate expected decoded birthday for seedTime1
		// birthdayEncode(seedTime1) = ((1638446400 - 1635768000) / 2629746) & 0x3FF = 1
		// birthdayDecode(1) = 1635768000 + 1 * 2629746 = 1638397746
		expectedBirthday := uint64(1638397746)
		if birthday != expectedBirthday {
			t.Errorf("Expected birthday %d (decoded from seedTime1), got %d", expectedBirthday, birthday)
		}

		// Verify features are 0 (no features)
		if seed.GetFeature(1) != 0 ||
			seed.GetFeature(2) != 0 ||
			seed.GetFeature(4) != 0 {
			t.Error("Expected all features to be 0")
		}

		// Verify we can encode it back to the same phrase
		encoded := seed.Encode(langEn, CoinMonero)
		if encoded != expectedPhraseEn1 {
			t.Errorf("Roundtrip failed:\nExpected: %q\nGot:      %q", expectedPhraseEn1, encoded)
		}

		// Verify key generation works
		key := seed.Keygen(CoinMonero, 32)
		if len(key) != 32 {
			t.Errorf("Expected key length 32, got %d", len(key))
		}
	})

	// Test 2: Create a seed with randBytes1 and verify it produces expectedPhraseEn1
	// This tests the forward direction: creating a seed with specific inputs
	// and verifying it produces the expected output phrase
	t.Run("CreateSeedFromRandBytes1", func(t *testing.T) {
		// Create seed with specific values matching Test Case 1
		seed, err := createSeedWithValues(randBytes1, seedTime1, 0)
		if err != nil {
			t.Fatalf("Failed to create seed with specific values: %v", err)
		}
		defer seed.Free()

		// Encode the seed to a phrase
		phrase := seed.Encode(langEn, CoinMonero)

		// Verify it matches the expected phrase
		if phrase != expectedPhraseEn1 {
			t.Errorf("Seed generation failed:\nExpected: %q\nGot:      %q", expectedPhraseEn1, phrase)
		}

		// Verify birthday
		birthday := seed.GetBirthday()
		expectedBirthday := uint64(1638397746) // Decoded birthday for seedTime1
		if birthday != expectedBirthday {
			t.Errorf("Expected birthday %d, got %d", expectedBirthday, birthday)
		}

		// Verify features are 0
		if seed.GetFeature(1) != 0 ||
			seed.GetFeature(2) != 0 ||
			seed.GetFeature(4) != 0 {
			t.Error("Expected all features to be 0")
		}
	})

	// Test 3: Decode the known Spanish phrase and verify it matches Test Case 2
	// This verifies that a seed created with:
	// - Random bytes: randBytes2
	// - Time: seedTime2 (3118651200, Oct 2068)
	// - Features: 0
	// - Coin: CoinMonero (0)
	// - Language: Spanish
	// Produces: expectedPhraseEs1
	langEs := getLangByName("Spanish")
	if langEs == nil {
		t.Fatal("Spanish language not found")
	}

	t.Run("DecodeKnownSpanishPhrase", func(t *testing.T) {
		seed, lang, err := Decode(expectedPhraseEs1, CoinMonero)
		if err != nil {
			t.Fatalf("Failed to decode known phrase: %v", err)
		}
		defer seed.Free()

		// Verify language
		if lang != langEs {
			t.Errorf("Expected Spanish language, got %s", lang.GetLangNameEn())
		}

		// Verify birthday matches seedTime2 (Oct 2068)
		// Note: Birthday is quantized to time steps
		birthday := seed.GetBirthday()
		// Calculate expected decoded birthday for seedTime2
		// birthdayEncode(seedTime2) = ((3118651200 - 1635768000) / 2629746) & 0x3FF
		// birthdayDecode(encoded) = epoch + encoded * timeStep
		// We'll calculate it based on the actual decoded value
		expectedBirthday := birthdayDecode(birthdayEncode(seedTime2))
		if birthday != expectedBirthday {
			t.Errorf("Expected birthday %d (decoded from seedTime2), got %d", expectedBirthday, birthday)
		}

		// Verify features are 0 (no features)
		if seed.GetFeature(1) != 0 ||
			seed.GetFeature(2) != 0 ||
			seed.GetFeature(4) != 0 {
			t.Error("Expected all features to be 0")
		}

		// Verify we can encode it back to the same phrase
		encoded := seed.Encode(langEs, CoinMonero)
		if encoded != expectedPhraseEs1 {
			t.Errorf("Roundtrip failed:\nExpected: %q\nGot:      %q", expectedPhraseEs1, encoded)
		}

		// Verify key generation works
		key := seed.Keygen(CoinMonero, 32)
		if len(key) != 32 {
			t.Errorf("Expected key length 32, got %d", len(key))
		}
	})

	// Test 4: Create a seed with randBytes2 and verify it produces expectedPhraseEs1
	// This tests the forward direction: creating a seed with specific inputs
	// and verifying it produces the expected Spanish phrase
	t.Run("CreateSeedFromRandBytes2", func(t *testing.T) {
		// Create seed with specific values matching Test Case 2
		seed, err := createSeedWithValues(randBytes2, seedTime2, 0)
		if err != nil {
			t.Fatalf("Failed to create seed with specific values: %v", err)
		}
		defer seed.Free()

		// Encode the seed to a phrase
		phrase := seed.Encode(langEs, CoinMonero)

		// Verify it matches the expected phrase
		if phrase != expectedPhraseEs1 {
			t.Errorf("Seed generation failed:\nExpected: %q\nGot:      %q", expectedPhraseEs1, phrase)
		}

		// Verify birthday
		birthday := seed.GetBirthday()
		expectedBirthday := birthdayDecode(birthdayEncode(seedTime2))
		if birthday != expectedBirthday {
			t.Errorf("Expected birthday %d, got %d", expectedBirthday, birthday)
		}

		// Verify features are 0
		if seed.GetFeature(1) != 0 ||
			seed.GetFeature(2) != 0 ||
			seed.GetFeature(4) != 0 {
			t.Error("Expected all features to be 0")
		}
	})
}
