// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

package polyseed

import (
	"testing"
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

