package main

import (
	"fmt"
	"polyseed"
	"polyseed/lang"
)

func main() {
	// Create a new seed
	seed, err := polyseed.Create(0)
	if err != nil {
		panic(err)
	}
	defer seed.Free()

	// Get the English language
	langEn := lang.GetLang(0) // English is first
	if langEn == nil {
		panic("language not found")
	}

	// Encode the seed to a mnemonic phrase
	phrase := seed.Encode(langEn, polyseed.CoinMonero)
	fmt.Printf("Generated mnemonic phrase:\n%s\n\n", phrase)

	// Decode it back
	decodedSeed, decodedLang, err := polyseed.Decode(phrase, polyseed.CoinMonero)
	if err != nil {
		fmt.Printf("Error decoding: %v\n", err)
		return
	}
	defer decodedSeed.Free()

	fmt.Printf("Successfully decoded seed!\n")
	fmt.Printf("Language: %s\n", decodedLang.GetLangNameEn())
	fmt.Printf("Birthday: %d\n", decodedSeed.GetBirthday())
}

