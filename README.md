# polyseed_go

A Go implementation of the [polyseed](https://github.com/tevador/polyseed) mnemonic seed phrase system for cryptocurrencies.

## Overview

polyseed is a mnemonic seed phrase system designed for cryptocurrency wallets, with support for multiple languages and coins. This library provides a complete Go implementation with the following features:

- **Multi-language support**: 10 languages with automatic language detection
- **Multi-coin support**: Monero, Aeon, Wownero, and extensible for more
- **Password encryption**: Optional passphrase protection for seed phrases
- **Feature flags**: Up to 3 user-configurable feature bits
- **Birthday tracking**: Automatic timestamp encoding for seed creation date
- **Secure storage**: Platform-independent serialization format

## Supported Languages

1. English
2. Japanese
3. Korean
4. Spanish
5. French
6. Italian
7. Czech
8. Portuguese
9. Chinese (Simplified)
10. Chinese (Traditional)

## Supported Coins

- **Monero** (`CoinMonero`)
- **Aeon** (`CoinAeon`)
- **Wownero** (`CoinWownero`)

Additional coins can be added by extending the `Coin` type.

## Installation

```bash
go get github.com/complex-gh/polyseed_go
```

## Quick Start

### Creating a New Seed

```go
package main

import (
    "fmt"
    "polyseed"
    "polyseed/lang"
)

func main() {
    // Create a new seed with no features enabled
    seed, err := polyseed.Create(0)
    if err != nil {
        panic(err)
    }
    defer seed.Free()

    // Get the English language
    langEn := lang.GetLang(0) // English is first

    // Encode the seed to a mnemonic phrase for Monero
    phrase := seed.Encode(langEn, polyseed.CoinMonero)
    fmt.Printf("Mnemonic phrase: %s\n", phrase)

    // Get the seed's birthday (creation timestamp)
    birthday := seed.GetBirthday()
    fmt.Printf("Birthday: %d\n", birthday)
}
```

### Decoding a Mnemonic Phrase

```go
// Decode a mnemonic phrase (auto-detects language)
phrase := "your mnemonic phrase here"
seed, detectedLang, err := polyseed.Decode(phrase, polyseed.CoinMonero)
if err != nil {
    panic(err)
}
defer seed.Free()

fmt.Printf("Detected language: %s\n", detectedLang.GetLangNameEn())
```

### Password Encryption

```go
// Encrypt the seed with a password
seed.Crypt("my-secure-password")

// Check if seed is encrypted
if seed.IsEncrypted() {
    fmt.Println("Seed is encrypted")
}

// Decrypt by calling Crypt again with the same password
seed.Crypt("my-secure-password")
```

### Key Generation

```go
// Generate a 32-byte key for a specific coin
key := seed.Keygen(polyseed.CoinMonero, 32)
defer func() {
    // Securely erase the key from memory
    for i := range key {
        key[i] = 0
    }
}()
```

### Storage and Loading

```go
// Serialize seed to storage format
var storage polyseed.Storage
seed.Store(&storage)

// Later, load the seed back
loadedSeed, err := polyseed.Load(&storage)
if err != nil {
    panic(err)
}
defer loadedSeed.Free()
```

## API Reference

### Seed Creation

- `Create(features uint8) (*Seed, error)` - Creates a new seed with specified features
- `CreateFromBytes(secretBytes []byte, features uint8) (*Seed, error)` - Creates a seed from existing secret bytes

### Seed Operations

- `Encode(lang *lang.Language, coin Coin) string` - Encodes seed to mnemonic phrase
- `Decode(str string, coin Coin) (*Seed, *lang.Language, error)` - Decodes mnemonic phrase (auto-detects language)
- `DecodeExplicit(str string, coin Coin, lang *lang.Language) (*Seed, error)` - Decodes with explicit language
- `Keygen(coin Coin, keySize int) []byte` - Derives a secret key from the seed
- `Crypt(password string)` - Encrypts or decrypts the seed with a password
- `Store(storage *Storage)` - Serializes seed to storage format
- `Load(storage *Storage) (*Seed, error)` - Deserializes seed from storage format
- `Free()` - Securely erases the seed from memory
- `GetBirthday() uint64` - Returns the seed creation timestamp
- `GetFeature(mask uint8) uint8` - Gets the value of a feature flag
- `IsEncrypted() bool` - Checks if the seed is encrypted

### Language Support

- `GetNumLangs() int` - Returns the number of supported languages
- `GetLang(i int) *lang.Language` - Gets a language by index
- `Language.GetLangName() string` - Gets the native language name
- `Language.GetLangNameEn() string` - Gets the English language name

### Error Handling

The library uses a `Status` type for error reporting:

- `StatusOK` - Success
- `StatusErrNumWords` - Wrong number of words in phrase
- `StatusErrLang` - Unknown language or unsupported words
- `StatusErrChecksum` - Checksum mismatch
- `StatusErrUnsupported` - Unsupported seed features
- `StatusErrFormat` - Invalid seed format
- `StatusErrMemory` - Memory allocation failure
- `StatusErrMultLang` - Phrase matches more than one language

## Features

### Feature Bits

Seeds support up to 3 user-configurable feature bits. Features can be enabled using `EnableFeatures()`:

```go
// Enable feature bit 0
polyseed.EnableFeatures(1)

// Enable feature bits 0 and 1
polyseed.EnableFeatures(3)
```

### Birthday

Each seed automatically encodes its creation timestamp (birthday) when created. This can be useful for wallet recovery and seed management.

## Security Considerations

- Always call `Free()` on seeds when done to securely erase sensitive data
- Use `Crypt()` to add password protection to seeds
- The library uses secure memory erasure (`memzero`) for sensitive operations
- Keys generated by `Keygen()` should be securely erased after use
- Never log or print seed phrases or secret keys

## Examples

See the `example/` directory for a complete working example.

## License

Copyright (c) 2025-2026 complex (complex@ft.hn)

See LICENSE file for licensing information.

## References

- [polyseed C Implementation](https://github.com/tevador/polyseed)
- [polyseed Specification](https://github.com/tevador/polyseed/blob/master/SPEC.md)

