// Copyright (c) 2025-2026 complex (complex@ft.hn)
// See LICENSE for licensing information

package polyseed

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"

	"github.com/complex-gh/polyseed_go/internal"
	"github.com/complex-gh/polyseed_go/lang"
)

// Constants
const (
	// NumWords is the number of words in the mnemonic phrase
	NumWords = 16

	// StorageSize is the size of the serialized seed
	StorageSize = 32

	// StrSize is the maximum possible length of a mnemonic phrase
	StrSize = 360

	// LangSize is the number of words in each language wordlist
	LangSize = 2048
)

// Coin represents the cryptocurrency for which the seed is intended.
// Seeds for different coins are incompatible.
type Coin uint16

const (
	// CoinMonero represents Monero
	CoinMonero Coin = 0

	// CoinAeon represents Aeon
	CoinAeon Coin = 1

	// CoinWownero represents Wownero
	CoinWownero Coin = 2
	// Other coins should be added here sequentially.
	// The maximum supported value is 2047.
)

// Status represents the result of a polyseed operation
type Status int

const (
	// StatusOK indicates success
	StatusOK Status = iota

	// StatusErrNumWords indicates wrong number of words in the phrase
	StatusErrNumWords

	// StatusErrLang indicates unknown language or unsupported words
	StatusErrLang

	// StatusErrChecksum indicates checksum mismatch
	StatusErrChecksum

	// StatusErrUnsupported indicates unsupported seed features
	StatusErrUnsupported

	// StatusErrFormat indicates invalid seed format
	StatusErrFormat

	// StatusErrMemory indicates memory allocation failure
	StatusErrMemory

	// StatusErrMultLang indicates phrase matches more than one language
	StatusErrMultLang
)

// Error returns the error message for the status
func (s Status) Error() string {
	switch s {
	case StatusOK:
		return "success"
	case StatusErrNumWords:
		return "wrong number of words in the phrase"
	case StatusErrLang:
		return "unknown language or unsupported words"
	case StatusErrChecksum:
		return "checksum mismatch"
	case StatusErrUnsupported:
		return "unsupported seed features"
	case StatusErrFormat:
		return "invalid seed format"
	case StatusErrMemory:
		return "memory allocation failure"
	case StatusErrMultLang:
		return "phrase matches more than one language"
	default:
		return "unknown error"
	}
}

// Storage is the serialized seed format. The contents are platform-independent.
type Storage [StorageSize]byte

// Seed represents a polyseed mnemonic seed
type Seed struct {
	birthday  uint16
	features  uint8
	secret    [32]byte
	checksum  uint16
}

// toData converts a Seed to internal data format
func (s *Seed) toData() *internal.Data {
	return &internal.Data{
		Birthday: s.birthday,
		Features: s.features,
		Secret:   s.secret,
		Checksum: s.checksum,
	}
}

// seedFromData creates a Seed from internal data format
func seedFromData(d *internal.Data) *Seed {
	return &Seed{
		birthday: d.Birthday,
		features: d.Features,
		secret:   d.Secret,
		checksum: d.Checksum,
	}
}


var (
	// reservedFeatures tracks which feature bits are reserved
	reservedFeatures uint8 = FeatureMask ^ encryptedMask
)

// memzero securely erases memory by overwriting it with zeros
func memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// getRandomBytes generates cryptographically secure random bytes
func getRandomBytes(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// pbkdf2SHA256 calculates PBKDF2 based on HMAC-SHA256
func pbkdf2SHA256(password []byte, salt []byte, iterations int, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// utf8NFC converts a UTF8 string to the composed canonical form (NFC)
func utf8NFC(str string) string {
	return norm.NFC.String(str)
}

// utf8NFKD converts a UTF8 string to the decomposed canonical form (NFKD)
func utf8NFKD(str string) string {
	return norm.NFKD.String(str)
}

// UTF8NFKDLazy only normalizes strings that contain non-ASCII characters
func UTF8NFKDLazy(str string) string {
	// Check if string contains non-ASCII characters
	for _, r := range str {
		if r > 127 {
			return utf8NFKD(str)
		}
	}
	return str
}

// getTime returns the current unix time
func getTime() uint64 {
	return uint64(time.Now().Unix())
}

const (
	kdfNumIterations = 10000
)

// Create creates a new seed with specific features.
//
// features are the values of the boolean features for this seed. Only
// the least significant 3 bits are used.
//
// Returns the seed and an error if the operation failed.
func Create(features uint8) (*Seed, error) {
	// Check features
	seedFeatures := makeFeatures(features)
	if !featuresSupported(seedFeatures) {
		return nil, StatusErrUnsupported
	}

	// Create seed
	seed := &Seed{
		birthday: birthdayEncode(getTime()),
		features: seedFeatures,
	}

	// Generate random secret
	if err := getRandomBytes(seed.secret[:internal.SecretSize]); err != nil {
		return nil, StatusErrMemory
	}
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

// CreateFromBytes creates a new seed from existing secret bytes.
// The secret bytes should be at least 19 bytes. Only the first 19 bytes
// (150 bits) will be used, with the last byte masked appropriately.
//
// features are the values of the boolean features for this seed. Only
// the least significant 3 bits are used.
//
// Returns the seed and an error if the operation failed.
func CreateFromBytes(secretBytes []byte, features uint8) (*Seed, error) {
	if len(secretBytes) < internal.SecretSize {
		return nil, StatusErrFormat
	}

	// Check features
	seedFeatures := makeFeatures(features)
	if !featuresSupported(seedFeatures) {
		return nil, StatusErrUnsupported
	}

	// Create seed
	seed := &Seed{
		birthday: birthdayEncode(getTime()),
		features: seedFeatures,
	}

	// Copy secret bytes
	copy(seed.secret[:internal.SecretSize], secretBytes[:internal.SecretSize])
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

// Free securely erases the seed data
func (s *Seed) Free() {
	memzero(s.secret[:])
}

// GetBirthday gets the approximate date when the seed was created
func (s *Seed) GetBirthday() uint64 {
	return birthdayDecode(s.birthday)
}

// GetFeature gets the value of a seed feature flag
func (s *Seed) GetFeature(mask uint8) uint8 {
	return getFeatures(s.features, mask)
}

// Encode encodes the mnemonic seed into a string
func (s *Seed) Encode(lang *lang.Language, coin Coin) string {
	d := s.toData()
	p := &internal.GfPoly{}
	p.Coeff[0] = internal.GfElem(d.Checksum)
	internal.DataToPoly(d, p)

	// Apply coin
	p.Coeff[internal.PolyNumCheckDigits] ^= internal.GfElem(coin)

	// Build phrase
	var words []string
	for i := 0; i < NumWords; i++ {
		words = append(words, lang.Words[p.Coeff[i]])
	}

	phrase := strings.Join(words, lang.Separator)

	// Compose if needed by the language
	if lang.Compose {
		phrase = utf8NFC(phrase)
	}

	memzero(d.Secret[:])

	return phrase
}

// Decode decodes the seed from a mnemonic phrase
func Decode(str string, coin Coin) (*Seed, *lang.Language, error) {
	// Canonical decomposition
	strNorm := UTF8NFKDLazy(str)

	// Split into words
	words := lang.SplitPhrase(strNorm)
	if len(words) != NumWords {
		return nil, nil, StatusErrNumWords
	}

	// Decode words into polynomial coefficients
	indices, foundLang, err := lang.PhraseDecode(words)
	if err != nil {
		if err == lang.ErrLang {
			return nil, nil, StatusErrLang
		}
		if err == lang.ErrMultLang {
			return nil, nil, StatusErrMultLang
		}
		return nil, nil, err
	}

	// Build polynomial
	p := &internal.GfPoly{}
	for i, idx := range indices {
		p.Coeff[i] = internal.GfElem(idx)
	}

	// Finalize polynomial
	p.Coeff[internal.PolyNumCheckDigits] ^= internal.GfElem(coin)

	// Check checksum
	if !p.Check() {
		return nil, nil, StatusErrChecksum
	}

	// Decode polynomial into seed data
	d := &internal.Data{}
	internal.PolyToData(p, d)

	// Check features
	if !featuresSupported(d.Features) {
		memzero(d.Secret[:])
		return nil, nil, StatusErrUnsupported
	}

	seed := seedFromData(d)

	return seed, foundLang, nil
}

// DecodeExplicit decodes the seed from a mnemonic phrase with a specific language
func DecodeExplicit(str string, coin Coin, foundLang *lang.Language) (*Seed, error) {
	// Canonical decomposition
	strNorm := UTF8NFKDLazy(str)

	// Split into words
	words := lang.SplitPhrase(strNorm)
	if len(words) != NumWords {
		return nil, StatusErrNumWords
	}

	// Decode words into polynomial coefficients
	indices, err := lang.PhraseDecodeExplicit(words, foundLang)
	if err != nil {
		if err == lang.ErrLang {
			return nil, StatusErrLang
		}
		return nil, err
	}

	// Build polynomial
	p := &internal.GfPoly{}
	for i, idx := range indices {
		p.Coeff[i] = internal.GfElem(idx)
	}

	// Finalize polynomial
	p.Coeff[internal.PolyNumCheckDigits] ^= internal.GfElem(coin)

	// Check checksum
	if !p.Check() {
		return nil, StatusErrChecksum
	}

	// Decode polynomial into seed data
	d := &internal.Data{}
	internal.PolyToData(p, d)

	// Check features
	if !featuresSupported(d.Features) {
		memzero(d.Secret[:])
		return nil, StatusErrUnsupported
	}

	seed := seedFromData(d)

	return seed, nil
}

// store32 stores a 32-bit value in little-endian format
func store32(p []byte, u uint32) {
	p[0] = byte(u)
	u >>= 8
	p[1] = byte(u)
	u >>= 8
	p[2] = byte(u)
	u >>= 8
	p[3] = byte(u)
}

// Keygen derives a secret key from the mnemonic seed
func (s *Seed) Keygen(coin Coin, keySize int) []byte {
	d := s.toData()

	salt := make([]byte, 32)
	copy(salt, "POLYSEED key")
	salt[13] = 0xFF
	salt[14] = 0xFF
	salt[15] = 0xFF

	// Domain separate by coin (32-bit)
	store32(salt[16:], uint32(coin))

	// Domain separate by birthday (32-bit)
	store32(salt[20:], uint32(d.Birthday))

	// Domain separate by features (32-bit)
	store32(salt[24:], uint32(d.Features))

	// Use full secret buffer (32 bytes) for PBKDF2
	key := pbkdf2SHA256(d.Secret[:], salt, kdfNumIterations, keySize)

	memzero(d.Secret[:])

	return key
}

// Crypt encrypts or decrypts the seed data with a password
func (s *Seed) Crypt(password string) {
	d := s.toData()

	// Normalize password (NFKD decomposition)
	passNorm := utf8NFKD(password)
	passBytes := []byte(passNorm)

	// Derive an encryption mask
	salt := []byte("POLYSEED mask")
	salt = append(salt, 0xFF, 0xFF)

	mask := pbkdf2SHA256(passBytes, salt, kdfNumIterations, 32)

	// Apply mask
	for i := 0; i < internal.SecretSize; i++ {
		d.Secret[i] ^= mask[i]
	}
	d.Secret[internal.SecretSize-1] &= internal.ClearMask

	d.Features ^= encryptedMask

	// Encode polynomial
	p := &internal.GfPoly{}
	internal.DataToPoly(d, p)

	// Calculate new checksum
	p.Encode()

	s.checksum = uint16(p.Coeff[0])
	s.features = d.Features
	copy(s.secret[:], d.Secret[:])

	memzero(d.Secret[:])
	memzero(mask)
}

// IsEncrypted determines if the seed contents are encrypted
func (s *Seed) IsEncrypted() bool {
	return isEncrypted(s.features)
}

// Store serializes the seed data in a platform-independent way
func (s *Seed) Store(storage *Storage) {
	d := s.toData()
	internal.DataStore(d, (*[32]byte)(storage))
	memzero(d.Secret[:])
}

// Load deserializes a seed from storage format
func Load(storage *Storage) (*Seed, error) {
	d := &internal.Data{}
	if err := internal.DataLoad((*[32]byte)(storage), d); err != nil {
		if err == internal.StatusErrFormat {
			return nil, StatusErrFormat
		}
		return nil, err
	}

	// Verify checksum
	p := &internal.GfPoly{}
	p.Coeff[0] = internal.GfElem(d.Checksum)
	internal.DataToPoly(d, p)
	if !p.Check() {
		memzero(d.Secret[:])
		return nil, StatusErrChecksum
	}

	// Check features
	if !featuresSupported(d.Features) {
		memzero(d.Secret[:])
		return nil, StatusErrUnsupported
	}

	seed := seedFromData(d)

	return seed, nil
}

// GetNumLangs returns the number of supported languages
func GetNumLangs() int {
	return lang.GetNumLangs()
}

// GetLang returns a language by its index
func GetLang(i int) *lang.Language {
	return lang.GetLang(i)
}

