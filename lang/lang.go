// Copyright (c) 2025 complex (complex@ft.hn)
// See LICENSE for licensing information

package lang

import (
	"errors"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var (
	// ErrLang indicates unknown language or unsupported words
	ErrLang = errors.New("unknown language or unsupported words")
	// ErrMultLang indicates phrase matches more than one language
	ErrMultLang = errors.New("phrase matches more than one language")
)

const (
	numCharsPrefix = 4
	// LangSize is the number of words in each language wordlist
	LangSize = 2048
	// NumWords is the number of words in the mnemonic phrase
	NumWords = 16
)

// Language represents a language wordlist
type Language struct {
	Name       string
	NameEn     string
	Separator  string
	IsSorted   bool
	HasPrefix  bool
	HasAccents bool
	Compose    bool
	Words      [LangSize]string
}

var (
	// languages contains all supported languages
	languages []*Language
)

// GetNumLangs returns the number of supported languages
func GetNumLangs() int {
	return len(languages)
}

// GetLang returns a language by its index
func GetLang(i int) *Language {
	if i < 0 || i >= len(languages) {
		return nil
	}
	return languages[i]
}

// GetLangName returns the native name of a language
func (l *Language) GetLangName() string {
	return l.Name
}

// GetLangNameEn returns the English name of a language
func (l *Language) GetLangNameEn() string {
	return l.NameEn
}

// compareStr compares two strings
func compareStr(key, elm string) int {
	return strings.Compare(key, elm)
}

// comparePrefix compares strings using prefix matching (first 4 chars for Latin)
func comparePrefix(key, elm string) int {
	keyRunes := []rune(key)
	elmRunes := []rune(elm)
	
	for i := 1; ; i++ {
		if len(keyRunes) == 0 {
			break
		}
		if i >= numCharsPrefix && len(keyRunes) == 1 {
			break
		}
		if len(elmRunes) == 0 {
			break
		}
		if keyRunes[0] != elmRunes[0] {
			break
		}
		keyRunes = keyRunes[1:]
		elmRunes = elmRunes[1:]
	}
	
	if len(keyRunes) == 0 && len(elmRunes) == 0 {
		return 0
	}
	if len(keyRunes) == 0 {
		return -1
	}
	if len(elmRunes) == 0 {
		return 1
	}
	if keyRunes[0] < elmRunes[0] {
		return -1
	}
	return 1
}

// removeAccents removes non-ASCII characters (simplified version)
func removeAccents(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r < 128 {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// compareStrNoAccent compares strings ignoring accents
func compareStrNoAccent(key, elm string) int {
	keyClean := removeAccents(key)
	elmClean := removeAccents(elm)
	return strings.Compare(keyClean, elmClean)
}

// comparePrefixNoAccent compares strings using prefix matching, ignoring accents
func comparePrefixNoAccent(key, elm string) int {
	keyClean := removeAccents(key)
	elmClean := removeAccents(elm)
	return comparePrefix(keyClean, elmClean)
}

// langSearch searches for a word in a language wordlist
func langSearch(lang *Language, word string, usePrefix, useNoAccent bool) int {
	var cmp func(string, string) int
	
	if usePrefix {
		if useNoAccent {
			cmp = comparePrefixNoAccent
		} else {
			cmp = comparePrefix
		}
	} else {
		if useNoAccent {
			cmp = compareStrNoAccent
		} else {
			cmp = compareStr
		}
	}
	
	if lang.IsSorted {
		// Binary search for sorted wordlists
		idx := sort.Search(LangSize, func(i int) bool {
			return cmp(word, lang.Words[i]) <= 0
		})
		if idx < LangSize && cmp(word, lang.Words[idx]) == 0 {
			return idx
		}
		return -1
	}
	
	// Linear search for unsorted wordlists
	for i := 0; i < LangSize; i++ {
		if cmp(word, lang.Words[i]) == 0 {
			return i
		}
	}
	return -1
}

// FindWord finds a word in a language wordlist
func (l *Language) FindWord(word string) int {
	return langSearch(l, word, l.HasPrefix, l.HasAccents)
}

// PhraseDecode decodes a phrase into word indices, auto-detecting the language
func PhraseDecode(phrase []string) ([]uint16, *Language, error) {
	var foundLang *Language
	var foundIndices []uint16
	
	for _, lang := range languages {
		indices := make([]uint16, NumWords)
		success := true
		
		for i, word := range phrase {
			idx := lang.FindWord(word)
			if idx < 0 {
				success = false
				break
			}
			indices[i] = uint16(idx)
		}
		
		if success {
			if foundLang != nil {
				return nil, nil, ErrMultLang
			}
			foundLang = lang
			foundIndices = indices
		}
	}
	
	if foundLang == nil {
		return nil, nil, ErrLang
	}
	
	return foundIndices, foundLang, nil
}

// PhraseDecodeExplicit decodes a phrase using a specific language
func PhraseDecodeExplicit(phrase []string, lang *Language) ([]uint16, error) {
	indices := make([]uint16, NumWords)
	
	for i, word := range phrase {
		idx := lang.FindWord(word)
		if idx < 0 {
			return nil, ErrLang
		}
		indices[i] = uint16(idx)
	}
	
	return indices, nil
}

// utf8NFKDLazy only normalizes strings that contain non-ASCII characters
func utf8NFKDLazy(str string) string {
	// Check if string contains non-ASCII characters
	for _, r := range str {
		if r > 127 {
			return norm.NFKD.String(str)
		}
	}
	return str
}

// SplitPhrase splits a mnemonic string into words
// It normalizes the string using NFKD decomposition before splitting
func SplitPhrase(str string) []string {
	// Normalize to NFKD first (lazy - only if non-ASCII)
	normalized := utf8NFKDLazy(str)
	
	// Split on spaces
	words := strings.Fields(normalized)
	return words
}

