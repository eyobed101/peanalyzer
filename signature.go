package peanalyzer

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Signature represents a PEiD packer/compiler signature.
type Signature struct {
	Name     string // e.g., "UPX v0.89 - v1.02"
	Mask     []byte // Pattern bytes (wildcards are 0x00)
	Values   []byte // Actual bytes (wildcards ignored)
	Length   int    // Length of pattern in bytes
	EpOnly   bool   // If true, only scan at Entry Point
	Category string // Category of signature ("packer", "protector", "compiler", "installer")
}

func inferCategory(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "protector") ||
		strings.Contains(lower, "armadillo") ||
		strings.Contains(lower, "themida") ||
		strings.Contains(lower, "vmprotect") ||
		strings.Contains(lower, "enigma") ||
		strings.Contains(lower, "obsidium") {
		return "protector"
	}
	if strings.Contains(lower, "compiler") ||
		strings.Contains(lower, "microsoft visual") ||
		strings.Contains(lower, "msc") ||
		strings.Contains(lower, "mingw") ||
		strings.Contains(lower, "gcc") ||
		strings.Contains(lower, "watcom") ||
		strings.Contains(lower, "borland") ||
		strings.Contains(lower, "delphi") ||
		strings.Contains(lower, "c++") ||
		strings.Contains(lower, "intel c") ||
		strings.Contains(lower, "gfortran") ||
		strings.Contains(lower, "purebasic") ||
		strings.Contains(lower, "fpc") {
		return "compiler"
	}
	if strings.Contains(lower, "installer") ||
		strings.Contains(lower, "nullsoft") ||
		strings.Contains(lower, "inno") ||
		strings.Contains(lower, "installshield") ||
		strings.Contains(lower, "wise") ||
		strings.Contains(lower, "sfx") {
		return "installer"
	}
	return "packer"
}

// NewSignature creates a signature from a hex pattern string.
// Pattern example: "55 8B EC 6A FF 68 ?? ?? ?? ??"
// Wildcards can be "??" or "?".
func NewSignature(name, pattern string, epOnly bool) (*Signature, error) {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ReplaceAll(pattern, ",", "")
	fields := strings.Fields(pattern)

	values := make([]byte, 0, len(fields))
	mask := make([]byte, 0, len(fields))

	for _, f := range fields {
		// Any token containing '?' is a wildcard byte
		if strings.Contains(f, "?") {
			if len(f) != 1 && len(f) != 2 {
				return nil, fmt.Errorf("invalid wildcard token %q", f)
			}
			values = append(values, 0x00)
			mask = append(mask, 0x00)
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("invalid token %q (expected 2 hex digits or wildcard)", f)
		}
		b, err := hex.DecodeString(f)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte %q: %w", f, err)
		}
		values = append(values, b[0])
		mask = append(mask, 0xFF)
	}

	if len(values) < 8 {
		return nil, fmt.Errorf("signature pattern length %d is less than 8 bytes", len(values))
	}

	return &Signature{
		Name:     name,
		Mask:     mask,
		Values:   values,
		Length:   len(values),
		EpOnly:   epOnly,
		Category: inferCategory(name),
	}, nil
}

// Match checks if the signature matches the data at the given offset.
// Data should be at least signature.Length bytes long starting from offset.
func (s *Signature) Match(data []byte, offset int) bool {
	if offset+s.Length > len(data) {
		return false
	}
	for i := 0; i < s.Length; i++ {
		if s.Mask[i] == 0xFF && data[offset+i] != s.Values[i] {
			return false
		}
	}
	return true
}

// LoadSignaturesFromFile loads signatures from a PEiD userdb.txt file.
// Format:
//
//	[Signature Name]
//	signature = 55 8B EC 6A FF 68 ?? ?? ?? ??
//	ep_only = true
//
// Lines starting with ';' are comments. Empty lines are ignored.
func LoadSignaturesFromFile(path string) ([]Signature, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var signatures []Signature
	scanner := bufio.NewScanner(f)
	var currentName string
	var currentPattern string
	var currentEpOnly bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// New signature block starts with [Name]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// Save previous signature if any
			if currentName != "" && currentPattern != "" {
				sig, err := NewSignature(currentName, currentPattern, currentEpOnly)
				if err == nil {
					signatures = append(signatures, *sig)
				}
			}
			// Start new signature
			currentName = strings.Trim(line, "[]")
			currentPattern = ""
			currentEpOnly = false
			continue
		}

		// Parse key = value
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])

			switch key {
			case "signature":
				currentPattern = value
			case "ep_only":
				currentEpOnly = value == "true" || value == "1" || value == "yes"
			}
		}
	}

	// Add the last signature
	if currentName != "" && currentPattern != "" {
		sig, err := NewSignature(currentName, currentPattern, currentEpOnly)
		if err == nil {
			signatures = append(signatures, *sig)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading signatures file: %w", err)
	}
	return signatures, nil
}
