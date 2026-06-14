package peanalyzer

import (
	"math"
)

// CalculateEntropy computes the Shannon entropy of the given data slice.
// It returns a value between 0 (completely predictable) and 8 (fully random)
// for byte data, as each byte can represent 256 possible values.
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count frequency of each byte value
	freq := make([]float64, 256)
	for _, b := range data {
		freq[b]++
	}

	// Compute probabilities and sum entropy
	var entropy float64
	for i := 0; i < 256; i++ {
		if freq[i] == 0 {
			continue
		}
		p := freq[i] / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// EntropyInfo holds entropy results for a file and its sections.
type EntropyInfo struct {
	FileEntropy   float64                `json:"file_entropy"`
	Sections      []SectionEntropyResult `json:"sections"`
	TotalSections int                    `json:"total_sections"`
}

// SectionEntropyResult contains entropy data for a single PE section.
type SectionEntropyResult struct {
	Name           string  `json:"name"`
	VirtualSize    uint32  `json:"virtual_size"`
	RawSize        uint32  `json:"raw_size"`
	VirtualAddress uint32  `json:"virtual_address"`
	Entropy        float64 `json:"entropy"`
}
