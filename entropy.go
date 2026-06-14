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

// EntropyAnomaly flags a section whose entropy deviates statistically from the mean.
type EntropyAnomaly struct {
	SectionName string  `json:"section_name"`
	Entropy     float64 `json:"entropy"`
	ZScore      float64 `json:"z_score"`
	Severity    string  `json:"severity"` // "low", "medium", "high"
}

// DetectEntropyAnomalies calculates the mean and standard deviation of entropies
// and flags sections where |Z-score| > 2.0.
func DetectEntropyAnomalies(sections []SectionEntropyResult) []EntropyAnomaly {
	if len(sections) == 0 {
		return nil
	}

	// Calculate mean
	var sum float64
	for _, sec := range sections {
		sum += sec.Entropy
	}
	mean := sum / float64(len(sections))

	// Calculate standard deviation
	var varianceSum float64
	for _, sec := range sections {
		diff := sec.Entropy - mean
		varianceSum += diff * diff
	}
	stdDev := math.Sqrt(varianceSum / float64(len(sections)))

	var anomalies []EntropyAnomaly
	for _, sec := range sections {
		var z float64
		if stdDev > 0 {
			z = (sec.Entropy - mean) / stdDev
		} else {
			z = 0.0
		}

		absZ := math.Abs(z)
		if absZ > 2.0 {
			var severity string
			if absZ > 3.0 {
				severity = "high"
			} else if absZ > 2.5 {
				severity = "medium"
			} else {
				severity = "low"
			}

			anomalies = append(anomalies, EntropyAnomaly{
				SectionName: sec.Name,
				Entropy:     sec.Entropy,
				ZScore:      z,
				Severity:    severity,
			})
		}
	}
	return anomalies
}

