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

// LowEntropyInjection details a small window with significantly low entropy in a high-entropy section.
type LowEntropyInjection struct {
	SectionName            string  `json:"section_name"`
	OverallEntropy         float64 `json:"overall_entropy"`
	LowEntropyRegionOffset int64   `json:"low_entropy_region_offset"`
	LowEntropyRegionSize   int     `json:"low_entropy_region_size"`
	RegionEntropy          float64 `json:"region_entropy"`
	Suspicious             bool    `json:"suspicious"`
}

// DetectLowEntropyInjections scans each section for small windows with entropy significantly lower than the section's overall entropy.
func (p *PETarget) DetectLowEntropyInjections() ([]LowEntropyInjection, error) {
	injections := []LowEntropyInjection{}
	const windowSize = 256       // bytes
	const entropyThreshold = 4.0 // if region entropy < overall - 2.5 and region entropy < entropyThreshold
	for _, section := range p.File.Sections {
		data, err := p.SectionData(section)
		if err != nil || len(data) < windowSize {
			continue
		}
		overall := CalculateEntropy(data)
		if overall < 6.0 {
			// Only scan high‑entropy sections (potential packed areas)
			continue
		}
		// Slide a window over the section
		for start := 0; start <= len(data)-windowSize; start += windowSize / 2 { // 50% overlap
			window := data[start : start+windowSize]
			regionEntropy := CalculateEntropy(window)
			if regionEntropy < entropyThreshold && (overall-regionEntropy) > 2.5 {
				injections = append(injections, LowEntropyInjection{
					SectionName:            section.Name,
					OverallEntropy:         overall,
					LowEntropyRegionOffset: int64(section.Offset) + int64(start),
					LowEntropyRegionSize:   windowSize,
					RegionEntropy:          regionEntropy,
					Suspicious:             true,
				})
				// Only report one per section to avoid spam
				break
			}
		}
	}
	return injections, nil
}


