package pe

import (
	"math"
)

func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make([]float64, 256)
	for _, b := range data {
		freq[b]++
	}

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

type EntropyInfo struct {
	FileEntropy	float64			`json:"file_entropy"`
	Sections	[]SectionEntropyResult	`json:"sections"`
	TotalSections	int			`json:"total_sections"`
}

type SectionEntropyResult struct {
	Name		string	`json:"name"`
	VirtualSize	uint32	`json:"virtual_size"`
	RawSize		uint32	`json:"raw_size"`
	VirtualAddress	uint32	`json:"virtual_address"`
	Entropy		float64	`json:"entropy"`
}

type EntropyAnomaly struct {
	SectionName	string	`json:"section_name"`
	Entropy		float64	`json:"entropy"`
	ZScore		float64	`json:"z_score"`
	Severity	string	`json:"severity"`
}

func DetectEntropyAnomalies(sections []SectionEntropyResult) []EntropyAnomaly {
	if len(sections) == 0 {
		return nil
	}

	var sum float64
	for _, sec := range sections {
		sum += sec.Entropy
	}
	mean := sum / float64(len(sections))

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
				SectionName:	sec.Name,
				Entropy:	sec.Entropy,
				ZScore:		z,
				Severity:	severity,
			})
		}
	}
	return anomalies
}

type LowEntropyInjection struct {
	SectionName		string	`json:"section_name"`
	OverallEntropy		float64	`json:"overall_entropy"`
	LowEntropyRegionOffset	int64	`json:"low_entropy_region_offset"`
	LowEntropyRegionSize	int	`json:"low_entropy_region_size"`
	RegionEntropy		float64	`json:"region_entropy"`
	Suspicious		bool	`json:"suspicious"`
}

func (p *PETarget) DetectLowEntropyInjections() ([]LowEntropyInjection, error) {
	injections := []LowEntropyInjection{}
	const windowSize = 256
	const entropyThreshold = 4.0
	for _, section := range p.File.Sections {
		data, err := p.SectionData(section)
		if err != nil || len(data) < windowSize {
			continue
		}
		overall := CalculateEntropy(data)
		if overall < 6.0 {

			continue
		}

		for start := 0; start <= len(data)-windowSize; start += windowSize / 2 {
			window := data[start : start+windowSize]
			regionEntropy := CalculateEntropy(window)
			if regionEntropy < entropyThreshold && (overall-regionEntropy) > 2.5 {
				injections = append(injections, LowEntropyInjection{
					SectionName:		section.Name,
					OverallEntropy:		overall,
					LowEntropyRegionOffset:	int64(section.Offset) + int64(start),
					LowEntropyRegionSize:	windowSize,
					RegionEntropy:		regionEntropy,
					Suspicious:		true,
				})

				break
			}
		}
	}
	return injections, nil
}
