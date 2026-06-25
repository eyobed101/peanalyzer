package heuristics

import (
	"fmt"
	"sort"
	"strings"

	"github.com/eyobed101/peanalyzer/pkg/pe"
	"github.com/eyobed101/peanalyzer/pkg/signatures"
)

type PackingLayer struct {
	SectionName	string	`json:"section_name"`
	SignatureName	string	`json:"signature_name"`
	Offset		int64	`json:"offset"`
	Entropy		float64	`json:"entropy"`
	LayerNumber	int	`json:"layer_number"`
	Category	string	`json:"category,omitempty"`
	Confidence	float64	`json:"confidence,omitempty"`
	Length		int	`json:"length,omitempty"`
}

type CascadingResult struct {
	IsCascading	bool		`json:"is_cascading"`
	Layers		[]PackingLayer	`json:"layers"`
	Description	string		`json:"description"`
	TotalLayers	int		`json:"total_layers"`
}

func isPackerSignature(name string) bool {
	lower := strings.ToLower(name)
	keywords := []string{
		"packer", "crypter", "protector", "upx", "aspack", "themida", "vmprotect",
		"enigma", "armadillo", "pecompact", "mpress", "nspack", "petite", "fsg",
		"mew", "yoda", "telock", "pklite", "winupack",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func DetectCascadingPacking(p *pe.PETarget, sigs []signatures.Signature) (*CascadingResult, error) {
	var allLayers []PackingLayer

	maxLen := 0
	for _, sig := range sigs {
		if sig.Length > maxLen {
			maxLen = sig.Length
		}
	}
	if maxLen == 0 {
		maxLen = 64
	}

	for _, section := range p.File.Sections {
		data, err := p.SectionData(section)
		if err != nil || len(data) == 0 {
			continue
		}
		entropy := pe.CalculateEntropy(data)

		var sectionMatches []PackingLayer
		seen := make(map[string]bool)

		for _, sig := range sigs {
			if sig.Length < 8 {
				continue
			}

			if sig.Category != "packer" {
				continue
			}

			for offset := 0; offset <= len(data)-sig.Length; offset++ {
				if sig.Match(data, offset) {
					key := fmt.Sprintf("%s:%d", sig.Name, offset)
					if seen[key] {
						continue
					}
					seen[key] = true

					factorEpOnly := 0.8
					if sig.EpOnly {
						factorEpOnly = 1.0
					}
					confidence := (float64(sig.Length) / float64(maxLen)) * 1.0 * factorEpOnly

					sectionMatches = append(sectionMatches, PackingLayer{
						SectionName:	section.Name,
						SignatureName:	sig.Name,
						Offset:		int64(section.Offset) + int64(offset),
						Entropy:	entropy,
						Category:	sig.Category,
						Confidence:	confidence,
						Length:		sig.Length,
					})

					break
				}
			}
		}

		sort.Slice(sectionMatches, func(i, j int) bool {
			return sectionMatches[i].Offset < sectionMatches[j].Offset
		})

		var monotonicMatches []PackingLayer
		var lastOffset int64 = -1
		for _, m := range sectionMatches {
			if lastOffset == -1 || m.Offset > lastOffset {
				monotonicMatches = append(monotonicMatches, m)
				lastOffset = m.Offset
			}
		}

		if len(monotonicMatches) > 0 {
			best := monotonicMatches[0]
			for _, m := range monotonicMatches[1:] {
				if m.Confidence > best.Confidence {
					best = m
				} else if m.Confidence == best.Confidence {
					if m.Entropy+float64(m.Length) > best.Entropy+float64(best.Length) {
						best = m
					}
				}
			}
			allLayers = append(allLayers, best)
		}
	}

	sort.Slice(allLayers, func(i, j int) bool {
		return allLayers[i].Offset < allLayers[j].Offset
	})

	var filteredLayers []PackingLayer
	var lastOffset int64 = -1
	for _, l := range allLayers {
		if lastOffset == -1 || l.Offset-lastOffset >= 16 {
			filteredLayers = append(filteredLayers, l)
			lastOffset = l.Offset
		}
	}

	totalLayers := len(filteredLayers)
	isCascading := totalLayers > 1

	displayLayers := filteredLayers
	if totalLayers > 5 {
		displayLayers = filteredLayers[:5]
	}

	for idx := range displayLayers {
		displayLayers[idx].LayerNumber = idx + 1
	}

	desc := "No packer signatures found."
	if totalLayers == 1 {
		desc = fmt.Sprintf("Single packer layer: %s (section %s)", displayLayers[0].SignatureName, displayLayers[0].SectionName)
	} else if totalLayers > 1 {
		desc = fmt.Sprintf("Cascading packing detected: %d layers. Unpack in order of increasing offset.", totalLayers)
		if totalLayers > 5 {
			desc += " Many packer signatures may be false positives due to signature noise."
		}
	}

	return &CascadingResult{
		IsCascading:	isCascading,
		Layers:		displayLayers,
		Description:	desc,
		TotalLayers:	totalLayers,
	}, nil
}
