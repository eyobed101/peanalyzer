package peanalyzer

import (
	"fmt"
	"strings"
)

// PackingLayer represents a single packing/encryption layer detected in a section.
type PackingLayer struct {
	SectionName   string  `json:"section_name"`
	SignatureName string  `json:"signature_name"`
	Offset        int64   `json:"offset"`
	Entropy       float64 `json:"entropy"`
	LayerNumber   int     `json:"layer_number"`
}

// CascadingResult contains results of cascading packer analysis.
type CascadingResult struct {
	IsCascading bool           `json:"is_cascading"`
	Layers      []PackingLayer `json:"layers"`
	Description string         `json:"description"`
	TotalLayers int            `json:"total_layers"`
}

// isPackerSignature returns true if the signature name indicates a packer/crypter/protector.
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

// DetectCascadingPacking scans all sections for packer signatures and reports multi‑layer packing.
func (p *PETarget) DetectCascadingPacking(signatures []Signature) (*CascadingResult, error) {
	layers := []PackingLayer{}
	for _, section := range p.File.Sections {
		data, err := p.SectionData(section)
		if err != nil || len(data) == 0 {
			continue
		}
		entropy := CalculateEntropy(data)
		for _, sig := range signatures {
			if !isPackerSignature(sig.Name) {
				continue
			}
			// Find first match in this section
			for offset := 0; offset <= len(data)-sig.Length; offset++ {
				if sig.Match(data, offset) {
					layers = append(layers, PackingLayer{
						SectionName:   section.Name,
						SignatureName: sig.Name,
						Offset:        int64(section.Offset) + int64(offset),
						Entropy:       entropy,
					})
					break
				}
			}
		}
	}
	// Sort by offset (ascending) and assign layer numbers
	for i := range layers {
		for j := i + 1; j < len(layers); j++ {
			if layers[i].Offset > layers[j].Offset {
				layers[i], layers[j] = layers[j], layers[i]
			}
		}
	}
	for idx := range layers {
		layers[idx].LayerNumber = idx + 1
	}
	total := len(layers)
	isCascading := total > 1
	desc := "No packer signatures found."
	if total == 1 {
		desc = fmt.Sprintf("Single packer layer: %s (section %s)", layers[0].SignatureName, layers[0].SectionName)
	} else if total > 1 {
		desc = fmt.Sprintf("Cascading packing detected: %d layers. Unpack in order of increasing offset.", total)
	}
	return &CascadingResult{
		IsCascading: isCascading,
		Layers:      layers,
		Description: desc,
		TotalLayers: total,
	}, nil
}
