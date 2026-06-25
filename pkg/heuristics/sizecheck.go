package heuristics

import (
	"github.com/eyobed101/peanalyzer/pkg/pe"
)

type SizeDiscrepancy struct {
	SectionName	string	`json:"section_name"`
	RawSize		uint32	`json:"raw_size"`
	VirtualSize	uint32	`json:"virtual_size"`
	Ratio		float64	`json:"ratio"`
	Suspicious	bool	`json:"suspicious"`
}

func CheckSizeDiscrepancies(sections []pe.SectionEntropyResult) []SizeDiscrepancy {
	var discrepancies []SizeDiscrepancy
	for _, sec := range sections {
		var ratio float64
		suspicious := false

		if sec.RawSize > 0 {
			ratio = float64(sec.VirtualSize) / float64(sec.RawSize)
		} else if sec.VirtualSize > 0 {
			suspicious = true
		}

		if ratio >= 1.5 {
			suspicious = true
		}

		if suspicious {
			discrepancies = append(discrepancies, SizeDiscrepancy{
				SectionName:	sec.Name,
				RawSize:	sec.RawSize,
				VirtualSize:	sec.VirtualSize,
				Ratio:		ratio,
				Suspicious:	true,
			})
		}
	}
	return discrepancies
}
