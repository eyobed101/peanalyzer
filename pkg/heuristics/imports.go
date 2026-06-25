package heuristics

import (
	"github.com/eyobed101/peanalyzer/pkg/pe"
)

type IATStatus struct {
	HasIAT			bool		`json:"has_iat"`
	ImportCount		int		`json:"import_count"`
	IsTampered		bool		`json:"is_tampered"`
	DynamicAPIs		[]string	`json:"dynamic_apis"`
	MissingIAT		bool		`json:"missing_iat"`
	ObfuscationHints	[]string	`json:"obfuscation_hints"`
}

func AnalyzeIAT(p *pe.PETarget) *IATStatus {
	status := &IATStatus{
		HasIAT:			false,
		ImportCount:		0,
		IsTampered:		false,
		DynamicAPIs:		[]string{},
		ObfuscationHints:	[]string{},
		MissingIAT:		true,
	}

	imports, err := p.File.ImportedSymbols()
	if err == nil && len(imports) > 0 {
		status.HasIAT = true
		status.MissingIAT = false
		status.ImportCount = len(imports)

		for _, sym := range imports {
			if sym == "LoadLibraryA" || sym == "LoadLibraryW" || sym == "GetProcAddress" {
				status.DynamicAPIs = append(status.DynamicAPIs, sym)
			}
		}
		if len(status.DynamicAPIs) > 0 {
			status.ObfuscationHints = append(status.ObfuscationHints, "Dynamic API resolution via LoadLibrary/GetProcAddress")
			status.IsTampered = true
		}

		if status.ImportCount < 5 && status.ImportCount > 0 {
			status.ObfuscationHints = append(status.ObfuscationHints, "Unusually small number of imports")
			status.IsTampered = true
		}
	} else {
		status.ObfuscationHints = append(status.ObfuscationHints, "No import table found (complete IAT obfuscation)")
		status.IsTampered = true
	}
	return status
}
