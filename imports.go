package peanalyzer

// IATStatus summarizes analysis of the Import Address Table.
type IATStatus struct {
	HasIAT           bool     `json:"has_iat"`
	ImportCount      int      `json:"import_count"`
	IsTampered       bool     `json:"is_tampered"`
	DynamicAPIs      []string `json:"dynamic_apis"` // LoadLibrary/GetProcAddress if imported
	MissingIAT       bool     `json:"missing_iat"`
	ObfuscationHints []string `json:"obfuscation_hints"`
}

// AnalyzeIAT checks the PE's import table for anomalies.
func (p *PETarget) AnalyzeIAT() *IATStatus {
	status := &IATStatus{
		HasIAT:           false,
		ImportCount:      0,
		IsTampered:       false,
		DynamicAPIs:      []string{},
		ObfuscationHints: []string{},
		MissingIAT:       true,
	}
	// Check if there are any imports
	imports, err := p.File.ImportedSymbols()
	if err == nil && len(imports) > 0 {
		status.HasIAT = true
		status.MissingIAT = false
		status.ImportCount = len(imports)
		// Look for dynamic API loading indicators
		for _, sym := range imports {
			if sym == "LoadLibraryA" || sym == "LoadLibraryW" || sym == "GetProcAddress" {
				status.DynamicAPIs = append(status.DynamicAPIs, sym)
			}
		}
		if len(status.DynamicAPIs) > 0 {
			status.ObfuscationHints = append(status.ObfuscationHints, "Dynamic API resolution via LoadLibrary/GetProcAddress")
			status.IsTampered = true
		}
		// Heuristic: very few imports (e.g., < 5) in a non‑trivial executable may indicate IAT obfuscation
		if status.ImportCount < 5 && status.ImportCount > 0 {
			status.ObfuscationHints = append(status.ObfuscationHints, "Unusually small number of imports")
			status.IsTampered = true
		}
	} else {
		// No imports at all – highly suspicious for any PE that is not a kernel driver
		status.ObfuscationHints = append(status.ObfuscationHints, "No import table found (complete IAT obfuscation)")
		status.IsTampered = true
	}
	return status
}
