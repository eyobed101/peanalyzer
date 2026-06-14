// Package peanalyzer provides entropy calculation and PEiD-style signature matching
// for PE (Portable Executable) files. It is designed to be integrated into security
// analysis tools, malware sandboxes, or file inspection applications.
//
// Features:
//   - Shannon entropy calculation for files, PE sections, and arbitrary byte slices
//   - PEiD signature matcher (userdb.txt format) with wildcard support (??)
//   - Detailed analysis results: per-section entropy, matched signatures with offsets
//   - Flexible scanning modes: entry point only, all sections, or raw file
//
// Example:
//
//	signatures, _ := peanalyzer.LoadSignaturesFromFile("userdb.txt")
//	scanner := peanalyzer.NewScanner(signatures)
//	result, _ := scanner.ScanFile("sample.exe")
//	fmt.Printf("File entropy: %.4f\n", result.EntropyInfo.FileEntropy)
//	for _, match := range result.Matches {
//	    fmt.Printf("Matched: %s at RVA 0x%X (section %s)\n",
//	        match.SignatureName, match.RVA, match.SectionName)
//	}
package peanalyzer
