package peanalyzer

import (
	"fmt"
)

// Match represents a successful signature match at a specific location.
type Match struct {
	SignatureName string `json:"signature_name"`
	Offset        int64  `json:"offset"`       // File offset where matched
	RVA           uint32 `json:"rva"`          // Relative virtual address
	SectionName   string `json:"section_name"` // Section containing the match
	EpOnly        bool   `json:"ep_only"`      // Whether signature required EP scanning
	MatchedBytes  []byte `json:"-"`            // Optional: first few bytes for debugging
}

// AnalysisResult is the complete output of scanning a file.
type AnalysisResult struct {
	FilePath              string                    `json:"file_path"`
	EntropyInfo           *EntropyInfo              `json:"entropy"`
	Matches               []Match                   `json:"matches"`
	ScanMode              string                    `json:"scan_mode"` // "ep_only", "all_sections", "raw"
	TotalSignatures       int                       `json:"total_signatures_loaded"`
	EntropyAnomalies      []EntropyAnomaly          `json:"entropy_anomalies"`
	SizeDiscrepancies     []SizeDiscrepancy         `json:"size_discrepancies"`
	Overlay               *OverlayInfo              `json:"overlay"`
	StubIntelligence      *StubIntelResult          `json:"stub_intelligence"`
	CascadingPacking      *CascadingResult          `json:"cascading_packing"`
	IATStatus             *IATStatus                `json:"iat_status"`
	LowEntropyInjections  []LowEntropyInjection     `json:"low_entropy_injections"`
	CompressionEncryption []CompressionVsEncryption `json:"compression_encryption"`
	// Hash-based detection
	FileHash       string `json:"file_hash"`              // SHA256 of the scanned file
	KnownMalicious bool   `json:"known_malicious"`        // true if hash matched the HashDB
	HashMatch      string `json:"hash_match,omitempty"`   // source path of the HashDB that matched
}

// Scanner performs entropy and signature analysis on PE files.
type Scanner struct {
	signatures []Signature
	hashDB     *HashDB // optional – for hash-based malicious file detection
}

// NewScanner creates a scanner with the given signatures.
func NewScanner(signatures []Signature) *Scanner {
	return &Scanner{signatures: signatures}
}

// WithHashDB attaches a HashDB to the scanner and returns the scanner for chaining.
// When set, every scan computes the file's SHA256 and checks it against the database.
func (s *Scanner) WithHashDB(db *HashDB) *Scanner {
	s.hashDB = db
	return s
}

// ScanFile analyzes a PE file using default settings (all sections, EP scan).
func (s *Scanner) ScanFile(filePath string) (*AnalysisResult, error) {
	return s.ScanFileWithMode(filePath, "all_sections")
}

// ScanFileWithMode analyzes a PE file with the specified scan mode.
// Modes: "ep_only" (only entry point area), "all_sections" (all sections),
// "raw" (entire file, slower).
func (s *Scanner) ScanFileWithMode(filePath string, mode string) (*AnalysisResult, error) {
	target, err := OpenPETarget(filePath)
	if err != nil {
		return nil, err
	}
	defer target.Close()

	// Compute entropy
	entropyInfo, err := target.ComputeEntropyForFile()
	if err != nil {
		return nil, fmt.Errorf("entropy calculation failed: %w", err)
	}

	// Perform signature matching
	var matches []Match
	switch mode {
	case "ep_only":
		matches, err = s.scanEntryPoint(target)
	case "all_sections":
		matches, err = s.scanAllSections(target)
	case "raw":
		matches, err = s.scanRawFile(target)
	default:
		return nil, fmt.Errorf("unknown scan mode: %s", mode)
	}
	if err != nil {
		return nil, err
	}

	// Detect entropy anomalies
	var anomalies []EntropyAnomaly
	if entropyInfo != nil {
		anomalies = DetectEntropyAnomalies(entropyInfo.Sections)
	}

	// Check for size discrepancies
	var sizeDiscrepancies []SizeDiscrepancy
	if entropyInfo != nil {
		sizeDiscrepancies = CheckSizeDiscrepancies(entropyInfo.Sections)
	}

	// Detect overlay
	overlay, err := target.DetectOverlay()
	if err != nil {
		overlay = nil
	}

	// Analyze stub intelligence
	stubIntel, err := target.AnalyzeStub()
	if err != nil {
		stubIntel = nil
	}

	// Detect cascading packing
	cascadingPacking, err := target.DetectCascadingPacking(s.signatures)
	if err != nil {
		cascadingPacking = nil
	}

	// Analyze Import Address Table
	iatStatus := target.AnalyzeIAT()

	// Detect low-entropy injections
	lowEntropyInjections, err := target.DetectLowEntropyInjections()
	if err != nil {
		lowEntropyInjections = []LowEntropyInjection{}
	}

	// Analyze compression vs encryption
	compEnc := []CompressionVsEncryption{}
	for _, sec := range target.File.Sections {
		secData, err := target.SectionData(sec)
		if err != nil || len(secData) == 0 {
			continue
		}
		if CalculateEntropy(secData) > 7.0 {
			res := AnalyzeCompressionVsEncryption(secData)
			if res != nil {
				res.SectionName = sec.Name
				compEnc = append(compEnc, *res)
			}
		}
	}

	// Hash-based known-malicious detection
	var fileHash string
	var knownMalicious bool
	var hashMatchSource string
	if s.hashDB != nil {
		h, err := target.SHA256()
		if err == nil {
			fileHash = h
			if s.hashDB.Contains(h) {
				knownMalicious = true
				hashMatchSource = s.hashDB.SourcePath()
			}
		}
	}

	return &AnalysisResult{
		FilePath:              filePath,
		EntropyInfo:           entropyInfo,
		Matches:               matches,
		ScanMode:              mode,
		TotalSignatures:       len(s.signatures),
		EntropyAnomalies:      anomalies,
		SizeDiscrepancies:     sizeDiscrepancies,
		Overlay:               overlay,
		StubIntelligence:      stubIntel,
		CascadingPacking:      cascadingPacking,
		IATStatus:             iatStatus,
		LowEntropyInjections:  lowEntropyInjections,
		CompressionEncryption: compEnc,
		FileHash:              fileHash,
		KnownMalicious:        knownMalicious,
		HashMatch:             hashMatchSource,
	}, nil
}

// scanEntryPoint only scans the area around the entry point (first 4096 bytes)
func (s *Scanner) scanEntryPoint(target *PETarget) ([]Match, error) {
	var matches []Match
	epRVA := target.EntryPointRVA
	const scanSize = 4096

	epData, err := target.DataAtRVARaw(epRVA, scanSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read EP data: %w", err)
	}

	for _, sig := range s.signatures {
		if !sig.EpOnly {
			// In ep_only mode we still only scan EP region, but we skip signatures that
			// are not marked ep_only? Actually PEiD in ep_only mode only scans signatures
			// that have ep_only=true. But we'll scan all signatures at EP if user requests EP mode.
			// We'll follow: in "ep_only" mode, only consider signatures where EpOnly==true.
			// But for flexibility, we'll allow all signatures at EP location.
			// We'll keep as is for now.
		}
		for offset := 0; offset <= len(epData)-sig.Length; offset++ {
			if sig.Match(epData, offset) {
				fileOffset, _ := offsetToFileOffset(target, epRVA, uint32(offset))
				rva := epRVA + uint32(offset)
				matches = append(matches, Match{
					SignatureName: sig.Name,
					Offset:        fileOffset,
					RVA:           rva,
					SectionName:   target.SectionNameFromRVA(rva),
					EpOnly:        sig.EpOnly,
				})
				// Break after first match per signature at EP area (typical PEiD behavior)
				break
			}
		}
	}
	return matches, nil
}

// scanAllSections scans every section of the PE file for all signatures.
func (s *Scanner) scanAllSections(target *PETarget) ([]Match, error) {
	var matches []Match
	for _, section := range target.File.Sections {
		data, err := target.SectionData(section)
		if err != nil {
			continue // skip unreadable sections
		}
		for _, sig := range s.signatures {
			if sig.EpOnly {
				// EpOnly signatures should only be scanned at EP, skip in all_sections mode.
				// But some tools still scan them. We'll skip them to match PEiD default.
				continue
			}
			for offset := 0; offset <= len(data)-sig.Length; offset++ {
				if sig.Match(data, offset) {
					rva := section.VirtualAddress + uint32(offset)
					fileOffset := int64(section.Offset) + int64(offset)
					matches = append(matches, Match{
						SignatureName: sig.Name,
						Offset:        fileOffset,
						RVA:           rva,
						SectionName:   section.Name,
						EpOnly:        false,
					})
					// Break after first match in this section for this signature
					break
				}
			}
		}
	}
	return matches, nil
}

// scanRawFile scans the entire raw file (header+all sections) for all signatures.
// This is the slowest but most thorough mode.
func (s *Scanner) scanRawFile(target *PETarget) ([]Match, error) {
	rawData, err := target.RawFileData()
	if err != nil {
		return nil, fmt.Errorf("failed to read raw file: %w", err)
	}
	var matches []Match
	for _, sig := range s.signatures {
		for offset := 0; offset <= len(rawData)-sig.Length; offset++ {
			if sig.Match(rawData, offset) {
				rva, _ := target.RVAFromFileOffset(int64(offset))
				matches = append(matches, Match{
					SignatureName: sig.Name,
					Offset:        int64(offset),
					RVA:           rva,
					SectionName:   target.SectionNameFromRVA(rva),
					EpOnly:        sig.EpOnly,
				})
				// break after first occurrence? PEiD reports first match only per signature.
				// We'll break to avoid flooding.
				break
			}
		}
	}
	return matches, nil
}

// Helper: convert RVA+offset to file offset (approximate)
func offsetToFileOffset(target *PETarget, baseRVA uint32, delta uint32) (int64, error) {
	rva := baseRVA + delta
	for _, section := range target.File.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			fileOffset := int64(section.Offset) + int64(rva-section.VirtualAddress)
			return fileOffset, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%X not in any section", rva)
}
