package peanalyzer

import (
	"fmt"
	"sort"

	"github.com/eyobed101/peanalyzer/pkg/heuristics"
	"github.com/eyobed101/peanalyzer/pkg/pe"
	"github.com/eyobed101/peanalyzer/pkg/signatures"
)

type Match struct {
	SignatureName	string	`json:"signature_name"`
	Offset		int64	`json:"offset"`
	RVA		uint32	`json:"rva"`
	SectionName	string	`json:"section_name"`
	EpOnly		bool	`json:"ep_only"`
	MatchedBytes	[]byte	`json:"-"`
	Category	string	`json:"category"`
	Confidence	float64	`json:"confidence"`
}

type AnalysisResult struct {
	FilePath		string				`json:"file_path"`
	EntropyInfo		*pe.EntropyInfo			`json:"entropy"`
	Matches			[]Match				`json:"matches"`
	ScanMode		string				`json:"scan_mode"`
	TotalSignatures		int				`json:"total_signatures_loaded"`
	EntropyAnomalies	[]pe.EntropyAnomaly		`json:"entropy_anomalies"`
	SizeDiscrepancies	[]heuristics.SizeDiscrepancy	`json:"size_discrepancies"`
	Overlay			*pe.OverlayInfo			`json:"overlay"`
	StubIntelligence	*heuristics.StubIntelResult	`json:"stub_intelligence"`
	CascadingPacking	*heuristics.CascadingResult	`json:"cascading_packing"`
	IATStatus		*heuristics.IATStatus		`json:"iat_status"`
	LowEntropyInjections	[]pe.LowEntropyInjection	`json:"low_entropy_injections"`
	CompressionEncryption	[]pe.CompressionVsEncryption	`json:"compression_encryption"`

	FileHash	string	`json:"file_hash"`
	KnownMalicious	bool	`json:"known_malicious"`
	HashMatch	string	`json:"hash_match,omitempty"`

	PackerMatches		[]Match	`json:"packer_matches"`
	ProtectorMatches	[]Match	`json:"protector_matches"`
}

type Scanner struct {
	signatures	[]signatures.Signature
	hashDB		*signatures.HashDB
}

func NewScanner(signatures []signatures.Signature) *Scanner {
	return &Scanner{signatures: signatures}
}

func (s *Scanner) WithHashDB(db *signatures.HashDB) *Scanner {
	s.hashDB = db
	return s
}

func (s *Scanner) ScanFile(filePath string) (*AnalysisResult, error) {
	return s.ScanFileWithMode(filePath, "all_sections")
}

func (s *Scanner) ScanFileWithMode(filePath string, mode string) (*AnalysisResult, error) {
	target, err := pe.OpenPETarget(filePath)
	if err != nil {
		return nil, err
	}
	defer target.Close()

	entropyInfo, err := target.ComputeEntropyForFile()
	if err != nil {
		return nil, fmt.Errorf("entropy calculation failed: %w", err)
	}

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

	maxLen := 0
	for _, sig := range s.signatures {
		if sig.Length > maxLen {
			maxLen = sig.Length
		}
	}
	if maxLen == 0 {
		maxLen = 64
	}

	sigMap := make(map[string]signatures.Signature, len(s.signatures))
	for _, sig := range s.signatures {
		sigMap[sig.Name] = sig
	}

	for i := range matches {
		sig, exists := sigMap[matches[i].SignatureName]
		if exists {
			matches[i].Category = sig.Category
			factorCategory := 0.5
			if sig.Category == "packer" {
				factorCategory = 1.0
			}
			factorEpOnly := 0.8
			if sig.EpOnly {
				factorEpOnly = 1.0
			}
			matches[i].Confidence = (float64(sig.Length) / float64(maxLen)) * factorCategory * factorEpOnly
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence > matches[j].Confidence
		}
		return matches[i].SignatureName < matches[j].SignatureName
	})

	var packerMatches []Match
	var protectorMatches []Match
	for _, m := range matches {
		if m.Category == "packer" {
			packerMatches = append(packerMatches, m)
		} else if m.Category == "protector" {
			protectorMatches = append(protectorMatches, m)
		}
	}

	var anomalies []pe.EntropyAnomaly
	if entropyInfo != nil {
		anomalies = pe.DetectEntropyAnomalies(entropyInfo.Sections)
	}

	var sizeDiscrepancies []heuristics.SizeDiscrepancy
	if entropyInfo != nil {
		sizeDiscrepancies = heuristics.CheckSizeDiscrepancies(entropyInfo.Sections)
	}

	overlay, err := target.DetectOverlay()
	if err != nil {
		overlay = nil
	}

	stubIntel, err := heuristics.AnalyzeStub(target)
	if err != nil {
		stubIntel = nil
	}

	cascadingPacking, err := heuristics.DetectCascadingPacking(target, s.signatures)
	if err != nil {
		cascadingPacking = nil
	}

	iatStatus := heuristics.AnalyzeIAT(target)

	lowEntropyInjections, err := target.DetectLowEntropyInjections()
	if err != nil {
		lowEntropyInjections = []pe.LowEntropyInjection{}
	}

	compEnc := []pe.CompressionVsEncryption{}
	for _, sec := range target.File.Sections {
		secData, err := target.SectionData(sec)
		if err != nil || len(secData) == 0 {
			continue
		}
		if pe.CalculateEntropy(secData) > 7.0 {
			res := pe.AnalyzeCompressionVsEncryption(secData)
			if res != nil {
				res.SectionName = sec.Name
				compEnc = append(compEnc, *res)
			}
		}
	}

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
		FilePath:		filePath,
		EntropyInfo:		entropyInfo,
		Matches:		matches,
		ScanMode:		mode,
		TotalSignatures:	len(s.signatures),
		EntropyAnomalies:	anomalies,
		SizeDiscrepancies:	sizeDiscrepancies,
		Overlay:		overlay,
		StubIntelligence:	stubIntel,
		CascadingPacking:	cascadingPacking,
		IATStatus:		iatStatus,
		LowEntropyInjections:	lowEntropyInjections,
		CompressionEncryption:	compEnc,
		FileHash:		fileHash,
		KnownMalicious:		knownMalicious,
		HashMatch:		hashMatchSource,
		PackerMatches:		packerMatches,
		ProtectorMatches:	protectorMatches,
	}, nil
}

func (s *Scanner) scanEntryPoint(target *pe.PETarget) ([]Match, error) {
	var matches []Match
	epRVA := target.EntryPointRVA
	const scanSize = 4096

	epData, err := target.DataAtRVARaw(epRVA, scanSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read EP data: %w", err)
	}

	seen := make(map[string]bool)
	for _, sig := range s.signatures {
		if sig.Length < 12 {
			continue
		}
		if sig.Category == "compiler" || sig.Category == "installer" {
			continue
		}
		if !sig.EpOnly {
			continue
		}
		if seen[sig.Name] {
			continue
		}
		for offset := 0; offset <= len(epData)-sig.Length; offset++ {
			if sig.Match(epData, offset) {
				fileOffset, _ := offsetToFileOffset(target, epRVA, uint32(offset))
				rva := epRVA + uint32(offset)
				matches = append(matches, Match{
					SignatureName:	sig.Name,
					Offset:		fileOffset,
					RVA:		rva,
					SectionName:	target.SectionNameFromRVA(rva),
					EpOnly:		sig.EpOnly,
				})
				seen[sig.Name] = true

				break
			}
		}
	}
	return matches, nil
}

func (s *Scanner) scanAllSections(target *pe.PETarget) ([]Match, error) {
	var matches []Match
	seen := make(map[string]bool)
	for _, section := range target.File.Sections {
		data, err := target.SectionData(section)
		if err != nil {
			continue
		}
		for _, sig := range s.signatures {
			if sig.Length < 8 {
				continue
			}
			if sig.EpOnly {
				continue
			}
			key := sig.Name + ":" + section.Name
			if seen[key] {
				continue
			}
			for offset := 0; offset <= len(data)-sig.Length; offset++ {
				if sig.Match(data, offset) {
					rva := section.VirtualAddress + uint32(offset)
					fileOffset := int64(section.Offset) + int64(offset)
					matches = append(matches, Match{
						SignatureName:	sig.Name,
						Offset:		fileOffset,
						RVA:		rva,
						SectionName:	section.Name,
						EpOnly:		false,
					})
					seen[key] = true

					break
				}
			}
		}
	}
	return matches, nil
}

func (s *Scanner) scanRawFile(target *pe.PETarget) ([]Match, error) {
	rawData, err := target.RawFileData()
	if err != nil {
		return nil, fmt.Errorf("failed to read raw file: %w", err)
	}
	var matches []Match
	seen := make(map[string]bool)
	for _, sig := range s.signatures {
		if sig.Length < 8 {
			continue
		}
		if seen[sig.Name] {
			continue
		}
		for offset := 0; offset <= len(rawData)-sig.Length; offset++ {
			if sig.Match(rawData, offset) {
				rva, _ := target.RVAFromFileOffset(int64(offset))
				matches = append(matches, Match{
					SignatureName:	sig.Name,
					Offset:		int64(offset),
					RVA:		rva,
					SectionName:	target.SectionNameFromRVA(rva),
					EpOnly:		sig.EpOnly,
				})
				seen[sig.Name] = true

				break
			}
		}
	}
	return matches, nil
}

func offsetToFileOffset(target *pe.PETarget, baseRVA uint32, delta uint32) (int64, error) {
	rva := baseRVA + delta
	for _, section := range target.File.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			fileOffset := int64(section.Offset) + int64(rva-section.VirtualAddress)
			return fileOffset, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%X not in any section", rva)
}
