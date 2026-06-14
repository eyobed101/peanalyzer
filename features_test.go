package peanalyzer

import (
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectEntropyAnomalies(t *testing.T) {
	sections := []SectionEntropyResult{
		{Name: ".text1", Entropy: 4.0},
		{Name: ".text2", Entropy: 4.0},
		{Name: ".text3", Entropy: 4.0},
		{Name: ".text4", Entropy: 4.0},
		{Name: ".text5", Entropy: 4.0},
		{Name: ".text6", Entropy: 4.0},
		{Name: ".text7", Entropy: 4.0},
		{Name: ".text8", Entropy: 4.0},
		{Name: ".text9", Entropy: 4.0},
		{Name: ".text10", Entropy: 4.0},
		{Name: ".anomaly", Entropy: 7.9}, // deviates significantly
	}

	anomalies := DetectEntropyAnomalies(sections)
	if len(anomalies) != 1 {
		t.Fatalf("expected exactly 1 anomaly, got %d", len(anomalies))
	}

	if anomalies[0].SectionName != ".anomaly" {
		t.Errorf("expected anomaly section to be .anomaly, got %s", anomalies[0].SectionName)
	}

	if anomalies[0].Severity != "high" {
		t.Errorf("expected anomaly severity to be high, got %s", anomalies[0].Severity)
	}
}

func TestCheckSizeDiscrepancies(t *testing.T) {
	sections := []SectionEntropyResult{
		{Name: ".text", RawSize: 1000, VirtualSize: 1000},
		{Name: ".data", RawSize: 1000, VirtualSize: 2000}, // ratio = 2.0 >= 1.5
		{Name: ".bss", RawSize: 0, VirtualSize: 500},     // virtual > 0 and raw = 0
		{Name: ".rdata", RawSize: 500, VirtualSize: 510}, // ratio = 1.02 < 1.5
	}

	discrepancies := CheckSizeDiscrepancies(sections)
	if len(discrepancies) != 2 {
		t.Fatalf("expected exactly 2 discrepancies, got %d", len(discrepancies))
	}

	expectedNames := map[string]bool{".data": true, ".bss": true}
	for _, d := range discrepancies {
		if !expectedNames[d.SectionName] {
			t.Errorf("unexpected discrepancy section: %s", d.SectionName)
		}
		if !d.Suspicious {
			t.Errorf("discrepancy for %s not marked suspicious", d.SectionName)
		}
	}
}

func createTinyPEBytes() []byte {
	data := make([]byte, 1024)
	// DOS Header
	data[0] = 'M'
	data[1] = 'Z'
	// PE Header Offset at 0x3C
	data[0x3C] = 0x40

	// PE Header Signature
	data[0x40] = 'P'
	data[0x41] = 'E'
	data[0x42] = 0
	data[0x43] = 0

	// COFF Header (20 bytes)
	// Machine (0x14C for i386)
	data[0x44] = 0x4C
	data[0x45] = 0x01
	// NumberOfSections = 1
	data[0x46] = 1
	data[0x47] = 0
	// SizeOfOptionalHeader = 224 (0xE0)
	data[0x54] = 0xE0
	data[0x55] = 0x00
	// Characteristics = 0x102 (executable, no relocations)
	data[0x56] = 0x02
	data[0x57] = 0x01

	// Optional Header (starts at 0x58, size 224)
	// Magic = 0x10B (PE32)
	data[0x58] = 0x0B
	data[0x59] = 0x01
	// AddressOfEntryPoint = 0x1000
	data[0x68] = 0x00
	data[0x69] = 0x10
	data[0x6A] = 0x00
	data[0x6B] = 0x00

	// SectionAlignment = 0x1000
	data[0x78] = 0x00
	data[0x79] = 0x10
	data[0x7A] = 0x00
	data[0x7B] = 0x00
	// FileAlignment = 0x200
	data[0x7C] = 0x00
	data[0x7D] = 0x02
	data[0x7E] = 0x00
	// NumberOfRvaAndSizes = 16
	data[0x58+92] = 16

	// Section Header starts at 0x58 + 224 = 0x138 (size 40)
	// Section Name: ".text"
	copy(data[0x138:0x138+8], []byte(".text\x00\x00\x00"))
	// VirtualSize = 0x1000
	data[0x138+8] = 0x00
	data[0x138+9] = 0x10
	// VirtualAddress = 0x1000
	data[0x138+12] = 0x00
	data[0x138+13] = 0x10
	// SizeOfRawData = 0x200 (512 bytes)
	data[0x138+16] = 0x00
	data[0x138+17] = 0x02
	// PointerToRawData = 0x200
	data[0x138+20] = 0x00
	data[0x138+21] = 0x02

	// Fill the section data area (from offset 0x200 to 0x400)
	// Inject some anti-analysis bytecode
	// 0x0F, 0x31 is rdtsc
	data[0x200] = 0x0F
	data[0x201] = 0x31
	// 0xCC is int3
	data[0x202] = 0xCC

	return data
}

func TestOverlayAndStubIntel(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "peanalyzer_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	peBytes := createTinyPEBytes()
	// Append overlay data
	overlayBytes := []byte("This is overlay! 16+ bytes of extra data here.")
	peBytes = append(peBytes, overlayBytes...)

	filePath := filepath.Join(tempDir, "test.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	target, err := OpenPETarget(filePath)
	if err != nil {
		t.Fatalf("failed to open test PE target: %v", err)
	}
	defer target.Close()

	// 1. Test Overlay detection
	overlay, err := target.DetectOverlay()
	if err != nil {
		t.Fatalf("DetectOverlay failed: %v", err)
	}
	if !overlay.Exists {
		t.Errorf("expected overlay to exist")
	}
	if overlay.Offset != 1024 {
		t.Errorf("expected overlay offset 1024, got %d", overlay.Offset)
	}
	if overlay.Size != int64(len(overlayBytes)) {
		t.Errorf("expected overlay size %d, got %d", len(overlayBytes), overlay.Size)
	}
	expectedFirst16 := string(overlayBytes[:16])
	if string(overlay.First16) != expectedFirst16 {
		t.Errorf("expected first 16 bytes %q, got %q", expectedFirst16, string(overlay.First16))
	}

	// 2. Test Stub Intelligence
	stubIntel, err := target.AnalyzeStub()
	if err != nil {
		t.Fatalf("AnalyzeStub failed: %v", err)
	}
	if stubIntel.StubSection != ".text" {
		t.Errorf("expected stub section to be .text, got %s", stubIntel.StubSection)
	}
	if !stubIntel.HasAntiDebug {
		t.Errorf("expected HasAntiDebug to be true")
	}
	if len(stubIntel.Checks) != 2 {
		t.Fatalf("expected 2 anti-analysis checks, got %d", len(stubIntel.Checks))
	}

	matchesFound := map[string]bool{}
	for _, check := range stubIntel.Checks {
		matchesFound[check.Match] = true
	}
	if !matchesFound["rdtsc"] {
		t.Errorf("expected check for rdtsc")
	}
	if !matchesFound["int3"] {
		t.Errorf("expected check for int3")
	}
}

func TestAdvancedFeatures(t *testing.T) {
	// 1. Test AnalyzeCompressionVsEncryption with random data (likely encrypted)
	randomData := make([]byte, 2048)
	for i := range randomData {
		randomData[i] = byte(i % 256) // high entropy, uniform
	}
	resEnc := AnalyzeCompressionVsEncryption(randomData)
	if resEnc == nil {
		t.Fatalf("expected non-nil result from AnalyzeCompressionVsEncryption")
	}
	if !resEnc.LikelyEncrypted {
		t.Errorf("expected random data to be classified as likely encrypted (entropy: %.2f)", resEnc.Entropy)
	}

	// 2. Test DetectLowEntropyInjections
	tempDir, err := os.MkdirTemp("", "peanalyzer_test_low")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Build PE with one high entropy section containing a low entropy region
	peBytes := createTinyPEBytes()
	// Let's modify the section size in the PE bytes to be 2048 bytes (0x800) instead of 512 (0x200)
	// PointerToRawData = 0x200
	// SizeOfRawData at 0x138+16 = 0x800 (2048 bytes)
	peBytes[0x138+16] = 0x00
	peBytes[0x138+17] = 0x08

	// Re-slice and build the PE data to have 0x200 + 0x800 = 0xA00 (2560 bytes)
	peBytes = peBytes[:0x200]
	sectionData := make([]byte, 2048)
	// Fill first 1792 bytes with high entropy data
	for i := 0; i < 1792; i++ {
		sectionData[i] = byte(i % 256)
	}
	// Leave last 256 bytes as 0x00 (low entropy injection)
	peBytes = append(peBytes, sectionData...)

	filePath := filepath.Join(tempDir, "test_low.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	target, err := OpenPETarget(filePath)
	if err != nil {
		t.Fatalf("failed to open test PE: %v", err)
	}
	defer target.Close()

	injections, err := target.DetectLowEntropyInjections()
	if err != nil {
		t.Fatalf("DetectLowEntropyInjections failed: %v", err)
	}
	if len(injections) != 1 {
		t.Fatalf("expected exactly 1 low-entropy injection, got %d", len(injections))
	}
	if injections[0].SectionName != ".text" {
		t.Errorf("expected injection in .text, got %s", injections[0].SectionName)
	}

	// 3. Test AnalyzeIAT on a PE with no imports
	iat := target.AnalyzeIAT()
	if !iat.IsTampered {
		t.Errorf("expected IAT to be marked as tampered due to missing imports")
	}
	if !iat.MissingIAT {
		t.Errorf("expected MissingIAT to be true")
	}

	// 4. Test DetectCascadingPacking
	// Add a mock second section to target to test multi-section cascading layers
	if target.File != nil {
		importSection := &pe.Section{
			SectionHeader: pe.SectionHeader{
				Name:             ".data",
				VirtualSize:      0x1000,
				VirtualAddress:   0x2000,
				Size:             512,
				Offset:           0x300,
			},
		}
		target.File.Sections = append(target.File.Sections, importSection)
	}

	sigs := []Signature{
		{
			Name:     "UPX packer",
			Mask:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:   8,
			EpOnly:   false,
			Category: "packer",
		},
		{
			Name:     "FSG packer",
			Mask:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:   8,
			EpOnly:   false,
			Category: "packer",
		},
	}
	cascadeRes, err := target.DetectCascadingPacking(sigs)
	if err != nil {
		t.Fatalf("DetectCascadingPacking failed: %v", err)
	}
	if !cascadeRes.IsCascading {
		t.Errorf("expected cascading packing to be detected")
	}
	if len(cascadeRes.Layers) < 2 {
		t.Errorf("expected at least 2 layers, got %d", len(cascadeRes.Layers))
	}
}

func TestHashDB(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "peanalyzer_test_hashdb")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	hashDBPath := filepath.Join(tempDir, "hashes.json")
	// Write a valid hash DB JSON file
	jsonContent := `{
		"f88876426b1d7b574f49b9ecf2020dba8a1ef86d4b8fd7b2627ed24b7f9c3029": "malware1",
		"0000000000000000000000000000000000000000000000000000000000000000": null,
		"invalid-hash": "skipped"
	}`
	if err := os.WriteFile(hashDBPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write test hash DB: %v", err)
	}

	db, err := LoadHashDB(hashDBPath)
	if err != nil {
		t.Fatalf("LoadHashDB failed: %v", err)
	}

	// It should skip "invalid-hash", and store the other two valid 64-char hashes.
	if db.Len() != 2 {
		t.Errorf("expected db length 2, got %d", db.Len())
	}

	if !db.Contains("f88876426b1d7b574f49b9ecf2020dba8a1ef86d4b8fd7b2627ed24b7f9c3029") {
		t.Errorf("expected db to contain hash")
	}

	if db.Contains("invalid-hash") {
		t.Errorf("expected db not to contain invalid-hash")
	}

	if db.SourcePath() != hashDBPath {
		t.Errorf("expected source path %q, got %q", hashDBPath, db.SourcePath())
	}

	// Verify integration with ScanFileWithMode
	peBytes := createTinyPEBytes()
	filePath := filepath.Join(tempDir, "test.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	// Create scanner, attach hash DB, and scan
	scanner := NewScanner(nil).WithHashDB(db)
	result, err := scanner.ScanFileWithMode(filePath, "all_sections")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.FileHash == "" {
		t.Errorf("expected FileHash to be computed")
	}

	// Write the actual hash to our hash DB JSON, reload, and verify known_malicious is true
	actualHash := result.FileHash
	jsonContentWithActual := fmt.Sprintf(`{"%s": "actual-malware"}`, actualHash)
	if err := os.WriteFile(hashDBPath, []byte(jsonContentWithActual), 0644); err != nil {
		t.Fatalf("failed to write updated test hash DB: %v", err)
	}

	dbUpdated, err := LoadHashDB(hashDBPath)
	if err != nil {
		t.Fatalf("LoadHashDB reload failed: %v", err)
	}

	scannerUpdated := NewScanner(nil).WithHashDB(dbUpdated)
	resultUpdated, err := scannerUpdated.ScanFileWithMode(filePath, "all_sections")
	if err != nil {
		t.Fatalf("scan with updated hash DB failed: %v", err)
	}

	if !resultUpdated.KnownMalicious {
		t.Errorf("expected KnownMalicious to be true")
	}

	if resultUpdated.HashMatch != hashDBPath {
		t.Errorf("expected HashMatch to be %q, got %q", hashDBPath, resultUpdated.HashMatch)
	}
}

func TestCleanHeuristics(t *testing.T) {
	// Test inferCategory
	if inferCategory("UPX v0.89") != "packer" {
		t.Errorf("expected UPX to be packer")
	}
	if inferCategory("Themida protector") != "protector" {
		t.Errorf("expected Themida to be protector")
	}
	if inferCategory("Microsoft Visual C++") != "compiler" {
		t.Errorf("expected VC++ to be compiler")
	}
	if inferCategory("Nullsoft Installer") != "installer" {
		t.Errorf("expected Nullsoft to be installer")
	}

	// Test strict NewSignature token and length checks
	_, err := NewSignature("Short", "55 8B", false)
	if err == nil {
		t.Errorf("expected error for too-short pattern (length < 8 bytes)")
	}

	_, err = NewSignature("InvalidToken", "55 8B EC 6A FF 68 8 ??", false)
	if err == nil {
		t.Errorf("expected error for invalid single-digit token '8'")
	}

	sigValid, err := NewSignature("Valid", "55 8B EC 6A FF 68 00 00", false)
	if err != nil {
		t.Fatalf("expected no error for valid signature, got: %v", err)
	}
	if sigValid.Length != 8 {
		t.Errorf("expected length 8, got %d", sigValid.Length)
	}

	// Test ep_only scan filters
	tempDir, err := os.MkdirTemp("", "peanalyzer_test_clean")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	peBytes := createTinyPEBytes()
	filePath := filepath.Join(tempDir, "test.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	// Signatures for scanning
	sigs := []Signature{
		{
			Name:     "EP Packer (long)",
			Mask:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:   12,
			EpOnly:   true,
			Category: "packer",
		},
		{
			Name:     "EP Compiler (long but ignored)",
			Mask:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:   12,
			EpOnly:   true,
			Category: "compiler",
		},
		{
			Name:     "EP Packer (too short)",
			Mask:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:   10,
			EpOnly:   true,
			Category: "packer",
		},
		{
			Name:     "Not EP Only Packer (skipped in ep_only)",
			Mask:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:   12,
			EpOnly:   false,
			Category: "packer",
		},
	}

	scanner := NewScanner(sigs)
	result, err := scanner.ScanFileWithMode(filePath, "ep_only")
	if err != nil {
		t.Fatalf("scan ep_only failed: %v", err)
	}

	// Only "EP Packer (long)" should match
	if len(result.Matches) != 1 {
		t.Errorf("expected exactly 1 match in ep_only mode, got %d", len(result.Matches))
	} else if result.Matches[0].SignatureName != "EP Packer (long)" {
		t.Errorf("expected match to be 'EP Packer (long)', got %s", result.Matches[0].SignatureName)
	}

	// Verify confidence calculation
	if result.Matches[0].Confidence <= 0 {
		t.Errorf("expected positive confidence score, got %f", result.Matches[0].Confidence)
	}
}


