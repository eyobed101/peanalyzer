package heuristics_test

import (
	debugpe "debug/pe"
	"os"
	"path/filepath"
	"testing"

	"github.com/eyobed101/peanalyzer/pkg/heuristics"
	"github.com/eyobed101/peanalyzer/pkg/pe"
	"github.com/eyobed101/peanalyzer/pkg/signatures"
)

func createTinyPEBytes() []byte {
	data := make([]byte, 1024)
	data[0] = 'M'
	data[1] = 'Z'
	data[0x3C] = 0x40
	data[0x40] = 'P'
	data[0x41] = 'E'
	data[0x42] = 0
	data[0x43] = 0
	data[0x44] = 0x4C
	data[0x45] = 0x01
	data[0x46] = 1
	data[0x47] = 0
	data[0x54] = 0xE0
	data[0x55] = 0x00
	data[0x56] = 0x02
	data[0x57] = 0x01
	data[0x58] = 0x0B
	data[0x59] = 0x01
	data[0x68] = 0x00
	data[0x69] = 0x10
	data[0x6A] = 0x00
	data[0x6B] = 0x00
	data[0x74] = 0x00
	data[0x75] = 0x10
	data[0x76] = 0x00
	data[0x77] = 0x00
	data[0x7C] = 0x00
	data[0x7D] = 0x02
	data[0x7E] = 0x00
	data[0x58+92] = 16
	copy(data[0x138:0x138+8], []byte(".text\x00\x00\x00"))
	data[0x138+8] = 0x00
	data[0x138+9] = 0x10
	data[0x138+12] = 0x00
	data[0x138+13] = 0x10
	data[0x138+16] = 0x00
	data[0x138+17] = 0x02
	data[0x138+20] = 0x00
	data[0x138+21] = 0x02
	data[0x200] = 0x0F
	data[0x201] = 0x31
	data[0x202] = 0xCC
	return data
}

func TestCheckSizeDiscrepancies(t *testing.T) {
	sections := []pe.SectionEntropyResult{
		{Name: ".text", RawSize: 1000, VirtualSize: 1000},
		{Name: ".data", RawSize: 1000, VirtualSize: 2000},
		{Name: ".bss", RawSize: 0, VirtualSize: 500},
		{Name: ".rdata", RawSize: 500, VirtualSize: 510},
	}

	discrepancies := heuristics.CheckSizeDiscrepancies(sections)
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

func TestStubIntelligence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "heuristics_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	peBytes := createTinyPEBytes()
	filePath := filepath.Join(tempDir, "test.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	target, err := pe.OpenPETarget(filePath)
	if err != nil {
		t.Fatalf("failed to open test PE target: %v", err)
	}
	defer target.Close()

	stubIntel, err := heuristics.AnalyzeStub(target)
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

func TestAnalyzeIAT(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "heuristics_iat_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	peBytes := createTinyPEBytes()
	filePath := filepath.Join(tempDir, "test.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	target, err := pe.OpenPETarget(filePath)
	if err != nil {
		t.Fatalf("failed to open test PE: %v", err)
	}
	defer target.Close()

	iat := heuristics.AnalyzeIAT(target)
	if !iat.IsTampered {
		t.Errorf("expected IAT to be marked as tampered due to missing imports")
	}
	if !iat.MissingIAT {
		t.Errorf("expected MissingIAT to be true")
	}
}

func TestDetectCascadingPacking(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "heuristics_cascade_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	peBytes := createTinyPEBytes()
	peBytes[0x138+16] = 0x00
	peBytes[0x138+17] = 0x08
	peBytes = peBytes[:0x200]
	sectionData := make([]byte, 2048)
	for i := 0; i < 1792; i++ {
		sectionData[i] = byte(i % 256)
	}
	peBytes = append(peBytes, sectionData...)

	filePath := filepath.Join(tempDir, "test_cascade.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	target, err := pe.OpenPETarget(filePath)
	if err != nil {
		t.Fatalf("failed to open test PE: %v", err)
	}
	defer target.Close()

	sigs := []signatures.Signature{
		{
			Name:		"UPX packer",
			Mask:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:		8,
			EpOnly:		false,
			Category:	"packer",
		},
		{
			Name:		"FSG packer",
			Mask:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:		8,
			EpOnly:		false,
			Category:	"packer",
		},
	}

	importSection := &debugpe.Section{
		SectionHeader: debugpe.SectionHeader{
			Name:		".data",
			VirtualSize:	0x1000,
			VirtualAddress:	0x2000,
			Size:		512,
			Offset:		0x300,
		},
	}
	target.File.Sections = append(target.File.Sections, importSection)

	cascadeRes, err := heuristics.DetectCascadingPacking(target, sigs)
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
