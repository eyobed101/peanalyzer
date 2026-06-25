package pe_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eyobed101/peanalyzer/pkg/pe"
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

	data[0x78] = 0x00
	data[0x79] = 0x20
	data[0x7A] = 0x00
	data[0x7B] = 0x00

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

func TestCalculateEntropy(t *testing.T) {
	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	e := pe.CalculateEntropy(uniform)
	if e < 7.9 || e > 8.0 {
		t.Errorf("expected entropy ~8.0 for fully uniform data, got %.4f", e)
	}

	zeros := make([]byte, 256)
	e2 := pe.CalculateEntropy(zeros)
	if e2 != 0.0 {
		t.Errorf("expected entropy 0.0 for all-zero data, got %.4f", e2)
	}

	e3 := pe.CalculateEntropy([]byte{})
	if e3 != 0.0 {
		t.Errorf("expected entropy 0.0 for empty data, got %.4f", e3)
	}
}

func TestDetectEntropyAnomalies(t *testing.T) {
	sections := []pe.SectionEntropyResult{
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
		{Name: ".anomaly", Entropy: 7.9},
	}

	anomalies := pe.DetectEntropyAnomalies(sections)
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

func TestCompressionVsEncryption(t *testing.T) {
	randomData := make([]byte, 2048)
	for i := range randomData {
		randomData[i] = byte(i % 256)
	}
	res := pe.AnalyzeCompressionVsEncryption(randomData)
	if res == nil {
		t.Fatalf("expected non-nil result from AnalyzeCompressionVsEncryption")
	}
	if !res.LikelyEncrypted {
		t.Errorf("expected random data to be classified as likely encrypted (entropy: %.2f)", res.Entropy)
	}
}

func TestOverlayDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pe_test_overlay")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	peBytes := createTinyPEBytes()
	overlayBytes := []byte("This is overlay! 16+ bytes of extra data here.")
	peBytes = append(peBytes, overlayBytes...)

	filePath := filepath.Join(tempDir, "test.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	target, err := pe.OpenPETarget(filePath)
	if err != nil {
		t.Fatalf("failed to open test PE target: %v", err)
	}
	defer target.Close()

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
}

func TestLowEntropyInjections(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pe_test_low")
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

	filePath := filepath.Join(tempDir, "test_low.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	target, err := pe.OpenPETarget(filePath)
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
}
