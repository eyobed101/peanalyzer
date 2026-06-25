package peanalyzer_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/eyobed101/peanalyzer/pkg/peanalyzer"
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

func TestHashDB(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "peanalyzer_test_hashdb")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	hashDBPath := filepath.Join(tempDir, "hashes.json")

	jsonContent := `{
		"f88876426b1d7b574f49b9ecf2020dba8a1ef86d4b8fd7b2627ed24b7f9c3029": "malware1",
		"0000000000000000000000000000000000000000000000000000000000000000": null,
		"invalid-hash": "skipped"
	}`
	if err := os.WriteFile(hashDBPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write test hash DB: %v", err)
	}

	db, err := signatures.LoadHashDB(hashDBPath)
	if err != nil {
		t.Fatalf("LoadHashDB failed: %v", err)
	}

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

	peBytes := createTinyPEBytes()
	filePath := filepath.Join(tempDir, "test.exe")
	if err := os.WriteFile(filePath, peBytes, 0644); err != nil {
		t.Fatalf("failed to write test PE: %v", err)
	}

	scanner := peanalyzer.NewScanner(nil).WithHashDB(db)
	result, err := scanner.ScanFileWithMode(filePath, "all_sections")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.FileHash == "" {
		t.Errorf("expected FileHash to be computed")
	}

	actualHash := result.FileHash
	jsonContentWithActual := fmt.Sprintf(`{"%s": "actual-malware"}`, actualHash)
	if err := os.WriteFile(hashDBPath, []byte(jsonContentWithActual), 0644); err != nil {
		t.Fatalf("failed to write updated test hash DB: %v", err)
	}

	dbUpdated, err := signatures.LoadHashDB(hashDBPath)
	if err != nil {
		t.Fatalf("LoadHashDB reload failed: %v", err)
	}

	scannerUpdated := peanalyzer.NewScanner(nil).WithHashDB(dbUpdated)
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

func TestScanEpOnly(t *testing.T) {
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

	sigs := []signatures.Signature{
		{
			Name:		"EP Packer (long)",
			Mask:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:		12,
			EpOnly:		true,
			Category:	"packer",
		},
		{
			Name:		"EP Compiler (long but ignored)",
			Mask:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:		12,
			EpOnly:		true,
			Category:	"compiler",
		},
		{
			Name:		"EP Packer (too short)",
			Mask:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:		10,
			EpOnly:		true,
			Category:	"packer",
		},
		{
			Name:		"Not EP Only Packer (skipped in ep_only)",
			Mask:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Values:		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Length:		12,
			EpOnly:		false,
			Category:	"packer",
		},
	}

	scanner := peanalyzer.NewScanner(sigs)
	result, err := scanner.ScanFileWithMode(filePath, "ep_only")
	if err != nil {
		t.Fatalf("scan ep_only failed: %v", err)
	}

	if len(result.Matches) != 1 {
		t.Errorf("expected exactly 1 match in ep_only mode, got %d", len(result.Matches))
	} else if result.Matches[0].SignatureName != "EP Packer (long)" {
		t.Errorf("expected match to be 'EP Packer (long)', got %s", result.Matches[0].SignatureName)
	}

	if result.Matches[0].Confidence <= 0 {
		t.Errorf("expected positive confidence score, got %f", result.Matches[0].Confidence)
	}
}
