package signatures_test

import (
	"testing"

	"github.com/eyobed101/peanalyzer/pkg/signatures"
)

func TestNewSignatureValidation(t *testing.T) {
	_, err := signatures.NewSignature("Short", "55 8B", false)
	if err == nil {
		t.Errorf("expected error for too-short pattern (length < 8 bytes)")
	}

	_, err = signatures.NewSignature("InvalidToken", "55 8B EC 6A FF 68 8 ??", false)
	if err == nil {
		t.Errorf("expected error for invalid single-digit token '8'")
	}

	sigValid, err := signatures.NewSignature("Valid", "55 8B EC 6A FF 68 00 00", false)
	if err != nil {
		t.Fatalf("expected no error for valid signature, got: %v", err)
	}
	if sigValid.Length != 8 {
		t.Errorf("expected length 8, got %d", sigValid.Length)
	}
}

func TestSignatureMatch(t *testing.T) {
	sig, err := signatures.NewSignature("TestSig", "55 8B EC 6A FF ?? ?? ??", false)
	if err != nil {
		t.Fatalf("failed to create signature: %v", err)
	}
	data := []byte{0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x00, 0x00, 0x00}
	if !sig.Match(data, 0) {
		t.Errorf("expected signature to match at offset 0")
	}

	data2 := []byte{0x00, 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x00, 0x00, 0x00}
	if !sig.Match(data2, 1) {
		t.Errorf("expected signature to match at offset 1")
	}

	data3 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if sig.Match(data3, 0) {
		t.Errorf("expected signature NOT to match")
	}
}

func TestInferCategory(t *testing.T) {
	if signatures.InferCategory("UPX v0.89") != "packer" {
		t.Errorf("expected UPX to be packer")
	}
	if signatures.InferCategory("Themida protector") != "protector" {
		t.Errorf("expected Themida to be protector")
	}
	if signatures.InferCategory("Microsoft Visual C++") != "compiler" {
		t.Errorf("expected VC++ to be compiler")
	}
	if signatures.InferCategory("Nullsoft Installer") != "installer" {
		t.Errorf("expected Nullsoft to be installer")
	}
}
