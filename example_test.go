package peanalyzer_test

import (
	"fmt"
	"log"
	"peanalyzer"
)

// Example demonstrates how to integrate the package into another application.
func Example() {
	// 1. Load PEiD signatures (you need a userdb.txt file)
	signatures, err := peanalyzer.LoadSignaturesFromFile("userdb.txt")
	if err != nil {
		log.Printf("Warning: could not load signatures: %v", err)
		// Continue without signatures or use built-in ones
		signatures = []peanalyzer.Signature{}
	}

	// 2. Create a scanner
	scanner := peanalyzer.NewScanner(signatures)

	// 3. Analyze a PE file
	result, err := scanner.ScanFileWithMode("sample.exe", "all_sections")
	if err != nil {
		log.Fatal(err)
	}

	// 4. Use detailed output
	fmt.Printf("File: %s\n", result.FilePath)
	fmt.Printf("Overall entropy: %.4f (max 8.0)\n", result.EntropyInfo.FileEntropy)
	fmt.Printf("Sections entropy:\n")
	for _, sec := range result.EntropyInfo.Sections {
		fmt.Printf("  %-8s : %.4f (size: %d bytes)\n", sec.Name, sec.Entropy, sec.RawSize)
	}

	fmt.Printf("\nMatched signatures (%d):\n", len(result.Matches))
	for _, match := range result.Matches {
		fmt.Printf("  [+] %s at RVA 0x%X (offset 0x%X) in section %s\n",
			match.SignatureName, match.RVA, match.Offset, match.SectionName)
	}
}

// Example_entropyOnly shows entropy calculation without signatures.
func Example_entropyOnly() {
	target, err := peanalyzer.OpenPETarget("sample.exe")
	if err != nil {
		log.Fatal(err)
	}
	defer target.Close()

	entropyInfo, err := target.ComputeEntropyForFile()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("File entropy: %.4f\n", entropyInfo.FileEntropy)
	for _, sec := range entropyInfo.Sections {
		fmt.Printf("Section %s: entropy %.4f\n", sec.Name, sec.Entropy)
	}
}

// Example_signatureOnly shows how to match raw byte slices.
func Example_signatureOnly() {
	sig, _ := peanalyzer.NewSignature("TestSig", "55 8B EC 6A FF ??", false)
	data := []byte{0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x00, 0x00}
	if sig.Match(data, 0) {
		fmt.Println("Signature matched at offset 0")
	}
	// Output: Signature matched at offset 0
}
