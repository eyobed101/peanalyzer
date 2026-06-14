# peanalyzer

[![Go Reference](https://pkg.go.dev/badge/peanalyzer.svg)](https://pkg.go.dev/peanalyzer)
[![Go Report Card](https://goreportcard.com/badge/github.com/eyobed101/peanalyzer)](https://goreportcard.com/report/github.com/eyobed101/peanalyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

`peanalyzer` is a high-performance Go package for analyzing Windows PE (Portable Executable) files. It combines **Shannon entropy calculation**, **advanced packer heuristics**, **evasion stub analysis**, and a **PEiD-style signature matcher** to detect packers, cryptors, protectors, and compilers. It is designed to be easily integrated into security tools, malware sandboxes, or threat intelligence platforms.

---

## ✨ Features

- **Entropy Analysis** – Computes Shannon entropy for entire files and individual PE sections. High entropy (>6.5) suggests packed or encrypted content.
- **PEiD Signature Matching** – Matches patterns from a `userdb.txt` signature database with strict token and minimum-length (8 bytes) verification.
- **Category & Confidence Scoring** – Automatically infers whether a signature belongs to a `packer`, `protector`, `compiler`, or `installer`. Assigns a confidence score to each match based on length, scan mode, and category.
- **Multi-Layer / Cascading Packing Detection** – Detects recursive packer configurations (e.g. UPX inside a cryptor), grouping by section and capping noise layers.
- **Evasion Stub Intelligence** – Scans the entry point section for anti-debug, anti-VM, and sandbox bypass opcodes (`rdtsc`, `int3`, `cpuid`, `sidt/sgdt`, `in eax, dx`, `jmp self / ebfe`).
- **Import Table (IAT) Tampering Heuristics** – Identifies hidden or suspicious IAT setups, empty import structures, and dynamic API resolution (`LoadLibrary`, `GetProcAddress`).
- **Low-Entropy Injection Detection** – Searches high-entropy sections for sliding 256-byte windows of suspiciously low entropy.
- **Compression vs Encryption Classifier** – Differentiates compressed sections from encrypted ones using byte-frequency distribution.
- **Deterministic Hash-Based Detection** – Complements heuristic analysis by comparing target executable SHA256 hashes against a known-malicious JSON database.

---

## 📦 Installation

`peanalyzer` is a **library** (not a standalone executable). To use it in your own Go project:

1. **Create or navigate to your Go application** (it must have a `go.mod` file).  
   If you don't have one yet, initialize it:
   ```bash
   go mod init myapp
   ```

2. **Import the package** in your `.go` code:
   ```go
   import "github.com/eyobed101/peanalyzer"
   ```

3. **Run `go mod tidy`** – this automatically downloads the library and adds it as a dependency:
   ```bash
   go mod tidy
   ```

---

## 📄 Signature Database

The package uses a signature database in the classic PEiD `userdb.txt` format. You can obtain a comprehensive, up-to-date database from the [peid-python](https://github.com/CrackerCat/peid-python) project.

### Download the Database

The file is located at `src/peid/db/userdb.txt` in the repository. You can download it directly using the raw URL:

*   **Direct Download**: [raw userdb.txt](https://raw.githubusercontent.com/CrackerCat/peid-python/main/src/peid/db/userdb.txt)

Place the downloaded `userdb.txt` file in your project's working directory, or provide its full path to the `LoadSignaturesFromFile` function.

---

## 🚀 Usage Example

Below is the implementation of a full-featured CLI tool showing how to load signatures, attach a hash database, run scans in different modes, and output structured human-readable results:

```go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/eyobed101/peanalyzer"
)

var (
	// Command line flags
	sigFile    = flag.String("sig", "userdb.txt", "Path to PEiD signature file (userdb.txt)")
	hashFile   = flag.String("hashdb", "", "Path to JSON file with known malicious SHA256 hashes")
	mode       = flag.String("mode", "all_sections", "Scan mode: ep_only, all_sections, raw")
	outputJSON = flag.Bool("json", false, "Output result in JSON format")
	help       = flag.Bool("help", false, "Show this help message")
	version    = flag.Bool("version", false, "Show version information")
)

const versionStr = "peanalyzer-cli v1.1.0"

func main() {
	flag.Usage = usage
	flag.Parse()

	if *help {
		usage()
		os.Exit(0)
	}

	if *version {
		fmt.Println(versionStr)
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing PE file path")
		usage()
		os.Exit(1)
	}
	peFile := flag.Arg(0)

	validModes := map[string]bool{"ep_only": true, "all_sections": true, "raw": true}
	if !validModes[*mode] {
		fmt.Fprintf(os.Stderr, "Error: invalid mode '%s'. Must be one of: ep_only, all_sections, raw\n", *mode)
		os.Exit(1)
	}

	var signatures []peanalyzer.Signature
	if _, err := os.Stat(*sigFile); err == nil {
		sigs, err := peanalyzer.LoadSignaturesFromFile(*sigFile)
		if err != nil {
			log.Printf("Warning: failed to load signatures from %s: %v\n", *sigFile, err)
		} else {
			signatures = sigs
			log.Printf("Loaded %d signatures from %s\n", len(signatures), *sigFile)
		}
	} else {
		log.Printf("Signature file %s not found. Continuing with entropy only.\n", *sigFile)
	}

	scanner := peanalyzer.NewScanner(signatures)

	if *hashFile != "" {
		db, err := peanalyzer.LoadHashDB(*hashFile)
		if err != nil {
			log.Printf("Warning: could not load hash DB from %s: %v\n", *hashFile, err)
		} else {
			scanner = scanner.WithHashDB(db)
			log.Printf("Loaded %d hashes from %s\n", db.Len(), *hashFile)
		}
	}

	result, err := scanner.ScanFileWithMode(peFile, *mode)
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	if *outputJSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalf("JSON marshaling failed: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		printHumanReadable(result)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [options] <PE-file>

Analyzes Windows PE files: computes entropy and matches PEiD signatures.

Options:
  -sig <file>     Path to signature database (default: userdb.txt)
  -hashdb <file>  Path to JSON file with known-malicious SHA256 hashes
  -mode <mode>    Scan mode: ep_only, all_sections, raw (default: all_sections)
  -json           Output result as JSON
  -help           Show this help message
  -version        Show version

Examples:
  %[1]s sample.exe
  %[1]s -sig /path/to/userdb.txt -mode ep_only sample.exe
  %[1]s -hashdb cryptors.json -json packed.exe > report.json

`, filepath.Base(os.Args[0]))
}

func printHumanReadable(result *peanalyzer.AnalysisResult) {
	fmt.Printf("File: %s\n", result.FilePath)
	fmt.Printf("Scan mode: %s\n", result.ScanMode)
	fmt.Printf("Signatures loaded: %d\n", result.TotalSignatures)
	if result.FileHash != "" {
		fmt.Printf("SHA256: %s\n", result.FileHash)
	}

	if result.KnownMalicious {
		fmt.Printf("\n🚨 KNOWN MALICIOUS (hash matched: %s)\n", result.HashMatch)
	}

	fmt.Printf("\n=== Entropy Analysis ===\n")
	fmt.Printf("Overall file entropy: %.4f (max 8.0)\n", result.EntropyInfo.FileEntropy)
	fmt.Printf("Sections: %d\n", result.EntropyInfo.TotalSections)
	for _, sec := range result.EntropyInfo.Sections {
		fmt.Printf("  %-10s : entropy %.4f  (size: %d bytes, raw: %d bytes)\n",
			sec.Name, sec.Entropy, sec.VirtualSize, sec.RawSize)
	}

	if len(result.EntropyAnomalies) > 0 {
		fmt.Println("\n⚠️  Entropy Anomalies (Z‑Score > 2):")
		for _, a := range result.EntropyAnomalies {
			fmt.Printf("  %s: entropy %.4f (z=%.2f) [%s]\n", a.SectionName, a.Entropy, a.ZScore, a.Severity)
		}
	}

	if len(result.SizeDiscrepancies) > 0 {
		fmt.Println("\n📦 Suspicious Size Discrepancies:")
		for _, d := range result.SizeDiscrepancies {
			fmt.Printf("  %s: virtual %d / raw %d (ratio %.2f)\n", d.SectionName, d.VirtualSize, d.RawSize, d.Ratio)
		}
	}

	if result.Overlay != nil && result.Overlay.Exists {
		fmt.Printf("\n🗂️  Overlay Detected: %d bytes at offset 0x%X\n", result.Overlay.Size, result.Overlay.Offset)
		if len(result.Overlay.First16) > 0 {
			fmt.Printf("     First 16 bytes: %s\n", result.Overlay.HexDump)
		}
	}

	if result.IATStatus != nil {
		fmt.Println("\n📁 Import Address Table (IAT) Analysis:")
		fmt.Printf("   Has IAT: %t\n", result.IATStatus.HasIAT)
		fmt.Printf("   Import count: %d\n", result.IATStatus.ImportCount)
		if result.IATStatus.IsTampered {
			fmt.Println("   ⚠️  Suspicious IAT Tampering detected:")
			for _, hint := range result.IATStatus.ObfuscationHints {
				fmt.Printf("      - %s\n", hint)
			}
		}
	}

	if len(result.LowEntropyInjections) > 0 {
		fmt.Println("\n💉 Low-Entropy Injections Detected:")
		for _, inj := range result.LowEntropyInjections {
			fmt.Printf("  Section %s (overall entropy %.4f): low entropy region of %d bytes at offset 0x%X (entropy %.4f)\n",
				inj.SectionName, inj.OverallEntropy, inj.LowEntropyRegionSize, inj.LowEntropyRegionOffset, inj.RegionEntropy)
		}
	}

	if len(result.CompressionEncryption) > 0 {
		fmt.Println("\n🔍 Compression vs Encryption Analysis:")
		for _, ce := range result.CompressionEncryption {
			typeStr := "Unknown"
			if ce.LikelyCompressed {
				typeStr = "Compressed"
			} else if ce.LikelyEncrypted {
				typeStr = "Encrypted"
			}
			fmt.Printf("  Section %s (entropy %.4f): classified as %s (confidence: %s)\n",
				ce.SectionName, ce.Entropy, typeStr, ce.Confidence)
		}
	}

	if result.StubIntelligence != nil {
		fmt.Println("\n🧠 Stub Intelligence:")
		if result.StubIntelligence.StubSection != "" {
			fmt.Printf("   Entry point section: %s\n", result.StubIntelligence.StubSection)
		}
		if result.StubIntelligence.HasAntiDebug {
			fmt.Println("   ⚠️  Anti‑debug techniques detected")
		}
		if result.StubIntelligence.HasAntiVM {
			fmt.Println("   ⚠️  Anti‑VM techniques detected")
		}
		if result.StubIntelligence.HasSandboxEvasion {
			fmt.Println("   ⚠️  Sandbox evasion detected")
		}
		if result.StubIntelligence.HasAdvancedDelay {
			fmt.Println("   ⚠️  Advanced execution delay detected")
		}
		if result.StubIntelligence.HasUserInteractionCheck {
			fmt.Println("   ⚠️  User interaction delay checks detected")
		}
		for _, c := range result.StubIntelligence.Checks {
			fmt.Printf("      - %s [%s]: %s\n", c.Match, c.Severity, c.Description)
		}
	}

	fmt.Printf("\n=== Packer Matches (%d) ===\n", len(result.PackerMatches))
	if len(result.PackerMatches) == 0 {
		fmt.Println("  None")
	} else {
		for _, match := range result.PackerMatches {
			fmt.Printf("  [+] %s (confidence: %.2f)\n", match.SignatureName, match.Confidence)
			fmt.Printf("      at RVA 0x%X (file offset 0x%X) in section %s\n",
				match.RVA, match.Offset, match.SectionName)
			if match.EpOnly {
				fmt.Printf("      (ep_only signature)\n")
			}
		}
	}

	fmt.Printf("\n=== Protector Matches (%d) ===\n", len(result.ProtectorMatches))
	if len(result.ProtectorMatches) == 0 {
		fmt.Println("  None")
	} else {
		fmt.Println("  ⚠️  Note: Protectors are often used for legitimate DRM; may not indicate malware.")
		for _, match := range result.ProtectorMatches {
			fmt.Printf("  [+] %s (confidence: %.2f)\n", match.SignatureName, match.Confidence)
			fmt.Printf("      at RVA 0x%X (file offset 0x%X) in section %s\n",
				match.RVA, match.Offset, match.SectionName)
			if match.EpOnly {
				fmt.Printf("      (ep_only signature)\n")
			}
		}
	}

	var otherMatches []peanalyzer.Match
	for _, m := range result.Matches {
		if m.Category != "packer" && m.Category != "protector" {
			otherMatches = append(otherMatches, m)
		}
	}
	if len(otherMatches) > 0 {
		fmt.Printf("\n=== Compiler / Installer / Other Matches (%d) ===\n", len(otherMatches))
		for _, match := range otherMatches {
			fmt.Printf("  [+] %s (confidence: %.2f)\n", match.SignatureName, match.Confidence)
			fmt.Printf("      at RVA 0x%X (file offset 0x%X) in section %s\n",
				match.RVA, match.Offset, match.SectionName)
			if match.EpOnly {
				fmt.Printf("      (ep_only signature)\n")
			}
		}
	}

	if result.CascadingPacking != nil && result.CascadingPacking.TotalLayers > 0 {
		fmt.Println("\n⛓️  Cascading Packing Analysis:")
		fmt.Printf("   %s\n", result.CascadingPacking.Description)
		if result.CascadingPacking.TotalLayers > 5 {
			fmt.Printf("   [Showing first 5 of %d layers due to noise filtering]\n", result.CascadingPacking.TotalLayers)
		}
		if len(result.CascadingPacking.Layers) > 0 {
			for _, l := range result.CascadingPacking.Layers {
				fmt.Printf("     Layer %d: %s in section %s (entropy: %.4f, offset: 0x%X)\n",
					l.LayerNumber, l.SignatureName, l.SectionName, l.Entropy, l.Offset)
			}
		}
	}
}
```

---

## 🔍 Scan Modes

The `ScanFileWithMode` function accepts the following modes:

| Mode             | Description |
|------------------|-------------|
| `"ep_only"`      | Scans only the first 4096 bytes of the entry point section. Filters compiler/installer signatures and requires `Length >= 12`. |
| `"all_sections"` | Scans every PE section for non‑`ep_only` signatures. This is the default and recommended mode. |
| `"raw"`          | Scans the entire file (including headers and overlay). Slowest, but most thorough. |

---

## 🧠 Comprehensive Schema

The `AnalysisResult` struct outputs all analytical components in a structured format:

```go
type AnalysisResult struct {
	FilePath              string                    `json:"file_path"`
	EntropyInfo           *EntropyInfo              `json:"entropy"`
	Matches               []Match                   `json:"matches"`
	ScanMode              string                    `json:"scan_mode"`
	TotalSignatures       int                       `json:"total_signatures_loaded"`
	EntropyAnomalies      []EntropyAnomaly          `json:"entropy_anomalies"`
	SizeDiscrepancies     []SizeDiscrepancy         `json:"size_discrepancies"`
	Overlay               *OverlayInfo              `json:"overlay"`
	StubIntelligence      *StubIntelResult          `json:"stub_intelligence"`
	CascadingPacking      *CascadingResult          `json:"cascading_packing"`
	IATStatus             *IATStatus                `json:"iat_status"`
	LowEntropyInjections  []LowEntropyInjection     `json:"low_entropy_injections"`
	CompressionEncryption []CompressionVsEncryption `json:"compression_encryption"`
	FileHash              string                    `json:"file_hash"`
	KnownMalicious        bool                      `json:"known_malicious"`
	HashMatch             string                    `json:"hash_match,omitempty"`
	PackerMatches         []Match                   `json:"packer_matches"`
	ProtectorMatches      []Match                   `json:"protector_matches"`
}
```

---

## ⚠️ Important Notes

*   **Signature Cleaning**: Malformed PEiD database signatures are skipped silently, preventing stderr logs during load.
*   **DRM Awareness**: Commercial protectors are labeled `"protector"` and warning alerts instruct users that their presence may be legitimate.
*   **Memory Efficiency**: Scanning extremely large files (e.g. >100 MB) in `"raw"` mode may consume significant memory. Use `"all_sections"` or `"ep_only"` for production use cases.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

*   [PEiD](https://www.aldeid.com/wiki/PEiD) – The original Packed Executable iDentifier.
*   [peid-python](https://github.com/CrackerCat/peid-python) – For providing a comprehensive, up‑to‑date signature database.
*   [pefile](https://github.com/erocarrera/pefile) – A Python library that heavily inspired the PE parsing logic in this package.
