package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/eyobed101/peanalyzer/pkg/peanalyzer"
	"github.com/eyobed101/peanalyzer/pkg/signatures"
)

var (
	sigFile		= flag.String("sig", "userdb.txt", "Path to PEiD signature file (userdb.txt)")
	hashFile	= flag.String("hashdb", "", "Path to JSON file with known malicious SHA256 hashes")
	mode		= flag.String("mode", "all_sections", "Scan mode: ep_only, all_sections, raw")
	outputJSON	= flag.Bool("json", false, "Output result in JSON format")
	help		= flag.Bool("help", false, "Show this help message")
	version		= flag.Bool("version", false, "Show version information")
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

	var sigs []signatures.Signature
	if _, err := os.Stat(*sigFile); err == nil {
		loaded, err := signatures.LoadSignaturesFromFile(*sigFile)
		if err != nil {
			log.Printf("Warning: failed to load signatures from %s: %v\n", *sigFile, err)
		} else {
			sigs = loaded
			log.Printf("Loaded %d signatures from %s\n", len(sigs), *sigFile)
		}
	} else {
		log.Printf("Signature file %s not found. Continuing with entropy only.\n", *sigFile)
	}

	scanner := peanalyzer.NewScanner(sigs)

	if *hashFile != "" {
		db, err := signatures.LoadHashDB(*hashFile)
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
