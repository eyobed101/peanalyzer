# peanalyzer

[![Go Reference](https://pkg.go.dev/badge/peanalyzer.svg)](https://pkg.go.dev/peanalyzer)
[![Go Report Card](https://goreportcard.com/badge/github.com/eyobed101/peanalyzer)](https://goreportcard.com/report/github.com/eyobed101/peanalyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

`peanalyzer` is a Go package for analyzing Windows PE (Portable Executable) files. It combines **Shannon entropy calculation** with a **PEiD-style signature matcher** to detect packers, cryptors, and compilers. It is designed to be easily integrated into security tools, malware sandboxes, or any application that needs to inspect PE files.

## ✨ Features

*   **Entropy Analysis** – Computes Shannon entropy for entire files and individual PE sections. High entropy (>6.5) often indicates packed or encrypted content.
*   **PEiD Signature Matching** – Loads and matches patterns from a `userdb.txt` signature database.
*   **Flexible Scanning Modes** – Scans the entry point only, all sections, or the entire raw file.
*   **Detailed Output** – Returns a structured result with entropy values, matched signature names, RVAs, file offsets, and section names.
*   **Easy Integration** – The package is self-contained and can be imported as a library.

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

That's it. There is no need to run `go install` on a library.

## 📄 Signature Database

The package uses a signature database in the classic PEiD `userdb.txt` format. You can obtain a comprehensive, up-to-date database from the [peid-python](https://github.com/CrackerCat/peid-python) project.

### Download the Database

The file is located at `src/peid/db/userdb.txt` in the repository. You can download it directly using the raw URL:

*   **Direct Download**: [raw userdb.txt](https://raw.githubusercontent.com/CrackerCat/peid-python/main/src/peid/db/userdb.txt)

Place the downloaded `userdb.txt` file in your project's working directory, or provide its full path to the `LoadSignaturesFromFile` function.

## 🚀 Usage

Here's a basic example of how to integrate `peanalyzer` into your application:

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
	mode       = flag.String("mode", "all_sections", "Scan mode: ep_only, all_sections, raw")
	outputJSON = flag.Bool("json", false, "Output result in JSON format")
	help       = flag.Bool("help", false, "Show this help message")
	version    = flag.Bool("version", false, "Show version information")
)

const versionStr = "peanalyzer-cli v1.0.0"

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

	// Validate arguments
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing PE file path")
		usage()
		os.Exit(1)
	}
	peFile := flag.Arg(0)

	// Validate mode
	validModes := map[string]bool{"ep_only": true, "all_sections": true, "raw": true}
	if !validModes[*mode] {
		fmt.Fprintf(os.Stderr, "Error: invalid mode '%s'. Must be one of: ep_only, all_sections, raw\n", *mode)
		os.Exit(1)
	}

	// Load signatures (optional, continue if file missing)
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

	// Create scanner and analyze
	scanner := peanalyzer.NewScanner(signatures)
	result, err := scanner.ScanFileWithMode(peFile, *mode)
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	// Output
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
  -mode <mode>    Scan mode: ep_only, all_sections, raw (default: all_sections)
  -json           Output result as JSON
  -help           Show this help message
  -version        Show version

Examples:
  %[1]s sample.exe
  %[1]s -sig /path/to/userdb.txt -mode ep_only sample.exe
  %[1]s -json -mode all_sections packed.exe > report.json

`, filepath.Base(os.Args[0]))
}

func printHumanReadable(result *peanalyzer.AnalysisResult) {
	fmt.Printf("File: %s\n", result.FilePath)
	fmt.Printf("Scan mode: %s\n", result.ScanMode)
	fmt.Printf("Signatures loaded: %d\n", result.TotalSignatures)
	fmt.Printf("\n=== Entropy Analysis ===\n")
	fmt.Printf("Overall file entropy: %.4f (max 8.0)\n", result.EntropyInfo.FileEntropy)
	for _, sec := range result.EntropyInfo.Sections {
		fmt.Printf("  %-10s : entropy %.4f  (size: %d bytes, raw: %d bytes)\n",
			sec.Name, sec.Entropy, sec.VirtualSize, sec.RawSize)
	}

	fmt.Printf("\n=== Signature Matches (%d) ===\n", len(result.Matches))
	if len(result.Matches) == 0 {
		fmt.Println("  None")
	} else {
		for _, match := range result.Matches {
			fmt.Printf("  [+] %s\n", match.SignatureName)
			fmt.Printf("      at RVA 0x%X (file offset 0x%X) in section %s\n",
				match.RVA, match.Offset, match.SectionName)
			if match.EpOnly {
				fmt.Printf("      (ep_only signature)\n")
			}
		}
	}
}

```

### Available Scan Modes

The `ScanFileWithMode` function accepts the following modes:

| Mode            | Description |
|-----------------|-------------|
| `"ep_only"`     | Scans only the entry point area (first 4096 bytes). Fastest, but only detects signatures with `ep_only = true` in the database. |
| `"all_sections"`| Scans every PE section for non‑`ep_only` signatures. This is the default and recommended mode. |
| `"raw"`         | Scans the entire file (including headers and sections). Slowest, but most thorough. |

## 🔍 Detailed Output

The `AnalysisResult` struct provides a rich set of information:

```go
type AnalysisResult struct {
    FilePath        string       `json:"file_path"`          // Path to the analyzed file
    EntropyInfo     *EntropyInfo `json:"entropy"`            // Entropy analysis data
    Matches         []Match      `json:"matches"`            // List of signature matches
    ScanMode        string       `json:"scan_mode"`          // Which scan mode was used
    TotalSignatures int          `json:"total_signatures_loaded"` // Number of signatures loaded
}

type EntropyInfo struct {
    FileEntropy   float64                `json:"file_entropy"`    // Entropy of the whole file
    Sections      []SectionEntropyResult `json:"sections"`        // Entropy of each PE section
    TotalSections int                    `json:"total_sections"`  // Number of sections
}

type Match struct {
    SignatureName string `json:"signature_name"` // Name of the matched signature
    Offset        int64  `json:"offset"`         // File offset where the match was found
    RVA           uint32 `json:"rva"`            // Relative Virtual Address (for debugging)
    SectionName   string `json:"section_name"`   // Name of the section containing the match
    EpOnly        bool   `json:"ep_only"`        // Whether the signature requires EP scanning
}
```

### Interpreting Entropy Values

| Entropy Range | Interpretation |
|---------------|----------------|
| 0.0 – 4.0     | Low randomness – typical for uncompiled resources, plaintext, or sparse data. |
| 4.0 – 6.5     | Moderate randomness – common for standard executable code. |
| 6.5 – 8.0     | High randomness – strongly suggests compression or encryption (e.g., packed executables). |

## ⚠️ Important Notes

*   The package does **not** include the signature database. You must download `userdb.txt` separately and provide its path at runtime. This keeps the repository clean and avoids potential licensing issues.
*   For the most up‑to‑date signature database, visit the [peid-python repository](https://github.com/CrackerCat/peid-python). The file is regularly updated with new packer signatures.
*   The package is designed for **x86 and x64 PE files**. It may not work correctly with other executable formats.
*   Scanning very large files (e.g., >100 MB) in `"raw"` mode may consume significant memory. Use `"all_sections"` or `"ep_only"` for better performance.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

*   [PEiD](https://www.aldeid.com/wiki/PEiD) – The original Packed Executable iDentifier.
*   [peid-python](https://github.com/CrackerCat/peid-python) – For providing a comprehensive, up‑to‑date signature database.
*   [pefile](https://github.com/erocarrera/pefile) – A Python library that heavily inspired the PE parsing logic in this package.
*   [Exeinfo PE](http://exeinfo.atwebpages.com/) – For maintaining a rich signature database.


