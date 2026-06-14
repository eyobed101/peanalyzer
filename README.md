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
    "fmt"
    "log"

    "github.com/eyobed101/peanalyzer"
)

func main() {
    // 1. Load the signature database
    sigPath := "userdb.txt"
    signatures, err := peanalyzer.LoadSignaturesFromFile(sigPath)
    if err != nil {
        log.Printf("Warning: could not load signatures: %v", err)
        // The scanner can still perform entropy analysis without signatures
        signatures = []peanalyzer.Signature{}
    }

    // 2. Create a scanner
    scanner := peanalyzer.NewScanner(signatures)

    // 3. Scan a PE file
    result, err := scanner.ScanFileWithMode("sample.exe", "all_sections")
    if err != nil {
        log.Fatal(err)
    }

    // 4. Use the detailed output
    fmt.Printf("File: %s\n", result.FilePath)
    fmt.Printf("Overall entropy: %.4f (max 8.0)\n", result.EntropyInfo.FileEntropy)

    // Print section entropy
    fmt.Println("\nSections:")
    for _, sec := range result.EntropyInfo.Sections {
        fmt.Printf("  %-8s : entropy %.4f (size: %d bytes)\n", sec.Name, sec.Entropy, sec.RawSize)
    }

    // Print signature matches
    fmt.Printf("\nMatched signatures (%d):\n", len(result.Matches))
    for _, match := range result.Matches {
        fmt.Printf("  [+] %s at RVA 0x%X (offset 0x%X) in section %s\n",
            match.SignatureName, match.RVA, match.Offset, match.SectionName)
    }

    // Optionally, output as JSON
    output, _ := json.MarshalIndent(result, "", "  ")
    fmt.Println(string(output))
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


