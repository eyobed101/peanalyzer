package peanalyzer

import (
	"bytes"
	"debug/pe"
	"encoding/hex"
)

// AntiAnalysisCheck represents a single flag or check found during stub analysis.
type AntiAnalysisCheck struct {
	Type        string `json:"type"`        // "anti_debug", "anti_vm", "sandbox_evasion"
	Match       string `json:"match"`       // API name or instruction
	Severity    string `json:"severity"`    // "low", "medium", "high"
	Description string `json:"description"`
}

// StubIntelResult summarizes the results of the stub anti-analysis scanning.
type StubIntelResult struct {
	HasAntiDebug            bool                `json:"has_anti_debug"`
	HasAntiVM               bool                `json:"has_anti_vm"`
	HasSandboxEvasion       bool                `json:"has_sandbox_evasion"`
	Checks                  []AntiAnalysisCheck `json:"checks"`
	StubSection             string              `json:"stub_section"`
	HasAdvancedDelay        bool                `json:"has_advanced_delay"`
	AdvancedDelayAPIs       []string            `json:"advanced_delay_apis"`
	HasUserInteractionCheck bool                `json:"has_user_interaction_check"`
	UserInteractionAPIs     []string            `json:"user_interaction_apis"`
}

var antiDebugAPIs = map[string]string{
	"IsDebuggerPresent":           "Checks for the presence of a user-mode debugger",
	"CheckRemoteDebuggerPresent":  "Checks if a process is being debugged by another process",
	"NtQueryInformationProcess":   "Queries process information, often used to detect debuggers",
	"OutputDebugString":           "Sends a string to the debugger; can be used for detection/evasion",
	"SetUnhandledExceptionFilter": "Registers a custom exception handler to intercept debugger exceptions",
	"GetTickCount":                "Measures elapsed time to detect debugger-induced delays",
}

var antiVMAPIs = map[string]string{
	"RegOpenKeyEx":             "Opens a registry key (often used to query VM artifacts)",
	"RegQueryValueEx":          "Queries registry values (often used to query VM artifacts)",
	"GetVersionEx":             "Gets OS version details (used to query VM/sandbox specific OS info)",
	"CreateToolhelp32Snapshot": "Takes a snapshot of processes (used to search for VM/sandbox processes)",
}

var sandboxEvasionAPIs = map[string]string{
	"Sleep":              "Delays execution to exhaust sandbox analysis timeouts",
	"NtDelayExecution":   "Delays execution (lower level sleep) to exhaust sandbox timeouts",
	"GetCursorPos":       "Checks for mouse movement to detect automated sandboxes",
	"GetDiskFreeSpaceEx": "Checks disk size to detect typical small sandbox environments",
}

var delayAPIs = map[string]string{
	"NtDelayExecution":       "Kernel-mode delay (more evasive than Sleep)",
	"WaitForSingleObject":    "Can wait on a timer object",
	"WaitForMultipleObjects": "Advanced waiting",
	"SetTimer":               "Timer-based delay",
	"timeSetEvent":           "Multimedia timer delay",
}

var userAPIs = map[string]string{
	"GetCursorPos":        "Checks for mouse movement",
	"GetAsyncKeyState":    "Checks keyboard state",
	"GetForegroundWindow": "Detects active window",
	"BlockInput":          "May indicate user activity requirement",
}

func matchAPI(importedName string, baseName string) bool {
	return importedName == baseName || importedName == baseName+"A" || importedName == baseName+"W"
}

// AnalyzeStub scans the entry point section (unpacking stub) for imports and byte patterns that indicate evasion techniques.
func (p *PETarget) AnalyzeStub() (*StubIntelResult, error) {
	result := &StubIntelResult{
		Checks:              []AntiAnalysisCheck{},
		AdvancedDelayAPIs:   []string{},
		UserInteractionAPIs: []string{},
	}

	// Find section containing the entry point RVA
	var stubSec *pe.Section
	for _, sec := range p.File.Sections {
		if p.EntryPointRVA >= sec.VirtualAddress && p.EntryPointRVA < sec.VirtualAddress+sec.VirtualSize {
			stubSec = sec
			break
		}
	}

	// Handle case where entry point does not lie in any section
	if stubSec == nil {
		return result, nil
	}

	result.StubSection = stubSec.Name

	// Read entry point section data
	stubData, err := p.SectionData(stubSec)
	if err != nil {
		// Handle gracefully
		return result, nil
	}

	// Scan imported symbols
	imports, err := p.File.ImportedSymbols()
	if err == nil {
		for _, imp := range imports {
			for api, desc := range antiDebugAPIs {
				if matchAPI(imp, api) {
					result.HasAntiDebug = true
					severity := "high"
					if api == "GetTickCount" {
						severity = "low"
					} else if api == "OutputDebugString" || api == "SetUnhandledExceptionFilter" {
						severity = "medium"
					}
					result.Checks = append(result.Checks, AntiAnalysisCheck{
						Type:        "anti_debug",
						Match:       imp,
						Severity:    severity,
						Description: desc,
					})
				}
			}
			for api, desc := range antiVMAPIs {
				if matchAPI(imp, api) {
					result.HasAntiVM = true
					severity := "low"
					if api == "CreateToolhelp32Snapshot" {
						severity = "medium"
					}
					result.Checks = append(result.Checks, AntiAnalysisCheck{
						Type:        "anti_vm",
						Match:       imp,
						Severity:    severity,
						Description: desc,
					})
				}
			}
			for api, desc := range sandboxEvasionAPIs {
				if matchAPI(imp, api) {
					result.HasSandboxEvasion = true
					severity := "low"
					if api == "NtDelayExecution" {
						severity = "medium"
					}
					result.Checks = append(result.Checks, AntiAnalysisCheck{
						Type:        "sandbox_evasion",
						Match:       imp,
						Severity:    severity,
						Description: desc,
					})
				}
			}
			for api, desc := range delayAPIs {
				if matchAPI(imp, api) {
					result.HasAdvancedDelay = true
					result.AdvancedDelayAPIs = append(result.AdvancedDelayAPIs, imp)
					result.HasSandboxEvasion = true
					result.Checks = append(result.Checks, AntiAnalysisCheck{
						Type:        "sandbox_evasion",
						Match:       imp,
						Severity:    "high",
						Description: desc,
					})
				}
			}
			for api, desc := range userAPIs {
				if matchAPI(imp, api) {
					result.HasUserInteractionCheck = true
					result.UserInteractionAPIs = append(result.UserInteractionAPIs, imp)
					result.HasSandboxEvasion = true
					result.Checks = append(result.Checks, AntiAnalysisCheck{
						Type:        "sandbox_evasion",
						Match:       imp,
						Severity:    "medium",
						Description: desc,
					})
				}
			}
		}
	}

	// Scan raw bytes of the entry point section for anti-analysis opcodes
	bytePatterns := []struct {
		hexStr      string
		matchName   string
		checkType   string
		severity    string
		description string
	}{
		{"0f31", "rdtsc", "anti_debug", "medium", "Read Time-Stamp Counter instruction to measure execution delays"},
		{"cc", "int3", "anti_debug", "medium", "Software breakpoint instruction"},
		{"0fa2", "cpuid", "anti_vm", "medium", "CPU ID query to detect virtualization/hypervisor signature"},
		{"0f01", "sidt/sgdt", "anti_vm", "high", "Store Interrupt/Global Descriptor Table instruction often used to detect VMs"},
		{"ed", "in eax, dx", "anti_vm", "high", "Input from port instruction often used to detect VMware VM ports"},
		{"ebfe", "jmp self", "sandbox_evasion", "medium", "Infinite loop (jmp self) pattern used to stall execution / bypass sandbox analysis"},
	}

	for _, pattern := range bytePatterns {
		patBytes, err := hex.DecodeString(pattern.hexStr)
		if err != nil {
			continue
		}
		if bytes.Contains(stubData, patBytes) {
			if pattern.checkType == "anti_debug" {
				result.HasAntiDebug = true
			} else if pattern.checkType == "anti_vm" {
				result.HasAntiVM = true
			} else if pattern.checkType == "sandbox_evasion" {
				result.HasSandboxEvasion = true
			}
			result.Checks = append(result.Checks, AntiAnalysisCheck{
				Type:        pattern.checkType,
				Match:       pattern.matchName,
				Severity:    pattern.severity,
				Description: pattern.description,
			})
		}
	}

	return result, nil
}
