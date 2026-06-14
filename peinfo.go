package peanalyzer

import (
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
)

// PETarget represents a parsed PE file with access to raw data and sections.
type PETarget struct {
	File          *pe.File
	RawReader     io.ReaderAt
	FilePath      string
	EntryPointRVA uint32
}

// OpenPETarget opens a PE file and prepares it for analysis.
// It returns a PETarget that must be closed with Close().
func OpenPETarget(path string) (*PETarget, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PE file: %w", err)
	}
	// Note: pe.NewFile reads from f, we keep the file open for raw reads
	peFile, err := pe.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse PE: %w", err)
	}

	entryPoint := peFile.OptionalHeader.(*pe.OptionalHeader64).AddressOfEntryPoint
	if peFile.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		entryPoint = peFile.OptionalHeader.(*pe.OptionalHeader32).AddressOfEntryPoint
	}

	return &PETarget{
		File:          peFile,
		RawReader:     f,
		FilePath:      path,
		EntryPointRVA: entryPoint,
	}, nil
}

// Close releases the underlying resources.
func (p *PETarget) Close() error {
	if p.File != nil {
		p.File.Close()
	}
	if closer, ok := p.RawReader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SectionData reads the raw bytes of a PE section from the file.
func (p *PETarget) SectionData(section *pe.Section) ([]byte, error) {
	if section.Size == 0 {
		return []byte{}, nil
	}
	data := make([]byte, section.Size)
	_, err := p.RawReader.ReadAt(data, int64(section.Offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read section %s: %w", section.Name, err)
	}
	return data, nil
}

// RawFileData reads the entire PE file (including headers and all sections).
func (p *PETarget) RawFileData() ([]byte, error) {
	if stat, ok := p.RawReader.(interface{ Stat() (os.FileInfo, error) }); ok {
		info, err := stat.Stat()
		if err == nil && info.Size() > 0 {
			data := make([]byte, info.Size())
			_, err := p.RawReader.ReadAt(data, 0)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return data, nil
		}
	}
	// Fallback: read chunk by chunk (shouldn't happen with os.File)
	return io.ReadAll(io.NewSectionReader(p.RawReader, 0, 1<<62))
}

// DataAtRVARaw reads raw bytes from the file starting at the given RVA.
// It maps the RVA to a file offset using section headers. If the RVA doesn't
// fall into any section, it reads from the raw file offset (not recommended).
func (p *PETarget) DataAtRVARaw(rva uint32, size int) ([]byte, error) {
	// Find which section contains the RVA
	for _, section := range p.File.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			offset := int64(rva - section.VirtualAddress + section.Offset)
			data := make([]byte, size)
			n, err := p.RawReader.ReadAt(data, offset)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return data[:n], nil
		}
	}
	return nil, fmt.Errorf("RVA 0x%X does not belong to any section", rva)
}

// ComputeEntropyForFile computes entropy for the entire file and each section.
func (p *PETarget) ComputeEntropyForFile() (*EntropyInfo, error) {
	// Compute file entropy
	rawData, err := p.RawFileData()
	if err != nil {
		return nil, fmt.Errorf("read file for entropy: %w", err)
	}
	fileEntropy := CalculateEntropy(rawData)

	// Compute per-section entropy
	sectionResults := make([]SectionEntropyResult, 0, len(p.File.Sections))
	for _, section := range p.File.Sections {
		data, err := p.SectionData(section)
		if err != nil {
			// Skip sections that can't be read but continue
			continue
		}
		entropy := CalculateEntropy(data)
		sectionResults = append(sectionResults, SectionEntropyResult{
			Name:           section.Name,
			VirtualSize:    section.VirtualSize,
			RawSize:        section.Size,
			VirtualAddress: section.VirtualAddress,
			Entropy:        entropy,
		})
	}

	return &EntropyInfo{
		FileEntropy:   fileEntropy,
		Sections:      sectionResults,
		TotalSections: len(sectionResults),
	}, nil
}

// RVAFromFileOffset converts a file offset to an RVA.
// This is useful for reporting match locations.
func (p *PETarget) RVAFromFileOffset(offset int64) (uint32, error) {
	for _, section := range p.File.Sections {
		if offset >= int64(section.Offset) && offset < int64(section.Offset+section.Size) {
			rva := section.VirtualAddress + uint32(offset-int64(section.Offset))
			return rva, nil
		}
	}
	return 0, fmt.Errorf("offset 0x%X is not inside any section", offset)
}

// SectionNameFromRVA returns the name of the section containing the given RVA.
func (p *PETarget) SectionNameFromRVA(rva uint32) string {
	for _, section := range p.File.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return section.Name
		}
	}
	return ""
}
