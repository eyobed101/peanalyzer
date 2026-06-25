package pe

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

type PETarget struct {
	File		*pe.File
	RawReader	io.ReaderAt
	FilePath	string
	EntryPointRVA	uint32
}

func OpenPETarget(path string) (*PETarget, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PE file: %w", err)
	}
	peFile, err := pe.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse PE: %w", err)
	}

	var entryPoint uint32
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryPoint = opt.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entryPoint = opt.AddressOfEntryPoint
	default:
		return nil, fmt.Errorf("unsupported optional header type")
	}

	return &PETarget{
		File:		peFile,
		RawReader:	f,
		FilePath:	path,
		EntryPointRVA:	entryPoint,
	}, nil
}

func (p *PETarget) Close() error {
	if p.File != nil {
		p.File.Close()
	}
	if closer, ok := p.RawReader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

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

	return io.ReadAll(io.NewSectionReader(p.RawReader, 0, 1<<62))
}

func (p *PETarget) DataAtRVARaw(rva uint32, size int) ([]byte, error) {

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

func (p *PETarget) ComputeEntropyForFile() (*EntropyInfo, error) {

	rawData, err := p.RawFileData()
	if err != nil {
		return nil, fmt.Errorf("read file for entropy: %w", err)
	}
	fileEntropy := CalculateEntropy(rawData)

	sectionResults := make([]SectionEntropyResult, 0, len(p.File.Sections))
	for _, section := range p.File.Sections {
		data, err := p.SectionData(section)
		if err != nil {

			continue
		}
		entropy := CalculateEntropy(data)
		sectionResults = append(sectionResults, SectionEntropyResult{
			Name:		section.Name,
			VirtualSize:	section.VirtualSize,
			RawSize:	section.Size,
			VirtualAddress:	section.VirtualAddress,
			Entropy:	entropy,
		})
	}

	return &EntropyInfo{
		FileEntropy:	fileEntropy,
		Sections:	sectionResults,
		TotalSections:	len(sectionResults),
	}, nil
}

func (p *PETarget) RVAFromFileOffset(offset int64) (uint32, error) {
	for _, section := range p.File.Sections {
		if offset >= int64(section.Offset) && offset < int64(section.Offset+section.Size) {
			rva := section.VirtualAddress + uint32(offset-int64(section.Offset))
			return rva, nil
		}
	}
	return 0, fmt.Errorf("offset 0x%X is not inside any section", offset)
}

func (p *PETarget) SectionNameFromRVA(rva uint32) string {
	for _, section := range p.File.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return section.Name
		}
	}
	return ""
}

type OverlayInfo struct {
	Exists	bool	`json:"exists"`
	Offset	int64	`json:"offset"`
	Size	int64	`json:"size"`
	First16	[]byte	`json:"first_16"`
	HexDump	string	`json:"hex_dump"`
}

func (p *PETarget) DetectOverlay() (*OverlayInfo, error) {
	info, err := os.Stat(p.FilePath)
	if err != nil {
		return nil, fmt.Errorf("stat PE file: %w", err)
	}
	fileSize := info.Size()

	var maxEnd int64
	for _, section := range p.File.Sections {
		endOffset := int64(section.Offset) + int64(section.Size)
		if endOffset > maxEnd {
			maxEnd = endOffset
		}
	}

	overlay := &OverlayInfo{
		Exists: false,
	}

	if fileSize > maxEnd {
		overlay.Exists = true
		overlay.Offset = maxEnd
		overlay.Size = fileSize - maxEnd

		readSize := int64(16)
		if overlay.Size < readSize {
			readSize = overlay.Size
		}

		first16 := make([]byte, readSize)
		_, err := p.RawReader.ReadAt(first16, maxEnd)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read overlay data: %w", err)
		}

		overlay.First16 = first16
		overlay.HexDump = hex.EncodeToString(first16)
	}

	return overlay, nil
}

func (p *PETarget) SHA256() (string, error) {
	data, err := p.RawFileData()
	if err != nil {
		return "", fmt.Errorf("read file for SHA256: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
