package sigthief

/*
	Digital Signature Theft Implementation
	Based on SigThief by Josh Pitts (@midnite_runr)
	Integrated into Sliver Framework for evasion purposes
*/

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// PEInfo holds information about a PE file structure
type PEInfo struct {
	PEHeaderLocation    uint32
	CertTableLocation   uint32
	CertLocation        uint32
	CertSize            uint32
	SizeOfImageLocation uint32
	SizeOfImage         uint32
	OptionalHeaderStart uint32
	NumberOfRvaAndSizes uint32
}

// ExtractSignature extracts digital signature from a PE file
func ExtractSignature(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	peInfo, err := gatherPEInfo(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE file: %v", err)
	}

	if peInfo.CertLocation == 0 || peInfo.CertSize == 0 {
		return nil, fmt.Errorf("input file is not signed")
	}

	// Read the certificate data
	_, err = file.Seek(int64(peInfo.CertLocation), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to certificate location: %v", err)
	}

	cert := make([]byte, peInfo.CertSize)
	_, err = file.Read(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}

	return cert, nil
}

// ApplySignature applies a digital signature to a PE file
func ApplySignature(targetPath string, signature []byte, outputPath string) error {
	// Read the target file
	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		return fmt.Errorf("failed to read target file: %v", err)
	}

	targetFile := bytes.NewReader(targetData)

	peInfo, err := gatherPEInfo(targetFile)
	if err != nil {
		return fmt.Errorf("failed to parse target PE file: %v", err)
	}

	// Create output file with signature
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer output.Close()

	// Write original file content
	if _, err := output.Write(targetData); err != nil {
		return fmt.Errorf("failed to write original content: %v", err)
	}

	// Update certificate table
	if _, err := output.Seek(int64(peInfo.CertTableLocation), 0); err != nil {
		return fmt.Errorf("failed to seek to certificate table: %v", err)
	}

	// Write new certificate location (at end of file)
	newCertLocation := uint32(len(targetData))
	if err := binary.Write(output, binary.LittleEndian, newCertLocation); err != nil {
		return fmt.Errorf("failed to write certificate location: %v", err)
	}

	// Write certificate size
	if err := binary.Write(output, binary.LittleEndian, uint32(len(signature))); err != nil {
		return fmt.Errorf("failed to write certificate size: %v", err)
	}

	// Append signature at end of file
	if _, err := output.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("failed to seek to end of file: %v", err)
	}

	if _, err := output.Write(signature); err != nil {
		return fmt.Errorf("failed to write signature: %v", err)
	}

	return nil
}

// gatherPEInfo parses PE headers to extract certificate table information
func gatherPEInfo(file io.ReadSeeker) (*PEInfo, error) {
	info := &PEInfo{}

	// Read PE header location
	if _, err := file.Seek(0x3C, 0); err != nil {
		return nil, err
	}
	if err := binary.Read(file, binary.LittleEndian, &info.PEHeaderLocation); err != nil {
		return nil, err
	}

	// Start of COFF header
	coffStart := info.PEHeaderLocation + 4
	if _, err := file.Seek(int64(coffStart), 0); err != nil {
		return nil, err
	}

	var machineType uint16
	if err := binary.Read(file, binary.LittleEndian, &machineType); err != nil {
		return nil, err
	}

	var numberOfSections uint16
	if err := binary.Read(file, binary.LittleEndian, &numberOfSections); err != nil {
		return nil, err
	}

	// Skip TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
	if _, err := file.Seek(12, 1); err != nil {
		return nil, err
	}

	var sizeOfOptionalHeader uint16
	if err := binary.Read(file, binary.LittleEndian, &sizeOfOptionalHeader); err != nil {
		return nil, err
	}

	var characteristics uint16
	if err := binary.Read(file, binary.LittleEndian, &characteristics); err != nil {
		return nil, err
	}

	// Optional header start
	info.OptionalHeaderStart = coffStart + 20

	if _, err := file.Seek(int64(info.OptionalHeaderStart), 0); err != nil {
		return nil, err
	}

	var magic uint16
	if err := binary.Read(file, binary.LittleEndian, &magic); err != nil {
		return nil, err
	}

	// Skip standard fields
	if magic == 0x20B { // PE32+
		// Skip: MajorLinkerVersion(1) + MinorLinkerVersion(1) + SizeOfCode(4) + SizeOfInitializedData(4) + SizeOfUninitializedData(4) + AddressOfEntryPoint(4) + BaseOfCode(4) = 22 bytes
		if _, err := file.Seek(22, 1); err != nil {
			return nil, err
		}
		// Read ImageBase (8 bytes in PE32+)
		var imageBase uint64
		if err := binary.Read(file, binary.LittleEndian, &imageBase); err != nil {
			return nil, err
		}
		// Skip: SectionAlignment(4) + FileAlignment(4) + MajorOSVersion(2) + MinorOSVersion(2) + MajorImageVersion(2) + MinorImageVersion(2) + MajorSubsystemVersion(2) + MinorSubsystemVersion(2) + Win32VersionValue(4) = 24 bytes
		if _, err := file.Seek(24, 1); err != nil {
			return nil, err
		}
		// Read SizeOfImage
		info.SizeOfImageLocation = uint32(getCurrentPosition(file))
		if err := binary.Read(file, binary.LittleEndian, &info.SizeOfImage); err != nil {
			return nil, err
		}
		// Skip: SizeOfHeaders(4) + CheckSum(4) + Subsystem(2) + DllCharacteristics(2) + SizeOfStackReserve(8) + SizeOfStackCommit(8) + SizeOfHeapReserve(8) + SizeOfHeapCommit(8) + LoaderFlags(4) = 48 bytes
		if _, err := file.Seek(48, 1); err != nil {
			return nil, err
		}
	} else { // PE32
		// Skip: MajorLinkerVersion(1) + MinorLinkerVersion(1) + SizeOfCode(4) + SizeOfInitializedData(4) + SizeOfUninitializedData(4) + AddressOfEntryPoint(4) + BaseOfCode(4) + BaseOfData(4) = 26 bytes
		if _, err := file.Seek(26, 1); err != nil {
			return nil, err
		}
		// Read ImageBase (4 bytes in PE32)
		var imageBase uint32
		if err := binary.Read(file, binary.LittleEndian, &imageBase); err != nil {
			return nil, err
		}
		// Skip: SectionAlignment(4) + FileAlignment(4) + MajorOSVersion(2) + MinorOSVersion(2) + MajorImageVersion(2) + MinorImageVersion(2) + MajorSubsystemVersion(2) + MinorSubsystemVersion(2) + Win32VersionValue(4) = 24 bytes
		if _, err := file.Seek(24, 1); err != nil {
			return nil, err
		}
		// Read SizeOfImage
		info.SizeOfImageLocation = uint32(getCurrentPosition(file))
		if err := binary.Read(file, binary.LittleEndian, &info.SizeOfImage); err != nil {
			return nil, err
		}
		// Skip: SizeOfHeaders(4) + CheckSum(4) + Subsystem(2) + DllCharacteristics(2) + SizeOfStackReserve(4) + SizeOfStackCommit(4) + SizeOfHeapReserve(4) + SizeOfHeapCommit(4) + LoaderFlags(4) = 32 bytes
		if _, err := file.Seek(32, 1); err != nil {
			return nil, err
		}
	}

	// Read NumberOfRvaAndSizes
	if err := binary.Read(file, binary.LittleEndian, &info.NumberOfRvaAndSizes); err != nil {
		return nil, err
	}

	// Skip export, import, resource and exception table entries (8 bytes each)
	if _, err := file.Seek(32, 1); err != nil {
		return nil, err
	}

	// Certificate table location
	info.CertTableLocation = uint32(getCurrentPosition(file))
	if err := binary.Read(file, binary.LittleEndian, &info.CertLocation); err != nil {
		return nil, err
	}
	if err := binary.Read(file, binary.LittleEndian, &info.CertSize); err != nil {
		return nil, err
	}

	return info, nil
}

// getCurrentPosition returns current position in file
func getCurrentPosition(file io.Seeker) int64 {
	pos, _ := file.Seek(0, io.SeekCurrent)
	return pos
}

// IsSignedExecutable checks if a PE file has a digital signature
func IsSignedExecutable(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	peInfo, err := gatherPEInfo(file)
	if err != nil {
		return false, fmt.Errorf("failed to parse PE file: %v", err)
	}

	return peInfo.CertLocation != 0 && peInfo.CertSize != 0, nil
}
