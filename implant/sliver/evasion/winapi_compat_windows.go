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

// Compatibility shim for kernel32 APIs not exported by golang.org/x/sys/windows.
// Resolved via LazyProc (hash-free, loaded on first use) so the implant builds
// against stock x/sys without CGO or custom syscalls.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetModuleHandleW       = modKernel32.NewProc("GetModuleHandleW")
	procCreateWaitableTimerExW = modKernel32.NewProc("CreateWaitableTimerExW")
	procSetWaitableTimer       = modKernel32.NewProc("SetWaitableTimer")
	procLoadLibraryW           = modKernel32.NewProc("LoadLibraryW")
)

// winLoadLibrary maps a DLL into the calling process (LoadLibraryW).
// Returns the module base address.
func winLoadLibrary(path string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, _, err := procLoadLibraryW.Call(uintptr(unsafe.Pointer(p)))
	if h == 0 {
		return 0, err
	}
	return h, nil
}

// winGetModuleHandleSelf returns the base address of the current executable
// image (GetModuleHandleW with NULL lpModuleName).
func winGetModuleHandleSelf() (uintptr, error) {
	h, _, err := procGetModuleHandleW.Call(0)
	if h == 0 {
		return 0, err
	}
	return h, nil
}

// winCreateWaitableTimer creates a synchronization timer handle
// (CreateWaitableTimerExW, manual-reset = FALSE, SYNCHRONIZE|TIMER_MODIFY_STATE).
func winCreateWaitableTimer() (windows.Handle, error) {
	const timerModifyState = 0x0002
	h, _, err := procCreateWaitableTimerExW.Call(
		0,          // lpTimerAttributes (NULL)
		0,          // lpTimerName (NULL, unnamed)
		0,          // dwFlags (0 = synchronization timer, auto-reset)
		uintptr(windows.SYNCHRONIZE|timerModifyState),
	)
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}

// winSetWaitableTimer arms the timer with a negative (relative) due time.
// The 100ns-interval FILETIME is built from the nanosecond duration.
func winSetWaitableTimer(timer windows.Handle, relNano int64) error {
	due := -relNano // negative = relative to now
	ft := &windows.Filetime{
		LowDateTime:  uint32(due),
		HighDateTime: uint32(due >> 32),
	}
	ret, _, err := procSetWaitableTimer.Call(
		uintptr(timer),
		uintptr(unsafe.Pointer(ft)),
		0, // lPeriod = 0 (one-shot)
		0, // pfnCompletionRoutine (NULL)
		0, // lpArgToCompletionRoutine (NULL)
		0, // fResume (FALSE)
	)
	if ret == 0 {
		return err
	}
	return nil
}
