package evasion

/*
	Advanced Anti-Analysis and Sandbox Detection
	Comprehensive detection and evasion of analysis environments
*/

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// AnalysisEnvironment represents different analysis environments
type AnalysisEnvironment int

const (
	EnvironmentProduction AnalysisEnvironment = iota
	EnvironmentSandbox
	EnvironmentVirtualMachine
	EnvironmentDebugger
	EnvironmentEmulator
	EnvironmentUnknown
)

// ThreatLevel represents the danger level of the environment
type ThreatLevel int

const (
	ThreatLow ThreatLevel = iota
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

// EnvironmentAnalysis contains analysis results
type EnvironmentAnalysis struct {
	Environment      AnalysisEnvironment
	ThreatLevel      ThreatLevel
	Confidence       float64
	DetectedFeatures []string
	Recommendations  []string
	ShouldExecute    bool
	DelayExecution   time.Duration
}

// AdvancedEnvironmentDetector comprehensive environment detection
type AdvancedEnvironmentDetector struct {
	checks          []EnvironmentCheck
	weights         map[string]float64
	thresholds      map[AnalysisEnvironment]float64
	timeoutDuration time.Duration
}

// EnvironmentCheck represents a single environment check
type EnvironmentCheck struct {
	Name        string
	Weight      float64
	CheckFunc   func() (bool, string)
	Environment AnalysisEnvironment
}

// NewAdvancedEnvironmentDetector creates a comprehensive detector
func NewAdvancedEnvironmentDetector() *AdvancedEnvironmentDetector {
	detector := &AdvancedEnvironmentDetector{
		weights:         make(map[string]float64),
		timeoutDuration: 30 * time.Second,
	}

	detector.initializeChecks()
	detector.initializeThresholds()

	return detector
}

// initializeChecks sets up all environment detection checks
func (aed *AdvancedEnvironmentDetector) initializeChecks() {
	aed.checks = []EnvironmentCheck{
		// Sandbox Detection
		{Name: "CPU_Cores", Weight: 0.8, CheckFunc: aed.checkCPUCores, Environment: EnvironmentSandbox},
		{Name: "RAM_Size", Weight: 0.7, CheckFunc: aed.checkRAMSize, Environment: EnvironmentSandbox},
		{Name: "Disk_Size", Weight: 0.6, CheckFunc: aed.checkDiskSize, Environment: EnvironmentSandbox},
		{Name: "Process_Count", Weight: 0.5, CheckFunc: aed.checkProcessCount, Environment: EnvironmentSandbox},
		{Name: "File_System", Weight: 0.9, CheckFunc: aed.checkFileSystem, Environment: EnvironmentSandbox},
		{Name: "Registry_Keys", Weight: 0.8, CheckFunc: aed.checkRegistryKeys, Environment: EnvironmentSandbox},
		{Name: "Network_Adapters", Weight: 0.7, CheckFunc: aed.checkNetworkAdapters, Environment: EnvironmentSandbox},

		// VM Detection
		{Name: "VM_Artifacts", Weight: 0.9, CheckFunc: aed.checkVMwareArtifacts, Environment: EnvironmentVirtualMachine},
		{Name: "VirtualBox_Artifacts", Weight: 0.9, CheckFunc: aed.checkVirtualBoxArtifacts, Environment: EnvironmentVirtualMachine},
		{Name: "Hyper_V_Artifacts", Weight: 0.8, CheckFunc: aed.checkHyperVArtifacts, Environment: EnvironmentVirtualMachine},
		{Name: "VM_MAC_Addresses", Weight: 0.7, CheckFunc: aed.checkVMMACAddresses, Environment: EnvironmentVirtualMachine},
		{Name: "VM_Hardware", Weight: 0.6, CheckFunc: aed.checkVMHardware, Environment: EnvironmentVirtualMachine},

		// Debugger Detection
		{Name: "IsDebuggerPresent", Weight: 1.0, CheckFunc: aed.checkIsDebuggerPresent, Environment: EnvironmentDebugger},
		{Name: "Remote_Debugger", Weight: 0.9, CheckFunc: aed.checkRemoteDebugger, Environment: EnvironmentDebugger},
		{Name: "Debug_Flags", Weight: 0.8, CheckFunc: aed.checkDebugFlags, Environment: EnvironmentDebugger},
		{Name: "Timing_Checks", Weight: 0.7, CheckFunc: aed.checkTimingAttacks, Environment: EnvironmentDebugger},

		// Analysis Tools Detection
		{Name: "Analysis_Tools", Weight: 0.9, CheckFunc: aed.checkAnalysisTools, Environment: EnvironmentSandbox},
		{Name: "Hooking_DLLs", Weight: 0.8, CheckFunc: aed.checkHookingDLLs, Environment: EnvironmentSandbox},
		{Name: "Monitoring_Processes", Weight: 0.7, CheckFunc: aed.checkMonitoringProcesses, Environment: EnvironmentSandbox},
	}
}

// initializeThresholds sets detection thresholds
func (aed *AdvancedEnvironmentDetector) initializeThresholds() {
	aed.thresholds = map[AnalysisEnvironment]float64{
		EnvironmentSandbox:        3.0,
		EnvironmentVirtualMachine: 2.5,
		EnvironmentDebugger:       1.5,
		EnvironmentEmulator:       2.0,
	}
}

// AnalyzeEnvironment performs comprehensive environment analysis
func (aed *AdvancedEnvironmentDetector) AnalyzeEnvironment() *EnvironmentAnalysis {
	analysis := &EnvironmentAnalysis{
		Environment:      EnvironmentProduction,
		ThreatLevel:      ThreatLow,
		Confidence:       0.0,
		DetectedFeatures: make([]string, 0),
		Recommendations:  make([]string, 0),
		ShouldExecute:    true,
		DelayExecution:   0,
	}

	scores := make(map[AnalysisEnvironment]float64)

	// Run all checks with timeout
	for _, check := range aed.checks {
		detected, details := aed.runCheckWithTimeout(check)
		if detected {
			scores[check.Environment] += check.Weight
			analysis.DetectedFeatures = append(analysis.DetectedFeatures,
				fmt.Sprintf("%s: %s", check.Name, details))
		}
	}

	// Determine environment and threat level
	analysis.Environment, analysis.Confidence = aed.determineEnvironment(scores)
	analysis.ThreatLevel = aed.calculateThreatLevel(analysis.Environment, analysis.Confidence)

	// Generate recommendations
	analysis.Recommendations = aed.generateRecommendations(analysis)

	// Decide execution strategy
	analysis.ShouldExecute, analysis.DelayExecution = aed.determineExecutionStrategy(analysis)

	return analysis
}

// runCheckWithTimeout runs a check with timeout protection
func (aed *AdvancedEnvironmentDetector) runCheckWithTimeout(check EnvironmentCheck) (bool, string) {
	type result struct {
		detected bool
		details  string
	}

	resultChan := make(chan result, 1)

	go func() {
		detected, details := check.CheckFunc()
		resultChan <- result{detected, details}
	}()

	select {
	case res := <-resultChan:
		return res.detected, res.details
	case <-time.After(5 * time.Second): // Per-check timeout
		return false, "timeout"
	}
}

// Sandbox Detection Checks
func (aed *AdvancedEnvironmentDetector) checkCPUCores() (bool, string) {
	cores := runtime.NumCPU()
	if cores < 2 {
		return true, fmt.Sprintf("Low CPU cores: %d", cores)
	}
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkRAMSize() (bool, string) {
	// Implementation depends on OS
	if runtime.GOOS == "windows" {
		return aed.checkWindowsRAM()
	}
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkWindowsRAM() (bool, string) {
	// Simplified RAM check for Windows
	// In real implementation, use Windows API to get total physical memory
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkDiskSize() (bool, string) {
	// Check for suspiciously small disk sizes
	// Common in sandboxes to save space
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkProcessCount() (bool, string) {
	// Too few processes might indicate sandbox
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkFileSystem() (bool, string) {
	// Check for sandbox-specific files and directories
	sandboxFiles := []string{
		"C:\\analysis",
		"C:\\sandbox",
		"C:\\malware",
		"C:\\sample",
		"/opt/cuckoo",
		"/tmp/analysis",
	}

	for _, file := range sandboxFiles {
		if _, err := os.Stat(file); err == nil {
			return true, fmt.Sprintf("Sandbox file found: %s", file)
		}
	}

	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkRegistryKeys() (bool, string) {
	if runtime.GOOS != "windows" {
		return false, ""
	}

	// Check for sandbox-specific registry keys
	// Implementation would use Windows registry API
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkNetworkAdapters() (bool, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}

	suspiciousNames := []string{
		"vEthernet",
		"VMware",
		"VirtualBox",
		"Hyper-V",
	}

	for _, iface := range interfaces {
		for _, suspicious := range suspiciousNames {
			if strings.Contains(iface.Name, suspicious) {
				return true, fmt.Sprintf("Suspicious network adapter: %s", iface.Name)
			}
		}
	}

	return false, ""
}

// VM Detection Checks
func (aed *AdvancedEnvironmentDetector) checkVMwareArtifacts() (bool, string) {
	vmwareFiles := []string{
		"C:\\Program Files\\VMware",
		"C:\\Program Files (x86)\\VMware",
		"/usr/bin/vmware-user",
		"/usr/bin/vmhgfs-fuse",
	}

	for _, file := range vmwareFiles {
		if _, err := os.Stat(file); err == nil {
			return true, fmt.Sprintf("VMware artifact: %s", file)
		}
	}

	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkVirtualBoxArtifacts() (bool, string) {
	vboxFiles := []string{
		"C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
		"C:\\Windows\\System32\\VBoxService.exe",
		"/usr/bin/VBoxClient",
		"/usr/bin/VBoxControl",
	}

	for _, file := range vboxFiles {
		if _, err := os.Stat(file); err == nil {
			return true, fmt.Sprintf("VirtualBox artifact: %s", file)
		}
	}

	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkHyperVArtifacts() (bool, string) {
	// Check for Hyper-V specific artifacts
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkVMMACAddresses() (bool, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}

	vmMACPrefixes := []string{
		"00:0C:29", // VMware
		"00:1C:14", // VMware
		"00:50:56", // VMware
		"08:00:27", // VirtualBox
		"00:15:5D", // Hyper-V
	}

	for _, iface := range interfaces {
		mac := iface.HardwareAddr.String()
		for _, prefix := range vmMACPrefixes {
			if strings.HasPrefix(strings.ToUpper(mac), prefix) {
				return true, fmt.Sprintf("VM MAC address detected: %s", mac)
			}
		}
	}

	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkVMHardware() (bool, string) {
	// Check for VM-specific hardware signatures
	return false, ""
}

// Debugger Detection Checks
func (aed *AdvancedEnvironmentDetector) checkIsDebuggerPresent() (bool, string) {
	if runtime.GOOS != "windows" {
		return false, ""
	}

	// Use Windows API to check for debugger
	// This is a simplified version
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkRemoteDebugger() (bool, string) {
	if runtime.GOOS != "windows" {
		return false, ""
	}

	// Check for remote debugger
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkDebugFlags() (bool, string) {
	// Check various debug flags in PEB (Windows) or similar structures
	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkTimingAttacks() (bool, string) {
	// Measure timing of operations to detect debugging
	start := time.Now()
	time.Sleep(time.Millisecond)
	elapsed := time.Since(start)

	// If operation took significantly longer, might be debugged
	if elapsed > 5*time.Millisecond {
		return true, fmt.Sprintf("Timing anomaly detected: %v", elapsed)
	}

	return false, ""
}

// Analysis Tools Detection
func (aed *AdvancedEnvironmentDetector) checkAnalysisTools() (bool, string) {
	analysisTools := []string{
		"wireshark",
		"ollydbg",
		"x64dbg",
		"ida",
		"ghidra",
		"procmon",
		"regmon",
		"filemon",
	}

	// Check for running processes (simplified)
	for _, tool := range analysisTools {
		// In real implementation, enumerate processes
		if aed.isProcessRunning(tool) {
			return true, fmt.Sprintf("Analysis tool detected: %s", tool)
		}
	}

	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkHookingDLLs() (bool, string) {
	// Check for DLLs commonly used by analysis tools
	hookingDLLs := []string{
		"api-ms-win-core-",
		"sbiedll.dll",   // Sandboxie
		"api_log.dll",   // API logging
		"dir_watch.dll", // Directory monitoring
	}

	// Check loaded modules (simplified)
	for _, dll := range hookingDLLs {
		if aed.isDLLLoaded(dll) {
			return true, fmt.Sprintf("Hooking DLL detected: %s", dll)
		}
	}

	return false, ""
}

func (aed *AdvancedEnvironmentDetector) checkMonitoringProcesses() (bool, string) {
	// Check for monitoring/analysis processes
	return false, ""
}

// Helper functions
func (aed *AdvancedEnvironmentDetector) isProcessRunning(name string) bool {
	// Simplified process enumeration
	return false
}

func (aed *AdvancedEnvironmentDetector) isDLLLoaded(name string) bool {
	// Simplified DLL enumeration
	return false
}

// Analysis functions
func (aed *AdvancedEnvironmentDetector) determineEnvironment(scores map[AnalysisEnvironment]float64) (AnalysisEnvironment, float64) {
	var maxEnv AnalysisEnvironment = EnvironmentProduction
	var maxScore float64 = 0

	for env, score := range scores {
		if score > maxScore && score >= aed.thresholds[env] {
			maxScore = score
			maxEnv = env
		}
	}

	confidence := maxScore / 10.0 // Normalize confidence
	if confidence > 1.0 {
		confidence = 1.0
	}

	return maxEnv, confidence
}

func (aed *AdvancedEnvironmentDetector) calculateThreatLevel(env AnalysisEnvironment, confidence float64) ThreatLevel {
	switch env {
	case EnvironmentDebugger:
		return ThreatCritical
	case EnvironmentSandbox:
		if confidence > 0.8 {
			return ThreatHigh
		}
		return ThreatMedium
	case EnvironmentVirtualMachine:
		return ThreatMedium
	case EnvironmentEmulator:
		return ThreatHigh
	default:
		return ThreatLow
	}
}

func (aed *AdvancedEnvironmentDetector) generateRecommendations(analysis *EnvironmentAnalysis) []string {
	recommendations := make([]string, 0)

	switch analysis.Environment {
	case EnvironmentSandbox:
		recommendations = append(recommendations,
			"Delay execution by 5-10 minutes",
			"Implement user interaction requirements",
			"Check for mouse/keyboard activity",
			"Validate file system realism")
	case EnvironmentVirtualMachine:
		recommendations = append(recommendations,
			"Check for VM-specific artifacts",
			"Validate hardware characteristics",
			"Monitor performance metrics")
	case EnvironmentDebugger:
		recommendations = append(recommendations,
			"Terminate immediately",
			"Clear sensitive data from memory",
			"Avoid revealing debugging information")
	}

	return recommendations
}

func (aed *AdvancedEnvironmentDetector) determineExecutionStrategy(analysis *EnvironmentAnalysis) (bool, time.Duration) {
	switch analysis.ThreatLevel {
	case ThreatCritical:
		return false, 0 // Don't execute at all
	case ThreatHigh:
		if analysis.Confidence > 0.8 {
			return false, 0
		}
		return true, 10 * time.Minute // Long delay
	case ThreatMedium:
		return true, 2 * time.Minute // Medium delay
	case ThreatLow:
		return true, 30 * time.Second // Short delay
	default:
		return true, 0
	}
}

// StealthExecution implements execution with anti-analysis measures
func StealthExecution(operation func() error) error {
	detector := NewAdvancedEnvironmentDetector()
	analysis := detector.AnalyzeEnvironment()

	if !analysis.ShouldExecute {
		return fmt.Errorf("execution aborted due to threat level: %d", analysis.ThreatLevel)
	}

	if analysis.DelayExecution > 0 {
		// Implement intelligent delay with activity simulation
		intelligentDelay(analysis.DelayExecution)
	}

	// Execute with additional protection
	return executeWithProtection(operation, analysis)
}

func intelligentDelay(duration time.Duration) {
	// Break delay into smaller chunks and simulate activity
	chunks := int(duration / (30 * time.Second))
	if chunks < 1 {
		chunks = 1
	}

	chunkDuration := duration / time.Duration(chunks)

	for i := 0; i < chunks; i++ {
		time.Sleep(chunkDuration)

		// Simulate user activity
		simulateUserActivity()
	}
}

func simulateUserActivity() {
	// Simulate mouse movements, keyboard activity, etc.
	// This makes the delay period look legitimate
}

func executeWithProtection(operation func() error, analysis *EnvironmentAnalysis) error {
	// Additional protection during execution
	// - Monitor for debugging attempts
	// - Implement checkpoints
	// - Validate execution environment continuously

	return operation()
}
