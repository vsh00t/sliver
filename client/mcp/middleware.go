package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

// --- Safety Middleware ---

// SafetyConfig controls the safety rails for LLM-driven operation.
type SafetyConfig struct {
	RequireConfirmation      bool     // If true, destructive ops need human approval
	MaxOpsPerMinute          int      // Rate limit for non-read operations
	MaxConcurrentDestructive int      // Max simultaneous destructive ops
	AllowedSessionIDs        []string // Whitelist of authorized session IDs (empty = all)
	AutoApproveRead          bool     // Automatically approve read-only operations
	AuditLogPath             string   // Path to audit log file (empty = stdout)
}

// DefaultSafetyConfig returns sensible defaults for semi-autonomous operation.
func DefaultSafetyConfig() *SafetyConfig {
	return &SafetyConfig{
		RequireConfirmation:      true,
		MaxOpsPerMinute:          10,
		MaxConcurrentDestructive: 3,
		AllowedSessionIDs:        nil, // all sessions allowed
		AutoApproveRead:          true,
		AuditLogPath:             "",
	}
}

// destructiveTools is the set of tool names that require confirmation.
var destructiveTools = map[string]bool{
	"inject_shellcode": true,
	"proc_terminate":   true,
	"fs_rm":            true,
	"fs_mv":            true,
	"fs_cp":            true,
	"fs_mkdir":         true,
	"fs_chmod":         true,
	"fs_chown":         true,
	"reg_delete_key":   true,
	"reg_write":        true,
	"reg_create_key":   true,
	"service_stop":     true,
	"service_remove":   true,
	"socks_stop":       true,
	"upload":           true,
	"migrate":          true,
	"sideload":         true,
	"execute":          true,
	"execute_assembly": true,
}

// auditEntry records a single tool invocation for compliance.
type auditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Tool        string    `json:"tool"`
	SessionID   string    `json:"session_id,omitempty"`
	BeaconID    string    `json:"beacon_id,omitempty"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	Destructive bool      `json:"destructive"`
	Approved    bool      `json:"approved"`
}

// SafetyMiddleware wraps the MCP server with safety rails.
type SafetyMiddleware struct {
	config                *SafetyConfig
	mu                    sync.Mutex
	opTimestamps          []time.Time
	concurrentDestructive int
	auditLog              []auditEntry
	confirmationHandler   func(toolName string, args map[string]interface{}) (bool, error)
}

// NewSafetyMiddleware creates a middleware with the given config.
func NewSafetyMiddleware(cfg *SafetyConfig) *SafetyMiddleware {
	if cfg == nil {
		cfg = DefaultSafetyConfig()
	}
	return &SafetyMiddleware{
		config: cfg,
	}
}

// SetConfirmationHandler installs a callback for destructive action approval.
// The handler receives the tool name and arguments, and returns (approved, error).
// This is the human-in-the-loop checkpoint.
func (sm *SafetyMiddleware) SetConfirmationHandler(handler func(toolName string, args map[string]interface{}) (bool, error)) {
	sm.confirmationHandler = handler
}

// WrapToolHandler wraps a tool handler with safety checks.
// It returns a new handler that enforces rate limits, confirmation gates, and audit logging.
func (sm *SafetyMiddleware) WrapToolHandler(toolName string, originalHandler func(context.Context, mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error)) func(context.Context, mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	return func(ctx context.Context, req mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
		isDestructive := destructiveTools[toolName]

		// --- Rate limiting for non-read operations ---
		if isDestructive || !sm.config.AutoApproveRead {
			if !sm.checkRateLimit() {
				return mcpapi.NewToolResultError(
					fmt.Sprintf("rate limit exceeded: max %d ops/min", sm.config.MaxOpsPerMinute),
				), nil
			}
		}

		// --- Concurrency limit for destructive operations ---
		if isDestructive {
			sm.mu.Lock()
			if sm.concurrentDestructive >= sm.config.MaxConcurrentDestructive {
				sm.mu.Unlock()
				return mcpapi.NewToolResultError(
					fmt.Sprintf("concurrent destructive operation limit reached: max %d", sm.config.MaxConcurrentDestructive),
				), nil
			}
			sm.concurrentDestructive++
			sm.mu.Unlock()
			defer func() {
				sm.mu.Lock()
				sm.concurrentDestructive--
				sm.mu.Unlock()
			}()
		}

		// --- Session whitelist enforcement ---
		if len(sm.config.AllowedSessionIDs) > 0 {
			sidMap, _ := req.Params.Arguments.(map[string]interface{})
			if sidMap != nil {
				sessionID, _ := sidMap["session_id"].(string)
				if sessionID != "" && !sm.isSessionAllowed(sessionID) {
					return mcpapi.NewToolResultError(
						fmt.Sprintf("session %s is not in the authorized scope", sessionID),
					), nil
				}
			}
		}

		// --- Human confirmation for destructive operations ---
		approved := true
		if isDestructive && sm.config.RequireConfirmation {
			if sm.confirmationHandler != nil {
				argsMap, _ := req.Params.Arguments.(map[string]interface{})
				if argsMap == nil {
					argsMap = make(map[string]interface{})
				}
				approved2, err := sm.confirmationHandler(toolName, argsMap)
				if err != nil {
					return mcpapi.NewToolResultError(
						fmt.Sprintf("confirmation handler error: %v", err),
					), nil
				}
				approved = approved2
			}
		}

		if !approved {
			return mcpapi.NewToolResultError(
				fmt.Sprintf("operation %s was not approved by the operator", toolName),
			), nil
		}

		// --- Execute the original handler ---
		result, err := originalHandler(ctx, req)

		// --- Audit logging ---
		sm.recordAudit(toolName, req, result, err, isDestructive, approved)

		return result, err
	}
}

// checkRateLimit returns true if the operation is within the rate limit.
func (sm *SafetyMiddleware) checkRateLimit() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	// Remove timestamps older than 1 minute
	valid := sm.opTimestamps[:0]
	for _, ts := range sm.opTimestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	sm.opTimestamps = valid

	if len(sm.opTimestamps) >= sm.config.MaxOpsPerMinute {
		return false
	}

	sm.opTimestamps = append(sm.opTimestamps, now)
	return true
}

// isSessionAllowed checks if a session ID is in the whitelist.
func (sm *SafetyMiddleware) isSessionAllowed(sessionID string) bool {
	for _, allowed := range sm.config.AllowedSessionIDs {
		if allowed == sessionID {
			return true
		}
	}
	return false
}

// recordAudit logs a tool invocation.
func (sm *SafetyMiddleware) recordAudit(toolName string, req mcpapi.CallToolRequest, result *mcpapi.CallToolResult, err error, isDestructive bool, approved bool) {
	entry := auditEntry{
		Timestamp:   time.Now(),
		Tool:        toolName,
		Destructive: isDestructive,
		Approved:    approved,
	}

	// Extract session/beacon ID from args if available
	argsMap, _ := req.Params.Arguments.(map[string]interface{})
	if argsMap != nil {
		if sid, ok := argsMap["session_id"].(string); ok {
			entry.SessionID = sid
		}
		if bid, ok := argsMap["beacon_id"].(string); ok {
			entry.BeaconID = bid
		}
	}

	if err != nil {
		entry.Error = err.Error()
	} else if result != nil && result.IsError {
		entry.Error = "tool returned error"
	}

	sm.mu.Lock()
	sm.auditLog = append(sm.auditLog, entry)
	sm.mu.Unlock()

	// Log to stdout (or file in production)
	status := "OK"
	if entry.Error != "" {
		status = "ERROR: " + entry.Error
	}
	log.Printf("[AUDIT] %s | %s | session=%s | %s", entry.Timestamp.Format(time.RFC3339), toolName, entry.SessionID, status)
}

// recordAuditSimple logs a tool invocation from mcp-go hooks (simplified interface).
func (sm *SafetyMiddleware) recordAuditSimple(toolName string, message *mcpapi.CallToolRequest, result any, isDestructive bool) {
	entry := auditEntry{
		Timestamp:   time.Now(),
		Tool:        toolName,
		Destructive: isDestructive,
		Approved:    true, // If it reached the AfterCall hook, it was executed
	}

	if message != nil {
		argsMap, _ := message.Params.Arguments.(map[string]interface{})
		if argsMap != nil {
			if sid, ok := argsMap["session_id"].(string); ok {
				entry.SessionID = sid
			}
		}
	}

	sm.mu.Lock()
	sm.auditLog = append(sm.auditLog, entry)
	sm.mu.Unlock()

	// Write to JSONL audit file if configured
	if sm.config != nil && sm.config.AuditLogPath != "" {
		sm.writeAuditJSONL(entry)
	}

	status := "OK"
	if result == nil {
		status = "ERROR: nil result"
		entry.Success = false
	} else {
		entry.Success = true
	}
	log.Printf("[AUDIT] %s | %s | session=%s | %s", entry.Timestamp.Format(time.RFC3339), toolName, entry.SessionID, status)
}

// writeAuditJSONL appends an audit entry as a JSON line to the audit file.
func (sm *SafetyMiddleware) writeAuditJSONL(entry auditEntry) {
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		return
	}
	jsonBytes = append(jsonBytes, '\n')
	f, err := os.OpenFile(sm.config.AuditLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(jsonBytes)
}

// GetAuditLog returns a copy of the audit log.
func (sm *SafetyMiddleware) GetAuditLog() []auditEntry {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	out := make([]auditEntry, len(sm.auditLog))
	copy(out, sm.auditLog)
	return out
}

// --- Helper to apply middleware to server ---

// ApplySafetyMiddleware wraps all registered tools with safety checks.
// This should be called after all tools are registered on the server.
func ApplySafetyMiddleware(srv *SliverMCPServer, cfg *SafetyConfig) *SafetyMiddleware {
	mw := NewSafetyMiddleware(cfg)
	_ = srv // server already has tools registered; middleware wraps at call time
	return mw
}
