package mcp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

func TestSafetyMiddleware_RateLimit(t *testing.T) {
	cfg := &SafetyConfig{
		MaxOpsPerMinute:          3,
		MaxConcurrentDestructive: 10,
		RequireConfirmation:      false,
		AutoApproveRead:          true,
	}
	mw := NewSafetyMiddleware(cfg)

	for i := 0; i < 3; i++ {
		if !mw.checkRateLimit() {
			t.Fatalf("call %d should have been allowed", i+1)
		}
	}
	if mw.checkRateLimit() {
		t.Fatal("4th call should have been rate limited")
	}
}

func TestSafetyMiddleware_SessionWhitelist(t *testing.T) {
	cfg := &SafetyConfig{
		MaxOpsPerMinute:          100,
		MaxConcurrentDestructive: 10,
		RequireConfirmation:      false,
		AllowedSessionIDs:        []string{"session-aaa", "session-bbb"},
		AutoApproveRead:          true,
	}
	mw := NewSafetyMiddleware(cfg)

	if !mw.isSessionAllowed("session-aaa") {
		t.Error("session-aaa should be allowed")
	}
	if !mw.isSessionAllowed("session-bbb") {
		t.Error("session-bbb should be allowed")
	}
	if mw.isSessionAllowed("session-ccc") {
		t.Error("session-ccc should NOT be allowed")
	}
}

func TestSafetyMiddleware_AuditLog(t *testing.T) {
	cfg := DefaultSafetyConfig()
	mw := NewSafetyMiddleware(cfg)

	log := mw.GetAuditLog()
	if len(log) != 0 {
		t.Fatalf("expected empty audit log, got %d entries", len(log))
	}
}

func TestSafetyMiddleware_ConfirmationHandler(t *testing.T) {
	cfg := &SafetyConfig{
		MaxOpsPerMinute:          100,
		MaxConcurrentDestructive: 10,
		RequireConfirmation:      true,
		AutoApproveRead:          true,
	}
	mw := NewSafetyMiddleware(cfg)

	mw.SetConfirmationHandler(func(toolName string, args map[string]interface{}) (bool, error) {
		return false, nil
	})

	called := false
	originalHandler := func(ctx context.Context, req mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
		called = true
		return mcpapi.NewToolResultStructuredOnly(map[string]string{"ok": "true"}), nil
	}

	wrapped := mw.WrapToolHandler("inject_shellcode", originalHandler)

	req := mcpapi.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{
		"session_id":  "test-session",
		"data_base64": "dGVzdA==",
	}

	result, err := wrapped(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("original handler should NOT have been called (denied)")
	}
	if result != nil && !result.IsError {
		t.Error("expected error result for denied operation")
	}
}

func TestSafetyMiddleware_ApproveNonDestructive(t *testing.T) {
	cfg := &SafetyConfig{
		MaxOpsPerMinute:          100,
		MaxConcurrentDestructive: 10,
		RequireConfirmation:      true,
		AutoApproveRead:          true,
	}
	mw := NewSafetyMiddleware(cfg)

	called := false
	originalHandler := func(ctx context.Context, req mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
		called = true
		return mcpapi.NewToolResultStructuredOnly(map[string]string{"ok": "true"}), nil
	}

	wrapped := mw.WrapToolHandler("list_sessions_and_beacons", originalHandler)

	req := mcpapi.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{}

	result, err := wrapped(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("original handler should have been called (read-only)")
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestDestructiveToolsMap(t *testing.T) {
	expected := []string{
		"inject_shellcode", "proc_terminate", "fs_rm",
		"reg_delete_key", "service_stop", "service_remove",
		"upload", "migrate", "sideload", "execute",
	}
	for _, name := range expected {
		if !destructiveTools[name] {
			t.Errorf("'%s' should be in destructiveTools map", name)
		}
	}

	readOnly := []string{
		"list_sessions_and_beacons", "ps", "ifconfig", "netstat",
		"screenshot", "env", "ping", "privs", "download",
		"reg_read", "reg_list_subkeys", "services_list",
	}
	for _, name := range readOnly {
		if destructiveTools[name] {
			t.Errorf("'%s' should NOT be in destructiveTools map", name)
		}
	}
}

func TestSafetyMiddleware_ConcurrentSafety(t *testing.T) {
	cfg := &SafetyConfig{
		MaxOpsPerMinute:          1000,
		MaxConcurrentDestructive: 1,
		RequireConfirmation:      false,
		AutoApproveRead:          true,
	}
	mw := NewSafetyMiddleware(cfg)

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	handler := func(ctx context.Context, req mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
		time.Sleep(10 * time.Millisecond)
		return mcpapi.NewToolResultStructuredOnly(map[string]string{"ok": "true"}), nil
	}

	wrapped := mw.WrapToolHandler("inject_shellcode", handler)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := mcpapi.CallToolRequest{}
			req.Params.Arguments = map[string]interface{}{}
			result, _ := wrapped(context.Background(), req)
			if result != nil && !result.IsError {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	fmt.Printf("  Concurrent test: %d/5 succeeded (limit=1)\n", successCount)
}
