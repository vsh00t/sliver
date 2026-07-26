package mcp

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	regReadToolName        = "reg_read"
	regWriteToolName       = "reg_write"
	regCreateKeyToolName   = "reg_create_key"
	regDeleteKeyToolName   = "reg_delete_key"
	regListSubKeysToolName = "reg_list_subkeys"
	regListValuesToolName  = "reg_list_values"
)

// --- Registry read ---

type regReadArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Hive           string `json:"hive"`               // e.g. HKLM, HKCU, HKCR, HKU, HKCC
	Path           string `json:"path"`               // Registry key path
	Key            string `json:"key"`                // Value name
	Hostname       string `json:"hostname,omitempty"` // Remote host (optional)
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type regReadResult struct {
	Value string `json:"value"`
}

func (s *SliverMCPServer) regReadHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args regReadArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Hive == "" || args.Path == "" || args.Key == "" {
		return mcpapi.NewToolResultError("hive, path, and key are required"), nil
	}
	return s.handleRegRead(ctx, args)
}

func (s *SliverMCPServer) handleRegRead(ctx context.Context, args regReadArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(regReadToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("hive=%s path=%q key=%q", args.Hive, args.Path, args.Key),
	)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	resp, err := s.Rpc.RegistryRead(ctx, &sliverpb.RegistryReadReq{
		Request:  req,
		Hive:     args.Hive,
		Path:     args.Path,
		Key:      args.Key,
		Hostname: args.Hostname,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to read registry", err), nil
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("reg_read", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.RegistryRead{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await reg_read task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(regReadResult{Value: resp.Value}), nil
}

// --- Registry write ---

type regWriteArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Hive           string `json:"hive"`
	Path           string `json:"path"`
	Key            string `json:"key"`
	Hostname       string `json:"hostname,omitempty"`
	StringValue    string `json:"string_value,omitempty"`
	DWordValue     uint32 `json:"dword_value,omitempty"`
	QWordValue     uint64 `json:"qword_value,omitempty"`
	Type           uint32 `json:"type"` // 0=Unknown, 1=Binary, 2=String, 3=DWORD, 4=QWORD
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) regWriteHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args regWriteArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Hive == "" || args.Path == "" || args.Key == "" {
		return mcpapi.NewToolResultError("hive, path, and key are required"), nil
	}
	return s.handleRegWrite(ctx, args)
}

func (s *SliverMCPServer) handleRegWrite(ctx context.Context, args regWriteArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(regWriteToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("hive=%s path=%q key=%q type=%d", args.Hive, args.Path, args.Key, args.Type),
	)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	resp, err := s.Rpc.RegistryWrite(ctx, &sliverpb.RegistryWriteReq{
		Request:     req,
		Hive:        args.Hive,
		Path:        args.Path,
		Key:         args.Key,
		Hostname:    args.Hostname,
		StringValue: args.StringValue,
		DWordValue:  args.DWordValue,
		QWordValue:  args.QWordValue,
		Type:        args.Type,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to write registry", err), nil
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("reg_write", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.RegistryWrite{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await reg_write task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]any{"written": true}), nil
}

// --- Registry create key ---

type regCreateKeyArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Hive           string `json:"hive"`
	Path           string `json:"path"`
	Key            string `json:"key"`
	Hostname       string `json:"hostname,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) regCreateKeyHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args regCreateKeyArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Hive == "" || args.Path == "" {
		return mcpapi.NewToolResultError("hive and path are required"), nil
	}
	return s.handleRegCreateKey(ctx, args)
}

func (s *SliverMCPServer) handleRegCreateKey(ctx context.Context, args regCreateKeyArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(regCreateKeyToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("hive=%s path=%q", args.Hive, args.Path),
	)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	resp, err := s.Rpc.RegistryCreateKey(ctx, &sliverpb.RegistryCreateKeyReq{
		Request:  req,
		Hive:     args.Hive,
		Path:     args.Path,
		Key:      args.Key,
		Hostname: args.Hostname,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to create registry key", err), nil
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("reg_create_key", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.RegistryCreateKey{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]any{"created": true}), nil
}

// --- Registry delete key ---

type regDeleteKeyArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Hive           string `json:"hive"`
	Path           string `json:"path"`
	Key            string `json:"key"`
	Hostname       string `json:"hostname,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) regDeleteKeyHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args regDeleteKeyArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Hive == "" || args.Path == "" {
		return mcpapi.NewToolResultError("hive and path are required"), nil
	}
	return s.handleRegDeleteKey(ctx, args)
}

func (s *SliverMCPServer) handleRegDeleteKey(ctx context.Context, args regDeleteKeyArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(regDeleteKeyToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("hive=%s path=%q key=%q", args.Hive, args.Path, args.Key),
	)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	resp, err := s.Rpc.RegistryDeleteKey(ctx, &sliverpb.RegistryDeleteKeyReq{
		Request:  req,
		Hive:     args.Hive,
		Path:     args.Path,
		Key:      args.Key,
		Hostname: args.Hostname,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to delete registry key", err), nil
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("reg_delete_key", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.RegistryDeleteKey{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]any{"deleted": true}), nil
}

// --- Registry list subkeys ---

type regListSubKeysArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Hive           string `json:"hive"`
	Path           string `json:"path"`
	Hostname       string `json:"hostname,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type regListSubKeysResult struct {
	Subkeys []string `json:"subkeys"`
}

func (s *SliverMCPServer) regListSubKeysHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args regListSubKeysArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Hive == "" || args.Path == "" {
		return mcpapi.NewToolResultError("hive and path are required"), nil
	}
	return s.handleRegListSubKeys(ctx, args)
}

func (s *SliverMCPServer) handleRegListSubKeys(ctx context.Context, args regListSubKeysArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(regListSubKeysToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("hive=%s path=%q", args.Hive, args.Path),
	)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	resp, err := s.Rpc.RegistryListSubKeys(ctx, &sliverpb.RegistrySubKeyListReq{
		Request:  req,
		Hive:     args.Hive,
		Path:     args.Path,
		Hostname: args.Hostname,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list registry subkeys", err), nil
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("reg_list_subkeys", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.RegistrySubKeyList{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(regListSubKeysResult{Subkeys: resp.Subkeys}), nil
}

// --- Registry list values ---

type regListValuesArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Hive           string `json:"hive"`
	Path           string `json:"path"`
	Hostname       string `json:"hostname,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type regListValuesResult struct {
	ValueNames []string `json:"value_names"`
}

func (s *SliverMCPServer) regListValuesHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args regListValuesArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Hive == "" || args.Path == "" {
		return mcpapi.NewToolResultError("hive and path are required"), nil
	}
	return s.handleRegListValues(ctx, args)
}

func (s *SliverMCPServer) handleRegListValues(ctx context.Context, args regListValuesArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(regListValuesToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("hive=%s path=%q", args.Hive, args.Path),
	)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	resp, err := s.Rpc.RegistryListValues(ctx, &sliverpb.RegistryListValuesReq{
		Request:  req,
		Hive:     args.Hive,
		Path:     args.Path,
		Hostname: args.Hostname,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list registry values", err), nil
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("reg_list_values", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.RegistryValuesList{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(regListValuesResult{ValueNames: resp.ValueNames}), nil
}
