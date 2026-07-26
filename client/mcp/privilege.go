package mcp

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	privsToolName       = "privs"
	impersonateToolName = "impersonate"
	revToSelfToolName   = "rev_to_self"
)

// --- Privileges ---

type privsArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type privEntry struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	Enabled          bool   `json:"enabled"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	Removed          bool   `json:"removed"`
	UsedForAccess    bool   `json:"used_for_access"`
}

type privsResult struct {
	Integrity   string      `json:"integrity"`
	ProcessName string      `json:"process_name"`
	Privileges  []privEntry `json:"privileges"`
}

func (s *SliverMCPServer) privsHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args privsArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handlePrivs(ctx, args)
}

func (s *SliverMCPServer) handlePrivs(ctx context.Context, args privsArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(privsToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	privsResp, err := s.Rpc.GetPrivs(ctx, &sliverpb.GetPrivsReq{Request: req})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to get privileges", err), nil
	}

	if privsResp.Response != nil && privsResp.Response.Err != "" {
		return mcpapi.NewToolResultError(privsResp.Response.Err), nil
	}

	if isBeacon && privsResp.Response != nil && privsResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("privs", privsResp.Response.TaskID, privsResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.GetPrivs{}
		if err := s.waitForBeaconTaskResponse(ctx, privsResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await privs task", err), nil
		}
		privsResp = resolved
		if privsResp.Response != nil && privsResp.Response.Err != "" {
			return mcpapi.NewToolResultError(privsResp.Response.Err), nil
		}
	}

	result := privsResult{
		Integrity:   privsResp.ProcessIntegrity,
		ProcessName: privsResp.ProcessName,
		Privileges:  make([]privEntry, 0, len(privsResp.PrivInfo)),
	}
	for _, p := range privsResp.PrivInfo {
		if p == nil {
			continue
		}
		result.Privileges = append(result.Privileges, privEntry{
			Name:             p.Name,
			Description:      p.Description,
			Enabled:          p.Enabled,
			EnabledByDefault: p.EnabledByDefault,
			Removed:          p.Removed,
			UsedForAccess:    p.UsedForAccess,
		})
	}

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

// --- Impersonate ---

type impersonateArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Username       string `json:"username"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) impersonateHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args impersonateArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Username == "" {
		return mcpapi.NewToolResultError("username is required"), nil
	}
	return s.handleImpersonate(ctx, args)
}

func (s *SliverMCPServer) handleImpersonate(ctx context.Context, args impersonateArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(impersonateToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("username=%q", args.Username),
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

	impResp, err := s.Rpc.Impersonate(ctx, &sliverpb.ImpersonateReq{
		Request:  req,
		Username: args.Username,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to impersonate user", err), nil
	}

	if impResp.Response != nil && impResp.Response.Err != "" {
		return mcpapi.NewToolResultError(impResp.Response.Err), nil
	}

	if isBeacon && impResp.Response != nil && impResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("impersonate", impResp.Response.TaskID, impResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Impersonate{}
		if err := s.waitForBeaconTaskResponse(ctx, impResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await impersonate task", err), nil
		}
		impResp = resolved
		if impResp.Response != nil && impResp.Response.Err != "" {
			return mcpapi.NewToolResultError(impResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]any{
		"impersonated": true,
		"username":     args.Username,
	}), nil
}

// --- Revert to self ---

type revToSelfArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) revToSelfHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args revToSelfArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handleRevToSelf(ctx, args)
}

func (s *SliverMCPServer) handleRevToSelf(ctx context.Context, args revToSelfArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(revToSelfToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	revResp, err := s.Rpc.RevToSelf(ctx, &sliverpb.RevToSelfReq{Request: req})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to revert to self", err), nil
	}

	if revResp.Response != nil && revResp.Response.Err != "" {
		return mcpapi.NewToolResultError(revResp.Response.Err), nil
	}

	if isBeacon && revResp.Response != nil && revResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("rev_to_self", revResp.Response.TaskID, revResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.RevToSelf{}
		if err := s.waitForBeaconTaskResponse(ctx, revResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await rev_to_self task", err), nil
		}
		revResp = resolved
		if revResp.Response != nil && revResp.Response.Err != "" {
			return mcpapi.NewToolResultError(revResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]any{
		"reverted": true,
	}), nil
}
