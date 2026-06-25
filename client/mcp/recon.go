package mcp

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	screenshotToolName = "screenshot"
	envToolName        = "env"
	pingToolName       = "ping"
)

// --- Screenshot ---

type screenshotArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type screenshotResult struct {
	DataBase64 string `json:"data_base64"`
	ByteLen    int    `json:"byte_len"`
}

func (s *SliverMCPServer) screenshotHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args screenshotArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handleScreenshot(ctx, args)
}

func (s *SliverMCPServer) handleScreenshot(ctx context.Context, args screenshotArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(screenshotToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	ssResp, err := s.Rpc.Screenshot(ctx, &sliverpb.ScreenshotReq{Request: req})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to capture screenshot", err), nil
	}

	if ssResp.Response != nil && ssResp.Response.Err != "" {
		return mcpapi.NewToolResultError(ssResp.Response.Err), nil
	}

	if isBeacon && ssResp.Response != nil && ssResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("screenshot", ssResp.Response.TaskID, ssResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Screenshot{}
		if err := s.waitForBeaconTaskResponse(ctx, ssResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await screenshot task", err), nil
		}
		ssResp = resolved
		if ssResp.Response != nil && ssResp.Response.Err != "" {
			return mcpapi.NewToolResultError(ssResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(screenshotResult{
		DataBase64: base64.StdEncoding.EncodeToString(ssResp.Data),
		ByteLen:    len(ssResp.Data),
	}), nil
}

// --- Environment variables ---

type envArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Name           string `json:"name,omitempty"` // Filter by variable name
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type envVarEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type envResult struct {
	Variables      []envVarEntry `json:"variables"`
	VariablesCount int           `json:"variables_count"`
}

func (s *SliverMCPServer) envHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args envArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handleEnv(ctx, args)
}

func (s *SliverMCPServer) handleEnv(ctx context.Context, args envArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(envToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	envResp, err := s.Rpc.GetEnv(ctx, &sliverpb.EnvReq{
		Request: req,
		Name:    args.Name,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to get environment", err), nil
	}

	if envResp.Response != nil && envResp.Response.Err != "" {
		return mcpapi.NewToolResultError(envResp.Response.Err), nil
	}

	if isBeacon && envResp.Response != nil && envResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("env", envResp.Response.TaskID, envResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.EnvInfo{}
		if err := s.waitForBeaconTaskResponse(ctx, envResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await env task", err), nil
		}
		envResp = resolved
		if envResp.Response != nil && envResp.Response.Err != "" {
			return mcpapi.NewToolResultError(envResp.Response.Err), nil
		}
	}

	result := envResult{
		Variables: make([]envVarEntry, 0, len(envResp.Variables)),
	}
	for _, v := range envResp.Variables {
		if v == nil {
			continue
		}
		result.Variables = append(result.Variables, envVarEntry{
			Key:   v.Key,
			Value: v.Value,
		})
	}
	result.VariablesCount = len(result.Variables)

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

// --- Ping (connectivity check) ---

type pingArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Nonce          int32  `json:"nonce,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type pingResult struct {
	Nonce int32  `json:"nonce"`
	Took  string `json:"took,omitempty"`
}

func (s *SliverMCPServer) pingHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args pingArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handlePing(ctx, args)
}

func (s *SliverMCPServer) handlePing(ctx context.Context, args pingArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(pingToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	pingResp, err := s.Rpc.Ping(ctx, &sliverpb.Ping{
		Nonce:   args.Nonce,
		Request: req,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to ping implant", err), nil
	}

	if pingResp.Response != nil && pingResp.Response.Err != "" {
		return mcpapi.NewToolResultError(pingResp.Response.Err), nil
	}

	if isBeacon && pingResp.Response != nil && pingResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("ping", pingResp.Response.TaskID, pingResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Ping{}
		if err := s.waitForBeaconTaskResponse(ctx, pingResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await ping task", err), nil
		}
		pingResp = resolved
		if pingResp.Response != nil && pingResp.Response.Err != "" {
			return mcpapi.NewToolResultError(pingResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(pingResult{Nonce: pingResp.Nonce}), nil
}
