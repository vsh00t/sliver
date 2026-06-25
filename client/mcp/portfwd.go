package mcp

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	portfwdToolName    = "portfwd"
	socksStartToolName = "socks_start"
	socksStopToolName  = "socks_stop"
)

// --- Port Forward ---

type portfwdArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Port           uint32 `json:"port"`                  // Local port to bind on the operator side
	Host           string `json:"host"`                  // Target host (from the implant's perspective)
	RemotePort     int32  `json:"remote_port,omitempty"` // Target port (stored in Protocol field as convenience)
	Protocol       int32  `json:"protocol,omitempty"`    // 0=TCP, 1=UDP
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type portfwdResult struct {
	Port     uint32 `json:"port"`
	Host     string `json:"host"`
	TunnelID string `json:"tunnel_id"`
}

func (s *SliverMCPServer) portfwdHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args portfwdArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Port == 0 {
		return mcpapi.NewToolResultError("port is required"), nil
	}
	if args.Host == "" {
		return mcpapi.NewToolResultError("host is required"), nil
	}
	return s.handlePortfwd(ctx, args)
}

func (s *SliverMCPServer) handlePortfwd(ctx context.Context, args portfwdArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(portfwdToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("port=%d", args.Port),
		fmt.Sprintf("host=%q", args.Host),
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

	pfResp, err := s.Rpc.Portfwd(ctx, &sliverpb.PortfwdReq{
		Request:  req,
		Port:     args.Port,
		Protocol: args.Protocol,
		Host:     args.Host,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to start port forward", err), nil
	}

	if pfResp.Response != nil && pfResp.Response.Err != "" {
		return mcpapi.NewToolResultError(pfResp.Response.Err), nil
	}

	if isBeacon && pfResp.Response != nil && pfResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("portfwd", pfResp.Response.TaskID, pfResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Portfwd{}
		if err := s.waitForBeaconTaskResponse(ctx, pfResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await portfwd task", err), nil
		}
		pfResp = resolved
		if pfResp.Response != nil && pfResp.Response.Err != "" {
			return mcpapi.NewToolResultError(pfResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(portfwdResult{
		Port:     pfResp.Port,
		Host:     pfResp.Host,
		TunnelID: fmt.Sprintf("%d", pfResp.TunnelID),
	}), nil
}

// --- SOCKS Proxy Start ---

type socksStartArgs struct {
	SessionID      string `json:"session_id"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type socksStartResult struct {
	TunnelID  string `json:"tunnel_id"`
	SessionID string `json:"session_id"`
	Started   bool   `json:"started"`
}

func (s *SliverMCPServer) socksStartHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args socksStartArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.SessionID == "" && args.BeaconID == "" {
		return mcpapi.NewToolResultError("session_id or beacon_id is required"), nil
	}
	return s.handleSocksStart(ctx, args)
}

func (s *SliverMCPServer) handleSocksStart(ctx context.Context, args socksStartArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(socksStartToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	// SOCKS requires a session (not beacon) — streaming tunnels are session-only
	if args.SessionID == "" {
		return mcpapi.NewToolResultError("socks requires session_id (beacons not supported for streaming tunnels)"), nil
	}

	socksResp, err := s.Rpc.CreateSocks(ctx, &sliverpb.Socks{
		SessionID: args.SessionID,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to start SOCKS proxy", err), nil
	}

	return mcpapi.NewToolResultStructuredOnly(socksStartResult{
		TunnelID:  fmt.Sprintf("%d", socksResp.TunnelID),
		SessionID: args.SessionID,
		Started:   true,
	}), nil
}

// --- SOCKS Proxy Stop ---

type socksStopArgs struct {
	TunnelID string `json:"tunnel_id"`
}

type socksStopResult struct {
	TunnelID string `json:"tunnel_id"`
	Stopped  bool   `json:"stopped"`
}

func (s *SliverMCPServer) socksStopHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args socksStopArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.TunnelID == "" {
		return mcpapi.NewToolResultError("tunnel_id is required"), nil
	}

	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(socksStopToolName, "", "", fmt.Sprintf("tunnel_id=%s", args.TunnelID))

	var tunnelID uint64
	if _, err := fmt.Sscanf(args.TunnelID, "%d", &tunnelID); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid tunnel_id: %v", err)), nil
	}

	_, err := s.Rpc.CloseSocks(ctx, &sliverpb.Socks{
		TunnelID: tunnelID,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to stop SOCKS proxy", err), nil
	}

	return mcpapi.NewToolResultStructuredOnly(socksStopResult{
		TunnelID: args.TunnelID,
		Stopped:  true,
	}), nil
}
