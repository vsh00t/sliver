package mcp

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	servicesListToolName  = "services_list"
	serviceStartToolName  = "service_start"
	serviceStopToolName   = "service_stop"
	serviceRemoveToolName = "service_remove"
)

// --- List Services ---

type servicesListArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Hostname       string `json:"hostname,omitempty"` // Empty = localhost
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type serviceDetail struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Status      uint32 `json:"status"`
	StartupType uint32 `json:"startup_type"`
	BinPath     string `json:"bin_path"`
	Account     string `json:"account"`
}

type servicesListResult struct {
	Hostname string          `json:"hostname"`
	Services []serviceDetail `json:"services"`
	Count    int             `json:"count"`
}

func (s *SliverMCPServer) servicesListHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args servicesListArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handleServicesList(ctx, args)
}

func (s *SliverMCPServer) handleServicesList(ctx context.Context, args servicesListArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(servicesListToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("hostname=%q", args.Hostname),
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

	svcResp, err := s.Rpc.Services(ctx, &sliverpb.ServicesReq{
		Hostname: args.Hostname,
		Request:  req,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list services", err), nil
	}

	if svcResp.Response != nil && svcResp.Response.Err != "" {
		return mcpapi.NewToolResultError(svcResp.Response.Err), nil
	}

	if isBeacon && svcResp.Response != nil && svcResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("services_list", svcResp.Response.TaskID, svcResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Services{}
		if err := s.waitForBeaconTaskResponse(ctx, svcResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await services task", err), nil
		}
		svcResp = resolved
		if svcResp.Response != nil && svcResp.Response.Err != "" {
			return mcpapi.NewToolResultError(svcResp.Response.Err), nil
		}
	}

	result := servicesListResult{
		Hostname: args.Hostname,
		Services: make([]serviceDetail, 0, len(svcResp.Details)),
	}
	for _, d := range svcResp.Details {
		if d == nil {
			continue
		}
		result.Services = append(result.Services, serviceDetail{
			Name:        d.Name,
			DisplayName: d.DisplayName,
			Description: d.Description,
			Status:      d.Status,
			StartupType: d.StartupType,
			BinPath:     d.BinPath,
			Account:     d.Account,
		})
	}
	result.Count = len(result.Services)

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

// --- Start Service by Name ---

type serviceStartArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	ServiceName    string `json:"service_name"`
	Hostname       string `json:"hostname,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) serviceStartHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args serviceStartArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.ServiceName == "" {
		return mcpapi.NewToolResultError("service_name is required"), nil
	}

	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(serviceStartToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("service=%q", args.ServiceName),
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

	resp, err := s.Rpc.StartServiceByName(ctx, &sliverpb.StartServiceByNameReq{
		ServiceInfo: &sliverpb.ServiceInfoReq{
			ServiceName: args.ServiceName,
			Hostname:    args.Hostname,
		},
		Request: req,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to start service", err), nil
	}

	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("service_start", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.ServiceInfo{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await service start task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]interface{}{
		"service_name": args.ServiceName,
		"started":      true,
	}), nil
}

// --- Stop Service ---

type serviceStopArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	ServiceName    string `json:"service_name"`
	Hostname       string `json:"hostname,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) serviceStopHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args serviceStopArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.ServiceName == "" {
		return mcpapi.NewToolResultError("service_name is required"), nil
	}

	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(serviceStopToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("service=%q", args.ServiceName),
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

	resp, err := s.Rpc.StopService(ctx, &sliverpb.StopServiceReq{
		ServiceInfo: &sliverpb.ServiceInfoReq{
			ServiceName: args.ServiceName,
			Hostname:    args.Hostname,
		},
		Request: req,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to stop service", err), nil
	}

	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("service_stop", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.ServiceInfo{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await service stop task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]interface{}{
		"service_name": args.ServiceName,
		"stopped":      true,
	}), nil
}

// --- Remove Service ---

type serviceRemoveArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	ServiceName    string `json:"service_name"`
	Hostname       string `json:"hostname,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

func (s *SliverMCPServer) serviceRemoveHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args serviceRemoveArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.ServiceName == "" {
		return mcpapi.NewToolResultError("service_name is required"), nil
	}

	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(serviceRemoveToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("service=%q", args.ServiceName),
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

	resp, err := s.Rpc.RemoveService(ctx, &sliverpb.RemoveServiceReq{
		ServiceInfo: &sliverpb.ServiceInfoReq{
			ServiceName: args.ServiceName,
			Hostname:    args.Hostname,
		},
		Request: req,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to remove service", err), nil
	}

	if resp.Response != nil && resp.Response.Err != "" {
		return mcpapi.NewToolResultError(resp.Response.Err), nil
	}

	if isBeacon && resp.Response != nil && resp.Response.Async {
		if !args.Wait {
			return newAsyncResult("service_remove", resp.Response.TaskID, resp.Response.BeaconID), nil
		}
		resolved := &sliverpb.ServiceInfo{}
		if err := s.waitForBeaconTaskResponse(ctx, resp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await service remove task", err), nil
		}
		resp = resolved
		if resp.Response != nil && resp.Response.Err != "" {
			return mcpapi.NewToolResultError(resp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(map[string]interface{}{
		"service_name": args.ServiceName,
		"removed":      true,
	}), nil
}
