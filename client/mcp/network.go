package mcp

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	ifconfigToolName = "ifconfig"
	netstatToolName  = "netstat"
)

// --- Ifconfig (network interfaces) ---

type ifconfigArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type ifconfigInterface struct {
	Index       int32    `json:"index"`
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ip_addresses"`
}

type ifconfigResult struct {
	Interfaces []ifconfigInterface `json:"interfaces"`
}

func (s *SliverMCPServer) ifconfigHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args ifconfigArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handleIfconfig(ctx, args)
}

func (s *SliverMCPServer) handleIfconfig(ctx context.Context, args ifconfigArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(ifconfigToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	ifResp, err := s.Rpc.Ifconfig(ctx, &sliverpb.IfconfigReq{Request: req})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to get network interfaces", err), nil
	}

	if ifResp.Response != nil && ifResp.Response.Err != "" {
		return mcpapi.NewToolResultError(ifResp.Response.Err), nil
	}

	if isBeacon && ifResp.Response != nil && ifResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("ifconfig", ifResp.Response.TaskID, ifResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Ifconfig{}
		if err := s.waitForBeaconTaskResponse(ctx, ifResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await ifconfig task", err), nil
		}
		ifResp = resolved
		if ifResp.Response != nil && ifResp.Response.Err != "" {
			return mcpapi.NewToolResultError(ifResp.Response.Err), nil
		}
	}

	result := ifconfigResult{
		Interfaces: make([]ifconfigInterface, 0, len(ifResp.NetInterfaces)),
	}
	for _, iface := range ifResp.NetInterfaces {
		if iface == nil {
			continue
		}
		result.Interfaces = append(result.Interfaces, ifconfigInterface{
			Index:       iface.Index,
			Name:        iface.Name,
			MAC:         iface.MAC,
			IPAddresses: iface.IPAddresses,
		})
	}

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

// --- Netstat (active connections) ---

type netstatArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	TCP            bool   `json:"tcp,omitempty"`
	UDP            bool   `json:"udp,omitempty"`
	IP4            bool   `json:"ip4,omitempty"`
	IP6            bool   `json:"ip6,omitempty"`
	Listening      bool   `json:"listening,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type netstatSockAddr struct {
	IP   string `json:"ip"`
	Port uint32 `json:"port"`
}

type netstatEntry struct {
	LocalAddr  netstatSockAddr `json:"local_addr"`
	RemoteAddr netstatSockAddr `json:"remote_addr"`
	State      string          `json:"state"`
	UID        uint32          `json:"uid"`
	Protocol   string          `json:"protocol"`
	Pid        int32           `json:"pid,omitempty"`
	Process    string          `json:"process,omitempty"`
}

type netstatResult struct {
	Entries      []netstatEntry `json:"entries"`
	EntriesCount int            `json:"entries_count"`
}

func (s *SliverMCPServer) netstatHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args netstatArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handleNetstat(ctx, args)
}

func (s *SliverMCPServer) handleNetstat(ctx context.Context, args netstatArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(netstatToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("tcp=%t", args.TCP),
		fmt.Sprintf("udp=%t", args.UDP),
		fmt.Sprintf("listening=%t", args.Listening),
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

	nsResp, err := s.Rpc.Netstat(ctx, &sliverpb.NetstatReq{
		Request:   req,
		TCP:       args.TCP,
		UDP:       args.UDP,
		IP4:       args.IP4,
		IP6:       args.IP6,
		Listening: args.Listening,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to get netstat", err), nil
	}

	if nsResp.Response != nil && nsResp.Response.Err != "" {
		return mcpapi.NewToolResultError(nsResp.Response.Err), nil
	}

	if isBeacon && nsResp.Response != nil && nsResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("netstat", nsResp.Response.TaskID, nsResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Netstat{}
		if err := s.waitForBeaconTaskResponse(ctx, nsResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await netstat task", err), nil
		}
		nsResp = resolved
		if nsResp.Response != nil && nsResp.Response.Err != "" {
			return mcpapi.NewToolResultError(nsResp.Response.Err), nil
		}
	}

	result := netstatResult{
		Entries: make([]netstatEntry, 0, len(nsResp.Entries)),
	}
	for _, entry := range nsResp.Entries {
		if entry == nil {
			continue
		}
		e := netstatEntry{
			State:    entry.SkState,
			UID:      entry.UID,
			Protocol: entry.Protocol,
		}
		if entry.LocalAddr != nil {
			e.LocalAddr = netstatSockAddr{IP: entry.LocalAddr.Ip, Port: entry.LocalAddr.Port}
		}
		if entry.RemoteAddr != nil {
			e.RemoteAddr = netstatSockAddr{IP: entry.RemoteAddr.Ip, Port: entry.RemoteAddr.Port}
		}
		if entry.Process != nil {
			e.Pid = entry.Process.Pid
			e.Process = entry.Process.Executable
		}
		result.Entries = append(result.Entries, e)
	}
	result.EntriesCount = len(result.Entries)

	return mcpapi.NewToolResultStructuredOnly(result), nil
}
