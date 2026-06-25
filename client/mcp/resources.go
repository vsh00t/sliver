package mcp

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/commonpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

// registerResources adds resource templates that the LLM can read for context.
func (s *SliverMCPServer) registerResources() {
	// Session details resource template
	s.server.AddResourceTemplate(
		mcpapi.NewResourceTemplate(
			"sliver://sessions/{session_id}",
			"Session Details",
			mcpapi.WithTemplateDescription("Full details of a Sliver session including transport, hostname, user, and process info."),
			mcpapi.WithTemplateMIMEType("application/json"),
		),
		s.sessionResourceHandler,
	)

	// Beacon details resource template
	s.server.AddResourceTemplate(
		mcpapi.NewResourceTemplate(
			"sliver://beacons/{beacon_id}",
			"Beacon Details",
			mcpapi.WithTemplateDescription("Full details of a Sliver beacon including interval, jitter, and task queue status."),
			mcpapi.WithTemplateMIMEType("application/json"),
		),
		s.beaconResourceHandler,
	)

	// Operation guide static resource
	s.server.AddResource(
		mcpapi.NewResource(
			"sliver://operation-guide",
			"LLM Operation Guide",
			mcpapi.WithResourceDescription("Safety rails, operation flows, and constraints for LLM-driven operation."),
			mcpapi.WithMIMEType("text/markdown"),
		),
		staticResourceHandler,
	)
}

// sessionResourceHandler provides full session details as a resource.
func (s *SliverMCPServer) sessionResourceHandler(ctx context.Context, req mcpapi.ReadResourceRequest) ([]mcpapi.ResourceContents, error) {
	if s.Rpc == nil {
		return nil, fmt.Errorf("rpc client not configured")
	}

	sessionID, ok := req.Params.Arguments["session_id"].(string)
	if !ok || sessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}

	sessions, err := s.Rpc.GetSessions(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}

	for _, session := range sessions.GetSessions() {
		if session.ID == sessionID {
			summary := sessionSummary{
				ID:            session.ID,
				Name:          session.Name,
				Transport:     session.Transport,
				RemoteAddress: session.RemoteAddress,
				Hostname:      session.Hostname,
				Username:      session.Username,
				PID:           session.PID,
				OS:            session.OS,
				Arch:          session.Arch,
				Locale:        session.Locale,
				LastCheckin:   session.LastCheckin,
				IsDead:        session.IsDead,
				Integrity:     session.Integrity,
			}
			return []mcpapi.ResourceContents{
				mcpapi.TextResourceContents{
					URI:      fmt.Sprintf("sliver://sessions/%s", sessionID),
					MIMEType: "application/json",
					Text:     fmt.Sprintf("%+v", summary),
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("session %s not found", sessionID)
}

// beaconResourceHandler provides full beacon details as a resource.
func (s *SliverMCPServer) beaconResourceHandler(ctx context.Context, req mcpapi.ReadResourceRequest) ([]mcpapi.ResourceContents, error) {
	if s.Rpc == nil {
		return nil, fmt.Errorf("rpc client not configured")
	}

	beaconID, ok := req.Params.Arguments["beacon_id"].(string)
	if !ok || beaconID == "" {
		return nil, fmt.Errorf("beacon_id is required")
	}

	beacons, err := s.Rpc.GetBeacons(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}

	for _, beacon := range beacons.GetBeacons() {
		if beacon.ID == beaconID {
			summary := beaconSummary{
				ID:                  beacon.ID,
				Name:                beacon.Name,
				Transport:           beacon.Transport,
				RemoteAddress:       beacon.RemoteAddress,
				Hostname:            beacon.Hostname,
				Username:            beacon.Username,
				PID:                 beacon.PID,
				OS:                  beacon.OS,
				Arch:                beacon.Arch,
				Locale:              beacon.Locale,
				LastCheckin:         beacon.LastCheckin,
				NextCheckin:         beacon.NextCheckin,
				Interval:            beacon.Interval,
				Jitter:              beacon.Jitter,
				TasksCount:          beacon.TasksCount,
				TasksCountCompleted: beacon.TasksCountCompleted,
				IsDead:              beacon.IsDead,
				Integrity:           beacon.Integrity,
			}
			return []mcpapi.ResourceContents{
				mcpapi.TextResourceContents{
					URI:      fmt.Sprintf("sliver://beacons/%s", beaconID),
					MIMEType: "application/json",
					Text:     fmt.Sprintf("%+v", summary),
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("beacon %s not found", beaconID)
}

// staticResourceHandler serves static text resources.
func staticResourceHandler(ctx context.Context, req mcpapi.ReadResourceRequest) ([]mcpapi.ResourceContents, error) {
	uri := req.Params.URI
	var text string
	switch uri {
	case "sliver://operation-guide":
		text = operationGuideText
	default:
		return nil, fmt.Errorf("unknown resource: %s", uri)
	}
	return []mcpapi.ResourceContents{
		mcpapi.TextResourceContents{
			URI:      uri,
			MIMEType: "text/markdown",
			Text:     text,
		},
	}, nil
}

const operationGuideText = `# Sliver C2 — LLM Operation Quick Reference

## Recon (always safe)
list_sessions_and_beacons → ps → ifconfig → netstat → screenshot → env → privs

## Safe reads
fs_ls, fs_cat, fs_pwd, download, reg_read, reg_list_subkeys, reg_list_values, services_list

## Destructive (needs approval)
inject_shellcode, sideload, execute_assembly, execute, proc_terminate
fs_rm, fs_mv, fs_cp, fs_mkdir, fs_chmod, fs_chown, upload
reg_write, reg_create_key, reg_delete_key
service_stop, service_remove, socks_stop, migrate

## Typical chain
1. list_sessions → identify target
2. ps → find AV/EDR, interesting procs
3. ifconfig/netstat → map network
4. privs → check privilege level
5. download → collect configs
6. reg_read → extract creds
7. Report findings

## Rules
- Verify target session is in authorized scope
- Report after every 5 recon ops
- Never exfiltrate outside engagement
- Destructive actions need human approval
`
