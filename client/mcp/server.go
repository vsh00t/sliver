package mcp

import (
	"context"
	"log"

	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

const (
	listSessionsAndBeaconsToolName = "list_sessions_and_beacons"
)

type sessionSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Transport     string `json:"transport"`
	RemoteAddress string `json:"remote_address"`
	Hostname      string `json:"hostname"`
	Username      string `json:"username"`
	PID           int32  `json:"pid"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Locale        string `json:"locale"`
	LastCheckin   int64  `json:"last_checkin"`
	IsDead        bool   `json:"is_dead"`
	Integrity     string `json:"integrity"`
}

type beaconSummary struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Transport           string `json:"transport"`
	RemoteAddress       string `json:"remote_address"`
	Hostname            string `json:"hostname"`
	Username            string `json:"username"`
	PID                 int32  `json:"pid"`
	OS                  string `json:"os"`
	Arch                string `json:"arch"`
	Locale              string `json:"locale"`
	LastCheckin         int64  `json:"last_checkin"`
	NextCheckin         int64  `json:"next_checkin"`
	Interval            int64  `json:"interval"`
	Jitter              int64  `json:"jitter"`
	TasksCount          int64  `json:"tasks_count"`
	TasksCountCompleted int64  `json:"tasks_count_completed"`
	IsDead              bool   `json:"is_dead"`
	Integrity           string `json:"integrity"`
}

type listSessionsAndBeaconsResult struct {
	Sessions      []sessionSummary `json:"sessions"`
	SessionsCount int              `json:"sessions_count"`
	Beacons       []beaconSummary  `json:"beacons"`
	BeaconsCount  int              `json:"beacons_count"`
}

// SliverMCPServer wraps the MCP server with Sliver RPC access for handlers.
type SliverMCPServer struct {
	Rpc    rpcpb.SliverRPCClient
	server *mcpserver.MCPServer
	logger *log.Logger
	safety *SafetyMiddleware
	toolHandlers map[string]toolHandlerFunc
}

func newServer(cfg Config, rpc rpcpb.SliverRPCClient, logger *log.Logger) *SliverMCPServer {
	// Create safety middleware first so hooks can reference it
	safety := NewSafetyMiddleware(nil)

	// Create hooks for audit logging of all tool calls
	hooks := &mcpserver.Hooks{}
	hooks.AddAfterCallTool(func(ctx context.Context, id any, message *mcpapi.CallToolRequest, result any) {
		if message == nil {
			return
		}
		toolName := message.Params.Name
		isDestructive := destructiveTools[toolName]
		safety.recordAuditSimple(toolName, message, result, isDestructive)
	})

	base := mcpserver.NewMCPServer(
		cfg.ServerName,
		cfg.ServerVersion,
		mcpserver.WithToolCapabilities(false),
		mcpserver.WithHooks(hooks),
	)

	listSessionsAndBeaconsTool := mcpapi.NewTool(
		listSessionsAndBeaconsToolName,
		mcpapi.WithDescription("List active sessions and beacons."),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithDestructiveHintAnnotation(false),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	lsTool := mcpapi.NewTool(
		lsToolName,
		mcpapi.WithDescription("List the contents of a remote directory."),
		mcpapi.WithInputSchema[lsArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithDestructiveHintAnnotation(false),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	cdTool := mcpapi.NewTool(
		cdToolName,
		mcpapi.WithDescription("Change the current directory on a remote session or beacon."),
		mcpapi.WithInputSchema[cdArgs](),
		mcpapi.WithReadOnlyHintAnnotation(false),
		mcpapi.WithDestructiveHintAnnotation(false),
	)
	catTool := mcpapi.NewTool(
		catToolName,
		mcpapi.WithDescription("Download and return the contents of a remote file."),
		mcpapi.WithInputSchema[catArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithDestructiveHintAnnotation(false),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	pwdTool := mcpapi.NewTool(
		pwdToolName,
		mcpapi.WithDescription("Return the current working directory of a remote session or beacon."),
		mcpapi.WithInputSchema[pwdArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithDestructiveHintAnnotation(false),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	rmTool := mcpapi.NewTool(
		rmToolName,
		mcpapi.WithDescription("Remove a file or directory on the remote target."),
		mcpapi.WithInputSchema[rmArgs](),
		mcpapi.WithReadOnlyHintAnnotation(false),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	mvTool := mcpapi.NewTool(
		mvToolName,
		mcpapi.WithDescription("Move or rename a file or directory on the remote target."),
		mcpapi.WithInputSchema[mvArgs](),
		mcpapi.WithReadOnlyHintAnnotation(false),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	cpTool := mcpapi.NewTool(
		cpToolName,
		mcpapi.WithDescription("Copy a file on the remote target."),
		mcpapi.WithInputSchema[cpArgs](),
		mcpapi.WithReadOnlyHintAnnotation(false),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	mkdirTool := mcpapi.NewTool(
		mkdirToolName,
		mcpapi.WithDescription("Create a directory on the remote target."),
		mcpapi.WithInputSchema[mkdirArgs](),
		mcpapi.WithReadOnlyHintAnnotation(false),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	chmodTool := mcpapi.NewTool(
		chmodToolName,
		mcpapi.WithDescription("Change file or directory permissions on the remote target."),
		mcpapi.WithInputSchema[chmodArgs](),
		mcpapi.WithReadOnlyHintAnnotation(false),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	chownTool := mcpapi.NewTool(
		chownToolName,
		mcpapi.WithDescription("Change file or directory ownership on the remote target."),
		mcpapi.WithInputSchema[chownArgs](),
		mcpapi.WithReadOnlyHintAnnotation(false),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	srv := &SliverMCPServer{
		Rpc:          rpc,
		server:       base,
		logger:       logger,
		toolHandlers: make(map[string]toolHandlerFunc),
	}
	srv.server.AddTool(listSessionsAndBeaconsTool, srv.listSessionsAndBeaconsHandler)
	srv.server.AddTool(lsTool, srv.lsHandler)
	srv.server.AddTool(cdTool, srv.cdHandler)
	srv.server.AddTool(catTool, srv.catHandler)
	srv.server.AddTool(pwdTool, srv.pwdHandler)
	srv.server.AddTool(rmTool, srv.rmHandler)
	srv.server.AddTool(mvTool, srv.mvHandler)
	srv.server.AddTool(cpTool, srv.cpHandler)
	srv.server.AddTool(mkdirTool, srv.mkdirHandler)
	srv.server.AddTool(chmodTool, srv.chmodHandler)
	srv.server.AddTool(chownTool, srv.chownHandler)

	// Process & execution tools
	psTool := mcpapi.NewTool(
		psToolName,
		mcpapi.WithDescription("List running processes on a remote session or beacon."),
		mcpapi.WithInputSchema[psArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	terminateTool := mcpapi.NewTool(
		terminateToolName,
		mcpapi.WithDescription("Terminate a process by PID on the remote target."),
		mcpapi.WithInputSchema[terminateArgs](),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	executeTool := mcpapi.NewTool(
		executeToolName,
		mcpapi.WithDescription("Execute a command on a remote session or beacon. Returns stdout/stderr if output=true."),
		mcpapi.WithInputSchema[executeArgs](),
	)
	uploadTool := mcpapi.NewTool(
		uploadToolName,
		mcpapi.WithDescription("Upload a file (base64-encoded) to a remote session or beacon."),
		mcpapi.WithInputSchema[uploadArgs](),
	)

	// Network tools
	ifconfigTool := mcpapi.NewTool(
		ifconfigToolName,
		mcpapi.WithDescription("List network interfaces on a remote session or beacon."),
		mcpapi.WithInputSchema[ifconfigArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	netstatTool := mcpapi.NewTool(
		netstatToolName,
		mcpapi.WithDescription("List active network connections (TCP/UDP) on a remote session or beacon."),
		mcpapi.WithInputSchema[netstatArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)

	// Recon tools
	screenshotTool := mcpapi.NewTool(
		screenshotToolName,
		mcpapi.WithDescription("Capture a screenshot from a remote session or beacon. Returns base64-encoded PNG."),
		mcpapi.WithInputSchema[screenshotArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
	)
	envTool := mcpapi.NewTool(
		envToolName,
		mcpapi.WithDescription("List environment variables on a remote session or beacon."),
		mcpapi.WithInputSchema[envArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	pingTool := mcpapi.NewTool(
		pingToolName,
		mcpapi.WithDescription("Ping a remote session or beacon to check connectivity."),
		mcpapi.WithInputSchema[pingArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)

	// Privilege tools
	privsTool := mcpapi.NewTool(
		privsToolName,
		mcpapi.WithDescription("List Windows privileges of the current process on a remote session or beacon."),
		mcpapi.WithInputSchema[privsArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	impersonateTool := mcpapi.NewTool(
		impersonateToolName,
		mcpapi.WithDescription("Impersonate a user token on a remote Windows session or beacon (requires SeAssignPrimaryToken/SeImpersonate)."),
		mcpapi.WithInputSchema[impersonateArgs](),
	)
	revToSelfTool := mcpapi.NewTool(
		revToSelfToolName,
		mcpapi.WithDescription("Revert to the original token after impersonation on a remote session or beacon."),
		mcpapi.WithInputSchema[revToSelfArgs](),
	)

	srv.server.AddTool(psTool, srv.psHandler)
	srv.server.AddTool(terminateTool, srv.terminateHandler)
	srv.server.AddTool(executeTool, srv.executeHandler)
	srv.server.AddTool(uploadTool, srv.uploadHandler)
	srv.server.AddTool(ifconfigTool, srv.ifconfigHandler)
	srv.server.AddTool(netstatTool, srv.netstatHandler)
	srv.server.AddTool(screenshotTool, srv.screenshotHandler)
	srv.server.AddTool(envTool, srv.envHandler)
	srv.server.AddTool(pingTool, srv.pingHandler)
	srv.server.AddTool(privsTool, srv.privsHandler)
	srv.server.AddTool(impersonateTool, srv.impersonateHandler)
	srv.server.AddTool(revToSelfTool, srv.revToSelfHandler)

	// Injection & advanced execution tools
	downloadTool := mcpapi.NewTool(
		downloadToolName,
		mcpapi.WithDescription("Download a file from a remote session or beacon. Returns base64-encoded file data."),
		mcpapi.WithInputSchema[downloadArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
	)
	injectShellcodeTool := mcpapi.NewTool(
		injectShellcodeName,
		mcpapi.WithDescription("Inject shellcode into a remote process (or self if pid=0) on a session or beacon."),
		mcpapi.WithInputSchema[injectShellcodeArgs](),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	sideloadTool := mcpapi.NewTool(
		sideloadToolName,
		mcpapi.WithDescription("Sideload a DLL into a sacrificial process on a remote Windows session or beacon."),
		mcpapi.WithInputSchema[sideloadArgs](),
	)
	executeAssemblyTool := mcpapi.NewTool(
		executeAssemblyName,
		mcpapi.WithDescription("Execute a .NET assembly in-memory on a remote Windows session or beacon. Supports AMSI/ETW bypass."),
		mcpapi.WithInputSchema[executeAssemblyArgs](),
	)

	// Registry tools (Windows)
	regReadTool := mcpapi.NewTool(
		regReadToolName,
		mcpapi.WithDescription("Read a Windows registry value on a remote session or beacon."),
		mcpapi.WithInputSchema[regReadArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	regWriteTool := mcpapi.NewTool(
		regWriteToolName,
		mcpapi.WithDescription("Write a Windows registry value on a remote session or beacon."),
		mcpapi.WithInputSchema[regWriteArgs](),
	)
	regCreateKeyTool := mcpapi.NewTool(
		regCreateKeyToolName,
		mcpapi.WithDescription("Create a Windows registry key on a remote session or beacon."),
		mcpapi.WithInputSchema[regCreateKeyArgs](),
	)
	regDeleteKeyTool := mcpapi.NewTool(
		regDeleteKeyToolName,
		mcpapi.WithDescription("Delete a Windows registry key on a remote session or beacon."),
		mcpapi.WithInputSchema[regDeleteKeyArgs](),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	regListSubKeysTool := mcpapi.NewTool(
		regListSubKeysToolName,
		mcpapi.WithDescription("List sub-keys of a Windows registry path on a remote session or beacon."),
		mcpapi.WithInputSchema[regListSubKeysArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	regListValuesTool := mcpapi.NewTool(
		regListValuesToolName,
		mcpapi.WithDescription("List values under a Windows registry key on a remote session or beacon."),
		mcpapi.WithInputSchema[regListValuesArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)

	// Port forwarding & SOCKS tools
	portfwdTool := mcpapi.NewTool(
		portfwdToolName,
		mcpapi.WithDescription("Start a port forward on a remote session or beacon. Traffic is tunneled through the Sliver C2 channel."),
		mcpapi.WithInputSchema[portfwdArgs](),
	)
	socksStartTool := mcpapi.NewTool(
		socksStartToolName,
		mcpapi.WithDescription("Start a SOCKS5 proxy on a remote session or beacon. Returns a tunnel ID for proxying traffic."),
		mcpapi.WithInputSchema[socksStartArgs](),
	)
	socksStopTool := mcpapi.NewTool(
		socksStopToolName,
		mcpapi.WithDescription("Stop a SOCKS5 proxy on a remote session or beacon by tunnel ID."),
		mcpapi.WithInputSchema[socksStopArgs](),
		mcpapi.WithDestructiveHintAnnotation(true),
	)

	// Windows services tools
	servicesListTool := mcpapi.NewTool(
		servicesListToolName,
		mcpapi.WithDescription("List Windows services on a remote session or beacon."),
		mcpapi.WithInputSchema[servicesListArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
		mcpapi.WithIdempotentHintAnnotation(true),
	)
	serviceStartTool := mcpapi.NewTool(
		serviceStartToolName,
		mcpapi.WithDescription("Start a Windows service by name on a remote session or beacon."),
		mcpapi.WithInputSchema[serviceStartArgs](),
	)
	serviceStopTool := mcpapi.NewTool(
		serviceStopToolName,
		mcpapi.WithDescription("Stop a Windows service by name on a remote session or beacon."),
		mcpapi.WithInputSchema[serviceStopArgs](),
		mcpapi.WithDestructiveHintAnnotation(true),
	)
	serviceRemoveTool := mcpapi.NewTool(
		serviceRemoveToolName,
		mcpapi.WithDescription("Remove (uninstall) a Windows service by name on a remote session or beacon."),
		mcpapi.WithInputSchema[serviceRemoveArgs](),
		mcpapi.WithDestructiveHintAnnotation(true),
	)

	// Implant management tools
	generateTool := mcpapi.NewTool(
		generateToolName,
		mcpapi.WithDescription("Generate a new Sliver implant binary with the specified configuration. Returns base64-encoded binary."),
		mcpapi.WithInputSchema[generateArgs](),
	)
	migrateTool := mcpapi.NewTool(
		migrateToolName,
		mcpapi.WithDescription("Migrate the current implant into a new process (by PID) on a remote session or beacon."),
		mcpapi.WithInputSchema[migrateArgs](),
	)
	implantsListTool := mcpapi.NewTool(
		implantsListToolName,
		mcpapi.WithDescription("List all generated implant builds on the server. Returns implant names, configs, platforms, evasion flags, and staged status."),
		mcpapi.WithInputSchema[implantsListArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
	)

	srv.server.AddTool(downloadTool, srv.downloadHandler)
	srv.server.AddTool(injectShellcodeTool, srv.injectShellcodeHandler)
	srv.server.AddTool(sideloadTool, srv.sideloadHandler)
	srv.server.AddTool(executeAssemblyTool, srv.executeAssemblyHandler)
	srv.server.AddTool(regReadTool, srv.regReadHandler)
	srv.server.AddTool(regWriteTool, srv.regWriteHandler)
	srv.server.AddTool(regCreateKeyTool, srv.regCreateKeyHandler)
	srv.server.AddTool(regDeleteKeyTool, srv.regDeleteKeyHandler)
	srv.server.AddTool(regListSubKeysTool, srv.regListSubKeysHandler)
	srv.server.AddTool(regListValuesTool, srv.regListValuesHandler)
	srv.server.AddTool(portfwdTool, srv.portfwdHandler)
	srv.server.AddTool(socksStartTool, srv.socksStartHandler)
	srv.server.AddTool(socksStopTool, srv.socksStopHandler)
	srv.server.AddTool(servicesListTool, srv.servicesListHandler)
	srv.server.AddTool(serviceStartTool, srv.serviceStartHandler)
	srv.server.AddTool(serviceStopTool, srv.serviceStopHandler)
	srv.server.AddTool(serviceRemoveTool, srv.serviceRemoveHandler)
	srv.server.AddTool(generateTool, srv.generateHandler)
	srv.server.AddTool(migrateTool, srv.migrateHandler)
	srv.server.AddTool(implantsListTool, srv.implantsListHandler)

	// ── New tools: Network Discovery (FASE 2) ──
	pingSweepTool := mcpapi.NewTool(
		pingSweepToolName,
		mcpapi.WithDescription("ICMP ping sweep of a CIDR network range to discover live hosts."),
		mcpapi.WithInputSchema[pingSweepArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
	)
	portScanTool := mcpapi.NewTool(
		portScanToolName,
		mcpapi.WithDescription("TCP connect port scan from the implant to specified hosts and ports."),
		mcpapi.WithInputSchema[portScanArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
	)
	arpScanTool := mcpapi.NewTool(
		arpScanToolName,
		mcpapi.WithDescription("Dump ARP table from the implant to discover L2 neighbors."),
		mcpapi.WithInputSchema[arpScanArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
	)
	srv.server.AddTool(pingSweepTool, srv.pingSweepHandler)
	srv.server.AddTool(portScanTool, srv.portScanHandler)
	srv.server.AddTool(arpScanTool, srv.arpScanHandler)

	// ── New tools: Credentials (FASE 3) ──
	credListTool := mcpapi.NewTool(
		credListToolName,
		mcpapi.WithDescription("List all stored credentials in the Sliver server's credential database."),
		mcpapi.WithInputSchema[credListArgs](),
		mcpapi.WithReadOnlyHintAnnotation(true),
	)
	credAddTool := mcpapi.NewTool(
		credAddToolName,
		mcpapi.WithDescription("Add a credential to the Sliver server's credential database."),
		mcpapi.WithInputSchema[credAddArgs](),
	)
	executeBOFTool := mcpapi.NewTool(
		executeBOFToolName,
		mcpapi.WithDescription("Execute a BOF (Beacon Object File) on the target. Pass args as flag-style tokens."),
		mcpapi.WithInputSchema[executeBOFArgs](),
	)
	srv.server.AddTool(credListTool, srv.credListHandler)
	srv.server.AddTool(credAddTool, srv.credAddHandler)
	srv.server.AddTool(executeBOFTool, srv.executeBOFHandler)

	// ── New tools: Batch Operations (FASE 5) ──
	batchTool := mcpapi.NewTool(
		batchToolName,
		mcpapi.WithDescription("Execute multiple MCP tool calls in parallel (max 20). Each call: {tool, args}."),
		mcpapi.WithInputSchema[batchArgs](),
	)
	srv.server.AddTool(batchTool, srv.batchHandler)

	// ── Register all handlers in internal map for batch dispatch ──
	srv.registerInternalHandlers()

	// Apply safety middleware (already created above for hooks)
	srv.safety = safety

	// Register MCP resources for LLM context
	srv.registerResources()

	return srv
}

func (s *SliverMCPServer) listSessionsAndBeaconsHandler(ctx context.Context, _ mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(listSessionsAndBeaconsToolName, "", "")

	sessionsResp, err := s.Rpc.GetSessions(ctx, &commonpb.Empty{})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list sessions", err), nil
	}

	beaconsResp, err := s.Rpc.GetBeacons(ctx, &commonpb.Empty{})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list beacons", err), nil
	}

	result := listSessionsAndBeaconsResult{
		Sessions: make([]sessionSummary, 0, len(sessionsResp.GetSessions())),
		Beacons:  make([]beaconSummary, 0, len(beaconsResp.GetBeacons())),
	}

	for _, session := range sessionsResp.GetSessions() {
		if session == nil {
			continue
		}
		result.Sessions = append(result.Sessions, sessionSummary{
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
		})
	}

	for _, beacon := range beaconsResp.GetBeacons() {
		if beacon == nil {
			continue
		}
		result.Beacons = append(result.Beacons, beaconSummary{
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
		})
	}

	result.SessionsCount = len(result.Sessions)
	result.BeaconsCount = len(result.Beacons)

	return mcpapi.NewToolResultStructuredOnly(result), nil
}
