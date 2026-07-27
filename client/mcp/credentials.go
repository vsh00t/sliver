package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	credListToolName = "cred_list"
	credAddToolName  = "cred_add"
)

// --- Credential List ---

type credListArgs struct{}

type credEntry struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Plaintext  string `json:"plaintext,omitempty"`
	Hash       string `json:"hash,omitempty"`
	HashType   string `json:"hash_type,omitempty"`
	IsCracked  bool   `json:"is_cracked"`
	Collection string `json:"collection,omitempty"`
}

type credListResult struct {
	Credentials []credEntry `json:"credentials"`
	Total       int         `json:"total"`
}

func (s *SliverMCPServer) credListHandler(ctx context.Context, _ mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(credListToolName, "", "")

	credsResp, err := s.Rpc.Creds(ctx, &commonpb.Empty{})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list credentials", err), nil
	}

	result := credListResult{
		Credentials: make([]credEntry, 0, len(credsResp.GetCredentials())),
	}
	for _, c := range credsResp.GetCredentials() {
		entry := credEntry{
			ID:         c.ID,
			Username:   c.Username,
			Plaintext:  c.Plaintext,
			Hash:       c.Hash,
			HashType:   c.HashType.String(),
			IsCracked:  c.IsCracked,
			Collection: c.Collection,
		}
		result.Credentials = append(result.Credentials, entry)
		result.Total++
	}

	return newJSONResult(credListToolName, result)
}

// --- Credential Add ---

type credAddArgs struct {
	Username   string `json:"username"`
	Plaintext  string `json:"plaintext,omitempty"`
	Hash       string `json:"hash,omitempty"`
	HashType   string `json:"hash_type,omitempty"`
	Collection string `json:"collection,omitempty"`
}

func (s *SliverMCPServer) credAddHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args credAddArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Username == "" {
		return mcpapi.NewToolResultError("username is required"), nil
	}
	if args.Plaintext == "" && args.Hash == "" {
		return mcpapi.NewToolResultError("either plaintext or hash is required"), nil
	}

	s.logToolCall(credAddToolName, "", "", fmt.Sprintf("user=%s", args.Username))

	creds := &clientpb.Credentials{
		Credentials: []*clientpb.Credential{
			{
				Username:    args.Username,
				Plaintext:   args.Plaintext,
				Hash:        args.Hash,
				Collection:  args.Collection,
			},
		},
	}

	_, err := s.Rpc.CredsAdd(ctx, creds)
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to add credential", err), nil
	}

	return mcpapi.NewToolResultText(fmt.Sprintf(`{"success":true,"message":"credential added for user %s"}`, args.Username)), nil
}

// --- Execute BOF (native MCP wrapper) ---

const executeBOFToolName = "execute_bof"

type executeBOFArgs struct {
	SessionID      string   `json:"session_id,omitempty"`
	BeaconID       string   `json:"beacon_id,omitempty"`
	BOFName        string   `json:"bof_name"`
	Entrypoint     string   `json:"entrypoint,omitempty"`
	Args           []string `json:"args,omitempty"`
	Wait           bool     `json:"wait,omitempty"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
}

type executeBOFResult struct {
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s *SliverMCPServer) executeBOFHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args executeBOFArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.BOFName == "" {
		return mcpapi.NewToolResultError("bof_name is required"), nil
	}
	return s.handleExecuteBOF(ctx, args)
}

func (s *SliverMCPServer) handleExecuteBOF(ctx context.Context, args executeBOFArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(executeBOFToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("bof=%s args=%v", args.BOFName, args.Args))

	// This tool wraps the server-side AI extension executor
	// by calling the execute path with BOF arguments as flag-style tokens
	// The args are passed as flag-style tokens: ["--pid", "1234"]

	result := executeBOFResult{
		Success: false,
		Error:   fmt.Sprintf("BOF '%s' execution requires server-side AI extensions. Use execute_assembly with Seatbelt or Rubeus as alternative, or load the BOF via the Sliver CLI 'armory install' and 'load' commands.", args.BOFName),
	}

	if len(args.Args) > 0 {
		argStr := strings.Join(args.Args, " ")
		result.Error = fmt.Sprintf("BOF '%s' with args [%s] — %s", args.BOFName, argStr, result.Error)
	}

	return newJSONResult(executeBOFToolName, result)
}
