package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	psToolName        = "ps"
	terminateToolName = "proc_terminate"
	executeToolName   = "execute"
)

// --- Process listing ---

type psArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	FullInfo       bool   `json:"full_info,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type psProcessEntry struct {
	Pid          int32    `json:"pid"`
	Ppid         int32    `json:"ppid"`
	Executable   string   `json:"executable"`
	Owner        string   `json:"owner"`
	Architecture string   `json:"architecture"`
	SessionID    int32    `json:"session_id"`
	CmdLine      []string `json:"cmd_line"`
}

type psResult struct {
	Processes      []psProcessEntry `json:"processes"`
	ProcessesCount int              `json:"processes_count"`
}

func (s *SliverMCPServer) psHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args psArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handlePs(ctx, args)
}

func (s *SliverMCPServer) handlePs(ctx context.Context, args psArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(psToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	psResp, err := s.Rpc.Ps(ctx, &sliverpb.PsReq{
		Request:  req,
		FullInfo: args.FullInfo,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list processes", err), nil
	}

	if psResp.Response != nil && psResp.Response.Err != "" {
		return mcpapi.NewToolResultError(psResp.Response.Err), nil
	}

	if isBeacon && psResp.Response != nil && psResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("ps", psResp.Response.TaskID, psResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Ps{}
		if err := s.waitForBeaconTaskResponse(ctx, psResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await ps task", err), nil
		}
		psResp = resolved
		if psResp.Response != nil && psResp.Response.Err != "" {
			return mcpapi.NewToolResultError(psResp.Response.Err), nil
		}
	}

	result := psResult{
		Processes: make([]psProcessEntry, 0, len(psResp.Processes)),
	}
	for _, p := range psResp.Processes {
		if p == nil {
			continue
		}
		result.Processes = append(result.Processes, psProcessEntry{
			Pid:          p.Pid,
			Ppid:         p.Ppid,
			Executable:   p.Executable,
			Owner:        p.Owner,
			Architecture: p.Architecture,
			SessionID:    p.SessionID,
			CmdLine:      p.CmdLine,
		})
	}
	result.ProcessesCount = len(result.Processes)

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

// --- Process termination ---

type terminateArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Pid            int32  `json:"pid"`
	Force          bool   `json:"force,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type terminateResult struct {
	Pid int32 `json:"pid"`
}

func (s *SliverMCPServer) terminateHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args terminateArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Pid == 0 {
		return mcpapi.NewToolResultError("pid is required"), nil
	}
	return s.handleTerminate(ctx, args)
}

func (s *SliverMCPServer) handleTerminate(ctx context.Context, args terminateArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(terminateToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("pid=%d", args.Pid),
		fmt.Sprintf("force=%t", args.Force),
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

	termResp, err := s.Rpc.Terminate(ctx, &sliverpb.TerminateReq{
		Request: req,
		Pid:     args.Pid,
		Force:   args.Force,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to terminate process", err), nil
	}

	if termResp.Response != nil && termResp.Response.Err != "" {
		return mcpapi.NewToolResultError(termResp.Response.Err), nil
	}

	if isBeacon && termResp.Response != nil && termResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("terminate", termResp.Response.TaskID, termResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Terminate{}
		if err := s.waitForBeaconTaskResponse(ctx, termResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await terminate task", err), nil
		}
		termResp = resolved
		if termResp.Response != nil && termResp.Response.Err != "" {
			return mcpapi.NewToolResultError(termResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(terminateResult{Pid: termResp.Pid}), nil
}

// --- Command execution ---

type executeArgs struct {
	SessionID      string            `json:"session_id,omitempty"`
	BeaconID       string            `json:"beacon_id,omitempty"`
	Path           string            `json:"path"`
	Args           []string          `json:"args,omitempty"`
	Output         bool              `json:"output,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	EnvInheritance bool              `json:"env_inheritance,omitempty"`
	Background     bool              `json:"background,omitempty"`
	PPid           uint32            `json:"ppid,omitempty"`
	Wait           bool              `json:"wait,omitempty"`
	TimeoutSeconds int64             `json:"timeout_seconds,omitempty"`
}

type executeResult struct {
	Path      string `json:"path"`
	Pid       uint32 `json:"pid"`
	Status    uint32 `json:"status"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	HasStdout bool   `json:"has_stdout"`
	HasStderr bool   `json:"has_stderr"`
}

func (s *SliverMCPServer) executeHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args executeArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Path == "" {
		return mcpapi.NewToolResultError("path is required"), nil
	}
	return s.handleExecute(ctx, args)
}

func (s *SliverMCPServer) handleExecute(ctx context.Context, args executeArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	extras := []string{
		fmt.Sprintf("path=%q", args.Path),
		fmt.Sprintf("output=%t", args.Output),
	}
	if len(args.Args) > 0 {
		extras = append(extras, fmt.Sprintf("args=%q", strings.Join(args.Args, " ")))
	}
	s.logToolCall(executeToolName, args.SessionID, args.BeaconID, extras...)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	execResp, err := s.Rpc.Execute(ctx, &sliverpb.ExecuteReq{
		Request:        req,
		Path:           args.Path,
		Args:           args.Args,
		Output:         args.Output,
		Env:            args.Env,
		EnvInheritance: args.EnvInheritance,
		Background:     args.Background,
		PPid:           args.PPid,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to execute command", err), nil
	}

	if execResp.Response != nil && execResp.Response.Err != "" {
		return mcpapi.NewToolResultError(execResp.Response.Err), nil
	}

	if isBeacon && execResp.Response != nil && execResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("execute", execResp.Response.TaskID, execResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Execute{}
		if err := s.waitForBeaconTaskResponse(ctx, execResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await execute task", err), nil
		}
		execResp = resolved
		if execResp.Response != nil && execResp.Response.Err != "" {
			return mcpapi.NewToolResultError(execResp.Response.Err), nil
		}
	}

	result := executeResult{
		Path:   args.Path,
		Pid:    execResp.Pid,
		Status: execResp.Status,
	}

	if len(execResp.Stdout) > 0 {
		result.Stdout = string(execResp.Stdout)
		result.HasStdout = true
	}
	if len(execResp.Stderr) > 0 {
		result.Stderr = string(execResp.Stderr)
		result.HasStderr = true
	}

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

// --- Upload ---

const uploadToolName = "upload"

type uploadArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Path           string `json:"path"`        // Remote destination path
	DataBase64     string `json:"data_base64"` // File contents, base64-encoded
	FileName       string `json:"file_name,omitempty"`
	IsDirectory    bool   `json:"is_directory,omitempty"`
	Overwrite      bool   `json:"overwrite,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type uploadResult struct {
	Path             string `json:"path"`
	WrittenFiles     int32  `json:"written_files"`
	UnwriteableFiles int32  `json:"unwriteable_files"`
}

func (s *SliverMCPServer) uploadHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args uploadArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Path == "" {
		return mcpapi.NewToolResultError("path is required"), nil
	}
	if args.DataBase64 == "" && !args.IsDirectory {
		return mcpapi.NewToolResultError("data_base64 is required (or set is_directory=true)"), nil
	}
	return s.handleUpload(ctx, args)
}

func (s *SliverMCPServer) handleUpload(ctx context.Context, args uploadArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(uploadToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("path=%q", args.Path),
		fmt.Sprintf("overwrite=%t", args.Overwrite),
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

	var data []byte
	if args.DataBase64 != "" {
		data, err = base64.StdEncoding.DecodeString(args.DataBase64)
		if err != nil {
			return mcpapi.NewToolResultError(fmt.Sprintf("failed to decode base64 data: %v", err)), nil
		}
	}

	uploadResp, err := s.Rpc.Upload(ctx, &sliverpb.UploadReq{
		Request:     req,
		Path:        args.Path,
		Data:        data,
		FileName:    args.FileName,
		IsDirectory: args.IsDirectory,
		Overwrite:   args.Overwrite,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to upload file", err), nil
	}

	if uploadResp.Response != nil && uploadResp.Response.Err != "" {
		return mcpapi.NewToolResultError(uploadResp.Response.Err), nil
	}

	if isBeacon && uploadResp.Response != nil && uploadResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("upload", uploadResp.Response.TaskID, uploadResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Upload{}
		if err := s.waitForBeaconTaskResponse(ctx, uploadResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await upload task", err), nil
		}
		uploadResp = resolved
		if uploadResp.Response != nil && uploadResp.Response.Err != "" {
			return mcpapi.NewToolResultError(uploadResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(uploadResult{
		Path:             uploadResp.Path,
		WrittenFiles:     uploadResp.WrittenFiles,
		UnwriteableFiles: uploadResp.UnwriteableFiles,
	}), nil
}
