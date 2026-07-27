package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const batchToolName = "batch"

// toolHandlerFunc is the signature for all MCP tool handlers
type toolHandlerFunc func(context.Context, mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error)

// executeToolByName dispatches a tool call by name using the registered handlers
func (s *SliverMCPServer) executeToolByName(ctx context.Context, toolName string, args map[string]interface{}) (*mcpapi.CallToolResult, error) {
	handler, ok := s.toolHandlers[toolName]
	if !ok {
		return mcpapi.NewToolResultError(fmt.Sprintf("unknown tool: %s", toolName)), nil
	}
	req := mcpapi.CallToolRequest{}
	req.Params.Name = toolName
	req.Params.Arguments = args
	return handler(ctx, req)
}

type batchArgs struct {
	Calls []batchCall `json:"calls"`
}

type batchCall struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args"`
}

type batchCallResult struct {
	Tool   string          `json:"tool"`
	Success bool           `json:"success"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	DurationMS int64       `json:"duration_ms"`
}

type batchResult struct {
	Results []batchCallResult `json:"results"`
	Total   int               `json:"total"`
	Success int               `json:"success"`
	Failed  int               `json:"failed"`
}

func (s *SliverMCPServer) batchHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args batchArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if len(args.Calls) == 0 {
		return mcpapi.NewToolResultError("calls array is required"), nil
	}
	if len(args.Calls) > 20 {
		return mcpapi.NewToolResultError("maximum 20 calls per batch"), nil
	}

	s.logToolCall(batchToolName, "", "", fmt.Sprintf("calls=%d", len(args.Calls)))

	// Execute all calls in parallel
	var wg sync.WaitGroup
	results := make([]batchCallResult, len(args.Calls))

	for i, call := range args.Calls {
		wg.Add(1)
		go func(idx int, c batchCall) {
			defer wg.Done()

			start := time.Now()
			results[idx].Tool = c.Tool

			// Dispatch via internal tool map
			result, err := s.executeToolByName(ctx, c.Tool, c.Args)
			elapsed := time.Since(start).Milliseconds()
			results[idx].DurationMS = elapsed

			if err != nil {
				results[idx].Error = err.Error()
				return
			}

			if len(result.Content) > 0 {
				for _, content := range result.Content {
					if textContent, ok := content.(mcpapi.TextContent); ok {
						results[idx].Result = json.RawMessage(textContent.Text)
						results[idx].Success = true
						break
					}
				}
			}

			if result.IsError {
				results[idx].Success = false
				results[idx].Error = "tool returned error"
			}
		}(i, call)
	}
	wg.Wait()

	total := len(results)
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	return newJSONResult(batchToolName, batchResult{
		Results: results,
		Total:   total,
		Success: successCount,
		Failed:  total - successCount,
	})
}
