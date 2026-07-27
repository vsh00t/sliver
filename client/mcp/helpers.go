package mcp

import (
	"encoding/json"

	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

// newJSONResult creates a tool result from any JSON-serializable value
func newJSONResult(toolName string, data interface{}) (*mcpapi.CallToolResult, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return mcpapi.NewToolResultErrorf("failed to marshal result: %v", err), nil
	}
	return mcpapi.NewToolResultText(string(jsonBytes)), nil
}
