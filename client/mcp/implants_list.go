package mcp

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const implantsListToolName = "implants_list"

// --- List Generated Implants ---

type implantsListArgs struct{}

type implantBuildInfo struct {
	Name           string `json:"name"`
	ImplantBuildID string `json:"implant_build_id"`
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	IsBeacon       bool   `json:"is_beacon"`
	Format         string `json:"format"`
	Evasion        bool   `json:"evasion"`
	IncludeMTLS    bool   `json:"include_mtls"`
	IncludeHTTP    bool   `json:"include_http"`
	IncludeWG      bool   `json:"include_wg"`
	IncludeDNS     bool   `json:"include_dns"`
	Staged         bool   `json:"staged"`
}

type implantsListResult struct {
	Count   int                `json:"count"`
	Implants []implantBuildInfo `json:"implants"`
}

func (s *SliverMCPServer) implantsListHandler(ctx context.Context, _ mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(implantsListToolName, "", "")

	builds, err := s.Rpc.ImplantBuilds(ctx, &commonpb.Empty{})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("failed to list implant builds", err), nil
	}

	result := implantsListResult{
		Implants: []implantBuildInfo{},
	}

	for name, config := range builds.GetConfigs() {
		info := implantBuildInfo{
			Name:           name,
			ImplantBuildID: config.ID,
			GOOS:           config.GOOS,
			GOARCH:         config.GOARCH,
			IsBeacon:       config.IsBeacon,
			Evasion:        config.Evasion,
			IncludeMTLS:    config.IncludeMTLS,
			IncludeHTTP:    config.IncludeHTTP,
			IncludeWG:      config.IncludeWG,
			IncludeDNS:     config.IncludeDNS,
		}

		// Map format enum to string
		switch config.Format {
		case clientpb.OutputFormat_EXECUTABLE:
			info.Format = "executable"
		case clientpb.OutputFormat_SHARED_LIB:
			info.Format = "shared_lib"
		case clientpb.OutputFormat_SHELLCODE:
			info.Format = "shellcode"
		default:
			info.Format = "unknown"
		}

		// Check if staged
		if staged, ok := builds.GetStaged()[name]; ok {
			info.Staged = staged
		}

		result.Implants = append(result.Implants, info)
	}
	result.Count = len(result.Implants)

	if result.Count == 0 {
		return mcpapi.NewToolResultStructuredOnly(implantsListResult{
			Count:   0,
			Implants: []implantBuildInfo{},
		}), nil
	}

	return mcpapi.NewToolResultStructuredOnly(result), nil
}

var _ = fmt.Sprintf
