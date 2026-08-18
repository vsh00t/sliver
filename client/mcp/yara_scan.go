package mcp

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
*/

// yara_scan — pre-delivery detection gate for generated implants.
//
// Scans any file (typically a freshly generated implant/stager) against a
// local cache of YARA rulesets. Default ruleset: elastic/protections-artifacts
// (public Elastic Defend YARA rules — the same rules the target EDR runs).
//
// The `generate` MCP tool auto-scans its output when rules are present
// (opt-out with skip_yara_scan) so every implant gets a detection verdict
// BEFORE it touches a target — technique from the DEF CON 34 EDR evasion
// workshop (tyeurada/edrEvasionWorkshop).
//
// Implementation shells out to the `yara` binary (libyara CLI) — no CGO,
// per repo convention. Rules live in <home>/.sliver/yara-rules/<name>/.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	yaraScanToolName = "yara_scan"
	yaraBinaryName   = "yara"

	// Default ruleset: Elastic Defend public YARA rules
	elasticRulesDir  = "elastic"
	elasticRulesRepo = "https://github.com/elastic/protections-artifacts"
)

// yaraRulesBaseDir returns the root dir for cached YARA rulesets.
func yaraRulesBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".sliver", "yara-rules"), nil
}

// --- yara_scan tool ---

type yaraScanArgs struct {
	FilePath     string `json:"file_path"`               // File to scan (server-local path)
	Ruleset      string `json:"ruleset,omitempty"`       // Ruleset name (default "elastic")
	RefreshRules bool   `json:"refresh_rules,omitempty"` // git pull the ruleset before scanning
}

type yaraScanResult struct {
	File       string          `json:"file"`
	Ruleset    string          `json:"ruleset"`
	Clean      bool            `json:"clean"`
	Matches    []yaraMatchInfo `json:"matches,omitempty"`
	RuleFiles  int             `json:"rule_files"`
	DurationMs int64           `json:"duration_ms"`
	Notes      []string        `json:"notes,omitempty"`
}

type yaraMatchInfo struct {
	Rule      string `json:"rule"`
	Namespace string `json:"namespace,omitempty"`
	Meta      string `json:"meta,omitempty"`
}

func (s *SliverMCPServer) yaraScanHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args yaraScanArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.FilePath == "" {
		return mcpapi.NewToolResultError("file_path is required"), nil
	}
	if args.Ruleset == "" {
		args.Ruleset = elasticRulesDir
	}

	s.logToolCall(yaraScanToolName, "", "",
		fmt.Sprintf("file=%q ruleset=%q refresh=%t", args.FilePath, args.Ruleset, args.RefreshRules),
	)

	res, err := YaraScanFile(args.FilePath, args.Ruleset, args.RefreshRules)
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("yara scan failed", err), nil
	}
	return mcpapi.NewToolResultStructuredOnly(res), nil
}

// --- scan engine ---

// YaraScanFile scans target against every .yar/.yara file in the ruleset dir.
// Missing ruleset / missing yara binary are reported as notes, not errors —
// a detection gate must never block implant delivery on tooling gaps.
func YaraScanFile(targetPath, ruleset string, refresh bool) (*yaraScanResult, error) {
	res := &yaraScanResult{
		File:    targetPath,
		Ruleset: ruleset,
		Clean:   true,
		Notes:   []string{},
	}
	start := time.Now()

	if _, err := os.Stat(targetPath); err != nil {
		return nil, fmt.Errorf("target file not accessible: %w", err)
	}

	yaraBin, err := exec.LookPath(yaraBinaryName)
	if err != nil {
		res.Notes = append(res.Notes, "yara binary not found in PATH — install libyara (apt install yara). Scan skipped.")
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}

	rulesPath, err := ensureRuleset(ruleset, refresh)
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("ruleset '%s' unavailable (%v) — run with refresh_rules to clone", ruleset, err))
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}

	ruleFiles, err := collectRuleFiles(rulesPath)
	if err != nil {
		return nil, err
	}
	res.RuleFiles = len(ruleFiles)
	if len(ruleFiles) == 0 {
		res.Notes = append(res.Notes, "ruleset dir contains no .yar/.yara files")
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}

	for _, ruleFile := range ruleFiles {
		out, err := exec.Command(yaraBin, "-m", ruleFile, targetPath).Output()
		if err != nil {
			// exit code 1 = no match (normal); other errors = malformed rule — note and continue
			if _, isExit := err.(*exec.ExitError); !isExit {
				res.Notes = append(res.Notes, fmt.Sprintf("rule file %s failed: %v", filepath.Base(ruleFile), err))
			}
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			match := parseYaraMatchLine(line)
			if match.Rule != "" {
				res.Matches = append(res.Matches, match)
				res.Clean = false
			}
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// parseYaraMatchLine parses `yara -m` output lines (JSON objects, one per match).
func parseYaraMatchLine(line string) yaraMatchInfo {
	var m yaraMatchInfo
	var raw struct {
		Rule      string                 `json:"rule"`
		Namespace string                 `json:"namespace"`
		Meta      map[string]interface{} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err == nil {
		m.Rule = raw.Rule
		m.Namespace = raw.Namespace
		if len(raw.Meta) > 0 {
			if metaBytes, err := json.Marshal(raw.Meta); err == nil {
				m.Meta = string(metaBytes)
			}
		}
	} else {
		// Fallback: plain "Namespace Rule" format
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			m.Rule = fields[len(fields)-1]
		}
	}
	return m
}

// collectRuleFiles walks a ruleset dir collecting .yar/.yara files.
func collectRuleFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yar" || ext == ".yara" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// ensureRuleset makes sure the ruleset dir exists (cloning on first use) and
// optionally refreshes it via git pull. Returns the path to the YARA rules.
func ensureRuleset(name string, refresh bool) (string, error) {
	base, err := yaraRulesBaseDir()
	if err != nil {
		return "", err
	}
	setPath := filepath.Join(base, name)

	switch name {
	case elasticRulesDir:
		yaraPath := filepath.Join(setPath, "yara")
		if _, err := os.Stat(yaraPath); os.IsNotExist(err) {
			if err := gitClone(elasticRulesRepo, setPath); err != nil {
				return "", fmt.Errorf("clone %s: %w", elasticRulesRepo, err)
			}
		} else if refresh {
			if err := gitPull(setPath); err != nil {
				return "", fmt.Errorf("pull %s: %w", setPath, err)
			}
		}
		return yaraPath, nil
	default:
		// Custom rulesets: caller-managed dir, use as-is
		if _, err := os.Stat(setPath); err != nil {
			return "", fmt.Errorf("ruleset dir not found: %s", setPath)
		}
		return setPath, nil
	}
}

func gitClone(repo, dest string) error {
	cmd := exec.Command("git", "clone", "--depth", "1", repo, dest)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func gitPull(dir string) error {
	cmd := exec.Command("git", "-C", dir, "pull", "--ff-only")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
