package mcp

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	mcpapi "github.com/mark3labs/mcp-go/mcp"
)

const (
	pingSweepToolName = "ping_sweep"
	arpScanToolName   = "arp_scan"
	portScanToolName  = "port_scan"
)

// --- Ping Sweep ---

type pingSweepArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	CIDR           string `json:"cidr"`
	Count          int    `json:"count,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type pingSweepHost struct {
	IP       string `json:"ip"`
	Alive    bool   `json:"alive"`
	Hostname string `json:"hostname,omitempty"`
}

type pingSweepResult struct {
	Hosts []pingSweepHost `json:"hosts"`
	Total int             `json:"total"`
	Alive int             `json:"alive"`
}

func (s *SliverMCPServer) pingSweepHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args pingSweepArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.CIDR == "" {
		return mcpapi.NewToolResultError("cidr is required (e.g. 10.20.30.0/24)"), nil
	}
	return s.handlePingSweep(ctx, args)
}

func (s *SliverMCPServer) handlePingSweep(ctx context.Context, args pingSweepArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(pingSweepToolName, args.SessionID, args.BeaconID, fmt.Sprintf("cidr=%s", args.CIDR))

	// Expand CIDR to IP list
	ipList, err := expandCIDR(args.CIDR)
	if err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid CIDR: %v", err)), nil
	}

	count := args.Count
	if count <= 0 {
		count = 1
	}

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	if args.TimeoutSeconds < int64(len(ipList)*2) {
		args.TimeoutSeconds = int64(len(ipList)*2 + 10)
	}
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	// Build a script that pings all IPs — PowerShell for Windows, bash for Linux
	var script string
	var execPath string
	var execArgs []string

	// Detect OS from session info
	isWindows := s.isSessionWindows(args.SessionID, args.BeaconID)

	if isWindows {
		// Windows: use PowerShell to ping each IP quickly
		execPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
		var hosts []string
		for _, ip := range ipList {
			hosts = append(hosts, fmt.Sprintf("'%s'", ip))
		}
		script = fmt.Sprintf(`$ips = @(%s); $results = @(); foreach ($ip in $ips) { $ping = Test-Connection -ComputerName $ip -Count %d -Quiet -ErrorAction SilentlyContinue; if ($ping) { try { $name = ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch { $name = '' }; $results += "$ip,ALIVE,$name" } else { $results += "$ip,DEAD," } }; $results -join "` + "\n" + `"`, strings.Join(hosts, ","), count)
		execArgs = []string{"-NoProfile", "-NonInteractive", "-Command", script}
	} else {
		// Linux: bash loop with ping
		execPath = "/bin/sh"
		var hosts []string
		for _, ip := range ipList {
			hosts = append(hosts, ip)
		}
		script = fmt.Sprintf(`for ip in %s; do if ping -c %d -W 1 "$ip" >/dev/null 2>&1; then name=$(host "$ip" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//'); echo "$ip,ALIVE,$name"; else echo "$ip,DEAD,"; fi; done`, strings.Join(hosts, " "), count)
		execArgs = []string{"-c", script}
	}

	executeResp, err := s.Rpc.Execute(ctx, &sliverpb.ExecuteReq{
		Request: req,
		Path:    execPath,
		Args:    execArgs,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("ping sweep failed", err), nil
	}

	if isBeacon && executeResp.Response != nil && executeResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("ping_sweep", executeResp.Response.TaskID, executeResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Execute{}
		if err := s.waitForBeaconTaskResponse(ctx, executeResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await ping sweep task", err), nil
		}
		executeResp = resolved
	}

	if executeResp.Response != nil && executeResp.Response.Err != "" {
		return mcpapi.NewToolResultError(executeResp.Response.Err), nil
	}

	// Parse output
	result := parsePingSweepOutput(string(executeResp.Stdout), ipList)
	return newJSONResult(pingSweepToolName, result)
}

// --- ARP Scan ---

type arpScanArgs struct {
	SessionID      string `json:"session_id,omitempty"`
	BeaconID       string `json:"beacon_id,omitempty"`
	Wait           bool   `json:"wait,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds,omitempty"`
}

type arpScanEntry struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Type     string `json:"type,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type arpScanResult struct {
	Entries []arpScanEntry `json:"entries"`
	Total   int            `json:"total"`
}

func (s *SliverMCPServer) arpScanHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args arpScanArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	return s.handleArpScan(ctx, args)
}

func (s *SliverMCPServer) handleArpScan(ctx context.Context, args arpScanArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(arpScanToolName, args.SessionID, args.BeaconID)

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	isWindows := s.isSessionWindows(args.SessionID, args.BeaconID)

	var execPath string
	var execArgs []string
	if isWindows {
		execPath = "C:\\Windows\\System32\\cmd.exe"
		execArgs = []string{"/c", "arp -a"}
	} else {
		execPath = "/bin/sh"
		execArgs = []string{"-c", "ip neigh || arp -n"}
	}

	executeResp, err := s.Rpc.Execute(ctx, &sliverpb.ExecuteReq{
		Request: req,
		Path:    execPath,
		Args:    execArgs,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("arp scan failed", err), nil
	}

	if isBeacon && executeResp.Response != nil && executeResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("arp_scan", executeResp.Response.TaskID, executeResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Execute{}
		if err := s.waitForBeaconTaskResponse(ctx, executeResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await arp scan task", err), nil
		}
		executeResp = resolved
	}

	if executeResp.Response != nil && executeResp.Response.Err != "" {
		return mcpapi.NewToolResultError(executeResp.Response.Err), nil
	}

	output := string(executeResp.Stdout)
	result := parseArpOutput(output, isWindows)
	return newJSONResult(arpScanToolName, result)
}

// --- Port Scan ---

type portScanArgs struct {
	SessionID      string   `json:"session_id,omitempty"`
	BeaconID       string   `json:"beacon_id,omitempty"`
	Hosts          []string `json:"hosts"`
	Ports          []int    `json:"ports"`
	TimeoutMS      int      `json:"timeout_ms,omitempty"`
	Wait           bool     `json:"wait,omitempty"`
	TimeoutSeconds int64    `json:"timeout_seconds,omitempty"`
}

type portScanPortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Open    bool   `json:"open"`
}

type portScanHostResult struct {
	IP    string               `json:"ip"`
	Ports []portScanPortResult `json:"ports"`
}

type portScanResult struct {
	Hosts []portScanHostResult `json:"hosts"`
}

func (s *SliverMCPServer) portScanHandler(ctx context.Context, request mcpapi.CallToolRequest) (*mcpapi.CallToolResult, error) {
	var args portScanArgs
	if err := request.BindArguments(&args); err != nil {
		return mcpapi.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if len(args.Hosts) == 0 {
		return mcpapi.NewToolResultError("hosts is required (list of IPs or CIDR)"), nil
	}
	if len(args.Ports) == 0 {
		return mcpapi.NewToolResultError("ports is required (list of port numbers)"), nil
	}
	return s.handlePortScan(ctx, args)
}

func (s *SliverMCPServer) handlePortScan(ctx context.Context, args portScanArgs) (*mcpapi.CallToolResult, error) {
	if s.Rpc == nil {
		return mcpapi.NewToolResultError("rpc client not configured"), nil
	}

	s.logToolCall(portScanToolName, args.SessionID, args.BeaconID, fmt.Sprintf("hosts=%d ports=%d", len(args.Hosts), len(args.Ports)))

	timeoutMS := args.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 500
	}

	// Expand hosts (may include CIDRs)
	var allHosts []string
	for _, h := range args.Hosts {
		if strings.Contains(h, "/") {
			expanded, err := expandCIDR(h)
			if err == nil {
				allHosts = append(allHosts, expanded...)
				continue
			}
		}
		allHosts = append(allHosts, h)
	}

	// Build port list string
	var portStrs []string
	for _, p := range args.Ports {
		portStrs = append(portStrs, strconv.Itoa(p))
	}
	portList := strings.Join(portStrs, ",")

	args.TimeoutSeconds = applyDefaultTimeout(args.Wait, args.TimeoutSeconds)
	expectedDuration := int64(len(allHosts)*len(args.Ports)*timeoutMS) / 1000
	if args.TimeoutSeconds < expectedDuration+30 {
		args.TimeoutSeconds = expectedDuration + 30
	}
	ctx, cancel := withTimeout(ctx, args.TimeoutSeconds)
	if cancel != nil {
		defer cancel()
	}

	req, isBeacon, err := buildRequest(args.SessionID, args.BeaconID, args.TimeoutSeconds)
	if err != nil {
		return mcpapi.NewToolResultError(err.Error()), nil
	}

	isWindows := s.isSessionWindows(args.SessionID, args.BeaconID)

	var execPath string
	var execArgs []string
	hostList := strings.Join(allHosts, ",")

	if isWindows {
		// Windows: PowerShell TCP connect scan
		execPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
		script := fmt.Sprintf(`$hosts = '%s'.Split(','); $ports = '%s'.Split(','); foreach ($h in $hosts) { foreach ($p in $ports) { try { $tcp = New-Object System.Net.Sockets.TcpClient; $iar = $tcp.BeginConnect($h, [int]$p, $null, $null); $success = $iar.AsyncWaitHandle.WaitOne(%d); if ($success -and $tcp.Connected) { Write-Output "$h,$p,OPEN" } else { Write-Output "$h,$p,CLOSED" }; $tcp.Close() } catch { Write-Output "$h,$p,CLOSED" } } }`, hostList, portList, timeoutMS)
		execArgs = []string{"-NoProfile", "-NonInteractive", "-Command", script}
	} else {
		// Linux: bash TCP connect with timeout
		execPath = "/bin/sh"
		script := fmt.Sprintf(`IFS=',' read -ra HOSTS <<< '%s'; IFS=',' read -ra PORTS <<< '%s'; for h in "${HOSTS[@]}"; do for p in "${PORTS[@]}"; do if timeout 1 bash -c "echo > /dev/tcp/$h/$p" 2>/dev/null; then echo "$h,$p,OPEN"; else echo "$h,$p,CLOSED"; fi; done; done`, hostList, portList)
		execArgs = []string{"-c", script}
	}

	executeResp, err := s.Rpc.Execute(ctx, &sliverpb.ExecuteReq{
		Request: req,
		Path:    execPath,
		Args:    execArgs,
	})
	if err != nil {
		return mcpapi.NewToolResultErrorFromErr("port scan failed", err), nil
	}

	if isBeacon && executeResp.Response != nil && executeResp.Response.Async {
		if !args.Wait {
			return newAsyncResult("port_scan", executeResp.Response.TaskID, executeResp.Response.BeaconID), nil
		}
		resolved := &sliverpb.Execute{}
		if err := s.waitForBeaconTaskResponse(ctx, executeResp.Response.TaskID, resolved); err != nil {
			return mcpapi.NewToolResultErrorFromErr("failed to await port scan task", err), nil
		}
		executeResp = resolved
	}

	if executeResp.Response != nil && executeResp.Response.Err != "" {
		return mcpapi.NewToolResultError(executeResp.Response.Err), nil
	}

	output := string(executeResp.Stdout)
	result := parsePortScanOutput(output)
	return newJSONResult(portScanToolName, result)
}

// --- Helpers ---

func expandCIDR(cidr string) ([]string, error) {
	// Handle single IP
	if !strings.Contains(cidr, "/") {
		return []string{cidr}, nil
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /24 and smaller
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (s *SliverMCPServer) isSessionWindows(sessionID, beaconID string) bool {
	// Check sessions
	sessionsResp, err := s.Rpc.GetSessions(context.Background(), nil)
	if err == nil {
		for _, sess := range sessionsResp.GetSessions() {
			if sess.ID == sessionID {
				return strings.ToLower(sess.OS) == "windows"
			}
		}
	}
	return true // default to Windows (most common engagement target)
}

func parsePingSweepOutput(output string, expectedIPs []string) pingSweepResult {
	result := pingSweepResult{
		Hosts: make([]pingSweepHost, 0),
	}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: IP,STATUS,hostname
		parts := strings.SplitN(line, ",", 3)
		if len(parts) >= 2 {
			host := pingSweepHost{
				IP:    strings.TrimSpace(parts[0]),
				Alive: strings.ToUpper(strings.TrimSpace(parts[1])) == "ALIVE",
			}
			if len(parts) >= 3 {
				host.Hostname = strings.TrimSpace(parts[2])
			}
			if host.IP != "" {
				result.Hosts = append(result.Hosts, host)
				result.Total++
				if host.Alive {
					result.Alive++
				}
			}
		}
	}

	// If no output parsed, return expected IPs as unknown
	if len(result.Hosts) == 0 {
		for _, ip := range expectedIPs {
			result.Hosts = append(result.Hosts, pingSweepHost{IP: ip, Alive: false})
			result.Total++
		}
	}

	return result
}

func parseArpOutput(output string, isWindows bool) arpScanResult {
	result := arpScanResult{
		Entries: make([]arpScanEntry, 0),
	}

	if isWindows {
		// Windows arp -a format:
		// 10.20.30.1        00-11-22-33-44-55    dynamic
		re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-:]+)\s+(\w+)`)
		for _, line := range strings.Split(output, "\n") {
			matches := re.FindStringSubmatch(line)
			if matches != nil {
				result.Entries = append(result.Entries, arpScanEntry{
					IP:   matches[1],
					MAC:  strings.ReplaceAll(matches[2], "-", ":"),
					Type: matches[3],
				})
				result.Total++
			}
		}
	} else {
		// Linux ip neigh format:
		// 10.20.30.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
		re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-fA-F:]+)\s+(\w+)`)
		for _, line := range strings.Split(output, "\n") {
			matches := re.FindStringSubmatch(line)
			if matches != nil {
				result.Entries = append(result.Entries, arpScanEntry{
					IP:   matches[1],
					MAC:  matches[2],
					Type: matches[3],
				})
				result.Total++
			}
		}
	}

	return result
}

func parsePortScanOutput(output string) portScanResult {
	result := portScanResult{
		Hosts: make([]portScanHostResult, 0),
	}

	hostMap := make(map[string]*portScanHostResult)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: IP,PORT,STATUS
		parts := strings.SplitN(line, ",", 3)
		if len(parts) >= 3 {
			ip := strings.TrimSpace(parts[0])
			port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				continue
			}
			status := strings.ToUpper(strings.TrimSpace(parts[2]))

			if hostMap[ip] == nil {
				hostMap[ip] = &portScanHostResult{IP: ip, Ports: make([]portScanPortResult, 0)}
			}

			if status == "OPEN" {
				hostMap[ip].Ports = append(hostMap[ip].Ports, portScanPortResult{
					Port:    port,
					Open:    true,
					Service: commonPortName(port),
				})
			}
		}
	}

	for _, h := range hostMap {
		if len(h.Ports) > 0 {
			result.Hosts = append(result.Hosts, *h)
		}
	}

	return result
}

func commonPortName(port int) string {
	names := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
		143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
		995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
		3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
		5986: "winrm-ssl", 6379: "redis", 8080: "http-proxy",
		8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
	}
	if name, ok := names[port]; ok {
		return name
	}
	return ""
}
