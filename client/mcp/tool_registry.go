package mcp

// registerInternalHandlers populates the toolHandlers map used by batch operations
// to dispatch tool calls by name without going through the mcp-go server layer.
func (s *SliverMCPServer) registerInternalHandlers() {
	// Filesystem
	s.toolHandlers[listSessionsAndBeaconsToolName] = s.listSessionsAndBeaconsHandler
	s.toolHandlers[lsToolName] = s.lsHandler
	s.toolHandlers[cdToolName] = s.cdHandler
	s.toolHandlers[catToolName] = s.catHandler
	s.toolHandlers[pwdToolName] = s.pwdHandler
	s.toolHandlers[rmToolName] = s.rmHandler
	s.toolHandlers[mvToolName] = s.mvHandler
	s.toolHandlers[cpToolName] = s.cpHandler
	s.toolHandlers[mkdirToolName] = s.mkdirHandler
	s.toolHandlers[chmodToolName] = s.chmodHandler
	s.toolHandlers[chownToolName] = s.chownHandler

	// Process
	s.toolHandlers[psToolName] = s.psHandler
	s.toolHandlers[terminateToolName] = s.terminateHandler
	s.toolHandlers[executeToolName] = s.executeHandler
	s.toolHandlers[uploadToolName] = s.uploadHandler
	s.toolHandlers[downloadToolName] = s.downloadHandler

	// Network
	s.toolHandlers[ifconfigToolName] = s.ifconfigHandler
	s.toolHandlers[netstatToolName] = s.netstatHandler
	s.toolHandlers[pingSweepToolName] = s.pingSweepHandler
	s.toolHandlers[portScanToolName] = s.portScanHandler
	s.toolHandlers[arpScanToolName] = s.arpScanHandler

	// Recon
	s.toolHandlers[screenshotToolName] = s.screenshotHandler
	s.toolHandlers[envToolName] = s.envHandler
	s.toolHandlers[pingToolName] = s.pingHandler

	// Privilege
	s.toolHandlers[privsToolName] = s.privsHandler
	s.toolHandlers[impersonateToolName] = s.impersonateHandler
	s.toolHandlers[revToSelfToolName] = s.revToSelfHandler

	// Injection
	s.toolHandlers[injectShellcodeName] = s.injectShellcodeHandler
	s.toolHandlers[sideloadToolName] = s.sideloadHandler
	s.toolHandlers[executeAssemblyName] = s.executeAssemblyHandler

	// Registry
	s.toolHandlers[regReadToolName] = s.regReadHandler
	s.toolHandlers[regWriteToolName] = s.regWriteHandler
	s.toolHandlers[regCreateKeyToolName] = s.regCreateKeyHandler
	s.toolHandlers[regDeleteKeyToolName] = s.regDeleteKeyHandler
	s.toolHandlers[regListSubKeysToolName] = s.regListSubKeysHandler
	s.toolHandlers[regListValuesToolName] = s.regListValuesHandler

	// Port forwarding
	s.toolHandlers[portfwdToolName] = s.portfwdHandler
	s.toolHandlers[socksStartToolName] = s.socksStartHandler
	s.toolHandlers[socksStopToolName] = s.socksStopHandler

	// Services
	s.toolHandlers[servicesListToolName] = s.servicesListHandler
	s.toolHandlers[serviceStartToolName] = s.serviceStartHandler
	s.toolHandlers[serviceStopToolName] = s.serviceStopHandler
	s.toolHandlers[serviceRemoveToolName] = s.serviceRemoveHandler

	// Implant management
	s.toolHandlers[generateToolName] = s.generateHandler
	s.toolHandlers[migrateToolName] = s.migrateHandler
	s.toolHandlers[implantsListToolName] = s.implantsListHandler

	// Credentials
	s.toolHandlers[credListToolName] = s.credListHandler
	s.toolHandlers[credAddToolName] = s.credAddHandler
	s.toolHandlers[executeBOFToolName] = s.executeBOFHandler

	// Batch (self-reference — allows nested batches, though not recommended)
	// Intentionally omitted to prevent infinite recursion
}
