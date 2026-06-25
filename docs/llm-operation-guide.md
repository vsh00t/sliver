# Sliver C2 — LLM Autonomous Operation Guide

## Overview

This document defines the safety rails, prompt structure, and operational constraints
for operating Sliver C2 via MCP with a Large Language Model (LLM) as the operator.

The MCP server exposes **42 tools** that an LLM can invoke. This guide ensures
the LLM operates safely, predictably, and with appropriate human-in-the-loop
checkpoints for destructive actions.

---

## System Prompt

```
You are an authorized security operator using the Sliver C2 framework via MCP.
You have access to 42 tools for post-exploitation on AUTHORIZED targets only.

## Operational Rules

1. AUTHORIZATION: Only operate on sessions/beacons that are part of the
   current authorized engagement. Verify session identity before acting.

2. CHAIN OF COMMAND: Always start with reconnaissance before action:
   list_sessions → ps → ifconfig → env → netstat → screenshot
   Then proceed to targeted actions based on findings.

3. DESTRUCTIVE ACTION GATES: The following actions require explicit
   human confirmation before execution:
   - inject_shellcode (code execution in remote process)
   - sideload (DLL injection)
   - execute_assembly (.NET execution)
   - proc_terminate (kill process)
   - service_stop / service_remove
   - reg_delete_key
   - generate (compile new implant)
   - migrate (move to new process)

4. NON-DESTRUCTIVE RECON is always permitted:
   - list_sessions_and_beacons, ps, ifconfig, netstat, screenshot
   - env, ping, privs, fs_ls, fs_cat, fs_pwd, download
   - services_list, reg_read, reg_list_subkeys, reg_list_values

5. DATA HANDLING:
   - Never exfiltrate data outside the engagement scope
   - Screenshots and downloads are engagement evidence, not for distribution
   - Credentials found must be reported, not reused outside scope

6. REPORTING: After each action, provide:
   - What was executed
   - What was found
   - Recommended next step

## Engagement Context

Engagement ID: {{engagement_id}}
Authorization: {{authorized_targets}}
Operator: {{operator_name}}
Scope: {{scope_description}}
```

---

## Safety Rails Architecture

### Tier 1: Tool Annotations (built into MCP server)

Each tool has `readOnlyHint`, `destructiveHint`, `idempotentHint` annotations
already set in `server.go`. The LLM client can use these to make UI decisions
(confirmation dialogs, danger highlighting).

### Tier 2: Confirmation Middleware

Destructive tools (those with `destructiveHint=true`) trigger a confirmation
request back to the human operator before execution. This is implemented in
`middleware.go` as a pre-execution hook.

**Destructive tools requiring confirmation:**
- `inject_shellcode` — arbitrary code execution
- `proc_terminate` — kills a process
- `rm` — deletes files/directories
- `mv`, `cp` — modifies filesystem
- `mkdir`, `chmod`, `chown` — modifies filesystem
- `reg_delete_key` — deletes registry keys
- `reg_write`, `reg_create_key` — modifies registry
- `service_stop`, `service_remove` — modifies services
- `socks_stop` — terminates network tunnel
- `upload` — writes to target filesystem
- `migrate` — process migration
- `sideload` — DLL injection
- `execute` — command execution

### Tier 3: Rate Limiting

- Max 10 tool calls per minute for non-read operations
- Max 3 concurrent destructive operations
- Beacon task queue depth limited to 50 pending tasks

### Tier 4: Audit Log

All tool calls are logged with:
- Timestamp, tool name, session/beacon ID
- Arguments (sanitized — no base64 blobs in logs)
- Result status (success/error)
- Operator identity (LLM model + human approver)

---

## Typical LLM Operation Flows

### Flow 1: Initial Reconnaissance

```
1. list_sessions_and_beacons → identify active implants
2. For each session:
   a. ps → enumerate processes (look for AV/EDR, interesting services)
   b. ifconfig → network interfaces and IPs
   c. netstat → active connections (look for domain controllers, DBs)
   d. env → environment variables (domain info, paths)
   e. privs → current privilege level
   f. screenshot → visual context of user session
3. Report findings and recommend next steps
```

### Flow 2: Lateral Movement Preparation

```
1. ps → identify processes running as domain accounts
2. download → grab config files, SSH keys, browser creds
3. reg_read → check stored credentials, auto-logon keys
4. services_list → identify services with weak permissions
5. netstat → identify internal services (DBs, shares, admin panels)
6. Report lateral movement opportunities
```

### Flow 3: Privilege Escalation Assessment

```
1. privs → check for SeImpersonate, SeDebug, SeAssignPrimaryToken
2. ps → look for processes running as SYSTEM/service accounts
3. env → check for writable paths in PATH variable
4. reg_read → check AlwaysInstallElevated, UAC settings
5. services_list → find services with unquoted paths or weak ACLs
6. Report privesc opportunities and recommend technique
```

### Flow 4: Post-Exploitation Evidence Collection

```
1. screenshot → capture user activity
2. download → collect documents, configs, credentials
3. reg_read → extract saved credentials
4. ps → document running software for license compliance
5. netstat → document network topology
6. Package findings for engagement report
```

---

## MCP Resource Templates

The MCP server exposes resource templates that the LLM can read for context:

- `sliver://sessions/{session_id}` — Full session details
- `sliver://beacons/{beacon_id}` — Beacon status and task queue
- `sliver://loot` — Collected evidence catalog
- `sliver://config` — Server configuration and listeners

---

## Error Handling

The LLM should handle these common error patterns:

| Error | Meaning | Action |
|---|---|---|
| `session_id required` | No session specified | Call list_sessions first |
| `rpc client not configured` | Not connected to server | Report connection issue |
| `beacon task pending` | Async operation queued | Use wait=true or poll later |
| `Response.Err: "access denied"` | Insufficient privileges | Try impersonate or report |
| `task timeout` | Operation exceeded timeout | Retry with longer timeout |

---

## Autonomous Operation Constraints

For fully autonomous operation (no human in the loop):

1. **READ-ONLY MODE**: LLM can only use tools with `readOnlyHint=true`
2. **RECON REPORTING**: LLM must summarize findings after every 5 read operations
3. **DESTRUCTIVE ACTIONS**: Always deferred to human operator
4. **TIMEOUT**: Autonomous sessions expire after 30 minutes of inactivity
5. **SCOPE ENFORCEMENT**: LLM must verify target is in authorized scope before any action

For semi-autonomous operation (human approves destructive actions):

1. LLM chains recon operations freely
2. Proposes destructive actions with justification
3. Human approves/denies
4. LLM executes and reports results
5. Loop continues until engagement objectives met
