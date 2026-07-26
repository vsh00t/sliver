# Sliver C2 — Evasion Mechanisms Deep Analysis

## Summary
This document catalogs every evasion mechanism found in the Sliver repository
(`/home/jorge/sliver-analysis`, main branch, depth=1 clone).

---

## 1. In-Memory Detection Evasion

### 1.1 AMSI Bypass
- **File:** `implant/sliver/taskrunner/task_windows.go`, lines 199–238
- **Technique:** Runtime patching of `amsi.dll` exports.
  - Loads `amsi.dll` via `windows.NewLazyDLL("amsi.dll")`
  - Resolves `AmsiScanBuffer`, `AmsiInitialize`, `AmsiScanString` proc addresses
  - Overwrites the first byte of each function with `0xC3` (x86/x64 `RET` instruction)
  - Uses `VirtualProtect` → `PAGE_READWRITE` to make the `.text` page writable, then restores original protections
  - Skips already-patched functions (idempotent check)
- **Trigger:** Only invoked when `--amsi-bypass` flag is set on `execute-assembly` or `load` commands (in-process .NET only)
  - **Client flag:** `client/command/exec/commands.go:88` (`--amsi-bypass / -M`)
  - **Server proto:** `server/rpc/aitools/package_tools.go:52` (`AmsiBypass bool`)

### 1.2 ETW Bypass
- **File:** `implant/sliver/taskrunner/task_windows.go`, lines 240–269
- **Technique:** Patches `EtwEventWrite` in `ntdll.dll`.
  - Resolves `ntdll.EtwEventWrite` via `windows.NewLazyDLL("ntdll.dll")`
  - Overwrites first byte with `0xC3` (`RET`)
  - Same `VirtualProtect` toggle pattern as AMSI bypass
  - Idempotent (checks if already patched)
- **Trigger:** Only when `--etw-bypass` flag is set (same commands as AMSI)
  - **Client flag:** `client/command/exec/commands.go:89` (`--etw-bypass`)

### 1.3 EDR Hook Removal (RefreshPE / "Unhooking")
- **File:** `implant/sliver/evasion/evasion_windows.go`, lines 33–87
- **Technique:** Overwrites the `.text` section of loaded DLLs with the on-disk copy.
  - `RefreshPE(name)` opens the DLL file from disk using `debug/pe.Open()`
  - Reads the `.text` section bytes
  - `VirtualProtect` → `PAGE_EXECUTE_READWRITE` on the loaded DLL's `.text` virtual address range
  - Copies clean bytes over the in-memory copy (byte-by-byte loop)
  - Restores original page protections
  - Targets `ntdll.dll` and `kernel32.dll` specifically
- **Invocation:** `implant/sliver/taskrunner/task_windows.go`, `refresh()` function (lines 413–436)
  - Called before every `RemoteTask`, `SpawnDll`, and `LocalTask` (amd64 only)
  - Gated behind `{{if .Config.Evasion}}` compile-time template flag
  - Explicitly **skipped on Windows 8.1** (build 9600) to avoid crashes

### 1.4 HideWindow
- **File:** `implant/sliver/taskrunner/task_windows.go`, line 447
- All spawned processes set `SysProcAttr.HideWindow = true`
- Also used in `shell/shell_windows.go` lines 59, 79

---

## 2. Process Injection Techniques

### 2.1 Classic Remote Thread Injection
- **File:** `implant/sliver/taskrunner/task_windows.go`, `injectTask()` lines 68–134
- **Flow:**
  1. `VirtualAllocEx` — allocate memory in target process (RWX or RW)
  2. `WriteProcessMemory` — write shellcode to allocated region
  3. If non-RWX: `VirtualProtectEx` → `PAGE_EXECUTE_READ`
  4. `CreateRemoteThread` — execute shellcode at written address
- **Used by:** `RemoteTask()` (line 137), `ExecuteAssembly()` (line 289), `SpawnDll()` (line 337)

### 2.2 Local Thread Injection
- **File:** `implant/sliver/taskrunner/task_windows.go`, `LocalTask()` lines 162–197
- Allocates RWX/RW memory in current process via `VirtualAlloc`
- Copies shellcode byte-by-byte via unsafe pointer writes
- If RW: `VirtualProtect` → `PAGE_EXECUTE_READ`
- Creates local thread via `CreateThread`

### 2.3 RWX vs RW Page Option
- Both `injectTask` and `LocalTask` accept `rwxPages bool` parameter
- When `false`: allocates RW, writes payload, then flips to RX via `VirtualProtect(Ex)`
- This avoids the RWX page detection pattern

### 2.4 Process Hollowing Pattern (ExecuteAssembly / SpawnDll)
- **File:** `task_windows.go`, `startProcess()` lines 438–468
- Creates process with `CREATE_SUSPENDED` flag
- Injects shellcode via remote thread
- Waits for thread completion
- Kills the sacrificial process

### 2.5 Syscall Wrappers (NOT Direct Syscalls)
- **File:** `implant/sliver/syscalls/syscalls_windows.go`
- Uses Go's `//sys` directive → generates standard `syscall.Syscall` stubs
- **Declared but appears unused in main code paths:**
  - `NtCreateThreadEx` (line 51) — alternative to `CreateRemoteThread`, stealthier
  - `QueueUserAPC` (line 16) — APC injection
- These are **declared** but I did not find them called in the main injection paths — they may be available for future use or called from generated template code

### 2.6 PPID Spoofing
- **File:** `implant/sliver/spoof/spoof_windows.go`
- `SpoofParent(ppid, cmd)` opens the parent process with `PROCESS_CREATE_PROCESS|PROCESS_DUP_HANDLE|PROCESS_QUERY_INFORMATION`
- Sets `cmd.SysProcAttr.ParentProcess` to the parent handle
- Used in `startProcess()` (task_windows.go:449) — fails open (continues if spoofing fails)

### 2.7 Token Impersonation
- **File:** `implant/sliver/priv/priv_windows.go`
- `impersonateProcess()` / `impersonateUser()` — steals and applies process tokens
- `syscalls_windows.go`: `ImpersonateLoggedOnUser` (line 24), `LogonUserW` (line 25)
- Token applied to spawned processes via `SysProcAttr.Token`

---

## 3. Network C2 Evasion

### 3.1 Transport Protocols
| Protocol | Code Location | Notes |
|---|---|---|
| **mTLS** | `implant/sliver/transports/mtls/mtls.go` | Per-binary mutual TLS certs, yamux multiplexing |
| **WireGuard** | `implant/sliver/transports/wireguard/` | Full WireGuard tunnel, uses userspace netstack |
| **HTTP/S** | `implant/sliver/transports/httpclient/` | Configurable profiles, WinINet driver on Windows |
| **DNS** | `implant/sliver/transports/dnsclient/` | Base32-encoded DNS tunneling |

### 3.2 Per-Binary TLS Certificates
- **File:** `implant/sliver/transports/mtls/mtls.go`, lines 57–61
- `caCertPEM`, `keyPEM`, `certPEM` are template-injected at compile time (`{{.Build.MtlsCACert}}` etc.)
- Each implant binary gets unique keys

### 3.3 HTTP C2 Profile System
- **Config:** `server/configs/http-c2.go`
- **Implant rendering:** `implant/sliver/transports/httpclient/httpclient.go`
- **Features:**
  - **Custom User-Agent** — Generated from Chrome version + OS version template (`GenerateUserAgent`)
  - **Nonce URL arguments** — Random query params or URL path segments to vary request appearance (lines 200–231)
  - **Custom HTTP headers** with probability-based inclusion (lines 266–293)
  - **Extra URL parameters** with probability (lines 295–319)
  - **Configurable path segments** — Random subdirectory depth/length
  - **Cookie-based session management** — Configurable cookie names
  - **Server response headers** — e.g., `Cache-Control: no-store, no-cache, must-revalidate`
  - **Nonce modes:** `Url` (inject into path) or `UrlParam` (inject as query param)
  - **Host header spoofing** — `--host-header` option for domain fronting

### 3.4 WinINet HTTP Driver (Windows)
- **File:** `implant/sliver/transports/httpclient/drivers/win/wininet/wininet_windows.go`
- Uses native Windows `WinINet` API (`InternetOpenW`, `HttpOpenRequestW`, `HttpSendRequestW`, etc.)
- Routes HTTP traffic through the system's WinINet stack — appears as legitimate browser traffic
- Supports proxy authentication via `InternetErrorDlg`
- Cookie persistence via WinINet's built-in cookie jar

### 3.5 DNS Tunneling
- **File:** `implant/sliver/transports/dnsclient/dnsclient.go`
- Base32 encoding of data into DNS subdomains
- ~39 bytes per subdomain, max ~60 bytes data per query
- Uses TXT records for server responses (configurable)
- Configurable resolvers, retry logic

### 3.6 WASM Traffic Encoders
- **Files:**
  - `implant/sliver/encoders/traffic/traffic-encoder.go` (implant side)
  - `server/encoders/encoders.go` (server side)
  - `server/assets/traffic-encoders/` (WASM encoder binaries)
- Custom WASM modules encode/decode C2 traffic
- Uses `wazero` (pure-Go WASM runtime)
- Encoder ID derived from SHA256 hash of WASM binary
- Allows pluggable traffic obfuscation — operators can write custom encoders in Rust/C and compile to WASM

### 3.7 DNS Canaries
- **File:** `server/generate/canaries.go`
- Each binary gets unique DNS canary domains (6 random chars + parent domain)
- Stored in database with implant build ID
- **Deliberately NOT obfuscated** during garble compilation (to preserve the canary)
- If the binary is analyzed in a sandbox that resolves domains, the canary fires

---

## 4. Binary Compilation & Obfuscation

### 4.1 Garble Integration
- **File:** `server/gogo/go.go`, lines 141–176 (`GarbleCmd`)
- **Flags:** `-seed=random -literals -tiny`
  - `-seed=random` — Random symbol obfuscation seed per build
  - `-literals` — Obfuscates string literals at compile time
  - `-tiny` — Strips debug info, file paths, and symbol tables
- Controlled by `GoConfig.Obfuscation bool` (line 58)
- Can be disabled with `--skip-symbols` / `-l` flag on generate commands

### 4.2 Build Flags
- **File:** `server/gogo/go.go`, `GoBuild()` lines 205–237
- `-trimpath` — Always applied; removes absolute filesystem paths from binary
- `-mod=vendor` — Always applied; uses vendored dependencies
- Configurable `-ldflags`, `-gcflags`, `-asmflags`
- Zig static linking for Linux (`applyZigStaticLinking`, binaries.go:198)

### 4.3 Compile-Time Code Stripping
- Template directives `{{if .Config.Debug}}` control debug logging inclusion
- When `Debug=false`, all `log.Printf` / `log.Println` calls are stripped from the binary
- Error messages are also stripped: `"{{if .Config.Debug}}Too much data to encode{{end}}"`

### 4.4 String Obfuscation Note
- **File:** `implant/sliver/taskrunner/task_windows.go`, line 49
- `ntdllPath` and `kernel32dllPath` are declared as `var` (not `const`) specifically so garble's `-literals` flag can obfuscate them at compile time

---

## 5. Sleep / Jitter / Beaconing

### 5.1 Beacon Interval & Jitter
- **File:** `implant/sliver/transports/transports.go`, lines 177–210
- `BeaconInterval` and `BeaconJitter` are compile-time template values
- **File:** `implant/sliver/transports/beacon.go`, `Duration()` lines 109–122
  - `duration = Interval + random(0, Jitter)`
  - Uses `util.Int63n()` (cryptographically-secure random)
- Runtime-adjustable via server commands: `SetInterval()`, `SetJitter()`

### 5.2 Beacon Sleep Loop
- **File:** `implant/sliver/runner/runner.go`, lines 271–309
- Main beacon loop: sleep for `beacon.Duration()`, check in, repeat
- Uses `time.After(duration)` for sleep — **no sleep mask or memory encryption during sleep**
- Supports short-circuiting when interval is dynamically changed

### 5.3 Reconnect Interval
- **File:** `transports.go`, lines 160–175
- Configurable reconnect interval (default 60s)
- Exponential backoff via max error count

### 5.4 HTTP Long Poll Jitter
- **File:** `server/c2/http.go`, line 75
- `DefaultLongPollJitter = time.Second`
- Server-side jitter on HTTP long-poll response timing

---

## 6. Additional Evasion Features

### 6.1 SGN Shellcode Encoder
- **File:** `server/encoders/shellcode/sgn/sgn.go`
- Multi-iteration Shikata Ga Nai encoding
- Bad character avoidance
- ASCII printable mode option
- Uses `github.com/moloch--/sgn/pkg`

### 6.2 sRDI (Shellcode Reflective DLL Injection)
- **File:** `server/generate/srdi.go`, lines 764–823
- Converts DLLs to position-independent shellcode
- Clears PE header (`clearHeader = true`)
- Function hash resolution (default `0x10` for `DllMain`)
- Supports x86 and x64 bootstrap shellcode

### 6.3 C2 Failover Strategies
- **File:** `implant/sliver/transports/transports.go`, lines 34–37
- `r` — Random C2 selection
- `rd` — Random within same protocol domain
- `s` — Sequential C2 iteration

### 6.4 Multiple C2 Formats
- Implant can be compiled as: Executable, Shared Library (.dll/.so/.dylib), Shellcode (sRDI)
- Template-based code inclusion — only needed transport code is compiled in
- `{{if .Config.IncludeHTTP}}`, `{{if .Config.IncludeMTLS}}`, etc.

---

## 7. GAPS — Missing or Weak Evasion (vs. Cobalt Strike / Mythic / Brute Ratel)

### 7.1 CRITICAL GAPS

| Gap | Impact | Modern C2s That Have It |
|---|---|---|
| **No Sleep Mask** | Implant memory is fully visible to scanners during sleep; beacon threads are detectable | Cobalt Strike (sleep_mask), Brute Ratel, Havoc |
| **No Direct/Indirect Syscalls** | All syscalls go through `ntdll.dll` via Go's `syscall.Syscall` — trivially hooked by EDR | Brute Ratel, Havoc, Mythic (Nighthawk) |
| **No Thread Stack Spoofing** | Beacon threads have recognizable call stacks pointing to unbacked memory | Cobalt Strike (via AGPs), Brute Ratel |
| **No Module Stomping / DLL Hollowing** | Injected code lives in unbacked private memory (VirtualAllocEx) — easily flagged | Cobalt Strike, Brute Ratel |
| **No Callback-Based Injection** | Uses `CreateRemoteThread` only — one of the most heavily monitored APIs | Mythic (Apollo), Brute Ratel |

### 7.2 SIGNIFICANT GAPS

| Gap | Details |
|---|---|
| **NtCreateThreadEx declared but unused** | `syscalls_windows.go:51` declares the stealthier thread creation API but the main injection code uses `CreateRemoteThread` instead |
| **QueueUserAPC declared but unused** | `syscalls_windows.go:16` declares APC injection API but it's not called in any injection path |
| **No ETW-TI bypass** | Only patches `EtwEventWrite` — does not address ETW Threat Intelligence providers |
| **No anti-sandbox/anti-debug** | No checks for analysis environments, debugger presence, VM artifacts |
| **No self-deletion** | Binary persists on disk after execution with no cleanup |
| **No memory encryption during sleep** | Implant config, session keys, and code remain in plaintext in memory |
| **No hardware breakpoint evasion** | EDRs using hardware breakpoints (DR registers) are not mitigated |
| **No syscall SSN/SSDT resolution** | No Halo's Gate / Hell's Gate / Tartarus' Gate dynamic SSN resolution |

### 7.3 MODERATE GAPS

| Gap | Details |
|---|---|
| **Limited injection methods** | Only `CreateRemoteThread` and local `CreateThread`; no process hollowing (full), no fiber injection, no early bird APC, no thread hijacking |
| **RefreshPE is crude** | Reads `.text` from disk via `pe.Open()` — leaves filesystem access traces; modern unhookers map a fresh copy from `KnownDlls` or `\Device\HarddiskVolume` |
| **No domain fronting automation** | Host header is configurable but no automatic CDN integration |
| **No HTTP profile marketplace** | HTTP profiles are custom but there's no rich library of malleable C2 profiles like Cobalt Strike |
| **No token privilege elevation via COM** | Only basic `LogonUser`/`ImpersonateLoggedOnUser` |
| **No process doppelgänging/herpaderping** | Not implemented |
| **No UAC bypass techniques** | Not built-in |
| **No kernel driver support** | Pure userspace only |
| **No clipboard/logger bypass** | No anti-keylogging or anti-screen-capture for sensitive ops |

### 7.4 AREAS WHERE SLIVER IS COMPETITIVE

- **Multi-platform** — Linux, macOS, Windows, cross-compilation
- **WireGuard transport** — Legitimate-looking VPN tunnel (unique among C2s)
- **WASM traffic encoders** — Extensible, pluggable traffic obfuscation (innovative)
- **Garble integration** — Proper Go binary obfuscation with literal encryption
- **DNS canaries** — Built-in blue team detection mechanism
- **Template-based compilation** — Minimal binary footprint, only needed code compiled
- **Per-binary crypto** — Unique key pairs per implant build
