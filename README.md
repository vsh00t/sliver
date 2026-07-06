# Sliver C2 — IronCybersec Fork

Fork de [BishopFox/sliver](https://github.com/BishopFox/sliver) con dos extensiones principales: **servidor MCP para operación autónoma via LLM** y **técnicas de evasión a nivel de implante**.

Rama activa: `feature/mcp-evasion-llm`
Upstream: BishopFox/sliver master (v1.26.2)

---

## Qué está hecho

### 1. MCP Server — Operación via LLM (~5,700 LOC)

Implementación completa de servidor [MCP](https://modelcontextprotocol.io) integrada en el cliente de Sliver. Permite que un LLM (Claude, GPT, etc.) opere el C2 a través de 42 herramientas estructuradas.

**42 herramientas en 8 categorías:**

- **Sesiones**: `list_sessions_and_beacons`
- **Reconocimiento**: `ps`, `ifconfig`, `env`, `netstat`, `ping`, `screenshot`, `privs`
- **Sistema de archivos**: `fs_ls`, `fs_cat`, `fs_pwd`, `fs_cd`, `fs_cp`, `fs_mv`, `fs_rm`, `fs_mkdir`, `fs_chmod`, `fs_chown`, `download`, `upload`
- **Procesos**: `proc_terminate`, `execute`, `migrate`, `inject_shellcode`, `sideload`
- **Red**: `portfwd`, `socks_start`, `socks_stop`
- **Registro Windows**: `reg_read`, `reg_write`, `reg_create_key`, `reg_delete_key`, `reg_list_subkeys`, `reg_list_values`
- **Servicios**: `services_list`, `service_start`, `service_stop`, `service_remove`
- **Privilegios**: `impersonate`, `rev_to_self`
- **Implantes**: `generate`

**3 recursos MCP** (contexto para el LLM):
- `sliver://sessions/{session_id}` — detalles de sesión
- `sliver://beacons/{beacon_id}` — estado de beacon y cola de tareas
- `sliver://loot` — catálogo de evidencia

**Middleware de seguridad (4 capas):**
- **Tier 1**: Anotaciones MCP (`readOnlyHint`, `destructiveHint`, `idempotentHint`) en cada tool
- **Tier 2**: Middleware de confirmación — tools destructivas (`inject_shellcode`, `proc_terminate`, `rm`, `migrate`, `sideload`, etc.) requieren aprobación humana explícita antes de ejecutar
- **Tier 3**: Rate limiting — máx 10 calls/min no-read, máx 3 destructivas concurrentes
- **Tier 4**: Audit log — toda invocación queda registrada con timestamp, tool, session/beacon ID, argumentos sanitizados y resultado

**Integración en CLI** (`mcp start`, `mcp stop`, `mcp status`, `mcp console`)
- 2 transportes: **stdio** (local) y **HTTP/SSE** (remoto)
- Auth por bearer token (`mcp.yaml`)
- Guía de operación LLM en `docs/llm-operation-guide.md`

### 2. Evasión a Nivel de Implante (~1,600 LOC)

4 técnicas nuevas, todas **gated behind `{{if .Config.Evasion}}`** (compile-time, se activan al generar el implante con flag de evasión):

**SleepMask** (`evasion/sleep_mask_windows.go`)
- Encripta la sección `.text` del implante durante el sleep cycle del beacon
- Integrado en `runner.go` → `beaconMainLoop`: durante cada intervalo de check-in, el goroutine de sleep ejecuta el encryption/decryption
- Recovery con `defer recover()` para evitar deadlock si SleepMask panica

**Stack Spoofing** (`evasion/stack_spoof_windows.go`)
- Envuelve `RemoteTask`, `LocalTask`, e `InProcExecuteAssembly` con call stacks falsificadas
- Evita análisis de call-stack por EDR que inspecciona el origen del thread

**Indirect Syscalls** (`evasion/indirect_syscalls_windows.go`)
- Resolución de SSN (System Service Numbers) sin tocar `ntdll.dll`
- Pre-cachea SSNs para funciones hot-path (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtProtectVirtualMemory`) durante `refresh()`

**Dynamic AMSI/ETW Patching** (`evasion/dynamic_patch_windows.go`)
- Patcheo dinámico basado en hash de API names (no hardcoded addresses)
- Incluye ETW Threat Intelligence provider
- Fallback automático al patch estático legacy (`0xC3 RET`) si el dinámico falla
- Refactor de `patchAmsi()`/`patchEtw()` originales: intenta dinámico primero, legacy como fallback

### 3. Documentación

- `docs/llm-operation-guide.md` (202 líneas) — system prompt para LLM, flujos operacionales típicos (recon, lateral movement, privesc, evidence collection), constraints autónomos
- `EVASION_ANALYSIS.md` (301 líneas) — análisis profundo de todos los mecanismos de evasión en el repo (preexistentes + nuevos)

### 4. Tests

- 7 unit tests para middleware (`middleware_test.go`): confirmación destructiva, rate limiting, audit logging
- Auth tests (`auth_test.go`): validación de bearer tokens

---

## Qué NO está hecho (honestamente)

- **Sin CI/CD**: los GitHub Actions workflows fueron eliminados (el token de push no tiene scope `workflow`). No hay builds automatizados ni tests en CI.
- **Evasión es Windows/amd64 únicamente**: los 4 mecanismos son `_windows.go`. Linux/macOS no tienen evasión extendida.
- **Indirect syscalls no wired en el path de inyección**: los SSNs se resuelven y cachean, pero las syscall reales en `RemoteTask`/`LocalTask` siguen usando la API normal. El caching está listo pero la sustitución del call site no está conectada.
- **SleepMask es goroutine-based**: encripta memoria en un goroutine durante sleep, pero no hace page-protection flipping (RWX→RW) que es lo que evadiría scanneadores de memoria en reposo. Es una primera versión funcional.
- **Sin tests de integración**: solo el middleware tiene unit tests. No hay tests E2E del MCP server ni de las técnicas de evasión.
- **Sin verificación de compilación en este entorno**: el código fue escrito y revisado, pero no se ha hecho `make` en este entorno para confirmar que compila limpio.
- **Sin server-side compilation de implantes con evasión**: el flag `Evasion` existe en el template, pero generar un implante con `--evasion` desde el server no está probado end-to-end.

---

## Diferencia vs Upstream

```
25 files changed, 5,881 insertions(+), 453 deletions(-)
```

- `client/mcp/` (15 archivos nuevos) — servidor MCP completo
- `client/command/mcp/` (5 archivos nuevos) — integración CLI
- `implant/sliver/evasion/` (4 archivos nuevos + 1 existente modificado) — técnicas de evasión
- `implant/sliver/runner/runner.go` — wiring de SleepMask en beacon loop
- `implant/sliver/taskrunner/task_windows.go` — wiring de stack spoofing, dynamic AMSI/ETW, indirect syscall pre-resolution
- `.github/workflows/*` — eliminados (4 archivos)

---

## Instalación

```bash
# Descargar binarios pre-compilados (patrón estándar de Sliver)
curl -fsSL https://raw.githubusercontent.com/vsh00t/sliver/main/install.sh | bash
```

O compilar desde source (requiere Go 1.26+, `make`):

```bash
git clone https://github.com/vsh00t/sliver.git
cd sliver
git checkout feature/mcp-evasion-llm
make
```

---

## Licencia

GPLv3 — heredada de [BishopFox/sliver](https://github.com/BishopFox/sliver). Ver [LICENSE](LICENSE).
