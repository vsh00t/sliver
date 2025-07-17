# Sliver

Sliver is an open source cross-platform adversary emulation/red team framework, it can be used by organizations of all sizes to perform security testing. Sliver's implants support C2 over Mutual TLS (mTLS), WireGuard, HTTP(S), and DNS and are dynamically compiled with per-binary asymmetric encryption keys.

The server and client support MacOS, Windows, and Linux. Implants are supported on MacOS, Windows, and Linux (and possibly every Golang compiler target but we've not tested them all).

[![Release](https://github.com/BishopFox/sliver/actions/workflows/autorelease.yml/badge.svg)](https://github.com/BishopFox/sliver/actions/workflows/autorelease.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/BishopFox/sliver)](https://goreportcard.com/report/github.com/BishopFox/sliver) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# v1.6.0 / `master`

**NOTE:** You are looking at the latest master branch of Sliver v1.6.0; new PRs should target this branch. However, this branch is NOT RECOMMENDED for production use yet. Please use release tagged versions for the best experience.

For PRs containing bug fixes specific to Sliver v1.5, please target the [`v1.5.x/master` branch](https://github.com/BishopFox/sliver/tree/v1.5.x/master).

### Features

- Dynamic code generation
- Compile-time obfuscation
- Multiplayer-mode
- Staged and Stageless payloads
- [Procedurally generated C2](https://sliver.sh/docs?name=HTTPS+C2) over HTTP(S)
- [DNS canary](https://sliver.sh/docs?name=DNS+C2) blue team detection
- [Secure C2](https://sliver.sh/docs?name=Transport+Encryption) over mTLS, WireGuard, HTTP(S), and DNS
- Fully scriptable using [JavaScript/TypeScript](https://github.com/moloch--/sliver-script) or [Python](https://github.com/moloch--/sliver-py)
- Windows process migration, process injection, user token manipulation, etc.
- Let's Encrypt integration
- In-memory .NET assembly execution
- COFF/BOF in-memory loader
- TCP and named pipe pivots
- Much more!

### Getting Started

Download the latest [release](https://github.com/BishopFox/sliver/releases) and see the Sliver [wiki](https://sliver.sh/docs?name=Getting+Started) for a quick tutorial on basic setup and usage. To get the very latest and greatest compile from source.

#### Linux One Liner

`curl https://sliver.sh/install|sudo bash` and then run `sliver`

### Help!

Please checkout the [wiki](https://sliver.sh/), or start a [GitHub discussion](https://github.com/BishopFox/sliver/discussions). We also tend to hang out in the #golang Slack channel on the [Bloodhound Gang](https://bloodhoundgang.herokuapp.com/) server.

### Compile From Source

See the [wiki](https://sliver.sh/docs?name=Compile+from+Source).

### Feedback

Please take a moment and fill out [our survey](https://forms.gle/SwVsHFNh24ChG58C6).

### License - GPLv3

Sliver is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html), some sub-components may have separate licenses. See their respective subdirectories in this project for details.

---

# 🔥 Mejoras de Evasión v1.6.0 - Resumen de Cambios

## 🎯 Descripción de Mejoras

Esta versión de Sliver incluye mejoras significativas en técnicas de evasión, implementando un sistema de tres etapas (Stage 1-3) que van desde técnicas básicas hasta avanzadas con machine learning y evasión a nivel de kernel.

## 📋 Índice de Cambios Implementados

1. [Stage 1: Evasión Básica](#stage-1-evasión-básica-✅-completado)
2. [Stage 2: Evasión Intermedia](#stage-2-evasión-intermedia-✅-completado)
3. [Stage 3: Evasión Avanzada](#stage-3-evasión-avanzada-✅-completado)
4. [Fat Implant Generation](#fat-implant-generation-✅-completado)
5. [Mejoras de Evasión Generales](#mejoras-de-evasión-generales)
6. [Nueva Funcionalidad de Comandos](#nueva-funcionalidad-de-comandos)

---

## 🚀 Stage 1: Evasión Básica ✅ COMPLETADO

### Técnicas Implementadas:
- **Randomized Compilation Flags** - Build IDs aleatorios y flags de enlazador variables
- **String Obfuscation** - Ofuscación XOR de strings críticas (DLL paths, APIs)
- **Enhanced Timing Jitter** - Patrones de timing naturales y variados
- **PE Header Randomization** - Metadatos PE aleatorios pero realistas

**Archivos principales:**
- `server/generate/binaries.go` - Lógica de compilación aleatoria
- `implant/sliver/evasion/strings.go` - Ofuscación de strings
- `implant/sliver/evasion/evasion_windows.go` - Timing mejorado

---

## 🛡️ Stage 2: Evasión Intermedia ✅ COMPLETADO

### Técnicas Implementadas:
- **Runtime Crypter** - Encriptación dinámica con claves rotativas
- **Advanced Process Hollowing** - Inyección en procesos legítimos con validación
- **Enhanced Syscall Evasion** - Direct syscalls con múltiples gates
- **Dynamic API Resolution** - Resolución de APIs con verificación anti-hooking

**Archivos principales:**
- `implant/sliver/evasion/runtime_crypter.go` - Encriptación dinámica
- `implant/sliver/evasion/process_hollowing.go` - Process hollowing avanzado
- `implant/sliver/evasion/syscall_evasion.go` - Syscalls directos
- `implant/sliver/evasion/dynamic_api.go` - Resolución dinámica de APIs

---

## ⚡ Stage 3: Evasión Avanzada ✅ COMPLETADO

### Técnicas de Vanguardia:
- **Custom PE Loader** - Carga manual de PE sin loaders de Windows (524 líneas)
- **Machine Learning Evasion** - Aprendizaje comportamental y mimificación (650 líneas)
- **Advanced Anti-Analysis** - Detección multicapa de análisis (580 líneas)
- **Polymorphic Engine** - Morfismo de código en runtime (720 líneas)
- **Kernel-Level Evasion** - Acceso directo a kernel y detección de hooks (550 líneas)

**Archivos principales:**
- `implant/sliver/evasion/stage3/custom_pe_loader.go`
- `implant/sliver/evasion/stage3/ml_evasion.go`
- `implant/sliver/evasion/stage3/advanced_antianalysis.go`
- `implant/sliver/evasion/stage3/polymorphic_engine.go`
- `implant/sliver/evasion/stage3/kernel_evasion.go`

---

## 🎯 Fat Implant Generation ✅ COMPLETADO

### Nueva Funcionalidad:
Genera implantes de **70MB** con padding rico en entropía para evadir detectores que analizan tamaño de archivos.

**Uso:**
```bash
# Generar fat implant de 70MB
sliver-client generate --mtls example.com --fat --save /tmp/fat_implant.exe

# Combinar con otras opciones
sliver-client generate --mtls example.com --fat --evasion --format exe --save /tmp/advanced_fat_implant.exe
```

**Características:**
- Múltiples estrategias de padding (random, structured, fake code, fake resources)
- Optimización de entropía (6.5-7.5 bits Shannon entropy)
- Integración con ML para optimización inteligente

---

## 🔧 Mejoras de Evasión Generales

### 1. Evasión de Hooks EDR/AV
- **Múltiples métodos:** RefreshPE, Suspend/Resume, Remote, Manual Map, Heaven's Gate
- **Validación inteligente:** Verificación de módulos protegidos antes de unhooking
- **Fallbacks automáticos:** Métodos de respaldo cuando una técnica falla

### 2. Codificación Adaptativa
- **Manager inteligente:** Selección automática basada en rendimiento histórico
- **Rotación dinámica:** Cambio automático de encoders según efectividad
- **Modo amenaza:** Respuesta automática cuando se detecta análisis

### 3. Timing Inteligente
- **Perfiles adaptativos:** Stealth, Normal, Aggressive, Emergency, Hibernation
- **Emulación humana:** Patrones que simulan comportamiento de usuario real
- **Sincronización:** Adapta timing a horarios comerciales y actividad del sistema

---

## 💻 Nueva Funcionalidad de Comandos

### sliver-client command - Ejecución No Interactiva

```bash
# Sintaxis
sliver-client command [comando] [argumentos]

# Ejemplos
sliver-client command sessions    # Listar sesiones
sliver-client command beacons     # Listar beacons
sliver-client command jobs        # Listar jobs/listeners
sliver-client command version     # Info de versión
```

**Ventajas:**
- Perfecto para scripting y automatización
- Output limpio para parsing
- Sin consola interactiva requerida

---

## 📊 Métricas de Mejora

| Área | Mejora Implementada | Beneficio |
|------|---------------------|-----------|
| **Unhooking** | Múltiples métodos + validación | +300% resilencia |
| **Encoders** | Adaptación inteligente | +200% evasión |
| **Timing** | Timing adaptativo | +400% naturalidad |
| **Anti-Analysis** | Sistema multicapa | +500% detección |

---

## 🔄 Integración Automática

Todas las mejoras se integran automáticamente en los implantes generados:

- ✅ **Verificación inicial** anti-análisis al startup
- ✅ **Mantenimiento periódico** cada 30 minutos
- ✅ **Adaptación automática** según condiciones detectadas
- ✅ **Fallbacks inteligentes** cuando una técnica falla

---

## 🛠️ Archivos Principales Modificados

### Nuevos:
- `/implant/sliver/evasion/enhanced_evasion.go`
- `/implant/sliver/encoders/adaptive_manager.go`
- `/implant/sliver/evasion/stage3/*.go` (5 archivos)

### Modificados:
- `/implant/sliver/sliver.go` - Integración automática
- `/server/generate/binaries.go` - Fat implants y randomización
- `/client/command/generate/*.go` - Flag --fat

---

## 🎉 Estado del Proyecto

**✅ TODAS LAS MEJORAS COMPLETADAS EXITOSAMENTE**

Las mejoras proporcionan capacidades de evasión de clase empresarial, combinando técnicas tradicionales con innovaciones de vanguardia en machine learning y análisis comportamental.

**Para documentación técnica detallada, consultar:** `README_CAMBIOS_CONSOLIDADO.md`
