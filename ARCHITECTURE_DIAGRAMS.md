# Aqiron Security Architecture Diagrams

These diagrams describe the current repository implementation. They do not represent a hosted cloud platform or future integrations. The extension currently gates workspace operations to Flutter workspaces.

## System architecture

```text
┌──────────────────────────────────────────────────────────────────────┐
│ VS Code extension host: src/                                         │
│                                                                      │
│ extension activation, commands, diagnostics, status bar              │
│ React webview, settings, AI/RAG workspace services                   │
│ WorkspaceScanner and ScanController                                  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
                                │ CoreClient / CoreProcessManager
                                │ newline-delimited JSON over stdio
                                v
┌──────────────────────────────────────────────────────────────────────┐
│ Private core runtime: packages/core/src/runtime/                     │
│                                                                      │
│ protocol dispatch and cancellation                                   │
│ filesystem, process, network, and credential adapters                │
└───────────────────────────────┬──────────────────────────────────────┘
                                v
┌──────────────────────────────────────────────────────────────────────┐
│ CoreScanService                                                       │
│                                                                      │
│  NativeWorkspaceScanner                                              │
│  ScannerManager                                                       │
│  AI services (separate optional operations)                           │
│  correlation, relationship graph, telemetry, report generation       │
└───────────────┬───────────────────────────────┬──────────────────────┘
                │                               │
                v                               v
┌─────────────────────────────┐   ┌────────────────────────────────────┐
│ Native Aqiron rules          │   │ Optional external scanners          │
│ Dart, Python, Android XML,   │   │ Betterleaks, MobSF, OSV-Scanner,   │
│ and Dockerfile patterns      │   │ Semgrep OSS, and Trivy             │
└───────────────┬─────────────┘   └──────────────────┬─────────────────┘
                └──────────────────┬─────────────────┘
                                   v
                    ┌──────────────────────────────┐
                    │ UnifiedFinding[]              │
                    │ normalized severity, source, │
                    │ location, remediation,       │
                    │ CWE/OWASP/tags where present │
                    └──────────────┬───────────────┘
                                   v
                    ┌──────────────────────────────┐
                    │ Correlation and graph engines │
                    │ fingerprint, deduplicate,    │
                    │ relate findings, build graph  │
                    └──────────────┬───────────────┘
                                   v
                    ┌──────────────────────────────┐
                    │ ReportGenerator               │
                    │ JSON, SARIF, minimal PDF,    │
                    │ executive summary, telemetry  │
                    └──────────────┬───────────────┘
                                   v
          ┌────────────────────────┴────────────────────────┐
          │                                                 │
          v                                                 v
┌───────────────────────────┐                 ┌────────────────────────┐
│ workspace/.aqiron-security│                 │ VS Code diagnostics and │
│ reports and threat history│                 │ Aqiron webview/sidebar  │
└───────────────────────────┘                 └────────────────────────┘
```

`packages/core` is marked private and is bundled into `dist/core-runtime.js`; it is not currently a separately published package.

## Scan data flow

```text
User command or supported-file save
                │
                v
       Flutter workspace check
                │
                v
       CoreClient scan.start
                │
                v
       CoreScanService.run
                │
       ┌────────┴────────┐
       v                 v
 Native rules      ScannerManager
       │                 │
       └────────┬────────┘
                v
        UnifiedFinding[]
                │
                v
       correlation + graph
                │
                v
             reports
                │
       ┌────────┴─────────┐
       v                  v
 VS Code issues       JSON/SARIF/PDF
 webview state        .aqiron-security/
```

Quick file scans use the extension's direct `WorkspaceScanner` path. Full workspace scans use the core runtime pipeline. Both paths apply supported-file, size, generated-file, minified-file, and exclusion checks, although their implementations are separate.

## Core runtime operations

```text
core.handshake       core.health          core.info
core.shutdown        core.cancel         project.detect
project.profile      rag.index            rag.status
rag.query            scan.start           scan.cancel
scan.status          ai.providers         ai.models
ai.chat              ai.cancel            ai.review
ai.vulnerabilityAnalysis
credentials.status   credentials.set      credentials.delete
credentials.exists   report.generate
```

Requests and pipeline events are exchanged through the protocol in `packages/core/src/runtime/protocol.ts`. Cancellation is propagated through the runtime's cancellation sources and scanner context.

## Scanner and parser relationship

```text
External executable/server output
              │
              v
Tool-specific parser
  BetterleaksParser
  OsvScannerParser
  SemgrepParser
  TrivyParser
  MobSF mapping inside MobSF scanner
              │
              v
        UnifiedFinding
              │
              v
      correlation / report
```

The current runtime does not register YARA. Older diagrams or notes that show YARA, fixed finding counts, HTML dashboards, or binary malware results are historical or prospective and are not current runtime behavior.

## RAG and AI side path

```text
RAG command/webview action
              │
              v
src/rag/ragWorkspaceService.ts
  trust + Flutter checks
  .aq policy creation
  optional AI suggestions
              │
              v
Core RAG services
  bounded file collection
  signal detection and chunking
  deterministic vectors
  lexical/vector retrieval
              │
              v
workspace/.aqiron-security/
  index.json, vectors.json, regexSources.json
  optional suggestions.md and benchmarks/latest.json
```

AI chat and vulnerability analysis use the configured Ollama or OpenRouter provider. AI operations may send selected workspace context to that configured provider. The non-AI local scan and index paths do not require a hosted Aqiron service.

## Build outputs

```text
src/extension.ts                    -> dist/extension.js
packages/core/src/runtime/main.ts   -> dist/core-runtime.js
src/webview/ui/index.tsx            -> dist/webview.js
src/**/*.test.ts                    -> out/**/*.test.js
```

`dist/`, `out/`, `node_modules/`, `.vscode-test/`, `.aqiron-security/`, and coverage output are local/generated content and are ignored by the repository. The source and runtime outputs are validated by the TypeScript, ESLint, esbuild, and VS Code test workflows.

## Current boundaries

- Flutter is the only workspace type accepted by the extension's workspace operations.
- External scanners are optional and report unavailable status when missing or unconfigured.
- YARA, cloud orchestration, executable fuzzing, dynamic sandbox analysis, Jira integration, public report sharing, and automatic workspace-wide remediation are not implemented current capabilities.
- Finding counts and risk scores are calculated per scan; this document intentionally uses no fabricated sample totals.
