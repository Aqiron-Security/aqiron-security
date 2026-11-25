# Aqiron Security Architecture

The current product is **Aqiron Desktop + Aqiron CLI, powered by Aqiron Core**. The repository root is the Tauri Desktop project. These diagrams describe the current source tree and supported runtime paths.

## Product architecture

```text
┌──────────────────────────────────┐       ┌──────────────────────────────────┐
│ Aqiron Desktop                   │       │ Aqiron CLI                       │
│ root src/ + src-tauri/            │       │ packages/cli/                     │
│ existing React UI and native host │       │ automation and CI output         │
└────────────────┬─────────────────┘       └────────────────┬─────────────────┘
                 │                                            │
                 └──────────────────┬─────────────────────────┘
                                    │ Core protocol / CoreClient
                                    v
┌────────────────────────────────────────────────────────────────────────────┐
│ Aqiron Core — packages/core/                                                │
│ protocol, validation, authorization, scan lifecycle, cancellation, RAG,     │
│ rules, findings, hypothesis lifecycle, evidence validation, persistence,   │
│ reports, provider policy                                                   │
└───────────────────────────────────────┬────────────────────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    v                                       v
          Native and optional scanners             Workspace state and reports
          normalized UnifiedFinding data           .aqiron-security/
```

Desktop uses the root Tauri application and the shared Node bridge in `packages/desktop/`. CLI runs independently through `packages/cli/`; it does not require Desktop or Tauri. Core owns security decisions and state. The frontend and Rust host provide presentation and transport only.

## Scan lifecycle

```text
Desktop project selection ─┐
                           ├──> Core protocol ──> validation and authorization
CLI workspace argument ───┘                            │
                                                       v
                                         Core scan orchestration
                                         native rules + scanners
                                                       │
                                                       v
                                  findings -> correlation -> reports
                                                       │
                              ┌────────────────────────┴───────────────────┐
                              v                                            v
                       Desktop findings                          CLI output formats
                       and scan history                          JSON, SARIF, text
```

Core validates workspace and file-scan requests, applies its scan policy, handles cancellation, and normalizes findings. Desktop's selected native project supplies workspace scope through the bridge. A `scan.file` request does not accept a caller-supplied `workspaceRoot`; Core rejects unknown request fields.

## Hypothesis lifecycle

```text
Completed Core scan
       │
       v
Evidence snapshot and freshness validation
       │
       v
Core hypothesis generation and persistence
       │
       v
Desktop review: prepare -> approve/deny -> validated outcome
       │
       v
Production synthesis gate remains disabled
```

Hypotheses remain distinct from confirmed findings. Core owns lifecycle, evidence freshness, authorization, persistence, and provider policy. Approval does not enable production synthesis.

## Current root layout

```text
src/                         Desktop frontend and adapter
src-tauri/                   Tauri Rust host, commands, capabilities, resources
packages/core/               Authoritative engine and protocol
packages/desktop/            Node bridge for Desktop
packages/cli/                Independent command-line interface
docs/                        Active architecture and development guides
```

Historical migration records may describe the former extension and nested Desktop paths. They are not current product or build instructions.
