# aqiron-security-vscode
=======
# Aqiron Security

Aqiron Security is a VS Code extension for security scanning and security-focused workspace analysis. The repository contains the extension, its React webview, and a private TypeScript core runtime that the extension starts as a separate Node.js process.

## Current status

This repository is version `0.0.1` and is under active development. The implementation is local-first and currently gates workspace scans to Flutter workspaces. Some UI actions and command handlers exist as preparation or presentation layers; they should not be read as evidence that a cloud service, Jira integration, dynamic analysis, or automatic workspace-wide remediation is implemented.

## What works today

- Scan a supported current file or Flutter workspace.
- Publish findings as VS Code diagnostics and show them in the Aqiron sidebar.
- Run deterministic native rules for selected Dart, Python, Android XML, and Dockerfile patterns.
- Run the registered external scanners when they are installed or configured: Betterleaks, MobSF, OSV-Scanner, Semgrep OSS, and Trivy.
- Normalize findings, correlate duplicate/related findings, build a relationship graph, and generate JSON, SARIF, and PDF report artifacts under `.aqiron-security/reports/`.
- Use the in-extension security agent with either Ollama or OpenRouter, when configured. Credentials are stored through the core runtime credential store.
- Build and query a workspace RAG index, with optional AI-assisted indexing.
- Apply the currently implemented file-level quick fixes for a small set of deterministic findings.

External scanners are optional. If a scanner is unavailable, the core reports that status rather than silently claiming that the scanner ran. MobSF additionally requires a configured server URL and API key. OSV-Scanner can use its supported OSV API fallback when the relevant input is available.

## Requirements

- VS Code `^1.118.0`.
- Node.js and npm capable of installing the versions in `package.json` and `package-lock.json`.
- A Flutter workspace for the extension's workspace scan path (`pubspec.yaml` or `.metadata` is used for detection).
- Optional tools for the corresponding scan stages: `betterleaks`, `osv-scanner`, `semgrep`, and `trivy` on `PATH`; MobSF configured through the extension settings.
- Optional AI provider setup: a reachable Ollama endpoint or an OpenRouter API credential.

## Installation and development

From the repository root:

```powershell
npm ci
npm run compile
```

To package the extension bundle:

```powershell
npm run package
```

To run type-checking and linting independently:

```powershell
npm run check-types
npm run lint
```

The VS Code launch configuration in `.vscode/launch.json` starts an Extension Development Host after the default build task. `npm run watch` runs the TypeScript and esbuild watchers in parallel.

## Testing

The repository uses the VS Code test CLI. Run the existing test suite with:

```powershell
npm test
```

`npm test` runs the `pretest` script first, which compiles test output, compiles the extension, and runs linting. The tests are in `src/test/` and cover core modules, scanners/parsers, RAG behavior, AI services, reports, and extension behavior.

## Commands and settings

The contributed command palette includes workspace/current-file scanning, refresh, issue explanation, the security agent, workspace analysis, and RAG index management. The extension also registers internal commands for cancellation, issue opening, and the currently implemented file quick-fix path.

Important settings include:

- `aqiron-security.enableQuickFixes`
- `aqiron-security.excludeFolders`
- `aqiron-security.enableRealtimeScan`
- `aqiron-security.scanGeneratedFiles`
- `aqiron-security.maxFileSizeKB`
- `aqiron-security.mobsfBaseUrl`
- `aqiron-security.mobsfApiKey`
- `aqiron-security.customRules`

The complete defaults and descriptions are authoritative in [`package.json`](package.json).

## Architecture

```text
VS Code extension (`src/`)
  ├─ commands, diagnostics, status bar, sidebar/webview, settings, credentials
  ├─ current-file scanner and VS Code integration
  └─ CoreClient ── newline-delimited JSON over stdin/stdout ──┐
                                                              │
private core runtime (`packages/core/`)
  ├─ NativeWorkspaceScanner and scanner manager                 │
  ├─ Betterleaks, MobSF, OSV-Scanner, Semgrep, Trivy adapters   │
  ├─ finding normalization, correlation, graph, telemetry       │
  ├─ AI providers, project/RAG services, report generation      │
  └─ Node adapters for filesystem, processes, network, secrets  │
                                                              └─ `dist/core-runtime.js`
```

`src/` is the VS Code host and user interface. `packages/core/` is a private package (`"private": true`) whose source is bundled into `dist/core-runtime.js`; it is not currently published as a standalone npm package. `src/core/CoreClient` starts and communicates with that runtime, performs the protocol handshake, forwards events, and exposes the runtime operations to the extension.

The extension's workspace scan path is Flutter-gated before it invokes the core pipeline. The core code contains broader portable rules and scanner capabilities, but that does not mean every capability is exposed for every workspace type through the current extension.

For deeper implementation notes, see [`AQIRON_SECURITY_RAG.md`](AQIRON_SECURITY_RAG.md), [`TECHNICAL_REVERSE_ENGINEERING.md`](TECHNICAL_REVERSE_ENGINEERING.md), and the source. Older implementation documents may describe intended or historical components; verify them against the current code before relying on them.

## Known limitations

- The extension currently supports Flutter workspaces for workspace scans; non-Flutter workspaces are explicitly reported as unsupported.
- External scanner results depend on local executables, server configuration, network access, tool versions, and tool-specific rules.
- The built-in rules are pattern-based and can miss data-flow vulnerabilities or produce false positives.
- Generated, minified, compiled, dependency, and configured exclusion paths are skipped by default; changing scan settings can change coverage and noise.
- AI output is advisory and depends on the selected provider/model. It must be reviewed before being used for security decisions.
- The repository contains UI paths for future or placeholder workflows. In particular, do not assume that every visible report/share/remediation action represents a connected external integration.
- There is no declared open-source license or published package contract yet.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Security-sensitive reports should follow [`SECURITY.md`](SECURITY.md).

## Roadmap

The evidence-based roadmap is in [`ROADMAP.md`](ROADMAP.md). It separates work visible in the current code from work that still needs design, implementation, validation, or maintainer decisions.

## License and trademark

No `LICENSE` file or project license declaration is present in this repository. The licensing decision must be made by the project owner before public distribution or accepting contributions under an assumed license. Do not infer a license from dependency metadata.

“Aqiron” and “Aqiron Security” should be treated as project names, not as a grant of trademark rights. Any trademark policy and permitted uses require owner/legal review.


---

## Full architecture diagrams

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


---

## Full VS Code development quickstart

# Aqiron Security VS Code development quickstart

This quickstart describes the current repository workflow. It replaces the generic VS Code extension template.

## Prerequisites

- VS Code `^1.118.0`.
- Node.js and npm compatible with the versions in `package.json` and `package-lock.json`.
- A trusted Flutter workspace for exercising workspace scans and RAG.
- Optional scanner executables or services when testing those integrations: Betterleaks, OSV-Scanner, Semgrep, Trivy, or MobSF.
- Optional Ollama or OpenRouter configuration for AI operations.

## Install dependencies

Run from the repository root:

```powershell
npm ci
```

The repository currently contains a private `packages/core` source package. It is bundled into the extension/runtime build; no separate `npm install` is required inside `packages/core`.

## Compile and lint

```powershell
npm run check-types
npm run lint
npm run compile
```

`npm run compile` performs type checking and linting, then builds the extension, core runtime, and webview bundles with esbuild.

## Run the extension

1. Open the repository folder in VS Code.
2. Run `npm run compile`, or use the default build task.
3. Press `F5` and select the `Run Extension` launch configuration.
4. In the Extension Development Host, open a trusted Flutter workspace.
5. Use the Aqiron Security activity-bar view or the Command Palette.

The launch configuration is in `.vscode/launch.json`. It points the Extension Development Host at the repository and uses `dist/**/*.js` as debug output.

## Watch mode

```powershell
npm run watch
```

This runs the TypeScript watch process and esbuild watch process in parallel. The VS Code task named `watch` in `.vscode/tasks.json` invokes the same watchers.

## Run tests

```powershell
npm test
```

The `pretest` script compiles tests into `out/`, compiles the extension, and runs linting before launching the VS Code test CLI. The test files are under `src/test/` and cover extension behavior, core modules, parsers/scanners, AI services, RAG, threat history, and runtime behavior.

If the global npm command is unavailable in a local environment, use the installed project binaries directly:

```powershell
node node_modules/typescript/bin/tsc --noEmit
node node_modules/eslint/bin/eslint.js src packages/core/src
node esbuild.js
node node_modules/@vscode/test-cli/out/bin.mjs
```

## Package the extension

```powershell
npm run package
```

Packaging performs type checking and linting, then creates production-minified bundles in `dist/`. The generated output is not source-controlled.

## Useful commands

Contributed commands include:

- `Aqiron Security: Open Sidebar`
- `Aqiron Security: Scan Workspace`
- `Aqiron Security: Scan Current File`
- `Aqiron Security: Refresh Scan`
- `Aqiron Security: Explain Issue`
- `Aqiron Security: Open Security Agent`
- `Aqiron Security: Analyze Workspace`
- `Aqiron Security: Reindex RAG`
- `Aqiron Security: Reindex RAG with AI`
- `Aqiron Security: Reindex RAG without AI`
- `Aqiron Security: Add RAG Regexes`
- `Aqiron Security: Sync Trusted RAG Regexes`

Workspace operations currently require Flutter workspace detection. RAG operations additionally require a trusted VS Code workspace.

## External scanner setup

The core runtime checks the availability of Betterleaks, OSV-Scanner, Semgrep, and Trivy on `PATH`. MobSF requires a configured base URL and API key through the extension settings. Missing tools are reported as unavailable and do not make the whole build invalid.

## AI setup

The current AI provider IDs are `ollama` and `openrouter`. Configure a reachable endpoint/model or API credential through the Aqiron settings UI. Credentials are passed to the core credential-store abstraction and should never be committed to the repository.

AI operations can send workspace-derived context to the configured provider. Review provider privacy and retention policies before using AI features with sensitive code.

## Generated workspace data

Scans, RAG, and threat history may create files under the workspace's `.aqiron-security/` directory. These files can contain source paths, findings, evidence, reports, vectors, and suggestions. Keep them local and do not commit them.

## Current limitations

- Workspace scans are Flutter-only at the extension boundary.
- Built-in rules are pattern-based and can produce false positives or miss data-flow issues.
- External scanner behavior depends on local tools, server configuration, network access, and tool versions.
- YARA, cloud services, executable fuzzing, dynamic sandbox analysis, Jira integration, and automatic workspace-wide remediation are not current implemented features.
- The repository has a private core package rather than a separately published library.

## Related documentation

- [`README.md`](README.md) — project overview and architecture.
- [`AQIRON_SECURITY_RAG.md`](AQIRON_SECURITY_RAG.md) — RAG implementation details.
- [`TECHNICAL_REVERSE_ENGINEERING.md`](TECHNICAL_REVERSE_ENGINEERING.md) — current technical architecture and boundaries.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution workflow and validation.
>>>>>>> 649781c (Initial build)
