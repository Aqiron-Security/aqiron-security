# Aqiron Security Technical Architecture

This document is a current-state technical description of the Aqiron Security repository. It separates implemented behavior from future possibilities and does not treat UI labels, design notes, or placeholder handlers as completed product capabilities.

## Evidence model

The implementation evidence for this document comes from:

- `package.json`, `tsconfig.json`, `esbuild.js`, and the lockfile.
- The VS Code host in `src/`.
- The private core source in `packages/core/src/`.
- The current tests in `src/test/`.
- The runtime protocol and extension/core client.

The repository has no remote backend, queue service, hosted database, cloud orchestration layer, or published `@aqiron/core` package. Those are outside the current implementation.

## Product boundary

Aqiron Security is a local-first VS Code extension. It provides a security sidebar/webview, diagnostics, status updates, workspace/current-file scanning, AI-assisted workspace analysis, RAG indexing, finding correlation, and local report artifacts.

The extension currently gates workspace operations to Flutter workspaces. Flutter detection uses `pubspec.yaml` or `.metadata`. Non-Flutter workspaces receive an unsupported-workspace message even though some reusable core rules and project-analysis code are broader.

The current version in package metadata is `0.0.1`. The project is under active development.

## Repository architecture

```text
VS Code extension host: src/
  extension activation and commands
  current-file scanner and diagnostics
  React webview provider and UI
  AI/RAG workspace services
  CoreClient and CoreProcessManager
             |
             | newline-delimited JSON over stdin/stdout
             v
Private Node runtime: packages/core/src/runtime/
  protocol and request dispatch
  filesystem/process/network/credential adapters
  scanner manager and core pipeline
  AI providers and analysis
  RAG/project/context services
  correlation, graph, telemetry, and reports
             |
             v
esbuild outputs: dist/extension.js, dist/core-runtime.js, dist/webview.js
```

`packages/core/package.json` is marked private. Its TypeScript source is imported by the extension during development and bundled into the runtime; it is not currently a separately published package.

## VS Code extension host

`src/extension.ts` creates and registers the primary services:

- `CoreClient` and its singleton.
- `AIService` for provider state and chat coordination.
- `WorkspaceScanner` for direct current-file and legacy local scan behavior.
- `ScanController` for commands, debouncing, diagnostics, status, and view updates.
- `RagWorkspaceService` for local RAG operations.
- `AqironWebviewProvider` for the React-based sidebar.
- `DiagnosticManager` and `AqironQuickFixProvider`.

The contributed command palette includes workspace scanning, current-file scanning, refresh, issue explanation, the security agent, workspace analysis, and RAG commands. Additional registered handlers exist for cancellation, issue opening, internal quick fixes, and UI workflows; registration alone does not mean every handler is exposed as a contributed command or connected to an external service.

The extension gates workspace scan, file scan, RAG, and related webview operations through the Flutter workspace check. Supported source extensions in the direct scanner include Dart, TypeScript, JavaScript, Python, Rust, Java, C/C++, JSON, XML, YAML, Gradle, and rules files. Generated, minified, compiled, dependency, and configured exclusion paths are skipped by default.

## Core process boundary

`CoreProcessManager` launches the bundled `dist/core-runtime.js`. `CoreClient` sends requests and receives responses/events using the protocol in `packages/core/src/runtime/protocol.ts`.

The runtime supports requests for:

- Handshake, health, information, shutdown, and cancellation.
- Project detection and profiling.
- RAG indexing, status, and query.
- Scan start, cancellation, and status.
- AI providers, models, chat, review, and vulnerability analysis.
- Credential status, storage, deletion, and existence checks.
- Report generation.

Credentials are handled through the runtime credential-store abstraction. The Node adapter uses the installed `keytar` dependency when available. The extension does not place provider secrets in source-controlled configuration.

## Current scan pipeline

The current full workspace flow is:

1. The extension verifies that a workspace is open and Flutter-supported.
2. `SecurityPipelineEngine` sends `scan.start` through `CoreClient`.
3. `CoreRuntime` builds a scanner context with filesystem, process, network, configuration, credential, and cancellation adapters.
4. `CoreScanService` runs the native workspace scanner.
5. `ScannerManager` checks availability and runs registered external scanners.
6. Findings are normalized into `UnifiedFinding` values.
7. Findings are correlated and deduplicated, and a relationship graph is built.
8. The core report generator creates report content and telemetry.
9. The extension writes JSON, SARIF, and PDF artifacts under the workspace `.aqiron-security/reports/` directory.
10. Findings are converted into VS Code issues and sent to diagnostics and the webview.

The quick mode selects scanners with source-code or secret capabilities. Deep and analysis modes select all registered scanners. A scanner that is missing or not configured is represented as unavailable; the pipeline does not claim that it ran.

## Implemented scanners

The core runtime currently registers:

| Scanner | Current behavior |
| --- | --- |
| Native Aqiron rules | Portable line-based rules for selected Dart, Python, Android XML, and Dockerfile patterns. |
| Betterleaks | Optional local executable; parses and redacts secret evidence. |
| MobSF | Optional configured MobSF server; uploads a discovered APK/IPA/AAB artifact and parses JSON findings when configured. |
| OSV-Scanner | Optional local executable with a supported OSV API fallback for applicable dependency input. |
| Semgrep OSS | Optional local executable with managed rule configuration and JSON parsing. |
| Trivy | Optional local executable for vulnerability, secret, and configuration results. |

YARA is not registered in the current core runtime. Mobile dynamic analysis, sandbox execution, executable API fuzzing, malware reputation, and artifact build/upload services are not current product capabilities.

## Findings, correlation, and reports

Findings are represented in a shared schema with severity, source tool, rule ID, file/location, remediation, CWE/OWASP mappings where available, tags, confidence, and redacted evidence fields.

The correlation engine fingerprints and deduplicates related findings and creates relationships. The relationship graph is an in-memory result for the scan and is included in report state. Telemetry records pipeline and scanner events for the current scan.

Reports currently provide:

- A JSON report model.
- SARIF 2.1.0-shaped output.
- A minimal generated PDF string.
- Executive-summary text from the report generator; AI summaries are used only when the relevant extension path supplies an AI summary generator.

The extension writes generated report files into `.aqiron-security/`, which is workspace-local and should remain ignored.

## AI implementation

The core AI provider type is limited to `ollama` and `openrouter`. The provider layer supports model discovery, streaming chat, retries/timeouts, credential access, and structured vulnerability-analysis/review services.

The extension webview provides chat, provider/model selection, credential management, and AI-assisted workspace workflows. AI analysis is optional and provider-dependent. Code or workspace context may be sent to the configured AI provider during AI operations; the non-AI local scan path does not require a hosted Aqiron service.

AI output is advisory. The current repository does not implement a general autonomous agent policy engine, unrestricted command execution, a hosted model gateway, tenant isolation, or a guarantee that generated remediation is safe.

## RAG and workspace intelligence

RAG is documented in detail in [`AQIRON_SECURITY_RAG.md`](AQIRON_SECURITY_RAG.md). In summary, it:

- Requires a trusted Flutter workspace.
- Indexes bounded source files and detected security signals.
- Persists local index/vector/catalog files under `.aqiron-security/`.
- Uses deterministic token-hash vectors with lexical/vector hybrid retrieval.
- Can optionally use `faiss-node`.
- Supports validated workspace regex sources.
- Can generate AI suggestions when a provider and model are configured.

RAG is not a hosted enterprise knowledge base and does not provide a general-purpose semantic code-search guarantee.

## Security and privacy boundaries

Current protections include workspace trust checks for RAG, path and generated-file exclusions, file-size bounds, redaction in secret-related parsing/AI paths, local credential-store abstraction, cancellation handling, and `execFile`-style process execution in the core adapters.

Current limitations include:

- Pattern-based rules can miss data-flow issues and produce false positives.
- External scanner security depends on local tool versions, configuration, and network/server behavior.
- AI prompts and responses may contain workspace-derived context.
- `.aqiron-security` output can contain source paths, findings, evidence, reports, and history and should not be committed.
- There is no remote authentication, authorization service, tenant model, artifact storage service, or hosted audit-log system.
- Permission labels in the UI do not constitute a complete policy enforcement engine.

## UI and workflow status

The webview contains Agent, Scan, Threats, Reports, and settings surfaces. Some visible actions are local exports or preparation paths; some names describe future workflow direction. In particular, the repository does not currently provide a connected Jira integration, public report-sharing service, cloud scan backend, executable fuzzing engine, or automatic workspace-wide remediation engine.

The implemented file-level quick-fix path targets a small deterministic set of issue rules. It is not a general patch-generation or autonomous remediation system.

## Build and test architecture

The root build uses TypeScript for type checking and esbuild for three bundles:

- `dist/extension.js` from `src/extension.ts`.
- `dist/core-runtime.js` from `packages/core/src/runtime/main.ts`.
- `dist/webview.js` from `src/webview/ui/index.tsx`.

The VS Code test CLI compiles tests into `out/` and runs the test suite in an installed VS Code test environment. Tests cover core modules, scanners/parsers, the runtime process, AI providers, RAG, threat history, reports, and extension behavior.

## Future work versus current implementation

The following are possible future directions, not current capabilities: additional workspace types, deeper AST/data-flow analysis, executable API fuzzing, mobile dynamic analysis, YARA integration, hosted orchestration, cloud artifact storage, multi-tenant controls, enterprise authentication, durable server-side scan history, and external workflow integrations.

Any future claim should be supported by code, tests, configuration, and user-facing documentation before being described as implemented.
