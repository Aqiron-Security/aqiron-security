# Core implementation inventory

**Inventory date:** 2026-10-01. This records the checked-in implementation before Phase 1 protocol changes. No duplicate code was deleted or merged during inventory.

## Core IPC inventory

Wire envelope is currently newline-delimited JSON: request `{ id, type: "request", method, params? }`; successful response `{ id, type: "response", success: true, result }`; failed response uses `error: { code, message, details? }`; event `{ type: "event", event, requestId?, payload? }`. The process manager owns framing, pending ids, timeout/cancel and restart. Runtime has an allowlist, but pre-change validation checks only envelope and that params is an object. Handler casts do not validate required fields.

| Method | Actual params (runtime/client) | Result | Events | Client-independent? / call sites |
|---|---|---|---|---|
| `core.handshake` | extensionVersion, protocolVersion, platform, architecture: strings/numbers | protocolVersion, coreVersion, status, optional reason | none | Runtime negotiation generic; extension supplies host metadata. CoreProcessManager only. |
| `core.health` | omitted | {ok:true, ready:boolean, uptimeMs:number} | none | Generic lifecycle; process manager and CoreClient.health. |
| `core.info` | omitted | {coreVersion, protocolVersion, runtime:"node", startedAt} | none | Generic lifecycle; CoreClient.info. |
| `core.shutdown` | client sends {} | {ok:true} | none | Generic lifecycle; process manager stop. |
| `core.cancel` | {requestId?:string} | {cancelled:boolean, requestId?:string} | none | Generic request lifecycle; manager timeout/cancel and CoreClient.cancelRequest. |
| `project.detect` | {workspaceRoot:string, trusted:boolean, currentFile?:string} | ProjectProfile | none | Domain generic with local path/workspace assumptions; CoreClient.detectProject. |
| `project.profile` | same as detect | {projectProfile, securities:string[]} | none | Domain generic; CoreClient.profileProject. |
| `rag.index` | {workspaceRoot:string, withAi?:boolean} | {index:RagIndexData} | declared rag.index.progress but indexer currently returns result; no observed progress emission | Generic domain capability; CoreClient.indexRag, VS Code RAG service call path. |
| `rag.status` | client sends {workspaceRoot, trusted:true}; protocol request currently uses project detect request shape | {hasIndex, updatedAt?, fileCount, chunkCount} | none | Generic domain; CoreClient.ragStatus. |
| `rag.query` | {workspaceRoot:string, query:string, limit?:number}; limit is not used in runtime query | {results:RagRetrievalResult[]} | none | Generic domain; CoreClient.queryRag and indirect analysis paths. |
| `scan.start` | {requestId?, workspaceRoot, targetPath?, mode?:quick/deep/analysis, trusted, currentFile?} | scanId, state, findings, report, optional counts/toolResults/correlation/graph/telemetry | PipelineEvent payloads, requestId=scanId | Generic security operation; CoreClient.startScan via `src/security/pipeline/pipelineEngine.ts`. |
| `scan.cancel` | {scanId?:string} | {cancelled:boolean} | none | Generic but client currently calls core.cancel instead; no direct caller found. |
| `scan.status` | {scanId?:string} | {scanId?, state?, running:boolean} | none | Generic; CoreClient.scanStatus, no other production call found. |
| `ai.providers` | omitted | {providers:string[]} | none | Generic capability; CoreClient.providers, VS Code `src/ai/services/aiService.ts`. |
| `ai.models` | {providerId?:string} | {models:AIModel[], status:ProviderConnectionStatus} | none | Generic capability but mutates selected Core provider when providerId given; CoreClient.models and VS Code AI service. |
| `ai.cancel` | {sessionId?:string} | {cancelled:true} | none | Generic AI operation; dispatch only, no CoreClient method caller observed. |
| `ai.chat` | {sessionId,text,history,model,intelligence,context} | {text:string} | ai.token StreamChunk, ai.error StreamChunk, ai.completed {text} | Generic analysis capability; CoreClient.chat via VS Code AI service. |
| `ai.review` | {sessionId, findings:UnifiedFinding[]} | {text:string} | ai.completed {text} | Generic analysis capability; CoreClient.review exists, production caller not found. |
| `ai.vulnerabilityAnalysis` | {sessionId, workspaceRoot, baselineFindings} | AIAnalysisResult {findings,summary,retrievalCount,filesAnalyzed,durationMs} | ai.completed {findings:number} | Generic security analysis; CoreClient.vulnerabilityAnalysis via `src/security/analysis/aiVulnerabilityAnalysisService.ts`. |
| `credentials.status` | {key:string} | {hasValue:boolean, updatedAt?} (status currently only hasValue) | none | Generic storage port operation; VS Code AI credential service. |
| `credentials.set` | {key:string,value:string} | {hasValue:true,updatedAt} | none | Generic storage port operation; VS Code AI credential service. |
| `credentials.delete` | {key:string} | {hasValue:false,updatedAt} | none | Generic storage port operation; VS Code AI credential service. |
| `credentials.exists` | {key:string} | {exists:boolean} | none | Generic storage port operation; VS Code AI credential service. |
| `report.generate` | {workspaceRoot?,scanId?,mode?,findings?,correlation?,graph?,telemetry?}; defaults several fields in handler | SecurityReportContent | none | Generic report generation; CoreClient.reportGenerate via `src/security/reports/reportGenerator.ts`. |

**Event payload notes:** scan events carry `PipelineEvent`; pipeline events include scan state, stage/tool/scanner status, logs, findings, counts, correlation summary and completion/failure/cancellation. AI stream payloads are StreamChunk-like. Event names and payload are currently split between `CoreProgressEnvelope` (not the runtime envelope) and arbitrary string/unknown in `CoreEventMessage`.

**Protocol inconsistencies / unsafe spots found:** `CoreRequestMessage.method` is string and params unknown; responses are untyped unknown. `CoreProcessManager.request<T>` lets callers choose any T/method pair. Runtime has unsafe params casts for nearly every method, including raw property extraction. The wire validator rejects non-object params globally, although no-params calls commonly omit params and shutdown sends {}. `scan.cancel` is dispatched but CoreClient.cancelScan sends `core.cancel`. `rag.status` reuses project request (including irrelevant trusted/currentFile). `rag.query.limit` is accepted but unused. AI provider id is cast from arbitrary string. AI chat context is cast to never, history role cast. report telemetry is cast to never; report fallback objects are asserted. `CoreScanStartRequest.mode` omits custom although downstream scanner/report accepts it. CoreScanStartResult telemetry is unknown. Runtime's `handle` response loses method/result correlation. Existing tests exercise process framing, timeout/restart, runtime handshake/health and credentials; they do not cover malformed method-specific params or event contract typing.

## Call-site inventory

The only direct Core protocol wrapper is `src/core/coreClient.ts`. It is used by:
- `src/security/pipeline/pipelineEngine.ts`: scan start, cancellation.
- `src/security/reports/reportGenerator.ts`: report generation.
- `src/security/analysis/aiVulnerabilityAnalysisService.ts`: AI vulnerability analysis.
- `src/ai/services/aiService.ts` and `src/ai/services/credentialService.ts`: provider/model/chat and credential methods.
- CoreProcessManager itself: handshake, health, shutdown and cancellation.
- CoreClient methods for project, RAG query/index/status, scan status, review, and scan.cancel exist; production call coverage is partial. Existing tests call manager with arbitrary fake methods and runtime with typed credential messages.

## Overlap inventory

| Capability | Core implementation | `src/security` / `src/ai` / `src/rag` implementation and callers | Tests | Likely status / safe to remove now? |
|---|---|---|---|---|
| Scanner adapters and parsers | Core `scanners/*`, `parsers/*`, scanner manager, native scanner; runtime registers Betterleaks, MobSF, OSV, Semgrep, Trivy | `src/security/scanners/*`, `parsers/*`, adapters/toolExecutor, scan modes and Flutter scope. Core IPC scan caller is `src/security/pipeline/pipelineEngine.ts`; legacy orchestrator paths are also referenced by extension composition. | `coreScanners`, `securityToolParsers`, extension tests | Both exist and may differ. Some src files are likely prior implementation, but do not remove until import/runtime graph confirms inactive. Unsafe now. |
| Scan orchestration/events/cache | Core `orchestration/CoreScanService`, `pipeline/*`, shared events/state | `src/security/orchestrator`, `pipeline/pipelineEngine`, worker queue, cache, events, scan state | `coreRuntime`, `coreProcessManager`, extension | Core runtime handles IPC scans; VS Code adapter/pipeline forwards events. Legacy orchestration remains potentially active. Unsafe now. |
| Findings/correlation/graph | Core shared `UnifiedFinding`, parsers, `correlation/*` | `src/security/findings`, `correlation/*`, `models/issue` and shared types/converters | `coreScanners`, parser tests, UI/provider tests | Core finding is used in IPC, but UI uses projected issue; overlap alone is insufficient to delete. Unsafe now. |
| Project/security context | Core `project/*`, `context/*` | `src/security/analysis/securityContextBuilder.ts`, context builder/tests | `coreProjectRag`, `securityContextBuilder` | Core API project profile exists; legacy context callers may remain. Unsafe now. |
| AI providers/services/review/analysis | Core `ai/*`, provider registry, review and vulnerability analysis; runtime constructs services | `src/ai/*` is mainly VS Code AI settings/credential/model UX and adapter forwarding; `src/security/analysis/aiVulnerabilityAnalysisService.ts` forwards to Core; webview invokes client AI | `coreAi`, `aiVulnerabilityAnalysis`, provider UI | Not a duplicate in full: Core runs provider operations, src adapts UX/config. Preserve. |
| RAG index/retrieval | Core `rag/*`, runtime methods | `src/rag/*` includes workspace service, regex catalog/UI commands, benchmark and wrappers importing Core; `src/security/analysis/ragRetrievalService.ts` legacy path | `coreProjectRag`, `rag` | Split responsibility, partial overlap. Preserve until call graph and data-store semantics are mapped. |
| Reports | Core `reports/*` builds report content/formats | `src/security/reports/reportGenerator.ts` forwards report to Core; `reportStorage.ts` owns VS Code artifact persistence | `reportExporters` | Adapter/storage vs generator, not safe to remove. |
| Telemetry and context | Core telemetry/context contracts and engines | `src/security/pipeline/threatIntelligenceAggregator.ts`, telemetry adapters and security-context modules | Relevant coverage spread across core/context tests | Similar concerns but not necessarily identical. No removal now. |

No duplicate implementation is declared safe to remove in Phase 1. Recommended migration is to map actual import/call graphs, designate Core as authority per behavior, then migrate one adapter at a time with parity tests before deleting legacy code in a separate change.


## Scan and orchestration call-graph inventory

This section follows actual callers, not directory names. “Active” means a checked-in production caller reaches the path; “adapter-only” means it translates or delegates to another implementation.

### Path A — workspace commands (Core is authoritative today)

    VS Code command -> ScanController.scanWorkspace/analyzeWorkspace
      -> SecurityOrchestrator.scanWorkspace
      -> SecurityPipelineEngine.scanWorkspace
      -> CoreClient.startScan -> CoreProcessManager -> CoreRuntime.startScan
      -> CoreScanService.run
      -> NativeWorkspaceScanner -> ScannerManager.run
      -> correlation -> relationship graph -> Core ReportGenerator
      -> CoreScanStartResult
      -> VS Code adapter persists report artifacts and projects findings to issues
      -> diagnostics, tree/webview, status presentation

The VS Code entry points are extension commands scanWorkspace, analyzeWorkspace and refreshScan. ScanController calls SecurityOrchestrator, then SecurityPipelineEngine, which calls CoreClient.startScan. SecurityPipelineEngine does not call its injected WorkspaceScanner; its constructor explicitly discards the value. SecurityOrchestrator also discards the injected AIService, RAG service and executive-summary generator. The main workspace command path is already Core-backed.

CoreRuntime registers scanners in this order: Betterleaks, MobSF, OSV-Scanner, Semgrep, Trivy. CoreScanService runs NativeWorkspaceScanner first, then ScannerManager sequentially. ScannerManager quick mode selects registered scanners with source-code or secret capability; the native scanner runs before that selection and still runs in quick mode. Deep and analysis select all registered scanners. Runtime passes aiAnalysis: undefined to CoreScanService, so analysis mode adds no optional AI scan step. This is distinct from the separate ai.vulnerabilityAnalysis IPC operation.

Parser/normalization flow: Core scanner classes parse with packages/core/src/parsers or scanner-local mappers and produce UnifiedFinding. NativeWorkspaceScanner also creates UnifiedFinding. ThreatCorrelationEngine correlates/deduplicates; RelationshipGraphEngine builds the graph; Core ReportGenerator builds report content. SecurityPipelineEngine maps findings to the VS Code issue projection and writes report files through reportStorage. The UI owns diagnostics, issue presentation, output/status, editor actions and artifact locations.

CoreScanRequest.targetPath is supplied to registered scanners, but NativeWorkspaceScanner always traverses workspaceRoot. currentFile and trusted are not used by scan orchestration. The VS Code workspace command gates scans to Flutter workspaces even though Core runtime itself has no such gate.

Event flow: CoreScanService emits PipelineEvent to a local bus; CoreRuntime wraps each payload in a Core event whose outer requestId is the request’s scan id; CoreProcessManager forwards it; CoreClient re-emits it; SecurityPipelineEngine unwraps it into orchestrator.events; ScanController forwards it to webview/output. The webview currently handles stage/tool/log/complete/cancelled/error variants.

Tests: coreScanners tests ScannerManager mode selection and scanner classes; coreRuntime tests handshake/credentials but not scan.start; coreProcessManager tests framing/cancel/restart but not scan event correlation; coreModules tests correlation/graph; reportExporters tests formats; extension.test is sample-only. There is no end-to-end scan.start test asserting scanner order, result, report, cancellation and event identity.

Status: Core owns the authoritative workspace command scan behavior today. SecurityOrchestrator and SecurityPipelineEngine are active VS Code adapters. Report persistence and issue/UI projection are client work.

### Path B — current-file and save/realtime scans (active separate implementation)

    scanCurrentFile / onDidSaveTextDocument
      -> ScanController.scanDocument
      -> WorkspaceScanner.scanDocument
      -> scanContent plus VS Code customRules
      -> AqironIssue -> diagnostics and views

This path does not call CoreClient, Core IPC, Core scanner manager, Core parser/correlation/report flow. It is implemented by src/scanner/workspaceScanner.ts and src/scanner/rules.ts. It is called by current-file scanning, on-save scanning, and after fixCurrentFile. It uses active unsaved document text, VS Code file discovery, and an mtime/size in-memory cache for file reads. No focused WorkspaceScanner or scanContent tests were found.

Behavior differs from Path A: the controller restricts it to Flutter; it uses supportedGlob/excludeGlob, configurable size limits and custom rules; scanContent has language-specific rules and some rule ids not present in Core native rules; and it returns AqironIssue without external scanner results, Core normalization, correlation, graph or report. Core uses a different native rule set, fixed runtime configuration/exclusions, plus external scanners. Redirecting this path would change scanner coverage, rules, custom-rule behavior, cache, unsaved-content behavior and results. It is active but not safe to mechanically redirect.

### Path C — AI-agent workspace/secret tools (active separate implementation)

    Webview runAgentTool
      -> runWorkspaceScan / runSecretsScan
      -> agentScanner.scanWorkspace
      -> WorkspaceScanner + scanContent
      -> secret filtering / agent response and webview state

src/webview/aqironWebviewProvider.ts routes workspace.scan and secrets.scan here. It does not run Core orchestration. It inherits WorkspaceScanner's Flutter restriction and does not generate Core correlation/report results. There are no dedicated tests for these methods. Migration must preserve secret-only filtering and response shape.

### Other duplicate-looking paths

| Files | Actual role/callers | Classification |
|---|---|---|
| src/security/orchestrator/securityOrchestrator.ts; src/security/pipeline/pipelineEngine.ts | Used by ScanController; pipeline adapter calls Core IPC | Active VS Code adapters; retain. |
| src/security/pipeline/events.ts, workerQueue.ts, threatIntelligenceAggregator.ts; src/security/scanners/types.ts; src/security/parsers/*; src/security/findings/finding.ts; src/security/correlation/*; src/security/rules/semgrepRuleManager.ts | Mostly re-export Core definitions. UI and parser tests import some barrels. | Compatibility/adaptation, not duplicate implementations; migrate imports before cleanup. |
| src/security/scanners/*Scanner.ts; src/security/adapters/semgrepAdapter.ts and trivyAdapter.ts | Wrappers instantiate Core scanners; no production construction/call site found in the active workspace path. | Likely unused adapters; no removal until import/test inventory and parity checks. |
| src/security/scanners/platform.ts, flutterScanScope.ts, scanModes.ts, exclusions.ts; src/security/adapters/toolExecutor.ts; src/security/pipeline/scanCache.ts | Alternate VS Code scanner context/scope/executor/cache; no active workspace-path call site found. | Likely legacy/uncertain; do not delete based on names. |
| src/security/reports/reportGenerator.ts | Forwards report generation to Core; no production call to its class found. ScanController passes an executive-summary callback that SecurityOrchestrator ignores. | Adapter-only, apparently unused for workspace scans. |
| src/security/reports/reportStorage.ts | Called by active Core pipeline adapter to persist JSON/SARIF/PDF. | Active VS Code-specific artifact persistence. |
| src/security/analysis/aiVulnerabilityAnalysisService.ts | Calls separate Core ai.vulnerabilityAnalysis IPC operation. | Active adapter for separate analysis, not scan.start. |
| src/scanner/workspaceScanner.ts and src/scanner/rules.ts | Called by Paths B/C. | Active duplicate scan implementation; unsafe to remove now. |

### Scan identity findings

1. SecurityPipelineEngine creates a client request id and supplies it as CoreScanStartRequest.requestId and as the CoreProcessManager request id.
2. CoreRuntime.startScan uses that id as its scan id, outer event requestId, returned CoreScanStartResult.scanId, and returned state.scanId.
3. CoreScanService.run independently creates a timestamp-derived scan id for its scan state and many findings/correlation/report/telemetry events. Scanner callbacks and optional AI callbacks independently create new timestamp-derived ids per event. CoreRuntime wraps these payloads without rewriting inner scanId fields.

Thus request/response identity and outer event identity agree, but inner PipelineEvent.scanId values often disagree with the final result and with each other. Consumers correlating on the outer request id can correlate; consumers matching the returned scanId against event payload ids can lose or misattribute events. The VS Code pipeline adapter now filters by the active outer request id, preventing unrelated request events from reaching that scan's bus. It does not fix inconsistent inner ids. This can break multi-scan/client event grouping even though process request/response matching remains correct. Core-generated inner ids are unchanged because changing event behavior needs compatibility tests.

### Safe migration sequence

1. Keep Path A as the authoritative workspace scan. Retain the request-id filter in the VS Code event adapter. Add CoreRuntime scan.start integration coverage using stub ports for scanner order/modes, normalized findings/correlation/report, event identity, cancellation and request isolation.
2. Before redirecting Paths B/C, add characterization fixtures for WorkspaceScanner/scanContent languages and rules, custom rules, Flutter gate, exclusions/generated/build behavior, file size, cache, unsaved document contents, secret-only filtering and issue mapping. Decide which behavior must become Core behavior.
3. Resolve scope/config blockers before redirect: target/current-file semantics and unsaved content; workspace trust; customRules, excludes, generated-file and max-size settings. Core currently hard-codes some configuration and native scan ignores targetPath. Keep editor actions, diagnostics, debounce, progress and artifact destinations in VS Code.
4. Migrate AI-agent workspace/secret tools only after Core can preserve secret filtering and response shape; migrate current-file/realtime scans after Core has a validated file-scoped or document-content contract. One entry point per change.
5. Compare Core and current outputs on fixtures and representative workspaces; verify scan modes/order, cancellation/events, reports and views; then remove only proven-unreferenced legacy code in a separate cleanup.

Other blockers: Core analysis mode does not wire AI analysis into scan.start; report-summary dependency from VS Code is ignored; scanner exclusion/configuration semantics differ; WorkspaceScanner behavior lacks direct characterization tests.
