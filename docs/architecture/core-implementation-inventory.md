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
