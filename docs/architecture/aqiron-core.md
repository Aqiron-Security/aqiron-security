# Aqiron Core architecture

**Status:** Current implementation and boundary map (2026-10-02)
**Scope:** describe the checked-in implementation and client boundaries for VS Code, CLI/CI, and a future Desktop host. Core and IPC behavior remain unchanged.

This document uses **Current** for behavior demonstrated by this repository, **Near-term** for boundary work that can be done while this remains one repository, and **Future** for capabilities not present yet. The implementation is the source of truth; proposed method names below are illustrative contracts, not existing APIs unless explicitly called Current.

## Current architecture

The repository is still a VS Code extension package with an embedded Core source tree. Root scripts build/typecheck/lint both `src` and `packages/core/src`; `@aqiron/core` is private and exports its TypeScript source. The extension bundles a separate Node Core runtime.

```mermaid
flowchart LR
  UI[VS Code webview] -->|command + payload| VP[Webview provider]
  VS[VS Code commands / extension host] --> SC[Scan controller and services]
  VP --> SC
  SC --> CC[Host-neutral CoreClient]
  CLI[CLI adapter] --> CC
  DESK[Future Desktop adapter] -.-> CC
  CC --> PM[CoreProcessManager / NDJSON transport]
  PM -->|newline JSON over stdin/stdout| RT[CoreRuntime]
  RT --> ORCH[CoreScanService]
  ORCH --> SCAN[Native + registered scanners]
  ORCH --> COR[Correlation + graph]
  ORCH --> REP[ReportGenerator]
  RT --> AI[AI / RAG / project services]
  SC --> LEG[legacy src/security, src/ai, src/rag services]
```

There is a real process boundary, protocol version handshake, request/response correlation by id, event forwarding, timeout cancellation, health check, and configurable crash restart in `packages/core/src/client/coreProcessManager.ts`. It preserves line-delimited JSON on child process stdio. The transport remains local and Node-specific; no networking or alternate wire protocol was added.

### Responsibilities visible today

| Area | Current implementation |
|---|---|
| Client / VS Code host | `src/extension.ts` registers VS Code commands/providers and creates the host-neutral `CoreClient` with extension version, packaged runtime path, and restart policy. `ScanController`, webview provider, VS Code configuration, workspace trust and editor interactions adapt user actions. |
| Core runtime | `packages/core/src/runtime/coreRuntime.ts` constructs Node adapters, scanner manager, RAG/context/AI/report services; dispatches protocol methods; keeps scan/request state. |
| Core domain and orchestration | Core owns scanner registry/manager, native workspace scanning, parsers, finding normalization, correlation/relationship graph, scan event/state types, RAG retrieval/indexing, project detection, AI services, report generation, telemetry. |
| Shared data | `packages/core/src/shared/` contains finding/issue, source-span, scanner, pipeline, AI, RAG, cancellation and platform-port contracts. The extension imports many types directly from `packages/core/src`; these are shared by convention, not through an independently versioned contract package. |
| IPC and host-neutral client | Protocol envelopes and DTOs are in `packages/core/src/runtime/protocol.ts`; typed Core operations are in `packages/core/src/client/coreClient.ts`; process lifecycle/framing/retries/timeouts are in `packages/core/src/client/coreProcessManager.ts`. |
| Scanner-specific | Scanner implementations and their adapters/parsers in Core handle tool invocation, output parsing and findings. `ScannerContext` supplies filesystem, process runner, network, configuration, credentials, logger, cancellation and environment ports. |
| UI-specific | Webview components/state/rendering, command registrations, editor navigation/diagnostics, prompts, settings UI, branch actions, notifications, and translation to/from webview models belong in `src/`. |

### What is already client-independent

**Current:** Core's scanner interfaces and manager; scanner parsing/normalization; `UnifiedFinding`; correlation and graph algorithms; project-profile detection; RAG indexing/retrieval services; AI provider/model/chat/review/analysis services; `CoreScanService`; report model/generator/exporters; event/state contracts. Their domain logic does not inherently require VS Code.

That does not make every current public-looking API ready for a CLI/Desktop client. Some accept local absolute paths and Core runtime currently binds concrete Node adapters. `CoreScanService` receives emitter, scanner manager, report generator, and adapters as dependencies; this is a useful seam, but not yet a stable package/client API. At runtime, `startScan` currently passes `aiAnalysis: undefined`, so the pipeline's optional AI analysis adapter is not wired there.

### VS Code coupling and duplicated paths

- The host-neutral `CoreClient` and its `CoreClientTransport` interface live in `packages/core/src/client`; `CoreProcessManager` implements the interface using Node child processes and the existing protocol types. The private `@aqiron/core` source exports this module; it is not a separately published client package.
- `src/extension.ts`, `src/commands/scanController.ts`, `src/webview/aqironWebviewProvider.ts`, `src/views`, `src/providers`, and diagnostics use VS Code APIs and should remain adapters/presentation.
- Webview types `src/webview/ui/types.ts` contain UI-only values and aggregates (section, zoom, selected threat, chat panel state, setup animation, assets, presentation counts). `WebviewIssue` is a projection of a finding, not the domain finding.
- Core protocol uses filesystem paths and Node runtime metadata. These are environment-neutral in concept but currently assume a local filesystem/workspace and Node transport.
- Core configuration is not yet a coherent cross-client contract: runtime's `projectConfiguration` reads hard-coded JSON paths/keys, while extension configuration is declared in root `package.json` and also read through VS Code. Scanner configuration ports are neutral, but their current provider is Core's JSON lookup.
- The former `src/scanner/WorkspaceScanner` and `scanContent` execution path has been retired. `src/security/pipeline/pipelineEngine.ts` remains the VS Code adapter to Core; `src/scanner/rules.ts` now only resolves portable current-file and custom-rule policy. Some separate AI, RAG, report, analysis, and compatibility types still exist in both `src/` and Core, so do not assume every feature shown in the UI is implemented by Core.
- Protocol version is explicit. Phase 1 now maps each current method to params and results at compile time and validates request envelopes and required parameter shapes before dispatch. The JSON-line wire shape and method names remain unchanged. Result payloads and event payloads still cross JSON as runtime values, and nested domain objects are not fully schema-validated; see [core-implementation-inventory.md](core-implementation-inventory.md).

## Current operations and IPC boundary

The actual runtime dispatch in `CoreRuntime.handle` is the authoritative method list:

| Current IPC method | Classification | Notes |
|---|---|---|
| `core.handshake`, `core.health`, `core.info`, `core.shutdown`, `core.cancel` | Generic Core runtime operations | Lifecycle and request cancellation, not security-domain operations. |
| `project.detect`, `project.profile` | Generic project/domain operations | Uses workspace root; profile result includes detected security signals. |
| `scan.start`, `scan.file`, `scan.cancel`, `scan.status` | Generic security operations | `scan.start` remains the existing workspace pipeline. New `scan.file` is an exact-file operation with explicit content and resolved policy; it does not redirect existing callers. |
| `rag.index`, `rag.status`, `rag.query` | Generic security-context operations | Index request can request AI; query currently builds a minimal profile around the query. |
| `ai.providers`, `ai.models`, `ai.cancel`, `ai.chat`, `ai.review`, `ai.vulnerabilityAnalysis` | Generic AI/security-analysis operations | Provider and model selection are domain/service capabilities; selection settings and UX remain client concerns. |
| `credentials.status`, `credentials.set`, `credentials.delete`, `credentials.exists` | Generic credential service operations | Credential storage implementation is injected/defaulted by the host runtime. Client must own consent and secret-entry UX. |
| `report.generate` | Generic report operation | Accepts findings/correlation/graph/telemetry or a scan id and returns report content. |
| Webview commands such as `focus`, `setZoom`, `ready`, `setupComplete`, `openIssue`, `checkoutBranch`, `createBranch`, `openPolicy`, `openRagSettings` | VS Code/UI-specific | These are not Core IPC. They are handled by the webview provider/host. |
| Webview intent such as `scanWorkspace`, `cancelScan`, `sendChat`, `ignoreIssue`, `exportReport` | UI-to-client interaction | Provider currently dispatches them; Agent `workspace.scan` and `secrets.scan` use generic `scan.start`. Keep the message contract distinct from Core protocol. |

The webview contract is currently `{ command: string; payload?: unknown }`. Provider inbound cases are at `aqironWebviewProvider.ts:356-524`; outbound `postMessage` updates send a large UI state projection. A future client should not implement this contract.

The process manager owns newline framing, pending request map, error decoding, timeouts, cancellation messages, handshake and child-process mechanics. Its request method constrains method/params and derives the response type from the method. Restart policy is supplied by each host and applied by this transport. Core owns method dispatch and security work, with structural validation before handlers. Domain event payloads remain protocol-level; formatting and UI/CLI presentation belong to clients. Event payloads remain loosely typed at the outer transport envelope today.

## Host-neutral Core client boundary

**Current:** the shared Node client lives in `packages/core/src/client/`, beside Core and its protocol contracts:

```text
VS Code host adapter ──┐
                       ├──> CoreClient ──> CoreClientTransport / CoreProcessManager ──NDJSON──> Core runtime
CLI host adapter ──────┘
```

`CoreClient` provides typed Core operations (`health`, `info`, project/RAG operations, scans, AI, credentials and report generation) and forwards protocol events as Core events. `CoreClientTransport`, implemented by `CoreProcessManager`, is the small low-level boundary:

```ts
interface CoreClientTransport {
  start(): Promise<CoreHandshakeResponse>;
  stop(): Promise<void>;
  request<M extends CoreMethod>(
    method: M,
    params: CoreMethodParams[M],
    timeoutMs?: number,
    requestId?: string,
  ): Promise<CoreResultFor<M>>;
  cancel(requestId: string): Promise<{ cancelled: boolean; requestId?: string }>;
  onCoreEvent(listener: (event: CoreEventMessage) => void): () => void;
  on(event: 'log', listener: (message: string) => void): this;
  on(event: 'exit', listener: (event: { code: number | null; signal: NodeJS.Signals | null }) => void): this;
}
```

The concrete client configuration requires `clientVersion`, `runtimePath`, and `restartOnCrash`; optional transport settings are the existing protocol version and request timeout. The transport maps `clientVersion` to the unchanged handshake field `extensionVersion`, and uses the explicitly supplied local runtime path. It retains the existing child process, stdio NDJSON framing, request IDs, typed method/result map, health check, timeouts, cancellation, malformed-message behavior, and crash handling.

VS Code supplies the extension package version, `<extensionPath>/dist/core-runtime.js`, and `restartOnCrash: true`; it owns extension activation/disposal, workspace trust, settings, editor/workspace state, diagnostics, notifications and presentation. The CLI supplies its bundled runtime path and `restartOnCrash: false`; it owns OS signals, CLI flags, output formatting, artifact destinations and exit codes. Both clients choose their own metadata and restart policy. The shared client imports no `vscode` module and contains no scanner or presentation logic.

This boundary exists so another host can use the same typed protocol and process mechanics without importing `src/core` or duplicating IPC. It is a source module inside the existing private Core package, not a new package or published API.

**Near-term:** if a third client needs it, document a package subpath and compatibility policy for the existing private source exports. Keep host policy at constructors/adapters and keep Core events unmodified until each host presents them.

**Future Desktop:** a Desktop adapter can construct the same client with its version, packaged Core runtime path, and lifecycle/restart choices. Window state, dialogs, credentials UX, workspace permissions and presentation remain Desktop responsibilities.

## Finding, report and configuration contracts

### Current types

- `UnifiedFinding` in `packages/core/src/shared/finding.ts` is the strongest existing domain contract: identity/fingerprint, severity, CWE/OWASP, CVSS, location, source tool/rule, confidence, remediation, tags, evidence, graph metadata, lifecycle status and risk score.
- `AqironIssue` and `AqironScanResult` in `shared/issue.ts` are another finding/result shape; `findingToIssue` and `issueToFinding` convert between shapes. Keep one canonical domain representation eventually and use client projections at edges.
- `SecurityReportModel` / `SecurityReportContent` in `reports/reportModels.ts` are Core-side report contracts. They include findings, correlation summary, graph, telemetry, text, SARIF and a PDF string. Paths, save dialogs and report destination are host concerns; rendered formats are export representations.
- `ScannerContext`, `ScannerMode`, `ScannerResult`, `ScanState`, `PipelineEvent`, `ProjectProfile`, `SecurityContext`, `RagIndexData`, AI request/result types and report model are candidates for shared contracts.
- Root extension settings (quick fixes, excludes, realtime behavior, size limits, MobSF endpoint/credential and custom rules) and Core's configuration lookups are not yet one validated portable configuration model.

### Recommendation

**Near-term:** document and validate a single versioned contract surface within this repository; keep file paths, scanner options and evidence formats explicit. Model client settings separately from Core security configuration, then pass resolved configuration into Core via a documented request/adapter. Keep secrets out of ordinary configuration and use a credential-store port.

**Future:** a finding should continue to mean a detected security issue. Research workflow concepts should be separate records linked by stable ids: hypothesis, evidence item, provenance/source, controlled validation result, confidence assessment, investigation state and human review. A confirmed hypothesis may cite or propose findings, but must not silently mutate the existing finding's meaning/status. See the future engine boundary below.

## Proposed Core API boundary

The following is a **Near-term Core service-boundary proposal**. The host-neutral client/NDJSON transport above is implemented; this section concerns later separation of domain services from runtime dispatch, not a replacement client API.

| Capability | Existing demonstrated operation | Boundary direction |
|---|---|---|
| Runtime lifecycle | `core.handshake/health/info/shutdown/cancel` | Keep transport/lifecycle envelope outside security application service. |
| Project context | `project.detect/profile` | Keep profile detection in Core; accept an explicit workspace descriptor and configuration. |
| Scanning | `scan.start/cancel/status`, `CoreScanService.run`; new `scan.file` | Core owns workspace orchestration as before. The new file operation scans exactly the supplied path/content and returns `UnifiedFinding[]`; client adapters still resolve policy and present results. |
| Findings | Finding converters and Core finding model | Use canonical finding DTOs and client-side projections; define schema/version and stable ids. |
| AI/RAG | Existing AI/RAG dispatch and services | Core owns retrieval/index/query and finding analysis/review; clients own provider choice UX, prompts as user interaction, consent, and display. Provider configuration/credential policy remains explicit. |
| Reports | `report.generate`, `ReportGenerator` | Core owns report model and format generation. Client owns file chooser, destination, reveal/share actions and any UI-specific naming flow. |
| Credentials | credential IPC | Keep secret storage behind a port; each host supplies a secure store and client UI manages input/consent. |

Do not prematurely add a large facade or new public method inventory. First align Core runtime behavior with existing types and determine which current APIs are actually used by the extension.

## Data flow

```mermaid
sequenceDiagram
  participant C as Client interaction
  participant A as Client adapter
  participant T as IPC transport
  participant K as Aqiron Core
  participant S as scanner / AI / RAG services
  participant D as domain result
  C->>A: User asks for scan and selects scope
  A->>T: scan.start request + resolved options
  T->>K: typed request envelope
  K->>S: orchestrate scan with ports and cancellation
  S-->>K: scanner results / normalized findings
  K-->>T: progress and domain events
  T-->>A: events correlated to request/scan
  K->>D: correlate, build graph, generate report
  K-->>T: final scan result
  T-->>A: result + events
  A-->>C: present results in client-native UI
```

**Current caveat:** workspace scan events include pipeline progress, some of which is presentation-shaped (`tool`, `log`, stages). Workspace scan identity is canonicalized by `CoreScanService`. The new file operation emits only start/completion metadata and uses the IPC request id as its scan id. See [file-scan-contract.md](file-scan-contract.md) for its limits and migration status.

## Future client boundaries

### VS Code

VS Code owns command palette and editor commands, active-file/workspace selection, workspace trust interaction, diagnostics/quick fixes, tree/webview presentation, notifications, opening source locations, branch/Git actions, settings UI, and choosing export destinations. It adapts these inputs to Core requests and maps Core events/results to VS Code views. It should not own scanner execution, parser rules, correlation semantics, AI analysis, RAG retrieval or report model generation.

### Agent workspace scan migration

**Current:** Agent tool selection, summary wording, commands, state and UI projection remain in `AqironWebviewProvider`. Both `workspace.scan` and `secrets.scan` use generic `CoreClient.startScan` (`scan.start`) with the first workspace root and actual `vscode.workspace.isTrusted`; the adapters preserve the Flutter host gate and forward only request-correlated Core progress. `secrets.scan` resolves and sends `ResolvedWorkspaceScanPolicy`, disables external scanners to retain its local-rule scope, then performs its case-sensitive secret-ID filtering, issue projection, merge, five-location summary cap and existing webview redaction at the Agent edge. See [agent-workspace-scan-migration.md](agent-workspace-scan-migration.md) for differences and remaining parity caveats.

### Aqiron CLI adapter

**Aqiron CLI:** `packages/cli/src/cli.ts` implements `scan <path>` with required `--trust-local-workspace`, `--format text|json|sarif` (text default), `--output <path>`, and `--fail-on critical|high|medium|low`. It validates the workspace directory and calls existing `CoreClient.startScan` / `scan.start` (`deep`, `trusted: true` only after the explicit flag). Text output summarizes actual Core findings and emitted stage names/statuses. JSON uses a documented versioned envelope around Core's existing report model; SARIF uses the existing `report.sarif`. Files are created exclusively, never overwritten. Exit status is 0 for a successful scan without a violated threshold, 1 for runtime/startup/scan/cancellation/output failure or threshold violation, and 2 for invalid usage or input.

The CLI imports `CoreClient` from `packages/core/src/client`, with no VS Code API or scanner imports. The build emits `dist/aqiron-cli.js` beside `dist/core-runtime.js`; the CLI explicitly supplies that runtime path and disables automatic restart so startup/runtime failures surface directly. Signals call existing Core request cancellation and the client is stopped in cleanup. See [Aqiron CLI](cli-prototype.md) for arguments, JSON shape, build invocation, exit semantics, and limitations.

This is a practical repository client, not a fully packaged production CLI: no npm publication or suitable GitHub Actions workflow exists yet. Future CI integration can use GitHub Actions → Aqiron CLI → Aqiron Core → SARIF once invocation and distribution are reliable. Configuration files, CI annotations, and policy frameworks remain future work.

### Future Desktop

The future desktop shell owns window lifecycle, navigation, assessment/project selection UX, local permissions and secure credential UI, result presentation, export dialogs, and client-specific persistence such as recent projects. It invokes the same Core security operations. Desktop-only interaction state must not become part of finding or scan-domain types.

## Future security-research engine boundary

**Future only; no autonomous exploitation or offensive engine is implemented or proposed here.** Place this workflow beside the existing finding pipeline as a separate, policy-gated investigation capability:

```mermaid
flowchart LR
  F[Observation: finding or user input] --> H[Security hypothesis]
  H --> E[Evidence collection with provenance]
  E --> V[Controlled validation under explicit scope]
  V --> R[Confirmed / rejected / inconclusive]
  R --> HR[Human review and disposition]
  R -. may reference .-> F
```

An investigation aggregate can own hypothesis text, scope/constraints, linked observations, evidence records, provenance (tool/source, timestamp, version, location, integrity metadata), validation plan/result, confidence with rationale, state and human decision/audit trail. Evidence should be append-only or revisioned with provenance; validation must record whether it ran and its bounded result. Keep this separate from `UnifiedFinding`: findings remain scanner/analysis results with their present lifecycle; investigations reference findings and can produce reviewed findings through an explicit domain operation later. Authorization, target scope, safe validation rules and human approval belong at an explicit policy boundary, not inside an ordinary scan.

## State placement

**Current UI/client state:** selected section/threat, zoom, setup animation, active chat/session UI, filters, assets, transient notification/panel state, provider/model selection controls and webview serialized state. These remain client-owned.

**State with eventual Core/domain ownership:** authoritative scan execution status and cancellation (already partly in Core's `scans` and protocol), scan results/history and stable scan identity, finding triage/status and ignore rules when those must be consistent across clients, project profile/index manifests, RAG index status, report metadata, AI analysis records, and future investigation/evidence/audit state. Today ignored findings, threat snapshots, chat histories, settings and report artifact paths are largely in VS Code/provider/workspace storage. Promote only state that must be shared or reproducible; keep view selections and presentation caches client-side.

## Migration strategy

1. **Current / in-place contract:** `scan.file` now establishes exact-file and in-memory-content semantics without changing `scan.start` or redirecting callers. See [file-scan-contract.md](file-scan-contract.md).
2. **Near-term / in-place:** inventory duplicate `src/security` vs Core code paths and call sites; identify the active implementation per feature. Agree canonical finding/report/configuration contracts and compatibility/version policy for any future public client API.
3. **Near-term / adapter cleanup:** make extension host resolve workspace/config/trust/credentials and pass explicit portable options; keep VS Code command and webview contracts in adapters. Route one feature at a time through Core only where this does not change behavior; remove duplication only after usage and tests confirm the Core path is authoritative.
4. **Current client boundary:** VS Code and CLI use `packages/core/src/client` with the existing typed NDJSON protocol. **Near-term:** publish no new package until a release/distribution requirement is established. **Future Desktop:** provide host metadata, runtime location, restart choices and window lifecycle in a Desktop adapter.
5. **Future / research capability:** design separate hypothesis/evidence/investigation records and policy/review lifecycle. Keep it out of the current finding model and scanner pipeline until separately specified.

## Explicitly do not refactor yet

- Do not build Desktop or publish an npm package as part of this boundary extraction.
- Do not split the repository or publish `@aqiron/core`.
- Do not rewrite Core or merge duplicate implementations wholesale.
- Do not change scanner ordering, modes, parsers, or unrelated rules/defaults/findings.
- Do not migrate UI settings or persistence without a cross-client ownership decision.
- Do not turn webview message names into Core protocol methods.
- Do not add autonomous exploitation, validation actions, or an offensive engine.
- Do not expand the finding model with hypothesis/evidence/investigation lifecycle fields.
- Do not treat every existing Core IPC method as a stable public API until schemas, compatibility and host adapters are validated.

### Deterministic secret rules

**Current:** Core's native scanner includes deterministic secret rules with the legacy IDs `critical.api-key`, `critical.secret`, `critical.password`, and `critical.private-key`. They are shared by Core workspace scans and `scan.file`, use the characterized legacy patterns/case behavior, and emit source locations plus safe metadata without copying the matched source line into finding evidence. The previous Dart-only rule remains as a fallback for shorter literals outside those patterns. Adjacent native findings on a matching line also omit raw line evidence.

**Agent migration:** Agent `secrets.scan` now invokes Core `scan.start`; its policy-aware native workspace path detects the characterized seven patterns. Agent filtering, state merge, summary limit, and webview redaction remain in the VS Code adapter. The pre-existing Core Dart short-literal rule can add findings through the unchanged `secret` substring filter; count/cache/enumeration parity with the previous VS Code traversal is not guaranteed. External scanners are disabled for this operation. See [Agent workspace scan migration](agent-workspace-scan-migration.md).

### Workspace policy parity in progress

**Current:** `ResolvedWorkspaceScanPolicy` is a portable request contract used by Agent `secrets.scan`. The VS Code adapter resolves supported extensions, custom rules, exclusions, `.aq` rules, generated/minified/compiled choices and byte-size limit; Core validates and enforces those values in native workspace traversal. Workspace existence, first-folder selection, Flutter eligibility and workspace trust are host decisions, not policy fields. Trust remains a separate actual host boolean and is not currently an enforcement policy.

**Remaining parity work:** policy-aware `scan.start` is used only by the migrated Agent secret operation; existing workspace scans omit policy and retain the prior path behavior. Core enumeration and file-count/cache semantics differ from the former VS Code scanner, and Core's older Dart short-literal secret rule may add a secret-filtered finding. See [Agent workspace scan migration](agent-workspace-scan-migration.md).
