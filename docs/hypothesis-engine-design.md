# Aqiron Hypothesis Engine: Architecture and Repository Audit

## 1. Executive summary and scope

This document designs a first version of a project-scoped Hypothesis Engine owned by Aqiron Core and consumable through the shared Core protocol. It is an architecture proposal only. No runtime, client, persistence, or UI code is changed by this design.

A hypothesis is a traceable, falsifiable, evidence-backed security proposition that still requires investigation. It is not a scanner finding and is never a confirmed vulnerability merely because an AI model proposed it. Only a separate explicit validation workflow, backed by validated evidence and an authorized security review, may create or link a confirmed `UnifiedFinding`.

The recommended first release has deterministic snapshot construction, evidence normalization, correlation, reference validation, deduplication, lifecycle transitions, persistence, and confidence calculation. AI is an optional candidate synthesizer over a bounded, redacted snapshot. AI does not assign authoritative confidence, create evidence, run tools, or mutate findings. Without AI, Core can still emit deterministic hypotheses from supported correlation relationships, but should return no candidate where the evidence is insufficient.

## 2. Existing architecture and reusable contracts discovered

### Authoritative layers

- `packages/core/src/shared/finding.ts` defines `UnifiedFinding`, `createFinding`, `createFingerprint`, `calculateRiskScore`, and `findingToIssue` / `issueToFinding`. `UnifiedFinding` carries `id`, title/description, `severity`, CWE/OWASP, optional CVSS and end range, `file`, one-based `line` / `column`, `sourceTool`, `ruleId`, categorical `confidence`, remediation, tags, `rawEvidence`, graph metadata, fingerprint, status (`Open | Triaged | Ignored | Fixed`), and `riskScore`.
- `packages/core/src/shared/issue.ts` defines `AqironIssue`, `AqironScanResult`, `AqironSeverity`, `AqironConfidence`, source tools, and graph metadata. `packages/core/src/shared/sourceSpan.ts` defines zero-based `SourceLocation`. The adapters translate between one-based finding coordinates and zero-based issue ranges. A hypothesis evidence reference must document its own coordinate convention and must not assume all incoming `rawEvidence` has a stable schema.
- `packages/core/src/orchestration/coreScanService.ts` owns `CoreScanService.run`: native scan, optional external scanners, optional AI analysis, `ThreatCorrelationEngine`, `RelationshipGraphEngine`, report generation, cancellation checks, and pipeline events. Workspace scan results are returned and retained in the runtime map; `scan.start` does not itself write a finding store.
- `packages/core/src/scanners/scannerManager.ts`, `packages/core/src/scanners/native/nativeScanner.ts`, and scanner implementations under `packages/core/src/scanners/` perform scanning. Native and Semgrep rules are separate mechanisms; custom rules are represented by `WorkspaceCustomRule` and loaded from `.aqiron-security/custom-rules.json` by `WorkspaceRuleStore` (`packages/core/src/shared/workspaceRules.ts`).
- `packages/core/src/project/projectDetector.ts` and `projectProfile.ts` provide deterministic project detection/profile data. `ProjectProfile` includes project types, languages, frameworks, platforms, services, authentication, databases, storage, dependency managers, native code, CI/CD, sensitive files, network clients, endpoints, security signals, and dependencies. The detector bounds candidate files and excludes `.aqiron-security`, generated and build directories.
- `packages/core/src/correlation/correlationEngine.ts` defines `ThreatCorrelationEngine`, `CorrelationResult`, and `CorrelatedRelationship`. It deduplicates findings and builds `same-file`, `secret-to-dependency`, `dependency-to-source`, `malware-to-artifact`, and `attack-path` relationships with weights and reason text. Its present `attack-path` condition is a coarse heuristic: presence of a secret, high/critical SAST, and a dependency can produce one relation; it does not prove data flow or reachability. Reuse relation inputs and rationale, but do not treat current weights/labels as proof or use severity boosting as hypothesis confidence.
- `packages/core/src/correlation/relationshipGraph.ts` defines `RelationshipGraphEngine` and `SecurityGraph`; graph edges support evidence and correlation visualization. This graph is useful as snapshot context, not evidence that an exploit path exists.
- `packages/core/src/context/securityContextBuilder.ts`, `packages/core/src/rag/ragIndexService.ts`, and `packages/core/src/rag/ragRetrievalService.ts` provide bounded source selection, secret-redacted excerpts, project profile context, indexed chunk retrieval, signal IDs, relative paths and line ranges. `RagIndexService` writes `.aqiron-security/index.json` (plus `vectors.json` via `RagVectorService`) with temporary-file rename. Retrieved RAG text is context, not validated evidence by itself.
- `packages/core/src/ai/services/aiService.ts`, `providerRegistry.ts`, `modelManager.ts`, `credentialService.ts`, and `packages/core/src/runtime/coreRuntime.ts` provide existing provider/model selection, stored credential access, and `ai.chat` handling. Providers currently include OpenRouter, OpenAI, Claude, and Gemini. `resolveChatGenerationPolicy` is used for model-aware request options. Hypothesis generation should use this Core path and never expose credential values to clients or prompts.
- `packages/core/src/ai/analysis/aiVulnerabilityAnalysis.ts` has an existing AI-analysis contract (`AIAnalysisResult`) and response parser/validator. It accepts `baselineFindings`, constructs context and RAG retrieval, and maps AI drafts to `UnifiedFinding` with `sourceTool: 'AI Analysis'`. This is a separate behavior, not a hypothesis store or lifecycle. Reusing its context/redaction ideas is appropriate; calling `validateFindings` or converting model proposals to `UnifiedFinding` for the new engine is not.
- `packages/core/src/shared/recommendations.ts` offers structured response parsing, bounded fields, rejection diagnostics, and rejection of reasoning-like output. `CoreRuntime.indexRag` invokes recommendation generation and writes `.aqiron-security/suggestions.md`; recommendations are separate and should not be modified or reused as hypothesis persistence.
- `packages/core/src/reports/reportGenerator.ts` builds `SecurityReportModel` from confirmed `UnifiedFinding[]`, correlation, graph, and telemetry. `report.generate` can use scan results or passed findings. `.aqiron-security/reports/` is where `workspace.reports.get` discovers existing artifacts. The first release must keep hypotheses out of SARIF/findings/remediation plans unless explicitly labeled in a future report section.

### Runtime protocol and shared clients

- `packages/core/src/runtime/protocol.ts` defines `CORE_PROTOCOL_VERSION = 1`, `CoreMethodParams`, `CoreMethodResults`, request/response/event envelopes, and operations including `project.detect`, `project.profile`, `workspace.rules.get/set`, `workspace.threat-history.get/delete`, `workspace.recommendations.get`, `rag.index/status/query`, `scan.start/file/cancel/status`, AI methods, and `report.generate`. Adding hypothesis methods requires typed parameter/result entries and runtime validation/dispatch. A protocol version bump is a compatibility decision; the current handshake checks compatibility.
- `packages/core/src/runtime/coreRuntime.ts` owns dispatch, injected filesystem/process/network/credential adapters, active-request cancellation, scan lifecycle, AI handling, and workspace-scoped operations. `core.cancel` already cancels by request ID; `ai.cancel` is session-based. Use the normal request-ID cancellation path for hypothesis generation.
- `packages/core/src/client/coreClient.ts` is the host-neutral typed client over `CoreProcessManager`. It wraps workspace history, rules, RAG, scans, AI and reports. `packages/core/src/client/coreProcessManager.ts` transports newline-delimited JSON, assigns request IDs, enforces timeouts, sends `core.cancel` after timeout, and forwards correlated Core events. This is the intended client seam.
- `packages/desktop/src/main.ts` dispatches a hand-maintained `DesktopMethod` allowlist to `CoreClient`; `apps/desktop/src-tauri/src/main.rs` has a separate allowlist and injects the selected project root into workspace calls. `apps/desktop/src/desktopAdapter.ts` binds those operations to current webview state. Hypothesis methods require additions at both bridge allowlists and a typed CoreClient wrapper. Keep engine and persistence in Core; Rust should forward scoped requests only.
- `packages/cli/src/cli.ts` currently provides `aqiron scan <path>` with text, JSON, SARIF, and PDF output through Core `scan.start`; its `CliCoreClient` currently specifies only `startScan`, cancellation, and lifecycle. A future hypothesis CLI command should call the same Core methods and serialize their typed result, preserving confirmed findings and hypotheses as distinct top-level objects.
- `src/` contains the VS Code extension and webview plus legacy/shared client-facing types. It has its own `src/security/threatHistoryService.ts` using `.aqiron-security/threats.json`; Core has a separately implemented history reader/deleter for that file. New hypothesis state should be accessed through Core, not a React/webview/extension-owned store.

### Persistence, abstractions, and existing tests

Workspace state lives under `<workspace>/.aqiron-security/`. Existing files include `threats.json`, `custom-rules.json`, `agent-sessions.json`, `suggestions.md`, `index.json`, `vectors.json`, and `reports/`. `agent-sessions.json` is `{ version: 1, sessions: [...] }`, validated and sanitized by Core. `custom-rules.json` is `{ version: 1, rules: [...] }`. RAG's `index.json` uses a versioned manifest. `CoreRuntime.saveWorkspaceAgentSessions`, `WorkspaceRuleStore`, `RagIndexService.persistIndex`, and Core threat-history deletion use temporary files plus rename. Existing conventions are JSON and atomic-replacement intent, although not every writer uses atomic rename. Do not overwrite these files.

There is no dedicated existing hypothesis, vulnerability triage, or hypothesis lifecycle abstraction. The `ThreatCorrelationEngine` attack-path relation is the closest relationship abstraction; `UnifiedFinding.status` is finding triage only; `threats.json` is scan history only. None should be overloaded to store generated hypotheses. `CoreRuntime` already tracks `activeRequests`, rejects duplicate active request IDs, propagates cancellation, and validates runtime requests. `CoreClient.startScan` supplies one request ID to response/events; `src/test/coreScanIdentity.test.ts` covers request/event identity and concurrent scan isolation.

Relevant tests include `src/test/coreProtocol.test.ts`, `coreRuntime.test.ts`, `coreClient.test.ts`, `coreProcessManager.test.ts`, `coreModules.test.ts`, `coreScanners.test.ts`, `coreFileScan.test.ts`, `coreProjectRag.test.ts`, `coreScanIdentity.test.ts`, `coreSecretParity.test.ts`, `coreAi.test.ts`, `aiVulnerabilityAnalysis.test.ts`, `rag.test.ts`, `recommendations.test.ts`, and `desktopFindings.test.ts`. They establish protocol validation, provider behavior, redaction, malformed AI response handling, project isolation for RAG/recommendations, rule persistence/application, finding correlation, and cancellation. `coreRuntime.test.ts` tests workspace reads without implicitly scanning and recommendation preservation after invalid model output.

## 3. Domain model and lifecycle

### Distinct concepts

- **Observed evidence** is an immutable, project-scoped observation captured from a specific source and snapshot. Examples: scanner finding ID, a `CorrelatedRelationship` ID derived from endpoints/type, indexed signal ID, or verified source span/hash. It is not a security conclusion.
- **Existing scanner finding** is a `UnifiedFinding` emitted by deterministic/native/external scanning (and, under current behavior, possibly the separate AI analysis). It remains in the finding namespace and keeps its own status.
- **Generated hypothesis** is a falsifiable explanation connecting cited observations to a suspected weakness or attack path. State `proposed` means unconfirmed. Store evidence references and a short evidence rationale, never hidden chain-of-thought.
- **Hypothesis under investigation** uses `investigating` triage; this does not change finding status or confidence.
- **Confirmed or rejected hypothesis** is a lifecycle outcome. `validated` requires validated supporting evidence and an explicit actor/action; `rejected` includes a concise reason and optional contrary references. `dismissed` is a user decision, not proof that the claim is false.
- **Confirmed vulnerability/finding** remains a distinct `UnifiedFinding`, created only by an explicit validation operation and linked back to `hypothesisId`. First release may allow marking a hypothesis validated and linking an existing finding. Creation of a new finding needs a separately specified validated payload/rule/source policy and must not be implicit AI promotion.

### Proposed minimal model (new Core contract)

```ts
interface SecurityHypothesis {
  id: string; // stable ID from project identity + normalized claim + evidence keys
  title: string;
  description: string;
  weakness?: string;                 // CWE/category when supported
  attackPath?: string;               // concise proposition, not proof
  asset: { kind: 'file' | 'dependency' | 'service' | 'project'; id: string; label?: string };
  evidence: HypothesisEvidenceRef[];
  rationale: string;                 // evidence-to-conclusion summary, not chain-of-thought
  confidence: { score: number; label: 'low' | 'moderate' | 'high'; basis: ConfidenceFactor[] };
  assumptions: string[];
  contradictions: HypothesisEvidenceRef[];
  impact?: string;
  verificationSteps: string[];
  status: 'proposed' | 'investigating' | 'validated' | 'rejected' | 'dismissed' | 'stale' | 'unsubstantiated';
  createdAt: string;
  updatedAt: string;
  snapshotId: string;
  relatedFindingIds: string[];
  relatedRuleIds: string[];
  relatedHypothesisIds: string[];
  triage?: { updatedAt: string; actor: 'user' | 'system'; note?: string };
  validatedByFindingId?: string;
}
```

All fields without `?` are required; fields marked `?` are optional. `score` is a bounded coarse display value, preferably integer 0–100, with `basis` describing components and missing signals. The implementation can use `confidenceBand` alone if product wants to avoid numeric precision. Avoid raw source excerpts in each hypothesis; evidence references point into the immutable generation snapshot, which may contain redacted excerpts.

Proposed transitions: `proposed` → `investigating` / `dismissed` / `rejected`; `investigating` → `validated` / `rejected` / `dismissed`; any nonterminal status → `stale` on invalidation. Stale can return to investigation only after evidence refresh. `validated` and `rejected` are terminal for that hypothesis version; new generation creates a successor if evidence changes. A matching regenerated stable key preserves `investigating` or `dismissed` unless the user explicitly reopens it.

## 4. Evidence model

Proposed evidence reference:

```ts
interface HypothesisEvidenceRef {
  id: string; // snapshot-local key: finding:<id>, relation:<key>, span:<path>:<lines>:<hash>
  kind: 'finding' | 'relationship' | 'source-span' | 'project-signal' | 'rag-chunk' | 'dependency';
  source: string; // verified scanner/rule/component identifier
  file?: string; // project-relative, normalized with `/`
  startLine?: number; // one-based when present
  endLine?: number;   // one-based inclusive when present
  contentHash?: string;
  findingId?: string;
  ruleId?: string;
  relationshipId?: string;
  excerpt?: string; // optional, redacted and bounded in generation snapshot only
  observedAt: string;
  freshness: 'current' | 'stale';
}
```

A Core-built immutable snapshot contains stable `snapshotId`, canonical workspace identity, generation time, current scan ID if any, fingerprint of included normalized evidence, finding IDs/summaries, allowed relationships, project profile hash, relevant source-span hashes and bounded redacted snippets, and optional RAG IDs. Resolve every candidate reference against this manifest. Paths must be relative and traversal-safe; line ranges must fall within captured spans; finding/rule/relationship IDs must exist in the snapshot. A model supplied file/line alone is never evidence.

RAG excerpts and project profile signals may guide selection, but a hypothesis should require at least one strong direct reference (validated finding or exact hashed source span) and may use RAG/project signals only as support. Current RAG chunks are 80-line chunks with score and signal IDs; that granularity is insufficient alone to substantiate a specific line-level vulnerability. Record contradictory evidence only when a snapshot reference exists. Missing contrary signals are not proof of absence.

## 5. Proposed pipeline

1. **Capture a consistent project-scoped snapshot (deterministic).** Accept only explicit `workspaceRoot`; use an explicitly supplied or queryable completed scan result. Do not call `scan.start`, `rag.index`, or execute project code. If no scan exists, generation may use only an explicitly defined read-only observation collector; otherwise return `no-evidence`. First release should require existing scan findings plus selected source corroboration for claims beyond those findings.
2. **Normalize and correlate observations (deterministic).** Reuse `ThreatCorrelationEngine` outputs as candidate edges with conservative predicates. Preserve relation type/reason/weight as heuristic signals. Require explicit endpoint references; do not infer data flow from `same-file`, tag co-occurrence, or visualization alone.
3. **Generate deterministic candidates (deterministic).** Convert supported high-value relations and selected finding-plus-source patterns into candidates with explicit evidence IDs and assumptions. This path works without AI.
4. **Synthesize additional candidates with AI only when configured and useful.** Pass a bounded snapshot of redacted, labeled untrusted data and validated reference IDs. Require strict structured candidates. AI cannot create IDs, spans, findings, confidence labels, or tool observations.
5. **Validate output against snapshot (deterministic).** Parse typed JSON; reject malformed/empty/reasoning-only results, unknown references, unsupported paths, invalid lengths/enums, fabricated locations, and claims unsupported by cited evidence. Reject as `unsubstantiated` or omit with safe diagnostics; never repair missing evidence by accepting prose.
6. **Deduplicate and rank (deterministic).** Stable key from normalized weakness, affected asset, and canonical evidence IDs. Merge only evidence-compatible candidates; retain provenance and a concise rationale. Rank by deterministic confidence factors, sourced impact category, then stable ID for ties.
7. **Persist accepted records through Core (deterministic).** Under workspace-scoped serialization, atomically merge generation output while preserving triage and unrelated records. Cancellation/failure leaves prior valid store untouched.
8. **Return typed records and diagnostics.** Report generation/snapshot IDs, accepted/deduplicated/rejected counts and safe reason codes, AI availability status without secrets, and records. Events may report start/progress/complete/failure correlated to request ID.

A partial pipeline may return validated deterministic results plus `ai-unavailable` or `ai-invalid-output` diagnostics if persistence semantics are clear. Snapshot or persistence failure must not persist partial unvalidated records. AI errors do not erase prior hypotheses.

## 6. Confidence and prioritization

Do not reuse `UnifiedFinding.confidence` as calibrated probability, and do not use model-generated numeric confidence. Existing `calculateRiskScore` combines finding severity, categorical confidence, and CVSS; it is a finding risk score, not hypothesis confidence.

Use three confidence bands and optionally an integer score only if calibration data supports it. Deterministic factors:

- **Evidence quality:** strong for a current scanner finding or exact source span with content hash; moderate for structured dependency metadata or a specific graph relation; weak for project profile/RAG-only context.
- **Independent corroboration:** count distinct source families/rules, not duplicate findings from one source. A correlation relation repeating endpoint findings is not independent evidence.
- **Reachability:** measured only with verified call/data-flow/usage signals. Current `dependency-to-source` tags and `attack-path` heuristic are weak signals, not proof.
- **Asset/impact:** copy sourced asset category and finding severity/CVSS as context; do not independently upgrade. AI may summarize plausible impact but cannot raise evidence score.
- **Exploit preconditions:** deterministic only where represented in a source. Unknown means unknown.
- **Contradictions/freshness:** current contradiction lowers the band; stale/hash-mismatched references mark stale or unsubstantiated and remove the item from current ranking.

Missing values are conservative and explicitly listed in `basis`; absent reachability/precondition data must never increase confidence. Score is an ordinal ranking aid, not a probability. Freeze a factor table before implementation; test monotonicity (independent current evidence cannot lower score; contradictions cannot raise it); calibrate bands against manually adjudicated examples. Version scoring policy so old scores remain interpretable.

## 7. Persistence and migration

Proposed location: `<workspaceRoot>/.aqiron-security/hypotheses.json`, adjacent to existing Core workspace JSON stores. It does not overwrite `threats.json`, `custom-rules.json`, `agent-sessions.json`, `suggestions.md`, `index.json`, `vectors.json`, or reports. Proposed envelope:

```json
{
  "version": 1,
  "scoringPolicyVersion": 1,
  "updatedAt": "...",
  "hypotheses": [],
  "snapshots": []
}
```

Keep snapshot metadata/evidence references sufficient to validate current records; bound retained snapshot history and avoid copying raw source contents into long-lived storage. Store stable IDs derived from canonical project-relative evidence keys and normalized claims, with version/update timestamps where evidence membership changes.

On load, validate envelope and every record. Missing is empty. Corrupt/unsupported data returns a typed Core storage error and preserves the file for recovery; do not silently replace it with empty data. Migrations are explicit, pure, sequential (`v1`→`v2`), fixture-tested, and preserve a backup or original until atomic replacement succeeds. Existing files need no migration because this is a new file.

Write to a unique temporary sibling, flush where supported by the current `FileSystem` abstraction, then rename atomically. The abstraction has `writeFile`/`rename` but no fsync or exclusive-create primitives; decide whether first release accepts process-level atomic replacement or adds narrow adapter support. Serialize read/merge/write per canonical root in Core. Duplicate request IDs are guarded, but distinct simultaneous generation IDs need a per-workspace lock or revision check. A revision/fingerprint check before rename prevents stale generation from overwriting newer triage. Recover orphan temp files conservatively; never treat them as committed.

Compare evidence IDs and source hashes to the new snapshot. New scans do not silently rewrite validated records; mark affected open hypotheses stale and preserve triage/history. A matching regenerated stable key refreshes evidence/timestamps while preserving `investigating` or `dismissed`; validated/rejected records remain historical and link to successors.

## 8. Core API/protocol proposal

The following are **proposed additions**, not existing operation names:

- `hypotheses.generate`: `{ workspaceRoot, scanId?, requestId?, includeAi?: boolean }` → `{ generationId, snapshotId, status, hypotheses, diagnostics }`. Explicitly consumes an existing scan when supplied; omission may use only a documented latest completed Core scan for the same canonical root. Never starts a scan or RAG indexing implicitly.
- `hypotheses.list`: `{ workspaceRoot, status?, includeStale?: boolean }` → `{ hypotheses, storeVersion }`.
- `hypotheses.get`: `{ workspaceRoot, hypothesisId }` → `{ hypothesis }` or typed not-found.
- `hypotheses.triage`: `{ workspaceRoot, hypothesisId, action: 'investigate' | 'dismiss' | 'reopen', note? }` → `{ hypothesis }`.
- `hypotheses.validate`: `{ workspaceRoot, hypothesisId, outcome: 'validated' | 'rejected', evidenceRefs, note?, findingId? }` → `{ hypothesis, linkedFindingId? }`. First release supports validation by linking an existing `UnifiedFinding`, or a separately approved deterministic workflow. AI text alone cannot promote a finding.

Do not add `hypotheses.status` unless generation becomes asynchronous/background. Current Core operations are request/response promises with streamed events; first version can return one result with progress events and standard cancellation. Add types to `CoreMethodParams`/`CoreMethodResults`, dispatch and validators in `coreRuntime.ts`, and wrappers in `CoreClient`. Increment `CORE_PROTOCOL_VERSION` only if compatibility policy requires it; it is currently 1.

Scope every operation with `workspaceRoot` and verify ownership in Core. Each request captures root and snapshot ID; a client discards results if selected project root/epoch changed. Cancellation uses request ID through `core.cancel`; cancellation before atomic persistence aborts without replacing prior state. Errors use stable codes and safe messages without excerpts/secrets.

## 9. AI integration and failure handling

Use existing Core provider/model selection and `AIService`; do not add credentials or provider settings. AI use is optional and explicit. Use a hypothesis-specific prompt/schema rather than `ai.vulnerabilityAnalysis`, whose current output is transformed into findings. Reuse model resolution, timeout/retry, cancellation, provider error mapping, and secret redaction patterns.

Every workspace excerpt, comment, manifest, lockfile, README/doc, or RAG chunk is untrusted. Delimit it as quoted evidence with source IDs, state that it cannot change instructions, and never concatenate it into system instructions. Exclude credential values and redact secrets before provider transmission. Secret findings carry redacted metadata; never send literal values. Provide product-level privacy disclosure/setting before provider transmission; existing scan `trusted` is not consent to upload workspace content. Do not log prompt text, excerpts, credentials, or raw model output.

Malformed/empty/reasoning-only responses produce zero AI candidates and safe diagnostics. Unknown references are rejected. Provider unavailable yields deterministic-only output. Timeout/cancellation before commit preserves old store. AI verification steps are never executed. Constrain them to safe manual review instructions; reject shell payloads or commands that modify/delete data, run project scripts, access networks, or expose secrets. Generation must not invoke scanner binaries, package scripts, builds, tests, or other project code and must not edit project files.

## 10. Security and trust boundaries

- Core validates inputs, snapshot references, transitions, workspace isolation, and persistence. Client mutations are untrusted.
- Prompt injection may appear in source comments, dependency metadata, docs, RAG chunks, and custom rules. Treat them as data. Deterministic validators decide acceptance.
- AI cannot add a file, line, dependency, scanner result, finding, rule, or relationship. Every item resolves against the snapshot.
- Reject unsupported cross-file/component claims unless explicit supported relationship evidence connects endpoints. Current tag-based edges and `same-file` relation do not prove flow/reachability.
- Credentials stay in `CredentialStore`; redact before AI and logging. Explain which provider receives workspace snippets and honor no-AI mode.
- Verification is advisory and never auto-runs. No project code execution, project-file writes, or implicit scan/index operation.
- Keep hypotheses separate in types, storage, UI, CLI, and reports. Never cast `SecurityHypothesis` to `UnifiedFinding`, `AqironIssue`, SARIF result, or finding UI state. A validated hypothesis links to a finding but does not mutate findings outside explicit validation.
- Logs may include request IDs, stages, counts, provider/model IDs where appropriate, timings, and safe reason codes. Never log prompts, excerpts, secrets, full model output, or credentials.

## 11. Client integration plan

No UI is part of this audit. For implementation, add typed Core contracts and client wrappers first, then test protocol/runtime/client. Add CLI output/commands and bridge forwarding later. VS Code handlers, React, webview state, and Tauri Rust remain transport/presentation only. `packages/desktop/src/main.ts` and Tauri `ALLOWED_METHODS` must allow the same operations; bridge continues injecting selected project root. Desktop project picker, chat, recommendations, history, and native window paths stay unchanged.

CLI hypothesis output should be opt-in and machine-readable with a distinct `hypotheses` property and schema version. Existing `scan` output and `--fail-on` semantics apply only to confirmed `UnifiedFinding` results. Never put hypotheses in current scan `findings`. Every client display labels items as hypotheses pending investigation.

## 12. Test strategy and acceptance criteria

### Deterministic unit tests

- Snapshot validator accepts known finding/span/relationship and rejects missing/fabricated finding IDs, paths, lines, rules, dependencies, and unsupported endpoints.
- Candidate validator rejects malformed, empty, reasoning-only, oversized, wrong-enum, and evidence-free model output; it never fills fabricated file/line data.
- Deduplication is stable across ordering, merges compatible evidence, and keeps incompatible assets/claims separate.
- Confidence tests verify quality/corroboration/reachability/contradiction/freshness; missing information is conservative; AI confidence is ignored.
- Transition tests distinguish dismissed/rejected/validated/stale from `UnifiedFinding.status`; only explicit validation links findings.
- Prompt/redaction tests ensure secrets/credentials are excluded; hostile content is data, not instructions.
- Verification-step validation rejects executable/destructive/network commands.
- No-AI generation is deterministic for identical snapshots and creates no unsupported hypotheses.

### Core integration tests

- `hypotheses.generate` uses only supplied/current project snapshot; assert no scanner manager, process runner, `scan.start`, RAG indexing, or project-code execution is triggered.
- New scan stales affected open hypotheses and preserves triage. Changed file hash invalidates source-span evidence.
- Provider unavailable and malformed/empty/reasoning-only output return deterministic results or safe no-candidate diagnostics and preserve existing state.
- Failure before commit leaves existing `hypotheses.json` byte-for-byte intact; success is valid JSON with atomic replacement.
- Missing store returns empty; corrupt store returns recoverable typed error without overwrite; migration fixtures preserve triage and IDs.
- Concurrent generation/mutation requests for one root serialize/merge without losing triage; roots stay isolated.
- Repeated request ID is rejected by existing guard; cancellation does not commit partial records.
- A hypothesis never appears in `scan.start` findings, SARIF, or `--fail-on` counts unless linked through approved finding validation.

### Client/protocol integration tests

- Extend `coreProtocol.test.ts`, `coreRuntime.test.ts`, and `coreClient.test.ts` for types, validation, events, cancellation, and result equivalence.
- CLI tests assert separate JSON fields and unchanged confirmed-finding behavior.
- Desktop forwarding/allowlist tests cover both `packages/desktop` and Tauri scoping; switching projects during generation discards stale selection results.
- Contract parity test invokes one Core fixture through VS Code/CoreClient, CLI, and Desktop bridge and compares normalized results.

Acceptance means every evidence reference resolves against its snapshot; unsupported candidates are rejected/unsubstantiated; deterministic mode repeats; no scan/project code is invoked; prior records survive failed generation; Core owns lifecycle and writes; clients separate hypotheses from findings; cancellation, isolation, and concurrency cannot corrupt triage.

## 13. Risks, unresolved questions, and trade-offs

1. **Validation semantics:** Does `validated` mean security review confirmed the claim, or create a formal finding? Recommended: keep distinct; link an existing finding, and require defined source/rule/severity plus explicit flow before creating a new one.
2. **AI/privacy consent:** Existing settings select provider/model, but no hypothesis-specific source-sharing consent contract was found. Decide whether generation defaults to deterministic-only, requires opt-in, or has an existing consent mechanism before sending snippets.
3. **Snapshot availability:** `CoreRuntime.scans` is in-memory; `scan.start` does not persist full `UnifiedFinding` snapshots. Legacy `threats.json` is written by the VS Code service and read/deleted by Core, but is not canonical evidence. Decide whether generation receives findings/scan ID while Core lives or whether new Core-owned scan snapshot persistence is in scope.
4. **Current AI findings:** `ai.vulnerabilityAnalysis` creates `UnifiedFinding` with AI source and location fallback; `scan.start` currently passes `aiAnalysis: undefined`. Decide if these are admissible as evidence or only support. Recommended: never count AI findings as independent corroboration; require source evidence validation.
5. **Scoring:** Existing risk score and correlation weights are not calibrated probabilities. Approve bands/factors and define independent signal. Start with bands and factor basis, not overprecise probability.
6. **Persistence durability:** `FileSystem` lacks explicit fsync/lock primitives. Choose acceptable crash guarantees and whether to add adapter support or use a process-local queue plus atomic rename.
7. **Protocol compatibility:** New methods may be backward-compatible. Confirm packaged runtime/client upgrade guarantees before deciding whether to bump `CORE_PROTOCOL_VERSION`.
8. **Desktop concurrency:** Tauri bridge serializes a `BridgeProcess` behind a mutex and scopes workspace at dispatch. Ensure long-running generation does not block project selection; capture root at request start.
9. **Reports:** Current reports include findings only. Decide whether a future report needs a distinct “Hypotheses” section; do not mix with SARIF or release gates by default.

## 14. Phased implementation plan and scope boundaries

**Phase 0 — Product decisions and contract review:** settle validation semantics, AI consent/default, scan snapshot source, score bands, protocol compatibility, and crash durability. No implementation until settled.

**Phase 1 — Core deterministic foundation:** add hypothesis/evidence types, immutable snapshot builder using existing scan/profile/correlation data, strict evidence validator, deterministic candidate rules, dedupe/ranking, store validation/migration/atomic merge, status transitions, and Core tests. AI disabled by default; no UI, CLI command, or report modifications.

**Phase 2 — Optional AI synthesis:** add separate Core candidate synthesizer using existing provider/model resolution, bounded redacted snapshot context, strict JSON parsing, evidence validation, safe diagnostics, and failure preservation. No AI finding promotion or verification command execution.

**Phase 3 — Client parity:** expose shared operations through CLI and Desktop bridge allowlists, then clients. Preserve project selection, chat, recommendations, history, and native window behavior. Add parity/isolation/cancellation tests. UI changes need separate scope.

**Phase 4 — Calibration and lifecycle expansion:** use a labeled fixture corpus to calibrate bands; consider report presentation and a separately validated finding-creation flow. Automated scans, code execution, active verification, or finding mutation remain out of scope until separately designed and authorized.

**Explicit boundaries for the original audit pass:** no production code, protocol behavior, persistence, recommendation behavior, UI, shared Ignore capability, scan orchestration, project selection, Desktop window behavior, branch, or commit changes. The audit pass added only this design document.

## Phase 1 implementation decisions (2026-10-20)

The reviewed Phase 1 decisions are: hypotheses remain provisional and separate from findings; AI is disabled; generation never starts scans, invokes project code, runs commands, or edits source; confidence is limited to low/moderate/high with deterministic factors; human validation does not create or mutate a finding; missing evidence is an explicit no-evidence result; and errors preserve stored hypotheses and triage.

Implementation uses only completed scan results retained in the current `CoreRuntime` process and requires an explicit `scanId` scoped to the normalized workspace root. Persisted `.aqiron-security/threats.json` is not used because it is legacy `AqironIssue` history, not the current Core `UnifiedFinding`/correlation snapshot. If the process restarted or scan ID/root do not match, generation returns `no-evidence`; Phase 1 does not add a competing scan-history parser or make scan results persistent.

New protocol operations are `hypotheses.generate`, `hypotheses.list`, `hypotheses.get`, and `hypotheses.review`; `CoreClient` exposes matching typed methods. The protocol remains version 1. Generation's only candidate rule is a low-confidence, falsifiable malware-to-mobile-artifact attribution question, requiring two existing findings, both source spans verified against current in-workspace files, and an actual `malware-to-artifact` relationship. Other existing correlation types are not used because their implementation depends on tag co-occurrence, same-file placement, dependency presence, or the coarse `attack-path` heuristic and cannot support a stronger first-release claim. A completed scan with findings that meet no allowlisted rule returns `no-supported-rule` and persists no speculative candidate.

Snapshots persist only ID/scan/time/fingerprint metadata. Hypothesis evidence stores project-relative paths, line ranges, finding/rule/relationship references, source hashes, and provenance; source excerpt text and `rawEvidence` are discarded. The existing filesystem abstraction did not replace an existing target reliably on Windows in focused tests. `FileSystem` has optional `unlink`, `rmdir`, and bounded-read capabilities; the hypothesis store writes a unique temporary sibling, moves an existing target to a unique backup, renames the temp into place, rolls back on replacement failure, and recovers a backup if a process stopped while the target was absent. Per-workspace process-local queues and an exclusive cross-process gate serialize lock-owner changes. Confirmed-dead owners are reclaimed under the gate; ambiguous owners fail closed. A process interrupted while holding the gate requires manual recovery after all Core processes stop. Store reads are capped at 5 MB before full decoding, and freshness revalidation is sequential with a 50 MB aggregate budget and deduplicated source-path reads. Replacement still has a brief target-absent window and no fsync durability guarantee. Root normalization uses physical `realpath`; path-based validation remains subject to TOCTOU races. Corrupt or unsupported stores return `HYPOTHESIS_STORE_INVALID` and are preserved. Validation requires a current evidence reference and stores the reviewer-selected reference IDs, but remains a reviewer assertion; no finding is created or linked in this phase.

The implemented confidence table is deliberately conservative:

| Conditions | Band |
| --- | --- |
| Any stale evidence, any explicit contradiction, or no verified source-span evidence | low |
| Verified source span + multiple source families + an explicit non-heuristic relationship, with no stale/contradictory evidence | moderate |
| All other combinations, including unknown preconditions or heuristic-only relationships | low |
| high | Not emitted in V1; no current relationship contract proves the required exploit path/reachability |

The only emitted candidate uses a heuristic relation and therefore remains `low`, regardless of severity. `ThreatCorrelationEngine` relation weights are discarded from hypothesis evidence and never interpreted as probabilities. `hypotheses.list` and review re-read cited source spans and mark nonterminal proposals stale when their current content hashes differ. A new scan with no trustworthy in-workspace findings also records an empty snapshot so earlier open hypotheses become stale. Generation rejects a completed scan older than the latest persisted hypothesis snapshot, using the scan completion timestamp retained in `ScanState`.

No AI, scanner, RAG, or project-code execution is called from hypothesis generation. The profile is obtained through the bounded read-only project detector. Desktop bridge allowlists, CLI, all UIs, reports, existing findings, recommendations, and credential behavior remain outside this phase.

## Corrective patch addendum (2026-10-21)

This addendum supersedes the earlier Phase 1 implementation paragraph where it describes scan-time hashes, freshness transitions, path canonicalization, and stale-lock reclamation.

Core currently retains scanner-observed source provenance for findings produced by the native scanner. Hypothesis generation accepts only completed scan records from the same normalized workspace and compares their captured file and source-span hashes with current in-workspace content. Findings without usable scan-time provenance, or whose current source is missing, changed, unreadable, outside the workspace, or over the configured byte limits, are excluded and reported through generation diagnostics; Core never substitutes a hash captured after the scan. External scanner findings without provenance therefore fail closed rather than being treated as verified source evidence.

Hypothesis storage and source evidence now require `realpath`, non-following `lstat`, regular-file checks, physical workspace canonicalization, and exclusive creation for temporary/lock-owner files. Symlinked `.aqiron-security` directories, store artifacts, lock paths, and source-path components are rejected. Validation and path operations remain separate calls through the current path-based filesystem abstraction; an attacker able to race mutations in the workspace may still exploit a TOCTOU window. The implementation does not claim descriptor-relative or race-free filesystem confinement. When required filesystem capabilities are missing, hypothesis storage fails closed.

Review state and evidence freshness are separate: `status: validated` records the human decision, while `evidenceFreshness: stale` and stale evidence references indicate that its source changed or disappeared. List/get/review preserve the historical decision and expose stale freshness; validating again requires a current hypothesis and current evidence. The evidence hash covers the complete canonicalized inclusive line span (LF-normalized) and spans are limited to 20 lines.

Cross-process lock directories contain an exclusively created owner record with the process ID and random token. Ownership transitions are serialized by a separate exclusive gate directory; stale-owner reclamation removes an owner only while holding that gate and never renames the shared lock directory. Missing, malformed, unreadable, or ambiguous owner data fails closed. A process terminated while holding the gate leaves it in place and requires manual recovery after all Core processes for that workspace stop. This intentionally trades automatic recovery for safety because the path-based filesystem adapter has no compare-and-swap or descriptor-relative rename primitive. Path validation remains subject to hostile concurrent filesystem mutation (TOCTOU).

## Scan-time provenance implementation addendum

The follow-on Core implementation captures provenance in `NativeWorkspaceScanner.scanWorkspace` while it still holds the exact decoded UTF-8 text passed into native rule evaluation. `hashSourceContent` is SHA-256 over that text re-encoded as UTF-8, including its original line-ending characters. `hashSourceSpan` is SHA-256 over the finding's inclusive, one-based lines joined with LF; line splitting follows the native scanner's `CRLF`/`LF` semantics. Both hashes are captured before `CoreScanService` correlation and are bound to finding ID, relative path, line range, source tool, and rule ID. The completed scan's internal runtime record retains the provenance; `scan.start` output and protocol version 1 remain unchanged.

At hypothesis generation, Core independently validates the recorded finding identity and workspace-relative path, rejects symlinks and unsafe spans, then compares both hashes to current content. This detects edits anywhere in the file between scan and generation as well as span changes after generation or human validation. Persisted source-span references retain both hashes, never source text. Work is bounded to 10 MB per source file, 50 MB of full-file hashing and 10 MB of unique span hashing per scan, 10,000 provenance records, 20 lines and 64 KB per span. Findings outside those bounds, without valid source spans, or produced by scanners that do not expose the exact scanned source content are excluded and counted in generation diagnostics. Older persisted source-span records lacking the full-file hash remain readable but are marked stale because their scan-time whole-file identity cannot be established.

Hypothesis persistence reads use the Node adapter's bounded handle-based reader, which checks the open handle size and stops after at most `limit + 1` raw bytes before decoding; adapters without this capability fail closed for hypothesis store operations. Freshness validation is sequential, reads each unique source path once per operation, and enforces a 50 MB aggregate raw-byte budget plus the existing 10 MB per-file raw-byte limit. A failed growing-file read charges bytes actually consumed, including its one-byte overflow probe; if a custom adapter cannot report consumed bytes on a read error, Core exhausts the remaining budget conservatively. Invalid UTF-8 is decoded only after raw-byte accounting, so replacement-character expansion cannot replenish the budget. Files beyond the budget are marked stale rather than trusted. Snapshot generation also uses bounded raw-byte reads, reads each normalized source path once, and applies the same 10 MB per-file/50 MB per-operation raw-byte ceilings before decoding. Findings excluded by missing, changed, unreadable, oversized, or budget-exhausted evidence are reflected in generation diagnostics.

## Focused corrective patch addendum (2026-10-21)

An existing lock directory with a missing owner record is now ambiguous and fails closed; only the process that successfully creates the lock directory under the exclusive gate may install its initial owner. Existing owners are re-read and their PID/token and resolved lock path are checked again under the gate before stale-owner unlink. Malformed/unreadable owner records are preserved and reported for manual recovery. The lock uses path-based filesystem operations, so exact inode identity cannot be proven against an unrelated hostile process that mutates lock artifacts concurrently; such concurrent mutation remains a documented TOCTOU limitation. A stranded gate or ambiguous owner requires stopping all Core processes for that workspace before manual recovery.

Persisted stores now include a monotonic committed `generation` field. Legacy version-1 stores without it are read as generation zero; the first successful update writes generation one. The field is included in the same validated JSON envelope written to a unique temporary sibling and becomes committed only when that complete temporary file is renamed into the target path. If the target is absent, recovery validates all backup envelopes and selects the highest generation, independent of filename ordering. Conflicting same-generation content or any corrupt, unsupported, or unreadable backup makes recovery fail closed without installing or deleting a candidate. Temporary files are uncommitted and are never recovery candidates. The existing no-fsync and brief target-absent limitations remain.

Hypothesis protocol validation caps absolute workspace roots at 4,096 characters and scan IDs at 128 ASCII letters, digits, dots, underscores, colons, or hyphens. Empty, whitespace-padded, NUL-containing, or oversized workspace roots and invalid scan IDs are rejected before Core path resolution. Protocol version remains 1.

## Provenance correctness follow-up

Legacy schema-v1 hypothesis records remain readable when they lack source-span references. Core marks their evidence `provenance-unavailable`, changes all evidence references to stale, preserves a prior validated/rejected status as historical review state, and refuses validate/reject actions with a `provenance-unavailable` diagnostic. A source-span record without its scan-time full-file hash continues to fail freshness validation as stale. Native scanning now builds one reusable source line index per file; inclusive one-based span hashes use the existing CRLF/LF split and LF-joined span semantics without splitting the full source once per uncached finding.
