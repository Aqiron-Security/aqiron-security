# Legacy scanner retirement record

**Status: complete for `WorkspaceScanner` and `scanContent`.** The extension's workspace, current-file, realtime, Agent workspace and Agent secret scans use the existing Core operations. This change removes the remaining unused local scan engine and its dependency plumbing. It does not change Core scanner behavior, request contracts, scan rules, or client presentation.

## Production call graph

Before retirement, the only production reference to `WorkspaceScanner` was constructor wiring:

```text
extension.ts creates WorkspaceScanner
  → ScanController stores and passes it
  → SecurityOrchestrator passes it
  → SecurityPipelineEngine stores it, then never reads it
```

No production caller invoked its `scanWorkspace`, `scanDocument`, or `scanFile` methods. `scanContent` was called only from those methods. Current-file, realtime and post-fix operations already used `CoreClient.fileScan`; workspace orchestration used `CoreClient.startScan`; both Agent scan tools used `startScan`.

After retirement:

```text
ScanController
  → SecurityOrchestrator
  → SecurityPipelineEngine
  → CoreClient.startScan
```

The file-scoped paths still use `CoreClient.fileScan`. Agent filtering, projection, redaction, and UI state remain at the VS Code boundary.

## Final classification

| Classification | Files/symbols | Evidence and disposition |
| --- | --- | --- |
| **Provably unused, removed** | `src/scanner/workspaceScanner.ts`; `scanContent` and its private detectors/comment-stripping/issue helpers; local scanner wrappers and helpers listed below; unused local pipeline cache/queue/aggregator shims | No production callers, package export, dynamic loading, or required direct tests remained. The Core implementations remain under `packages/core/src`. |
| **Test-only, moved to Core coverage** | Legacy `WorkspaceScanner.scanDocument`/`scanFile`/cache characterization and local `scanContent` oracle tests | The local scanner feature has retired. File and realtime behavior assertions now target Core-backed adapters directly; secret-pattern expected IDs, cases, source positions, and fixture coverage remain tested by `coreSecretParity.test.ts` and Core scanner tests. |
| **Compatibility/re-export, removed** | `src/security/parsers/*`; `src/security/adapters/semgrepAdapter.ts`, `trivyAdapter.ts`; `src/security/pipeline/workerQueue.ts`, `threatIntelligenceAggregator.ts` | Parser tests import Core parsers directly. No callers or package exports used these local paths. Core parser/queue/aggregator implementations remain intact. |
| **Still production-required, retained** | `src/scanner/rules.ts`: `getResolvedCurrentFileRules`, `getResolvedCustomRules`, portable rule model and defaults | `ScanController` uses current-file rules for `scan.file`; `resolveWorkspaceScanPolicy` uses configured custom rules for Agent `scan.start`. This file no longer performs analysis and imports no Core/scanner implementation. |
| **Still production-required, retained** | `src/security/pipeline/pipelineEngine.ts`, `src/security/pipeline/events.ts`, `src/security/scanners/types.ts` | The pipeline is the active Core workspace adapter; the events module is the webview's Core event type seam; scanner types re-export shared types used by the pipeline and AI-analysis service. |
| **Provably unused, removed** | `src/security/scanners/{platform.ts,flutterScanScope.ts,exclusions.ts,scanModes.ts}` and wrapper files under `betterleaks/`, `mobsf/`, `osv/`, `semgrep/`, `trivy/`; `src/security/adapters/toolExecutor.ts`; `src/security/pipeline/scanCache.ts` | Static import and construction search found no remaining production, test, package, or dynamic-loading use. Runtime scanner construction is in `packages/core/src/runtime/coreRuntime.ts`. |
| **Core authoritative, retained** | `packages/core/src/scanners/*`, `packages/core/src/parsers/*`, `packages/core/src/pipeline/workerQueue.ts`, `packages/core/src/pipeline/threatIntelligenceAggregator.ts` | Core runtime imports and constructs these implementations; Core and integration tests exercise them. None were removed or changed by this retirement. |
| **Uncertain** | None identified in the inspected scanner, parser, and pipeline subtrees | Historical prose in release notes/checklists may mention removed paths; it does not load or export code. |

## Removed files

- `src/scanner/workspaceScanner.ts`
- `src/security/adapters/semgrepAdapter.ts`, `trivyAdapter.ts`, `toolExecutor.ts`
- `src/security/parsers/betterleaksParser.ts`, `engineMappers.ts`, `osvScannerParser.ts`, `semgrepParser.ts`, `trivyParser.ts`, `vulnerabilitySchema.ts`
- `src/security/pipeline/scanCache.ts`, `threatIntelligenceAggregator.ts`, `workerQueue.ts`
- `src/security/scanners/platform.ts`, `flutterScanScope.ts`, `exclusions.ts`, `scanModes.ts`
- `src/security/scanners/betterleaks/betterleaksScanner.ts`, `mobsf/mobsfScanner.ts`, `osv/osvScanner.ts`, `semgrep/semgrepScanner.ts`, `trivy/trivyScanner.ts`

The local `scanContent` function and its dedicated matching/stripping implementation were removed from `src/scanner/rules.ts`; the file remains as the VS Code policy resolver.

## Constructor cleanup

Removed the `WorkspaceScanner` import, construction, field and constructor argument from `extension.ts`, `ScanController`, `SecurityOrchestrator`, and `SecurityPipelineEngine`. The active pipeline still forwards Core scan events, projects Core findings, and writes report bundles. Its constructor now takes only the `PipelineEventBus`.

## Tests retained or moved

- Current-file, post-fix and realtime adapter tests continue to verify buffer semantics, policy, source projection, diagnostics, debounce, fallback, errors and Core request behavior without constructing the legacy scanner.
- Agent workspace and secret scan tests continue to verify Core calls, trust, policy, filtering, cancellation, state merge and redaction.
- `coreSecretParity.test.ts` now uses explicit characterized rule IDs/case expectations and the existing fixture instead of comparing against `scanContent`; it retains all eight fixture examples, severity, line/range validity, and privacy assertions.
- `securityToolParsers.test.ts` imports `packages/core/src/parsers` directly. Core implementations and parser redaction/location tests remain.
- Legacy cache behavior and direct legacy scanner output tests were removed because the implementation and cache consumer no longer exist.

## Import graph result

Production references to the legacy `WorkspaceScanner` class and `scanContent` are zero. The similarly named `NativeWorkspaceScanner` remains the Core implementation and is constructed in `packages/core/src/runtime/coreRuntime.ts`. Core's own methods named `scanWorkspace` and `scanFile` are also active and are not legacy extension code.

`src/scanner/rules.ts` is retained only for `getResolvedCurrentFileRules` and `getResolvedCustomRules`; both resolvers remain reachable from their Core request adapters. `src/security/pipeline/events.ts` and `src/security/scanners/types.ts` remain local type seams. The package has no public package export for the removed `src/security/*` internal paths; esbuild bundles explicit extension, Core runtime, CLI, and webview entry points.

## Retirement boundary

`WorkspaceScanner` and `scanContent` are retired. Core scanner and parser implementations are authoritative. No further removal of `src/security/scanners/types.ts`, `events.ts`, `pipelineEngine.ts`, or the policy resolvers is justified by this call graph.
