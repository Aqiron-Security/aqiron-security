# Legacy scanner retirement readiness

**Status:** the post-fix current-document rescan now uses the existing Core `scan.file` operation. This document records remaining call sites and the evidence required before deleting legacy scanner code. No legacy scanner or rule implementation was deleted in this change.

## Runtime call graph

### Post-fix current-document rescan

```text
aqiron-security.fixCurrentFile
  → ScanController.fixCurrentFile
  → apply WorkspaceEdit
  → document.save()
  → ScanController.scanDocument(document, true)
  → ScanController.runScan
  → capture document.getText() after runScan accepts the task
  → resolve workspace membership and Flutter eligibility
  → scanDocumentWithCore
  → resolveFileScanPolicy (same helper as current-file/realtime)
  → CoreClient.fileScan
  → scan.file / NativeWorkspaceScanner.scanFileContent
  → UnifiedFinding[]
  → projectFinding / findingToIssue using the captured content lines
  → replaceFile / DiagnosticManager / sidebar
```

`fixCurrentFile` supports the active document only, and rejects unsupported extensions before editing. The `WorkspaceEdit` is applied and the document is saved before the rescan is called. The document remains available; `getText()` is read within the task after `runScan` accepts it, matching the old timing. If a scan is already active, `runScan` retains its existing workspace-scan debounce fallback and does not start a file scan.

### Before this change

The final three arrows before projection were `WorkspaceScanner.scanDocument(document) → scanContent(path, document.getText())`. That method checked workspace membership and Flutter eligibility, checked `.aq`, directory, generated, minified, and compiled skip rules, scanned the in-memory document buffer, cached the result, logged counts, and returned `AqironIssue[]`. The controller then replaced diagnostics for the file and showed the existing completion message.

### Current behavior and parity

The rescan now uses `scanDocumentWithCore`, the same VS Code adapter used by the current-file command and realtime path. It passes the exact path, post-edit document text, resolved supported extensions/exclusions/skip flags, unlimited current-file size policy, Flutter eligibility, and resolved current-file rules. Core does not read the file from disk. The adapter reconstructs source-line context from that captured buffer, preserves issue IDs/ranges/severity through the existing projection, filters visible issues, updates the same file issue store and diagnostics, and keeps the completion wording.

The adapter retains the old Output-channel start/skip/count/duration summary. The legacy document cache write is gone. Its cache entry was only consumed by `WorkspaceScanner.scanUri`; import/call-site analysis found no production caller of `WorkspaceScanner.scanFile` or `scanWorkspace`, so the cache did not influence an active post-fix or workspace execution path. Core file-scan failure is presented by the existing `runScan` failure handler, as are failures from the former implementation.

## Remaining production imports and calls

| Symbol/path | Production use found | Test use found | Retirement note |
| --- | --- | --- | --- |
| `WorkspaceScanner` | Constructed in `extension.ts`; passed through `ScanController` → `SecurityOrchestrator` → `SecurityPipelineEngine`. The pipeline stores the argument but explicitly does not use it. No production call remains to `scanDocument`, `scanFile`, or `scanWorkspace`. | Direct legacy behavior and adapter tests in `fileScanCharacterization.test.ts` and `agentScanCharacterization.test.ts`. | The class is now an inert constructor dependency in production. Remove that dependency chain before deleting the class. |
| `scanContent` | No production call site remains after the post-fix migration. It is still called by `WorkspaceScanner` methods, which have no production method caller. | Used as the legacy oracle by characterization and Core secret parity tests. | Keep while characterization tests depend on it; later replace oracle assertions with explicit expected fixtures before removal. |
| `scanFile` (legacy `WorkspaceScanner.scanFile`) | No production call site found. | Direct saved-file/size/cache characterization. | Retire only after replacing the legacy behavior tests or explicitly preserving them as a compatibility suite. |
| `WorkspaceScanner.scanWorkspace` | No production call site found. The active VS Code workspace adapter calls `CoreClient.startScan`. | Legacy workspace characterization in `agentScanCharacterization.test.ts`. | Keep until tests and constructor wiring no longer need it. |
| `getResolvedCustomRules` in `src/scanner/rules.ts` | Used by `resolveWorkspaceScanPolicy` in `src/utils/files.ts`, which supplies policy to Agent `secrets.scan`. | Rule-resolution tests. | Actively required; move policy resolution before retiring `rules.ts`. |
| `getResolvedCurrentFileRules` in `src/scanner/rules.ts` | Used by `ScanController.resolveFileScanPolicy` for current-file, realtime, and post-fix scans. | Current-file/realtime policy tests. | Actively required; move this resolver and its rule data before retiring `rules.ts`. |
| Private rule functions behind `scanContent` | No independent production imports. | Exercised through `scanContent` characterization/parity tests. | Test-only after workspace and document legacy execution were migrated. |
| `src/security/pipeline/pipelineEngine.ts` | Active VS Code adapter: calls `CoreClient.startScan`, forwards correlated Core events, projects findings, and persists Core reports. | Adapter event/correlation tests. | Keep; it is a Core adapter, not the duplicate scanner implementation. |
| `src/security/pipeline/events.ts` | Re-exports Core pipeline event types used by `AqironWebviewProvider` contracts. | Pipeline adapter tests. | Keep as a compatibility/type boundary unless imports move directly to Core types. |
| `src/security/scanners/types.ts` | Type exports are used by the active pipeline result type and AI-analysis service types. | Several scanner characterization tests use related types. | Keep until those type imports are moved or the dependent adapter types are retired. |

## Legacy helper inventory

### `src/scanner/`

| File/function | Classification | Evidence |
| --- | --- | --- |
| `workspaceScanner.ts` / `WorkspaceScanner` | No active scan-method caller after this migration; constructor-only compatibility dependency remains. | `extension.ts` constructs it; `ScanController` passes it into `SecurityOrchestrator`; `SecurityPipelineEngine` retains but does not use it. Direct method calls are test-only. |
| `WorkspaceScanner.scanDocument` | Test-only after this migration. | The only production caller was `fixCurrentFile`; it now invokes `scanDocumentWithCore`. |
| `WorkspaceScanner.scanWorkspace` | Test-only. | Production workspace and Agent scan paths use Core `scan.start`. |
| `WorkspaceScanner.scanFile` / private `scanUri` / cache | Test-only. | No production caller found; scan URI/cache behavior is exercised only by characterization tests. |
| `rules.ts` / `scanContent` and scanner rules | Test-only execution path after migration. | The scanner class still references it, but its scan methods are no longer reached by a production caller. Existing characterization tests use it as the legacy baseline. |
| `rules.ts` / `getResolvedCurrentFileRules` | Actively required policy resolver. | Used in the Core file-scan policy for current-file, realtime, and post-fix paths. |
| `rules.ts` / `getResolvedCustomRules` | Actively required policy resolver. | Used by workspace policy resolution for Agent secret scanning. |

### `src/security/scanners/`

| File | Classification | Evidence |
| --- | --- | --- |
| `types.ts` | Active type boundary. | Imported by the Core-backed workspace adapter and AI-analysis types. |
| `platform.ts` | Provably unused by the production entry graph; used internally by the scanner adapter subtree. | No production caller imports it directly. Scanner wrappers below are not instantiated from production code. |
| `betterleaks/betterleaksScanner.ts` | Core adapter with no production caller found. | Delegates to the Core scanner; only reachable from the unused adapter subtree. |
| `mobsf/mobsfScanner.ts` | Core adapter with no production caller found. | Delegates to the Core scanner; only reachable from the unused adapter subtree. |
| `osv/osvScanner.ts` | Core adapter with no production caller found. | Delegates to the Core scanner; only reachable from the unused adapter subtree. |
| `semgrep/semgrepScanner.ts` | Core adapter with no production caller found. | Delegates to the Core scanner; only reachable from the unused adapter subtree and an unused compatibility re-export. |
| `trivy/trivyScanner.ts` | Core adapter with no production caller found. | Delegates to the Core scanner; only reachable from the unused adapter subtree and an unused compatibility re-export. |
| `flutterScanScope.ts` | Provably unused helper. | No production or test imports found. It reads files from disk but is not on the active Core scan path. |
| `exclusions.ts` | Provably unused helper/constants. | No production or test imports found. |
| `scanModes.ts` | Provably unused helper/types. | No production or test imports found. |

`src/security/adapters/semgrepAdapter.ts` and `trivyAdapter.ts` only re-export the two unused Core scanner wrappers; no production imports were found. `src/security/adapters/toolExecutor.ts` has no production caller. These are compatibility candidates, not part of this migration.

### `src/security/parsers/`

All six files are compatibility re-exports of `packages/core/src/parsers/*`: `betterleaksParser.ts`, `osvScannerParser.ts`, `semgrepParser.ts`, `trivyParser.ts`, `engineMappers.ts`, and `vulnerabilitySchema.ts`. No production import of these `src/security/parsers` paths was found. `securityToolParsers.test.ts` imports the Betterleaks and OSV re-exports directly; the other four have no repository caller. The Core parser implementations remain active through Core scanners and must not be removed with these re-export shims.

### `src/security/pipeline/`

| File | Classification | Evidence |
| --- | --- | --- |
| `pipelineEngine.ts` | Active client adapter. | Production `ScanController` → `SecurityOrchestrator` calls its Core `startScan` bridge. Its `WorkspaceScanner` field is unused and removable only in a separate constructor cleanup. |
| `events.ts` | Active compatibility/type re-export. | The webview provider imports Core event types from this path; scanner platform and tests also refer to its emitter type. |
| `workerQueue.ts` | Unused Core re-export. | No production or test import found. |
| `threatIntelligenceAggregator.ts` | Unused Core re-export. | No production or test import found. |
| `scanCache.ts` | Provably unused local implementation. | No production or test import found. |

`src/security/parsers` and the scanner adapter subtree are not on the runtime route used by the active Core workspace pipeline. The active tool implementations and parsers live under `packages/core/src`; source-only wrappers must not be mistaken for those Core implementations.

## Core versus post-fix scan semantics

| Concern | Existing post-fix behavior | Core adapter behavior after migration |
| --- | --- | --- |
| Input | Active `TextDocument` after edit and save | Same document path plus `getText()` captured inside the accepted `runScan` task |
| Workspace/Flutter gate | `WorkspaceScanner.scanDocument` rejects missing/non-Flutter workspace | Adapter resolves the same eligibility and sends `eligible: false` to `scan.file` |
| Supported extensions | `fixCurrentFile` rejects unsupported URI before applying edits | Same command gate; policy also contains the current supported extension set |
| Exclusions/generated/minified/compiled | `getSkipReason(path, buffer)` | Same policy resolver encodes skip as excluded path/eligibility and passes skip flags |
| Size | No explicit max-size check in `scanDocument` | `maxFileSizeBytes: null`, preserving the uncapped file-scoped behavior |
| Rules | `scanContent` local rules and configured rules | The established Core file scanner plus `getResolvedCurrentFileRules(path)` converted into portable rules |
| Output | `AqironIssue[]`, replace file issues and diagnostics | `UnifiedFinding[]` projected by the existing `findingToIssue` adapter, then the same issue store/diagnostics |
| Failure/cancel | No dedicated document-scan cancellation; thrown errors flow through `runScan` | Core request failures flow through the same `runScan` handler; no new cancellation control was introduced |
| Cache | Writes a document cache entry; no active consumer of that cache entry was found | No cache write; no production behavior depends on that cache after Core workspace/file migrations |

Behavior parity is covered by the existing current-file fixture comparison and the added post-fix adapter regression test. The Core client must be available for the rescan, as it is for the existing current-file and realtime paths; a Core transport failure is surfaced through the same scan failure UI.

## Import graph after migration

Production imports/calls:

- `src/extension.ts` constructs `WorkspaceScanner` and passes it to `ScanController`.
- `ScanController` passes the stored scanner to `SecurityOrchestrator`; the orchestrator passes it to `SecurityPipelineEngine`.
- `SecurityPipelineEngine` explicitly ignores the scanner instance and calls the Core client. It is the only active scan orchestration path, not a legacy implementation call.
- `ScanController` now calls `CoreClient.fileScan` for current-file, realtime, and post-fix file scans.
- `AqironWebviewProvider` uses Core workspace scans and imports workspace policy from `src/utils/files.ts`.
- `src/utils/files.ts` imports `getResolvedCustomRules`; `ScanController` imports `getResolvedCurrentFileRules`.
- The Agent/webview imports `PipelineEvent` types from `src/security/pipeline/events.ts`; the path re-exports the Core event contracts.

Test-only imports/calls:

- `fileScanCharacterization.test.ts` imports `WorkspaceScanner` and `scanContent` as legacy baselines, and tests its old `scanFile`/cache behavior.
- `agentScanCharacterization.test.ts` imports `WorkspaceScanner` and `scanContent` to pin the former Agent behavior and secret patterns.
- `coreSecretParity.test.ts` imports `scanContent` to compare the legacy secret pattern set to Core.
- `securityToolParsers.test.ts` imports the Betterleaks/OSV parser re-export shims.
- Other scanner/parser/pipeline tests primarily import Core implementations or Core-backed adapters directly.

No production `scanContent`, `WorkspaceScanner.scanDocument`, `WorkspaceScanner.scanFile`, or `WorkspaceScanner.scanWorkspace` invocation remains after the post-fix migration. The `WorkspaceScanner` class symbol remains in the production constructor graph only.

## Retirement plan

### Safe now

- Do not remove any scanner implementation in this change. The import graph proves several orphan helper/re-export files, but deleting them would be unrelated cleanup and is not required to finish the post-fix migration.
- In a separate cleanup, the no-import `src/security/pipeline/scanCache.ts`, `workerQueue.ts`, and `threatIntelligenceAggregator.ts` can be reviewed for immediate retirement; confirm package exports and generated bundle references first.

### Safe after constructor cleanup

1. Remove the unused `WorkspaceScanner` argument/field from `SecurityPipelineEngine`, `SecurityOrchestrator`, and `ScanController`; remove its instantiation in `extension.ts`. Risk: constructor/test wiring and extension activation. Preserve the Core workspace adapter and verify scan.start event/report behavior.
2. With no production `WorkspaceScanner` imports, retire `workspaceScanner.ts` after replacing tests that directly assert old cache and scanFile behavior. Risk: hidden internal consumers and changed characterization oracle; search the full repository and package scripts first.
3. Move `getResolvedCustomRules` and `getResolvedCurrentFileRules` plus their portable rule model into a policy-focused module. Then remove `scanContent`, its private rule detectors, and `rules.ts` only after tests no longer import it. Risk: changing policy resolution or losing a useful legacy comparison baseline; keep parity fixtures as explicit expected results.

### Safe after adapter-consumer review

4. Remove the unused `src/security/scanners` wrappers, `platform.ts`, `flutterScanScope.ts`, `exclusions.ts`, `scanModes.ts`, and `src/security/adapters` re-exports/tool executor. Risk: internal extension consumers not found by static search, or downstream source imports. Confirm these paths are not documented as an extension API.
5. Remove parser re-export shims after moving parser tests to `packages/core/src/parsers` and checking all workspace references. Risk: tests or consumers relying on those source paths; Core parser implementations remain.
6. Remove unused pipeline re-export shims/helpers individually; keep `pipelineEngine.ts` and the event re-export while production callers remain. Risk: webview type imports or tests may rely on stable local paths.

### Do not remove yet

- `src/security/pipeline/pipelineEngine.ts`: active Core client adapter for workspace scans, events, result projection, and report storage.
- `src/security/pipeline/events.ts`: current webview-facing Core event type seam.
- `src/security/scanners/types.ts`: types still referenced by pipeline and AI-analysis code.
- `src/scanner/rules.ts` policy resolvers: currently required to produce explicit Core policies for current-file and Agent workspace/secret operations.
- Core scanner and parser implementations under `packages/core/src`.

## Tests required before deletion

- Preserve current-file, realtime, post-fix, workspace and Agent parity fixtures as explicit expected contracts; avoid using the implementation slated for deletion as the only expected-value source.
- Verify current-file and post-fix source ranges, IDs, severity, diagnostic replacement, skip policy, custom rules and in-memory content.
- Verify realtime debounce/latest-buffer behavior and that no save path reads stale disk content.
- Verify workspace and Agent Core request policy, trust, progress correlation, cancellation, error presentation, Agent filtering/state merge and redaction.
- Verify `scan.start` workspace behavior and Core pipeline events/reports independently from the adapter files proposed for deletion.
- Compile/typecheck after removing each constructor/import layer, then run the full VS Code suite and inspect the built extension bundle for remaining legacy imports.
