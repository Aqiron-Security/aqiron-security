# Core file-scan contract

**Status:** new Core capability; no existing caller migrated. This contract is an architectural bridge, not a claim of parity with the characterized VS Code scanners.

## Current

- Workspace scans use `scan.start` → `CoreScanService` → native and registered scanners. Supplying `targetPath` does not constrain the native scanner to that path.
- `NativeWorkspaceScanner` reads workspace files from its filesystem port and owns its current native rule subset, size check, and directory exclusions.
- VS Code current-file/realtime scans use `TextDocument.getText()` and `src/scanner/rules.ts`; Agent scans use `WorkspaceScanner`. Those paths retain their separate Flutter gates, supported extensions, custom rules, exclusions, limits, cache and projections.
- `UnifiedFinding` is the Core domain model. `AqironIssue`, diagnostics, Agent summaries, debounce, editor state, and webview projections remain client concerns.

## New contract

The typed IPC operation is `scan.file`. Its request is:

```ts
interface CoreFileScanRequest {
  filePath: string;
  content: string;
  policy: ResolvedFileScanPolicy;
}
```

`filePath` gives findings their source location and defines the one exact target. `content` is the text to analyze, including an unsaved editor buffer; Core does not reread that path. The request has no `workspaceRoot`, traversal selector, or `TextDocument` dependency. Optional revision/hash is deferred because this operation has no cache and current callers do not supply a portable revision contract.

`ResolvedFileScanPolicy` is caller-resolved effective policy, not raw settings. It currently carries:

| Field | Why it exists |
|---|---|
| `supportedExtensions` | Makes the caller's selected file types explicit; unsupported targets are returned as skipped. |
| `excludedPaths` | Carries resolved exact paths or directory prefixes; matching is normalized for slash direction and case. |
| `maxFileSizeBytes` | Expresses the effective limit in one unit; `null` means unlimited. Core measures supplied content as UTF-8 bytes. |
| `skipGeneratedFiles`, `skipMinifiedFiles`, `skipCompiledFiles` | Makes those policy choices explicit and applies portable path/content heuristics. |
| `eligible` | Carries a resolved project/client gate (for example, VS Code's Flutter requirement) without teaching Core about Flutter workspace configuration. |
| `customRules` | Represents the existing portable regex subset (`id`, title, message, severity, pattern, optional extensions); malformed regexes are ignored as in the VS Code scanner. |

The current operation uses Core's native built-in rule subset plus the supplied custom regex rules. Custom-rule findings use canonical `UnifiedFinding` fields. It intentionally does not claim parity with `src/scanner/rules.ts` across languages. Source content is not copied into result evidence, event payloads, or Core request logs. File events contain only scan id, path, state and counts.

The result is `CoreFileScanResult`: canonical request-derived `scanId`, `filePath`, `state` (`completed` or `skipped`), optional bounded `skipReason`, canonical `UnifiedFinding[]`, `filesScanned`, `findingCount`, and `durationMs`. Malformed requests fail through the existing Core protocol error envelope. Cancellation uses existing `core.cancel` with the request id; start/completion events use that same id. The operation does not generate a report or telemetry snapshot.

## Not migrated yet

No VS Code current-file, realtime, workspace-Agent, or secret-Agent caller invokes `scan.file`. They remain on their existing paths. `WorkspaceScanner` and `scan.start` are unchanged. Client adapters must continue to own:

- resolving VS Code settings, workspace trust, Flutter/project gates, custom-rule configuration and `.aq`/glob semantics;
- `TextDocument` access, save listeners, debounce, editor generations, cancellation UX and diagnostics;
- Agent secret-only filtering, five-location message limit, issue merging, error presentation and result serialization;
- conversion such as `UnifiedFinding → AqironIssue` and client-specific UI projection.

`excludedPaths` is intentionally a resolved path list, not a general glob language. VS Code `.aq` patterns and exclusion globs therefore need explicit resolution/adaptation before a caller can use this operation. The built-in scanner subset and skip heuristics also differ from the characterized VS Code implementation. Current callers must not be redirected until parity tests cover their own language rules, Flutter behavior, settings, exclusions, generated/minified/compiled policy, custom rules, size behavior, cache semantics, diagnostic/result mapping, Agent filtering and cancellation/error UX.

## Future work

### Required before faithful migration

- characterize and port/compose the exact current rule set needed by each path, with parity fixtures;
- resolve client policy into the portable fields above, including `.aq` and configured exclusions;
- settle unsupported-extension and skipped-result mapping at each client adapter;
- test stale-result handling/revision semantics and cancellation under realistic long-running work;
- implement and test `UnifiedFinding → AqironIssue` projection at the VS Code edge;
- compare privacy handling for secret evidence across all client projections.

### Future improvements

- optional content revision/hash and policy fingerprint if a shared Core cache is designed;
- explicit caching abstraction with invalidation semantics; do not copy the VS Code path/mtime/size cache blindly;
- language identifiers beyond extension selection where concrete scanner behavior requires them;
- richer skip/count metadata only when a client demonstrates a need.

Core owns exact-target execution, supplied-content analysis, the resolved policy decisions represented by this contract, canonical findings, operation state, request cancellation and non-sensitive domain events. Clients own content acquisition, settings resolution, debounce, diagnostics, UI projection, Agent-specific filtering and client persistence.
