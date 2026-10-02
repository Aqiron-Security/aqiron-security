# Core file-scan contract

**Status:** `scan.file` backs the VS Code current-file command and save/realtime document path. Agent callers remain unmigrated; parity is path-specific.

## Current

- Workspace scans use `scan.start` → `CoreScanService` → native and registered scanners. Supplying `targetPath` does not constrain the native scanner to that path.
- `NativeWorkspaceScanner` reads workspace files from its filesystem port and owns its current native rule subset, size check, and directory exclusions.
- VS Code current-file and save/realtime scans use `TextDocument.getText()` and pass supplied content plus resolved policy to `CoreClient.fileScan`. The save adapter reads the buffer only when the existing debounced task is admitted by `runScan`. Agent scans retain their existing implementations.
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

The file operation uses Core's native file-rule subset plus supplied portable regex rules. The VS Code adapter resolves the current-file line rules and configured rules into that subset. Optional `caseSensitive` preserves built-in rule matching; absent retains case-insensitive configured-rule behavior. Comment stripping and file-specific language checks are limited to supplied-content scanning, leaving workspace scan behavior unchanged. Some language-rule details may still differ from `src/scanner/rules.ts`. Source content is not copied into result evidence, event payloads, or Core request logs; file events contain only scan id, path, state and counts.

The result is `CoreFileScanResult`: canonical request-derived `scanId`, `filePath`, `state` (`completed` or `skipped`), optional bounded `skipReason`, canonical `UnifiedFinding[]`, `filesScanned`, `findingCount`, and `durationMs`. Malformed requests fail through the existing Core protocol error envelope. Cancellation uses existing `core.cancel` with the request id; start/completion events use that same id. The operation does not generate a report or telemetry snapshot.

## Current-file migrated; other callers not migrated

`ScanController.scanCurrentFile` and the debounced realtime/save adapter invoke `CoreClient.fileScan`, passing the editor/document's in-memory content and resolved policy. Both reconstruct `AqironIssue.lineText` locally from the same content snapshot. Workspace scans, workspace-Agent, and secret-Agent callers remain on their existing paths. `WorkspaceScanner` remains for Agent workspace scanning and the separate post-fix current-document flow; `scan.start` is unchanged. Client adapters continue to own:

- resolving VS Code settings, workspace trust, Flutter/project gates, custom-rule configuration and `.aq`/glob semantics;
- `TextDocument` access, save listeners, debounce, active-scan fallback, editor generations, cancellation UX and diagnostics;
- Agent secret-only filtering, five-location message limit, issue merging, error presentation and result serialization;
- conversion such as `UnifiedFinding → AqironIssue` and client-specific UI projection. Current-file projection preserves rule metadata, range, severity, and issue ID format; webview serialization continues through its existing redaction boundary.

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

## Current-file parity audit

The fixture comparison now checks issue file, title, message, rule ID, severity, and full source range against `scanContent`. The vulnerable and clean fixtures, configured custom rule case, supported-extension policy list, unsaved-buffer input, Flutter gate, and representative `.aq`/generated/minified skips are covered.

Parity differences resolved by the audit:

- **CORS case matching:** the legacy JavaScript rule is case-insensitive. Converted current-file rules preserve that flag, so uppercase forms such as `CORS({ ORIGIN: '*' })` remain detectable.
- **Minified-content threshold:** Core's file-only skip predicate now matches the legacy current-file basename and content thresholds. A long line in otherwise short content is scanned; `.min.` files and content meeting both legacy length thresholds are skipped.
- **Python multiline strings:** Core's file-only Python comment stripper now tracks triple-quoted strings across lines, so rule-like text inside a docstring remains non-executable as in the legacy path.
- **Skipped metadata:** VS Code sets `eligible: false` and supplies the exact path in `excludedPaths`; Core reports `state: skipped` with `filesScanned: 0` and generic `ineligible`. For compatibility the command still reports one current-file target in its client scan stats and ignores the Core skipped-state reason. The result/event metadata therefore differs while the visible finding list remains empty.
- **Compiled extensions:** `.class` and other compiled outputs are not in the current supported-extension set. The VS Code command rejects them before calling Core, so Core's compiled-file policy is not exercised by this client path.

Workspace isolation was checked separately: `scanWorkspace` still enumerates disk files and calls its existing `scanFile` implementation, which still scans raw lines with evidence. Comment stripping, custom-rule matching and the added unused-variable/long-function checks are only called by `scanFileContent`; the workspace path does not execute them. A regression test confirms comment-line findings remain in workspace scanning while file-content scanning strips that comment.
