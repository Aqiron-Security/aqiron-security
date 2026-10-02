# File and Agent Scan Characterization

Status: original characterization baseline. The current-file command and save/realtime path now use `scan.file`; Agent workspace and Agent secret scans remain on their characterized paths. The baseline below records legacy behavior that migration must preserve.

## Runtime call graphs

### A. Current-file scan

```text
VS Code command aqiron-security.scanCurrentFile
  → ScanController.scanCurrentFile
  → activeTextEditor.document + workspace/Flutter eligibility
  → runScan admission
  → TextDocument.getText() + resolved file policy
  → CoreClient.fileScan → scan.file → UnifiedFinding[]
  → shared VS Code projection (AqironIssue + local lineText)
  → diagnostics / issue store / sidebar
```

The `scanCurrentFile` command is registered in `src/extension.ts`. The webview and tree provider can invoke the command, but neither owns a separate current-file scan implementation. `WorkspaceScanner.scanFile(uri)` is a separate disk-reading API; repository call-site search found no production caller for it outside `WorkspaceScanner` itself.

### B. Save/realtime scan

```text
VS Code onDidSaveTextDocument
  → ScanController.scanDocumentDebounced(document)
  → enableRealtimeScan setting (default true) + file/supported-extension gate
  → shared Debouncer(800ms)
  → ScanController.scanRealtimeDocument
  → existing runScan admission (active run schedules workspace fallback)
  → document.getText() at task execution + resolved VS Code file policy
  → CoreClient.fileScan → scan.file → UnifiedFinding[]
  → shared VS Code projection (AqironIssue + lineText from captured buffer)
  → diagnostics / issue store / sidebar
```

`scanWorkspaceDebounced` still uses the same `Debouncer` instance, so workspace-folder changes and document saves can replace one another while pending. If the controller is already running when the debounced document task reaches `runScan`, the controller schedules a workspace scan and returns; it does not queue that document for a later file scan. Content is read only after that admission check, at debounce execution time. The existing Flutter gate is now represented as resolved `eligible` policy for Core; there is no new trust check, queue, cache, or document generation tracking. Core request timeout/cancellation failures flow through the same `runScan` failure presentation. `WorkspaceScanner.scanDocument` remains for the separate post-fix scan call; the save/realtime path no longer calls it.

### C. AI-agent workspace scan

```text
Agent prompt
  → selectAgentTool(prompt) selects workspace.scan (unless secret terms select secrets.scan)
  → AqironWebviewProvider.runAgentTool
  → runWorkspaceScan
  → first vscode.workspace.workspaceFolders entry
  → provider-owned WorkspaceScanner.scanWorkspace
  → Flutter workspace gate
  → VS Code findFiles(supportedGlob, excludeGlob)
  → per-file WorkspaceScanner.scanUri (disk bytes, local scanContent rules)
  → AgentToolResult { content, commands, issues, stats }
  → finishAssistantMessage updates shared provider state and posts serialized state
```

This agent scanner is a separate `WorkspaceScanner` instance from the controller's instance. It invokes the extension's local Aqiron rules, not Semgrep, Trivy, OSV, Betterleaks, MobSF, or another external scanner. The current Core workspace scan is a different path with Core-owned native and registered scanners.

The agent path does not add filtering to the `AqironScanResult.issues` list. It returns all issues from its `WorkspaceScanner`, and reports the file count and issue count in a short content string. It uses the first workspace folder. It has no explicit trust gate. Flutter gating happens inside `WorkspaceScanner.scanWorkspace`.

### D. AI-agent secret scan

```text
Agent prompt containing secret/token/key/credential/password terms
  → selectAgentTool chooses secrets.scan before workspace.scan
  → AqironWebviewProvider.runSecretsScan
  → same provider-owned WorkspaceScanner.scanWorkspace as C
  → filter result.issues by case-sensitive ruleId substring:
      secret | api-key | password | private-key | token
  → generate a count and at most five path/line bullets
  → merge new secret issues with existing non-secret provider issues
  → AgentToolResult and serialized Agent UI state
```

No secret-specific scanner is invoked. Secret findings use the same local rule engine as the agent workspace scan. `runSecretsScan` does not catch scanner failures; the enclosing webview message handler catches them and shows a VS Code error message. The result content avoids displaying the matched value, but `AqironIssue.lineText` retains the entire original source line. `serializeIssue` sends trimmed `lineText` without applying `redactWebviewEvidence` to that field, so the Agent UI state can contain the source line, including a matched secret. Raw evidence has a separate redaction function; it does not redact `lineText`.

## Observed behavior

| Behavior | Current-file | Realtime | Agent workspace | Agent secret | Core equivalent today |
|---|---|---|---|---|---|
| Entry and caller | Command → `ScanController.scanCurrentFile` → `CoreClient.fileScan` → `scan.file` | `onDidSaveTextDocument` → existing controller debounce → `CoreClient.fileScan` → `scan.file` | Agent tool → provider method | Agent tool → provider method | `scan.start` through Core client/runtime for workspace scans |
| Input model | `TextDocument` buffer | Saved-document event object; latest `getText()` read after debounce and active-run admission | Workspace folder path plus files enumerated by VS Code | Same workspace scan, then rule-ID filter | Workspace root, target path, mode, trust flag; no document-content field |
| Source bytes | Adapter snapshots `document.getText()`; Core analyzes supplied buffer including unsaved edits | Core receives the latest in-memory text captured when the debounced scan begins; it does not read disk | `fs.readFile` from disk | `fs.readFile` from disk | `scan.file` accepts explicit content; workspace operation remains disk-backed |
| Workspace/project gate | Supported file, workspace membership, Flutter | Setting + file URI/extension first; Flutter gate in scanner | Flutter gate in scanner | Flutter gate in shared scanner | Core scan accepts workspace paths and does not reproduce the extension's Flutter-only command gate |
| Workspace trust | No explicit check | No explicit check | No explicit check | No explicit check | Request validates `trusted` as true, but extension adapter supplies that value; this is not equivalent to a VS Code trust decision for local editor content |
| Rules/scanners | Adapter resolves existing line rules/configured custom rules; Core scans supplied content and returns canonical findings | Same resolved file-rule policy and Core analysis as current-file scanning | Same local scanner/rules | Same local scanner/rules; filters result afterward | Core file operation supports supplied custom rules; some rule behavior remains a parity caveat |
| Supported extensions | `.dart`, `.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.rs`, `.java`, `.c`, `.cpp`, `.h`, `.json`, `.xml`, `.yaml`, `.yml`, `.gradle`, `.rules` | Same | Same glob/extensions | Same | Core scanner support is scanner-specific; no contract for this extension list |
| Custom rules | `aqiron-security.customRules` via VS Code configuration; built-in defaults apply when setting is absent; invalid entries/regexes are ignored | Same VS Code setting resolved into the portable Core policy | Same provider process/config | Same, then secret rule-ID filter | Not supplied to workspace scan orchestration; supplied to `scan.file` |
| Exclusions/generated files | `getSkipReason`: `.aq`, configured/default folders, generated policy, minified files, compiled outputs | Same | Static VS Code `excludeGlob` plus per-file `getSkipReason` | Same | Core has its own exclusions/configuration; parity with `.aq`, VS Code settings, and generated-file policy is unproven |
| Size policy | `scanDocument` does not call `getMaxFileSizeBytes`; content size is not capped here | Same | `scanUri` skips disk files over configured `maxFileSizeKB` (default 512 KB) | Same | Core currently uses its own scanner-specific limits; no equivalent resolved VS Code max-size input |
| Cache | Legacy `scanDocument` wrote an entry but did not read it | No new cache; file scan is content-driven | Uses a per-instance path + `mtimeMs` + size cache in `scanUri` | Same agent scanner/cache | Different Core scanner caches; no parity contract |
| Concurrency | Single `runScan` guard; while another scan runs the request schedules a workspace scan | Shared 800 ms debounce; one active controller scan | Per-file batches of 50 run concurrently; batches are sequential | Same as agent workspace | Core worker queue and scanner execution policy differ |
| Result shape | `AqironScanResult` adapter result with projected `AqironIssue[]`; reports one file even when skipped | Same local result | `AgentToolResult` with summary, command, all issues, file-count stats | Same shape but only secret-rule issues are merged into the issue state; content lists at most five locations | `scan.file` returns `CoreFileScanResult` with `UnifiedFinding[]`; client projects findings |
| UI/diagnostics | Replaces that file in `issuesByFile`, then refreshes all diagnostics and sidebar state | Same | Agent result updates provider state and posts Agent UI state; no diagnostic-manager call here | Preserves existing non-secret issues, replaces prior secret issues, updates counts/risk from merged state | Core scan events are projected by the VS Code adapter; they do not implement the Agent tool result contract |
| Error behavior | Core IPC errors flow through controller `runScan`, which marks Failed, logs and shows an error | Same Core error/cancellation path through `runScan` | Per-file `scanUri` catches stat/read errors and skips that file; top-level `findFiles` errors propagate to webview handler | Top-level scanner errors propagate to webview handler | Core returns IPC error/cancellation contracts; UI presentation is client-owned |

## Detailed current-file contract (original characterization; command now uses Core)

- **Saved and unsaved input:** the command gets the active `TextDocument`, snapshots `document.getText()`, and passes it to `CoreClient.fileScan`; it does not read disk. An unsaved edit is scanned. The separate legacy `scanFile` method reads disk.
- **Supported types and language dispatch:** `isSupportedFile` is extension based and requires the `file` scheme. `scanContent` dispatches Dart, JavaScript/TypeScript, Python, C/C++, and Java rules. Other supported extensions get secret checks and configured custom rules, but not equivalent language-specific rules. In particular `.rs` is accepted but currently receives fallback secret/custom checks.
- **Flutter gating:** the command requires a workspace folder and `isFlutterWorkspace`; `WorkspaceScanner.scanDocument` repeats the gate. Flutter is detected from `pubspec.yaml` content (`flutter:`/`flutter_test:`) or `.metadata`.
- **Rule matching and severity:** the adapter resolves current-file line rules/configuration into the Core rule contract; Core returns canonical findings. The adapter projects `AqironIssue` and reconstructs source line from the captured content. Cross-language differences from the former local matcher remain a parity caveat. Diagnostic mapping remains Critical/High→Error, Medium→Warning, Low→Information.
- **Skip and size behavior:** document scans apply `.aq`, configured/default folder exclusions, generated-file policy, minified-file detection, and compiled-output policy through `getSkipReason`. They do not enforce `maxFileSizeKB`. They return `filesScanned: 1` even when unsupported or skipped. `scanFile`/workspace enumeration use disk size and report zero scanned on skips.
- **Cache behavior:** `scanDocument` writes `{Date.now(), text.length, issues}` to the scanner cache but never reads it. `scanUri` reads cached results when path, stat mtime, and size match. It does not include rule/config/exclusion versions or a content hash; unchanged metadata can therefore serve stale results after a file or rule change.
- **Errors and projections:** `scanDocument` itself does not catch errors. The controller catches them around the scan task and sets failure UI status. `filterVisibleIssues` suppresses internal Aqiron issues now excluded by policy; external-tool findings are deliberately exempt. `DiagnosticManager` clears and repopulates diagnostics from all file buckets; source is `Aqiron Security`, code is `ruleId`, and severity maps as above.

## Core contract gaps

### Required for parity before migration

1. **Explicit file target semantics:** Core needs a request that means “scan this one file” and does not silently scan the full workspace. `targetPath` on `scan.start` does not currently establish equivalent file-only behavior for native/Core scanners.
2. **In-memory content input:** current-file and save scans use editor-buffer text. Core needs an explicit content/revision input or a documented host adapter that supplies those bytes without reading a stale disk copy.
3. **Resolved policy input:** reproduce the effective supported extensions, Flutter/project gate, configured custom rules (including built-in defaults), `.aq` and folder exclusions, generated/minified/compiled policy, and file-size policy. Preserve the current per-path difference where file scans have no max-size cap and workspace enumeration defaults to 512 KB unless Aqiron intentionally changes it.
4. **Finding compatibility conversion:** preserve rule IDs, severities, messages, source line text, and zero-based ranges expected by diagnostics, quick fixes, and the issue store, or provide a tested adapter conversion.
5. **Agent result projection:** keep the `AgentToolResult` content/commands/issues/stats shape and the secret tool's current filtering, merge, display cap, and error behavior until an intentional UI contract change is approved.
6. **Concurrency and cache semantics:** characterize and choose explicit replacements for the current 800 ms shared debounce, 50-file batches, active-run deferral, and cache invalidation. Cache contents cannot be assumed equivalent across Core and the current VS Code instances.

### Nice to have

- A content hash and resolved-policy fingerprint in cache keys.
- Explicit cancellation for current-file/realtime scans and per-document scan generations to prevent stale diagnostics.
- One declarative rule catalog shared by Core and the extension, with the same language dispatch and severity mapping.
- A structured secret-only selection/filter operation if another client needs the same behavior. Agent wording, command labels, five-line summary cap, and state merge remain presentation concerns.
- A stable scanner result summary that separates “files selected”, “files scanned”, and “files skipped”; current `scanDocument` uses `filesScanned: 1` for skipped results.

## Preserve versus intentional future changes

### Preserve for a behavior-parity migration

- Current-file and realtime scans must observe the VS Code document buffer, including unsaved content, and return file-relative issue locations.
- The existing Flutter/workspace/file gates, rule IDs and severities, custom-rule settings, exclusion behavior, and diagnostic/status projection must remain stable until parity tests pass.
- Workspace-based agent scans must keep using the same issue set and workspace scope. The secret tool must continue to exclude non-secret rule IDs, retain all secret issues in its result/state, display at most five paths in message content, and preserve existing non-secret issues while replacing prior secret issues.
- Preserve current scanner error propagation and user-visible failure behavior during the first migration step.

### Candidates for separately approved changes

- Apply a size limit to current-file scans, correct skipped-file counts, change Flutter-only gates, improve cache invalidation, remove the shared debounce coupling, or queue a busy document scan instead of requesting a workspace scan.
- Redact secret values from `AqironIssue.lineText` before Agent UI state serialization. This is a distinct security/privacy behavior change and should have dedicated regression coverage; it is not silently folded into a Core migration.
- Change which language extensions receive language-specific rules, expand external scanner participation, change agent summary limits, or change the shape of agent findings/stats.

## Migration order

1. Keep the Core workspace scan authoritative for workspace scans; the current-file command and save/realtime document path now use `scan.file` through VS Code adapters.
2. Keep both Agent tools on their characterized `WorkspaceScanner` path until their filtering, scope, error and UI contracts are migrated separately.
3. Keep the current-file/realtime parity fixtures and compare findings, counts, ranges, diagnostics, cancellation/errors and Agent result payloads for any future changes.
4. Keep VS Code commands, save listeners, document access and Agent UI projection in VS Code adapters.
5. Remove duplicated implementations only after all remaining callers and behavior are covered. `WorkspaceScanner.scanDocument` still serves the post-fix current-document flow; `WorkspaceScanner` itself remains required by Agent scans.

## Characterization coverage and remaining unknowns

Added tests use the Flutter fixture in `src/test/fixtures/file-scan/flutter` and cover built-in vulnerable/clean/comment-only inputs, configured custom rules, unsaved document versus disk content, supported extension/size/skip policy, metadata-keyed cache reuse, 800 ms save-request coalescing, Core-backed realtime policy/projection and busy-scan fallback, Agent workspace result projection, and Agent secret filter/merge/no-result/error/multiple-result behavior.

Still not directly covered: command registration and its warning/info messages; unsupported/untitled command behavior; untrusted-workspace behavior; changing custom rules/exclusions while cache entries exist; concurrent save while an actual scan is still running (the controller busy branch is tested directly); diagnostic severity/source/code assertions against a captured VS Code diagnostic collection; secret rule-ID case sensitivity and every substring; serialization of secret-bearing `lineText`; `findFiles` failure; and multi-folder Agent selection beyond the first folder. These are current source observations, not asserted future contracts.
