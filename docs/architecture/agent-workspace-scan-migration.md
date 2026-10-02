# Agent workspace scan migration

**Status:** `workspace.scan` and `secrets.scan` are Core-backed through the existing `scan.start` operation. Agent-specific selection, filtering, summary, merge, projection and redaction remain in the VS Code adapter.

## `secrets.scan` inventory and Core parity decision

**Migration completed:** Core performs the security analysis; the Agent adapter retains the characterized host gate and applies the same case-sensitive secret rule-ID substring filter (`secret`, `api-key`, `password`, `private-key`, `token`). The adapter still owns issue projection, merge/replacement, summary wording and five-location cap, errors, state, and serialization redaction.

### Exact legacy dependencies

- **Entry/selection:** secret-related prompt terms select `secrets.scan` before the general workspace scan. The provider selects `vscode.workspace.workspaceFolders[0]`; no multi-root iteration occurs.
- **Scope/gate:** `WorkspaceScanner.scanWorkspace` requires a Flutter workspace, enumerates VS Code `findFiles` with `supportedGlob`, then filters file URIs/extensions. The supported extensions are `.dart`, `.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.rs`, `.java`, `.c`, `.cpp`, `.h`, `.json`, `.xml`, `.yaml`, `.yml`, `.gradle`, `.rules`.
- **Exclusions:** VS Code `excludeGlob` omits common build/vendor directories and generated suffixes; per-file `getSkipReason` adds default/configured excluded folders, `.aq` exclusions, generated code policy, minified-content checks and compiled-output extensions.
- **Size/cache/concurrency:** `scanUri` checks configured `maxFileSizeKB` (default 512 KB), then caches by path + mtime + size. Files run in batches of 50 with `Promise.all` per batch. These affect the old workspace tool's eligible file set and counts, not just performance.
- **Local secret rules:** `src/scanner/rules.ts` emits `critical.api-key` for generic API/client/access keys and AWS `AKIA…`, Google `AIza…`, and `sk|pk_(live|test)_…` patterns; `critical.secret` for quoted `secret`/`token` assignments; `critical.password` for quoted passwords; and `critical.private-key` for supported PEM private-key headers. Generic assignment expressions use case-insensitive regex flags; the AWS/Google/provider token and PEM patterns have no `i` flag. The local rule catalog applies across its supported language dispatch.
- **Agent filter:** `isSecretRule` is case-sensitive and accepts only rule-id substrings `secret`, `api-key`, `password`, `private-key`, or `token`. It does not consult finding tags, source tool or evidence.
- **Projection/presentation:** all matching issues are retained in `AgentToolResult.issues`; the text summary includes the total and at most five path/line locations. Secret findings replace prior secret findings while prior non-secret Agent issues remain (`mergeIssues` dedupes by issue id). No-match text reports scanned file count. Scanner failures propagate to the enclosing Agent message handler, which presents a VS Code error.
- **Privacy:** summary locations contain paths/lines, not values. Issue `lineText` may hold source text internally, but webview serialization redacts the matched secret source span before client state is posted. Keep this serialization boundary unchanged.

### Core secret capability and Agent migration

Core's always-present `NativeWorkspaceScanner` now applies the seven characterized deterministic patterns with legacy IDs (`critical.api-key`, `critical.secret`, `critical.password`, `critical.private-key`) to files in its native workspace source/config scope and to explicit `scan.file` content. When one of these exact patterns overlaps Core's older Dart-only secret rule, Core emits the legacy-ID finding instead of a duplicate; the older rule remains as a Dart-specific fallback for shorter literals outside the legacy patterns. Native workspace enumeration includes the characterized legacy extension set for this capability; the pre-existing non-secret native rule set remains limited to its prior targets. Secret findings contain rule/location/safe metadata and omit source-line evidence. If a native finding on the same line could otherwise carry matched secret text as raw evidence, that evidence is omitted as well.

`secrets.scan` invokes generic `scan.start` in quick mode with `includeExternalScanners: false`; no Agent-specific Core operation or external-scanner findings are involved. This preserves the old local-rule-only execution scope and avoids exposing scanner output through Core events. The Core response still includes other native findings, which the unchanged Agent filter drops unless their rule ID contains one of the established substrings. In particular, Core's pre-existing `native.dart.hardcoded-secret` fallback can add short Dart secret findings that the legacy seven-pattern rules did not produce; this is an additive coverage difference, not a change to the Agent filter.

The Agent resolves and sends the portable `ResolvedWorkspaceScanPolicy`; Core consumes it for extension scope, directory/file exclusions, ordered `.aq` rules, generated/minified/compiled skips, byte-size limits and custom rules. Workspace existence, first-folder selection, Flutter eligibility and actual trust remain host inputs. Core trust is recorded/validated but is not an enforcement policy. There is no workspace cache equivalent, and Core traversal/counting may differ from VS Code `findFiles`; skipped or unreadable files remain absent from the aggregate count. Core correlation can also normalize/deduplicate findings. These are documented remaining parity caveats; they do not cause the adapter to union old scanner output. Webview redaction remains mandatory because the Agent edge reconstructs source-line context for issues.

## Workspace policy inventory and contract preparation

**Current Agent secret path:** `runSecretsScan` selects the first VS Code workspace folder, applies the Flutter eligibility gate, resolves effective policy, and invokes Core. This replaces the former `WorkspaceScanner.scanWorkspace` path described below as historical characterization. The adapter passes `vscode.workspace.isTrusted` as received; Core currently validates but does not enforce trust policy.

| Existing input/decision | Effective current value/source | Portable contract mapping | Ownership / caveat |
|---|---|---|---|
| Workspace selection | First VS Code workspace folder | `workspaceRoot` on a future scan request | VS Code adapter; do not switch to all folders during migration. |
| Workspace/Flutter eligibility | Folder must exist; `WorkspaceScanner` reads Flutter markers | Not included in `ResolvedWorkspaceScanPolicy` | VS Code host gate. Core must not detect Flutter. Agent scan reports zero scanned on a non-Flutter workspace through the existing scanner. |
| Trust | Agent secret path currently does not inspect trust | Separate top-level `trusted` request value, sourced from `vscode.workspace.isTrusted` | Host state, not a scan policy field. Existing `scan.start` validates/receives this boolean but does not enforce a trust policy. Add no stronger assumption during migration. |
| Supported scope | `.dart`, `.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.rs`, `.java`, `.c`, `.cpp`, `.h`, `.json`, `.xml`, `.yaml`, `.yml`, `.gradle`, `.rules` | `supportedExtensions` | Resolver copies the current `supportedExtensions` set. This task does not broaden it. |
| Static workspace selection exclusions | `excludeGlob` filters standard vendor/build directories and generated filename patterns before `scanUri` | `excludedDirectoryPaths` plus `excludedFileNamePatterns` | The policy resolver carries the current directory fragments and file-name globs as separate portable values. These selector exclusions remain unconditional even when `scanGeneratedFiles=true`. |
| Configured/default folders | `aqiron-security.excludeFolders`; defaults in `src/utils/files.ts`; matching is case-insensitive path-fragment matching anywhere in the normalized path | `excludedDirectoryPaths` | Resolver unions defaults and configured values, normalizes separators/case, and removes duplicates. Core policy matching must preserve the path-fragment semantics rather than silently interpreting these as arbitrary globs. |
| `.aq` rules | Existing `.aq` file lines, after blank/comment filtering, appended to defaults; ordered `!` rules can re-include a path; default list is used when no `.aq` exists in a Flutter workspace | `aqExclusionPatterns` | Carries the existing ordered `.aq` pattern syntax, not raw settings or source content. Preserve current `.aq` matcher semantics and ordering; do not invent a replacement glob language. |
| Generated files | `scanGeneratedFiles` defaults false; `getSkipReason` applies generated suffix/path/header checks when false. Static `excludeGlob` still omits several generated name patterns when true. | `skipGeneratedFiles` plus `excludedFileNamePatterns` | The policy keeps the configurable heuristic distinct from unconditional selector exclusions. This split is needed to represent the actual setting behavior. |
| Minified files | Always skipped by basename `.min.` or when first-20-line longest length exceeds 1000 and average line length exceeds 300 | `skipMinifiedFiles: true` | No current setting disables it. The Core implementation must match both conditions before migration. |
| Compiled outputs | `getSkipReason` recognizes `.class`, `.jar`, `.wasm`, `.dll`, `.exe`, `.o`, `.obj`, `.so`, `.dylib`; most are already outside the supported extension selector | `skipCompiledFiles: true` | The current per-file check is retained in the contract, though the workspace supported-file gate makes much of this path unreachable. |
| Size | `aqiron-security.maxFileSizeKB`, default 512; effective bytes are `Math.max(1, setting) * 1024`; compare filesystem `stat.size > limit` | `maxFileSizeBytes` | Workspace only. `scanDocument` has no corresponding cap. A size skip produces no findings and zero scanned files, with no per-file reason in the aggregate. |

### Resolved policy wired to `scan.start`

`packages/core/src/shared/workspaceScanPolicy.ts` defines `ResolvedWorkspaceScanPolicy`. `src/utils/files.ts` exports `resolveWorkspaceScanPolicy(root)`, which resolves current VS Code settings, custom rules and `.aq` rules into that type. `scan.start` validates and passes it to Core's native workspace traversal. It contains no `TextDocument`, source content, credentials, Flutter eligibility or trust. Tests cover deterministic policy resolution and Core enforcement.

This policy is used for Agent `secrets.scan`; existing non-Agent workspace scan requests omit it and retain their current behavior. VS Code keeps first-folder selection, Flutter eligibility and trust resolution. Agent secret filtering, merge, summary cap and redaction remain at the client edge.

## Call paths

Before:

```text
Agent tool selection
  → AqironWebviewProvider.runWorkspaceScan
  → first VS Code workspace folder
  → provider-owned WorkspaceScanner.scanWorkspace [former path]
  → VS Code findFiles + local scanContent rules/cache [former path]
  → AqironScanResult / AqironIssue [former result]
  → AgentToolResult summary + UI state
```

Current:

```text
Agent tool selection
  → AqironWebviewProvider.runSecretsScan
  → first VS Code workspace folder + Flutter eligibility + workspace trust
  → resolveWorkspaceScanPolicy + CoreClient.startScan / scan.start (quick, native-only)
  → Core policy-aware native workspace traversal, findings, correlation, report
  → request-correlated Core pipeline events → Agent pipeline projection
  → UnifiedFinding → AqironIssue + local source-line context
  → existing AgentToolResult summary/stats and UI state
```

No Agent-specific IPC was added. The scan request id is generated by the Agent adapter and used to correlate progress and cancellation with that scan. Agent UI wording, command metadata, result state, and failure presentation remain client-owned.

## Behavior comparison

| Behavior | Previous Agent workspace scan | Core-backed Agent workspace scan | Classification / migration note |
|---|---|---|---|
| Workspace selection | First entry in `vscode.workspace.workspaceFolders` | Same first entry | Preserved product behavior. |
| Flutter gate | `WorkspaceScanner.scanWorkspace` returned an empty, zero-file result for non-Flutter workspaces | Agent adapter keeps the Flutter gate and returns the same empty-result shape without invoking Core | Preserved existing VS Code product gate; Core remains client-neutral. |
| Workspace traversal | `vscode.workspace.findFiles` scoped to the workspace with `supportedGlob` and static `excludeGlob` | Core filesystem/native traversal and registered scanner targets | Intentional ownership change; traversal implementation and resulting file count can differ. |
| Supported extensions | `.dart`, `.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.rs`, `.java`, `.c`, `.cpp`, `.h`, `.json`, `.xml`, `.yaml`, `.yml`, `.gradle`, `.rules` | Core native scanner and each registered external scanner have their own target coverage | Behavior differs; extension's local list is no longer the complete scan boundary. |
| Local rules | `src/scanner/rules.ts` `scanContent` rules and VS Code custom rules | Core native rules plus registered scanner findings | Intentional move to Core authority, but rule ids/coverage can differ; do not claim finding parity. |
| External scanners | None in this Agent path; it used local rules only | `scan.start` deep mode uses Core scanner orchestration, which can invoke registered external scanners | Intentional product capability change from using the shared Core workspace engine. Availability/errors follow Core scanner results. |
| Custom rules | Local `aqiron-security.customRules` configuration | Not explicitly passed to `scan.start`; Core runtime uses its own scanner configuration | Known lost behavior for Agent workspace scans. Core `scan.start` has no resolved custom-rule field; do not imply these rules are applied. A future explicit portable configuration contract is needed. |
| Exclusions | VS Code static glob, configured/default folder exclusions, `.aq`, generated/minified/compiled checks | Core's fixed scanner-context exclusions and scanner-specific behavior | Known parity difference. VS Code `excludeFolders`, `.aq` and local generated-file policy are not resolved into `scan.start`. |
| Generated/minified/compiled files | Local `getSkipReason` policy, including generated suffixes, content heuristics and compiled extensions | Core workspace scanner has its own path/scanner behavior; it does not receive these VS Code policies | Known parity difference; adapter does not attempt to emulate a per-file policy over a workspace scan. |
| Maximum file size | Configured `maxFileSizeKB` applied per file (default 512 KB) | Core scanner-specific limits; no VS Code size setting passed in this request | Known parity difference. |
| Cache | Per-Agent-scanner path + mtime + size cache | Core operation has no equivalent VS Code `WorkspaceScanner` cache contract | Intentional removal of this adapter-local cache from the Agent path; no new cache was added. |
| Concurrency | Files grouped in batches of 50; each batch uses `Promise.all` | Core native traversal and bounded Core scanner queue/order | Intentional orchestration ownership change; concurrency and scanner order may differ. |
| Error handling | Individual file stat/read errors were logged and skipped; workspace `findFiles` errors propagated | Core request failures are surfaced in Agent result, mark status Failed and show the existing VS Code error notification; individual Core scanner failures may be returned as tool results | Intentional use of Core failure semantics; no failure is presented as success. |
| Finding model | `AqironIssue[]` directly from local scanner | `UnifiedFinding[]` converted at the Agent edge to `AqironIssue[]` | Required client projection. Source line is read at the adapter edge for UI context and continues through the existing webview redaction boundary. |
| File counts | Count of successfully scanned enumerated files | `CoreScanStartResult.filesScanned` (fallback zero if omitted) | Count semantics can differ due traversal/scanner coverage. Agent still exposes `filesScanned` and `indexedFiles`. |
| Summary | Compact “Scanned N files and found M issues” plus `workspace.scan` command | Same summary and command shape on successful scan | Preserved Agent-facing result contract. Failures return an explicit failed summary and unavailable command. |
| Trust | No explicit trust value or gate | Sends current `vscode.workspace.isTrusted` | Trust value is now truthful; Core currently validates the value but does not enforce a scan policy based on it. This is not a security policy guarantee. |
| Cancellation/progress | Agent tool had no Core request correlation/cancel path; local scanner had no exposed cancellation | Existing Agent generation-cancel action requests Core cancellation by request id; correlated Core stage/tool/log events are projected to Agent pipeline state | Adds support using existing generic Core mechanisms; progress comes only from real Core events. |
| Report | Agent result did not expose a Core report | `scan.start` produces the existing Core report result, which this Agent adapter does not expose as a new UI contract | Core behavior is unchanged; report presentation remains outside this migration. |

### Intentional versus accidental differences

The first-folder selection, Flutter-only eligibility, compact Agent summary, command descriptor, Agent-owned filtering/merge and UI state are retained deliberately. Moving deterministic security analysis and orchestration to Core, using Core correlation/report generation, and adopting Core request cancellation/progress are intentional consequences of making Core authoritative. External scanners are disabled for this tool because the former Agent path used only local deterministic rules.

Portable policy now supplies custom rules, configured/default exclusions, `.aq`, generated/minified/compiled policy, extensions and file size to Core. Exact file counts/cache behavior and enumeration semantics still differ from the former VS Code scanner. Core's native non-secret rules also execute but are filtered at the Agent edge; an existing short-literal Dart rule ID contains `secret` and therefore can add results under the unchanged substring filter. The seven characterized legacy patterns remain covered and no external scanner is added to the Agent secret scan.

## Remaining implementation boundaries

- `secrets.scan` now calls `CoreClient.startScan`; no production Agent secret caller invokes `WorkspaceScanner.scanWorkspace`. It filters findings with the existing case-sensitive ID substrings, merges/replaces state, retains all matched issues, caps text at five locations and uses the existing serializer redaction.
- `WorkspaceScanner` and `src/scanner/rules.ts` remain for `ScanController` workspace/current-document paths and characterization coverage. No scanner code was deleted.
- Core progress forwarding filters by the supplied request id and only maps existing stage, scanner, output, completion, cancellation and failure events. Finding events are not copied into Agent progress state.
- The adapter sends `vscode.workspace.isTrusted`; Core's current workspace scan does not use that flag to deny or alter scanning. A future trust/policy decision must be implemented explicitly in Core/runtime contracts.
