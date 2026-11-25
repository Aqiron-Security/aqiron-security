# Evidence Engine V1

## Purpose and scope

Evidence Engine V1 stores and rechecks bounded source-span observations produced during Core native workspace scans. Its role is to preserve a Core-owned link between a native scanner finding and the exact source bytes observed for that finding, then make changed or unavailable source explicit when a hypothesis snapshot is built.

V1 covers local source files only. It does not collect HTTP/API, service, dependency, asset, build, or runtime evidence. It does not perform controlled validation or establish exploitability. A source observation establishes only that a particular scanner finding was associated with a source location and that its recorded digests can still be checked.

## Ownership and trust boundaries

The production path is:

1. `NativeWorkspaceScanner` reads a file and produces a finding plus `FindingSourceProvenance` from that same content.
2. Core's runtime passes that private scan result to `EvidenceEngine.captureScan` after scan execution.
3. `captureScan` validates scanner metadata and independently rereads bounded source bytes before persisting an observation.
4. Hypothesis snapshot construction resolves observations by physical workspace, scan ID, and finding ID, verifies every locator and digest, then rechecks freshness.

The protocol scan response does not contain source provenance or an evidence ID. Callers cannot pass an observation ID, `originatingFindingId`, or source digest through the scan protocol. `EvidenceEngine` is internal to the Core package implementation and is not re-exported from the public package root; its module is not a declared package subpath. Desktop and CLI have no direct evidence-store read/write API in V1.

The filesystem is local workspace state, not a cryptographic trust anchor. A process or user with write access to the workspace can alter or delete its evidence file and source files. V1 detects schema/path/hash inconsistencies and fails closed, but it does not authenticate workspace files against a same-user attacker or provide tamper-evident signatures.

## Observation schema and identity

The persisted store is `.aqiron-security/evidence.json` with schema version `1` and an append-only `observations` array. A `SourceSpanObservation` contains:

- `id`: a Core-generated `ev1_` identifier followed by a UUID. IDs are random and unique per captured observation, not deterministic finding IDs.
- `schemaVersion` and `kind`: version `1` and `source_span`.
- `workspaceIdentity`: the physical workspace root resolved by Core.
- `scanId`: the scan that supplied the provenance.
- `originatingFindingId`: the native finding ID associated by the scanner.
- `collector`: `aqiron.native-scanner`, version `1`.
- `observedAt`: the scanner's observation time.
- `source`: normalized relative path, inclusive one-based start/end lines, full-file SHA-256, and source-span SHA-256.

There is no observation update or delete method. Capture appends new observations; a later scan receives new IDs even if the source and finding are unchanged. Returned objects are snapshots; mutating a returned JavaScript object does not mutate the persisted store.

## Scanner provenance and digest semantics

Native scanner provenance records the finding ID, file, line range, source tool, rule ID, time, and the two scanner-time digests. Evidence capture accepts provenance only when the source tool is the native Core scanner, paths and line bounds are valid, and both digests have the expected SHA-256 form. Capture rereads the file with a bounded byte read, decodes strict UTF-8, and requires both digests to match before it creates an observation.

The full-file digest is SHA-256 of the exact decoded UTF-8 text, including line endings. The span digest hashes the selected inclusive one-based lines after the source line index's LF normalization. Spans are limited to 20 lines and 64 KiB. Capture bounds an individual source file at 10 MB, aggregate capture reads at 50 MB, provenance input at 10,000 records, and the persisted store at 20,000 observations and 5 MB.

Path handling rejects absolute paths, traversal, empty/dot segments, symlinked path components, and physical paths outside the resolved workspace. Store reads require bounded reads plus `lstat` and `realpath` checks. Workspace identity comparisons use the physical root, with case folding on Windows.

## Workspace and scan association

`findForFinding` returns only observations whose workspace identity, scan ID, and originating finding ID all equal the requested values. Snapshot construction then requires exactly one observation and checks the physical workspace, scan, finding ID, relative path, inclusive span, span digest, and full-file digest against the current scan provenance.

- No association: retain the historical `span:` reference form, if the current file still matches scanner provenance.
- One exact association: use the canonical `ev1_` observation ID and recheck it.
- A contradictory or duplicate association: exclude the finding from the snapshot; do not downgrade it to a current legacy reference.
- A stale or unavailable exact observation: retain its canonical ID with stale freshness, which fails evidence-reference validation and cannot be used as current evidence.

An observation from another workspace or scan does not match the lookup and cannot be selected as a canonical association. V1 deterministic hypothesis IDs remain independent of random evidence IDs: canonical source spans are reduced to a stable path/span/digest key when the candidate ID is computed.

## Freshness and validation

`recheck` first reloads the observation by ID and requires the supplied observation to match the persisted record exactly. It then revalidates workspace identity and source path safety, performs a bounded strict UTF-8 read, and recomputes both digests.

Freshness results are:

- `current`: both full-file and span digests match.
- `stale`: the full file or span changed.
- `unavailable`: the file is missing, unsafe, unreadable, oversized, or invalid UTF-8.
- `not-rechecked`: a type-level state for callers that have not performed a check; Core does not promote it to current evidence.

Canonical hypothesis references carry `referenceOrigin: canonical` and `canonicalFreshness`. `current` requires ordinary freshness `current`; `stale` or `unavailable` requires ordinary freshness `stale`. Legacy references may omit both markers or use `referenceOrigin: legacy`, but cannot carry canonical freshness. A canonical ID without canonical markers is rejected. Snapshot/reference validation and persisted-store validation apply the same marker rules. Historical markerless records with legacy `span:` IDs remain readable without migration.

Hypothesis AI preparation additionally validates selected references against the Core snapshot and rechecks source excerpts under bounded read budgets. Preparation is a local disclosure preview. The production synthesis route remains disabled; this document does not authorize provider execution.

## Persistence, locking, and recovery

Evidence operations use the workspace lock implementation shared with the hypothesis store (`.aqiron-security/hypotheses.json.lock` and its recovery gate). The lock serializes in-process and cross-process operations, records an owner PID/token, and uses bounded acquisition. Lock release occurs in `finally`. Ambiguous or malformed lock ownership fails closed and can require manual recovery after Core processes stop.

Writes serialize the whole bounded store to a randomized sibling `.tmp` path created with exclusive `wx` semantics. If writing fails after creation, the adapter closes its owned handle and leaves any partial file as an orphan. Callers do not unlink temporary paths after write or rename failures because pathname cleanup cannot safely establish ownership after an ambiguous failure. Evidence reads ignore `.tmp` files and read only the primary store; backup discovery is limited to `.bak` names.

When replacing an existing primary, Core first renames it to a randomized `.bak`, then renames the completed temporary file into place. If installation fails, Core attempts to restore the backup. If restoration also fails, the prior committed contents remain in the recovery backup. Backup cleanup after a successful replacement is best-effort. No write path truncates the existing primary in place.

Recovery occurs only when the primary is absent. It accepts at most 32 backup candidates, checks regular-file and physical-path safety, bounded size, JSON/schema validity, unique observation IDs, and workspace identity for every observation. All candidates must have identical contents before one is installed. Invalid, foreign-workspace, or conflicting backups are preserved and rejected. A corrupt existing primary is preserved and reported as an error; it is not silently replaced by a backup. Interrupted `.tmp` files are not recovery candidates.

The shared workspace lock and atomic rename behavior assume filesystem operations provide their usual local-filesystem semantics. Network filesystems, filesystem corruption, process termination during multi-rename replacement, and same-user concurrent tampering are not covered by an OS-level durability or adversarial isolation guarantee.

## Security invariants

- Core creates observation IDs; protocol callers do not supply them.
- Only native scanner provenance is eligible for capture, and capture rechecks source bytes before persistence.
- Canonical association requires exact workspace, scan, finding, path, span, and digest agreement.
- Duplicate or contradictory associations fail closed; stale/unavailable evidence is never current.
- Cross-workspace store records and recovery backups are rejected.
- Temporary write failure leaves an orphan; cleanup never uses pathname-based deletion of a possibly replaced temporary file.
- Existing committed evidence is retained as the primary or in a recovery backup on replacement failure.
- Evidence storage does not rewrite scanner findings or reviewer metadata. Hypothesis generation preserves prior review state for matching hypotheses; AI proposals append new hypotheses and reject ID collisions rather than updating existing findings or hypotheses.
- Production hypothesis synthesis is disabled by a fixed source constant. No environment variable, CLI option, protocol field, Desktop argument, or `runCoreRuntime` option enables it. Source-level tests can inject a test executor through an internal constructor seam, which is not exposed through the package root or production runner.

## Implemented V1 and limits

Implemented: native source-span capture, immutable append observations, bounded persistent storage, workspace/scan/finding association, freshness rechecks, canonical hypothesis references, explicit legacy compatibility, workspace locking, atomic replacement with backup recovery, and local tests for collisions, partial writes, recovery, concurrent appends, and bounded listing.

Not implemented: independent signatures or tamper-proof storage; retention/compaction/deletion policy; cross-device evidence identity; event/audit history for evidence; a public evidence query protocol; Desktop/CLI evidence browsing; service/API/dependency/asset evidence; controlled validation; or automation. Orphan `.tmp` files are ignored and are not automatically pruned, so repeated interrupted writes can consume workspace disk space.

## Deferred roadmap

These are future investigations, not V1 behavior or delivery commitments:

| Area | Deferred work | Dependencies and open decisions |
|---|---|---|
| Collectors | Additional deterministic collectors | Define collector trust, schema evolution, byte budgets, and duplicate semantics. |
| Network and service | HTTP/API endpoint and service evidence | Define authorization, secret handling, active-request policy, and durable endpoint identity. |
| Assets and dependencies | Asset and dependency evidence | Agree canonical asset identity and ownership across scanners and package ecosystems. |
| Verification | Controlled validation and reproducible verification | Require a separate safety policy, reproducibility model, permissions, and audit trail. |
| Human workflows | Research workflows and reviewer controls | Define roles, evidence citations, immutable review events, and product interaction. |
| Relationships | Typed evidence relationships and provenance expansion | Specify versioned edge types, derivation provenance, and contradiction semantics. |
| Lifecycle | Evidence retention and lifecycle policy | Decide retention period, user deletion/export, store compaction, and backup lifecycle. |
| Clients | Desktop and CLI evidence consumption | Design a versioned read-only API and client UX without caller-supplied provenance. |
| Automation | CI integration and automation | Define noninteractive workspace trust, artifact retention, and failure/reporting contracts. |
| Isolation | Stronger cross-process or OS-level trust boundaries | Assess target platforms, ACLs, handle-based operations, and network filesystem support before choosing controls. |

Any production synthesis activation requires a separate security and product decision. Evidence Engine V1 acceptance does not grant that authorization.
