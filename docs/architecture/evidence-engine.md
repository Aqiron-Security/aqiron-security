# Aqiron Evidence Engine: source span foundation

> **Historical Milestone 18 architecture; superseded as the current contract.** This document preserves the original source-span foundation design. Milestone 19 added the canonical evidence-to-hypothesis bridge and updated persistence failure semantics. For current V1 behavior, read the [canonical Evidence Engine V1 technical reference](../evidence_engine.md).

## Milestone 18 baseline (historical)

The only supported kind is `source_span`. Core creates one immutable observation for each native-scanner provenance item that passes path, span, source-byte and digest verification. Each observation has a random UUID-backed `ev1_` ID; IDs are not derived from a path, line, finding, or hash. Re-scanning the same location creates a new observation. There is no cross-scan deduplication or subject identity.

Records contain schema version, kind, canonical physical workspace root, Core scan ID, fixed collector ID/version, scan-time timestamp, normalized workspace relative path, inclusive one-based lines, exact full-file UTF-8 SHA-256 and LF-normalized span SHA-256. Raw source text is not stored. Hashes describe bytes read by Core; they do not establish who authored a record or prevent a same-user process from editing local files.

## Baseline capture, persistence and freshness (historical)

`CoreRuntime.startScan` captures only its private native scanner provenance after the pipeline completes. The Evidence Engine independently normalizes the path, rejects symlinks, checks workspace containment and regular-file status, performs bounded raw-byte reads, decodes UTF-8 strictly, and recalculates both hashes before assigning the ID. Caller-supplied IDs and collector values are not accepted.

Core stores observations in `.aqiron-security/evidence.json`. Appends run under the existing workspace lock used by Core hypothesis persistence. The versioned bounded manifest is validated as a whole, rewritten through a unique exclusive temporary file and atomic rename, and retains a backup while replacement is in flight. Invalid/unsupported content fails closed and is not replaced. There is no observation update or delete operation. Limits are 20,000 observations, 5 MB manifest, 10 MB per source file, 50 MB per capture operation, 10,000 provenance candidates per scan, and 500 records per list response.

Freshness is on demand and separate from the record. It returns `current`, `stale`, `unavailable`, or `not-rechecked`; errors use bounded reason codes. Verification re-resolves the recorded workspace, validates the relative path and symlink-free containment, then bounded-reads and recalculates hashes. Missing or inaccessible data is unavailable. A mismatch is stale. No result mutates the observation.

## Historical hypothesis bridge status (superseded)

At the Milestone 18 baseline, the Hypothesis Engine consumed scan-scoped `span:` and `finding:` references without canonical evidence IDs. That statement is superseded: Milestone 19 adds canonical `ev1_` references after exact workspace/scan/finding/locator/digest matching and a freshness recheck. Legacy `span:` references remain for findings without a canonical association. Conflicting or ambiguous associations fail closed. See the canonical reference above for full matching and marker rules.

Evidence persistence and authority remain Core-owned. No public protocol, Desktop, or CLI operation exposes store paths or write access. A future typed Core interface can provide bounded list, get-by-ID, and recheck operations, with workspace and scan constraints resolved inside Core.

The local store is not signed or tamper-proof against a process running as the same user. The manifest currently uses atomic replacement under the repository's shared workspace lock; the atomic rename and lock capabilities depend on the Core filesystem adapter. There is no general retention, blob store, background freshness service, relationship graph, or evidence beyond native source spans. Endpoints, HTTP requests, assets, uploads, and dynamic validation remain deferred.
