# Aqiron Security Workspace RAG

This document describes the current workspace Retrieval-Augmented Generation (RAG) implementation. It is based on the code in `src/rag/`, `packages/core/src/rag/`, the webview provider, and the current tests. It documents implemented behavior only; broader AI or cloud-platform ideas are not treated as features.

## Purpose

Aqiron builds a local workspace index for a trusted Flutter workspace. The index combines bounded source-file collection, deterministic security-signal detection, chunked text, local vector embeddings, lexical retrieval, and optional AI-generated suggestions.

The RAG index is separate from the live security scan findings. Both are exposed through the VS Code extension and share workspace exclusions and trust checks. Scan findings and historical threat snapshots are stored separately from the RAG index.

## Runtime architecture

```text
VS Code command / webview action
        |
        v
src/rag/ragWorkspaceService.ts
  - workspace, trust, and Flutter checks
  - .aq creation and user-facing notifications
  - AI suggestion generation and benchmarks
        |
        +--> src/rag/ragIndexService.ts
        |      - local index compatibility and orchestration
        |
        +--> CoreClient --> packages/core runtime
               - filesystem-backed index build
               - regex catalog loading and validation
               - signal detection and chunking
               - vector persistence and retrieval
               - optional trusted-source network access
        |
        v
workspace/.aqiron-security/
  index.json, vectors.json, regexSources.json
  optional suggestions.md and benchmarks/latest.json
```

The extension starts `dist/core-runtime.js` and communicates with it through the core protocol. `packages/core` is private and is not currently published as a standalone package.

## Source modules

| Area | Current responsibility |
| --- | --- |
| `src/rag/ragWorkspaceService.ts` | VS Code commands, workspace checks, `.aq` creation, AI suggestions, user notifications, and benchmark invocation. |
| `src/rag/ragIndexService.ts` | Extension-facing index wrapper and persisted index access. |
| `src/rag/ragVectorService.ts` | Local vector fallback and optional `faiss-node` backend for extension-side retrieval. |
| `src/rag/regexSignals.ts` | Built-in grouped signal definitions. |
| `src/rag/regexLoader.ts` | Workspace regex catalog import and synchronization. |
| `packages/core/src/rag/ragIndexService.ts` | Bounded file collection, cache reuse, chunking, signal detection, and index persistence. |
| `packages/core/src/rag/ragVectorService.ts` | Deterministic 128-dimensional token-hash embeddings, lexical/semantic hybrid search, and optional FAISS acceleration. |
| `packages/core/src/rag/signalDetector.ts` | Text and AST-assisted security signal detection. |
| `packages/core/src/runtime/coreRuntime.ts` | RAG protocol operations: `rag.index`, `rag.status`, and `rag.query`. |

## Workspace requirements and safety

RAG indexing currently requires:

1. An open workspace folder.
2. A trusted VS Code workspace. Restricted Mode blocks source reads and indexing.
3. A Flutter workspace detected from `pubspec.yaml` or `.metadata`.

Non-Flutter workspaces are reported as unsupported. This is an extension boundary, even though some core file and signal logic is reusable for other project types.

The index excludes common dependency, build, generated, compiled, and Aqiron directories, including `node_modules`, `.git`, `dist`, `build`, `out`, `coverage`, `.dart_tool`, `target`, `bin`, `obj`, and `.aqiron-security`. The index also applies generated-file and minified-file checks.

The core index currently bounds collection at 2,000 files and 256,000 bytes per file. The extension scanner has its own configurable `maxFileSizeKB` setting; these are related but separate code paths.

## `.aqiron-security/` storage

The workspace-local directory is generated and is ignored by the repository's `.gitignore`. Current RAG-related files include:

- `index.json`: manifest, file records, chunks, detected signals, and build metadata.
- `vectors.json`: persisted deterministic vectors keyed by chunk ID.
- `regexSources.json`: validated workspace regex source catalog.
- `suggestions.md`: optional AI-generated workspace suggestions.
- `benchmarks/latest.json`: optional AI-mode benchmark output.

The same directory also receives security report and threat-history files from other subsystems. It must not be committed because it may contain workspace paths, findings, source-derived evidence, and generated reports.

## `.aq` exclusions

When an index is created and `.aq` does not exist, the extension creates a workspace-root `.aq` file containing default exclusions. Users can add gitignore-style paths and patterns. `.aq` is a workspace policy file, not a repository-level configuration file.

The default entries cover Flutter build/generated locations such as `build/`, `.dart_tool/`, `ios/Pods/`, platform build folders, and generated Dart suffixes. The index and scanner apply exclusions independently, so changes should be verified against the relevant subsystem.

## File and index model

The index stores:

- A manifest with schema/version, timestamps, file count, chunk count, signal count, and build options.
- File records with workspace-relative paths, modification metadata, content hashes, and detected signals.
- Chunks with stable IDs, relative paths, line ranges, token lists, and text used for retrieval.
- Security signals with category, provider, description, file, line, evidence, and confidence-related metadata.

The service reuses a file record when its relative path, modification time, and size are unchanged. Changed files are re-read, re-hashed, re-tokenized, and re-detected. Per-file failures are recorded rather than aborting the entire build.

## Signal detection

Built-in signal groups cover categories such as databases, payments, LLM usage, secrets, endpoints, and services. The catalog includes patterns for API keys, bearer tokens, passwords, private keys, AWS-like credentials, cloud credentials, HTTP endpoints, database use, authentication, and service integrations.

Signals are evidence for workspace intelligence, not proof of exploitability. The implementation is pattern-based and can produce false positives or miss data-flow behavior. Secret evidence is redacted in the relevant security-analysis/reporting paths; users should still treat generated workspace artifacts as sensitive.

The detector also uses executable-code checks and AST parsing where available. Comments and non-executable text are intentionally handled differently from executable evidence.

## External regex sources

The extension can import regex signals from clipboard JSON or a selected JSON file. It validates imported entries before adding them to `regexSources.json`.

Trusted-source synchronization uses a deliberately constrained source list and validates response shape, signal fields, and regular-expression safety. Invalid entries are rejected without replacing the last known-good catalog. Rebuilding the index is required before catalog changes affect indexed chunks.

## Retrieval

Embeddings are deterministic local token-hash vectors with 128 dimensions. Retrieval combines lexical token overlap and cosine/vector similarity, then removes duplicate results from the same path and line range.

If `faiss-node` is available and initializes successfully, the vector service can use FAISS for nearest-neighbor scoring. Otherwise it uses the local in-memory/vector-file fallback. The persisted vectors do not require a cloud embedding service.

The core runtime exposes `rag.query`, while the extension-side service provides the webview and agent context. The retrieval implementation is bounded and should not be described as a general-purpose semantic code search engine.

## AI-assisted indexing

The non-AI build creates the local index without an AI provider. The AI build requires a connected provider and selected model, then generates up to five concise workspace suggestions from detected signals. The extension currently supports the Ollama and OpenRouter providers through the core AI service.

AI suggestion generation may send selected workspace context to the configured provider. It should therefore be treated differently from the non-AI local build, and provider privacy/retention policies apply.

AI failures preserve the local index when possible and surface an error notification. Suggestions are advisory and require human review.

## VS Code commands

The contributed commands include:

- `Aqiron Security: Reindex RAG with AI`
- `Aqiron Security: Reindex RAG without AI`
- `Aqiron Security: Reindex RAG`
- `Aqiron Security: Add RAG Regexes`
- `Aqiron Security: Sync Trusted RAG Regexes`

The webview displays index readiness, build state, selected build mode, restricted-workspace state, suggestion state, and the reported vector backend.

## Verification

Run the repository checks from the root. The standard project scripts are authoritative; when npm is unavailable, invoke the installed local TypeScript, ESLint, esbuild, and VS Code test binaries directly.

For a manual check:

1. Open a trusted Flutter workspace.
2. Run `Aqiron Security: Reindex RAG without AI`.
3. Confirm the expected files are created under `.aqiron-security/`.
4. Change a source file and rebuild to exercise cache invalidation.
5. Configure an AI provider and model, then run the AI reindex command.
6. Confirm suggestions and benchmark output are written without exposing secret values in the generated suggestion text.

## Current boundaries

- Flutter is the only supported workspace type at the extension boundary.
- The default embedding is deterministic token hashing, not a transformer model.
- FAISS is optional and has a local fallback.
- Trusted regex synchronization is intentionally constrained.
- The RAG index is local workspace data and is not a hosted multi-tenant knowledge base.
- AI suggestions are advisory and provider-dependent.
- Generated `.aqiron-security` data should remain local and ignored.
