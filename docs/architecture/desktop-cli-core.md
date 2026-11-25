# Desktop, CLI, and Core architecture

Aqiron Security has three product components and one authoritative engine.

- **Desktop** is the primary UI. The repository root is its Vite/Tauri project. React communicates through `src/desktopAdapter.ts`, Tauri IPC, and the Rust host. Rust owns native project selection and its explicit Core method allowlist.
- **CLI** is a standalone Node process. It parses scan/output options and uses `CoreClient`; it does not depend on the Desktop frontend or Tauri runtime.
- **Core** owns scanner orchestration, rules and configuration, findings, provider policy, reports, Hypothesis lifecycle and evidence validation, persistence, and protocol validation. Client code may present Core results but does not make authoritative security decisions.
- **Desktop bridge** is a Node adapter for the Tauri host. It maps the host's allowlisted operations to `CoreClient` and does not contain a second scanner implementation.

The JSON-line Core protocol and typed client live in `packages/core/src/runtime` and `packages/core/src/client`. Desktop and CLI share the same runtime build. Hypothesis production synthesis is guarded off in Core source; this migration does not activate it or add an override.

The retired VS Code extension is not a product, build target, test target, package, or CI job. Historical architecture records may mention its former boundaries.
