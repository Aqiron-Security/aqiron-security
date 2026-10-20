# Desktop architecture audit

Audited 2026-10-02 before implementation.

## Repository findings

- This repository is a single VS Code extension package, not a workspace monorepo. The root `package.json`, `package-lock.json`, `esbuild.js`, and root `tsconfig.json` are the build and dependency authority. `packages/core` and `packages/cli` are source packages, not independent installable workspaces.
- The React 19 webview is `src/webview/ui`: `index.tsx`, `AqironApp.tsx`, `tabs.tsx`, `styles.css`, and `design/{tokens,typography,motion,components}.css` plus `primitives.tsx`. `esbuild.js` already bundles this UI as browser code to `dist/webview.js`.
- `AqironApp` contains the existing application shell/navigation. Its existing screens are `ScanTab`, `ThreatTab` (Findings), `ReportsTab`, `AgentTab`/`AgentPanel`, and `SettingsTab`. No separate Overview screen is required. Project onboarding is rendered by the shell when `rag.ready` is false; it currently describes VS Code trust and indexing.
- `AqironApp` takes a VS Code-shaped `postMessage` prop, listens for window `message` state updates, and announces `ready`. The top-level UI entry probes `window.acquireVsCodeApi`. Actual filesystem, settings, agent, report and workspace behavior is implemented in the large `AqironWebviewProvider`, which directly imports VS Code APIs. That provider cannot be reused as a desktop host without extracting substantial host logic.
- The design token CSS has safe palette fallbacks, but typography and component rules are already imported by `styles.css`; Codicons and the app CSS are bundled with the React UI.
- `packages/core/src/client` exposes `CoreClient` over `CoreProcessManager`; the manager owns Node subprocess startup and NDJSON framing, handshake, timeouts, cancellation, events, crash handling, and restart behavior. It uses Node APIs and therefore cannot run in a browser webview.
- Core runtime entry is `packages/core/src/runtime/main.ts`; the existing esbuild output is `dist/core-runtime.js`. CLI runtime resolution and VS Code runtime resolution use this root build output. Runtime startup is not a Rust concern beyond launching the Node executable in development.
- Core protocol already exposes `project.detect`, `project.profile`, `scan.start`, and `report.generate`; `scan.start` returns normalized UnifiedFinding records, generated report data, scanner results and progress events. The shared report PDF renderer remains in Core.
- Tests are Node/Mocha-style VS Code extension tests under `src/test`, including Core client, process manager, runtime, protocol, reports and CLI coverage. Root scripts have `check-types`, `lint`, `compile`, `compile-tests`, and `test`.
- There is no existing Tauri, Vite, Cargo workspace, or npm workspace configuration. The existing browser UI can be bundled a second time as static desktop assets while keeping its source shared.

## Minimum desktop boundary

Keep the React screens/design source in `src/webview/ui`, add a dedicated `apps/desktop/src-tauri` Tauri 2 shell, and bundle a second shared React entry to desktop static assets. Since the browser cannot host `CoreClient`/`CoreProcessManager`, a small Node bridge uses the shared `CoreClient`, and Tauri only relays a separate allowlisted desktop request interface and Core events. The Rust host must not implement scanner, finding, or report behavior. The frontend adapter presents the existing screen state/action contract without importing VS Code APIs. A Rust-owned native folder picker stores the selected workspace; the Tauri host injects that path into only the project and scan calls, ignoring caller-supplied paths.

## Scope caveats to address

The current VS Code provider is the source of truth for rich UI state and many workflows; extracting all of it is not a minimum port. Phase 1 should establish the shell and a real Core scan vertical slice, with existing screen components and design system shared. The rest of the host-specific workflows (AI chat/settings persistence, RAG onboarding/indexing, report artifact browsing/export) need explicit adapters before they can all be functional in Desktop. Packaging the Node runtime is explicitly deferred.
