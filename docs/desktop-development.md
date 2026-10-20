# Aqiron Security Desktop development

## Architecture

The Tauri 2 Rust application is a desktop host. It owns the native folder picker, the selected workspace path, and a short allowlist of frontend commands (`select_workspace`, `core_request`). The host accepts only `project.detect`, `project.profile`, and `scan.start`; it ignores path parameters from the webview and injects the path selected by the native picker. It does not expose a shell or arbitrary process command.

The host launches `dist/aqiron-desktop-bridge.js` with Node. That bridge calls the existing shared `CoreClient`; `CoreProcessManager` starts and supervises `dist/core-runtime.js`, including the existing handshake, NDJSON protocol, progress/events, failure handling, and restart behavior. Rust relays bridge responses and Core events. Core remains the only scanner and report generator.

The Desktop entry imports the same `AqironApp`, screen components, CSS, design tokens, typography, motion, and primitives as the VS Code webview. The adapter translates shared UI actions to the two Tauri commands and maps Core `UnifiedFinding` results into the existing Findings model. Reports display the executive summary and report text returned in `CoreScanStartResult`; PDF rendering stays in Core.

## Run in development

1. Install the root npm dependencies with `npm install`.
2. Install the Rust toolchain and platform Tauri prerequisites described by the official Tauri 2 setup guide.
3. Run `npm run desktop`. The Tauri config first builds Core and the desktop bridge, then starts the Vite development server and Tauri window.

`AQIRON_NODE_BINARY` may point to a specific Node executable if `node` is not on the environment path. Production Node/Core packaging is intentionally not configured in this milestone.

## Capabilities

The default window capability grants Tauri's standard core APIs plus only the four window mutations used by the custom titlebar: minimize, toggle maximize, close, and start dragging. No shell/process plugin permission is configured. The dialog plugin is called from the Rust host; the webview does not receive the plugin's `dialog:allow-open` permission. Tauri IPC requests are constrained by an explicit method allowlist and selected workspace state.

The borderless native window uses the shared Aqiron tokens to render its own restrained glass titlebar. Its desktop-only adapter owns Tauri window API calls; the shared VS Code app receives no direct Tauri imports. Desktop branding and the Windows ICO are generated from `resources/aqiron.png`.

Desktop project selection stays pending until both Core `project.detect` and `project.profile` return. The frontend only receives the host-selected canonical path, and a failed picker/Core request is displayed on the selection card so the app cannot appear to have selected a project silently.
