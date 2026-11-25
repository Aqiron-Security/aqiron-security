# Aqiron Security Desktop development

## Architecture

The repository root is the Desktop project. Root `index.html`, `vite.config.mts`, and `src/main.tsx` build the existing Aqiron UI. Root `src-tauri/` contains the native Tauri host, capabilities, icons, and Rust sources. The standard Tauri CLI discovers `src-tauri/tauri.conf.json` from the root project; `npm run tauri dev` starts the native application without a custom configuration path or directory change.

Tauri owns native folder selection, the selected workspace path, and a short command allowlist. It launches the Node bridge in `packages/desktop`, which uses the shared `CoreClient`; `CoreProcessManager` starts and supervises the Core runtime. Core remains the authoritative scanner, report generator, Hypothesis lifecycle, validation, and persistence layer. The CLI independently calls the same Core runtime without Desktop or Tauri.

## Feature preservation inventory

| Desktop capability | Current implementation |
| --- | --- |
| Existing layout, navigation, tabs, styling, and branding | `src/webview/ui/` (the promoted existing Desktop UI) |
| Native project selection and persistence | `src-tauri/src/main.rs` and `src/desktopAdapter.ts` |
| Scanning, progress, findings, and cancellation | Desktop adapter and Core runtime protocol |
| Threat history, rules, credentials, provider/model configuration, and assistant | Desktop adapter, UI, Core runtime |
| Hypothesis preparation, approval, denial, review, and execution state | Desktop UI, adapter, and Core lifecycle; production synthesis remains disabled |
| Recommendations and reports | Desktop adapter and Core report/recommendation interfaces |
| Native window behavior and IPC boundary | `src-tauri/`, its capabilities, and Tauri configuration |

The UI is retained from the existing Desktop application; this migration changes its project location and build entry, not its design.

## Run and build

```sh
npm ci
npm run tauri dev
npm run desktop:build
npm run build
npm run desktop:build:native
```

The repository uses npm and `package-lock.json`. Install the Rust toolchain and the platform-specific prerequisites in the [Tauri 2 setup guide](https://v2.tauri.app/start/prerequisites/). The Tauri `beforeDevCommand` builds Core and starts Vite; `beforeBuildCommand` builds Core and the frontend. `npm run desktop:build:native` builds the release executable with Tauri's `custom-protocol` feature so it loads the frontend from `src-tauri/tauri.conf.json`'s `frontendDist` instead of requiring a running Vite server. Run `npm run build` first to refresh Core and frontend assets. The executable is written to `.aqiron-build/rust-target/release/aqiron-security-desktop.exe` on Windows. JavaScript artifacts are written under `.aqiron-build/` so existing `dist/` data is preserved. `AQIRON_NODE_BINARY` may select a Node executable when `node` is not on `PATH`.

## Security and limitations

The host does not expose a shell or arbitrary process command. It injects the canonical path selected through the native picker and dispatches only explicitly allowed Core methods. No production Node/Core installer or signed platform bundle is configured here. The standard root command and build scripts are validated in CI per operating system; distribution and signing require separate release setup.
