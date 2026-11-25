# Aqiron Security

Aqiron Security is a local-first security product built around three components:

- **Aqiron Desktop** is the primary application. It provides project selection, scanning, findings and threat history, rules, credentials and provider configuration, the AI assistant, Hypothesis workflows, recommendations, and reports.
- **Aqiron CLI** runs scans independently for automation and CI. It supports text, JSON, SARIF, and PDF output, cancellation, and severity thresholds.
- **Aqiron Core** is the shared engine for scanning, findings, rules, provider policy, reports, Hypothesis lifecycle and evidence validation, persistence, and protocol validation. Desktop and CLI call Core through its typed client and runtime protocol.

## Quick start

Install dependencies with the repository's npm lockfile:

```sh
npm ci
```

Start the native Desktop application from the repository root using the standard Tauri CLI script:

```sh
npm run tauri dev
```

Select a project folder in the native window to begin. Desktop owns native folder selection and communicates with Core through the Node bridge; it does not expose a shell or arbitrary process execution.

Build Desktop frontend and the shared Core, CLI, and bridge bundles from the root:

```sh
npm run build
```

Run the CLI from this checkout:

```sh
npm run cli -- scan . --trust-local-workspace
npm run cli -- scan . --format sarif --output aqiron-results.sarif --fail-on high --trust-local-workspace
```

The CLI accepts `text`, `json`, `sarif`, and `pdf` formats. PDF requires `--output`. The CLI starts Core directly and does not require Desktop or Tauri to be running. See [CLI usage](docs/architecture/cli-prototype.md).

## Development and validation

```sh
npm ci
npm run tauri dev                 # Native Desktop development from the root
npm run desktop:build             # Desktop frontend
npm run check-types               # Desktop, Core, CLI, and bridge TypeScript
npm run test:focused              # Core/Hypothesis and CLI acceptance tests
npm run desktop:test              # Desktop bridge tests
npm run desktop:check             # Tauri Rust check
npm run desktop:test:rust         # Tauri Rust unit tests
npm run desktop:build:native      # Native Tauri host build
npm run lint
```

Platform prerequisites and product boundaries are documented in [Desktop development](docs/desktop-development.md) and [architecture](docs/architecture/desktop-cli-core.md). CI validates Windows, macOS, and Ubuntu runners; a passing runner matrix is evidence for the commands actually completed on each platform, not a claim that every packaging or distribution path is available.

Production Hypothesis synthesis remains disabled. Reviewer approval and test seams do not enable provider execution. No Evidence Engine is implemented by this repository migration.

## Project structure

```text
src/                    Desktop frontend and preserved Desktop UI
src-tauri/              Native Tauri host, capabilities, resources, and Rust tests
packages/core/           Authoritative security engine and protocol
packages/cli/            Independent CLI client
packages/desktop/        Node bridge and Desktop bridge tests
docs/                    Product, architecture, and development documentation
```
