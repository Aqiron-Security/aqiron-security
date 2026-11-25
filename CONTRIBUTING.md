# Contributing to Aqiron Security

Thank you for helping improve Aqiron Security. Aqiron is a Desktop + CLI product built on Aqiron Core. Read the [README](README.md), [Desktop development guide](docs/desktop-development.md), [architecture](docs/architecture/desktop-cli-core.md), and [roadmap](ROADMAP.md) before changing product behavior.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue. Do not include API keys, credentials, workspace data, generated reports, or proprietary code in commits or test fixtures. Review the implementation and tests before describing a capability as supported.

## Local setup

```sh
npm ci
npm run tauri dev
```

Desktop development starts from the repository root. The CLI can be run independently with `npm run cli -- scan <path> --trust-local-workspace` after installing dependencies.

## Validation

Run checks relevant to the changed product area:

```sh
npm run check-types
npm run test:focused
npm run desktop:test
npm run desktop:check
npm run desktop:test:rust
npm run desktop:build
npm run lint
```

The cross-platform workflow validates Core, CLI, the Desktop frontend and bridge, and the Tauri host on Windows, macOS, and Ubuntu. Report any unavailable platform prerequisite or validation step accurately.

## Pull requests

1. Keep changes focused and preserve unrelated working-tree changes.
2. Explain user-visible behavior and the affected product component.
3. Add or update tests for behavior changes.
4. Update documentation when commands, limitations, or supported integrations change.
5. Report validation commands and environment-dependent checks.
6. Do not claim an integration is complete when the implementation is only a placeholder.
7. Do not commit `.codex/`, `node_modules/`, `.aqiron-build/`, `dist/`, test output, credentials, or local reports.

## Licensing

The project license is Mozilla Public License 2.0 (MPL 2.0). By contributing, you confirm you have the right to submit the contribution and that it contains no unauthorized third-party or confidential material.
