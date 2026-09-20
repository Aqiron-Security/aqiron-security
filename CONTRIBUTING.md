# Contributing to Aqiron Security

Thank you for helping improve Aqiron Security. The project is an early-stage VS Code extension and contributions should stay grounded in the behavior and interfaces currently present in the repository.

## Before you start

- Read the [README](README.md), [technical architecture](TECHNICAL_REVERSE_ENGINEERING.md), and [roadmap](ROADMAP.md).
- Check existing issues and pull requests if a public repository is available.
- For security vulnerabilities, do not open a public issue; follow [SECURITY.md](SECURITY.md).
- Do not include API keys, credentials, workspace data, generated reports, or proprietary code in commits or test fixtures.
- Review the current source and tests before describing a feature as supported.

## Local setup

```powershell
npm ci
npm run compile
```

Use `npm run watch` during extension development. Optional external scanners and AI providers are only needed when working on those integrations.

## Validation

Before submitting a change, run the checks relevant to the files changed. For a normal source change, run:

```powershell
npm run check-types
npm run lint
npm test
```

`npm test` includes compilation and linting through the `pretest` script. If a test requires a local executable, server, or provider, document that prerequisite and keep the test deterministic where possible.

## Pull requests

1. Keep the change focused and preserve unrelated working-tree changes.
2. Explain the user-visible behavior and the architectural area affected.
3. Add or update tests for behavior changes.
4. Update documentation when commands, settings, limitations, or supported integrations change.
5. Report validation commands and any environment-dependent checks in the pull request description.
6. Never claim an integration is complete when the code only contains a placeholder or UI path.
7. Do not commit `.codex/`, `node_modules/`, `dist/`, `out/`, `.vscode-test/`, `.aqiron-security/`, coverage output, credentials, or local reports.

## Licensing

The project owner has identified the Mozilla Public License 2.0 (MPL 2.0) as the intended project license. This update does create the official `LICENSE` file. 

By submitting a contribution, you confirm that you have the right to submit it and that it does not contain third-party or confidential material that you are not authorized to share. Any formal contribution terms remain subject to the license.
