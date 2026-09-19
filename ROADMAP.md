# Roadmap

This roadmap describes direction based on the current repository. It is not a promise of delivery dates or feature completeness.

## Current foundation

- VS Code extension host with sidebar/webview, diagnostics, status bar, commands, and settings.
- Separate private core runtime connected through a newline-delimited JSON protocol.
- Portable deterministic rules, external scanner adapters, finding normalization, correlation, graph construction, telemetry, and report generation.
- Ollama/OpenRouter AI provider support and workspace RAG indexing/querying.
- TypeScript tests and build/lint validation.

## Next areas to validate

- Establish a supported-workspace matrix beyond the current Flutter workspace gate.
- Improve scanner availability reporting, integration tests, and documentation for external tool versions and configuration.
- Define stable report, protocol, and core-package boundaries before treating `packages/core` as a reusable public package.
- Clarify which webview actions are implemented integrations and which are placeholders or local export flows.
- Improve rule coverage, false-positive handling, and user-controlled exclusions without weakening safe defaults.
- Define release, support, vulnerability-response, licensing, and trademark policies.

## Longer-term possibilities

These are areas visible in the codebase or existing design notes, not committed features: broader workspace support, deeper data-flow analysis, richer mobile artifact workflows, additional scanner integrations, durable scan history, and external workflow integrations.

Any item should be considered planned only after a maintainer-approved design, implementation, tests, and documentation are added.
