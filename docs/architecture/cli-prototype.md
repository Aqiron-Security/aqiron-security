# Aqiron CLI prototype

This is a **prototype / architecture proof**, not a production CLI. It demonstrates a non-VS-Code client invoking the existing Aqiron Core workspace scan.

## Usage

```sh
npm run cli:build
npm run cli -- scan <workspace> --trust-local-workspace
```

Alternatively, after the repository build, run `node dist/aqiron-cli.js scan <workspace> --trust-local-workspace`.

The command accepts one local workspace directory and requires the explicit `--trust-local-workspace` opt-in before starting Core. Without the flag it does not scan. With the flag, it passes `trusted: true` to `scan.start`, runs in `deep` mode, prints matching Core stage/scanner events and a concise finding/severity/duration summary, then stops Core. Results containing findings still exit with status `0`; invalid arguments/paths or a missing trust opt-in return `2`; Core or CLI failures return nonzero (`1` for scan failures).

The adapter has no scanner, finding-normalization, correlation or report-generation implementation. It reuses the Node process manager in `src/core/`; that manager resolves `core-runtime.js` relative to its bundled `__dirname`, so the CLI bundle and Core runtime must be emitted together into `dist/`. This flag is a deliberate local-user opt-in, not production-grade trust or policy handling: the prototype has no workspace trust policy/configuration system, configuration files, signal-driven cancellation, CI annotations, report destinations, auth/cloud services or independent package publishing.
