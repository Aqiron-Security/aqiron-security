# Aqiron CLI

The repository contains a practical, in-repository CLI client for local and CI scans. It is not yet a published or fully packaged product. The CLI remains a thin caller of Core and supports the same local workspace behavior exposed by the existing `scan.start` operation.

## Build and use

Build the VS Code extension bundle, CLI, and Core runtime together:

```sh
npm run cli:build
node dist/aqiron-cli.js scan <path> --trust-local-workspace
```

The build emits `dist/aqiron-cli.js` and `dist/core-runtime.js` together. The CLI adapter explicitly supplies the runtime path to the shared Core client, so location is host configuration rather than a path assumption inside the transport. No npm package is published. The repository has no GitHub Actions workflow suitable for reliable CLI invocation yet, so a CI workflow is future work:

```text
GitHub Actions → Aqiron CLI → Aqiron Core → SARIF
```

## Commands and behavior

```sh
aqiron scan <path> --trust-local-workspace
aqiron scan <path> --format json --output result.json --trust-local-workspace
aqiron scan <path> --format sarif --output result.sarif --trust-local-workspace
aqiron scan <path> --fail-on high --trust-local-workspace
```

During repository development, invoke these as `node dist/aqiron-cli.js ...` or `npm run cli -- ...`. `--format` accepts only `text` (default), `json`, or `sarif`. Results go to stdout unless `--output <path>` is supplied. Output files are created exclusively; an existing file is never overwritten. `--output` may also be used with text format.

The JSON document has this stable top-level shape:

```json
{
  "schemaVersion": 1,
  "scan": {
    "scanId": "Core scan id",
    "mode": "deep",
    "filesScanned": 0,
    "durationMs": 0
  },
  "report": "Core SecurityReportModel"
}
```

`report` is the existing Core JSON report representation, including its summary and canonical findings; raw evidence uses the Core exporter's redaction behavior and unavailable optional scan measurements are `null`. SARIF is the existing `report.sarif` representation returned by Core's scan result. The CLI does not construct a report model or SARIF.

Exit codes are exact: `0` means the scan completed and no `--fail-on` threshold was violated; `1` means Core startup/scan failure, cancellation, output failure, or a matching finding; `2` means invalid command, option, format, severity, missing explicit trust, or invalid workspace path. `--fail-on critical|high|medium|low` checks actual Core findings and includes all severities at or above the requested level. Findings alone do not fail an un-gated scan.

The workspace must be an accessible local directory. The `--trust-local-workspace` option is required and is the only condition under which this CLI sends `trusted: true` to Core. It acknowledges the caller's choice; it does not add a new trust policy framework. Scans use Core's existing deep workspace scan semantics.

Text output shows the workspace, actual stage names/statuses emitted by Core, and findings/severity/duration summary. It does not synthesize progress. Errors are concise and omit raw Core messages by default; `AQIRON_DEBUG=1` prints only a diagnostic error code. CLI flags and values are not logged.

Ctrl+C (`SIGINT`) and `SIGTERM` where supported call Core's existing request cancellation. The CLI waits for the scan request to settle, then stops its Core client in cleanup. On Windows, Ctrl+C and supported process termination are handled by Node's corresponding process signals.

## Communication boundary and limits

```text
CLI adapter → packages/core/src/client/CoreClient → CoreClientTransport / CoreProcessManager → line-delimited JSON IPC → Core runtime
```

The host-neutral client is shared with the VS Code adapter and imports protocol/domain types from Core. The CLI adapter supplies `clientVersion`, the bundled runtime path, and `restartOnCrash: false`; it owns process signals, CLI formatting, output files and exit codes. The VS Code adapter supplies the extension version, packaged runtime path, and `restartOnCrash: true`; it owns extension-host lifecycle and UI integration. The shared modules import no VS Code APIs and do not implement scanning, parsing, normalization, correlation, or report presentation.

## Host roadmap

- **Current:** VS Code and CLI use the same host-neutral client/NDJSON transport. The client is source inside the existing private Core package.
- **Near-term:** only if another consumer needs it, define a stable package subpath/version policy. A GitHub Actions workflow can invoke CLI and consume SARIF after CLI distribution is reliable.
- **Future Desktop:** pass Desktop runtime location and lifecycle choices into the same client; keep windows, workspace interaction, permissions, dialogs and presentation in the Desktop adapter.

This in-repository CLI has no release packaging, npm publication, configuration file, policy framework, CI annotations, or GitHub Actions integration. Continue using CLI flags and current Core defaults until a concrete need justifies those additions.
