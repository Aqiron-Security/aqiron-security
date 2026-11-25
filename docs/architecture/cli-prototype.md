# Aqiron CLI

The Aqiron CLI scans local workspaces through the shared Core runtime. It runs independently of the Desktop UI and Tauri host. Core owns scanning, validation, and report generation; the CLI handles arguments, progress, output files, cancellation signals, and exit codes.

## Build and use

From a clean repository checkout:

```sh
npm ci
npm run cli:build
npm run cli -- scan <path> --trust-local-workspace
```

The root build emits CLI, Core runtime, and Desktop bridge bundles under `.aqiron-build/node/`. The workspace package can delegate build and scan operations to the root scripts with `npm run build --workspace=@aqiron/cli` and `npm run scan --workspace=@aqiron/cli -- scan <path> --trust-local-workspace`.

## Supported commands

```sh
aqiron scan <path> --trust-local-workspace
aqiron scan <path> --format json --output result.json --trust-local-workspace
aqiron scan <path> --format sarif --output result.sarif --trust-local-workspace
aqiron scan . --format pdf --output report.pdf --trust-local-workspace
aqiron scan <path> --fail-on high --trust-local-workspace
```

`--format` accepts `text` (default), `json`, `sarif`, or `pdf`. PDF requires `--output`. Results go to stdout unless an output path is supplied. Output files are created exclusively, so existing files are preserved. Machine-readable output does not mix progress text into stdout. `--fail-on` evaluates findings after writing the selected artifact.
