# Security policy

## Scope

This policy covers the Aqiron Security VS Code extension and the TypeScript core runtime in this repository. The extension invokes local scanners and may send configured requests to Ollama, OpenRouter, OSV, or a configured MobSF server; those services have their own security and privacy policies.

## Reporting a vulnerability

Please do not disclose exploitable vulnerability details in a public issue or pull request. Send vulnerability reports privately to [opendeveloper.ai@gmail.com](mailto:opendeveloper.ai@gmail.com).

Include the affected version or commit, environment, reproduction steps, impact, and a proposed mitigation where available. Redact credentials, tokens, private source, and personal data. Allow maintainers reasonable time to investigate before public disclosure.

If a secret may have been exposed, revoke or rotate it first and mention the exposure privately. Do not attach raw credentials, keychain exports, `.aqiron-security` reports, workspace archives, or private code unless specifically requested through a secure channel.

## Handling secrets

Never commit API keys, MobSF credentials, Ollama tokens, OpenRouter keys, local credential-store data, `.aqiron-security` reports, or workspace data. Test fixtures must use clearly fake values and must not resemble active credentials.

## Supported versions

No supported-version or backport policy has been established. The current repository version is `0.0.1` and is under active development.

## Licensing context

The project owner has identified the Mozilla Public License 2.0 (MPL 2.0) as the intended project license. The official `LICENSE` file has been created in this update.
