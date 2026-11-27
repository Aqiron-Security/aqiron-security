# Controlled Validation Core Procedure Registry (M22.3.4)

This milestone adds a Core-owned, immutable, metadata-only registry for Controlled Validation v1. It does not add a procedure body, protocol operation, authorization mechanism, lifecycle store, launch API, supervisor integration, or execution endpoint. It uses the existing authorization and approval history in `authorization.ts` / `approvalHistory.ts` and the durable `ValidationLifecycleStore` start-commit receipt unchanged. The receipt remains historical/non-executable and registry lookup does not consume approval or commit a start.

## Registry contract

`packages/core/src/validation/procedures/registry.ts` defines a strict typed schema DSL (bounded strings, integers, booleans, enums, arrays, and closed objects), immutable `ProcedureDescriptorV1` metadata, `ProcedureRegistry`, and typed registry errors. Registration validates exact fields, schema depth and shape, identity, semantic version, policy, capabilities, resource ceilings, compatibility, audit metadata and canonical JSON bounds. The v1 catalog rejects duplicate procedure IDs and duplicate versions, including repeated registration of an otherwise identical entry. Lookup requires exact ID and version and returns the same deeply frozen descriptor. No client can provide a body, script, command, module path, or arbitrary executable instruction.

Argument validation runs for every call. It checks canonical input size, schema types and bounds, nesting/node limits, unknown/missing fields, exact project identity and single-target count, and equality with the target facts resolved by Core. The caller of this metadata boundary must supply target facts from Core-retained state; client values are not authoritative. The only accepted capability is `captured-source-read`, representing a future read of one Core-captured immutable source blob. Network, project writes, credentials and child processes are rejected. V1 also requires offline/read-only operation, no project modifications, no inherited credentials, one process, and the fixed policy ceilings encoded in the registry.

The initial `source-span-integrity-check-v1` descriptor captures the proposed narrow purpose and typed input/result contracts: compare a Core-captured file and span with retained digests. Input binds one observation, snapshot, scan, finding, relative path, one-based line range and expected whole-file/span digests. Its stated limits include a 32 KiB input, 10 MiB read, 8 KiB result, 2-second timeout, 64 MiB memory and one process. The typed result vocabulary is `match`, `changed`, `unavailable`, `unsafe-target`, `invalid-encoding`, or `limit-exceeded`. Registration adds metadata only; it does not implement or run the check.

## Artifact verification boundary

`ProcedureArtifactVerifier` binds the supplied artifact bytes to the descriptor's SHA-256 digest, exact procedure ID/version and catalog identity. It requires external providers for trusted catalog validation, signing-key status, cryptographic signature verification, and current revocation status. The verifier has no embedded trust root, signing-key lifecycle, catalog update mechanism, or revocation freshness policy; those remain owned by the future release/catalog providers. Its successful result is a deeply frozen `VerifiedProcedureDescriptor` containing the exact descriptor, artifact digest, catalog identity and signing-key identity. It provides no executable bytes or launch capability.

Verification fails with typed errors for digest or identity mismatch, unavailable catalog/signature/key/revocation providers, untrusted catalogs, invalid signatures or identities, revoked signing identities, and revoked artifacts. Missing providers never imply success. A digest is an integrity identifier only; by itself it does not establish trusted authorship. Deterministic providers in the focused test are test fixtures only and are not production trust roots.

For the initial proposed descriptor there is no built artifact. Its fixed digest identifies the canonical descriptor package only, as indicated by `artifact.kind: descriptor-package`; it must not be interpreted as the digest of a procedure implementation, a signed release artifact, proof of authorship, or permission to execute. Production verification still requires the release/catalog providers and matching bytes and will fail closed without them. A production signed catalog must bind the eventual reviewed artifact before any future supervisor integration.

## Isolation and integration boundary

The registry is not imported by `CoreRuntime`, protocol, Desktop, or CLI code. It does not alter shared exports. A later integration may adapt the `VerifiedProcedureDescriptor` output to the supervisor, but must accept only this verified frozen descriptor and independently enforce authorization, the existing atomic start commitment, target capture, OS isolation, resource ceilings and result validation. No execution path is introduced in this milestone.

## Focused validation

`src/test/controlledValidationProcedureRegistry.test.ts` covers unique immutable registration, duplicate IDs/versions, malformed definitions, artifact digest mismatch, missing providers, invalid/revoked signer and artifact states, argument types and limits, nested/oversized input, capability/policy rejection, exact project/target matching, the initial descriptor and absence of launch/execute methods. Test verifiers are deterministic fixtures only.

The repository uses explicit test discovery lists. This milestone leaves shared configuration untouched. Later integration must add src/test/controlledValidationProcedureRegistry.test.ts to tsconfig.acceptance.json include and add .ci-compiled-tests/src/test/controlledValidationProcedureRegistry.test.js to the Mocha file list in package.json test:focused. This milestone compiled the test directly to temporary output and ran it with Mocha. No VS Code extension-host suite is applicable.

