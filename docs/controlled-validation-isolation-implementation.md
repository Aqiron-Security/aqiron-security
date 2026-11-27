# M22.3.5 Controlled Validation isolation foundation

**Status: execution disabled; no platform qualified.** This module is a Core-owned admission and provider contract only. It does not create a worker process, VM, sandbox, protocol route, or client entry point. The production supervisor factory always rejects launch. Capability/API discovery is never qualification evidence.

## Supervisor lifecycle

1. An internal caller supplies the M22.3.3 consumed start receipt through the local receipt adapter, a verified immutable procedure descriptor, Core-derived project/target scope, a validated restrictive resource profile, and bounded input bytes.
2. The supervisor verifies that the receipt was accepted at the internal adapter boundary, that the descriptor and scope are well formed and mutually consistent, and that the input is within its cap. Invalid inputs are blocked before provider invocation.
3. Admission requires a provider for the current platform and an explicit `qualified` status with evidence ID and every required capability true. Provider and supervisor qualification must agree.
4. An accepted provider would receive only a fixed worker-entry identifier, verified data descriptor, read-only scope/profile, bounded input, and a constant environment allowlist (`LANG`, `LC_ALL`, `TZ`). There is no command, executable, shell, or environment inheritance field.
5. Once `launch` returns a handle, the supervisor transfers all wait, deadline, cancellation, termination-confirmation, cleanup, and terminal-outcome ownership to `WorkerCancellationCoordinator`. The supervisor only converts the coordinator's settled result and checks the output bound; it never independently calls handle lifecycle methods. A launch rejection has no handle and follows a separate failure path.

This lifecycle exists as a narrow internal contract. The non-test production gate is source-controlled `false`; the test factory requires an explicit fake-provider seam and cannot modify that gate. Nothing imports this module from CoreRuntime or shared export barrels.

## Cross-workstream adapters

- **M22.3.3 committed start:** a Core-only adapter must accept only `ConsumedControlledValidationAuthorizationV1` with `nonExecutable: true`, map its execution/approval IDs and authorization-binding digest into the local `CommittedStartReceipt`, and never use historical receipts. This workstream does not invoke or recreate authorization commitment.
- **M22.3.4 registry:** adapter must resolve an immutable registry entry, verify signature/revocation/digest and policy, then produce `VerifiedProcedureDescriptor`. No registry code is imported here.
- **Scope and limits:** Core must derive canonical project identity, target IDs, and exact captured input paths and supply approved ceilings. Caller-provided paths, limits, or launch strings are not authoritative.
- **M22.3.6 cancellation:** adapter must deliver cancellation by execution identity and report confirmed local teardown separately from request acknowledgement. A provider must terminate the whole OS job/VM, not just a direct child.
- **M22.3.6 lifecycle ownership:** the supervisor now registers the coordinator for internal cancellation while a launch is active. Explicit cancellation and the coordinator's profile deadline share the same operation; timeout, completion, and cancellation cannot independently terminate or clean the handle. This internal method is not wired to CoreRuntime, protocol, Desktop, or CLI.
- A later integration must also supply safe immutable input staging. The current contract validates lexical containment; it does not implement race-safe path opening or filesystem snapshots.

## Provider status and required controls

Every production platform currently has `qualification-pending`, an all-false capability report, and no provider. All platforms default disabled. `qualified` requires a reviewed evidence identifier plus every required capability; discovering a command/API is insufficient.

| Platform | Candidate design to evaluate | Current implementation and acceptance requirements |
| --- | --- | --- |
| Windows | Windows Sandbox or stronger VM boundary; explicit read-only mapped input; deny networking in guest; Job Object limits and kill-on-close | No provider. Prove guest filesystem allowlist and project-root containment; immutable/read-only mapping; reparse-point and replacement race resistance; OS network denial including DNS/IPv6/loopback/side channels; Job Object descendant containment, CPU/memory/process limits and forced termination; execution/output caps and cleanup. Job Objects alone do not provide filesystem or network isolation. Evaluate host/guest escape, brokered host folders and clipboard/device sharing. |
| Linux | Namespaces plus Landlock, seccomp and cgroup v2, or a disposable VM where any required control cannot be guaranteed | No provider. Prove mount allowlist/read-only mounts and root containment; `openat2`/descriptor-relative resolution or equivalent against symlink and rename races; deny network namespace and validate no host network handles; restrict syscalls with seccomp and filesystem with Landlock; cgroup v2 CPU, memory, pids and teardown; output/deadline caps and descendant kill. Evaluate namespace/user-namespace misconfiguration, kernel attack surface, writable proc/sys, inherited descriptors and cgroup delegation. Container mechanisms alone are not accepted without host threat review. |
| macOS | Virtualization.framework disposable networkless guest with read-only project input sharing | No provider. Prove guest-only filesystem allowlist and read-only share; stable identity and path/race controls in guest; no virtual NIC or other egress path; guest process/child containment; enforceable CPU/memory/process/deadline/output limits and hard VM destruction; cleanup. Evaluate host/guest escape, shared-folder implementation, device/clipboard/drag-drop channels, hypervisor and guest image update chain. Sandbox APIs or an ordinary child process are not substitutes. |

For each platform, acceptance must also include signed/reproducible provider and worker provenance, minimal environment and descriptor inheritance audit, secret scanning of environment/handles, abnormal worker/host shutdown, cleanup after partial setup, resource exhaustion, output flooding, path traversal/symlink swaps, network probes beyond HTTP, and repeated escape attempts under the supported OS versions. Test the actual packaged release configuration, not only a developer shell. Independent security review must record residual kernel/hypervisor and same-user host risks. Until all required adversarial tests pass and are reviewed, status stays pending or revoked.

## Tests and evidence

The two source test files use fakes only. They cover default-off states, incomplete capabilities, containment/profile restrictions, resource limits, receipt/descriptor validation, no command-shaped launch surface, environment allowlisting, timeout termination, and cleanup behavior. Fake evidence IDs are labels for contract tests only and do not qualify a platform.

No real OS-level adversarial isolation tests have been implemented or run. The platform-specific requirements in the table are acceptance blockers; passing these TypeScript contracts is not evidence of OS isolation. No launch route is wired through CoreRuntime, protocol, Desktop, or CLI.
