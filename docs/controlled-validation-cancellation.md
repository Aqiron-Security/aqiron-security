# M22.3.6 Controlled Validation cancellation foundation

**Status: integrated Core coordination foundation; production execution remains disabled and every platform remains unqualified.** The supervisor transfers each successfully returned `IsolatedWorkerHandle` to one `WorkerCancellationCoordinator`. No second lifecycle owner operates that handle.

## Contract and lifecycle

The M22.3.5 handle exposes `wait(): Promise<IsolatedWorkerResult>`, `terminate('timeout' | 'cancel' | 'failure'): Promise<{ confirmed: boolean }>`, and `cleanup(): Promise<void>`. The contract does not define cleanup as safe while a worker may still be using its resources. Accordingly, the coordinator calls cleanup after natural completion or confirmed termination only. If termination throws, returns `confirmed: false`, or exceeds its bound, it returns `interrupted` with `executionUncertain: true` and skips provider cleanup. It cannot claim that an unconfirmed worker stopped.

States are `registered → running`; running can become cancellation-requested or proceed to cleanup and a terminal result. Cancellation proceeds `cancellation-requested → termination-requested → termination-confirmed → cleanup-completed | cleanup-failed → cancelled | timed-out | failed`. An unconfirmed termination leads to `interrupted`. Natural wait resolution or rejection leads through bounded cleanup to `completed` or `failed`. Cleanup timeout is `cleanup-failed`; it does not wait indefinitely. Terminal results are frozen and first commit wins. Late worker settlement is observed with a rejection handler and cannot replace the committed result.

The cancellation linearization point is the synchronous `running → cancellation-requested` transition in `cancel()`. Calls accepted after an already observed worker settlement preserve its outcome. Simultaneous cancellation/shutdown calls share one promise and therefore make at most one termination request. Completion observed while termination is in progress produces a completion/failure outcome with termination confirmation retained, rather than contradictory cancellation.

## Bounds and outcomes

The defaults are 120 seconds for natural wait, 2 seconds to request termination, 5 seconds for confirmation, 2 seconds for cleanup, and a 10 second overall shutdown budget. Each value must be a safe positive integer no greater than 120 seconds. The total must cover the termination and cleanup allocations and cannot exceed the sum of operation bounds. A monotonic clock is injectable; the default uses `process.hrtime.bigint()`.

Results separately report whether cancellation was requested, whether termination was confirmed, the outcome (`completed`, `failed`, `cancelled`, `interrupted`, or `timed-out`), cleanup outcome, and execution uncertainty. A timeout during termination is never successful cancellation. A start commitment remains committed: cancellation neither restores consumed authorization nor proves the procedure never began.

Timeout races attach handlers to each underlying promise. A timed-out provider operation may continue in the background because this abstract contract has no abort mechanism. The result reports uncertainty and does not interpret that promise's later settlement as proof of shutdown.

## Supervisor integration and audit boundary

Admission remains in `ExecutionSupervisor`: it validates the committed receipt, descriptor, scope, input bounds, and qualification before calling the provider. Provider launch rejection occurs before a handle exists and returns `failed` without coordinator termination or cleanup. After launch returns a handle, the supervisor creates the coordinator, registers it by execution ID for the duration of the launch, and delegates natural waiting, the profile execution deadline, cancellation, termination confirmation, and cleanup to it. The supervisor translates its one result into `SupervisorResult`; it no longer calls `wait`, `terminate`, or `cleanup` itself.

`ExecutionSupervisor.cancel(executionId)` is a Core-internal method for coordinating existing in-process work. It is not registered with CoreRuntime, protocol, Desktop, CLI, or another client. The production factory continues to reject launch before provider invocation, so it has no registered workers to cancel. Explicit cancellation and the profile deadline both call the coordinator's same `cancel()` operation. Concurrent requests join its in-flight promise; whichever reason linearizes first determines the reason passed to the one termination call. The registry entry is removed after launch settles; later cancel calls have no active handle and return `undefined`.

Natural successful completion or a resolved worker-error result selects completion/failure and performs one cleanup. A rejected `wait()` is not proof the worker stopped: it requests bounded termination with reason `failure`, then cleans only after confirmation. During termination, a worker `terminated` category maps to cancelled/timed-out/failed according to the winning request reason; a success or worker error preserves its own execution result. Cleanup failure is surfaced in `cleanupOutcome` without changing a selected completed/failed/cancelled/timed-out result. Unconfirmed termination maps to `interrupted`, preserves execution uncertainty, and skips worker cleanup. Launch and admission outcomes remain distinct from post-handle lifecycle outcomes.

No terminal-event writer is integrated: M22.3.3 persists only durable start-commit events, despite reserving terminal event categories. This module makes no durable cancellation-audit claim. A start commitment remains committed after cancellation and does not establish whether execution began.

Tests use fake handles and injected monotonic clocks only. No OS process implementation, platform adapter, qualification evidence, Desktop/CLI/protocol route, or production execution path is added. OS-level descendant containment, truthful OS termination confirmation, cleanup safety after abnormal shutdown, and adversarial qualification remain deferred.
