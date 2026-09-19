export class TimeoutError extends Error {
	constructor(timeoutMs: number) {
		super(`Request timed out after ${timeoutMs}ms.`);
		this.name = 'TimeoutError';
	}
}

export function createTimeoutSignal(timeoutMs: number, parent?: AbortSignal): { signal: AbortSignal; dispose: () => void } {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(new TimeoutError(timeoutMs)), timeoutMs);
	const onAbort = () => controller.abort(parent?.reason);
	if (parent) {
		if (parent.aborted) {
			onAbort();
		} else {
			parent.addEventListener('abort', onAbort, { once: true });
		}
	}
	return {
		signal: controller.signal,
		dispose: () => {
			clearTimeout(timer);
			parent?.removeEventListener('abort', onAbort);
		},
	};
}
