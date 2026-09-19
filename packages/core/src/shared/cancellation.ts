export interface CancellationTokenLike {
	readonly isCancellationRequested: boolean;
	readonly onCancellationRequested?: (listener: (...args: any[]) => any, thisArgs?: any, disposables?: { dispose(): void }[]) => { dispose(): void };
}

export interface CancellationSource {
	readonly token: CancellationTokenLike;
	cancel(): void;
}

export function createCancellationSource(): CancellationSource {
	let cancelled = false;
	const listeners = new Set<() => void>();
	const token: CancellationTokenLike = {
		get isCancellationRequested(): boolean {
			return cancelled;
		},
		onCancellationRequested(listener: () => void): { dispose(): void } {
			if (cancelled) {
				listener();
				return { dispose: () => undefined };
			}
			listeners.add(listener);
			return { dispose: () => listeners.delete(listener) };
		},
	};
	return {
		token,
		cancel(): void {
			if (cancelled) {
				return;
			}
			cancelled = true;
			for (const listener of listeners) {
				listener();
			}
			listeners.clear();
		},
	};
}

export function isCancellationRequested(token?: CancellationTokenLike): boolean {
	return Boolean(token?.isCancellationRequested);
}
