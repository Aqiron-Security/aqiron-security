export interface RetryOptions {
	retries: number;
	baseDelayMs?: number;
	shouldRetry?: (error: unknown, attempt: number) => boolean;
}

export async function withRetry<T>(operation: () => Promise<T>, options: RetryOptions): Promise<T> {
	const retries = Math.max(0, options.retries);
	const baseDelayMs = options.baseDelayMs ?? 350;
	let lastError: unknown;
	for (let attempt = 0; attempt <= retries; attempt++) {
		try {
			return await operation();
		} catch (error) {
			lastError = error;
			if (attempt >= retries || options.shouldRetry?.(error, attempt) === false) {
				break;
			}
			await sleep(baseDelayMs * Math.pow(2, attempt));
		}
	}
	throw lastError;
}

export function isTransientError(error: unknown): boolean {
	if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
		return false;
	}
	const status = typeof error === 'object' && error !== null && 'status' in error ? Number((error as { status: unknown }).status) : 0;
	return status === 0 || status === 408 || status === 429 || status >= 500;
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
