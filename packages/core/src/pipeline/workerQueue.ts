export class WorkerQueue {
	private running = 0;
	private readonly pending: Array<() => void> = [];

	constructor(private readonly concurrency: number) {}

	async run<T>(task: () => Promise<T>): Promise<T> {
		await this.acquire();
		try {
			return await task();
		} finally {
			this.release();
		}
	}

	private async acquire(): Promise<void> {
		if (this.running < this.concurrency) {
			this.running += 1;
			return;
		}
		await new Promise<void>((resolve) => this.pending.push(resolve));
		this.running += 1;
	}

	private release(): void {
		this.running = Math.max(0, this.running - 1);
		const next = this.pending.shift();
		next?.();
	}
}
