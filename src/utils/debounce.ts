export class Debouncer {
	private timer: NodeJS.Timeout | undefined;

	constructor(private readonly delayMs: number) {}

	run(task: () => void): void {
		if (this.timer) {
			clearTimeout(this.timer);
		}

		this.timer = setTimeout(task, this.delayMs);
	}

	dispose(): void {
		if (this.timer) {
			clearTimeout(this.timer);
		}
	}
}
