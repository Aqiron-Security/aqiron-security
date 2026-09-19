import * as fs from 'fs/promises';

export interface ScanCacheEntry<T> {
	mtimeMs: number;
	size: number;
	value: T;
}

export class ScanCache<T> {
	private readonly entries = new Map<string, ScanCacheEntry<T>>();

	async get(file: string): Promise<T | undefined> {
		const stat = await fs.stat(file);
		const entry = this.entries.get(file);
		if (entry && entry.mtimeMs === stat.mtimeMs && entry.size === stat.size) {
			return entry.value;
		}
		return undefined;
	}

	async set(file: string, value: T): Promise<void> {
		const stat = await fs.stat(file);
		this.entries.set(file, { mtimeMs: stat.mtimeMs, size: stat.size, value });
	}

	clear(): void {
		this.entries.clear();
	}
}
