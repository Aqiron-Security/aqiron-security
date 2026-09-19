import { addRegexSignals as coreAddRegexSignals, loadRegexCatalog as coreLoadRegexCatalog, saveRegexCatalog as coreSaveRegexCatalog, syncRegexes as coreSyncRegexes, validateRegexCatalog, validateRegexSignal } from '../../packages/core/src/rag';
import { FileSystem, NetworkClient } from '../../packages/core/src/shared/platform';

function createFileSystem(): FileSystem {
	return {
		readFile: nodeReadFile,
		writeFile: async (file: string, contents: string | Uint8Array, encoding?: BufferEncoding) => {
			const fs = await import('fs/promises');
			return fs.writeFile(file, contents, encoding);
		},
		mkdir: async (file: string, options?: { recursive?: boolean }) => {
			const fs = await import('fs/promises');
			await fs.mkdir(file, options);
		},
		readdir: async (file: string, options?: { withFileTypes?: boolean }) => {
			const fs = await import('fs/promises');
			return fs.readdir(file, options as { withFileTypes: true });
		},
		stat: async (file: string) => {
			const fs = await import('fs/promises');
			const stat = await fs.stat(file);
			return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs };
		},
		access: async (file: string) => {
			const fs = await import('fs/promises');
			await fs.access(file);
		},
		rename: async (oldPath: string, newPath: string) => {
			const fs = await import('fs/promises');
			await fs.rename(oldPath, newPath);
		},
		exists: async (file: string) => {
			const fs = await import('fs/promises');
			return fs.access(file).then(() => true).catch(() => false);
		},
	};
}

function createNetworkClient(): NetworkClient {
	return {
		async request(url: string, options: { method?: string; headers?: Record<string, string>; body?: string | Uint8Array; timeoutMs?: number } = {}) {
			const controller = new AbortController();
			const timeout = typeof options.timeoutMs === 'number' ? setTimeout(() => controller.abort(), options.timeoutMs) : undefined;
			const response = await fetch(url, { method: options.method ?? 'GET', headers: options.headers, body: options.body as BodyInit | undefined, signal: controller.signal });
			if (timeout) {
				clearTimeout(timeout);
			}
			return {
				ok: response.ok,
				status: response.status,
		headers: (() => {
			const headers: Record<string, string> = {};
			response.headers.forEach((value, key) => {
				headers[key] = value;
			});
			return headers;
		})(),
				text: async () => response.text(),
				json: async <T = unknown>() => response.json() as Promise<T>,
			};
		},
	};
}

async function nodeReadFile(file: string, encoding: BufferEncoding): Promise<string>;
async function nodeReadFile(file: string): Promise<Uint8Array>;
async function nodeReadFile(file: string, encoding?: BufferEncoding): Promise<string | Uint8Array> {
	const fs = await import('fs/promises');
	return encoding ? fs.readFile(file, encoding) : fs.readFile(file);
}

export { validateRegexSignal, validateRegexCatalog };

export async function loadRegexCatalog(root: string) {
	return coreLoadRegexCatalog(root, createFileSystem());
}

export async function saveRegexCatalog(root: string, catalog: Parameters<typeof coreSaveRegexCatalog>[1]) {
	return coreSaveRegexCatalog(root, catalog, createFileSystem());
}

export async function addRegexSignals(root: string, source: Parameters<typeof coreAddRegexSignals>[1]) {
	return coreAddRegexSignals(root, source, createFileSystem());
}

export async function syncRegexes(root: string, fetcher?: typeof fetch) {
	if (fetcher) {
		return coreSyncRegexes(root, {
			async request(url: string) {
				const response = await fetcher(url);
				return {
					ok: response.ok,
					status: response.status,
					headers: (() => {
						const headers: Record<string, string> = {};
						response.headers?.forEach((value, key) => {
							headers[key] = value;
						});
						return headers;
					})(),
					text: async () => response.text(),
					json: async <T = unknown>() => response.json() as Promise<T>,
				};
			},
		}, createFileSystem());
	}
	return coreSyncRegexes(root, createNetworkClient(), createFileSystem());
}
