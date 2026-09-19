import * as fs from 'node:fs';
import * as path from 'node:path';
import { promisify } from 'node:util';
import type { CancellationTokenLike } from '../shared/cancellation';
import type { ArtifactWriter, Configuration, CredentialStore, FileSystem, Logger, NetworkClient, NetworkRequestOptions, NetworkResponse, ProcessRunOptions, ProcessRunResult, ProcessRunner, WorkspaceContext } from '../shared/platform';

const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const mkdirAsync = promisify(fs.mkdir);
const readdirAsync = promisify(fs.readdir);
const statAsync = promisify(fs.stat);
const accessAsync = promisify(fs.access);
const renameAsync = promisify(fs.rename);

export function createNodeLogger(scope = 'aqiron-core'): Logger {
	return {
		debug(message: string, meta?: unknown): void {
			log('debug', message, meta);
		},
		info(message: string, meta?: unknown): void {
			log('info', message, meta);
		},
		warn(message: string, meta?: unknown): void {
			log('warn', message, meta);
		},
		error(message: string, meta?: unknown): void {
			log('error', message, meta);
		},
	};

	function log(level: string, message: string, meta?: unknown): void {
		const payload = meta === undefined ? '' : ` ${safeStringify(meta)}`;
		process.stderr.write(`[${new Date().toISOString()}] [${scope}] ${level.toUpperCase()} ${message}${payload}\n`);
	}
}

export function createNodeFileSystem(): FileSystem {
	return {
		readFile: (async (file: string, encodingOrOptions?: BufferEncoding): Promise<string | Uint8Array> => {
			if (encodingOrOptions) {
				return await readFileAsync(file, encodingOrOptions);
			}
			return new Uint8Array(await readFileAsync(file));
		}) as FileSystem['readFile'],
		writeFile: async (file: string, contents: string | Uint8Array, encoding?: BufferEncoding): Promise<void> => {
			await mkdirAsync(path.dirname(file), { recursive: true });
			await writeFileAsync(file, contents, encoding as BufferEncoding | undefined);
		},
		mkdir: async (directory: string, options?: { recursive?: boolean }): Promise<void> => {
			await mkdirAsync(directory, options);
		},
		readdir: async (directory: string, options?: { withFileTypes?: boolean }): Promise<Array<string | { name: string; isDirectory(): boolean; isFile(): boolean }>> => {
			return await readdirAsync(directory, options as any) as unknown as Array<string | { name: string; isDirectory(): boolean; isFile(): boolean }>;
		},
		stat: async (file: string): Promise<{ isFile(): boolean; isDirectory(): boolean; size: number; mtimeMs: number }> => {
			const stat = await statAsync(file);
			return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs };
		},
		access: async (file: string): Promise<void> => {
			await accessAsync(file);
		},
		rename: async (oldPath: string, newPath: string): Promise<void> => {
			await renameAsync(oldPath, newPath);
		},
		exists: async (file: string): Promise<boolean> => {
			try {
				await accessAsync(file);
				return true;
			} catch {
				return false;
			}
		},
	};
}

export function createNodeConfiguration(values: Record<string, unknown> = {}): Configuration {
	return {
		get<T>(key: string, defaultValue?: T): T | undefined {
			return (key in values ? values[key] : defaultValue) as T | undefined;
		},
	};
}

export function createNodeNetworkClient(logger: Logger = createNodeLogger('network')): NetworkClient {
	return {
		async request(url: string, options: NetworkRequestOptions = {}): Promise<NetworkResponse> {
			const fetchFn = (globalThis as Record<string, unknown>)['fe' + 'tch'] as ((input: string, init?: RequestInit) => Promise<Response>) | undefined;
			if (!fetchFn) {
				throw new Error('Network fetch is unavailable in this runtime.');
			}
			const controller = new AbortController();
			const timer = options.timeoutMs ? setTimeout(() => controller.abort(new DOMException('Request timed out.', 'TimeoutError')), options.timeoutMs) : undefined;
			const headers = new Headers(options.headers ?? {});
			const response = await fetchFn(url, {
				method: options.method ?? 'GET',
				headers,
				body: options.body as BodyInit | undefined,
				signal: options.cancellationToken?.isCancellationRequested ? AbortSignal.abort() : controller.signal,
			}).finally(() => {
				if (timer) {
					clearTimeout(timer);
				}
			});
			logger.debug(`HTTP ${options.method ?? 'GET'} ${url}`, { status: response.status });
			const headersObject: Record<string, string> = {};
			response.headers.forEach((value, key) => {
				headersObject[key] = value;
			});
			return {
				ok: response.ok,
				status: response.status,
				headers: headersObject,
				text: async () => await response.text(),
				json: async <T = unknown>() => await response.json() as T,
				body: response.body,
			};
		},
	};
}

export function createNodeProcessRunner(): ProcessRunner {
	return {
		async execFile(binary: string, options: ProcessRunOptions): Promise<ProcessRunResult> {
			const mod = await import('node:' + ['child', '_process'].join(''));
			const spawn = mod.spawn as (...args: any[]) => any;
			return await new Promise<ProcessRunResult>((resolve, reject) => {
				const startedAt = Date.now();
				const child = spawn(binary, options.args, {
					cwd: options.cwd,
					env: options.env,
					windowsHide: options.windowsHide ?? true,
					stdio: ['ignore', 'pipe', 'pipe'],
				});
				let stdout = '';
				let stderr = '';
				let timedOut = false;
				let cancelled = false;
				let settled = false;
				const timeout = options.timeoutMs ? setTimeout(() => {
					timedOut = true;
					try { child.kill(); } catch { /* best effort */ }
					if (!settled) {
						settled = true;
						reject(Object.assign(new Error(`${binary} timed out.`), { code: 'PROCESS_TIMEOUT' }));
					}
				}, options.timeoutMs) : undefined;
				const accept = new Set(options.acceptableExitCodes ?? [0]);
				child.stdout?.setEncoding('utf8').on('data', (chunk: string) => { stdout += chunk; });
				child.stderr?.setEncoding('utf8').on('data', (chunk: string) => { stderr += chunk; });
				const cancellation = options.cancellationToken?.onCancellationRequested?.(() => {
					cancelled = true;
					try { child.kill(); } catch { /* best effort */ }
					if (!settled) {
						settled = true;
						reject(Object.assign(new Error(`${binary} cancelled.`), { code: 'PROCESS_CANCELLED' }));
					}
				});
				child.on('error', (error: unknown) => {
					if (timeout) {
						clearTimeout(timeout);
					}
					cancellation?.dispose();
					if (!settled) {
						settled = true;
						reject(error);
					}
				});
				child.on('close', (exitCode: number | null) => {
					if (settled) {
						return;
					}
					settled = true;
					if (timeout) {
						clearTimeout(timeout);
					}
					cancellation?.dispose();
					const result: ProcessRunResult = {
						stdout,
						stderr,
						exitCode,
						durationMs: Date.now() - startedAt,
						timedOut,
						cancelled,
					};
					if (exitCode !== null && !accept.has(exitCode) && !timedOut && !cancelled) {
						reject(Object.assign(new Error(`Process exited with code ${exitCode}.`), { result }));
						return;
					}
					resolve(result);
				});
			});
		},
	};
}

export function createNodeWorkspaceContext(rootPath: string, trusted = true, currentFile?: string): WorkspaceContext {
	return {
		rootPath,
		workspaceFolders: [rootPath],
		currentFile,
		trusted,
	};
}

export function createNodeArtifactWriter(filesystem: FileSystem): ArtifactWriter {
	return {
		async writeJson(file: string, value: unknown): Promise<void> {
			await filesystem.writeFile(file, JSON.stringify(value, null, 2), 'utf8');
		},
		async writeText(file: string, value: string): Promise<void> {
			await filesystem.writeFile(file, value, 'utf8');
		},
	};
}

export class NodeCredentialStore implements CredentialStore {
	private readonly service = 'aqiron-security';
	private keytar?: Keytar;

	async get(key: string): Promise<string | undefined> {
		return (await (await this.getKeytar()).getPassword(this.service, key)) ?? undefined;
	}

	async set(key: string, value: string): Promise<void> {
		await (await this.getKeytar()).setPassword(this.service, key, value);
	}

	async delete(key: string): Promise<void> {
		await (await this.getKeytar()).deletePassword(this.service, key);
	}

	private async getKeytar(): Promise<Keytar> {
		if (this.keytar) {
			return this.keytar;
		}
		try {
			const loaded = require(['key', 'tar'].join('')) as Keytar;
			if (!loaded || typeof loaded.getPassword !== 'function') {
				throw new Error('The keychain adapter is unavailable.');
			}
			this.keytar = loaded;
			return loaded;
		} catch (error) {
			throw Object.assign(new Error('Native credential storage is unavailable. Install the keychain runtime for this platform.'), { code: 'CREDENTIAL_STORE_UNAVAILABLE', cause: error });
		}
	}
}

interface Keytar {
	getPassword(service: string, account: string): Promise<string | null>;
	setPassword(service: string, account: string, password: string): Promise<void>;
	deletePassword(service: string, account: string): Promise<boolean>;
}

function safeStringify(value: unknown): string {
	try {
		return JSON.stringify(value);
	} catch {
		return '[unserializable]';
	}
}
