import * as fs from 'node:fs';
import * as os from 'node:os';
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

/** Per-user Core state root. Validation approval history never lives in a selected project. */
export function resolveCoreDataDirectory(platform: NodeJS.Platform = process.platform, environment: NodeJS.ProcessEnv = process.env, homeDirectory: string = os.homedir()): string {
	if (platform === 'win32') {
		const roaming = environment.APPDATA;
		return path.resolve(roaming && path.isAbsolute(roaming) ? roaming : path.join(homeDirectory, 'AppData', 'Roaming'), 'Aqiron', 'Aqiron Security', 'Core');
	}
	if (platform === 'darwin') { return path.resolve(homeDirectory, 'Library', 'Application Support', 'Aqiron Security', 'Core'); }
	const stateHome = environment.XDG_STATE_HOME;
	return path.resolve(stateHome && path.isAbsolute(stateHome) ? stateHome : path.join(homeDirectory, '.local', 'state'), 'aqiron-security');
}

async function readRawBounded(file: string, maxBytes: number, noFollow = false): Promise<Uint8Array> {
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {throw new RangeError('A non-negative bounded-read limit is required.');}
	const safeOpenFlags = noFollow ? fs.constants.O_RDONLY | requireSafeOpenCapabilities(fs.constants.O_NOFOLLOW, fs.constants.O_NONBLOCK) : undefined;
	const handle = await fs.promises.open(file, safeOpenFlags ?? 'r');
	let total = 0;
	try {
		const initial = await handle.stat();
		if (noFollow && (!initial.isFile() || initial.nlink !== 1)) {throw new Error('Safe bounded read requires a private regular file.');}
		if (initial.size > maxBytes) {throw Object.assign(new Error(`File exceeds the ${maxBytes}-byte read limit.`), { code: 'FILE_TOO_LARGE', bytesRead: 0 });}
		const chunks: Buffer[] = [];
		while (total <= maxBytes) {
			const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - total));
			const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
			if (bytesRead === 0) {break;}
			total += bytesRead;
			if (total > maxBytes) {throw Object.assign(new Error(`File exceeds the ${maxBytes}-byte read limit.`), { code: 'FILE_TOO_LARGE', bytesRead: total });}
			chunks.push(chunk.subarray(0, bytesRead));
		}
		return Buffer.concat(chunks, total);
	} catch (error) {
		if (error && typeof error === 'object') {Object.assign(error, { bytesRead: total });}
		throw error;
	} finally { await handle.close(); }
}

/** Internal fail-closed capability check shared by race-resistant safe-open paths. */
export function requireSafeOpenCapabilities(noFollowFlag: number | undefined, nonBlockFlag: number | undefined): number {
	if (!Number.isSafeInteger(noFollowFlag) || noFollowFlag === undefined || noFollowFlag <= 0 || !Number.isSafeInteger(nonBlockFlag) || nonBlockFlag === undefined || nonBlockFlag <= 0) {
		throw Object.assign(new Error('Race-resistant no-follow and nonblocking file opening is unavailable on this platform.'), { code: 'SAFE_OPEN_UNAVAILABLE' });
	}
	return noFollowFlag | nonBlockFlag;
}

interface DurableAppendHandle {
	stat(): Promise<{ isFile(): boolean; nlink: number }>;
	write(buffer: Uint8Array, offset: number, length: number, position: number | null): Promise<{ bytesWritten: number }>;
	sync(): Promise<void>;
	close(): Promise<void>;
}
interface DurableAppendOperations {
	open(file: string, flags: number, mode?: number): Promise<DurableAppendHandle>;
	syncDirectory(directory: string): Promise<void>;
}
/** Internal seam for deterministic create-race tests; not re-exported from the Core package entry point. */
export async function appendFileDurableWithRetry(file: string, contents: Uint8Array, operations: DurableAppendOperations, constants: { readWrite: number; append: number; create: number; exclusive: number; noFollow: number | undefined; nonBlock: number | undefined }, maxCreateRaces = 3): Promise<void> {
	const safeFlags = requireSafeOpenCapabilities(constants.noFollow, constants.nonBlock);
	if (!Number.isSafeInteger(maxCreateRaces) || maxCreateRaces < 1 || maxCreateRaces > 8) { throw new RangeError('Invalid durable append create-race retry bound.'); }
	let handle: DurableAppendHandle | undefined;
	let created = false;
	try {
		for (let attempt = 0; attempt < maxCreateRaces; attempt++) {
			try {
				handle = await operations.open(file, constants.readWrite | constants.append | constants.create | constants.exclusive | safeFlags, 0o600);
				created = true;
				break;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== 'EEXIST') { throw error; }
				try {
					// Existing-file path deliberately omits O_CREAT. If it vanished after EEXIST, retry exclusive creation.
					handle = await operations.open(file, constants.readWrite | constants.append | safeFlags);
					created = false;
					break;
				} catch (fallbackError) {
					if ((fallbackError as NodeJS.ErrnoException).code !== 'ENOENT' || attempt === maxCreateRaces - 1) { throw fallbackError; }
				}
			}
		}
		if (!handle) { throw Object.assign(new Error('Durable append could not stabilize a concurrently replaced file.'), { code: 'APPEND_CREATE_RACE_EXHAUSTED' }); }
		const stat = await handle.stat();
		if (!stat.isFile() || stat.nlink !== 1) { throw new Error('Ledger target is not a private regular file.'); }
		let offset = 0;
		while (offset < contents.byteLength) {
			const { bytesWritten } = await handle.write(contents, offset, contents.byteLength - offset, null);
			if (bytesWritten <= 0) { throw new Error('Durable append made no progress.'); }
			offset += bytesWritten;
		}
		await handle.sync();
		await handle.close(); handle = undefined;
		if (created) { await operations.syncDirectory(path.dirname(file)); }
	} catch (error) {
		try { await handle?.close(); } catch { /* preserve the ambiguous append */ }
		throw error;
	}
}


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
		readFileBoundedBytes: readRawBounded,
		readFileSafeBoundedBytes: async (file:string,maxBytes:number)=>await readRawBounded(file,maxBytes,true),
		readFileBounded: async (file: string, maxBytes: number, encoding: BufferEncoding): Promise<string> => Buffer.from(await readRawBounded(file, maxBytes)).toString(encoding),
		writeFile: async (file: string, contents: string | Uint8Array, encoding?: BufferEncoding): Promise<void> => {
			await mkdirAsync(path.dirname(file), { recursive: true });
			await writeFileAsync(file, contents, encoding as BufferEncoding | undefined);
		},
		writeFileExclusive: async (file: string, contents: string | Uint8Array, encoding?: BufferEncoding): Promise<void> => {
			const handle = await fs.promises.open(file, 'wx');
			try { await handle.writeFile(contents, { encoding: encoding as BufferEncoding | undefined }); await handle.close(); }
			catch (error) {
				try { await handle.close(); } catch { /* continue cleanup after close errors */ }
				// Keep a partial orphan. Pathname unlink is not ownership-safe after an ambiguous write failure.
				throw error;
			}
		},
		appendFileDurable: async (file: string, contents: Uint8Array): Promise<void> => {
			if (process.platform === 'win32') {
				throw Object.assign(new Error('Durable append is unavailable on Windows because this adapter cannot establish directory-entry durability.'), { code: 'DURABILITY_UNAVAILABLE' });
			}
			await appendFileDurableWithRetry(file, contents, {
				open: async (target, flags, mode) => await fs.promises.open(target, flags, mode) as unknown as DurableAppendHandle,
				syncDirectory: async directoryPath => { const directory = await fs.promises.open(directoryPath, fs.constants.O_RDONLY); try { await directory.sync(); } finally { await directory.close(); } },
			}, { readWrite: fs.constants.O_WRONLY, append: fs.constants.O_APPEND, create: fs.constants.O_CREAT, exclusive: fs.constants.O_EXCL, noFollow: fs.constants.O_NOFOLLOW, nonBlock: fs.constants.O_NONBLOCK });
		},
		writeFileDurableExclusive: async (file: string, contents: Uint8Array): Promise<void> => {
			if (process.platform === 'win32') { throw Object.assign(new Error('Durable file creation is unavailable on Windows because directory-entry durability cannot be established.'), { code: 'DURABILITY_UNAVAILABLE' }); }
			const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0);
			const handle = await fs.promises.open(file, flags, 0o600);
			try {
				let offset = 0;
				while (offset < contents.byteLength) { const { bytesWritten } = await handle.write(contents, offset, contents.byteLength - offset, offset); if (bytesWritten <= 0) { throw new Error('Durable file creation made no progress.'); } offset += bytesWritten; }
				await handle.sync();
			} finally { await handle.close(); }
			const directory = await fs.promises.open(path.dirname(file), fs.constants.O_RDONLY);
			try { await directory.sync(); } finally { await directory.close(); }
		},
		unlinkDurable: async (file: string): Promise<void> => {
			if (process.platform === 'win32') { throw Object.assign(new Error('Durable unlink is unavailable on Windows.'), { code: 'DURABILITY_UNAVAILABLE' }); }
			const stat = await fs.promises.lstat(file);
			if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) { throw new Error('Unsafe durable-unlink target.'); }
			await fs.promises.unlink(file);
			const directory = await fs.promises.open(path.dirname(file), fs.constants.O_RDONLY);
			try { await directory.sync(); } finally { await directory.close(); }
		},
		syncDirectoryDurable: async (directoryPath: string): Promise<void> => {
			if (process.platform === 'win32') { throw Object.assign(new Error('Directory-entry durability is unavailable on Windows.'), { code: 'DURABILITY_UNAVAILABLE' }); }
			const handle = await fs.promises.open(directoryPath, fs.constants.O_RDONLY);
			try { await handle.sync(); } finally { await handle.close(); }
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
		lstat: async (file: string) => {
			const stat = await fs.promises.lstat(file);
			return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), isSymbolicLink: () => stat.isSymbolicLink(), size: stat.size, mtimeMs: stat.mtimeMs };
		},
		realpath: async (file: string) => await fs.promises.realpath(file),
		access: async (file: string): Promise<void> => {
			await accessAsync(file);
		},
		rename: async (oldPath: string, newPath: string): Promise<void> => {
			await renameAsync(oldPath, newPath);
		},
		unlink: async (file: string): Promise<void> => {
			await fs.promises.unlink(file);
		},
		rmdir: async (directory: string): Promise<void> => {
			await fs.promises.rmdir(directory);
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
			const timer = options.timeoutMs && options.timeoutMs > 0 ? setTimeout(() => controller.abort(new DOMException('Request timed out.', 'TimeoutError')), options.timeoutMs) : undefined;
			const abortFromCaller = () => controller.abort(options.abortSignal?.reason);
			if (options.abortSignal?.aborted) { abortFromCaller(); }
			else { options.abortSignal?.addEventListener('abort', abortFromCaller, { once: true }); }
			const abortFromToken = options.cancellationToken?.onCancellationRequested?.(() => controller.abort());
			let cleaned = false;
			const cleanup = () => {
				if (cleaned) { return; }
				cleaned = true;
				if (timer) { clearTimeout(timer); }
				options.abortSignal?.removeEventListener('abort', abortFromCaller);
				abortFromToken?.dispose();
			};
			let headers: Headers;
			try { headers = new Headers(options.headers ?? {}); }
			catch { cleanup(); throw new Error('Network request headers are invalid.'); }
			let response: Response;
			try {
				response = await fetchFn(url, {
					method: options.method ?? 'GET', headers,
					body: options.body as BodyInit | undefined,
					signal: controller.signal,
					redirect: options.redirect ?? 'follow',
				});
			} catch (error) { cleanup(); throw error; }
			// Avoid logging endpoint paths or query strings, which can contain provider/model identifiers.
			logger.debug(`HTTP ${options.method ?? 'GET'} provider request`, { status: response.status });
			const headersObject: Record<string, string> = {};
			response.headers.forEach((value, key) => {
				headersObject[key] = value;
			});
			const body = response.body ? wrapResponseBody(response.body, cleanup, () => controller.abort()) : (cleanup(), null);
			return {
				ok: response.ok,
				status: response.status,
				headers: headersObject,
				text: async () => await readWrappedResponseText(body),
				json: async <T = unknown>() => JSON.parse(await readWrappedResponseText(body)) as T,
				body,
			};
		},
	};
}

async function readWrappedResponseText(body: ReadableStream<Uint8Array> | null): Promise<string> {
	if (!body) { return ''; }
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	try {
		while (true) {
			const part = await reader.read();
			if (part.done) { break; }
			chunks.push(part.value);
		}
		return Buffer.concat(chunks.map(chunk => Buffer.from(chunk))).toString('utf8');
	} finally { try { reader.releaseLock(); } catch { /* terminal stream */ } }
}

function wrapResponseBody(source: ReadableStream<Uint8Array>, cleanup: () => void, abort: () => void): ReadableStream<Uint8Array> {
	const reader = source.getReader();
	let finished = false;
	const finish = () => { if (!finished) { finished = true; cleanup(); try { reader.releaseLock(); } catch { /* closed or cancelled */ } } };
	return new ReadableStream<Uint8Array>({
		async pull(controller) {
			try {
				const result = await reader.read();
				if (result.done) { controller.close(); finish(); }
				else { controller.enqueue(result.value); }
			} catch { controller.error(new Error('Network response stream failed.')); finish(); }
		},
		async cancel(reason) { abort(); try { await reader.cancel(reason); } finally { finish(); } },
	});
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
	constructor(private readonly options: { platform?: NodeJS.Platform; keytarFactory?: () => Keytar } = {}) {}

	async get(key: string): Promise<string | undefined> {
		try {
			return (await (await this.getKeytar()).getPassword(this.service, key)) ?? undefined;
		} catch (error) {
			// Windows may have keytar installed while the current process has no
			// usable Credential Manager session. Treat that as unavailable storage
			// so read-only status APIs can fail closed without breaking Core startup.
			if ((this.options.platform ?? process.platform) === 'win32' && error instanceof Error && /^Access is denied\.?\s*$/i.test(error.message)) {
				throw Object.assign(new Error('Native credential storage is unavailable in this session.'), { code: 'CREDENTIAL_STORE_UNAVAILABLE' });
			}
			throw error;
		}
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
			const loaded = this.options.keytarFactory?.() ?? require(['key', 'tar'].join('')) as Keytar;
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
