import { CancellationTokenLike } from './cancellation';

export interface FileSystem {
	readFile(path: string, encoding: BufferEncoding): Promise<string>;
	readFile(path: string): Promise<Uint8Array>;
	writeFile(path: string, contents: string | Uint8Array, encoding?: BufferEncoding): Promise<void>;
	mkdir(path: string, options?: { recursive?: boolean }): Promise<void>;
	readdir(path: string, options?: { withFileTypes?: boolean }): Promise<Array<string | { name: string; isDirectory(): boolean; isFile(): boolean }>>;
	stat(path: string): Promise<{ isFile(): boolean; isDirectory(): boolean; size: number; mtimeMs: number }>;
	access(path: string): Promise<void>;
	rename(oldPath: string, newPath: string): Promise<void>;
	exists(path: string): Promise<boolean>;
}

export interface ProcessRunOptions {
	cwd: string;
	args: string[];
	env?: NodeJS.ProcessEnv;
	timeoutMs?: number;
	maxBuffer?: number;
	windowsHide?: boolean;
	cancellationToken?: CancellationTokenLike;
	acceptableExitCodes?: number[];
}

export interface ProcessRunResult {
	stdout: string;
	stderr: string;
	exitCode: number | null;
	durationMs: number;
	timedOut: boolean;
	cancelled: boolean;
}

export interface ProcessRunner {
	execFile(binary: string, options: ProcessRunOptions): Promise<ProcessRunResult>;
}

export interface CredentialStore {
	get(key: string): Promise<string | undefined>;
	set(key: string, value: string): Promise<void>;
	delete(key: string): Promise<void>;
}

export interface NetworkRequestOptions {
	method?: string;
	headers?: Record<string, string>;
	body?: string | Uint8Array;
	timeoutMs?: number;
	cancellationToken?: CancellationTokenLike;
}

export interface NetworkResponse {
	ok: boolean;
	status: number;
	headers: Record<string, string>;
	text(): Promise<string>;
	json<T = unknown>(): Promise<T>;
	body?: ReadableStream<Uint8Array> | null;
}

export interface NetworkClient {
	request(url: string, options?: NetworkRequestOptions): Promise<NetworkResponse>;
}

export interface Logger {
	debug(message: string, meta?: unknown): void;
	info(message: string, meta?: unknown): void;
	warn(message: string, meta?: unknown): void;
	error(message: string, meta?: unknown): void;
}

export interface Configuration {
	get<T>(key: string, defaultValue: T): T;
	get<T>(key: string): T | undefined;
}

export interface Cancellation {
	readonly isCancellationRequested: boolean;
	readonly onCancellationRequested?: (listener: (...args: any[]) => any, thisArgs?: any, disposables?: { dispose(): void }[]) => { dispose(): void };
}

export interface ArtifactWriter {
	writeJson(path: string, value: unknown): Promise<void>;
	writeText(path: string, value: string): Promise<void>;
}

export interface WorkspaceContext {
	rootPath: string;
	workspaceFolders: string[];
	currentFile?: string;
	trusted: boolean;
}
