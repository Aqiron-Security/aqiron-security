import * as childProcess from 'child_process';
import * as fs from 'fs/promises';
import * as vscode from 'vscode';
import { ProcessRunner, ProcessRunOptions, ProcessRunResult, FileSystem, NetworkClient, NetworkRequestOptions, Configuration, Logger, ScannerContext, ScannerMode } from '../../../packages/core/src';
import { PipelineEmitter } from '../pipeline/events';
import { ScanTarget, ScannerRunContext } from './types';
import { getAqExclusions } from '../../utils/files';

export function createScannerContext(target: ScanTarget, context: ScannerRunContext, mode: ScannerMode = 'deep'): ScannerContext {
	return {
		workspaceRoot: target.workspaceRoot,
		targetPath: target.targetPath,
		containerImage: target.containerImage,
		policyPath: target.policyPath,
		exclusions: target.exclusions.length ? target.exclusions : getAqExclusions(target.workspaceRoot),
		mode,
		cancellationToken: context.cancellationToken,
		configuration: createConfiguration(),
		filesystem: createFileSystem(),
		processRunner: createProcessRunner(context.emitter),
		networkClient: createNetworkClient(),
		logger: createLogger(context.emitter),
		environment: {
			platform: process.platform,
			arch: process.arch,
			os: process.platform,
		},
	};
}

function createConfiguration(): Configuration {
	return {
		get<T>(key: string, defaultValue?: T): T | undefined {
			return vscode.workspace.getConfiguration('aqiron-security').get<T>(key, defaultValue as T) as T | undefined;
		},
	};
}

function createFileSystem(): FileSystem {
	return {
		readFile: fs.readFile,
		writeFile: fs.writeFile,
		mkdir: async (file: string, options?: { recursive?: boolean }) => { await fs.mkdir(file, options); },
		readdir: async (file: string, options?: { withFileTypes?: boolean }) => fs.readdir(file, options as { withFileTypes: true }),
		stat: async (file: string) => {
			const stat = await fs.stat(file);
			return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs };
		},
		access: fs.access,
		rename: fs.rename,
		exists: async (file: string) => fs.access(file).then(() => true).catch(() => false),
	};
}

function createProcessRunner(emitter: PipelineEmitter): ProcessRunner {
	return {
		async execFile(binary: string, options: ProcessRunOptions): Promise<ProcessRunResult> {
			const startedAt = Date.now();
			let stdout = '';
			let stderr = '';
			let timedOut = false;
			let cancelled = false;
			const child = childProcess.execFile(binary, options.args, {
				cwd: options.cwd,
				timeout: options.timeoutMs,
				maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
				windowsHide: options.windowsHide ?? true,
				env: { ...process.env, ...options.env },
			}, (error, finalStdout, finalStderr) => {
				stdout = stdout || String(finalStdout ?? '');
				stderr = stderr || String(finalStderr ?? '');
				const durationMs = Date.now() - startedAt;
				const exitCode = typeof error?.code === 'number' ? error.code : 0;
				timedOut = timedOut || Boolean(error && 'killed' in error && error.killed && durationMs >= (options.timeoutMs ?? durationMs));
				const acceptable = exitCode === 0 || options.acceptableExitCodes?.includes(exitCode);
				if (error && !timedOut && !cancelled && !acceptable) {
					stderr = stderr || error.message;
				}
			});
			child.stdout?.on('data', (chunk: Buffer | string) => emitLines(emitter, binary, chunk.toString()));
			child.stderr?.on('data', (chunk: Buffer | string) => emitLines(emitter, binary, chunk.toString()));
			const subscription = options.cancellationToken?.onCancellationRequested?.(() => {
				cancelled = true;
				child.kill();
			});
			return new Promise<ProcessRunResult>((resolve, reject) => {
				child.on('error', (error) => {
					subscription?.dispose();
					reject(error);
				});
				child.on('close', (code) => {
					subscription?.dispose();
					const durationMs = Date.now() - startedAt;
					const exitCode = typeof code === 'number' ? code : null;
					const acceptable = exitCode === 0 || (exitCode !== null && options.acceptableExitCodes?.includes(exitCode));
					if (!acceptable && !cancelled && !timedOut && exitCode !== 0) {
						reject(new Error(stderr.trim() || `${binary} exited with code ${exitCode}`));
						return;
					}
					resolve({ stdout, stderr, exitCode, durationMs, timedOut, cancelled });
				});
			});
		},
	};
}

function createNetworkClient(): NetworkClient {
	return {
		async request(url: string, options: NetworkRequestOptions = {}) {
			const controller = new AbortController();
			const timeout = typeof options.timeoutMs === 'number'
				? setTimeout(() => controller.abort(), options.timeoutMs)
				: undefined;
			const cancelSubscription = options.cancellationToken?.onCancellationRequested?.(() => controller.abort());
			const response = await fetch(url, {
				method: options.method ?? 'GET',
				headers: options.headers,
				body: options.body as BodyInit | undefined,
				signal: controller.signal,
			});
			if (timeout) {
				clearTimeout(timeout);
			}
			cancelSubscription?.dispose();
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

function createLogger(emitter: PipelineEmitter): Logger {
	return {
		debug: (message, meta) => emitter.emit({ type: 'log', tool: 'scanner', message: format(message, meta), timestamp: new Date().toISOString() }),
		info: (message, meta) => emitter.emit({ type: 'log', tool: 'scanner', message: format(message, meta), timestamp: new Date().toISOString() }),
		warn: (message, meta) => emitter.emit({ type: 'log', tool: 'scanner', message: format(message, meta), timestamp: new Date().toISOString() }),
		error: (message, meta) => emitter.emit({ type: 'log', tool: 'scanner', message: format(message, meta), timestamp: new Date().toISOString() }),
	};
}

function emitLines(emitter: PipelineEmitter, tool: string, text: string): void {
	for (const line of text.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)) {
		emitter.emit({ type: 'log', tool, message: line, timestamp: new Date().toISOString() });
	}
}

function format(message: string, meta?: unknown): string {
	return meta === undefined ? message : `${message} ${typeof meta === 'string' ? meta : JSON.stringify(meta)}`;
}
