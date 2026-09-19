import * as childProcess from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { PipelineEmitter, CancellationTokenLike } from '../../../packages/core/src';

export interface ToolRunOptions {
	toolId: string;
	label: string;
	binary: string;
	args: string[];
	cwd: string;
	timeoutMs: number;
	cancellationToken?: CancellationTokenLike;
	env?: NodeJS.ProcessEnv;
	streamStdout?: boolean;
	streamStderr?: boolean;
	acceptableExitCodes?: number[];
}

export interface ToolRunResult {
	stdout: string;
	stderr: string;
	exitCode: number | null;
	durationMs: number;
	timedOut: boolean;
	cancelled: boolean;
}

export class ToolUnavailableError extends Error {
	constructor(readonly binary: string) {
		super(`${binary} is not installed or is not available on PATH.`);
	}
}

export class SecureToolExecutor {
	constructor(private readonly emitter: PipelineEmitter) {}

	async run(options: ToolRunOptions): Promise<ToolRunResult> {
		validateBinaryName(options.binary);
		validateWorkingDirectory(options.cwd);
		validateArgs(options.args);

		const startedAt = Date.now();
		this.emitter.emit({
			type: 'tool',
			tool: {
				id: options.toolId,
				label: options.label,
				command: formatCommand(options.binary, options.args),
				status: 'running',
				startedAt: new Date(startedAt).toISOString(),
			},
		});

		await this.assertBinaryAvailable(options.binary, options.cwd, options.timeoutMs);

		return new Promise<ToolRunResult>((resolve, reject) => {
			let stdout = '';
			let stderr = '';
			let timedOut = false;
			let cancelled = false;
			const child = childProcess.execFile(
				options.binary,
				options.args,
				{
					cwd: options.cwd,
					timeout: options.timeoutMs,
					maxBuffer: 64 * 1024 * 1024,
					windowsHide: true,
					env: { ...process.env, ...options.env },
				},
				(error, finalStdout, finalStderr) => {
					stdout = stdout || finalStdout;
					stderr = stderr || finalStderr;
					const durationMs = Date.now() - startedAt;
					const exitCode = getExitCode(error);
					timedOut = timedOut || Boolean(error && 'killed' in error && error.killed && durationMs >= options.timeoutMs);
					const acceptable = exitCode === 0 || options.acceptableExitCodes?.includes(exitCode ?? -1);
					const status = cancelled ? 'cancelled' : timedOut ? 'timeout' : acceptable ? 'completed' : 'failed';
					this.emitter.emit({
						type: 'tool',
						tool: {
							id: options.toolId,
							label: options.label,
							command: formatCommand(options.binary, options.args),
							status,
							completedAt: new Date().toISOString(),
							durationMs,
							exitCode: exitCode ?? undefined,
							message: stderr.trim().slice(0, 500) || undefined,
						},
					});
					if (error && !timedOut && !cancelled && !acceptable) {
						reject(new Error(stderr.trim() || error.message));
						return;
					}
					resolve({ stdout, stderr, exitCode, durationMs, timedOut, cancelled });
				},
			);

			child.stdout?.on('data', (chunk: Buffer | string) => {
				const text = chunk.toString();
				stdout += text;
				if (options.streamStdout !== false) {
					this.emitLines(options.toolId, text);
				}
			});
			child.stderr?.on('data', (chunk: Buffer | string) => {
				const text = chunk.toString();
				stderr += text;
				if (options.streamStderr !== false) {
					this.emitLines(options.toolId, text);
				}
			});
			const subscription = options.cancellationToken?.onCancellationRequested?.(() => {
				cancelled = true;
				child.kill();
			});
			child.on('close', () => subscription?.dispose());
		});
	}

	private async assertBinaryAvailable(binary: string, cwd: string, timeoutMs: number): Promise<void> {
		try {
			await fs.access(cwd);
			await new Promise<void>((resolve, reject) => {
				childProcess.execFile(binary, ['--version'], { cwd, timeout: Math.min(timeoutMs, 5000), windowsHide: true }, (error) => {
					if (error && isMissingBinary(error)) {
						reject(new ToolUnavailableError(binary));
						return;
					}
					resolve();
				});
			});
		} catch (error) {
			if (error instanceof ToolUnavailableError) {
				this.emitter.emit({ type: 'tool', tool: { id: binary, label: binary, command: `${binary} --version`, status: 'unavailable', message: error.message } });
			}
			throw error;
		}
	}

	private emitLines(toolId: string, text: string): void {
		for (const line of text.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)) {
			this.emitter.emit({ type: 'log', tool: toolId, message: line, timestamp: new Date().toISOString() });
		}
	}
}

function validateBinaryName(binary: string): void {
	if (!/^[\w.-]+(?:\.exe)?$/i.test(binary)) {
		throw new Error(`Refusing to execute invalid binary name: ${binary}`);
	}
}

function validateWorkingDirectory(cwd: string): void {
	if (!path.isAbsolute(cwd)) {
		throw new Error('Tool working directory must be absolute.');
	}
}

function validateArgs(args: readonly string[]): void {
	for (const arg of args) {
		if (arg.includes('\u0000')) {
			throw new Error('Tool argument contains an invalid NUL byte.');
		}
	}
}

function formatCommand(binary: string, args: readonly string[]): string {
	return [binary, ...args.map((arg) => /\s/.test(arg) ? JSON.stringify(arg) : arg)].join(' ');
}

function getExitCode(error: childProcess.ExecFileException | null): number | null {
	if (!error) {
		return 0;
	}
	return typeof error.code === 'number' ? error.code : null;
}

function isMissingBinary(error: childProcess.ExecFileException): boolean {
	return typeof error.code === 'string' && ['ENOENT', 'UNKNOWN'].includes(error.code);
}
