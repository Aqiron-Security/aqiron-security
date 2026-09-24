import * as childProcess from 'child_process';
import * as path from 'path';
import { EventEmitter } from 'events';
import { CORE_PROTOCOL_VERSION, CoreEventMessage, CoreHandshakeRequest, CoreHandshakeResponse, CoreMessage, CoreRequestMessage, CoreResponseMessage } from '../../packages/core/src/runtime';

export interface CoreProcessOptions {
	extensionVersion: string;
	protocolVersion?: number;
	timeoutMs?: number;
	restartOnCrash?: boolean;
}

export interface CoreProcessEvent {
	event: string;
	requestId?: string;
	payload?: unknown;
}

export type CoreProcessState = 'stopped' | 'starting' | 'ready' | 'unhealthy' | 'crashed' | 'restarting';

export class CoreProcessManager extends EventEmitter {
	private child?: childProcess.ChildProcessWithoutNullStreams;
	private buffer = '';
	private readonly pending = new Map<string, PendingRequest>();
	private readonly protocolVersion: number;
	private started = false;
	private expectedShutdown = false;
	private restartAttempts = 0;
	private restartTimer?: ReturnType<typeof setTimeout>;
	private state: CoreProcessState = 'stopped';
	private startPromise?: Promise<CoreHandshakeResponse>;

	constructor(private readonly options: CoreProcessOptions) {
		super();
		this.protocolVersion = options.protocolVersion ?? CORE_PROTOCOL_VERSION;
	}

	async start(): Promise<CoreHandshakeResponse> {
		if (this.state === 'ready' && this.child) {
			return { protocolVersion: this.protocolVersion, coreVersion: this.options.extensionVersion, status: 'compatible' };
		}
		if (this.startPromise) {
			return await this.startPromise;
		}
		this.startPromise = this.launch();
		try {
			return await this.startPromise;
		} finally {
			this.startPromise = undefined;
		}
	}

	getState(): CoreProcessState {
		return this.state;
	}

	private async launch(): Promise<CoreHandshakeResponse> {
		this.state = 'starting';
		this.emit('state', this.state);
		this.expectedShutdown = false;
		this.buffer = '';
		const runtimePath = path.join(__dirname, 'core-runtime.js');
		this.child = childProcess.spawn(process.execPath, [runtimePath], {
			cwd: path.dirname(runtimePath),
			env: { ...process.env, AQIRON_CORE_VERSION: this.options.extensionVersion },
			stdio: ['pipe', 'pipe', 'pipe'],
			windowsHide: true,
		});
		this.started = true;
		this.child.stdout.setEncoding('utf8');
		this.child.stderr.setEncoding('utf8');
		this.child.stdout.on('data', (chunk: string) => this.handleStdout(chunk));
		this.child.stderr.on('data', (chunk: string) => this.emit('log', chunk));
		this.child.on('exit', (code, signal) => {
			const expected = this.expectedShutdown;
			const error = Object.assign(new Error(`Core runtime exited unexpectedly (${code ?? signal ?? 'unknown'}).`), { code: 'CORE_PROCESS_CRASHED' });
			for (const pending of this.pending.values()) {
				pending.reject(error);
			}
			this.pending.clear();
			this.child = undefined;
			this.started = false;
			this.buffer = '';
			this.state = expected ? 'stopped' : 'crashed';
			this.emit('state', this.state);
			this.emit('exit', { code, signal });
			if (!expected) {
				this.scheduleRestart();
			}
		});
		try {
			const response = await this.handshake();
			if (response.status !== 'compatible') {
				throw Object.assign(new Error(response.reason ?? 'Core handshake failed.'), { code: 'CORE_HANDSHAKE_FAILED' });
			}
			await this.request('core.health');
			this.state = 'ready';
			this.restartAttempts = 0;
			this.emit('state', this.state);
			return response;
		} catch (error) {
			this.state = 'unhealthy';
			this.emit('state', this.state);
			try { this.child?.kill(); } catch { /* best effort */ }
			throw error;
		}
	}

	async stop(): Promise<void> {
		if (!this.child) {
			return;
		}
		this.expectedShutdown = true;
		if (this.restartTimer) {
			clearTimeout(this.restartTimer);
			this.restartTimer = undefined;
		}
		try {
			await this.request('core.shutdown', {});
		} catch {
			// best effort
		}
		this.child.kill();
		this.child = undefined;
		this.started = false;
		this.state = 'stopped';
		this.emit('state', this.state);
	}

	async request<T = unknown>(method: string, params?: unknown, timeoutMs = this.options.timeoutMs ?? 120_000, requestId = createId()): Promise<T> {
		await this.ensureStarted();
		const id = requestId;
		const message: CoreRequestMessage = { id, type: 'request', method, params };
		const payload = `${JSON.stringify(message)}\n`;
		return await new Promise<T>((resolve, reject) => {
			const timeout = timeoutMs ? setTimeout(() => {
				this.pending.delete(id);
				if (method !== 'core.cancel' && method !== 'core.shutdown') {
					this.sendCancellation(id);
				}
				const error = Object.assign(new Error(`Core request timed out after ${timeoutMs}ms: ${method}`), { code: 'CORE_REQUEST_TIMEOUT' });
				reject(error);
			}, timeoutMs) : undefined;
			this.pending.set(id, {
				resolve: (value) => {
					if (timeout) {
						clearTimeout(timeout);
					}
					resolve(value as T);
				},
				reject: (error) => {
					if (timeout) {
						clearTimeout(timeout);
					}
					reject(error);
				},
			});
			try {
				this.child?.stdin.write(payload);
			} catch (error) {
				this.pending.delete(id);
				reject(Object.assign(new Error('Core process is unavailable.'), { code: 'CORE_PROCESS_CRASHED', cause: error }));
			}
		});
	}

	private sendCancellation(requestId: string): void {
		if (!this.child || !this.started) {
			return;
		}
		const message: CoreRequestMessage = {
			id: `cancel-${requestId}-${Date.now().toString(36)}`,
			type: 'request',
			method: 'core.cancel',
			params: { requestId },
		};
		try {
			this.child.stdin.write(`${JSON.stringify(message)}\n`);
		} catch {
			// The exit handler will reject the original request if the process is gone.
		}
	}

	async cancel(requestId: string): Promise<{ cancelled: boolean; requestId?: string }> {
		return await this.request<{ cancelled: boolean; requestId?: string }>('core.cancel', { requestId });
	}

	onCoreEvent(listener: (event: CoreProcessEvent) => void): void {
		this.on('core-event', listener);
	}

	private async handshake(): Promise<CoreHandshakeResponse> {
		return await this.request<CoreHandshakeResponse>('core.handshake', {
			extensionVersion: this.options.extensionVersion,
			protocolVersion: this.protocolVersion,
			platform: process.platform,
			architecture: process.arch,
		} satisfies CoreHandshakeRequest);
	}

	private async ensureStarted(): Promise<void> {
		if (!this.started || !this.child) {
			await this.start();
		}
	}

	private scheduleRestart(): void {
		if (!this.options.restartOnCrash || this.expectedShutdown || this.restartTimer || this.restartAttempts >= 3) {
			if (this.restartAttempts >= 3) {
				this.state = 'unhealthy';
				this.emit('state', this.state);
				this.emit('restart-failed', new Error('Core restart limit reached.'));
			}
			return;
		}
		this.restartAttempts += 1;
		const delay = Math.min(10_000, 250 * (2 ** (this.restartAttempts - 1)));
		this.state = 'restarting';
		this.emit('state', this.state);
		this.restartTimer = setTimeout(() => {
			this.restartTimer = undefined;
			void this.start().catch((error) => this.emit('restart-failed', error));
		}, delay);
	}

	private handleStdout(chunk: string): void {
		this.buffer += chunk;
		const lines = this.buffer.split(/\r?\n/);
		this.buffer = lines.pop() ?? '';
		for (const line of lines) {
			if (!line.trim()) {
				continue;
			}
			this.handleMessage(line);
		}
	}

	private handleMessage(raw: string): void {
		let parsed: CoreMessage;
		try {
			parsed = JSON.parse(raw) as CoreMessage;
		} catch (error) {
			this.emit('log', `Malformed message from core: ${raw}`);
			return;
		}
		if (parsed.type === 'event') {
			this.emit('core-event', { event: parsed.event, requestId: parsed.requestId, payload: parsed.payload } satisfies CoreProcessEvent);
			return;
		}
		if (parsed.type === 'response') {
			const pending = this.pending.get(parsed.id);
			if (!pending) {
				return;
			}
			this.pending.delete(parsed.id);
			if (parsed.success) {
				pending.resolve(parsed.result);
			} else {
				const error = new Error(parsed.error?.message ?? 'Core request failed.');
				(error as Error & { code?: string; details?: unknown }).code = parsed.error?.code;
				(error as Error & { code?: string; details?: unknown }).details = parsed.error?.details;
				pending.reject(error);
			}
		}
	}
}

interface PendingRequest {
	resolve(value: unknown): void;
	reject(error: unknown): void;
}

function createId(): string {
	return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
