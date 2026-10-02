import * as fs from 'node:fs';
import * as path from 'node:path';
import { CoreClient } from '../../../src/core/coreClient';
import { CoreScanStartResult } from '../../core/src/runtime/protocol';

export interface CliOutput {
	write(text: string): void;
}

export interface CliCoreClient {
	startScan(request: { requestId: string; workspaceRoot: string; trusted: boolean; mode: 'deep' }): Promise<CoreScanStartResult>;
	stop(): Promise<void>;
	on(event: 'event', listener: (event: { event: string; requestId?: string; payload?: unknown }) => void): this;
	removeListener(event: 'event', listener: (event: { event: string; requestId?: string; payload?: unknown }) => void): this;
}

export interface CliOptions {
	stdout?: CliOutput;
	stderr?: CliOutput;
	createClient?: () => CliCoreClient;
}

export async function runCli(args: readonly string[], options: CliOptions = {}): Promise<number> {
	const stdout = options.stdout ?? process.stdout;
	const stderr = options.stderr ?? process.stderr;
	if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
		stdout.write('Usage: aqiron scan <workspace> --trust-local-workspace\n');
		return 0;
	}
	if (args.length !== 3 || args[0] !== 'scan' || args[2] !== '--trust-local-workspace') {
		stderr.write('Usage: aqiron scan <workspace> --trust-local-workspace\n');
		return 2;
	}

	const workspaceRoot = path.resolve(args[1]);
	try {
		if (!fs.statSync(workspaceRoot).isDirectory()) {
			throw new Error(`Workspace path is not a directory: ${workspaceRoot}`);
		}
	} catch (error) {
		stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
		return 2;
	}

	const client = options.createClient?.() ?? new CoreClient({ extensionVersion: '0.0.1', restartOnCrash: false });
	const requestId = `cli-${process.pid}-${Date.now().toString(36)}`;
	const onEvent = (event: { event: string; requestId?: string; payload?: unknown }) => {
		if (event.requestId === requestId) {
			writeProgress(event, stdout);
		}
	};
	client.on('event', onEvent);
	try {
		stdout.write('Aqiron Security\n');
		stdout.write(`Workspace: ${args[1]}\n\nScanning...\n`);
		const result = await client.startScan({ requestId, workspaceRoot, trusted: true, mode: 'deep' });
		const counts = countSeverities(result);
		stdout.write('\nScan complete\n\n');
		stdout.write(`Findings: ${result.findings.length}\n`);
		stdout.write(`Critical: ${counts.Critical}\n`);
		stdout.write(`High:     ${counts.High}\n`);
		stdout.write(`Medium:   ${counts.Medium}\n`);
		stdout.write(`Low:      ${counts.Low}\n`);
		stdout.write(`Duration: ${formatDuration(result.durationMs ?? 0)}\n`);
		return 0;
	} catch (error) {
		stderr.write(`Scan failed: ${error instanceof Error ? error.message : String(error)}\n`);
		return 1;
	} finally {
		client.removeListener('event', onEvent);
		await client.stop();
	}
}

function writeProgress(event: { event: string; payload?: unknown }, output: CliOutput): void {
	const payload = isRecord(event.payload) ? event.payload : undefined;
	if (!payload) {
		return;
	}
	if (event.event === 'stage' && isRecord(payload.stage)) {
		const stage = payload.stage;
		if (typeof stage.name === 'string' && typeof stage.status === 'string') {
			output.write(`${stage.name}: ${stage.status}${typeof stage.progress === 'number' ? ` (${stage.progress}%)` : ''}\n`);
		}
	} else if (event.event === 'tool' && isRecord(payload.tool) && typeof payload.tool.label === 'string' && typeof payload.tool.status === 'string') {
		output.write(`Scanner: ${payload.tool.label} (${payload.tool.status})\n`);
	} else if (event.event === 'correlation.completed') {
		output.write('Correlation completed\n');
	}
}

function countSeverities(result: CoreScanStartResult): Record<'Critical' | 'High' | 'Medium' | 'Low', number> {
	const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
	for (const finding of result.findings) {
		if (finding.severity in counts) {
			counts[finding.severity as keyof typeof counts] += 1;
		}
	}
	return counts;
}

function formatDuration(durationMs: number): string {
	return `${(durationMs / 1000).toFixed(1)}s`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}
