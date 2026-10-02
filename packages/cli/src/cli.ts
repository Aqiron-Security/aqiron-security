import * as fs from 'node:fs';
import * as path from 'node:path';
import { CoreClient } from '../../core/src/client';
import { CoreScanStartResult } from '../../core/src/runtime/protocol';
import { createJsonReport } from '../../core/src/reports/reportExporters';
import { SecurityReportModel } from '../../core/src/reports/reportModels';

export interface CliOutput { write(text: string): void; }
export interface CliEvent { event: string; requestId?: string; payload?: unknown; }
export interface CliCoreClient {
	startScan(request: { requestId: string; workspaceRoot: string; trusted: boolean; mode: 'deep' }): Promise<CoreScanStartResult>;
	start?(): Promise<unknown>;
	cancelRequest?(requestId: string): Promise<unknown>;
	stop(): Promise<void>;
	on(event: 'event', listener: (event: CliEvent) => void): this;
	removeListener(event: 'event', listener: (event: CliEvent) => void): this;
}
export interface CliOptions {
	stdout?: CliOutput;
	stderr?: CliOutput;
	createClient?: () => CliCoreClient;
	registerSignalHandlers?: (handlers: { onInterrupt: () => void; onTerminate: () => void }) => () => void;
}

type Format = 'text' | 'json' | 'sarif';
type Severity = 'critical' | 'high' | 'medium' | 'low';
interface ScanArgs { workspace: string; format: Format; output?: string; failOn?: Severity; }

const usage = 'Usage: aqiron scan <path> --trust-local-workspace [--format text|json|sarif] [--output <path>] [--fail-on critical|high|medium|low]\n';
const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export async function runCli(args: readonly string[], options: CliOptions = {}): Promise<number> {
	const stdout = options.stdout ?? process.stdout;
	const stderr = options.stderr ?? process.stderr;
	if (args.length === 1 && ['--help', '-h'].includes(args[0])) { stdout.write(usage); return 0; }
	let parsed: ScanArgs;
	try { parsed = parseArgs(args); }
	catch (error) { stderr.write(`${safeMessage(error)}\n${usage}`); return 2; }
	const workspaceRoot = path.resolve(parsed.workspace);
	try {
		if (!fs.statSync(workspaceRoot).isDirectory()) { stderr.write('Invalid workspace: path must be a directory.\n'); return 2; }
	} catch { stderr.write('Invalid workspace: directory does not exist or cannot be accessed.\n'); return 2; }

	const client = options.createClient?.() ?? new CoreClient({ clientVersion: '0.0.1', runtimePath: path.join(__dirname, 'core-runtime.js'), restartOnCrash: false });
	const requestId = `cli-${process.pid}-${Date.now().toString(36)}`;
	let cancelled = false;
	const onEvent = (event: CliEvent) => { if (event.requestId === requestId && parsed.format === 'text') { writeProgress(event, stdout); } };
	const unregisterSignals = (options.registerSignalHandlers ?? registerSignalHandlers)({
		onInterrupt: () => { cancelled = true; void client.cancelRequest?.(requestId).catch(() => undefined); },
		onTerminate: () => { cancelled = true; void client.cancelRequest?.(requestId).catch(() => undefined); },
	});
	client.on('event', onEvent);
	let phase: 'startup' | 'scan' = 'startup';
	try {
		if (parsed.format === 'text') {
			stdout.write('Aqiron Security\n');
			stdout.write(`Workspace: ${path.relative(process.cwd(), workspaceRoot) || '.'}\n\nScanning...\n`);
		}
		await client.start?.();
		if (cancelled) { return 1; }
		phase = 'scan';
		const result = await client.startScan({ requestId, workspaceRoot, trusted: true, mode: 'deep' });
		if (cancelled) { stderr.write('Scan cancelled.\n'); return 1; }
		const output = renderResult(parsed.format, result);
		try { writeResult(parsed, output, stdout); }
		catch { stderr.write('Output failed: could not write the requested output file. It may already exist or its directory may be unavailable.\n'); return 1; }
		return parsed.failOn && hasThresholdViolation(result, parsed.failOn) ? 1 : 0;
	} catch (error) {
		if (cancelled || isCancellation(error)) { stderr.write('Scan cancelled.\n'); }
		else if (phase === 'startup') { stderr.write('Core startup failed. Check that the bundled Core runtime is available. Use AQIRON_DEBUG=1 for details.\n'); writeDebug(error, stderr); }
		else { stderr.write('Core scan failed. Use AQIRON_DEBUG=1 for details.\n'); writeDebug(error, stderr); }
		return 1;
	} finally {
		unregisterSignals();
		client.removeListener('event', onEvent);
		try { await client.stop(); } catch { /* process cleanup is best effort after the Core request ends */ }
	}
}

function parseArgs(args: readonly string[]): ScanArgs {
	if (args[0] !== 'scan' || !args[1] || args[1].startsWith('-')) { throw new Error('Invalid command or missing workspace path.'); }
	if (!args.includes('--trust-local-workspace')) { throw new Error('Workspace trust is required. Add --trust-local-workspace to scan this local directory.'); }
	const parsed: ScanArgs = { workspace: args[1], format: 'text' };
	for (let i = 2; i < args.length; i++) {
		const flag = args[i];
		if (flag === '--trust-local-workspace') { continue; }
		if (flag === '--format' || flag === '--output' || flag === '--fail-on') {
			const value = args[++i];
			if (!value || value.startsWith('--')) { throw new Error(`Missing value for ${flag}.`); }
			if (flag === '--format') {
				if (!['text', 'json', 'sarif'].includes(value)) { throw new Error('Invalid format. Choose text, json, or sarif.'); }
				parsed.format = value as Format;
			} else if (flag === '--output') { parsed.output = value; }
			else {
				if (!(value in severityRank)) { throw new Error('Invalid --fail-on severity. Choose critical, high, medium, or low.'); }
				parsed.failOn = value as Severity;
			}
			continue;
		}
		throw new Error('Unknown CLI option.');
	}
	return parsed;
}

function renderResult(format: Format, result: CoreScanStartResult): string {
	if (format === 'sarif') { return `${JSON.stringify(result.report.sarif, null, 2)}\n`; }
	if (format === 'json') {
		return `${JSON.stringify({ schemaVersion: 1, scan: { scanId: result.scanId, mode: result.state.mode, filesScanned: result.filesScanned ?? null, durationMs: result.durationMs ?? null }, report: createJsonReport(result.report.model as SecurityReportModel) }, null, 2)}\n`;
	}
	const counts = countSeverities(result);
	return `\nFindings: ${result.findings.length}\nCritical: ${counts.Critical}\nHigh:     ${counts.High}\nMedium:   ${counts.Medium}\nLow:      ${counts.Low}\nDuration: ${((result.durationMs ?? 0) / 1000).toFixed(1)}s\n`;
}

function writeResult(args: ScanArgs, content: string, stdout: CliOutput): void {
	if (!args.output) { stdout.write(content); return; }
	const file = path.resolve(args.output);
	const descriptor = fs.openSync(file, 'wx');
	try { fs.writeFileSync(descriptor, content, 'utf8'); }
	finally { fs.closeSync(descriptor); }
}

function countSeverities(result: CoreScanStartResult): Record<'Critical' | 'High' | 'Medium' | 'Low', number> {
	const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
	for (const finding of result.findings) { if (finding.severity in counts) { counts[finding.severity as keyof typeof counts] += 1; } }
	return counts;
}

function hasThresholdViolation(result: CoreScanStartResult, threshold: Severity): boolean {
	return result.findings.some((finding) => severityRank[String(finding.severity).toLowerCase() as Severity] >= severityRank[threshold]);
}

function writeProgress(event: CliEvent, output: CliOutput): void {
	const payload = isRecord(event.payload) ? event.payload : undefined;
	const stage = payload && isRecord(payload.stage) ? payload.stage : undefined;
	if (event.event === 'stage' && stage && typeof stage.name === 'string' && typeof stage.status === 'string') { output.write(`${stage.name}: ${stage.status}\n`); }
	else if (event.event === 'tool' && payload && isRecord(payload.tool) && typeof payload.tool.label === 'string' && typeof payload.tool.status === 'string') { output.write(`Scanner: ${payload.tool.label} (${payload.tool.status})\n`); }
}

function registerSignalHandlers(handlers: { onInterrupt: () => void; onTerminate: () => void }): () => void {
	const interrupt = () => handlers.onInterrupt();
	const terminate = () => handlers.onTerminate();
	process.on('SIGINT', interrupt);
	process.on('SIGTERM', terminate);
	return () => { process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', terminate); };
}

function isCancellation(error: unknown): boolean { return /cancel/i.test(error instanceof Error ? `${error.name} ${error.message}` : String(error)); }
function safeMessage(error: unknown): string { return error instanceof Error ? error.message : 'Invalid CLI input.'; }
function writeDebug(error: unknown, output: CliOutput): void {
	if (process.env.AQIRON_DEBUG === '1') {
		const code = isRecord(error) && typeof error.code === 'string' ? error.code : 'unclassified';
		output.write(`Debug: ${code}\n`);
	}
}
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null; }
