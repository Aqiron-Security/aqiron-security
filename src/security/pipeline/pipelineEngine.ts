import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { CancellationTokenLike, PipelineEventBus, findingToIssue, issueToFinding, SecurityReportBundle, SecurityGraph, UnifiedFinding } from '../../../packages/core/src';
import { CoreScanResult } from '../../../packages/core/src/orchestration';
import { getCoreClient } from '../../core/coreClientSingleton';
import { WorkspaceScanner } from '../../scanner/workspaceScanner';
import { ScannerResult } from '../scanners/types';

export interface PipelineScanOptions {
	mode?: 'quick' | 'deep' | 'analysis';
	cancellationToken?: CancellationTokenLike;
}

export interface OrchestratedScanResult {
	workspaceRoot?: string;
	target: string;
	filesScanned: number;
	issues: ReturnType<typeof findingToIssue>[];
	durationMs: number;
	findings: UnifiedFinding[];
	graph: SecurityGraph;
	report?: SecurityReportBundle;
	toolResults: ScannerResult[];
}

export class SecurityPipelineEngine {
	constructor(
		private readonly nativeScanner: WorkspaceScanner,
		private readonly events: PipelineEventBus,
	) {
		void this.nativeScanner;
	}

	async scanWorkspace(workspaceFolder: vscode.WorkspaceFolder, options: PipelineScanOptions = {}): Promise<OrchestratedScanResult> {
		const client = getCoreClient();
		const listener = (event: { event: string; payload?: unknown }) => {
			if (event.payload && typeof event.payload === 'object' && 'type' in event.payload) {
				this.events.emit(event.payload as never);
			}
		};
		client.on('event', listener);
		const requestId = `scan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
		const cancellation = options.cancellationToken?.onCancellationRequested?.(() => {
			void client.cancelRequest(requestId).catch(() => undefined);
		});
		try {
			const result = await client.startScan({
				requestId,
				workspaceRoot: workspaceFolder.uri.fsPath,
				targetPath: workspaceFolder.uri.fsPath,
				mode: options.mode ?? 'deep',
				trusted: true,
				currentFile: workspaceFolder.uri.fsPath,
			});
			const report = await writeReportBundle(workspaceFolder.uri.fsPath, result.report);
			const issues = await findingsToIssues(result.findings);
			return {
				workspaceRoot: result.state.workspaceRoot,
				target: result.state.targetPath,
				filesScanned: result.filesScanned ?? result.state.findingsCount,
				issues,
				durationMs: result.durationMs ?? 0,
				findings: result.findings,
				graph: result.graph ?? { nodes: [], edges: [] },
				report,
				toolResults: result.toolResults ?? [],
			};
		} finally {
			cancellation?.dispose();
			client.removeListener('event', listener);
		}
	}
}

async function writeReportBundle(workspaceRoot: string, report: CoreScanResult['report']): Promise<SecurityReportBundle> {
	const reportDirectory = path.join(workspaceRoot, '.aqiron-security', 'reports');
	await fs.mkdir(reportDirectory, { recursive: true });
	const stamp = new Date().toISOString().replace(/[:.]/g, '-');
	const jsonPath = path.join(reportDirectory, `aqiron-security-${stamp}.json`);
	const sarifPath = path.join(reportDirectory, `aqiron-security-${stamp}.sarif`);
	const pdfPath = path.join(reportDirectory, `aqiron-security-${stamp}.pdf`);
	await fs.writeFile(jsonPath, JSON.stringify(report.model, null, 2), 'utf8');
	await fs.writeFile(sarifPath, JSON.stringify(report.sarif, null, 2), 'utf8');
	await fs.writeFile(pdfPath, report.pdf, 'binary');
	return {
		json: report.model,
		sarif: report.sarif,
		executiveSummary: report.model.executiveSummary,
		exports: { jsonPath, sarifPath, pdfPath },
	};
}

async function findingsToIssues(findings: readonly UnifiedFinding[]): Promise<ReturnType<typeof findingToIssue>[]> {
	return await Promise.all(findings.map(async (finding) => findingToIssue(finding, await readLine(finding.file, finding.line))));
}

async function readLine(file: string, line: number): Promise<string> {
	try {
		const content = await fs.readFile(file, 'utf8');
		return content.split(/\r?\n/)[Math.max(0, line - 1)] ?? '';
	} catch {
		return '';
	}
}
