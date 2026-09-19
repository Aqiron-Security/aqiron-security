import { UnifiedFinding } from '../shared/finding';
import { TelemetryEngine } from '../telemetry';
import { ThreatCorrelationEngine } from '../correlation';
import { RelationshipGraphEngine } from '../correlation';
import { WorkerQueue } from '../pipeline/workerQueue';
import { PipelineEmitter } from '../shared/pipeline';
import { createScanState, markCompleted, markReportState, updateFindingState } from '../pipeline/scanState';
import { CoreScanRequest, CoreScanResult } from './types';

export class CoreScanService {
	private readonly queue = new WorkerQueue(3);
	private readonly correlation = new ThreatCorrelationEngine();
	private readonly graphEngine = new RelationshipGraphEngine();

	async run(request: CoreScanRequest): Promise<CoreScanResult> {
		const startedAt = Date.now();
		const scanId = `scan-${startedAt}`;
		const telemetry = new TelemetryEngine(scanId);
		const scanState = createScanState({
			scanId,
			workspaceRoot: request.workspaceRoot,
			targetPath: request.targetPath ?? request.workspaceRoot,
			mode: request.mode ?? 'deep',
		});
		const emit = (event: Parameters<PipelineEmitter['emit']>[0]) => {
			request.emitter.emit(event);
			telemetry.record(event as Parameters<TelemetryEngine['record']>[0]);
		};
		try {
			throwIfCancelled(request.cancellationToken);
			emit({ type: 'scan.started', scan: scanState });
			emit({ type: 'stage', stage: { name: 'Preparing', status: 'running', progress: 10, startedAt: new Date().toISOString() } });

			const native = request.nativeScanner
				? await request.nativeScanner.scanWorkspace(request.workspaceRoot, request.cancellationToken)
				: { findings: [], filesScanned: 0, durationMs: 0 };
			const nativeFindings = native.findings ?? [];
			throwIfCancelled(request.cancellationToken);
			for (const finding of nativeFindings) {
				emit({ type: 'finding', finding });
			}
			let state = updateFindingState(scanState, nativeFindings.length, aggregateRisk(nativeFindings));
			emit({ type: 'findings.updated', scanId, findingsCount: state.findingsCount, riskScore: state.riskScore, timestamps: [state.updatedAt] });
			emit({ type: 'stage', stage: { name: 'Indexing', status: 'completed', progress: 100, startedAt: new Date().toISOString() } });
			emit({ type: 'stage', stage: { name: 'Scanner Execution', status: 'running', progress: 20, startedAt: new Date().toISOString() } });

			const scannerContext = request.scannerContext;
			const scannerResults = await this.runScanners(request, scannerContext);
			throwIfCancelled(request.cancellationToken);
			emit({ type: 'stage', stage: { name: 'Scanner Execution', status: 'completed', progress: 100, startedAt: new Date().toISOString() } });
			const scannerFindings = scannerResults.flatMap((result) => result.findings);
			state = updateFindingState(state, nativeFindings.length + scannerFindings.length, aggregateRisk([...nativeFindings, ...scannerFindings]));
			emit({ type: 'findings.updated', scanId, findingsCount: state.findingsCount, riskScore: state.riskScore, timestamps: [state.updatedAt] });

			const baselineFindings = [...nativeFindings, ...scannerFindings];
			const aiFindings = await this.runAiAnalysis(request, baselineFindings);
			throwIfCancelled(request.cancellationToken);
			const allFindings = [...baselineFindings, ...aiFindings];
			state = updateFindingState(state, allFindings.length, aggregateRisk(allFindings));
			emit({ type: 'findings.updated', scanId, findingsCount: state.findingsCount, riskScore: state.riskScore, timestamps: [state.updatedAt] });

			const correlation = this.correlation.correlate(allFindings);
			throwIfCancelled(request.cancellationToken);
			const graph = this.graphEngine.build(correlation.findings, correlation.relationships);
			emit({ type: 'correlation.completed', scanId, findingsCount: correlation.findings.length, relationships: correlation.relationships.length, duplicates: correlation.summary.deduplicated });
			emit({ type: 'stage', stage: { name: 'AI Correlation', status: 'completed', progress: 100, startedAt: new Date().toISOString() } });

			emit({ type: 'report.started', scanId });
			state = markReportState(state, 'running');
			const report = await request.reportGenerator.generate(request.workspaceRoot, correlation.findings, correlation, graph, telemetry.getSnapshot());
			throwIfCancelled(request.cancellationToken);
			state = markReportState(state, 'completed');
			emit({ type: 'report.completed', scanId });

			const completed = markCompleted(state);
			emit({ type: 'scan.completed', scan: completed });
			emit({ type: 'complete', durationMs: Date.now() - startedAt, findingsCount: correlation.findings.length });

			return {
				workspaceRoot: request.workspaceRoot,
				targetPath: request.targetPath ?? request.workspaceRoot,
				filesScanned: native.filesScanned || scannerResults.reduce((total, result) => total + (result.filesScanned ?? 0), 0),
				durationMs: Date.now() - startedAt,
				findings: correlation.findings,
				toolResults: [
					{ toolId: 'Aqiron', label: 'Aqiron', findings: nativeFindings, durationMs: native.durationMs },
					...scannerResults,
					{ toolId: 'ai-analysis', label: 'AI Vulnerability Analysis', findings: aiFindings, durationMs: 0 },
				],
				correlation,
				graph,
				telemetry: telemetry.getSnapshot(),
				report,
			};
		} catch (error) {
			const reason = error instanceof Error ? error.message : String(error);
			if (request.cancellationToken?.isCancellationRequested) {
				const cancelled = { ...scanState, cancelled: true, finalState: 'cancelled' as const, updatedAt: new Date().toISOString(), completedAt: new Date().toISOString() };
				emit({ type: 'scan.cancelled', scan: cancelled, reason: 'Scan cancelled by the client.' });
				throw new Error('Core request cancelled.');
			}
			emit({ type: 'scan.failed', scan: markCompleted(scanState, 'failed'), message: reason });
			emit({ type: 'error', message: reason });
			throw error;
		}
	}

	private async runScanners(request: CoreScanRequest, scannerContext: CoreScanRequest['scannerContext']): Promise<import('../scanners').ScannerResult[]> {
		const selection = { mode: request.mode ?? 'deep' };
		const results = await this.queue.run(() => request.scannerManager.run(scannerContext, selection, (event) => {
			switch (event.type) {
				case 'start':
					request.emitter.emit({ type: 'scanner.started', scanId: `scan-${Date.now()}`, scanner: { id: event.scannerId, label: event.scannerId, command: event.scannerId, status: 'running', startedAt: event.timestamp } });
					request.emitter.emit({ type: 'tool', tool: { id: event.scannerId, label: event.scannerId, command: event.scannerId, status: 'running', startedAt: event.timestamp } });
					break;
				case 'log':
					request.emitter.emit({ type: 'scanner.output', scanId: `scan-${Date.now()}`, scannerId: event.scannerId, message: event.message ?? '', timestamp: event.timestamp });
					request.emitter.emit({ type: 'log', tool: event.scannerId, message: event.message ?? '', timestamp: event.timestamp });
					break;
				case 'finding':
					request.emitter.emit({ type: 'finding', finding: event.finding! });
					break;
				case 'complete':
					request.emitter.emit({ type: 'scanner.completed', scanId: `scan-${Date.now()}`, scanner: { id: event.scannerId, label: event.scannerId, command: event.scannerId, status: 'completed', completedAt: event.timestamp, durationMs: event.result?.durationMs, findingsCount: event.result?.findings.length } });
					request.emitter.emit({ type: 'tool', tool: { id: event.scannerId, label: event.scannerId, command: event.scannerId, status: 'completed', completedAt: event.timestamp, durationMs: event.result?.durationMs, findingsCount: event.result?.findings.length } });
					break;
				case 'unavailable':
					request.emitter.emit({ type: 'tool', tool: { id: event.scannerId, label: event.scannerId, command: event.scannerId, status: 'unavailable', completedAt: event.timestamp, message: event.message } });
					break;
				case 'error':
					request.emitter.emit({ type: 'tool', tool: { id: event.scannerId, label: event.scannerId, command: event.scannerId, status: 'failed', completedAt: event.timestamp, message: event.message } });
					break;
			}
		}));
		return results.results;
	}

	private async runAiAnalysis(request: CoreScanRequest, baselineFindings: readonly UnifiedFinding[]): Promise<UnifiedFinding[]> {
		if (!request.aiAnalysis) {
			return [];
		}
			request.emitter.emit({ type: 'ai.analysis.started', scanId: `scan-${Date.now()}`, workspaceRoot: request.workspaceRoot });
		const result = await request.aiAnalysis.analyze(request.workspaceRoot, baselineFindings, request.emitter, request.cancellationToken);
			for (const finding of result.findings) {
				request.emitter.emit({ type: 'finding', finding });
			}
			request.emitter.emit({ type: 'ai.analysis.completed', scanId: `scan-${Date.now()}`, findingsCount: result.findings.length, durationMs: result.durationMs });
			return result.findings;
		}
	}

function aggregateRisk(findings: readonly UnifiedFinding[]): number {
	if (findings.length === 0) {
		return 0;
	}
	const total = findings.reduce((sum, finding) => sum + finding.riskScore, 0);
	return Math.round(total / findings.length);
}

function throwIfCancelled(token: CoreScanRequest['cancellationToken']): void {
	if (token?.isCancellationRequested) {
		throw new Error('Core request cancelled.');
	}
}
