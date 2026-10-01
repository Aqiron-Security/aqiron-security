import { strict as assert } from 'assert';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { CoreScanService } from '../../packages/core/src/orchestration';
import { CoreScanRequest } from '../../packages/core/src/orchestration/types';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { CoreEventMessage, CoreResponseMessage } from '../../packages/core/src/runtime/protocol';
import { createCancellationSource } from '../../packages/core/src/shared/cancellation';
import { PipelineEvent, PipelineEventBus } from '../../packages/core/src/shared/pipeline';
import { ScannerManager } from '../../packages/core/src/scanners';

suite('Core scan identity', () => {
	test('keeps scan.start response identity and event request correlation intact', async () => {
		const workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-scan-identity-'));
		try {
			const emitted: CoreEventMessage[] = [];
			const response = await new CoreRuntime({ coreVersion: 'test' }).handle({
				type: 'request',
				id: 'ipc-request-1',
				method: 'scan.start',
				params: { workspaceRoot, trusted: true, mode: 'quick', requestId: 'scan-canonical-1' },
			}, event => emitted.push(event)) as CoreResponseMessage;
			assert.equal(response.id, 'ipc-request-1');
			assert.equal(response.success, true);
			if (!response.success) { return; }
			assert.ok(response.result && typeof response.result === 'object' && 'scanId' in response.result);
			assert.equal((response.result as { scanId: string }).scanId, 'scan-canonical-1');
			assert.ok(emitted.length > 0);
			for (const event of emitted) {
				assert.equal(event.requestId, 'scan-canonical-1');
				if (event.payload && typeof event.payload === 'object' && 'scanId' in event.payload) {
					assert.equal(event.payload.scanId, 'scan-canonical-1');
				}
			}
		} finally {
			await fs.rm(workspaceRoot, { recursive: true, force: true });
		}
	});

	test('uses one supplied ID for scanner callbacks, AI callbacks, report metadata, telemetry, and result', async () => {
		const { request, events, reportContexts } = createRequest('scan-deterministic', {
			aiAnalysis: {
				async analyze(_root, _findings, emitter) {
					emitter?.emit({ type: 'ai.analysis.completed', scanId: 'callback-manufactured-id', findingsCount: 0, durationMs: 1 });
					return { findings: [], summary: '', retrievalCount: 0, filesAnalyzed: 0, durationMs: 1 };
				},
			},
		});

		const result = await new CoreScanService().run(request);
		const identities = events.flatMap(event => {
			if ('scanId' in event) { return [event.scanId]; }
			if ('scan' in event) { return [event.scan.scanId]; }
			return [];
		});
		assert.ok(events.some(event => event.type === 'scanner.started'));
		assert.ok(events.some(event => event.type === 'scanner.output'));
		assert.ok(events.some(event => event.type === 'scanner.completed'));
		assert.ok(events.some(event => event.type === 'ai.analysis.completed'));
		assert.ok(identities.length > 0);
		assert.deepEqual(new Set(identities), new Set(['scan-deterministic']));
		assert.equal(result.scanId, 'scan-deterministic');
		assert.equal(result.telemetry.scanId, 'scan-deterministic');
		assert.equal(reportContexts[0]?.scanId, 'scan-deterministic');
	});

	test('preserves the canonical ID in cancellation state events', async () => {
		const source = createCancellationSource();
		const { request, events } = createRequest('scan-cancelled', {
			cancellationToken: source.token,
			nativeScanner: { async scanWorkspace() { source.cancel(); return { findings: [], filesScanned: 0, durationMs: 0 }; } },
		});
		await assert.rejects(new CoreScanService().run(request), /cancelled/i);
		const cancelled = events.find(event => event.type === 'scan.cancelled');
		assert.ok(cancelled && 'scan' in cancelled);
		assert.equal(cancelled.scan.scanId, 'scan-cancelled');
	});

	test('keeps concurrent scans isolated by their supplied IDs', async () => {
		const left = createRequest('scan-left');
		const right = createRequest('scan-right');
		const service = new CoreScanService();
		const [leftResult, rightResult] = await Promise.all([service.run(left.request), service.run(right.request)]);
		for (const [id, events, result] of [
			['scan-left', left.events, leftResult],
			['scan-right', right.events, rightResult],
		] as const) {
			assert.equal(result.scanId, id);
			for (const event of events) {
				if ('scanId' in event) { assert.equal(event.scanId, id); }
				if ('scan' in event) { assert.equal(event.scan.scanId, id); }
			}
		}
	});
});

function createRequest(scanId: string, overrides: Partial<CoreScanRequest> = {}) {
	const events: PipelineEvent[] = [];
	const eventBus = new PipelineEventBus();
	eventBus.on(event => events.push(event));
	const reportContexts: Array<{ scanId?: string }> = [];
	const scannerManager = new ScannerManager();
	scannerManager.register({
		id: 'identity-test',
		name: 'Identity test scanner',
		capabilities: ['source-code'],
		async isAvailable() { return { available: true }; },
		async scan() { return { toolId: 'identity-test', label: 'Identity test scanner', findings: [], durationMs: 1 }; },
	});
	const request: CoreScanRequest = {
		scanId,
		workspaceRoot: '/workspace',
		mode: 'quick',
		emitter: eventBus,
		scannerContext: { workspaceRoot: '/workspace', targetPath: '/workspace', mode: 'quick' } as CoreScanRequest['scannerContext'],
		scannerManager,
		reportGenerator: {
			async generate(_root, _findings, _correlation, _graph, _telemetry, context) {
				reportContexts.push(context ?? {});
				return { model: {} } as never;
			},
		},
		...overrides,
	};
	return { request, events, reportContexts };
}
