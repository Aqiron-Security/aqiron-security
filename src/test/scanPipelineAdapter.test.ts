import * as assert from 'assert';
import { PipelineEvent, PipelineEventBus } from '../../packages/core/src/shared/pipeline';
import { forwardCoreScanEvent } from '../security/pipeline/pipelineEngine';

suite('Core scan event adapter', () => {
	test('forwards only events correlated to the active scan request', () => {
		const events = new PipelineEventBus();
		const received: PipelineEvent[] = [];
		events.on((event) => received.push(event));
		const payload: PipelineEvent = { type: 'complete', durationMs: 12, findingsCount: 2 };

		forwardCoreScanEvent({ requestId: 'other-scan', payload }, 'active-scan', events);
		assert.deepStrictEqual(received, []);

		forwardCoreScanEvent({ requestId: 'active-scan', payload }, 'active-scan', events);
		assert.deepStrictEqual(received, [payload]);
	});
});
