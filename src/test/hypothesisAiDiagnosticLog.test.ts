import { strict as assert } from 'node:assert';
import { formatHypothesisAiDiagnosticLogLine } from '../core/hypothesisAiDiagnosticLog';

suite('Hypothesis AI diagnostic log filtering', () => {
	test('formats only allowlisted stage fields and distinguishes adapter invocation from remote receipt', () => {
		const line = '[time] [aqiron-core-runtime] WARN hypothesis.ai.execution.diagnostic {"stage":"transport","outcome":"failed","failureCategory":"transport-failed","transportInvoked":true,"transportResponseReceived":false,"providerResponseValidated":false,"persistenceAttempted":false}';
		const summary = formatHypothesisAiDiagnosticLogLine(line);
		assert.match(summary ?? '', /transportAdapterInvoked=true/);
		assert.match(summary ?? '', /transportResponseReceived=false/);
		assert.match(summary ?? '', /does not confirm remote receipt/);
	});

	test('drops malformed diagnostics and never forwards extra secret or exception fields', () => {
		const secretMarker = 'synthetic secret exception detail';
		const value = { stage: 'persistence', outcome: 'failed', failureCategory: 'persistence-failed', transportInvoked: true, transportResponseReceived: true, providerResponseValidated: true, persistenceAttempted: true, error: secretMarker, credential: secretMarker };
		const summary = formatHypothesisAiDiagnosticLogLine(`hypothesis.ai.execution.diagnostic ${JSON.stringify(value)}`) ?? '';
		assert.doesNotMatch(summary, new RegExp(secretMarker));
		assert.equal(formatHypothesisAiDiagnosticLogLine('hypothesis.ai.execution.diagnostic {not-json'), undefined);
		assert.equal(formatHypothesisAiDiagnosticLogLine('unrelated provider log'), undefined);
	});
});
