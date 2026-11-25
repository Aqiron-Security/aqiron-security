const DIAGNOSTIC_MARKER = 'hypothesis.ai.execution.diagnostic ';
const STAGES = ['executor-preflight', 'request-construction', 'transport', 'response-validation', 'persistence', 'complete', 'unknown'] as const;
const CATEGORIES = ['executor-preflight-failed', 'request-construction-failed', 'transport-failed', 'response-validation-failed', 'persistence-failed', 'unexpected-executor-failure'] as const;

/** Returns only a fixed, allowlisted summary of Core's local hypothesis execution diagnostic. */
export function formatHypothesisAiDiagnosticLogLine(line: string): string | undefined {
	const markerIndex = line.indexOf(DIAGNOSTIC_MARKER);
	if (markerIndex < 0) {return undefined;}
	let value: unknown;
	try {value = JSON.parse(line.slice(markerIndex + DIAGNOSTIC_MARKER.length));} catch {return undefined;}
	if (!value || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
	const diagnostic = value as Record<string, unknown>;
	if (!STAGES.includes(diagnostic.stage as typeof STAGES[number]) || (diagnostic.outcome !== 'failed' && diagnostic.outcome !== 'succeeded')
		|| typeof diagnostic.transportInvoked !== 'boolean' || typeof diagnostic.transportResponseReceived !== 'boolean'
		|| typeof diagnostic.providerResponseValidated !== 'boolean' || typeof diagnostic.persistenceAttempted !== 'boolean'
		|| (diagnostic.failureCategory !== undefined && !CATEGORIES.includes(diagnostic.failureCategory as typeof CATEGORIES[number]))) {return undefined;}
	const category = typeof diagnostic.failureCategory === 'string' ? diagnostic.failureCategory : 'none';
	return `Hypothesis AI execution: stage=${diagnostic.stage}; outcome=${diagnostic.outcome}; category=${category}; transportAdapterInvoked=${diagnostic.transportInvoked}; transportResponseReceived=${diagnostic.transportResponseReceived}; providerResponseValidated=${diagnostic.providerResponseValidated}; persistenceAttempted=${diagnostic.persistenceAttempted}. Adapter invocation does not confirm remote receipt.`;
}
