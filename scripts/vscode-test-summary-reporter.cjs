const fs = require('node:fs');
const path = require('node:path');

module.exports = class VscodeTestSummaryReporter {
	constructor(runner) {
		const result = { tests: 0, passes: 0, failures: 0, pending: 0, failureDetails: [] };
		runner.on('pass', () => {
			result.tests += 1;
			result.passes += 1;
		});
		runner.on('fail', (test, error) => {
			result.tests += 1;
			result.failures += 1;
			if (result.failureDetails.length < 25) {
				result.failureDetails.push({
					title: sanitize(test?.fullTitle?.() ?? test?.title ?? 'Unknown test'),
					error: sanitize(error?.message ?? test?.err?.message ?? 'No error message was provided'),
				});
			}
		});
		runner.on('pending', () => {
			result.tests += 1;
			result.pending += 1;
		});
		runner.once('end', () => {
			const output = process.env.AQIRON_VSCODE_TEST_SUMMARY
				?? path.resolve(process.env.AQIRON_TEST_OUTDIR ?? 'out', 'vscode-test-summary.json');
			fs.mkdirSync(path.dirname(output), { recursive: true });
			fs.writeFileSync(output, `${JSON.stringify(result)}\n`, 'utf8');
		});
	}
};

function sanitize(value) {
	return String(value)
		.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
		.replace(/[\u0000-\u001f\u007f]/g, ' ')
		.replace(/\bBearer\s+\S+/gi, 'Bearer [redacted]')
		.replace(/\b(?:sk[-_][A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|AIza[0-9A-Za-z_-]{12,})\b/g, '[redacted-secret]')
		.replace(/(["']?(?:api[_-]?key|api[_-]?secret|password|passwd|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?token|id[_-]?token|token|auth(?:orization)?|credential(?:s)?|private[_-]?key|signing[_-]?key|subscription[_-]?key)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}&]+)/gi, '$1[redacted]')
		.replace(/(https?:\/\/)[^/@\s]+@/gi, '$1[redacted]@')
		.replace(/([?&](?:token|key|secret|auth|signature|api_key)=)[^&#\s]+/gi, '$1[redacted]')
		.replace(/\b[A-Za-z]:\\Users\\[^\\\s]+/g, '[user-path]')
		.replace(/\/(?:home|Users)\/[^/\s]+/g, '[user-path]')
		.slice(0, 500);
}
