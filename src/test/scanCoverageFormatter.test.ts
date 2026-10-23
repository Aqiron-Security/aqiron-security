import * as assert from 'assert';
import { formatAgentScanCoverage, normalizeScanCoverage } from '../shared/scanCoverage';

suite('Shared agent scan-coverage formatter', () => {
	test('normalization distinguishes clean, partial, unavailable, conflict, and saturated counts', () => {
		const clean = normalizeScanCoverage(0, {});
		assert.deepEqual([clean.coverageStatus, clean.coverageDiagnosticsPresent, clean.coverageDiagnosticsValid, clean.skippedFilesCountCertainty], ['complete', true, true, 'exact']);
		const invalidatedClean = normalizeScanCoverage(-1, {}, undefined, clean);
		assert.deepEqual([invalidatedClean.coverageStatus, invalidatedClean.coverageDiagnosticsValid, invalidatedClean.coverageDiagnosticsAvailable], ['unavailable', false, false]);

		const explicit = normalizeScanCoverage(2, { 'line-limit': 2 });
		assert.deepEqual([explicit.coverageStatus, explicit.skippedFiles, explicit.skippedFilesCountCertainty], ['partial', 2, 'exact']);
		assert.deepEqual([normalizeScanCoverage(undefined, { 'line-limit': 2 }).skippedFiles, normalizeScanCoverage(0, { 'line-limit': 2 }).coverageStatus], [2, 'partial']);

		const unavailable = normalizeScanCoverage(undefined, undefined);
		assert.deepEqual([unavailable.coverageStatus, unavailable.coverageDiagnosticsPresent, unavailable.skippedFilesCountCertainty], ['unavailable', false, 'indeterminate']);
		assert.equal(normalizeScanCoverage(-1, {}).coverageStatus, 'unavailable');

		for (const [explicitTotal, reasons, lower] of [
			[1, { first: 2, second: 3 }, 5],
			[8, { first: 2 }, 8],
		] as const) {
			const conflict = normalizeScanCoverage(explicitTotal, reasons);
			assert.equal(conflict.skippedFiles, lower);
			assert.equal(conflict.coverageStatus, 'partial');
			assert.equal(conflict.skipCountConflict, true);
			assert.equal(conflict.skippedFilesCountCertainty, 'lower-bound');
		}

		const equal = normalizeScanCoverage(5, { first: 2, second: 3 });
		assert.deepEqual([equal.skipCountConflict, equal.skippedFilesCountCertainty], [false, 'exact']);
		const overflow = normalizeScanCoverage(undefined, { first: Number.MAX_SAFE_INTEGER, second: 1 });
		assert.deepEqual([overflow.skippedFiles, overflow.skippedFilesIsLowerBound, overflow.coverageStatus], [Number.MAX_SAFE_INTEGER, true, 'partial']);
		assert.equal(overflow.coverageDiagnosticsValid, true, 'valid individual values remain valid even when their sum saturates');
		const malformed = normalizeScanCoverage(Number.NaN, { first: Number.MAX_SAFE_INTEGER + 1, '<script>': 2 });
		assert.deepEqual([malformed.coverageStatus, malformed.coverageDiagnosticsValid], ['unavailable', false]);
		for (const invalidCount of [-1, 1.5, Number.POSITIVE_INFINITY, Number.MAX_VALUE]) {
			assert.equal(normalizeScanCoverage(invalidCount, undefined).coverageStatus, 'unavailable');
			assert.equal(normalizeScanCoverage(undefined, { invalid: invalidCount }).coverageStatus, 'unavailable');
		}
		const invalidExplicitWithReason = normalizeScanCoverage(-1, { 'line-limit': 2 });
		assert.deepEqual([invalidExplicitWithReason.coverageStatus, invalidExplicitWithReason.skippedFilesCountCertainty], ['partial', 'lower-bound']);
	});

	test('secret and workspace completion paths share complete, partial, and unavailable wording', () => {
		const complete = formatAgentScanCoverage(normalizeScanCoverage(0, {}));
		assert.equal(`Secret scan ${complete.completion}. I scanned 2 files.${complete.note}`, 'Secret scan complete. I scanned 2 files.');
		assert.equal(`Workspace scan ${complete.completion}. Scanned 2 files.${complete.note}`, 'Workspace scan complete. Scanned 2 files.');

		const partial = formatAgentScanCoverage(normalizeScanCoverage(undefined, { 'line-limit': 2 }));
		assert.equal(partial.completion, 'finished with incomplete coverage');
		assert.match(partial.note, /2 files were skipped/);
		assert.match(partial.note, /line-limit 2/);

		const unavailable = formatAgentScanCoverage(normalizeScanCoverage(undefined, undefined));
		assert.equal(unavailable.completion, 'completed, but coverage diagnostics are unavailable');
		assert.match(unavailable.note, /Full coverage could not be confirmed/);
	});

	test('conflicts, overflow, malformed counts, and unsafe labels never produce an exact total', () => {
		const conflict = formatAgentScanCoverage(normalizeScanCoverage(1, { first: 2, second: 3 }));
		assert.match(conflict.note, /at least 5 files were skipped/);
		assert.match(conflict.note, /explicit skipped-file total conflicts/);
		const reverseConflict = formatAgentScanCoverage(normalizeScanCoverage(8, { first: 2 }));
		assert.match(reverseConflict.note, /at least 8 files were skipped/);

		const overflow = formatAgentScanCoverage(normalizeScanCoverage(undefined, { first: Number.MAX_SAFE_INTEGER, second: 1 }));
		assert.match(overflow.note, new RegExp(`at least ${Number.MAX_SAFE_INTEGER} files were skipped`));

		const malformed = formatAgentScanCoverage(normalizeScanCoverage(Number.NaN, { 'bad\u001b[31m': 1, '<img onerror=alert(1)>': 4, 'line-limit': -2 }));
		assert.equal(malformed.completion, 'completed, but coverage diagnostics are unavailable');
		assert.doesNotMatch(`${malformed.completion}${malformed.note}`, /\u001b|<img|onerror/);
	});
});
