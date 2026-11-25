import * as assert from 'assert';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { formatSkippedFileCount, formatWorkspaceScanCompletion, normalizeScanCoverage, scanCoverageLabel, statsForHistoricalSnapshot, statsWithoutSelectedSnapshot } from '../shared/scanCoverage';
import { ScanTab } from '../webview/ui/tabs';
import { WebviewState } from '../webview/ui/types';

suite('Scan coverage diagnostic presentation', () => {
	test('completion messages reconcile skipped count and reason counts conservatively', () => {
		const counted = normalizeScanCoverage(2, { 'line-limit': 2 });
		assert.match(formatWorkspaceScanCompletion(1, 0, counted), /finished with incomplete coverage/);
		assert.equal(counted.coverageStatus, 'partial');
		assert.equal(counted.coverageDiagnosticsPresent, true);
		assert.equal(counted.coverageDiagnosticsValid, true);
		assert.equal(counted.skippedFilesCountCertainty, 'exact');

		const reasonsOnly = normalizeScanCoverage(undefined, { 'size-limit': 1 });
		assert.equal(reasonsOnly.skippedFiles, 1);
		assert.match(formatWorkspaceScanCompletion(0, 0, reasonsOnly), /1 file skipped/);

		const countConflict = normalizeScanCoverage(0, { 'line-limit': 2 });
		assert.equal(countConflict.skippedFiles, 2);
		assert.equal(countConflict.skipCountConflict, true);
		assert.equal(countConflict.skippedFilesIsLowerBound, true);
		assert.equal(countConflict.skippedFilesCountCertainty, 'lower-bound');
		assert.match(formatWorkspaceScanCompletion(0, 0, countConflict), /finished with incomplete coverage/);
		assert.match(formatWorkspaceScanCompletion(0, 0, countConflict), /at least 2 files skipped/);
		assert.match(formatWorkspaceScanCompletion(0, 0, countConflict), /conflicts/);
	});

	test('clean diagnostics preserve the completion message and missing legacy fields remain safe but unknown', () => {
		const clean = normalizeScanCoverage(0, {});
		assert.equal(formatWorkspaceScanCompletion(1, 0, clean), 'Aqiron Security scan completed: 1 actionable issue found.');
		assert.equal(scanCoverageLabel('Complete', clean), 'Complete');
		assert.equal(clean.coverageStatus, 'complete');
		assert.equal(clean.coverageDiagnosticsValid, true);

		const legacy = normalizeScanCoverage(undefined, undefined);
		assert.equal(legacy.coverageDiagnosticsAvailable, false);
		assert.equal(legacy.coverageStatus, 'unavailable');
		assert.equal(legacy.coverageDiagnosticsPresent, false);
		assert.equal(legacy.skippedFilesCountCertainty, 'indeterminate');
		assert.equal(formatWorkspaceScanCompletion(0, 0, legacy), 'Aqiron Security scan completed, but coverage diagnostics are unavailable: 0 actionable issues found. Full coverage could not be confirmed.');
	});

	test('malformed and unsafe reason labels cannot crash or enter the completion message', () => {
		const malformed = normalizeScanCoverage(-1, { '<img onerror=alert(1)>': 9, 'bad\u001b[31m': 2, 'line-limit': Number.MAX_VALUE, 'size-limit': 1 });
		const message = formatWorkspaceScanCompletion(0, 0, malformed);
		assert.match(message, /Coverage is incomplete/);
		assert.match(message, /size-limit 1/);
		assert.doesNotMatch(message, /<img|onerror|\u001b|line-limit/);
	});

	test('reason aggregation stays exact within the safe range and marks overflow as a lower bound', () => {
		const safeTotal = normalizeScanCoverage(undefined, { first: Number.MAX_SAFE_INTEGER - 2, second: 1 });
		assert.equal(safeTotal.skippedFiles, Number.MAX_SAFE_INTEGER - 1);
		assert.equal(safeTotal.skippedFilesIsLowerBound, false);
		assert.equal(formatSkippedFileCount(safeTotal), String(Number.MAX_SAFE_INTEGER - 1));

		const overflow = normalizeScanCoverage(undefined, { first: Number.MAX_SAFE_INTEGER, second: 1 });
		assert.equal(overflow.skippedFiles, Number.MAX_SAFE_INTEGER);
		assert.equal(overflow.skippedFilesIsLowerBound, true);
		assert.match(formatWorkspaceScanCompletion(0, 0, overflow), new RegExp(`at least ${Number.MAX_SAFE_INTEGER} files skipped`));
		assert.equal(scanCoverageLabel('Complete', overflow), 'Partial coverage');

		const explicitLargeTotal = normalizeScanCoverage(Number.MAX_SAFE_INTEGER, undefined);
		assert.equal(explicitLargeTotal.skippedFilesIsLowerBound, false);
		assert.equal(formatSkippedFileCount(explicitLargeTotal), String(Number.MAX_SAFE_INTEGER));

		const equalTotals = normalizeScanCoverage(5, { one: 2, two: 3 });
		assert.equal(equalTotals.skippedFiles, 5);
		assert.equal(equalTotals.skipCountConflict, false);
		assert.equal(equalTotals.skippedFilesIsLowerBound, false);

		const reasonsExceedExplicit = normalizeScanCoverage(1, { one: 2, two: 3 });
		assert.equal(reasonsExceedExplicit.skippedFiles, 5);
		assert.equal(reasonsExceedExplicit.skippedFilesCountCertainty, 'lower-bound');
		assert.match(formatWorkspaceScanCompletion(0, 0, reasonsExceedExplicit), /at least 5 files skipped/);
		assert.equal(scanCoverageLabel('Complete', reasonsExceedExplicit), 'Partial coverage');

		const explicitExceedsReasons = normalizeScanCoverage(8, { one: 2 });
		assert.equal(explicitExceedsReasons.skippedFiles, 8);
		assert.equal(explicitExceedsReasons.skipCountConflict, true);
		assert.equal(explicitExceedsReasons.skippedFilesCountCertainty, 'lower-bound');
		assert.match(formatWorkspaceScanCompletion(0, 0, explicitExceedsReasons), /at least 8 files skipped/);

		const invalidReasonWithExplicit = normalizeScanCoverage(4, { one: 1, invalid: -1 });
		assert.equal(invalidReasonWithExplicit.coverageStatus, 'partial');
		assert.equal(invalidReasonWithExplicit.coverageDiagnosticsValid, false);
		assert.equal(invalidReasonWithExplicit.skippedFilesCountCertainty, 'lower-bound');
	});

	test('reason display stays bounded while aggregation includes later valid categories', () => {
		const reasons = Object.fromEntries(Array.from({ length: 21 }, (_, index) => [`reason${index}`, 1]));
		const normalized = normalizeScanCoverage(undefined, reasons);
		assert.equal(normalized.skippedFiles, 21);
		assert.equal(normalized.skippedFilesIsLowerBound, false);
		assert.equal(Object.keys(normalized.skipReasons).length, 20);
		assert.equal(scanCoverageLabel('Complete', normalized), 'Partial coverage');
		const roundTripped = normalizeScanCoverage(normalized.skippedFiles, normalized.skipReasons, normalized.skippedFilesIsLowerBound, normalized);
		assert.equal(roundTripped.skippedFiles, 21);
		assert.equal(roundTripped.skipReasonsTruncated, true);
		assert.equal(roundTripped.skipCountConflict, false);
		assert.equal(roundTripped.skippedFilesCountCertainty, 'exact');
	});

	test('malformed reason data prevents a clean classification when the explicit count is zero', () => {
		const malformed = normalizeScanCoverage(0, { 'line-limit': Number.NaN });
		assert.equal(malformed.coverageDiagnosticsAvailable, false);
		assert.equal(scanCoverageLabel('Complete', malformed), 'Coverage unavailable');
	});

	test('historical transitions clear live diagnostics and returning to a live snapshot restores its own diagnostics', () => {
		const liveCoverage = normalizeScanCoverage(2, { 'line-limit': 2 });
		const liveStats = { filesScanned: 8, indexedFiles: 8, scanStatus: 'Complete' as const, lastScanDurationMs: 12, ...liveCoverage };
		const historyLoaded = statsForHistoricalSnapshot(liveStats, { filesScanned: 3 });
		assert.equal(historyLoaded.filesScanned, 3);
		assert.equal(historyLoaded.coverageDiagnosticsAvailable, false);
		assert.equal(historyLoaded.skippedFiles, undefined);
		assert.equal(historyLoaded.skipReasons, undefined);
		assert.equal(scanCoverageLabel('Complete', normalizeScanCoverage(historyLoaded.skippedFiles, historyLoaded.skipReasons)), 'Coverage unavailable');

		const afterDelete = statsForHistoricalSnapshot(liveStats, { filesScanned: 4 });
		assert.equal(afterDelete.coverageDiagnosticsAvailable, false);
		const noSelection = statsWithoutSelectedSnapshot(liveStats);
		assert.equal(noSelection.coverageDiagnosticsAvailable, false);
		assert.equal(noSelection.skippedFiles, undefined);

		const returnedToLive = statsForHistoricalSnapshot(historyLoaded, { filesScanned: 8, ...liveCoverage, coverageDiagnosticsAvailable: true });
		assert.equal(returnedToLive.coverageDiagnosticsAvailable, true);
		assert.equal(returnedToLive.skippedFiles, 2);
		assert.deepEqual(returnedToLive.skipReasons, { 'line-limit': 2 });
		assert.equal(scanCoverageLabel('Complete', normalizeScanCoverage(returnedToLive.skippedFiles, returnedToLive.skipReasons)), 'Partial coverage');
	});

	test('historical scan UI says coverage is unavailable rather than complete or inheriting live skips', () => {
		Object.defineProperty(globalThis, 'window', { configurable: true, value: { __AQIRON_DESKTOP__: true } });
		const historical = statsForHistoricalSnapshot({ filesScanned: 9, indexedFiles: 9, scanStatus: 'Complete' as const, lastScanDurationMs: 1, coverageDiagnosticsAvailable: true, skippedFiles: 2, skipReasons: { 'line-limit': 2 } }, { filesScanned: 3 });
		const markup = renderToStaticMarkup(React.createElement(ScanTab, { state: makeState(historical), post: () => undefined }));
		assert.match(markup, /Coverage unavailable/);
		assert.match(markup, /full coverage cannot be confirmed/);
		assert.doesNotMatch(markup, /2 files were skipped|Scan complete/);
	});

	test('an availability flag without a valid diagnostic count cannot establish clean coverage', () => {
		Object.defineProperty(globalThis, 'window', { configurable: true, value: { __AQIRON_DESKTOP__: true } });
		const stats = { filesScanned: 3, indexedFiles: 3, scanStatus: 'Complete' as const, lastScanDurationMs: 1, coverageDiagnosticsAvailable: true };
		const markup = renderToStaticMarkup(React.createElement(ScanTab, { state: makeState(stats), post: () => undefined }));
		assert.match(markup, /Coverage unavailable/);
		assert.doesNotMatch(markup, />Complete</);
	});

	test('live partial coverage remains visible in the scan UI', () => {
		Object.defineProperty(globalThis, 'window', { configurable: true, value: { __AQIRON_DESKTOP__: true } });
		const coverage = normalizeScanCoverage(2, { 'line-limit': 2 });
		const stats = { filesScanned: 8, indexedFiles: 8, scanStatus: 'Complete' as const, lastScanDurationMs: 1, ...coverage };
		const markup = renderToStaticMarkup(React.createElement(ScanTab, { state: makeState(stats), post: () => undefined }));
		assert.match(markup, /Incomplete coverage/);
		assert.match(markup, /2 files were skipped; coverage is incomplete/);
		assert.match(markup, /line-limit: 2/);
	});

	test('clean coverage stays complete and malformed diagnostics render as unavailable inert text', () => {
		Object.defineProperty(globalThis, 'window', { configurable: true, value: { __AQIRON_DESKTOP__: true } });
		const cleanCoverage = normalizeScanCoverage(0, {});
		const cleanMarkup = renderToStaticMarkup(React.createElement(ScanTab, { state: makeState({ filesScanned: 3, indexedFiles: 3, scanStatus: 'Complete', lastScanDurationMs: 1, ...cleanCoverage }), post: () => undefined }));
		assert.match(cleanMarkup, />Complete</);
		assert.match(cleanMarkup, /Scan complete/);

		const malformedCoverage = normalizeScanCoverage(Number.NaN, { '<img onerror=alert(1)>': 1, 'bad\u001b[31m': 2 });
		const malformedMarkup = renderToStaticMarkup(React.createElement(ScanTab, { state: makeState({ filesScanned: 3, indexedFiles: 3, scanStatus: 'Complete', lastScanDurationMs: 1, ...malformedCoverage }), post: () => undefined }));
		assert.match(malformedMarkup, /Coverage unavailable/);
		assert.doesNotMatch(malformedMarkup, /<img|onerror|\u001b/);
	});
});

function makeState(stats: WebviewState['stats']): WebviewState {
	return {
		workspace: { name: 'Fixture', types: [], currentFile: 'No file' },
		stats,
		branches: [],
		pipeline: { stages: [], tools: [], logs: [] },
		counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, filesAffected: 0 },
		issues: [],
		threatSnapshots: [],
		zoom: 1,
	} as unknown as WebviewState;
}
