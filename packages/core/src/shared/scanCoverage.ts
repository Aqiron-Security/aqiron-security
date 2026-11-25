export type ScanCoverageStatus = 'complete' | 'partial' | 'unavailable';
export type ScanCoverageCountCertainty = 'exact' | 'lower-bound' | 'indeterminate';

export interface ScanCoverageHints {
	coverageDiagnosticsPresent?: boolean;
	coverageDiagnosticsValid?: boolean;
	coverageStatus?: ScanCoverageStatus;
	skipCountConflict?: boolean;
	skippedFilesCountCertainty?: ScanCoverageCountCertainty;
	skipReasonsTruncated?: boolean;
}

export interface NormalizedScanCoverage extends ScanCoverageHints {
	coverageDiagnosticsAvailable: boolean;
	coverageStatus: ScanCoverageStatus;
	hasReportedSkips: boolean;
	skippedFiles: number;
	skippedFilesIsLowerBound: boolean;
	skipReasons: Record<string, number>;
}

const SAFE_REASON = /^[a-zA-Z0-9._-]{1,80}$/;
const MAX_DISPLAYED_REASONS = 20;

/**
 * Normalizes the Core scan coverage fields. When both totals are valid but disagree,
 * the larger reported total is shown only as a lower bound and the conflict is explicit.
 * Aggregation is saturated at MAX_SAFE_INTEGER; it is never presented as an exact total.
 */
export function normalizeScanCoverage(skippedValue: unknown, reasonsValue: unknown, lowerBoundValue?: unknown, priorHints?: ScanCoverageHints): NormalizedScanCoverage {
	const explicitWasPresent = skippedValue !== undefined;
	const reportedSkippedFiles = Number.isSafeInteger(skippedValue) && (skippedValue as number) >= 0 ? skippedValue as number : undefined;
	const invalidExplicitCount = explicitWasPresent && reportedSkippedFiles === undefined;
	const reasonsWerePresent = reasonsValue !== undefined;
	const reasonsObject = typeof reasonsValue === 'object' && reasonsValue !== null && !Array.isArray(reasonsValue);
	const priorNormalized = priorHints?.coverageStatus !== undefined && priorHints.coverageDiagnosticsPresent !== undefined;
	const priorTruncated = priorNormalized && priorHints.skipReasonsTruncated === true;
	let malformedReasonData = reasonsWerePresent && !reasonsObject;
	let reasonTotal = 0;
	let reasonTotalSaturated = false;
	let displayedReasonCount = 0;
	const skipReasons = Object.create(null) as Record<string, number>;
	if (reasonsObject) {
		for (const reason in reasonsValue as Record<string, unknown>) {
			if (!Object.prototype.hasOwnProperty.call(reasonsValue, reason)) { continue; }
			const count = (reasonsValue as Record<string, unknown>)[reason];
			if (!SAFE_REASON.test(reason) || !Number.isSafeInteger(count) || (count as number) < 0) {
				malformedReasonData = true;
				continue;
			}
			if ((count as number) === 0) { continue; }
			if (displayedReasonCount++ < MAX_DISPLAYED_REASONS) { skipReasons[reason] = count as number; }
			if ((count as number) > Number.MAX_SAFE_INTEGER - reasonTotal) {
				reasonTotal = Number.MAX_SAFE_INTEGER;
				reasonTotalSaturated = true;
			} else if (!reasonTotalSaturated) {
				reasonTotal += count as number;
			}
		}
	}
	const skipReasonsTruncated = priorTruncated || displayedReasonCount > MAX_DISPLAYED_REASONS;
	const canCompareTotals = reportedSkippedFiles !== undefined && reasonsObject && !malformedReasonData && !priorNormalized;
	const computedConflict = canCompareTotals && (reasonTotalSaturated || reportedSkippedFiles !== reasonTotal);
	const skipCountConflict = priorNormalized
		? priorHints?.skipCountConflict === true
		: Boolean(computedConflict || priorHints?.skipCountConflict === true);
	const skippedFiles = Math.max(reportedSkippedFiles ?? 0, reasonTotal);
	const hasReportedSkips = skippedFiles > 0;
	const calculatedStatus: ScanCoverageStatus = hasReportedSkips
		? 'partial'
		: !invalidExplicitCount && !malformedReasonData && !reasonTotalSaturated && !skipCountConflict
			&& (reportedSkippedFiles === 0 || (reportedSkippedFiles === undefined && reasonsObject && !priorTruncated))
			? 'complete'
			: 'unavailable';
	const coverageStatus: ScanCoverageStatus = priorNormalized && !hasReportedSkips && !invalidExplicitCount && !malformedReasonData
		? priorHints.coverageStatus!
		: calculatedStatus;
	const coverageDiagnosticsAvailable = coverageStatus !== 'unavailable';
	const diagnosticsPresent = priorNormalized && priorHints?.coverageDiagnosticsPresent !== undefined
		? priorHints.coverageDiagnosticsPresent
		: explicitWasPresent || reasonsWerePresent;
	const diagnosticsValid = priorNormalized && priorHints?.coverageDiagnosticsValid !== undefined
		? priorHints.coverageDiagnosticsValid && !malformedReasonData && !invalidExplicitCount
		: diagnosticsPresent && !invalidExplicitCount && !malformedReasonData && !skipCountConflict;
	const uncertain = reasonTotalSaturated || malformedReasonData || invalidExplicitCount || skipCountConflict
		|| lowerBoundValue === true || priorHints?.skippedFilesCountCertainty === 'lower-bound';
	const skippedFilesCountCertainty: ScanCoverageCountCertainty = coverageStatus === 'unavailable'
		? 'indeterminate'
		: hasReportedSkips && uncertain ? 'lower-bound' : 'exact';
	return {
		coverageDiagnosticsPresent: diagnosticsPresent,
		coverageDiagnosticsValid: diagnosticsValid,
		coverageDiagnosticsAvailable,
		coverageStatus,
		hasReportedSkips,
		skippedFiles,
		skippedFilesIsLowerBound: skippedFilesCountCertainty === 'lower-bound',
		skippedFilesCountCertainty,
		skipCountConflict,
		skipReasonsTruncated,
		skipReasons,
	};
}

export function formatSkippedFileCount(coverage: Pick<NormalizedScanCoverage, 'skippedFiles' | 'skippedFilesIsLowerBound'>): string {
	return `${coverage.skippedFilesIsLowerBound ? 'at least ' : ''}${coverage.skippedFiles}`;
}

export function formatSkipReasonList(reasons: Record<string, number>): string {
	return Object.entries(reasons).map(([reason, count]) => `${reason} ${count}`).join(', ');
}

export function formatAgentScanCoverage(coverage: NormalizedScanCoverage): { completion: string; note: string } {
	if (coverage.coverageStatus === 'unavailable') {
		return { completion: 'completed, but coverage diagnostics are unavailable', note: ' Full coverage could not be confirmed because skip diagnostics were not reported or were invalid.' };
	}
	if (coverage.coverageStatus === 'complete') { return { completion: 'complete', note: '' }; }
	const count = `${formatSkippedFileCount(coverage)} file${coverage.skippedFiles === 1 ? '' : 's'}`;
	const conflict = coverage.skipCountConflict ? ' The explicit skipped-file total conflicts with the reason-derived total.' : '';
	const reasons = formatSkipReasonList(coverage.skipReasons);
	const omitted = coverage.skipReasonsTruncated ? '; additional reason categories omitted' : '';
	return {
		completion: 'finished with incomplete coverage',
		note: ` Coverage is incomplete: ${count} ${coverage.skippedFiles === 1 ? 'was' : 'were'} skipped${reasons ? ` (reasons: ${reasons}${omitted})` : ''}.${conflict}`,
	};
}
