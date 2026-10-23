import { formatAgentScanCoverage, formatSkippedFileCount, formatSkipReasonList, normalizeScanCoverage, NormalizedScanCoverage, ScanCoverageHints } from '../../packages/core/src/shared/scanCoverage';

export { formatAgentScanCoverage, formatSkippedFileCount, formatSkipReasonList, normalizeScanCoverage };
export type { NormalizedScanCoverage, ScanCoverageHints };

export interface CoverageStatsLike {
	filesScanned: number;
	indexedFiles: number;
	scanStatus: 'Idle' | 'Scanning' | 'Complete' | 'Failed';
	coverageDiagnosticsAvailable?: boolean;
	coverageDiagnosticsPresent?: boolean;
	coverageDiagnosticsValid?: boolean;
	coverageStatus?: NormalizedScanCoverage['coverageStatus'];
	skippedFiles?: number;
	skippedFilesIsLowerBound?: boolean;
	skippedFilesCountCertainty?: NormalizedScanCoverage['skippedFilesCountCertainty'];
	skipCountConflict?: boolean;
	skipReasonsTruncated?: boolean;
	skipReasons?: Partial<Record<string, number>>;
}

export interface CoverageSnapshotLike {
	filesScanned: number;
	coverageDiagnosticsAvailable?: boolean;
	coverageDiagnosticsPresent?: boolean;
	coverageDiagnosticsValid?: boolean;
	coverageStatus?: NormalizedScanCoverage['coverageStatus'];
	skippedFiles?: number;
	skippedFilesIsLowerBound?: boolean;
	skippedFilesCountCertainty?: NormalizedScanCoverage['skippedFilesCountCertainty'];
	skipCountConflict?: boolean;
	skipReasonsTruncated?: boolean;
	skipReasons?: Partial<Record<string, number>>;
}

export function statsForHistoricalSnapshot<T extends CoverageStatsLike>(current: T, snapshot: CoverageSnapshotLike): T {
	const diagnostics = snapshot.coverageDiagnosticsAvailable === true
		? normalizeScanCoverage(snapshot.skippedFiles, snapshot.skipReasons, snapshot.skippedFilesIsLowerBound, snapshot)
		: normalizeScanCoverage(undefined, undefined);
	return {
		...current,
		filesScanned: safeNonNegativeCount(snapshot.filesScanned),
		indexedFiles: safeNonNegativeCount(snapshot.filesScanned),
		scanStatus: 'Complete',
		coverageDiagnosticsAvailable: diagnostics.coverageDiagnosticsAvailable,
		coverageDiagnosticsPresent: diagnostics.coverageDiagnosticsPresent,
		coverageDiagnosticsValid: diagnostics.coverageDiagnosticsValid,
		coverageStatus: diagnostics.coverageStatus,
		...(diagnostics.coverageDiagnosticsAvailable ? { skippedFiles: diagnostics.skippedFiles, skippedFilesIsLowerBound: diagnostics.skippedFilesIsLowerBound, skippedFilesCountCertainty: diagnostics.skippedFilesCountCertainty, skipCountConflict: diagnostics.skipCountConflict, skipReasonsTruncated: diagnostics.skipReasonsTruncated, skipReasons: diagnostics.skipReasons } : { skippedFiles: undefined, skippedFilesIsLowerBound: undefined, skippedFilesCountCertainty: 'indeterminate' as const, skipCountConflict: false, skipReasonsTruncated: false, skipReasons: undefined }),
	};
}

export function statsWithoutSelectedSnapshot<T extends CoverageStatsLike>(current: T): T {
	return {
		...current,
		filesScanned: 0,
		indexedFiles: 0,
		coverageDiagnosticsAvailable: false,
		coverageDiagnosticsPresent: false,
		coverageDiagnosticsValid: false,
		coverageStatus: 'unavailable',
		skippedFiles: undefined,
		skippedFilesIsLowerBound: undefined,
		skippedFilesCountCertainty: 'indeterminate',
		skipCountConflict: false,
		skipReasonsTruncated: false,
		skipReasons: undefined,
		scanStatus: 'Complete',
	};
}

export function scanCoverageLabel(status: CoverageStatsLike['scanStatus'], coverage: Pick<NormalizedScanCoverage, 'coverageDiagnosticsAvailable' | 'skippedFiles'>): 'Partial coverage' | 'Coverage unavailable' | 'Complete' | 'Scanning' | 'Failed' | 'Idle' {
	if (status !== 'Complete') { return status; }
	if (coverage.skippedFiles > 0) { return 'Partial coverage'; }
	return coverage.coverageDiagnosticsAvailable ? 'Complete' : 'Coverage unavailable';
}

export function formatWorkspaceScanCompletion(issueCount: unknown, hiddenCount: unknown, coverage: NormalizedScanCoverage): string {
	const safeIssues = safeNonNegativeCount(issueCount);
	const safeHidden = safeNonNegativeCount(hiddenCount);
	const hiddenSuffix = safeHidden > 0 ? ` (${safeHidden} generated/build finding${safeHidden === 1 ? '' : 's'} hidden)` : '';
	const issues = `${safeIssues} actionable issue${safeIssues === 1 ? '' : 's'} found${hiddenSuffix}`;
	if (coverage.skippedFiles > 0) {
		const reasons = formatSkipReasonList(coverage.skipReasons);
		const skipped = formatSkippedFileCount(coverage);
		const conflict = coverage.skipCountConflict ? ' The explicit skipped-file total conflicts with the reason-derived total.' : '';
		const omitted = coverage.skipReasonsTruncated ? '; additional reason categories omitted' : '';
		return `Aqiron Security scan finished with incomplete coverage: ${issues}. Coverage is incomplete: ${skipped} file${coverage.skippedFiles === 1 ? '' : 's'} skipped${reasons ? ` (reasons: ${reasons}${omitted})` : ''}.${conflict}`;
	}
	if (!coverage.coverageDiagnosticsAvailable) {
		return `Aqiron Security scan completed, but coverage diagnostics are unavailable: ${issues}. Full coverage could not be confirmed.`;
	}
	return `Aqiron Security scan completed: ${issues}.`;
}

export function safeNonNegativeCount(value: unknown): number {
	return Number.isSafeInteger(value) && (value as number) >= 0 ? value as number : 0;
}
