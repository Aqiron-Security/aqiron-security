import { UnifiedFinding } from './finding';

/** Effective, client-resolved policy for one exact file target. */
export interface ResolvedFileScanPolicy {
	/** File extensions the client permits for this scan, normalized with a leading dot. */
	supportedExtensions: string[];
	/** Absolute file or directory paths excluded by the client's resolved policy. */
	excludedPaths: string[];
	/** null means unlimited; otherwise measured against UTF-8 encoded content bytes. */
	maxFileSizeBytes: number | null;
	skipGeneratedFiles: boolean;
	skipMinifiedFiles: boolean;
	skipCompiledFiles: boolean;
	/** A false value represents a resolved project/client gate (for example Flutter-only policy). */
	eligible: boolean;
	customRules: ResolvedCustomRule[];
}

/** Portable regex-rule subset matching the existing VS Code custom-rule shape. */
export interface ResolvedCustomRule {
	id: string;
	title: string;
	message: string;
	severity: 'Critical' | 'High' | 'Medium' | 'Low';
	pattern: string;
	extensions?: string[];
	/** Omit for the existing case-insensitive custom-rule behavior. */
	caseSensitive?: boolean;
}

/** Content is supplied explicitly; Core must not reread filePath for this operation. */
export interface CoreFileScanRequest {
	filePath: string;
	content: string;
	policy: ResolvedFileScanPolicy;
}

export interface CoreFileScanResult {
	scanId: string;
	filePath: string;
	state: 'completed' | 'skipped';
	skipReason?: 'ineligible' | 'excluded' | 'unsupported' | 'generated' | 'minified' | 'compiled' | 'size-limit';
	findings: UnifiedFinding[];
	filesScanned: 0 | 1;
	findingCount: number;
	durationMs: number;
}
