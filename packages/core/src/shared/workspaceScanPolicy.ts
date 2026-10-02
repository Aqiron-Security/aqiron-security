/**
 * Client-resolved policy contract for Core workspace scans that need explicit host policy.
 * This describes scan scope only; host eligibility and trust remain separate inputs.
 * `aqExclusionPatterns` uses the existing ordered .aq syntax, including `!` negation.
 */
export interface ResolvedWorkspaceScanPolicy {
	/** Extensions allowed by the client, normalized with a leading dot. */
	supportedExtensions: string[];
	/** Directory path fragments from default and client settings, normalized with `/`. */
	excludedDirectoryPaths: string[];
	/** Unconditional name globs from the current workspace selector (for example `*.g.dart`). */
	excludedFileNamePatterns: string[];
	/** Ordered .aq rule lines; blank lines and comments have already been removed. */
	aqExclusionPatterns: string[];
	/** Maximum stat/file size in bytes. The current VS Code workspace policy has no unlimited mode. */
	maxFileSizeBytes: number;
	/** Resolved custom rules used by the host scanner, without the raw VS Code configuration object. */
	customRules: Array<{
		id: string;
		title: string;
		message: string;
		severity: 'Critical' | 'High' | 'Medium' | 'Low';
		pattern: string;
		extensions?: string[];
		caseSensitive?: boolean;
	}>;
	skipGeneratedFiles: boolean;
	skipMinifiedFiles: boolean;
	skipCompiledFiles: boolean;
}
