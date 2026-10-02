/**
 * Client-resolved policy contract for a future Core workspace scan request.
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
	skipGeneratedFiles: boolean;
	skipMinifiedFiles: boolean;
	skipCompiledFiles: boolean;
}
