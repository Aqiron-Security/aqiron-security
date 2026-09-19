/**
 * Scan Mode Configuration
 * Defines two separate scan strategies for comprehensive security analysis
 */

export enum ScanMode {
	/**
	 * SOURCE_CODE mode: Scans only developer-written source code
	 * Uses Semgrep for SAST analysis
	 * Excludes: build artifacts, cache, ephemeral, generated code
	 */
	SOURCE_CODE = 'source-code',

	/**
	 * ARTIFACT_BINARY mode: Scans compiled artifacts and binaries
	 * Uses Trivy for vulnerabilities and MobSF for mobile security
	 * Targets: .apk, .aar, .dex, .jar, .so, .dll, .exe files
	 */
	ARTIFACT_BINARY = 'artifact-binary',

	/**
	 * ALL mode: Runs both scan modes for comprehensive coverage
	 */
	ALL = 'all',
}

export interface ScanModeConfig {
	mode: ScanMode;
	enableSourceCodeScan: boolean;
	enableArtifactBinaryScan: boolean;
	enableMobileScan: boolean;
}

export function getScanModeConfig(mode: ScanMode): ScanModeConfig {
	switch (mode) {
		case ScanMode.SOURCE_CODE:
			return {
				mode,
				enableSourceCodeScan: true,
				enableArtifactBinaryScan: false,
				enableMobileScan: false,
			};
		case ScanMode.ARTIFACT_BINARY:
			return {
				mode,
				enableSourceCodeScan: false,
				enableArtifactBinaryScan: true,
				enableMobileScan: true,
			};
		case ScanMode.ALL:
			return {
				mode,
				enableSourceCodeScan: true,
				enableArtifactBinaryScan: true,
				enableMobileScan: true,
			};
	}
}
