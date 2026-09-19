import { UnifiedFinding } from '../shared/finding';
import { CancellationTokenLike } from '../shared/cancellation';
import { Configuration, CredentialStore, FileSystem, Logger, NetworkClient, ProcessRunner } from '../shared/platform';
import { ScanTarget, ScannerInputFile, ScannerResult } from '../shared/scanner';

export type { ScanTarget, ScannerInputFile, ScannerResult } from '../shared/scanner';

export type ScannerMode = 'quick' | 'deep' | 'analysis' | 'custom';

export type ScannerCapability = 'source-code' | 'dependency' | 'secret' | 'binary' | 'mobile' | 'artifact' | 'config';

export interface ScannerArtifactPaths {
	tempDir?: string;
	outputDir?: string;
	reportDir?: string;
}

export interface ScannerEnvironment {
	platform?: NodeJS.Platform;
	arch?: string;
	os?: string;
	[key: string]: unknown;
}

export interface ScannerContext extends ScanTarget {
	mode: ScannerMode;
	cancellationToken?: CancellationTokenLike;
	configuration: Configuration;
	filesystem: FileSystem;
	processRunner: ProcessRunner;
	networkClient?: NetworkClient;
	credentialStore?: CredentialStore;
	logger?: Logger;
	artifactPaths?: ScannerArtifactPaths;
	environment?: ScannerEnvironment;
	fileScope?: ScannerInputFile[];
}

export interface ToolAvailability {
	available: boolean;
	reason?: string;
	details?: unknown;
}

export interface ScannerEvent {
	type: 'start' | 'log' | 'finding' | 'complete' | 'unavailable' | 'error';
	scannerId: string;
	timestamp: string;
	message?: string;
	finding?: UnifiedFinding;
	result?: ScannerResult;
	availability?: ToolAvailability;
}

export interface SecurityScanner {
	readonly id: string;
	readonly name: string;
	readonly capabilities: ScannerCapability[];
	isAvailable(context: ScannerContext): Promise<ToolAvailability>;
	scan(context: ScannerContext): Promise<ScannerResult>;
}

export interface ScannerSelection {
	mode?: ScannerMode;
	scannerIds?: string[];
}

export interface ScannerManagerResult {
	findings: UnifiedFinding[];
	results: ScannerResult[];
}
