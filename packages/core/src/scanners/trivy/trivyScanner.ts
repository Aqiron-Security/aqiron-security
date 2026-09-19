import * as path from 'path';
import { createFinding, normalizeSeverity, UnifiedFinding } from '../../shared/finding';
import { ScannerContext, ScannerResult, SecurityScanner, ToolAvailability, ScannerCapability } from '../types';
import { TrivyParser } from '../../parsers/trivyParser';

interface TrivyReport {
	Results?: TrivyResult[];
}

interface TrivyResult {
	Target?: string;
	Class?: string;
	Type?: string;
	Vulnerabilities?: TrivyVulnerability[];
	Misconfigurations?: TrivyMisconfiguration[];
	Secrets?: TrivySecret[];
}

interface TrivyVulnerability {
	VulnerabilityID?: string;
	PkgName?: string;
	InstalledVersion?: string;
	FixedVersion?: string;
	Severity?: string;
	Title?: string;
	Description?: string;
	PrimaryURL?: string;
	CVSS?: Record<string, { V3Score?: number; V2Score?: number }>;
	CweIDs?: string[];
}

interface TrivyMisconfiguration {
	ID?: string;
	Title?: string;
	Description?: string;
	Severity?: string;
	Message?: string;
	Resolution?: string;
	PrimaryURL?: string;
	CauseMetadata?: { StartLine?: number; EndLine?: number; Code?: { Lines?: Array<{ Number?: number; Content?: string }> } };
}

interface TrivySecret {
	RuleID?: string;
	Category?: string;
	Severity?: string;
	Title?: string;
	StartLine?: number;
	EndLine?: number;
	Match?: string;
}

export class TrivyScanner implements SecurityScanner {
	readonly id = 'trivy';
	readonly name = 'Trivy';
	readonly capabilities: ScannerCapability[] = ['dependency', 'secret', 'config'];

	constructor(private readonly parser = new TrivyParser()) {}

	async isAvailable(context: ScannerContext): Promise<ToolAvailability> {
		try {
			await context.processRunner.execFile('trivy', { cwd: context.workspaceRoot, args: ['--version'], timeoutMs: 5_000, cancellationToken: context.cancellationToken, windowsHide: true });
			return { available: true };
		} catch (error) {
			return { available: false, reason: error instanceof Error ? error.message : String(error) };
		}
	}

	async scan(context: ScannerContext): Promise<ScannerResult> {
		const startedAt = Date.now();
		const result = await context.processRunner.execFile('trivy', {
			cwd: context.workspaceRoot,
			args: ['fs', context.targetPath, '--format', 'json', '--scanners', 'vuln,secret,config', '--skip-version-check', '--skip-dirs', context.exclusions.join(',')],
			timeoutMs: 120_000,
			cancellationToken: context.cancellationToken,
			windowsHide: true,
		});
		return {
			toolId: this.id,
			label: this.name,
			findings: this.parser.parse(result.stdout, context.workspaceRoot),
			durationMs: Date.now() - startedAt,
		};
	}

	async scanContainer(image: string, context: ScannerContext): Promise<ScannerResult> {
		const startedAt = Date.now();
		const result = await context.processRunner.execFile('trivy', {
			cwd: context.workspaceRoot,
			args: ['image', image, '--format', 'json', '--scanners', 'vuln,secret,config', '--skip-version-check'],
			timeoutMs: 120_000,
			cancellationToken: context.cancellationToken,
			windowsHide: true,
		});
		return {
			toolId: `${this.id}:container`,
			label: 'Trivy Container',
			findings: this.parser.parse(result.stdout, context.workspaceRoot),
			durationMs: Date.now() - startedAt,
		};
	}
}
