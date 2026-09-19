import * as path from 'path';
import { createFinding, normalizeSeverity, UnifiedFinding } from '../findings/finding';
import { TrivyFieldMapper } from './engineMappers';

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

export class TrivyParser {
	parse(stdout: string, workspaceRoot: string): UnifiedFinding[] {
		const report = safeJson<TrivyReport>(stdout);
		if (!report?.Results) {
			return [];
		}
		return report.Results.flatMap((result) => [
			...this.parseVulnerabilities(result, workspaceRoot),
			...this.parseMisconfigurations(result, workspaceRoot),
			...this.parseSecrets(result, workspaceRoot),
		]);
	}

	private parseVulnerabilities(result: TrivyResult, workspaceRoot: string): UnifiedFinding[] {
		const mapper = new TrivyFieldMapper('vulnerability');
		return (result.Vulnerabilities ?? []).map((vulnerability) => {
			const raw = { ...vulnerability, Target: result.Target, Class: result.Class, Type: result.Type } as Record<string, unknown>;
			const file = resolveTarget(workspaceRoot, result.Target);
			const cve = vulnerability.VulnerabilityID ?? 'TRIVY-VULNERABILITY';
			const cvss = getCvss(vulnerability.CVSS);
			
			const tags = ['dependency', 'sca', result.Class ?? 'filesystem', result.Type ?? 'package'];
			// Add source_type tag - dependencies are typically source-level
			tags.push('source-code');
			
			return createFinding({
				title: vulnerability.Title || `${cve} in ${vulnerability.PkgName ?? 'dependency'}`,
				description: vulnerability.Description || `${vulnerability.PkgName ?? 'Dependency'} ${vulnerability.InstalledVersion ?? ''} is vulnerable.`,
				severity: normalizeSeverity(vulnerability.Severity),
				cwe: vulnerability.CweIDs ?? [],
				owasp: ['A06:2021-Vulnerable and Outdated Components'],
				cvss,
				file,
				line: 1,
				column: 1,
				sourceTool: 'Trivy',
				ruleId: cve,
				confidence: 'High',
				remediation: vulnerability.FixedVersion ? `Upgrade ${vulnerability.PkgName} to ${vulnerability.FixedVersion} or later.` : 'Upgrade the affected dependency or apply vendor mitigation.',
				tags,
				rawEvidence: raw,
			});
		});
	}

	private parseMisconfigurations(result: TrivyResult, workspaceRoot: string): UnifiedFinding[] {
		const mapper = new TrivyFieldMapper('misconfiguration');
		return (result.Misconfigurations ?? []).map((misconfiguration) => {
			const file = resolveTarget(workspaceRoot, result.Target);
			const line = misconfiguration.CauseMetadata?.StartLine ?? misconfiguration.CauseMetadata?.Code?.Lines?.[0]?.Number ?? 1;
			const ruleId = misconfiguration.ID ?? 'TRIVY-CONFIG';
			
			const tags = ['configuration', 'iac', result.Type ?? 'config'];
			// Add source_type tag - configs are source-level
			tags.push('source-code');
			
			return createFinding({
				title: misconfiguration.Title || ruleId,
				description: misconfiguration.Description || misconfiguration.Message || 'Configuration weakness detected by Trivy.',
				severity: normalizeSeverity(misconfiguration.Severity),
				cwe: [],
				owasp: ['A05:2021-Security Misconfiguration'],
				file,
				line,
				column: 1,
				endLine: misconfiguration.CauseMetadata?.EndLine,
				sourceTool: 'Trivy',
				ruleId,
				confidence: 'High',
				remediation: misconfiguration.Resolution || 'Harden the configuration according to the referenced benchmark.',
				tags,
				rawEvidence: { ...misconfiguration, target: result.Target },
			});
		});
	}

	private parseSecrets(result: TrivyResult, workspaceRoot: string): UnifiedFinding[] {
		const mapper = new TrivyFieldMapper('secret');
		return (result.Secrets ?? []).map((secret) => {
			const ruleId = secret.RuleID ?? 'TRIVY-SECRET';
			
			const tags = ['secret', 'credential'];
			// Add source_type tag - secrets are typically in source code
			tags.push('source-code');
			
			return createFinding({
				title: secret.Title || `${secret.Category ?? 'Secret'} detected`,
				description: 'Secret-like material was detected in the workspace.',
				severity: normalizeSeverity(secret.Severity || 'Critical'),
				cwe: ['CWE-798'],
				owasp: ['A02:2021-Cryptographic Failures'],
				file: resolveTarget(workspaceRoot, result.Target),
				line: secret.StartLine ?? 1,
				column: 1,
				endLine: secret.EndLine,
				sourceTool: 'Trivy',
				ruleId,
				confidence: 'High',
				remediation: 'Rotate the exposed value and move it into a managed secret store.',
				tags,
				rawEvidence: { ...secret, Match: secret.Match ? '[redacted]' : undefined, target: result.Target },
			});
		});
	}
}

function safeJson<T>(value: string): T | undefined {
	try {
		return JSON.parse(value) as T;
	} catch {
		return undefined;
	}
}

function resolveTarget(workspaceRoot: string, target?: string): string {
	if (!target) {
		return workspaceRoot;
	}
	return path.isAbsolute(target) ? target : path.join(workspaceRoot, target);
}

function getCvss(cvss: TrivyVulnerability['CVSS']): number | undefined {
	const entries = Object.values(cvss ?? {});
	return entries.map((entry) => entry.V3Score ?? entry.V2Score).find((score): score is number => typeof score === 'number');
}
