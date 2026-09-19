/**
 * Engine-specific field mappers
 * Normalize findings from different security tools
 */

import { VulnerabilityEnvelope, VulnerabilityCategory, normalizeSeverityToStandard, inferSourceType } from './vulnerabilitySchema';

/**
 * Mapper interface for tool-specific field mapping
 */
export interface EngineFieldMapper {
	extractRuleId(raw: Record<string, unknown>): string;
	extractTitle(raw: Record<string, unknown>): string;
	extractDescription(raw: Record<string, unknown>): string;
	extractSeverity(raw: Record<string, unknown>): string;
	extractFile(raw: Record<string, unknown>): string;
	extractLine(raw: Record<string, unknown>): number;
	extractColumn(raw: Record<string, unknown>): number | undefined;
	extractEndLine(raw: Record<string, unknown>): number | undefined;
	extractEndColumn(raw: Record<string, unknown>): number | undefined;
	extractCwe(raw: Record<string, unknown>): string[];
	extractOwasp(raw: Record<string, unknown>): string[];
	extractCvss(raw: Record<string, unknown>): number | undefined;
	extractConfidence(raw: Record<string, unknown>): 'low' | 'medium' | 'high';
	extractRemediation(raw: Record<string, unknown>): string;
	extractCategory(raw: Record<string, unknown>): VulnerabilityCategory;
	extractTags(raw: Record<string, unknown>): string[];
}

/**
 * Semgrep field mapper
 * Converts Semgrep JSON results to standard schema
 */
export class SemgrepFieldMapper implements EngineFieldMapper {
	extractRuleId(raw: Record<string, unknown>): string {
		return String(raw.check_id ?? raw.id ?? 'semgrep.unknown');
	}

	extractTitle(raw: Record<string, unknown>): string {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const message = String(extra?.['message'] ?? raw.message ?? '');
		if (message) return message;
		
		const checkId = String(raw.check_id ?? '');
		return checkId.split('.').slice(-2).join(' / ') || 'Semgrep finding';
	}

	extractDescription(raw: Record<string, unknown>): string {
		const extra = raw.extra as Record<string, unknown> | undefined;
		return String(extra?.['message'] ?? 'Semgrep detected a source security issue.');
	}

	extractSeverity(raw: Record<string, unknown>): string {
		const extra = raw.extra as Record<string, unknown> | undefined;
		return String(extra?.['severity'] ?? 'medium');
	}

	extractFile(raw: Record<string, unknown>): string {
		return String(raw.path ?? '');
	}

	extractLine(raw: Record<string, unknown>): number {
		const start = raw.start as Record<string, unknown> | undefined;
		return Number(start?.line ?? 1);
	}

	extractColumn(raw: Record<string, unknown>): number | undefined {
		const start = raw.start as Record<string, unknown> | undefined;
		return start?.col ? Number(start.col) : undefined;
	}

	extractEndLine(raw: Record<string, unknown>): number | undefined {
		const end = raw.end as Record<string, unknown> | undefined;
		return end?.line ? Number(end.line) : undefined;
	}

	extractEndColumn(raw: Record<string, unknown>): number | undefined {
		const end = raw.end as Record<string, unknown> | undefined;
		return end?.col ? Number(end.col) : undefined;
	}

	extractCwe(raw: Record<string, unknown>): string[] {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const metadata = extra?.['metadata'] as Record<string, unknown> | undefined;
		const cwe = metadata?.cwe;
		if (Array.isArray(cwe)) return cwe.map(String);
		if (cwe) return [String(cwe)];
		return [];
	}

	extractOwasp(raw: Record<string, unknown>): string[] {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const metadata = extra?.['metadata'] as Record<string, unknown> | undefined;
		const owasp = metadata?.owasp;
		if (Array.isArray(owasp)) return owasp.map(String);
		if (owasp) return [String(owasp)];
		return [];
	}

	extractCvss(raw: Record<string, unknown>): number | undefined {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const metadata = extra?.['metadata'] as Record<string, unknown> | undefined;
		const cvss = metadata?.cvss;
		return cvss ? Number(cvss) : undefined;
	}

	extractConfidence(raw: Record<string, unknown>): 'low' | 'medium' | 'high' {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const metadata = extra?.['metadata'] as Record<string, unknown> | undefined;
		const confidence = String(metadata?.confidence ?? 'medium').toLowerCase();
		return (confidence === 'high' || confidence === 'low') ? confidence as 'low' | 'high' : 'medium';
	}

	extractRemediation(raw: Record<string, unknown>): string {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const fix = extra?.['fix'];
		if (fix) return String(fix);
		return 'Review the matched data flow and apply the Semgrep rule guidance.';
	}

	extractCategory(raw: Record<string, unknown>): VulnerabilityCategory {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const metadata = extra?.['metadata'] as Record<string, unknown> | undefined;
		const category = String(metadata?.category ?? '').toLowerCase();
		
		if (category.includes('secret')) return 'secret';
		if (category.includes('cve') || category.includes('vulnerability')) return 'cve';
		
		return 'insecure-code';
	}

	extractTags(raw: Record<string, unknown>): string[] {
		const extra = raw.extra as Record<string, unknown> | undefined;
		const metadata = extra?.['metadata'] as Record<string, unknown> | undefined;
		const category = metadata?.category;
		const technology = metadata?.technology as string[] | undefined;
		
		const tags = ['sast', 'semgrep'];
		if (category) tags.push(String(category));
		if (technology) tags.push(...technology);
		
		return tags;
	}
}

/**
 * Trivy field mapper
 * Converts Trivy JSON results to standard schema
 */
export class TrivyFieldMapper implements EngineFieldMapper {
	constructor(private resultType: 'vulnerability' | 'misconfiguration' | 'secret' = 'vulnerability') {}

	extractRuleId(raw: Record<string, unknown>): string {
		switch (this.resultType) {
			case 'vulnerability':
				return String(raw.VulnerabilityID ?? 'trivy.vuln');
			case 'misconfiguration':
				return String(raw.ID ?? 'trivy.misconfig');
			case 'secret':
				return String(raw.RuleID ?? 'trivy.secret');
		}
	}

	extractTitle(raw: Record<string, unknown>): string {
		return String(raw.Title ?? raw.ID ?? 'Trivy finding');
	}

	extractDescription(raw: Record<string, unknown>): string {
		return String(raw.Description ?? raw.Message ?? 'Issue detected by Trivy.');
	}

	extractSeverity(raw: Record<string, unknown>): string {
		return String(raw.Severity ?? 'medium');
	}

	extractFile(raw: Record<string, unknown>): string {
		return String(raw.Target ?? raw.Path ?? '');
	}

	extractLine(raw: Record<string, unknown>): number {
		if (this.resultType === 'misconfiguration') {
			const metadata = raw.CauseMetadata as Record<string, unknown> | undefined;
			return Number(metadata?.StartLine ?? 1);
		}
		if (this.resultType === 'secret') {
			return Number(raw.StartLine ?? 1);
		}
		return 1;
	}

	extractColumn(raw: Record<string, unknown>): number | undefined {
		return undefined;
	}

	extractEndLine(raw: Record<string, unknown>): number | undefined {
		if (this.resultType === 'misconfiguration') {
			const metadata = raw.CauseMetadata as Record<string, unknown> | undefined;
			return metadata?.EndLine ? Number(metadata.EndLine) : undefined;
		}
		if (this.resultType === 'secret') {
			return raw.EndLine ? Number(raw.EndLine) : undefined;
		}
		return undefined;
	}

	extractEndColumn(raw: Record<string, unknown>): number | undefined {
		return undefined;
	}

	extractCwe(raw: Record<string, unknown>): string[] {
		const cweIds = raw.CweIDs as string[] | undefined;
		return cweIds ?? [];
	}

	extractOwasp(raw: Record<string, unknown>): string[] {
		if (this.resultType === 'vulnerability') {
			return ['A06:2021-Vulnerable and Outdated Components'];
		}
		if (this.resultType === 'misconfiguration') {
			return ['A05:2021-Security Misconfiguration'];
		}
		return ['A02:2021-Cryptographic Failures'];
	}

	extractCvss(raw: Record<string, unknown>): number | undefined {
		if (this.resultType !== 'vulnerability') return undefined;
		
		const cvss = raw.CVSS as Record<string, Record<string, number>> | undefined;
		if (!cvss) return undefined;
		
		for (const score of Object.values(cvss)) {
			if (score.V3Score) return score.V3Score;
			if (score.V2Score) return score.V2Score;
		}
		return undefined;
	}

	extractConfidence(raw: Record<string, unknown>): 'low' | 'medium' | 'high' {
		return 'high';
	}

	extractRemediation(raw: Record<string, unknown>): string {
		if (this.resultType === 'vulnerability') {
			const fixedVersion = raw.FixedVersion;
			const pkgName = raw.PkgName;
			if (fixedVersion && pkgName) {
				return `Upgrade ${pkgName} to ${fixedVersion} or later.`;
			}
			return 'Upgrade the affected dependency or apply vendor mitigation.';
		}
		
		const resolution = raw.Resolution;
		if (resolution) return String(resolution);
		
		return 'Harden the configuration according to the referenced benchmark.';
	}

	extractCategory(raw: Record<string, unknown>): VulnerabilityCategory {
		if (this.resultType === 'vulnerability') {
			return 'cve';
		}
		if (this.resultType === 'secret') {
			return 'secret';
		}
		return 'config';
	}

	extractTags(raw: Record<string, unknown>): string[] {
		const tags = ['trivy', this.resultType];
		
		if (this.resultType === 'vulnerability') {
			const type = String(raw.Type ?? 'package');
			const clazz = String(raw.Class ?? 'filesystem');
			tags.push('dependency', 'sca', type, clazz);
		} else if (this.resultType === 'misconfiguration') {
			const type = String(raw.Type ?? 'config');
			tags.push('configuration', 'iac', type);
		} else {
			const category = raw.Category;
			if (category) tags.push(String(category));
		}
		
		return tags;
	}
}

/**
 * MobSF field mapper
 * Converts MobSF findings to standard schema
 */
export class MobSfFieldMapper implements EngineFieldMapper {
	extractRuleId(raw: Record<string, unknown>): string {
		return String(raw.ruleId ?? raw.permission ?? raw.rule ?? 'mobsf.finding');
	}

	extractTitle(raw: Record<string, unknown>): string {
		return String(raw.title ?? raw.permission ?? 'MobSF finding');
	}

	extractDescription(raw: Record<string, unknown>): string {
		return String(raw.description ?? 'Mobile security issue detected by MobSF.');
	}

	extractSeverity(raw: Record<string, unknown>): string {
		return String(raw.severity ?? 'medium');
	}

	extractFile(raw: Record<string, unknown>): string {
		return String(raw.file ?? raw.artifact ?? '');
	}

	extractLine(raw: Record<string, unknown>): number {
		return 1;
	}

	extractColumn(raw: Record<string, unknown>): number | undefined {
		return undefined;
	}

	extractEndLine(raw: Record<string, unknown>): number | undefined {
		return undefined;
	}

	extractEndColumn(raw: Record<string, unknown>): number | undefined {
		return undefined;
	}

	extractCwe(raw: Record<string, unknown>): string[] {
		return [];
	}

	extractOwasp(raw: Record<string, unknown>): string[] {
		const type = String(raw.type ?? '').toLowerCase();
		if (type === 'permission') return ['M1: Improper Credential Usage'];
		if (type === 'manifest') return ['M8: Security Misconfiguration'];
		return ['M8: Security Misconfiguration'];
	}

	extractCvss(raw: Record<string, unknown>): number | undefined {
		return undefined;
	}

	extractConfidence(raw: Record<string, unknown>): 'low' | 'medium' | 'high' {
		return 'high';
	}

	extractRemediation(raw: Record<string, unknown>): string {
		const type = String(raw.type ?? '').toLowerCase();
		if (type === 'permission') {
			return 'Review the permission, remove it when unnecessary, and document the business justification.';
		}
		return 'Harden the Android manifest setting and rerun MobSF.';
	}

	extractCategory(raw: Record<string, unknown>): VulnerabilityCategory {
		const type = String(raw.type ?? '').toLowerCase();
		if (type === 'permission') return 'permission';
		return 'config';
	}

	extractTags(raw: Record<string, unknown>): string[] {
		const type = String(raw.type ?? '').toLowerCase();
		return ['mobile', 'android', 'mobsf', type];
	}
}

/**
 * Get mapper for engine
 */
export function getMapperForEngine(engine: string): EngineFieldMapper {
	const lower = engine.toLowerCase();
	
	if (lower === 'semgrep') return new SemgrepFieldMapper();
	if (lower === 'trivy') return new TrivyFieldMapper('vulnerability');
	if (lower === 'mobsf') return new MobSfFieldMapper();
	
	return new SemgrepFieldMapper();
}
