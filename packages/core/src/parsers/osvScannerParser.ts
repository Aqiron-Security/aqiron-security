import * as path from 'path';
import { createFinding, normalizeSeverity, UnifiedFinding } from '../findings/finding';

interface OsvReport { results?: OsvResult[]; }
interface OsvResult { source?: { path?: string; type?: string }; packages?: OsvPackage[]; }
interface OsvPackage { package?: { name?: string; version?: string; ecosystem?: string }; vulnerabilities?: OsvVulnerability[]; }
interface OsvVulnerability {
	id?: string; aliases?: string[]; summary?: string; details?: string; severity?: Array<{ type?: string; score?: string }>;
	affected?: Array<{ ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string }> }> }>;
	database_specific?: { severity?: string; cvss?: string | { score?: number } };
}

export interface OsvFindingContext {
	line?: number;
	directness?: 'direct-dependency' | 'dev-dependency' | 'transitive-dependency' | 'dependency';
}
export type OsvContextResolver = (packageName: string) => OsvFindingContext;

export class OsvScannerParser {
	parse(stdout: string, workspaceRoot: string, resolveContext: OsvContextResolver = () => ({})): UnifiedFinding[] {
		const report = safeJson<OsvReport>(stdout);
		if (!report && stdout.trim()) {
			throw new Error('OSV-Scanner returned malformed JSON output.');
		}
		if (!report || !Array.isArray(report.results)) { return []; }
		return report.results.flatMap((result) => (result.packages ?? []).flatMap((pkg) => (pkg.vulnerabilities ?? []).map((vulnerability) => this.toFinding(result, pkg, vulnerability, workspaceRoot, resolveContext(pkg.package?.name || 'dependency')))));
	}

	private toFinding(result: OsvResult, pkg: OsvPackage, vulnerability: OsvVulnerability, root: string, context: OsvFindingContext): UnifiedFinding {
		const packageName = pkg.package?.name || 'dependency';
		const id = vulnerability.id || vulnerability.aliases?.[0] || 'OSV-UNKNOWN';
		const aliases = vulnerability.aliases ?? [];
		const lockfile = result.source?.path && path.isAbsolute(result.source.path) ? result.source.path : path.join(root, result.source?.path || 'pubspec.lock');
		const line = context.line ?? 1;
		const cvss = getCvss(vulnerability);
		const fixed = getFixedVersions(vulnerability);
		const affected = getAffectedRanges(vulnerability);
		const directness = context.directness ?? 'dependency';
		return createFinding({
			title: `${id} in ${packageName}${aliases.length ? ` (${aliases.join(', ')})` : ''}`,
			description: vulnerability.summary || vulnerability.details || `${packageName} ${pkg.package?.version || ''} is affected by ${id}.`,
			severity: normalizeSeverity(vulnerability.database_specific?.severity || (cvss !== undefined && cvss >= 9 ? 'Critical' : cvss !== undefined && cvss >= 7 ? 'High' : 'Medium')),
			cwe: [],
			owasp: ['A06:2021-Vulnerable and Outdated Components'],
			cvss,
			file: lockfile,
			line,
			column: 1,
			sourceTool: 'OSV-Scanner',
			ruleId: id,
			confidence: 'High',
			remediation: fixed ? `Upgrade ${packageName} to ${fixed}.` : `Upgrade ${packageName} to a non-affected version or apply the vendor mitigation.`,
			tags: ['dependency', 'sca', 'osv', directness],
			rawEvidence: { id, aliases, package: pkg.package, affected, fixedVersion: fixed, source: result.source },
		});
	}
}

function safeJson<T>(value: string): T | undefined { try { return JSON.parse(value) as T; } catch { return undefined; } }
function getCvss(vulnerability: OsvVulnerability): number | undefined {
	const value = vulnerability.database_specific?.cvss;
	if (typeof value === 'object' && typeof value.score === 'number') { return value.score; }
	if (typeof value === 'string') {
		const score = Number(value);
		if (Number.isFinite(score)) { return score; }
	}
	const score = vulnerability.severity?.find((item) => item.score)?.score;
	const match = score?.match(/(?:AV:[^/]+\/?.*)?([0-9]+(?:\.[0-9]+)?)/);
	return match ? Number(match[1]) : undefined;
}
function getFixedVersions(vulnerability: OsvVulnerability): string | undefined {
	const fixed = (vulnerability.affected?.flatMap((item) => item.ranges ?? []).flatMap((range) => range.events ?? []).map((event) => event.fixed).filter(Boolean) ?? []) as string[];
	return fixed.length ? fixed.join(', ') : undefined;
}
function getAffectedRanges(vulnerability: OsvVulnerability): string[] {
	return vulnerability.affected?.flatMap((item) => item.ranges ?? []).flatMap((range) => (range.events ?? []).map((event) => event.introduced ? `introduced:${event.introduced}` : event.fixed ? `fixed:${event.fixed}` : '')) .filter(Boolean) as string[] ?? [];
}
function escapeRegExp(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
