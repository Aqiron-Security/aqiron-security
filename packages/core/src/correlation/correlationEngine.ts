import { calculateRiskScore, createFinding, UnifiedFinding } from '../findings/finding';

export interface CorrelationResult {
	findings: UnifiedFinding[];
	relationships: CorrelatedRelationship[];
	summary: {
		deduplicated: number;
		boosted: number;
		attackPaths: number;
	};
}

export interface CorrelatedRelationship {
	sourceId: string;
	targetId: string;
	type: 'duplicate-of' | 'same-file' | 'secret-to-dependency' | 'dependency-to-source' | 'malware-to-artifact' | 'attack-path';
	weight: number;
	reason: string;
}

export class ThreatCorrelationEngine {
	correlate(findings: readonly UnifiedFinding[]): CorrelationResult {
		const deduped = this.dedupe(findings);
		const relationships = this.buildRelationships(deduped);
		const boosted = this.applySeverityBoosting(deduped, relationships);
		const attackPaths = relationships.filter((relationship) => relationship.type === 'attack-path').length;
		return {
			findings: boosted,
			relationships,
			summary: {
				deduplicated: findings.length - deduped.length,
				boosted: boosted.filter((finding, index) => finding.riskScore > deduped[index]?.riskScore).length,
				attackPaths,
			},
		};
	}

	private dedupe(findings: readonly UnifiedFinding[]): UnifiedFinding[] {
		const byKey = new Map<string, UnifiedFinding>();
		for (const finding of findings) {
			const key = [finding.file.toLowerCase(), finding.line, normalizeRule(finding.ruleId), finding.title.toLowerCase()].join('|');
			const existing = byKey.get(key);
			if (!existing || finding.riskScore > existing.riskScore) {
				byKey.set(key, finding);
			}
		}
		return [...byKey.values()].sort((left, right) => right.riskScore - left.riskScore);
	}

	private buildRelationships(findings: readonly UnifiedFinding[]): CorrelatedRelationship[] {
		const relationships: CorrelatedRelationship[] = [];
		for (let leftIndex = 0; leftIndex < findings.length; leftIndex++) {
			for (let rightIndex = leftIndex + 1; rightIndex < findings.length; rightIndex++) {
				const left = findings[leftIndex];
				const right = findings[rightIndex];
				if (left.file === right.file) {
					relationships.push({ sourceId: left.id, targetId: right.id, type: 'same-file', weight: 0.35, reason: 'Findings share source evidence in the same file.' });
				}
				if (hasTag(left, 'dependency') && hasTag(right, 'sast')) {
					relationships.push({ sourceId: left.id, targetId: right.id, type: 'dependency-to-source', weight: 0.55, reason: 'Dependency vulnerability may be reachable from application source.' });
				}
				if (hasTag(left, 'secret') && hasTag(right, 'dependency')) {
					relationships.push({ sourceId: left.id, targetId: right.id, type: 'secret-to-dependency', weight: 0.7, reason: 'Leaked credential and vulnerable dependency can amplify exploitability.' });
				}
				if (hasTag(left, 'malware') && /apk|android|asset/i.test(right.file)) {
					relationships.push({ sourceId: left.id, targetId: right.id, type: 'malware-to-artifact', weight: 0.75, reason: 'Malware signature is tied to a mobile or packaged artifact.' });
				}
			}
		}

		const hasSecret = findings.some((finding) => hasTag(finding, 'secret'));
		const hasSastHigh = findings.some((finding) => hasTag(finding, 'sast') && ['Critical', 'High'].includes(finding.severity));
		const hasDependency = findings.some((finding) => hasTag(finding, 'dependency'));
		if (hasSecret && hasSastHigh && hasDependency) {
			const source = findings.find((finding) => hasTag(finding, 'secret'));
			const target = findings.find((finding) => hasTag(finding, 'sast') && ['Critical', 'High'].includes(finding.severity));
			if (source && target) {
				relationships.push({ sourceId: source.id, targetId: target.id, type: 'attack-path', weight: 0.9, reason: 'Credential exposure, vulnerable dependency, and source weakness form a plausible attack path.' });
			}
		}
		return relationships;
	}

	private applySeverityBoosting(findings: readonly UnifiedFinding[], relationships: readonly CorrelatedRelationship[]): UnifiedFinding[] {
		return findings.map((finding) => {
			const weight = relationships
				.filter((relationship) => relationship.sourceId === finding.id || relationship.targetId === finding.id)
				.reduce((total, relationship) => total + relationship.weight, 0);
			if (weight < 0.7) {
				return finding;
			}
			const riskScore = Math.min(100, finding.riskScore + Math.round(weight * 8));
			const severity = riskScore >= 90 ? 'Critical' : riskScore >= 70 ? 'High' : riskScore >= 40 ? 'Medium' : 'Low';
			return createFinding({
				...finding,
				severity,
				riskScore,
				tags: [...new Set([...finding.tags, 'correlated'])],
				remediation: finding.remediation,
				graph: {
					...finding.graph,
					edges: [
						...finding.graph.edges,
						...relationships
							.filter((relationship) => relationship.sourceId === finding.id || relationship.targetId === finding.id)
							.map((relationship) => ({
								targetId: relationship.sourceId === finding.id ? relationship.targetId : relationship.sourceId,
								type: 'correlates-with' as const,
							})),
					],
				},
				fingerprint: finding.fingerprint,
				status: finding.status,
				cvss: finding.cvss,
				confidence: finding.confidence,
				rawEvidence: finding.rawEvidence,
				sourceTool: finding.sourceTool,
				ruleId: finding.ruleId,
				cwe: finding.cwe,
				owasp: finding.owasp,
				file: finding.file,
				line: finding.line,
				column: finding.column,
				title: finding.title,
				description: finding.description,
			});
		});
	}
}

function normalizeRule(ruleId: string): string {
	return ruleId.replace(/^CVE-\d{4}-/i, 'cve-').toLowerCase();
}

function hasTag(finding: UnifiedFinding, tag: string): boolean {
	return finding.tags.some((candidate) => candidate.toLowerCase().includes(tag));
}
