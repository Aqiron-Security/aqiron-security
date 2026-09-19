/**
 * Threat Intelligence Aggregation Service
 * Collects, normalizes, and filters findings from all security scanners
 */

import { UnifiedFinding } from '../findings/finding';
import { VulnerabilityEnvelope, SourceType, VulnerabilityCategory, normalizeSeverityToStandard, inferSourceType, createVulnerabilityFingerprint } from '../parsers/vulnerabilitySchema';
import { EngineFieldMapper, getMapperForEngine } from '../parsers/engineMappers';

export interface ThreatIntelligenceFilter {
	sourceTypes?: SourceType[];
	categories?: VulnerabilityCategory[];
	severities?: string[];
	engines?: string[];
	tagsIncludeAny?: string[];
	tagsExcludeAll?: string[];
}

export interface AggregatedThreatIntelligence {
	total: number;
	byEngine: Record<string, number>;
	byCategory: Record<VulnerabilityCategory, number>;
	bySeverity: Record<string, number>;
	bySourceType: Record<SourceType, number>;
	findings: VulnerabilityEnvelope[];
	deduplicatedCount: number;
}

export class ThreatIntelligenceAggregator {
	private mapper = new Map<string, EngineFieldMapper>();
	private seenFingerprints = new Set<string>();

	/**
	 * Register engine-specific mapper
	 */
	registerMapper(engine: string, mapper: EngineFieldMapper): void {
		this.mapper.set(engine.toLowerCase(), mapper);
	}

	/**
	 * Aggregate findings from all sources
	 */
	aggregate(
		findings: UnifiedFinding[],
		engineName: string = 'Unknown'
	): VulnerabilityEnvelope[] {
		const mapper = this.mapper.get(engineName.toLowerCase()) || getMapperForEngine(engineName);
		
		return findings.map(finding => this.normalizeUnifiedFinding(finding, engineName, mapper));
	}

	/**
	 * Convert UnifiedFinding to VulnerabilityEnvelope
	 */
	private normalizeUnifiedFinding(
		finding: UnifiedFinding,
		engine: string,
		mapper: EngineFieldMapper
	): VulnerabilityEnvelope {
		const raw = (finding.rawEvidence as Record<string, unknown>) || {};
		const tags = finding.tags || [];
		const sourceType = inferSourceType(engine, tags);
		
		return {
			engine,
			rule_id: finding.ruleId,
			title: finding.title,
			description: finding.description,
			severity: normalizeSeverityToStandard(finding.severity),
			file: finding.file,
			line: finding.line,
			column: finding.column,
			endLine: finding.endLine,
			endColumn: finding.endColumn,
			category: this.inferCategory(finding),
			confidence: finding.confidence as 'low' | 'medium' | 'high',
			tags: finding.tags,
			source_type: sourceType,
			cwe: finding.cwe,
			owasp: finding.owasp,
			cvss: finding.cvss,
			remediation: finding.remediation,
			raw,
		};
	}

	/**
	 * Infer vulnerability category from findings
	 */
	private inferCategory(finding: UnifiedFinding): VulnerabilityCategory {
		const tags = finding.tags || [];
		const title = finding.title.toLowerCase();
		const ruleId = finding.ruleId.toLowerCase();
		
		if (tags.includes('secret') || title.includes('secret') || title.includes('credential')) {
			return 'secret';
		}
		if (tags.includes('cve') || tags.includes('vulnerability') || title.includes('cve')) {
			return 'cve';
		}
		if (tags.includes('malware')) {
			return 'malware';
		}
		if (tags.includes('permission') || title.includes('permission')) {
			return 'permission';
		}
		if (tags.includes('dependency') || tags.includes('sca')) {
			return 'dependency';
		}
		if (tags.includes('config') || tags.includes('configuration')) {
			return 'config';
		}
		
		return 'insecure-code';
	}

	/**
	 * Deduplicate findings by fingerprint
	 */
	deduplicate(envelopes: VulnerabilityEnvelope[]): VulnerabilityEnvelope[] {
		this.seenFingerprints.clear();
		const deduplicated: VulnerabilityEnvelope[] = [];
		
		for (const envelope of envelopes) {
			const fingerprint = createVulnerabilityFingerprint(
				envelope.engine,
				envelope.rule_id,
				envelope.file,
				envelope.line,
				envelope.title
			);
			
			if (!this.seenFingerprints.has(fingerprint)) {
				this.seenFingerprints.add(fingerprint);
				deduplicated.push(envelope);
			}
		}
		
		return deduplicated;
	}

	/**
	 * Filter findings by criteria
	 */
	filter(envelopes: VulnerabilityEnvelope[], criteria: ThreatIntelligenceFilter): VulnerabilityEnvelope[] {
		return envelopes.filter(envelope => {
			// Source type filter
			if (criteria.sourceTypes && !criteria.sourceTypes.includes(envelope.source_type)) {
				return false;
			}
			
			// Category filter
			if (criteria.categories && !criteria.categories.includes(envelope.category)) {
				return false;
			}
			
			// Severity filter
			if (criteria.severities && !criteria.severities.includes(envelope.severity)) {
				return false;
			}
			
			// Engine filter
			if (criteria.engines && !criteria.engines.some(e => e.toLowerCase() === envelope.engine.toLowerCase())) {
				return false;
			}
			
			// Tags include any
			if (criteria.tagsIncludeAny && criteria.tagsIncludeAny.length > 0) {
				const hasTag = envelope.tags.some(tag => criteria.tagsIncludeAny!.includes(tag));
				if (!hasTag) {
					return false;
				}
			}
			
			// Tags exclude all
			if (criteria.tagsExcludeAll && criteria.tagsExcludeAll.length > 0) {
				const hasExcluded = envelope.tags.some(tag => criteria.tagsExcludeAll!.includes(tag));
				if (hasExcluded) {
					return false;
				}
			}
			
			return true;
		});
	}

	/**
	 * Build aggregated statistics
	 */
	buildStatistics(envelopes: VulnerabilityEnvelope[]): Omit<AggregatedThreatIntelligence, 'findings'> {
		const stats = {
			total: envelopes.length,
			byEngine: {} as Record<string, number>,
			byCategory: {} as Record<VulnerabilityCategory, number>,
			bySeverity: {} as Record<string, number>,
			bySourceType: {} as Record<SourceType, number>,
			deduplicatedCount: this.seenFingerprints.size,
		};
		
		for (const envelope of envelopes) {
			stats.byEngine[envelope.engine] = (stats.byEngine[envelope.engine] || 0) + 1;
			stats.byCategory[envelope.category] = (stats.byCategory[envelope.category] || 0) + 1;
			stats.bySeverity[envelope.severity] = (stats.bySeverity[envelope.severity] || 0) + 1;
			stats.bySourceType[envelope.source_type] = (stats.bySourceType[envelope.source_type] || 0) + 1;
		}
		
		return stats;
	}

	/**
	 * Complete aggregation pipeline
	 */
	async aggregateAll(
		findingsByEngine: Map<string, UnifiedFinding[]>
	): Promise<AggregatedThreatIntelligence> {
		const allEnvelopes: VulnerabilityEnvelope[] = [];
		
		// Normalize findings from each engine
		for (const [engine, findings] of findingsByEngine) {
			const envelopes = this.aggregate(findings, engine);
			allEnvelopes.push(...envelopes);
		}
		
		// Deduplicate
		const deduplicated = this.deduplicate(allEnvelopes);
		
		// Build statistics
		const stats = this.buildStatistics(deduplicated);
		
		return {
			...stats,
			findings: deduplicated,
		};
	}

	/**
	 * Filter aggregated findings
	 */
	filterAggregation(
		aggregation: AggregatedThreatIntelligence,
		criteria: ThreatIntelligenceFilter
	): AggregatedThreatIntelligence {
		const filtered = this.filter(aggregation.findings, criteria);
		const stats = this.buildStatistics(filtered);
		
		return {
			...stats,
			findings: filtered,
		};
	}

	/**
	 * Get common filters for dashboard
	 */
	static getCommonFilters() {
		return {
			sourceCodeOnly: {
				sourceTypes: ['source'],
			} as ThreatIntelligenceFilter,
			
			binaryOnly: {
				sourceTypes: ['binary'],
			} as ThreatIntelligenceFilter,
			
			secretsOnly: {
				categories: ['secret'],
			} as ThreatIntelligenceFilter,
			
			malwareOnly: {
				categories: ['malware'],
			} as ThreatIntelligenceFilter,
			
			cveOnly: {
				categories: ['cve'],
			} as ThreatIntelligenceFilter,
			
			highAndCritical: {
				severities: ['critical', 'high'],
			} as ThreatIntelligenceFilter,
			
			apkRisksOnly: {
				tagsIncludeAny: ['apk', 'mobile', 'android'],
				sourceTypes: ['binary'],
			} as ThreatIntelligenceFilter,
		};
	}
}
