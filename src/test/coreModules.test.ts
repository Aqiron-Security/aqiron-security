import * as assert from 'assert';
import { createFinding, ThreatCorrelationEngine, RelationshipGraphEngine, ThreatIntelligenceAggregator } from '../../packages/core/src';

suite('Core modules', () => {
	test('correlates findings and builds relationships', () => {
		const secret = createFinding({
			title: 'Leaked credential',
			description: 'Secret detected',
			severity: 'High',
			cwe: ['CWE-798'],
			owasp: ['A02:2021-Cryptographic Failures'],
			file: 'lib/auth.dart',
			line: 12,
			column: 4,
			sourceTool: 'Betterleaks',
			ruleId: 'secret.leak',
			confidence: 'High',
			remediation: 'Rotate the secret.',
			tags: ['secret'],
			rawEvidence: {},
		});
		const dependency = createFinding({
			title: 'Vulnerable package',
			description: 'Dependency issue',
			severity: 'High',
			cwe: [],
			owasp: ['A06:2021-Vulnerable and Outdated Components'],
			file: 'pubspec.lock',
			line: 2,
			column: 1,
			sourceTool: 'OSV-Scanner',
			ruleId: 'CVE-2024-0001',
			confidence: 'High',
			remediation: 'Upgrade the package.',
			tags: ['dependency'],
			rawEvidence: {},
		});
		const sast = createFinding({
			title: 'Unsafe eval',
			description: 'Code issue',
			severity: 'High',
			cwe: ['CWE-94'],
			owasp: ['A03:2021-Injection'],
			file: 'lib/auth.dart',
			line: 21,
			column: 2,
			sourceTool: 'Semgrep',
			ruleId: 'semgrep.unsafe-eval',
			confidence: 'High',
			remediation: 'Avoid dynamic evaluation.',
			tags: ['sast'],
			rawEvidence: {},
		});

		const correlation = new ThreatCorrelationEngine().correlate([secret, dependency, sast]);
		assert.strictEqual(correlation.summary.attackPaths, 1);
		assert.ok(correlation.relationships.length > 0);
		assert.ok(correlation.findings.some((finding) => finding.riskScore > 80));

		const graph = new RelationshipGraphEngine().build(correlation.findings, correlation.relationships);
		assert.ok(graph.nodes.some((node) => node.id === secret.id));
		assert.ok(graph.edges.some((edge) => edge.type === 'correlation'));
	});

	test('aggregates and deduplicates normalized findings', async () => {
		const finding = createFinding({
			title: 'Example dependency issue',
			description: 'Dependency issue',
			severity: 'Medium',
			cwe: [],
			owasp: ['A06:2021-Vulnerable and Outdated Components'],
			file: 'pubspec.lock',
			line: 3,
			column: 1,
			sourceTool: 'Semgrep',
			ruleId: 'semgrep.dependency',
			confidence: 'Medium',
			remediation: 'Upgrade the package.',
			tags: ['dependency', 'sca'],
			rawEvidence: {},
		});

		const aggregator = new ThreatIntelligenceAggregator();
		const aggregation = await aggregator.aggregateAll(new Map([['Semgrep', [finding, finding]]]));
		assert.strictEqual(aggregation.total, 1);
		assert.strictEqual(aggregation.deduplicatedCount, 1);
		assert.strictEqual(aggregation.byEngine.Semgrep, 1);
		assert.strictEqual(aggregation.byCategory.dependency, 1);
		assert.strictEqual(aggregation.bySourceType.source, 1);
	});
});
