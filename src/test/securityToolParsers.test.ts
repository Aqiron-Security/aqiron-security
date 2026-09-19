import * as assert from 'assert';
import { BetterleaksParser } from '../security/parsers/betterleaksParser';
import { OsvScannerParser } from '../security/parsers/osvScannerParser';

suite('Security tool parsers', () => {
	test('redacts Betterleaks secret evidence and preserves location', () => {
		const secret = 'super-secret-value';
		const findings = new BetterleaksParser().parse(JSON.stringify([{ RuleID: 'aws-access-key', Description: 'AWS access key', File: 'lib/main.dart', StartLine: 7, StartColumn: 4, Secret: secret, Match: secret }]), 'C:\\workspace');
		assert.strictEqual(findings.length, 1);
		assert.strictEqual(findings[0].sourceTool, 'Betterleaks');
		assert.strictEqual(findings[0].line, 7);
		assert.strictEqual(findings[0].column, 4);
		assert.ok(!JSON.stringify(findings[0]).includes(secret));
	});

	test('parses OSV aliases and multiple vulnerabilities', () => {
		const output = JSON.stringify({ results: [{ source: { path: 'pubspec.lock', type: 'lockfile' }, packages: [{ package: { name: 'http', version: '0.13.0', ecosystem: 'Pub' }, vulnerabilities: [{ id: 'GHSA-test', aliases: ['CVE-2024-0001'], summary: 'Example issue', database_specific: { cvss: { score: 8.1 } } }, { id: 'OSV-TEST-2', summary: 'Second issue' }] }] }] });
		const findings = new OsvScannerParser().parse(output, 'C:\\workspace');
		assert.strictEqual(findings.length, 2);
		assert.strictEqual(findings[0].sourceTool, 'OSV-Scanner');
		assert.ok(findings[0].title.includes('CVE-2024-0001'));
		assert.strictEqual(findings[0].cvss, 8.1);
	});

	test('returns no findings for malformed or empty output', () => {
		assert.throws(() => new BetterleaksParser().parse('{bad json', 'C:\\workspace'), /malformed JSON/);
		assert.throws(() => new OsvScannerParser().parse('{bad json', 'C:\\workspace'), /malformed JSON/);
		assert.deepStrictEqual(new OsvScannerParser().parse(JSON.stringify({ results: [] }), 'C:\\workspace'), []);
	});
});
