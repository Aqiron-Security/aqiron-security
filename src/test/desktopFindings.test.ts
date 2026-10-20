import * as assert from 'assert';
import * as path from 'path';
import { createFinding } from '../../packages/core/src/shared/finding';
import { countFindings, mapFinding } from '../../packages/desktop/src/findings';

suite('Desktop finding adapter', () => {
	test('maps Core findings into the shared Findings screen model and severity counts', () => {
		const root = path.resolve('workspace');
		const finding = createFinding({
			title: 'Exposed secret', description: 'Rotate this credential.', severity: 'High', cwe: ['CWE-798'], owasp: ['A07'],
			file: path.join(root, 'lib', 'main.dart'), line: 12, column: 4, sourceTool: 'Aqiron', ruleId: 'secret.literal',
			confidence: 'High', remediation: 'Rotate and replace the credential.', tags: ['secret'], rawEvidence: { lineText: 'secret = ...' },
		});
		const issue = mapFinding(finding, root);
		assert.equal(issue.relativeFile, path.join('lib', 'main.dart'));
		assert.equal(issue.line, 12);
		assert.equal(issue.message, 'Rotate this credential.');
		assert.deepEqual(countFindings([issue]), { total: 1, critical: 0, high: 1, medium: 0, low: 0, filesAffected: 1 });
	});
});
