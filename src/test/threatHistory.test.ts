import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { AqironIssue } from '../models/issue';
import { ThreatHistoryService } from '../security/threatHistoryService';

suite('Threat history', () => {
	test('persists completed scan results in the hidden workspace folder', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-threat-history-'));
		try {
			const history = new ThreatHistoryService();
			const snapshots = await history.record(root, [fixtureIssue()], 12);
			assert.strictEqual(snapshots.length, 1);
			assert.strictEqual(snapshots[0].issues[0].id, 'finding-1');
			await fs.access(path.join(root, '.aqiron-security', 'threats.json'));
			const loaded = await history.load(root);
			assert.strictEqual(loaded[0].filesScanned, 12);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});

function fixtureIssue(): AqironIssue {
	return {
		id: 'finding-1',
		file: '/workspace/lib/main.dart',
		title: 'Test finding',
		message: 'Fixture finding for storage verification.',
		severity: 'High',
		ruleId: 'high.test',
		range: { file: '/workspace/lib/main.dart', startLine: 1, startColumn: 0, endLine: 1, endColumn: 4 },
		lineText: 'final token = value;',
	};
}
