import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import { CoreScanService } from '../../packages/core/src/orchestration';
import { CoreScanRequest } from '../../packages/core/src/orchestration/types';
import { NativeWorkspaceScanner } from '../../packages/core/src/scanners/native/nativeScanner';
import { ScannerManager } from '../../packages/core/src/scanners';
import { FileSystem } from '../../packages/core/src/shared/platform';
import { PipelineEvent, PipelineEventBus } from '../../packages/core/src/shared/pipeline';
import { scanContent } from '../scanner/rules';

const cases = [
	{ line: 'const api_key = "0123456789abcdef";', id: 'critical.api-key' },
	{ line: 'const aws = "AKIA1234567890ABCDEF";', id: 'critical.api-key' },
	{ line: 'const google = "AIza12345678901234567890123456789012345";', id: 'critical.api-key' },
	{ line: 'const provider = "sk_live_12345678901234567890";', id: 'critical.api-key' },
	{ line: 'const secret = "0123456789abcdef";', id: 'critical.secret' },
	{ line: 'const token = "0123456789abcdef";', id: 'critical.secret' },
	{ line: 'const password = "12345678";', id: 'critical.password' },
	{ line: '-----BEGIN RSA PRIVATE KEY-----', id: 'critical.private-key' },
];

suite('Core deterministic secret parity', () => {
	test('covers characterized legacy patterns with the same IDs, critical severity, and source ranges', async () => {
		const content = cases.map(item => item.line).join('\n');
		const result = await new NativeWorkspaceScanner({} as never).scanFileContent('src/secrets.js', content, 'secret-parity', filePolicy);
		const findings = result.findings.filter(finding => finding.ruleId.startsWith('critical.'));
		assert.deepEqual(findings.map(finding => finding.ruleId), cases.map(item => item.id));
		assert.deepEqual(findings.map(finding => [finding.line, finding.column, finding.endColumn]), cases.map((item, index) => {
			const match = legacyMatch(item.line);
			return [index + 1, match.index + 1, match.index + match.length + 1];
		}));
		assert.ok(findings.every(finding => finding.severity === 'Critical'));
		assert.ok(findings.every(finding => finding.tags.includes('secret')));
		for (const [index, finding] of findings.entries()) {
			const legacy = scanContent('src/secrets.js', cases[index].line).find(issue => issue.ruleId.startsWith('critical.'));
			assert.equal(finding.title, legacy?.title);
			assert.equal(finding.description, legacy?.message);
		}
	});

	test('keeps legacy case rules and rejects short or malformed lookalikes', async () => {
		const lines = [
			'const API_KEY = "0123456789abcdef";',
			'const SECRET = "0123456789abcdef";',
			'const TOKEN = "0123456789abcdef";',
			'const PASSWORD = "12345678";',
			'const aws = "akia1234567890abcd";',
			'const provider = "SK_live_12345678901234567890";',
			'-----begin RSA PRIVATE KEY-----',
			'const secret = "short";',
			'const ordinary = "just-a-normal-value";',
		];
		const result = await new NativeWorkspaceScanner({} as never).scanFileContent('src/secrets.ts', lines.join('\n'), 'secret-case', filePolicy);
		const expected = ['critical.api-key', 'critical.secret', 'critical.secret', 'critical.password'];
		assert.deepEqual(result.findings.filter(finding => finding.ruleId.startsWith('critical.')).map(finding => finding.ruleId), expected);
		assert.deepEqual(scanContent('src/secrets.ts', lines.join('\n')).filter(issue => issue.ruleId.startsWith('critical.')).map(issue => issue.ruleId), expected);
	});

	test('retains the previous Dart-only shorter-literal fallback without duplicating legacy matches', async () => {
		const scanner = new NativeWorkspaceScanner({} as never);
		const fallback = await scanner.scanFileContent('lib/config.dart', 'const apiKey = "short1234";', 'dart-secret-fallback', filePolicy);
		assert.ok(fallback.findings.some(finding => finding.ruleId === 'native.dart.hardcoded-secret'));
		assert.equal(fallback.findings.some(finding => finding.ruleId === 'critical.api-key'), false);
		assert.equal(fallback.findings.find(finding => finding.ruleId === 'native.dart.hardcoded-secret')?.rawEvidence, undefined);
	});

	test('fixture parity compares every legacy secret class against Core', async () => {
		const fixturePath = path.resolve(__dirname, '../../../src/test/fixtures/core-secrets/legacy-patterns.txt');
		const fixture = await fs.readFile(fixturePath, 'utf8');
		const sourcePath = fixturePath.replace(/\.txt$/, '.js');
		const legacy = scanContent(sourcePath, fixture).filter(issue => issue.ruleId.startsWith('critical.'));
		const core = await new NativeWorkspaceScanner({} as never).scanFileContent(sourcePath, fixture, 'fixture-parity', filePolicy);
		const coreSecrets = core.findings.filter(finding => finding.ruleId.startsWith('critical.'));
		assert.deepEqual(legacy.map(issue => issue.ruleId), cases.map(item => item.id));
		assert.deepEqual(coreSecrets.map(finding => finding.ruleId), legacy.map(issue => issue.ruleId));
		for (const [index, finding] of coreSecrets.entries()) {
			assert.equal(finding.severity, legacy[index].severity);
			assert.deepEqual([finding.line, finding.column, finding.endColumn], [legacy[index].range.startLine + 1, legacy[index].range.startColumn + 1, legacy[index].range.endColumn + 1]);
		}
	});

	test('workspace scan applies portable secret rules across the characterized supported file scope', async () => {
		const root = '/fixture';
		const filePath = `${root}/src/config.js`;
		const filesystem = memoryFileSystem(root, 'src', 'config.js', '// const secret = "commented-secret-value-1234";\nconst api_key = "0123456789abcdef";');
		const result = await new NativeWorkspaceScanner(filesystem).scanWorkspace(root);
		assert.equal(result.filesScanned, 1);
		assert.deepEqual(result.findings.map(finding => finding.ruleId), ['critical.api-key']);
		assert.equal(path.normalize(result.findings[0].file), path.normalize(filePath));
	});

	test('secret values do not appear in Core finding events or telemetry', async () => {
		const secret = 'dummy-secret-value-never-log-123456';
		const root = '/fixture';
		const filesystem = memoryFileSystem(root, 'src', 'main.dart', `debugPrint('secret = "${secret}"');`);
		const nativeScanner = new NativeWorkspaceScanner(filesystem);
		const events: PipelineEvent[] = [];
		const emitter = new PipelineEventBus();
		emitter.on(event => events.push(event));
		const request: CoreScanRequest = {
			scanId: 'secret-safe-scan', workspaceRoot: root, mode: 'quick', emitter,
			scannerContext: { workspaceRoot: root, targetPath: root, mode: 'quick' } as CoreScanRequest['scannerContext'],
			nativeScanner, scannerManager: new ScannerManager(),
			reportGenerator: { async generate() { return { model: {} } as never; } } as CoreScanRequest['reportGenerator'],
		};
		const result = await new CoreScanService().run(request);
		const serialized = JSON.stringify({ events, telemetry: result.telemetry, findings: result.findings, report: result.report });
		assert.ok(result.findings.some(finding => finding.ruleId === 'critical.secret'));
		assert.ok(!serialized.includes(secret));
		assert.ok(events.some(event => event.type === 'finding' && event.finding.ruleId === 'critical.secret'));
		assert.equal(result.telemetry.findings, result.findings.length);
	});
});

const filePolicy = {
	supportedExtensions: ['.js', '.ts', '.dart', '.py', '.xml', '.json', '.yaml', '.yml', '.gradle', '.rules', '.rs', '.java', '.c', '.cpp', '.h'],
	excludedPaths: [], maxFileSizeBytes: null, skipGeneratedFiles: false, skipMinifiedFiles: false,
	skipCompiledFiles: false, eligible: true, customRules: [],
};

function legacyMatch(line: string): { index: number; length: number } {
	const issue = scanContent('fixture.js', line).find(item => item.ruleId.startsWith('critical.'));
	assert.ok(issue);
	return { index: issue.range.startColumn, length: issue.range.endColumn - issue.range.startColumn };
}

function memoryFileSystem(root: string, directoryName: string, fileName: string, content: string): FileSystem {
	const rootPath = path.normalize(root);
	const directoryPath = path.join(rootPath, directoryName);
	return {
		async readdir(directory: string) {
			const normalized = path.normalize(directory);
			if (normalized === rootPath) {return [{ name: directoryName, isDirectory: () => true, isFile: () => false }];}
			if (normalized === directoryPath) {return [{ name: fileName, isDirectory: () => false, isFile: () => true }];}
			return [];
		},
		async readFile() {return content;},
	} as unknown as FileSystem;
}
