import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { CoreScanService } from '../../packages/core/src/orchestration';
import { CoreScanRequest } from '../../packages/core/src/orchestration/types';
import { NativeWorkspaceScanner } from '../../packages/core/src/scanners/native/nativeScanner';
import { ScannerManager } from '../../packages/core/src/scanners';
import { FileSystem } from '../../packages/core/src/shared/platform';
import { PipelineEvent, PipelineEventBus } from '../../packages/core/src/shared/pipeline';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';
import { ResolvedWorkspaceScanPolicy } from '../../packages/core/src/shared/workspaceScanPolicy';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';

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
		assert.deepEqual(findings.map(finding => [finding.line, finding.column, finding.endColumn]), [
			[1, 7, 35], [2, 14, 34], [3, 17, 56], [4, 19, 47],
			[5, 7, 34], [6, 7, 33], [7, 7, 28], [8, 1, 32],
		]);
		assert.ok(findings.every(finding => finding.severity === 'Critical'));
		assert.ok(findings.every(finding => finding.tags.includes('secret')));
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
	});

	test('retains the previous Dart-only shorter-literal fallback without duplicating legacy matches', async () => {
		const scanner = new NativeWorkspaceScanner({} as never);
		const fallback = await scanner.scanFileContent('lib/config.dart', 'const apiKey = "short1234";', 'dart-secret-fallback', filePolicy);
		assert.ok(fallback.findings.some(finding => finding.ruleId === 'native.dart.hardcoded-secret'));
		assert.equal(fallback.findings.some(finding => finding.ruleId === 'critical.api-key'), false);
		assert.equal(fallback.findings.find(finding => finding.ruleId === 'native.dart.hardcoded-secret')?.rawEvidence, undefined);
	});

	test('fixture covers every characterized secret class in Core', async () => {
		const fixturePath = path.resolve(__dirname, '../../../src/test/fixtures/core-secrets/legacy-patterns.txt');
		const fixture = await fs.readFile(fixturePath, 'utf8');
		const sourcePath = fixturePath.replace(/\.txt$/, '.js');
		const core = await new NativeWorkspaceScanner({} as never).scanFileContent(sourcePath, fixture, 'fixture-parity', filePolicy);
		const coreSecrets = core.findings.filter(finding => finding.ruleId.startsWith('critical.'));
		assert.deepEqual(coreSecrets.map(finding => finding.ruleId), cases.map(item => item.id));
		assert.ok(coreSecrets.every(finding => finding.severity === 'Critical' && (finding.endColumn ?? 0) > finding.column));
	});

	test('workspace scan applies portable secret rules across the characterized supported file scope', async () => {
		const root = '/fixture';
		const filePath = `${root}/src/config.js`;
		const filesystem = memoryFileSystem(root, 'src', 'config.js', '// const secret = "commented-secret-value-1234";\nconst api_key = "0123456789abcdef";');
		const scanner = new NativeWorkspaceScanner(filesystem);
		const result = await scanner.scanWorkspace(root);
		const directFileResult = await scanner.scanFileContent(filePath, '// const secret = "commented-secret-value-1234";\nconst api_key = "0123456789abcdef";', 'direct-identity', filePolicy);
		assert.equal(result.filesScanned, 1);
		assert.deepEqual(result.findings.map(finding => finding.ruleId), ['critical.api-key']);
		assert.equal(path.normalize(result.findings[0].file), path.normalize(filePath));
		assert.equal(result.findings[0].id, directFileResult.findings.find(finding => finding.ruleId === 'critical.api-key')?.id, 'workspace scan requests without explicit policy retain the existing finding identity');
	});

	test('workspace scan honors resolved extensions, .aq negation, exclusions, file policy, size, and custom rules', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-workspace-policy-'));
		try {
			const files: Record<string, string> = {
				'secret/blocked.js': 'const secret = "blocked-secret-value-123";',
				'secret/keep.js': 'const secret = "0123456789abcdef";\ncredentialMarker();',
				'vendor/hidden.js': 'const token = "vendor-secret-value-123";',
				'lib/model.generated.js': 'const token = "generated-secret-value-123";',
				'lib/bundle.min.js': 'x'.repeat(1200),
				'lib/large.js': 'x'.repeat(1500),
				'lib/notes.txt': 'const secret = "unsupported-secret-value-123";',
				'lib/clean.js': 'const safe = true;',
			};
			for (const [relative, content] of Object.entries(files)) {
				const target = path.join(root, relative);
				await fs.mkdir(path.dirname(target), { recursive: true });
				await fs.writeFile(target, content, 'utf8');
			}
			await fs.writeFile(path.join(root, '.aq'), 'secret/\n!secret/keep.js\n', 'utf8');
			const policy: ResolvedWorkspaceScanPolicy = {
				supportedExtensions: ['.js'],
				excludedDirectoryPaths: ['vendor'],
				excludedFileNamePatterns: ['*.generated.*'],
				aqExclusionPatterns: ['secret/', '!secret/keep.js'],
				maxFileSizeBytes: 1400,
				customRules: [{ id: 'critical.secret.custom', title: 'Custom secret marker', message: 'Review this marker.', severity: 'High', pattern: 'credentialMarker', extensions: ['.js'] }],
				skipGeneratedFiles: true,
				skipMinifiedFiles: true,
				skipCompiledFiles: true,
			};
			const result = await new NativeWorkspaceScanner(createNodeFileSystem()).scanWorkspace(root, undefined, policy);
			assert.equal(result.filesScanned, 2, 'only the .aq re-included file and clean eligible file count as scanned');
			assert.deepEqual(result.findings.filter(finding => finding.ruleId.startsWith('critical.secret')).map(finding => finding.ruleId), ['critical.secret', 'critical.secret.custom']);
			assert.ok(result.findings.filter(finding => finding.ruleId.startsWith('critical.secret')).every(finding => path.join(root, 'secret', 'keep.js') === finding.file));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('scan.start rejects malformed resolved workspace policy before scanning', async () => {
		const runtime = new CoreRuntime({ coreVersion: 'secret-policy-validation' });
		const response = await runtime.handle({
			id: 'bad-workspace-policy', type: 'request', method: 'scan.start',
			params: { workspaceRoot: '/fixture', trusted: false, workspacePolicy: {
				supportedExtensions: ['.js'], excludedDirectoryPaths: [], excludedFileNamePatterns: [], aqExclusionPatterns: [],
				maxFileSizeBytes: -1, customRules: [], skipGeneratedFiles: true, skipMinifiedFiles: true, skipCompiledFiles: true,
			} },
		}, () => undefined);
		assert.equal(response.success, false);
		assert.equal(response.error?.code, 'CORE_INVALID_REQUEST');
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
