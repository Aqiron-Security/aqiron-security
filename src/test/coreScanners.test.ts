import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { BetterleaksScanner, MobSfScanner, NativeWorkspaceScanner, OsvScanner, ScannerContext, ScannerManager, ScannerMode, SemgrepScanner, TrivyScanner } from '../../packages/core/src';
import { FileSystem, NetworkClient, ProcessRunOptions, ProcessRunResult, ProcessRunner } from '../../packages/core/src/shared/platform';
import { createNodeFileSystem } from '../../packages/core/src/runtime/nodeAdapters';

suite('Core scanners', () => {
	test('scanner manager registers and selects scanners by mode', async () => {
		const manager = new ScannerManager();
		manager.register(fakeScanner('semgrep', ['source-code']));
		manager.register(fakeScanner('trivy', ['dependency']));
		manager.register(fakeScanner('betterleaks', ['secret', 'source-code']));
		const context = fakeContext('deep');
		const selection = await manager.discoverAvailable(context);
		assert.strictEqual(selection.length, 3);
		const quick = await manager.run({ ...context, mode: 'quick' });
		assert.strictEqual(quick.results.length, 2);
		assert.deepStrictEqual(quick.results.map((result) => result.toolId), ['semgrep', 'betterleaks']);
	});

	test('semgrep availability reports missing executables', async () => {
		const scanner = new SemgrepScanner();
		const context = fakeContext('deep', { processRunner: missingBinaryRunner() });
		const availability = await scanner.isAvailable(context);
		assert.strictEqual(availability.available, false);
	});

	test('trivy parses vulnerability output', async () => {
		const scanner = new TrivyScanner();
		const context = fakeContext('deep', {
			processRunner: runnerWithResponses({
				'trivy --version': okResult('trivy version 0.0.0'),
				'trivy fs /workspace --format json --scanners vuln,secret,config --skip-version-check --skip-dirs ': okResult(JSON.stringify({
					Results: [{
						Target: 'pubspec.lock',
						Class: 'filesystem',
						Type: 'package',
						Vulnerabilities: [{
							VulnerabilityID: 'CVE-2024-0001',
							PkgName: 'http',
							Severity: 'HIGH',
							Title: 'Example vuln',
							Description: 'Example vuln description',
							FixedVersion: '1.0.1',
						}],
					}],
				})),
			}),
		});
		const result = await scanner.scan(context);
		assert.strictEqual(result.findings.length, 1);
		assert.strictEqual(result.findings[0].sourceTool, 'Trivy');
	});

	test('betterleaks redacts secret evidence', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-betterleaks-'));
		try {
			await fs.writeFile(path.join(root, 'pubspec.yaml'), 'name: demo\nflutter:\n  sdk: flutter\n');
			await fs.mkdir(path.join(root, 'lib'), { recursive: true });
			await fs.writeFile(path.join(root, 'lib', 'main.dart'), 'const secret = "top-secret";\n');
			const scanner = new BetterleaksScanner();
			const context = fakeContext('deep', {
				workspaceRoot: root,
				targetPath: root,
				processRunner: runnerWithResponses({
					'betterleaks --version': okResult('betterleaks 1.0.0'),
					'betterleaks dir ': okResult(JSON.stringify([{ RuleID: 'test', Description: 'Secret found', File: 'lib/main.dart', StartLine: 1, StartColumn: 1, Secret: 'top-secret', Match: 'top-secret' }])),
				}),
				filesystem: createNodeFileSystem(),
			});
			const result = await scanner.scan(context);
			assert.strictEqual(result.findings.length, 1);
			assert.ok(!JSON.stringify(result.findings[0]).includes('top-secret'));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('osv scanner parses dependency findings', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-osv-'));
		try {
			await fs.writeFile(path.join(root, 'pubspec.yaml'), 'name: demo\ndependencies:\n  http: ^1.0.0\n');
			await fs.writeFile(path.join(root, 'pubspec.lock'), 'packages:\n  http:\n');
			const scanner = new OsvScanner();
			const context = fakeContext('deep', {
				workspaceRoot: root,
				targetPath: root,
				processRunner: runnerWithResponses({
					'osv-scanner --version': okResult('osv-scanner 1.0.0'),
					'osv-scanner scan source --format json -r ': okResult(JSON.stringify({
						results: [{
							packages: [{
								package: { name: 'http', version: '1.0.0' },
								vulnerabilities: [{ id: 'GHSA-test', aliases: ['CVE-2024-0002'], summary: 'Example issue' }],
							}],
						}],
					})),
				}),
				filesystem: createNodeFileSystem(),
			});
			const result = await scanner.scan(context);
			assert.strictEqual(result.findings.length, 1);
			assert.ok(result.findings[0].title.includes('CVE-2024-0002'));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('osv scanner falls back to the OSV API when the binary is missing', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-osv-api-'));
		try {
			await fs.writeFile(path.join(root, 'pubspec.lock'), 'packages:\n  http:\n    version: "1.0.0"\n');
			const scanner = new OsvScanner();
			const context = fakeContext('deep', {
				workspaceRoot: root,
				processRunner: missingBinaryRunner(),
				filesystem: createNodeFileSystem(),
				networkClient: {
					request: async () => ({ ok: true, status: 200, headers: {}, text: async () => '', json: async <T = unknown>() => ({ results: [{ vulns: [{ id: 'GHSA-api', summary: 'API fallback issue' }] }] } as T) }),
				} satisfies NetworkClient,
			});
			const availability = await scanner.isAvailable(context);
			assert.strictEqual(availability.available, true);
			const result = await scanner.scan(context);
			assert.strictEqual(result.findings.length, 1);
			assert.ok(result.findings[0].title.includes('GHSA-api'));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('native Core rules scan Flutter and container files without external SAST tools', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-native-'));
		try {
			await fs.mkdir(path.join(root, 'lib'), { recursive: true });
			await fs.writeFile(path.join(root, 'lib', 'main.dart'), 'const token = "secret-token-123456789";\nfinal url = "http://example.test";\n');
			await fs.writeFile(path.join(root, 'Dockerfile'), 'FROM python:3.12\nUSER root\n');
			const result = await new NativeWorkspaceScanner(createNodeFileSystem()).scanWorkspace(root);
			assert.strictEqual(result.filesScanned, 2);
			assert.ok(result.findings.some((finding) => finding.ruleId === 'native.dart.insecure-http'));
			assert.ok(result.findings.some((finding) => finding.ruleId === 'native.docker.root'));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('MobSF reports missing configuration', async () => {
		const scanner = new MobSfScanner();
		const context = fakeContext('deep', {
			configuration: { get: () => '' },
		});
		const availability = await scanner.isAvailable(context);
		assert.strictEqual(availability.available, false);
	});
});

function fakeScanner(id: string, capabilities: Array<'source-code' | 'dependency' | 'secret' | 'binary' | 'mobile' | 'artifact' | 'config'>) {
	return {
		id,
		name: id,
		capabilities,
		isAvailable: async () => ({ available: true }),
		scan: async () => ({ toolId: id, label: id, findings: [], durationMs: 0 }),
	};
}

function fakeContext(mode: ScannerMode, overrides: Partial<ScannerContext> = {}): ScannerContext {
	return {
		workspaceRoot: overrides.workspaceRoot ?? '/workspace',
		targetPath: overrides.targetPath ?? '/workspace',
		exclusions: overrides.exclusions ?? [],
		mode,
		configuration: overrides.configuration ?? { get: (_key: string, defaultValue?: unknown) => defaultValue as never },
		filesystem: overrides.filesystem ?? defaultFilesystem,
		processRunner: overrides.processRunner ?? runnerWithResponses({}),
		networkClient: overrides.networkClient,
		credentialStore: overrides.credentialStore,
		logger: overrides.logger,
		cancellationToken: overrides.cancellationToken,
		artifactPaths: overrides.artifactPaths,
		environment: overrides.environment,
		fileScope: overrides.fileScope,
	};
}

const defaultFilesystem: FileSystem = {
	readFile: defaultReadFile,
	writeFile: async () => undefined,
	mkdir: async () => undefined,
	readdir: async () => [],
	stat: async () => ({ isFile: () => true, isDirectory: () => false, size: 1, mtimeMs: 1 }),
	access: async () => undefined,
	rename: async () => undefined,
	exists: async () => false,
};

async function defaultReadFile(_file: string, encoding: BufferEncoding): Promise<string>;
async function defaultReadFile(_file: string): Promise<Uint8Array>;
async function defaultReadFile(_file: string, encoding?: BufferEncoding): Promise<string | Uint8Array> {
	return encoding ? '' : new Uint8Array();
}

function missingBinaryRunner(): ProcessRunner {
	return { execFile: async () => { throw Object.assign(new Error('not found'), { code: 'ENOENT' }); } };
}

function runnerWithResponses(responses: Record<string, ProcessRunResult>): ProcessRunner {
	return {
		async execFile(binary: string, options: ProcessRunOptions): Promise<ProcessRunResult> {
			const key = [binary, ...options.args].join(' ');
			const response = responses[key] ?? Object.entries(responses).find(([expected]) => key.startsWith(expected))?.[1];
			if (!response) {
				throw new Error(`Unexpected command: ${key}`);
			}
			return response;
		},
	};
}

function okResult(stdout: string): ProcessRunResult {
	return { stdout, stderr: '', exitCode: 0, durationMs: 1, timedOut: false, cancelled: false };
}
