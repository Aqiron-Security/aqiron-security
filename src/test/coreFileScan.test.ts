import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import { CoreRuntime } from '../../packages/core/src/runtime/coreRuntime';
import { CoreFileScanRequest, CoreFileScanResult } from '../../packages/core/src/shared/fileScan';

suite('Core file scan contract', () => {
	test('scans exactly the supplied in-memory file and returns canonical findings with the request scan ID', async () => {
		const runtime = new CoreRuntime({ coreVersion: 'test' });
		const secret = 'source-secret-123456';
		const events: Array<{ requestId?: string; payload?: unknown }> = [];
		const response = await runtime.handle(request('file-memory', 'scan.file', {
			filePath: 'D:/workspace/lib/main.dart',
			content: `const apiKey = "${secret}";`,
			policy: policy({ supportedExtensions: ['.dart'] }),
		}), event => { events.push(event); });
		assert.equal(response.success, true, response.error?.message);
		const result = response.result as CoreFileScanResult;
		assert.equal(result.scanId, 'file-memory');
		assert.equal(result.filePath, 'D:/workspace/lib/main.dart');
		assert.equal(result.filesScanned, 1);
		assert.equal(result.findingCount, 1);
		assert.equal(result.findings[0].ruleId, 'native.dart.hardcoded-secret');
		assert.equal(result.findings[0].file, result.filePath);
		assert.equal('rawEvidence' in result.findings[0] ? result.findings[0].rawEvidence : undefined, undefined);
		assert.ok(!JSON.stringify(response).includes(secret));
		assert.deepEqual(events.map(event => event.requestId), ['file-memory', 'file-memory']);
		assert.equal((events[0].payload as { scanId: string }).scanId, result.scanId);
		assert.equal((events[1].payload as { scanId: string }).scanId, result.scanId);
	});

	test('honors resolved language, exclusion, eligibility, size, and generated/minified/compiled policies', async () => {
		const runtime = new CoreRuntime({ coreVersion: 'test' });
		const scan = async (id: string, filePath: string, content: string, policyOverride: Partial<CoreFileScanRequest['policy']>) => {
			const response = await runtime.handle(request(id, 'scan.file', { filePath, content, policy: policy(policyOverride) }), () => undefined);
			assert.equal(response.success, true, response.error?.message);
			return response.result as CoreFileScanResult;
		};
		assert.equal((await scan('unsupported', 'file.ts', 'USER root', { supportedExtensions: ['.dart'] })).skipReason, 'unsupported');
		assert.equal((await scan('excluded', '/repo/private/main.dart', 'USER root', { excludedPaths: ['/repo/private'] })).skipReason, 'excluded');
		assert.equal((await scan('ineligible', 'main.dart', 'USER root', { eligible: false })).skipReason, 'ineligible');
		assert.equal((await scan('too-large', 'main.dart', 'x'.repeat(20), { maxFileSizeBytes: 10 })).skipReason, 'size-limit');
		assert.equal((await scan('generated', 'lib/main.g.dart', 'USER root', { skipGeneratedFiles: true })).skipReason, 'generated');
		assert.equal((await scan('minified', 'assets/app.min.js', 'x();', { skipMinifiedFiles: true, supportedExtensions: ['.js'] })).skipReason, 'minified');
		assert.equal((await scan('compiled', 'out/Main.class', 'x', { skipCompiledFiles: true, supportedExtensions: ['.class'] })).skipReason, 'compiled');
	});

	test('applies represented custom rules and returns UnifiedFinding data', async () => {
		const runtime = new CoreRuntime({ coreVersion: 'test' });
		const response = await runtime.handle(request('custom-rule', 'scan.file', {
			filePath: 'src/input.ts',
			content: 'dangerousCall(userInput);',
			policy: policy({
				supportedExtensions: ['.ts'],
				customRules: [{ id: 'high.custom-call', title: 'Custom call', message: 'Review this call.', severity: 'High', pattern: 'dangerousCall', extensions: ['.ts'] }],
			}),
		}), () => undefined);
		assert.equal(response.success, true, response.error?.message);
		const result = response.result as CoreFileScanResult;
		assert.equal(result.findings[0].ruleId, 'high.custom-call');
		assert.equal(result.findings[0].line, 1);
		assert.equal(result.findings[0].sourceTool, 'Aqiron');
		assert.equal(typeof result.findings[0].fingerprint, 'string');
	});

	test('cancels through the existing request cancellation operation and rejects malformed params', async () => {
		const runtime = new CoreRuntime({ coreVersion: 'test' });
		let started = false;
		const pending = runtime.handle(request('cancel-file', 'scan.file', {
			filePath: 'main.dart', content: '', policy: policy(),
		}), event => { if (event.event === 'scan.file.started') {started = true;} });
		assert.equal(started, true);
		const cancelled = await runtime.handle(request('cancel-request', 'core.cancel', { requestId: 'cancel-file' }), () => undefined);
		assert.deepEqual(cancelled.result, { cancelled: true, requestId: 'cancel-file' });
		const result = await pending;
		assert.equal(result.success, false);
		assert.equal(result.error?.message, 'Core request cancelled.');
		const malformed = await runtime.handle(request('bad-file', 'scan.file', { filePath: 'main.dart', content: 12, policy: {} }), () => undefined);
		assert.equal(malformed.success, false);
		assert.equal(malformed.error?.code, 'CORE_INVALID_REQUEST');
	});

	test('Core source has no VS Code module imports', async () => {
		const root = path.resolve(__dirname, '../../../packages/core/src');
		const files = await listTypeScriptFiles(root);
		for (const file of files) {
			const source = await fs.readFile(file, 'utf8');
			assert.doesNotMatch(source, /(?:from\s*|require\s*\()(['"])vscode\1/, `${path.relative(root, file)} imports vscode`);
		}
	});
});

function request(id: string, method: string, params: unknown): unknown {
	return { id, type: 'request', method, params };
}

function policy(overrides: Partial<CoreFileScanRequest['policy']> = {}): CoreFileScanRequest['policy'] {
	return {
		supportedExtensions: ['.dart', '.py', '.xml', '.js', '.ts'],
		excludedPaths: [],
		maxFileSizeBytes: null,
		skipGeneratedFiles: false,
		skipMinifiedFiles: false,
		skipCompiledFiles: false,
		eligible: true,
		customRules: [],
		...overrides,
	};
}

async function listTypeScriptFiles(directory: string): Promise<string[]> {
	const entries = await fs.readdir(directory, { withFileTypes: true });
	const nested = await Promise.all(entries.map(async entry => {
		const fullPath = path.join(directory, entry.name);
		return entry.isDirectory() ? listTypeScriptFiles(fullPath) : entry.isFile() && entry.name.endsWith('.ts') ? [fullPath] : [];
	}));
	return nested.flat();
}
