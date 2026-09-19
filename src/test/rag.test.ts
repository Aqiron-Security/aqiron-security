import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { builtInRegexSignals, databaseSignals, endpointSignals, llmSignals, paymentSignals, secretSignals } from '../rag/regexSignals';
import { syncRegexes, validateRegexCatalog, validateRegexSignal } from '../rag/regexLoader';
import { RagIndexService } from '../rag/ragIndexService';
import { detectSecuritySignals, detectViaAST } from '../rag/signalDetector';
import { isAqExcludedPath, isFlutterWorkspace } from '../utils/files';

suite('RAG signals', () => {
	test('ships all required grouped signal categories', () => {
		assert.ok(databaseSignals.length > 0);
		assert.ok(paymentSignals.length > 0);
		assert.ok(llmSignals.length > 0);
		assert.ok(secretSignals.length > 0);
		assert.ok(endpointSignals.length > 0);
		assert.ok(builtInRegexSignals.every((signal) => validateRegexSignal(signal).valid));
	});

	test('rejects an unsafe nested-quantifier import', () => {
		const result = validateRegexSignal({ id: 'unsafe', category: 'service', provider: 'Test', pattern: '(a+)+$', confidence: 'Low', description: 'unsafe', falsePositiveGuidance: 'none' });
		assert.strictEqual(result.valid, false);
	});

	test('keeps valid entries when an imported catalog includes invalid entries', () => {
		const result = validateRegexCatalog({ version: 1, updatedAt: new Date().toISOString(), sources: [{ id: 'mixed', name: 'mixed', type: 'vetted-json', url: 'workspace://mixed', status: 'pending', rejected: [], patterns: [builtInRegexSignals[0], { ...builtInRegexSignals[0], id: 'unsafe', pattern: '(a+)+$' }] }] });
		assert.strictEqual(result.accepted.sources[0].patterns.length, 1);
		assert.strictEqual(result.rejected.length, 1);
	});

	test('synchronizes only validated trusted source patterns', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-rag-sync-'));
		try {
			const catalog = await syncRegexes(root, async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ patterns: [builtInRegexSignals[0], { ...builtInRegexSignals[0], id: 'unsafe', pattern: '(a+)+$' }] }) }) as Response);
			assert.strictEqual(catalog.sources.at(-1)?.patterns.length, 1);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('does not index a signal found only in a comment', () => {
		const signals = detectSecuritySignals('example.ts', '// const client = new OpenAI({ apiKey: "sk-not-real" });');
		assert.strictEqual(signals.length, 0);
	});

	test('detects imports and constructor calls with AST', () => {
		const signals = detectViaAST('client.ts', 'import OpenAI from "openai"; const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });');
		assert.ok(signals.some((signal) => signal.provider === 'OpenAI' && signal.evidenceType === 'ast'));
	});

	test('detects Firebase and HTTP evidence from executable code', () => {
		const signals = detectSecuritySignals('app.ts', 'import { initializeApp } from "firebase/app"; await fetch("https://api.example.test/v1");');
		assert.ok(signals.some((signal) => signal.provider === 'Firebase'));
		assert.ok(signals.some((signal) => signal.provider === 'REST'));
	});

	test('reuses cached signals for unchanged files and persists the hidden index', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-rag-cache-'));
		try {
			await fs.writeFile(path.join(root, 'app.ts'), 'import { initializeApp } from "firebase/app";');
			const index = new RagIndexService();
			const first = await index.reindex(root, { withAi: false });
			const firstIndexedAt = first.files[0].indexedAt;
			const second = await index.reindex(root, { withAi: false });
			assert.strictEqual(second.files[0].indexedAt, firstIndexedAt);
			await fs.access(path.join(root, '.aqiron-security', 'index.json'));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	test('applies Flutter defaults and custom .aq exclusions during RAG indexing', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-rag-aq-'));
		try {
			await fs.mkdir(path.join(root, 'lib'), { recursive: true });
			await fs.mkdir(path.join(root, 'build'), { recursive: true });
			await fs.writeFile(path.join(root, 'pubspec.yaml'), 'dependencies:\n  flutter:\n    sdk: flutter\n');
			await fs.writeFile(path.join(root, '.aq'), 'lib/ignored.dart\n');
			await fs.writeFile(path.join(root, 'lib', 'main.dart'), 'void main() {}');
			await fs.writeFile(path.join(root, 'lib', 'ignored.dart'), 'const token = "ignored";');
			await fs.writeFile(path.join(root, 'build', 'generated.dart'), 'const token = "build";');

			assert.ok(isFlutterWorkspace(root));
			assert.ok(isAqExcludedPath(path.join(root, 'build', 'generated.dart'), root));
			assert.ok(isAqExcludedPath(path.join(root, 'lib', 'ignored.dart'), root));
			const index = new RagIndexService();
			const result = await index.reindex(root, { withAi: false });
			assert.deepStrictEqual(result.files.map((file) => file.relativePath), ['lib/main.dart']);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
