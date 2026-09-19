import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { detectProjectProfile } from '../../packages/core/src/project';
import { RagIndexService } from '../../packages/core/src/rag';
import { FileSystem } from '../../packages/core/src/shared/platform';

suite('Core project and RAG', () => {
	test('detects Flutter project intelligence and indexes security-relevant files', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-core-prag-'));
		try {
			await fs.mkdir(path.join(root, 'lib'), { recursive: true });
			await fs.writeFile(path.join(root, 'pubspec.yaml'), 'name: demo\nflutter:\n  sdk: flutter\n');
			await fs.writeFile(path.join(root, 'lib', 'main.dart'), 'import "package:flutter/material.dart";\nconst apiKey = "sk-test-12345678901234567890";\n');
			await fs.writeFile(path.join(root, 'firebase.json'), '{}');
			const filesystem = createFileSystem();
			const profile = await detectProjectProfile(root, filesystem, {});
			assert.ok(profile.projectTypes.includes('Flutter'));
			assert.ok(profile.languages.includes('Dart'));
			assert.ok(profile.services.includes('Firebase'));

			const index = new RagIndexService({ filesystem });
			const result = await index.reindex(root, { withAi: false });
			assert.ok(result.files.length > 0);
			assert.ok(result.chunks.length > 0);
			assert.ok(result.chunks.some((chunk) => chunk.text.includes('apiKey')));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});

function createFileSystem(): FileSystem {
	return {
		readFile: nodeReadFile,
		writeFile: fs.writeFile,
		mkdir: async (file: string, options?: { recursive?: boolean }) => {
			await fs.mkdir(file, options);
		},
		readdir: fs.readdir,
		stat: async (file: string) => {
			const stat = await fs.stat(file);
			return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs };
		},
		access: fs.access,
		rename: fs.rename,
		exists: async (file: string) => fs.access(file).then(() => true).catch(() => false),
	};
}

async function nodeReadFile(file: string, encoding: BufferEncoding): Promise<string>;
async function nodeReadFile(file: string): Promise<Uint8Array>;
async function nodeReadFile(file: string, encoding?: BufferEncoding): Promise<string | Uint8Array> {
	return encoding ? fs.readFile(file, encoding) : fs.readFile(file);
}
