import * as assert from 'assert';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { SecurityContextBuilder, detectProjectTypes } from '../security/analysis/securityContextBuilder';

suite('Security context builder', () => {
	test('detects Flutter projects, respects exclusions, and keeps bounded candidate files', async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aqiron-context-'));
		try {
			await fs.mkdir(path.join(root, 'lib'), { recursive: true });
			await fs.mkdir(path.join(root, 'build'), { recursive: true });
			await fs.writeFile(path.join(root, 'pubspec.yaml'), 'name: demo\nflutter:\n  sdk: flutter\n');
			await fs.writeFile(path.join(root, 'lib', 'main.dart'), 'import "package:flutter/material.dart";\nvoid main() {}\n');
			await fs.writeFile(path.join(root, 'lib', 'ignored.dart'), 'const token = "should-not-appear";\n');
			await fs.writeFile(path.join(root, 'build', 'generated.dart'), 'const token = "generated";\n');
			await fs.writeFile(path.join(root, '.aq'), 'lib/ignored.dart\n');
			await fs.writeFile(path.join(root, 'firebase.json'), '{}');
			await fs.writeFile(path.join(root, 'firestore.rules'), 'allow read, write: if false;');

			const projectTypes = await detectProjectTypes(root);
			assert.ok(projectTypes.includes('Flutter'));

			const context = await new SecurityContextBuilder().build(root, []);
			assert.ok(context.projectTypes.includes('Flutter'));
			assert.ok(context.profile.languages.includes('Dart'));
			assert.ok(context.profile.frameworks.includes('Flutter'));
			assert.ok(context.profile.services.includes('Firebase'));
			assert.ok(context.candidateFiles.length > 0);
			assert.ok(context.candidateFiles.length <= 28);
			assert.ok(context.candidateFiles.every((file) => !file.path.includes('build/generated.dart')));
			assert.ok(context.candidateFiles.every((file) => !file.path.includes('lib/ignored.dart')));
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});
});
