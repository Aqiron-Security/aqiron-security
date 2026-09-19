import * as fs from 'fs/promises';
import * as path from 'path';
import { getMaxFileSizeBytes, getSkipReason, isAqExcludedPath } from '../../utils/files';
import { ScanTarget, ScannerInputFile } from './types';

const textExtensions = new Set([
	'.dart', '.yaml', '.yml', '.json', '.xml', '.gradle', '.properties', '.toml', '.ini', '.cfg', '.conf',
	'.env', '.txt', '.md', '.sh', '.bat', '.ps1', '.js', '.ts', '.tsx', '.jsx', '.java', '.kt', '.swift',
	'.plist', '.rules', '.gitignore', '.dockerfile',
]);
const textNames = new Set(['.env', '.env.local', '.env.production', 'pubspec.yaml', 'pubspec.lock', 'Podfile', 'Gemfile', 'Dockerfile']);

export async function resolveFlutterScanInputs(target: ScanTarget): Promise<ScannerInputFile[]> {
	const files: ScannerInputFile[] = [];
	await visit(target.workspaceRoot, target.workspaceRoot, target, files);
	return files;
}

async function visit(root: string, current: string, target: ScanTarget, output: ScannerInputFile[]): Promise<void> {
	let entries;
	try {
		entries = await fs.readdir(current, { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries) {
		const fullPath = path.join(current, entry.name);
		if (entry.isDirectory()) {
			if (fullPath !== root && shouldSkipDirectory(fullPath, target)) {
				continue;
			}
			await visit(root, fullPath, target, output);
			continue;
		}
		if (!entry.isFile() || !isCandidateTextFile(entry.name)) {
			continue;
		}
		const skipReason = isAqExcludedPath(fullPath, root) ? 'excluded by .aq' : getSkipReason(fullPath);
		if (skipReason) {
			continue;
		}
		try {
			const stat = await fs.stat(fullPath);
			if (stat.size <= getMaxFileSizeBytes()) {
				output.push({ path: fullPath, relativePath: path.relative(root, fullPath).split(path.sep).join('/') });
			}
		} catch {
			// Files that disappear or cannot be read are omitted from the external scan scope.
		}
	}
}

function shouldSkipDirectory(directory: string, target: ScanTarget): boolean {
	if (target.exclusions.some((value) => directory.split(path.sep).join('/').includes(`/${value.replace(/\\/g, '/')}`))) {
		return true;
	}
	if (isAqExcludedPath(directory, target.workspaceRoot)) {
		return true;
	}
	return Boolean(getSkipReason(directory));
}

function isCandidateTextFile(file: string): boolean {
	const basename = path.basename(file);
	return textNames.has(basename) || textExtensions.has(path.extname(file).toLowerCase()) || basename.startsWith('.env.');
}
