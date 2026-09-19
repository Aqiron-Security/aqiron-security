import * as path from 'path';
import { ScannerContext, ScannerInputFile } from './types';

const TEXT_EXTENSIONS = new Set([
	'.dart', '.yaml', '.yml', '.json', '.xml', '.gradle', '.properties', '.toml', '.ini', '.cfg', '.conf',
	'.env', '.txt', '.md', '.sh', '.bat', '.ps1', '.js', '.ts', '.tsx', '.jsx', '.java', '.kt', '.swift',
	'.plist', '.rules', '.gitignore', '.dockerfile',
]);
const TEXT_NAMES = new Set(['.env', '.env.local', '.env.production', 'pubspec.yaml', 'pubspec.lock', 'Podfile', 'Gemfile', 'Dockerfile']);
const GENERATED_SUFFIXES = ['.g.dart', '.freezed.dart', '.generated.dart', '.generated.ts', '.generated.js', '.pb.dart', '.pb.go', '.min.js', '.min.css', '.mocks.dart', '.mock.dart', '.config.dart'];
const COMPILED_OUTPUT_EXTENSIONS = new Set(['.class', '.jar', '.wasm', '.dll', '.exe', '.o', '.obj', '.so', '.dylib']);

export async function resolveFlutterScanInputs(context: ScannerContext): Promise<ScannerInputFile[]> {
	const files: ScannerInputFile[] = [];
	await visit(context.workspaceRoot, context.workspaceRoot, context, files);
	return files;
}

export async function findMobileArtifact(context: ScannerContext): Promise<string | undefined> {
	const candidates: string[] = [];
	await visitMobileArtifact(context.workspaceRoot, context.workspaceRoot, context, candidates);
	return candidates.sort((left, right) => scoreArtifact(right) - scoreArtifact(left))[0];
}

export async function findPackageLine(context: ScannerContext, packageName: string, filePath?: string): Promise<number> {
	const lockfile = filePath ?? path.join(context.workspaceRoot, 'pubspec.lock');
	try {
		const content = await context.filesystem.readFile(lockfile, 'utf8');
		const lines = content.split(/\r?\n/);
		const index = lines.findIndex((line) => new RegExp(`^\\s{2}${escapeRegExp(packageName)}:`).test(line));
		return index >= 0 ? index + 1 : 1;
	} catch {
		return 1;
	}
}

export async function classifyDependency(context: ScannerContext, packageName: string): Promise<'direct-dependency' | 'dev-dependency' | 'transitive-dependency' | 'dependency'> {
	try {
		const pubspec = await context.filesystem.readFile(path.join(context.workspaceRoot, 'pubspec.yaml'), 'utf8');
		return new RegExp(`^\\s{2}${escapeRegExp(packageName)}\\s*:`, 'm').test(section(pubspec, 'dependencies'))
			? 'direct-dependency'
			: new RegExp(`^\\s{2}${escapeRegExp(packageName)}\\s*:`, 'm').test(section(pubspec, 'dev_dependencies'))
				? 'dev-dependency'
				: 'transitive-dependency';
	} catch {
		return 'dependency';
	}
}

export async function shouldSkipScanFile(context: ScannerContext, file: string, content?: string): Promise<string | undefined> {
	if (isExcludedByPatterns(file, context.workspaceRoot, context.exclusions)) {
		return 'excluded by .aq';
	}
	if (isInsideSkippedDirectory(file, context.workspaceRoot, context.exclusions)) {
		return 'excluded folder';
	}
	if (!context.configuration.get<boolean>('scanGeneratedFiles', false) && isGeneratedFile(file, content)) {
		return 'generated code';
	}
	if (isMinifiedFile(file, content)) {
		return 'minified file';
	}
	if (COMPILED_OUTPUT_EXTENSIONS.has(path.extname(file).toLowerCase())) {
		return 'compiled output';
	}
	return undefined;
}

export function isCandidateTextFile(file: string): boolean {
	const basename = path.basename(file);
	return TEXT_NAMES.has(basename) || TEXT_EXTENSIONS.has(path.extname(file).toLowerCase()) || basename.startsWith('.env.');
}

async function visit(root: string, current: string, context: ScannerContext, output: ScannerInputFile[]): Promise<void> {
	let entries;
	try {
		entries = await context.filesystem.readdir(current, { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries as Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>) {
		const fullPath = path.join(current, entry.name);
		if (entry.isDirectory()) {
			if (fullPath !== root && shouldSkipDirectory(fullPath, context)) {
				continue;
			}
			await visit(root, fullPath, context, output);
			continue;
		}
		if (!entry.isFile() || !isCandidateTextFile(entry.name)) {
			continue;
		}
		const skipReason = await shouldSkipScanFile(context, fullPath);
		if (skipReason) {
			continue;
		}
		try {
			const stat = await context.filesystem.stat(fullPath);
			if (stat.size <= getMaxFileSizeBytes(context)) {
				output.push({ path: fullPath, relativePath: path.relative(root, fullPath).split(path.sep).join('/') });
			}
		} catch {
			// Files that disappear or cannot be read are omitted from the external scan scope.
		}
	}
}

async function visitMobileArtifact(root: string, current: string, context: ScannerContext, output: string[]): Promise<void> {
	let entries;
	try {
		entries = await context.filesystem.readdir(current, { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries as Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>) {
		const fullPath = path.join(current, entry.name);
		if (entry.isDirectory()) {
			if (fullPath !== root && shouldSkipDirectory(fullPath, context)) {
				continue;
			}
			await visitMobileArtifact(root, fullPath, context, output);
			continue;
		}
		if (!entry.isFile()) {
			continue;
		}
		if (['.apk', '.ipa', '.aab'].includes(path.extname(fullPath).toLowerCase())) {
			output.push(fullPath);
		}
	}
}

function shouldSkipDirectory(directory: string, context: ScannerContext): boolean {
	if (isExcludedByPatterns(directory, context.workspaceRoot, context.exclusions)) {
		return true;
	}
	return Boolean(shouldSkipByDefault(directory, context.workspaceRoot, context.exclusions));
}

function shouldSkipByDefault(file: string, root: string, exclusions: readonly string[]): boolean {
	const relative = normalizePath(path.relative(root, file));
	if (relative.startsWith('../')) {
		return true;
	}
	return exclusions.some((pattern) => matchesPattern(relative, pattern));
}

function getMaxFileSizeBytes(context: ScannerContext): number {
	const maxFileSizeKB = context.configuration.get<number>('maxFileSizeKB', 512);
	return Math.max(1, maxFileSizeKB) * 1024;
}

function isExcludedByPatterns(file: string, root: string, exclusions: readonly string[]): boolean {
	const relative = normalizePath(path.relative(root, file));
	if (!relative || relative.startsWith('../')) {
		return false;
	}
	let ignored = false;
	for (const rawPattern of exclusions) {
		const negated = rawPattern.startsWith('!');
		const pattern = negated ? rawPattern.slice(1) : rawPattern;
		if (matchesPattern(relative, pattern)) {
			ignored = !negated;
		}
	}
	return ignored;
}

function isInsideSkippedDirectory(file: string, root: string, exclusions: readonly string[]): boolean {
	const normalized = normalizePath(path.relative(root, file));
	return exclusions.some((folder) => {
		const normalizedFolder = normalizePath(folder);
		return normalized.includes(`/${normalizedFolder}/`) || normalized.endsWith(`/${normalizedFolder}`);
	});
}

function isGeneratedFile(file: string, content?: string): boolean {
	const basename = path.basename(file);
	const normalized = normalizePath(file);
	if (/^app_localizations(?:_[a-z_]+)?\.dart$/.test(basename)) {
		return true;
	}
	if (basename.includes('.generated.') || basename.endsWith('.generated')) {
		return true;
	}
	if (GENERATED_SUFFIXES.some((suffix) => basename.endsWith(suffix))) {
		return true;
	}
	if (normalized.includes('/.generated/') || normalized.includes('/generated/') || normalized.includes('/gen/') || normalized.includes('/.dart_tool/')) {
		return true;
	}
	if (!content) {
		return false;
	}
	const header = content.slice(0, 2048);
	return /(@generated|<auto-generated|generated code|do not edit|DO NOT EDIT|coverage:ignore-file|Generated file|This file is generated)/i.test(header);
}

function isMinifiedFile(file: string, content?: string): boolean {
	if (path.basename(file).includes('.min.')) {
		return true;
	}
	if (!content) {
		return false;
	}
	const lines = content.split(/\r?\n/).slice(0, 20);
	const longestLine = Math.max(0, ...lines.map((line) => line.length));
	return longestLine > 1000 && content.length / Math.max(1, content.split(/\r?\n/).length) > 300;
}

function normalizePath(value: string): string {
	return value.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '').toLowerCase();
}

function matchesPattern(relative: string, rawPattern: string): boolean {
	const pattern = normalizePath(rawPattern).replace(/^\/+/, '');
	if (!pattern) {
		return false;
	}
	const directory = pattern.endsWith('/');
	const normalizedPattern = directory ? pattern.slice(0, -1) : pattern;
	if (directory && (relative === normalizedPattern || relative.startsWith(`${normalizedPattern}/`))) {
		return true;
	}
	const expression = globToRegExp(normalizedPattern, pattern.includes('/'));
	return pattern.includes('/') ? expression.test(relative) : relative.split('/').some((segment) => expression.test(segment));
}

function globToRegExp(pattern: string, fullPath: boolean): RegExp {
	let source = '';
	for (let index = 0; index < pattern.length; index++) {
		const character = pattern[index];
		if (character === '*' && pattern[index + 1] === '*') {
			source += '.*';
			index++;
		} else if (character === '*') {
			source += fullPath ? '[^/]*' : '.*';
		} else if (character === '?') {
			source += '.';
		} else {
			source += /[\\^$+?.()|{}[\]]/.test(character) ? `\\${character}` : character;
		}
	}
	return new RegExp(`^${source}$`, 'i');
}

function scoreArtifact(file: string): number {
	const lower = file.toLowerCase();
	return (lower.includes('release') ? 4 : 0) + (lower.includes('debug') ? 1 : 0) + (lower.endsWith('.apk') ? 2 : 0);
}

function section(text: string, heading: string): string {
	const match = text.match(new RegExp(`(?:^|\\n)${heading}:\\n([\\s\\S]*?)(?=\\n\\S|$)`));
	return match?.[1] ?? '';
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
