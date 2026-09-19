import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { AqironIssue } from '../models/issue';

export const supportedExtensions = new Set([
	'.dart',
	'.ts',
	'.tsx',
	'.js',
	'.jsx',
	'.py',
	'.rs',
	'.java',
	'.c',
	'.cpp',
	'.h',
	'.json',
	'.xml',
	'.yaml',
	'.yml',
	'.gradle',
	'.rules',
]);

export const supportedGlob = '**/*.{dart,ts,tsx,js,jsx,py,rs,java,c,cpp,h,json,xml,yaml,yml,gradle,rules}';

const defaultExcludeFolders = [
	'node_modules',
	'dist',
	'build',
	'coverage',
	'.gradle',
	'.git',
	'.next',
	'.dart_tool',
	'.aqiron-security',
	'generated',
	'gen',
	'target',
	'bin',
	'obj',
	'ios/build',
	'android/build',
	'windows/flutter',
	'linux/flutter',
	'macos/flutter',
	'windows/runner',
	'macos/runner',
	'macos/Runner',
];

const generatedSuffixes = [
	'.g.dart',
	'.freezed.dart',
	'.generated.dart',
	'.generated.ts',
	'.generated.js',
	'.pb.dart',
	'.pb.go',
	'.min.js',
	'.min.css',
	'.mocks.dart',
	'.mock.dart',
	'.config.dart',
];

const compiledOutputExtensions = new Set([
	'.class',
	'.jar',
	'.wasm',
	'.dll',
	'.exe',
	'.o',
	'.obj',
	'.so',
	'.dylib',
]);

export const defaultAqExclusions = [
	'build/',
	'.build/',
	'.dart_tool/',
	'.pub-cache/',
	'.packages',
	'.aqiron-security/',
	'.idea/',
	'android/.gradle/',
	'ios/Pods/',
	'*.g.dart',
	'*.freezed.dart',
	'*.mocks.dart',
	'*.config.dart',
];

const aqPatternCache = new Map<string, { mtimeMs: number; patterns: string[] }>();

export const excludeGlob = '{**/node_modules/**,**/dist/**,**/build/**,**/coverage/**,**/.gradle/**,**/.git/**,**/.next/**,**/.dart_tool/**,**/.aqiron-security/**,**/generated/**,**/gen/**,**/target/**,**/bin/**,**/obj/**,**/ios/build/**,**/android/build/**,**/windows/flutter/**,**/linux/flutter/**,**/macos/flutter/**,**/windows/runner/**,**/macos/Runner/**,**/*.g.dart,**/*.freezed.dart,**/*.generated.*,**/*.mocks.dart,**/*.mock.dart,**/*.config.dart}';

export function isSupportedFile(uri: vscode.Uri): boolean {
	return uri.scheme === 'file' && supportedExtensions.has(path.extname(uri.fsPath).toLowerCase());
}

export function getWorkspaceRootForFile(file: string): string | undefined {
	const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(file));
	return folder?.uri.fsPath ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

export function isInsideSkippedDirectory(file: string): boolean {
	const normalized = normalizePath(file);
	const configured = vscode.workspace.getConfiguration('aqiron-security').get<string[]>('excludeFolders', defaultExcludeFolders);
	const folders = new Set([...defaultExcludeFolders, ...configured].map(normalizePath));
	return [...folders].some((folder) => normalized.includes(`/${folder}/`) || normalized.endsWith(`/${folder}`));
}

export function shouldScanGeneratedFiles(): boolean {
	return vscode.workspace.getConfiguration('aqiron-security').get<boolean>('scanGeneratedFiles', false);
}

export function getMaxFileSizeBytes(): number {
	const maxFileSizeKB = vscode.workspace.getConfiguration('aqiron-security').get<number>('maxFileSizeKB', 512);
	return Math.max(1, maxFileSizeKB) * 1024;
}

export function getSkipReason(file: string, content?: string): string | undefined {
	if (isAqExcludedPath(file)) {
		return 'excluded by .aq';
	}
	if (isInsideSkippedDirectory(file)) {
		return 'excluded folder';
	}

	if (!shouldScanGeneratedFiles() && isGeneratedFile(file, content)) {
		return 'generated code';
	}

	if (isMinifiedFile(file, content)) {
		return 'minified file';
	}

	if (compiledOutputExtensions.has(path.extname(file).toLowerCase())) {
		return 'compiled output';
	}

	return undefined;
}

export function isFlutterWorkspace(root: string): boolean {
	try {
		const pubspec = fs.readFileSync(path.join(root, 'pubspec.yaml'), 'utf8');
		return /(^|\n)\s*flutter\s*:/m.test(pubspec) || /(^|\n)\s*flutter_test\s*:/m.test(pubspec) || fs.existsSync(path.join(root, '.metadata'));
	} catch {
		return false;
	}
}

export function getAqExclusions(root: string): string[] {
	const file = path.join(root, '.aq');
	let mtimeMs = -1;
	try {
		mtimeMs = fs.statSync(file).mtimeMs;
	} catch {
		return isFlutterWorkspace(root) ? [...defaultAqExclusions] : [];
	}
	const cached = aqPatternCache.get(root);
	if (cached?.mtimeMs === mtimeMs) {
		return cached.patterns;
	}
	try {
		const userPatterns = fs.readFileSync(file, 'utf8').split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
		const patterns = [...defaultAqExclusions, ...userPatterns];
		aqPatternCache.set(root, { mtimeMs, patterns });
		return patterns;
	} catch {
		return [...defaultAqExclusions];
	}
}

export function isAqExcludedPath(file: string, root = getWorkspaceRootForFile(file)): boolean {
	if (!root) {
		return false;
	}
	const relative = normalizePath(path.relative(root, file));
	if (!relative || relative.startsWith('../')) {
		return false;
	}
	let ignored = false;
	for (const rawPattern of getAqExclusions(root)) {
		const negated = rawPattern.startsWith('!');
		const pattern = negated ? rawPattern.slice(1) : rawPattern;
		if (matchesAqPattern(relative, pattern)) {
			ignored = !negated;
		}
	}
	return ignored;
}

/** External scanners already apply their own target and exclusion rules. */
export function getIssueSkipReason(issue: Pick<AqironIssue, 'file' | 'lineText' | 'sourceTool'>): string | undefined {
	if (issue.sourceTool && issue.sourceTool !== 'Aqiron') {
		return undefined;
	}
	return getSkipReason(issue.file, issue.lineText);
}

export function isGeneratedFile(file: string, content?: string): boolean {
	const basename = path.basename(file);
	const normalized = normalizePath(file);

	if (/^app_localizations(?:_[a-z_]+)?\.dart$/.test(basename)) {
		return true;
	}

	if (basename.includes('.generated.') || basename.endsWith('.generated')) {
		return true;
	}

	if (generatedSuffixes.some((suffix) => basename.endsWith(suffix))) {
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

export function isMinifiedFile(file: string, content?: string): boolean {
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

function matchesAqPattern(relative: string, rawPattern: string): boolean {
	const pattern = normalizePath(rawPattern).replace(/^\/+/, '');
	if (!pattern) {
		return false;
	}
	const directory = pattern.endsWith('/');
	const normalizedPattern = directory ? pattern.slice(0, -1) : pattern;
	const candidate = directory ? relative === normalizedPattern || relative.startsWith(`${normalizedPattern}/`) : relative;
	if (directory && candidate) {
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
