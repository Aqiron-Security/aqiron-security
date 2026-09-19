import * as path from 'path';
import { FileSystem } from '../shared/platform';
import { add, createEmptyProjectProfile, inferDependencyManager, mergeProjectProfile, ProjectProfile } from './projectProfile';
import { detectTechnologySignals } from './technologyDetector';

export interface ProjectDetectorOptions {
	isExcludedPath?: (file: string, root: string) => boolean;
	maxFileSizeBytes?: number;
	maxCandidateFiles?: number;
	maxDirectoryVisits?: number;
}

const DEFAULT_MAX_CANDIDATE_FILES = 28;
const DEFAULT_MAX_DIRECTORY_VISITS = 240;
const EXCERPT_BYTES = 8_192;

const SECURITY_FILE_PATTERNS: Array<{ test: (relative: string) => boolean; reason: string; kind?: string }> = [
	{ test: (relative) => /(^|\/)pubspec\.(yaml|lock)$/i.test(relative), reason: 'Flutter dependency manifest', kind: 'dependency' },
	{ test: (relative) => /(^|\/)package\.json$/i.test(relative), reason: 'JavaScript package manifest', kind: 'dependency' },
	{ test: (relative) => /(^|\/)package-lock\.json$/i.test(relative), reason: 'JavaScript lockfile', kind: 'dependency' },
	{ test: (relative) => /(^|\/)firebase\.json$/i.test(relative), reason: 'Firebase project configuration', kind: 'config' },
	{ test: (relative) => /(^|\/)(firestore|storage)\.rules$/i.test(relative), reason: 'Firebase security rules', kind: 'config' },
	{ test: (relative) => /(^|\/)supabase.*\.(toml|json)$/i.test(relative), reason: 'Supabase configuration', kind: 'config' },
	{ test: (relative) => /(^|\/)analysis_options\.yaml$/i.test(relative), reason: 'Dart analyzer policy', kind: 'config' },
	{ test: (relative) => /(^|\/)android\/app\/src\/main\/AndroidManifest\.xml$/i.test(relative), reason: 'Android manifest', kind: 'native' },
	{ test: (relative) => /(^|\/)ios\/Runner\/Info\.plist$/i.test(relative), reason: 'iOS app configuration', kind: 'native' },
	{ test: (relative) => /(^|\/)\.github\/workflows\/.*\.(yml|yaml)$/i.test(relative), reason: 'CI/CD workflow', kind: 'cicd' },
	{ test: (relative) => /(^|\/)\.(env|env\.[^/]+)$/i.test(relative) || /(^|\/)\.env(\.[^/]+)?$/i.test(relative), reason: 'Environment file', kind: 'config' },
];

const PROFILE_PATTERNS = [
	{ test: (text: string) => /\bflutter\b/i.test(text), projectType: 'Flutter', apply: (profile: ProjectProfile) => add(profile.languages, 'Dart') },
	{ test: (text: string) => /\bflutter\b/i.test(text), projectType: 'Flutter', apply: (profile: ProjectProfile) => add(profile.frameworks, 'Flutter') },
	{ test: (text: string) => /\bfirebase\b/i.test(text), projectType: 'Firebase', apply: (profile: ProjectProfile) => add(profile.services, 'Firebase') },
	{ test: (text: string) => /\bsupabase\b/i.test(text), projectType: 'Supabase', apply: (profile: ProjectProfile) => add(profile.services, 'Supabase') },
	{ test: (text: string) => /\bgraphql\b/i.test(text), projectType: 'GraphQL', apply: (profile: ProjectProfile) => add(profile.endpoints, 'GraphQL') },
	{ test: (text: string) => /\baxios\b|\bfetch\b|\bdio\b|\bokhttp\b|\bretrofit\b/i.test(text), projectType: 'REST', apply: (profile: ProjectProfile) => add(profile.services, 'REST/HTTP') },
	{ test: (text: string) => /\bauth\b|\boauth\b|\boidc\b|\bjwt\b/i.test(text), projectType: 'Auth', apply: (profile: ProjectProfile) => add(profile.authentication, 'Authentication') },
	{ test: (text: string) => /\bfirestore\b|\brealtime database\b|\bpostgres\b|\bmysql\b|\bsqlite\b|\bmongodb\b/i.test(text), projectType: 'Database', apply: (profile: ProjectProfile) => add(profile.databases, 'Database') },
	{ test: (text: string) => /\bsharedpreferences\b|\bsecure storage\b|\bkeychain\b|\bkeystore\b|\buserdefaults\b/i.test(text), projectType: 'Storage', apply: (profile: ProjectProfile) => add(profile.storage, 'Local storage') },
	{ test: (text: string) => /\bandroid\b|\bandroidmanifest\b|\bgradle\b|\bkeystore\b/i.test(text), projectType: 'Android', apply: (profile: ProjectProfile) => add(profile.platforms, 'Android') },
	{ test: (text: string) => /\bios\b|\binfo\.plist\b|\bxcode\b|\bswift\b/i.test(text), projectType: 'iOS', apply: (profile: ProjectProfile) => add(profile.platforms, 'iOS') },
	{ test: (text: string) => /\bgithub actions\b|\bgitlab ci\b|\bazure pipelines\b|\bcircleci\b|\bworkflow\b/i.test(text), projectType: 'CI/CD', apply: (profile: ProjectProfile) => add(profile.ciCd, 'CI/CD') },
];

export async function detectProjectTypes(root: string, filesystem: FileSystem, isExcludedPath?: (file: string, root: string) => boolean): Promise<string[]> {
	const checks: Array<[string, string[]]> = [
		['Flutter', ['pubspec.yaml', 'lib/main.dart']],
		['Android', ['AndroidManifest.xml', 'build.gradle', 'settings.gradle']],
		['iOS', ['Info.plist', 'Runner.xcodeproj']],
		['Firebase', ['firebase.json', 'firestore.rules', 'storage.rules']],
		['Supabase', ['supabase.toml']],
		['GraphQL', ['graphql', 'apollo', 'urql']],
		['REST', ['axios', 'fetch', 'dio', 'retrofit']],
		['CI/CD', ['.github/workflows', 'gitlab-ci.yml', '.circleci']],
	];
	const detected: string[] = [];
	for (const [type, files] of checks) {
		if (await hasAnyPath(root, files, filesystem, isExcludedPath)) {
			detected.push(type);
		}
	}
	return detected.length ? detected : ['Source workspace'];
}

export async function collectProjectFiles(root: string, filesystem: FileSystem, options: ProjectDetectorOptions = {}): Promise<string[]> {
	const files: string[] = [];
	const maxCandidateFiles = options.maxCandidateFiles ?? DEFAULT_MAX_CANDIDATE_FILES;
	const maxDirectoryVisits = options.maxDirectoryVisits ?? DEFAULT_MAX_DIRECTORY_VISITS;
	const maxFileSizeBytes = options.maxFileSizeBytes ?? 512 * 1024;
	let visits = 0;

	async function visit(current: string): Promise<void> {
		if (visits >= maxDirectoryVisits || files.length >= maxCandidateFiles * 5) {
			return;
		}
		visits += 1;
		let entries: Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>;
		try {
			entries = (await filesystem.readdir(current, { withFileTypes: true })) as Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>;
		} catch {
			return;
		}
		for (const entry of entries) {
			if (files.length >= maxCandidateFiles * 5) {
				return;
			}
			const fullPath = path.join(current, entry.name);
			if (entry.isDirectory()) {
				if (shouldSkipDirectory(fullPath, root, options.isExcludedPath)) {
					continue;
				}
				await visit(fullPath);
				continue;
			}
			if (!isCandidateFile(fullPath)) {
				continue;
			}
			if (options.isExcludedPath?.(fullPath, root)) {
				continue;
			}
			try {
				const stat = await filesystem.stat(fullPath);
				if (stat.size <= maxFileSizeBytes) {
					files.push(fullPath);
				}
			} catch {
				// Ignore files that disappear during indexing.
			}
		}
	}

	await visit(root);
	return files;
}

export async function detectProjectProfile(root: string, filesystem: FileSystem, options: ProjectDetectorOptions = {}): Promise<ProjectProfile> {
	const projectTypes = await detectProjectTypes(root, filesystem, options.isExcludedPath);
	const profile = createEmptyProjectProfile(root);
	profile.projectTypes = [...projectTypes];
	const candidateFiles = await collectProjectFiles(root, filesystem, options);
	for (const file of candidateFiles.slice(0, options.maxCandidateFiles ?? DEFAULT_MAX_CANDIDATE_FILES)) {
		const relative = path.relative(root, file).split(path.sep).join('/').toLowerCase();
		const text = await readExcerpt(file, filesystem, EXCERPT_BYTES);
		addByPath(profile, relative);
		const combined = `${relative}\n${text}`;
		const signals = detectTechnologySignals(combined);
		mergeProjectProfile(profile, signals);
		for (const pattern of SECURITY_FILE_PATTERNS) {
			if (pattern.test(relative)) {
				add(profile.sensitiveFiles, path.relative(root, file).split(path.sep).join('/'));
				if (pattern.kind === 'dependency') {
					add(profile.dependencyManagers, inferDependencyManager(relative, text));
				}
				if (pattern.kind === 'native') {
					add(profile.nativeCode, path.basename(relative));
				}
				if (pattern.kind === 'cicd') {
					add(profile.ciCd, 'CI/CD workflow');
				}
			}
		}
	}
	for (const type of projectTypes) {
		if (type === 'Flutter') {
			add(profile.languages, 'Dart');
			add(profile.frameworks, 'Flutter');
		}
		if (type === 'Android') {
			add(profile.platforms, 'Android');
		}
		if (type === 'iOS') {
			add(profile.platforms, 'iOS');
		}
	}
	return profile;
}

async function readExcerpt(file: string, filesystem: FileSystem, maxBytes: number): Promise<string> {
	try {
		const content = await filesystem.readFile(file, 'utf8');
		return content.slice(0, maxBytes);
	} catch {
		return '';
	}
}

function shouldSkipDirectory(directory: string, root: string, isExcludedPath?: (file: string, root: string) => boolean): boolean {
	const relative = path.relative(root, directory).split(path.sep).join('/');
	if (!relative || relative.startsWith('..')) {
		return false;
	}
	return Boolean(isExcludedPath?.(directory, root) || /(^|\/)(dist|build|out|coverage|\.dart_tool|node_modules|\.git|\.aqiron-security|generated|gen|bin|obj)(\/|$)/i.test(relative));
}

function isCandidateFile(file: string): boolean {
	const basename = path.basename(file).toLowerCase();
	const extension = path.extname(basename);
	return [
		'.dart', '.kt', '.kts', '.java', '.swift', '.m', '.mm', '.ts', '.tsx', '.js', '.jsx',
		'.json', '.yaml', '.yml', '.xml', '.gradle', '.toml', '.plist', '.xcconfig', '.rules',
		'.env', '.txt', '.md',
	].includes(extension) || [
		'pubspec.yaml', 'pubspec.lock', 'package.json', 'package-lock.json', 'firebase.json', 'analysis_options.yaml',
		'androidmanifest.xml', 'infoplist', 'supabase.toml', 'firestore.rules', 'storage.rules',
	].some((value) => basename.includes(value));
}

function addByPath(profile: ProjectProfile, relative: string): void {
	if (relative.endsWith('.dart')) {
		add(profile.languages, 'Dart');
	}
	if (relative.endsWith('.kt') || relative.endsWith('.kts')) {
		add(profile.languages, 'Kotlin');
		add(profile.nativeCode, 'Android native code');
	}
	if (relative.endsWith('.swift')) {
		add(profile.languages, 'Swift');
		add(profile.nativeCode, 'iOS native code');
	}
	if (relative.endsWith('.m') || relative.endsWith('.mm')) {
		add(profile.nativeCode, 'Objective-C');
	}
	if (relative.endsWith('.ts') || relative.endsWith('.tsx')) {
		add(profile.languages, 'TypeScript');
	}
	if (relative.endsWith('.js') || relative.endsWith('.jsx')) {
		add(profile.languages, 'JavaScript');
	}
	if (relative.includes('pubspec')) {
		add(profile.dependencyManagers, 'pub');
	}
	if (relative.includes('package.json')) {
		add(profile.dependencyManagers, 'npm');
	}
	if (relative.includes('build.gradle') || relative.endsWith('.kts')) {
		add(profile.dependencyManagers, 'gradle');
	}
	if (relative.includes('pom.xml')) {
		add(profile.dependencyManagers, 'maven');
	}
	if (relative.includes('requirements.txt') || relative.includes('pyproject.toml')) {
		add(profile.dependencyManagers, 'python');
	}
	if (relative.includes('cargo.toml')) {
		add(profile.dependencyManagers, 'cargo');
	}
	if (relative.includes('github/workflows')) {
		add(profile.ciCd, 'GitHub Actions');
	}
}

async function hasAnyPath(root: string, values: readonly string[], filesystem: FileSystem, isExcludedPath?: (file: string, root: string) => boolean): Promise<boolean> {
	for (const value of values) {
		if (await pathExists(path.join(root, value), filesystem, isExcludedPath)) {
			return true;
		}
	}
	return false;
}

async function pathExists(candidate: string, filesystem: FileSystem, isExcludedPath?: (file: string, root: string) => boolean): Promise<boolean> {
	try {
		if (isExcludedPath?.(candidate, path.dirname(candidate))) {
			return false;
		}
		await filesystem.access(candidate);
		return true;
	} catch {
		return false;
	}
}
