import * as path from 'path';
import { SecurityContextFile, SecurityDeterministicFindingSummary } from '../shared/analysis';

export interface ContextPrioritizerInput {
	workspaceRoot: string;
	files: string[];
	findings: SecurityDeterministicFindingSummary[];
	maxFiles?: number;
}

export function prioritizeContextFiles(input: ContextPrioritizerInput): SecurityContextFile[] {
	const maxFiles = input.maxFiles ?? 28;
	return input.files
		.map((file) => ({ file, score: scoreFile(file, input.findings) }))
		.sort((left, right) => right.score - left.score)
		.slice(0, maxFiles)
		.map((entry) => ({
			path: path.relative(input.workspaceRoot, entry.file).split(path.sep).join('/'),
			reason: explainPath(entry.file, input.findings),
			language: inferLanguage(entry.file),
			excerpt: '',
		}));
}

function scoreFile(file: string, findings: SecurityDeterministicFindingSummary[]): number {
	const relative = file.split(path.sep).join('/').toLowerCase();
	let score = 0;
	for (const keyword of ['auth', 'login', 'token', 'secret', 'credential', 'firebase', 'firestore', 'storage', 'supabase', 'graphql', 'api', 'network', 'http', 'manifest', 'rules', 'config', 'env', 'security', 'mobile', 'android', 'ios', 'ci', 'workflow', 'pipeline', 'pubspec', 'package']) {
		if (relative.includes(keyword)) {
			score += 8;
		}
	}
	for (const finding of findings) {
		if (relative.includes(path.basename(finding.file).toLowerCase())) {
			score += 18;
		}
		if (finding.file && relative.includes(finding.file.split(path.sep).pop()?.toLowerCase() ?? '')) {
			score += 12;
		}
	}
	return score;
}

function explainPath(relative: string, findings: SecurityDeterministicFindingSummary[]): string {
	if (/pubspec/i.test(relative) || /package\.json/i.test(relative)) {
		return 'Dependency and package metadata';
	}
	if (/firebase|firestore|storage\.rules/i.test(relative)) {
		return 'Security-sensitive cloud or backend configuration';
	}
	if (/androidmanifest|info\.plist|\.github\/workflows/i.test(relative)) {
		return 'Platform or CI security surface';
	}
	if (findings.some((finding) => relative.includes(path.basename(finding.file).toLowerCase()))) {
		return 'File linked to deterministic scan evidence';
	}
	return 'Relevant workspace source or configuration';
}

function inferLanguage(relative: string): string | undefined {
	if (relative.endsWith('.dart')) return 'Dart';
	if (relative.endsWith('.kt') || relative.endsWith('.kts')) return 'Kotlin';
	if (relative.endsWith('.java')) return 'Java';
	if (relative.endsWith('.swift')) return 'Swift';
	if (relative.endsWith('.m') || relative.endsWith('.mm')) return 'Objective-C';
	if (relative.endsWith('.ts') || relative.endsWith('.tsx')) return 'TypeScript';
	if (relative.endsWith('.js') || relative.endsWith('.jsx')) return 'JavaScript';
	if (relative.endsWith('.py')) return 'Python';
	if (relative.endsWith('.xml')) return 'XML';
	if (relative.endsWith('.yaml') || relative.endsWith('.yml')) return 'YAML';
	return undefined;
}
