import * as path from 'path';
import { createFinding, UnifiedFinding } from '../../shared/finding';
import { CancellationTokenLike } from '../../shared/cancellation';
import { FileSystem } from '../../shared/platform';

export interface NativeRuleScanResult {
	findings: UnifiedFinding[];
	filesScanned: number;
	durationMs: number;
}

/** Portable baseline rules used when external SAST binaries are unavailable. */
export class NativeWorkspaceScanner {
	constructor(private readonly filesystem: FileSystem) {}

	async scanWorkspace(root: string, token?: CancellationTokenLike): Promise<NativeRuleScanResult> {
		const startedAt = Date.now();
		const files = await collectFiles(root, root, this.filesystem, token);
		const findings: UnifiedFinding[] = [];
		for (const file of files) {
			if (token?.isCancellationRequested) {
				break;
			}
			try {
				const content = await this.filesystem.readFile(file, 'utf8');
				findings.push(...scanFile(file, content));
			} catch {
				// Individual unreadable files do not abort the workspace scan.
			}
		}
		return { findings, filesScanned: files.length, durationMs: Date.now() - startedAt };
	}
}

async function collectFiles(root: string, current: string, filesystem: FileSystem, token?: CancellationTokenLike): Promise<string[]> {
	if (token?.isCancellationRequested || isExcluded(current, root)) {
		return [];
	}
	const entries = await filesystem.readdir(current, { withFileTypes: true });
	const files: string[] = [];
	for (const entry of entries) {
		if (token?.isCancellationRequested) {
			break;
		}
		const name = typeof entry === 'string' ? entry : entry.name;
		const fullPath = path.join(current, name);
		if (isExcluded(fullPath, root)) {
			continue;
		}
		if (typeof entry !== 'string' && entry.isDirectory()) {
			files.push(...await collectFiles(root, fullPath, filesystem, token));
		} else if (typeof entry === 'string' || entry.isFile()) {
			if (isSupported(fullPath)) {
				files.push(fullPath);
			}
		}
	}
	return files;
}

function scanFile(file: string, content: string): UnifiedFinding[] {
	if (content.length > 512 * 1024) {
		return [];
	}
	const extension = path.extname(file).toLowerCase();
	const lines = content.split(/\r?\n/);
	const findings: UnifiedFinding[] = [];
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index];
		const rules = extension === '.dart' ? dartRules(line) : extension === '.py' ? pythonRules(line) : extension === '.xml' ? androidRules(line) : dockerRules(file, line);
		for (const rule of rules) {
			if (!rule.id) {
				continue;
			}
			findings.push(createFinding({
				title: rule.title,
				description: rule.description,
				severity: rule.severity,
				cwe: rule.cwe,
				owasp: rule.owasp,
				file,
				line: index + 1,
				column: Math.max(1, line.indexOf(rule.match) + 1),
				sourceTool: 'Aqiron',
				ruleId: rule.id,
				confidence: 'Medium',
				remediation: rule.remediation,
				tags: ['flutter', 'portable', 'native-rule'],
				rawEvidence: { line: line.slice(0, 500) },
			}));
		}
	}
	return findings;
}

interface Rule {
	id: string;
	title: string;
	description: string;
	severity: 'Critical' | 'High' | 'Medium' | 'Low';
	match: string;
	remediation: string;
	cwe: string[];
	owasp: string[];
}

function dartRules(line: string): Rule[] {
	return [
		match(line, /\b(?:api[_-]?key|client[_-]?secret|password|token)\b\s*[:=]\s*['"][^'"]{8,}['"]/i, 'native.dart.hardcoded-secret', 'Hardcoded secret in Dart source', 'Critical', 'Move secrets to secure runtime configuration and rotate exposed values.', ['CWE-798'], ['M2: Security Misconfiguration']),
		match(line, /['"]http:\/\//i, 'native.dart.insecure-http', 'Insecure HTTP URL in Flutter source', 'High', 'Use HTTPS for authenticated or sensitive network requests.', ['CWE-319'], ['M5: Insecure Communication']),
		match(line, /\b(?:SharedPreferences|Hive|sqflite)\b.*\b(?:password|token|secret|credential)\b/i, 'native.dart.insecure-storage', 'Sensitive data may be stored in client-side storage', 'High', 'Store credentials and tokens in platform-backed secure storage.', ['CWE-922'], ['M9: Insecure Data Storage']),
		match(line, /\b(?:rawQuery|rawInsert|rawUpdate|rawDelete)\s*\([^)]*\$[A-Za-z_]/, 'native.dart.sql-injection', 'User-controlled interpolation reaches a raw SQL call', 'High', 'Use parameterized SQL arguments instead of string interpolation.', ['CWE-89'], ['M4: Insufficient Input Validation']),
		match(line, /\b(?:print|debugPrint)\s*\(/, 'native.dart.sensitive-logging', 'Debug logging remains in Dart source', 'Medium', 'Remove sensitive production logs or use a redacting logger.', ['CWE-532'], ['M6: Inadequate Privacy Controls']),
	];
}

function pythonRules(line: string): Rule[] {
	return [
		match(line, /\bDEBUG\s*=\s*True\b/i, 'native.python.debug-enabled', 'Python debug mode is enabled', 'High', 'Disable debug mode in production deployments.', ['CWE-489'], ['M8: Security Misconfiguration']),
		match(line, /['"]http:\/\//i, 'native.python.insecure-http', 'Insecure HTTP URL in backend source', 'High', 'Use HTTPS for authenticated or sensitive network requests.', ['CWE-319'], ['M5: Insecure Communication']),
		match(line, /\b(?:print|logging\.(?:debug|info))\s*\(/i, 'native.python.logging', 'Backend logging may expose sensitive runtime data', 'Medium', 'Redact secrets and sensitive user data from logs.', ['CWE-532'], ['M6: Inadequate Privacy Controls']),
	];
}

function androidRules(line: string): Rule[] {
	return [
		match(line, /android:usesCleartextTraffic\s*=\s*["']true["']/i, 'native.android.cleartext', 'Android cleartext traffic is enabled', 'High', 'Disable cleartext traffic and allow exceptions only for controlled local development.', ['CWE-319'], ['M5: Insecure Communication']),
		match(line, /android:exported\s*=\s*["']true["']/i, 'native.android.exported', 'Android component is exported', 'Medium', 'Set exported=false or protect the component with an explicit permission.', ['CWE-926'], ['M1: Improper Platform Usage']),
	];
}

function dockerRules(file: string, line: string): Rule[] {
	if (path.basename(file).toLowerCase() !== 'dockerfile') {
		return [];
	}
	return [
		match(line, /^\s*USER\s+root\b/i, 'native.docker.root', 'Container runs as root', 'High', 'Create and run the container as a non-root user.', ['CWE-250'], ['M8: Security Misconfiguration']),
	];
}

function match(line: string, pattern: RegExp, id: string, title: string, severity: Rule['severity'], remediation: string, cwe: string[], owasp: string[]): Rule {
	const found = line.match(pattern);
	return found ? { id, title, description: title, severity, match: found[0], remediation, cwe, owasp } : emptyRule;
}

const emptyRule: Rule = { id: '', title: '', description: '', severity: 'Low', match: '', remediation: '', cwe: [], owasp: [] };

function isSupported(file: string): boolean {
	return /\.(dart|py|xml)$/i.test(file) || path.basename(file).toLowerCase() === 'dockerfile';
}

function isExcluded(file: string, root: string): boolean {
	const relative = path.relative(root, file).replace(/\\/g, '/');
	return /(^|\/)(node_modules|\.git|\.dart_tool|build|dist|coverage|out|generated|gen|target|bin|obj|\.aqiron|\.aqiron-security)(\/|$)/i.test(relative);
}
