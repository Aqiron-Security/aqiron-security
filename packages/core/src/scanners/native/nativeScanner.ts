import * as path from 'path';
import { createFinding, UnifiedFinding } from '../../shared/finding';
import { CancellationTokenLike } from '../../shared/cancellation';
import { FileSystem } from '../../shared/platform';
import { CoreFileScanResult, ResolvedFileScanPolicy } from '../../shared/fileScan';

export interface NativeRuleScanResult {
	findings: UnifiedFinding[];
	filesScanned: number;
	durationMs: number;
}

const legacySecretRules: Array<{ pattern: RegExp; id: string; title: string; description: string }> = [
	{ pattern: /\b(?:api[_-]?key|client[_-]?secret|access[_-]?key)\b\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]/i, id: 'critical.api-key', title: 'Hardcoded API Key', description: 'Move hardcoded API keys to a secret manager or environment variable.' },
	{ pattern: /\bAKIA[0-9A-Z]{16}\b/, id: 'critical.api-key', title: 'Hardcoded API Key', description: 'AWS access keys must not be stored in source code.' },
	{ pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/, id: 'critical.api-key', title: 'Hardcoded API Key', description: 'Google API keys must not be stored in source code.' },
	{ pattern: /\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{20,}\b/, id: 'critical.api-key', title: 'Hardcoded API Key', description: 'Provider API keys must not be stored in source code.' },
	{ pattern: /\b(?:secret|token)\b\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]/i, id: 'critical.secret', title: 'Hardcoded Secret', description: 'Move hardcoded secrets to a protected secret source.' },
	{ pattern: /\bpassword\b\s*[:=]\s*['"][^'"\s]{8,}['"]/i, id: 'critical.password', title: 'Hardcoded Password', description: 'Move hardcoded passwords to a protected secret source.' },
	{ pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, id: 'critical.private-key', title: 'Private Key Material', description: 'Private key material must not be stored in source code.' },
];

/** Portable baseline rules used when external SAST binaries are unavailable. */
export class NativeWorkspaceScanner {
	constructor(private readonly filesystem: FileSystem) {}

	/** Scan exactly the supplied source path and content. This method never reads the file from disk. */
	async scanFileContent(filePath: string, content: string, scanId: string, policy: ResolvedFileScanPolicy, token?: CancellationTokenLike): Promise<CoreFileScanResult> {
		const startedAt = Date.now();
		await new Promise<void>((resolve) => setImmediate(resolve));
		if (token?.isCancellationRequested) {throw new Error('Core request cancelled.');}
		const skipReason = getFileSkipReason(filePath, content, policy);
		if (skipReason) {
			return { scanId, filePath, state: 'skipped', skipReason, findings: [], filesScanned: 0, findingCount: 0, durationMs: Date.now() - startedAt };
		}
		const findings: UnifiedFinding[] = [];
		const extension = path.extname(filePath).toLowerCase();
		const executable = stripFileComments(content, extension);
		const lines = executable.split(/\r?\n/);
		const customRules = compileCustomRules(filePath, policy.customRules);
		for (let index = 0; index < lines.length; index += 1) {
			if (token?.isCancellationRequested) {throw new Error('Core request cancelled.');}
			findings.push(...scanSourceLine(filePath, lines[index], index, extension, false));
			findings.push(...scanCustomRuleLine(filePath, lines[index], index, customRules));
			const unused = findUnusedVariable(filePath, lines[index], lines, index, extension);
			if (unused) {findings.push(unused);}
			if (index > 0 && index % 256 === 0) {await new Promise<void>((resolve) => setImmediate(resolve));}
		}
		findings.push(...findLongFunctions(filePath, lines, extension));
		return { scanId, filePath, state: 'completed', findings, filesScanned: 1, findingCount: findings.length, durationMs: Date.now() - startedAt };
	}

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

function findUnusedVariable(filePath: string, line: string, lines: readonly string[], lineIndex: number, extension: string): UnifiedFinding | undefined {
	const trimmed = line.trim();
	if (/^(?:export|public|private|protected|static|return|for|if|while|switch)\b/.test(trimmed)) {return undefined;}
	const patterns: RegExp[] = [];
	if (['.js', '.jsx', '.ts', '.tsx'].includes(extension)) {patterns.push(/^(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:['"`\d[{]|true|false|null|undefined)/);}
	if (extension === '.dart') {patterns.push(/^(?:final|var|const|String|int|double|bool)\s+([A-Za-z_]\w*)\s*=\s*(?:['"\d[{]|true|false|null)/);}
	if (extension === '.rs') {patterns.push(/^let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*(?:["'\d[{]|true|false)/);}
	if (extension === '.py') {patterns.push(/^([A-Za-z_]\w*)\s*=\s*(?:['"\d[{]|True|False|None)/);}
	const match = patterns.map((pattern) => pattern.exec(trimmed)).find(Boolean);
	const name = match?.[1];
	if (!name || name.startsWith('_') || ['build', 'initState', 'dispose', 'didChangeDependencies', 'setUp', 'tearDown', 'main', 'callback', 'handler'].includes(name)) {return undefined;}
	const declaration = lines.join('\n').replace(line, '');
	if (new RegExp(`\\b${escapeRegExp(name)}\\b`).test(declaration)) {return undefined;}
	const column = Math.max(1, line.indexOf(name) + 1);
	return createFinding({
		title: 'Unused Variable', description: `Variable "${name}" appears to be unused.`, severity: 'Low', cwe: [], owasp: [],
		file: filePath, line: lineIndex + 1, column, endColumn: column + name.length, sourceTool: 'Aqiron',
		ruleId: 'low.unused-variable', confidence: 'Medium', remediation: '', tags: ['portable', 'native-rule'], rawEvidence: undefined,
	});
}

function findLongFunctions(filePath: string, lines: readonly string[], extension: string): UnifiedFinding[] {
	const findings: UnifiedFinding[] = [];
	if (extension === '.py') {
		for (let index = 0; index < lines.length; index += 1) {
			const match = /^(\s*)def\s+([A-Za-z_]\w*)\s*\(/.exec(lines[index]);
			if (!match || isFrameworkCallbackName(match[2])) {continue;}
			const baseIndent = match[1].length;
			let endLine = index;
			for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
				if (lines[cursor].trim().length === 0) {continue;}
				if (lines[cursor].length - lines[cursor].trimStart().length <= baseIndent) {break;}
				endLine = cursor;
			}
			if (endLine - index + 1 > 100) {findings.push(createLongFunctionFinding(filePath, index, lines[index], match[2], endLine - index + 1));}
		}
		return findings;
	}
	if (!['.js', '.jsx', '.ts', '.tsx', '.dart', '.java', '.c', '.cpp', '.h', '.rs'].includes(extension)) {return findings;}
	const stack: Array<{ line: number; braceDepth: number; name: string }> = [];
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index];
		if (isFunctionStart(line, extension)) {
			stack.push({ line: index, braceDepth: countBraces(line), name: getFunctionName(line) ?? 'function' });
			continue;
		}
		if (!stack.length) {continue;}
		const active = stack[stack.length - 1];
		active.braceDepth += countBraces(line);
		if (active.braceDepth <= 0) {
			const length = index - active.line + 1;
			if (length > 100) {findings.push(createLongFunctionFinding(filePath, active.line, lines[active.line], active.name, length));}
			stack.pop();
		}
	}
	return findings;
}

function createLongFunctionFinding(filePath: string, index: number, line: string, name: string, length: number): UnifiedFinding {
	return createFinding({
		title: 'Long Function', description: `${name} is ${length} lines long. Consider splitting it into smaller functions.`, severity: 'Low',
		cwe: [], owasp: [], file: filePath, line: index + 1, column: 1, endColumn: Math.max(2, line.trim().length + 1),
		sourceTool: 'Aqiron', ruleId: 'low.long-function', confidence: 'Medium', remediation: '', tags: ['portable', 'native-rule'], rawEvidence: undefined,
	});
}

function isFunctionStart(line: string, extension: string): boolean {
	const trimmed = line.trim();
	if (!trimmed.includes('{')) {return false;}
	if (['.js', '.jsx', '.ts', '.tsx'].includes(extension)) {return /^(?:export\s+)?(?:async\s+)?function\b|^(?:const|let)\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*{|^(?:public|private|protected)?\s*[A-Za-z_$][\w$]*\s*\([^)]*\)\s*{/.test(trimmed);}
	if (extension === '.dart') {return /^(?:Future<[^>]+>|void|String|int|double|bool|Widget|[A-Z]\w*)\s+\w+\s*\([^)]*\)\s*(?:async\s*)?{/.test(trimmed);}
	if (extension === '.java') {return /^(?:public|private|protected|static|final|\s)+[\w<>\[\]]+\s+\w+\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?{/.test(trimmed);}
	if (['.c', '.cpp', '.h'].includes(extension)) {return /^[\w:*&<>\s]+\s+\w+\s*\([^;]*\)\s*{/.test(trimmed);}
	if (extension === '.rs') {return /^(?:pub\s+)?(?:async\s+)?fn\s+\w+\s*\([^)]*\)\s*(?:->\s*[^{]+)?{/.test(trimmed);}
	return false;
}

function getFunctionName(line: string): string | undefined {
	return /\b(?:function|fn)?\s*([A-Za-z_$][\w$]*)\s*\(/.exec(line)?.[1];
}

function countBraces(line: string): number {
	const withoutStrings = line.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '');
	return (withoutStrings.match(/{/g) ?? []).length - (withoutStrings.match(/}/g) ?? []).length;
}

function isFrameworkCallbackName(name: string): boolean {
	return ['build', 'initState', 'dispose', 'didChangeDependencies', 'setUp', 'tearDown', 'main', 'callback', 'handler'].includes(name);
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripFileComments(content: string, extension: string): string {
	if (extension === '.py') {
		return stripPythonComments(content);
	}
	let result = '';
	let lineComment = false;
	let blockComment = false;
	let quote: string | undefined;
	for (let index = 0; index < content.length; index += 1) {
		const char = content[index];
		const next = content[index + 1];
		if (lineComment) {
			if (char === '\n') { lineComment = false; result += char; }
			else {result += ' ';}
		} else if (blockComment) {
			if (char === '*' && next === '/') { result += '  '; index += 1; blockComment = false; }
			else {result += char === '\n' ? '\n' : ' ';}
		} else if (quote) {
			result += char;
			if (char === '\\') { result += next ?? ''; index += 1; }
			else if (char === quote) {quote = undefined;}
		} else if (char === '"' || char === '\'' || char === '`') { quote = char; result += char; }
		else if (char === '/' && next === '/') { result += '  '; index += 1; lineComment = true; }
		else if (char === '/' && next === '*') { result += '  '; index += 1; blockComment = true; }
		else {result += char;}
	}
	return result;
}

function stripPythonComments(content: string): string {
	const lines = content.split(/\r?\n/);
	let tripleQuote: string | undefined;

	return lines.map((line) => {
		if (tripleQuote) {
			const closeIndex = line.indexOf(tripleQuote);
			if (closeIndex === -1) {
				return ' '.repeat(line.length);
			}

			const strippedPrefix = ' '.repeat(closeIndex + tripleQuote.length);
			tripleQuote = undefined;
			return strippedPrefix + stripPythonLineComments(line.slice(closeIndex + 3));
		}

		const tripleMatch = /("""|''')/.exec(line);
		if (tripleMatch) {
			const quote = tripleMatch[1];
			const secondIndex = line.indexOf(quote, tripleMatch.index + quote.length);
			if (secondIndex === -1) {
				tripleQuote = quote;
				return line.slice(0, tripleMatch.index) + ' '.repeat(line.length - tripleMatch.index);
			}

			const before = line.slice(0, tripleMatch.index);
			const hidden = ' '.repeat(secondIndex + quote.length - tripleMatch.index);
			const after = stripPythonLineComments(line.slice(secondIndex + quote.length));
			return before + hidden + after;
		}

		return stripPythonLineComments(line);
	}).join('\n');
}

function stripPythonLineComments(line: string): string {
	let quote: string | undefined;
	for (let index = 0; index < line.length; index += 1) {
		const char = line[index];
		if (quote) {
			if (char === '\\') {
				index += 1;
			} else if (char === quote) {
				quote = undefined;
			}
			continue;
		}

		if (char === '"' || char === '\'') {
			quote = char;
			continue;
		}

		if (char === '#') {
			return line.slice(0, index) + ' '.repeat(line.length - index);
		}
	}

	return line;
}

function getFileSkipReason(filePath: string, content: string, policy: ResolvedFileScanPolicy): CoreFileScanResult['skipReason'] {
	if (!policy.eligible) {return 'ineligible';}
	const normalizedPath = filePath.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
	if (policy.excludedPaths.some((excluded) => {
		const normalizedExcluded = excluded.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
		return normalizedPath === normalizedExcluded || normalizedPath.startsWith(`${normalizedExcluded}/`);
	})) {return 'excluded';}
	const extension = path.extname(filePath).toLowerCase();
	if (!policy.supportedExtensions.map((item) => item.toLowerCase().startsWith('.') ? item.toLowerCase() : `.${item.toLowerCase()}`).includes(extension)) {return 'unsupported';}
	const normalized = normalizedPath;
	const basename = path.posix.basename(normalized);
	if (policy.skipGeneratedFiles && (/\.(?:g|freezed|generated|mocks|mock)\.dart$/.test(basename) || /(^|\/)\.(?:generated|dart_tool)\/|\/(?:generated|gen)\//.test(normalized) || /@generated|<auto-generated|generated code|do not edit|DO NOT EDIT|Generated file|This file is generated/i.test(content.slice(0, 2048)))) {return 'generated';}
	if (policy.skipMinifiedFiles && isMinifiedFile(filePath, content)) {return 'minified';}
	if (policy.skipCompiledFiles && /\.(?:class|jar|war|pyc|pyo|o|obj|so|dll|dylib|exe|a|lib|wasm)$/i.test(filePath)) {return 'compiled';}
	if (policy.maxFileSizeBytes !== null && Buffer.byteLength(content, 'utf8') > policy.maxFileSizeBytes) {return 'size-limit';}
	return undefined;
}

type CompiledCustomRule = { rule: ResolvedFileScanPolicy['customRules'][number]; pattern: RegExp };

function compileCustomRules(filePath: string, rules: ResolvedFileScanPolicy['customRules']): CompiledCustomRule[] {
	const extension = path.extname(filePath).toLowerCase();
	const compiled: CompiledCustomRule[] = [];
	for (const rule of rules) {
		if (rule.extensions?.length && !rule.extensions.some((item) => (item.startsWith('.') ? item : `.${item}`).toLowerCase() === extension)) {continue;}
		try {
			compiled.push({ rule, pattern: new RegExp(rule.pattern, rule.caseSensitive ? '' : 'i') });
		} catch {
			continue;
		}
	}
	return compiled;
}

function scanCustomRuleLine(filePath: string, line: string, index: number, rules: readonly CompiledCustomRule[]): UnifiedFinding[] {
	const findings: UnifiedFinding[] = [];
	for (const { rule, pattern } of rules) {
		const match = pattern.exec(line);
		if (!match) {continue;}
		findings.push(createFinding({
			title: rule.title, description: rule.message, severity: rule.severity, cwe: [], owasp: [], file: filePath,
			line: index + 1, column: Math.max(1, match.index + 1), endColumn: Math.max(1, match.index + 1) + match[0].length, sourceTool: 'Aqiron', ruleId: rule.id,
			confidence: 'Medium', remediation: 'Review this custom rule finding.', tags: ['custom-rule'], rawEvidence: undefined,
		}));
	}
	return findings;
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
	const executableLines = stripFileComments(content, extension).split(/\r?\n/);
	const findings: UnifiedFinding[] = [];
	for (let index = 0; index < lines.length; index += 1) {
		findings.push(...scanSourceLine(file, lines[index], index, extension, true, false, executableLines[index] ?? lines[index]));
		findings.push(...scanLegacySecretRules(file, executableLines[index] ?? lines[index], index));
	}
	return findings;
}

function scanSourceLine(file: string, line: string, index: number, extension: string, includeEvidence: boolean, includeSecretRules = true, evidenceScanLine = line): UnifiedFinding[] {
	const rules = extension === '.dart' ? dartRules(line) : extension === '.py' ? pythonRules(line) : extension === '.xml' ? androidRules(line) : dockerRules(file, line);
	const secretFindings = includeSecretRules ? scanLegacySecretRules(file, line, index) : [];
	const legacySecretMatchesSource = hasLegacySecret(evidenceScanLine);
	const hasNativeDartSecret = rules.some((rule) => rule.id === 'native.dart.hardcoded-secret');
	const suppressEvidence = hasLegacySecret(line) || hasLegacySecret(evidenceScanLine) || hasNativeDartSecret;
	const findings = rules.filter((rule) => Boolean(rule.id) && (rule.id !== 'native.dart.hardcoded-secret' || !legacySecretMatchesSource)).map((rule) => createFinding({
		title: rule.title, description: rule.description, severity: rule.severity, cwe: rule.cwe, owasp: rule.owasp,
		file, line: index + 1, column: Math.max(1, line.indexOf(rule.match) + 1), sourceTool: 'Aqiron', ruleId: rule.id,
		confidence: 'Medium', remediation: rule.remediation, tags: ['flutter', 'portable', 'native-rule'],
		...(!includeEvidence ? { endColumn: Math.max(1, line.indexOf(rule.match) + 1) + rule.match.length } : {}),
		rawEvidence: includeEvidence && !suppressEvidence ? { line: line.slice(0, 500) } : undefined,
	}));
	return [...findings, ...secretFindings];
}

/** Deterministic, language-neutral secret rules retained from the characterized VS Code scanner. */
function scanLegacySecretRules(file: string, line: string, index: number): UnifiedFinding[] {
	return legacySecretRules.flatMap(({ pattern, id, title, description }) => {
		const match = pattern.exec(line);
		if (!match) {return [];}
		const column = match.index + 1;
		return [createFinding({
			title, description, severity: 'Critical', cwe: ['CWE-798'], owasp: ['M2: Security Misconfiguration'],
			file, line: index + 1, column, endColumn: column + match[0].length,
			sourceTool: 'Aqiron', ruleId: id, confidence: 'High',
			remediation: 'Rotate exposed credentials and move values into a managed secret store.',
			tags: ['secret', 'credential', 'portable', 'native-rule'], rawEvidence: undefined,
		})];
	});
}

function hasLegacySecret(line: string): boolean {
	return legacySecretRules.some(({ pattern }) => pattern.test(line));
}

function isMinifiedFile(filePath: string, content: string): boolean {
	const basename = path.posix.basename(filePath.replace(/\\/g, '/'));
	if (basename.includes('.min.')) {
		return true;
	}

	const lines = content.split(/\r?\n/);
	const longestLine = Math.max(0, ...lines.slice(0, 20).map((line) => line.length));
	return longestLine > 1000 && content.length / Math.max(1, lines.length) > 300;
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
	return /\.(dart|ts|tsx|js|jsx|py|rs|java|c|cpp|h|json|xml|yaml|yml|gradle|rules)$/i.test(file) || path.basename(file).toLowerCase() === 'dockerfile';
}

function isExcluded(file: string, root: string): boolean {
	const relative = path.relative(root, file).replace(/\\/g, '/');
	return /(^|\/)(node_modules|\.git|\.dart_tool|build|dist|coverage|out|generated|gen|target|bin|obj|\.aqiron|\.aqiron-security)(\/|$)/i.test(relative);
}
