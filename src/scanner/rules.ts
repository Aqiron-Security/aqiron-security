import * as path from 'path';
import * as vscode from 'vscode';
import { AqironIssue, AqironRuleId, AqironSeverity } from '../models/issue';
import { createSourceLocation } from '../shared/sourceSpan';

interface RuleMatch {
	title: string;
	message: string;
	severity: AqironSeverity;
	ruleId: AqironRuleId | string;
	index: number;
	length: number;
}

interface FunctionStart {
	line: number;
	braceDepth: number;
	name: string;
}

interface CustomRule {
	id: string;
	title: string;
	message: string;
	severity: AqironSeverity;
	pattern: string;
	extensions?: string[];
}

const jsExtensions = new Set(['.js', '.jsx', '.ts', '.tsx']);
const cExtensions = new Set(['.c', '.cpp', '.h']);

export function scanContent(file: string, content: string): AqironIssue[] {
	const extension = path.extname(file).toLowerCase();
	const executable = stripComments(content, extension);
	const originalLines = content.split(/\r?\n/);
	const executableLines = executable.split(/\r?\n/);
	const issues: AqironIssue[] = [];

	for (let lineIndex = 0; lineIndex < executableLines.length; lineIndex++) {
		const executableLine = executableLines[lineIndex];
		const originalLine = originalLines[lineIndex] ?? executableLine;
		const trimmedLine = executableLine.trim();
		if (trimmedLine.length === 0) {
			continue;
		}

		for (const match of detectLineIssues(executableLine, extension)) {
			issues.push(createIssue(file, lineIndex, originalLine, match));
		}

		for (const match of detectConfiguredRuleIssues(executableLine, extension)) {
			issues.push(createIssue(file, lineIndex, originalLine, match));
		}

		const unusedVariable = detectUnusedVariable(executableLine, executable, extension);
		if (unusedVariable) {
			issues.push(createIssue(file, lineIndex, originalLine, unusedVariable));
		}
	}

	issues.push(...detectLongFunctions(file, executableLines, originalLines, extension));
	return dedupeIssues(issues);
}

function detectLineIssues(line: string, extension: string): RuleMatch[] {
	if (extension === '.dart') {
		return detectDartIssues(line);
	}

	if (jsExtensions.has(extension)) {
		return detectJavaScriptIssues(line);
	}

	if (extension === '.py') {
		return detectPythonIssues(line);
	}

	if (cExtensions.has(extension)) {
		return detectCIssues(line);
	}

	if (extension === '.java') {
		return detectJavaIssues(line);
	}

	return detectSecrets(line);
}

function detectDartIssues(line: string): RuleMatch[] {
	return [
		...detectSecrets(line),
		...matchRules(line, [
			[/\bprint\s*\(/, 'Flutter print() Statement', 'Use structured logging or remove print() before shipping Flutter apps.', 'Medium', 'medium.print'],
			[/\bdebugPrint\s*\(/, 'Flutter debugPrint() Statement', 'Remove debugPrint() or guard it behind a debug-only condition.', 'Medium', 'medium.debug'],
			[/['"]http:\/\/[^'"]+['"]/, 'Insecure HTTP URL', 'Use HTTPS for Flutter network calls unless a clear exception is required.', 'Medium', 'medium.insecure-http'],
		]),
	];
}

function detectJavaScriptIssues(line: string): RuleMatch[] {
	return [
		...detectSecrets(line),
		...matchRules(line, [
			[/\bconsole\.log\s*\(/, 'Console Statement', 'console.log should not be committed in production code.', 'Medium', 'medium.console-log'],
			[/\beval\s*\(/, 'Dangerous eval()', 'Avoid eval() because it can execute untrusted code.', 'High', 'high.eval'],
			[/\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(/, 'Shell Execution', 'child_process shell execution can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'],
			[/\b(?:exec|execSync|spawn|spawnSync)\s*\(/, 'Shell Execution', 'Shell execution can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'],
			[/\brejectUnauthorized\s*:\s*false\b/, 'TLS Verification Disabled', 'Do not disable TLS certificate validation. Use trusted certificates and keep rejectUnauthorized enabled.', 'High', 'high.tls-disabled'],
			[/\bcors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/i, 'Permissive CORS Origin', 'Avoid wildcard CORS on authenticated or sensitive APIs. Restrict origins to trusted domains.', 'High', 'high.permissive-cors'],
			[/\bjwt\.verify\s*\([^)]*,\s*['"][^'"]*['"]\s*,\s*\{[^}]*ignoreExpiration\s*:\s*true/i, 'JWT Expiration Ignored', 'Do not ignore JWT expiration during verification.', 'High', 'high.jwt-expiration-ignored'],
			[/\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/, 'TLS Verification Disabled', 'Do not disable TLS verification with NODE_TLS_REJECT_UNAUTHORIZED=0.', 'High', 'high.tls-disabled'],
		]),
	];
}

function detectPythonIssues(line: string): RuleMatch[] {
	return [
		...detectSecrets(line),
		...matchRules(line, [
			[/\bexec\s*\(/, 'Dangerous exec()', 'Avoid exec() because it can execute untrusted code.', 'High', 'high.eval'],
			[/\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(/, 'Dangerous Subprocess', 'Subprocess execution can become command injection when arguments are user-controlled.', 'High', 'high.subprocess'],
			[/\bpickle\.loads\s*\(/, 'Unsafe Deserialization', 'pickle.loads can execute code during deserialization. Avoid it for untrusted data.', 'High', 'high.unsafe-deserialization'],
			[/\byaml\.load\s*\([^)]*(?:Loader\s*=\s*yaml\.Loader|FullLoader)?/i, 'Unsafe YAML Loading', 'Use yaml.safe_load for untrusted YAML input.', 'High', 'high.unsafe-deserialization'],
			[/\bverify\s*=\s*False\b/, 'TLS Verification Disabled', 'Do not disable TLS certificate validation in HTTP clients.', 'High', 'high.tls-disabled'],
			[/\bDEBUG\s*=\s*True\b/, 'Debug Mode Enabled', 'Debug mode can expose stack traces and secrets in production.', 'Medium', 'medium.debug'],
		]),
	];
}

function detectCIssues(line: string): RuleMatch[] {
	return [
		...detectSecrets(line),
		...matchRules(line, [
			[/\bsystem\s*\(/, 'Shell Execution', 'system() can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'],
			[/\bstrcpy\s*\(/, 'Unsafe C API', 'strcpy() can overflow buffers. Prefer bounded alternatives.', 'High', 'high.unsafe-c-api'],
			[/\bgets\s*\(/, 'Unsafe C API', 'gets() is unsafe and should not be used.', 'High', 'high.unsafe-c-api'],
			[/\bsprintf\s*\(/, 'Unsafe C API', 'sprintf() can overflow buffers. Prefer snprintf() with explicit bounds.', 'High', 'high.unsafe-c-api'],
			[/\bmemcpy\s*\([^,]+,[^,]+,\s*strlen\s*\(/, 'Unsafe Copy Length', 'Copying strlen() bytes with memcpy can miss terminators and cause memory safety defects.', 'Medium', 'medium.unsafe-copy'],
		]),
	];
}

function detectJavaIssues(line: string): RuleMatch[] {
	return [
		...detectSecrets(line),
		...matchRules(line, [
			[/\bRuntime\.getRuntime\(\)\.exec\s*\(/, 'Shell Execution', 'Runtime.exec() can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'],
			[/\bsetJavaScriptEnabled\s*\(\s*true\s*\)/, 'WebView JavaScript Enabled', 'Only enable WebView JavaScript for trusted content and harden bridges.', 'Medium', 'medium.webview-javascript'],
			[/\bsetAllowFileAccess\s*\(\s*true\s*\)/, 'WebView File Access Enabled', 'Avoid WebView file access unless it is strictly required and sandboxed.', 'High', 'high.webview-file-access'],
			[/\bTrustManager\b|\bHostnameVerifier\b/, 'Custom TLS Trust Manager', 'Custom certificate or hostname trust logic can disable TLS protections. Prefer platform defaults.', 'High', 'high.tls-disabled'],
		]),
	];
}

function detectSecrets(line: string): RuleMatch[] {
	const rules: Array<[RegExp, string, string, AqironRuleId]> = [
		[/\b(?:api[_-]?key|client[_-]?secret|access[_-]?key)\b\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]/i, 'Hardcoded API Key', 'Move hardcoded API keys to a secret manager or environment variable.', 'critical.api-key'],
		[/\bAKIA[0-9A-Z]{16}\b/, 'Hardcoded API Key', 'AWS access keys must not be stored in source code.', 'critical.api-key'],
		[/\bAIza[0-9A-Za-z_\-]{35}\b/, 'Hardcoded API Key', 'Google API keys must not be stored in source code.', 'critical.api-key'],
		[/\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{20,}\b/, 'Hardcoded API Key', 'Provider API keys must not be stored in source code.', 'critical.api-key'],
		[/\b(?:secret|token)\b\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]/i, 'Hardcoded Secret', 'Move hardcoded secrets to a protected secret source.', 'critical.secret'],
		[/\bpassword\b\s*[:=]\s*['"][^'"\s]{8,}['"]/i, 'Hardcoded Password', 'Move hardcoded passwords to a protected secret source.', 'critical.password'],
		[/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, 'Private Key Material', 'Private key material must not be stored in source code.', 'critical.private-key'],
	];

	return rules.flatMap(([pattern, title, message, ruleId]) => {
		const match = pattern.exec(line);
		return match ? [{
			title,
			message,
			severity: 'Critical' as const,
			ruleId,
			index: match.index,
			length: match[0].length,
		}] : [];
	});
}

function detectConfiguredRuleIssues(line: string, extension: string): RuleMatch[] {
	return getCustomRules()
		.filter((rule) => !rule.extensions?.length || rule.extensions.map(normalizeExtension).includes(extension))
		.flatMap((rule) => {
			try {
				const pattern = new RegExp(rule.pattern, 'i');
				const match = pattern.exec(line);
				return match ? [{
					title: rule.title,
					message: rule.message,
					severity: rule.severity,
					ruleId: rule.id,
					index: match.index,
					length: match[0].length,
				}] : [];
			} catch {
				return [];
			}
		});
}

function getCustomRules(): CustomRule[] {
	const rules = vscode.workspace.getConfiguration('aqiron-security').get<unknown[]>('customRules', defaultCustomRules);
	if (!Array.isArray(rules)) {
		return [];
	}
	return rules.flatMap((item) => {
		if (!item || typeof item !== 'object') {
			return [];
		}
		const value = item as Record<string, unknown>;
		if (typeof value.id !== 'string' || typeof value.title !== 'string' || typeof value.message !== 'string' || typeof value.pattern !== 'string' || !isSeverity(value.severity)) {
			return [];
		}
		const extensions = Array.isArray(value.extensions)
			? value.extensions.filter((extension): extension is string => typeof extension === 'string').map(normalizeExtension)
			: undefined;
		return [{
			id: value.id,
			title: value.title,
			message: value.message,
			severity: value.severity,
			pattern: value.pattern,
			extensions,
		}];
	});
}

const defaultCustomRules: CustomRule[] = [
	{
		id: 'high.firebase-open-rules',
		title: 'Open Firebase Rules',
		message: 'Firebase rules allow broad read/write access. Require authenticated users and resource-level authorization.',
		severity: 'High',
		pattern: 'allow\\s+(?:read|write|read,\\s*write)\\s*:\\s*if\\s+true',
		extensions: ['.rules', '.json'],
	},
	{
		id: 'high.android-exported-component',
		title: 'Exported Android Component',
		message: 'Exported Android components can expose app entry points. Add permissions or set exported=false unless intentionally public.',
		severity: 'High',
		pattern: "android:exported\\s*=\\s*[\"']true[\"']",
		extensions: ['.xml'],
	},
	{
		id: 'medium.gradle-dynamic-version',
		title: 'Dynamic Dependency Version',
		message: 'Dynamic dependency versions reduce build reproducibility and can pull unexpected vulnerable releases.',
		severity: 'Medium',
		pattern: "(implementation|api|compileOnly|runtimeOnly)\\s*\\(?\\s*[\"'][^\"']+:(?:\\+|latest\\.)",
		extensions: ['.gradle'],
	},
];

function isSeverity(value: unknown): value is AqironSeverity {
	return value === 'Critical' || value === 'High' || value === 'Medium' || value === 'Low';
}

function normalizeExtension(value: string): string {
	const normalized = value.trim().toLowerCase();
	return normalized.startsWith('.') ? normalized : `.${normalized}`;
}

function detectUnusedVariable(line: string, content: string, extension: string): RuleMatch | undefined {
	const declaration = getUnusedVariableCandidate(line, extension);
	if (!declaration) {
		return undefined;
	}

	const withoutDeclaration = content.replace(line, '');
	const usages = new RegExp(`\\b${escapeRegExp(declaration.name)}\\b`, 'g');
	if (usages.test(withoutDeclaration)) {
		return undefined;
	}

	return {
		title: 'Unused Variable',
		message: `Variable "${declaration.name}" appears to be unused.`,
		severity: 'Low',
		ruleId: 'low.unused-variable',
		index: declaration.index,
		length: declaration.name.length,
	};
}

function getUnusedVariableCandidate(line: string, extension: string): { name: string; index: number } | undefined {
	const trimmed = line.trim();
	if (/^(?:export|public|private|protected|static|return|for|if|while|switch)\b/.test(trimmed)) {
		return undefined;
	}

	const patterns: RegExp[] = [];
	if (jsExtensions.has(extension)) {
		patterns.push(/^(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:['"`\d[{]|true|false|null|undefined)/);
	}
	if (extension === '.dart') {
		patterns.push(/^(?:final|var|const|String|int|double|bool)\s+([A-Za-z_]\w*)\s*=\s*(?:['"\d[{]|true|false|null)/);
	}
	if (extension === '.rs') {
		patterns.push(/^let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*(?:["'\d[{]|true|false)/);
	}
	if (extension === '.py') {
		patterns.push(/^([A-Za-z_]\w*)\s*=\s*(?:['"\d[{]|True|False|None)/);
	}

	for (const pattern of patterns) {
		const match = pattern.exec(trimmed);
		const name = match?.[1];
		if (name && !name.startsWith('_') && !isFrameworkCallbackName(name)) {
			return { name, index: Math.max(0, line.indexOf(name)) };
		}
	}

	return undefined;
}

function detectLongFunctions(
	file: string,
	executableLines: readonly string[],
	originalLines: readonly string[],
	extension: string,
): AqironIssue[] {
	if (extension === '.py') {
		return detectPythonLongFunctions(file, executableLines, originalLines);
	}

	const issues: AqironIssue[] = [];
	const stack: FunctionStart[] = [];

	for (let index = 0; index < executableLines.length; index++) {
		const line = executableLines[index];
		if (isFunctionStart(line, extension)) {
			stack.push({
				line: index,
				braceDepth: countBraces(line),
				name: getFunctionName(line) ?? 'function',
			});
			continue;
		}

		if (stack.length === 0) {
			continue;
		}

		const active = stack[stack.length - 1];
		active.braceDepth += countBraces(line);
		if (active.braceDepth <= 0) {
			const length = index - active.line + 1;
			if (length > 100) {
				issues.push(createIssue(file, active.line, originalLines[active.line] ?? executableLines[active.line], {
					title: 'Long Function',
					message: `${active.name} is ${length} lines long. Consider splitting it into smaller functions.`,
					severity: 'Low',
					ruleId: 'low.long-function',
					index: 0,
					length: Math.max(1, executableLines[active.line].trim().length),
				}));
			}
			stack.pop();
		}
	}

	return issues;
}

function detectPythonLongFunctions(
	file: string,
	executableLines: readonly string[],
	originalLines: readonly string[],
): AqironIssue[] {
	const issues: AqironIssue[] = [];

	for (let index = 0; index < executableLines.length; index++) {
		const line = executableLines[index];
		const match = /^(\s*)def\s+([A-Za-z_]\w*)\s*\(/.exec(line);
		if (!match || isFrameworkCallbackName(match[2])) {
			continue;
		}

		const baseIndent = match[1].length;
		let endLine = index;
		for (let cursor = index + 1; cursor < executableLines.length; cursor++) {
			const candidate = executableLines[cursor];
			if (candidate.trim().length === 0) {
				continue;
			}
			const indent = candidate.length - candidate.trimStart().length;
			if (indent <= baseIndent) {
				break;
			}
			endLine = cursor;
		}

		const length = endLine - index + 1;
		if (length > 100) {
			issues.push(createIssue(file, index, originalLines[index] ?? line, {
				title: 'Long Function',
				message: `${match[2]} is ${length} lines long. Consider splitting it into smaller functions.`,
				severity: 'Low',
				ruleId: 'low.long-function',
				index: 0,
				length: Math.max(1, line.trim().length),
			}));
		}
	}

	return issues;
}

function matchRules(
	line: string,
	rules: Array<[RegExp, string, string, AqironSeverity, AqironRuleId | string]>,
): RuleMatch[] {
	return rules.flatMap(([pattern, title, message, severity, ruleId]) => {
		const match = pattern.exec(line);
		return match ? [{
			title,
			message,
			severity,
			ruleId,
			index: match.index,
			length: match[0].length,
		}] : [];
	});
}

function stripComments(content: string, extension: string): string {
	if (extension === '.py') {
		return stripPythonComments(content);
	}

	return stripSlashComments(content);
}

function stripSlashComments(content: string): string {
	let result = '';
	let inLineComment = false;
	let inBlockComment = false;
	let stringQuote: string | undefined;

	for (let index = 0; index < content.length; index++) {
		const char = content[index];
		const next = content[index + 1];

		if (inLineComment) {
			if (char === '\n') {
				inLineComment = false;
				result += char;
			} else {
				result += ' ';
			}
			continue;
		}

		if (inBlockComment) {
			if (char === '*' && next === '/') {
				result += '  ';
				index++;
				inBlockComment = false;
			} else {
				result += char === '\n' ? '\n' : ' ';
			}
			continue;
		}

		if (stringQuote) {
			result += char;
			if (char === '\\') {
				result += next ?? '';
				index++;
			} else if (char === stringQuote) {
				stringQuote = undefined;
			}
			continue;
		}

		if ((char === '"' || char === '\'' || char === '`')) {
			stringQuote = char;
			result += char;
			continue;
		}

		if (char === '/' && next === '/') {
			result += '  ';
			index++;
			inLineComment = true;
			continue;
		}

		if (char === '/' && next === '*') {
			result += '  ';
			index++;
			inBlockComment = true;
			continue;
		}

		result += char;
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
		for (let index = 0; index < line.length; index++) {
			const char = line[index];
			if (quote) {
				if (char === '\\') {
					index++;
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

function isFunctionStart(line: string, extension: string): boolean {
	const trimmed = line.trim();
	if (!trimmed.includes('{')) {
		return false;
	}

	if (jsExtensions.has(extension)) {
		return /^(?:export\s+)?(?:async\s+)?function\b|^(?:const|let)\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*{|^(?:public|private|protected)?\s*[A-Za-z_$][\w$]*\s*\([^)]*\)\s*{/.test(trimmed);
	}

	if (extension === '.dart') {
		return /^(?:Future<[^>]+>|void|String|int|double|bool|Widget|[A-Z]\w*)\s+\w+\s*\([^)]*\)\s*(?:async\s*)?{/.test(trimmed);
	}

	if (extension === '.java') {
		return /^(?:public|private|protected|static|final|\s)+[\w<>\[\]]+\s+\w+\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?{/.test(trimmed);
	}

	if (cExtensions.has(extension)) {
		return /^[\w:*&<>\s]+\s+\w+\s*\([^;]*\)\s*{/.test(trimmed);
	}

	if (extension === '.rs') {
		return /^(?:pub\s+)?(?:async\s+)?fn\s+\w+\s*\([^)]*\)\s*(?:->\s*[^{]+)?{/.test(trimmed);
	}

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

function createIssue(file: string, lineIndex: number, lineText: string, match: RuleMatch): AqironIssue {
	return {
		id: `${file}:${lineIndex + 1}:${match.ruleId}:${match.index}`,
		file,
		title: match.title,
		message: match.message,
		severity: match.severity,
		ruleId: match.ruleId,
		range: createSourceLocation(file, lineIndex, Math.max(0, match.index), lineIndex, Math.max(match.index + Math.max(1, match.length), match.index + 1)),
		lineText,
	};
}

function dedupeIssues(issues: AqironIssue[]): AqironIssue[] {
	const seen = new Set<string>();
	return issues.filter((issue) => {
		const key = issue.id;
		if (seen.has(key)) {
			return false;
		}
		seen.add(key);
		return true;
	});
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
