import * as path from 'path';
import * as vscode from 'vscode';
import { AqironSeverity } from '../models/issue';

export interface ResolvedVsCodeCustomRule {
	id: string;
	title: string;
	message: string;
	severity: AqironSeverity;
	pattern: string;
	extensions?: string[];
	caseSensitive?: boolean;
}

/** Resolve configured rules into portable values for Core scan requests. */
export function getResolvedCustomRules(): ResolvedVsCodeCustomRule[] {
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

/** Portable file-rule policy; matching runs in Core. */
export function getResolvedCurrentFileRules(file: string): ResolvedVsCodeCustomRule[] {
	const extension = path.extname(file).toLowerCase();
	const rule = (pattern: RegExp, title: string, message: string, severity: AqironSeverity, id: string): ResolvedVsCodeCustomRule => ({
		id, title, message, severity, pattern: pattern.source, extensions: [extension], caseSensitive: !pattern.flags.includes('i'),
	});
	const secrets = [
		rule(/\b(?:api[_-]?key|client[_-]?secret|access[_-]?key)\b\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]/, 'Hardcoded API Key', 'Move hardcoded API keys to a secret manager or environment variable.', 'Critical', 'critical.api-key'),
		rule(/\bAKIA[0-9A-Z]{16}\b/, 'Hardcoded API Key', 'AWS access keys must not be stored in source code.', 'Critical', 'critical.api-key'),
		rule(/\bAIza[0-9A-Za-z_\-]{35}\b/, 'Hardcoded API Key', 'Google API keys must not be stored in source code.', 'Critical', 'critical.api-key'),
		rule(/\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{20,}\b/, 'Hardcoded API Key', 'Provider API keys must not be stored in source code.', 'Critical', 'critical.api-key'),
		rule(/\b(?:secret|token)\b\s*[:=]\s*['"][A-Za-z0-9_\-./+=]{16,}['"]/, 'Hardcoded Secret', 'Move hardcoded secrets to a protected secret source.', 'Critical', 'critical.secret'),
		rule(/\bpassword\b\s*[:=]\s*['"][^'"\s]{8,}['"]/, 'Hardcoded Password', 'Move hardcoded passwords to a protected secret source.', 'Critical', 'critical.password'),
		rule(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, 'Private Key Material', 'Private key material must not be stored in source code.', 'Critical', 'critical.private-key'),
	];
	let builtIns = [...secrets];
	if (extension === '.dart') {
		builtIns.push(
			rule(/\bprint\s*\(/, 'Flutter print() Statement', 'Use structured logging or remove print() before shipping Flutter apps.', 'Medium', 'medium.print'),
			rule(/\bdebugPrint\s*\(/, 'Flutter debugPrint() Statement', 'Remove debugPrint() or guard it behind a debug-only condition.', 'Medium', 'medium.debug'),
			rule(/['"]http:\/\/[^'"]+['"]/, 'Insecure HTTP URL', 'Use HTTPS for Flutter network calls unless a clear exception is required.', 'Medium', 'medium.insecure-http'),
		);
	} else if (['.js', '.jsx', '.ts', '.tsx'].includes(extension)) {
		builtIns.push(
			rule(/\bconsole\.log\s*\(/, 'Console Statement', 'console.log should not be committed in production code.', 'Medium', 'medium.console-log'),
			rule(/\beval\s*\(/, 'Dangerous eval()', 'Avoid eval() because it can execute untrusted code.', 'High', 'high.eval'),
			rule(/\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(/, 'Shell Execution', 'child_process shell execution can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'),
			rule(/\b(?:exec|execSync|spawn|spawnSync)\s*\(/, 'Shell Execution', 'Shell execution can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'),
			rule(/\brejectUnauthorized\s*:\s*false\b/, 'TLS Verification Disabled', 'Do not disable TLS certificate validation. Use trusted certificates and keep rejectUnauthorized enabled.', 'High', 'high.tls-disabled'),
			rule(/\bcors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/i, 'Permissive CORS Origin', 'Avoid wildcard CORS on authenticated or sensitive APIs. Restrict origins to trusted domains.', 'High', 'high.permissive-cors'),
			rule(/\bjwt\.verify\s*\([^)]*,\s*['"][^'"]*['"]\s*,\s*\{[^}]*ignoreExpiration\s*:\s*true/i, 'JWT Expiration Ignored', 'Do not ignore JWT expiration during verification.', 'High', 'high.jwt-expiration-ignored'),
			rule(/\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/, 'TLS Verification Disabled', 'Do not disable TLS verification with NODE_TLS_REJECT_UNAUTHORIZED=0.', 'High', 'high.tls-disabled'),
		);
	} else if (extension === '.py') {
		builtIns.push(
			rule(/\bexec\s*\(/, 'Dangerous exec()', 'Avoid exec() because it can execute untrusted code.', 'High', 'high.eval'),
			rule(/\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(/, 'Dangerous Subprocess', 'Subprocess execution can become command injection when arguments are user-controlled.', 'High', 'high.subprocess'),
			rule(/\bpickle\.loads\s*\(/, 'Unsafe Deserialization', 'pickle.loads can execute code during deserialization. Avoid it for untrusted data.', 'High', 'high.unsafe-deserialization'),
			rule(/\byaml\.load\s*\([^)]*(?:Loader\s*=\s*yaml\.Loader|FullLoader)?/i, 'Unsafe YAML Loading', 'Use yaml.safe_load for untrusted data.', 'High', 'high.unsafe-deserialization'),
			rule(/\bverify\s*=\s*False\b/, 'TLS Verification Disabled', 'Do not disable TLS certificate validation in HTTP clients.', 'High', 'high.tls-disabled'),
			rule(/\bDEBUG\s*=\s*True\b/, 'Debug Mode Enabled', 'Debug mode can expose stack traces and secrets in production.', 'Medium', 'medium.debug'),
		);
	} else if (['.c', '.cpp', '.h'].includes(extension)) {
		builtIns.push(
			rule(/\bsystem\s*\(/, 'Shell Execution', 'system() can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'),
			rule(/\bstrcpy\s*\(/, 'Unsafe C API', 'strcpy() can overflow buffers. Prefer bounded alternatives.', 'High', 'high.unsafe-c-api'),
			rule(/\bgets\s*\(/, 'Unsafe C API', 'gets() is unsafe and should not be used.', 'High', 'high.unsafe-c-api'),
			rule(/\bsprintf\s*\(/, 'Unsafe C API', 'sprintf() can overflow buffers. Prefer snprintf() with explicit bounds.', 'High', 'high.unsafe-c-api'),
			rule(/\bmemcpy\s*\([^,]+,[^,]+,\s*strlen\s*\(/, 'Unsafe Copy Length', 'Copying strlen() bytes with memcpy can miss terminators and cause memory safety defects.', 'Medium', 'medium.unsafe-copy'),
		);
	} else if (extension === '.java') {
		builtIns.push(
			rule(/\bRuntime\.getRuntime\(\)\.exec\s*\(/, 'Shell Execution', 'Runtime.exec() can become command injection when arguments are user-controlled.', 'High', 'high.shell-execution'),
			rule(/\bsetJavaScriptEnabled\s*\(\s*true\s*\)/, 'WebView JavaScript Enabled', 'Only enable WebView JavaScript for trusted content and harden bridges.', 'Medium', 'medium.webview-javascript'),
			rule(/\bsetAllowFileAccess\s*\(\s*true\s*\)/, 'WebView File Access Enabled', 'Avoid WebView file access unless it is strictly required and sandboxed.', 'High', 'high.webview-file-access'),
			rule(/\bTrustManager\b|\bHostnameVerifier\b/, 'Custom TLS Trust Manager', 'Custom certificate or hostname trust logic can disable TLS protections. Prefer platform defaults.', 'High', 'high.tls-disabled'),
		);
	}
	return [...builtIns, ...getResolvedCustomRules()];
}

const defaultCustomRules: ResolvedVsCodeCustomRule[] = [
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
