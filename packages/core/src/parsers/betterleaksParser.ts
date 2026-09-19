import * as path from 'path';
import { createFinding, normalizeSeverity, UnifiedFinding } from '../findings/finding';

interface BetterleaksReport {
	findings?: BetterleaksFinding[];
}
interface BetterleaksFinding {
	RuleID?: string;
	Description?: string;
	File?: string;
	StartLine?: number;
	EndLine?: number;
	StartColumn?: number;
	EndColumn?: number;
	Secret?: unknown;
	Match?: unknown;
	Tags?: string[];
	Fingerprint?: string;
	Validation?: unknown;
	Severity?: string;
}

export class BetterleaksParser {
	parse(stdout: string, workspaceRoot: string): UnifiedFinding[] {
		const parsed = safeJson<BetterleaksReport | BetterleaksFinding[]>(stdout);
		if (parsed === undefined && stdout.trim()) {
			throw new Error('Betterleaks returned malformed JSON output.');
		}
		const findings = Array.isArray(parsed) ? parsed : parsed?.findings;
		if (!findings) {
			return [];
		}
		return findings.map((finding) => {
			const ruleId = finding.RuleID || 'BETTERLEAKS-SECRET';
			const file = resolvePath(workspaceRoot, finding.File);
			return createFinding({
				title: finding.Description || `${ruleId} secret detected`,
				description: 'Betterleaks detected exposed secret-like material. The secret value has been redacted.',
				severity: normalizeSeverity(finding.Severity || 'High'),
				cwe: ['CWE-798'],
				owasp: ['A02:2021-Cryptographic Failures'],
				file,
				line: finding.StartLine ?? 1,
				column: finding.StartColumn ?? 1,
				endLine: finding.EndLine,
				endColumn: finding.EndColumn,
				sourceTool: 'Betterleaks',
				ruleId,
				confidence: 'High',
				remediation: 'Rotate the exposed credential and move it into a managed secret store.',
				tags: ['secret', 'credential', 'source-code', ...(finding.Tags ?? [])],
				rawEvidence: redactFinding(finding),
				fingerprint: finding.Fingerprint,
			});
		});
	}
}

function safeJson<T>(value: string): T | undefined {
	try { return JSON.parse(value) as T; } catch { return undefined; }
}

function resolvePath(root: string, file?: string): string {
	return file && path.isAbsolute(file) ? file : path.join(root, file || '');
}

function redactFinding(finding: BetterleaksFinding): Record<string, unknown> {
	return redactValue(finding) as Record<string, unknown>;
}

function redactValue(value: unknown, key = ''): unknown {
	if (/(secret|match|password|token|credential|authorization|api.?key|private.?key)/i.test(key)) {
		return '[redacted]';
	}
	if (Array.isArray(value)) { return value.map((item) => redactValue(item, key)); }
	if (value && typeof value === 'object') {
		return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, redactValue(childValue, childKey)]));
	}
	return value;
}
