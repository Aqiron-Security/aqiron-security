import * as path from 'path';
import { createFinding, normalizeSeverity, UnifiedFinding } from '../findings/finding';
import { SemgrepFieldMapper } from './engineMappers';

interface SemgrepReport {
	results?: SemgrepResult[];
}

interface SemgrepResult {
	check_id?: string;
	path?: string;
	start?: { line?: number; col?: number };
	end?: { line?: number; col?: number };
	extra?: {
		message?: string;
		severity?: string;
		metadata?: {
			cwe?: string | string[];
			owasp?: string | string[];
			confidence?: string;
			impact?: string;
			technology?: string[];
			category?: string;
			references?: string[];
		};
		lines?: string;
		fingerprint?: string;
		fix?: string;
	};
}

export class SemgrepParser {
	private mapper = new SemgrepFieldMapper();

	parse(stdout: string, workspaceRoot: string): UnifiedFinding[] {
		const report = safeJson<SemgrepReport>(stdout);
		return (report?.results ?? []).map((result) => {
			const raw = result as Record<string, unknown>;

			const ruleId = this.mapper.extractRuleId(raw);
			const cwe = this.mapper.extractCwe(raw);
			const owasp = this.mapper.extractOwasp(raw);
			const tags = this.mapper.extractTags(raw);

			// Add source_type tag for source code analysis
			tags.push('source-code');

			// Handle optional column with safe fallback
			const column = this.mapper.extractColumn(raw) ?? 1;

			return createFinding({
				title: this.mapper.extractTitle(raw),
				description: this.mapper.extractDescription(raw),
				severity: normalizeSeverity(this.mapper.extractSeverity(raw)),
				cwe,
				owasp,
				file: resolvePath(workspaceRoot, this.mapper.extractFile(raw)),
				line: this.mapper.extractLine(raw),
				column,
				endLine: this.mapper.extractEndLine(raw),
				endColumn: this.mapper.extractEndColumn(raw),
				sourceTool: 'Semgrep',
				ruleId,
				confidence: normalizeConfidence(this.mapper.extractConfidence(raw)),
				remediation: this.mapper.extractRemediation(raw),
				tags,
				rawEvidence: result,
				fingerprint: result.extra?.fingerprint,
			});
		});
	}
}

function safeJson<T>(value: string): T | undefined {
	try {
		return JSON.parse(value) as T;
	} catch {
		return undefined;
	}
}

function resolvePath(workspaceRoot: string, file?: string): string {
	if (!file) {
		return workspaceRoot;
	}
	return path.isAbsolute(file) ? file : path.join(workspaceRoot, file);
}

function normalizeMetadataArray(value: string | string[] | undefined): string[] {
	if (Array.isArray(value)) {
		return value;
	}
	if (!value) {
		return [];
	}
	return [value];
}

function normalizeConfidence(value: string | undefined): 'Low' | 'Medium' | 'High' {
	const normalized = value?.toLowerCase();
	if (normalized === 'high') {
		return 'High';
	}
	if (normalized === 'low') {
		return 'Low';
	}
	return 'Medium';
}
