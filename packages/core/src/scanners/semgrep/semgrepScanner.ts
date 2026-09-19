import * as path from 'path';
import { createFinding, normalizeSeverity, UnifiedFinding } from '../../shared/finding';
import { ToolAvailability, ScannerContext, ScannerResult, SecurityScanner, ScannerCapability } from '../types';
import { SemgrepFieldMapper } from '../../parsers/engineMappers';
import { SemgrepRuleManager } from './semgrepRuleManager';

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

export class SemgrepScanner implements SecurityScanner {
	readonly id = 'semgrep';
	readonly name = 'Semgrep OSS';
	readonly capabilities: ScannerCapability[] = ['source-code', 'secret'];

	constructor(
		private readonly parser = new SemgrepFieldMapper(),
		private readonly rules = new SemgrepRuleManager(),
	) {}

	async isAvailable(context: ScannerContext): Promise<ToolAvailability> {
		try {
			await context.processRunner.execFile('semgrep', { cwd: context.workspaceRoot, args: ['--version'], timeoutMs: 5_000, cancellationToken: context.cancellationToken, windowsHide: true });
			return { available: true };
		} catch (error) {
			return { available: false, reason: error instanceof Error ? error.message : String(error) };
		}
	}

	async scan(context: ScannerContext): Promise<ScannerResult> {
		const startedAt = Date.now();
		await context.filesystem.mkdir(path.join(context.workspaceRoot, '.aqiron'), { recursive: true });
		const configs = await this.rules.getConfigs(context);
		const args = [
			'scan',
			...configs.flatMap((config) => ['--config', config]),
			'--json',
			'--sarif-output',
			'.aqiron/semgrep.sarif',
			...this.rules.getExcludeArgs(context),
			context.targetPath,
		];
		const result = await context.processRunner.execFile('semgrep', {
			cwd: context.workspaceRoot,
			args,
			timeoutMs: 120_000,
			cancellationToken: context.cancellationToken,
			env: { PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
			windowsHide: true,
		});
		return {
			toolId: this.id,
			label: this.name,
			findings: this.parse(result.stdout, context.workspaceRoot),
			durationMs: Date.now() - startedAt,
		};
	}

	private parse(stdout: string, workspaceRoot: string): UnifiedFinding[] {
		const report = safeJson<SemgrepReport>(stdout);
		return (report?.results ?? []).map((result) => {
			const raw = result as Record<string, unknown>;
			const ruleId = this.parser.extractRuleId(raw);
			const cwe = this.parser.extractCwe(raw);
			const owasp = this.parser.extractOwasp(raw);
			const tags = this.parser.extractTags(raw);
			tags.push('source-code');
			const column = this.parser.extractColumn(raw) ?? 1;
			return createFinding({
				title: this.parser.extractTitle(raw),
				description: this.parser.extractDescription(raw),
				severity: normalizeSeverity(this.parser.extractSeverity(raw)),
				cwe,
				owasp,
				file: resolvePath(workspaceRoot, this.parser.extractFile(raw)),
				line: this.parser.extractLine(raw),
				column,
				endLine: this.parser.extractEndLine(raw),
				endColumn: this.parser.extractEndColumn(raw),
				sourceTool: 'Semgrep',
				ruleId,
				confidence: normalizeConfidence(this.parser.extractConfidence(raw)),
				remediation: this.parser.extractRemediation(raw),
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
