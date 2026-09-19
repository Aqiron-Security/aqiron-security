import * as path from 'path';
import { UnifiedFinding } from '../../shared';
import { AIContextSnapshot } from '../../shared/ai';
import { AIService } from '../services/aiService';
import type { AIChatInput } from '../services/aiService';

export class AIReviewService {
	constructor(private readonly aiService: AIService) {}

	async explainFinding(finding: UnifiedFinding): Promise<string> {
		return await this.runReview({
			title: `Explain the security finding: ${finding.title}`,
			prompt: `Explain the vulnerability, why it matters, and the safest remediation path. Focus on the evidence and avoid speculation.`,
			findings: [finding],
		});
	}

	async summarizeFindings(findings: readonly UnifiedFinding[]): Promise<string> {
		return await this.runReview({
			title: 'Summarize the current security findings',
			prompt: 'Summarize the overall scan results, prioritize the highest-risk issues, and give concise remediation guidance.',
			findings,
		});
	}

	private async runReview(input: { title: string; prompt: string; findings: readonly UnifiedFinding[] }): Promise<string> {
		const state = await this.aiService.getState();
		const model = state.selection.model;
		if (!model) {
			throw new Error('Select a model before starting AI review.');
		}
		const context = this.buildContext(input.findings);
		const request: AIChatInput = {
			sessionId: `ai-review-${Date.now()}`,
			text: input.prompt,
			history: [],
			model,
			intelligence: 'Medium',
			context,
		};
		let output = '';
		for await (const chunk of this.aiService.chat(request)) {
			if (chunk.type === 'error') {
				throw new Error(chunk.error ?? 'AI review failed.');
			}
			if (chunk.type === 'token') {
				output += chunk.content ?? '';
			}
		}
		return output.trim() || `${input.title}.`;
	}

	private buildContext(findings: readonly UnifiedFinding[]): AIContextSnapshot {
		const first = findings[0];
		const workspaceRoot = first ? path.dirname(first.file) : undefined;
		return {
			workspaceName: 'AI Review',
			workspaceRoot,
			projectTypes: [],
			backend: 'AI Review',
			currentFile: first?.file ?? 'n/a',
			scanStatus: 'Complete',
			stats: {
				filesScanned: findings.length,
				indexedFiles: findings.length,
			},
			apis: [],
			issues: findings.map((finding) => ({
				title: finding.title,
				message: finding.description,
				severity: finding.severity,
				ruleId: finding.ruleId,
				file: finding.file,
				line: finding.line,
				lineText: '',
				remediation: finding.remediation,
			})),
		};
	}
}
