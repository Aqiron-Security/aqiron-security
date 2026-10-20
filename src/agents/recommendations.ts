import { AqironSeverity } from '../models/issue';
import { parseRecommendationSource, WorkspaceRecommendation } from '../../packages/core/src/shared/recommendations';

export { parseRecommendationSource };
export type { WorkspaceRecommendation };

export interface RecommendationIssue {
	title: string;
	message: string;
	severity: AqironSeverity;
	relativeFile: string;
	line: number;
	ruleId?: string;
}

/** Project generated recommendation content without inventing titles or fallback actions. */
export function buildWorkspaceRecommendations(issues: readonly RecommendationIssue[], aiSuggestions: readonly string[] = []): WorkspaceRecommendation[] {
	const generated = aiSuggestions.flatMap(parseRecommendationSource);
	const fromFindings = issues.slice(0, 4).map((issue): WorkspaceRecommendation => ({
		title: issue.title,
		detail: issue.message,
		severity: issue.severity,
		recommended: issue.severity === 'Critical' || issue.severity === 'High',
		command: `Investigate ${issue.relativeFile}:${issue.line}`,
		metadata: { ...(issue.ruleId ? { ruleId: issue.ruleId } : {}), file: issue.relativeFile, line: issue.line },
	}));
	return [...generated, ...fromFindings];
}

/** Accepts current structured JSON and legacy plain-text suggestion files. */
export function recommendationChatPayload(recommendation: WorkspaceRecommendation, action: 'run' | 'explain'): { text: string; useTaskDefaults: true } {
	return { text: action === 'run' ? recommendation.command : `Explain ${recommendation.title}`, useTaskDefaults: true };
}

