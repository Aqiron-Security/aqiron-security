import { AqironSeverity } from './issue';

export interface WorkspaceRecommendation {
	title: string;
	detail: string;
	severity?: AqironSeverity;
	recommended?: boolean;
	command: string;
	metadata?: { ruleId?: string; file?: string; line?: number; category?: string };
}

export interface RecommendationParseDiagnostics {
	format: 'empty' | 'json' | 'fenced-json' | 'text' | 'malformed-json';
	branch: 'empty' | 'json-array' | 'json-recommendations' | 'json-object' | 'text-lines' | 'malformed-json';
	candidates: number;
	accepted: number;
	rejected: number;
	rejectionReasons: Record<string, number>;
}

/** Parse structured JSON and legacy text recommendation formats used by Aqiron clients. */
export function parseRecommendationSource(source: string): WorkspaceRecommendation[] {
	return parseRecommendationSourceDetailed(source).recommendations;
}

export function parseRecommendationSourceDetailed(source: string): { recommendations: WorkspaceRecommendation[]; diagnostics: RecommendationParseDiagnostics } {
	const text = source.trim();
	if (!text) { return { recommendations: [], diagnostics: { format: 'empty', branch: 'empty', candidates: 0, accepted: 0, rejected: 0, rejectionReasons: {} } }; }
	const fenced = /^```(?:json)?\s*/i.test(text);
	const jsonText = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
	try {
		const parsed: unknown = JSON.parse(jsonText);
		const branch = Array.isArray(parsed) ? 'json-array' : isRecord(parsed) && Array.isArray(parsed.recommendations) ? 'json-recommendations' : 'json-object';
		const entries = Array.isArray(parsed) ? parsed : isRecord(parsed) && Array.isArray(parsed.recommendations) ? parsed.recommendations : [parsed];
		const rejectionReasons: Record<string, number> = {};
		const accepted = entries.flatMap((entry) => {
			const parsedEntry = isRecord(entry) ? structuredRecommendation(entry) : { recommendation: undefined, reason: 'invalid-shape' };
			if (!parsedEntry.recommendation) {
				rejectionReasons[parsedEntry.reason ?? 'invalid-shape'] = (rejectionReasons[parsedEntry.reason ?? 'invalid-shape'] ?? 0) + 1;
			}
			return parsedEntry.recommendation ? [parsedEntry.recommendation] : [];
		}).slice(0, 5);
		return { recommendations: accepted, diagnostics: { format: fenced ? 'fenced-json' : 'json', branch, candidates: entries.length, accepted: accepted.length, rejected: entries.length - accepted.length, rejectionReasons } };
	} catch {
		if (/^[\[{]/.test(jsonText)) {
			return { recommendations: [], diagnostics: { format: 'malformed-json', branch: 'malformed-json', candidates: 0, accepted: 0, rejected: 0, rejectionReasons: { malformedJson: 1 } } };
		}
		const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
		const rejectionReasons: Record<string, number> = {};
		const parsed = lines.map((line) => {
			const item = legacyRecommendation(line);
			if (!item) {
				const reason = isReasoningText(line) ? 'reasoning-content' : 'invalid-text-line';
				rejectionReasons[reason] = (rejectionReasons[reason] ?? 0) + 1;
			}
			return item;
		});
		const recommendations = parsed.filter((item): item is WorkspaceRecommendation => Boolean(item)).slice(0, 5);
		return { recommendations, diagnostics: { format: 'text', branch: 'text-lines', candidates: lines.length, accepted: recommendations.length, rejected: lines.length - recommendations.length, rejectionReasons } };
	}
}

function structuredRecommendation(value: Record<string, unknown>): { recommendation?: WorkspaceRecommendation; reason?: string } {
	if (typeof value.title !== 'string' || typeof (value.detail ?? value.description) !== 'string') { return { reason: 'invalid-shape' }; }
	const title = value.title.trim();
	const detail = String(value.detail ?? value.description).trim();
	if (!title || !detail) { return { reason: 'missing-title-or-detail' }; }
	if (isReasoningText(title) || isReasoningText(detail)) { return { reason: 'reasoning-content' }; }
	const severity = isSeverity(value.severity) ? value.severity : undefined;
	const metadataValue = isRecord(value.metadata) ? value.metadata : {};
	const metadata = {
		...(typeof metadataValue.ruleId === 'string' ? { ruleId: metadataValue.ruleId } : {}),
		...(typeof metadataValue.file === 'string' ? { file: metadataValue.file } : {}),
		...(typeof metadataValue.line === 'number' && Number.isFinite(metadataValue.line) ? { line: metadataValue.line } : {}),
		...(typeof metadataValue.category === 'string' ? { category: metadataValue.category } : {}),
	};
	return { recommendation: { title, detail, ...(severity ? { severity } : {}), ...(typeof value.recommended === 'boolean' ? { recommended: value.recommended } : {}), command: typeof value.command === 'string' && value.command.trim() ? value.command.trim() : `${title}: ${detail}`, ...(Object.keys(metadata).length ? { metadata } : {}) } };
}

function legacyRecommendation(line: string): WorkspaceRecommendation | undefined {
	const content = line.replace(/^\s*(?:[-*+] |\d+[.)]\s*)/, '').replace(/^\*\*(.+)\*\*$/, '$1').trim();
	if (!content || isReasoningText(content)) { return undefined; }
	const titled = content.match(/^\*\*(.{2,100}?)\*\*\s*[:—-]\s*(.{3,})$/) ?? content.match(/^([^:—-]{3,90})\s*[:—]\s*(.{3,})$/);
	const title = titled?.[1]?.trim() ?? firstSentence(content);
	if (!title || isReasoningText(title)) { return undefined; }
	const detail = titled?.[2]?.trim() ?? (title === content ? '' : content.slice(title.length).replace(/^[.\s-]+/, '').trim());
	return { title, detail, command: content };
}

function firstSentence(value: string): string {
	const match = value.match(/^(.{1,100}?[.!?])(?:\s|$)/);
	return (match?.[1] ?? value.slice(0, 100)).trim();
}

function isReasoningText(value: string): boolean {
	return /^(?:here(?:['’]s| is) (?:a )?(?:thinking|reasoning) process\b|let me (?:think|reason)\b|i (?:will|should|need to) (?:think|reason|analy[sz]e)\b|step\s*\d+\s*:\s*(?:thinking|analysis)\b)/i.test(value.trim());
}

function isSeverity(value: unknown): value is AqironSeverity {
	return value === 'Critical' || value === 'High' || value === 'Medium' || value === 'Low';
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
