import { HYPOTHESIS_AI_PREPARATION_LIMITS } from './contracts';
import type { HypothesisEvidenceRef } from './contracts';

/** Canonical proposal fields shared by the provider schema, prompt, and Core validator. */
export const HYPOTHESIS_AI_PROPOSAL_FIELDS = Object.freeze({
	title: { schema: { type: 'string' }, example: 'Review the authentication boundary' },
	claim: { schema: { type: 'string' }, example: 'Could this route accept an unauthenticated request?' },
	evidenceRationale: { schema: { type: 'string' }, example: 'The selected evidence identifies the route and its guard.' },
	supportingEvidenceAliases: { schema: { type: 'array', items: { type: 'string' } }, example: ['e1'] },
	contradictoryEvidenceAliases: { schema: { type: 'array', items: { type: 'string' } }, example: [] },
	verificationCriteria: { schema: { type: 'array', items: { type: 'string' } }, example: ['Review the route guard and caller.'] },
	falsificationCriteria: { schema: { type: 'array', items: { type: 'string' } }, example: ['Confirm unauthenticated requests are rejected.'] },
	uncertainties: { schema: { type: 'array', items: { type: 'string' } }, example: ['Runtime configuration was not observed.'] },
} as const);

export const HYPOTHESIS_AI_MAX_EVIDENCE_ALIASES = HYPOTHESIS_AI_PREPARATION_LIMITS.maxEvidenceSelectors;

export function hypothesisAiProposalKeys(): string[] {
	return Object.keys(HYPOTHESIS_AI_PROPOSAL_FIELDS);
}

export function hypothesisAiProposalSchemaProperties(): Record<string, unknown> {
	return Object.fromEntries(Object.entries(HYPOTHESIS_AI_PROPOSAL_FIELDS).map(([key, field]) => [key, field.schema]));
}

export function hypothesisAiProposalExample(): Record<string, unknown> {
	return Object.fromEntries(Object.entries(HYPOTHESIS_AI_PROPOSAL_FIELDS).map(([key, field]) => [key, field.example]));
}

/** Assigns the one canonical alias map; callers still validate each reference against Core evidence. */
export function canonicalHypothesisAiEvidenceAliases(references: readonly HypothesisEvidenceRef[]): Array<{ alias: string; reference: HypothesisEvidenceRef }> {
	if (references.length > HYPOTHESIS_AI_MAX_EVIDENCE_ALIASES) {throw new RangeError('Hypothesis synthesis evidence exceeds the alias limit.');}
	const sorted = [...references].sort((left, right) => left.id.localeCompare(right.id));
	const ids = new Set<string>();
	return sorted.map((reference, index) => {
		if (!reference || typeof reference.id !== 'string' || reference.id.length === 0 || ids.has(reference.id)) {
			throw new TypeError('Hypothesis synthesis aliases require unique evidence references.');
		}
		ids.add(reference.id);
		return { alias: `e${index + 1}`, reference };
	});
}

/** Detects duplicate decoded property names in syntactically valid JSON. */
export function hasDuplicateJsonObjectKeys(json: string): boolean {
	const objects: Array<Set<string>> = [];
	for (let index = 0; index < json.length; index += 1) {
		const character = json[index];
		if (character === '{') { objects.push(new Set()); continue; }
		if (character === '}') { objects.pop(); continue; }
		if (character !== '"') { continue; }
		const start = index;
		index += 1;
		while (index < json.length) {
			if (json[index] === '\\') { index += 2; continue; }
			if (json[index] === '"') { break; }
			index += 1;
		}
		if (objects.length === 0) {continue;}
		let next = index + 1;
		while (/\s/.test(json[next] ?? '')) { next += 1; }
		if (json[next] !== ':') {continue;}
		let key: unknown;
		try {key = JSON.parse(json.slice(start, index + 1)) as unknown;} catch {continue;}
		if (typeof key !== 'string') {continue;}
		const current = objects[objects.length - 1]!;
		if (current.has(key)) {return true;}
		current.add(key);
	}
	return false;
}
