import { SecurityAnalysisContext, SecurityRagEvidence } from '../shared/analysis';
import { RagIndexService } from './ragIndexService';

export class RagRetrievalService {
	constructor(private readonly rag: RagIndexService) {}

	async retrieve(context: SecurityAnalysisContext): Promise<RagRetrievalResult[]> {
		const results: RagRetrievalResult[] = [];
		let available = false;
		try {
			available = await this.rag.hasIndex(context.workspaceRoot ?? '');
		} catch {
			available = false;
		}
		if (!available) {
			return results;
		}
		const chunks = new Map<string, RagRetrievalResult>();
		for (const query of context.retrievalQueries) {
			const matches = this.rag.search(query, 6);
			for (const match of matches) {
				const evidence = toEvidence(query, match);
				const key = `${evidence.file}:${evidence.startLine}:${evidence.endLine}`;
				const existing = chunks.get(key);
				if (!existing || existing.score < evidence.score) {
					chunks.set(key, evidence);
				}
			}
		}
		for (const evidence of chunks.values()) {
			results.push(evidence);
		}
		return results.sort((left, right) => right.score - left.score).slice(0, 12);
	}
}

export interface RagRetrievalResult extends SecurityRagEvidence {}

function toEvidence(query: string, result: ReturnType<RagIndexService['search']>[number]): RagRetrievalResult {
	return {
		query,
		file: result.chunk.relativePath,
		startLine: result.chunk.startLine,
		endLine: result.chunk.endLine,
		score: Number((result.score * 100).toFixed(2)),
		excerpt: redactSecrets(result.chunk.text.slice(0, 1200)),
		signalIds: result.chunk.signalIds,
	};
}

function redactSecrets(value: string): string {
	return value
		.replace(/\b(?:sk|pk|ghp|glpat|xox[baprs]?)-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]')
		.replace(/\b[A-Za-z0-9_\/+=-]{32,}\b/g, '[REDACTED]')
		.replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED]');
}
