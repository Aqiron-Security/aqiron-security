import * as fs from 'fs/promises';
import * as path from 'path';
import { RagIndexService } from './ragIndexService';

export const benchmarkQueries = [
	'How does the app talk to Firebase?',
	'List all endpoints that use http',
];

export interface RagBenchmarkReport {
	generatedAt: string;
	queries: Array<{ query: string; lexicalTop5: string[]; hybridTop5: string[]; lexicalLatencyMs: number; hybridLatencyMs: number; lexicalPrecisionAt5: number; hybridPrecisionAt5: number }>;
	indexSizeBytes: number;
	precisionAt5?: number;
	relevanceBoost?: number;
}

export async function runRagBenchmark(root: string, index: RagIndexService): Promise<RagBenchmarkReport> {
	const queries = benchmarkQueries.map((query) => {
		const started = Date.now();
		const hybrid = index.search(query, 5);
		const hybridLatencyMs = Date.now() - started;
		const lexicalStarted = Date.now();
		const lexical = index.searchLexical(query, 5);
		const lexicalLatencyMs = Date.now() - lexicalStarted;
		const expectedSignal = query.toLowerCase().includes('firebase') ? 'database.firebase' : 'endpoint.rest';
		return { query, lexicalTop5: lexical.map((item) => `${item.chunk.relativePath}:${item.chunk.startLine}`), hybridTop5: hybrid.map((item) => `${item.chunk.relativePath}:${item.chunk.startLine}`), lexicalLatencyMs, hybridLatencyMs, lexicalPrecisionAt5: precisionAt5(lexical.map((item) => item.chunk.signalIds), expectedSignal), hybridPrecisionAt5: precisionAt5(hybrid.map((item) => item.chunk.signalIds), expectedSignal) };
	});
	const lexicalPrecision = queries.reduce((sum, query) => sum + query.lexicalPrecisionAt5, 0) / Math.max(1, queries.length);
	const hybridPrecision = queries.reduce((sum, query) => sum + query.hybridPrecisionAt5, 0) / Math.max(1, queries.length);
	const report: RagBenchmarkReport = { generatedAt: new Date().toISOString(), queries, indexSizeBytes: await fileSize(path.join(root, '.aqiron-security', 'index.json')), precisionAt5: hybridPrecision, relevanceBoost: lexicalPrecision > 0 ? (hybridPrecision - lexicalPrecision) / lexicalPrecision : hybridPrecision > 0 ? 1 : 0 };
	await fs.mkdir(path.join(root, '.aqiron-security', 'benchmarks'), { recursive: true });
	await fs.writeFile(path.join(root, '.aqiron-security', 'benchmarks', 'latest.json'), JSON.stringify(report, null, 2), 'utf8');
	return report;
}

async function fileSize(file: string): Promise<number> {
	try { return (await fs.stat(file)).size; } catch { return 0; }
}

function precisionAt5(signalIds: string[][], expectedSignal: string): number {
	return signalIds.filter((ids) => ids.includes(expectedSignal)).length / 5;
}
