import { FileSystem } from '../shared/platform';
import { RagChunk, RagSearchResult } from './types';

interface StoredVector {
	id: string;
	values: number[];
}

export class RagVectorService {
	private vectors = new Map<string, number[]>();
	private chunks: RagChunk[] = [];
	private backend: 'faiss' | 'local' = 'local';
	private faiss: { index: { search: (values: Float32Array, count: number) => { labels?: number[]; distances?: number[] } }; ids: string[] } | undefined;

	constructor(private readonly filesystem: FileSystem) {}

	async initialize(root: string): Promise<void> {
		this.backend = 'local';
		try {
			const raw = await this.filesystem.readFile(`${root}/.aqiron-security/vectors.json`, 'utf8');
			const stored = JSON.parse(raw) as StoredVector[];
			this.vectors = new Map(stored.map((item) => [item.id, item.values]));
		} catch {
			this.vectors.clear();
		}
	}

	async rebuild(root: string, chunks: RagChunk[]): Promise<void> {
		this.chunks = chunks;
		this.vectors = new Map(chunks.map((chunk) => [chunk.id, embed(chunk.text)]));
		this.faiss = createFaissIndex([...this.vectors]);
		this.backend = this.faiss ? 'faiss' : 'local';
		await this.filesystem.mkdir(`${root}/.aqiron-security`, { recursive: true });
		await this.filesystem.writeFile(`${root}/.aqiron-security/vectors.json`, JSON.stringify([...this.vectors].map(([id, values]) => ({ id, values }))), 'utf8');
	}

	search(query: string, chunks = this.chunks, limit = 5): RagSearchResult[] {
		const queryTokens = tokenize(query);
		const queryVector = embed(query);
		const nativeScores = this.searchFaiss(queryVector, limit);
		return chunks.map((chunk) => {
			const lexicalScore = overlap(queryTokens, chunk.tokens);
			const semanticScore = nativeScores.get(chunk.id) ?? cosine(queryVector, this.vectors.get(chunk.id) ?? embed(chunk.text));
			return { chunk, lexicalScore, semanticScore, score: lexicalScore * 0.6 + semanticScore * 0.4 };
		}).sort((left, right) => right.score - left.score).filter((item, index, all) => all.findIndex((candidate) => candidate.chunk.relativePath === item.chunk.relativePath && candidate.chunk.startLine === item.chunk.startLine) === index).slice(0, limit);
	}

	getBackend(): 'faiss' | 'local' {
		return this.backend;
	}

	private searchFaiss(query: number[], limit: number): Map<string, number> {
		if (!this.faiss) {
			return new Map();
		}
		try {
			const result = this.faiss.index.search(Float32Array.from(query), limit);
			const scores = new Map<string, number>();
			for (let index = 0; index < (result.labels?.length ?? 0); index++) {
				const id = this.faiss.ids[result.labels?.[index] ?? -1];
				if (id) {
					scores.set(id, 1 / (1 + (result.distances?.[index] ?? 0)));
				}
			}
			return scores;
		} catch {
			this.faiss = undefined;
			this.backend = 'local';
			return new Map();
		}
	}
}

export function tokenize(value: string): string[] {
	return [...new Set(value.toLowerCase().match(/[a-z0-9_@./:-]{2,}/g) ?? [])];
}

function embed(value: string): number[] {
	const vector = new Array<number>(128).fill(0);
	for (const token of tokenize(value)) {
		let hash = 2166136261;
		for (let index = 0; index < token.length; index++) {
			hash = Math.imul(hash ^ token.charCodeAt(index), 16777619);
		}
		vector[Math.abs(hash) % vector.length] += 1;
	}
	const magnitude = Math.sqrt(vector.reduce((sum, item) => sum + item * item, 0)) || 1;
	return vector.map((item) => item / magnitude);
}

function overlap(left: string[], right: string[]): number {
	if (left.length === 0 || right.length === 0) {
		return 0;
	}
	const matches = left.filter((token) => right.includes(token)).length;
	return matches / Math.max(left.length, right.length);
}

function cosine(left: number[], right: number[]): number {
	return left.reduce((sum, value, index) => sum + value * (right[index] ?? 0), 0);
}

function createFaissIndex(entries: Array<[string, number[]]>): RagVectorService['faiss'] | undefined {
	try {
		const dynamicRequire = Function('return require')() as NodeRequire;
		const native = dynamicRequire('faiss-node') as { IndexFlatL2?: new (dimensions: number) => { add: (values: Float32Array) => void; search: (values: Float32Array, count: number) => { labels?: number[]; distances?: number[] } } };
		if (!native.IndexFlatL2 || entries.length === 0) {
			return undefined;
		}
		const index = new native.IndexFlatL2(128);
		index.add(Float32Array.from(entries.flatMap(([, values]) => values)));
		return { index, ids: entries.map(([id]) => id) };
	} catch {
		return undefined;
	}
}
