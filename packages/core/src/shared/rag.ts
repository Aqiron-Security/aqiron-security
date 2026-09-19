export type RegexCategory = 'database' | 'payment' | 'llm' | 'secret' | 'endpoint' | 'service';
export type SignalEvidence = 'regex' | 'ast' | 'filename';

export interface RegexSignal {
	id: string;
	category: RegexCategory;
	provider: string;
	pattern: string;
	flags?: string;
	extensions?: string[];
	confidence: 'Low' | 'Medium' | 'High';
	description: string;
	falsePositiveGuidance: string;
	positiveSamples?: string[];
}

export interface SecuritySignal {
	id: string;
	category: RegexCategory;
	provider: string;
	confidence: 'Low' | 'Medium' | 'High';
	evidenceType: SignalEvidence;
	file: string;
	line: number;
	column: number;
	match?: string;
	description: string;
}

export interface RegexSourceRecord {
	id: string;
	name: string;
	type: 'official-docs' | 'curated-github' | 'vetted-json';
	url: string;
	checksum?: string;
	lastSyncedAt?: string;
	status: 'pending' | 'validated' | 'failed';
	patterns: RegexSignal[];
	rejected: Array<{ id?: string; reason: string }>;
}

export interface RegexCatalog {
	version: 1;
	updatedAt: string;
	sources: RegexSourceRecord[];
}

export interface FileSignalRecord {
	relativePath: string;
	mtimeMs: number;
	size: number;
	contentHash: string;
	tokens: string[];
	signals: SecuritySignal[];
	indexedAt: string;
}

export interface RagChunk {
	id: string;
	relativePath: string;
	startLine: number;
	endLine: number;
	text: string;
	tokens: string[];
	signalIds: string[];
}

export interface RagManifest {
	version: 1;
	createdAt: string;
	updatedAt: string;
	filesIndexed: number;
	filesSkipped: number;
	errors: Array<{ file: string; message: string }>;
	aiSuggestionsGenerated: boolean;
}

export interface RagIndexData {
	manifest: RagManifest;
	files: FileSignalRecord[];
	chunks: RagChunk[];
}

export interface RagSearchResult {
	chunk: RagChunk;
	lexicalScore: number;
	semanticScore: number;
	score: number;
}

export interface RagBuildOptions {
	withAi: boolean;
	generateSuggestions?: (signals: SecuritySignal[]) => Promise<unknown>;
}
