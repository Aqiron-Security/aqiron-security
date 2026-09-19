import { RegexCatalog, RegexSignal, RegexSourceRecord, RagBuildOptions, RagChunk, RagIndexData, RagManifest, RagSearchResult, FileSignalRecord, SecuritySignal } from '../shared/rag';
import { FileSystem, NetworkClient } from '../shared/platform';

export type { RegexCatalog, RegexSignal, RegexSourceRecord, RagBuildOptions, RagChunk, RagIndexData, RagManifest, RagSearchResult, FileSignalRecord, SecuritySignal };

export const RAG_DIR = '.aqiron-security';
export const REGEX_CATALOG_FILE = 'regexSources.json';

export interface RagHostDependencies {
	filesystem: FileSystem;
	networkClient?: NetworkClient;
	isExcludedPath?: (file: string, root: string) => boolean;
	maxFileSizeBytes?: number;
}

export interface RagIndexRequest extends RagHostDependencies {
	root: string;
}

export interface RagRetrievalRequest {
	queries: string[];
	limit?: number;
}

export interface RagRetrievalResult {
	query: string;
	file: string;
	startLine: number;
	endLine: number;
	score: number;
	excerpt: string;
	signalIds: string[];
}
