import * as crypto from 'crypto';
import * as path from 'path';
import { FileSystem } from '../shared/platform';
import { RagBuildOptions, RagChunk, RagIndexData, RagManifest, FileSignalRecord, SecuritySignal } from '../shared/rag';
import { detectSecuritySignals } from './signalDetector';
import { getExternalRegexSignals, loadRegexCatalog } from './regexLoader';
import { RagVectorService, tokenize } from './ragVectorService';
import { RagHostDependencies, RAG_DIR } from './types';

export const MAX_FILES = 2000;
export const MAX_BYTES = 256_000;
const supportedExtensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.java', '.kt', '.go', '.rs', '.dart', '.json', '.yaml', '.yml', '.xml', '.gradle', '.toml', '.env', '.rules', '.md']);
const excludedDirectories = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', RAG_DIR, '.dart_tool', 'target', 'bin', 'obj']);

export class RagIndexService {
	private data: RagIndexData = emptyIndex();
	private root?: string;
	private readonly vectors: RagVectorService;

	constructor(private readonly deps: RagHostDependencies) {
		this.vectors = new RagVectorService(deps.filesystem);
	}

	async hasIndex(root: string): Promise<boolean> {
		try {
			await this.deps.filesystem.access(indexPath(root));
			if (this.data.manifest.updatedAt === '') {
				await this.load(root);
			}
			return true;
		} catch {
			return false;
		}
	}

	async load(root: string): Promise<RagIndexData> {
		this.root = root;
		try {
			this.data = JSON.parse(await this.deps.filesystem.readFile(indexPath(root), 'utf8')) as RagIndexData;
		} catch {
			this.data = emptyIndex();
		}
		await this.vectors.initialize(root);
		return this.data;
	}

	async reindex(root: string, options: RagBuildOptions): Promise<RagIndexData> {
		this.root = root;
		const previous = await this.load(root);
		const catalog = await loadRegexCatalog(root, this.deps.filesystem);
		const externalSignals = getExternalRegexSignals(catalog);
		const previousFiles = new Map(previous.files.map((file) => [file.relativePath, file]));
		const files = await collectFiles(root, this.deps.filesystem, this.deps);
		const nextFiles: FileSignalRecord[] = [];
		const chunks: RagChunk[] = [];
		const errors: Array<{ file: string; message: string }> = [];

		for (const file of files) {
			const relativePath = path.relative(root, file).replace(/\\/g, '/');
			try {
				const stat = await this.deps.filesystem.stat(file);
				const cached = previousFiles.get(relativePath);
				if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
					nextFiles.push(cached);
					chunks.push(...makeChunks(cached.relativePath, await this.deps.filesystem.readFile(file, 'utf8'), cached.signals));
					continue;
				}
				const content = await this.deps.filesystem.readFile(file, 'utf8');
				const signals = detectSecuritySignals(relativePath, content, externalSignals);
				const record: FileSignalRecord = { relativePath, mtimeMs: stat.mtimeMs, size: stat.size, contentHash: hash(content), tokens: tokenize(content), signals, indexedAt: new Date().toISOString() };
				nextFiles.push(record);
				chunks.push(...makeChunks(relativePath, content, signals));
			} catch (error) {
				errors.push({ file: relativePath, message: error instanceof Error ? error.message : String(error) });
			}
		}

		const manifest: RagManifest = { version: 1, createdAt: previous.manifest.createdAt || new Date().toISOString(), updatedAt: new Date().toISOString(), filesIndexed: nextFiles.length, filesSkipped: Math.max(0, files.length - nextFiles.length), errors, aiSuggestionsGenerated: Boolean(options.withAi && options.generateSuggestions) };
		this.data = { manifest, files: nextFiles, chunks };
		await persistIndex(root, this.data, this.deps.filesystem);
		await this.vectors.rebuild(root, chunks);
		if (options.withAi && options.generateSuggestions) {
			await options.generateSuggestions(nextFiles.flatMap((file) => file.signals));
		}
		return this.data;
	}

	search(query: string, limit = 5) {
		return this.vectors.search(query, this.data.chunks, limit);
	}

	searchLexical(query: string, limit = 5) {
		const queryTokens = tokenize(query);
		return this.data.chunks.map((chunk) => ({
			chunk,
			lexicalScore: tokenOverlap(queryTokens, chunk.tokens),
			semanticScore: 0,
			score: tokenOverlap(queryTokens, chunk.tokens),
		})).sort((left, right) => right.score - left.score).slice(0, limit);
	}

	getData(): RagIndexData {
		return this.data;
	}

	getVectorBackend(): 'faiss' | 'local' {
		return this.vectors.getBackend();
	}
}

async function collectFiles(root: string, filesystem: FileSystem, deps: RagHostDependencies): Promise<string[]> {
	const output: string[] = [];
	async function visit(current: string): Promise<void> {
		if (output.length >= MAX_FILES) {
			return;
		}
		let entries;
		try {
			entries = await filesystem.readdir(current, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries as Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>) {
			if (output.length >= MAX_FILES) {
				return;
			}
			if (entry.name.startsWith('.') && entry.name !== '.env') {
				continue;
			}
			if (entry.isDirectory()) {
				if (!excludedDirectories.has(entry.name) && !deps.isExcludedPath?.(path.join(current, entry.name), root)) {
					await visit(path.join(current, entry.name));
				}
				continue;
			}
			if (entry.name !== 'pubspec.yaml' && supportedExtensions.has(path.extname(entry.name).toLowerCase())) {
				const target = path.join(current, entry.name);
				try {
					if ((await filesystem.stat(target)).size <= (deps.maxFileSizeBytes ?? MAX_BYTES) && !deps.isExcludedPath?.(target, root)) {
						output.push(target);
					}
				} catch {
					// Omit unreadable files.
				}
			}
		}
	}
	await visit(root);
	return output;
}

function makeChunks(relativePath: string, content: string, signals: SecuritySignal[]): RagChunk[] {
	const lines = content.split(/\r?\n/);
	const chunks: RagChunk[] = [];
	for (let start = 0; start < lines.length; start += 80) {
		const end = Math.min(lines.length, start + 80);
		const text = lines.slice(start, end).join('\n');
		const signalIds = signals.filter((signal) => signal.line >= start + 1 && signal.line <= end).map((signal) => signal.id);
		chunks.push({ id: `${relativePath}:${start + 1}`, relativePath, startLine: start + 1, endLine: end, text, tokens: tokenize(text), signalIds });
	}
	return chunks;
}

async function persistIndex(root: string, data: RagIndexData, filesystem: FileSystem): Promise<void> {
	const directory = path.join(root, RAG_DIR);
	await filesystem.mkdir(directory, { recursive: true });
	const target = indexPath(root);
	const temporary = `${target}.${Date.now()}.tmp`;
	await filesystem.writeFile(temporary, JSON.stringify(data), 'utf8');
	await filesystem.rename(temporary, target);
}

function indexPath(root: string): string {
	return path.join(root, RAG_DIR, 'index.json');
}

function hash(content: string): string {
	return crypto.createHash('sha256').update(content).digest('hex');
}

function emptyIndex(): RagIndexData {
	return { manifest: { version: 1, createdAt: '', updatedAt: '', filesIndexed: 0, filesSkipped: 0, errors: [], aiSuggestionsGenerated: false }, files: [], chunks: [] };
}

function tokenOverlap(left: string[], right: string[]): number {
	return left.length === 0 ? 0 : left.filter((token) => right.includes(token)).length / left.length;
}
