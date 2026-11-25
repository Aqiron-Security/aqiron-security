import * as crypto from 'node:crypto';
import type { FileSystem } from './platform';

/** Prevent pathological newline-heavy inputs from allocating unbounded line arrays. */
export const MAX_SOURCE_LINE_INDEX_LINES = 100_000;

export class SourceLineIndexLimitError extends Error {
	constructor() { super(`Source exceeds the ${MAX_SOURCE_LINE_INDEX_LINES}-line indexing limit.`); this.name = 'SourceLineIndexLimitError'; }
}

export class SourceReadBudgetExceededError extends Error {
	constructor() { super('Preparation source-read budget exceeded.'); this.name = 'SourceReadBudgetExceededError'; }
}

/** Per-operation aggregate raw-byte budget shared by snapshot and excerpt reads. */
export class SourceReadBudget {
	private consumedBytes = 0;
	constructor(readonly maxBytes: number) {}
	get bytesRead(): number { return this.consumedBytes; }
	async read(filesystem: FileSystem, file: string, perFileLimit: number): Promise<Uint8Array> {
		if (!filesystem.readFileBoundedBytes) { throw new Error('Bounded raw-byte reads are required.'); }
		const remaining = this.maxBytes - this.consumedBytes;
		if (remaining <= 0) { throw new SourceReadBudgetExceededError(); }
		try {
			const bytes = await filesystem.readFileBoundedBytes(file, Math.min(perFileLimit, remaining));
			if (bytes.byteLength > perFileLimit || bytes.byteLength > remaining) {
				this.consumedBytes = this.maxBytes;
				throw new SourceReadBudgetExceededError();
			}
			this.consumedBytes += bytes.byteLength;
			return bytes;
		} catch (error) {
			if (error instanceof SourceReadBudgetExceededError) { throw error; }
			const bytesRead = error && typeof error === 'object' && 'bytesRead' in error && Number.isSafeInteger((error as { bytesRead?: unknown }).bytesRead)
				? Math.max(0, Number((error as { bytesRead: number }).bytesRead)) : remaining;
			this.consumedBytes = Math.min(this.maxBytes, this.consumedBytes + bytesRead);
			if (bytesRead >= remaining) { throw new SourceReadBudgetExceededError(); }
			throw error;
		}
	}
}

/** Counts line delimiters without allocating per-line strings or arrays. */
export function sourceLineCount(content: string): number {
	let count = 1;
	for (let index = 0; index < content.length; index += 1) {
		if (content.charCodeAt(index) === 10) { count += 1; }
	}
	return count;
}

/** A reusable one-pass index over scanner-observed source lines, with exact bounded span extraction. */
export interface SourceLineIndex {
	readonly lineCount: number;
	spanByteLength(startLine: number, endLine: number): number;
	spanText(startLine: number, endLine: number): string;
	hashSpan(startLine: number, endLine: number): string;
}

/**
 * Splits once using the established scanner convention: CRLF and LF delimit lines,
 * while a lone CR remains part of its line. Span bytes are the selected lines joined
 * with LF, inclusive and one-based; the full-file hash continues to use exact text.
 */
export function createSourceLineIndex(content: string): SourceLineIndex {
	if (sourceLineCount(content) > MAX_SOURCE_LINE_INDEX_LINES) { throw new SourceLineIndexLimitError(); }
	const lines = content.split(/\r?\n/);
	const validateSpan = (startLine: number, endLine: number): void => {
		if (!Number.isInteger(startLine) || !Number.isInteger(endLine) || startLine < 1 || endLine < startLine || endLine > lines.length || endLine - startLine + 1 > 20) {throw new Error('Invalid or oversized source span.');}
	};
	const spanText = (startLine: number, endLine: number): string => {
		validateSpan(startLine, endLine);
		const span = lines.slice(startLine - 1, endLine).join('\n');
		if (Buffer.byteLength(span, 'utf8') > 64_000) {throw new Error('Source span exceeds the 64 KB evidence limit.');}
		return span;
	};
	return {
		lineCount: lines.length,
		spanByteLength: (startLine, endLine) => {
			validateSpan(startLine, endLine);
			let total = endLine - startLine;
			for (let index = startLine - 1; index < endLine; index += 1) {total += Buffer.byteLength(lines[index]!, 'utf8');}
			return total;
		},
		spanText,
		hashSpan: (startLine, endLine) => {
			const span = spanText(startLine, endLine);
			return crypto.createHash('sha256').update(span, 'utf8').digest('hex');
		},
	};
}

/** Hashes inclusive one-based scanner-observed source lines after LF normalization. */
export function hashSourceSpan(content: string, startLine: number, endLine: number): string {
	return createSourceLineIndex(content).hashSpan(startLine, endLine);
}

/** SHA-256 of the exact UTF-8 text string supplied to the scanner, including line endings. */
export function hashSourceContent(content: string): string {
	return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/** Provenance captured from the exact text passed to the native scanner. */
export interface FindingSourceProvenance {
	findingId: string;
	file: string;
	startLine: number;
	endLine: number;
	contentHash: string;
	sourceContentHash: string;
	sourceTool: string;
	ruleId: string;
	observedAt: string;
}
