import * as crypto from 'node:crypto';

/** A reusable one-pass index over scanner-observed source lines. */
export interface SourceLineIndex {
	readonly lineCount: number;
	spanByteLength(startLine: number, endLine: number): number;
	hashSpan(startLine: number, endLine: number): string;
}

/**
 * Splits once using the established scanner convention: CRLF and LF delimit lines,
 * while a lone CR remains part of its line. Span bytes are the selected lines joined
 * with LF, inclusive and one-based; the full-file hash continues to use exact text.
 */
export function createSourceLineIndex(content: string): SourceLineIndex {
	const lines = content.split(/\r?\n/);
	const validateSpan = (startLine: number, endLine: number): void => {
		if (!Number.isInteger(startLine) || !Number.isInteger(endLine) || startLine < 1 || endLine < startLine || endLine > lines.length || endLine - startLine + 1 > 20) {throw new Error('Invalid or oversized source span.');}
	};
	return {
		lineCount: lines.length,
		spanByteLength: (startLine, endLine) => {
			validateSpan(startLine, endLine);
			let total = endLine - startLine;
			for (let index = startLine - 1; index < endLine; index += 1) {total += Buffer.byteLength(lines[index]!, 'utf8');}
			return total;
		},
		hashSpan: (startLine, endLine) => {
			validateSpan(startLine, endLine);
			const span = lines.slice(startLine - 1, endLine).join('\n');
			if (Buffer.byteLength(span, 'utf8') > 64_000) {throw new Error('Source span exceeds the 64 KB evidence limit.');}
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
