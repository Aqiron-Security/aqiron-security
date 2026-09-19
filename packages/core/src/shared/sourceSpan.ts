export interface SourceLocation {
	file: string;
	startLine: number;
	startColumn: number;
	endLine: number;
	endColumn: number;
}

export function createSourceLocation(file: string, startLine: number, startColumn: number, endLine: number, endColumn: number): SourceLocation {
	return {
		file,
		startLine: Math.max(0, startLine),
		startColumn: Math.max(0, startColumn),
		endLine: Math.max(0, endLine),
		endColumn: Math.max(0, endColumn),
	};
}
