import * as vscode from 'vscode';
import { AqironIssue, AqironSeverity } from '../models/issue';
import { SourceLocation } from '../shared/sourceSpan';

export const aqironDiagnosticSource = 'Aqiron Security';

export class DiagnosticManager implements vscode.Disposable {
	private readonly collection = vscode.languages.createDiagnosticCollection('aqiron-security');

	setIssues(issues: readonly AqironIssue[]): void {
		const byFile = new Map<string, vscode.Diagnostic[]>();

		for (const issue of issues) {
			const diagnostics = byFile.get(issue.file) ?? [];
			diagnostics.push(toDiagnostic(issue));
			byFile.set(issue.file, diagnostics);
		}

		this.collection.clear();
		for (const [file, diagnostics] of byFile) {
			this.collection.set(vscode.Uri.file(file), diagnostics);
		}
	}

	replaceFileIssues(file: string, issues: readonly AqironIssue[]): void {
		this.collection.set(vscode.Uri.file(file), issues.map(toDiagnostic));
	}

	clear(): void {
		this.collection.clear();
	}

	dispose(): void {
		this.collection.dispose();
	}
}

function toDiagnostic(issue: AqironIssue): vscode.Diagnostic {
	const diagnostic = new vscode.Diagnostic(toVscodeRange(issue.range), issue.message, toDiagnosticSeverity(issue.severity));
	diagnostic.source = aqironDiagnosticSource;
	diagnostic.code = issue.ruleId;
	return diagnostic;
}

function toDiagnosticSeverity(severity: AqironSeverity): vscode.DiagnosticSeverity {
	switch (severity) {
		case 'Critical':
			return vscode.DiagnosticSeverity.Error;
		case 'High':
			return vscode.DiagnosticSeverity.Error;
		case 'Medium':
			return vscode.DiagnosticSeverity.Warning;
		case 'Low':
			return vscode.DiagnosticSeverity.Information;
	}
}

function toVscodeRange(range: SourceLocation): vscode.Range {
	return new vscode.Range(range.startLine, range.startColumn, range.endLine, range.endColumn);
}
