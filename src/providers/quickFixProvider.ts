import * as vscode from 'vscode';
import { aqironDiagnosticSource } from '../diagnostics/diagnosticManager';
import { AqironRuleId } from '../models/issue';

export class AqironQuickFixProvider implements vscode.CodeActionProvider {
	static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

	provideCodeActions(
		document: vscode.TextDocument,
		range: vscode.Range,
		context: vscode.CodeActionContext,
	): vscode.CodeAction[] {
		if (!vscode.workspace.getConfiguration('aqiron-security').get<boolean>('enableQuickFixes', true)) {
			return [];
		}

		const diagnostics = context.diagnostics.filter((diagnostic) => diagnostic.source === aqironDiagnosticSource);
		return diagnostics.flatMap((diagnostic) => createActions(document, range, diagnostic, diagnostics));
	}
}

function createActions(
	document: vscode.TextDocument,
	range: vscode.Range,
	diagnostic: vscode.Diagnostic,
	diagnostics: readonly vscode.Diagnostic[],
): vscode.CodeAction[] {
	const ruleId = String(diagnostic.code ?? '') as AqironRuleId;
	const line = document.lineAt(range.start.line);

	switch (ruleId) {
		case 'medium.console-log':
		case 'medium.print':
		case 'medium.debug':
			return [deleteLineAction(document, line, 'Remove debug statement', diagnostics)];
		case 'medium.todo':
			return [replaceLineAction(document, line, 'Remove TODO', line.text.replace(/\bTODO\b:?\s*/i, ''), diagnostics)];
		case 'low.unused-variable':
			return [deleteLineAction(document, line, 'Remove unused variable', diagnostics)];
		case 'critical.api-key':
		case 'critical.secret':
		case 'critical.token':
		case 'critical.password':
			return [replaceLineAction(document, line, 'Replace hardcoded secret', replaceSecret(line.text), diagnostics)];
		default:
			return [];
	}
}

function deleteLineAction(
	document: vscode.TextDocument,
	line: vscode.TextLine,
	title: string,
	diagnostics: readonly vscode.Diagnostic[],
): vscode.CodeAction {
	const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
	action.diagnostics = [...diagnostics];
	action.edit = new vscode.WorkspaceEdit();
	action.edit.delete(document.uri, line.rangeIncludingLineBreak);
	action.isPreferred = true;
	return action;
}

function replaceLineAction(
	document: vscode.TextDocument,
	line: vscode.TextLine,
	title: string,
	replacement: string,
	diagnostics: readonly vscode.Diagnostic[],
): vscode.CodeAction {
	const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
	action.diagnostics = [...diagnostics];
	action.edit = new vscode.WorkspaceEdit();
	action.edit.replace(document.uri, line.range, replacement);
	return action;
}

function replaceSecret(line: string): string {
	const replacement = getSecretReplacement();
	return line.replace(
		/(['"])(?:[A-Za-z0-9_\-./+=]{8,}|[^'"]{8,})\1/,
		replacement,
	);
}

function getSecretReplacement(): string {
	const editor = vscode.window.activeTextEditor;
	const extension = editor?.document.uri.fsPath.split('.').pop()?.toLowerCase();

	switch (extension) {
		case 'dart':
			return 'String.fromEnvironment("AQIRON_SECRET")';
		case 'py':
			return 'os.environ.get("AQIRON_SECRET", "")';
		case 'rs':
			return 'std::env::var("AQIRON_SECRET").unwrap_or_default()';
		case 'java':
			return 'System.getenv("AQIRON_SECRET")';
		case 'c':
		case 'cpp':
		case 'h':
			return 'getenv("AQIRON_SECRET")';
		default:
			return 'process.env.AQIRON_SECRET ?? ""';
	}
}
