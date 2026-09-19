import * as fs from 'fs/promises';
import * as vscode from 'vscode';
import { AqironIssue, AqironScanResult } from '../models/issue';
import { excludeGlob, getMaxFileSizeBytes, getSkipReason, isFlutterWorkspace, isSupportedFile, supportedGlob } from '../utils/files';
import { scanContent } from './rules';

interface CacheEntry {
	mtimeMs: number;
	size: number;
	issues: AqironIssue[];
}

export class WorkspaceScanner {
	private readonly cache = new Map<string, CacheEntry>();

	constructor(private readonly output: vscode.OutputChannel) {}

	async scanWorkspace(workspaceFolder: vscode.WorkspaceFolder): Promise<AqironScanResult> {
		const startedAt = Date.now();
		this.output.appendLine(`Scan started: ${workspaceFolder.uri.fsPath}`);
		if (!isFlutterWorkspace(workspaceFolder.uri.fsPath)) {
			this.output.appendLine('Scan skipped: Aqiron Security currently supports Flutter workspaces only.');
			return { workspaceRoot: workspaceFolder.uri.fsPath, target: workspaceFolder.uri.fsPath, filesScanned: 0, issues: [], durationMs: Date.now() - startedAt };
		}

		const files = await vscode.workspace.findFiles(
			new vscode.RelativePattern(workspaceFolder, supportedGlob),
			excludeGlob,
		);

		const issues: AqironIssue[] = [];
		let filesScanned = 0;
		let skippedFiles = 0;
		const batches = chunk(files.filter((file) => isSupportedFile(file)), 50);

		for (const batch of batches) {
			const results = await Promise.all(batch.map((file) => this.scanUri(file)));
			for (const result of results) {
				filesScanned += result.filesScanned;
				skippedFiles += result.skipped ? 1 : 0;
				issues.push(...result.issues);
			}
		}

		const durationMs = Date.now() - startedAt;
		this.logSummary(filesScanned, skippedFiles, issues.length, durationMs);

		return {
			workspaceRoot: workspaceFolder.uri.fsPath,
			target: workspaceFolder.uri.fsPath,
			filesScanned,
			issues,
			durationMs,
		};
	}

	async scanDocument(document: vscode.TextDocument): Promise<AqironScanResult> {
		const startedAt = Date.now();
		this.output.appendLine(`Scan started: ${document.uri.fsPath}`);
		const workspaceRoot = vscode.workspace.getWorkspaceFolder(document.uri)?.uri.fsPath;
		const skipReason = !workspaceRoot || !isFlutterWorkspace(workspaceRoot) ? 'Flutter workspaces only' : getSkipReason(document.uri.fsPath, document.getText());
		if (skipReason) {
			this.output.appendLine(`Skipped ${document.uri.fsPath}: ${skipReason}`);
		}
		const issues = isSupportedFile(document.uri) && !skipReason
			? scanContent(document.uri.fsPath, document.getText())
			: [];
		const durationMs = Date.now() - startedAt;
		this.cache.set(document.uri.fsPath, {
			mtimeMs: Date.now(),
			size: document.getText().length,
			issues,
		});
		this.logSummary(skipReason ? 0 : 1, skipReason ? 1 : 0, issues.length, durationMs);

		return {
			workspaceRoot,
			target: document.uri.fsPath,
			filesScanned: 1,
			issues,
			durationMs,
		};
	}

	async scanFile(uri: vscode.Uri): Promise<AqironScanResult> {
		const startedAt = Date.now();
		this.output.appendLine(`Scan started: ${uri.fsPath}`);
		const result = await this.scanUri(uri);
		const durationMs = Date.now() - startedAt;
		this.logSummary(result.filesScanned, result.skipped ? 1 : 0, result.issues.length, durationMs);

		return {
			workspaceRoot: vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath,
			target: uri.fsPath,
			filesScanned: result.filesScanned,
			issues: result.issues,
			durationMs,
		};
	}

	private async scanUri(uri: vscode.Uri): Promise<{ filesScanned: number; issues: AqironIssue[]; skipped: boolean }> {
		if (!isSupportedFile(uri)) {
			return { filesScanned: 0, issues: [], skipped: true };
		}

		try {
			const stat = await fs.stat(uri.fsPath);
			const sizeLimit = getMaxFileSizeBytes();
			if (stat.size > sizeLimit) {
				this.output.appendLine(`Skipped ${uri.fsPath}: larger than ${Math.round(sizeLimit / 1024)}KB`);
				return { filesScanned: 0, issues: [], skipped: true };
			}

			const cached = this.cache.get(uri.fsPath);
			if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
				return { filesScanned: 1, issues: cached.issues, skipped: false };
			}

			const content = await fs.readFile(uri.fsPath, 'utf8');
			const skipReason = getSkipReason(uri.fsPath, content);
			if (skipReason) {
				this.output.appendLine(`Skipped ${uri.fsPath}: ${skipReason}`);
				this.cache.delete(uri.fsPath);
				return { filesScanned: 0, issues: [], skipped: true };
			}

			const issues = scanContent(uri.fsPath, content);
			this.cache.set(uri.fsPath, {
				mtimeMs: stat.mtimeMs,
				size: stat.size,
				issues,
			});

			return {
				filesScanned: 1,
				issues,
				skipped: false,
			};
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			this.output.appendLine(`Skipped ${uri.fsPath}: ${message}`);
			return { filesScanned: 0, issues: [], skipped: true };
		}
	}

	private logSummary(filesScanned: number, skippedFiles: number, issuesFound: number, durationMs: number): void {
		this.output.appendLine(`Files scanned: ${filesScanned}`);
		this.output.appendLine(`Files skipped: ${skippedFiles}`);
		this.output.appendLine(`Issues found: ${issuesFound}`);
		this.output.appendLine(`Scan time: ${durationMs}ms`);
	}
}

function chunk<T>(items: T[], size: number): T[][] {
	const chunks: T[][] = [];
	for (let index = 0; index < items.length; index += size) {
		chunks.push(items.slice(index, index + size));
	}
	return chunks;
}
