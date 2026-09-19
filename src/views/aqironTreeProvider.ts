import * as path from 'path';
import * as vscode from 'vscode';
import { agentDefinitions } from '../agents/agentRegistry';
import { aiActions } from '../ai/aiPlatform';
import { workflowDefinitions } from '../automation/workflowRegistry';
import { AqironIssue, AqironSeverity, AqironSeverityCounts, AqironWorkspaceStats, severityOrder } from '../models/issue';

type NodeKind = 'section' | 'metric' | 'severity' | 'file' | 'issue' | 'action';
export type AqironViewSection = 'agent' | 'scan' | 'threats' | 'reports';

interface TreeNode {
	kind: NodeKind;
	label: string;
	description?: string;
	count?: number;
	section?: AqironViewSection;
	severity?: AqironSeverity;
	file?: string;
	issue?: AqironIssue;
	parentSeverity?: AqironSeverity;
	command?: string;
	icon?: string;
}

const defaultStats: AqironWorkspaceStats = {
	filesScanned: 0,
	indexedFiles: 0,
	scanStatus: 'Idle',
	lastScanDurationMs: 0,
};

export interface AqironTreeViewController {
	update(issues: readonly AqironIssue[], stats?: Partial<AqironWorkspaceStats>): void;
	setScanStatus(scanStatus: AqironWorkspaceStats['scanStatus']): void;
}

export class AqironTreeProvider implements vscode.TreeDataProvider<TreeNode>, AqironTreeViewController {
	private readonly changeEmitter = new vscode.EventEmitter<TreeNode | undefined | void>();
	private issues: AqironIssue[] = [];
	private stats: AqironWorkspaceStats = defaultStats;

	readonly onDidChangeTreeData = this.changeEmitter.event;

	constructor(private readonly rootSection?: AqironViewSection) {}

	update(issues: readonly AqironIssue[], stats?: Partial<AqironWorkspaceStats>): void {
		this.issues = [...issues];
		this.stats = { ...this.stats, ...stats };
		this.changeEmitter.fire();
	}

	setScanStatus(scanStatus: AqironWorkspaceStats['scanStatus']): void {
		this.stats = { ...this.stats, scanStatus };
		this.changeEmitter.fire();
	}

	getTreeItem(element: TreeNode): vscode.TreeItem {
		const item = new vscode.TreeItem(element.label, getCollapsibleState(element));
		item.description = element.description ?? (element.count !== undefined ? String(element.count) : undefined);
		item.iconPath = new vscode.ThemeIcon(element.icon ?? getIconId(element));
		item.tooltip = getTooltip(element);

		if (element.issue) {
			item.command = {
				command: 'aqiron-security.openIssue',
				title: 'Open Issue',
				arguments: [element.issue],
			};
		} else if (element.command) {
			item.command = {
				command: element.command,
				title: element.label,
			};
		}

		return item;
	}

	getChildren(element?: TreeNode): TreeNode[] {
		if (!element) {
			if (this.rootSection) {
				return this.getSectionChildren(this.rootSection);
			}

			return [
				{ kind: 'section', label: 'Agent', section: 'agent', icon: 'hubot' },
				{ kind: 'section', label: 'Scan', section: 'scan', icon: 'shield' },
				{ kind: 'section', label: 'Threats', section: 'threats', icon: 'warning' },
				{ kind: 'section', label: 'Reports', section: 'reports', icon: 'graph' },
			];
		}

		if (element.kind === 'section') {
			return this.getSectionChildren(element.section);
		}

		if (element.kind === 'severity' && element.severity) {
			return getFilesForSeverity(this.issues, element.severity);
		}

		if (element.kind === 'file' && element.file && element.parentSeverity) {
			return this.issues
				.filter((issue) => issue.file === element.file && issue.severity === element.parentSeverity)
				.sort((left, right) => left.range.startLine - right.range.startLine)
				.map((issue) => ({
					kind: 'issue' as const,
					label: issue.title,
					description: `Ln ${issue.range.startLine + 1}`,
					issue,
				}));
		}

		return [];
	}

	private getSectionChildren(section: AqironViewSection | undefined): TreeNode[] {
		switch (section) {
			case 'agent':
				return [
					...aiActions.map((action) => ({
						kind: 'action' as const,
						label: action.title,
						command: getAiCommand(action.id),
						icon: getAiIcon(action.id),
					})),
					...agentDefinitions.map((agent) => ({
						kind: 'action' as const,
						label: agent.name,
						command: getAgentCommand(agent.id),
						icon: getAgentIcon(agent.id),
					})),
				];
			case 'scan':
				return getScanNodes(this.stats);
			case 'threats':
				return getThreatNodes(this.issues);
			case 'reports':
				return [
					...getReportNodes(this.stats, this.issues),
					...workflowDefinitions.map((workflow) => ({
						kind: 'action' as const,
						label: workflow.name,
						command: workflow.id === 'fix-workspace' ? 'aqiron-security.fixWorkspace' : 'aqiron-security.analyzeWorkspace',
						icon: getWorkflowIcon(workflow.id),
					})),
				];
			default:
				return [];
		}
	}
}

function getAiCommand(id: string): string {
	if (id === 'chat') {
		return 'aqiron-security.openChat';
	}

	return id === 'explain-code' ? 'aqiron-security.explainIssue' : 'aqiron-security.analyzeWorkspace';
}

function getAiIcon(id: string): string {
	switch (id) {
		case 'chat':
			return 'comment-discussion';
		case 'explain-code':
			return 'lightbulb';
		case 'refactor':
			return 'wand';
		case 'generate-tests':
			return 'beaker';
		default:
			return 'sparkle';
	}
}

function getAgentCommand(id: string): string {
	return id === 'code' ? 'aqiron-security.openChat' : 'aqiron-security.analyzeWorkspace';
}

function getAgentIcon(id: string): string {
	switch (id) {
		case 'security':
			return 'shield';
		case 'refactor':
			return 'tools';
		case 'automation':
			return 'run-all';
		default:
			return 'hubot';
	}
}

function getWorkflowIcon(id: string): string {
	switch (id) {
		case 'run-workflow':
			return 'play';
		case 'generate-commit':
			return 'git-commit';
		case 'analyze-project':
			return 'graph';
		case 'fix-workspace':
			return 'tools';
		default:
			return 'run-all';
	}
}

export function getCounts(issues: readonly AqironIssue[]): AqironSeverityCounts {
	const files = new Set(issues.map((issue) => issue.file));
	return {
		total: issues.length,
		critical: issues.filter((issue) => issue.severity === 'Critical').length,
		high: issues.filter((issue) => issue.severity === 'High').length,
		medium: issues.filter((issue) => issue.severity === 'Medium').length,
		low: issues.filter((issue) => issue.severity === 'Low').length,
		filesAffected: files.size,
	};
}

function getScanNodes(stats: AqironWorkspaceStats): TreeNode[] {
	return [
		{ kind: 'action', label: 'Scan Workspace', command: 'aqiron-security.scanWorkspace', icon: 'shield' },
		{ kind: 'action', label: 'Scan Current File', command: 'aqiron-security.scanCurrentFile', icon: 'file-code' },
		{ kind: 'action', label: 'Refresh Scan', command: 'aqiron-security.refreshScan', icon: 'refresh' },
		{ kind: 'metric', label: 'Files Scanned', count: stats.filesScanned, icon: 'files' },
		{ kind: 'metric', label: 'Indexed Files', count: stats.indexedFiles, icon: 'database' },
		{ kind: 'metric', label: 'Scan Status', description: stats.scanStatus, icon: stats.scanStatus === 'Scanning' ? 'sync' : 'check' },
	];
}

function getThreatNodes(issues: readonly AqironIssue[]): TreeNode[] {
	const counts = getCounts(issues);
	return [
		{ kind: 'metric', label: 'Total Issues', count: counts.total, icon: 'shield' },
		...severityOrder.map((severity) => ({
			kind: 'severity' as const,
			label: severity,
			severity,
			count: getSeverityCount(counts, severity),
		})),
		{ kind: 'metric', label: 'Files Affected', count: counts.filesAffected, icon: 'file-code' },
	];
}

function getReportNodes(stats: AqironWorkspaceStats, issues: readonly AqironIssue[]): TreeNode[] {
	return [
		{ kind: 'metric', label: 'Workspace Health', description: getWorkspaceHealth(issues), icon: 'pulse' },
		{ kind: 'metric', label: 'Last Scan Duration', description: `${stats.lastScanDurationMs} ms`, icon: 'watch' },
	];
}

function getFilesForSeverity(issues: readonly AqironIssue[], severity: AqironSeverity): TreeNode[] {
	const fileCounts = new Map<string, number>();
	for (const issue of issues.filter((candidate) => candidate.severity === severity)) {
		fileCounts.set(issue.file, (fileCounts.get(issue.file) ?? 0) + 1);
	}

	return Array.from(fileCounts.entries())
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([file, count]) => ({
			kind: 'file' as const,
			label: path.basename(file),
			description: vscode.workspace.asRelativePath(file),
			count,
			file,
			parentSeverity: severity,
		}));
}

function getSeverityCount(counts: AqironSeverityCounts, severity: AqironSeverity): number {
	switch (severity) {
		case 'Critical':
			return counts.critical;
		case 'High':
			return counts.high;
		case 'Medium':
			return counts.medium;
		case 'Low':
			return counts.low;
	}
}

function getWorkspaceHealth(issues: readonly AqironIssue[]): string {
	if (issues.some((issue) => issue.severity === 'Critical')) {
		return 'Needs attention';
	}

	if (issues.some((issue) => issue.severity === 'High')) {
		return 'Review recommended';
	}

	return issues.length === 0 ? 'Healthy' : 'Stable';
}

function getCollapsibleState(node: TreeNode): vscode.TreeItemCollapsibleState {
	if (node.kind === 'section' || node.kind === 'severity' || node.kind === 'file') {
		return vscode.TreeItemCollapsibleState.Expanded;
	}

	return vscode.TreeItemCollapsibleState.None;
}

function getIconId(node: TreeNode): string {
	if (node.kind === 'file') {
		return 'file-code';
	}

	if (node.kind === 'issue') {
		return 'circle-filled';
	}

	switch (node.severity) {
		case 'Critical':
			return 'error';
		case 'High':
			return 'warning';
		case 'Medium':
			return 'info';
		case 'Low':
			return 'lightbulb';
		default:
			return 'circle-outline';
	}
}

function getTooltip(node: TreeNode): string {
	if (node.issue) {
		return `${node.issue.message}\n${vscode.workspace.asRelativePath(node.issue.file)}:${node.issue.range.startLine + 1}`;
	}

	if (node.file) {
		return vscode.workspace.asRelativePath(node.file);
	}

	return node.description ?? `${node.label}: ${node.count ?? ''}`.trim();
}
