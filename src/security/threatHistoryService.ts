import * as fs from 'fs/promises';
import * as path from 'path';
import { AqironIssue } from '../models/issue';

export interface ThreatSnapshot {
	id: string;
	title: string;
	createdAt: string;
	filesScanned: number;
	executiveSummary?: string;
	issues: AqironIssue[];
}

const HISTORY_DIRECTORY = '.aqiron-security';
const HISTORY_FILE = 'threats.json';
const MAX_SNAPSHOTS = 50;

export class ThreatHistoryService {
	async load(workspaceRoot: string): Promise<ThreatSnapshot[]> {
		try {
			const raw = JSON.parse(await fs.readFile(historyPath(workspaceRoot), 'utf8')) as unknown;
			return isThreatSnapshotList(raw) ? raw.slice(0, MAX_SNAPSHOTS).map(normalizeSnapshot) : [];
		} catch {
			return [];
		}
	}

	async record(workspaceRoot: string, issues: readonly AqironIssue[], filesScanned: number, executiveSummary?: string): Promise<ThreatSnapshot[]> {
		const snapshots = await this.load(workspaceRoot);
		const createdAt = new Date().toISOString();
		const snapshot: ThreatSnapshot = {
			id: `threat-scan-${Date.now()}`,
			title: issues.length === 0 ? 'Security scan - no findings' : `Security scan - ${issues.length} finding${issues.length === 1 ? '' : 's'}`,
			createdAt,
			filesScanned,
			executiveSummary,
			issues: JSON.parse(JSON.stringify(issues)) as AqironIssue[],
		};
		const next = [snapshot, ...snapshots].slice(0, MAX_SNAPSHOTS);
		await fs.mkdir(path.dirname(historyPath(workspaceRoot)), { recursive: true });
		const target = historyPath(workspaceRoot);
		const temporary = `${target}.${process.pid}.tmp`;
		await fs.writeFile(temporary, JSON.stringify(next, null, 2), 'utf8');
		await fs.rename(temporary, target);
		return next;
	}
}

function historyPath(workspaceRoot: string): string {
	return path.join(workspaceRoot, HISTORY_DIRECTORY, HISTORY_FILE);
}

function isThreatSnapshotList(value: unknown): value is ThreatSnapshot[] {
	return Array.isArray(value) && value.every((entry) => Boolean(entry) && typeof entry === 'object' && typeof (entry as ThreatSnapshot).id === 'string' && Array.isArray((entry as ThreatSnapshot).issues));
}

function normalizeSnapshot(snapshot: ThreatSnapshot): ThreatSnapshot {
	return {
		...snapshot,
		issues: snapshot.issues.filter((issue) => Boolean(issue) && typeof issue.id === 'string').map((issue) => {
			const range = issue.range as unknown as {
				startLine?: number;
				startColumn?: number;
				endLine?: number;
				endColumn?: number;
				start?: { line?: number; character?: number };
				end?: { line?: number; character?: number };
			} | undefined;
			return {
				...issue,
				range: {
					file: issue.file,
					startLine: range?.startLine ?? range?.start?.line ?? 0,
					startColumn: range?.startColumn ?? range?.start?.character ?? 0,
					endLine: range?.endLine ?? range?.end?.line ?? range?.start?.line ?? 0,
					endColumn: range?.endColumn ?? range?.end?.character ?? range?.start?.character ?? 0,
				},
			};
		}),
	};
}
