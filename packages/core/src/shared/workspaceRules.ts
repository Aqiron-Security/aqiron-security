import * as path from 'node:path';
import { FileSystem } from './platform';

export interface WorkspaceCustomRule {
	id: string;
	title: string;
	message: string;
	severity: 'Critical' | 'High' | 'Medium' | 'Low';
	pattern: string;
	extensions?: string[];
	caseSensitive?: boolean;
}

interface StoredRules { version: 1; rules: WorkspaceCustomRule[]; }

export class WorkspaceRuleStore {
	constructor(private readonly filesystem: FileSystem) {}

	async has(workspaceRoot: string): Promise<boolean> {
		return await this.filesystem.exists(this.file(workspaceRoot));
	}

	async get(workspaceRoot: string): Promise<WorkspaceCustomRule[]> {
		const file = this.file(workspaceRoot);
		if (!(await this.filesystem.exists(file))) {
			return [];
		}
		try {
			const stored = JSON.parse(await this.filesystem.readFile(file, 'utf8')) as StoredRules;
			if (stored.version !== 1 || !Array.isArray(stored.rules) || !stored.rules.every(isRule)) {
				throw new Error('Stored custom rules have an unsupported format.');
			}
			return stored.rules;
		} catch (error) {
			throw new Error(`Could not read Aqiron workspace rules: ${error instanceof Error ? error.message : String(error)}`);
		}
	}

	async set(workspaceRoot: string, input: unknown): Promise<WorkspaceCustomRule[]> {
		if (!Array.isArray(input) || !input.every(isRule)) {
			throw new Error('Custom rules must be a JSON array of valid Aqiron rule objects.');
		}
		const ids = new Set<string>();
		for (const rule of input) {
			if (ids.has(rule.id)) {
				throw new Error(`Custom rule id "${rule.id}" is duplicated.`);
			}
			ids.add(rule.id);
			try {
				new RegExp(rule.pattern, rule.caseSensitive ? '' : 'i');
			} catch {
				throw new Error(`Custom rule "${rule.id}" has an invalid regular expression.`);
			}
		}
		const directory = path.join(workspaceRoot, '.aqiron-security');
		await this.filesystem.mkdir(directory, { recursive: true });
		await this.filesystem.writeFile(this.file(workspaceRoot), JSON.stringify({ version: 1, rules: input }, null, 2), 'utf8');
		return input;
	}

	private file(root: string): string { return path.join(root, '.aqiron-security', 'custom-rules.json'); }
}

function isRule(value: unknown): value is WorkspaceCustomRule {
	if (!value || typeof value !== 'object') {
		return false;
	}
	const rule = value as Record<string, unknown>;
	return typeof rule.id === 'string' && rule.id.trim().length > 0
		&& typeof rule.title === 'string' && rule.title.trim().length > 0
		&& typeof rule.message === 'string' && typeof rule.pattern === 'string' && rule.pattern.length > 0
		&& ['Critical', 'High', 'Medium', 'Low'].includes(String(rule.severity))
		&& (rule.extensions === undefined || (Array.isArray(rule.extensions) && rule.extensions.every((item) => typeof item === 'string')))
		&& (rule.caseSensitive === undefined || typeof rule.caseSensitive === 'boolean');
}
