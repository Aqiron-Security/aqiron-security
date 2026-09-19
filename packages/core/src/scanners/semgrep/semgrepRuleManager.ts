import * as path from 'path';
import { ScannerContext } from '../types';

export class SemgrepRuleManager {
	async getConfigs(context: ScannerContext): Promise<string[]> {
		const configs = ['p/default'];
		const projectHints = await this.detectProjectHints(context);
		if (projectHints.flutter) {
			configs.push('p/secrets');
		}
		if (projectHints.android) {
			configs.push('p/java', 'p/kotlin', 'p/secrets');
		}
		const customRules = await this.findCustomRulePacks(context);
		return [...new Set([...configs, ...customRules])];
	}

	getExcludeArgs(context: ScannerContext): string[] {
		return context.exclusions.flatMap((pattern) => ['--exclude', pattern]);
	}

	private async detectProjectHints(context: ScannerContext): Promise<{ flutter: boolean; android: boolean }> {
		const exists = async (relative: string): Promise<boolean> => {
			try {
				await context.filesystem.access(path.join(context.workspaceRoot, relative));
				return true;
			} catch {
				return false;
			}
		};
		return {
			flutter: await exists('pubspec.yaml'),
			android: await exists('AndroidManifest.xml') || await exists(path.join('app', 'src', 'main', 'AndroidManifest.xml')) || await exists('build.gradle'),
		};
	}

	private async findCustomRulePacks(context: ScannerContext): Promise<string[]> {
		const candidates = [
			path.join(context.workspaceRoot, '.aqiron', 'semgrep'),
			path.join(context.workspaceRoot, 'security', 'semgrep'),
			path.join(context.workspaceRoot, '.semgrep'),
		];
		const available: string[] = [];
		for (const candidate of candidates) {
			try {
				const stat = await context.filesystem.stat(candidate);
				if (stat.isDirectory()) {
					available.push(candidate);
				}
			} catch {
				// Optional rule locations.
			}
		}
		return available;
	}
}
