import { isAqExcludedPath } from '../../utils/files';
import { SecurityContextBuilder as CoreSecurityContextBuilder } from '../../../packages/core/src/context';
import { detectProjectTypes as coreDetectProjectTypes } from '../../../packages/core/src/project';
import { issueToFinding, UnifiedFinding } from '../../../packages/core/src';
import { SecurityAnalysisContext } from './types';

export async function detectProjectTypes(root: string): Promise<string[]> {
	return coreDetectProjectTypes(root, createFileSystem(), isAqExcludedPath);
}

export class SecurityContextBuilder {
	private readonly core = new CoreSecurityContextBuilder({
		filesystem: createFileSystem(),
		isExcludedPath: isAqExcludedPath,
	});

	async build(workspaceRoot: string, issues: readonly import('../../models/issue').AqironIssue[]): Promise<SecurityAnalysisContext> {
		const findings: UnifiedFinding[] = issues.map(issueToFinding);
		const context = await this.core.build(workspaceRoot, findings);
		return {
			workspaceName: context.workspaceName,
			workspaceRoot: context.workspaceRoot,
			projectTypes: context.projectTypes,
			profile: context.profile,
			analysisGoals: context.analysisGoals,
			retrievalQueries: context.retrievalQueries,
			candidateFiles: context.candidateFiles,
			deterministicFindings: context.deterministicFindings,
			ragEvidence: context.ragEvidence,
		};
	}
}

function createFileSystem() {
	return {
		readFile: nodeReadFile,
		writeFile: async (file: string, contents: string | Uint8Array, encoding?: BufferEncoding) => {
			const fs = await import('fs/promises');
			return fs.writeFile(file, contents, encoding);
		},
		mkdir: async (file: string, options?: { recursive?: boolean }) => {
			const fs = await import('fs/promises');
			await fs.mkdir(file, options);
		},
		readdir: async (file: string, options?: { withFileTypes?: boolean }) => {
			const fs = await import('fs/promises');
			return fs.readdir(file, options as { withFileTypes: true });
		},
		stat: async (file: string) => {
			const fs = await import('fs/promises');
			const stat = await fs.stat(file);
			return { isFile: () => stat.isFile(), isDirectory: () => stat.isDirectory(), size: stat.size, mtimeMs: stat.mtimeMs };
		},
		access: async (file: string) => {
			const fs = await import('fs/promises');
			await fs.access(file);
		},
		rename: async (oldPath: string, newPath: string) => {
			const fs = await import('fs/promises');
			await fs.rename(oldPath, newPath);
		},
		exists: async (file: string) => {
			const fs = await import('fs/promises');
			return fs.access(file).then(() => true).catch(() => false);
		},
	};
}

async function nodeReadFile(file: string, encoding: BufferEncoding): Promise<string>;
async function nodeReadFile(file: string): Promise<Uint8Array>;
async function nodeReadFile(file: string, encoding?: BufferEncoding): Promise<string | Uint8Array> {
	const fs = await import('fs/promises');
	return encoding ? fs.readFile(file, encoding) : fs.readFile(file);
}
