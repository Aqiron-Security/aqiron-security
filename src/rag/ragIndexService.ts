import * as path from 'path';
import { RagIndexService as CoreRagIndexService } from '../../packages/core/src/rag';
import { FileSystem } from '../../packages/core/src/shared/platform';
import { isAqExcludedPath } from '../utils/files';

function createFileSystem(): FileSystem {
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

export class RagIndexService extends CoreRagIndexService {
	constructor() {
		super({
			filesystem: createFileSystem(),
			isExcludedPath: isAqExcludedPath,
		});
	}

	/** Ensure the workspace storage directory exists before the core index build. */
	override async reindex(root: string, options: Parameters<CoreRagIndexService['reindex']>[1]): Promise<Awaited<ReturnType<CoreRagIndexService['reindex']>>> {
		const fs = await import('fs/promises');
		await fs.mkdir(path.join(root, '.aqiron-security'), { recursive: true });
		return super.reindex(root, options);
	}
}
