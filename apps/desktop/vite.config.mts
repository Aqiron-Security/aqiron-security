import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const appDirectory = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	root: appDirectory,
	publicDir: resolve(appDirectory, '../../assets'),
	server: {
		host: '127.0.0.1',
		port: 1420,
		strictPort: true,
		fs: { allow: [resolve(appDirectory, '../..')] },
	},
	clearScreen: false,
	build: { outDir: resolve(appDirectory, '../../dist/desktop'), emptyOutDir: true },
});
