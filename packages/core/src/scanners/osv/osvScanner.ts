import * as path from 'path';
import { OsvContextResolver, OsvScannerParser } from '../../parsers/osvScannerParser';
import { ScannerContext, ScannerResult, SecurityScanner, ToolAvailability, ScannerCapability } from '../types';

export class OsvScanner implements SecurityScanner {
	readonly id = 'osv-scanner';
	readonly name = 'OSV-Scanner';
	readonly capabilities: ScannerCapability[] = ['dependency'];

	constructor(private readonly parser = new OsvScannerParser()) {}

	async isAvailable(context: ScannerContext): Promise<ToolAvailability> {
		try {
			await context.processRunner.execFile('osv-scanner', { cwd: context.workspaceRoot, args: ['--version'], timeoutMs: 5_000, cancellationToken: context.cancellationToken, windowsHide: true });
			return { available: true };
		} catch (error) {
			if (context.networkClient) {
				try {
					await context.filesystem.access(path.join(context.workspaceRoot, 'pubspec.lock'));
					return { available: true, details: { backend: 'osv-api' } };
				} catch {
					// Fall through to the explicit unavailable result below.
				}
			}
			return { available: false, reason: `osv-scanner is not installed and no supported OSV API input is available. ${error instanceof Error ? error.message : String(error)}` };
		}
	}

	async scan(context: ScannerContext): Promise<ScannerResult> {
		const startedAt = Date.now();
		const lockfile = path.join(context.workspaceRoot, 'pubspec.lock');
		try {
			await context.filesystem.access(lockfile);
		} catch {
			return { toolId: this.id, label: this.name, findings: [], durationMs: Date.now() - startedAt, error: 'No pubspec.lock was found; OSV-Scanner has no supported Flutter dependency input.' };
		}
		let stdout: string;
		try {
			const result = await context.processRunner.execFile('osv-scanner', {
				cwd: context.workspaceRoot,
				args: ['scan', 'source', '--format', 'json', '-r', context.workspaceRoot],
				timeoutMs: 120_000,
				cancellationToken: context.cancellationToken,
				windowsHide: true,
				acceptableExitCodes: [1],
			});
			stdout = result.stdout;
		} catch (error) {
			if (!context.networkClient) {
				throw error;
			}
			stdout = await queryOsvApi(context);
		}
		const packageContexts = await buildPackageContexts(context, stdout);
		const resolveContext: OsvContextResolver = (packageName) => packageContexts.get(packageName) ?? {};
		return {
			toolId: this.id,
			label: this.name,
			findings: this.parser.parse(stdout, context.workspaceRoot, resolveContext),
			filesScanned: 1,
			durationMs: Date.now() - startedAt,
		};
	}
}

async function queryOsvApi(context: ScannerContext): Promise<string> {
	const lockfile = await context.filesystem.readFile(path.join(context.workspaceRoot, 'pubspec.lock'), 'utf8');
	const packages = parsePubPackages(lockfile);
	if (!packages.length) {
		return JSON.stringify({ results: [] });
	}
	const response = await context.networkClient!.request('https://api.osv.dev/v1/querybatch', {
		method: 'POST',
		headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
		body: JSON.stringify({ queries: packages.map((pkg) => ({ package: { ecosystem: 'Pub', name: pkg.name }, version: pkg.version })) }),
		timeoutMs: 120_000,
		cancellationToken: context.cancellationToken,
	});
	if (!response.ok) {
		throw new Error(`OSV API returned HTTP ${response.status}.`);
	}
	const data = await response.json<{ results?: Array<{ vulns?: unknown[] }> }>();
	return JSON.stringify({
		results: packages.map((pkg, index) => ({
			source: { path: 'pubspec.lock', type: 'lockfile' },
			packages: [{ package: { name: pkg.name, version: pkg.version, ecosystem: 'Pub' }, vulnerabilities: data.results?.[index]?.vulns ?? [] }],
		})),
	});
}

function parsePubPackages(lockfile: string): Array<{ name: string; version: string }> {
	const packages: Array<{ name: string; version: string }> = [];
	const blocks = lockfile.split(/\r?\n(?=  [A-Za-z0-9_.-]+:\s*$)/);
	for (const block of blocks) {
		const name = block.match(/^  ([A-Za-z0-9_.-]+):\s*$/m)?.[1];
		const version = block.match(/^\s{4}version:\s*["']?([^"'\s]+)["']?\s*$/m)?.[1];
		if (name && version) {
			packages.push({ name, version });
		}
	}
	return packages;
}

async function buildPackageContexts(context: ScannerContext, stdout: string): Promise<Map<string, { line?: number; directness?: 'direct-dependency' | 'dev-dependency' | 'transitive-dependency' | 'dependency' }>> {
	const contexts = new Map<string, { line?: number; directness?: 'direct-dependency' | 'dev-dependency' | 'transitive-dependency' | 'dependency' }>();
	const report = safeJson<OsvReport>(stdout);
	const packages = report?.results?.flatMap((result) => result.packages ?? []) ?? [];
	for (const pkg of packages) {
		const packageName = pkg?.package?.name;
		if (!packageName || contexts.has(packageName)) {
			continue;
		}
		contexts.set(packageName, {
			line: await findPackageLineFromContext(context, packageName),
			directness: await classifyDependencyFromContext(context, packageName),
		});
	}
	return contexts;
}

async function findPackageLineFromContext(context: ScannerContext, packageName: string): Promise<number> {
	try {
		const lines = (await context.filesystem.readFile(path.join(context.workspaceRoot, 'pubspec.lock'), 'utf8')).split(/\r?\n/);
		const index = lines.findIndex((line) => new RegExp(`^\\s{2}${escapeRegExp(packageName)}:`).test(line));
		return index >= 0 ? index + 1 : 1;
	} catch {
		return 1;
	}
}

async function classifyDependencyFromContext(context: ScannerContext, packageName: string): Promise<'direct-dependency' | 'dev-dependency' | 'transitive-dependency' | 'dependency'> {
	try {
		const pubspec = await context.filesystem.readFile(path.join(context.workspaceRoot, 'pubspec.yaml'), 'utf8');
		return new RegExp(`^\\s{2}${escapeRegExp(packageName)}\\s*:`, 'm').test(section(pubspec, 'dependencies'))
			? 'direct-dependency'
			: new RegExp(`^\\s{2}${escapeRegExp(packageName)}\\s*:`, 'm').test(section(pubspec, 'dev_dependencies'))
				? 'dev-dependency'
				: 'transitive-dependency';
	} catch {
		return 'dependency';
	}
}

function safeJson<T>(value: string): T | undefined {
	try {
		return JSON.parse(value) as T;
	} catch {
		return undefined;
	}
}

function section(text: string, heading: string): string {
	const match = text.match(new RegExp(`(?:^|\\n)${heading}:\\n([\\s\\S]*?)(?=\\n\\S|$)`));
	return match?.[1] ?? '';
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

interface OsvReport {
	results?: Array<{ packages?: Array<{ package?: { name?: string } }> }>;
}
