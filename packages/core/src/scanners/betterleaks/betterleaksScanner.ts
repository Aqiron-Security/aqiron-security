import * as path from 'path';
import { BetterleaksParser } from '../../parsers/betterleaksParser';
import { ScannerContext, ScannerResult, SecurityScanner, ToolAvailability, ScannerCapability } from '../types';
import { resolveFlutterScanInputs } from '../scope';

export class BetterleaksScanner implements SecurityScanner {
	readonly id = 'betterleaks';
	readonly name = 'Betterleaks';
	readonly capabilities: ScannerCapability[] = ['secret', 'source-code'];

	constructor(private readonly parser = new BetterleaksParser()) {}

	async isAvailable(context: ScannerContext): Promise<ToolAvailability> {
		try {
			await context.processRunner.execFile('betterleaks', { cwd: context.workspaceRoot, args: ['--version'], timeoutMs: 5_000, cancellationToken: context.cancellationToken, windowsHide: true });
			return { available: true };
		} catch (error) {
			return { available: false, reason: error instanceof Error ? error.message : String(error) };
		}
	}

	async scan(context: ScannerContext): Promise<ScannerResult> {
		const startedAt = Date.now();
		const inputs = await resolveFlutterScanInputs(context);
		if (!inputs.length) {
			return { toolId: this.id, label: this.name, findings: [], durationMs: Date.now() - startedAt, error: 'No eligible project files were found for Betterleaks.' };
		}
		const findings = [];
		for (const batch of batches(inputs.map((input) => input.path))) {
			const result = await context.processRunner.execFile('betterleaks', {
				cwd: context.workspaceRoot,
				args: ['dir', ...batch, '--report-path', '-', '--report-format', 'json', '--exit-code', '0', '--redact', '--no-banner'],
				timeoutMs: 120_000,
				cancellationToken: context.cancellationToken,
				windowsHide: true,
			});
			findings.push(...this.parser.parse(result.stdout, context.workspaceRoot));
		}
		return { toolId: this.id, label: this.name, findings, filesScanned: inputs.length, durationMs: Date.now() - startedAt };
	}
}

function batches(paths: string[]): string[][] {
	const result: string[][] = [];
	let current: string[] = [];
	let size = 0;
	for (const file of paths) {
		if (current.length >= 64 || size + file.length > 24_000) {
			result.push(current);
			current = [];
			size = 0;
		}
		current.push(file);
		size += file.length;
	}
	if (current.length) {
		result.push(current);
	}
	return result;
}
