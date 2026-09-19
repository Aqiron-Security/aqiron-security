import { UnifiedFinding } from '../shared/finding';
import { ScannerContext, ScannerEvent, ScannerManagerResult, ScannerSelection, SecurityScanner, ToolAvailability } from './types';

export class ScannerManager {
	private readonly scanners = new Map<string, SecurityScanner>();
	private readonly order: string[] = [];

	register(scanner: SecurityScanner): void {
		const key = scanner.id.toLowerCase();
		if (!this.scanners.has(key)) {
			this.order.push(key);
		}
		this.scanners.set(key, scanner);
	}

	list(): SecurityScanner[] {
		return this.order.map((id) => this.scanners.get(id)).filter((scanner): scanner is SecurityScanner => Boolean(scanner));
	}

	async discoverAvailable(context: ScannerContext, selection: ScannerSelection = {}): Promise<Array<{ scanner: SecurityScanner; availability: ToolAvailability }>> {
		const scanners = this.selectScanners(context, selection);
		const results: Array<{ scanner: SecurityScanner; availability: ToolAvailability }> = [];
		for (const scanner of scanners) {
			const availability = await scanner.isAvailable(context);
			results.push({ scanner, availability });
		}
		return results;
	}

	async run(context: ScannerContext, selection: ScannerSelection = {}, emit?: (event: ScannerEvent) => void): Promise<ScannerManagerResult> {
		const findings: UnifiedFinding[] = [];
		const results = [] as ScannerManagerResult['results'];
		for (const scanner of this.selectScanners(context, selection)) {
			if (context.cancellationToken?.isCancellationRequested) {
				emit?.(event('error', scanner.id, 'Scan cancelled before execution.'));
				break;
			}
			emit?.(event('log', scanner.id, `Checking ${scanner.name} availability.`));
			emit?.(event('start', scanner.id));
			const availability = await scanner.isAvailable(context);
			if (!availability.available) {
				emit?.(event('log', scanner.id, `${scanner.name} unavailable: ${availability.reason ?? 'not installed or not configured.'}`));
				emit?.(event('unavailable', scanner.id, availability.reason, availability));
				results.push({
					toolId: scanner.id,
					label: scanner.name,
					findings: [],
					durationMs: 0,
					unavailable: true,
					error: availability.reason,
				});
				continue;
			}
			try {
				emit?.(event('log', scanner.id, `${scanner.name} scan started.`));
				const result = await scanner.scan(context);
				results.push(result);
				for (const finding of result.findings) {
					findings.push(finding);
					emit?.({ type: 'finding', scannerId: scanner.id, timestamp: new Date().toISOString(), finding });
				}
				emit?.(event('complete', scanner.id, undefined, undefined, result));
				emit?.(event('log', scanner.id, `${scanner.name} scan completed with ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'}.`));
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				const failed = {
					toolId: scanner.id,
					label: scanner.name,
					findings: [],
					durationMs: 0,
					error: message,
				} satisfies ScannerManagerResult['results'][number];
				results.push(failed);
				emit?.(event('log', scanner.id, `${scanner.name} failed: ${message}`));
				emit?.(event('error', scanner.id, message, undefined, failed));
			}
		}
		return { findings, results };
	}

	private selectScanners(context: ScannerContext, selection: ScannerSelection): SecurityScanner[] {
		const scannerIds = selection.scannerIds?.length ? new Set(selection.scannerIds.map((value) => value.toLowerCase())) : undefined;
		const mode = selection.mode ?? context.mode;
		return this.list().filter((scanner) => {
			if (scannerIds && !scannerIds.has(scanner.id.toLowerCase())) {
				return false;
			}
			if (!scannerIds && mode === 'quick') {
				return scanner.capabilities.some((capability) => capability === 'source-code' || capability === 'secret');
			}
			return true;
		});
	}
}

function event(type: ScannerEvent['type'], scannerId: string, message?: string, availability?: ToolAvailability, result?: ScannerEvent['result']): ScannerEvent {
	return {
		type,
		scannerId,
		message,
		availability,
		result,
		timestamp: new Date().toISOString(),
	};
}
