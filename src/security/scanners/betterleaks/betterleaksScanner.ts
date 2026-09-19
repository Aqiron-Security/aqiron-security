import { BetterleaksScanner as CoreBetterleaksScanner } from '../../../../packages/core/src';
import { createScannerContext } from '../platform';
import { ScannerResult, ScannerRunContext, ScanTarget, SecurityScanner } from '../types';

export class BetterleaksScanner implements SecurityScanner {
	readonly id = 'betterleaks';
	readonly label = 'Betterleaks';

	private readonly core = new CoreBetterleaksScanner();

	constructor(..._args: unknown[]) {}

	async scan(target: ScanTarget, context: ScannerRunContext): Promise<ScannerResult> {
		return this.core.scan(createScannerContext(target, context));
	}
}
