import { OsvScanner as CoreOsvScanner } from '../../../../packages/core/src';
import { createScannerContext } from '../platform';
import { ScannerResult, ScannerRunContext, ScanTarget, SecurityScanner } from '../types';

export class OsvScanner implements SecurityScanner {
	readonly id = 'osv-scanner';
	readonly label = 'OSV-Scanner';

	private readonly core = new CoreOsvScanner();

	constructor(..._args: unknown[]) {}

	async scan(target: ScanTarget, context: ScannerRunContext): Promise<ScannerResult> {
		return this.core.scan(createScannerContext(target, context));
	}
}
