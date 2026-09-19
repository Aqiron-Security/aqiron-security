import { MobSfScanner as CoreMobSfScanner } from '../../../../packages/core/src';
import { createScannerContext } from '../platform';
import { ScannerResult, ScannerRunContext, ScanTarget, SecurityScanner } from '../types';

export class MobSfScanner implements SecurityScanner {
	readonly id = 'mobsf';
	readonly label = 'MobSF';

	private readonly core = new CoreMobSfScanner();

	constructor(..._args: unknown[]) {}

	async scan(target: ScanTarget, context: ScannerRunContext): Promise<ScannerResult> {
		return this.core.scan(createScannerContext(target, context));
	}
}
