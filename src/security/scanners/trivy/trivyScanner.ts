import { TrivyScanner as CoreTrivyScanner } from '../../../../packages/core/src';
import { createScannerContext } from '../platform';
import { ScannerResult, ScannerRunContext, ScanTarget, SecurityScanner } from '../types';

export class TrivyScanner implements SecurityScanner {
	readonly id = 'trivy';
	readonly label = 'Trivy';

	private readonly core = new CoreTrivyScanner();

	constructor(..._args: unknown[]) {}

	async scan(target: ScanTarget, context: ScannerRunContext): Promise<ScannerResult> {
		return this.core.scan(createScannerContext(target, context));
	}

	async scanContainer(image: string, target: ScanTarget, context: ScannerRunContext): Promise<ScannerResult> {
		return this.core.scanContainer(image, createScannerContext(target, context));
	}
}
