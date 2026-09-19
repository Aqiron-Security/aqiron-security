import { SemgrepScanner as CoreSemgrepScanner } from '../../../../packages/core/src';
import { createScannerContext } from '../platform';
import { ScannerResult, ScannerRunContext, ScanTarget, SecurityScanner } from '../types';

export class SemgrepScanner implements SecurityScanner {
	readonly id = 'semgrep';
	readonly label = 'Semgrep OSS';

	private readonly core = new CoreSemgrepScanner();

	constructor(..._args: unknown[]) {}

	async scan(target: ScanTarget, context: ScannerRunContext): Promise<ScannerResult> {
		return this.core.scan(createScannerContext(target, context));
	}
}
