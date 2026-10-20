import { UnifiedFinding } from '../../core/src/shared/finding';
import { WebviewState } from '../../../src/webview/ui/types';

export function mapFinding(finding: UnifiedFinding, root: string): WebviewState['issues'][number] {
	const file = finding.file;
	const normalizedRoot = root.replace(/[\\/]+$/, '');
	const relativeFile = file.toLowerCase().startsWith(`${normalizedRoot.toLowerCase()}${file.includes('\\') ? '\\' : '/'}`)
		? file.slice(normalizedRoot.length).replace(/^[\\/]+/, '')
		: file;
	return {
		id: finding.id, title: finding.title, message: finding.description, severity: finding.severity,
		ruleId: finding.ruleId, file, relativeFile, line: finding.line, column: finding.column,
		lineText: '', tool: finding.sourceTool, cwe: finding.cwe?.join(', ') ?? '',
		owasp: finding.owasp?.join(', ') ?? '', status: finding.status, confidence: finding.confidence,
		riskScore: finding.riskScore, rawEvidence: finding.rawEvidence,
	};
}

export function countFindings(issues: WebviewState['issues']): WebviewState['counts'] {
	const count = (severity: string) => issues.filter((issue) => issue.severity === severity).length;
	return { total: issues.length, critical: count('Critical'), high: count('High'), medium: count('Medium'), low: count('Low'), filesAffected: new Set(issues.map((issue) => issue.file)).size };
}
