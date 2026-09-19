import * as path from 'path';
import { createFinding, normalizeSeverity, UnifiedFinding } from '../../shared/finding';
import { ScannerContext, ScannerResult, SecurityScanner, ToolAvailability, ScannerCapability } from '../types';
import { findMobileArtifact } from '../scope';

interface MobSfUploadResponse {
	hash?: string;
	scan_type?: string;
	file_name?: string;
}

export class MobSfScanner implements SecurityScanner {
	readonly id = 'mobsf';
	readonly name = 'MobSF';
	readonly capabilities: ScannerCapability[] = ['binary', 'mobile', 'artifact'];

	async isAvailable(context: ScannerContext): Promise<ToolAvailability> {
		const baseUrl = normalizeBaseUrl(await readMobSfBaseUrl(context));
		const apiKey = await readMobSfApiKey(context);
		if (!baseUrl) {
			return { available: false, reason: 'MobSF base URL is not configured.' };
		}
		if (!apiKey) {
			return { available: false, reason: 'MobSF API key is not configured.' };
		}
		if (!context.networkClient) {
			return { available: false, reason: 'MobSF network client is not configured.' };
		}
		return { available: true, details: { baseUrl } };
	}

	async scan(context: ScannerContext): Promise<ScannerResult> {
		const startedAt = Date.now();
		try {
			const configuredBaseUrl = await readMobSfBaseUrl(context);
			const apiKey = await readMobSfApiKey(context);
			if (!configuredBaseUrl) {
				return this.completed(startedAt, [], 'MobSF base URL is not configured.');
			}
			if (!apiKey) {
				return this.completed(startedAt, [], 'MobSF API key is not configured.');
			}
			if (!context.networkClient) {
				return this.completed(startedAt, [], 'MobSF network client is not configured.');
			}
			const baseUrl = normalizeBaseUrl(configuredBaseUrl);
			const apk = await findMobileArtifact(context);
			if (!apk) {
				return this.completed(startedAt, [], 'No APK/IPA mobile artifact found for MobSF upload.');
			}
			if (context.cancellationToken?.isCancellationRequested) {
				return this.cancelled(startedAt);
			}
			const upload = await uploadFile(context, baseUrl, apiKey, apk, 120_000);
			if (!upload.hash || !upload.scan_type || !upload.file_name) {
				throw new Error('MobSF upload response did not include hash, scan_type, and file_name.');
			}
			await postForm(context, baseUrl, '/api/v1/scan', apiKey, {
				hash: upload.hash,
				scan_type: upload.scan_type,
				file_name: upload.file_name,
			}, 120_000);
			const report = await postForm(context, baseUrl, '/api/v1/report_json', apiKey, { hash: upload.hash }, 120_000);
			return this.completed(startedAt, parseMobSfFindings(report, apk), `Scanned ${path.basename(apk)} with MobSF.`);
		} catch (error) {
			return { toolId: this.id, label: this.name, findings: [], durationMs: Date.now() - startedAt, unavailable: false, error: error instanceof Error ? error.message : String(error) };
		}
	}

	private completed(startedAt: number, findings: UnifiedFinding[], message?: string): ScannerResult {
		return { toolId: this.id, label: this.name, findings, durationMs: Date.now() - startedAt, error: message && findings.length === 0 ? message : undefined };
	}

	private cancelled(startedAt: number): ScannerResult {
		return { toolId: this.id, label: this.name, findings: [], durationMs: Date.now() - startedAt, error: 'MobSF scan cancelled.' };
	}
}

async function readMobSfBaseUrl(context: ScannerContext): Promise<string> {
	return context.configuration.get<string>('mobsfBaseUrl', '').trim();
}

async function readMobSfApiKey(context: ScannerContext): Promise<string> {
	const configured = context.configuration.get<string>('mobsfApiKey', '').trim();
	if (configured) {
		return configured;
	}
	return context.credentialStore ? (await context.credentialStore.get('mobsfApiKey'))?.trim() ?? '' : '';
}

async function uploadFile(context: ScannerContext, baseUrl: string, apiKey: string, file: string, timeoutMs: number): Promise<MobSfUploadResponse> {
	const boundary = `----aqiron-${Date.now().toString(16)}`;
	const bytes = await context.filesystem.readFile(file);
	const header = Buffer.from([
		`--${boundary}`,
		`Content-Disposition: form-data; name="file"; filename="${path.basename(file)}"`,
		'Content-Type: application/octet-stream',
		'',
	].join('\r\n') + '\r\n');
	const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
	const body = Buffer.concat([header, Buffer.from(bytes), footer]);
	return requestJson<MobSfUploadResponse>(context, baseUrl, '/api/v1/upload', apiKey, body, {
		'Content-Type': `multipart/form-data; boundary=${boundary}`,
		'Content-Length': String(body.length),
	}, timeoutMs);
}

async function postForm(context: ScannerContext, baseUrl: string, endpoint: string, apiKey: string, values: Record<string, string>, timeoutMs: number): Promise<unknown> {
	const body = Buffer.from(new URLSearchParams(values).toString(), 'utf8');
	return requestJson(context, baseUrl, endpoint, apiKey, body, {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Content-Length': String(body.length),
	}, timeoutMs);
}

async function requestJson<T>(context: ScannerContext, baseUrl: string, endpoint: string, apiKey: string, body: Buffer, headers: Record<string, string>, timeoutMs: number): Promise<T> {
	const url = new URL(endpoint, baseUrl).toString();
	const response = await context.networkClient!.request(url, {
		method: 'POST',
		headers: { Authorization: apiKey, ...headers },
		body,
		timeoutMs,
		cancellationToken: context.cancellationToken,
	});
	const text = await response.text();
	if (!response.ok) {
		throw new Error(`MobSF ${endpoint} failed with HTTP ${response.status}: ${text.slice(0, 300)}`);
	}
	try {
		return JSON.parse(text) as T;
	} catch {
		throw new Error(`MobSF ${endpoint} returned invalid JSON.`);
	}
}

function parseMobSfFindings(report: unknown, artifact: string): UnifiedFinding[] {
	const findings: UnifiedFinding[] = [];
	if (!report || typeof report !== 'object') {
		return findings;
	}
	const data = report as Record<string, unknown>;
	const permissions = data.permissions;
	if (permissions && typeof permissions === 'object') {
		for (const [permission, value] of Object.entries(permissions as Record<string, unknown>)) {
			const detail = typeof value === 'object' && value ? value as Record<string, unknown> : {};
			const status = String(detail.status ?? detail.info ?? '');
			if (/dangerous|high|warning|signature/i.test(status)) {
				findings.push(createFinding({
					title: `MobSF permission: ${permission}`,
					description: `MobSF flagged Android permission ${permission}. ${status}`,
					severity: normalizeSeverity(/dangerous|high/i.test(status) ? 'High' : 'Medium'),
					cwe: [],
					owasp: ['M1: Improper Credential Usage'],
					file: artifact,
					line: 1,
					column: 1,
					sourceTool: 'MobSF',
					ruleId: `mobsf.permission.${permission}`,
					confidence: 'High',
					remediation: 'Review the permission, remove it when unnecessary, and document the business justification.',
					tags: ['mobile', 'android', 'mobsf', 'binary-artifact', 'apk-risk'],
					rawEvidence: { permission, detail },
				}));
			}
		}
	}
	const manifestAnalysis = data.manifest_analysis;
	if (manifestAnalysis && typeof manifestAnalysis === 'object') {
		for (const [rule, value] of Object.entries(manifestAnalysis as Record<string, unknown>)) {
			const detail = typeof value === 'object' && value ? value as Record<string, unknown> : {};
			const severity = normalizeSeverity(detail.severity ?? detail.status);
			if (severity === 'High' || severity === 'Critical' || severity === 'Medium') {
				findings.push(createFinding({
					title: `MobSF manifest: ${rule}`,
					description: String(detail.description ?? detail.title ?? 'MobSF manifest analysis finding.'),
					severity,
					cwe: [],
					owasp: ['M8: Security Misconfiguration'],
					file: artifact,
					line: 1,
					column: 1,
					sourceTool: 'MobSF',
					ruleId: `mobsf.manifest.${rule}`,
					confidence: 'High',
					remediation: String(detail.name ?? 'Harden the Android manifest setting and rerun MobSF.'),
					tags: ['mobile', 'android', 'mobsf', 'manifest', 'binary-artifact', 'apk-risk'],
					rawEvidence: { rule, detail },
				}));
			}
		}
	}
	return findings;
}

function normalizeBaseUrl(value: string): string {
	return value.endsWith('/') ? value : `${value}/`;
}
