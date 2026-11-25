import * as crypto from 'crypto';
import * as path from 'path';
import { FileSystem, NetworkClient } from '../shared/platform';
import { RegexCatalog, RegexSignal, RegexSourceRecord } from './types';

export const RAG_DIR = '.aqiron-security';
export const REGEX_CATALOG_FILE = 'regexSources.json';
const MAX_REGEX_LENGTH = 500;
const MAX_REPEAT_COUNT = 1000;

export const trustedRegexSources = [
	{ id: 'aqiron-curated-json', name: 'Aqiron curated signal list', type: 'vetted-json' as const, url: 'https://raw.githubusercontent.com/aqiron-security/regex-signals/main/regexSources.json' },
];

export interface RegexValidationResult {
	valid: boolean;
	reason?: string;
}

export function validateRegexSignal(signal: RegexSignal): RegexValidationResult {
	if (!isRecord(signal) || typeof signal.id !== 'string' || !signal.id.trim()
		|| !['database', 'payment', 'llm', 'secret', 'endpoint', 'service'].includes(String(signal.category))
		|| typeof signal.provider !== 'string' || !signal.provider.trim()
		|| typeof signal.pattern !== 'string' || !signal.pattern
		|| !['Low', 'Medium', 'High'].includes(String(signal.confidence))
		|| typeof signal.description !== 'string' || !signal.description.trim()
		|| typeof signal.falsePositiveGuidance !== 'string' || !signal.falsePositiveGuidance.trim()
		|| (signal.flags !== undefined && typeof signal.flags !== 'string')
		|| (signal.extensions !== undefined && (!Array.isArray(signal.extensions) || !signal.extensions.every((item: unknown) => typeof item === 'string' && item.length > 0)))
		|| (signal.positiveSamples !== undefined && (!Array.isArray(signal.positiveSamples) || !signal.positiveSamples.every((item: unknown) => typeof item === 'string')))) {
		return { valid: false, reason: 'Missing required signal fields.' };
	}
	if (signal.pattern.length > MAX_REGEX_LENGTH) {
		return { valid: false, reason: `Pattern exceeds ${MAX_REGEX_LENGTH} characters.` };
	}
	try {
		new RegExp(signal.pattern, signal.flags);
	} catch (error) {
		return { valid: false, reason: `Invalid regular expression: ${error instanceof Error ? error.message : String(error)}` };
	}
	if (hasUnsafeQuantifierStructure(signal.pattern) || hasExcessiveRepetition(signal.pattern)) {
		return { valid: false, reason: 'Pattern contains nested or ambiguous quantifiers that may cause excessive backtracking.' };
	}
	const samples = signal.positiveSamples ?? [];
	if (samples.length > 0 && !samples.some((sample) => new RegExp(signal.pattern, signal.flags).test(sample))) {
		return { valid: false, reason: 'Pattern did not match any supplied positive sample.' };
	}
	return { valid: true };
}

export function validateRegexCatalog(catalog: RegexCatalog): { accepted: RegexCatalog; rejected: Array<{ id?: string; reason: string }> } {
	const rejected: Array<{ id?: string; reason: string }> = [];
	if (!isRecord(catalog) || catalog.version !== 1 || typeof catalog.updatedAt !== 'string' || !Array.isArray(catalog.sources)) {
		return { accepted: { version: 1, updatedAt: new Date().toISOString(), sources: [] }, rejected: [{ reason: 'Malformed regex catalog.' }] };
	}
	const sources = catalog.sources.flatMap((candidateSource: unknown) => {
		if (!isRegexSourceRecord(candidateSource)) {
			rejected.push({ reason: 'Malformed regex source record.' });
			return [];
		}
		const source = candidateSource;
		const patterns: RegexSignal[] = [];
		const sourceRejected: Array<{ id?: string; reason: string }> = [];
		if (!Array.isArray(source.patterns)) {
			const item = { id: source.id, reason: 'Regex source patterns must be an array.' };
			rejected.push(item);
			sourceRejected.push(item);
		}
		for (const candidate of Array.isArray(source.patterns) ? source.patterns : []) {
			const result = validateRegexSignal(candidate);
			if (result.valid) {
				patterns.push(candidate);
			} else {
				const item = { id: isRecord(candidate) && typeof candidate.id === 'string' ? candidate.id : undefined, reason: result.reason ?? 'Rejected.' };
				rejected.push(item);
				sourceRejected.push(item);
			}
		}
		const previousRejected = Array.isArray(source.rejected) ? source.rejected.filter(isRejectedRegexEntry) : [];
		return [{ ...source, patterns, rejected: [...previousRejected, ...sourceRejected], status: 'validated' as const }];
	});
	return { accepted: { ...catalog, sources }, rejected };
}

export async function loadRegexCatalog(root: string, filesystem: FileSystem): Promise<RegexCatalog> {
	const file = path.join(root, RAG_DIR, REGEX_CATALOG_FILE);
	try {
		const parsed = JSON.parse(await filesystem.readFile(file, 'utf8')) as RegexCatalog;
		return validateRegexCatalog(parsed).accepted;
	} catch {
		const catalog = defaultCatalog();
		await saveRegexCatalog(root, catalog, filesystem);
		return catalog;
	}
}

export async function saveRegexCatalog(root: string, catalog: RegexCatalog, filesystem: FileSystem): Promise<void> {
	const directory = path.join(root, RAG_DIR);
	await filesystem.mkdir(directory, { recursive: true });
	const target = path.join(directory, REGEX_CATALOG_FILE);
	const temporary = `${target}.${Date.now()}.tmp`;
	await filesystem.writeFile(temporary, JSON.stringify(catalog, null, 2), 'utf8');
	await filesystem.rename(temporary, target);
}

export function getExternalRegexSignals(catalog: RegexCatalog): RegexSignal[] {
	return catalog.sources.flatMap((source) => source.patterns ?? []).filter((pattern) => validateRegexSignal(pattern).valid);
}

export async function addRegexSignals(root: string, source: Omit<RegexSourceRecord, 'status' | 'rejected'>, filesystem: FileSystem): Promise<{ accepted: RegexSignal[]; rejected: Array<{ id?: string; reason: string }> }> {
	const result = validateRegexCatalog({ version: 1, updatedAt: new Date().toISOString(), sources: [{ ...source, status: 'pending', rejected: [] }] });
	const existing = await loadRegexCatalog(root, filesystem);
	const next: RegexCatalog = {
		version: 1,
		updatedAt: new Date().toISOString(),
		sources: [...existing.sources.filter((item) => item.id !== source.id), ...result.accepted.sources],
	};
	await saveRegexCatalog(root, next, filesystem);
	return { accepted: result.accepted.sources[0]?.patterns ?? [], rejected: result.rejected };
}

export async function syncRegexes(root: string, networkClient: NetworkClient, filesystem: FileSystem): Promise<RegexCatalog> {
	const existing = await loadRegexCatalog(root, filesystem);
	const synced: RegexSourceRecord[] = [];
	for (const source of trustedRegexSources) {
		if (!isTrustedUrl(source.url)) {
			throw new Error(`Untrusted regex source URL: ${source.url}`);
		}
		const response = await networkClient.request(source.url);
		if (!response.ok) {
			throw new Error(`Regex source returned HTTP ${response.status}: ${source.name}`);
		}
		const body = await response.text();
		const parsed = parseRemotePatterns(body);
		const validated = validateRegexCatalog({ version: 1, updatedAt: new Date().toISOString(), sources: [{ ...source, status: 'pending', patterns: parsed, rejected: [] }] });
		synced.push({ ...validated.accepted.sources[0], checksum: sha256(body), lastSyncedAt: new Date().toISOString() });
	}
	const catalog = { version: 1 as const, updatedAt: new Date().toISOString(), sources: [...existing.sources.filter((source) => !trustedRegexSources.some((trusted) => trusted.id === source.id)), ...synced] };
	await saveRegexCatalog(root, catalog, filesystem);
	return catalog;
}

function defaultCatalog(): RegexCatalog {
	return {
		version: 1,
		updatedAt: new Date().toISOString(),
		sources: trustedRegexSources.map((source) => ({ ...source, status: 'pending', patterns: [], rejected: [] })),
	};
}

function parseRemotePatterns(body: string): RegexSignal[] {
	const parsed = JSON.parse(body) as unknown;
	if (Array.isArray(parsed)) {
		return parsed as RegexSignal[];
	}
	if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { patterns?: unknown }).patterns)) {
		return (parsed as { patterns: RegexSignal[] }).patterns;
	}
	throw new Error('Regex source must contain an array of patterns.');
}

function isTrustedUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol === 'https:' && trustedRegexSources.some((source) => new URL(source.url).hostname === url.hostname);
	} catch {
		return false;
	}
}

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function hasUnsafeQuantifierStructure(pattern: string): boolean {
	return /\([^)]*[+*]\)[+*{]/.test(pattern) || /(?:\.\*|\.\+).*(?:\.\*|\.\+)/.test(pattern);
}

function hasExcessiveRepetition(pattern: string): boolean {
	for (const match of pattern.matchAll(/\{\s*(\d+)\s*(?:,\s*(\d*)\s*)?\}/g)) {
		const lower = Number(match[1]);
		const upper = match[2] === undefined || match[2] === '' ? lower : Number(match[2]);
		if (!Number.isSafeInteger(lower) || !Number.isSafeInteger(upper) || lower > MAX_REPEAT_COUNT || upper > MAX_REPEAT_COUNT || upper < lower) {return true;}
	}
	return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isRegexSourceRecord(value: unknown): value is RegexSourceRecord {
	return isRecord(value) && typeof value.id === 'string' && Boolean(value.id.trim())
		&& typeof value.name === 'string' && Boolean(value.name.trim())
		&& ['official-docs', 'curated-github', 'vetted-json'].includes(String(value.type))
		&& typeof value.url === 'string' && Boolean(value.url.trim())
		&& ['pending', 'validated', 'failed'].includes(String(value.status))
		&& Array.isArray(value.patterns)
		&& (value.rejected === undefined || Array.isArray(value.rejected));
}

function isRejectedRegexEntry(value: unknown): value is { id?: string; reason: string } {
	return isRecord(value) && typeof value.reason === 'string' && (value.id === undefined || typeof value.id === 'string');
}
