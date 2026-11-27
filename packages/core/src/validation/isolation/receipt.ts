/** Local M22.3.5 boundary; adapter must map only an M22.3.3 consumed start receipt here. */
export interface CommittedStartReceipt {
	readonly executionId: string;
	readonly approvalId: string;
	readonly authorizationBindingDigest: string;
	readonly nonExecutable: true;
}

const acceptedReceipts = new WeakSet<object>();

/** Internal bridge adapter hook. It is intentionally not re-exported from any shared barrel. */
export function acceptCommittedStartReceipt(value: unknown): CommittedStartReceipt {
	if (!value || typeof value !== 'object' || Array.isArray(value)) { throw new TypeError('Committed-start receipt is missing or invalid.'); }
	const item = value as Record<string, unknown>;
	const expectedKeys = ['schemaVersion', 'approvalId', 'executionId', 'commitmentEventId', 'authorizationBindingDigest', 'consumedAt', 'status', 'nonExecutable'];
	if (Object.keys(item).length !== expectedKeys.length || Object.keys(item).some(key => !expectedKeys.includes(key))
		|| item.schemaVersion !== 1 || item.status !== 'consumed' || item.nonExecutable !== true
		|| !isUuid(item.executionId) || !isUuid(item.approvalId) || !isUuid(item.commitmentEventId) || !isDigest(item.authorizationBindingDigest) || !isIsoTimestamp(item.consumedAt)) {
		throw new TypeError('Committed-start receipt is missing or invalid.');
	}
	const receipt = Object.freeze({ executionId: item.executionId, approvalId: item.approvalId, authorizationBindingDigest: item.authorizationBindingDigest, nonExecutable: true as const });
	acceptedReceipts.add(receipt);
	return receipt;
}

export function isAcceptedCommittedStartReceipt(value: unknown): value is CommittedStartReceipt { return Boolean(value && typeof value === 'object' && acceptedReceipts.has(value)); }
function isUuid(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value); }
function isDigest(value: unknown): value is string { return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value); }
function isIsoTimestamp(value: unknown): value is string { return typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value; }
