import { ProjectTechnologySignals, add } from './projectProfile';

const PROFILE_KEYWORDS: Array<{ test: (text: string) => boolean; push: (signals: ProjectTechnologySignals) => void }> = [
	{ test: (text) => /\bflutter\b/i.test(text), push: (signals) => add(signals.securitySignals, 'Flutter') },
	{ test: (text) => /\bflutter\b/i.test(text), push: (signals) => add(signals.services, 'Flutter') },
	{ test: (text) => /\bfirebase\b/i.test(text), push: (signals) => add(signals.services, 'Firebase') },
	{ test: (text) => /\bsupabase\b/i.test(text), push: (signals) => add(signals.services, 'Supabase') },
	{ test: (text) => /\bgraphql\b/i.test(text), push: (signals) => add(signals.endpoints, 'GraphQL') },
	{ test: (text) => /\baxios\b|\bfetch\b|\bdio\b|\bokhttp\b|\bretrofit\b/i.test(text), push: (signals) => add(signals.networkClients, 'REST/HTTP') },
	{ test: (text) => /\bauth\b|\boauth\b|\boidc\b|\bjwt\b/i.test(text), push: (signals) => add(signals.authentication, 'Authentication') },
	{ test: (text) => /\bfirestore\b|\brealtime database\b|\bpostgres\b|\bmysql\b|\bsqlite\b|\bmongodb\b/i.test(text), push: (signals) => add(signals.databases, 'Database') },
	{ test: (text) => /\bsharedpreferences\b|\bsecure storage\b|\bkeychain\b|\bkeystore\b|\buserdefaults\b/i.test(text), push: (signals) => add(signals.storage, 'Local storage') },
	{ test: (text) => /\bandroid\b|\bandroidmanifest\b|\bgradle\b|\bkeystore\b/i.test(text), push: (signals) => add(signals.nativeCode, 'Android') },
	{ test: (text) => /\bios\b|\binfo\.plist\b|\bxcode\b|\bswift\b/i.test(text), push: (signals) => add(signals.nativeCode, 'iOS') },
	{ test: (text) => /\bgithub actions\b|\bgitlab ci\b|\bazure pipelines\b|\bcircleci\b|\bworkflow\b/i.test(text), push: (signals) => add(signals.ciCd, 'CI/CD') },
];

export function detectTechnologySignals(text: string): ProjectTechnologySignals {
	const signals: ProjectTechnologySignals = {
		services: [],
		authentication: [],
		databases: [],
		storage: [],
		dependencyManagers: [],
		nativeCode: [],
		ciCd: [],
		networkClients: [],
		endpoints: [],
		securitySignals: [],
	};
	for (const detector of PROFILE_KEYWORDS) {
		if (detector.test(text)) {
			detector.push(signals);
		}
	}
	return signals;
}

export function applyTechnologyHint(signals: ProjectTechnologySignals, value: string): void {
	add(signals.securitySignals, value);
}
