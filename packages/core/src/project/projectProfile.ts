import { UnifiedFinding } from '../shared/finding';

export interface ProjectProfile {
	rootPath: string;
	projectTypes: string[];
	languages: string[];
	frameworks: string[];
	platforms: string[];
	services: string[];
	authentication: string[];
	databases: string[];
	storage: string[];
	dependencyManagers: string[];
	nativeCode: string[];
	ciCd: string[];
	sensitiveFiles: string[];
	networkClients: string[];
	endpoints: string[];
	securitySignals: string[];
	dependencies: string[];
}

export interface ProjectTechnologySignals {
	services: string[];
	authentication: string[];
	databases: string[];
	storage: string[];
	dependencyManagers: string[];
	nativeCode: string[];
	ciCd: string[];
	networkClients: string[];
	endpoints: string[];
	securitySignals: string[];
}

export function createEmptyProjectProfile(rootPath: string): ProjectProfile {
	return {
		rootPath,
		projectTypes: [],
		languages: [],
		frameworks: [],
		platforms: [],
		services: [],
		authentication: [],
		databases: [],
		storage: [],
		dependencyManagers: [],
		nativeCode: [],
		ciCd: [],
		sensitiveFiles: [],
		networkClients: [],
		endpoints: [],
		securitySignals: [],
		dependencies: [],
	};
}

export function applyFindingSignals(profile: ProjectProfile, findings: readonly UnifiedFinding[]): void {
	for (const finding of findings) {
		for (const tag of finding.tags ?? []) {
			if (/secret|credential|token|password/i.test(tag)) {
				add(profile.securitySignals, 'Secrets exposed');
			}
			if (/dependency|sca/i.test(tag)) {
				add(profile.dependencyManagers, inferDependencyManager(finding.file, finding.description));
			}
		}
		if (finding.sourceTool === 'Betterleaks') {
			add(profile.authentication, 'Secrets exposed');
		}
	}
}

export function inferDependencyManager(relative: string, content: string): string {
	if (/pubspec/i.test(relative)) {
		return 'pub';
	}
	if (/package(-lock)?\.json/i.test(relative)) {
		return 'npm';
	}
	if (/pom\.xml/i.test(relative)) {
		return 'maven';
	}
	if (/gradle|\.kts$/i.test(relative)) {
		return 'gradle';
	}
	if (/pyproject|requirements\.txt/i.test(relative)) {
		return 'python';
	}
	if (/cargo\.toml/i.test(relative)) {
		return 'cargo';
	}
	return /dependencies:/i.test(content) ? 'yaml-deps' : 'unknown';
}

export function mergeProjectProfile(profile: ProjectProfile, signals: ProjectTechnologySignals): void {
	for (const value of signals.services) {
		add(profile.services, value);
	}
	for (const value of signals.authentication) {
		add(profile.authentication, value);
	}
	for (const value of signals.databases) {
		add(profile.databases, value);
	}
	for (const value of signals.storage) {
		add(profile.storage, value);
	}
	for (const value of signals.dependencyManagers) {
		add(profile.dependencyManagers, value);
	}
	for (const value of signals.nativeCode) {
		add(profile.nativeCode, value);
	}
	for (const value of signals.ciCd) {
		add(profile.ciCd, value);
	}
	for (const value of signals.networkClients) {
		add(profile.networkClients, value);
	}
	for (const value of signals.endpoints) {
		add(profile.endpoints, value);
	}
	for (const value of signals.securitySignals) {
		add(profile.securitySignals, value);
	}
}

export function add(list: string[], value: string): void {
	if (value && !list.includes(value)) {
		list.push(value);
	}
}
