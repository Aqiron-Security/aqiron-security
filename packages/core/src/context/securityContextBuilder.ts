import * as path from 'path';
import { UnifiedFinding } from '../shared/finding';
import { SecurityAnalysisContext, SecurityContext, SecurityContextBuilderOptions } from './contextTypes';
import { collectProjectFiles, detectProjectProfile } from '../project/projectDetector';
import { applyFindingSignals } from '../project/projectProfile';
import { prioritizeContextFiles } from './contextPrioritizer';
import { RagRetrievalService } from '../rag/ragRetrievalService';

const MAX_CANDIDATE_FILES = 28;
const EXCERPT_BYTES = 8_192;

export class SecurityContextBuilder {
	constructor(private readonly options: SecurityContextBuilderOptions) {}

	async build(workspaceRoot: string, findings: readonly UnifiedFinding[], rag?: RagRetrievalService): Promise<SecurityContext> {
		const projectProfile = await detectProjectProfile(workspaceRoot, this.options.filesystem, {
			isExcludedPath: this.options.isExcludedPath,
			maxFileSizeBytes: this.options.maxFileSizeBytes,
			maxCandidateFiles: MAX_CANDIDATE_FILES,
		});
		applyFindingSignals(projectProfile, findings);
		const deterministicFindings = this.summarizeFindings(findings);
		const candidateFiles = await this.selectFiles(workspaceRoot, deterministicFindings);
		const retrievalQueries = buildRetrievalQueries(projectProfile, projectProfile.projectTypes, deterministicFindings, candidateFiles);
		const base: SecurityAnalysisContext = {
			workspaceName: path.basename(workspaceRoot),
			workspaceRoot,
			projectTypes: projectProfile.projectTypes,
			profile: {
				languages: projectProfile.languages,
				frameworks: projectProfile.frameworks,
				platforms: projectProfile.platforms,
				services: projectProfile.services,
				authentication: projectProfile.authentication,
				databases: projectProfile.databases,
				storage: projectProfile.storage,
				dependencyManagers: projectProfile.dependencyManagers,
				nativeCode: projectProfile.nativeCode,
				ciCd: projectProfile.ciCd,
				sensitiveFiles: projectProfile.sensitiveFiles,
			},
			analysisGoals: buildAnalysisGoals(projectProfile, projectProfile.projectTypes, deterministicFindings),
			retrievalQueries,
			candidateFiles,
			deterministicFindings,
			ragEvidence: [],
		};
		const retrievedKnowledge = rag ? await rag.retrieve(base) : [];
		return {
			...base,
			projectProfile,
			securitySignals: [...projectProfile.securitySignals],
			retrievedKnowledge,
		};
	}

	private summarizeFindings(findings: readonly UnifiedFinding[]) {
		return findings.slice(0, 18).map((finding) => ({
			title: finding.title,
			description: finding.description,
			severity: finding.severity,
			sourceTool: finding.sourceTool,
			ruleId: finding.ruleId,
			file: finding.file,
			line: finding.line,
			tags: finding.tags ?? [],
			remediation: finding.remediation,
		}));
	}

	private async selectFiles(workspaceRoot: string, findings: SecurityContext['deterministicFindings']) {
		const projectFiles = await collectProjectFiles(workspaceRoot, this.options.filesystem, {
			isExcludedPath: this.options.isExcludedPath,
			maxFileSizeBytes: this.options.maxFileSizeBytes,
			maxCandidateFiles: MAX_CANDIDATE_FILES,
		});
		const files = await prioritizeContextFiles({
			workspaceRoot,
			files: projectFiles,
			findings,
			maxFiles: MAX_CANDIDATE_FILES,
		});
		const output = [];
		for (const file of files) {
			output.push({
				...file,
				excerpt: redactSecrets(await readExcerpt(path.join(workspaceRoot, file.path), this.options.filesystem, EXCERPT_BYTES)),
			});
		}
		return output;
	}
}

function buildRetrievalQueries(profile: import('../project/projectProfile').ProjectProfile, projectTypes: string[], findings: SecurityContext['deterministicFindings'], files: SecurityContext['candidateFiles']): string[] {
	const queries = new Set<string>();
	if (profile.frameworks.includes('Flutter') || projectTypes.includes('Flutter')) {
		addQuery(queries, 'Flutter Dart secure storage certificate pinning authentication authorization');
		addQuery(queries, 'Flutter dependency vulnerabilities pubspec.lock secret scanning');
	}
	if (profile.services.includes('Firebase')) {
		addQuery(queries, 'Firebase Auth Firestore rules Storage rules insecure client trust');
		addQuery(queries, 'Firebase configuration security rules authorization');
	}
	if (profile.services.includes('Supabase')) {
		addQuery(queries, 'Supabase auth row level security client side trust');
	}
	if (profile.services.includes('REST/HTTP')) {
		addQuery(queries, 'REST API authentication authorization IDOR injection sensitive data exposure');
	}
	if (profile.authentication.length > 0) {
		addQuery(queries, 'authentication authorization session token validation');
	}
	if (profile.storage.length > 0) {
		addQuery(queries, 'secure storage keychain keystore shared preferences secrets');
	}
	if (profile.ciCd.length > 0) {
		addQuery(queries, 'CI/CD secrets environment variables build pipeline security');
	}
	if (findings.some((finding) => finding.tags.some((tag) => /secret|credential/i.test(tag)))) {
		addQuery(queries, 'secret exposure hardcoded credentials token leakage');
	}
	if (findings.some((finding) => finding.tags.some((tag) => /dependency|sca/i.test(tag)))) {
		addQuery(queries, 'dependency vulnerability version range pubspec lockfile remediation');
	}
	if (files.some((file) => /androidmanifest|info\.plist|\.github\/workflows|firestore\.rules|storage\.rules/i.test(file.path))) {
		addQuery(queries, 'mobile configuration manifest security rules permissions');
	}
	return [...queries].slice(0, 10);
}

function buildAnalysisGoals(profile: import('../project/projectProfile').ProjectProfile, projectTypes: string[], findings: SecurityContext['deterministicFindings']): string[] {
	const goals = ['find evidence-backed vulnerabilities', 'validate against deterministic scanner findings'];
	if (profile.services.includes('Firebase') || projectTypes.includes('Firebase')) {
		goals.push('review Firebase auth and security rules');
	}
	if (profile.services.includes('REST/HTTP')) {
		goals.push('review API authorization and injection paths');
	}
	if (profile.platforms.includes('Android') || profile.platforms.includes('iOS')) {
		goals.push('review mobile storage, network trust, and platform config');
	}
	if (findings.some((finding) => finding.sourceTool === 'Betterleaks')) {
		goals.push('correlate secret exposure with code paths and configuration');
	}
	if (findings.some((finding) => finding.tags.some((tag) => tag.includes('dependency')))) {
		goals.push('correlate vulnerable dependencies with reachable source code');
	}
	return [...new Set(goals)];
}

async function readExcerpt(file: string, filesystem: import('../shared/platform').FileSystem, maxBytes: number): Promise<string> {
	try {
		return (await filesystem.readFile(file, 'utf8')).slice(0, maxBytes);
	} catch {
		return '';
	}
}

function addQuery(queries: Set<string>, value: string): void {
	queries.add(value);
}

function redactSecrets(value: string): string {
	return value
		.replace(/\b(?:sk|pk|ghp|glpat|xox[baprs]?)-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]')
		.replace(/\b[A-Za-z0-9_\/+=-]{32,}\b/g, '[REDACTED]')
		.replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED]');
}
