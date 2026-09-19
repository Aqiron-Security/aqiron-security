import * as path from 'path';
import { UnifiedFinding } from '../findings/finding';
import { CorrelatedRelationship } from './correlationEngine';

export interface SecurityGraph {
	nodes: SecurityGraphNode[];
	edges: SecurityGraphEdge[];
}

export interface SecurityGraphNode {
	id: string;
	label: string;
	type: 'API' | 'Auth' | 'Dependency' | 'Secret' | 'Vulnerability' | 'File' | 'Mobile Artifact' | 'Malware Indicator';
	severity?: string;
}

export interface SecurityGraphEdge {
	id: string;
	source: string;
	target: string;
	type: 'imports' | 'api-calls' | 'auth-relationships' | 'vulnerable-dependency-usage' | 'data-flow' | 'evidence' | 'correlation';
	weight?: number;
}

export class RelationshipGraphEngine {
	build(findings: readonly UnifiedFinding[], relationships: readonly CorrelatedRelationship[]): SecurityGraph {
		const nodes = new Map<string, SecurityGraphNode>();
		const edges: SecurityGraphEdge[] = [];
		for (const finding of findings) {
			const fileId = `file:${finding.file}`;
			nodes.set(fileId, { id: fileId, label: path.basename(finding.file), type: inferFileType(finding.file) });
			nodes.set(finding.id, {
				id: finding.id,
				label: finding.title,
				type: inferFindingType(finding),
				severity: finding.severity,
			});
			edges.push({
				id: `evidence:${finding.id}`,
				source: fileId,
				target: finding.id,
				type: 'evidence',
				weight: 1,
			});
			for (const graphEdge of finding.graph.edges) {
				edges.push({
					id: `${finding.id}:${graphEdge.targetId}`,
					source: finding.id,
					target: graphEdge.targetId,
					type: graphEdge.type === 'vulnerable-dependency-usage' ? 'vulnerable-dependency-usage' : graphEdge.type === 'data-flow' ? 'data-flow' : 'correlation',
				});
			}
		}
		for (const relationship of relationships) {
			edges.push({
				id: `${relationship.type}:${relationship.sourceId}:${relationship.targetId}`,
				source: relationship.sourceId,
				target: relationship.targetId,
				type: relationship.type === 'dependency-to-source' ? 'vulnerable-dependency-usage' : 'correlation',
				weight: relationship.weight,
			});
		}
		return { nodes: [...nodes.values()], edges };
	}
}

function inferFindingType(finding: UnifiedFinding): SecurityGraphNode['type'] {
	if (finding.tags.includes('secret')) {
		return 'Secret';
	}
	if (finding.tags.includes('malware')) {
		return 'Malware Indicator';
	}
	if (finding.tags.includes('dependency')) {
		return 'Dependency';
	}
	return 'Vulnerability';
}

function inferFileType(file: string): SecurityGraphNode['type'] {
	if (/auth|login|session|guard/i.test(file)) {
		return 'Auth';
	}
	if (/api|route|controller/i.test(file)) {
		return 'API';
	}
	if (/apk|manifest|android|ios/i.test(file)) {
		return 'Mobile Artifact';
	}
	return 'File';
}
