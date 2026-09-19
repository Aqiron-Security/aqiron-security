import { RagRetrievalService as CoreRagRetrievalService } from '../../../packages/core/src/analysis';
import { RagWorkspaceService } from '../../rag/ragWorkspaceService';
import { SecurityAnalysisContext, SecurityRagEvidence } from './types';

export class RagRetrievalService {
	private readonly core: CoreRagRetrievalService;

	constructor(private readonly rag: RagWorkspaceService) {
		this.core = new CoreRagRetrievalService(this.rag.index);
	}

	async retrieve(context: SecurityAnalysisContext): Promise<SecurityRagEvidence[]> {
		return this.core.retrieve(context);
	}
}
