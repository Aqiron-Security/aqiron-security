import * as vscode from 'vscode';
import { AIService } from '../../ai/services/aiService';
import { RagWorkspaceService } from '../../rag/ragWorkspaceService';
import { WorkspaceScanner } from '../../scanner/workspaceScanner';
import { OrchestratedScanResult, SecurityPipelineEngine } from '../pipeline/pipelineEngine';
import { PipelineEventBus } from '../../../packages/core/src';
import { ExecutiveSummaryGenerator } from '../reports/reportGenerator';

export class SecurityOrchestrator implements vscode.Disposable {
	readonly events = new PipelineEventBus();
	private readonly pipeline: SecurityPipelineEngine;
	private cancellation?: vscode.CancellationTokenSource;

	constructor(nativeScanner: WorkspaceScanner, aiService?: AIService, rag?: RagWorkspaceService, reportSummaryGenerator?: ExecutiveSummaryGenerator) {
		void aiService;
		void rag;
		void reportSummaryGenerator;
		this.pipeline = new SecurityPipelineEngine(nativeScanner, this.events);
	}

	async scanWorkspace(workspaceFolder: vscode.WorkspaceFolder, mode: 'quick' | 'deep' | 'analysis' = 'deep'): Promise<OrchestratedScanResult> {
		this.cancel();
		this.cancellation = new vscode.CancellationTokenSource();
		try {
			return await this.pipeline.scanWorkspace(workspaceFolder, { mode, cancellationToken: this.cancellation.token });
		} finally {
			this.cancellation.dispose();
			this.cancellation = undefined;
		}
	}

	cancel(): void {
		if (!this.cancellation) {
			return;
		}
		this.cancellation?.cancel();
		this.events.emit({ type: 'cancelled', reason: 'User cancelled the active scan.' });
	}

	dispose(): void {
		this.cancel();
	}
}
