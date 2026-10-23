import { AIProviderId } from '../../packages/core/src/shared/ai';

const WEBVIEW_COMMANDS = new Set([
	'ready','focus','openChatSession','renameChatSession','deleteChatSession','shareChatSession','selectPermissionMode','selectModel','refreshModels','switchProvider','configureProvider','saveProviderSettings','removeProviderCredentials','saveApiCredential','selectApiCredential','deleteApiCredential','saveTaskDefaults','saveMobSfSettings','saveCustomRules','applyModelFilter','cancelGeneration','selectIntelligence','checkoutBranch','createBranch','sendChat','sendChatToSession','scanWorkspace','aiVulnerabilityAnalysis','scanCurrentFile','cancelScan','ragReindexWithAi','ragReindexWithoutAi','ragSyncRegexes','ragAddRegex','ragRefreshSuggestions','openRagSettings','setZoom','clearTerminal','exportReport','renameReportArtifact','exportFinding','ignoreIssue','createRuleFromFinding','openIssue','selectThreatSnapshot','deleteThreatSnapshot','openPolicy','agentAction','setupComplete','selectWorkspace','prepareHypothesisAi','approveHypothesisAi','denyHypothesisAi','executeHypothesisAi','cancelHypothesisAiExecution',
]);

export function isWebviewMessage(value: unknown): value is { command: string; payload?: unknown } {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {return false;}
	const message = value as Record<string, unknown>;
	if (Object.keys(message).some((key) => key !== 'command' && key !== 'payload') || typeof message.command !== 'string' || message.command.length > 80 || !WEBVIEW_COMMANDS.has(message.command)) {return false;}
	if (message.payload === undefined) {return true;}
	try { return Buffer.byteLength(JSON.stringify(message.payload), 'utf8') <= 1_048_576; } catch { return false; }
}

export function isHypothesisAiPrepareMessage(value: unknown): value is { providerId: AIProviderId; modelId: string; evidenceIds: string[]; includeSourceExcerpts?: boolean } {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {return false;}
	const payload = value as Record<string, unknown>;
	if (Object.keys(payload).some((key) => !['providerId','modelId','evidenceIds','includeSourceExcerpts'].includes(key)) || !['openrouter','openai','claude','gemini'].includes(String(payload.providerId))
		|| typeof payload.modelId !== 'string' || !/^[A-Za-z0-9._:/-]{1,128}$/.test(payload.modelId) || !Array.isArray(payload.evidenceIds) || payload.evidenceIds.length < 1 || payload.evidenceIds.length > 40
		|| payload.evidenceIds.some((id) => typeof id !== 'string' || id.length < 1 || id.length > 200 || id.trim() !== id || /[\u0000-\u001f\u007f]/.test(id))
		|| new Set(payload.evidenceIds).size !== payload.evidenceIds.length || (payload.includeSourceExcerpts !== undefined && typeof payload.includeSourceExcerpts !== 'boolean')) {return false;}
	return true;
}

export function isHypothesisAiResponseMessage(value: unknown): value is { preparationId: string; contentFingerprint: string } {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {return false;}
	const payload = value as Record<string, unknown>;
	return Object.keys(payload).length === 2 && Object.keys(payload).every((key) => key === 'preparationId' || key === 'contentFingerprint')
		&& typeof payload.preparationId === 'string' && /^[a-f0-9-]{36}$/i.test(payload.preparationId)
		&& typeof payload.contentFingerprint === 'string' && /^[a-f0-9]{64}$/.test(payload.contentFingerprint);
}
