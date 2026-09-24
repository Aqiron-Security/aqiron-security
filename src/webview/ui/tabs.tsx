import React, { memo, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ChatSession, Severity, WebviewIssue, WebviewState } from './types.js';
import { Markdown } from './markdown.js';

type Post = (command: string, payload?: unknown) => void;

export const AgentTab = memo(function AgentTab({ state, post }: { state: WebviewState; post: Post }): React.ReactElement {
	return (
		<div className="tab-page">
			<ContextBar state={state} />
			<section className="section">
				<div className="section-head"><h2>Smart Actions</h2><span>AI-native DevSecOps workflows</span></div>
				<div className="action-grid">
					{['Explain this code', 'Hunt secrets', 'Analyze network security', 'Review auth flow', 'Scan dependencies', 'Reverse engineer APK', 'Generate exploit simulation'].map((title, index) => (
						<motion.button key={title} className="action-card" whileHover={{ y: -2 }} transition={{ duration: 0.16 }} onClick={() => post('sendChat', { text: title })}>
							<span className="mini-icon">{index + 1}</span>
							<strong>{title}</strong>
							<small>{actionDetail(title)}</small>
						</motion.button>
					))}
				</div>
			</section>
			<section className="section">
				<div className="section-head"><h2>Chat Sessions</h2></div>
				<ChatSessionList state={state} post={post} />
			</section>
			<section className="section">
				<div className="section-head"><h2>Smart Suggestions</h2><span>Generated from workspace graph and memory</span><button className="rag-refresh" title="Refresh AI regenerates Smart Suggestions from the current workspace index using the configured AI provider." aria-label="Refresh AI suggestions" onClick={() => post('ragRefreshSuggestions')} disabled={state.rag.building}>Refresh AI</button></div>
				<div className="suggestion-list">
					{state.suggestions.length ? state.suggestions.map((suggestion) => (
						<div key={suggestion.command} className="suggestion-card">
							<div className="suggestion-copy"><strong>{suggestion.title}</strong><Markdown content={suggestion.detail} /></div>
							<div className="suggestion-actions">
								<SeverityBadge severity={suggestion.severity} />
								{suggestion.recommended && <span className="badge">Recommended</span>}
								<button type="button" onClick={() => post('sendChat', { text: suggestion.command, useTaskDefaults: true })}>Run</button>
								<button type="button" onClick={() => post('sendChat', { text: `Explain ${suggestion.title}`, useTaskDefaults: true })}>Explain</button>
							</div>
						</div>
					)) : <div className="empty">No suggestions are generated. Build with AI or use Refresh AI after configuring a provider.</div>}
				</div>
			</section>
			<AgentComposer state={state} post={post} />
		</div>
	);
});

export const AgentPanel = memo(function AgentPanel({ state, post }: { state: WebviewState; post: Post }): React.ReactElement {
	const [sidebarOpen, setSidebarOpen] = useState(true);
	const [sidebarWidth, setSidebarWidth] = useState(260);
	const resizing = useRef(false);
	const panelRef = useRef<HTMLDivElement | null>(null);
	const activeSession = state.chatSessions.find((session) => session.id === state.activeChatSessionId) ?? state.chatSessions[0];
	const scrollRef = useRef<HTMLDivElement | null>(null);
	const latestMessage = activeSession?.messages.at(-1);
	useEffect(() => {
		const stopResize = () => { resizing.current = false; };
		const resize = (event: PointerEvent) => {
			if (!resizing.current) {
				return;
			}
			const left = panelRef.current?.getBoundingClientRect().left ?? 0;
			setSidebarWidth(Math.max(210, Math.min(420, event.clientX - left)));
		};
		window.addEventListener('pointermove', resize);
		window.addEventListener('pointerup', stopResize);
		return () => {
			window.removeEventListener('pointermove', resize);
			window.removeEventListener('pointerup', stopResize);
		};
	}, []);
	useEffect(() => {
		const node = scrollRef.current;
		if (!node) {
			return;
		}
		node.scrollTo({ top: node.scrollHeight, behavior: latestMessage?.streaming ? 'auto' : 'smooth' });
	}, [activeSession?.id, activeSession?.messages.length, latestMessage?.content, latestMessage?.streaming]);
	return (
		<div ref={panelRef} className={sidebarOpen ? 'agent-panel codex-chat sidebar-open' : 'agent-panel codex-chat sidebar-closed'} style={{ '--chat-sidebar-width': `${sidebarWidth}px` } as React.CSSProperties}>
			{sidebarOpen && <><aside className="chat-sidebar"><div className="chat-sidebar-head"><strong>Chats</strong></div><ChatSessionList state={state} post={post} compact /></aside><div className="chat-sidebar-resize" role="separator" aria-label="Resize chat sidebar" onPointerDown={(event) => { resizing.current = true; event.currentTarget.setPointerCapture?.(event.pointerId); }} /></>}
			<div className="chat-workspace">
				<div className="chat-titlebar">
					<button className="sidebar-toggle" aria-label={sidebarOpen ? 'Hide chat sidebar' : 'Show chat sidebar'} title={sidebarOpen ? 'Hide chat sidebar' : 'Show chat sidebar'} onClick={() => setSidebarOpen((value) => !value)}><span className={`codicon ${sidebarOpen ? 'codicon-layout-sidebar-left-off' : 'codicon-layout-sidebar-left'}`} aria-hidden="true" /></button>
					<div><h2>{activeSession?.title ?? 'New chat'}</h2><span>{activeSession ? `${activeSession.model} | ${activeSession.intelligence}` : 'Aqiron Agent'}</span></div>
				</div>
				<div className="conversation-scroll" ref={scrollRef}>
					{!activeSession || activeSession.messages.length === 0 ? <div className="agent-empty">Ask about this workspace, a finding, or a release risk.</div> : activeSession.messages.map((message) => (
						<div key={message.id} className={`chat-turn ${message.role}`}>
							<div className="chat-bubble"><Markdown content={message.content || (message.streaming ? 'Thinking...' : '')} />{message.commands?.length ? <CommandCards commands={message.commands} /> : null}</div>
						</div>
					))}
				</div>
			</div>
			<AgentComposer state={state} post={post} sessionId={activeSession?.id} />
		</div>
	);
});

function ChatSessionList({ state, post, compact = false }: { state: WebviewState; post: Post; compact?: boolean }): React.ReactElement {
	const [openSessionMenu, setOpenSessionMenu] = useState<string | undefined>();
	const [renameSession, setRenameSession] = useState<ChatSession | undefined>();
	const [renameTitle, setRenameTitle] = useState('');
	const [deleteSession, setDeleteSession] = useState<ChatSession | undefined>();
	const iconStyle = (url: string) => ({ '--icon': `url("${url}")` }) as React.CSSProperties;
	useEffect(() => {
		const closeSessionMenu = () => setOpenSessionMenu(undefined);
		document.addEventListener('click', closeSessionMenu);
		return () => document.removeEventListener('click', closeSessionMenu);
	}, []);
	return (
		<>
			<div className={compact ? 'session-list compact' : 'session-list'}>
				{state.chatSessions.length === 0 ? <div className="empty">Start a prompt below to create your first Aqiron AI Agent session.</div> : state.chatSessions.map((session) => {
					const latest = session.messages[session.messages.length - 1];
					return (
						<div key={session.id} className={session.id === state.activeChatSessionId ? 'session-card active' : 'session-card'} role="button" tabIndex={0} onClick={() => post('openChatSession', session.id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { post('openChatSession', session.id); } }}>
							<div className="session-copy">
								<strong>{session.title}</strong>
								<div className="session-preview"><Markdown content={latest?.content ? latest.content.slice(0, compact ? 120 : 220) : 'No messages yet.'} /></div>
								<small>{session.model} | {session.intelligence} | {new Date(session.updatedAt).toLocaleString()}</small>
							</div>
							<div className={openSessionMenu === session.id ? 'session-options open' : 'session-options'} onClick={(event) => event.stopPropagation()}>
								<button className="session-option-trigger" aria-label="Session options" onClick={() => setOpenSessionMenu((current) => current === session.id ? undefined : session.id)}><span className="svg-icon" style={iconStyle(state.assets.sessionOptionIcon)} /></button>
								<div className="session-menu">
									<button onClick={() => { setOpenSessionMenu(undefined); post('shareChatSession', session.id); }}><span className="svg-icon" style={iconStyle(state.assets.sessionShareIcon)} />Share</button>
									<button onClick={() => { setOpenSessionMenu(undefined); setRenameSession(session); setRenameTitle(session.title); }}><span className="svg-icon" style={iconStyle(state.assets.sessionRenameIcon)} />Rename</button>
									<button className="danger-action" onClick={() => { setOpenSessionMenu(undefined); setDeleteSession(session); }}><span className="svg-icon" style={iconStyle(state.assets.sessionDeleteIcon)} />Delete</button>
								</div>
							</div>
						</div>
					);
				})}
			</div>
			{renameSession && (
				<div className="modal-backdrop" role="presentation" onClick={() => setRenameSession(undefined)}>
					<form className="chat-modal rename-modal" onClick={(event) => event.stopPropagation()} onSubmit={(event) => { event.preventDefault(); post('renameChatSession', { sessionId: renameSession.id, title: renameTitle }); setRenameSession(undefined); }}>
						<h2>Rename chat</h2>
						<input value={renameTitle} onChange={(event) => setRenameTitle(event.target.value)} autoFocus />
						<div className="modal-actions"><button type="button" onClick={() => setRenameSession(undefined)}>Cancel</button><button type="submit" className="primary-action">Save</button></div>
					</form>
				</div>
			)}
			{deleteSession && (
				<div className="modal-backdrop" role="presentation" onClick={() => setDeleteSession(undefined)}>
					<div className="chat-modal delete-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
						<h2>Delete chat?</h2>
						<p>This will delete <strong>{deleteSession.title}</strong>.</p>
						<span>Visit settings to delete memories saved during this chat.</span>
						<div className="modal-actions"><button onClick={() => setDeleteSession(undefined)}>Cancel</button><button className="delete-action" onClick={() => { post('deleteChatSession', deleteSession.id); setDeleteSession(undefined); }}>Delete</button></div>
					</div>
				</div>
			)}
		</>
	);
}

function CommandCards({ commands }: { commands: NonNullable<WebviewState['chatSessions'][number]['messages'][number]['commands']> }): React.ReactElement {
	return <div className="command-cards">{commands.map((item) => <CommandCard key={`${item.label}-${item.command}`} item={item} />)}</div>;
}

function CommandCard({ item }: { item: NonNullable<WebviewState['chatSessions'][number]['messages'][number]['commands']>[number] }): React.ReactElement {
	const [copied, setCopied] = useState(false);
	const copy = async () => {
		try {
			if (navigator.clipboard?.writeText) {
				await navigator.clipboard.writeText(item.command);
			} else {
				const input = document.createElement('textarea');
				input.value = item.command;
				input.setAttribute('readonly', '');
				input.style.position = 'fixed';
				input.style.opacity = '0';
				document.body.appendChild(input);
				input.select();
				document.execCommand('copy');
				input.remove();
			}
			setCopied(true);
			window.setTimeout(() => setCopied(false), 1400);
		} catch {
			setCopied(false);
		}
	};
	return <div className="command-card"><div className="command-card-head"><strong>{item.label}</strong><button type="button" className="command-copy" aria-label={copied ? 'Copied' : 'Copy code'} title={copied ? 'Copied' : 'Copy code'} onClick={copy}><span className={`codicon ${copied ? 'codicon-check' : 'codicon-copy'}`} aria-hidden="true" /></button></div><pre><code>{item.command}</code></pre></div>;
}

export const ScanTab = memo(function ScanTab({ state, post }: { state: WebviewState; post: Post }): React.ReactElement {
	const fallbackStages = ['Preparing', 'Indexing', 'Dependency Analysis', 'SAST', 'Secret Scanning', 'AI Vulnerability Analysis', 'AI Correlation', 'Report Generation'];
	const pipelineStages = state.pipeline?.stages.length ? state.pipeline.stages : [];
	const toolStates = new Map((state.pipeline?.tools ?? []).map((tool) => [normalizeToolName(tool.label), tool]));
	const terminalLines = state.pipeline?.logs.length ? state.pipeline.logs.slice(-80).join('\n') : 'No scan logs yet. Start a scan to stream real engine output.';
	const visibleStages = getVisiblePipelineStages(pipelineStages, state.stats.scanStatus);
	const visibleTools = getVisiblePipelineTools(state.pipeline?.tools ?? [], state.stats.scanStatus);
	return (
		<div className="tab-page">
			<section className="section">
				<div className="section-head"><h2>Live Pipeline</h2><span>{getPipelineHeadline(state.stats.scanStatus, visibleStages.length)}</span></div>
				{visibleStages.length ? (
					<div className="pipeline">
						{visibleStages.map((stage) => (
							<details key={stage.name} className={`stage ${stage.status}`} open={stage.status === 'running'}>
								<summary>
									<span className="stage-status" aria-hidden="true">{getStageMarker(stage.status)}</span>
									<strong>{stage.name}</strong>
									<em>{formatStageStatus(stage)}</em>
								</summary>
								<div className="stage-progress" aria-label={`${stage.name} progress`}><span style={{ width: `${Math.max(0, Math.min(100, stage.progress))}%` }} /></div>
								<pre>[{stage.name}] {formatStageTelemetry(stage)}</pre>
							</details>
						))}
					</div>
				) : <PipelineEmptyState scanStatus={state.stats.scanStatus} fallbackStages={fallbackStages} durationMs={state.stats.lastScanDurationMs} />}
			</section>
			<section className="section">
				<div className="section-head"><h2>Tool Execution</h2><span>SAST - DAST - IAST - SCA - AI penetration testing</span></div>
				{visibleTools.length ? (
					<div className="tool-grid">
						{visibleTools.map((tool) => (
							<details key={tool.id} className={`tool-card ${tool.status}`} open={tool.status === 'running'}>
								<summary><strong>{tool.label}</strong><span>{formatToolStatus(tool.status)}</span></summary>
								<p>{getToolDetail(tool.label, toolStates)}</p>
							</details>
						))}
					</div>
				) : <div className="empty">No tools are running right now. Start a scan to show live tool execution.</div>}
			</section>
			<section className="section">
				<div className="section-head"><h2>Terminal Stream</h2><span>Colorized realtime logs</span></div>
				<pre className="terminal">{terminalLines}</pre>
				<div className="control-row ai-analysis-row">
					<button title={scanActionDetail('AI Vulnerability Analysis')} onClick={() => post('aiVulnerabilityAnalysis')}>AI Vulnerability Analysis</button>
				</div>
				<div className="control-row">
					<button title={scanActionDetail('Quick Scan')} onClick={() => post('scanWorkspace', { mode: 'quick' })}>Quick Scan</button>
					<button title={scanActionDetail('Deep Scan')} onClick={() => post('scanWorkspace', { mode: 'deep' })}>Deep Scan</button>
					<button title={scanActionDetail('AI Audit')} onClick={() => post('sendChat', { text: 'Analyze this workspace security posture and prioritize risk using the current scan context.' })}>AI Audit</button>
					<button title={scanActionDetail('Dynamic Analysis')} onClick={() => post('sendChat', { text: 'Assess runtime security behavior and execution risks from the current workspace context.' })}>Dynamic Analysis</button>
					<button onClick={() => post('clearTerminal')}>Clear Terminal</button>
					<button className="danger" onClick={() => post('cancelScan')}>Cancel Scan</button>
				</div>
				<div className="scan-action-help">
					{['Quick Scan', 'Deep Scan', 'AI Vulnerability Analysis', 'Dynamic Analysis', 'AI Audit'].map((label) => (
						<span key={label}><strong>{label}</strong>{scanActionDetail(label)}</span>
					))}
				</div>
			</section>
		</div>
	);
});

function getVisiblePipelineStages(stages: WebviewState['pipeline']['stages'], scanStatus: WebviewState['stats']['scanStatus']): WebviewState['pipeline']['stages'] {
	if (scanStatus === 'Scanning') {
		const running = stages.filter((stage) => stage.status === 'running');
		return running.length ? running : stages.filter((stage) => stage.status !== 'queued').slice(-1);
	}
	if (scanStatus === 'Complete' || scanStatus === 'Failed') {
		return stages.filter((stage) => stage.status !== 'queued');
	}
	return [];
}

function getVisiblePipelineTools(tools: WebviewState['pipeline']['tools'], scanStatus: WebviewState['stats']['scanStatus']): WebviewState['pipeline']['tools'] {
	if (scanStatus === 'Scanning') {
		return tools.filter((tool) => tool.status === 'running');
	}
	if (scanStatus === 'Complete' || scanStatus === 'Failed') {
		return tools.filter((tool) => tool.status !== 'queued');
	}
	return [];
}

function PipelineEmptyState({ scanStatus, fallbackStages, durationMs }: { scanStatus: WebviewState['stats']['scanStatus']; fallbackStages: string[]; durationMs: number }): React.ReactElement {
	if (scanStatus === 'Complete') {
		return <div className="pipeline-empty complete"><strong>Scan finished</strong><span>{durationMs ? `Last run completed in ${formatDuration(durationMs)}.` : 'The last run completed successfully.'}</span></div>;
	}
	if (scanStatus === 'Failed') {
		return <div className="pipeline-empty failed"><strong>Scan stopped</strong><span>Review the terminal stream for the last reported error or cancellation reason.</span></div>;
	}
	return <div className="pipeline-empty"><strong>No scan running</strong><span>When a scan starts, only active pipeline stages appear here: {fallbackStages.join(', ')}.</span></div>;
}

function getPipelineHeadline(scanStatus: WebviewState['stats']['scanStatus'], visibleCount: number): string {
	if (scanStatus === 'Scanning') {
		return visibleCount ? `${visibleCount} active stage${visibleCount === 1 ? '' : 's'}` : 'Waiting for engine telemetry';
	}
	if (scanStatus === 'Complete') {
		return 'Finished stages and report status';
	}
	if (scanStatus === 'Failed') {
		return 'Stopped with last known stage state';
	}
	return 'Idle until the next scan starts';
}

function getStageMarker(status: WebviewState['pipeline']['stages'][number]['status']): string {
	if (status === 'running') {
		return '';
	}
	if (status === 'completed') {
		return 'OK';
	}
	if (status === 'failed' || status === 'timeout' || status === 'cancelled') {
		return '!';
	}
	if (status === 'unavailable') {
		return 'NA';
	}
	return '';
}

function formatStageStatus(stage: WebviewState['pipeline']['stages'][number]): string {
	const parts = [formatToolStatus(stage.status)];
	if (stage.progress > 0) {
		parts.push(`${stage.progress}%`);
	}
	if (stage.durationMs !== undefined) {
		parts.push(formatDuration(stage.durationMs));
	}
	return parts.join(' - ');
}

function formatStageTelemetry(stage: WebviewState['pipeline']['stages'][number]): string {
	if (stage.status === 'running') {
		return `running at ${stage.progress}%`;
	}
	if (stage.durationMs !== undefined) {
		return `${formatToolStatus(stage.status).toLowerCase()} in ${formatDuration(stage.durationMs)}`;
	}
	return formatToolStatus(stage.status).toLowerCase();
}

function formatToolStatus(status: WebviewState['pipeline']['tools'][number]['status']): string {
	return status === 'completed' ? 'Complete' : status[0].toUpperCase() + status.slice(1);
}

function formatDuration(durationMs: number): string {
	if (durationMs < 1000) {
		return `${durationMs}ms`;
	}
	return `${Math.round(durationMs / 100) / 10}s`;
}

function scanActionDetail(label: string): string {
	if (label === 'Quick Scan') {
		return 'Runs Custom Rules, Trivy dependency analysis, Semgrep SAST, Betterleaks secret scanning, AI correlation, and report generation.';
	}
	if (label === 'Deep Scan') {
		return 'Runs Quick Scan plus OSV-Scanner dependency vulnerability analysis and MobSF mobile artifact analysis when MobSF is configured and an APK, IPA, or AAB artifact exists.';
	}
	if (label === 'AI Vulnerability Analysis') {
		return 'Runs deterministic scanners, relevant RAG retrieval, and the dedicated AI vulnerability analysis workflow.';
	}
	if (label === 'Dynamic Analysis') {
		return 'Asks the configured AI provider to assess runtime behavior and execution risks from the current workspace context; it is not a live DAST engine yet.';
	}
	return 'Asks the configured AI provider to review current workspace context and findings for risk prioritization and remediation guidance.';
}
function normalizeToolName(value: string): string {
	const lower = value.toLowerCase();
	if (lower.includes('mobsf')) {
		return 'mobsf';
	}
	if (lower.includes('semgrep')) {
		return 'semgrep';
	}
	if (lower.includes('betterleaks')) {
		return 'betterleaks';
	}
	if (lower.includes('osv')) {
		return 'osv-scanner';
	}
	if (lower.includes('vulnerability') && lower.includes('analysis')) {
		return 'ai analysis';
	}
	if (lower.includes('trivy') || lower.includes('depend')) {
		return 'trivy';
	}
	if (lower.includes('ai') || lower.includes('correlation')) {
		return 'ai analyzer';
	}
	if (lower.includes('custom') || lower.includes('aqiron')) {
		return 'custom rules';
	}
	return lower;
}

function getToolDetail(tool: string, states: Map<string, WebviewState['pipeline']['tools'][number]>): string {
	const state = states.get(normalizeToolName(tool));
	if (!state) {
		if (tool === 'MobSF') {
			return 'MobSF REST API via configured local server';
		}
		if (tool === 'Betterleaks') {
			return 'Local Betterleaks secret scan over eligible Flutter project files; secret values are redacted.';
		}
		if (tool === 'OSV-Scanner') {
			return 'OSV-Scanner dependency vulnerability analysis for pubspec.lock and supported Dart metadata.';
		}
		if (tool === 'AI Security Review') {
			return 'Aqiron AI review and correlation over normalized findings.';
		}
		if (tool === 'AI Analysis') {
			return 'Dedicated AI vulnerability analysis that combines deterministic findings, RAG evidence, validation, and correlated risk output.';
		}
		if (tool === 'AI Analyzer') {
			return 'Aqiron correlation engine that deduplicates findings, links related risks, builds the threat graph, and prepares reports.';
		}
		if (tool === 'Custom Rules') {
			return 'Aqiron native static rules plus editable workspace custom rules from Settings.';
		}
		return 'Waiting for the next scan run';
	}
	const parts = [state.command];
	if (state.durationMs !== undefined) {
		parts.push(`${state.durationMs}ms`);
	}
	if (state.findingsCount !== undefined) {
		parts.push(`${state.findingsCount} findings`);
	}
	if (state.message) {
		parts.push(state.message);
	}
	return parts.join(' · ');
}

export const ThreatTab = memo(function ThreatTab({ state, post }: { state: WebviewState; post: Post }): React.ReactElement {
	const visibleIssues = state.issues;
	const [historyOpen, setHistoryOpen] = useState(true);
	const [historyWidth, setHistoryWidth] = useState(264);
	const [deleteSnapshot, setDeleteSnapshot] = useState<WebviewState['threatSnapshots'][number] | undefined>();
	const [selectedId, setSelectedId] = useState(state.selectedThreatId ?? visibleIssues[0]?.id);
	useEffect(() => {
		setSelectedId(state.selectedThreatId ?? visibleIssues[0]?.id);
	}, [state.activeThreatSnapshotId, state.selectedThreatId, visibleIssues]);
	const selected = visibleIssues.find((issue) => issue.id === selectedId) ?? visibleIssues[0];
	const toolSummary = summarizeTools(visibleIssues);
	const startResize = (event: React.PointerEvent<HTMLDivElement>) => {
		if (!historyOpen) {
			return;
		}
		const startX = event.clientX;
		const startWidth = historyWidth;
		const move = (moveEvent: PointerEvent) => setHistoryWidth(Math.min(380, Math.max(210, startWidth + moveEvent.clientX - startX)));
		const stop = () => {
			document.removeEventListener('pointermove', move);
			document.removeEventListener('pointerup', stop);
		};
		document.addEventListener('pointermove', move);
		document.addEventListener('pointerup', stop, { once: true });
	};
	return (
		<div className={historyOpen ? 'threat-workbench' : 'threat-workbench history-collapsed'}>
			<aside className={historyOpen ? 'threat-history' : 'threat-history collapsed'} style={historyOpen ? { width: `${historyWidth}px` } : undefined} aria-label="Stored threat results">
				<div className="threat-history-head"><button className="threat-history-toggle" aria-label={historyOpen ? 'Collapse threat results' : 'Expand threat results'} onClick={() => setHistoryOpen((value) => !value)}><span className="codicon codicon-layout-sidebar-left" aria-hidden="true" /></button>{historyOpen && <div><strong>Threat Results</strong><span>Stored locally</span></div>}</div>
				{historyOpen && <>
				<div className="threat-history-label"><span>Recent scans</span><span className="codicon codicon-history" aria-hidden="true" /></div>
				<div className="threat-history-list">
					{state.threatSnapshots.length ? state.threatSnapshots.map((snapshot) => <ThreatSnapshotCard key={snapshot.id} active={snapshot.id === state.activeThreatSnapshotId} snapshot={snapshot} onSelect={() => post('selectThreatSnapshot', snapshot.id)} onDelete={() => setDeleteSnapshot(snapshot)} />) : <div className="threat-history-empty"><span className="codicon codicon-search-stop" aria-hidden="true" />No scan results yet.</div>}
				</div>
				<div className="threat-history-resizer" role="separator" aria-label="Resize threat results sidebar" onPointerDown={startResize}><span /></div>
				</>}
			</aside>
			<div className="tab-page threat-layout">
				<section className="section table-section">
				<div className="section-head"><h2>Threat Intelligence</h2><span>{visibleIssues.length} actionable findings</span></div>
				<div className="threat-summary">
					<span><strong>{visibleIssues.length}</strong>Open findings</span>
					<span><strong>{toolSummary}</strong>Source coverage</span>
					<span><strong>{state.stats.filesScanned}</strong>Files scanned</span>
				</div>
				<div className="threat-help">
					<span><strong>CWE</strong>Common Weakness Enumeration: the underlying software weakness class.</span>
					<span><strong>OWASP</strong>The OWASP Top 10 risk category mapped to the finding.</span>
					<span><strong>Confidence</strong>How strongly the scanner evidence supports the finding.</span>
				</div>
				<div className="threat-table-scroll">
				<div className="threat-table" role="table" aria-label="Threat intelligence findings">
					<div className="th-row head" role="row"><span>Threat</span><span>Severity</span><span>File</span><span>CWE</span><span>OWASP</span><span>Source Tool</span><span>Confidence</span><span>Status</span></div>
					{visibleIssues.length ? visibleIssues.map((issue) => (
						<button key={issue.id} className={issue.id === selected?.id ? 'th-row active' : 'th-row'} onClick={() => setSelectedId(issue.id)}>
							<span className="th-threat-copy">
								<strong>{issue.title}</strong>
								<small>{formatThreatMessage(issue)}</small>
								<span className="th-threat-meta">
									<span>{issue.relativeFile}:{issue.line}</span>
									<span>{formatSourceTool(issue.tool)}</span>
								</span>
							</span>
							<SeverityBadge severity={issue.severity} />
							<span>{issue.relativeFile}:{issue.line}</span>
							<span>{issue.cwe}</span>
							<span>{issue.owasp}</span>
							<span>{formatSourceTool(issue.tool)}</span>
							<span>{issue.confidence}</span>
							<span>{issue.status}</span>
						</button>
					)) : <div className="empty">No actionable threats indexed. Start a scan to build the vulnerability inventory.</div>}
				</div>
			</div>
				</section>
				<section className="section">
				<div className="section-head"><h2>Threat Details</h2><span>Evidence, impact, remediation</span></div>
				{selected ? <ThreatDetails issue={selected} post={post} /> : <div className="empty">No threats indexed yet.</div>}
				</section>
				<section className="section">
				<div className="section-head"><h2>Relationship Graph</h2><span>Files - tools - risk clusters</span></div>
				<GraphPreview state={{ ...state, issues: visibleIssues }} />
				</section>
			</div>
			{deleteSnapshot && <div className="modal-backdrop" role="presentation" onClick={() => setDeleteSnapshot(undefined)}>
				<div className="chat-modal delete-modal" role="dialog" aria-modal="true" aria-labelledby="delete-threat-title" onClick={(event) => event.stopPropagation()}>
					<h2 id="delete-threat-title">Delete threat report?</h2>
					<p>This will permanently delete <strong>{deleteSnapshot.title}</strong>.</p>
					<div className="modal-actions"><button type="button" onClick={() => setDeleteSnapshot(undefined)}>Cancel</button><button type="button" className="delete-action" onClick={() => { post('deleteThreatSnapshot', deleteSnapshot.id); setDeleteSnapshot(undefined); }}>Delete</button></div>
				</div>
			</div>}
		</div>
	);
});

function ThreatSnapshotCard({ snapshot, active, onSelect, onDelete }: { snapshot: WebviewState['threatSnapshots'][number]; active: boolean; onSelect: () => void; onDelete: () => void }): React.ReactElement {
	const counts = countSnapshotSeverities(snapshot.issues);
	return <div className={active ? 'threat-snapshot active' : 'threat-snapshot'} role="button" tabIndex={0} onClick={onSelect} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(); } }} aria-pressed={active}>
		<div className="threat-snapshot-title"><strong>{snapshot.title}</strong><span className="threat-snapshot-actions"><span className="codicon codicon-files" aria-hidden="true" /><button type="button" className="threat-snapshot-delete" aria-label={`Delete ${snapshot.title}`} title="Delete threat report" onClick={(event) => { event.stopPropagation(); onDelete(); }}><span className="codicon codicon-trash" aria-hidden="true" /></button></span></div>
		<div className="threat-snapshot-meta"><span>{formatThreatTimestamp(snapshot.createdAt)}</span><span>{snapshot.filesScanned} files</span></div>
		<div className="threat-snapshot-counts" aria-label={`${snapshot.issues.length} findings`}><span className="critical"><i />{counts.critical}</span><span className="high"><i />{counts.high}</span><span className="medium"><i />{counts.medium}</span><span className="low"><i />{counts.low}</span></div>
	</div>;
}

function countSnapshotSeverities(issues: readonly WebviewIssue[]): Record<Lowercase<Severity>, number> {
	return issues.reduce<Record<Lowercase<Severity>, number>>((counts, issue) => {
		counts[issue.severity.toLowerCase() as Lowercase<Severity>] += 1;
		return counts;
	}, { critical: 0, high: 0, medium: 0, low: 0 });
}

function formatThreatTimestamp(value: string): string {
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function formatTimelineTimestamp(value: string): string {
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function summarizeTools(issues: readonly WebviewIssue[]): string {
	const tools = [...new Set(issues.map((issue) => issue.tool))].filter(Boolean);
	return tools.length ? tools.slice(0, 3).join(', ') + (tools.length > 3 ? ` +${tools.length - 3}` : '') : 'None';
}

export const ReportsTab = memo(function ReportsTab({ state, post }: { state: WebviewState; post: Post }): React.ReactElement {
	const scores = useMemo(() => [78, 82, 76, 86, 89, 84, Math.max(48, 96 - state.counts.critical * 12 - state.counts.high * 6)], [state.counts]);
	const activeReport = state.threatSnapshots.find((snapshot) => snapshot.id === state.activeThreatSnapshotId);
	return (
		<div className="tab-page">
			<section className="metric-grid">
				<Metric title="Security Score" value={`${scores[scores.length - 1]}`} />
				<Metric title="Open Findings" value={`${state.counts.total}`} />
				<Metric title="OWASP Coverage" value="92%" />
				<Metric title="Files Scanned" value={`${state.stats.filesScanned}`} />
			</section>
			<section className="section">
				<div className="section-head"><h2>Security Score Evolution</h2><span>{activeReport ? `Report for ${activeReport.title}` : 'Rolling posture trend'} <span className="report-info" title="These bars show how Aqiron’s calculated security posture changes across recent scans. Higher bars mean fewer or lower-risk findings; use the trend to confirm remediation is improving the release posture."><span className="codicon codicon-info" aria-hidden="true" /> What is this?</span></span></div>
				<div className="line-chart">{scores.map((score, index) => <i key={index} style={{ height: `${score}%` }} />)}</div>
			</section>
			<section className="section report-grid">
				<div>
					<div className="section-head"><h2>Executive Summary</h2></div>
					<div className="executive executive-scroll"><Markdown content={state.pipeline.lastReport?.executiveSummary ?? (state.counts.total ? `Aqiron found ${state.counts.total} findings. Prioritize critical secrets, injection paths, and permissions before the next release gate.` : 'No open findings are currently indexed. Continue scheduled scans, dependency monitoring, and release-gate audits.')} /></div>
				</div>
				<div>
					<div className="section-head"><h2>Compliance</h2></div>
					{state.compliance.map((item) => <div key={item.name} className="compliance"><strong>{item.name}</strong><span>{item.score}%</span><em>{item.status}</em></div>)}
				</div>
			</section>
			<section className="section report-graph-card">
				<div className="section-head"><h2>Security Influence Graph</h2><span>Which tool found the risk and where the evidence lives</span></div>
				<div className="report-graph-layout">
					<GraphPreview state={state} />
					<div className="graph-insights">
						<p className="graph-explanation">Each path reads left to right: scanner → finding → file. Betterleaks represents exposed secrets; OSV-Scanner represents dependency vulnerabilities.</p>
						<div className="tool-influence-list">{summarizeToolInfluence(state.issues).map((item) => <div key={item.tool} className="tool-influence"><span className="tool-influence-dot" /><div><strong>{item.tool}</strong><small>{item.findings} finding{item.findings === 1 ? '' : 's'} · {item.highRisk} high-risk</small></div><span className="tool-influence-count">{item.findings}</span></div>)}</div>
					</div>
				</div>
			</section>
			<section className="section">
				<div className="section-head"><h2>Scan Timeline</h2><span>Completed scan history</span></div>
				<div className="timeline-list">{state.timeline.map((item) => <div key={item.id} className="timeline"><div className="timeline-head"><strong>{item.title}</strong><time>{formatTimelineTimestamp(item.timestamp)}</time></div><span>{item.detail}</span></div>)}</div>
				<div className="control-row"><button onClick={() => post('exportReport', 'pdf')}>Export PDF</button><button onClick={() => post('exportReport', 'json')}>Export JSON</button><button onClick={() => post('exportReport', 'share')}>Share Report</button><button onClick={() => post('exportReport', 'jira')}>Create Jira Ticket</button></div>
			</section>
		</div>
	);
});

function ContextBar({ state }: { state: WebviewState }): React.ReactElement {
	return <div className="context-bar">{[state.workspace.currentFile, state.workspace.types[0] ?? 'Workspace', state.workspace.backend, state.branches[0] ?? 'No branch', state.stats.scanStatus, `${state.workspace.apis.length} APIs`].map((item) => <span key={item}>{item}</span>)}</div>;
}

function ReasoningPanel(): React.ReactElement {
	const steps = ['Analyzing auth flow...', 'Correlating dependency risks...', 'Inspecting manifest permissions...'];
	return <details className="reasoning" open><summary>AI reasoning visibility</summary>{steps.map((step) => <motion.div key={step} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }}>{step}</motion.div>)}</details>;
}

function AgentComposer({ state, post, sessionId }: { state: WebviewState; post: Post; sessionId?: string }): React.ReactElement {
	const [openMenu, setOpenMenu] = useState<string | undefined>();
	const [text, setText] = useState('');
	const [branchQuery, setBranchQuery] = useState('');
	const [settingsOpen, setSettingsOpen] = useState(false);
	const [modelSubmenuOpen, setModelSubmenuOpen] = useState(false);
	const toggleMenu = (menu: string) => setOpenMenu((current) => current === menu ? undefined : menu);
	const closeMenus = () => {
		setOpenMenu(undefined);
		setModelSubmenuOpen(false);
	};
	const iconStyle = (url: string) => ({ '--icon': `url("${url}")` }) as React.CSSProperties;
	const branches = state.branches.filter((branch) => branch.toLowerCase().includes(branchQuery.trim().toLowerCase()));
	const tokenPercent = Math.min(100, Math.max(0, state.tokenUsage.contextUsed));
	const selectedModel = state.ai.models.find((model) => model.id === state.ai.selection.model)?.label ?? 'No models selected';
	const selectedProvider = state.ai.providers.find((provider) => provider.id === state.ai.selection.provider);
	const providerApis = state.ai.apiCredentials;
	const activeSession = sessionId ? state.chatSessions.find((session) => session.id === sessionId) : state.chatSessions.find((session) => session.id === state.activeChatSessionId);
	const isStreaming = Boolean(activeSession?.streaming || activeSession?.messages.some((message) => message.streaming));
	const send = () => {
		const prompt = text.trim();
		if (!prompt || isStreaming) {
			return;
		}
		post('sendChat', sessionId ? { text: prompt, sessionId } : { text: prompt });
		setText('');
	};
	useEffect(() => {
		document.addEventListener('click', closeMenus);
		return () => document.removeEventListener('click', closeMenus);
	}, []);
	return (
		<div className="composer" onClick={(event) => event.stopPropagation()}>
			<textarea value={text} onClick={closeMenus} onFocus={closeMenus} onChange={(event) => setText(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send(); } }} placeholder="Ask Aqiron to analyze, explain, fuzz, patch, or report..." />
			<div className="composer-footer">
				<div className="composer-control edge">
					<button className="round" onClick={() => post('attachContext')}><span className="svg-icon" style={iconStyle(state.assets.addIcon)} /></button>
					<span className="tip edge-left">Add files and more</span>
				</div>
				<div className={openMenu === 'provider' ? 'provider-pill provider-slot open' : 'provider-pill provider-slot'}>
					<span className={state.ai.status.connected ? 'provider-dot ok-dot' : 'provider-dot warn-dot'} />
					<button onClick={() => toggleMenu('provider')}>{selectedProvider?.name ?? 'Provider'}<span className="svg-icon" style={iconStyle(state.assets.chevronDownIcon)} /></button>
					<div className={openMenu === 'provider' ? 'composer-pop provider-pop open-pop edge-left' : 'composer-pop provider-pop edge-left'} onClick={(event) => event.stopPropagation()}>
						<ProviderMenu state={state} post={post} providerApis={providerApis} onClose={closeMenus} onSettings={() => setSettingsOpen(true)} />
					</div>
				</div>
				{state.workspace.hasGit ? (
					<div className={openMenu === 'branch' ? 'composer-control edge open' : 'composer-control edge'}>
						<button onClick={() => toggleMenu('branch')}><span className="svg-icon" style={iconStyle(state.assets.branchesIcon)} />{state.branches[0] ?? 'No branch'}<span className="svg-icon" style={iconStyle(state.assets.chevronDownIcon)} /></button>
						<span className="tip edge-left">Switch branch</span>
						<div className="composer-pop branch-pop edge-left" onClick={(event) => event.stopPropagation()}>
							<div className="branch-search"><span className="svg-icon" style={iconStyle(state.assets.searchIcon)} /><input value={branchQuery} onChange={(event) => setBranchQuery(event.target.value)} placeholder="Search branches" /></div>
							<div className="menu-title">Branches</div>
							<div className="branch-box">
								{state.branches.length === 0 ? <div className="menu-option muted">No Git branches detected</div> : branches.map((branch, index) => <button key={branch} className="menu-option" onClick={() => { post('checkoutBranch', branch); closeMenus(); }}><span className="svg-icon" style={iconStyle(state.assets.branchesIcon)} />{branch}<span className="option-spacer" />{index === 0 ? <span className="branch-check">Active</span> : null}</button>)}
								{state.branches.length > 0 && branches.length === 0 ? <div className="menu-option muted">No matching branches</div> : null}
							</div>
							<button className="menu-option branch-create" onClick={() => { post('createBranch'); closeMenus(); }}><span className="svg-icon" style={iconStyle(state.assets.addIcon)} />Create and checkout new branch...</button>
						</div>
					</div>
				) : null}
				<div className="composer-spacer" onClick={closeMenus} />
				<div className="token-control">
					<div className="token-ring" style={{ background: `conic-gradient(#56b8ff 0 ${tokenPercent}%, rgba(255,255,255,.12) ${tokenPercent}% 100%)` }} />
					<div className="token-pop"><strong>Context window:</strong><span>{tokenPercent}% used</span><span>{state.tokenUsage.totalTokens} / {state.tokenUsage.contextWindow} tokens</span><span>Prompt {state.tokenUsage.promptTokens} | Completion {state.tokenUsage.completionTokens}</span><b>Live usage from the selected session.</b></div>
				</div>
				<div className={openMenu === 'model' ? 'composer-control open' : 'composer-control'}>
					<button className="model-button" onClick={() => toggleMenu('model')}><span><strong>{selectedModel}</strong><em>{state.ai.selection.intelligence}</em></span><span className="svg-icon" style={iconStyle(state.assets.chevronDownIcon)} /></button>
					<span className="tip">Select model <kbd>Ctrl+Shift+M</kbd></span>
					<div className="composer-pop model-pop" onClick={(event) => event.stopPropagation()}>
						<div className="menu-title">Intelligence</div>
						{state.ai.intelligenceProfiles.map((profile) => <button key={profile.level} className="menu-option" onClick={() => { post('selectIntelligence', profile.level); closeMenus(); }}>{profile.label}<span className="option-spacer" />{profile.level === state.ai.selection.intelligence ? <span className="hint">Selected</span> : null}</button>)}
						<div className="menu-separator" />
						<div className={modelSubmenuOpen ? 'submenu-wrap open' : 'submenu-wrap'}>
							<button className="menu-option" onClick={() => setModelSubmenuOpen((value) => !value)}>Aqiron models<span className="option-spacer" />&gt;</button>
							<div className="side-menu">
								<div className="menu-title">Model</div>
								<div className="model-search"><input value={state.ai.modelFilter.query} onChange={(event) => post('applyModelFilter', { query: event.target.value })} placeholder="Search models" /></div>
								<div className="model-filters">
									{(['freeOnly', 'codingOnly', 'reasoningOnly', 'visionOnly'] as const).map((key) => <button key={key} type="button" aria-pressed={state.ai.modelFilter[key]} className={state.ai.modelFilter[key] ? 'filter-chip active' : 'filter-chip'} onClick={() => post('applyModelFilter', { [key]: !state.ai.modelFilter[key] })}>{filterLabel(key)}</button>)}
								</div>
								{state.ai.loadingModels ? <div className="menu-option muted">Loading models...</div> : null}
								{state.ai.modelError ? <div className="menu-option muted">{state.ai.modelError}</div> : null}
								{!state.ai.loadingModels && state.ai.filteredModels.length === 0 ? <div className="menu-option muted">No matching models</div> : state.ai.filteredModels.slice(0, 80).map((model) => <button key={model.id} className="menu-option model-option" onClick={() => { post('selectModel', model.id); closeMenus(); }}><span><strong>{model.label}</strong><small>{model.contextWindow ? `${model.contextWindow.toLocaleString()} ctx` : model.family ?? model.providerId}</small></span><span className="option-spacer" />{model.badges.slice(0, 3).map((badge) => <span key={badge} className="model-badge">{badge}</span>)}{model.id === state.ai.selection.model ? <span className="hint">Selected</span> : null}</button>)}
							</div>
						</div>
					</div>
				</div>
				<div className="send-wrap"><button className="send" onClick={isStreaming ? () => post('cancelGeneration', sessionId) : send}>{isStreaming ? 'Stop' : <span className="svg-icon" style={iconStyle(state.assets.upArrowIcon)} />}</button><span className="tip">{isStreaming ? 'Cancel generation' : 'Send'}</span></div>
			</div>
			{settingsOpen ? <AISettingsModal state={state} post={post} onClose={() => setSettingsOpen(false)} /> : null}
		</div>
	);
}

function AISettingsModal({ state, post, onClose }: { state: WebviewState; post: Post; onClose: () => void }): React.ReactElement {
	const [temperature, setTemperature] = useState(String(state.ai.settings.temperature));
	const [maxTokens, setMaxTokens] = useState(String(state.ai.settings.maxTokens));
	const [timeoutMs, setTimeoutMs] = useState(String(state.ai.settings.timeoutMs));
	const [retries, setRetries] = useState(String(state.ai.settings.retries));
	const [streaming, setStreaming] = useState(state.ai.settings.streaming);
	const activeProvider = state.ai.providers.find((provider) => provider.id === state.ai.selection.provider);
	const save = () => {
		post('saveProviderSettings', {
			temperature: Number(temperature),
			maxTokens: Number(maxTokens),
			timeoutMs: Number(timeoutMs),
			retries: Number(retries),
			streaming,
		});
		onClose();
	};
	return (
		<div className="modal-backdrop" role="presentation" onClick={onClose}>
			<div className="chat-modal ai-settings-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
				<h2>AI Settings</h2>
				<label>Provider<span>{activeProvider?.name}</span></label>
				<label>API key<span>{activeProvider?.hasCredential ? 'Saved in SecretStorage' : 'Not saved'}</span></label>
				<label>Temperature<input type="number" min="0" max="2" step="0.1" value={temperature} onChange={(event) => setTemperature(event.target.value)} /></label>
				<label>Max tokens<input type="number" min="16" step="128" value={maxTokens} onChange={(event) => setMaxTokens(event.target.value)} /></label>
				<label>Timeout ms<input type="number" min="5000" step="1000" value={timeoutMs} onChange={(event) => setTimeoutMs(event.target.value)} /></label>
				<label>Retries<input type="number" min="0" max="5" value={retries} onChange={(event) => setRetries(event.target.value)} /></label>
				<label className="toggle-row"><input type="checkbox" checked={streaming} onChange={(event) => setStreaming(event.target.checked)} /> Streaming</label>
				<div className="modal-actions"><button type="button" onClick={() => post('configureProvider', state.ai.selection.provider)}>Save credentials</button><button type="button" onClick={() => post('removeProviderCredentials', state.ai.selection.provider)}>Remove credentials</button><button type="button" onClick={onClose}>Cancel</button><button type="button" className="primary-action" onClick={save}>Save</button></div>
			</div>
		</div>
	);
}

export const SettingsTab = memo(function SettingsTab({ state, post }: { state: WebviewState; post: Post }): React.ReactElement {
	const [editingId, setEditingId] = useState<string | undefined>();
	const editing = state.ai.apiCredentials.find((api) => api.id === editingId);
	const [activeSettingsPanel, setActiveSettingsPanel] = useState<'credentials' | 'general' | 'flutter'>('credentials');
	const [frameworksOpen, setFrameworksOpen] = useState(true);
	const [apiKey, setApiKey] = useState('');
	const [apiProvider, setApiProvider] = useState<WebviewState['ai']['selection']['provider']>(state.ai.selection.provider);
	const [deleteApi, setDeleteApi] = useState<WebviewState['ai']['apiCredentials'][number] | undefined>();
	const [mobSfBaseUrl, setMobSfBaseUrl] = useState(state.mobsf.baseUrl);
	const [mobSfApiKey, setMobSfApiKey] = useState('');
	const defaults = state.ai.taskDefaults;
	const [useChatDefaults, setUseChatDefaults] = useState(defaults.useChatDefaults);
	const [provider, setProvider] = useState(defaults.provider ?? state.ai.selection.provider);
	const [model, setModel] = useState(defaults.model ?? state.ai.selection.model);
	const [intelligence, setIntelligence] = useState(defaults.intelligence ?? state.ai.selection.intelligence);
	const [customRules, setCustomRules] = useState(state.customRules);
	useEffect(() => {
		if (!editing) {
			return;
		}
		setApiKey('');
	}, [editing]);
	const resetApiForm = () => {
		setEditingId(undefined);
		setApiKey('');
	};
	const saveApi = () => {
		if (!apiKey.trim()) {
			return;
		}
		post('saveApiCredential', { id: editing?.id, providerId: editing?.providerId ?? apiProvider, key: apiKey });
		resetApiForm();
	};
	const saveMobSfSettings = () => {
		post('saveMobSfSettings', { baseUrl: mobSfBaseUrl, apiKey: mobSfApiKey });
		setMobSfApiKey('');
	};
	const updateTaskDefaults = (next: { useChatDefaults?: boolean; provider?: WebviewState['ai']['selection']['provider']; model?: string; intelligence?: string }) => {
		const nextDefaults = { useChatDefaults, provider, model, intelligence, ...next };
		setUseChatDefaults(nextDefaults.useChatDefaults);
		setProvider(nextDefaults.provider);
		setModel(nextDefaults.model);
		setIntelligence(nextDefaults.intelligence);
		post('saveTaskDefaults', nextDefaults);
	};
	const saveCustomRules = () => {
		post('saveCustomRules', customRules);
	};
	const apiManagementCard = (
		<section className="section">
				<div className="section-head"><h2>API Management</h2><span>Saved provider credentials</span></div>
				<div className="api-list">
					{state.ai.apiCredentials.length === 0 ? <div className="empty">No API keys saved yet.</div> : state.ai.apiCredentials.map((api) => (
						<div key={api.id} className={api.id === state.ai.settings.activeApiCredentialId ? 'api-row active' : 'api-row'}>
							<div><strong>{api.name}</strong><span>{providerName(api.providerId)} · {maskApiKey(api.last4)}</span></div>
							<div className="api-actions">
								<button className={api.id === state.ai.settings.activeApiCredentialId ? 'api-action selected' : 'api-action'} onClick={() => post('selectApiCredential', api.id)}>{api.id === state.ai.settings.activeApiCredentialId ? 'Selected' : 'Use'}</button>
								<button className="api-action edit" onClick={() => setEditingId(api.id)}>Edit</button>
								<button className="api-action delete" onClick={() => setDeleteApi(api)}>Delete</button>
							</div>
						</div>
					))}
				</div>
				<div className="settings-form">
					<label>Provider<select value={editing?.providerId ?? apiProvider} disabled={Boolean(editing)} onChange={(event) => setApiProvider(event.target.value as WebviewState['ai']['selection']['provider'])}><option value="openrouter">OpenRouter</option><option value="openai">OpenAI</option><option value="claude">Claude</option><option value="gemini">Gemini</option></select></label>
					<label>API key<input value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder={editing ? 'Paste API key to revalidate' : 'Paste API key'} type="password" /></label>
					<p className="settings-help">Credentials are stored securely and used only with the selected provider.</p>
					<div className="control-row"><button onClick={saveApi}>{editing ? 'Save API' : 'Add API'}</button>{editing ? <button onClick={resetApiForm}>Cancel edit</button> : null}</div>
				</div>
				{deleteApi ? (
					<div className="modal-backdrop" role="presentation" onClick={() => setDeleteApi(undefined)}>
						<div className="chat-modal delete-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
							<h2>Delete API key?</h2>
							<p>This will delete <strong>{deleteApi.name}</strong>.</p>
							<span>The key will be removed from VS Code SecretStorage and cannot be used by Aqiron until it is added again.</span>
							<div className="modal-actions"><button onClick={() => setDeleteApi(undefined)}>Cancel</button><button className="delete-action" onClick={() => { post('deleteApiCredential', deleteApi.id); setDeleteApi(undefined); }}>Delete</button></div>
						</div>
					</div>
				) : null}
			</section>
	);
	const mobSfCard = (
		<section className="section">
				<div className="section-head"><h2>MobSF Integration</h2><span>Mobile artifact scanning</span></div>
				<div className="settings-form">
					<label>Base URL<input value={mobSfBaseUrl} onChange={(event) => setMobSfBaseUrl(event.target.value)} placeholder="http://localhost:1337/" /></label>
					<label>API key<input value={mobSfApiKey} onChange={(event) => setMobSfApiKey(event.target.value)} placeholder={state.mobsf.apiKeyConfigured ? 'Saved - paste new key to replace or leave blank to clear' : 'Paste MobSF API key'} type="password" /></label>
					<p className="settings-help">MobSF runs only when both a server base URL and API key are configured. The extension no longer ships a default MobSF endpoint or key.</p>
					<div className="control-row"><button onClick={saveMobSfSettings}>Save MobSF settings</button><span className={state.mobsf.apiKeyConfigured ? 'settings-status ok' : 'settings-status'}>{state.mobsf.apiKeyConfigured ? 'API key configured' : 'API key not configured'}</span></div>
				</div>
			</section>
	);
	const generalCard = (
		<section className="section">
				<div className="section-head"><h2>Threats & Reports AI</h2><span>Defaults for non-agent features</span></div>
				<div className="settings-form ai-defaults-form">
					<label className="toggle-row"><input type="checkbox" checked={useChatDefaults} onChange={(event) => updateTaskDefaults({ useChatDefaults: event.target.checked })} /> Use chat widget provider, model, and intelligence</label>
					<SettingsAiDropdowns state={state} post={post} disabled={useChatDefaults} provider={provider} model={model} intelligence={intelligence} onProvider={(value) => updateTaskDefaults({ provider: value })} onModel={(value) => updateTaskDefaults({ model: value })} onIntelligence={(value) => updateTaskDefaults({ intelligence: value })} />
				</div>
				<div className="section-head"><h2>Accessibility</h2><span>Adjust Aqiron text and controls</span></div>
				<div className="zoom-control"><span>Interface zoom</span><div><button aria-label="Decrease interface zoom" onClick={() => post('setZoom', Math.max(0.85, state.zoom - 0.05))}><span className="codicon codicon-remove" aria-hidden="true" /></button><strong>{Math.round(state.zoom * 100)}%</strong><button aria-label="Increase interface zoom" onClick={() => post('setZoom', Math.min(1.3, state.zoom + 0.05))}><span className="codicon codicon-add" aria-hidden="true" /></button><button onClick={() => post('setZoom', 1)}>Reset</button></div></div>
			</section>
	);
	const flutterCard = (
		<section className="section">
				<div className="section-head"><h2>Flutter Custom Rules</h2><span>Framework-specific scanner rules</span></div>
				<div className="settings-form custom-rules-form">
					<textarea value={customRules} onChange={(event) => setCustomRules(event.target.value)} spellCheck={false} />
					<p className="settings-help">Flutter rules are JSON objects with id, title, message, severity, pattern, and optional extensions. Other frameworks can have their own custom rule cards here later.</p>
					<div className="control-row"><button onClick={saveCustomRules}>Save custom rules</button></div>
				</div>
			</section>
	);
	return (
		<div className="tab-page settings-page">
			<aside className="settings-sidebar" aria-label="Settings navigation">
				<div className="settings-sidebar-head"><strong>Settings</strong></div>
				<button className={activeSettingsPanel === 'credentials' ? 'settings-nav active' : 'settings-nav'} onClick={() => setActiveSettingsPanel('credentials')}><span className="codicon codicon-key" aria-hidden="true" /><span>Api and credentials</span></button>
				<button className={activeSettingsPanel === 'general' ? 'settings-nav active' : 'settings-nav'} onClick={() => setActiveSettingsPanel('general')}><span className="codicon codicon-settings-gear" aria-hidden="true" /><span>General</span></button>
				<div className={frameworksOpen ? 'settings-nav-group open' : 'settings-nav-group'}>
					<button className="settings-nav group-trigger" onClick={() => setFrameworksOpen((value) => !value)} aria-expanded={frameworksOpen}>
						<span className="codicon codicon-library" aria-hidden="true" />
						<span>Languages and framework</span>
						<span className={frameworksOpen ? 'codicon codicon-chevron-down' : 'codicon codicon-chevron-right'} aria-hidden="true" />
					</button>
					{frameworksOpen ? <button className={activeSettingsPanel === 'flutter' ? 'settings-nav child active' : 'settings-nav child'} onClick={() => setActiveSettingsPanel('flutter')}><span className="settings-child-dot" />Flutter</button> : null}
				</div>
			</aside>
			<div className="settings-content">
				{activeSettingsPanel === 'credentials' ? <>{apiManagementCard}{mobSfCard}</> : null}
				{activeSettingsPanel === 'general' ? generalCard : null}
				{activeSettingsPanel === 'flutter' ? flutterCard : null}
			</div>
		</div>
	);
});

function SettingsAiDropdowns({ state, post, disabled, provider, model, intelligence, onProvider, onModel, onIntelligence }: {
	state: WebviewState;
	post: Post;
	disabled: boolean;
	provider: WebviewState['ai']['selection']['provider'];
	model: string;
	intelligence: string;
	onProvider: (value: WebviewState['ai']['selection']['provider']) => void;
	onModel: (value: string) => void;
	onIntelligence: (value: string) => void;
}): React.ReactElement {
	const [openMenu, setOpenMenu] = useState<string | undefined>();
	const [modelSubmenuOpen, setModelSubmenuOpen] = useState(false);
	const selectedModel = state.ai.models.find((item) => item.id === model)?.label ?? 'No models selected';
	const selectedProvider = state.ai.providers.find((item) => item.id === provider);
	const providerApis = state.ai.apiCredentials;
	const closeMenus = () => {
		setOpenMenu(undefined);
		setModelSubmenuOpen(false);
	};
	const toggleMenu = (menu: string) => {
		if (!disabled) {
			setOpenMenu((current) => current === menu ? undefined : menu);
		}
	};
	const iconStyle = (url: string) => ({ '--icon': `url("${url}")` }) as React.CSSProperties;
	useEffect(() => {
		document.addEventListener('click', closeMenus);
		return () => document.removeEventListener('click', closeMenus);
	}, []);
	return (
		<div className={disabled ? 'settings-menu-row disabled' : 'settings-menu-row'} onClick={(event) => event.stopPropagation()}>
			<div className={openMenu === 'model' ? 'composer-control settings-model-control open' : 'composer-control settings-model-control'}>
				<button className="model-button" disabled={disabled} onClick={() => toggleMenu('model')}><span><strong>{selectedModel}</strong><em>{intelligence}</em></span><span className="svg-icon" style={iconStyle(state.assets.chevronDownIcon)} /></button>
				<div className="composer-pop model-pop settings-model-pop" onClick={(event) => event.stopPropagation()}>
					<div className="menu-title">Intelligence</div>
					{state.ai.intelligenceProfiles.map((profile) => <button key={profile.level} className="menu-option" onClick={() => { onIntelligence(profile.level); closeMenus(); }}>{profile.label}<span className="option-spacer" />{profile.level === intelligence ? <span className="hint">Selected</span> : null}</button>)}
					<div className="menu-separator" />
					<div className={modelSubmenuOpen ? 'submenu-wrap open' : 'submenu-wrap'}>
						<button className="menu-option" onClick={() => setModelSubmenuOpen((value) => !value)}>Aqiron models<span className="option-spacer" />&gt;</button>
						<div className="side-menu">
							<div className="menu-title">Model</div>
							<div className="model-search"><input value={state.ai.modelFilter.query} onChange={(event) => post('applyModelFilter', { query: event.target.value })} placeholder="Search models" /></div>
							<div className="model-filters">
								{(['freeOnly', 'codingOnly', 'reasoningOnly', 'visionOnly'] as const).map((key) => <button key={key} type="button" aria-pressed={state.ai.modelFilter[key]} className={state.ai.modelFilter[key] ? 'filter-chip active' : 'filter-chip'} onClick={() => post('applyModelFilter', { [key]: !state.ai.modelFilter[key] })}>{filterLabel(key)}</button>)}
							</div>
							{state.ai.loadingModels ? <div className="menu-option muted">Loading models...</div> : null}
							{state.ai.modelError ? <div className="menu-option muted">{state.ai.modelError}</div> : null}
							{!state.ai.loadingModels && state.ai.filteredModels.length === 0 ? <div className="menu-option muted">No matching models</div> : state.ai.filteredModels.slice(0, 80).map((item) => <button key={item.id} className="menu-option model-option" onClick={() => { onModel(item.id); closeMenus(); }}><span><strong>{item.label}</strong><small>{item.contextWindow ? `${item.contextWindow.toLocaleString()} ctx` : item.family ?? item.providerId}</small></span><span className="option-spacer" />{item.badges.slice(0, 3).map((badge) => <span key={badge} className="model-badge">{badge}</span>)}{item.id === model ? <span className="hint">Selected</span> : null}</button>)}
						</div>
					</div>
				</div>
			</div>
			<div className={openMenu === 'provider' ? 'provider-pill settings-provider open' : 'provider-pill settings-provider'}>
				<span className={state.ai.status.connected ? 'provider-dot ok-dot' : 'provider-dot warn-dot'} />
				<button disabled={disabled} onClick={() => toggleMenu('provider')}>{selectedProvider?.name ?? 'Provider'}<span className="svg-icon" style={iconStyle(state.assets.chevronDownIcon)} /></button>
				<div className={openMenu === 'provider' ? 'composer-pop provider-pop open-pop' : 'composer-pop provider-pop'} onClick={(event) => event.stopPropagation()}>
					<ProviderMenu state={state} post={post} providerApis={providerApis} onClose={closeMenus} onSelectProvider={onProvider} />
				</div>
			</div>
		</div>
	);
}

function ProviderMenu({ state, post, providerApis, onClose, onSettings, onSelectProvider }: {
	state: WebviewState;
	post: Post;
	providerApis: WebviewState['ai']['apiCredentials'];
	onClose: () => void;
	onSettings?: () => void;
	onSelectProvider?: (value: WebviewState['ai']['selection']['provider']) => void;
}): React.ReactElement {
	const selectProvider = (provider: WebviewState['ai']['selection']['provider']) => {
		onSelectProvider?.(provider);
		post('switchProvider', provider);
		onClose();
	};
	const providers = [
		{ id: 'openrouter' as const, name: 'OpenRouter' },
		{ id: 'openai' as const, name: 'OpenAI' },
		{ id: 'claude' as const, name: 'Claude' },
		{ id: 'gemini' as const, name: 'Gemini' },
	];
	return (
		<>
			<div className="menu-title">Provider</div>
			{providers.map((provider) => {
				const apis = providerApis.filter((api) => api.providerId === provider.id);
				return <div className="submenu-wrap provider-api-wrap" key={provider.id}>
					<button className="menu-option" onClick={() => selectProvider(provider.id)}>{provider.name}<span className="option-spacer" />{state.ai.selection.provider === provider.id ? <span className="hint">Active</span> : apis.length ? <span className="hint">{apis.length} saved</span> : null}<span>&gt;</span></button>
					<div className="side-menu provider-api-menu"><div className="menu-title">Saved APIs</div>{apis.length === 0 ? <div className="menu-option muted">No saved APIs</div> : apis.map((api) => <button key={api.id} className="menu-option" onClick={() => { post('selectApiCredential', api.id); onClose(); }}>{api.name}<span className="option-spacer" />{api.id === state.ai.settings.activeApiCredentialId ? <span className="hint">Selected</span> : <span className="hint">{maskApiKey(api.last4)}</span>}</button>)}</div>
				</div>;
			})}
			<div className="menu-separator" />
			<button className="menu-option" onClick={() => { post('refreshModels'); onClose(); }}>Refresh models</button>
			<button className="menu-option" onClick={() => { post('configureProvider', state.ai.selection.provider); onClose(); }}>Add Provider</button>
			{onSettings ? <button className="menu-option" onClick={() => { onSettings(); onClose(); }}>Settings</button> : null}
			<div className="provider-status">{state.ai.status.message}</div>
		</>
	);
}

function providerName(providerId: WebviewState['ai']['selection']['provider']): string {
	return providerId === 'openrouter' ? 'OpenRouter' : 'Provider';
}

function maskApiKey(last4: string): string {
	return last4 ? `${'*'.repeat(12)}${last4}` : '****************';
}

function filterLabel(key: 'freeOnly' | 'codingOnly' | 'reasoningOnly' | 'visionOnly'): string {
	return key === 'freeOnly' ? 'Free' : key === 'codingOnly' ? 'Coding' : key === 'reasoningOnly' ? 'Reasoning' : 'Vision';
}

function ThreatDetails({ issue, post }: { issue: WebviewIssue; post: Post }): React.ReactElement {
	const codePreview = compactText(getThreatCodePreview(issue), 360);
	return (
		<div className="detail-card">
			<div className="detail-head">
				<SeverityBadge severity={issue.severity} />
				<span>{formatSourceTool(issue.tool)}</span>
				<span>{issue.confidence} confidence</span>
				<span>Risk {issue.riskScore}%</span>
			</div>
			<h3>{issue.title}</h3>
			<p>{formatThreatMessage(issue)}</p>
			<div className="detail-meta">
				<span><strong>CWE</strong>{issue.cwe}</span>
				<span><strong>OWASP</strong>{issue.owasp}</span>
				<span><strong>Status</strong>{issue.status}</span>
			</div>
			<pre className="detail-snippet">{codePreview}</pre>
			{issue.tool === 'AI Analysis' && renderAiEvidence(issue.rawEvidence)}
			<p><strong>Attack scenario:</strong> An attacker chains this finding through exposed inputs, weak trust boundaries, or leaked credentials.</p>
			<p><strong>Remediation:</strong> Validate input, reduce privileges, rotate credentials, and add regression tests.</p>
			<div className="control-row">
				<button onClick={() => post('sendChat', { text: `Explain ${issue.title} in ${issue.relativeFile}:${issue.line}` })}>Explain</button>
				<button onClick={() => post('sendChat', { text: `Fix ${issue.title} in ${issue.relativeFile}:${issue.line}` })}>Fix</button>
				<button onClick={() => post('ignoreIssue', issue.id)}>Ignore</button>
				<button onClick={() => post('exportFinding', issue.id)}>Export</button>
				<button onClick={() => post('createRuleFromFinding', issue.id)}>Create Rule</button>
				<button onClick={() => post('openIssue', issue.id)}>Open File</button>
			</div>
		</div>
	);
}

function renderAiEvidence(rawEvidence: unknown): React.ReactElement | null {
	const evidence = rawEvidence && typeof rawEvidence === 'object' ? rawEvidence as { evidence?: string; reasoning?: string; sources?: Array<{ label?: string; file?: string; line?: number; excerpt?: string }> } : undefined;
	if (!evidence) {
		return null;
	}
	const sourceItems = Array.isArray(evidence.sources)
		? evidence.sources.filter((source) => Boolean(source?.excerpt || source?.file || source?.label)).slice(0, 4)
		: [];
	return (
		<div className="ai-evidence">
			<div className="ai-evidence-summary">
				{evidence.reasoning ? <p><strong>AI reasoning:</strong> {compactText(evidence.reasoning, 320)}</p> : null}
				{evidence.evidence ? <p><strong>Evidence:</strong> {compactText(evidence.evidence, 280)}</p> : null}
				{!evidence.evidence && sourceItems.length === 0 ? <p><strong>Evidence:</strong> AI analysis produced structured findings but no snippet was attached.</p> : null}
			</div>
			{sourceItems.length > 0 ? (
				<details className="ai-source-list">
					<summary>Sources ({sourceItems.length})</summary>
					{sourceItems.map((source, index) => (
						<div key={`${source.label ?? 'source'}-${index}`} className="ai-source-item">
							<span>{source.label ?? 'Source'}</span>
							<small>{source.file ? `${source.file}${source.line ? `:${source.line}` : ''}` : 'RAG / scanner evidence'}</small>
							{source.excerpt ? <pre>{compactText(source.excerpt, 260)}</pre> : null}
						</div>
					))}
				</details>
			) : null}
		</div>
	);
}

function GraphPreview({ state }: { state: WebviewState }): React.ReactElement {
	const findings = useMemo(() => selectGraphFindings(state.issues), [state.issues]);
	if (findings.length === 0) {
		return <div className="graph-empty"><strong>No relationships yet</strong><span>Run a scan with actionable findings to build file, tool, and risk links.</span></div>;
	}
	return (
		<div className="graph-panel">
			<div className="graph-flow" role="list" aria-label="Threat relationship graph">
				{findings.map((issue) => (
					<div key={issue.id} className="graph-flow-row" role="listitem">
						<div className="graph-node graph-tool">
							<span className="graph-node-label">{issue.tool}</span>
							<small>Scanner</small>
						</div>
						<div className="graph-connector" aria-hidden="true"><span /></div>
						<div className={`graph-node graph-finding severity-${issue.severity.toLowerCase()}`}>
							<span className="graph-node-label">{compactText(issue.title, 26)}</span>
							<small>{issue.severity} · {issue.confidence}</small>
						</div>
						<div className="graph-connector" aria-hidden="true"><span /></div>
						<div className="graph-node graph-file">
							<span className="graph-node-label">{compactText(issue.relativeFile.split(/[\\/]/).pop() ?? issue.relativeFile, 24)}</span>
							<small>{issue.relativeFile}:{issue.line}</small>
						</div>
					</div>
				))}
			</div>
			<div className="graph-legend graph-legend-horizontal"><span>Scanner</span><span>Finding</span><span>Evidence file</span></div>
		</div>
	);
}

interface ThreatGraphNode {
	id: string;
	label: string;
	kind: 'Finding' | 'File' | 'Tool';
	x: number;
	y: number;
	severity?: Severity;
}

function buildThreatGraph(state: WebviewState): { nodes: ThreatGraphNode[]; links: Array<{ id: string; source: ThreatGraphNode; target: ThreatGraphNode; type: string }> } {
	const findings = selectGraphFindings(state.issues);
	const nodeMap = new Map<string, ThreatGraphNode>();
	const addNode = (node: ThreatGraphNode): ThreatGraphNode => {
		const existing = nodeMap.get(node.id);
		if (existing) {
			return existing;
		}
		nodeMap.set(node.id, node);
		return node;
	};
	const centerX = 260;
	const centerY = 140;
	const toolNames = [...new Set(findings.map((issue) => issue.tool))].slice(0, 6);
	const toolNodes = toolNames.map((tool, index) => addNode({ id: `tool:${tool}`, label: tool, kind: 'Tool', x: 80, y: 42 + index * 36 }));
	const links: Array<{ id: string; source: ThreatGraphNode; target: ThreatGraphNode; type: string }> = [];
	findings.forEach((issue, index) => {
		const angle = (Math.PI * 2 * index) / Math.max(1, findings.length);
		const finding = addNode({ id: issue.id, label: issue.title, kind: 'Finding', severity: issue.severity, x: centerX + Math.cos(angle) * 110, y: centerY + Math.sin(angle) * 82 });
		const file = addNode({ id: `file:${issue.relativeFile}`, label: issue.relativeFile.split(/[\\/]/).pop() ?? issue.relativeFile, kind: 'File', x: 430, y: 44 + (index % 5) * 46 });
		const tool = toolNodes.find((candidate) => candidate.label === issue.tool) ?? addNode({ id: `tool:${issue.tool}`, label: issue.tool, kind: 'Tool', x: 80, y: 70 });
		links.push({ id: `tool-${issue.id}`, source: tool, target: finding, type: 'tool' });
		links.push({ id: `file-${issue.id}`, source: finding, target: file, type: 'evidence' });
	});
	return { nodes: [...nodeMap.values()], links };
}

function summarizeToolInfluence(issues: readonly WebviewIssue[]): Array<{ tool: string; findings: number; highRisk: number }> {
	const preferredOrder = ['Betterleaks', 'OSV-Scanner', 'Semgrep', 'Trivy', 'MobSF', 'AI Analysis', 'Custom Rules', 'AI Security Review'];
	const counts = new Map<string, { findings: number; highRisk: number }>();
	for (const issue of issues) {
		const current = counts.get(issue.tool) ?? { findings: 0, highRisk: 0 };
		current.findings += 1;
		if (issue.severity === 'Critical' || issue.severity === 'High') {
			current.highRisk += 1;
		}
		counts.set(issue.tool, current);
	}
	return [...new Set([...preferredOrder, ...counts.keys()])]
		.map((tool) => ({ tool, ...(counts.get(tool) ?? { findings: 0, highRisk: 0 }) }));
}

function selectGraphFindings(issues: readonly WebviewIssue[]): WebviewIssue[] {
	const selected: WebviewIssue[] = [];
	const seenTools = new Set<string>();
	for (const issue of issues) {
		if (!seenTools.has(issue.tool)) {
			selected.push(issue);
			seenTools.add(issue.tool);
		}
	}
	for (const issue of issues) {
		if (selected.length >= 10) break;
		if (!selected.some((candidate) => candidate.id === issue.id)) {
			selected.push(issue);
		}
	}
	return selected;
}

function compactText(value: string, max: number): string {
	const text = String(value ?? '').replace(/\s+/g, ' ').trim();
	if (!text) {
		return '';
	}
	return text.length > max ? `${text.slice(0, Math.max(0, max - 1)).trimEnd()}…` : text;
}

function getThreatCodePreview(issue: WebviewIssue): string {
	const evidenceSnippet = getAiEvidenceSnippet(issue.rawEvidence);
	if (issue.tool === 'AI Analysis' && evidenceSnippet) {
		return evidenceSnippet;
	}
	if (issue.lineText && !looksLikeStructuredBlob(issue.lineText)) {
		return issue.lineText;
	}
	if (issue.tool === 'AI Analysis' && issue.message) {
		const cleanedMessage = stripRepeatedThreatPrefix(issue.message, issue.title);
		if (cleanedMessage) {
			return cleanedMessage;
		}
	}
	return `${issue.relativeFile}:${issue.line}`;
}

function getAiEvidenceSnippet(rawEvidence: unknown): string {
	const evidence = rawEvidence && typeof rawEvidence === 'object' ? rawEvidence as { evidence?: string; sources?: Array<{ excerpt?: string }> } : undefined;
	const sourceExcerpt = evidence?.sources?.find((source) => typeof source?.excerpt === 'string' && source.excerpt.trim())?.excerpt?.trim();
	if (sourceExcerpt) {
		return sourceExcerpt;
	}
	const evidenceText = typeof evidence?.evidence === 'string' ? evidence.evidence.trim() : '';
	if (evidenceText) {
		return evidenceText;
	}
	return '';
}

function formatThreatMessage(issue: WebviewIssue): string {
	const message = stripRepeatedThreatPrefix(issue.message, issue.title).trim();
	if (!message) {
		return 'Finding detected in the workspace.';
	}
	if (/secret-like material was detected/i.test(message) || /api key detected/i.test(message)) {
		return message;
	}
	return compactText(message, 220);
}

function formatSourceTool(tool: string): string {
	if (tool === 'AI Analysis' || tool === 'AI Analyzer') {
		return 'AI Analyzer';
	}
	return tool;
}

function stripRepeatedThreatPrefix(value: string, title: string): string {
	const text = String(value ?? '').replace(/\s+/g, ' ').trim();
	if (!text) {
		return '';
	}
	const lowered = text.toLowerCase();
	if (title && lowered.startsWith(title.toLowerCase())) {
		return text.slice(title.length).trim().replace(/^[:\-–—\s]+/, '');
	}
	return text
		.replace(/^secret-like material was detected in (the )?workspace\.?\s*/i, '')
		.replace(/^api key detected[:\s-]*/i, '')
		.replace(/^hardcoded (api )?key[:\s-]*/i, '');
}

function looksLikeStructuredBlob(value: string): boolean {
	const text = String(value ?? '').trim();
	return (text.startsWith('{') && text.includes('"runs"')) || (text.startsWith('{') && text.includes('"toolExecutionNotifications"')) || text.includes('Syntax error at line');
}
function Metric({ title, value }: { title: string; value: string }): React.ReactElement {
	return <div className="metric"><strong>{value}</strong><span>{title}</span></div>;
}

function SeverityBadge({ severity }: { severity: Severity }): React.ReactElement {
	return <span className={`sev sev-${severity.toLowerCase()}`}>{severity}</span>;
}

function actionDetail(title: string): string {
	if (title.includes('fuzz')) {
		return 'Generate endpoint payloads from the workspace graph.';
	}
	if (title.includes('secrets')) {
		return 'Find keys, tokens, certs, and leaked credentials.';
	}
	if (title.includes('APK')) {
		return 'Build and inspect Android artifacts with MobSF.';
	}
	return 'Run a contextual AI security workflow.';
}

