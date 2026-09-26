import React, { memo, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ChatSession, Severity, WebviewIssue, WebviewState } from './types.js';
import { Markdown } from './markdown.js';
import { configuredProviderOptions, providerName } from './providerOptions';
import { AqironBadge, AqironButton, AqironIconButton, AqironMetric, AqironSectionHeader, AqironSeverity } from './design/primitives.js';

type Post = (command: string, payload?: unknown) => void;

export const AgentTab = memo(function AgentTab({ state, post }: { state: WebviewState; post: Post }): React.ReactElement {
	return (
		<div className="tab-page agent-tab">
			<section className="agent-hero aq-surface-panel">
				<div className="agent-hero-copy">
					<AqironBadge tone="ai"><span className="codicon codicon-sparkle" aria-hidden="true" />Aqiron AI</AqironBadge>
					<AqironSectionHeader title="Security assistant" description="Context-aware analysis for the active workspace" />
				</div>
				<div className="agent-hero-state"><span className="agent-state-dot" aria-hidden="true" />{state.stats.scanStatus === 'Scanning' ? 'Working from live scan data' : 'Ready for workspace context'}</div>
			</section>
			<section className="agent-context section">
				<AqironSectionHeader title="Project context" description="Signals available to Aqiron for the next action" />
				<ContextBar state={state} />
			</section>
			<section className="section agent-actions-section">
				<AqironSectionHeader title="Security actions" description="Start with a focused workflow" />
				<div className="action-grid">
					{['Explain this code', 'Hunt secrets', 'Analyze network security', 'Review auth flow', 'Scan dependencies', 'Reverse engineer APK', 'Generate exploit simulation'].map((title) => (
						<motion.button key={title} className="action-card agent-action-card" whileHover={{ y: -2 }} whileTap={{ scale: 0.99 }} transition={{ duration: 0.16 }} onClick={() => post('sendChat', { text: title })}>
							<span className="mini-icon" aria-hidden="true"><span className={`codicon ${actionIcon(title)}`} /></span>
							<span className="agent-action-copy"><strong>{title}</strong><small>{actionDetail(title)}</small></span>
							<span className="codicon codicon-arrow-right agent-action-arrow" aria-hidden="true" />
						</motion.button>
					))}
				</div>
			</section>
			<section className="section agent-sessions-section">
				<AqironSectionHeader title="Conversation history" description="Pick up where you left off" />
				<ChatSessionList state={state} post={post} />
			</section>
			<section className="section agent-recommendations-section">
				<AqironSectionHeader title="Recommended actions" description="Generated from the workspace graph and memory" action={<AqironButton variant="ghost" className="rag-refresh" title="Refresh AI regenerates Smart Suggestions from the current workspace index using the configured AI provider." aria-label="Refresh AI suggestions" onClick={() => post('ragRefreshSuggestions')} disabled={state.rag.building}>Refresh AI</AqironButton>} />
				<div className="suggestion-list">
					{state.suggestions.length ? state.suggestions.map((suggestion) => (
						<motion.div key={suggestion.command} className="suggestion-card agent-suggestion-card" initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.18 }}>
							<div className="suggestion-copy"><strong>{suggestion.title}</strong><Markdown content={suggestion.detail} /></div>
							<div className="suggestion-actions">
								<SeverityBadge severity={suggestion.severity} />
								{suggestion.recommended && <AqironBadge>Recommended</AqironBadge>}
								<AqironButton variant="secondary" type="button" onClick={() => post('sendChat', { text: suggestion.command, useTaskDefaults: true })}>Run</AqironButton>
								<AqironButton variant="ghost" type="button" onClick={() => post('sendChat', { text: `Explain ${suggestion.title}`, useTaskDefaults: true })}>Explain</AqironButton>
							</div>
						</motion.div>
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
		<div ref={panelRef} className={sidebarOpen ? 'agent-panel agent-conversation-panel codex-chat sidebar-open' : 'agent-panel agent-conversation-panel codex-chat sidebar-closed'} style={{ '--chat-sidebar-width': `${sidebarWidth}px` } as React.CSSProperties}>
			{sidebarOpen && <><aside className="chat-sidebar"><div className="chat-sidebar-head"><strong>Chats</strong></div><ChatSessionList state={state} post={post} compact /></aside><div className="chat-sidebar-resize" role="separator" aria-label="Resize chat sidebar" onPointerDown={(event) => { resizing.current = true; event.currentTarget.setPointerCapture?.(event.pointerId); }} /></>}
			<div className="chat-workspace">
				<div className="chat-titlebar">
					<button className="sidebar-toggle" aria-label={sidebarOpen ? 'Hide chat sidebar' : 'Show chat sidebar'} title={sidebarOpen ? 'Hide chat sidebar' : 'Show chat sidebar'} onClick={() => setSidebarOpen((value) => !value)}><span className={`codicon ${sidebarOpen ? 'codicon-layout-sidebar-left-off' : 'codicon-layout-sidebar-left'}`} aria-hidden="true" /></button>
					<div><h2>{activeSession?.title ?? 'New chat'}</h2><span>{activeSession ? `${activeSession.model} | ${activeSession.intelligence}` : 'Aqiron Agent'}</span></div>
				</div>
				<div className="conversation-scroll agent-conversation-scroll" ref={scrollRef}>
					{!activeSession || activeSession.messages.length === 0 ? <div className="agent-empty aq-empty-state"><span className="codicon codicon-comment-discussion" aria-hidden="true" /><strong>Start a security conversation</strong><span>Ask about this workspace, a finding, or a release risk.</span></div> : activeSession.messages.map((message) => (
						<div key={message.id} className={`chat-turn agent-chat-turn ${message.role}${message.streaming ? ' streaming' : ''}`}>
							<span className="agent-message-label">{message.role === 'user' ? 'You' : 'Aqiron'}</span>
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
								<AqironIconButton className="session-option-trigger" aria-label="Session options" onClick={() => setOpenSessionMenu((current) => current === session.id ? undefined : session.id)}><span className="svg-icon" style={iconStyle(state.assets.sessionOptionIcon)} /></AqironIconButton>
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
	const [target, setTarget] = useState<'workspace' | 'current-file'>('workspace');
	const [mode, setMode] = useState<'quick' | 'deep' | 'analysis'>('deep');
	const [advancedOpen, setAdvancedOpen] = useState(false);
	const [executionOpen, setExecutionOpen] = useState(false);
	const fallbackStages = ['Preparing', 'Indexing', 'Dependency Analysis', 'SAST', 'Secret Scanning', 'AI Vulnerability Analysis', 'AI Correlation', 'Report Generation'];
	const pipelineStages = state.pipeline?.stages.length ? state.pipeline.stages : [];
	const toolStates = new Map((state.pipeline?.tools ?? []).map((tool) => [normalizeToolName(tool.label), tool]));
	const terminalLines = state.pipeline?.logs.length ? state.pipeline.logs.slice(-80).join('\n') : 'No scan logs yet. Start a scan to stream real engine output.';
	const visibleStages = getVisiblePipelineStages(pipelineStages, state.stats.scanStatus);
	const visibleTools = getVisiblePipelineTools(state.pipeline?.tools ?? [], state.stats.scanStatus);
	const activeStage = pipelineStages.find((stage) => stage.status === 'running') ?? visibleStages.at(-1);
	const activeTool = state.pipeline?.tools.find((tool) => tool.status === 'running');
	const currentFileAvailable = Boolean(state.workspace.currentFile && state.workspace.currentFile !== 'No file');
	const startScan = () => {
		if (state.stats.scanStatus === 'Scanning') {
			return;
		}
		if (target === 'current-file') {
			post('scanCurrentFile');
			return;
		}
		if (mode === 'analysis') {
			post('aiVulnerabilityAnalysis');
			return;
		}
		post('scanWorkspace', { mode });
	};
	const runAgain = () => {
		setExecutionOpen(false);
		startScan();
	};
	return (
		<div className="tab-page scan-tab">
			<section className="scan-hero aq-surface-panel">
				<AqironSectionHeader title="Security scan" description="Choose a target and depth, then review the evidence as it arrives." />
				<span className={`aq-status aq-status--${scanStatusTone(state.stats.scanStatus)}`}>{formatScanStatus(state.stats.scanStatus)}</span>
			</section>
			<section className="scan-context section">
				<AqironSectionHeader title="Project context" description="Current workspace signals" />
				<div className="scan-context-list"><span>{state.workspace.name}</span><span>{state.workspace.types[0] ?? 'Workspace'}</span><span>{state.branches[0] ?? 'No branch'}</span><span>{state.stats.scanStatus}</span></div>
			</section>
			<section className="scan-config section">
				<AqironSectionHeader title="What do you want to scan?" description="Start with the smallest useful scope." />
				<div className="scan-choice-grid" role="group" aria-label="Scan target">
					<button type="button" className={target === 'workspace' ? 'scan-choice active' : 'scan-choice'} aria-pressed={target === 'workspace'} onClick={() => setTarget('workspace')}>
						<span className="scan-choice-icon codicon codicon-root-folder" aria-hidden="true" /><span><strong>Current workspace</strong><small>Analyze the supported project and its dependencies.</small></span>
					</button>
					<button type="button" className={target === 'current-file' ? 'scan-choice active' : 'scan-choice'} aria-pressed={target === 'current-file'} disabled={!currentFileAvailable} onClick={() => setTarget('current-file')}>
						<span className="scan-choice-icon codicon codicon-file-code" aria-hidden="true" /><span><strong>Current file</strong><small>{currentFileAvailable ? state.workspace.currentFile : 'Open a supported file to enable this target.'}</small></span>
					</button>
				</div>
				<AqironSectionHeader title="Scan mode" description="Coverage follows the existing scanner pipeline." />
				<div className="scan-mode-grid" role="group" aria-label="Scan mode">
					{([['quick', 'Quick', 'Fast workspace coverage with the native and configured security engines.'], ['deep', 'Deep', 'Adds deeper dependency and mobile artifact analysis when configured.'], ['analysis', 'AI analysis', 'Runs the existing dedicated AI vulnerability analysis workflow.']] as const).map(([value, label, detail]) => (
						<button key={value} type="button" className={mode === value ? 'scan-mode active' : 'scan-mode'} aria-pressed={mode === value} onClick={() => setMode(value)}><strong>{label}</strong><small>{detail}</small></button>
					))}
				</div>
				<div className="scan-config-actions"><AqironButton variant="primary" className="scan-start" disabled={state.stats.scanStatus === 'Scanning' || (target === 'current-file' && !currentFileAvailable)} onClick={startScan}><span className="codicon codicon-play" aria-hidden="true" />{state.stats.scanStatus === 'Scanning' ? 'Scan running' : 'Start scan'}</AqironButton><span className="scan-config-hint">{target === 'current-file' ? 'Uses the existing current-file scanner.' : mode === 'analysis' ? 'Uses the existing AI analysis command.' : `Runs the existing ${mode} workspace pipeline.`}</span></div>
				<details className="scan-advanced" open={advancedOpen} onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}>
					<summary><span><strong>Advanced options and actions</strong><small>AI review, dynamic analysis, terminal controls</small></span><span className="codicon codicon-chevron-down" aria-hidden="true" /></summary>
					<div className="scan-advanced-content">
						<div className="control-row"><AqironButton variant="secondary" title={scanActionDetail('AI Vulnerability Analysis')} onClick={() => post('aiVulnerabilityAnalysis')}>AI Vulnerability Analysis</AqironButton><AqironButton variant="secondary" title={scanActionDetail('AI Audit')} onClick={() => post('sendChat', { text: 'Analyze this workspace security posture and prioritize risk using the current scan context.' })}>AI Audit</AqironButton><AqironButton variant="secondary" title={scanActionDetail('Dynamic Analysis')} onClick={() => post('sendChat', { text: 'Assess runtime security behavior and execution risks from the current workspace context.' })}>Dynamic Analysis</AqironButton></div>
						<div className="scan-action-help">{['Quick Scan', 'Deep Scan', 'AI Vulnerability Analysis', 'Dynamic Analysis', 'AI Audit'].map((label) => <span key={label}><strong>{label}</strong>{scanActionDetail(label)}</span>)}</div>
					</div>
				</details>
			</section>
			<section className={`scan-status-section section scan-status-${state.stats.scanStatus.toLowerCase()}`}>
				{state.stats.scanStatus === 'Idle' ? <ScanIdleState onStart={startScan} disabled={target === 'current-file' && !currentFileAvailable} /> : null}
				{state.stats.scanStatus === 'Scanning' ? <ScanRunningState activeStage={activeStage} activeTool={activeTool} stages={pipelineStages} tools={state.pipeline?.tools ?? []} onCancel={() => post('cancelScan')} /> : null}
				{state.stats.scanStatus === 'Complete' ? <ScanCompleteState state={state} onRunAgain={runAgain} post={post} /> : null}
				{state.stats.scanStatus === 'Failed' ? <ScanFailedState stages={pipelineStages} logs={state.pipeline?.logs ?? []} onRetry={runAgain} /> : null}
			</section>
			{state.stats.scanStatus !== 'Idle' && <details className="scan-execution" open={executionOpen} onToggle={(event) => setExecutionOpen(event.currentTarget.open)}>
				<summary><span><strong>Execution details</strong><small>Pipeline, scanner output, and terminal stream</small></span><span className="codicon codicon-chevron-down" aria-hidden="true" /></summary>
				<div className="scan-execution-content">
					<section className="scan-detail-block"><AqironSectionHeader title="Pipeline" description={getPipelineHeadline(state.stats.scanStatus, visibleStages.length)} />{visibleStages.length ? <div className="scan-pipeline-list">{visibleStages.map((stage) => <ScanPipelineRow key={stage.name} stage={stage} />)}</div> : <PipelineEmptyState scanStatus={state.stats.scanStatus} fallbackStages={fallbackStages} durationMs={state.stats.lastScanDurationMs} />}</section>
					<section className="scan-detail-block"><AqironSectionHeader title="Tool execution" description="Scanner status and concise telemetry" />{visibleTools.length ? <div className="scan-tool-list">{visibleTools.map((tool) => <ScanToolRow key={tool.id} tool={tool} detail={getToolDetail(tool.label, toolStates)} />)}</div> : <div className="empty">No tool telemetry is available for this scan state.</div>}</section>
					<section className="scan-detail-block"><AqironSectionHeader title="Terminal stream" description="Colorized realtime logs" action={<AqironButton variant="ghost" onClick={() => post('clearTerminal')}>Clear</AqironButton>} /><pre className="terminal">{terminalLines}</pre></section>
				</div>
			</details>}
		</div>
	);
});

function ScanIdleState({ onStart, disabled }: { onStart: () => void; disabled: boolean }): React.ReactElement {
	return <div className="scan-empty-state"><span className="scan-empty-icon codicon codicon-shield" aria-hidden="true" /><div><strong>Run your first security scan</strong><span>Select a target and scan mode above to analyze the current project.</span></div><AqironButton variant="secondary" disabled={disabled} onClick={onStart}>Start scan</AqironButton></div>;
}

function ScanRunningState({ activeStage, activeTool, stages, tools, onCancel }: { activeStage?: WebviewState['pipeline']['stages'][number]; activeTool?: WebviewState['pipeline']['tools'][number]; stages: WebviewState['pipeline']['stages']; tools: WebviewState['pipeline']['tools']; onCancel: () => void }): React.ReactElement {
	const completedStages = stages.filter((stage) => stage.status === 'completed').length;
	const completedTools = tools.filter((tool) => tool.status === 'completed').length;
	const progress = activeStage && activeStage.progress > 0 ? activeStage.progress : undefined;
	return <div className="scan-run-state"><div className="scan-run-heading"><div><span className="aq-status aq-status--info">Scanning</span><h2>{activeStage?.name ?? 'Preparing scan'}</h2><p>{activeTool ? `${activeTool.label} is running.` : completedStages || completedTools ? `${completedStages} stage${completedStages === 1 ? '' : 's'} completed.` : 'Waiting for engine telemetry.'}</p></div><AqironButton variant="danger" onClick={onCancel}><span className="codicon codicon-stop" aria-hidden="true" />Cancel scan</AqironButton></div>{progress !== undefined ? <div className="scan-progress"><div><span>Current stage progress</span><strong>{progress}%</strong></div><div className="scan-progress-track"><span style={{ width: `${Math.max(0, Math.min(100, progress))}%` }} /></div></div> : <div className="scan-indeterminate"><span />Analyzing with the active security engines</div>}<div className="scan-run-meta">{activeTool ? <span><strong>Current scanner</strong>{activeTool.label}</span> : null}{tools.length ? <span><strong>Tools completed</strong>{completedTools} / {tools.length}</span> : null}</div></div>;
}

function ScanCompleteState({ state, onRunAgain, post }: { state: WebviewState; onRunAgain: () => void; post: Post }): React.ReactElement {
	return <div className="scan-complete-state"><div className="scan-complete-heading"><div><span className="aq-status aq-status--success">Complete</span><h2>Scan complete</h2><p>{state.stats.lastScanDurationMs ? `Completed in ${formatDuration(state.stats.lastScanDurationMs)}.` : 'The existing scan pipeline completed.'}</p></div><AqironButton variant="primary" onClick={onRunAgain}>Run again</AqironButton></div><div className="scan-findings-summary"><span><strong>{state.counts.total}</strong>Total findings</span><span><AqironSeverity severity="Critical" /><strong>{state.counts.critical}</strong></span><span><AqironSeverity severity="High" /><strong>{state.counts.high}</strong></span><span><AqironSeverity severity="Medium" /><strong>{state.counts.medium}</strong></span><span><AqironSeverity severity="Low" /><strong>{state.counts.low}</strong></span><span><strong>{state.stats.filesScanned}</strong>Files scanned</span></div><div className="scan-result-actions"><AqironButton variant="secondary" onClick={() => post('focus', 'threats')}>View findings</AqironButton><AqironButton variant="secondary" onClick={() => post('focus', 'reports')}>Open reports</AqironButton>{state.pipeline.lastReport?.pdfPath ? <AqironButton variant="ghost" onClick={() => post('exportReport', 'pdf')}>Export PDF</AqironButton> : null}</div></div>;
}

function ScanFailedState({ stages, logs, onRetry }: { stages: WebviewState['pipeline']['stages']; logs: string[]; onRetry: () => void }): React.ReactElement {
	const cancelled = stages.some((stage) => stage.status === 'cancelled');
	return <div className="scan-failed-state"><div><span className="aq-status aq-status--danger">Failed</span><h2>{cancelled ? 'Scan stopped' : 'Scan did not complete'}</h2><p>{cancelled ? 'Cancellation was requested before the pipeline finished.' : 'The scan stopped before all stages completed.'}</p></div><AqironButton variant="secondary" onClick={onRetry}>Try again</AqironButton>{logs.length ? <details className="scan-error-detail"><summary>Show technical detail</summary><pre>{logs.slice(-8).join('\n')}</pre></details> : null}</div>;
}

function ScanPipelineRow({ stage }: { stage: WebviewState['pipeline']['stages'][number] }): React.ReactElement {
	return <div className={`scan-pipeline-row ${stage.status}`}><span className="stage-status" aria-hidden="true">{getStageMarker(stage.status)}</span><strong>{stage.name}</strong><span>{formatStageStatus(stage)}</span>{stage.progress > 0 ? <div className="scan-row-progress" aria-label={`${stage.name} progress`}><span style={{ width: `${Math.max(0, Math.min(100, stage.progress))}%` }} /></div> : null}<small>{formatStageTelemetry(stage)}</small></div>;
}

function ScanToolRow({ tool, detail }: { tool: WebviewState['pipeline']['tools'][number]; detail: string }): React.ReactElement {
	return <div className={`scan-tool-row ${tool.status}`}><span className="stage-status" aria-hidden="true">{getStageMarker(tool.status)}</span><strong>{tool.label}</strong><span>{formatToolStatus(tool.status)}</span><small>{detail}</small></div>;
}

function scanStatusTone(status: WebviewState['stats']['scanStatus']): 'info' | 'success' | 'danger' | 'warning' {
	return status === 'Scanning' ? 'info' : status === 'Complete' ? 'success' : status === 'Failed' ? 'danger' : 'warning';
}

function formatScanStatus(status: WebviewState['stats']['scanStatus']): string {
	return status === 'Idle' ? 'Ready to scan' : status;
}

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
	const initialSelected = visibleIssues.find((issue) => issue.id === state.selectedThreatId) ?? visibleIssues[0];
	const [selectedKey, setSelectedKey] = useState(initialSelected ? findingSelectionKey(initialSelected, visibleIssues.indexOf(initialSelected)) : undefined);
	const [query, setQuery] = useState('');
	const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
	const [toolFilter, setToolFilter] = useState('all');
	const [statusFilter, setStatusFilter] = useState('all');
	const [filtersOpen, setFiltersOpen] = useState(false);
	useEffect(() => {
		const nextSelected = visibleIssues.find((issue) => issue.id === state.selectedThreatId) ?? visibleIssues[0];
		setSelectedKey(nextSelected ? findingSelectionKey(nextSelected, visibleIssues.indexOf(nextSelected)) : undefined);
	}, [state.activeThreatSnapshotId, state.selectedThreatId, visibleIssues]);
	const toolOptions = useMemo(() => [...new Set(visibleIssues.map((issue) => formatSourceTool(issue.tool)).filter(Boolean))].sort(), [visibleIssues]);
	const statusOptions = useMemo(() => [...new Set(visibleIssues.map((issue) => issue.status).filter(Boolean))].sort(), [visibleIssues]);
	const filteredIssues = useMemo(() => {
		const normalizedQuery = query.trim().toLowerCase();
		return visibleIssues.filter((issue) => {
			const matchesQuery = !normalizedQuery || [issue.title, issue.message, issue.relativeFile, issue.ruleId, issue.cwe, issue.owasp, issue.tool, issue.status, issue.lineText].some((value) => value.toLowerCase().includes(normalizedQuery));
			const matchesSeverity = severityFilter === 'all' || issue.severity === severityFilter;
			const matchesTool = toolFilter === 'all' || formatSourceTool(issue.tool) === toolFilter;
			const matchesStatus = statusFilter === 'all' || issue.status === statusFilter;
			return matchesQuery && matchesSeverity && matchesTool && matchesStatus;
		});
	}, [query, severityFilter, statusFilter, toolFilter, visibleIssues]);
	const selected = filteredIssues.find((issue) => findingSelectionKey(issue, visibleIssues.indexOf(issue)) === selectedKey) ?? filteredIssues[0];
	const filtersActive = Boolean(query.trim()) || severityFilter !== 'all' || toolFilter !== 'all' || statusFilter !== 'all';
	const clearFilters = () => {
		setQuery('');
		setSeverityFilter('all');
		setToolFilter('all');
		setStatusFilter('all');
	};
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
			<div className="tab-page threat-layout findings-layout">
				<section className="findings-hero">
					<AqironSectionHeader title="Findings" description="Triage security issues by severity, source, status, and code location." action={<AqironBadge tone={state.stats.scanStatus === 'Scanning' ? 'ai' : 'brand'}><span className="codicon codicon-shield" aria-hidden="true" />{state.stats.scanStatus === 'Scanning' ? 'Scan in progress' : `${filteredIssues.length} shown`}</AqironBadge>} />
					<div className="findings-context"><span><span className="codicon codicon-folder" aria-hidden="true" />{state.workspace.name}</span><span><span className="codicon codicon-file-code" aria-hidden="true" />{state.stats.filesScanned} files scanned</span><span><span className="codicon codicon-symbol-method" aria-hidden="true" />{toolOptions.length || 'No'} source tools</span></div>
				</section>
				<section className="findings-summary" aria-label="Finding summary">
					<AqironMetric title="All findings" value={`${state.counts.total}`} />
					<AqironMetric title="Critical" value={`${state.counts.critical}`} />
					<AqironMetric title="High" value={`${state.counts.high}`} />
					<AqironMetric title="Medium" value={`${state.counts.medium}`} />
					<AqironMetric title="Low" value={`${state.counts.low}`} />
				</section>
				<section className="findings-toolbar aq-surface-panel" aria-label="Finding filters">
					<label className="findings-search"><span className="codicon codicon-search" aria-hidden="true" /><span className="sr-only">Search findings</span><input className="aq-input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings, files, rules, CWE, or OWASP..." /></label>
					<div className="findings-toolbar-actions"><AqironButton variant={filtersOpen ? 'secondary' : 'ghost'} type="button" onClick={() => setFiltersOpen((value) => !value)} aria-expanded={filtersOpen}><span className="codicon codicon-filter" aria-hidden="true" />Filters{filtersActive ? ` · ${[severityFilter !== 'all', toolFilter !== 'all', statusFilter !== 'all'].filter(Boolean).length}` : ''}</AqironButton>{filtersActive && <AqironButton variant="ghost" type="button" onClick={clearFilters}>Clear</AqironButton>}</div>
					{filtersOpen && <div className="findings-filter-grid">
						<label className="aq-field"><span className="aq-field__label">Severity</span><select className="aq-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as Severity | 'all')}><option value="all">All severities</option>{(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((severity) => <option key={severity} value={severity}>{severity}</option>)}</select></label>
						<label className="aq-field"><span className="aq-field__label">Source tool</span><select className="aq-select" value={toolFilter} onChange={(event) => setToolFilter(event.target.value)}><option value="all">All source tools</option>{toolOptions.map((tool) => <option key={tool} value={tool}>{tool}</option>)}</select></label>
						<label className="aq-field"><span className="aq-field__label">Status</span><select className="aq-select" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="all">All statuses</option>{statusOptions.map((status) => <option key={status} value={status}>{status}</option>)}</select></label>
					</div>}
				</section>
				<section className="findings-list-section" aria-label="Security findings">
					<AqironSectionHeader title="Security findings" description={filtersActive ? `${filteredIssues.length} of ${visibleIssues.length} findings match the current view.` : 'Select a finding to inspect evidence and available actions.'} />
					<div className="findings-list" role="list">
						{filteredIssues.length ? filteredIssues.map((issue) => { const rowKey = findingSelectionKey(issue, visibleIssues.indexOf(issue)); return <button key={rowKey} type="button" className={issue === selected ? 'finding-row active' : 'finding-row'} onClick={() => setSelectedKey(rowKey)} role="listitem" aria-pressed={issue === selected}>
							<span className={`finding-row-severity severity-${issue.severity.toLowerCase()}`}><AqironSeverity severity={issue.severity} /></span>
							<span className="finding-row-main"><strong>{issue.title}</strong><small>{formatThreatMessage(issue)}</small><span className="finding-row-location"><span className="codicon codicon-file-code" aria-hidden="true" />{issue.relativeFile}:{issue.line}</span></span>
							<span className="finding-row-context"><AqironBadge>{formatSourceTool(issue.tool)}</AqironBadge><span>{issue.cwe}</span><span>{issue.owasp}</span></span>
							<span className="finding-row-status"><span>{issue.status}</span><small>{issue.confidence} confidence</small></span>
							<span className="codicon codicon-chevron-right finding-row-chevron" aria-hidden="true" />
						</button>; }) : <div className="findings-empty aq-empty-state"><span className="codicon codicon-search-stop" aria-hidden="true" /><strong>{visibleIssues.length ? 'No findings match these filters' : 'No findings indexed yet'}</strong><span>{visibleIssues.length ? 'Clear or adjust the filters to widen the triage view.' : 'Run a scan to build the vulnerability inventory.'}</span>{filtersActive && <AqironButton variant="secondary" type="button" onClick={clearFilters}>Clear filters</AqironButton>}</div>}
					</div>
				</section>
				<section className="findings-detail-section" aria-label="Selected finding details">
					<AqironSectionHeader title="Finding detail" description="Evidence, context, and next actions" />
					{selected ? <ThreatDetails issue={selected} post={post} /> : <div className="findings-empty aq-empty-state"><span className="codicon codicon-info" aria-hidden="true" /><strong>Select a finding to inspect it</strong><span>Finding details will appear here.</span></div>}
				</section>
				<section className="findings-graph-section" aria-label="Finding relationships">
					<AqironSectionHeader title="Related context" description="Files, source tools, and risk relationships" />
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

function findingSelectionKey(issue: WebviewIssue, index: number): string {
	return `${issue.id}:${issue.relativeFile}:${issue.line}:${issue.column}:${index}`;
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
				<p className="report-export-note">JSON, PDF, and SARIF are already generated in <code>{reportFolderLabel(state.pipeline.lastReport?.directory)}</code>. Use those existing files to avoid creating duplicate reports.</p>
				<div className="control-row"><button disabled={!state.pipeline.lastReport?.pdfPath} title={state.pipeline.lastReport?.pdfPath ? 'Export the generated PDF' : 'Run a scan to generate a report bundle'} onClick={() => post('exportReport', 'pdf')}>Export PDF</button><button disabled={!state.pipeline.lastReport?.jsonPath} onClick={() => post('exportReport', 'json')}>Export JSON</button><button disabled={!state.pipeline.lastReport?.sarifPath} onClick={() => post('exportReport', 'sarif')}>Export SARIF</button><button onClick={() => post('exportReport', 'share')}>Share Report</button><button onClick={() => post('exportReport', 'jira')}>Create Jira Ticket</button></div>
			</section>
		</div>
	);
});

function reportFolderLabel(directory?: string): string {
	if (!directory) {
		return '.aqiron-security/reports/<scan-folder>';
	}
	const normalized = directory.replace(/\\/g, '/');
	const marker = '/.aqiron-security/reports/';
	const markerIndex = normalized.lastIndexOf(marker);
	return markerIndex >= 0 ? `.aqiron-security/reports/${normalized.slice(markerIndex + marker.length)}` : '.aqiron-security/reports/<scan-folder>';
}

function ContextBar({ state }: { state: WebviewState }): React.ReactElement {
	return <div className="context-bar agent-context-bar">{[state.workspace.currentFile, state.workspace.types[0] ?? 'Workspace', state.workspace.backend, state.branches[0] ?? 'No branch', state.stats.scanStatus, `${state.workspace.apis.length} APIs`].map((item) => <span key={item}>{item}</span>)}</div>;
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
					<AqironIconButton className="round" aria-label="Add files and more" onClick={() => post('attachContext')}><span className="svg-icon" style={iconStyle(state.assets.addIcon)} /></AqironIconButton>
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
				<div className="send-wrap"><AqironButton variant={isStreaming ? 'danger' : 'primary'} className="send" aria-label={isStreaming ? 'Cancel generation' : 'Send'} disabled={!isStreaming && !text.trim()} onClick={isStreaming ? () => post('cancelGeneration', sessionId) : send}>{isStreaming ? 'Stop' : <span className="svg-icon" style={iconStyle(state.assets.upArrowIcon)} />}</AqironButton><span className="tip">{isStreaming ? 'Cancel generation' : 'Send'}</span></div>
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
	const providers = configuredProviderOptions(providerApis);
	return (
		<>
			<div className="menu-title">Provider</div>
			{providers.length === 0 ? <div className="menu-option muted">No providers configured</div> : providers.map((provider) => {
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

function maskApiKey(last4: string): string {
	return last4 ? `${'*'.repeat(12)}${last4}` : '****************';
}

function filterLabel(key: 'freeOnly' | 'codingOnly' | 'reasoningOnly' | 'visionOnly'): string {
	return key === 'freeOnly' ? 'Free' : key === 'codingOnly' ? 'Coding' : key === 'reasoningOnly' ? 'Reasoning' : 'Vision';
}

function ThreatDetails({ issue, post }: { issue: WebviewIssue; post: Post }): React.ReactElement {
	const codePreview = compactText(getThreatCodePreview(issue), 360);
	return (
		<div className="finding-detail aq-surface-panel">
			<div className="finding-detail-top"><div className="finding-detail-badges"><AqironSeverity severity={issue.severity} /><AqironBadge>{formatSourceTool(issue.tool)}</AqironBadge><AqironBadge>{issue.status}</AqironBadge></div><AqironBadge tone="neutral"><span className="codicon codicon-location" aria-hidden="true" />{issue.relativeFile}:{issue.line}</AqironBadge></div>
			<div className="finding-detail-title"><h3>{issue.title}</h3><span>{issue.confidence} confidence</span></div>
			<p className="finding-detail-description">{formatThreatMessage(issue)}</p>
			<div className="finding-detail-meta"><span><strong>CWE</strong>{issue.cwe}</span><span><strong>OWASP</strong>{issue.owasp}</span><span><strong>Rule</strong>{issue.ruleId}</span><span><strong>Column</strong>{issue.column}</span></div>
			<div className="finding-evidence"><div className="finding-detail-block-head"><div><strong>Evidence</strong><span>Captured source context</span></div><AqironBadge tone="brand">{issue.lineText ? 'Source line' : 'Location only'}</AqironBadge></div><pre className="detail-snippet">{codePreview}</pre></div>
			{issue.tool === 'AI Analysis' && renderAiEvidence(issue.rawEvidence)}
			<div className="finding-detail-actions"><AqironButton variant="primary" type="button" onClick={() => post('openIssue', issue.id)}><span className="codicon codicon-go-to-file" aria-hidden="true" />Open file</AqironButton><AqironButton variant="secondary" type="button" onClick={() => post('sendChat', { text: `Explain ${issue.title} in ${issue.relativeFile}:${issue.line}` })}>Explain</AqironButton><AqironButton variant="secondary" type="button" onClick={() => post('sendChat', { text: `Fix ${issue.title} in ${issue.relativeFile}:${issue.line}` })}>Fix with AI</AqironButton><AqironButton variant="ghost" type="button" onClick={() => post('exportFinding', issue.id)}>Export</AqironButton><AqironButton variant="ghost" type="button" onClick={() => post('createRuleFromFinding', issue.id)}>Create rule</AqironButton><AqironButton variant="danger" type="button" onClick={() => post('ignoreIssue', issue.id)}>Ignore</AqironButton>
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
	return <AqironMetric title={title} value={value} />;
}

function SeverityBadge({ severity }: { severity: Severity }): React.ReactElement {
	return <AqironSeverity severity={severity} />;
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

function actionIcon(title: string): string {
	if (title.includes('code')) return 'codicon-code';
	if (title.includes('secrets')) return 'codicon-key';
	if (title.includes('network')) return 'codicon-globe';
	if (title.includes('auth')) return 'codicon-lock';
	if (title.includes('dependencies')) return 'codicon-package';
	if (title.includes('APK')) return 'codicon-device-mobile';
	return 'codicon-beaker';
}

