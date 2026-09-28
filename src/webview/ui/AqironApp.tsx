import React, { Suspense, lazy, memo, useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Section, VsCodeApi, WebviewState } from './types.js';
import { AqironBadge, AqironButton, AqironIconButton, AqironSectionHeader } from './design/primitives.js';

const AgentTab = lazy(async () => ({ default: (await import('./tabs.js')).AgentTab }));
const AgentPanel = lazy(async () => ({ default: (await import('./tabs.js')).AgentPanel }));
const ScanTab = lazy(async () => ({ default: (await import('./tabs.js')).ScanTab }));
const ThreatTab = lazy(async () => ({ default: (await import('./tabs.js')).ThreatTab }));
const ReportsTab = lazy(async () => ({ default: (await import('./tabs.js')).ReportsTab }));
const SettingsTab = lazy(async () => ({ default: (await import('./tabs.js')).SettingsTab }));

interface Props {
	initialState: WebviewState;
	vscode: VsCodeApi;
}

export function AqironApp({ initialState, vscode }: Props): React.ReactElement {
	const [state, setState] = useState(initialState);

	useEffect(() => {
		const listener = (event: MessageEvent<{ type: string; state: WebviewState }>) => {
			if (event.data.type === 'state') {
				setState(event.data.state);
			}
		};
		window.addEventListener('message', listener);
		vscode.postMessage({ command: 'ready' });
		return () => window.removeEventListener('message', listener);
	}, [vscode]);

	const post = (command: string, payload?: unknown) => vscode.postMessage({ command, payload });
	const active = state.section;
	const orb = getOrbState(state);
	const primaryDestinations: Array<{ id: Section; label: string }> = [
		{ id: 'agent', label: 'Agent' },
		{ id: 'scan', label: 'Scan' },
		{ id: 'threats', label: 'Findings' },
		{ id: 'reports', label: 'Reports' },
	];

	return (
		<div className="aq-shell" style={{ '--aq-zoom': state.zoom } as React.CSSProperties}>
			<div className="aq-bg" style={{ backgroundImage: `url("${sanitizeAssetUrl(state.assets.bg)}")` }} />
			<div className="aq-grid" />
			<main className={active === 'agent' || active === 'aiAgent' ? 'aq-content has-composer' : 'aq-content'}>
				<header className="aq-top">
					<DashboardHero state={state} />
					<div className="orb-actions">
						<span className={`aq-status ${getScanStatusTone(state.stats.scanStatus)}`} aria-label={`Scan status: ${state.stats.scanStatus}`}>{state.stats.scanStatus}</span>
						<AqironIconButton className="top-settings" aria-label="Open settings" onClick={() => post('focus', 'settings')}><span className="codicon codicon-settings-gear" aria-hidden="true" /></AqironIconButton>
						<div className="orb-wrap">
						<button className={`security-orb ${orb}`} aria-label="Security summary" />
						<div className="orb-pop">
							<strong>{state.workspace.risk} posture</strong>
							<span>{state.counts.total} open findings across {state.counts.filesAffected} files</span>
							<span>{state.stats.scanStatus === 'Scanning' ? 'Scan in progress' : `${state.stats.filesScanned} files scanned`}</span>
						</div>
						</div>
					</div>
					<nav className="aq-tabs" aria-label="Primary navigation">
						{primaryDestinations.map(({ id, label }) => {
							const selected = id === active || (id === 'agent' && active === 'aiAgent');
							return <button key={id} type="button" aria-current={selected ? 'page' : undefined} className={selected ? 'tab aq-tab active' : 'tab aq-tab'} onClick={() => post('focus', id)}>
								<span className="svg-icon tab-svg" style={{ '--icon': `url("${tabIcon(id, state)}")` } as React.CSSProperties} />
								<span>{label}</span>
							</button>;
						})}
					</nav>
				</header>
				<div className="aq-scroll">
					<Suspense fallback={<div className="skeleton">Loading secure workspace...</div>}>
						<AnimatePresence mode="wait">
							<motion.section className="aq-view" key={active} initial={{ opacity: 0, scale: 0.992 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.992 }} transition={{ duration: 0.2 }}>
								{active === 'agent' && <AgentTab state={state} post={post} />}
								{active === 'aiAgent' && <AgentPanel state={state} post={post} />}
								{active === 'scan' && <ScanTab state={state} post={post} />}
								{active === 'threats' && <ThreatTab state={state} post={post} />}
								{active === 'reports' && <ReportsTab state={state} post={post} />}
								{active === 'settings' && <SettingsTab state={state} post={post} />}
							</motion.section>
						</AnimatePresence>
					</Suspense>
				</div>
			</main>
			{!state.rag.ready && active !== 'settings' && <WorkspaceOnboarding state={state} post={post} />}
		</div>
	);
}

const DashboardHero = memo(function DashboardHero({ state }: { state: WebviewState }): React.ReactElement {
	return (
		<section className="hero-panel">
			<div className="brandline">
				<img src={sanitizeAssetUrl(state.assets.logo)} alt="" />
				<div>
					<div className="eyebrow">{state.workspace.name}</div>
					<h1>Aqiron Security</h1>
				</div>
			</div>
			<div className="hero-pills">
				<span>{state.workspace.types[0] ?? 'Workspace'}</span>
				<span>{state.workspace.backend}</span>
				<span>{state.workspace.risk}</span>
			</div>
		</section>
	);
});

function InitializationOverlay({ state, post }: { state: WebviewState; post: (command: string, payload?: unknown) => void }): React.ReactElement {
	const [index, setIndex] = useState(0);
	const stages = ['Detecting framework', 'Building workspace graph', 'Loading security engines', 'Indexing dependencies', 'Initializing AI agents', 'Preparing threat intelligence', 'Workspace ready'];
	useEffect(() => {
		if (index >= stages.length) {
			const timer = window.setTimeout(() => post('setupComplete'), 420);
			return () => window.clearTimeout(timer);
		}
		const timer = window.setTimeout(() => setIndex((value) => value + 1), 360);
		return () => window.clearTimeout(timer);
	}, [index, post, stages.length]);
	return (
		<motion.div className="init-overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.24 }}>
			<div className="init-grid" style={{ backgroundImage: `url("${state.assets.initializationGrid}")` }} />
			<motion.img className="init-logo" src={state.assets.logo} alt="" animate={{ scale: [1, 1.05, 1], opacity: [0.78, 1, 0.78] }} transition={{ duration: 1.5, repeat: Infinity }} />
			<h1>Initializing Aqiron Security Workspace</h1>
			<div className="init-progress"><span style={{ width: `${Math.min(100, (index / stages.length) * 100)}%` }} /></div>
			<div className="init-steps">
				{stages.map((stage, stageIndex) => (
					<div key={stage} className={stageIndex < index ? 'done' : stageIndex === index ? 'live' : ''}>
						<span>{stageIndex < index ? '✓' : '○'}</span>{stage}
					</div>
				))}
			</div>
			<pre className="init-log">{stages.slice(0, Math.max(1, index)).map((stage) => `[aqiron] ${stage.toLowerCase()}...`).join('\n')}</pre>
		</motion.div>
	);
}

function WorkspaceOnboarding({ state, post }: { state: WebviewState; post: (command: string, payload?: unknown) => void }): React.ReactElement {
	const [withAi, setWithAi] = useState(true);
	const hasWorkspace = Boolean(state.workspace.root && state.workspace.status !== 'No workspace');
	return <motion.div className="workspace-onboarding" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
		<section className="workspace-card aq-surface-panel" aria-label="Workspace setup">
			<div className="workspace-card-top">
				<div className="workspace-brand"><img src={sanitizeAssetUrl(state.assets.logo)} alt="" /><AqironBadge tone="brand">AQIRON SECURITY</AqironBadge></div>
				<AqironButton type="button" variant="ghost" className="workspace-settings" onClick={() => post('openRagSettings')}><span className="codicon codicon-settings-gear" aria-hidden="true" />Settings</AqironButton>
			</div>
			<AqironSectionHeader title={state.rag.restricted ? 'Workspace trust required' : 'Set up this security workspace'} description={state.rag.restricted ? 'Aqiron needs workspace trust before it can read files and build the local index.' : 'Build Aqiron’s local security index for the folder currently open in VS Code.'} />
			<div className="workspace-context">
				<div className="workspace-context-heading"><span className="codicon codicon-folder" aria-hidden="true" /><strong>Open workspace</strong><AqironBadge>{state.workspace.status}</AqironBadge></div>
				<strong className="workspace-context-name">{state.workspace.name}</strong>
				{hasWorkspace ? <code title={state.workspace.root}>{state.workspace.root}</code> : <span className="workspace-context-empty">Open a project folder in VS Code to index its files.</span>}
				{state.workspace.types.length > 0 && <div className="workspace-project-types" aria-label="Detected project types">{state.workspace.types.map((type) => <AqironBadge key={type}>{type}</AqironBadge>)}</div>}
			</div>
			{state.rag.restricted ? <div className="workspace-notice" role="status"><span className="codicon codicon-lock" aria-hidden="true" /><span>Trust this folder using VS Code’s workspace trust controls, then return here to build the index.</span></div> : <>
				<div className="workspace-setup-options">
					<div><strong>Indexing setup</strong><span>Choose whether Aqiron should also generate suggestions after indexing.</span></div>
					<div className="workspace-mode-options" role="group" aria-label="Workspace indexing mode">
						<button type="button" aria-pressed={withAi} className={withAi ? 'workspace-mode active' : 'workspace-mode'} onClick={() => setWithAi(true)}><span className="codicon codicon-sparkle" aria-hidden="true" /><span><strong>Build with AI</strong><small>Generate suggestions after indexing</small></span><span className="workspace-mode-check" aria-hidden="true" /></button>
						<button type="button" aria-pressed={!withAi} className={!withAi ? 'workspace-mode active' : 'workspace-mode'} onClick={() => setWithAi(false)}><span className="codicon codicon-database" aria-hidden="true" /><span><strong>Build without AI</strong><small>Generate suggestions later</small></span><span className="workspace-mode-check" aria-hidden="true" /></button>
					</div>
				</div>
				<div className="workspace-card-footer"><span className={state.rag.building ? 'aq-status aq-status--info' : 'workspace-footer-note'} role={state.rag.building ? 'status' : undefined}>{state.rag.building ? 'Building local workspace index…' : 'Your source files remain in the open VS Code workspace.'}</span><AqironButton type="button" variant="primary" disabled={state.rag.building} onClick={() => post(withAi ? 'ragReindexWithAi' : 'ragReindexWithoutAi')}><span className={state.rag.building ? 'codicon codicon-loading codicon-modifier-spin' : 'codicon codicon-shield'} aria-hidden="true" />{state.rag.building ? 'Building workspace…' : 'Create Workspace'}</AqironButton></div>
			</>}
		</section>
	</motion.div>;
}

function sanitizeAssetUrl(url: string | undefined | null): string {
	if (!url) {
		return '';
	}
	const trimmed = url.trim();
	if (!trimmed) {
		return '';
	}
	if (trimmed.startsWith('/')) {
		return trimmed;
	}
	try {
		const parsed = new URL(trimmed, window.location.origin);
		if (parsed.protocol === 'https:' || parsed.protocol === 'vscode-webview-resource:') {
			return parsed.href;
		}
	} catch {
		return '';
	}
	return '';
}

function tabIcon(tab: Section, state: WebviewState): string {
	if (tab === 'agent') {
		return state.assets.agentIcon;
	}
	if (tab === 'scan') {
		return state.assets.scanIcon;
	}
	if (tab === 'threats') {
		return state.assets.threatIcon;
	}
	if (tab === 'settings') {
		return state.assets.infoIcon;
	}
	return state.assets.reportsIcon;
}

function getOrbState(state: WebviewState): string {
	if (state.stats.scanStatus === 'Scanning') {
		return 'blue';
	}
	if (state.counts.critical > 0) {
		return 'red';
	}
	if (state.counts.high + state.counts.medium > 0) {
		return 'yellow';
	}
	return 'green';
}

function getScanStatusTone(status: WebviewState['stats']['scanStatus']): string {
	if (status === 'Scanning') {
		return 'aq-status--info';
	}
	if (status === 'Complete') {
		return 'aq-status--success';
	}
	if (status === 'Failed') {
		return 'aq-status--danger';
	}
	return '';
}
