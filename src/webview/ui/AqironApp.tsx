import React, { Suspense, lazy, memo, useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Section, VsCodeApi, WebviewState } from './types.js';
import { AqironIconButton } from './design/primitives.js';

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

	return (
		<div className="aq-shell" style={{ '--aq-zoom': state.zoom } as React.CSSProperties}>
			<div className="aq-bg" style={{ backgroundImage: `url("${sanitizeAssetUrl(state.assets.bg)}")` }} />
			<div className="aq-grid" />
			<main className={active === 'agent' || active === 'aiAgent' ? 'aq-content has-composer' : 'aq-content'}>
				<header className="aq-top">
					<nav className="aq-tabs">
						{(['agent', 'scan', 'threats', 'reports'] as Section[]).map((tab) => (
							<button key={tab} aria-selected={tab === active} className={tab === active ? 'tab aq-tab active' : 'tab aq-tab'} onClick={() => post('focus', tab)}>
								<span className="svg-icon tab-svg" style={{ '--icon': `url("${tabIcon(tab, state)}")` } as React.CSSProperties} />
								<span>{tab === 'threats' ? 'Threat' : tab[0].toUpperCase() + tab.slice(1)}</span>
							</button>
						))}
					</nav>
					<div className="orb-actions">
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
				</header>
				<div className="aq-scroll">
					<DashboardHero state={state} />
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
				<span>{state.stats.scanStatus}</span>
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
	const [open, setOpen] = useState(false);
	return <motion.div className="workspace-onboarding" initial={{ opacity: 0 }} animate={{ opacity: 1 }}><div className="workspace-card">
		<button className="workspace-settings" aria-label="Open settings" onClick={() => post('openRagSettings')}><span className="codicon codicon-settings-gear" aria-hidden="true" />Settings</button>
		<img src={sanitizeAssetUrl(state.assets.logo)} alt="Aqiron Security" />
		<h1>{state.rag.restricted ? 'Workspace trust required' : 'Create your security workspace'}</h1>
		<p>{state.rag.restricted ? 'Aqiron cannot read or index files while VS Code is in Restricted Mode. Trust this workspace, then build the local RAG index.' : 'Index code, services, APIs, secrets, and dependencies locally in .aqiron-security.'}</p>
		{!state.rag.restricted && <div className="workspace-build"><button className="primary-action" disabled={state.rag.building} onClick={() => post(withAi ? 'ragReindexWithAi' : 'ragReindexWithoutAi')}>{state.rag.building ? 'Building workspace...' : 'Create Workspace'}</button><div className="build-menu"><button aria-label="Choose build mode" aria-expanded={open} onClick={() => setOpen((value) => !value)}><span className="codicon codicon-chevron-down" aria-hidden="true" /></button>{open && <div><button onClick={() => { setWithAi(true); setOpen(false); }}>Build with AI</button><button onClick={() => { setWithAi(false); setOpen(false); }}>Build without AI</button></div>}</div></div>}
		<span>{withAi ? 'Build with AI is selected. Suggestions will be generated after indexing.' : 'Build without AI is selected. Suggestions can be generated later.'}</span>
	</div></motion.div>;
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
