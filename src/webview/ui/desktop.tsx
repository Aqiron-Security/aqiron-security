import React from 'react';
import { createRoot } from 'react-dom/client';
import '@vscode/codicons/dist/codicon.css';
import { AqironApp } from './AqironApp.js';
import { createDesktopAdapter } from '../../../apps/desktop/src/desktopAdapter.js';
import './styles.css';

declare global {
	interface Window { __AQIRON_DESKTOP__?: boolean; }
}

window.__AQIRON_DESKTOP__ = true;
const adapter = createDesktopAdapter();
const root = createRoot(document.getElementById('app') as HTMLElement);
root.render(<React.StrictMode><AqironApp initialState={adapter.state} hostApi={adapter} /></React.StrictMode>);
