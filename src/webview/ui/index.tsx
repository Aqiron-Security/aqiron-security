import React from 'react';
import { createRoot } from 'react-dom/client';
import '@vscode/codicons/dist/codicon.css';
import { AqironApp } from './AqironApp.js';
import './styles.css';
import { VsCodeApi, WebviewState } from './types.js';

declare global {
	interface Window {
		acquireVsCodeApi?: () => VsCodeApi;
		__AQIRON_STATE__: WebviewState;
	}
}

const vscode = window.acquireVsCodeApi?.() ?? { postMessage: () => undefined };
const root = createRoot(document.getElementById('app') as HTMLElement);

root.render(
	<React.StrictMode>
		<AqironApp initialState={window.__AQIRON_STATE__} vscode={vscode} />
	</React.StrictMode>,
);
