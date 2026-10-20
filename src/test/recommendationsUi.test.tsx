import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AqironButton, AqironSectionHeader } from '../webview/ui/design/primitives';
import { RecommendationsSection } from '../webview/ui/tabs';
import { WebviewState } from '../webview/ui/types';

suite('Desktop recommendations UI', () => {
	test('renders Refresh AI in the section header and dispatches the existing refresh command', () => {
	setDesktopWindow();
		const calls: Array<{ command: string; payload?: unknown }> = [];
		const element = RecommendationsSection({ state: state(), post: (command, payload) => calls.push({ command, payload }) });
		const markup = renderToStaticMarkup(element);
		assert.match(markup, /Recommended actions/);
		assert.match(markup, /Refresh AI/);
		const children = getProps<{ children: React.ReactNode }>(element).children as React.ReactElement[];
		const header = children[0]!;
		const headerElement = AqironSectionHeader(getProps<React.ComponentProps<typeof AqironSectionHeader>>(header));
		const action = (getProps<{ children: React.ReactNode }>(headerElement).children as React.ReactNode[])[1] as React.ReactElement;
		const button = AqironButton(getProps<React.ComponentProps<typeof AqironButton>>(action));
		getProps<{ onClick?: () => void }>(button).onClick?.();
		assert.deepEqual(calls, [{ command: 'ragRefreshSuggestions', payload: undefined }]);
	});

	test('shows loading and disables another click while a refresh is in progress', () => {
		setDesktopWindow();
		const element = RecommendationsSection({ state: state({ building: true }), post: () => assert.fail('A disabled refresh button must not be clicked.') });
		const header = (getProps<{ children: React.ReactNode }>(element).children as React.ReactElement[])[0]!;
		const headerElement = AqironSectionHeader(getProps<React.ComponentProps<typeof AqironSectionHeader>>(header));
		const action = (getProps<{ children: React.ReactNode }>(headerElement).children as React.ReactNode[])[1] as React.ReactElement;
		const button = AqironButton(getProps<React.ComponentProps<typeof AqironButton>>(action));
		assert.equal(getProps<{ disabled?: boolean }>(button).disabled, true);
		assert.equal(getProps<{ 'aria-busy'?: boolean }>(button)['aria-busy'], true);
		assert.match(renderToStaticMarkup(element), /Refreshing…/);
	});

	test('keeps valid recommendation content visible with a refresh error and preserves Run and Explain payloads', () => {
		setDesktopWindow();
		const calls: Array<{ command: string; payload?: unknown }> = [];
		const recommendation = { title: 'Review auth storage', detail: 'Restrict token access.', command: 'Review auth storage', metadata: { ruleId: 'auth.storage', file: 'lib/auth.dart' } };
		const element = RecommendationsSection({ state: state({ suggestionError: 'Provider unavailable' }, [recommendation]), post: (command, payload) => calls.push({ command, payload }) });
		const children = getProps<{ children: React.ReactNode }>(element).children as React.ReactElement[];
		const listChildren = getProps<{ children: React.ReactNode }>(children[1]!).children as React.ReactElement[];
		assert.deepEqual(getProps<{ children: React.ReactNode }>(listChildren[0]!).children, ['Recommendations could not be refreshed: ', 'Provider unavailable']);
		const cards = (listChildren[1] as unknown as React.ReactElement[])[0]!;
		const cardChildren = getProps<{ children: React.ReactNode }>(cards).children as React.ReactElement[];
		const copy = cardChildren[0]!;
		const copyChildren = getProps<{ children: React.ReactNode }>(copy).children as React.ReactElement[];
		assert.equal(getProps<{ children: React.ReactNode }>(copyChildren[0]!).children, 'Review auth storage');
		assert.equal(getProps<{ children: React.ReactNode }>(copyChildren[2]!).children, 'auth.storage · lib/auth.dart');
		const actionRow = cardChildren[1]!;
		const buttons = (getProps<{ children: React.ReactNode }>(actionRow).children as React.ReactElement[]);
		for (const buttonElement of buttons) {
			if (!buttonElement || buttonElement.type !== AqironButton) { continue; }
			const button = AqironButton(getProps<React.ComponentProps<typeof AqironButton>>(buttonElement));
			getProps<{ onClick?: () => void }>(button).onClick?.();
		}
		assert.deepEqual(calls, [
			{ command: 'sendChat', payload: { text: 'Review auth storage', useTaskDefaults: true } },
			{ command: 'sendChat', payload: { text: 'Explain Review auth storage', useTaskDefaults: true } },
		]);
	});

	test('recommendation layout wraps actions and long content at narrow widths', () => {
		const css = fs.readFileSync(path.resolve('src/webview/ui/styles.css'), 'utf8');
		assert.match(css, /\.agent-recommendations-section \.aq-section-header \{[^}]*flex-wrap:\s*wrap/s);
		assert.match(css, /\.agent-suggestion-card \.suggestion-copy > strong \{[^}]*overflow-wrap:\s*anywhere/s);
		assert.match(css, /\.agent-suggestion-card \.suggestion-actions \{[^}]*flex-wrap:\s*wrap/s);
		assert.match(css, /@container aq-agent \(max-width: 680px\)[\s\S]*?\.agent-suggestion-card \{ grid-template-columns: 1fr/);
	});
});

function state(ragOverrides: Partial<WebviewState['rag']> = {}, suggestions: WebviewState['suggestions'] = []): WebviewState {
	return {
		workspace: { root: 'C:\\project' },
		rag: { ready: true, building: false, withAi: true, suggestionsGenerated: true, suggestions: [], restricted: false, backend: 'local', ...ragOverrides },
		suggestions,
	} as WebviewState;
}

function setDesktopWindow(): void {
	Object.defineProperty(globalThis, 'window', { configurable: true, value: { __AQIRON_DESKTOP__: true } });
}

function getProps<T>(element: React.ReactElement): T {
	return element.props as unknown as T;
}
