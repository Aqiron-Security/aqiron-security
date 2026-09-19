import { parse } from '@babel/parser';
import { builtInRegexSignals } from './regexSignals';
import { RegexSignal, SecuritySignal } from './types';

const jsExtensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const astProviders: Array<{ category: SecuritySignal['category']; provider: string; needles: string[]; description: string }> = [
	{ category: 'database', provider: 'Firebase', needles: ['firebase', '@firebase'], description: 'Firebase import or client construction.' },
	{ category: 'database', provider: 'Supabase', needles: ['supabase', '@supabase'], description: 'Supabase import or client construction.' },
	{ category: 'database', provider: 'MongoDB', needles: ['mongodb', 'mongoose'], description: 'MongoDB import or client construction.' },
	{ category: 'database', provider: 'DynamoDB', needles: ['dynamodb', '@aws-sdk/lib-dynamodb'], description: 'DynamoDB import or client construction.' },
	{ category: 'payment', provider: 'Stripe', needles: ['stripe', '@stripe'], description: 'Stripe import or client construction.' },
	{ category: 'payment', provider: 'PayPal', needles: ['paypal', '@paypal'], description: 'PayPal import or client construction.' },
	{ category: 'payment', provider: 'Braintree', needles: ['braintree'], description: 'Braintree import or client construction.' },
	{ category: 'llm', provider: 'OpenAI', needles: ['openai'], description: 'OpenAI import or client construction.' },
	{ category: 'llm', provider: 'Anthropic', needles: ['anthropic', '@anthropic-ai'], description: 'Anthropic import or client construction.' },
	{ category: 'llm', provider: 'Gemini', needles: ['generative-ai', 'gemini', 'generativelanguage'], description: 'Gemini import or client construction.' },
	{ category: 'endpoint', provider: 'REST', needles: ['axios', 'node-fetch', 'got', 'superagent', 'fetch'], description: 'REST client import or call.' },
	{ category: 'endpoint', provider: 'GraphQL', needles: ['graphql', '@apollo', 'urql'], description: 'GraphQL client import or call.' },
];

export function detectSecuritySignals(file: string, content: string, externalSignals: RegexSignal[] = []): SecuritySignal[] {
	const signals = [...builtInRegexSignals, ...externalSignals];
	const code = stripComments(content);
	const detected = detectWithRegex(file, code, signals);
	if (jsExtensions.has(extensionOf(file))) {
		detected.push(...detectViaAST(file, content));
	}
	return dedupeSignals(detected);
}

export function detectViaAST(file: string, content: string): SecuritySignal[] {
	try {
		const ast = parse(content, {
			sourceType: 'unambiguous',
			allowReturnOutsideFunction: true,
			plugins: ['typescript', 'jsx', 'decorators-legacy', 'classProperties', 'dynamicImport', 'optionalChaining', 'topLevelAwait'],
		});
		const output: SecuritySignal[] = [];
		walk(ast, (node) => {
			const source = stringValue(node.source) ?? stringValue(node.callee) ?? stringValue(node.arguments?.[0]) ?? '';
			if (!source) {
				return;
			}
			const normalized = source.toLowerCase();
			for (const provider of astProviders) {
				if (!provider.needles.some((needle) => normalized.includes(needle))) {
					continue;
				}
				const location = node.loc?.start;
				output.push({
					id: `ast.${provider.category}.${provider.provider.toLowerCase()}`,
					category: provider.category,
					provider: provider.provider,
					confidence: 'High',
					evidenceType: 'ast',
					file,
					line: location?.line ?? 1,
					column: (location?.column ?? 0) + 1,
					match: provider.category === 'secret' ? '[redacted]' : source.slice(0, 120),
					description: provider.description,
				});
			}
		});
		return output;
	} catch {
		return [];
	}
}

function detectWithRegex(file: string, code: string, signals: RegexSignal[]): SecuritySignal[] {
	const output: SecuritySignal[] = [];
	for (const signal of signals) {
		if (signal.extensions && signal.extensions.length > 0 && !signal.extensions.includes(extensionOf(file))) {
			continue;
		}
		let expression: RegExp;
		try {
			expression = new RegExp(signal.pattern, signal.flags?.includes('g') ? signal.flags : `${signal.flags ?? ''}g`);
		} catch {
			continue;
		}
		for (const match of code.matchAll(expression)) {
			const offset = match.index ?? 0;
			const before = code.slice(0, offset);
			const line = before.split('\n').length;
			const column = offset - before.lastIndexOf('\n');
			output.push({
				id: signal.id,
				category: signal.category,
				provider: signal.provider,
				confidence: signal.confidence,
				evidenceType: 'regex',
				file,
				line,
				column,
				match: signal.category === 'secret' ? '[redacted]' : match[0].slice(0, 120),
				description: signal.description,
			});
			if (output.length >= 100) {
				return output;
			}
		}
	}
	return output;
}

function stripComments(content: string): string {
	return content
		.replace(/\/\*[\s\S]*?\*\//g, (value) => value.replace(/[^\n]/g, ' '));
}

function walk(value: unknown, visit: (node: any) => void): void {
	if (!value || typeof value !== 'object') {
		return;
	}
	if (Array.isArray(value)) {
		for (const item of value) {
			walk(item, visit);
		}
		return;
	}
	const node = value as Record<string, unknown>;
	if (typeof node.type === 'string') {
		visit(node);
	}
	for (const [key, child] of Object.entries(node)) {
		if (key === 'loc' || key === 'start' || key === 'end' || key === 'tokens' || key === 'comments') {
			continue;
		}
		walk(child, visit);
	}
}

function stringValue(value: any): string | undefined {
	if (!value) {
		return undefined;
	}
	if (typeof value === 'string') {
		return value;
	}
	if (value.type === 'StringLiteral' || value.type === 'Literal') {
		return value.value;
	}
	if (value.type === 'Identifier') {
		return value.name;
	}
	if (value.type === 'MemberExpression') {
		return `${stringValue(value.object) ?? ''}.${stringValue(value.property) ?? ''}`;
	}
	return undefined;
}

function extensionOf(file: string): string {
	const match = /\.[^.\\/]+$/.exec(file.toLowerCase());
	return match?.[0] ?? '';
}

function dedupeSignals(signals: SecuritySignal[]): SecuritySignal[] {
	return [...new Map(signals.map((signal) => [`${signal.id}|${signal.file}|${signal.line}`, signal])).values()];
}
