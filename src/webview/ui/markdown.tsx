import React, { useState } from 'react';

export function Markdown({ content }: { content: string }): React.ReactElement {
	return <div className="markdown">{parseBlocks(content).map(renderBlock)}</div>;
}

type Inline = { kind: 'text' | 'bold' | 'italic' | 'code'; text: string };
type Block =
	| { kind: 'heading'; level: number; text: Inline[] }
	| { kind: 'paragraph'; text: Inline[] }
	| { kind: 'ul'; items: Inline[][] }
	| { kind: 'ol'; items: Inline[][] }
	| { kind: 'code'; text: string }
	| { kind: 'table'; rows: Inline[][][] };

function stripDangerousHtmlBlocks(input: string): string {
	let current = input;
	let previous: string;
	do {
		previous = current;
		current = current.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<iframe[\s\S]*?<\/iframe>/gi, '');
	} while (current !== previous);
	return current;
}

export function parseBlocks(content: string): Block[] {
	const lines = stripDangerousHtmlBlocks(content).split(/\r?\n/);
	const blocks: Block[] = [];
	let index = 0;
	while (index < lines.length) {
		const line = lines[index] ?? '';
		if (!line.trim()) {
			index++;
			continue;
		}
		if (line.startsWith('```')) {
			const code: string[] = [];
			index++;
			while (index < lines.length && !lines[index].startsWith('```')) {
				code.push(lines[index]);
				index++;
			}
			index++;
			blocks.push({ kind: 'code', text: code.join('\n') });
			continue;
		}
		const heading = line.match(/^(#{1,4})\s+(.+)$/);
		if (heading) {
			blocks.push({ kind: 'heading', level: Math.min(4, heading[1].length + 2), text: parseInline(heading[2]) });
			index++;
			continue;
		}
		if (isTableStart(lines, index)) {
			const rows: Inline[][][] = [];
			while (index < lines.length && /^\s*\|.*\|\s*$/.test(lines[index])) {
				if (!/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(lines[index])) {
					rows.push(splitTableRow(lines[index]).map(parseInline));
				}
				index++;
			}
			blocks.push({ kind: 'table', rows });
			continue;
		}
		if (/^\s*[-*]\s+/.test(line)) {
			const items: Inline[][] = [];
			while (index < lines.length && /^\s*[-*]\s+/.test(lines[index])) {
				items.push(parseInline(lines[index].replace(/^\s*[-*]\s+/, '')));
				index++;
			}
			blocks.push({ kind: 'ul', items });
			continue;
		}
		if (/^\s*\d+\.\s+/.test(line)) {
			const items: Inline[][] = [];
			while (index < lines.length && /^\s*\d+\.\s+/.test(lines[index])) {
				items.push(parseInline(lines[index].replace(/^\s*\d+\.\s+/, '')));
				index++;
			}
			blocks.push({ kind: 'ol', items });
			continue;
		}
		const paragraph: string[] = [];
		while (index < lines.length && lines[index].trim() && !/^(#{1,4})\s+/.test(lines[index]) && !/^\s*(?:[-*]|\d+\.)\s+/.test(lines[index]) && !lines[index].startsWith('```') && !isTableStart(lines, index)) {
			paragraph.push(lines[index]);
			index++;
		}
		blocks.push({ kind: 'paragraph', text: parseInline(paragraph.join(' ')) });
	}
	return blocks;
}

function renderBlock(block: Block, index: number): React.ReactNode {
	if (block.kind === 'code') {
		return <CodeBlock key={index} text={block.text} />;
	}
	if (block.kind === 'heading') {
		const Tag = `h${block.level}` as 'h3' | 'h4' | 'h5' | 'h6';
		return <Tag key={index}>{renderInline(block.text)}</Tag>;
	}
	if (block.kind === 'ul') {
		return <ul key={index}>{block.items.map((item, itemIndex) => <li key={itemIndex}>{renderInline(item)}</li>)}</ul>;
	}
	if (block.kind === 'ol') {
		return <ol key={index}>{block.items.map((item, itemIndex) => <li key={itemIndex}>{renderInline(item)}</li>)}</ol>;
	}
	if (block.kind === 'table') {
		const [head, ...body] = block.rows;
		return <div key={index} className="md-table-wrap"><table><thead><tr>{head?.map((cell, cellIndex) => <th key={cellIndex}>{renderInline(cell)}</th>)}</tr></thead><tbody>{body.map((row, rowIndex) => <tr key={rowIndex}>{row.map((cell, cellIndex) => <td key={cellIndex}>{renderInline(cell)}</td>)}</tr>)}</tbody></table></div>;
	}
	return <p key={index}>{renderInline(block.text)}</p>;
}

function CodeBlock({ text }: { text: string }): React.ReactElement {
	const [copied, setCopied] = useState(false);
	const copy = async () => {
		try {
			if (navigator.clipboard?.writeText) {
				await navigator.clipboard.writeText(text);
			} else {
				const input = document.createElement('textarea');
				input.value = text;
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
	return <div className="markdown-code-card"><button type="button" className="command-copy" aria-label={copied ? 'Copied' : 'Copy code'} title={copied ? 'Copied' : 'Copy code'} onClick={copy}><span className={`codicon ${copied ? 'codicon-check' : 'codicon-copy'}`} aria-hidden="true" /></button><pre><code>{text}</code></pre></div>;
}

function parseInline(value: string): Inline[] {
	const normalizedValue = value.replace(/\*([^*\n]+)\*\*/g, '**$1**');
	const nodes: Inline[] = [];
	const regex = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g;
	let lastIndex = 0;
	let match: RegExpExecArray | null;
  while ((match = regex.exec(normalizedValue)) !== null) {
		if (match.index > lastIndex) {
			nodes.push({ kind: 'text', text: normalizedValue.slice(lastIndex, match.index) });
		}
		const token = match[0];
		nodes.push(token.startsWith('**') ? { kind: 'bold', text: token.slice(2, -2) } : token.startsWith('*') ? { kind: 'italic', text: token.slice(1, -1) } : { kind: 'code', text: token.slice(1, -1) });
		lastIndex = match.index + token.length;
	}
	if (lastIndex < normalizedValue.length) {
		nodes.push({ kind: 'text', text: normalizedValue.slice(lastIndex) });
	}
	return nodes;
}

function renderInline(nodes: Inline[]): React.ReactNode[] {
	return nodes.map((node, index) => {
		if (node.kind === 'bold') {
			return <strong key={index}>{node.text}</strong>;
		}
		if (node.kind === 'code') {
			return <code key={index}>{node.text}</code>;
		}
		if (node.kind === 'italic') {
			return <em key={index}>{node.text}</em>;
		}
		return node.text;
	});
}

function isTableStart(lines: string[], index: number): boolean {
	return /^\s*\|.*\|\s*$/.test(lines[index] ?? '') && /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(lines[index + 1] ?? '');
}

function splitTableRow(line: string): string[] {
	return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((cell) => cell.trim());
}
