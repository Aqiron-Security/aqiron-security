export interface AiAction {
	id: string;
	title: string;
	description: string;
}

export const aiActions: readonly AiAction[] = [
	{
		id: 'chat',
		title: 'Security Agent',
		description: 'Future conversational security analysis interface.',
	},
	{
		id: 'explain-code',
		title: 'Explain Code',
		description: 'Future code explanation workflow.',
	},
	{
		id: 'refactor',
		title: 'Refactor',
		description: 'Future AI-assisted refactoring workflow.',
	},
	{
		id: 'generate-tests',
		title: 'Generate Tests',
		description: 'Future test generation workflow.',
	},
];
