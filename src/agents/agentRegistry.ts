export interface AqironAgentDefinition {
	id: string;
	name: string;
	purpose: string;
}

export const agentDefinitions: readonly AqironAgentDefinition[] = [
	{
		id: 'code',
		name: 'Code Agent',
		purpose: 'Future implementation and code navigation agent.',
	},
	{
		id: 'security',
		name: 'Security Agent',
		purpose: 'Future security analysis and remediation agent.',
	},
	{
		id: 'refactor',
		name: 'Refactor Agent',
		purpose: 'Future code modernization and restructuring agent.',
	},
	{
		id: 'automation',
		name: 'Automation Agent',
		purpose: 'Future workflow and project automation agent.',
	},
];
