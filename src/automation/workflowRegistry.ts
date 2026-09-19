export interface AqironWorkflowDefinition {
	id: string;
	name: string;
	description: string;
}

export const workflowDefinitions: readonly AqironWorkflowDefinition[] = [
	{
		id: 'run-workflow',
		name: 'Run Workflow',
		description: 'Future workspace workflow runner.',
	},
	{
		id: 'generate-commit',
		name: 'Generate Commit',
		description: 'Future commit summary and preparation workflow.',
	},
	{
		id: 'analyze-project',
		name: 'Analyze Project',
		description: 'Future full-project intelligence workflow.',
	},
	{
		id: 'fix-workspace',
		name: 'Fix Workspace',
		description: 'Future workspace-wide repair workflow.',
	},
];
