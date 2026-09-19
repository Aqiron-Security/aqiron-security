import { ProjectProfile } from './projectProfile';

export interface WorkspaceModel {
	rootPath: string;
	workspaceName: string;
	projectTypes: string[];
	profile: ProjectProfile;
	files: Array<{ path: string; language?: string; reason?: string; excerpt?: string }>;
}
