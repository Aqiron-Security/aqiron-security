import * as fs from 'fs/promises';
import * as path from 'path';

export interface ReportBundlePaths {
	directory: string;
	jsonPath: string;
	sarifPath: string;
	pdfPath: string;
}

export async function createReportBundlePaths(workspaceRoot: string, generatedAt = new Date().toISOString()): Promise<ReportBundlePaths> {
	const directory = path.join(workspaceRoot, '.aqiron-security', 'reports', reportFolderName(generatedAt));
	await fs.mkdir(directory, { recursive: true });
	return {
		directory,
		jsonPath: path.join(directory, 'report.json'),
		sarifPath: path.join(directory, 'report.sarif'),
		pdfPath: path.join(directory, 'report.pdf'),
	};
}

function reportFolderName(value: string): string {
	return value.replace(/[:.]/g, '-');
}
