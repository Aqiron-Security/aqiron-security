/**
 * Flutter-Specific Exclusion Lists
 * Prevents scanning of generated, build, and cache artifacts
 */

export const FLUTTER_EXCLUSIONS = [
	'build',
	'.dart_tool',
	'.gradle',
	'.aqiron',
	'android/build',
	'ios/build',
	'windows/flutter/ephemeral',
	'linux/flutter/ephemeral',
	'macos/Flutter/ephemeral',
];

export const ANDROID_EXCLUSIONS = [
	'build',
	'.gradle',
	'android/build',
	'android/app/intermediates',
	'android/app/generated',
];

export const IOS_EXCLUSIONS = [
	'ios/build',
	'ios/Pods',
];

export const WINDOWS_EXCLUSIONS = [
	'windows/flutter/ephemeral',
	'build',
];

export const LINUX_EXCLUSIONS = [
	'linux/flutter/ephemeral',
	'build',
];

export const MACOS_EXCLUSIONS = [
	'macos/Flutter/ephemeral',
	'build',
];

export const STANDARD_EXCLUSIONS = [
	'node_modules',
	'.idea',
	'.vscode',
	'.*/.metadata',
	'.*/.packages',
	'**/pubspec.lock',
];

/**
 * Get comprehensive exclusion list for Flutter project
 */
export function getFlutterExclusions(): string[] {
	const exclusions = new Set<string>([
		...FLUTTER_EXCLUSIONS,
		...ANDROID_EXCLUSIONS,
		...IOS_EXCLUSIONS,
		...WINDOWS_EXCLUSIONS,
		...LINUX_EXCLUSIONS,
		...MACOS_EXCLUSIONS,
		...STANDARD_EXCLUSIONS,
	]);
	return Array.from(exclusions);
}

/**
 * Get platform-specific exclusions
 */
export function getPlatformExclusions(platform: 'android' | 'ios' | 'windows' | 'linux' | 'macos' | 'all'): string[] {
	const base = STANDARD_EXCLUSIONS;
	const platformMap: Record<string, string[]> = {
		android: ANDROID_EXCLUSIONS,
		ios: IOS_EXCLUSIONS,
		windows: WINDOWS_EXCLUSIONS,
		linux: LINUX_EXCLUSIONS,
		macos: MACOS_EXCLUSIONS,
		all: FLUTTER_EXCLUSIONS,
	};
	return [...new Set([...base, ...(platformMap[platform] ?? [])])];
}

/**
 * Binary file extensions to scan in ARTIFACT_BINARY mode
 */
export const BINARY_EXTENSIONS = [
	'.apk',
	'.aar',
	'.aab',
	'.dex',
	'.jar',
	'.so',
	'.dll',
	'.exe',
	'.bin',
	'.ipa',
];

/**
 * Check if file is a binary artifact
 */
export function isBinaryArtifact(filePath: string): boolean {
	const ext = filePath.toLowerCase().split('.').pop() || '';
	return BINARY_EXTENSIONS.some(binary => binary.toLowerCase() === `.${ext}`);
}
