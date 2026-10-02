import { runCli } from './cli';

void runCli(process.argv.slice(2)).then((exitCode) => {
	process.exitCode = exitCode;
}).catch((error: unknown) => {
	process.stderr.write('CLI runtime failure. Use AQIRON_DEBUG=1 for a diagnostic code.\n');
	if (process.env.AQIRON_DEBUG === '1') {
		const code = typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string' ? error.code : 'unclassified';
		process.stderr.write(`Debug: ${code}\n`);
	}
	process.exitCode = 1;
});
