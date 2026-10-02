import { runCli } from './cli';

void runCli(process.argv.slice(2)).then((exitCode) => {
	process.exitCode = exitCode;
}).catch((error: unknown) => {
	process.stderr.write(`CLI failure: ${error instanceof Error ? error.message : String(error)}\n`);
	process.exitCode = 1;
});
