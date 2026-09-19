import * as readline from 'node:readline';
import { runCoreRuntime } from './coreRuntime';
import { CORE_PROTOCOL_VERSION, CoreMessage } from './protocol';

const coreVersion = process.env.AQIRON_CORE_VERSION ?? '0.0.1';

async function main(): Promise<void> {
	process.stderr.write(`[${new Date().toISOString()}] [aqiron-core-runtime] starting\n`);
	const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
	const lines = (async function* () {
		for await (const line of rl) {
			yield line;
		}
	})();
	const write = (message: CoreMessage): void => {
		process.stdout.write(`${JSON.stringify(message)}\n`);
	};
	try {
		await runCoreRuntime(lines, write, { coreVersion, protocolVersion: CORE_PROTOCOL_VERSION });
	} catch (error) {
		process.stderr.write(`[${new Date().toISOString()}] [aqiron-core-runtime] fatal ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
		process.exitCode = 1;
	} finally {
		rl.close();
		process.stderr.write(`[${new Date().toISOString()}] [aqiron-core-runtime] stopped\n`);
	}
}

void main();
