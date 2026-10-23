import { runCoreRuntime } from './coreRuntime';
import { CORE_PROTOCOL_VERSION, CoreMessage } from './protocol';
import { frameCoreProtocolBytes } from './protocolFraming';

const coreVersion = process.env.AQIRON_CORE_VERSION ?? '0.0.1';

async function main(): Promise<void> {
	process.stderr.write(`[${new Date().toISOString()}] [aqiron-core-runtime] starting\n`);
	const frames = frameCoreProtocolBytes(process.stdin);
	const write = (message: CoreMessage): void => {
		process.stdout.write(`${JSON.stringify(message)}\n`);
	};
	try {
		// Real-provider synthesis remains disabled by CoreRuntime's fixed source
		// gate. This entry point exposes no executor, transport, or gate override.
		await runCoreRuntime(frames, write, { coreVersion, protocolVersion: CORE_PROTOCOL_VERSION });
	} catch (error) {
		process.stderr.write(`[${new Date().toISOString()}] [aqiron-core-runtime] fatal ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
		process.exitCode = 1;
	} finally {
		process.stderr.write(`[${new Date().toISOString()}] [aqiron-core-runtime] stopped\n`);
	}
}

void main();
