const fs = require('fs');

// TypeScript does not remove compiled tests whose source was deleted. Clear only
// the generated test directory so stale suites cannot run in the VS Code host.
fs.rmSync('out', { recursive: true, force: true });
