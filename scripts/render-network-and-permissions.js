// Writes docs/network-and-permissions.md from the surface the scanner declares
// (packages/scanner/src/scanner-surface.ts) and the access guide, through
// packages/scanner/src/surface-doc.ts, so the document cannot say more or less
// than the code does. Run `npm run build` first: this requires the compiled
// module. A test compares the committed file with the same rendering.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const compiled = path.join(__dirname, '..', 'packages', 'scanner', 'dist', 'surface-doc.js');
if (!fs.existsSync(compiled)) {
    process.stderr.write('scanent is not built yet: run `npm run build` first.\n');
    process.exit(2);
}
const { renderNetworkAndPermissionsMarkdown } = require(compiled);
fs.writeFileSync(path.join(__dirname, '..', 'docs', 'network-and-permissions.md'), renderNetworkAndPermissionsMarkdown());
