// Writes docs/access.md from the access guide the wizard prints
// (packages/scanner/src/init/access-guide.ts), so the two cannot disagree.
// Run `npm run build` first: this requires the compiled module.
// A test compares the committed file with the same rendering.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const compiled = path.join(__dirname, '..', 'packages', 'scanner', 'dist', 'init', 'access-guide.js');
if (!fs.existsSync(compiled)) {
    process.stderr.write('scanent is not built yet: run `npm run build` first.\n');
    process.exit(2);
}
const { renderAccessMarkdown } = require(compiled);
fs.writeFileSync(path.join(__dirname, '..', 'docs', 'access.md'), renderAccessMarkdown());
