#!/usr/bin/env node
/**
 * The `scanent-probe` command: the active flavour's own entry point, never a
 * mode of `scanent` (docs/design/active-flavour.md, decision 1).
 *
 * A committed launcher, as `packages/scanner/bin/scanent.js` is, so the
 * command exists after `npm ci` and survives a clean rebuild. It holds no
 * logic of its own.
 */
'use strict';

const path = require('node:path');

const compiled = path.join(__dirname, '..', 'dist', 'cli.js');
if (!require('node:fs').existsSync(compiled)) {
    process.stderr.write('scanent-probe is not built yet: run `npm run build && npm run build:probe` in the repository root first.\n');
    process.exit(2);
}
require(compiled).run();
