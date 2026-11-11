#!/usr/bin/env node
/**
 * The `scanent` and `aes` commands.
 *
 * A committed launcher rather than a `bin` entry pointing into `dist/`: npm
 * links a bin when it installs, which is before `npm run build` has written
 * `dist/`, and `tsc` writes `dist/cli.js` without the execute bit. This file
 * exists and is executable in every checkout, so both commands are there
 * after `npm ci` and survive a clean rebuild.
 *
 * It holds no logic of its own: it starts the compiled command line through
 * the same `run` that `node dist/cli.js` uses.
 */
'use strict';

const path = require('node:path');

const compiled = path.join(__dirname, '..', 'dist', 'cli.js');
if (!require('node:fs').existsSync(compiled)) {
    process.stderr.write('scanent is not built yet: run `npm run build` in the repository root first.\n');
    process.exit(2);
}
require(compiled).run();
