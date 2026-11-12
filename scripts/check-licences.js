// The licence gate: every package that ships in the image is under a licence
// on the allowlist below, or the check fails. CI runs it (`checks`).
//
//   node scripts/check-licences.js
//
// "Ships" is read from package-lock.json: every entry that is not a
// development dependency. For each, the licence is the `license` field of the
// installed package's own package.json; the lockfile's copy must agree where
// it has one. A package with no licence, with a licence that is not a plain
// identifier on the list, or that is not installed, fails: nothing is assumed.
//
// It reads two kinds of file and needs no dependency. Run `npm ci` first.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

/** Licences a production dependency may carry. An identifier, exactly: no expression is evaluated. */
const ALLOWED = Object.freeze(['0BSD', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'BlueOak-1.0.0', 'ISC', 'MIT', 'PSF-2.0', 'Python-2.0']);

/** scanent's own packages, and the licence each must state. */
const OWN_LICENCE = 'BUSL-1.1';
const isOwnPackage = (key) => /^packages\/[a-z0-9-]+$/.test(key);

/**
 * The production packages of a lockfile: every entry but the root, a
 * development dependency, and a workspace link (its target is listed itself).
 */
function productionPackages(lock) {
    const packages = lock !== null && typeof lock === 'object' ? lock.packages : undefined;
    if (packages === null || typeof packages !== 'object') throw new Error('the lockfile has no packages member');
    return Object.entries(packages)
        .filter(([key, entry]) => key !== '' && entry.dev !== true && entry.link !== true)
        .map(([key, entry]) => ({ key, name: key.replace(/^.*node_modules\//, ''), version: entry.version, lockLicence: entry.license }))
        .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

/**
 * Check every production package. `readManifest(key)` returns the parsed
 * package.json of the package installed at `key`, or null when it is absent.
 * Returns the packages checked and the problems found; no problem is a pass,
 * and an empty population is a problem.
 */
function checkLicences(lock, readManifest) {
    const checked = [];
    const problems = [];
    const packages = productionPackages(lock);
    if (packages.length === 0) problems.push('the lockfile lists no production package; nothing was checked');
    for (const pkg of packages) {
        const manifest = readManifest(pkg.key);
        if (manifest === null) {
            problems.push(`${pkg.key}: not installed, so its licence cannot be read (run npm ci)`);
            continue;
        }
        const licence = manifest.license;
        if (typeof licence !== 'string' || licence.trim() === '') {
            problems.push(`${pkg.key}: states no licence`);
            continue;
        }
        if (pkg.lockLicence !== undefined && pkg.lockLicence !== licence) {
            problems.push(`${pkg.key}: the lockfile says ${JSON.stringify(pkg.lockLicence)} and the package says ${JSON.stringify(licence)}`);
            continue;
        }
        if (isOwnPackage(pkg.key)) {
            if (licence !== OWN_LICENCE) problems.push(`${pkg.key}: scanent's own package states ${JSON.stringify(licence)}, not ${OWN_LICENCE}`);
        } else if (!ALLOWED.includes(licence)) {
            problems.push(`${pkg.key}: ${JSON.stringify(licence)} is not on the allowlist`);
        }
        checked.push({ key: pkg.key, name: pkg.name, version: pkg.version, licence });
    }
    return { checked, problems };
}

function main(root) {
    const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
    const readManifest = (key) => {
        try {
            return JSON.parse(fs.readFileSync(path.join(root, key, 'package.json'), 'utf8'));
        } catch {
            return null;
        }
    };
    const { checked, problems } = checkLicences(lock, readManifest);
    for (const pkg of checked) process.stdout.write(`${pkg.licence.padEnd(14)} ${pkg.name}@${pkg.version}\n`);
    if (problems.length > 0) {
        for (const problem of problems) process.stderr.write(`licence: ${problem}\n`);
        process.stderr.write(`licence: allowed for a dependency: ${ALLOWED.join(', ')}\n`);
        return 1;
    }
    process.stdout.write(`licences: ${checked.length} production packages, all allowed\n`);
    return 0;
}

module.exports = { ALLOWED, OWN_LICENCE, productionPackages, checkLicences };

if (require.main === module) process.exit(main(path.join(__dirname, '..')));
