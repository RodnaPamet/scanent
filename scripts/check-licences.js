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
// ONE KIND OF EXCEPTION, and it is not an assumption either. A package whose
// manifest states no licence, but whose licence file does, may be listed in
// LICENCE_READ_FROM_FILE with the exact version that was read, the file, and
// the words that file must hold. The gate then reads that file of the
// installed package and accepts the licence only when the words are there. A
// new version of the package is not covered and fails until somebody reads
// its file again.
//
// It reads two kinds of file and needs no dependency. Run `npm ci` first.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

/** Licences a production dependency may carry. An identifier, exactly: no expression is evaluated. */
const ALLOWED = Object.freeze(['0BSD', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'BlueOak-1.0.0', 'ISC', 'MIT', 'PSF-2.0', 'Python-2.0']);

/**
 * Packages whose manifest states no licence, read from their licence file
 * instead. Each entry names the exact version read, the file, and text that
 * file must contain; the licence must itself be on the allowlist.
 *
 *   png-js 2.0.0   a dependency of pdfkit (report.pdf). Its package.json has no
 *                  `license` field; its LICENSE file is the MIT License,
 *                  "Copyright (c) 2017 Devon Govett".
 */
const LICENCE_READ_FROM_FILE = Object.freeze({
    'png-js': Object.freeze({
        version: '2.0.0',
        licence: 'MIT',
        file: 'LICENSE',
        mustContain: Object.freeze(['MIT License', 'Permission is hereby granted, free of charge, to any person obtaining a copy']),
    }),
});

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
 * The licence a package's licence file states, for a package listed in
 * LICENCE_READ_FROM_FILE at the version read; null otherwise, or when the
 * file cannot be read or lacks the words.
 */
function licenceFromFile(pkg, readText) {
    const entry = Object.prototype.hasOwnProperty.call(LICENCE_READ_FROM_FILE, pkg.name) ? LICENCE_READ_FROM_FILE[pkg.name] : undefined;
    if (entry === undefined || entry.version !== pkg.version || readText === undefined) return null;
    const text = readText(pkg.key, entry.file);
    if (typeof text !== 'string') return null;
    return entry.mustContain.every((words) => text.includes(words)) ? entry.licence : null;
}

/**
 * Check every production package. `readManifest(key)` returns the parsed
 * package.json of the package installed at `key`, or null when it is absent.
 * `readText(key, file)`, when given, returns a file of that package as text,
 * or null; it is read only for a package LICENCE_READ_FROM_FILE lists.
 * Returns the packages checked and the problems found; no problem is a pass,
 * and an empty population is a problem.
 */
function checkLicences(lock, readManifest, readText) {
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
        let licence = manifest.license;
        if (typeof licence !== 'string' || licence.trim() === '') {
            licence = licenceFromFile(pkg, readText);
            if (licence === null) {
                problems.push(`${pkg.key}: states no licence`);
                continue;
            }
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
    const readText = (key, file) => {
        try {
            return fs.readFileSync(path.join(root, key, file), 'utf8');
        } catch {
            return null;
        }
    };
    const { checked, problems } = checkLicences(lock, readManifest, readText);
    for (const pkg of checked) process.stdout.write(`${pkg.licence.padEnd(14)} ${pkg.name}@${pkg.version}\n`);
    if (problems.length > 0) {
        for (const problem of problems) process.stderr.write(`licence: ${problem}\n`);
        process.stderr.write(`licence: allowed for a dependency: ${ALLOWED.join(', ')}\n`);
        return 1;
    }
    process.stdout.write(`licences: ${checked.length} production packages, all allowed\n`);
    return 0;
}

module.exports = { ALLOWED, OWN_LICENCE, LICENCE_READ_FROM_FILE, productionPackages, checkLicences };

if (require.main === module) process.exit(main(path.join(__dirname, '..')));
