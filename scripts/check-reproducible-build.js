// The reproducible-build check: two builds of the same source give the same
// compiled files, byte for byte. CI runs it (`checks`).
//
//   node scripts/check-reproducible-build.js
//
// The source is copied to two new directories of different names and depths.
// Each copy is built with the copy's own compiler, one in UTC at the clock's
// first second, the other in a zone thirteen hours away and ten years later.
// Every file under packages/*/dist is hashed, and the two lists compared. The
// first file that differs, or that only one build wrote, is printed.
//
// The working tree is not touched: no `dist` of yours is cleaned or replaced.
// Run `npm ci` first; the copies take their node_modules from here.
//
// What this covers is the compiled JavaScript that goes into the image. It
// does not claim two image builds give the same digest: layer timestamps and
// the installed tree's metadata differ between builds.
'use strict';

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PACKAGES = ['contract', 'report', 'scanner'];

/** `relative path -> sha256` for every file under each package's dist, relative to `root`. */
function hashBuild(root) {
    const out = new Map();
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const child = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(child);
            else if (entry.isFile()) {
                out.set(path.relative(root, child).split(path.sep).join('/'), crypto.createHash('sha256').update(fs.readFileSync(child)).digest('hex'));
            }
        }
    };
    for (const name of PACKAGES) {
        const dist = path.join(root, 'packages', name, 'dist');
        if (fs.existsSync(dist)) walk(dist);
    }
    return out;
}

/**
 * Compare two builds. Same only when both hold at least one file, the same
 * files, with the same hashes. Otherwise the first difference by path.
 */
function compareBuilds(first, second) {
    if (first.size === 0 || second.size === 0) return { same: false, files: 0, difference: { file: null, kind: 'EMPTY_BUILD' } };
    const names = [...new Set([...first.keys(), ...second.keys()])].sort();
    for (const file of names) {
        if (!second.has(file)) return { same: false, files: names.length, difference: { file, kind: 'ONLY_IN_FIRST' } };
        if (!first.has(file)) return { same: false, files: names.length, difference: { file, kind: 'ONLY_IN_SECOND' } };
        if (first.get(file) !== second.get(file)) return { same: false, files: names.length, difference: { file, kind: 'CONTENT' } };
    }
    return { same: true, files: names.length, difference: null };
}

/** Copy what a build reads: the manifests, the compiler settings, each package's source, and node_modules with its links as they are. */
function copySource(repo, target) {
    fs.mkdirSync(target, { recursive: true });
    for (const file of ['package.json', 'package-lock.json', 'tsconfig.base.json', 'tsconfig.json']) fs.copyFileSync(path.join(repo, file), path.join(target, file));
    // A package's own earlier build, its tests and its build record stay behind;
    // a dependency's `dist` under the package's node_modules does not.
    const left = PACKAGES.flatMap((name) => ['dist', 'tests', 'coverage', 'tsconfig.tsbuildinfo'].map((entry) => path.join(repo, 'packages', name, entry)));
    fs.cpSync(path.join(repo, 'packages'), path.join(target, 'packages'), {
        recursive: true,
        verbatimSymlinks: true,
        filter: (source) => !left.includes(source),
    });
    fs.cpSync(path.join(repo, 'node_modules'), path.join(target, 'node_modules'), { recursive: true, verbatimSymlinks: true });
}

function build(root, env) {
    const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
    const run = spawnSync(process.execPath, [tsc, '-b', ...PACKAGES.map((name) => `packages/${name}`)], {
        cwd: root,
        env: { ...process.env, ...env },
        encoding: 'utf8',
    });
    if (run.status !== 0) throw new Error(`the build in ${root} failed:\n${run.stdout}${run.stderr}`);
}

function main(repo) {
    if (!fs.existsSync(path.join(repo, 'node_modules', 'typescript'))) {
        process.stderr.write('reproducible build: run `npm ci` first.\n');
        return 2;
    }
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-repro-'));
    try {
        const first = path.join(work, 'a');
        const second = path.join(work, 'a-second-build', 'at', 'another', 'depth');
        copySource(repo, first);
        copySource(repo, second);
        build(first, { TZ: 'UTC', SOURCE_DATE_EPOCH: '1' });
        build(second, { TZ: 'Pacific/Auckland', SOURCE_DATE_EPOCH: '315532800' });
        const result = compareBuilds(hashBuild(first), hashBuild(second));
        if (!result.same) {
            const { file, kind } = result.difference;
            process.stderr.write(`reproducible build: FAILED. ${kind}${file === null ? '' : `: ${file}`}\n`);
            return 1;
        }
        process.stdout.write(`reproducible build: ${result.files} files, the same from two builds in two places\n`);
        return 0;
    } finally {
        fs.rmSync(work, { recursive: true, force: true });
    }
}

module.exports = { hashBuild, compareBuilds };

if (require.main === module) process.exit(main(path.join(__dirname, '..')));
