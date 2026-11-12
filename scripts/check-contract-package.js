// The contract package check: the tarball `npm pack` made of
// packages/contract holds the compiled contract, its manifest, README.md,
// LICENSE and NOTICE, and nothing else. The release workflow runs it on the
// tarball it is about to publish (`contract-package`).
//
//   (cd packages/contract && npm pack --pack-destination <dir>)
//   node scripts/check-contract-package.js <dir>/rodnapamet-scanent-contract-<version>.tgz [--version <version>]
//
// What it holds the tarball to:
//
//   - its entries are exactly `dist/<module>.js` and `dist/<module>.d.ts` for
//     each file under packages/contract/src, and the four files above. No
//     source map, no test, no TypeScript source, no build record, and no
//     compiled file whose source is gone;
//   - every entry is a regular file under `package/`;
//   - the manifest names the package, is not private, publishes to GitHub
//     Packages, points at this repository, and carries the version asked for;
//   - LICENSE and NOTICE are the repository's own, byte for byte;
//   - no file refers to a source map, and none holds the path of the
//     directory it was built in, of this checkout, or of a home directory.
//
// It reads the tarball itself (gzip, then the tar headers) and needs no
// dependency and no `tar` on the path.
'use strict';

const { Buffer } = require('node:buffer');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const PACKAGE_NAME = '@rodnapamet/scanent-contract';
const REGISTRY = 'https://npm.pkg.github.com';
const REPOSITORY_URL = 'https://github.com/RodnaPamet/scanent.git';
const REPOSITORY_DIRECTORY = 'packages/contract';
/** What a package carries beside its compiled files. */
const FIXED_FILES = Object.freeze(['LICENSE', 'NOTICE', 'README.md', 'package.json']);

/** Every `.ts` file under a source directory, as paths from it with `/`, sorted. */
function sourceModules(srcDir) {
    const out = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const child = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(child);
            else if (entry.isFile() && entry.name.endsWith('.ts')) out.push(path.relative(srcDir, child).split(path.sep).join('/'));
        }
    };
    walk(srcDir);
    return out.sort();
}

/** The files a package made from these source modules holds, as paths inside the package, sorted. */
function expectedFiles(modules) {
    const compiled = modules.flatMap((file) => {
        const stem = file.replace(/\.ts$/, '');
        return [`dist/${stem}.d.ts`, `dist/${stem}.js`];
    });
    return [...FIXED_FILES, ...compiled].sort();
}

/** What kind of file a path is, when it is one a package must not hold. */
function unwantedKind(file) {
    if (/\.map$/.test(file)) return 'a source map';
    if (/(^|\/)(tests?|__tests__|fixtures)\//.test(file) || /\.(test|spec)\.[a-z]+$/.test(file)) return 'a test';
    if (/\.tsbuildinfo$/.test(file)) return 'a build record';
    if (/\.ts$/.test(file) && !/\.d\.ts$/.test(file)) return 'TypeScript source';
    return 'not a file of the package';
}

/** Compare the files a package holds with the files it should. Returns the problems; none is a pass. */
function checkFiles(files, expected) {
    const problems = [];
    if (expected.length <= FIXED_FILES.length) problems.push('no source module was found, so nothing compiled is expected; nothing was checked');
    const have = new Set(files);
    const want = new Set(expected);
    for (const file of [...have].sort()) if (!want.has(file)) problems.push(`${file}: ${unwantedKind(file)}`);
    for (const file of expected) if (!have.has(file)) problems.push(`${file}: missing`);
    if (new Set(files).size !== files.length) problems.push('a file is listed twice');
    return problems;
}

/**
 * Read a gzipped tar archive. Returns its regular files, by name, and a
 * problem for every entry that is anything else: a link, a device, an
 * extended header. A directory entry is passed over.
 */
function readTarball(buffer) {
    const files = new Map();
    const problems = [];
    let tar;
    try {
        tar = zlib.gunzipSync(buffer);
    } catch {
        return { files, problems: ['the file is not a gzipped archive'] };
    }
    const text = (block, from, length) => {
        const field = block.subarray(from, from + length);
        const end = field.indexOf(0);
        return field.subarray(0, end < 0 ? length : end).toString('utf8');
    };
    let offset = 0;
    while (offset + 512 <= tar.length) {
        const header = tar.subarray(offset, offset + 512);
        if (header.every((byte) => byte === 0)) break;
        const prefix = text(header, 345, 155);
        const name = (prefix === '' ? '' : `${prefix}/`) + text(header, 0, 100);
        const size = Number.parseInt(text(header, 124, 12).trim() || '0', 8);
        const type = String.fromCharCode(header[156] === 0 ? 0x30 : header[156]);
        if (!Number.isInteger(size) || size < 0 || offset + 512 + size > tar.length) {
            problems.push(`${name}: the archive is cut short`);
            break;
        }
        if (type === '0') {
            if (files.has(name)) problems.push(`${name}: in the archive twice`);
            files.set(name, tar.subarray(offset + 512, offset + 512 + size));
        } else if (type !== '5') {
            problems.push(`${name}: not a regular file (tar type ${JSON.stringify(type)})`);
        }
        offset += 512 + Math.ceil(size / 512) * 512;
    }
    if (files.size === 0 && problems.length === 0) problems.push('the archive holds no file');
    return { files, problems };
}

/**
 * Check a package's files, given as `path inside the package -> bytes`.
 *
 *   expected        the files it should hold (`expectedFiles`)
 *   licence, notice the repository's LICENSE and NOTICE
 *   version         the version the manifest must carry, or undefined to accept any
 *   forbiddenPaths  directory paths no file may contain
 */
function checkPackage(files, { expected, licence, notice, version, forbiddenPaths = [] }) {
    const problems = checkFiles([...files.keys()], expected);

    const manifestBytes = files.get('package.json');
    let manifest = null;
    try {
        manifest = manifestBytes === undefined ? null : JSON.parse(manifestBytes.toString('utf8'));
    } catch {
        problems.push('package.json: not JSON');
    }
    if (manifest !== null && typeof manifest === 'object') {
        if (manifest.name !== PACKAGE_NAME) problems.push(`package.json: the name is ${JSON.stringify(manifest.name)}, not ${PACKAGE_NAME}`);
        if (manifest.private !== undefined) problems.push('package.json: marked private, so it cannot be published');
        if (typeof manifest.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(manifest.version)) {
            problems.push(`package.json: the version ${JSON.stringify(manifest.version)} is not MAJOR.MINOR.PATCH`);
        } else if (version !== undefined && manifest.version !== version) {
            problems.push(`package.json: the version is ${manifest.version}, not ${version}`);
        }
        if (manifest.license !== 'BUSL-1.1') problems.push(`package.json: the licence is ${JSON.stringify(manifest.license)}, not BUSL-1.1`);
        if ((manifest.publishConfig ?? {}).registry !== REGISTRY) problems.push(`package.json: publishConfig.registry is not ${REGISTRY}`);
        const repository = manifest.repository ?? {};
        if (repository.url !== REPOSITORY_URL) problems.push(`package.json: repository.url is not ${REPOSITORY_URL}`);
        if (repository.directory !== REPOSITORY_DIRECTORY) problems.push(`package.json: repository.directory is not ${REPOSITORY_DIRECTORY}`);
    }

    for (const [name, mine] of [['LICENSE', licence], ['NOTICE', notice]]) {
        const theirs = files.get(name);
        if (theirs !== undefined && !Buffer.from(theirs).equals(Buffer.from(mine))) problems.push(`${name}: not the repository's ${name}`);
    }

    const paths = forbiddenPaths.filter((p) => typeof p === 'string' && p.length > 1);
    for (const [name, bytes] of [...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
        const content = bytes.toString('utf8');
        if (content.includes('sourceMappingURL')) problems.push(`${name}: refers to a source map`);
        for (const forbidden of paths) {
            if (content.includes(forbidden)) problems.push(`${name}: holds the path of a directory on the machine that built it`);
        }
    }
    return problems;
}

/** Check a tarball as `npm pack` writes one: every entry under `package/`, then `checkPackage`. */
function checkTarball(buffer, options) {
    const { files: entries, problems } = readTarball(buffer);
    const files = new Map();
    for (const [name, bytes] of entries) {
        if (!name.startsWith('package/') || name.split('/').includes('..')) problems.push(`${name}: not under package/`);
        else files.set(name.slice('package/'.length), bytes);
    }
    return { files, problems: [...problems, ...checkPackage(files, options)] };
}

function main(repo, argv) {
    const at = argv.indexOf('--version');
    const version = at < 0 ? undefined : argv[at + 1];
    const rest = argv.filter((_, i) => at < 0 || (i !== at && i !== at + 1));
    if (rest.length !== 1 || (at >= 0 && version === undefined)) {
        process.stderr.write('usage: node scripts/check-contract-package.js <tarball> [--version <version>]\n');
        return 2;
    }
    const tarball = path.resolve(rest[0]);
    const buffer = fs.readFileSync(tarball);
    const { files, problems } = checkTarball(buffer, {
        expected: expectedFiles(sourceModules(path.join(repo, 'packages', 'contract', 'src'))),
        licence: fs.readFileSync(path.join(repo, 'LICENSE')),
        notice: fs.readFileSync(path.join(repo, 'NOTICE')),
        version,
        forbiddenPaths: [repo, fs.realpathSync(repo), path.dirname(tarball), os.homedir(), process.env.RUNNER_TEMP, process.env.GITHUB_WORKSPACE],
    });
    for (const [name, bytes] of [...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
        process.stdout.write(`${String(bytes.length).padStart(7)}  ${name}\n`);
    }
    if (problems.length > 0) {
        for (const problem of problems) process.stderr.write(`contract package: ${problem}\n`);
        return 1;
    }
    const manifest = JSON.parse(files.get('package.json').toString('utf8'));
    process.stdout.write(`sha256:${crypto.createHash('sha256').update(buffer).digest('hex')}  ${path.basename(tarball)}\n`);
    process.stdout.write(`contract package: ${manifest.name}@${manifest.version}, ${files.size} files, nothing else\n`);
    return 0;
}

module.exports = { PACKAGE_NAME, REGISTRY, REPOSITORY_URL, FIXED_FILES, sourceModules, expectedFiles, checkFiles, readTarball, checkPackage, checkTarball };

if (require.main === module) process.exit(main(path.join(__dirname, '..'), process.argv.slice(2)));
