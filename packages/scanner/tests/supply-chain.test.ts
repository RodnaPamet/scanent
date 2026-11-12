/**
 * The two supply-chain scripts CI runs, each proved on inputs made here:
 *
 *   scripts/check-licences.js           every production package is under an
 *                                       allowed licence, or the check fails
 *   scripts/check-reproducible-build.js two builds give the same files
 *
 * CI runs the scripts for real. These cases prove the detectors: a lockfile
 * with a licence that is not allowed, a missing one, a package that is not
 * installed; two build trees that are the same, differ by one byte, or differ
 * by one file. The real two-build comparison takes two compiles and is not
 * part of `npm test`.
 */
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const REPO = path.resolve(__dirname, '../../..');

interface LicenceCheck {
    ALLOWED: readonly string[];
    OWN_LICENCE: string;
    productionPackages(lock: unknown): { key: string; name: string; version: string; lockLicence?: string }[];
    checkLicences(lock: unknown, readManifest: (key: string) => { license?: unknown } | null): { checked: { key: string; licence: string }[]; problems: string[] };
}
interface ReproducibleBuild {
    hashBuild(root: string): Map<string, string>;
    compareBuilds(first: Map<string, string>, second: Map<string, string>): { same: boolean; files: number; difference: null | { file: string | null; kind: string } };
}

// eslint-disable-next-line @typescript-eslint/no-require-imports
const licences = require(path.join(REPO, 'scripts/check-licences.js')) as LicenceCheck;
// eslint-disable-next-line @typescript-eslint/no-require-imports
const reproducible = require(path.join(REPO, 'scripts/check-reproducible-build.js')) as ReproducibleBuild;

describe('scripts/check-licences.js', () => {
    /** A lockfile of the repository's shape: the root, three workspace packages and their links, two dependencies, one development dependency. */
    const lock = (over: Record<string, Record<string, unknown> | undefined> = {}) => {
        const packages: Record<string, Record<string, unknown> | undefined> = {
            '': { name: 'scanent', workspaces: ['packages/contract'] },
            'node_modules/@rodnapamet/scanent-contract': { resolved: 'packages/contract', link: true },
            'node_modules/zod': { version: '4.0.0', license: 'MIT' },
            'node_modules/typescript': { version: '5.9.3', license: 'Apache-2.0' },
            'node_modules/jest': { version: '30.0.0', license: 'GPL-3.0', dev: true },
            'packages/contract': { version: '0.0.0', license: 'BUSL-1.1' },
            'packages/scanner/node_modules/js-yaml': { version: '5.0.0', license: 'MIT' },
            ...over,
        };
        for (const key of Object.keys(packages)) if (packages[key] === undefined) delete packages[key];
        return { lockfileVersion: 3, packages };
    };
    /** What is installed: each package's own manifest, by default agreeing with the lockfile. */
    const installed = (over: Record<string, { license?: unknown } | null> = {}) => (key: string) => {
        if (key in over) return over[key];
        const entry = lock().packages[key];
        return entry === undefined ? null : { license: entry.license };
    };

    it('takes the production packages: not the root, not a development dependency, not a workspace link', () => {
        expect(licences.productionPackages(lock()).map((p) => p.key)).toEqual([
            'node_modules/typescript',
            'node_modules/zod',
            'packages/contract',
            'packages/scanner/node_modules/js-yaml',
        ]);
        expect(licences.productionPackages(lock()).find((p) => p.key.endsWith('js-yaml'))?.name).toBe('js-yaml');
    });

    it('passes when every one is allowed, and says which it checked', () => {
        const { checked, problems } = licences.checkLicences(lock(), installed());
        expect(problems).toEqual([]);
        expect(checked.map((c) => `${c.key} ${c.licence}`)).toEqual([
            'node_modules/typescript Apache-2.0',
            'node_modules/zod MIT',
            'packages/contract BUSL-1.1',
            'packages/scanner/node_modules/js-yaml MIT',
        ]);
    });

    it.each([
        ['a licence that is not on the list', { 'node_modules/zod': { license: 'GPL-3.0' } }, { 'node_modules/zod': { version: '4.0.0', license: 'GPL-3.0' } }, 'node_modules/zod: "GPL-3.0" is not on the allowlist'],
        ['a licence the lockfile does not record', { 'node_modules/zod': { license: 'GPL-3.0' } }, { 'node_modules/zod': { version: '4.0.0' } }, 'node_modules/zod: "GPL-3.0" is not on the allowlist'],
        [
            'an expression, which is not evaluated',
            { 'node_modules/zod': { license: '(MIT OR GPL-3.0)' } },
            { 'node_modules/zod': { version: '4.0.0', license: '(MIT OR GPL-3.0)' } },
            'node_modules/zod: "(MIT OR GPL-3.0)" is not on the allowlist',
        ],
        ['no licence', { 'node_modules/zod': {} }, {}, 'node_modules/zod: states no licence'],
        ['a blank licence', { 'node_modules/zod': { license: '  ' } }, {}, 'node_modules/zod: states no licence'],
        ['a licence that is not text', { 'node_modules/zod': { license: { type: 'MIT' } } }, {}, 'node_modules/zod: states no licence'],
        ['a package that is not installed', { 'node_modules/zod': null }, {}, 'node_modules/zod: not installed, so its licence cannot be read (run npm ci)'],
        ['a package whose lockfile entry and manifest disagree', { 'node_modules/zod': { license: 'ISC' } }, {}, 'node_modules/zod: the lockfile says "MIT" and the package says "ISC"'],
        ['scanent\'s own package under another licence', { 'packages/contract': { license: 'MIT' } }, { 'packages/contract': { version: '0.0.0', license: 'MIT' } }, 'packages/contract: scanent\'s own package states "MIT", not BUSL-1.1'],
        ['a dependency under scanent\'s own licence', { 'node_modules/zod': { license: 'BUSL-1.1' } }, { 'node_modules/zod': { version: '4.0.0', license: 'BUSL-1.1' } }, 'node_modules/zod: "BUSL-1.1" is not on the allowlist'],
    ])('fails on %s', (_name, manifests, lockOver, problem) => {
        const { problems } = licences.checkLicences(lock(lockOver), installed(manifests));
        expect(problems).toEqual([problem]);
    });

    it('fails when nothing was checked, and on a lockfile that is not one', () => {
        const none = lock({ 'node_modules/zod': undefined, 'node_modules/typescript': undefined, 'packages/contract': undefined, 'packages/scanner/node_modules/js-yaml': undefined });
        expect(licences.checkLicences(none, installed()).problems).toEqual(['the lockfile lists no production package; nothing was checked']);
        expect(() => licences.checkLicences({}, installed())).toThrow('the lockfile has no packages member');
        expect(() => licences.checkLicences(null, installed())).toThrow('the lockfile has no packages member');
    });

    it('a development dependency under any licence does not fail it, and a new production one does', () => {
        expect(licences.checkLicences(lock(), installed()).problems).toEqual([]);
        const moved = lock({ 'node_modules/jest': { version: '30.0.0', license: 'GPL-3.0' } });
        expect(licences.checkLicences(moved, (key) => ({ license: moved.packages[key]?.license })).problems).toEqual(['node_modules/jest: "GPL-3.0" is not on the allowlist']);
    });

    it('allows permissive licences only, by exact name', () => {
        expect([...licences.ALLOWED].sort()).toEqual(['0BSD', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'BlueOak-1.0.0', 'ISC', 'MIT', 'PSF-2.0', 'Python-2.0']);
        expect(licences.ALLOWED.some((l) => /GPL|AGPL|SSPL|BUSL|UNLICENSED/i.test(l))).toBe(false);
        expect(licences.OWN_LICENCE).toBe('BUSL-1.1');
    });

    it('passes on this repository as installed, over the packages the image carries', () => {
        const out = execFileSync(process.execPath, [path.join(REPO, 'scripts/check-licences.js')], { encoding: 'utf8' });
        expect(out).toMatch(/licences: \d+ production packages, all allowed\n$/);
        // What the image's build copies: the three packages and the four dependencies they declare.
        const names = out
            .trim()
            .split('\n')
            .slice(0, -1)
            .map((line) => line.replace(/^\S+\s+/, '').replace(/@[^@]+$/, ''))
            .sort();
        expect(names).toEqual(['argparse', 'js-yaml', 'packages/contract', 'packages/report', 'packages/scanner', 'typescript', 'zod']);
    });
});

describe('scripts/check-reproducible-build.js', () => {
    let dir: string;
    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-repro-test-'));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    /** A build tree: `packages/<name>/dist/<file>` for each entry. */
    function tree(name: string, files: Record<string, string>): string {
        const root = path.join(dir, name);
        for (const [rel, content] of Object.entries(files)) {
            fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
            fs.writeFileSync(path.join(root, rel), content);
        }
        return root;
    }
    const FILES = {
        'packages/contract/dist/cidr.js': 'exports.a = 1;\n',
        'packages/report/dist/render/html.js': 'exports.b = 2;\n',
        'packages/scanner/dist/cli.js': 'exports.c = 3;\n',
        'packages/scanner/dist/sources/code/files.js': 'exports.d = 4;\n',
    };

    it('hashes every file under each package\'s dist, by its path from the root, and nothing else', () => {
        const root = tree('a', { ...FILES, 'packages/scanner/src/cli.ts': 'source', 'packages/other/dist/x.js': 'not one of the three', 'README.md': 'x' });
        const hashes = reproducible.hashBuild(root);
        expect([...hashes.keys()].sort()).toEqual(Object.keys(FILES).sort());
        for (const hash of hashes.values()) expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('two trees with the same files, at different paths, are the same', () => {
        const a = reproducible.hashBuild(tree('a', FILES));
        const b = reproducible.hashBuild(tree('b/deeper/still', FILES));
        expect(reproducible.compareBuilds(a, b)).toEqual({ same: true, files: 4, difference: null });
    });

    it('one byte of one file is a difference, and the file is named', () => {
        const a = reproducible.hashBuild(tree('a', FILES));
        const b = reproducible.hashBuild(tree('b', { ...FILES, 'packages/scanner/dist/cli.js': 'exports.c = 4;\n' }));
        expect(reproducible.compareBuilds(a, b)).toEqual({ same: false, files: 4, difference: { file: 'packages/scanner/dist/cli.js', kind: 'CONTENT' } });
    });

    it('a file only one build wrote is a difference, either way round', () => {
        const a = reproducible.hashBuild(tree('a', FILES));
        const { 'packages/report/dist/render/html.js': _dropped, ...fewer } = FILES;
        const b = reproducible.hashBuild(tree('b', fewer));
        expect(reproducible.compareBuilds(a, b).difference).toEqual({ file: 'packages/report/dist/render/html.js', kind: 'ONLY_IN_FIRST' });
        expect(reproducible.compareBuilds(b, a).difference).toEqual({ file: 'packages/report/dist/render/html.js', kind: 'ONLY_IN_SECOND' });
    });

    it('two builds that wrote nothing are not the same build: nothing compared is nothing proved', () => {
        const empty = reproducible.hashBuild(tree('empty', { 'README.md': 'x' }));
        expect(empty.size).toBe(0);
        expect(reproducible.compareBuilds(empty, empty)).toEqual({ same: false, files: 0, difference: { file: null, kind: 'EMPTY_BUILD' } });
        expect(reproducible.compareBuilds(reproducible.hashBuild(tree('a', FILES)), empty).same).toBe(false);
    });

    it('the script builds twice, in two places, under two time zones and two clocks', () => {
        const script = fs.readFileSync(path.join(REPO, 'scripts/check-reproducible-build.js'), 'utf8');
        expect(script).toContain("build(first, { TZ: 'UTC', SOURCE_DATE_EPOCH: '1' });");
        expect(script).toContain("build(second, { TZ: 'Pacific/Auckland', SOURCE_DATE_EPOCH: '315532800' });");
        expect(script).toContain("const second = path.join(work, 'a-second-build', 'at', 'another', 'depth');");
        // It compiles the three packages the image's build compiles.
        const rootBuild = (JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8')) as { scripts: { build: string } }).scripts.build;
        expect(rootBuild).toBe('tsc -b packages/contract packages/report packages/scanner');
        expect(script).toContain("const PACKAGES = ['contract', 'report', 'scanner'];");
    });
});
