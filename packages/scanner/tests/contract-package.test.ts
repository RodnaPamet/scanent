/**
 * The report contract as a published package: `@rodnapamet/scanent-contract`.
 *
 * Four things are held here.
 *
 *   The manifest   the name GitHub Packages needs, the registry, the version
 *                  (the scanner's), and the licence files beside it.
 *   The tarball    `npm pack` is run, for real, on a copy of the package made
 *                  in a temporary directory, with the package's tests and its
 *                  source beside it. What it lists (`--dry-run`) and what it
 *                  writes hold the compiled contract, package.json, README.md,
 *                  LICENSE and NOTICE, and nothing else: no source map, no
 *                  test, no TypeScript source, no path of the machine.
 *   The check      scripts/check-contract-package.js, which the release
 *                  workflow runs on the tarball it publishes, proved on
 *                  tarballs that hold what must not be published.
 *   The workflow   release.yml packs and checks in a job that cannot publish,
 *                  and publishes, on a release tag only, the tarball that job
 *                  checked.
 *
 * Nothing is published by any of this: no command here reaches a registry.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';

import * as yaml from 'js-yaml';

import { SCANNER_VERSION } from '../src/scanner-surface';

jest.setTimeout(300_000);

const REPO = path.resolve(__dirname, '../../..');
const read = (rel: string): string => fs.readFileSync(path.join(REPO, rel), 'utf8');
const json = <T>(rel: string): T => JSON.parse(read(rel)) as T;

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

interface CheckOptions {
    expected: string[];
    licence: Buffer;
    notice: Buffer;
    version?: string;
    forbiddenPaths?: (string | undefined)[];
}
interface PackageCheck {
    PACKAGE_NAME: string;
    REGISTRY: string;
    REPOSITORY_URL: string;
    FIXED_FILES: readonly string[];
    sourceModules(srcDir: string): string[];
    expectedFiles(modules: string[]): string[];
    checkFiles(files: string[], expected: string[]): string[];
    readTarball(buffer: Buffer): { files: Map<string, Buffer>; problems: string[] };
    checkPackage(files: Map<string, Buffer>, options: CheckOptions): string[];
    checkTarball(buffer: Buffer, options: CheckOptions): { files: Map<string, Buffer>; problems: string[] };
}
// eslint-disable-next-line @typescript-eslint/no-require-imports
const check = require(path.join(REPO, 'scripts/check-contract-package.js')) as PackageCheck;

interface Manifest {
    name: string;
    version: string;
    private?: boolean;
    license: string;
    repository?: { type: string; url: string; directory: string };
    publishConfig?: { registry: string };
    files?: string[];
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    exports?: Record<string, unknown>;
}
const manifest = json<Manifest>('packages/contract/package.json');
const TARBALL = `rodnapamet-scanent-contract-${SCANNER_VERSION}.tgz`;
const MODULES = check.sourceModules(path.join(REPO, 'packages/contract/src'));
const EXPECTED = check.expectedFiles(MODULES);
const LICENCE = fs.readFileSync(path.join(REPO, 'LICENSE'));
const NOTICE = fs.readFileSync(path.join(REPO, 'NOTICE'));

/** The environment a command run from a clean shell has: nothing an enclosing `npm run` set. */
function cleanEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {};
    for (const [key, value] of Object.entries(process.env)) if (!/^npm_/i.test(key) && key !== 'INIT_CWD') env[key] = value;
    return { ...env, npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false', ...extra };
}

// ───────────────────────────── the manifest ─────────────────────────────

describe('the contract package\'s manifest', () => {
    it('is named in the scope GitHub Packages takes for this repository: its owner, in lower case', () => {
        expect(manifest.name).toBe('@rodnapamet/scanent-contract');
        expect(manifest.name).toBe(manifest.name.toLowerCase());
        const scope = manifest.name.slice(1, manifest.name.indexOf('/'));
        // The owner, read from the two other places the repository names it.
        const owner = /^https:\/\/github\.com\/([^/]+)\/([^/]+)\.git$/.exec(manifest.repository?.url ?? '');
        expect(owner).not.toBeNull();
        expect(scope).toBe((owner as RegExpExecArray)[1].toLowerCase());
        const release = yaml.load(read('.github/workflows/release.yml')) as Json;
        expect(String(release.env.IMAGE_REPOSITORY)).toBe(`ghcr.io/${scope}/${(owner as RegExpExecArray)[2]}`);
        // An npm scope is its own name: `@scanent` would be an account called scanent.
        expect(scope).not.toBe('scanent');
    });

    it('publishes to GitHub Packages, is linked to this repository, and is the one package that can be published', () => {
        expect(manifest.publishConfig).toEqual({ registry: 'https://npm.pkg.github.com' });
        expect(manifest.repository).toEqual({ type: 'git', url: 'https://github.com/RodnaPamet/scanent.git', directory: 'packages/contract' });
        expect(manifest.private).toBeUndefined();
        expect(manifest.license).toBe('BUSL-1.1');
        for (const pkg of ['report', 'scanner']) expect(json<Manifest>(`packages/${pkg}/package.json`).private).toBe(true);
        expect(json<Manifest>('package.json').private).toBe(true);
        // The check the workflow runs holds a tarball to these same three values.
        expect([check.PACKAGE_NAME, check.REGISTRY, check.REPOSITORY_URL]).toEqual([manifest.name, manifest.publishConfig?.registry, manifest.repository?.url]);
    });

    it('carries the scanner\'s version, and the two packages that use it name that version exactly', () => {
        expect(manifest.version).toBe(SCANNER_VERSION);
        for (const pkg of ['report', 'scanner']) {
            // An exact version that is the workspace's own: npm links the directory, and never asks a registry for it.
            expect(json<Manifest>(`packages/${pkg}/package.json`).dependencies?.[manifest.name]).toBe(SCANNER_VERSION);
        }
        const lock = json<{ packages: Record<string, { version?: string; resolved?: string; link?: boolean; dependencies?: Record<string, string> }> }>('package-lock.json');
        expect(lock.packages['packages/contract'].version).toBe(SCANNER_VERSION);
        expect(lock.packages[`node_modules/${manifest.name}`]).toEqual({ resolved: 'packages/contract', link: true });
        expect(Object.keys(lock.packages).filter((key) => key.includes('@scanent/contract'))).toEqual([]);
    });

    it('holds the repository\'s LICENSE and NOTICE, byte for byte', () => {
        expect(fs.readFileSync(path.join(REPO, 'packages/contract/LICENSE')).equals(LICENCE)).toBe(true);
        expect(fs.readFileSync(path.join(REPO, 'packages/contract/NOTICE')).equals(NOTICE)).toBe(true);
        expect(LICENCE.length).toBeGreaterThan(1000);
        expect(NOTICE.toString('utf8')).toContain('packages/contract/src/receipt-verification.ts');
    });

    it('lists what it ships, compiles before it is packed, and writes no source map', () => {
        expect(manifest.files).toEqual(['dist/**/*.js', 'dist/**/*.d.ts', 'LICENSE', 'NOTICE', 'README.md']);
        expect(manifest.scripts).toEqual({ prepack: 'tsc -b .' });
        const tsconfig = JSON.parse(
            read('packages/contract/tsconfig.json')
                .split('\n')
                .filter((line) => !line.trimStart().startsWith('//'))
                .join('\n'),
        ) as { compilerOptions: Record<string, unknown> };
        expect(tsconfig.compilerOptions.sourceMap).toBe(false);
        expect(tsconfig.compilerOptions.declarationMap).toBeUndefined();
    });

    it('no file of the repository still imports the name it had', () => {
        const stale: string[] = [];
        const walk = (dir: string): void => {
            for (const entry of fs.readdirSync(path.join(REPO, dir), { withFileTypes: true })) {
                const rel = `${dir}/${entry.name}`;
                if (entry.isDirectory()) {
                    if (!['node_modules', 'dist', 'fixtures'].includes(entry.name)) walk(rel);
                } else if (/\.(ts|js|mjs|json)$/.test(entry.name) && /['"`]@scanent\/contract/.test(read(rel))) {
                    stale.push(rel);
                }
            }
        };
        for (const dir of ['packages', 'scripts', 'deploy']) walk(dir);
        for (const file of ['jest.config.js', 'tsconfig.json', 'eslint.config.mjs', 'package.json']) {
            if (/@scanent\/contract/.test(read(file))) stale.push(file);
        }
        // This file names the old name on purpose, in the two lines that look for it.
        expect(stale).toEqual(['packages/scanner/tests/contract-package.test.ts']);
    });
});

// ───────────────────────────── the tarball ─────────────────────────────

describe('what npm pack puts in the package', () => {
    let work: string;
    let pkg: string;
    let dry: { filename: string; integrity: string; files: { path: string; size: number }[] };
    let packed: { filename: string; integrity: string };
    let tarball: Buffer;
    let files: Map<string, Buffer>;

    const npm = (args: string[], cwd: string): string => execFileSync('npm', args, { cwd, env: cleanEnv(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

    beforeAll(() => {
        work = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-contract-pack-'));
        // A checkout in small: the base compiler settings, the package's own directory as the repository has it
        // (source, tests, manifest, licence files), and the installed dependencies, linked.
        const checkout = path.join(work, 'checkout');
        pkg = path.join(checkout, 'packages', 'contract');
        fs.mkdirSync(pkg, { recursive: true });
        fs.copyFileSync(path.join(REPO, 'tsconfig.base.json'), path.join(checkout, 'tsconfig.base.json'));
        for (const name of ['package.json', 'tsconfig.json', 'README.md', 'LICENSE', 'NOTICE']) {
            fs.copyFileSync(path.join(REPO, 'packages/contract', name), path.join(pkg, name));
        }
        for (const dir of ['src', 'tests']) fs.cpSync(path.join(REPO, 'packages/contract', dir), path.join(pkg, dir), { recursive: true });
        fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(checkout, 'node_modules'), 'dir');

        // `--dry-run` lists what a pack would hold and writes no tarball. It runs `prepack`, so this is also the first build.
        dry = (JSON.parse(npm(['pack', '--dry-run', '--json'], pkg)) as (typeof dry)[])[0];
        // What an earlier build with source maps would have left behind, and what a test run leaves.
        fs.writeFileSync(path.join(pkg, 'dist', 'cidr.js.map'), '{"version":3,"file":"cidr.js","sources":["../src/cidr.ts"]}');
        fs.mkdirSync(path.join(pkg, 'coverage'));
        fs.writeFileSync(path.join(pkg, 'coverage', 'lcov.info'), 'SF:src/cidr.ts\n');
        const out = path.join(work, 'out');
        fs.mkdirSync(out);
        packed = (JSON.parse(npm(['pack', '--json', '--pack-destination', out], pkg)) as (typeof packed)[])[0];
        tarball = fs.readFileSync(path.join(out, packed.filename));
        files = check.checkTarball(tarball, { expected: EXPECTED, licence: LICENCE, notice: NOTICE }).files;
    });
    afterAll(() => fs.rmSync(work, { recursive: true, force: true }));

    it('npm pack --dry-run lists the compiled contract, package.json, README.md, LICENSE and NOTICE, and nothing else', () => {
        const listed = dry.files.map((f) => f.path).sort();
        expect(listed).toEqual(EXPECTED);
        // Spelled out, so that a change to the derivation above cannot quietly change what is expected.
        expect(MODULES).toEqual(['audit-redact.ts', 'canonical-json.ts', 'cidr.ts', 'harness-contract-rules.ts', 'harness-contract.ts', 'harness-findings.ts', 'harness-ladder.ts', 'harness-matrix-model.ts', 'receipt-verification.ts']);
        expect(listed).toHaveLength(MODULES.length * 2 + 4);
        expect(listed.filter((f) => !f.startsWith('dist/'))).toEqual(['LICENSE', 'NOTICE', 'README.md', 'package.json']);
        for (const file of listed.filter((f) => f.startsWith('dist/'))) expect(file).toMatch(/^dist\/[a-z-]+\.(js|d\.ts)$/);
        for (const file of dry.files) expect(file.size).toBeGreaterThan(0);
    });

    it('holds no source map, no test, no TypeScript source and no build record, though the directory it was packed from held each', () => {
        for (const present of ['tests/harness-contract.test.ts', 'tests/helpers', 'src/harness-contract.ts', 'tsconfig.json', 'tsconfig.tsbuildinfo', 'dist/cidr.js.map', 'coverage/lcov.info']) {
            expect([present, fs.existsSync(path.join(pkg, present))]).toEqual([present, true]);
        }
        const names = [...files.keys()];
        expect(names.filter((f) => /\.map$/.test(f))).toEqual([]);
        expect(names.filter((f) => /(^|\/)(tests?|fixtures|coverage|src)\//.test(f) || /\.test\./.test(f))).toEqual([]);
        expect(names.filter((f) => /\.ts$/.test(f) && !/\.d\.ts$/.test(f))).toEqual([]);
        expect(names.filter((f) => /tsbuildinfo|tsconfig/.test(f))).toEqual([]);
    });

    it('the tarball holds exactly what the dry run listed, under the name the release workflow publishes', () => {
        expect(packed.filename).toBe(TARBALL);
        expect(dry.filename).toBe(TARBALL);
        expect([...files.keys()].sort()).toEqual(dry.files.map((f) => f.path).sort());
        for (const { path: name, size } of dry.files) expect([name, files.get(name)?.length]).toEqual([name, size]);
        // The same source packs to the same bytes: the stray files written between the two packs changed nothing.
        expect(packed.integrity).toBe(dry.integrity);
    });

    it('passes the check the release workflow runs, held to the scanner\'s version and to this machine\'s paths', () => {
        const forbiddenPaths = [work, fs.realpathSync(work), REPO, os.homedir()];
        expect(check.checkTarball(tarball, { expected: EXPECTED, licence: LICENCE, notice: NOTICE, version: SCANNER_VERSION, forbiddenPaths }).problems).toEqual([]);
        const run = spawnSync(process.execPath, [path.join(REPO, 'scripts/check-contract-package.js'), path.join(work, 'out', TARBALL), '--version', SCANNER_VERSION], { encoding: 'utf8', env: cleanEnv() });
        expect([run.status, run.stderr]).toEqual([0, '']);
        expect(run.stdout).toContain(`contract package: ${manifest.name}@${SCANNER_VERSION}, ${EXPECTED.length} files, nothing else`);
        expect(run.stdout).toMatch(new RegExp(`^sha256:[0-9a-f]{64} {2}${TARBALL.replace(/\./g, '\\.')}$`, 'm'));
        // Another version is refused, and so is no tarball at all.
        const other = spawnSync(process.execPath, [path.join(REPO, 'scripts/check-contract-package.js'), path.join(work, 'out', TARBALL), '--version', '99.0.0'], { encoding: 'utf8', env: cleanEnv() });
        expect(other.status).toBe(1);
        expect(other.stderr).toContain(`contract package: package.json: the version is ${SCANNER_VERSION}, not 99.0.0`);
        expect(spawnSync(process.execPath, [path.join(REPO, 'scripts/check-contract-package.js')], { encoding: 'utf8', env: cleanEnv() }).status).toBe(2);
    });

    it('no file refers to a source map or names a directory of the machine that built it', () => {
        for (const [name, bytes] of files) {
            const text = bytes.toString('utf8');
            expect([name, text.includes('sourceMappingURL')]).toEqual([name, false]);
            for (const dir of [work, fs.realpathSync(work), REPO, os.homedir()]) expect([name, text.includes(dir)]).toEqual([name, false]);
        }
        // The compiled files are the compiler's output, as written: nothing rewrote them on the way in.
        for (const name of EXPECTED.filter((f) => f.startsWith('dist/'))) {
            expect([name, files.get(name)?.equals(fs.readFileSync(path.join(pkg, name)))]).toEqual([name, true]);
        }
        expect(files.get('package.json')?.equals(fs.readFileSync(path.join(REPO, 'packages/contract/package.json')))).toBe(true);
    });

    it('installed where a consumer installs it, every module loads by the path the documents give, and the types resolve', () => {
        const consumer = path.join(work, 'consumer');
        const installed = path.join(consumer, 'node_modules', '@rodnapamet', 'scanent-contract');
        for (const [name, bytes] of files) {
            fs.mkdirSync(path.dirname(path.join(installed, name)), { recursive: true });
            fs.writeFileSync(path.join(installed, name), bytes);
        }
        // The package's one dependency, and the types of the Node it runs on, as an install would place them.
        expect(Object.keys(manifest.dependencies ?? {})).toEqual(['zod']);
        fs.symlinkSync(path.join(REPO, 'node_modules', 'zod'), path.join(consumer, 'node_modules', 'zod'), 'dir');
        fs.symlinkSync(path.join(REPO, 'node_modules', '@types'), path.join(consumer, 'node_modules', '@types'), 'dir');

        const specifiers = MODULES.map((file) => `${manifest.name}/${file.replace(/\.ts$/, '')}`);
        const load = `for (const m of ${JSON.stringify(specifiers)}) { if (Object.keys(require(m)).length === 0) throw new Error(m + ' exports nothing'); }
            const { verifyAndParseHarnessReport } = require('${manifest.name}/harness-contract');
            const refused = verifyAndParseHarnessReport('{}', []);
            if (refused.ok !== false || refused.reason !== 'UNSIGNED') throw new Error('the verifier did not refuse an unsigned report');
            process.stdout.write(require('${manifest.name}/package.json').version);`;
        const ran = spawnSync(process.execPath, ['-e', load], { cwd: consumer, encoding: 'utf8', env: cleanEnv() });
        expect([ran.status, ran.stderr, ran.stdout]).toEqual([0, '', SCANNER_VERSION]);
        // What is not a module of the contract cannot be reached through the package.
        const outside = spawnSync(process.execPath, ['-e', `require('${manifest.name}/dist/cidr.js')`], { cwd: consumer, encoding: 'utf8', env: cleanEnv() });
        expect(outside.status).not.toBe(0);

        // A TypeScript consumer, under the two ways of resolving a package: `exports` (a bundler, as the
        // originating application uses) and the older rule that reads `typesVersions`.
        fs.writeFileSync(
            path.join(consumer, 'consumer.ts'),
            [
                `import { verifyAndParseHarnessReport, type HarnessParseResult } from '${manifest.name}/harness-contract';`,
                `import { scoreHarness } from '${manifest.name}/harness-ladder';`,
                `import { planHarnessScan } from '${manifest.name}/harness-findings';`,
                `import { canonicalJson } from '${manifest.name}/canonical-json';`,
                'export const result: HarnessParseResult = verifyAndParseHarnessReport(canonicalJson({}), []);',
                'export const level: string = scoreHarness([]).level;',
                'export const plan: typeof planHarnessScan = planHarnessScan;',
                '',
            ].join('\n'),
        );
        const tsc = path.join(REPO, 'node_modules', 'typescript', 'bin', 'tsc');
        for (const resolution of [
            ['--module', 'esnext', '--moduleResolution', 'bundler'],
            ['--module', 'commonjs', '--moduleResolution', 'node10'],
        ]) {
            // No `skipLibCheck`: the package's own declarations are checked, not only resolved.
            const typed = spawnSync(process.execPath, [tsc, '--noEmit', '--strict', '--esModuleInterop', '--target', 'es2022', '--types', 'node', ...resolution, 'consumer.ts'], {
                cwd: consumer,
                encoding: 'utf8',
                env: cleanEnv(),
            });
            expect([resolution[3], typed.status, typed.stdout]).toEqual([resolution[3], 0, '']);
        }
        // The check is not vacuous: a module the package does not have fails to resolve.
        fs.writeFileSync(path.join(consumer, 'missing.ts'), `import { x } from '${manifest.name}/no-such-module';\nexport const y: unknown = x;\n`);
        const missing = spawnSync(process.execPath, [tsc, '--noEmit', '--esModuleInterop', '--types', 'node', '--module', 'esnext', '--moduleResolution', 'bundler', 'missing.ts'], {
            cwd: consumer,
            encoding: 'utf8',
            env: cleanEnv(),
        });
        expect(missing.status).not.toBe(0);
        expect(missing.stdout).toContain(`Cannot find module '${manifest.name}/no-such-module'`);
    });

    it('a compiled file whose source is gone is packed by npm and refused by the check', () => {
        // `files` admits every .js under dist, so a leftover of a deleted module would ship: the check is what stops it.
        fs.writeFileSync(path.join(pkg, 'dist', 'removed-module.js'), 'exports.x = 1;\n');
        fs.writeFileSync(path.join(pkg, 'dist', 'removed-module.d.ts'), 'export declare const x = 1;\n');
        const out = path.join(work, 'out-stale');
        fs.mkdirSync(out);
        const stale = (JSON.parse(npm(['pack', '--json', '--pack-destination', out], pkg)) as (typeof packed)[])[0];
        const result = check.checkTarball(fs.readFileSync(path.join(out, stale.filename)), { expected: EXPECTED, licence: LICENCE, notice: NOTICE, version: SCANNER_VERSION });
        expect(result.problems).toEqual(['dist/removed-module.d.ts: not a file of the package', 'dist/removed-module.js: not a file of the package']);
        const run = spawnSync(process.execPath, [path.join(REPO, 'scripts/check-contract-package.js'), path.join(out, stale.filename)], { encoding: 'utf8', env: cleanEnv() });
        expect(run.status).toBe(1);
        expect(run.stderr).toContain('contract package: dist/removed-module.js: not a file of the package');
    });
});

// ───────────────────────────── the check ─────────────────────────────

describe('scripts/check-contract-package.js', () => {
    /** A package that passes: two modules, the four fixed files. */
    const good = (over: Record<string, string | undefined> = {}): Map<string, Buffer> => {
        const base: Record<string, string | undefined> = {
            'package.json': JSON.stringify({
                name: '@rodnapamet/scanent-contract',
                version: '1.2.3',
                license: 'BUSL-1.1',
                repository: { type: 'git', url: 'https://github.com/RodnaPamet/scanent.git', directory: 'packages/contract' },
                publishConfig: { registry: 'https://npm.pkg.github.com' },
            }),
            'README.md': '# the package\n',
            LICENSE: 'the licence\n',
            NOTICE: 'the notice\n',
            'dist/a.js': 'exports.a = 1;\n',
            'dist/a.d.ts': 'export declare const a = 1;\n',
            'dist/deep/b.js': 'exports.b = 2;\n',
            'dist/deep/b.d.ts': 'export declare const b = 2;\n',
            ...over,
        };
        return new Map(Object.entries(base).flatMap(([name, text]) => (text === undefined ? [] : [[name, Buffer.from(text)] as [string, Buffer]])));
    };
    const options = (over: Partial<CheckOptions> = {}): CheckOptions => ({
        expected: check.expectedFiles(['a.ts', 'deep/b.ts']),
        licence: Buffer.from('the licence\n'),
        notice: Buffer.from('the notice\n'),
        version: '1.2.3',
        forbiddenPaths: ['/home/builder/work/scanent'],
        ...over,
    });
    const withManifest = (change: (m: Json) => void): Map<string, Buffer> => {
        const m = JSON.parse((good().get('package.json') as Buffer).toString('utf8')) as Json;
        change(m);
        return good({ 'package.json': JSON.stringify(m) });
    };

    it('expects, for each source module, its compiled file and its declaration, and the four files beside them', () => {
        expect(check.expectedFiles(['a.ts', 'deep/b.ts'])).toEqual(['LICENSE', 'NOTICE', 'README.md', 'dist/a.d.ts', 'dist/a.js', 'dist/deep/b.d.ts', 'dist/deep/b.js', 'package.json']);
        expect([...check.FIXED_FILES]).toEqual(['LICENSE', 'NOTICE', 'README.md', 'package.json']);
        expect(check.checkPackage(good(), options())).toEqual([]);
    });

    it.each([
        ['dist/a.js.map', 'a source map'],
        ['dist/a.d.ts.map', 'a source map'],
        ['tests/a.test.ts', 'a test'],
        ['dist/a.test.js', 'a test'],
        ['tests/fixtures/report.json', 'a test'],
        ['src/a.ts', 'TypeScript source'],
        ['tsconfig.tsbuildinfo', 'a build record'],
        ['dist/gone.js', 'not a file of the package'],
        ['.npmrc', 'not a file of the package'],
        ['.env', 'not a file of the package'],
    ])('refuses %s, as %s', (file, kind) => {
        expect(check.checkPackage(good({ [file]: 'x' }), options())).toEqual([`${file}: ${kind}`]);
    });

    it('refuses a package with a file missing, and a population of nothing', () => {
        expect(check.checkPackage(good({ 'dist/deep/b.d.ts': undefined }), options())).toEqual(['dist/deep/b.d.ts: missing']);
        expect(check.checkPackage(good({ NOTICE: undefined }), options())).toEqual(['NOTICE: missing']);
        // No source module found is nothing to compare with, not a pass.
        const empty = check.checkFiles(['LICENSE', 'NOTICE', 'README.md', 'package.json'], check.expectedFiles([]));
        expect(empty).toEqual(['no source module was found, so nothing compiled is expected; nothing was checked']);
    });

    it('holds the manifest to the name, the registry, the repository, the licence and the version asked for', () => {
        const problems = (change: (m: Json) => void): string[] => check.checkPackage(withManifest(change), options());
        expect(problems((m) => (m.name = '@scanent/contract'))).toEqual(['package.json: the name is "@scanent/contract", not @rodnapamet/scanent-contract']);
        expect(problems((m) => (m.private = true))).toEqual(['package.json: marked private, so it cannot be published']);
        expect(problems((m) => (m.version = '1.2.4'))).toEqual(['package.json: the version is 1.2.4, not 1.2.3']);
        expect(problems((m) => (m.version = '1.2.3-rc.1'))).toEqual(['package.json: the version "1.2.3-rc.1" is not MAJOR.MINOR.PATCH']);
        expect(problems((m) => (m.license = 'MIT'))).toEqual(['package.json: the licence is "MIT", not BUSL-1.1']);
        expect(problems((m) => (m.publishConfig = { registry: 'https://registry.npmjs.org' }))).toEqual(['package.json: publishConfig.registry is not https://npm.pkg.github.com']);
        expect(problems((m) => delete m.publishConfig)).toEqual(['package.json: publishConfig.registry is not https://npm.pkg.github.com']);
        expect(problems((m) => (m.repository.url = 'https://github.com/someone/else.git'))).toEqual(['package.json: repository.url is not https://github.com/RodnaPamet/scanent.git']);
        expect(problems((m) => delete m.repository)).toEqual([
            'package.json: repository.url is not https://github.com/RodnaPamet/scanent.git',
            'package.json: repository.directory is not packages/contract',
        ]);
        expect(check.checkPackage(good({ 'package.json': '{' }), options())).toEqual(['package.json: not JSON']);
        // With no version asked for, any MAJOR.MINOR.PATCH is accepted.
        expect(check.checkPackage(withManifest((m) => (m.version = '9.0.0')), options({ version: undefined }))).toEqual([]);
    });

    it('refuses a licence file that is not the repository\'s, a reference to a source map, and a path of the build machine', () => {
        expect(check.checkPackage(good({ LICENSE: 'another licence\n' }), options())).toEqual(["LICENSE: not the repository's LICENSE"]);
        expect(check.checkPackage(good({ NOTICE: 'the notice\n\n' }), options())).toEqual(["NOTICE: not the repository's NOTICE"]);
        expect(check.checkPackage(good({ 'dist/a.js': 'exports.a = 1;\n//# sourceMappingURL=a.js.map' }), options())).toEqual(['dist/a.js: refers to a source map']);
        expect(check.checkPackage(good({ 'dist/a.d.ts': '// from /home/builder/work/scanent/packages/contract/src/a.ts\n' }), options())).toEqual([
            'dist/a.d.ts: holds the path of a directory on the machine that built it',
        ]);
        // An unset path (a variable the machine does not have) forbids nothing, and neither does the root.
        expect(check.checkPackage(good({ 'dist/a.js': 'exports.a = "/";\n' }), options({ forbiddenPaths: [undefined, '', '/'] }))).toEqual([]);
    });

    describe('reading a tarball', () => {
        /** One tar entry: a 512-byte header, then the content padded to 512. */
        const entry = (name: string, content: string, type = '0'): Buffer => {
            const header = Buffer.alloc(512);
            header.write(name, 0, 100, 'utf8');
            header.write(Buffer.byteLength(content).toString(8).padStart(11, '0'), 124, 12, 'utf8');
            header.write(type, 156, 1, 'utf8');
            const body = Buffer.alloc(Math.ceil(Buffer.byteLength(content) / 512) * 512);
            body.write(content, 0, 'utf8');
            return Buffer.concat([header, body]);
        };
        const tgz = (...entries: Buffer[]): Buffer => zlib.gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));
        const whole = (over: Record<string, string | undefined> = {}): Buffer[] => [...good(over)].map(([name, bytes]) => entry(`package/${name}`, bytes.toString('utf8')));

        it('reads the files of an archive, and a package of the right files passes', () => {
            const result = check.checkTarball(tgz(...whole()), options());
            expect(result.problems).toEqual([]);
            expect([...result.files.keys()].sort()).toEqual(options().expected);
            expect(result.files.get('dist/a.js')?.toString('utf8')).toBe('exports.a = 1;\n');
        });

        it('passes over a directory entry, and refuses a link, an entry outside package/ and a second copy of a file', () => {
            expect(check.checkTarball(tgz(entry('package/dist/', '', '5'), ...whole()), options()).problems).toEqual([]);
            expect(check.checkTarball(tgz(...whole(), entry('package/dist/link.js', '', '2')), options()).problems).toEqual(['package/dist/link.js: not a regular file (tar type "2")']);
            expect(check.checkTarball(tgz(...whole(), entry('PaxHeader/x', 'path=y\n', 'x')), options()).problems).toEqual(['PaxHeader/x: not a regular file (tar type "x")']);
            expect(check.checkTarball(tgz(...whole(), entry('elsewhere/a.js', 'x')), options()).problems).toEqual(['elsewhere/a.js: not under package/']);
            expect(check.checkTarball(tgz(...whole(), entry('package/../a.js', 'x')), options()).problems).toEqual(['package/../a.js: not under package/']);
            expect(check.checkTarball(tgz(...whole(), entry('package/dist/a.js', 'exports.a = 1;\n')), options()).problems).toEqual(['package/dist/a.js: in the archive twice']);
        });

        it('refuses what is not an archive, an archive of nothing, and one that is cut short', () => {
            expect(check.readTarball(Buffer.from('not gzip')).problems).toEqual(['the file is not a gzipped archive']);
            expect(check.readTarball(tgz()).problems).toEqual(['the archive holds no file']);
            const cut = zlib.gzipSync(entry('package/dist/a.js', 'x'.repeat(2000)).subarray(0, 512 + 600));
            expect(check.readTarball(cut).problems).toEqual(['package/dist/a.js: the archive is cut short']);
        });
    });
});

// ───────────────────────────── the release workflow ─────────────────────────────

describe('the release workflow and the contract package', () => {
    const text = read('.github/workflows/release.yml');
    const release = yaml.load(text) as Json;
    const steps = (job: Json): Json[] => job.steps as Json[];
    const named = (job: Json, needle: string): Json => {
        const found = steps(job).filter((s) => String(s.name ?? '').includes(needle));
        expect(found).toHaveLength(1);
        return found[0];
    };
    const order = (job: Json, needles: string[]): void => {
        const names = steps(job).map((s) => String(s.name ?? s.uses ?? ''));
        const at = needles.map((n) => names.findIndex((name) => name.includes(n)));
        expect(at.every((i) => i >= 0)).toBe(true);
        expect([...at].sort((a, b) => a - b)).toEqual(at);
    };
    // A tag's push, or a dispatch on the tag by GitHub Actions itself (auto-release.yml); never a person's manual run.
    const TAG_ONLY = "github.ref_type == 'tag' && (github.event_name == 'push' || github.actor == 'github-actions[bot]')";
    const pack = release.jobs['contract-package'] as Json;
    const publish = release.jobs['publish-contract'] as Json;
    const WORKFLOW_TARBALL = 'contract-package/rodnapamet-scanent-contract-${VERSION}.tgz';

    it('packs and checks on every run, after the gates, in a job that can neither publish nor sign', () => {
        expect(pack.if).toBeUndefined();
        // `build` needs `gates`, and gives the version the tag was held to.
        expect(pack.needs).toBe('build');
        expect(release.jobs.build.needs).toBe('gates');
        expect(pack.permissions).toEqual({ contents: 'read' });
        expect(pack.env).toEqual({ VERSION: '${{ needs.build.outputs.version }}' });
        expect(JSON.stringify(pack)).not.toMatch(/NODE_AUTH_TOKEN|github\.token|GITHUB_TOKEN|id-token|npm publish|registry-url|attest/);
        order(pack, ['actions/checkout', 'actions/setup-node', 'Install', 'Pack the contract', 'The package holds', 'Upload the package']);
        expect(steps(pack)[0].with).toEqual({ 'persist-credentials': false });
        // Installed as everywhere else: the lockfile's tree, and no install script.
        expect(named(pack, 'Install').run).toBe(named(release.jobs.gates as Json, 'Install').run);
        const packing = String(named(pack, 'Pack the contract').run);
        expect(packing).toContain('(cd packages/contract && npm pack --pack-destination "$GITHUB_WORKSPACE/contract-package")');
        // The name npm gave the tarball in this test is the one the workflow looks for, with the version in place.
        expect(packing).toContain(`test -s "${WORKFLOW_TARBALL}"`);
        expect(WORKFLOW_TARBALL.replace('${VERSION}', SCANNER_VERSION)).toBe(`contract-package/${TARBALL}`);
        expect(packing).toContain('[ "$(find contract-package -type f | wc -l)" -eq 1 ]');
        expect(named(pack, 'The package holds').run).toBe(`node scripts/check-contract-package.js "${WORKFLOW_TARBALL}" --version "\${VERSION}"`);
        const upload = named(pack, 'Upload the package');
        expect(upload.with).toMatchObject({ name: 'contract-package', path: 'contract-package/rodnapamet-scanent-contract-*.tgz', 'if-no-files-found': 'error' });
        for (const step of steps(pack)) expect(step.if).toBeUndefined();
    });

    it('publishes on a release tag only, after the images, the tarball that was checked, with no checkout', () => {
        expect(publish.if).toBe(TAG_ONLY);
        expect(publish.needs).toEqual(['build', 'contract-package', 'publish']);
        expect(publish.permissions).toEqual({ contents: 'read', packages: 'write', 'id-token': 'write', attestations: 'write' });
        expect(publish.env).toEqual({ VERSION: '${{ needs.build.outputs.version }}', PACKAGE: manifest.name, REGISTRY: manifest.publishConfig?.registry });
        // Three actions, none of them a checkout: the job that holds the token runs nothing of the repository's.
        expect(steps(publish).filter((s) => s.uses !== undefined).map((s) => String(s.uses).split('@')[0])).toEqual([
            'actions/download-artifact',
            'actions/setup-node',
            'actions/attest-build-provenance',
        ]);
        expect(JSON.stringify(publish)).not.toMatch(/npm ci|npm install|npm run|npm pack|node scripts|tsc /);
        const download = steps(publish)[0];
        expect(download.with).toEqual({ name: named(pack, 'Upload the package').with.name, path: 'contract-package' });
        const node = steps(publish)[1];
        const scope = manifest.name.slice(0, manifest.name.indexOf('/'));
        expect(node.with).toEqual({ 'node-version': 24, 'registry-url': manifest.publishConfig?.registry, scope });
        order(publish, ['actions/download-artifact', 'actions/setup-node', 'The package is here', 'Refuse a version', "Attest the package's provenance", 'Publish to GitHub Packages']);
        expect(steps(publish)).toHaveLength(6);
        for (const step of steps(publish)) expect(step.if).toBeUndefined();
    });

    it('attests the tarball it is about to publish, with the action the image and the bundle are attested with', () => {
        const attest = named(publish, "Attest the package's provenance");
        expect(String(attest.uses)).toBe(String(named(release.jobs.publish as Json, 'Attest the build').uses));
        expect(String(attest.uses)).toMatch(/^actions\/attest-build-provenance@[0-9a-f]{40}$/);
        expect(attest.with).toEqual({ 'subject-path': 'contract-package/rodnapamet-scanent-contract-${{ needs.build.outputs.version }}.tgz' });
    });

    it('publishes that tarball and no directory, runs no script of it, and gives the token to the two steps that ask the registry', () => {
        const step = named(publish, 'Publish to GitHub Packages');
        // `./`: without it npm reads the path as a GitHub shorthand and runs git (0.13.1's publish failed so).
        expect(step.run).toBe(`npm publish "./${WORKFLOW_TARBALL}" --ignore-scripts --registry "\${REGISTRY}"`);
        // The pack job, which every run reaches, asks npm to read the very same path.
        expect(String(named(pack, 'npm reads the publish path as this file').run)).toContain(`npm pack --dry-run --ignore-scripts "./${WORKFLOW_TARBALL}"`);
        // GitHub Packages documents no support for npm's own provenance statement: the attestation above is the provenance.
        expect(String(step.run)).not.toContain('--provenance');
        const tokened = steps(publish).filter((s) => JSON.stringify(s).includes('github.token'));
        expect(tokened.map((s) => s.name)).toEqual(['Refuse a version that is already published', 'Publish to GitHub Packages']);
        for (const s of tokened) expect(s.env).toEqual({ NODE_AUTH_TOKEN: '${{ github.token }}' });
        // The job's own token, never a stored secret, here as in the rest of the workflow.
        expect(text).not.toMatch(/\$\{\{\s*secrets\./);
        // Every job that names the registry or the token is one of the two that may write a package.
        for (const [name, job] of Object.entries(release.jobs as Record<string, Json>)) {
            if (/npm publish|NODE_AUTH_TOKEN|npm\.pkg\.github\.com/.test(JSON.stringify(job))) expect(name).toBe('publish-contract');
        }
    });

    it('refuses a version the registry already holds, and nothing else: run here against a stand-in for npm', () => {
        const refuse = named(publish, 'Refuse a version');
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-refuse-'));
        try {
            const asked = path.join(dir, 'asked');
            // A stand-in `npm`: records what it was asked, then answers as the test says.
            fs.writeFileSync(path.join(dir, 'npm'), `#!/bin/sh\nprintf '%s\\n' "$*" >> "${asked}"\n[ -n "$ANSWER" ] && printf '%s\\n' "$ANSWER"\nexit "$STATUS"\n`, { mode: 0o755 });
            const run = (answer: string, status: string) =>
                spawnSync('bash', ['-c', String(refuse.run)], {
                    cwd: dir,
                    encoding: 'utf8',
                    env: { PATH: `${dir}:${process.env.PATH ?? ''}`, PACKAGE: manifest.name, VERSION: '1.2.3', REGISTRY: 'https://npm.pkg.github.com', ANSWER: answer, STATUS: status },
                });
            // The registry holds that version: refused.
            const held = run('1.2.3', '0');
            expect(held.status).toBe(1);
            expect(held.stderr).toContain(`${manifest.name}@1.2.3 is already published; a version is never published twice`);
            // A first release: the registry does not know the package, and npm fails.
            expect(run('', '1').status).toBe(0);
            // The package exists and that version does not: npm prints nothing.
            expect(run('', '0').status).toBe(0);
            // An answer that is not that version is not a positive answer.
            expect(run('1.2.4', '0').status).toBe(0);
            expect(fs.readFileSync(asked, 'utf8').split('\n')[0]).toBe(`view ${manifest.name}@1.2.3 version --registry https://npm.pkg.github.com`);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('creates the release only after both publishing jobs, and says in its notes where the package is', () => {
        const job = release.jobs.release as Json;
        expect(job.needs).toContain('publish');
        expect(job.needs).toContain('publish-contract');
        const create = steps(job).map((s) => String(s.run ?? '')).join('\n');
        expect(create).toContain(`The report contract is published to GitHub Packages as ${manifest.name}@\${VERSION}, with build provenance.`);
    });

    it('says, after it logs out, whether the image answers with no login, and fails the release either way round never', () => {
        const images = release.jobs.publish as Json;
        order(images, ['Log in', 'Push each', 'Verify the signatures', 'Log out', 'Say whether the image can be pulled with no login']);
        const say = named(images, 'Say whether the image');
        expect(steps(images)[steps(images).length - 1]).toBe(say);
        expect(say.if).toBeUndefined();
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-public-'));
        try {
            const asked = path.join(dir, 'asked');
            fs.writeFileSync(path.join(dir, 'docker'), `#!/bin/sh\nprintf '%s\\n' "$*" >> "${asked}"\nexit "$STATUS"\n`, { mode: 0o755 });
            const run = (status: string) =>
                spawnSync('bash', ['-c', String(say.run)], {
                    cwd: dir,
                    encoding: 'utf8',
                    env: { PATH: `${dir}:${process.env.PATH ?? ''}`, IMAGE_REPOSITORY: String(release.env.IMAGE_REPOSITORY), VERSION: '1.2.3', STATUS: status },
                });
            const open = run('0');
            expect([open.status, open.stdout.trim()]).toEqual([0, 'public: ghcr.io/rodnapamet/scanent:1.2.3 answers with no login']);
            // A private package, as GitHub creates it: a warning that names the step to take, and the job goes on.
            const closed = run('1');
            expect(closed.status).toBe(0);
            expect(closed.stdout).toMatch(/^::warning title=The image is not public yet::ghcr\.io\/rodnapamet\/scanent:1\.2\.3 does not answer without a login\./);
            expect(closed.stdout).toContain('docs/release-checklist.md');
            expect(fs.readFileSync(asked, 'utf8').split('\n')[0]).toBe('buildx imagetools inspect ghcr.io/rodnapamet/scanent:1.2.3');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

// ───────────────────────────── the documents ─────────────────────────────

describe('what the documents say about the package and the image', () => {
    const contractDoc = read('docs/contract.md');
    const readme = read('packages/contract/README.md');
    const flat = (text: string): string => text.replace(/\s+/g, ' ');

    it('docs/contract.md and the package\'s README give the two .npmrc lines and the token scope', () => {
        const scope = manifest.name.slice(0, manifest.name.indexOf('/'));
        const host = new URL(manifest.publishConfig?.registry ?? '').host;
        for (const doc of [contractDoc, readme]) {
            expect(doc).toContain(`${scope}:registry=${manifest.publishConfig?.registry}`);
            expect(doc).toContain(`//${host}/:_authToken=<token>`);
            expect(doc).toContain('`read:packages`');
            expect(flat(doc)).toContain('personal access token (classic)');
            expect(doc).toContain(`npm install --save-exact ${manifest.name}@<version>`);
            // A token is a secret, and no document shows one or tells a reader to commit one.
            expect(doc).not.toMatch(/_authToken=(?!<token>|\$\{NODE_AUTH_TOKEN\})\S/);
            expect(doc).not.toMatch(/gh[pousr]_[A-Za-z0-9]{20,}/);
        }
        expect(flat(contractDoc)).toContain('The token, which is never committed');
        expect(flat(readme)).toContain('never in the project');
        // In a workflow: the job's own token, and read access granted to the consuming repository.
        expect(contractDoc).toContain('"Manage Actions access"');
        expect(contractDoc).toContain('`permissions: packages: read`');
        expect(contractDoc).toContain(`registry-url: ${manifest.publishConfig?.registry}`);
        expect(contractDoc).toContain(`scope: "${scope}"`);
    });

    it('say why the scope is the owner\'s, and which release first published it', () => {
        expect(flat(contractDoc)).toContain('This repository belongs to `RodnaPamet`, so the scope is `@rodnapamet`');
        expect(flat(contractDoc)).toContain('**Status: published from 0.13.2.**');
        // Installing it has not been tried, and the page says so rather than implying it works.
        expect(flat(contractDoc)).toContain('has not been tried yet.');
        expect(flat(read('docs/EXTRACTION.md'))).toContain('**Published from 0.13.2** (2026-11-13).');
        expect(flat(read('docs/EXTRACTION.md'))).toContain('`@scanent/contract` could not be published from a repository of `RodnaPamet`');
        // One release exists, and no page still says there is none.
        for (const doc of ['docs/verify-a-release.md', 'docs/deployment.md', 'docs/release-checklist.md', 'docs/roadmap.md', 'docs/security-pack/assurance-status.md', 'docs/security-pack/support-and-maintenance.md', 'docs/guide/run-it.md', 'docs/guide/faq.md', 'docs/scanner.md', 'docs/threat-model.md']) {
            expect([doc, /no release (has been|exists)|No release\.|No release has been|No finished release/i.test(flat(read(doc)))]).toEqual([doc, false]);
        }
        for (const doc of ['docs/deployment.md', 'docs/release-checklist.md', 'docs/security-pack/assurance-status.md']) {
            expect([doc, flat(read(doc)).includes('0.13.2')]).toEqual([doc, true]);
        }
    });

    it('name every module of the package, and only modules and exports it has', () => {
        const modules = MODULES.map((file) => file.replace(/\.ts$/, '')).sort();
        const block = /<!-- contract:package-modules -->\n([\s\S]*?)<!-- \/contract:package-modules -->/.exec(contractDoc);
        expect(block).not.toBeNull();
        expect([...(block as RegExpExecArray)[1].matchAll(/`([^`]+)`/g)].map((m) => m[1])).toEqual(modules);
        // The README's table: one row per module, and every function or constant a row names is exported by that module.
        const rows = readme
            .split('\n')
            .filter((line) => line.startsWith(`| \`${manifest.name}/`))
            .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()));
        expect(rows.map(([specifier]) => specifier.replace(/`/g, '').slice(manifest.name.length + 1)).sort()).toEqual(modules);
        let exportsNamed = 0;
        for (const [specifier, holds] of rows) {
            const source = read(`packages/contract/src/${specifier.replace(/`/g, '').slice(manifest.name.length + 1)}.ts`);
            for (const m of holds.matchAll(/`([A-Za-z_][A-Za-z0-9_]*)`/g)) {
                exportsNamed += 1;
                expect([specifier, m[1], new RegExp(`export (const|function|type|interface) ${m[1]}\\b|export \\{[^}]*\\b${m[1]}\\b`).test(source)]).toEqual([specifier, m[1], true]);
            }
        }
        expect(exportsNamed).toBeGreaterThanOrEqual(12);
        // Every import a document shows names a module that exists and something it exports.
        let shown = 0;
        for (const doc of [contractDoc, readme]) {
            for (const m of doc.matchAll(new RegExp(`import \\{ ([^}]+) \\} from '${manifest.name}/([a-z-]+)';`, 'g'))) {
                shown += 1;
                expect(modules).toContain(m[2]);
                const source = read(`packages/contract/src/${m[2]}.ts`);
                for (const name of m[1].split(',').map((n) => n.trim())) expect([m[2], name, new RegExp(`export (const|function) ${name}\\b`).test(source)]).toEqual([m[2], name, true]);
            }
        }
        expect(shown).toBeGreaterThanOrEqual(5);
    });

    it('say the image is public and pulled with no login, in each document a client or a maintainer reads', () => {
        expect(flat(read('docs/verify-a-release.md'))).toContain('**The image is public.** Pulling it, and every check of it below, needs no GitHub account and no login to the registry.');
        expect(flat(read('docs/deployment.md'))).toContain('**The image is public.** Pulling it needs no GitHub account and no login');
        expect(flat(read('docs/quick-start.md'))).toContain('The image is public: the pull needs no account and no login.');
        expect(flat(read('docs/guide/run-it.md'))).toContain('The download is public: it needs no account with us or with GitHub, and no password.');
        expect(flat(read('docs/security-pack/support-and-maintenance.md'))).toContain('Public: a pull needs no login.');
        expect(flat(read('docs/roadmap.md'))).toContain('The image is public (owner decision, 2026-11-12, issue 19)');
        // No document tells a client to log in to the registry, and the chart ships no pull secret.
        for (const doc of ['docs/verify-a-release.md', 'docs/deployment.md', 'docs/quick-start.md', 'docs/guide/run-it.md', 'docs/scanner.md', 'README.md']) {
            expect([doc, /docker login ghcr\.io|podman login ghcr\.io/.test(read(doc))]).toEqual([doc, false]);
        }
        expect(read('deploy/helm/scanent/values.yaml')).toMatch(/^imagePullSecrets: \[\]$/m);
        // The open question is closed where it was asked.
        for (const doc of ['docs/roadmap.md', 'docs/security-pack/assurance-status.md', 'docs/security-pack/support-and-maintenance.md']) {
            expect([doc, /open owner decision \(issue 19\)|waits on an owner decision/.test(flat(read(doc)).replace('Changing the default is an open decision (issue 19)', ''))]).toEqual([doc, false]);
        }
    });

    it('the release checklist has the step that makes the image public, after the first push, and says it cannot be undone', () => {
        const checklist = read('docs/release-checklist.md');
        const after = checklist.slice(checklist.indexOf('## After the tag'), checklist.indexOf('## What has never been run'));
        expect(flat(after)).toContain('**Make the image public** (done 2026-11-13, after 0.13.1 created the package). The organisation must allow public packages first');
        expect(flat(after)).toContain('GitHub creates a package private');
        for (const control of ['**Packages** tab', '**Package settings**', '"Danger Zone"', '**Change visibility**', '**Public**']) expect(flat(after)).toContain(control);
        expect(flat(after)).toContain('It cannot be made private again.');
        expect(flat(after)).toContain('**With no login** (`docker logout ghcr.io` first): `docker pull ghcr.io/rodnapamet/scanent:<version>` succeeds.');
        // And it has the package: published, attested, installable.
        expect(flat(after)).toContain(`gh attestation verify rodnapamet-scanent-contract-<version>.tgz --repo RodnaPamet/scanent`);
        expect(flat(checklist)).toContain('**0.13.2 is the first complete release** (2026-11-13).');
        const never = checklist.slice(checklist.indexOf('## What has never been run'));
        expect(flat(never)).toContain('`npm publish` to GitHub Packages');
        expect(flat(never)).toContain('A pull of the image with no login');
    });
});
