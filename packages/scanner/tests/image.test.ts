/**
 * The image's build files, held to each other.
 *
 * `deploy/smoke.sh` is the behavioural check of a built image; it needs a
 * container runtime and runs in CI. These are the properties a text read can
 * hold on every `npm test`: the build context is exactly what the Dockerfile
 * copies, the base is pinned by digest, the runtime stage takes nothing from
 * the checkout, and the workflow's actions are pinned by commit.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const read = (rel: string): string => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');

/** The Dockerfile's instructions, comments dropped and continuation lines joined. */
function instructions(dockerfile: string): string[] {
    return dockerfile
        .split('\n')
        .filter((line) => !line.trimStart().startsWith('#'))
        .join('\n')
        .replace(/\\\n/g, ' ')
        .split('\n')
        .map((line) => line.trim().replace(/\s+/g, ' '))
        .filter((line) => line.length > 0);
}

interface Stage {
    readonly name: string;
    readonly from: string;
    readonly lines: readonly string[];
}

function stages(dockerfile: string): Stage[] {
    const out: Array<{ name: string; from: string; lines: string[] }> = [];
    for (const line of instructions(dockerfile)) {
        const from = /^FROM (\S+) AS (\S+)$/.exec(line);
        if (from) out.push({ name: from[2], from: from[1], lines: [] });
        else if (out.length > 0) out[out.length - 1].lines.push(line);
        else throw new Error(`instruction before the first FROM: ${line}`);
    }
    return out;
}

const dockerfile = read('deploy/Dockerfile');
const [build, runtime, ...others] = stages(dockerfile);

describe('deploy/Dockerfile', () => {
    it('has exactly a build stage and a runtime stage, in that order', () => {
        expect(others).toEqual([]);
        expect([build.name, runtime.name]).toEqual(['build', 'runtime']);
    });

    it('pins both stages to one base image by digest', () => {
        expect(build.from).toMatch(/^node:24-alpine@sha256:[0-9a-f]{64}$/);
        expect(runtime.from).toBe(build.from);
    });

    it('copies into the build stage exactly what the build context allowlist lets in', () => {
        const copied = build.lines
            .filter((line) => line.startsWith('COPY '))
            .flatMap((line) => line.split(' ').slice(1, -1))
            .sort();
        const rules = read('.dockerignore')
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.length > 0 && !line.startsWith('#'));
        expect(rules[0]).toBe('*');
        const allowed = rules.slice(1);
        expect(allowed.every((rule) => rule.startsWith('!'))).toBe(true);
        expect(allowed.map((rule) => rule.slice(1)).sort()).toEqual(copied);
        expect(copied.length).toBeGreaterThan(0);
    });

    it('takes every file of the runtime stage from the build stage, never from the checkout', () => {
        const copies = runtime.lines.filter((line) => line.startsWith('COPY '));
        expect(copies.length).toBeGreaterThan(0);
        for (const line of copies) expect(line).toMatch(/^COPY --from=build \/src\/\S+ \.\/\S+$/);
    });

    it('copies compiled output and manifests into the runtime stage, and no source', () => {
        const sources = runtime.lines.filter((line) => line.startsWith('COPY ')).map((line) => line.split(' ')[2]);
        expect([...sources].sort()).toEqual([
            '/src/node_modules',
            '/src/packages/contract/dist',
            '/src/packages/contract/package.json',
            '/src/packages/scanner/dist',
            '/src/packages/scanner/node_modules',
            '/src/packages/scanner/package.json',
        ]);
    });

    it('installs with the lockfile and no install scripts, and prunes to production before the runtime copies', () => {
        const installs = build.lines.filter((line) => /\bnpm (ci|install|i)\b/.test(line));
        expect(installs).toHaveLength(2);
        for (const line of installs) expect(line).toMatch(/^RUN npm ci (--omit=dev )?--ignore-scripts /);
        expect(installs[1]).toContain('--omit=dev');
        expect(runtime.lines.some((line) => /\bnpm (ci|install|i)\b/.test(line))).toBe(false);
    });

    it('removes the package managers from the runtime stage and asserts they are gone', () => {
        const removal = runtime.lines.find((line) => line.startsWith('RUN rm -rf '));
        expect(removal).toBeDefined();
        for (const tool of ['npm', 'npx', 'corepack']) {
            expect(removal).toContain(`/usr/local/bin/${tool}`);
            expect(removal).toContain(`! command -v ${tool}`);
        }
    });

    it('runs as the non-root node user, set after the last file is copied', () => {
        const user = runtime.lines.filter((line) => line.startsWith('USER '));
        expect(user).toEqual(['USER node']);
        const lastCopy = runtime.lines.map((line) => line.startsWith('COPY ')).lastIndexOf(true);
        expect(runtime.lines.indexOf('USER node')).toBeGreaterThan(lastCopy);
    });

    it('starts the compiled command line directly, in exec form, on the schedule by default', () => {
        const entrypoint = runtime.lines.find((line) => line.startsWith('ENTRYPOINT '));
        const cmd = runtime.lines.find((line) => line.startsWith('CMD '));
        expect(JSON.parse(entrypoint!.slice('ENTRYPOINT '.length))).toEqual(['node', '/app/packages/scanner/dist/cli.js']);
        expect(JSON.parse(cmd!.slice('CMD '.length))).toEqual(['schedule', '--config', '/etc/scanent/config.json']);
    });

    it('declares the command line the entrypoint names as the scanner package bins', () => {
        const manifest = JSON.parse(read('packages/scanner/package.json')) as { bin: Record<string, string> };
        expect(manifest.bin).toEqual({ scanent: './dist/cli.js', aes: './dist/cli.js' });
    });
});

describe('.github/workflows', () => {
    const dir = path.join(REPO_ROOT, '.github/workflows');
    const uses = fs
        .readdirSync(dir)
        .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
        .flatMap((name) =>
            fs
                .readFileSync(path.join(dir, name), 'utf8')
                .split('\n')
                .map((line) => /^\s*(?:- )?uses:\s*(.+)$/.exec(line)?.[1])
                .filter((ref): ref is string => ref !== undefined),
        );

    it('pins every action to a full commit SHA, with the version beside it', () => {
        expect(uses.length).toBeGreaterThan(0);
        for (const ref of uses) expect(ref).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40} # v\d+(\.\d+){0,2}$/);
    });
});
