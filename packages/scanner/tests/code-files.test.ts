/**
 * Which files the `code` source reads, and how far (#3737) — over an in-memory
 * file system, so every bound and every refusal is reached without a disk.
 *
 *   1. The walk: sorted, depth-first, source files only, and only those that
 *      name a framework are handed on.
 *   2. What is never entered or followed: dependency and build directories,
 *      symbolic links, anything that is neither a file nor a directory.
 *   3. Every bound is reported where it was reached: file size, file count,
 *      total bytes, depth, and the deadline.
 *   4. What the operating system refused is AUTH_FAILED; what is missing is
 *      UNREACHABLE; one bad root does not stop the next.
 */
import {
    FRAMEWORK_MARKERS,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    readCodeFiles,
    SKIPPED_DIRECTORIES,
    SOURCE_EXTENSIONS,
    type CodeFs,
    type CodeRoot,
    type ReadableFile,
} from '../src/sources/code/files';

type Node =
    | { readonly t: 'dir'; readonly entries: Record<string, Node>; readonly readdirError?: string }
    | { readonly t: 'file'; readonly data: Buffer; readonly statedSize?: number; readonly readError?: string }
    | { readonly t: 'link' }
    | { readonly t: 'socket' }
    | { readonly t: 'broken'; readonly code: string };

const dir = (entries: Record<string, Node>, readdirError?: string): Node => ({ t: 'dir', entries, readdirError });
const file = (text: string | Buffer, extra: { statedSize?: number; readError?: string } = {}): Node => ({
    t: 'file',
    data: typeof text === 'string' ? Buffer.from(text) : text,
    ...extra,
});
const AGENT = 'from langchain.agents import AgentExecutor\n';
const failure = (code: string) => Object.assign(new Error(code), { code });

/** A `CodeFs` over a tree, recording every operation it was asked for. */
function fakeFs(tree: Record<string, Node>) {
    const ops: string[] = [];
    const find = (path: string): Node | undefined => {
        const parts = path.split('/').filter((p) => p !== '');
        let node: Node | undefined = dir(tree);
        for (const part of parts) {
            if (node?.t !== 'dir') return undefined;
            node = node.entries[part];
        }
        return node;
    };
    const fs: CodeFs = {
        async lstat(path) {
            ops.push(`lstat ${path}`);
            const node = find(path);
            if (node === undefined) throw failure('ENOENT');
            if (node.t === 'broken') throw failure(node.code);
            return {
                isDirectory: () => node.t === 'dir',
                isFile: () => node.t === 'file',
                isSymbolicLink: () => node.t === 'link',
                size: node.t === 'file' ? (node.statedSize ?? node.data.length) : 0,
            };
        },
        async readdir(path) {
            ops.push(`readdir ${path}`);
            const node = find(path);
            if (node?.t !== 'dir') throw failure('ENOTDIR');
            if (node.readdirError) throw failure(node.readdirError);
            // Deliberately unsorted: the walk must not depend on the order it is given.
            return Object.keys(node.entries).reverse();
        },
        async readFile(path) {
            ops.push(`readFile ${path}`);
            const node = find(path);
            if (node?.t !== 'file') throw failure('EISDIR');
            if (node.readError) throw failure(node.readError);
            return node.data;
        },
    };
    return { fs, ops };
}

const ROOT: CodeRoot = { label: 'acme', path: '/src' };
const NEVER = { deadline: Number.MAX_SAFE_INTEGER, now: () => 0 };

async function walk(tree: Record<string, Node>, roots: readonly CodeRoot[] = [ROOT], clock = NEVER) {
    const { fs, ops } = fakeFs(tree);
    const files: ReadableFile[] = [];
    const result = await readCodeFiles(roots, fs, clock, (f) => files.push(f));
    return { ...result, files, ops, paths: files.map((f) => f.path) };
}
const at = (path: string, label = 'acme') => ({ label, path, line: 0 });

describe('1. the walk', () => {
    it('reads a tree depth-first in sorted order, whatever order the directory lists', async () => {
        const { paths, rows, problems } = await walk({
            src: dir({
                'b.py': file(AGENT),
                a: dir({ 'z.ts': file(AGENT), 'y.ts': file(AGENT) }),
                'a.py': file(AGENT),
                c: dir({ deep: dir({ 'x.mjs': file(AGENT) }) }),
            }),
        });
        expect(paths).toEqual(['a/y.ts', 'a/z.ts', 'a.py', 'b.py', 'c/deep/x.mjs']);
        expect(rows).toBe(5);
        expect(problems).toEqual([]);
    });

    it('counts every source file examined, and hands on only those that name a framework', async () => {
        const { files, rows, problems } = await walk({
            src: dir({
                'agent.py': file(AGENT),
                'graph.ts': file('import { StateGraph } from "@langchain/langgraph";\n'),
                'sdk.ts': file('import { query } from "@anthropic-ai/claude-agent-sdk";\n'),
                'sdk.py': file('from claude_agent_sdk import query\n'),
                'plain.py': file('print("hello")\n'),
                'empty.js': file(''),
            }),
        });
        expect(files.map((f) => f.path)).toEqual(['agent.py', 'graph.ts', 'sdk.py', 'sdk.ts']);
        expect(files[0]).toEqual({ label: 'acme', path: 'agent.py', text: AGENT });
        expect(rows).toBe(6);
        expect(problems).toEqual([]);
        expect(FRAMEWORK_MARKERS).toEqual(['langchain', 'langgraph', 'claude-agent-sdk', 'claude_agent_sdk']);
    });

    it('reads every source extension in any case, and nothing else — not even a declaration file', async () => {
        const entries: Record<string, Node> = {};
        for (const ext of SOURCE_EXTENSIONS) entries[`f${ext}`] = file(AGENT);
        const { paths, rows, ops } = await walk({
            src: dir({
                ...entries,
                'UPPER.PY': file(AGENT),
                'types.d.ts': file(AGENT),
                'types.d.mts': file(AGENT),
                'TYPES.D.CTS': file(AGENT),
                'notes.md': file(AGENT),
                'data.json': file(AGENT),
                Makefile: file(AGENT),
                'agent.py.bak': file(AGENT),
            }),
        });
        expect(paths.sort()).toEqual(['UPPER.PY', ...SOURCE_EXTENSIONS.map((ext) => `f${ext}`)].sort());
        expect(rows).toBe(SOURCE_EXTENSIONS.length + 1);
        // A file that is not source is never opened.
        expect(ops.filter((op) => op.startsWith('readFile')).some((op) => /notes\.md|data\.json|Makefile|\.bak|\.d\./i.test(op))).toBe(false);
    });

    it('reports a location by the root\'s label and the path below it, with or without a trailing slash on the root', async () => {
        const tree = { src: dir({ pkg: dir({ 'agent.py': file(AGENT) }) }) };
        for (const path of ['/src', '/src/']) {
            const { files, ops } = await walk(tree, [{ label: 'estate', path }]);
            expect(files).toEqual([{ label: 'estate', path: 'pkg/agent.py', text: AGENT }]);
            expect(ops).toContain('readFile /src/pkg/agent.py');
        }
    });

    it('reads each root in the order configured, under its own label', async () => {
        const { files } = await walk(
            { two: dir({ 'b.py': file(AGENT) }), one: dir({ 'a.py': file(AGENT) }) },
            [
                { label: 'second', path: '/two' },
                { label: 'first', path: '/one' },
            ],
        );
        expect(files.map((f) => `${f.label}:${f.path}`)).toEqual(['second:b.py', 'first:a.py']);
    });

    it('only ever stats, lists and reads', async () => {
        const { ops } = await walk({ src: dir({ a: dir({ 'x.py': file(AGENT) }) }) });
        expect(ops).toEqual(['lstat /src', 'readdir /src', 'lstat /src/a', 'readdir /src/a', 'lstat /src/a/x.py', 'readFile /src/a/x.py']);
    });
});

describe('2. what is never entered or followed', () => {
    it('does not enter a dependency or build directory at any depth, and says nothing about it', async () => {
        const skipped: Record<string, Node> = {};
        for (const name of SKIPPED_DIRECTORIES) skipped[name] = dir({ 'agent.py': file(AGENT) });
        const { paths, rows, problems, ops } = await walk({
            src: dir({ ...skipped, app: dir({ node_modules: dir({ 'agent.js': file(AGENT) }), 'agent.py': file(AGENT) }) }),
        });
        expect(paths).toEqual(['app/agent.py']);
        expect(rows).toBe(1);
        expect(problems).toEqual([]);
        expect(ops.filter((op) => op.startsWith('readdir'))).toEqual(['readdir /src', 'readdir /src/app']);
    });

    it('a root is read whatever it is called, and a file named like a skipped directory is a file', async () => {
        const { paths } = await walk({ dist: dir({ 'agent.py': file(AGENT), build: dir({ 'x.py': file(AGENT) }) }) }, [{ label: 'acme', path: '/dist' }]);
        expect(paths).toEqual(['agent.py']);
        const named = await walk({ src: dir({ 'dist.py': file(AGENT), 'build.ts': file(AGENT) }) });
        expect(named.paths).toEqual(['build.ts', 'dist.py']);
    });

    it('never follows a symbolic link, to a file or a directory: it is a location not read', async () => {
        const { paths, problems, ops } = await walk({
            src: dir({ 'linked.py': { t: 'link' }, vendor: { t: 'link' }, 'real.py': file(AGENT) }),
        });
        expect(paths).toEqual(['real.py']);
        expect(problems).toEqual([
            { reason: 'UNREACHABLE', at: at('linked.py') },
            { reason: 'UNREACHABLE', at: at('vendor') },
        ]);
        expect(ops).not.toContain('readFile /src/linked.py');
        expect(ops).not.toContain('readdir /src/vendor');
    });

    it('passes over what is neither a file nor a directory, even with a source extension', async () => {
        const { paths, rows, problems } = await walk({ src: dir({ 'pipe.py': { t: 'socket' }, 'real.py': file(AGENT) }) });
        expect(paths).toEqual(['real.py']);
        expect(rows).toBe(1);
        expect(problems).toEqual([]);
    });
});

describe('3. every bound is reported where it was reached', () => {
    it('a file over the size limit is not opened, and the walk carries on', async () => {
        const { paths, rows, problems, ops } = await walk({
            src: dir({
                'big.py': file(AGENT, { statedSize: MAX_FILE_BYTES + 1 }),
                'exact.py': file(AGENT, { statedSize: MAX_FILE_BYTES }),
                'small.py': file(AGENT),
            }),
        });
        expect(paths).toEqual(['exact.py', 'small.py']);
        expect(rows).toBe(3);
        expect(problems).toEqual([{ reason: 'BYTE_CAP', at: at('big.py') }]);
        expect(ops).not.toContain('readFile /src/big.py');
    });

    it('a file that grew past the limit between the stat and the read is not used', async () => {
        const grown = Buffer.concat([Buffer.from(AGENT), Buffer.alloc(MAX_FILE_BYTES, 0x20)]);
        const { paths, problems } = await walk({ src: dir({ 'grew.py': file(grown, { statedSize: 10 }), 'next.py': file(AGENT) }) });
        expect(paths).toEqual(['next.py']);
        expect(problems).toEqual([{ reason: 'BYTE_CAP', at: at('grew.py') }]);
    });

    it('stops at the total byte budget, at the file that would exceed it', async () => {
        const full = Buffer.alloc(MAX_FILE_BYTES, 0x20);
        const entries: Record<string, Node> = {};
        const count = MAX_TOTAL_BYTES / MAX_FILE_BYTES;
        for (let i = 0; i < count; i += 1) entries[`f${String(i).padStart(4, '0')}.py`] = file(full);
        entries['g-over.py'] = file(AGENT);
        entries['h-never.py'] = file(AGENT);
        const { paths, rows, problems, ops } = await walk({ src: dir(entries), later: dir({ 'agent.py': file(AGENT) }) }, [
            ROOT,
            { label: 'later', path: '/later' },
        ]);
        expect(paths).toEqual([]);
        expect(rows).toBe(count + 1);
        expect(problems).toEqual([{ reason: 'BYTE_CAP', at: at('g-over.py') }]);
        // Nothing after the stop is touched: not the next file, not the next root.
        expect(ops).not.toContain('lstat /src/h-never.py');
        expect(ops).not.toContain('lstat /later');
    });

    it('stops at the file-count limit, and reports the first file past it', async () => {
        const entries: Record<string, Node> = {};
        const shared = file('x = 1\n');
        for (let i = 0; i <= MAX_FILES + 1; i += 1) entries[`f${String(i).padStart(6, '0')}.py`] = shared;
        const { rows, problems, ops } = await walk({ src: dir(entries) });
        expect(rows).toBe(MAX_FILES + 1);
        expect(problems).toEqual([{ reason: 'BYTE_CAP', at: at(`f${String(MAX_FILES).padStart(6, '0')}.py`) }]);
        expect(ops.filter((op) => op.startsWith('readFile'))).toHaveLength(MAX_FILES);
    });

    it('stops descending at the depth limit, reports where, and reads what is beside it', async () => {
        let node: Node = dir({ 'bottom.py': file(AGENT) });
        const names: string[] = [];
        for (let i = 0; i < 40; i += 1) {
            names.unshift(`d${i}`);
            node = dir({ [`d${i}`]: node, 'beside.py': file(AGENT) });
        }
        const { paths, problems } = await walk({ src: node });
        expect(paths).not.toContain(`${names.join('/')}/bottom.py`);
        expect(problems).toHaveLength(1);
        expect(problems[0].reason).toBe('BYTE_CAP');
        // 32 levels below the root are read; the 33rd is where it stops.
        expect(problems[0].at!.path.split('/')).toHaveLength(33);
        expect(paths.filter((p) => p.endsWith('beside.py'))).toHaveLength(33);
    });

    it('stops at the deadline, once, with no location: it is the scan that ran out, not a file', async () => {
        let ticks = 0;
        const clock = { deadline: 3, now: () => (ticks += 1) };
        const { paths, problems, ops } = await walk(
            { src: dir({ 'a.py': file(AGENT), 'b.py': file(AGENT), 'c.py': file(AGENT), 'd.py': file(AGENT) }), next: dir({ 'e.py': file(AGENT) }) },
            [ROOT, { label: 'next', path: '/next' }],
            clock,
        );
        // now() is 1 entering the root, 2 and 3 before the first two files, 4 before the third.
        expect(paths).toEqual(['a.py', 'b.py']);
        expect(problems).toEqual([{ reason: 'TIME_BOX', at: null }]);
        expect(ops).not.toContain('lstat /src/c.py');
        expect(ops).not.toContain('lstat /next');
    });

    it('a deadline already past reads nothing below the root, and one found inside a directory stops its parents too', async () => {
        const past = await walk({ src: dir({ 'a.py': file(AGENT) }) }, [ROOT], { deadline: 0, now: () => 1 });
        expect(past.paths).toEqual([]);
        expect(past.problems).toEqual([{ reason: 'TIME_BOX', at: null }]);
        expect(past.ops).toEqual(['lstat /src']);

        let ticks = 0;
        const nested = await walk({ src: dir({ a: dir({ 'x.py': file(AGENT) }), 'z.py': file(AGENT) }) }, [ROOT], { deadline: 2, now: () => (ticks += 1) });
        expect(nested.paths).toEqual([]);
        expect(nested.problems).toEqual([{ reason: 'TIME_BOX', at: null }]);
        expect(nested.ops).not.toContain('lstat /src/z.py');
    });
});

describe('4. what could not be read', () => {
    it.each([
        ['EACCES', 'AUTH_FAILED'],
        ['EPERM', 'AUTH_FAILED'],
        ['ENOENT', 'UNREACHABLE'],
        ['EIO', 'UNREACHABLE'],
    ])('a root whose stat fails with %s is %s, and the next root is still read', async (code, reason) => {
        const { paths, problems } = await walk({ locked: { t: 'broken', code }, src: dir({ 'agent.py': file(AGENT) }) }, [
            { label: 'locked', path: '/locked' },
            ROOT,
        ]);
        expect(problems).toEqual([{ reason, at: at('', 'locked') }]);
        expect(paths).toEqual(['agent.py']);
    });

    it('a root that is missing, a file or a link is UNREACHABLE', async () => {
        const { problems, ops } = await walk({ 'file.py': file(AGENT), link: { t: 'link' } }, [
            { label: 'missing', path: '/nowhere' },
            { label: 'file', path: '/file.py' },
            { label: 'link', path: '/link' },
        ]);
        expect(problems).toEqual([
            { reason: 'UNREACHABLE', at: at('', 'missing') },
            { reason: 'UNREACHABLE', at: at('', 'file') },
            { reason: 'UNREACHABLE', at: at('', 'link') },
        ]);
        expect(ops.some((op) => op.startsWith('readFile') || op.startsWith('readdir'))).toBe(false);
    });

    it.each([
        ['EACCES', 'AUTH_FAILED'],
        ['EPERM', 'AUTH_FAILED'],
        ['EMFILE', 'UNREACHABLE'],
    ])('a directory that cannot be listed (%s) is %s, at the directory, and its siblings are read', async (code, reason) => {
        const { paths, problems } = await walk({ src: dir({ private: dir({ 'agent.py': file(AGENT) }, code), 'agent.py': file(AGENT) }) });
        expect(problems).toEqual([{ reason, at: at('private') }]);
        expect(paths).toEqual(['agent.py']);
    });

    it('a root that cannot be listed is reported at the root', async () => {
        const { problems } = await walk({ src: dir({}, 'EACCES') });
        expect(problems).toEqual([{ reason: 'AUTH_FAILED', at: at('') }]);
    });

    it('an entry whose stat fails, and a file whose read fails, are each reported and passed over', async () => {
        const { paths, rows, problems } = await walk({
            src: dir({
                'a-gone.py': { t: 'broken', code: 'ENOENT' },
                'b-denied.py': { t: 'broken', code: 'EACCES' },
                'c-unreadable.py': file(AGENT, { readError: 'EPERM' }),
                'd-failed.py': file(AGENT, { readError: 'EIO' }),
                'e-fine.py': file(AGENT),
            }),
        });
        expect(problems).toEqual([
            { reason: 'UNREACHABLE', at: at('a-gone.py') },
            { reason: 'AUTH_FAILED', at: at('b-denied.py') },
            { reason: 'AUTH_FAILED', at: at('c-unreadable.py') },
            { reason: 'UNREACHABLE', at: at('d-failed.py') },
        ]);
        expect(paths).toEqual(['e-fine.py']);
        // A file that was found counts as examined even when its read failed.
        expect(rows).toBe(3);
    });

    it('a failure that carries no code, or is not an error at all, is UNREACHABLE', async () => {
        const fs: CodeFs = {
            lstat: async (path) => {
                if (path === '/a') throw new Error('no code');
                if (path === '/b') throw null;
                throw 'a string';
            },
            readdir: async () => [],
            readFile: async () => Buffer.alloc(0),
        };
        const result = await readCodeFiles(
            ['a', 'b', 'c'].map((label) => ({ label, path: `/${label}` })),
            fs,
            NEVER,
            () => undefined,
        );
        expect(result.problems.map((p) => p.reason)).toEqual(['UNREACHABLE', 'UNREACHABLE', 'UNREACHABLE']);
    });

    it('no roots, and an empty root, read nothing and report nothing', async () => {
        expect(await walk({}, [])).toMatchObject({ rows: 0, problems: [], paths: [] });
        expect(await walk({ src: dir({}) })).toMatchObject({ rows: 0, problems: [], paths: [] });
    });
});
