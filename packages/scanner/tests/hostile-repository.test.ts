/**
 * A hostile repository, on a real file system.
 *
 * The `code` source is pointed at a directory somebody else wrote. This suite
 * builds the worst such tree it can in a temporary directory (so nothing
 * hostile is committed) and reads it with the real file system:
 *
 *   1. Links: to the tree's own parent, out of the root, to nowhere. None is
 *      followed, and nothing outside the root is opened.
 *   2. Size: a file over the cap, and a sparse file that claims gigabytes, are
 *      not opened at all.
 *   3. Depth: two thousand directories deep stops at the depth bound.
 *   4. Content: binary under a source name, invalid UTF-8, UTF-16.
 *   5. Names: a newline in a file name, a name that looks like an option.
 *   6. A pipe: never opened, whether it was a pipe when it was looked at or
 *      became one afterwards.
 *   7. A tree that changes while it is read: a file that grows, one swapped
 *      for a link out of the root, one that vanishes.
 *   8. The bounds a real tree cannot reach cheaply (the file count, the total
 *      bytes), through a file system that only claims them.
 *
 * For all of it: the read ends, each problem is reported with a reason, the
 * source is INCOMPLETE and never complete with fewer files, the agents in the
 * good files are still reported, and the tree is left as it was.
 */
import { execFileSync } from 'child_process';
import { appendFileSync, closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, relative } from 'path';

import { createSourceWire } from '../src/http';
import { MAX_FILE_BYTES, MAX_FILES, MAX_MARKER_SCAN_BYTES, MAX_TOTAL_BYTES, readCodeFiles, type CodeFs, type ReadableFile } from '../src/sources/code/files';
import { langchainCodeSource, NODE_CODE_FS } from '../src/sources/langchain';
import { LANGCHAIN_PYTHON } from './helpers/agent-harness-code-fixtures';

// A slow runner must not fail a test that is only slow.
jest.setTimeout(60_000);

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const GOOD = LANGCHAIN_PYTHON[Object.keys(LANGCHAIN_PYTHON)[0]];
const AGENT_LINE = 'from langchain.agents import AgentExecutor\nstolen = AgentExecutor(agent=None, tools=[])\n';

/** The real file system, with every operation recorded, and a hook that runs between a file's stat and its read. */
function recordingFs(betweenStatAndRead: (path: string) => void = () => undefined) {
    const ops: { op: 'lstat' | 'readdir' | 'readFile'; path: string }[] = [];
    const fs: CodeFs = {
        lstat: async (p) => {
            ops.push({ op: 'lstat', path: p });
            return NODE_CODE_FS.lstat(p);
        },
        readdir: async (p) => {
            ops.push({ op: 'readdir', path: p });
            return NODE_CODE_FS.readdir(p);
        },
        readFile: async (p) => {
            ops.push({ op: 'readFile', path: p });
            betweenStatAndRead(p);
            return NODE_CODE_FS.readFile(p);
        },
    };
    return { fs, ops };
}

const noNetwork = async (): Promise<Response> => {
    throw new Error('the code source reaches no network');
};
const ctx = () => ({ asOf: new Date(NOW), deadline: NOW + 60_000, now: () => NOW, ...createSourceWire({ fetchImpl: noNetwork, deadline: NOW + 60_000, now: () => NOW }) });

async function walk(root: string, fs: CodeFs) {
    const files: ReadableFile[] = [];
    const { rows, problems } = await readCodeFiles([{ label: 'hostile', path: root }], fs, { deadline: NOW + 60_000, now: () => NOW }, (f) => files.push(f));
    return { rows, files, problems: problems.map((p) => `${p.reason} ${p.at?.path ?? '(scan)'}`) };
}

/** Every entry under a directory with its kind, size and modification time: what "left as it was" means. */
function snapshot(dir: string): string[] {
    const out: string[] = [];
    const visit = (at: string, depth: number): void => {
        for (const name of readdirSync(at).sort()) {
            const full = join(at, name);
            const st = lstatSync(full);
            out.push(`${relative(dir, full)} ${st.isSymbolicLink() ? 'link' : st.isDirectory() ? 'dir' : st.isFIFO() ? 'fifo' : 'file'} ${st.isFile() ? st.size : 0} ${st.mtimeMs}`);
            if (st.isDirectory() && depth < 40) visit(full, depth + 1);
        }
    };
    visit(dir, 0);
    return out;
}

let base: string;
let root: string;
let outside: string;
let hasFifo = false;

beforeAll(() => {
    base = mkdtempSync(join(tmpdir(), 'scanent-hostile-'));
    root = join(base, 'repo');
    outside = join(base, 'outside');
    mkdirSync(root);
    mkdirSync(outside);
    // What must never be read: an agent definition outside the root.
    writeFileSync(join(outside, 'secret_agent.py'), AGENT_LINE);

    writeFileSync(join(root, 'good.py'), GOOD);
    // 1. Links.
    symlinkSync('..', join(root, 'loop'));
    symlinkSync(outside, join(root, 'escape'));
    symlinkSync(join(outside, 'secret_agent.py'), join(root, 'linked_agent.py'));
    symlinkSync(join(base, 'nowhere'), join(root, 'dangling.py'));
    // 2. Size.
    writeFileSync(join(root, 'big.py'), Buffer.concat([Buffer.from(AGENT_LINE), Buffer.alloc(MAX_FILE_BYTES, 0x23)]));
    closeSync(openSync(join(root, 'sparse.py'), 'w'));
    truncateSync(join(root, 'sparse.py'), 8 * 1024 * 1024 * 1024);
    // 3. Depth: two thousand levels, made one step at a time so no path passes the system's limit.
    let deep = join(root, 'deep');
    mkdirSync(deep);
    for (let i = 0; i < 2_000; i++) {
        deep = join(deep, 'd');
        try {
            mkdirSync(deep);
        } catch {
            break; // the path limit of this system: the tree is as deep as it can be made
        }
    }
    // 4. Content.
    writeFileSync(join(root, 'binary.py'), Buffer.concat([Buffer.from('langchain\n'), Buffer.from(Array.from({ length: 8192 }, (_, i) => (i * 131) % 256))]));
    writeFileSync(join(root, 'invalid_utf8.py'), Buffer.concat([Buffer.from('import langchain\nname = "'), Buffer.from([0xff, 0xc0, 0x80, 0xed, 0xa0, 0x80]), Buffer.from('"\nagent = (\n')]));
    writeFileSync(join(root, 'wide.py'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(GOOD, 'utf16le')]));
    // 5. Names.
    writeFileSync(join(root, 'new\nline.py'), GOOD);
    writeFileSync(join(root, '--out'), 'not a source file');
    writeFileSync(join(root, '--config.py'), GOOD);
    // 6. A pipe, where the platform has one.
    try {
        execFileSync('mkfifo', [join(root, 'pipe.py')]);
        hasFifo = true;
    } catch {
        hasFifo = false;
    }
});

afterAll(() => {
    // The deep chain is taken apart one level at a time first: a recursive removal of two thousand levels overflows the stack.
    let level = join(root, 'deep');
    for (let i = 0; existsSync(join(level, 'd')); i++) {
        const moved = join(base, `level-${i}`);
        renameSync(join(level, 'd'), moved);
        level = moved;
    }
    rmSync(base, { recursive: true, force: true });
});

describe('the tree as it stands', () => {
    let result: Awaited<ReturnType<typeof walk>>;
    let ops: ReturnType<typeof recordingFs>['ops'];
    let before: string[];
    let elapsedMs: number;
    let heapGrowth: number;

    beforeAll(async () => {
        before = snapshot(root);
        const rec = recordingFs();
        ops = rec.ops;
        global.gc?.();
        const heap = process.memoryUsage().heapUsed;
        const started = Date.now();
        result = await walk(root, rec.fs);
        elapsedMs = Date.now() - started;
        heapGrowth = process.memoryUsage().heapUsed - heap;
    });

    it('ends quickly, and holds little: nothing over the cap was read into memory', () => {
        expect(elapsedMs).toBeLessThan(15_000);
        // The tree claims 8 GiB and holds 1 MiB over the cap; the read may keep a few files of text.
        expect(heapGrowth).toBeLessThan(64 * 1024 * 1024);
    });

    it('1. no link is followed: each is a location not read', () => {
        for (const link of ['loop', 'escape', 'linked_agent.py', 'dangling.py']) expect(result.problems).toContain(`UNREACHABLE ${link}`);
        // A link is looked at and never listed or opened.
        for (const link of ['loop', 'escape', 'linked_agent.py', 'dangling.py']) {
            expect(ops.filter((o) => o.path === join(root, link)).map((o) => o.op)).toEqual(['lstat']);
        }
    });

    it('1b. nothing outside the root was touched', () => {
        expect(ops.length).toBeGreaterThan(10);
        for (const { path } of ops) expect(path === root || path.startsWith(`${root}/`)).toBe(true);
        for (const { path } of ops) expect(path.split('/')).not.toContain('..');
        expect(result.files.map((f) => f.text).join('')).not.toContain('stolen');
    });

    it('2. a file too large to parse that names a framework is reported; one that claims gigabytes is never opened', () => {
        // Over the per-file limit and naming a framework: searched, not parsed, and reported.
        expect(result.problems).toContain('BYTE_CAP big.py');
        expect(result.files.map((f) => f.path)).not.toContain('big.py');
        // Over the most that is ever read of one file: not opened at all.
        expect(result.problems).toContain('BYTE_CAP sparse.py');
        const opened = ops.filter((o) => o.op === 'readFile').map((o) => relative(root, o.path));
        expect(opened).not.toContain('sparse.py');
    });

    it('3. the walk stops at the depth bound, says where, and does not list below it', () => {
        const depthProblems = result.problems.filter((p) => p.startsWith('BYTE_CAP deep/'));
        expect(depthProblems).toHaveLength(1);
        const deepest = Math.max(...ops.filter((o) => o.op === 'readdir').map((o) => relative(root, o.path).split('/').length));
        expect(deepest).toBeLessThanOrEqual(34);
    });

    it('4. binary under a source name is read as text that names no agent; a UTF-16 file is reported', () => {
        expect(result.problems).toContain('UNPARSEABLE wide.py');
        expect(result.files.map((f) => f.path)).toContain('binary.py');
        expect(result.files.map((f) => f.path)).toContain('invalid_utf8.py');
        expect(result.files.map((f) => f.path)).not.toContain('wide.py');
    });

    it('5. a name is data: one with a newline and one shaped like an option are files like any other', () => {
        expect(result.files.map((f) => f.path)).toEqual(expect.arrayContaining(['new\nline.py', '--config.py', 'good.py']));
        // Not a source extension: looked at, not read.
        expect(ops.filter((o) => o.path === join(root, '--out')).map((o) => o.op)).toEqual(['lstat']);
    });

    it('6. a pipe with a source name is passed over and never opened', () => {
        if (!hasFifo) return;
        expect(ops.filter((o) => o.path === join(root, 'pipe.py')).map((o) => o.op)).toEqual(['lstat']);
        expect(result.problems.some((p) => p.endsWith(' pipe.py'))).toBe(false);
    });

    it('only stats, lists and reads; and the tree is as it was', () => {
        expect([...new Set(ops.map((o) => o.op))].sort()).toEqual(['lstat', 'readFile', 'readdir']);
        expect(snapshot(root)).toEqual(before);
    });

    it('the source is INCOMPLETE, names the gravest reason, and still reports the agents of the good files', async () => {
        const alone = mkdtempSync(join(base, 'alone-'));
        writeFileSync(join(alone, 'good.py'), GOOD);
        const expected = (await langchainCodeSource({ roots: [{ label: 'hostile', path: alone }] }).read(ctx())).observations.map((o) => o.discoveredId);
        expect(expected.length).toBeGreaterThan(0);

        const read = await langchainCodeSource({ roots: [{ label: 'hostile', path: root }] }).read(ctx());
        expect(read.status).toBe('INCOMPLETE');
        // What was not read at all outranks what was too big or did not parse.
        expect(read.reason).toBe('UNREACHABLE');
        const ids = read.observations.map((o) => o.discoveredId);
        for (const id of expected) expect(ids).toContain(id);
        expect(ids.join('\n')).not.toContain('stolen');
        expect(ids.join('\n')).not.toContain('secret_agent');
        // Every source file that was examined is counted, readable or not.
        expect(read.rows).toBeGreaterThanOrEqual(8);
    });
});

describe('7. a tree that changes between the stat and the read', () => {
    let dir: string;
    beforeEach(() => {
        dir = mkdtempSync(join(base, 'race-'));
        writeFileSync(join(dir, 'a_first.py'), GOOD);
        writeFileSync(join(dir, 'm_target.py'), GOOD);
        writeFileSync(join(dir, 'z_last.py'), GOOD);
    });
    const target = () => join(dir, 'm_target.py');
    const racing = (change: () => void) => recordingFs((path) => (path === target() ? change() : undefined));

    it('a file swapped for a link out of the root is not followed: the link is refused at the open', async () => {
        const { fs } = racing(() => {
            unlinkSync(target());
            symlinkSync(join(outside, 'secret_agent.py'), target());
        });
        const result = await walk(dir, fs);
        expect(result.problems).toEqual(['UNREACHABLE m_target.py']);
        expect(result.files.map((f) => f.path)).toEqual(['a_first.py', 'z_last.py']);
        expect(result.files.map((f) => f.text).join('')).not.toContain('stolen');
    });

    it('a file swapped for a link to a directory, or to itself, is refused the same way', async () => {
        for (const to of [outside, 'm_target.py']) {
            writeFileSync(target(), GOOD);
            const { fs } = racing(() => {
                unlinkSync(target());
                symlinkSync(to, target());
            });
            expect((await walk(dir, fs)).problems).toEqual(['UNREACHABLE m_target.py']);
            unlinkSync(target());
        }
    });

    it('a file that grows past the cap after its stat is not read whole: the read stops one byte over', async () => {
        let returned = -1;
        const rec = racing(() => appendFileSync(target(), Buffer.alloc(MAX_MARKER_SCAN_BYTES + 3 * MAX_FILE_BYTES, 0x23)));
        const fs: CodeFs = { ...rec.fs, readFile: async (p) => {
            const buf = await rec.fs.readFile(p);
            if (p === target()) returned = buf.length;
            return buf;
        } };
        const result = await walk(dir, fs);
        expect(result.problems).toEqual(['BYTE_CAP m_target.py']);
        expect(returned).toBe(MAX_MARKER_SCAN_BYTES + 1);
        expect(result.files.map((f) => f.path)).toEqual(['a_first.py', 'z_last.py']);
    });

    it('a file that vanishes is a location not read, and the walk carries on', async () => {
        const { fs } = racing(() => unlinkSync(target()));
        const result = await walk(dir, fs);
        expect(result.problems).toEqual(['UNREACHABLE m_target.py']);
        expect(result.files.map((f) => f.path)).toEqual(['a_first.py', 'z_last.py']);
    });

    it('a file swapped for a directory is refused', async () => {
        const { fs } = racing(() => {
            unlinkSync(target());
            mkdirSync(target());
        });
        expect((await walk(dir, fs)).problems).toEqual(['UNREACHABLE m_target.py']);
    });

    it('a file swapped for a pipe does not block the scan', async () => {
        if (!hasFifo) return;
        const { fs } = racing(() => {
            unlinkSync(target());
            execFileSync('mkfifo', [target()]);
        });
        const started = Date.now();
        const result = await walk(dir, fs);
        expect(Date.now() - started).toBeLessThan(5_000);
        expect(result.problems).toEqual(['UNREACHABLE m_target.py']);
        expect(result.files.map((f) => f.path)).toEqual(['a_first.py', 'z_last.py']);
    });

    it('a file replaced by another regular file is read as what it now is, whole', async () => {
        const { fs } = racing(() => {
            writeFileSync(`${target()}.new`, AGENT_LINE);
            renameSync(`${target()}.new`, target());
        });
        const result = await walk(dir, fs);
        expect(result.problems).toEqual([]);
        expect(result.files.find((f) => f.path === 'm_target.py')?.text).toBe(AGENT_LINE);
    });

    it('the real reader returns a regular file exactly, and an empty one as empty', async () => {
        writeFileSync(join(dir, 'empty.py'), '');
        expect((await NODE_CODE_FS.readFile(join(dir, 'empty.py'))).length).toBe(0);
        expect((await NODE_CODE_FS.readFile(target())).equals(readFileSync(target()))).toBe(true);
        const exact = Buffer.alloc(MAX_FILE_BYTES, 0x61);
        writeFileSync(join(dir, 'exact.py'), exact);
        expect((await NODE_CODE_FS.readFile(join(dir, 'exact.py'))).equals(exact)).toBe(true);
    });
});

describe('8. bounds a real tree cannot reach cheaply', () => {
    /** A file system that only claims its files: `count` source files of `size` bytes each, never allocated together. */
    function claimed(count: number, size: number): { fs: CodeFs; read: () => number } {
        let read = 0;
        const names = Array.from({ length: count }, (_, i) => `f${String(i).padStart(6, '0')}.py`);
        const one = Buffer.alloc(size, 0x23);
        return {
            read: () => read,
            fs: {
                lstat: async (p) => ({ isDirectory: () => p === '/claimed', isFile: () => p !== '/claimed', isSymbolicLink: () => false, size: p === '/claimed' ? 0 : size }),
                readdir: async () => names,
                readFile: async () => {
                    read += 1;
                    return one;
                },
            },
        };
    }

    it('more files than the file bound: the walk stops at the first one past it and says so', async () => {
        const { fs, read } = claimed(MAX_FILES + 500, 16);
        const result = await walk('/claimed', fs);
        expect(result.rows).toBe(MAX_FILES + 1);
        expect(read()).toBe(MAX_FILES);
        expect(result.problems).toEqual([`BYTE_CAP f${String(MAX_FILES).padStart(6, '0')}.py`]);
    });

    it('more bytes than the total bound: the walk stops at the file that would pass it', async () => {
        const { fs, read } = claimed(MAX_TOTAL_BYTES / MAX_FILE_BYTES + 50, MAX_FILE_BYTES);
        global.gc?.();
        const heap = process.memoryUsage().heapUsed;
        const result = await walk('/claimed', fs);
        expect(read()).toBe(MAX_TOTAL_BYTES / MAX_FILE_BYTES);
        expect(result.problems).toEqual([`BYTE_CAP f${String(MAX_TOTAL_BYTES / MAX_FILE_BYTES).padStart(6, '0')}.py`]);
        // The text of a file that names no framework is not kept: reading 128 MiB holds far less than that.
        expect(process.memoryUsage().heapUsed - heap).toBeLessThan(96 * 1024 * 1024);
    });

    it('a deadline that passes mid-walk ends it, once', async () => {
        const { fs } = claimed(5_000, 16);
        let clock = NOW;
        const { problems } = await readCodeFiles([{ label: 'hostile', path: '/claimed' }], fs, { deadline: NOW + 1_000, now: () => (clock += 1) }, () => undefined);
        expect(problems).toEqual([{ reason: 'TIME_BOX', at: null }]);
    });
});
