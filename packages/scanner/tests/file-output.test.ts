/**
 * The file output: one run, one directory, whole or not at all.
 *
 *   1. The six files, their modes, the manifest and the pointer.
 *   2. A write that fails part-way leaves no run, no temporary directory and
 *      the previous pointer.
 *   3. Nothing that exists is replaced; a second run does not disturb the
 *      first.
 *   4. Nothing is removed unless `retainRuns` says so, and then only real runs.
 *   5. A scan id that is not a safe name writes nothing.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import { RUN_FILE_NAMES } from '@scanent/report/render/files';
import { LocalResultsSchema } from '@scanent/report/results/schema';
import type { LocalResults } from '@scanent/report/results/types';

import { applyRetention, RUN_DIR_MODE, RUN_FILE_MODE, SCAN_ID_PATTERN, writeRun } from '../src/file-output';
import { PUBLIC_HEX, scanExample, tree } from './helpers/output-fixtures';

const T1 = Date.parse('2026-11-03T03:30:00.000Z');
const DAY = 24 * 3_600_000;
const SIX = [...Object.values(RUN_FILE_NAMES)].sort();

let dir: string;
let umask: number;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-out-'));
    umask = process.umask(0);
});
afterEach(() => {
    process.umask(umask);
    fs.rmSync(dir, { recursive: true, force: true });
});

const modeOf = (p: string): number => fs.statSync(p).mode & 0o777;
const sha = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

describe('1. what one run writes', () => {
    it('six files in runs/<scanId>, with the manifest\'s hashes, and a pointer to the run', async () => {
        const { raw, results } = await scanExample(T1);
        const written = writeRun({ dir }, { raw, results }, { now: () => T1 });
        const id = results.scan.id;
        expect(written).toEqual({ scanId: id, dir: `runs/${id}`, files: expect.any(Array), removedRuns: [] });
        expect([...written.files].sort()).toEqual(SIX);
        const run = path.join(dir, 'runs', id);
        expect(fs.readdirSync(run).sort()).toEqual(SIX);
        expect(fs.readdirSync(dir).sort()).toEqual(['latest.json', 'runs']);
        expect(fs.readdirSync(path.join(dir, 'runs'))).toEqual([id]);

        // The signed report is the scan's bytes, and still verifies.
        const report = fs.readFileSync(path.join(run, RUN_FILE_NAMES.report), 'utf8');
        expect(report).toBe(raw);
        expect(verifyAndParseHarnessReport(report, [PUBLIC_HEX])).toMatchObject({ ok: true });

        const parsed = LocalResultsSchema.parse(JSON.parse(fs.readFileSync(path.join(run, RUN_FILE_NAMES.results), 'utf8')));
        expect(parsed).toEqual(results);
        expect(parsed.report.sha256).toBe(sha(report));

        const manifest = JSON.parse(fs.readFileSync(path.join(run, RUN_FILE_NAMES.manifest), 'utf8')) as {
            manifest: string;
            scanId: string;
            files: { name: string; bytes: number; sha256: string }[];
        };
        expect(manifest).toMatchObject({ manifest: 'scanent-run/1', scanId: id });
        expect(manifest.files.map((f) => f.name).sort()).toEqual(SIX.filter((n) => n !== RUN_FILE_NAMES.manifest));
        for (const f of manifest.files) {
            const bytes = fs.readFileSync(path.join(run, f.name));
            expect(f.bytes).toBe(bytes.length);
            expect(f.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));
        }

        expect(JSON.parse(fs.readFileSync(path.join(dir, 'latest.json'), 'utf8'))).toEqual({
            scanId: id,
            dir: `runs/${id}`,
            asOf: results.scan.asOf,
            complete: true,
            agentCount: 1,
        });
    });

    it('directories are 0750 and files 0640: readable by the group, not by everyone', async () => {
        const { raw, results } = await scanExample(T1);
        writeRun({ dir }, { raw, results });
        const run = path.join(dir, 'runs', results.scan.id);
        expect(modeOf(path.join(dir, 'runs'))).toBe(RUN_DIR_MODE);
        expect(modeOf(run)).toBe(RUN_DIR_MODE);
        for (const name of SIX) expect(modeOf(path.join(run, name))).toBe(RUN_FILE_MODE);
        expect(modeOf(path.join(dir, 'latest.json'))).toBe(RUN_FILE_MODE);
        expect([RUN_DIR_MODE, RUN_FILE_MODE]).toEqual([0o750, 0o640]);
    });

    it('creates the output directory when it does not exist', async () => {
        const { raw, results } = await scanExample(T1);
        const nested = path.join(dir, 'not', 'yet');
        writeRun({ dir: nested }, { raw, results });
        expect(fs.existsSync(path.join(nested, 'runs', results.scan.id, RUN_FILE_NAMES.summary))).toBe(true);
    });

    it('the files hold no absolute path of this machine and no time but the scan\'s', async () => {
        const { raw, results } = await scanExample(T1);
        writeRun({ dir }, { raw, results }, { now: () => T1 + 5 * DAY });
        for (const [name, content] of Object.entries(tree(dir))) {
            expect(content).not.toContain(dir);
            expect(content).not.toContain(os.tmpdir());
            if (!name.endsWith(RUN_FILE_NAMES.report)) expect(content).not.toContain('2026-11-08');
        }
    });
});

describe('2. a write that fails leaves nothing', () => {
    it.each([1, 2, 3, 4, 5, 6])('failing on file %i of the run leaves no run, no temporary directory and the previous pointer', async (n) => {
        const first = await scanExample(T1);
        writeRun({ dir }, first);
        const before = tree(dir);

        const second = await scanExample(T1 + DAY);
        let count = 0;
        const failing = (p: string, content: string) => {
            count += 1;
            if (count === n) throw Object.assign(new Error('no space left on device'), { code: 'ENOSPC' });
            fs.writeFileSync(p, content, { flag: 'wx' });
        };
        expect(() => writeRun({ dir }, second, { writeFile: failing })).toThrow('no space left on device');
        expect(tree(dir)).toEqual(before);
        expect(fs.readdirSync(path.join(dir, 'runs'))).toEqual([first.results.scan.id]);
        expect(fs.readdirSync(dir).sort()).toEqual(['latest.json', 'runs']);
    });

    it('failing on the pointer leaves the run written, the old pointer in place and no temporary file', async () => {
        const first = await scanExample(T1);
        writeRun({ dir }, first);
        const pointer = fs.readFileSync(path.join(dir, 'latest.json'), 'utf8');
        const second = await scanExample(T1 + DAY);
        let count = 0;
        const failing = (p: string, content: string) => {
            count += 1;
            if (count === 7) throw new Error('pointer refused');
            fs.writeFileSync(p, content, { flag: 'wx' });
        };
        expect(() => writeRun({ dir }, second, { writeFile: failing })).toThrow('pointer refused');
        expect(fs.readFileSync(path.join(dir, 'latest.json'), 'utf8')).toBe(pointer);
        expect(fs.readdirSync(dir).sort()).toEqual(['latest.json', 'runs']);
        expect(fs.readdirSync(path.join(dir, 'runs')).sort()).toEqual([first.results.scan.id, second.results.scan.id].sort());
    });

    it('a file that already exists is never opened for writing over', async () => {
        const { raw, results } = await scanExample(T1);
        // A temporary directory left by a run that was killed: the next run of the same id fails rather than write into it.
        fs.mkdirSync(path.join(dir, 'runs', `.${results.scan.id}.tmp`), { recursive: true });
        expect(() => writeRun({ dir }, { raw, results }, { now: () => T1 })).toThrow(/EEXIST/);
        expect(fs.existsSync(path.join(dir, 'runs', results.scan.id))).toBe(false);
        expect(fs.existsSync(path.join(dir, 'latest.json'))).toBe(false);
    });
});

describe('3. nothing is replaced', () => {
    it('a run that already exists fails the write and is left as it was', async () => {
        const { raw, results } = await scanExample(T1);
        writeRun({ dir }, { raw, results });
        const before = tree(dir);
        expect(() => writeRun({ dir }, { raw, results })).toThrow(`run ${results.scan.id} already exists; nothing was replaced`);
        expect(tree(dir)).toEqual(before);
    });

    it('an existing empty directory of that name is not replaced either', async () => {
        const { raw, results } = await scanExample(T1);
        fs.mkdirSync(path.join(dir, 'runs', results.scan.id), { recursive: true });
        expect(() => writeRun({ dir }, { raw, results })).toThrow('already exists');
        expect(fs.readdirSync(path.join(dir, 'runs', results.scan.id))).toEqual([]);
    });

    it('a second run adds a directory, moves the pointer and leaves the first run byte-identical', async () => {
        const first = await scanExample(T1);
        writeRun({ dir }, first);
        const firstDir = path.join(dir, 'runs', first.results.scan.id);
        const before = tree(firstDir);
        const second = await scanExample(T1 + DAY);
        writeRun({ dir }, second);
        expect(tree(firstDir)).toEqual(before);
        expect(fs.readdirSync(path.join(dir, 'runs')).sort()).toEqual([first.results.scan.id, second.results.scan.id].sort());
        expect((JSON.parse(fs.readFileSync(path.join(dir, 'latest.json'), 'utf8')) as { scanId: string }).scanId).toBe(second.results.scan.id);
    });
});

describe('4. retention', () => {
    async function threeRuns(retainRuns?: number): Promise<string[]> {
        const ids: string[] = [];
        for (const day of [0, 1, 2]) {
            const run = await scanExample(T1 + day * DAY);
            ids.push(run.results.scan.id);
            writeRun({ dir, retainRuns }, run, { now: () => T1 + day * DAY });
        }
        return ids;
    }

    it('by default nothing is ever removed', async () => {
        const ids = await threeRuns();
        expect(fs.readdirSync(path.join(dir, 'runs')).sort()).toEqual([...ids].sort());
    });

    it('retainRuns: 2 after three runs leaves the newest two, and says what it removed', async () => {
        const first = await scanExample(T1);
        const second = await scanExample(T1 + DAY);
        const third = await scanExample(T1 + 2 * DAY);
        writeRun({ dir, retainRuns: 2 }, first);
        expect(writeRun({ dir, retainRuns: 2 }, second).removedRuns).toEqual([]);
        expect(writeRun({ dir, retainRuns: 2 }, third).removedRuns).toEqual([first.results.scan.id]);
        expect(fs.readdirSync(path.join(dir, 'runs')).sort()).toEqual([second.results.scan.id, third.results.scan.id].sort());
    });

    it('only a real run is removed: not a foreign name, a directory with no manifest, a file or a link', async () => {
        const runs = path.join(dir, 'runs');
        fs.mkdirSync(path.join(runs, 'notes'), { recursive: true });
        fs.writeFileSync(path.join(runs, 'notes', 'keep.txt'), 'mine');
        // A scan-id name with no manifest: something else's directory, or a run somebody is restoring.
        const bare = 'example-code-20200101T000000Z-00000000';
        fs.mkdirSync(path.join(runs, bare));
        fs.writeFileSync(path.join(runs, bare, 'keep.txt'), 'mine');
        fs.writeFileSync(path.join(runs, 'example-code-20200102T000000Z-00000000'), 'a file with a run\'s name');
        const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-elsewhere-'));
        fs.writeFileSync(path.join(elsewhere, RUN_FILE_NAMES.manifest), '{}');
        fs.symlinkSync(elsewhere, path.join(runs, 'example-code-20200103T000000Z-00000000'));
        try {
            const ids = await threeRuns(1);
            expect(fs.readdirSync(runs).sort()).toEqual(
                [ids[2], bare, 'notes', 'example-code-20200102T000000Z-00000000', 'example-code-20200103T000000Z-00000000'].sort(),
            );
            expect(fs.readFileSync(path.join(runs, bare, 'keep.txt'), 'utf8')).toBe('mine');
            expect(fs.existsSync(path.join(elsewhere, RUN_FILE_NAMES.manifest))).toBe(true);
        } finally {
            fs.rmSync(elsewhere, { recursive: true, force: true });
        }
    });

    it('the run just written is never removed, even when its stamp is the oldest', async () => {
        const newer = await scanExample(T1 + DAY);
        const older = await scanExample(T1);
        writeRun({ dir, retainRuns: 1 }, newer);
        expect(writeRun({ dir, retainRuns: 1 }, older).removedRuns).toEqual([]);
        expect(fs.readdirSync(path.join(dir, 'runs')).sort()).toEqual([newer.results.scan.id, older.results.scan.id].sort());
        // Called again, the rule still keeps the named run and removes down to the count.
        expect(applyRetention(dir, 1, older.results.scan.id)).toEqual([]);
        expect(applyRetention(dir, 1, 'none-of-them')).toEqual([older.results.scan.id]);
    });

    it('a temporary directory left by a killed run is removed after a day, and not before', async () => {
        const runs = path.join(dir, 'runs');
        const stale = path.join(runs, '.example-code-20200101T000000Z-0000000a.tmp');
        const foreign = path.join(runs, '.cache.tmp');
        fs.mkdirSync(stale, { recursive: true });
        fs.mkdirSync(foreign);
        const made = fs.statSync(stale).mtimeMs;
        const first = await scanExample(T1);
        writeRun({ dir }, first, { now: () => made + DAY - 1_000 });
        expect(fs.existsSync(stale)).toBe(true);
        const second = await scanExample(T1 + DAY);
        writeRun({ dir }, second, { now: () => made + DAY + 1_000 });
        expect(fs.existsSync(stale)).toBe(false);
        expect(fs.existsSync(foreign)).toBe(true);
    });
});

describe('5. the directory name', () => {
    it.each(['../escape', 'a/b', 'example-code', 'Example-20261103T033000Z-0a1b2c3d', 'example-20261103T033000Z-0a1b2c3d/..', ''])(
        'a scan id %j is not a safe name: nothing is written',
        async (id) => {
            const { raw, results } = await scanExample(T1);
            const renamed: LocalResults = { ...results, scan: { ...results.scan, id } };
            expect(() => writeRun({ dir }, { raw, results: renamed })).toThrow('the scan id is not a safe directory name; nothing was written');
            expect(fs.readdirSync(dir)).toEqual([]);
        },
    );

    it('a scan id as the scanner builds it is one', async () => {
        const { results } = await scanExample(T1);
        expect(results.scan.id).toMatch(SCAN_ID_PATTERN);
        expect(results.scan.id).toMatch(/^example-code-20261103T033000Z-[0-9a-f]{8}$/);
    });
});
