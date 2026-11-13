/**
 * The schedule loop over a long time, on an injected clock.
 *
 * A scanner is started once and left for months. Two things can go wrong
 * that no single run shows: the schedule drifts, and memory grows.
 *
 *   1. A thousand runs of a `run` that fails, overruns and throws things that
 *      are not errors, on a seeded pattern: the count is right, each start is
 *      anchored to the one before it, an overrun is followed at once, and each
 *      failure is logged once, by its name and nothing else.
 *   2. Scheduled scans of the offline example, written to a directory with
 *      retention: the directory holds what retention says, the pointer names
 *      the last run, every run verifies, and the heap does not grow with the
 *      number of runs. Two hundred runs always; five thousand under
 *      SCANENT_LONG=1.
 *
 * The real-time soak (a process left running for hours) is `npm run soak`:
 * see `scripts/soak.js`.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';

import type { ScannerLog } from '../src/log';
import { scanAndDeliver } from '../src/outputs';
import { runOnSchedule } from '../src/schedule';
import { configOf, ENV, noFetch, PUBLIC_HEX } from './helpers/output-fixtures';
import { LONG, rng, TEST_TIMEOUT_MS } from './helpers/prng';

jest.setTimeout(TEST_TIMEOUT_MS);

const HOUR = 3_600_000;
const T0 = Date.UTC(2026, 0, 1);

function recordingLog() {
    const errors: { msg: string; fields: Record<string, unknown> }[] = [];
    const log: ScannerLog = { info: () => {}, warn: () => {}, error: (msg, fields) => void errors.push({ msg, fields: fields ?? {} }) };
    return { log, errors };
}

describe('1. a thousand runs that fail, overrun and throw', () => {
    const RUNS = 1_000;
    const PERIOD = 6 * HOUR;
    type Behaviour = { readonly takes: number; readonly throws: 'no' | 'error' | 'string' | 'null' | 'object' };

    /** The seeded pattern: most runs are quick and clean; some fail, some overrun, some do both. */
    const pattern: Behaviour[] = (() => {
        const r = rng(0x50a4);
        return Array.from({ length: RUNS }, () => ({
            takes: r.chance(0.1) ? r.int(PERIOD + 1, 3 * PERIOD) : r.chance(0.02) ? PERIOD : r.int(0, PERIOD - 1),
            throws: r.chance(0.7) ? ('no' as const) : r.pick(['error', 'string', 'null', 'object'] as const),
        }));
    })();

    let clock = T0;
    const starts: number[] = [];
    const ends: number[] = [];
    const sleeps: number[] = [];
    const { log, errors } = recordingLog();
    let returned = 0;

    beforeAll(async () => {
        returned = await runOnSchedule({
            everyHours: PERIOD / HOUR,
            log,
            now: () => clock,
            sleep: async (ms) => {
                sleeps.push(ms);
                clock += ms;
            },
            maxRuns: RUNS,
            run: async () => {
                const b = pattern[starts.length];
                starts.push(clock);
                clock += b.takes;
                ends.push(clock);
                if (b.throws === 'error') throw new RangeError(`a failure that names a path: /home/somebody/key.pem ${starts.length}`);
                if (b.throws === 'string') throw 'a string, not an error';
                if (b.throws === 'null') throw null;
                if (b.throws === 'object') throw { code: 'ECONNRESET' };
            },
        });
    });

    it('the pattern has every kind of run in it', () => {
        expect(pattern.filter((b) => b.takes > PERIOD).length).toBeGreaterThan(50);
        expect(pattern.filter((b) => b.takes === PERIOD).length).toBeGreaterThan(0);
        for (const kind of ['error', 'string', 'null', 'object'] as const) expect(pattern.filter((b) => b.throws === kind).length).toBeGreaterThan(20);
    });

    it('runs exactly as many times as asked, failures included', () => {
        expect(returned).toBe(RUNS);
        expect(starts).toHaveLength(RUNS);
    });

    it('each start is the later of the previous start plus the period and the previous end: no drift, however long it runs', () => {
        for (let i = 1; i < RUNS; i++) expect(starts[i]).toBe(Math.max(starts[i - 1] + PERIOD, ends[i - 1]));
        // A run that kept to its slot is followed exactly one period after it STARTED, whatever it took.
        const onTime = starts.filter((_, i) => i > 0 && pattern[i - 1].takes <= PERIOD);
        expect(onTime.length).toBeGreaterThan(800);
    });

    it('a run that overran its slot is followed at once: nothing is slept and no run is skipped', () => {
        const overran = pattern.slice(0, RUNS - 1).filter((b) => b.takes >= PERIOD).length;
        // One sleep per run that left time in its slot, the last run excepted.
        expect(sleeps).toHaveLength(RUNS - 1 - overran);
        expect(sleeps.every((ms) => ms > 0 && ms <= PERIOD)).toBe(true);
        pattern.slice(0, RUNS - 1).forEach((b, i) => {
            if (b.takes > PERIOD) expect(starts[i + 1]).toBe(ends[i]);
        });
    });

    it('every failure is logged once, by its name alone', () => {
        const failed = pattern.filter((b) => b.throws !== 'no');
        expect(errors).toHaveLength(failed.length);
        expect(errors.map((e) => e.fields.error)).toEqual(failed.map((b) => (b.throws === 'error' ? 'RangeError' : 'unknown')));
        for (const e of errors) {
            expect(e.msg).toBe('scheduled scan failed; the schedule continues');
            expect(Object.keys(e.fields)).toEqual(['error']);
            // The message of what was thrown is not logged: it can name a path or a value.
            expect(JSON.stringify(e.fields)).not.toMatch(/somebody|key\.pem|ECONNRESET|a string/);
        }
    });

    // What is measured is memory still held after a collection. Without one it is
    // garbage not yet collected, which says nothing and varies with the machine
    // (58 MiB once in CI, under a megabyte the next run). `npm test`,
    // `npm run test:coverage` and `npm run test:long` start Node with
    // `--expose-gc` (the test below holds them to it); a bare `npx jest` has no
    // collector to call, and shows this test as skipped.
    const measured = typeof global.gc === 'function' ? it : it.skip;

    measured('a hundred thousand more runs do not grow the heap', async () => {
        const quiet = recordingLog().log;
        let t = T0;
        const loop = (runs: number) => runOnSchedule({ everyHours: 1, log: quiet, now: () => t, sleep: async (ms) => void (t += ms), maxRuns: runs, run: async () => void (t += 1_000) });
        await loop(10_000);
        global.gc?.();
        const before = process.memoryUsage().heapUsed;
        await loop(100_000);
        global.gc?.();
        expect(process.memoryUsage().heapUsed - before).toBeLessThan(32 * 1024 * 1024);
    });
});

describe('the heap is measured where the tests are gated', () => {
    const scripts = (JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'package.json'), 'utf8')) as { scripts: Record<string, string> }).scripts;

    it.each(['test', 'test:coverage', 'test:long'])('`npm run %s` starts Node with a collector the tests can call', (name) => {
        expect(scripts[name]).toMatch(/(^| )node --expose-gc node_modules\/jest\/bin\/jest\.js( |$)/);
    });

    it('the CI and release workflows run the suite through those scripts, never a bare jest', () => {
        for (const workflow of ['ci.yml', 'release.yml', 'long-tests.yml']) {
            const text = readFileSync(join(__dirname, '..', '..', '..', '.github', 'workflows', workflow), 'utf8');
            const runs = text.split('\n').filter((line) => /^\s*run: /.test(line) && /jest|npm (run )?test/.test(line));
            expect(runs.length).toBeGreaterThan(0);
            // A run of one named file is a targeted check; the whole suite goes through a script.
            for (const line of runs) expect(line).toMatch(/npm test$|npm run test:(coverage|long)$|npx jest packages\/\S+\.test\.ts$/);
        }
    });
});

describe('2. scheduled scans of the example, written with retention', () => {
    const RUNS = LONG ? 5_000 : 200;
    const RETAIN = 5;
    let dir: string;
    let clock = T0;
    const heap: number[] = [];
    const { log, errors } = recordingLog();

    beforeAll(async () => {
        dir = mkdtempSync(join(tmpdir(), 'scanent-soak-'));
        const config = configOf({ outputs: [{ kind: 'file', dir, retainRuns: RETAIN }], schedule: { everyHours: 1 } });
        let done = 0;
        await runOnSchedule({
            everyHours: 1,
            log,
            now: () => clock,
            // A real sleep is a timer, so the event loop turns between runs. The fake one turns it too:
            // without that the whole soak is one chain of microtasks, and every Node stream a run made
            // (the PDF is written through one) waits for a turn that never comes before it can be freed.
            sleep: async (ms) => {
                clock += ms;
                await new Promise((resolve) => setImmediate(resolve));
            },
            maxRuns: RUNS,
            run: async () => {
                const result = await scanAndDeliver({ config, env: ENV, log, fetchImpl: noFetch, now: () => clock, outputs: [{ kind: 'file', dir, retainRuns: RETAIN }] });
                if (!result.ok) throw new Error('the run was not delivered');
                clock += 90_000;
                done += 1;
                if (done % (RUNS / 10) === 0) {
                    global.gc?.();
                    heap.push(process.memoryUsage().heapUsed);
                }
            },
        });
    }, 1_800_000);
    afterAll(() => {
        rmSync(dir, { recursive: true, force: true });
    });

    it('no run failed', () => {
        expect(errors).toEqual([]);
    });

    it('the directory holds what retention says, and nothing else: no temporary file is left behind', () => {
        expect(readdirSync(dir).sort()).toEqual(['latest.json', 'runs']);
        const runs = readdirSync(join(dir, 'runs'));
        expect(runs).toHaveLength(RETAIN);
        for (const run of runs) {
            expect(readdirSync(join(dir, 'runs', run)).sort()).toEqual(['agents.csv', 'findings.csv', 'manifest.json', 'report.pdf', 'report.signed.json', 'results.json', 'summary.html']);
        }
    });

    it('the pointer names the last run, and the runs kept are the newest', () => {
        const latest = JSON.parse(readFileSync(join(dir, 'latest.json'), 'utf8')) as { scanId: string; asOf: string };
        const lastStart = T0 + (RUNS - 1) * HOUR;
        expect(latest.asOf).toBe(new Date(lastStart).toISOString());
        const kept = readdirSync(join(dir, 'runs')).map((run) => (JSON.parse(readFileSync(join(dir, 'runs', run, 'results.json'), 'utf8')) as { scan: { asOf: string } }).scan.asOf).sort();
        expect(kept).toEqual(Array.from({ length: RETAIN }, (_, i) => new Date(lastStart - (RETAIN - 1 - i) * HOUR).toISOString()));
    });

    it('every run kept is a signed report that verifies', () => {
        for (const run of readdirSync(join(dir, 'runs'))) {
            expect(verifyAndParseHarnessReport(readFileSync(join(dir, 'runs', run, 'report.signed.json'), 'utf8'), [PUBLIC_HEX])).toMatchObject({ ok: true, complete: true });
        }
    });

    it('the heap at the end is about what it was a tenth of the way in', () => {
        expect(heap).toHaveLength(10);
        // Without a forced collection the figure is noisy; a leak of even a kilobyte a run would not hide in this bound over the long run.
        expect(heap[9] - heap[0]).toBeLessThan(48 * 1024 * 1024);
    });
});
