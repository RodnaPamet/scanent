/**
 * The schedule loop on its own clock: with nothing injected it sleeps on the
 * real timer, anchored to each run's start.
 */
import { runOnSchedule } from '../src/schedule';
import type { ScannerLog } from '../src/log';

const HOUR = 3_600_000;

function recordingLog() {
    const errors: [string, unknown][] = [];
    const log: ScannerLog = { info: () => {}, warn: () => {}, error: (msg, fields) => void errors.push([msg, fields]) };
    return { log, errors };
}

describe('the schedule loop', () => {
    beforeEach(() => jest.useFakeTimers({ now: Date.UTC(2026, 0, 1) }));
    afterEach(() => jest.useRealTimers());

    it('runs at once, then every `everyHours` on the wall clock', async () => {
        const starts: number[] = [];
        const { log } = recordingLog();
        const done = runOnSchedule({ everyHours: 6, log, maxRuns: 3, run: async () => void starts.push(Date.now()) });
        await jest.advanceTimersByTimeAsync(0);
        expect(starts).toHaveLength(1);
        await jest.advanceTimersByTimeAsync(6 * HOUR - 1);
        expect(starts).toHaveLength(1);
        await jest.advanceTimersByTimeAsync(1);
        expect(starts).toHaveLength(2);
        await jest.advanceTimersByTimeAsync(6 * HOUR);
        expect(await done).toBe(3);
        const t0 = Date.UTC(2026, 0, 1);
        expect(starts).toEqual([t0, t0 + 6 * HOUR, t0 + 12 * HOUR]);
    });

    it('anchors to the start of a run, so a slow scan does not push the next one later', async () => {
        const starts: number[] = [];
        const { log } = recordingLog();
        const done = runOnSchedule({
            everyHours: 1,
            log,
            maxRuns: 3,
            run: async () => {
                starts.push(Date.now());
                await new Promise((r) => setTimeout(r, 20 * 60_000));
            },
        });
        await jest.advanceTimersByTimeAsync(3 * HOUR);
        expect(await done).toBe(3);
        expect(starts.map((s) => s - starts[0])).toEqual([0, HOUR, 2 * HOUR]);
    });

    it('a run that overran its slot is followed by the next at once, not skipped', async () => {
        const starts: number[] = [];
        const { log } = recordingLog();
        const done = runOnSchedule({
            everyHours: 1,
            log,
            maxRuns: 2,
            run: async () => {
                starts.push(Date.now());
                await new Promise((r) => setTimeout(r, 90 * 60_000));
            },
        });
        await jest.advanceTimersByTimeAsync(3 * HOUR);
        expect(await done).toBe(2);
        expect(starts[1] - starts[0]).toBe(90 * 60_000);
    });

    it('a failed run is logged by the kind of error only, and the schedule continues', async () => {
        const { log, errors } = recordingLog();
        let n = 0;
        const done = runOnSchedule({
            everyHours: 1,
            log,
            maxRuns: 3,
            run: async () => {
                n += 1;
                if (n === 1) throw new TypeError('fetch failed: Authorization: Bearer abc');
                if (n === 2) throw 'not an Error';
            },
        });
        await jest.advanceTimersByTimeAsync(2 * HOUR);
        expect(await done).toBe(3);
        expect(errors).toEqual([
            ['scheduled scan failed; the schedule continues', { error: 'TypeError' }],
            ['scheduled scan failed; the schedule continues', { error: 'unknown' }],
        ]);
    });

    it('without a run limit it does not stop', async () => {
        const { log } = recordingLog();
        let runs = 0;
        let settled = false;
        void runOnSchedule({ everyHours: 1, log, run: async () => void (runs += 1) }).then(() => (settled = true));
        await jest.advanceTimersByTimeAsync(48 * HOUR);
        expect(runs).toBe(49);
        expect(settled).toBe(false);
        jest.clearAllTimers();
    });
});
