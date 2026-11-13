/**
 * The run before this one: what `--out` knows of it, and what the page and the
 * PDF say of it.
 *
 *   1. No pointer is no earlier run; a pointer that names a run whose results
 *      can be read is compared by `scanent diff`'s own rules.
 *   2. Anything else the directory holds is untrusted input, read as `diff`
 *      reads it: refused by name, never half-read, and never a reason not to
 *      write the run.
 *   3. A second run's page and PDF say what changed since the first.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { renderResultsJson } from '@scanent/report/render/results-json';

import { writeRun } from '../src/file-output';
import { scanAndDeliver } from '../src/outputs';
import { previousRunOf } from '../src/previous-run';
import { CANARIES, capturedLog, configOf, ENV, noFetch, pageDataOf, pdfTextOf, scanExample } from './helpers/output-fixtures';

const T1 = Date.parse('2026-11-03T03:30:00.000Z');
const DAY = 86_400_000;

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-previous-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('1. what the directory says of the run before', () => {
    it('no pointer: there was no earlier run', async () => {
        const { results } = await scanExample(T1);
        expect(previousRunOf(dir, results)).toBeNull();
        expect(previousRunOf(path.join(dir, 'absent'), results)).toBeNull();
    });

    it('the run the pointer names is compared with this one', async () => {
        const first = await scanExample(T1);
        writeRun({ dir }, first);
        const second = await scanExample(T1 + DAY);
        const previous = previousRunOf(dir, second.results);
        expect(previous?.kind).toBe('COMPARED');
        if (previous?.kind !== 'COMPARED') return;
        expect(previous.diff.old.scanId).toBe(first.results.scan.id);
        expect(previous.diff.new.scanId).toBe(second.results.scan.id);
        expect(previous.diff.outcome).toBe('SAME');
    });

    it('two runs the comparison refuses are not compared, and say which rule', async () => {
        const first = await scanExample(T1 + DAY);
        writeRun({ dir }, first);
        // An earlier scan than the one the pointer names.
        const earlier = await scanExample(T1);
        expect(previousRunOf(dir, earlier.results)).toEqual({ kind: 'NOT_COMPARED', scanId: first.results.scan.id, reason: 'NOT_LATER' });
        const other = await scanExample(T1 + 2 * DAY, configOf({ scanner: { agentId: 'agt_other', signingKeyEnv: 'SCANNER_SIGNING_KEY' } }));
        expect(previousRunOf(dir, other.results)).toEqual({ kind: 'NOT_COMPARED', scanId: first.results.scan.id, reason: 'SCANNER_DIFFERS' });
    });
});

describe('2. what the directory holds is untrusted', () => {
    const later = () => scanExample(T1 + DAY);

    it.each([
        ['a pointer that is not JSON', (d: string) => fs.writeFileSync(path.join(d, 'latest.json'), '{nope')],
        ['a pointer whose scan id is a path', (d: string) => fs.writeFileSync(path.join(d, 'latest.json'), JSON.stringify({ scanId: '../../etc' }))],
        ['a pointer that is a directory', (d: string) => fs.mkdirSync(path.join(d, 'latest.json'))],
    ])('%s is UNREADABLE, naming no run', async (_label, plant) => {
        plant(dir);
        expect(previousRunOf(dir, (await later()).results)).toEqual({ kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' });
    });

    it('a pointer that names this very run is not a previous run', async () => {
        const run = await later();
        fs.writeFileSync(path.join(dir, 'latest.json'), JSON.stringify({ scanId: run.results.scan.id }));
        expect(previousRunOf(dir, run.results)).toEqual({ kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' });
    });

    it.each([
        ['is missing', () => undefined],
        ['is not JSON', (file: string) => fs.writeFileSync(file, 'not json')],
        ['is a results file the schema refuses', (file: string) => fs.writeFileSync(file, JSON.stringify({ schema: 'scanent-results/1', agents: 'no' }))],
        ['names another schema', (file: string) => fs.writeFileSync(file, JSON.stringify({ schema: 'scanent-results/9' }))],
    ])('a results file that %s is UNREADABLE, naming the run', async (_label, plant) => {
        const first = await scanExample(T1);
        writeRun({ dir }, first);
        const file = path.join(dir, 'runs', first.results.scan.id, 'results.json');
        fs.rmSync(file);
        plant(file);
        expect(previousRunOf(dir, (await later()).results)).toEqual({ kind: 'NOT_COMPARED', scanId: first.results.scan.id, reason: 'UNREADABLE' });
    });

    it.each(CANARIES)('a previous results file holding %s is refused, and the canary is in nothing this run writes', async (_label, canary) => {
        const first = await scanExample(T1);
        writeRun({ dir }, first);
        const file = path.join(dir, 'runs', first.results.scan.id, 'results.json');
        const armed = { ...first.results, findings: first.results.findings.map((f, i) => (i === 0 ? { ...f, title: canary } : f)) };
        fs.rmSync(file);
        fs.writeFileSync(file, renderResultsJson(armed));
        const second = await later();
        const previous = previousRunOf(dir, second.results);
        expect(previous).toEqual({ kind: 'NOT_COMPARED', scanId: first.results.scan.id, reason: 'UNREADABLE' });
        writeRun({ dir }, { ...second, previous });
        const run = path.join(dir, 'runs', second.results.scan.id);
        for (const name of fs.readdirSync(run)) expect(fs.readFileSync(path.join(run, name), 'latin1')).not.toContain(canary);
    });

    it('a results file that is a link is not followed: the run it names is UNREADABLE, and the target is never read', async () => {
        const first = await scanExample(T1);
        writeRun({ dir }, first);
        const file = path.join(dir, 'runs', first.results.scan.id, 'results.json');
        // A valid results file elsewhere, linked in place of the run's own: reading it would compare with a run this directory never wrote.
        const elsewhere = path.join(dir, 'elsewhere.json');
        fs.renameSync(file, elsewhere);
        fs.symlinkSync(elsewhere, file);
        expect(previousRunOf(dir, (await later()).results)).toEqual({ kind: 'NOT_COMPARED', scanId: first.results.scan.id, reason: 'UNREADABLE' });
        // And a pointer that is a link is no pointer of this directory's.
        const pointer = path.join(dir, 'latest.json');
        fs.renameSync(pointer, path.join(dir, 'pointer-elsewhere.json'));
        fs.symlinkSync(path.join(dir, 'pointer-elsewhere.json'), pointer);
        expect(previousRunOf(dir, (await later()).results)).toEqual({ kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' });
    });

    it('a read that fails is a refusal the page states, never a run that is not written', async () => {
        const run = await later();
        const throwing = () => {
            throw Object.assign(new Error('permission denied'), { code: 'EACCES' });
        };
        expect(previousRunOf(dir, run.results, { readFile: throwing })).toEqual({ kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' });
    });
});

describe('3. a second run says what changed since the first', () => {
    it('the page\'s data, its static section and the PDF name the run it was compared with', async () => {
        let clock = T1;
        const config = configOf({ outputs: [{ kind: 'file', dir }] });
        const deliver = () => scanAndDeliver({ config, env: ENV, log: capturedLog().log, fetchImpl: noFetch, now: () => clock, outputs: [{ kind: 'file', dir }] });
        const first = await deliver();
        clock += DAY;
        const second = await deliver();
        expect([first.ok, second.ok]).toEqual([true, true]);
        const runOf = (id: string) => path.join(dir, 'runs', id);

        // The first run had no earlier one, and says so.
        const firstPage = fs.readFileSync(path.join(runOf(first.scan.body.scan.id), 'summary.html'), 'utf8');
        expect((pageDataOf(firstPage) as { drift: unknown }).drift).toEqual({ kind: 'FIRST' });
        expect(firstPage).toContain('This output directory held no earlier run, so there is nothing to compare with.');

        const page = fs.readFileSync(path.join(runOf(second.scan.body.scan.id), 'summary.html'), 'utf8');
        const drift = (pageDataOf(page) as { drift: { kind: string; old: { scanId: string }; outcomeText: string } }).drift;
        expect(drift).toMatchObject({ kind: 'COMPARED', old: { scanId: first.scan.body.scan.id } });
        expect(page).toContain(`Compared with <code class="id">${first.scan.body.scan.id}</code>`);
        expect(page).toContain(drift.outcomeText);

        const pdf = pdfTextOf(fs.readFileSync(path.join(runOf(second.scan.body.scan.id), 'report.pdf')));
        expect(pdf.lines).toContain('7. Since the previous run');
        expect(pdf.joined).toContain(`Compared with ${first.scan.body.scan.id}`);
    });
});
