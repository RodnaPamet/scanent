/**
 * WHY A SOURCE STOPPED, AND WHERE: the log and the local results say it, and
 * the signed report does not change.
 *
 * Found by the first scan of a real repository: the code source answered
 * `BYTE_CAP` and nothing else, so the operator could not tell which file to
 * look at. A reason is a code; a person needs the sentence and the place.
 */
import { generateKeyPairSync } from 'crypto';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { LocalResultsSchema } from '@scanent/report/results/schema';

import { parseScannerConfig } from '../src/config';
import { scoreScanLocally } from '../src/local-results';
import { jsonLineLog } from '../src/log';
import { rawPublicKeyHex } from '../src/report';
import { runScan, sourceNotesOf } from '../src/scan';
import { MAX_NOT_READ_LOCATIONS, sourceResult, SourceReadError, type SourceRead } from '../src/source';

const made: string[] = [];
afterAll(() => {
    for (const dir of made) rmSync(dir, { recursive: true, force: true });
});

describe('a source result says why it stopped in the scanner\'s own words only', () => {
    it('repeats a SourceReadError\'s message, which this code wrote', () => {
        const r = sourceResult('okta-app', 3, [], new SourceReadError('RATE_LIMITED', 'the source answered HTTP 429', 429));
        expect(r).toEqual({ kind: 'okta-app', status: 'INCOMPLETE', reason: 'RATE_LIMITED', detail: 'the source answered HTTP 429', rows: 3, observations: [] });
    });

    it('never repeats another error\'s message, which may quote what the estate answered', () => {
        const r = sourceResult('okta-app', 0, [], new Error('GET https://acme.example/?token=not-for-a-log failed'));
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'UNREACHABLE', detail: 'the reader stopped on an error of its own' });
        expect(JSON.stringify(r).includes('not-for-a-log')).toBe(false);
    });

    it('says nothing more of a read that reached the end', () => {
        expect(sourceResult('okta-app', 3, [], null)).toEqual({ kind: 'okta-app', status: 'COMPLETE', rows: 3, observations: [] });
    });
});

describe('sourceNotesOf: one note per source kind, for the sources that stopped', () => {
    const read = (over: Partial<SourceRead>): SourceRead => ({ kind: 'cicd', status: 'INCOMPLETE', reason: 'UNREACHABLE', rows: 0, observations: [], ...over });

    it('has no note for a source read in full', () => {
        expect(sourceNotesOf([{ kind: 'cicd', status: 'COMPLETE', rows: 2, observations: [] }])).toEqual([]);
    });

    it('joins two sources of one kind: each detail once, the places together, the totals added', () => {
        const notes = sourceNotesOf([
            read({ detail: 'the source answered HTTP 404', notRead: [{ where: 'a', reason: 'UNREACHABLE' }], notReadTotal: 1 }),
            read({ detail: 'the source answered HTTP 404' }),
            read({ reason: 'AUTH_FAILED', detail: 'the source answered HTTP 401', notRead: [{ where: 'b', reason: 'AUTH_FAILED' }], notReadTotal: 4 }),
            read({ kind: 'entra-sp' }),
        ]);
        expect(notes).toEqual([
            {
                kind: 'cicd',
                detail: 'the source answered HTTP 404; the source answered HTTP 401',
                notRead: [{ where: 'a', reason: 'UNREACHABLE' }, { where: 'b', reason: 'AUTH_FAILED' }],
                notReadTotal: 5,
            },
            { kind: 'entra-sp', detail: null, notRead: [], notReadTotal: 0 },
        ]);
    });

    it('lists no more places than one source may', () => {
        const many = Array.from({ length: MAX_NOT_READ_LOCATIONS }, (_, i) => ({ where: `p${i}`, reason: 'UNREACHABLE' as const }));
        const [note] = sourceNotesOf([read({ notRead: many, notReadTotal: 40 }), read({ notRead: many, notReadTotal: 40 })]);
        expect(note.notRead).toHaveLength(MAX_NOT_READ_LOCATIONS);
        expect(note.notReadTotal).toBe(80);
    });
});

describe('one scan, end to end', () => {
    it('logs the detail and each place, writes them to the local results, and signs a report that carries neither', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'scanent-notes-'));
        made.push(dir);
        writeFileSync(join(dir, 'ok.py'), '# nothing here\n');
        symlinkSync(join(dir, 'ok.py'), join(dir, 'link.py'));
        const { privateKey, publicKey } = generateKeyPairSync('ed25519');
        const lines: Record<string, unknown>[] = [];
        const config = parseScannerConfig({
            estate: 'acme-code',
            scanner: { agentId: 'agt_scanner_code', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
            schedule: { everyHours: 24 },
            sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: dir }] }],
        });
        const scan = await runScan({
            config,
            env: { SCANNER_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
            log: jsonLineLog((line) => void lines.push(JSON.parse(line) as Record<string, unknown>)),
            fetchImpl: async () => {
                throw new Error('the code source makes no request');
            },
        });

        expect(lines.find((l) => l.msg === 'source incomplete')).toMatchObject({ source: 'code', reason: 'UNREACHABLE', detail: expect.stringContaining('symbolic link') });
        expect(lines.filter((l) => l.msg === 'not read')).toEqual([expect.objectContaining({ level: 'warn', source: 'code', where: 'code://acme/link.py#L0', reason: 'UNREACHABLE' })]);
        expect(lines.some((l) => l.msg === 'not read: more places than are listed')).toBe(false);

        // The signed report is the contract's, unchanged: the reason and nothing else.
        expect(scan.body.population.sources).toEqual([{ kind: 'code', status: 'INCOMPLETE', reason: 'UNREACHABLE', rows: 1 }]);
        expect(verifyAndParseHarnessReport(scan.raw, [rawPublicKeyHex(publicKey)])).toMatchObject({ ok: true, complete: false });
        expect(scan.raw.includes('link.py')).toBe(false);

        const results = scoreScanLocally({ config, raw: scan.raw, body: scan.body, inventory: null, sourceNotes: scan.sourceNotes });
        expect(LocalResultsSchema.safeParse(results).success).toBe(true);
        expect(results.sources).toEqual([
            {
                kind: 'code',
                status: 'INCOMPLETE',
                reason: 'UNREACHABLE',
                rows: 1,
                agents: 0,
                detail: expect.stringContaining('symbolic link') as unknown as string,
                notRead: [{ where: 'code://acme/link.py#L0', reason: 'UNREACHABLE' }],
                notReadTotal: 1,
            },
        ]);
        // Scored without the run's notes (a report from elsewhere), the same source says only its reason.
        expect(scoreScanLocally({ config, raw: scan.raw, body: scan.body, inventory: null }).sources).toEqual([
            { kind: 'code', status: 'INCOMPLETE', reason: 'UNREACHABLE', rows: 1, agents: 0 },
        ]);
    });

    it('says how many places it did not list', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'scanent-notes-'));
        made.push(dir);
        for (let i = 0; i < MAX_NOT_READ_LOCATIONS + 3; i++) symlinkSync('/etc/hostname', join(dir, `l${i}.py`));
        const { privateKey } = generateKeyPairSync('ed25519');
        const lines: Record<string, unknown>[] = [];
        await runScan({
            config: parseScannerConfig({
                estate: 'acme-code',
                scanner: { agentId: 'agt_scanner_code', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
                schedule: { everyHours: 24 },
                sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: dir }] }],
            }),
            env: { SCANNER_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
            log: jsonLineLog((line) => void lines.push(JSON.parse(line) as Record<string, unknown>)),
            fetchImpl: async () => {
                throw new Error('the code source makes no request');
            },
        });
        expect(lines.filter((l) => l.msg === 'not read')).toHaveLength(MAX_NOT_READ_LOCATIONS);
        expect(lines.find((l) => l.msg === 'not read: more places than are listed')).toMatchObject({ source: 'code', unlisted: 3 });
    });
});
