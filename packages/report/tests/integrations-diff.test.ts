/**
 * The integrations compared run to run, and the comparison scanner by scanner.
 *
 * The agent diff's rule, held for the integrations scanner: absence concludes
 * something only on a full read. An application missing from the new run is
 * GONE only when its source was read in full and found at least one; a
 * finding no longer raised is CLOSED only when the new run answered the
 * question it asks. A scanner that ran in one run only is named, and nothing
 * about it is concluded.
 */
import type { IntegrationsReportApplication, IntegrationsReportBody } from '@rodnapamet/scanent-contract/integrations-contract';

import { DIFF_SCHEMA, DiffRefused, diffExitCode } from '../src/diff/diff';
import { diffIntegrations, INTEGRATIONS_DIFF_SCHEMA, type IntegrationsDiffInput } from '../src/diff/integrations-diff';
import { diffRuns, integrationsSideOf, RUN_DIFF_SCHEMA, RunsShareNoScanner, type RunDiff } from '../src/diff/run-diff';
import { renderRunDiffText } from '../src/render/run-diff-text';
import { scoreIntegrationsLocally } from '../src/results/integrations';
import type { LocalResults } from '../src/results/types';
import { application, body, DIR } from '../../contract/tests/helpers/integrations-bodies';
import { laterBody, plainResults } from './helpers/results';
import { input } from './helpers/fixtures';
import { scoreReportLocally } from '../src/results/score';

const T1 = '2026-10-19T03:00:00.000Z';
const T2 = '2026-10-20T03:00:00.000Z';
const SP2 = 'a0000007-0000-4000-8000-000000003686';
const APP = `entra:${DIR}:sp:a0000006-0000-4000-8000-000000003686`;
const APP2 = `entra:${DIR}:sp:${SP2}`;

/** One side: a body, scored as the scanner scores it. */
function side(b: IntegrationsReportBody, opts: { asOf?: string; estate?: string | null; scanner?: string; unusedDays?: number } = {}): IntegrationsDiffInput {
    const asOf = opts.asOf ?? T1;
    return {
        scan: { id: `acme-${asOf.replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')}-0a1b2c3d`, asOf, estate: opts.estate === undefined ? 'acme' : opts.estate, scannerAgentId: opts.scanner ?? 'agt_scanner' },
        integrations: scoreIntegrationsLocally({ body: { ...b, scan: { ...b.scan, asOf } }, unusedDays: opts.unusedDays ?? 90, report: { file: 'report.integrations.signed.json', sha256: 'a'.repeat(64) } }),
    };
}

const later = (b: IntegrationsReportBody, opts: Parameters<typeof side>[1] = {}) => side(b, { asOf: T2, ...opts });
const second = (over: Partial<IntegrationsReportApplication> = {}) => application({ id: APP2, appId: 'e0000007-0000-4000-8000-000000003686', displayName: 'Second', ...over });
const findingsOf = (d: ReturnType<typeof diffIntegrations>, change: string) => d.findings.filter((f) => f.change === change).map((f) => f.code).sort();

describe('the integrations, compared', () => {
    it('the same directory again is SAME, with nothing listed and nothing left unconcluded', () => {
        const d = diffIntegrations(side(body()), later(body()));
        expect(d).toMatchObject({ schema: INTEGRATIONS_DIFF_SCHEMA, outcome: 'SAME', warnings: [], sources: [], findings: [], notConcluded: [], summary: { differences: 0, notConcluded: 0 } });
        expect(d.applications).toEqual({ added: [], gone: [], notSeen: [] });
        expect(d.old).toMatchObject({ complete: true, applicationCount: 1 });
    });

    it('refuses two runs of different scanners, and a newer run that is not later', () => {
        expect(() => diffIntegrations(side(body()), later(body(), { scanner: 'other' }))).toThrow(DiffRefused);
        expect(() => diffIntegrations(side(body()), side(body()))).toThrow(new DiffRefused('NOT_LATER'));
    });

    it('an application in the new run only is new; one gone from a source read in full is gone, and its findings close as gone', () => {
        const d = diffIntegrations(side(body({ applications: [application(), second()] })), later(body({ applications: [application({ id: APP2, appId: 'x', displayName: 'X' }), application({ id: `entra:${DIR}:sp:a0000008-0000-4000-8000-000000003686` })] })));
        expect(d.applications.added).toEqual([`entra:${DIR}:sp:a0000008-0000-4000-8000-000000003686`]);
        expect(d.applications.gone).toEqual([APP]);
        expect(d.findings.filter((f) => f.applicationId === APP).every((f) => f.change === 'NOT_CONCLUDED' && f.why === 'APPLICATION_GONE')).toBe(true);
        expect(d.outcome).toBe('DIFFERENT');
    });

    it.each([
        ['SOURCE_INCOMPLETE', body({ sources: [{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'TIME_BOX', rows: 1, signInActivity: { status: 'NOT_READ' } }], applications: [application()] })],
        ['SOURCE_ABSENT', body({ sources: [], applications: [] })],
        ['NEW_SOURCE_EMPTY', body({ applications: [] })],
    ])('an application missing because %s is not seen, and nothing about it is concluded', (why, next) => {
        const d = diffIntegrations(side(body({ applications: [application(), second()] })), later(next));
        expect(d.applications.gone).toEqual([]);
        expect(d.applications.notSeen).toEqual(expect.arrayContaining([{ id: APP2, why }]));
        expect(d.notConcluded).toEqual(expect.arrayContaining([`APPLICATION_NOT_SEEN:${APP2}`]));
        expect(findingsOf(d, 'CLOSED')).toEqual([]);
    });

    it('a finding opens, and closes only where the new run answered its question', () => {
        // Old: an unverified publisher, no owner, a high grant, unused. New: verified, owned, no high grant, used.
        const old = side(body());
        const fixed = application({ publisherVerified: true, owners: [{ kind: 'user', id: 'u1' }], delegatedGrants: { read: true, grants: [] }, applicationPermissions: { read: true, permissions: [] }, signIn: { read: true, lastSeen: '2026-10-19' } });
        const d = diffIntegrations(old, later(body({ applications: [fixed] })));
        expect(findingsOf(d, 'CLOSED')).toEqual(['INTEGRATION_HIGH_PRIVILEGE_GRANT', 'INTEGRATION_NO_OWNER', 'INTEGRATION_UNUSED', 'INTEGRATION_UNVERIFIED_PUBLISHER']);
        const back = diffIntegrations(side(body({ applications: [fixed] })), later(body()));
        expect(findingsOf(back, 'OPENED')).toEqual(['INTEGRATION_HIGH_PRIVILEGE_GRANT', 'INTEGRATION_NO_OWNER', 'INTEGRATION_UNUSED', 'INTEGRATION_UNVERIFIED_PUBLISHER']);
        expect(diffExitCode(back)).toBe(1);
    });

    it('an unused finding is not closed when the sign-in read failed; the source change and the question are listed', () => {
        const failed = body({ sources: [{ kind: 'entra-integrations', status: 'COMPLETE', rows: 12, signInActivity: { status: 'INCOMPLETE', reason: 'RATE_LIMITED', rows: 0 } }], applications: [application({ signIn: { read: false, lastSeen: null } })] });
        const d = diffIntegrations(side(body()), later(failed));
        expect(d.findings.filter((f) => f.code === 'INTEGRATION_UNUSED')).toEqual([expect.objectContaining({ change: 'NOT_CONCLUDED', why: 'SIGN_IN_READ_INCOMPLETE' })]);
        expect(d.sources).toEqual([expect.objectContaining({ kind: 'entra-integrations#signInActivity', change: 'NOW_INCOMPLETE' })]);
        expect(d.notConcluded).toEqual(expect.arrayContaining(['SCAN_INCOMPLETE:new', `FINDING_NOT_CONCLUDED:${d.findings[0].sourceRef}`]));
        expect(d.new.complete).toBe(false);
    });

    it('no difference with an incomplete side is SAME_AS_FAR_AS_COMPARED, never SAME', () => {
        const incomplete = body({ sources: [{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'TIME_BOX', rows: 1, signInActivity: { status: 'NOT_READ' } }] });
        const d = diffIntegrations(side(incomplete), later(incomplete));
        expect(d.outcome).toBe('SAME_AS_FAR_AS_COMPARED');
        expect(diffExitCode(d)).toBe(3);
    });

    it('the empty inventory closes on any application found, and stays open while none is', () => {
        const empty = body({ applications: [] });
        expect(findingsOf(diffIntegrations(side(empty), later(body())), 'CLOSED')).toEqual(['INTEGRATION_EMPTY_INVENTORY']);
        expect(diffIntegrations(side(empty), later(empty)).findings).toEqual([]);
        const gone = diffIntegrations(side(empty), later(body({ sources: [] , applications: [] })));
        expect(gone.findings).toEqual([expect.objectContaining({ code: 'INTEGRATION_EMPTY_INVENTORY', change: 'NOT_CONCLUDED', why: 'SOURCE_ABSENT' })]);
    });

    it('different scanners (when allowed), estates and windows are warnings, and the first two conclude no absence', () => {
        const d = diffIntegrations(side(body({ applications: [application(), second()] })), later(body(), { scanner: 'other', estate: 'beta', unusedDays: 30 }), { allowDifferentScanner: true });
        expect(d.warnings).toEqual(['SCANNER_DIFFERS', 'ESTATE_DIFFERS', 'UNUSED_DAYS_DIFFER']);
        expect(d.applications.notSeen).toEqual([{ id: APP2, why: 'DIFFERENT_SCANNER' }]);
        const estate = diffIntegrations(side(body({ applications: [application(), second()] })), later(body(), { estate: 'beta' }));
        expect(estate.applications.notSeen).toEqual([{ id: APP2, why: 'DIFFERENT_ESTATE' }]);
        expect(estate.findings.filter((f) => f.applicationId === APP2).every((f) => f.why === 'DIFFERENT_ESTATE')).toBe(true);
    });

    it.each([
        ['ADDED', body({ sources: [] , applications: [] }), body()],
        ['NO_LONGER_READ', body(), body({ sources: [], applications: [] })],
        ['NOW_COMPLETE', body({ sources: [{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'TIME_BOX', rows: 1, signInActivity: { status: 'COMPLETE', rows: 1 } }] }), body()],
        ['REASON_CHANGED', body({ sources: [{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'TIME_BOX', rows: 1, signInActivity: { status: 'COMPLETE', rows: 1 } }] }), body({ sources: [{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'BYTE_CAP', rows: 1, signInActivity: { status: 'COMPLETE', rows: 1 } }] })],
    ])('a source %s', (change, a, b) => {
        expect(diffIntegrations(side(a), later(b)).sources.map((s) => s.change)).toContain(change);
    });
});

describe('two runs, scanner by scanner', () => {
    const agents = (): LocalResults => plainResults();
    const agentsLater = (): LocalResults => scoreReportLocally(input(laterBody()));
    const withIntegrations = (r: LocalResults, b: IntegrationsReportBody): LocalResults => ({ ...r, integrations: side(b, { asOf: r.scan.asOf }).integrations });

    it('two runs of the agent scanner alone: the agent diff, unchanged', () => {
        const d = diffRuns({ agents: agents(), integrations: null }, { agents: agentsLater(), integrations: null });
        expect(d.schema).toBe(DIFF_SCHEMA);
    });

    it('two runs of the integrations scanner alone: one member per scanner, the agent scanner run by neither', () => {
        const d = diffRuns({ agents: null, integrations: side(body()) }, { agents: null, integrations: later(body({ applications: [] })) }) as RunDiff;
        expect(d).toMatchObject({ schema: RUN_DIFF_SCHEMA, scanners: { agents: { compared: false, change: 'NOT_RUN' }, integrations: { schema: INTEGRATIONS_DIFF_SCHEMA } } });
        expect(d.outcome).toBe('DIFFERENT');
        const text = renderRunDiffText(d);
        expect(text).toContain('== Agent scanner ==\nThe agent scanner ran in neither run.');
        expect(text).toContain('== Integrations scanner ==\nThe two runs differ.');
        expect(text).toContain('not seen   ');
    });

    it('both scanners in both runs: each compared by its own rules, one outcome over both', () => {
        const a = withIntegrations(agents(), body());
        const b = withIntegrations(agentsLater(), body());
        const d = diffRuns({ agents: a, integrations: integrationsSideOf(a) }, { agents: b, integrations: integrationsSideOf(b) }) as RunDiff;
        expect(d.schema).toBe(RUN_DIFF_SCHEMA);
        expect(d.outcome).toBe('SAME');
        expect(diffExitCode(d)).toBe(0);
        const text = renderRunDiffText(d);
        expect(text.indexOf('== Agent scanner ==')).toBeLessThan(text.indexOf('== Integrations scanner =='));
        expect(text).toContain('scanent diff: No difference, and every comparison could be made.');
    });

    it('a scanner added or no longer run is a difference, and concludes nothing about what it would find', () => {
        const a = agents();
        const b = withIntegrations(agentsLater(), body());
        const added = diffRuns({ agents: a, integrations: integrationsSideOf(a) }, { agents: b, integrations: integrationsSideOf(b) }) as RunDiff;
        expect(added.scanners.integrations).toEqual({ compared: false, change: 'ADDED' });
        expect(added).toMatchObject({ outcome: 'DIFFERENT', summary: { differences: 1, notConcluded: 0 } });
        expect(renderRunDiffText(added)).toContain('The integrations scanner ran in the new run only');
        const gone = diffRuns({ agents: null, integrations: side(body()) }, { agents: agentsLater(), integrations: later(body()) }) as RunDiff;
        expect(gone.scanners.agents).toEqual({ compared: false, change: 'ADDED' });
        const dropped = diffRuns({ agents: withIntegrations(agents(), body()), integrations: side(body()) }, { agents: null, integrations: later(body()) }) as RunDiff;
        expect(dropped.scanners.agents).toEqual({ compared: false, change: 'NO_LONGER_RUN' });
        expect(renderRunDiffText(dropped)).toContain('The agent scanner ran in the old run only');
    });

    it('an incomplete integrations side makes the whole comparison SAME_AS_FAR_AS_COMPARED, exit 3', () => {
        const incomplete = body({ sources: [{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'TIME_BOX', rows: 1, signInActivity: { status: 'NOT_READ' } }] });
        const a = withIntegrations(agents(), incomplete);
        const b = withIntegrations(agentsLater(), incomplete);
        const d = diffRuns({ agents: a, integrations: integrationsSideOf(a) }, { agents: b, integrations: integrationsSideOf(b) });
        expect(d.outcome).toBe('SAME_AS_FAR_AS_COMPARED');
        expect(diffExitCode(d)).toBe(3);
        expect(renderRunDiffText(d as RunDiff)).toContain('Not concluded');
    });

    it('two runs that share no scanner are refused', () => {
        expect(() => diffRuns({ agents: agents(), integrations: null }, { agents: null, integrations: later(body()) })).toThrow(RunsShareNoScanner);
    });

    it('an application id cannot add a line to the text, nor send the terminal an escape', () => {
        const evil = application({ id: `entra:${DIR}:sp:x\u001b[2J\nforged` });
        const d = diffRuns({ agents: null, integrations: side(body({ applications: [] })) }, { agents: null, integrations: later(body({ applications: [evil] })) }) as RunDiff;
        const text = renderRunDiffText(d);
        expect(text).not.toContain('\u001b');
        // Every line that carries the id carries all of it: none starts with what followed the newline.
        expect(text.split('\n').some((l) => l.startsWith('forged'))).toBe(false);
        expect(text).toContain('x\\u{1b}[2J\\u{a}forged');
    });
});
