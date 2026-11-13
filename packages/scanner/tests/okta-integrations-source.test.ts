/**
 * The integrations scanner's Okta source over the fake org, answered as Okta
 * documents "List all applications" and "List all app grants": JSON arrays,
 * paged by the `Link` header's `next`, rate-limited with a 429 and Okta's
 * `X-Rate-Limit-*` headers.
 *
 *   1. WHAT IS REPORTED: every application the org lists, with its label,
 *      status and sign-on mode, and the Okta scopes with an active grant.
 *   2. WHAT NEVER LEAVES THE PAGE: who consented, who created a grant, an
 *      app's credentials, settings and profile.
 *   3. COMPLETENESS: paging followed to the end; a 429, a failed page or a
 *      torn page ends the read INCOMPLETE with its reason, and what was read
 *      stays, each application saying whether its grants were read; a row
 *      with no usable id fails the read.
 *   4. READ-ONLY: every request is a declared GET, and the preflight asks for
 *      nothing the read does not.
 */
import { IntegrationsReportBodyV1Schema, type OktaIntegrationsApplication } from '@rodnapamet/scanent-contract/integrations-contract';
import { planIntegrationsScan } from '@rodnapamet/scanent-contract/integrations-findings';

import { createSourceWire } from '../src/http';
import type { IntegrationsSourceRead } from '../src/integrations-source';
import { buildIntegrationsReportBody } from '../src/integrations-report';
import { isDeclaredRequest } from '../src/scanner-surface';
import type { ProbeStep } from '../src/source';
import { OKTA_FIRST_PARTY_APP_NAMES, OKTA_FIRST_PARTY_EXCLUSION, OKTA_INTEGRATIONS_READ_PATHS, oktaIntegrationsSource } from '../src/sources/okta-integrations';
import { createSourceFakes, OKTA_CLIENT_SECRET_VALUE, OKTA_GRANT_MARKERS, OKTA_ORG, OKTA_TOKEN_VALUE, oktaFixture, oktaGrant, type Fakes } from './helpers/agent-harness-source-fakes';

const ASOF = new Date('2026-10-19T03:00:00.000Z');
const HOST = 'acme.okta.com';
const app = (id: string) => `okta:${HOST}:app:${id}`;

const source = (apiToken = OKTA_TOKEN_VALUE) => oktaIntegrationsSource({ orgUrl: OKTA_ORG, apiToken });

function wire(fakes: Fakes) {
    return createSourceWire({ fetchImpl: fakes.fetchImpl, deadline: ASOF.getTime() + 60_000, now: () => ASOF.getTime() });
}

async function read(fakes: Fakes, apiToken?: string): Promise<IntegrationsSourceRead> {
    return source(apiToken).read({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire(fakes) });
}

async function preflight(fakes: Fakes, apiToken?: string): Promise<readonly ProbeStep[]> {
    return source(apiToken).preflight({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire(fakes) });
}

const byId = (r: IntegrationsSourceRead, id: string): OktaIntegrationsApplication | undefined =>
    r.applications.find((a): a is OktaIntegrationsApplication => a.sourceKind === 'okta-integrations' && a.id === app(id));

/** Okta's documented rate-limit answer. */
const RATE_LIMITED = {
    status: 429,
    body: { errorCode: 'E0000047', errorSummary: 'API call exceeded rate limit due to too many requests.' },
    headers: { 'content-type': 'application/json', 'x-rate-limit-limit': '100', 'x-rate-limit-remaining': '0', 'x-rate-limit-reset': '1760842860' },
};

describe('1. what is reported', () => {
    it('every application of the org, every page, each with the scopes of its active grants', async () => {
        const fakes = createSourceFakes();
        const r = await read(fakes);
        expect(r).toMatchObject({ kind: 'okta-integrations', status: 'COMPLETE', signInActivity: { status: 'NOT_READ' } });
        // Okta's own three apps are read, counted and left out; one only labelled like one is an integration.
        expect(r.applications.map((a) => a.id)).toEqual([app('0oaLookalike'), app('0oaSaml1'), app('0oaService1'), app('0oaService2'), app('0oaWeb1')]);
        expect(r.excluded).toEqual({ count: 3, what: OKTA_FIRST_PARTY_EXCLUSION });
        expect(fakes.log.some((e) => /0oaOkta/.test(e.path))).toBe(false);
        expect(byId(r, '0oaService1')).toEqual({
            id: app('0oaService1'),
            sourceKind: 'okta-integrations',
            appId: '0oaService1',
            displayName: 'Reporting service',
            status: 'ACTIVE',
            signOnMode: 'OPENID_CONNECT',
            // The revoked grant of okta.users.manage is not one it holds.
            scopeGrants: { read: true, scopes: ['okta.logs.read', 'okta.users.read'], unreadableScopes: 0 },
        });
        // Two pages of grants, both read; an inactive app is still listed with what it holds.
        expect(byId(r, '0oaService2')).toMatchObject({ status: 'INACTIVE', scopeGrants: { read: true, scopes: ['okta.groups.manage', 'okta.logs.read'] } });
        expect(byId(r, '0oaSaml1')).toMatchObject({ signOnMode: 'SAML_2_0', scopeGrants: { read: true, scopes: [], unreadableScopes: 0 } });
        // 8 applications (Okta's own three among them) and 6 grants were read, the revoked one included.
        expect(r.rows).toBe(14);
        expect(fakes.log.filter((e) => e.path === '/api/v1/apps/0oaService2/grants').map((e) => e.query)).toEqual(['', '?limit=200&after=1']);
    });

    it('becomes a report the contract accepts, and the planner reads it per Okta', async () => {
        const r = await read(createSourceFakes());
        const body = buildIntegrationsReportBody({ scanId: 'acme-20261019T030000Z-0a1b2c3d', asOf: ASOF, scannerAgentId: 'agt_scanner' }, [r]);
        expect(IntegrationsReportBodyV1Schema.safeParse(body).success).toBe(true);
        const plan = planIntegrationsScan(body);
        // okta.users.read and okta.groups.manage are high; okta.logs.read alone is not; an unknown scope is listed.
        expect(plan.findings.map((f) => `${f.code} ${f.applicationId}`)).toEqual([
            `INTEGRATION_HIGH_PRIVILEGE_GRANT ${app('0oaService1')}`,
            `INTEGRATION_HIGH_PRIVILEGE_GRANT ${app('0oaService2')}`,
        ]);
        expect(plan.applications.find((a) => a.id === app('0oaWeb1'))?.privilege).toBe('NOT_CONCLUDED');
        expect(plan.applications.find((a) => a.id === app('0oaSaml1'))?.privilege).toBe('NOT_HIGH');
        expect(plan.notConcluded.filter((n) => n.applicationId === null).map((n) => n.why)).toEqual(['PUBLISHER_NOT_EXPOSED', 'OWNER_NOT_EXPOSED', 'SIGN_IN_NOT_EXPOSED']);
    });

    it('Okta\'s own apps are told apart by their definition\'s name key, never by a label', () => {
        expect([...OKTA_FIRST_PARTY_APP_NAMES].sort()).toEqual(['okta_browser_plugin', 'okta_enduser', 'saasure']);
    });

    it('a scope or a label that cannot be reported is counted or withheld, never carried', async () => {
        const okta = oktaFixture();
        const token = ['gh', 'p_', 'E5'.repeat(12)].join('');
        okta.allApps = [[{ id: '0oaOdd1', label: `sync ${token}`, status: 'SOMETHING', signOnMode: 'NEW_MODE' }]];
        okta.grants = { '0oaOdd1': [[oktaGrant('g1', '0oaOdd1', token), oktaGrant('g2', '0oaOdd1', 'has spaces')]] };
        const r = await read(createSourceFakes({ okta }));
        expect(byId(r, '0oaOdd1')).toEqual({
            id: app('0oaOdd1'),
            sourceKind: 'okta-integrations',
            appId: '0oaOdd1',
            displayName: null,
            status: null,
            signOnMode: null,
            scopeGrants: { read: true, scopes: [], unreadableScopes: 2 },
        });
        expect(JSON.stringify(r)).not.toContain(token);
    });
});

describe('2. what never leaves the page', () => {
    it('who consented, who created a grant, an app\'s credentials and profile, and no secret is ever asked for', async () => {
        const fakes = createSourceFakes();
        const r = await read(fakes);
        const text = JSON.stringify(r);
        for (const marker of [...Object.values(OKTA_GRANT_MARKERS), OKTA_CLIENT_SECRET_VALUE, 'jane.doe@acme.example', 'client_secret_basic', OKTA_TOKEN_VALUE]) expect(text).not.toContain(marker);
        expect(fakes.log.some((e) => e.path.includes('/credentials'))).toBe(false);
    });
});

describe('3. completeness', () => {
    it('a 429 on a grants page ends the read RATE_LIMITED; what was read stays, and the application says its grants were not read', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === '/api/v1/apps/0oaService2/grants' && req.query !== '' ? RATE_LIMITED : undefined);
        const r = await read(fakes);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'RATE_LIMITED' });
        expect(byId(r, '0oaService2')?.scopeGrants).toEqual({ read: false, scopes: ['okta.logs.read'], unreadableScopes: 0 });
        // The applications whose grants were read before the stop keep them.
        expect(byId(r, '0oaSaml1')?.scopeGrants.read).toBe(true);
        expect(byId(r, '0oaService1')?.scopeGrants.read).toBe(true);
        // A presence counts on a partial read; the absence of a write does not.
        const body = buildIntegrationsReportBody({ scanId: 'acme-20261019T030000Z-0a1b2c3d', asOf: ASOF, scannerAgentId: 'agt' }, [r]);
        expect(IntegrationsReportBodyV1Schema.safeParse(body).success).toBe(true);
    });

    it('a 429 on the apps listing ends the read RATE_LIMITED with what the first page held, and no grant read', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === '/api/v1/apps' && req.query.includes('after=1') ? RATE_LIMITED : undefined);
        const r = await read(fakes);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'RATE_LIMITED', rows: 4, excluded: { count: 2 } });
        expect(r.applications.map((a) => a.id)).toEqual([app('0oaService1'), app('0oaWeb1')]);
        expect(r.applications.every((a) => a.sourceKind === 'okta-integrations' && !a.scopeGrants.read)).toBe(true);
        expect(fakes.log.some((e) => e.path.endsWith('/grants'))).toBe(false);
    });

    it('a page that fails, a page that is not a listing, and a refused token each stop the read with their reason', async () => {
        for (const [answer, reason] of [
            [{ status: 500, body: { errorCode: 'E0000009' } }, 'UNREACHABLE'],
            [{ status: 200, body: { errorCode: 'not a list' } }, 'PAGINATION_TORN'],
            ['throw', 'UNREACHABLE'],
        ] as const) {
            const fakes = createSourceFakes();
            fakes.override = (req) => (req.path === '/api/v1/apps/0oaWeb1/grants' ? (answer === 'throw' ? 'throw' : { ...answer, headers: { 'content-type': 'application/json' } }) : undefined);
            const r = await read(fakes);
            expect([reason, r.status, r.reason]).toEqual([reason, 'INCOMPLETE', reason]);
            expect(byId(r, '0oaWeb1')?.scopeGrants.read).toBe(false);
        }
        const refused = await read(createSourceFakes(), 'not-the-token');
        expect(refused).toMatchObject({ status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0, applications: [] });
    });

    it('a row that cannot be keyed fails the read: an application or a grant with no usable id, a grant with no scope', async () => {
        const cases: [Partial<ReturnType<typeof oktaFixture>>, string][] = [
            [{ allApps: [[{ label: 'No id', status: 'ACTIVE' }]] }, 'an application had no usable id'],
            [{ allApps: [[{ id: '0oa1', label: 'Twice' }, { id: '0oa1', label: 'Twice' }]] }, 'an application was listed twice'],
            [{ allApps: [[{ id: '0oa1' }]], grants: { '0oa1': [[{ status: 'ACTIVE', scopeId: 'okta.users.read' }]] } }, 'a grant had no usable id'],
            [{ allApps: [[{ id: '0oa1' }]], grants: { '0oa1': [[{ id: 'g1', status: 'ACTIVE' }]] } }, 'a grant had no scope'],
        ];
        for (const [over, detail] of cases) {
            const r = await read(createSourceFakes({ okta: { ...oktaFixture(), ...over } }));
            expect([detail, r.status, r.reason, r.detail]).toEqual([detail, 'INCOMPLETE', 'PAGINATION_TORN', detail]);
        }
    });

    it('an empty org read in full is COMPLETE with no application, which the planner calls a finding', async () => {
        const r = await read(createSourceFakes({ okta: { ...oktaFixture(), allApps: [[]], grants: {} } }));
        expect(r).toMatchObject({ status: 'COMPLETE', applications: [] });
        const plan = planIntegrationsScan(buildIntegrationsReportBody({ scanId: 'acme-20261019T030000Z-0a1b2c3d', asOf: ASOF, scannerAgentId: 'agt' }, [r]));
        expect(plan.findings.map((f) => f.code)).toEqual(['INTEGRATION_EMPTY_INVENTORY']);
    });
});

describe('4. read-only', () => {
    it('every request the read and the preflight make is a declared GET, with the token and nothing else of it', async () => {
        const fakes = createSourceFakes();
        await read(fakes);
        const steps = await preflight(fakes);
        expect(fakes.log.length).toBeGreaterThan(0);
        for (const e of fakes.log) {
            expect(e.method).toBe('GET');
            expect([e.path, isDeclaredRequest('GET', `${OKTA_ORG}${e.path}`)]).toEqual([e.path, true]);
        }
        expect(steps.map((s) => [s.id, s.what, s.outcome === 'ok' ? 'ok' : s.outcome.reason])).toEqual([
            ['read', 'applications', 'ok'],
            ['read', 'application grants', 'ok'],
            ['write', 'write access', 'ok'],
        ]);
        expect(steps[2].observed?.write).toMatchObject({ state: 'NOT_OBSERVABLE' });
        expect(Object.values(OKTA_INTEGRATIONS_READ_PATHS)).toEqual(['/api/v1/apps', '/api/v1/apps/{app}/grants']);
    });

    it('a refused token stops the preflight at its first read', async () => {
        const steps = await preflight(createSourceFakes(), 'not-the-token');
        expect(steps.map((s) => [s.what, s.outcome === 'ok' ? 'ok' : s.outcome.reason])).toEqual([['applications', 'AUTH_FAILED']]);
    });

    it('an org with no application asks for no grant, and still says what it could not observe', async () => {
        const steps = await preflight(createSourceFakes({ okta: { ...oktaFixture(), allApps: [[]] } }));
        expect(steps.map((s) => s.what)).toEqual(['applications', 'write access']);
    });
});
