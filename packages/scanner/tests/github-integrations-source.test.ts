/**
 * The integrations scanner's GitHub source over the fake organisation,
 * answered as GitHub documents "List app installations for an organization"
 * and "List organization webhooks": paged by `page` with the next page in the
 * `Link` header, the installations wrapped with a `total_count`, and a rate
 * limit answered 403 or 429 with GitHub's `x-ratelimit-*` or `retry-after`.
 *
 *   1. WHAT IS REPORTED: each installation's app, permissions, repository
 *      selection, events and suspension; each webhook by HOST.
 *   2. A WEBHOOK'S URL NEVER LEAVES THE WIRE BOUNDARY: its path, query,
 *      userinfo and the hook's secret are in nothing the source returns.
 *   3. COMPLETENESS: paging to the end and the count held; a rate limit in
 *      either of GitHub's two forms is RATE_LIMITED, any other 403 is
 *      AUTH_FAILED; what was read stays; a row with no usable id fails.
 *   4. READ-ONLY: every request a declared GET; the preflight's view of the
 *      token.
 */
import { IntegrationsReportBodyV1Schema, type GitHubInstallation } from '@rodnapamet/scanent-contract/integrations-contract';
import { planIntegrationsScan } from '@rodnapamet/scanent-contract/integrations-findings';

import { createSourceWire } from '../src/http';
import type { IntegrationsSourceRead } from '../src/integrations-source';
import { buildIntegrationsReportBody } from '../src/integrations-report';
import { isDeclaredRequest } from '../src/scanner-surface';
import type { ProbeStep } from '../src/source';
import { GITHUB_INTEGRATIONS_READ_PATHS, githubIntegrationsSource, githubIntegrationsWriteObservation, webhookHost } from '../src/sources/github-integrations';
import { GITHUB_TOKEN_VALUE } from './helpers/doctor-world';
import {
    createEstateWorld,
    GITHUB_HOOK_MARKERS,
    GITHUB_INTEGRATIONS_TOKEN_VALUE,
    GITHUB_ORG,
    githubInstallation,
    githubOrgFixture,
    type EstateWorld,
    type GithubOrgFixture,
} from './helpers/estate-world';

const ASOF = new Date('2026-10-19T03:00:00.000Z');
const inst = (id: number) => `github:${GITHUB_ORG}:installation:${id}`;

const source = (token = GITHUB_INTEGRATIONS_TOKEN_VALUE, organization = GITHUB_ORG) => githubIntegrationsSource({ organization, token });

function wire(world: EstateWorld) {
    return createSourceWire({ fetchImpl: world.fetchImpl, deadline: ASOF.getTime() + 60_000, now: () => ASOF.getTime() });
}

async function read(world: EstateWorld, token?: string, organization?: string): Promise<IntegrationsSourceRead> {
    return source(token, organization).read({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire(world) });
}

async function preflight(world: EstateWorld, token?: string): Promise<readonly ProbeStep[]> {
    return source(token).preflight({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire(world) });
}

const world = (orgs?: Record<string, GithubOrgFixture>) => createEstateWorld(orgs === undefined ? {} : { githubOrgs: orgs });
const byId = (r: IntegrationsSourceRead, id: number): GitHubInstallation | undefined =>
    r.applications.find((a): a is GitHubInstallation => a.sourceKind === 'github-integrations' && a.id === inst(id));

const withOrg = (over: Partial<GithubOrgFixture>) => ({ [GITHUB_ORG]: { ...githubOrgFixture()[GITHUB_ORG], ...over } });

describe('1. what is reported', () => {
    it('every installation of the organisation, every page, with what GitHub says of each', async () => {
        const w = world();
        const r = await read(w);
        expect(r).toMatchObject({ kind: 'github-integrations', status: 'COMPLETE', rows: 5, signInActivity: { status: 'NOT_READ' } });
        expect(byId(r, 41)).toEqual({
            id: inst(41),
            sourceKind: 'github-integrations',
            appId: 9041,
            appSlug: 'acme-deploy-bot',
            repositorySelection: 'selected',
            suspended: false,
            events: ['pull_request', 'push'],
            permissions: { read: true, grants: [{ name: 'contents', level: 'write' }, { name: 'metadata', level: 'read' }, { name: 'pull_requests', level: 'write' }], unreadable: 0 },
        });
        expect(byId(r, 43)).toMatchObject({ appSlug: 'old-ci', suspended: true, repositorySelection: 'all', events: [] });
        expect(r.applications.map((a) => a.id)).toEqual([inst(41), inst(42), inst(43)]);
        expect(w.log.filter((e) => e.path === `/orgs/${GITHUB_ORG}/installations`).map((e) => e.query)).toEqual(['?per_page=100', '?per_page=100&page=2']);
    });

    it('each webhook by its host, with its events, state and day of creation', async () => {
        const r = await read(world());
        expect(r.webhooks).toEqual({
            read: true,
            hooks: [
                { id: `github:${GITHUB_ORG}:hook:7`, sourceKind: 'github-integrations', host: 'hooks.chat.example', events: ['pull_request', 'push'], active: true, created: '2026-01-04' },
                { id: `github:${GITHUB_ORG}:hook:8`, sourceKind: 'github-integrations', host: '10.20.30.40', events: ['*'], active: false, created: '2025-12-01' },
            ],
        });
    });

    it('becomes a report the contract accepts, and the planner reads it per GitHub', async () => {
        const r = await read(world());
        const body = buildIntegrationsReportBody({ scanId: 'acme-20261019T030000Z-0a1b2c3d', asOf: ASOF, scannerAgentId: 'agt_scanner' }, [r]);
        expect(IntegrationsReportBodyV1Schema.safeParse(body).success).toBe(true);
        expect(body.webhooks?.hooks).toHaveLength(2);
        const plan = planIntegrationsScan(body);
        // issues:read is repository content, so high; repository_projects:read is not in the table, and listed.
        expect(plan.findings.map((f) => `${f.code} ${f.applicationId}`)).toEqual([`INTEGRATION_HIGH_PRIVILEGE_GRANT ${inst(41)}`, `INTEGRATION_HIGH_PRIVILEGE_GRANT ${inst(42)}`]);
        expect(plan.applications.map((a) => a.privilege)).toEqual(['HIGH', 'HIGH', 'NOT_HIGH']);
        expect(plan.unknownPermissionNames).toEqual([{ via: 'GITHUB_PERMISSION', resourceAppId: null, name: 'repository_projects:read' }]);
        expect(plan.notConcluded.filter((n) => n.applicationId === null).map((n) => n.why)).toEqual(['PUBLISHER_NOT_EXPOSED', 'OWNER_NOT_EXPOSED', 'SIGN_IN_NOT_EXPOSED']);
    });

    it('a permission or an event that is not GitHub\'s shape is counted or dropped; an unknown slug or selection is null', async () => {
        const odd = githubInstallation({ id: 50, app_slug: 'Not A Slug', repository_selection: 'some', permissions: { contents: 'owner', 'bad name': 'read', metadata: 'read' }, events: ['push', 'Bad Event', 7], app_id: 'x' });
        const r = await read(world(withOrg({ installations: [[odd]], hooks: [[]] })));
        expect(byId(r, 50)).toMatchObject({ appId: null, appSlug: null, repositorySelection: null, events: ['push'], permissions: { read: true, grants: [{ name: 'metadata', level: 'read' }], unreadable: 2 } });
        const noMap = githubInstallation({ id: 51, permissions: 'all' });
        const r2 = await read(world(withOrg({ installations: [[noMap]], hooks: [[]] })));
        expect(byId(r2, 51)?.permissions).toEqual({ read: false, grants: [], unreadable: 0 });
        expect(byId(r2, 51)).toMatchObject({ suspended: false });
        const unknownSuspension = githubInstallation({ id: 52 });
        delete unknownSuspension.suspended_at;
        expect(byId(await read(world(withOrg({ installations: [[unknownSuspension]], hooks: [[]] }))), 52)?.suspended).toBeNull();
    });
});

describe('2. a webhook\'s URL never leaves the wire boundary', () => {
    it('its path, query, userinfo and the hook\'s secret are in nothing the read returns', async () => {
        const text = JSON.stringify(await read(world()));
        for (const marker of [...Object.values(GITHUB_HOOK_MARKERS), 'services', 'token=', '8443', '/in', 'api.github.com/orgs', 'jane-admin', 'apps@vendor.example']) expect([marker, text.includes(marker)]).toEqual([marker, false]);
    });

    it('reduces a URL to its host, and nothing else to anything', () => {
        expect(webhookHost('https://hooks.chat.example/a/b?c=d#e')).toBe('hooks.chat.example');
        expect(webhookHost('https://User:Pass@Hooks.Chat.Example:8443/x')).toBe('hooks.chat.example');
        expect(webhookHost('http://10.0.0.7/x')).toBe('10.0.0.7');
        expect(webhookHost('https://[2001:db8::1]:9000/x')).toBe('[2001:db8::1]');
        for (const v of ['ftp://files.example/x', 'not a url', 42, null, undefined, `https://${['gh', 'p_', 'F6'.repeat(12)].join('')}.example/x`]) expect([v, webhookHost(v)]).toEqual([v, null]);
    });

    it('a hook with no config, or no URL in it, is listed with no host', async () => {
        const hooks = [[{ id: 9, name: 'web', active: true, events: ['push'], created_at: 'garbage' }, { id: 10, name: 'web', config: { content_type: 'json' } }]];
        const r = await read(world(withOrg({ hooks })));
        // Sorted by id as text, as every list of the report is.
        expect(r.webhooks?.hooks.map((h) => [h.id, h.host, h.active, h.created])).toEqual([
            [`github:${GITHUB_ORG}:hook:10`, null, null, null],
            [`github:${GITHUB_ORG}:hook:9`, null, true, null],
        ]);
    });
});

describe('3. completeness', () => {
    const rateLimits: [string, { status: number; body: unknown; headers: Record<string, string> }][] = [
        ['a 403 with x-ratelimit-remaining: 0', { status: 403, body: { message: 'API rate limit exceeded' }, headers: { 'x-ratelimit-limit': '5000', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1760842860', 'x-ratelimit-resource': 'core' } }],
        ['a 403 with retry-after (a secondary limit)', { status: 403, body: { message: 'You have exceeded a secondary rate limit' }, headers: { 'retry-after': '60' } }],
        ['a 429 with retry-after', { status: 429, body: { message: 'You have exceeded a secondary rate limit' }, headers: { 'retry-after': '60' } }],
    ];

    it.each(rateLimits)('%s on the second page of installations is RATE_LIMITED, keeping the first page', async (_label, answer) => {
        const w = world();
        w.inject = (req) => (req.path.endsWith('/installations') && req.query.includes('page=2') ? answer : undefined);
        const r = await read(w);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'RATE_LIMITED', rows: 2 });
        expect(r.applications.map((a) => a.id)).toEqual([inst(41), inst(42)]);
        // The webhooks were never reached: not listed in full, and none claimed.
        expect(r.webhooks).toEqual({ read: false, hooks: [] });
    });

    it('a rate limit on the webhooks keeps every installation and says the webhooks were not listed in full', async () => {
        const w = world();
        w.inject = (req) => (req.path.endsWith('/hooks') ? rateLimits[0][1] : undefined);
        const r = await read(w);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'RATE_LIMITED' });
        expect(r.applications).toHaveLength(3);
        expect(r.webhooks).toEqual({ read: false, hooks: [] });
    });

    it('a 403 that is not a rate limit is AUTH_FAILED: the token without the organisation permission', async () => {
        const r = await read(world(), GITHUB_TOKEN_VALUE);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0, applications: [] });
    });

    it('a page that fails, a page that is not the listing, a count that changes or falls short: each stops the read', async () => {
        const fixture = githubOrgFixture()[GITHUB_ORG];
        const cases: [EstateWorld['inject'], string, string | undefined][] = [
            [(req) => (req.query.includes('page=2') ? { status: 502, body: { message: 'Server Error' } } : undefined), 'UNREACHABLE', undefined],
            [(req) => (req.path.endsWith('/hooks') ? { status: 200, body: { not: 'a list' } } : undefined), 'PAGINATION_TORN', 'a page was not the listing it should be'],
            [(req) => (req.query.includes('page=2') ? { status: 200, body: { total_count: 9, installations: fixture.installations[1] } } : undefined), 'PAGINATION_TORN', 'the installation count changed while it was read'],
            [
                (req) => (req.path.endsWith('/installations') ? { status: 200, body: { total_count: 4, installations: fixture.installations[0] } } : undefined),
                'PAGINATION_TORN',
                'the installation listing held a different number than it counted',
            ],
            [(req) => (req.path.endsWith('/hooks') ? 'throw' : undefined), 'UNREACHABLE', undefined],
        ];
        for (const [inject, reason, detail] of cases) {
            const w = world();
            w.inject = inject;
            const r = await read(w);
            expect([reason, r.status, r.reason]).toEqual([reason, 'INCOMPLETE', reason]);
            if (detail !== undefined) expect(r.detail).toBe(detail);
        }
    });

    it('a row that cannot be keyed fails the read: an installation or a webhook with no usable id, or one seen twice', async () => {
        const one = githubInstallation({ id: 41 });
        const cases: [Partial<GithubOrgFixture>, string][] = [
            [{ installations: [[{ ...one, id: 'x' }]] }, 'an installation had no usable id, or one seen twice'],
            [{ installations: [[one, one]] }, 'an installation had no usable id, or one seen twice'],
            [{ installations: [['not an object']] }, 'an installation was not an object'],
            [{ hooks: [[{ name: 'web' }]] }, 'a webhook had no usable id, or one seen twice'],
            [{ hooks: [[7]] }, 'a webhook was not an object'],
            [{ installations: [[{ ...one, events: 'push' }]] }, 'a listed object had a malformed event list'],
        ];
        for (const [over, detail] of cases) {
            const r = await read(world(withOrg(over)));
            expect([detail, r.status, r.reason, r.detail]).toEqual([detail, 'INCOMPLETE', 'PAGINATION_TORN', detail]);
        }
    });

    it('an organisation that is not a login is refused before any request; one with no installation is COMPLETE and empty', async () => {
        const w = world();
        expect(await read(w, undefined, 'acme/web')).toMatchObject({ status: 'INCOMPLETE', reason: 'UNPARSEABLE' });
        expect(w.log).toEqual([]);
        const empty = await read(world(withOrg({ installations: [[]], hooks: [[]] })));
        expect(empty).toMatchObject({ status: 'COMPLETE', applications: [], webhooks: { read: true, hooks: [] } });
        const plan = planIntegrationsScan(buildIntegrationsReportBody({ scanId: 'acme-20261019T030000Z-0a1b2c3d', asOf: ASOF, scannerAgentId: 'agt' }, [empty]));
        expect(plan.findings.map((f) => [f.code, f.severity])).toEqual([['INTEGRATION_EMPTY_INVENTORY', 'LOW']]);
        expect(plan.findings[0].description).toContain('no webhook either');
        expect(plan.findings[0].description).toContain('wrong organisation');
    });
});

describe('4. read-only', () => {
    it('every request the read and the preflight make is a declared GET', async () => {
        const w = world();
        await read(w);
        const steps = await preflight(w);
        expect(w.log.length).toBeGreaterThan(0);
        for (const e of w.log) {
            expect(e.method).toBe('GET');
            expect([e.path, isDeclaredRequest('GET', e.url)]).toEqual([e.path, true]);
        }
        expect(steps.map((s) => [s.id, s.what, s.outcome === 'ok' ? 'ok' : s.outcome.reason])).toEqual([
            ['read', 'app installations', 'ok'],
            ['read', 'webhooks', 'ok'],
            ['write', 'write access', 'ok'],
        ]);
        expect(steps[2].observed?.write).toMatchObject({ state: 'NOT_OBSERVABLE' });
        expect(Object.values(GITHUB_INTEGRATIONS_READ_PATHS)).toEqual(['/orgs/{org}/installations', '/orgs/{org}/hooks']);
    });

    it('the preflight stops at a refused token, and reads a classic token\'s scopes', async () => {
        expect((await preflight(world(), GITHUB_TOKEN_VALUE)).map((s) => [s.what, s.outcome === 'ok' ? 'ok' : s.outcome.reason])).toEqual([['app installations', 'AUTH_FAILED']]);
        expect(githubIntegrationsWriteObservation('admin:org_hook, read:org')).toMatchObject({ state: 'WRITE', names: ['admin:org_hook'] });
        expect(githubIntegrationsWriteObservation('read:org')).toEqual({ state: 'READ_ONLY', detail: 'a classic token holding read:org' });
        expect(githubIntegrationsWriteObservation('')).toEqual({ state: 'READ_ONLY', detail: 'a classic token with no scope' });
        expect(githubIntegrationsWriteObservation('Not A Scope!')).toMatchObject({ state: 'NOT_OBSERVABLE' });
        const w = world();
        w.inject = (req) => (req.path.endsWith('/installations') ? { status: 200, body: { total_count: 0, installations: [] }, headers: { 'x-oauth-scopes': 'admin:org, admin:org_hook' } } : undefined);
        const steps = await preflight(w);
        expect(steps[2].observed?.write).toMatchObject({ state: 'WRITE', names: ['admin:org', 'admin:org_hook'] });
    });
});
