/**
 * The integrations scanner's Entra source over the fake directory, answered as
 * Microsoft Graph documents its listings: `servicePrincipals`, `applications`,
 * `oauth2PermissionGrants`, each principal's `appRoleAssignments` and the beta
 * report `servicePrincipalSignInActivities`, each paged by `@odata.nextLink`.
 *
 *   1. WHICH APPLICATIONS: every enabled Application principal, the directory's
 *      own and other directories', never Microsoft's own, a managed identity
 *      or a disabled one.
 *   2. WHAT IS REPORTED: publisher, owners (the principal's and, for an own
 *      application, its registration's), delegated grants as scopes, consent
 *      type and a COUNT of people, application permissions by the resource's
 *      own role names, the last sign-in to the day, credentials by reference.
 *   3. WHAT NEVER LEAVES THE PAGE: a secret's hint, an app role's words, a
 *      resource's or a publisher's display name, a consenting person's id.
 *   4. COMPLETENESS: paging followed to the end; a throttled, failed or torn
 *      page ends the read INCOMPLETE with its reason, what was read stays and
 *      says how far it got; a row that cannot be keyed fails the read.
 *   5. SIGN-IN ACTIVITY is its own read: not configured is NOT_READ and
 *      makes no request; refused leaves the inventory complete.
 *   6. READ-ONLY: every request is a declared GET or the declared exchange,
 *      and the preflight asks for nothing the read does not.
 */
import {
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET_VALUE,
    createSourceFakes,
    ENTRA,
    ENTRA_DIRECTORY_ID,
    ENTRA_MARKERS,
    graphFixture,
    type Fakes,
    type GraphFixture,
} from './helpers/agent-harness-source-fakes';
import { IntegrationsReportBodyV1Schema } from '@rodnapamet/scanent-contract/integrations-contract';
import { createSourceWire } from '../src/http';
import type { IntegrationsSourceRead } from '../src/integrations-source';
import { isDeclaredRequest, isDeclaredTokenExchange } from '../src/scanner-surface';
import { entraIntegrationsSource, entraIntegrationsWriteObservation, reportableName, reportablePermission } from '../src/sources/entra-integrations';
import type { ProbeStep } from '../src/source';

const ASOF = new Date('2026-10-19T03:00:00.000Z');
const GRAPH_APP = '00000003-0000-0000-c000-000000000000';
const app = (sp: string) => `entra:${ENTRA_DIRECTORY_ID}:sp:${sp}`;

function source(readSignInActivity = true) {
    return entraIntegrationsSource({ directoryId: ENTRA_DIRECTORY_ID, clientId: AZURE_CLIENT_ID, clientSecret: AZURE_CLIENT_SECRET_VALUE, readSignInActivity });
}

async function read(fakes: Fakes, readSignInActivity = true): Promise<IntegrationsSourceRead> {
    const wire = createSourceWire({ fetchImpl: fakes.fetchImpl, deadline: ASOF.getTime() + 60_000, now: () => ASOF.getTime() });
    return source(readSignInActivity).read({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire });
}

async function preflight(fakes: Fakes, readSignInActivity = true): Promise<readonly ProbeStep[]> {
    const wire = createSourceWire({ fetchImpl: fakes.fetchImpl, deadline: ASOF.getTime() + 60_000, now: () => ASOF.getTime() });
    return source(readSignInActivity).preflight({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire });
}

const byId = (r: IntegrationsSourceRead, sp: string) => r.applications.find((a) => a.id === app(sp));

describe('1. which applications', () => {
    it('the directory\'s own and other directories\' enabled applications; never Microsoft\'s, a managed identity or a disabled one', async () => {
        const r = await read(createSourceFakes());
        expect(r).toMatchObject({ kind: 'entra-integrations', status: 'COMPLETE', signInActivity: { status: 'COMPLETE', rows: 3 } });
        expect(r.applications.map((a) => a.id)).toEqual([app(ENTRA.spSupport), app(ENTRA.spReporting), app(ENTRA.spThirdParty)].sort());
        // Six principals, four registrations, five grants, three assignments over three pages: every row counted.
        expect(r.rows).toBe(6 + 4 + 5 + 4);
        // What the source returns is what the contract accepts.
        expect(IntegrationsReportBodyV1Schema.safeParse({
            contract: 'scanent-integrations/1',
            scan: { id: 's', asOf: ASOF.toISOString(), scanner: { agentId: 'a', version: '0', manifestHash: `sha256:${'0'.repeat(64)}` } },
            sources: [{ kind: r.kind, status: r.status, rows: r.rows, signInActivity: r.signInActivity }],
            applications: r.applications,
        }).success).toBe(true);
    });
});

describe('2. what is reported', () => {
    it('a third party: its publisher not verified, no owner, Mail.ReadWrite and User.Read.All by role name over two pages, a sign-in in March', async () => {
        const third = byId(await read(createSourceFakes()), ENTRA.spThirdParty);
        expect(third).toEqual({
            id: app(ENTRA.spThirdParty),
            sourceKind: 'entra-integrations',
            appId: 'e0000006-0000-4000-8000-000000003686',
            displayName: 'Acme Mail Sync',
            origin: 'OTHER_DIRECTORY',
            publisherVerified: false,
            owners: [],
            delegatedGrants: { read: true, grants: [] },
            applicationPermissions: {
                read: true,
                permissions: [
                    { resourceAppId: GRAPH_APP, roleId: ENTRA.roleMailReadWrite, name: 'Mail.ReadWrite' },
                    { resourceAppId: GRAPH_APP, roleId: ENTRA.roleUserReadAll, name: 'User.Read.All' },
                ],
            },
            signIn: { read: true, lastSeen: '2026-03-02' },
            credentials: [{ ref: `entra://${ENTRA_DIRECTORY_ID}/servicePrincipals/${ENTRA.spThirdParty}/password/${ENTRA.keyThirdPartyPasswordCred}`, ageDays: 18, expires: true }],
        });
    });

    it('an own application: owners from its principal and its registration, grants made for two named people counted, an API the table does not know, no sign-in', async () => {
        const reporting = byId(await read(createSourceFakes()), ENTRA.spReporting);
        expect(reporting?.origin).toBe('THIS_DIRECTORY');
        expect(reporting?.owners).toEqual([{ kind: 'user', id: ENTRA.userZed }]);
        expect(reporting?.delegatedGrants).toEqual({
            read: true,
            grants: [
                { resourceAppId: GRAPH_APP, consentType: 'Principal', principalCount: 2, scopes: ['Files.Read.All', 'User.Read'], unreadableScopes: 0 },
                { resourceAppId: 'e0000006-0000-4000-8000-000000003686', consentType: 'AllPrincipals', principalCount: null, scopes: ['records.read'], unreadableScopes: 0 },
            ],
        });
        // The default-access assignment grants no permission and is not one.
        expect(reporting?.applicationPermissions.permissions).toEqual([{ resourceAppId: 'e0000006-0000-4000-8000-000000003686', roleId: ENTRA.roleThirdPartyExport, name: 'Records.Export.All' }]);
        expect(reporting?.signIn).toEqual({ read: true, lastSeen: null });
        const support = byId(await read(createSourceFakes()), ENTRA.spSupport);
        // Its registration's owners: two users and a principal, by kind and id. The principal's own list was empty.
        expect(support?.owners).toEqual([
            { kind: 'servicePrincipal', id: ENTRA.spOwnerPrincipal },
            { kind: 'user', id: ENTRA.userJane },
            { kind: 'user', id: ENTRA.userZed },
        ]);
        // A SAML signing certificate is not a credential it signs in with.
        expect(support?.credentials).toEqual([]);
        expect(support?.signIn).toEqual({ read: true, lastSeen: '2026-10-12' });
    });
});

describe('3. what never leaves the page', () => {
    it('no hint, no role or resource words, no publisher name, no consenting person', async () => {
        const text = JSON.stringify(await read(createSourceFakes()));
        for (const marker of [ENTRA_MARKERS.secretHint, ENTRA_MARKERS.credentialName, ENTRA_MARKERS.roleDescription, ENTRA_MARKERS.resourceName, ENTRA_MARKERS.publisherName, ENTRA_MARKERS.applicationNotes]) {
            expect(text).not.toContain(marker);
        }
        // The people a grant was made for are counted: neither id is in the read.
        expect(text).not.toContain(ENTRA.userJane.replace(/^c/, 'x'));
        const jane = JSON.stringify(byId(await read(createSourceFakes()), ENTRA.spReporting)?.delegatedGrants);
        expect(jane).not.toContain(ENTRA.userJane);
        expect(jane).not.toContain(ENTRA.userZed);
    });

    it('a name the directory holds is reported only when printable, bounded and not secret-shaped', () => {
        const token = ['gh', 'p_', 'C3'.repeat(12)].join('');
        expect(reportableName('Acme Mail Sync')).toBe('Acme Mail Sync');
        expect(reportableName(`sync ${token}`)).toBeNull();
        expect(reportableName('line\nbreak')).toBeNull();
        expect(reportableName('x'.repeat(257))).toBeNull();
        expect(reportableName('   ')).toBeNull();
        expect(reportableName(42)).toBeNull();
        expect(reportablePermission('Mail.Read')).toBe('Mail.Read');
        expect(reportablePermission(token)).toBeNull();
        expect(reportablePermission('has space')).toBeNull();
    });

    it('a secret-shaped scope is counted as unreadable and not reported; a secret-shaped name is withheld', async () => {
        const token = ['gh', 'p_', 'D4'.repeat(12)].join('');
        const graph = graphFixture();
        graph.oauth2PermissionGrants = [[{ clientId: ENTRA.spThirdParty, consentType: 'AllPrincipals', principalId: null, resourceId: ENTRA.spGraph, scope: `Mail.Read ${token}` }]];
        (graph.servicePrincipals[1][2] as Record<string, unknown>).displayName = `sync ${token}`;
        const r = await read(createSourceFakes({ graph }));
        const third = byId(r, ENTRA.spThirdParty);
        expect(third?.delegatedGrants.grants).toEqual([{ resourceAppId: GRAPH_APP, consentType: 'AllPrincipals', principalCount: null, scopes: ['Mail.Read'], unreadableScopes: 1 }]);
        expect(third?.displayName).toBeNull();
        expect(JSON.stringify(r)).not.toContain(token);
    });
});

describe('4. completeness', () => {
    it('a throttled page (429 with Retry-After) ends the read RATE_LIMITED; what was read stays, and says how far it got', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === `/v1.0/servicePrincipals/${ENTRA.spThirdParty}/appRoleAssignments` ? { status: 429, body: { error: { code: 'TooManyRequests' } }, headers: { 'retry-after': '30' } } : undefined);
        const r = await read(fakes);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'RATE_LIMITED' });
        // The delegated grants were read in full; the third party's permissions were not; sign-in was never reached.
        expect(byId(r, ENTRA.spThirdParty)?.delegatedGrants.read).toBe(true);
        expect(byId(r, ENTRA.spThirdParty)?.applicationPermissions).toEqual({ read: false, permissions: [] });
        expect(r.signInActivity).toMatchObject({ status: 'INCOMPLETE', reason: 'RATE_LIMITED', rows: 0 });
        expect(r.applications.every((a) => !a.signIn.read)).toBe(true);
        // No retry: the throttled page was asked for once.
        expect(fakes.log.filter((e) => e.path === `/v1.0/servicePrincipals/${ENTRA.spThirdParty}/appRoleAssignments`)).toHaveLength(1);
    });

    it('a second page of the grants that fails ends the read UNREACHABLE; the first page\'s grants are kept and marked as not read in full', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === '/v1.0/oauth2PermissionGrants' && req.query.includes('skiptoken=1') ? { status: 503 } : undefined);
        const r = await read(fakes);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'UNREACHABLE' });
        const reporting = byId(r, ENTRA.spReporting);
        expect(reporting?.delegatedGrants).toEqual({ read: false, grants: [{ resourceAppId: GRAPH_APP, consentType: 'Principal', principalCount: 1, scopes: ['Files.Read.All', 'User.Read'], unreadableScopes: 0 }] });
        expect(reporting?.applicationPermissions.read).toBe(false);
    });

    it('a registrations listing that fails leaves an own application\'s owners NOT READ, unless its principal named one', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === '/v1.0/applications' ? 'throw' : undefined);
        const r = await read(fakes);
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'UNREACHABLE' });
        expect(byId(r, ENTRA.spSupport)?.owners).toBeNull();
        expect(byId(r, ENTRA.spReporting)?.owners).toEqual([{ kind: 'user', id: ENTRA.userZed }]);
        // Another directory's application is owned on its principal alone.
        expect(byId(r, ENTRA.spThirdParty)?.owners).toEqual([]);
    });

    it.each<[string, (g: GraphFixture) => void, string]>([
        ['a principal with no id', (g) => delete (g.servicePrincipals[0][0] as Record<string, unknown>).id, 'a service principal had no usable id'],
        ['an application principal with no application id', (g) => delete (g.servicePrincipals[1][2] as Record<string, unknown>).appId, 'an application had no usable application id'],
        ['a registration with no application id', (g) => delete (g.applications[0][0] as Record<string, unknown>).appId, 'an application registration had no usable id'],
        ['a grant with no client', (g) => delete ((g.oauth2PermissionGrants ?? [])[0][0] as Record<string, unknown>).clientId, 'a delegated grant had no usable ids'],
        ['a grant for named people with no principal', (g) => (((g.oauth2PermissionGrants ?? [])[0][1] as Record<string, unknown>).principalId = null), 'a delegated grant had no usable ids'],
        ['an assignment with no role', (g) => delete ((g.appRoleAssignments ?? {})[ENTRA.spThirdParty][0][0] as Record<string, unknown>).appRoleId, 'an assignment had no usable ids'],
        ['an assignment for another principal', (g) => (((g.appRoleAssignments ?? {})[ENTRA.spThirdParty][0][0] as Record<string, unknown>).principalId = ENTRA.spSupport), 'an assignment named another principal'],
        ['an owner with no id', (g) => ((g.servicePrincipals[0][1] as Record<string, unknown>).owners = [{ '@odata.type': '#microsoft.graph.user' }]), 'an owner had no usable id'],
    ])('a row that cannot be keyed fails the read rather than being skipped: %s', async (_name, mutate, detail) => {
        const graph = graphFixture();
        mutate(graph);
        const r = await read(createSourceFakes({ graph }));
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'PAGINATION_TORN', detail });
    });

    it('a sign-in record with no application id fails the sign-in read, and only it', async () => {
        const graph = graphFixture();
        delete ((graph.signInActivities ?? [])[1][0] as Record<string, unknown>).appId;
        const r = await read(createSourceFakes({ graph }));
        expect(r.status).toBe('COMPLETE');
        expect(r.signInActivity).toMatchObject({ status: 'INCOMPLETE', reason: 'PAGINATION_TORN', rows: 3 });
        // What the first page read is kept; an application it did not list is not read.
        expect(byId(r, ENTRA.spSupport)?.signIn).toEqual({ read: true, lastSeen: '2026-10-12' });
        expect(byId(r, ENTRA.spThirdParty)?.signIn).toEqual({ read: false, lastSeen: null });
    });

    it('a page that is not the listing\'s shape tears the read', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === '/v1.0/servicePrincipals' ? { status: 200, body: { message: 'welcome' } } : undefined);
        expect(await read(fakes)).toMatchObject({ status: 'INCOMPLETE', reason: 'PAGINATION_TORN', applications: [] });
    });

    it('a refused token exchange is AUTH_FAILED, and so is the sign-in read it never reached', async () => {
        const wire = createSourceWire({ fetchImpl: createSourceFakes().fetchImpl, deadline: ASOF.getTime() + 60_000, now: () => ASOF.getTime() });
        const r = await entraIntegrationsSource({ directoryId: ENTRA_DIRECTORY_ID, clientId: AZURE_CLIENT_ID, clientSecret: 'wrong', readSignInActivity: true }).read({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire });
        expect(r).toMatchObject({ status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0, applications: [], signInActivity: { status: 'INCOMPLETE', reason: 'AUTH_FAILED' } });
    });
});

describe('5. sign-in activity', () => {
    it('not configured: NOT_READ, no request to the report, and no application says it was read', async () => {
        const fakes = createSourceFakes();
        const r = await read(fakes, false);
        expect(r).toMatchObject({ status: 'COMPLETE', signInActivity: { status: 'NOT_READ' } });
        expect(r.applications.every((a) => a.signIn.read === false && a.signIn.lastSeen === null)).toBe(true);
        expect(fakes.log.some((e) => e.path.startsWith('/beta/'))).toBe(false);
    });

    it('refused (no licence, or no AuditLog.Read.All): the inventory stays complete, and no application is read', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === '/beta/reports/servicePrincipalSignInActivities' ? { status: 403, body: { error: { code: 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' } } } : undefined);
        const r = await read(fakes);
        expect(r.status).toBe('COMPLETE');
        expect(r.signInActivity).toMatchObject({ status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0 });
        expect(r.applications.every((a) => !a.signIn.read)).toBe(true);
    });
});

describe('6. read-only', () => {
    it('every request is a declared GET, after one declared client-credentials exchange', async () => {
        const fakes = createSourceFakes();
        await read(fakes);
        const exchanges = fakes.log.filter((e) => e.method === 'POST');
        expect(exchanges).toHaveLength(1);
        expect(exchanges[0].host).toBe('login.microsoftonline.com');
        for (const e of fakes.log.filter((x) => x.method !== 'POST')) {
            expect([e.method, e.path, isDeclaredRequest(e.method, `https://${e.host}${e.path}`)]).toEqual(['GET', e.path, true]);
        }
        // Every page of every listing was followed.
        const pages = (path: string) => fakes.log.filter((e) => e.path === path).length;
        expect([pages('/v1.0/servicePrincipals'), pages('/v1.0/applications'), pages('/v1.0/oauth2PermissionGrants'), pages('/beta/reports/servicePrincipalSignInActivities')]).toEqual([2, 2, 2, 2]);
        expect(pages(`/v1.0/servicePrincipals/${ENTRA.spThirdParty}/appRoleAssignments`)).toBe(2);
        // Assignments are asked for the reported applications only.
        expect(pages(`/v1.0/servicePrincipals/${ENTRA.spGraph}/appRoleAssignments`)).toBe(0);
        expect(isDeclaredTokenExchange('entra-integrations', 'grant_type=client_credentials')).toBe(true);
        expect(isDeclaredTokenExchange('entra-integrations', 'grant_type=password')).toBe(false);
    });

    it('the preflight: the exchange, one row of each listing the read makes, and what the token says about writing', async () => {
        const fakes = createSourceFakes();
        const steps = await preflight(fakes);
        expect(steps.map((s) => [s.id, s.what, s.outcome === 'ok'])).toEqual([
            ['exchange', 'token', true],
            ['read', 'servicePrincipals', true],
            ['read', 'applications', true],
            ['read', 'oauth2PermissionGrants', true],
            ['read', 'appRoleAssignments', true],
            ['read', 'servicePrincipalSignInActivities', true],
            ['write', 'write access', true],
        ]);
        for (const e of fakes.log.filter((x) => x.method !== 'POST')) expect(isDeclaredRequest(e.method, `https://${e.host}${e.path}`)).toBe(true);
        expect((await preflight(createSourceFakes(), false)).map((s) => s.what)).not.toContain('servicePrincipalSignInActivities');
    });

    it('the preflight stops at a refused read and says so', async () => {
        const fakes = createSourceFakes();
        fakes.override = (req) => (req.path === '/v1.0/oauth2PermissionGrants' ? { status: 403 } : undefined);
        const steps = await preflight(fakes);
        expect(steps.map((s) => s.what)).toEqual(['token', 'servicePrincipals', 'applications', 'oauth2PermissionGrants']);
        expect(steps[3].outcome).toMatchObject({ reason: 'AUTH_FAILED', status: 403 });
    });

    it('what a token\'s roles say: read-only, a write, or not observable', () => {
        const jwt = (roles: unknown) => `e30.${Buffer.from(JSON.stringify({ roles })).toString('base64url')}.sig`;
        expect(entraIntegrationsWriteObservation(jwt(['Application.Read.All', 'Directory.Read.All']), false)).toEqual({ state: 'READ_ONLY', detail: 'the token holds Application.Read.All, Directory.Read.All' });
        expect(entraIntegrationsWriteObservation(jwt(['Application.ReadWrite.All']), true)).toMatchObject({ state: 'WRITE', names: ['Application.ReadWrite.All'] });
        expect(entraIntegrationsWriteObservation('opaque', true)).toMatchObject({ state: 'NOT_OBSERVABLE' });
        expect((entraIntegrationsWriteObservation('opaque', true) as { verify: string }).verify).toContain('AuditLog.Read.All');
    });
});
