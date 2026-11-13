/**
 * THE ENTRA INTEGRATIONS SOURCE — `entra-integrations`, the integrations
 * scanner's first reader.
 *
 * What one Entra directory has granted to applications, and who owns them,
 * read from Microsoft Graph with the one client-credentials exchange the
 * agent scanner's Entra reader makes. It is a source kind of its own, read
 * into a report of its own (`scanent-integrations/1`): a product read by two
 * scanners is two kinds with two entries, which may name the same credential.
 *
 * WHICH SERVICE PRINCIPALS ARE APPLICATIONS HERE: every enabled `Application`
 * service principal, the directory's own and other directories', except
 * Microsoft's own first-party applications, which are the platform. A managed
 * identity, a legacy or social principal, and a disabled one are read and
 * counted in `rows`, and reported as nothing.
 *
 * WHAT IS READ, IN ORDER, ALL BY GET (five listings, the fifth only when asked):
 *
 *   1. `/v1.0/servicePrincipals`, with each principal's verified publisher,
 *      its app roles (to name what an assignment grants), its credentials'
 *      ids and dates, and its owners' ids;
 *   1b. `/v1.0/applications`, for the owners of the directory's OWN
 *      applications: an application registered here is owned on its
 *      registration as much as on its principal, and reading only the
 *      principal's would call most of them unowned;
 *   2. `/v1.0/oauth2PermissionGrants`: the delegated grants. Each is kept as
 *      its scopes, its consent type and, for a grant made for named people,
 *      HOW MANY: the principal ids are counted and dropped;
 *   3. `/v1.0/servicePrincipals/{id}/appRoleAssignments` for each application:
 *      its application permissions, named by the resource's own app roles;
 *   4. only when the configuration asks for it, the beta report
 *      `/beta/reports/servicePrincipalSignInActivities`: each application's
 *      last sign-in, to the day.
 *
 * WHAT IS NEVER KEPT: a credential's hint or secret text, an app role's or a
 * credential's description and display name, a principal id of a person who
 * consented, a resource's display name. A name the directory holds is reported
 * only when it is printable, short enough and not secret-shaped; otherwise it
 * is withheld (null), and a scope name that cannot be reported is counted.
 *
 * COMPLETENESS, as every other source: a listing that stops (an error, the
 * page cap, a torn page, a rate limit) ends the read INCOMPLETE with its
 * reason, and what was read is reported with each member saying whether it was
 * read in full. A row that cannot be keyed (a principal, a grant or an
 * assignment without its ids) fails the read rather than being skipped. The
 * sign-in read has its own status: it failing leaves the inventory complete,
 * and "unused" unconcluded.
 */
import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract';
import {
    ENTRA_OBJECT_ID,
    MAX_APPLICATION_PERMISSIONS_PER_APPLICATION,
    MAX_APPLICATIONS,
    MAX_CREDENTIALS_PER_APPLICATION,
    MAX_DELEGATED_GRANTS_PER_APPLICATION,
    MAX_DISPLAY_NAME_CHARS,
    MAX_OWNERS_PER_APPLICATION,
    MAX_SCOPES_PER_GRANT,
    PERMISSION_NAME,
    type ApplicationOrigin,
    type IntegrationsApplicationPermission,
    type IntegrationsDelegatedGrant,
    type EntraIntegrationsApplication,
    type OwnerKind,
} from '@rodnapamet/scanent-contract/integrations-contract';

import type { IntegrationsSource, IntegrationsSourceRead, SignInRead } from '../integrations-source';
import {
    ageInDays,
    isJsonObject,
    ProbeLog,
    readPages,
    SourceReadError,
    type ProbeStep,
    type SourceContext,
    type WriteObservation,
} from '../source';
import { AZURE_LOGIN_ORIGIN } from './azure-key-vault';
import { entraTokenRoles, GRAPH_ORIGIN, GRAPH_SCOPE, MICROSOFT_APP_OWNER_TENANTS } from './entra';

/** The four reads, in the order they are made. `scanner-surface.ts` declares them for the manifest hash. */
export const ENTRA_INTEGRATIONS_READ_PATHS = {
    servicePrincipals: '/v1.0/servicePrincipals',
    applications: '/v1.0/applications',
    delegatedGrants: '/v1.0/oauth2PermissionGrants',
    appRoleAssignments: '/v1.0/servicePrincipals/{id}/appRoleAssignments',
    signInActivity: '/beta/reports/servicePrincipalSignInActivities',
} as const;

/** What the results say was left out, in fixed words. */
export const ENTRA_FIRST_PARTY_EXCLUSION = "Microsoft's own first-party applications, which every directory holds";

/** The application permissions the identity the source reads with needs, and the one more for sign-in activity. */
export const ENTRA_INTEGRATIONS_REQUIRED_ROLES = ['Application.Read.All', 'Directory.Read.All'] as const;
export const ENTRA_SIGN_IN_ROLE = 'AuditLog.Read.All';

/** How many applications' assignments are read at once. Graph throttles per application; four stays well under it. */
export const ASSIGNMENT_CONCURRENCY = 4;

/** The app role id an assignment carries when it grants access to the application and no named role. */
const DEFAULT_ACCESS_ROLE = '00000000-0000-0000-0000-000000000000';

export interface EntraIntegrationsSourceOptions {
    readonly directoryId: string;
    readonly clientId: string;
    /** Resolved from the environment by the caller. */
    readonly clientSecret: string;
    /** Read each application's last sign-in. Needs `AuditLog.Read.All`, and a licence that records it. */
    readonly readSignInActivity: boolean;
}

const guid = (v: unknown): string | null => (typeof v === 'string' && ENTRA_OBJECT_ID.test(v.toLowerCase()) ? v.toLowerCase() : null);

function dateOrNull(v: unknown): Date | null {
    if (typeof v !== 'string') return null;
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
}

/** One Graph listing page: `{ value: [...], '@odata.nextLink'? }`. */
function graphPage(body: unknown): { items: readonly unknown[]; next: string | null } | null {
    if (!isJsonObject(body)) return null;
    const { value } = body;
    const next = body['@odata.nextLink'];
    if (!Array.isArray(value)) return null;
    if (next !== undefined && next !== null && typeof next !== 'string') return null;
    return { items: value, next: typeof next === 'string' && next !== '' ? next : null };
}

/** An array member, `[]` when absent; any other shape tears the page. */
function arrayMember(v: unknown): readonly unknown[] {
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v)) throw new SourceReadError('PAGINATION_TORN', 'a listed object had a malformed collection');
    return v;
}

/** A name the directory holds, when it may be reported: printable, bounded, and not secret-shaped. */
export function reportableName(v: unknown): string | null {
    if (typeof v !== 'string') return null;
    const name = v.trim();
    if (name === '' || [...name].length > MAX_DISPLAY_NAME_CHARS) return null;
    if ([...name].some((ch) => { const c = ch.codePointAt(0) as number; return c < 0x20 || (c >= 0x7f && c <= 0x9f); })) return null;
    return looksLikeSecret(name) ? null : name;
}

/** A scope or role name, when it may be reported. */
export function reportablePermission(v: unknown): string | null {
    return typeof v === 'string' && PERMISSION_NAME.test(v) && !looksLikeSecret(v) ? v : null;
}

const OWNER_TYPES: Readonly<Record<string, OwnerKind>> = { '#microsoft.graph.user': 'user', '#microsoft.graph.servicePrincipal': 'servicePrincipal' };

/** The owners Graph expanded, by kind and id; null when the member was not returned at all. */
function ownersOf(v: unknown): EntraIntegrationsApplication['owners'] {
    if (v === undefined) return null;
    const owners = arrayMember(v).map((o) => {
        const id = guid((o as { id?: unknown } | null)?.id);
        if (id === null) throw new SourceReadError('PAGINATION_TORN', 'an owner had no usable id');
        const type = (o as { '@odata.type'?: unknown })['@odata.type'];
        return { kind: (typeof type === 'string' ? OWNER_TYPES[type] : undefined) ?? ('other' as const), id };
    });
    if (owners.length > MAX_OWNERS_PER_APPLICATION) throw new SourceReadError('BYTE_CAP', 'an application had more owners than a report may carry');
    return owners.sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/** The credentials a service principal holds in this directory, by reference. A signing-only certificate is not one it signs in with. */
function credentialsOf(sp: Record<string, unknown>, base: string, asOf: Date): EntraIntegrationsApplication['credentials'] {
    const out: { ref: string; ageDays: number | null; expires: boolean | null }[] = [];
    const add = (raw: unknown, kind: 'password' | 'certificate') => {
        const c = raw as { keyId?: unknown; startDateTime?: unknown; endDateTime?: unknown; usage?: unknown } | null;
        const keyId = guid(c?.keyId);
        if (keyId === null) throw new SourceReadError('PAGINATION_TORN', 'a credential had no usable key id');
        if (kind === 'certificate' && c?.usage !== 'Verify') return;
        out.push({ ref: `${base}/${kind}/${keyId}`, ageDays: ageInDays(dateOrNull(c?.startDateTime), asOf), expires: dateOrNull(c?.endDateTime) !== null });
    };
    for (const c of arrayMember(sp.passwordCredentials)) add(c, 'password');
    for (const c of arrayMember(sp.keyCredentials)) add(c, 'certificate');
    if (out.length > MAX_CREDENTIALS_PER_APPLICATION) throw new SourceReadError('BYTE_CAP', 'an application had more credentials than a report may carry');
    return out.sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
}

/** Whether a verified publisher is recorded: true, false, or null when the member is not what Graph documents. */
function publisherVerifiedOf(v: unknown): boolean | null {
    if (!isJsonObject(v)) return null;
    const id = v.verifiedPublisherId;
    if (id === null || id === undefined || id === '') return false;
    return typeof id === 'string' ? true : null;
}

/** A sign-in time, to the day; null when there is none. */
function dayOf(v: unknown): string | null {
    const d = dateOrNull(v);
    return d === null ? null : d.toISOString().slice(0, 10);
}

interface Mutable {
    app: EntraIntegrationsApplication;
    /** For an application of this directory: whether its registration's owners were read. */
    registrationSeen: boolean;
    grants: Map<string, { resourceId: string; consentType: 'AllPrincipals' | 'Principal'; principals: Set<string>; scopes: Set<string>; unreadable: number }>;
}

/** The token exchange, the one the agent scanner's Entra reader makes. */
function tokenOf(ctx: SourceContext, opts: EntraIntegrationsSourceOptions, directoryId: string): Promise<string> {
    return ctx.tokens.clientCredentials({
        tokenUrl: `${AZURE_LOGIN_ORIGIN}/${directoryId}/oauth2/v2.0/token`,
        origin: AZURE_LOGIN_ORIGIN,
        clientId: opts.clientId,
        clientSecret: opts.clientSecret,
        scope: GRAPH_SCOPE,
    });
}

/** The URL of one declared read. `{id}` is the one segment a template carries. */
function urlOf(path: string, query = ''): string {
    return `${GRAPH_ORIGIN}${path}${query}`;
}

const SP_SELECT = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,verifiedPublisher,appRoles,passwordCredentials,keyCredentials';

/** What a Graph token's roles say about write access, for this source's needs. */
export function entraIntegrationsWriteObservation(token: string, readSignInActivity: boolean): WriteObservation {
    const needed = [...ENTRA_INTEGRATIONS_REQUIRED_ROLES, ...(readSignInActivity ? [ENTRA_SIGN_IN_ROLE] : [])].join(', ');
    const roles = entraTokenRoles(token);
    if (roles === null) {
        return { state: 'NOT_OBSERVABLE', verify: `the access token did not list its permissions; confirm in the app registration's API permissions that it holds ${needed} only` };
    }
    const writing = roles.filter((r) => /ReadWrite|Write|FullControl|Manage|AccessAsUser/.test(r));
    if (writing.length > 0) return { state: 'WRITE', names: writing, fix: `Remove ${writing.join(', ')}; the integrations source needs ${needed} only.` };
    return { state: 'READ_ONLY', detail: `the token holds ${roles.join(', ')}` };
}

export function entraIntegrationsSource(opts: EntraIntegrationsSourceOptions): IntegrationsSource {
    const directoryId = opts.directoryId.toLowerCase();
    const KIND = 'entra-integrations' as const;

    return {
        kind: KIND,
        product: 'entra',
        async read(ctx: SourceContext): Promise<IntegrationsSourceRead> {
            let rows = 0;
            let excluded = 0;
            const apps = new Map<string, Mutable>();
            let signIn: SignInRead = { status: 'NOT_READ' };
            let registrationsRead = false;
            // Every service principal's application id and app roles: what names a grant's resource and an assignment's role.
            const resources = new Map<string, { appId: string | null; roles: Map<string, string | null> }>();
            const grantsOf = (grants: Mutable['grants']): IntegrationsDelegatedGrant[] =>
                [...grants.values()]
                    .map((g) => ({
                        resourceAppId: resources.get(g.resourceId)?.appId ?? null,
                        consentType: g.consentType,
                        principalCount: g.consentType === 'AllPrincipals' ? null : g.principals.size,
                        scopes: [...g.scopes].sort(cmp),
                        unreadableScopes: g.unreadable,
                    }))
                    .sort((a, b) => cmp(a.resourceAppId ?? '', b.resourceAppId ?? '') || cmp(a.consentType, b.consentType));
            const finish = (stoppedBy: unknown): IntegrationsSourceRead => {
                const applications = [...apps.values()].map(({ app, grants, registrationSeen }) => ({
                    ...app,
                    // An own application whose registration was never reached has owners nobody read, unless its principal named one.
                    owners: app.origin === 'THIS_DIRECTORY' && !registrationsRead && !registrationSeen && (app.owners === null || app.owners.length === 0) ? null : app.owners,
                    delegatedGrants: { read: app.delegatedGrants.read, grants: grantsOf(grants) },
                }));
                applications.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
                const exclusion = { excluded: { count: excluded, what: ENTRA_FIRST_PARTY_EXCLUSION } };
                if (stoppedBy === null) return { kind: KIND, status: 'COMPLETE', rows, signInActivity: signIn, applications, ...exclusion };
                const err = stoppedBy instanceof SourceReadError ? stoppedBy : new SourceReadError('UNREACHABLE', 'the reader stopped on an error of its own');
                // Sign-in activity that was asked for and never reached stopped with the source.
                if (opts.readSignInActivity && signIn.status === 'NOT_READ') signIn = { status: 'INCOMPLETE', reason: err.reason, rows: 0, detail: 'the source stopped before sign-in activity was read' };
                return { kind: KIND, status: 'INCOMPLETE', reason: err.reason, detail: err.message, rows, signInActivity: signIn, applications, ...exclusion };
            };
            try {
                const token = await tokenOf(ctx, opts, directoryId);
                const headers = { Authorization: `Bearer ${token}` };
                const page = { origin: GRAPH_ORIGIN, headers, parse: graphPage };

                // 1. Every service principal: the applications, and every resource's app roles.
                const spsUrl = urlOf(
                    ENTRA_INTEGRATIONS_READ_PATHS.servicePrincipals,
                    `?$select=${encodeURIComponent(SP_SELECT)}&$expand=${encodeURIComponent('owners($select=id)')}&$top=100`,
                );
                for await (const items of readPages(ctx.http, spsUrl, page)) {
                    for (const raw of items) {
                        rows += 1;
                        if (!isJsonObject(raw)) throw new SourceReadError('PAGINATION_TORN', 'a service principal was not an object');
                        const id = guid(raw.id);
                        if (id === null) throw new SourceReadError('PAGINATION_TORN', 'a service principal had no usable id');
                        const appId = guid(raw.appId);
                        const roles = new Map<string, string | null>();
                        for (const role of arrayMember(raw.appRoles)) {
                            const roleId = guid((role as { id?: unknown } | null)?.id);
                            if (roleId !== null) roles.set(roleId, reportablePermission((role as { value?: unknown }).value));
                        }
                        resources.set(id, { appId, roles });

                        const ownerOrg = guid(raw.appOwnerOrganizationId);
                        if (raw.servicePrincipalType !== 'Application' || raw.accountEnabled === false) continue;
                        if (ownerOrg !== null && MICROSOFT_APP_OWNER_TENANTS.has(ownerOrg)) {
                            excluded += 1;
                            continue;
                        }
                        if (appId === null) throw new SourceReadError('PAGINATION_TORN', 'an application had no usable application id');
                        if (apps.size >= MAX_APPLICATIONS) throw new SourceReadError('BYTE_CAP', 'more applications than one report may carry');
                        const origin: ApplicationOrigin = ownerOrg === null ? 'UNKNOWN' : ownerOrg === directoryId ? 'THIS_DIRECTORY' : 'OTHER_DIRECTORY';
                        apps.set(id, {
                            app: {
                                id: `entra:${directoryId}:sp:${id}`,
                                sourceKind: KIND,
                                appId,
                                displayName: reportableName(raw.displayName),
                                origin,
                                publisherVerified: publisherVerifiedOf(raw.verifiedPublisher),
                                owners: ownersOf(raw.owners),
                                delegatedGrants: { read: false, grants: [] },
                                applicationPermissions: { read: false, permissions: [] },
                                signIn: { read: false, lastSeen: null },
                                credentials: credentialsOf(raw, `entra://${directoryId}/servicePrincipals/${id}`, ctx.asOf),
                            },
                            grants: new Map(),
                            registrationSeen: false,
                        });
                    }
                }

                // 1b. The registrations of this directory's own applications, for their owners.
                const own = new Map<string, Mutable[]>();
                for (const m of apps.values()) if (m.app.origin === 'THIS_DIRECTORY' && m.app.appId !== null) own.set(m.app.appId, [...(own.get(m.app.appId) ?? []), m]);
                const appsUrl = urlOf(ENTRA_INTEGRATIONS_READ_PATHS.applications, `?$select=appId&$expand=${encodeURIComponent('owners($select=id)')}&$top=100`);
                for await (const items of readPages(ctx.http, appsUrl, page)) {
                    for (const raw of items) {
                        rows += 1;
                        const appId = guid((raw as { appId?: unknown } | null)?.appId);
                        if (appId === null) throw new SourceReadError('PAGINATION_TORN', 'an application registration had no usable id');
                        const registrationOwners = ownersOf((raw as { owners?: unknown }).owners) ?? [];
                        for (const m of own.get(appId) ?? []) {
                            const merged = new Map([...(m.app.owners ?? []), ...registrationOwners].map((o) => [`${o.kind}\u0000${o.id}`, o]));
                            if (merged.size > MAX_OWNERS_PER_APPLICATION) throw new SourceReadError('BYTE_CAP', 'an application had more owners than a report may carry');
                            const owners = [...merged.values()].sort((a, b) => cmp(a.kind, b.kind) || cmp(a.id, b.id));
                            m.app = { ...m.app, owners: m.app.owners === null && registrationOwners.length === 0 ? null : owners };
                            m.registrationSeen = true;
                        }
                    }
                }
                registrationsRead = true;

                // 2. The delegated grants, every one in the directory, kept against the application they were made to.
                for await (const items of readPages(ctx.http, urlOf(ENTRA_INTEGRATIONS_READ_PATHS.delegatedGrants), page)) {
                    for (const raw of items) {
                        rows += 1;
                        const g = raw as { clientId?: unknown; resourceId?: unknown; consentType?: unknown; principalId?: unknown; scope?: unknown } | null;
                        const clientId = guid(g?.clientId);
                        const resourceId = guid(g?.resourceId);
                        const consentType = g?.consentType === 'AllPrincipals' || g?.consentType === 'Principal' ? g.consentType : null;
                        const principalId = consentType === 'Principal' ? guid(g?.principalId) : null;
                        if (clientId === null || resourceId === null || consentType === null || (consentType === 'Principal' && principalId === null)) {
                            throw new SourceReadError('PAGINATION_TORN', 'a delegated grant had no usable ids');
                        }
                        if (g?.scope !== undefined && g.scope !== null && typeof g.scope !== 'string') throw new SourceReadError('PAGINATION_TORN', 'a delegated grant had a malformed scope');
                        const target = apps.get(clientId);
                        if (target === undefined) continue;
                        const key = `${resourceId}\u0000${consentType}`;
                        const grant = target.grants.get(key) ?? { resourceId, consentType, principals: new Set<string>(), scopes: new Set<string>(), unreadable: 0 };
                        if (principalId !== null) grant.principals.add(principalId);
                        for (const token of (typeof g?.scope === 'string' ? g.scope : '').split(/\s+/).filter((t) => t !== '')) {
                            const name = reportablePermission(token);
                            if (name === null) grant.unreadable += 1;
                            else grant.scopes.add(name);
                        }
                        if (grant.scopes.size > MAX_SCOPES_PER_GRANT) throw new SourceReadError('BYTE_CAP', 'a grant held more scopes than a report may carry');
                        target.grants.set(key, grant);
                        if (target.grants.size > MAX_DELEGATED_GRANTS_PER_APPLICATION) throw new SourceReadError('BYTE_CAP', 'an application held more grants than a report may carry');
                    }
                }
                // The listing was read to its end: every application's delegated grants are whole.
                // The principal ids stay in memory to be counted, and only the count is reported.
                for (const m of apps.values()) m.app = { ...m.app, delegatedGrants: { read: true, grants: [] } };

                // 3. Each application's application permissions.
                const resourceAppIdOf = (resourceId: string) => resources.get(resourceId)?.appId ?? null;
                const queue = [...apps.keys()].sort();
                let failed: unknown = null;
                const worker = async () => {
                    for (let spId = queue.shift(); spId !== undefined && failed === null; spId = queue.shift()) {
                        const permissions = new Map<string, IntegrationsApplicationPermission>();
                        try {
                            const url = urlOf(ENTRA_INTEGRATIONS_READ_PATHS.appRoleAssignments.replace('{id}', spId));
                            for await (const items of readPages(ctx.http, url, page)) {
                                for (const raw of items) {
                                    rows += 1;
                                    const a = raw as { appRoleId?: unknown; resourceId?: unknown; principalId?: unknown } | null;
                                    const roleId = guid(a?.appRoleId);
                                    const resourceId = guid(a?.resourceId);
                                    if (roleId === null || resourceId === null) throw new SourceReadError('PAGINATION_TORN', 'an assignment had no usable ids');
                                    if (guid(a?.principalId) !== spId) throw new SourceReadError('PAGINATION_TORN', 'an assignment named another principal');
                                    if (roleId === DEFAULT_ACCESS_ROLE) continue;
                                    const resourceAppId = resourceAppIdOf(resourceId);
                                    permissions.set(`${resourceAppId ?? resourceId}\u0000${roleId}`, { resourceAppId, roleId, name: resources.get(resourceId)?.roles.get(roleId) ?? null });
                                    if (permissions.size > MAX_APPLICATION_PERMISSIONS_PER_APPLICATION) throw new SourceReadError('BYTE_CAP', 'an application held more permissions than a report may carry');
                                }
                            }
                        } catch (err) {
                            failed ??= err;
                            return;
                        }
                        const m = apps.get(spId) as Mutable;
                        const sorted = [...permissions.values()].sort((x, y) => cmp(x.resourceAppId ?? '', y.resourceAppId ?? '') || cmp(x.name ?? '', y.name ?? '') || cmp(x.roleId, y.roleId));
                        m.app = { ...m.app, applicationPermissions: { read: true, permissions: sorted } };
                    }
                };
                await Promise.all(Array.from({ length: ASSIGNMENT_CONCURRENCY }, worker));
                if (failed !== null) throw failed;

                // 4. Sign-in activity, when asked for. Its failure is its own: the inventory stays complete.
                if (opts.readSignInActivity) signIn = await readSignIns(ctx, headers, apps);
                return finish(null);
            } catch (err) {
                return finish(err);
            }
        },
        async preflight(ctx: SourceContext): Promise<readonly ProbeStep[]> {
            const log = new ProbeLog();
            const graphHost = new URL(GRAPH_ORIGIN).hostname;
            const isListing = (body: unknown) => isJsonObject(body) && Array.isArray(body.value);
            await ProbeLog.run(async () => {
                const token = await log.exchange('token', new URL(AZURE_LOGIN_ORIGIN).hostname, () => tokenOf(ctx, opts, directoryId));
                const headers = { Authorization: `Bearer ${token}` };
                const first = await log.listing('servicePrincipals', graphHost, () => ctx.http.getJson(urlOf(ENTRA_INTEGRATIONS_READ_PATHS.servicePrincipals, '?$top=1&$select=id'), { origin: GRAPH_ORIGIN, headers }), isListing);
                await log.listing('applications', graphHost, () => ctx.http.getJson(urlOf(ENTRA_INTEGRATIONS_READ_PATHS.applications, '?$top=1&$select=appId'), { origin: GRAPH_ORIGIN, headers }), isListing);
                await log.listing('oauth2PermissionGrants', graphHost, () => ctx.http.getJson(urlOf(ENTRA_INTEGRATIONS_READ_PATHS.delegatedGrants, '?$top=1'), { origin: GRAPH_ORIGIN, headers }), isListing);
                const spId = guid(((first.body as { value: unknown[] }).value[0] as { id?: unknown } | undefined)?.id);
                if (spId !== null) {
                    await log.listing(
                        'appRoleAssignments',
                        graphHost,
                        () => ctx.http.getJson(urlOf(ENTRA_INTEGRATIONS_READ_PATHS.appRoleAssignments.replace('{id}', spId), '?$top=1'), { origin: GRAPH_ORIGIN, headers }),
                        isListing,
                    );
                }
                if (opts.readSignInActivity) {
                    await log.listing('servicePrincipalSignInActivities', graphHost, () => ctx.http.getJson(urlOf(ENTRA_INTEGRATIONS_READ_PATHS.signInActivity, '?$top=1'), { origin: GRAPH_ORIGIN, headers }), isListing);
                }
                log.write(entraIntegrationsWriteObservation(token, opts.readSignInActivity));
            });
            return log.steps;
        },
    };
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The beta sign-in report, every page, and each application's last sign-in.
 * A failure here is the sign-in read's own: it is returned, never thrown, so the
 * inventory read before it stays complete. An application the report lists
 * gets its date even when a later page failed; one it does not list was read
 * only when the whole report was.
 */
async function readSignIns(ctx: SourceContext, headers: Readonly<Record<string, string>>, apps: ReadonlyMap<string, Mutable>): Promise<SignInRead> {
    let rows = 0;
    const seen = new Map<string, string | null>();
    const apply = (complete: boolean) => {
        for (const m of apps.values()) {
            const listed = m.app.appId !== null && seen.has(m.app.appId);
            if (complete || listed) m.app = { ...m.app, signIn: { read: true, lastSeen: listed ? (seen.get(m.app.appId as string) ?? null) : null } };
        }
    };
    try {
        for await (const items of readPages(ctx.http, `${GRAPH_ORIGIN}${ENTRA_INTEGRATIONS_READ_PATHS.signInActivity}`, { origin: GRAPH_ORIGIN, headers, parse: graphPage })) {
            for (const raw of items) {
                rows += 1;
                const appId = guid((raw as { appId?: unknown } | null)?.appId);
                if (appId === null) throw new SourceReadError('PAGINATION_TORN', 'a sign-in record had no usable application id');
                const last = (raw as { lastSignInActivity?: unknown }).lastSignInActivity;
                const day = isJsonObject(last) ? dayOf(last.lastSignInDateTime) : null;
                const before = seen.get(appId) ?? null;
                seen.set(appId, before === null || (day !== null && day > before) ? day : before);
            }
        }
    } catch (err) {
        apply(false);
        const e = err instanceof SourceReadError ? err : new SourceReadError('UNREACHABLE', 'the reader stopped on an error of its own');
        return { status: 'INCOMPLETE', reason: e.reason, rows, detail: e.message };
    }
    apply(true);
    return { status: 'COMPLETE', rows };
}
