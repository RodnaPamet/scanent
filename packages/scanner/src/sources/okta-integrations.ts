/**
 * THE OKTA INTEGRATIONS SOURCE — `okta-integrations`, the integrations
 * scanner's Okta reader.
 *
 * What one Okta org has granted to the applications in it: every application
 * the org lists, and the Okta API scopes consented to each. A source kind of
 * its own beside the agent scanner's `okta-app`, read with the same kind of
 * credential (an SSWS token of a Read-only Administrator), which may be the
 * same token.
 *
 * WHAT IS READ, IN ORDER, ALL BY GET (two listings):
 *
 *   1. `/api/v1/apps?limit=200`, every page by the `Link` header's `next`
 *      (developer.okta.com, "List all applications"): each application's id,
 *      label, status and sign-on mode;
 *   2. `/api/v1/apps/{appId}/grants` for each application ("List all app
 *      grants"): the scope of each consent grant, and whether it is active.
 *      Okta documents no page size for it; a `next` link is followed when one
 *      is sent.
 *
 * OKTA'S OWN APPS ARE NOT INTEGRATIONS. Every org holds Okta's first-party
 * apps (help.okta.com, "Modify app sign-in policies for first-party apps"):
 * the Okta Admin Console, the Okta End-User Dashboard and the Okta Browser
 * Plugin. They are the platform, as Microsoft's own applications are in Entra:
 * read, counted in `rows` and in the exclusion the results show, and reported
 * as nothing. They are told apart by the app definition's `name` key
 * (`OKTA_FIRST_PARTY_APP_NAMES`), which Okta sets and an administrator cannot,
 * never by a label anybody can type.
 *
 * WHAT OKTA DOES NOT SAY, and so this does not report. The documented app
 * object has no owner, no publisher verification (nothing marks an app as an
 * Okta Integration Network one) and no time of last use; that is only in the
 * System Log, which this source does not read. Those three questions are not
 * concluded for Okta, and the planner says why (`NOT_EXPOSED_BY_PRODUCT`).
 *
 * WHAT IS NEVER KEPT: a grant's `userId` (who consented), its `clientId`,
 * `issuer` and `createdBy`, an app's `credentials`, `settings` and `profile`.
 * An app's `/credentials/secrets` is never requested.
 *
 * COMPLETENESS, as every source: a listing that stops (an error, the page cap,
 * a torn page, a 429 from Okta's rate limiter) ends the read INCOMPLETE with
 * its reason, and what was read is reported, each application saying whether
 * its grants were read in full. An application or a grant with no usable id,
 * or a grant with no scope, fails the read rather than being skipped.
 */
import {
    MAX_APPLICATIONS,
    MAX_OKTA_SCOPES_PER_APPLICATION,
    OKTA_APP_STATUSES,
    OKTA_OBJECT_ID,
    OKTA_SIGN_ON_MODES,
    type OktaIntegrationsApplication,
} from '@rodnapamet/scanent-contract/integrations-contract';

import { nextLinkFrom } from '../http';
import type { IntegrationsSource, IntegrationsSourceRead } from '../integrations-source';
import { isJsonObject, isPlainId, ProbeLog, readPages, SourceReadError, type ProbeStep, type SourceContext, type WriteObservation } from '../source';
import { reportableName, reportablePermission } from './entra-integrations';

/** The two reads, in the order they are made. `{app}` is one application's id. `scanner-surface.ts` declares them. */
export const OKTA_INTEGRATIONS_READ_PATHS = {
    apps: '/api/v1/apps',
    grants: '/api/v1/apps/{app}/grants',
} as const;

/**
 * The `name` keys of Okta's first-party apps: the Admin Console (`saasure`),
 * the End-User Dashboard (`okta_enduser`) and the Browser Plugin
 * (`okta_browser_plugin`). Okta's API reference does not list them; they are
 * the keys these three apps carry in the apps listing of every org.
 */
export const OKTA_FIRST_PARTY_APP_NAMES: ReadonlySet<string> = new Set(['saasure', 'okta_enduser', 'okta_browser_plugin']);

/** What the results say was left out, in fixed words. */
export const OKTA_FIRST_PARTY_EXCLUSION = "Okta's own apps (the Okta Admin Console, the Okta End-User Dashboard and the Okta Browser Plugin), which every org holds";

/** How many applications' grants are read at once: Okta's rate limit is per endpoint and per minute, and four stays well under it. */
export const GRANT_CONCURRENCY = 4;

const PAGE_LIMIT = '200';

export interface OktaIntegrationsSourceOptions {
    /** The org's https origin, e.g. `https://acme.okta.com`. */
    readonly orgUrl: string;
    /** The SSWS token's value, resolved from the environment by the caller. */
    readonly apiToken: string;
}

/** What the reads showed about write access: an SSWS token carries its administrator's role, which no declared read shows. */
export const OKTA_INTEGRATIONS_WRITE_OBSERVATION: WriteObservation = {
    state: 'NOT_OBSERVABLE',
    verify: "confirm in Security, Administrators that the token's user holds the Read-only Administrator role only",
};

/** A page of Okta's list API: a JSON array, and the next link from the `Link` header. */
function oktaPage(body: unknown, headers: Headers): { items: readonly unknown[]; next: string | null } | null {
    if (!Array.isArray(body)) return null;
    return { items: body, next: nextLinkFrom(headers.get('link')) };
}

const oneOf = <T extends string>(list: readonly T[], v: unknown): T | null => (typeof v === 'string' && (list as readonly string[]).includes(v) ? (v as T) : null);

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

interface Mutable {
    app: OktaIntegrationsApplication;
    readonly scopes: Set<string>;
    unreadable: number;
}

export function oktaIntegrationsSource(opts: OktaIntegrationsSourceOptions): IntegrationsSource {
    const origin = new URL(opts.orgUrl).origin;
    const host = new URL(opts.orgUrl).hostname.toLowerCase();
    const headers = { Authorization: `SSWS ${opts.apiToken}` };
    const KIND = 'okta-integrations' as const;
    const page = { origin, headers, parse: oktaPage };

    return {
        kind: KIND,
        product: 'okta',
        async read(ctx: SourceContext): Promise<IntegrationsSourceRead> {
            let rows = 0;
            let excluded = 0;
            const apps = new Map<string, Mutable>();
            const finish = (stoppedBy: unknown): IntegrationsSourceRead => {
                const applications = [...apps.values()]
                    .map(({ app, scopes, unreadable }) => ({ ...app, scopeGrants: { read: app.scopeGrants.read, scopes: [...scopes].sort(cmp), unreadableScopes: unreadable } }))
                    .sort((a, b) => cmp(a.id, b.id));
                const exclusion = { excluded: { count: excluded, what: OKTA_FIRST_PARTY_EXCLUSION } };
                if (stoppedBy === null) return { kind: KIND, status: 'COMPLETE', rows, signInActivity: { status: 'NOT_READ' }, applications, ...exclusion };
                const err = stoppedBy instanceof SourceReadError ? stoppedBy : new SourceReadError('UNREACHABLE', 'the reader stopped on an error of its own');
                return { kind: KIND, status: 'INCOMPLETE', reason: err.reason, detail: err.message, rows, signInActivity: { status: 'NOT_READ' }, applications, ...exclusion };
            };
            try {
                // 1. Every application the org lists.
                for await (const items of readPages(ctx.http, `${origin}${OKTA_INTEGRATIONS_READ_PATHS.apps}?limit=${PAGE_LIMIT}`, page)) {
                    for (const raw of items) {
                        rows += 1;
                        if (!isJsonObject(raw)) throw new SourceReadError('PAGINATION_TORN', 'an application was not an object');
                        const id = raw.id;
                        if (typeof id !== 'string' || !OKTA_OBJECT_ID.test(id)) throw new SourceReadError('PAGINATION_TORN', 'an application had no usable id');
                        if (apps.has(id)) throw new SourceReadError('PAGINATION_TORN', 'an application was listed twice');
                        // A deleted application is not one the org holds; Okta does not list it by default.
                        if (raw.status === 'DELETED') continue;
                        // Okta's own apps are the platform, not an integration: counted, and left out.
                        if (typeof raw.name === 'string' && OKTA_FIRST_PARTY_APP_NAMES.has(raw.name)) {
                            excluded += 1;
                            continue;
                        }
                        if (apps.size >= MAX_APPLICATIONS) throw new SourceReadError('BYTE_CAP', 'more applications than one report may carry');
                        apps.set(id, {
                            app: {
                                id: `okta:${host}:app:${id}`,
                                sourceKind: KIND,
                                appId: id,
                                displayName: reportableName(raw.label),
                                status: oneOf(OKTA_APP_STATUSES, raw.status),
                                signOnMode: oneOf(OKTA_SIGN_ON_MODES, raw.signOnMode),
                                scopeGrants: { read: false, scopes: [], unreadableScopes: 0 },
                            },
                            scopes: new Set(),
                            unreadable: 0,
                        });
                    }
                }

                // 2. Each application's consent grants.
                const queue = [...apps.keys()].sort(cmp);
                let failed: unknown = null;
                const worker = async () => {
                    for (let id = queue.shift(); id !== undefined && failed === null; id = queue.shift()) {
                        const m = apps.get(id) as Mutable;
                        try {
                            const url = `${origin}${OKTA_INTEGRATIONS_READ_PATHS.grants.replace('{app}', encodeURIComponent(id))}`;
                            for await (const items of readPages(ctx.http, url, page)) {
                                for (const raw of items) {
                                    rows += 1;
                                    const g = isJsonObject(raw) ? raw : null;
                                    if (g === null || !isPlainId(g.id)) throw new SourceReadError('PAGINATION_TORN', 'a grant had no usable id');
                                    if (typeof g.scopeId !== 'string' || g.scopeId === '') throw new SourceReadError('PAGINATION_TORN', 'a grant had no scope');
                                    // A revoked consent is not a grant the application holds.
                                    if (g.status === 'REVOKED') continue;
                                    const scope = reportablePermission(g.scopeId);
                                    if (scope === null) m.unreadable += 1;
                                    else m.scopes.add(scope);
                                    if (m.scopes.size > MAX_OKTA_SCOPES_PER_APPLICATION) throw new SourceReadError('BYTE_CAP', 'an application held more scopes than a report may carry');
                                }
                            }
                        } catch (err) {
                            failed ??= err;
                            return;
                        }
                        m.app = { ...m.app, scopeGrants: { ...m.app.scopeGrants, read: true } };
                    }
                };
                await Promise.all(Array.from({ length: GRANT_CONCURRENCY }, worker));
                if (failed !== null) throw failed;
                return finish(null);
            } catch (err) {
                return finish(err);
            }
        },
        async preflight(ctx: SourceContext): Promise<readonly ProbeStep[]> {
            const log = new ProbeLog();
            const hostname = new URL(origin).hostname;
            await ProbeLog.run(async () => {
                const first = await log.listing('applications', hostname, () => ctx.http.getJson(`${origin}${OKTA_INTEGRATIONS_READ_PATHS.apps}?limit=1`, { origin, headers }), Array.isArray);
                const id = ((first.body as unknown[])[0] as { id?: unknown } | undefined)?.id;
                if (typeof id === 'string' && OKTA_OBJECT_ID.test(id)) {
                    await log.listing(
                        'application grants',
                        hostname,
                        () => ctx.http.getJson(`${origin}${OKTA_INTEGRATIONS_READ_PATHS.grants.replace('{app}', encodeURIComponent(id))}`, { origin, headers }),
                        Array.isArray,
                    );
                }
                log.write(OKTA_INTEGRATIONS_WRITE_OBSERVATION);
            });
            return log.steps;
        },
    };
}
