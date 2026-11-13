/**
 * THE GITHUB INTEGRATIONS SOURCE — `github-integrations`, the integrations
 * scanner's GitHub reader.
 *
 * What one GitHub organisation has granted to the apps installed on it, and
 * where it sends its events. A source kind of its own beside the agent
 * scanner's `cicd`, on the same host with its own token: these two endpoints
 * are the organisation's, and `cicd`'s token is scoped to repositories.
 *
 * WHAT IS READ, IN ORDER, ALL BY GET (two listings):
 *
 *   1. `/orgs/{org}/installations?per_page=100` (docs.github.com, "List app
 *      installations for an organization"): each installation's app id and
 *      slug, its permissions map, its repository selection, its events and
 *      whether it is suspended. Paged by the `Link` header; the `total_count`
 *      every page declares must not change and must equal what was read.
 *   2. `/orgs/{org}/hooks?per_page=100` ("List organization webhooks"): each
 *      webhook's events, whether it is active and when it was created, and
 *      the HOST of its target.
 *
 * A WEBHOOK'S URL NEVER LEAVES THIS FILE. `config.url` is reduced to its host
 * where the response is read (`webhookHost`), and nothing else of it, its
 * path, its query, or `config.secret` (which GitHub masks, and which is read
 * no further), is kept, logged or reported. A URL that cannot be reduced to a
 * host the contract may carry is reported as a null host.
 *
 * WHAT GITHUB DOES NOT SAY, and so this does not report. The installation
 * response names no owner of the installation, no publisher verification of
 * the app and no time of last use. Those three are not concluded for GitHub,
 * and the planner says why (`NOT_EXPOSED_BY_PRODUCT`).
 *
 * COMPLETENESS, as every source. A 403 or 429 that GitHub marks as a rate
 * limit (`x-ratelimit-remaining: 0`, or `retry-after`) is RATE_LIMITED; any
 * other 403 is AUTH_FAILED; both end the read INCOMPLETE, keeping what was
 * read. An installation or a webhook with no usable id fails the read.
 *
 * THE TOKEN. Both endpoints take an organisation owner's token: a
 * fine-grained token whose resource owner is the organisation, with the
 * organisation permissions Administration: Read-only (installations) and
 * Webhooks: Read-only (hooks), and nothing else.
 */
import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract';
import {
    EVENT_NAME,
    GITHUB_APP_SLUG,
    GITHUB_ORGANIZATION,
    GITHUB_PERMISSION_LEVELS,
    ISO_DATE,
    MAX_APPLICATIONS,
    MAX_EVENTS,
    MAX_GITHUB_PERMISSIONS_PER_INSTALLATION,
    MAX_WEBHOOKS,
    REPOSITORY_SELECTIONS,
    WEBHOOK_HOST,
    type GitHubInstallation,
    type IntegrationsWebhook,
} from '@rodnapamet/scanent-contract/integrations-contract';

import { nextLinkFrom } from '../http';
import type { IntegrationsSource, IntegrationsSourceRead } from '../integrations-source';
import { isJsonObject, ProbeLog, readPages, SourceReadError, type ProbeStep, type SourceContext, type WriteObservation } from '../source';
import { reportablePermission } from './entra-integrations';
import { GITHUB_API_ORIGIN, SCOPE_NAME, WRITING_SCOPE } from './github-actions';

/** The two reads. `{org}` is the organisation's login. `scanner-surface.ts` declares them. */
export const GITHUB_INTEGRATIONS_READ_PATHS = {
    installations: '/orgs/{org}/installations',
    hooks: '/orgs/{org}/hooks',
} as const;

export interface GitHubIntegrationsSourceOptions {
    /** The organisation's login. */
    readonly organization: string;
    /** A fine-grained token holding organisation Administration: read and Webhooks: read, resolved by the caller. */
    readonly token: string;
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

const positiveId = (v: unknown): number | null => (typeof v === 'number' && Number.isSafeInteger(v) && v > 0 ? v : null);

/**
 * A webhook target's HOST, or null. The URL is parsed here and only its host
 * is returned; the caller never holds the URL in anything it keeps. Only an
 * http or https URL has a host the contract takes, and a host with a secret's
 * shape is withheld like any other value.
 */
export function webhookHost(url: unknown): string | null {
    if (typeof url !== 'string') return null;
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return null;
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
    const host = parsed.hostname.toLowerCase();
    return WEBHOOK_HOST.test(host) && !looksLikeSecret(host) ? host : null;
}

/** An event list as GitHub writes it: each name once, those that are not an event's shape dropped. Any other shape tears the page. */
function eventsOf(v: unknown): string[] {
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v)) throw new SourceReadError('PAGINATION_TORN', 'a listed object had a malformed event list');
    const events = [...new Set(v.filter((e): e is string => typeof e === 'string' && EVENT_NAME.test(e)))].sort(cmp);
    if (events.length > MAX_EVENTS) throw new SourceReadError('BYTE_CAP', 'more events than a report may carry');
    return events;
}

/** A day, `YYYY-MM-DD`, from an ISO time; null when there is none. */
function dayOf(v: unknown): string | null {
    if (typeof v !== 'string') return null;
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return null;
    const day = d.toISOString().slice(0, 10);
    return ISO_DATE.test(day) ? day : null;
}

/** An installation's permissions map: each name and level GitHub writes, the rest counted. Read false when there is no map. */
function permissionsOf(v: unknown): GitHubInstallation['permissions'] {
    if (!isJsonObject(v)) return { read: false, grants: [], unreadable: 0 };
    const grants: { name: string; level: (typeof GITHUB_PERMISSION_LEVELS)[number] }[] = [];
    let unreadable = 0;
    for (const [rawName, rawLevel] of Object.entries(v)) {
        const name = reportablePermission(rawName);
        const level = typeof rawLevel === 'string' && (GITHUB_PERMISSION_LEVELS as readonly string[]).includes(rawLevel) ? (rawLevel as (typeof GITHUB_PERMISSION_LEVELS)[number]) : null;
        if (name === null || level === null) unreadable += 1;
        else grants.push({ name, level });
    }
    if (grants.length > MAX_GITHUB_PERMISSIONS_PER_INSTALLATION) throw new SourceReadError('BYTE_CAP', 'an installation held more permissions than a report may carry');
    return { read: true, grants: grants.sort((a, b) => cmp(a.name, b.name)), unreadable };
}

/**
 * The installations listing's pages, `{ total_count, installations }`, and the
 * count every page declared. A count that changes between pages is a listing
 * that changed under the read.
 */
function installationsListing(): {
    readonly parse: (body: unknown, headers: Headers) => { items: readonly unknown[]; next: string | null } | null;
    readonly total: () => number | null;
} {
    let total: number | null = null;
    return {
        parse(body, headers) {
            if (!isJsonObject(body) || !Array.isArray(body.installations) || typeof body.total_count !== 'number') return null;
            if (total !== null && total !== body.total_count) throw new SourceReadError('PAGINATION_TORN', 'the installation count changed while it was read');
            total = body.total_count;
            return { items: body.installations, next: nextLinkFrom(headers.get('link')) };
        },
        total: () => total,
    };
}

/** A page of the webhooks listing: a JSON array, and the next link. */
function hooksPage(body: unknown, headers: Headers): { items: readonly unknown[]; next: string | null } | null {
    if (!Array.isArray(body)) return null;
    return { items: body, next: nextLinkFrom(headers.get('link')) };
}

/**
 * What GitHub's `X-OAuth-Scopes` header says about write access. Sent for a
 * classic token only. A classic token cannot list an organisation's webhooks
 * without `admin:org_hook`, which can also change them, so a classic token is
 * never read-only for this source.
 */
export function githubIntegrationsWriteObservation(scopesHeader: string | null): WriteObservation {
    if (scopesHeader === null) {
        return {
            state: 'NOT_OBSERVABLE',
            verify: "the token is not a classic token, so GitHub does not list its permissions; confirm in the token's settings that it holds the organisation permissions Administration: Read-only and Webhooks: Read-only and nothing else",
        };
    }
    const scopes = [...new Set(scopesHeader.split(',').map((s) => s.trim()).filter((s) => s !== ''))].sort();
    if (!scopes.every((s) => SCOPE_NAME.test(s))) {
        return { state: 'NOT_OBSERVABLE', verify: "GitHub's list of the token's scopes could not be read; confirm the token's permissions in its settings" };
    }
    const writing = scopes.filter((s) => WRITING_SCOPE.test(s));
    if (writing.length > 0) {
        return {
            state: 'WRITE',
            names: writing,
            fix: 'Replace the classic token with a fine-grained token whose resource owner is the organisation, holding Administration: Read-only and Webhooks: Read-only.',
        };
    }
    return { state: 'READ_ONLY', detail: scopes.length === 0 ? 'a classic token with no scope' : `a classic token holding ${scopes.join(', ')}` };
}

export function githubIntegrationsSource(opts: GitHubIntegrationsSourceOptions): IntegrationsSource {
    const org = opts.organization.toLowerCase();
    const headers = {
        Authorization: `Bearer ${opts.token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'inflect-agent-harness-scanner',
    };
    const origin = GITHUB_API_ORIGIN;
    const KIND = 'github-integrations' as const;
    const pathOf = (template: string) => `${origin}${template.replace('{org}', encodeURIComponent(org))}`;

    return {
        kind: KIND,
        product: 'github',
        async read(ctx: SourceContext): Promise<IntegrationsSourceRead> {
            let rows = 0;
            const applications: GitHubInstallation[] = [];
            const hooks: IntegrationsWebhook[] = [];
            let hooksRead = false;
            const finish = (stoppedBy: unknown): IntegrationsSourceRead => {
                const sorted = [...applications].sort((a, b) => cmp(a.id, b.id));
                const webhooks = { read: hooksRead, hooks: [...hooks].sort((a, b) => cmp(a.id, b.id)) };
                if (stoppedBy === null) return { kind: KIND, status: 'COMPLETE', rows, signInActivity: { status: 'NOT_READ' }, applications: sorted, webhooks };
                const err = stoppedBy instanceof SourceReadError ? stoppedBy : new SourceReadError('UNREACHABLE', 'the reader stopped on an error of its own');
                return { kind: KIND, status: 'INCOMPLETE', reason: err.reason, detail: err.message, rows, signInActivity: { status: 'NOT_READ' }, applications: sorted, webhooks };
            };
            try {
                if (!GITHUB_ORGANIZATION.test(org)) throw new SourceReadError('UNPARSEABLE', 'an organisation that is not a GitHub login');

                // 1. The organisation's app installations.
                const seen = new Set<number>();
                const listing = installationsListing();
                for await (const items of readPages(ctx.http, `${pathOf(GITHUB_INTEGRATIONS_READ_PATHS.installations)}?per_page=100`, { origin, headers, parse: listing.parse })) {
                    for (const raw of items) {
                        rows += 1;
                        if (!isJsonObject(raw)) throw new SourceReadError('PAGINATION_TORN', 'an installation was not an object');
                        const id = positiveId(raw.id);
                        if (id === null || seen.has(id)) throw new SourceReadError('PAGINATION_TORN', 'an installation had no usable id, or one seen twice');
                        seen.add(id);
                        if (applications.length >= MAX_APPLICATIONS) throw new SourceReadError('BYTE_CAP', 'more applications than one report may carry');
                        const slug = typeof raw.app_slug === 'string' && GITHUB_APP_SLUG.test(raw.app_slug) ? raw.app_slug : null;
                        const selection = typeof raw.repository_selection === 'string' && (REPOSITORY_SELECTIONS as readonly string[]).includes(raw.repository_selection)
                            ? (raw.repository_selection as (typeof REPOSITORY_SELECTIONS)[number])
                            : null;
                        applications.push({
                            id: `github:${org}:installation:${id}`,
                            sourceKind: KIND,
                            appId: positiveId(raw.app_id),
                            appSlug: slug,
                            repositorySelection: selection,
                            // `suspended_at` is a time when suspended and null when not; absent, it says neither.
                            suspended: raw.suspended_at === null ? false : typeof raw.suspended_at === 'string' ? true : null,
                            events: eventsOf(raw.events),
                            permissions: permissionsOf(raw.permissions),
                        });
                    }
                }
                // Every installation the listing counted, read: a short listing is one whose missing installations would read as absent.
                if (listing.total() !== applications.length) throw new SourceReadError('PAGINATION_TORN', 'the installation listing held a different number than it counted');

                // 2. The organisation's webhooks, by host.
                const hookIds = new Set<number>();
                for await (const items of readPages(ctx.http, `${pathOf(GITHUB_INTEGRATIONS_READ_PATHS.hooks)}?per_page=100`, { origin, headers, parse: hooksPage })) {
                    for (const raw of items) {
                        rows += 1;
                        if (!isJsonObject(raw)) throw new SourceReadError('PAGINATION_TORN', 'a webhook was not an object');
                        const id = positiveId(raw.id);
                        if (id === null || hookIds.has(id)) throw new SourceReadError('PAGINATION_TORN', 'a webhook had no usable id, or one seen twice');
                        hookIds.add(id);
                        if (hooks.length >= MAX_WEBHOOKS) throw new SourceReadError('BYTE_CAP', 'more webhooks than one report may carry');
                        hooks.push({
                            id: `github:${org}:hook:${id}`,
                            sourceKind: KIND,
                            // The URL is reduced to its host here, and goes no further.
                            host: webhookHost(isJsonObject(raw.config) ? raw.config.url : undefined),
                            events: eventsOf(raw.events),
                            active: typeof raw.active === 'boolean' ? raw.active : null,
                            created: dayOf(raw.created_at),
                        });
                    }
                }
                hooksRead = true;
                return finish(null);
            } catch (err) {
                return finish(err);
            }
        },
        async preflight(ctx: SourceContext): Promise<readonly ProbeStep[]> {
            const log = new ProbeLog();
            const hostname = new URL(origin).hostname;
            await ProbeLog.run(async () => {
                const first = await log.listing(
                    'app installations',
                    hostname,
                    async () => {
                        if (!GITHUB_ORGANIZATION.test(org)) throw new SourceReadError('UNPARSEABLE', 'an organisation that is not a GitHub login');
                        return ctx.http.getJson(`${pathOf(GITHUB_INTEGRATIONS_READ_PATHS.installations)}?per_page=1`, { origin, headers });
                    },
                    (body) => isJsonObject(body) && Array.isArray(body.installations),
                );
                await log.listing('webhooks', hostname, () => ctx.http.getJson(`${pathOf(GITHUB_INTEGRATIONS_READ_PATHS.hooks)}?per_page=1`, { origin, headers }), Array.isArray);
                log.write(githubIntegrationsWriteObservation(first.headers.get('x-oauth-scopes')));
            });
            return log.steps;
        },
    };
}
