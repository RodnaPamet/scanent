/**
 * Hostile responses: every network source over answers that are mutated, of
 * the wrong type, deeply nested, huge, or that point the pager somewhere else.
 * A provider's API is outside the scanner's trust: it may be wrong, it may sit
 * behind a proxy that rewrites it, and it may be compromised.
 *
 * For any answer a source is given:
 *
 *   1. `runScan` returns a signed report, or refuses to sign with
 *      `ReportRefusedLocally`. It never throws anything else.
 *   2. The source is COMPLETE, or INCOMPLETE with a reason of the contract.
 *   3. EVERY request it makes is still on the declared surface. A next link
 *      to another host, to another path on the same host, or to a URL with
 *      credentials in it is never followed.
 *   4. A listing that never ends is ended: by the page cap, the byte budget or
 *      the time box, with the reason.
 *
 * The seed and the count come from `helpers/prng.ts`.
 */
import { verifyAndParseHarnessReport, INCOMPLETE_REASONS_V2 } from '@scanent/contract/harness-contract';

import { parseScannerConfig } from '../src/config';
import type { FetchLike } from '../src/http';
import { jsonLineLog } from '../src/log';
import { rawPublicKeyHex, ReportRefusedLocally } from '../src/report';
import { loadSigningKey, runScan } from '../src/scan';
import { MAX_PAGES_PER_SOURCE } from '../src/source';
import { langSmithFixture, LANGSMITH_SELF_HOSTED, LANGSMITH_US } from './helpers/agent-harness-source-fakes';
import { SIGNING_PEM } from './helpers/doctor-world';
import { createEstateWorld, ESTATE_SOURCES, estateConfig, estateEnv, PUBLIC_RESOLVER, SELF_HOSTED_RUNTIME, type EstateSourceKind } from './helpers/estate-world';
import { forAll, FUZZ_ITERATIONS, mutateJson, randomJson, type Rng } from './helpers/prng';
import { configuredHostsOf, readOnlyProblems, recordRequests } from './helpers/request-recorder';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const quiet = jsonLineLog(() => undefined);
const PUBLIC_KEY = rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey);

const NETWORK_KINDS = (Object.keys(ESTATE_SOURCES) as EstateSourceKind[]).filter((k) => k !== 'code');
const ROWS: readonly { name: string; source: unknown }[] = [
    ...NETWORK_KINDS.map((kind) => ({ name: kind as string, source: ESTATE_SOURCES[kind] as unknown })),
    { name: 'runtime (self-hosted)', source: SELF_HOSTED_RUNTIME },
];

const worldFor = () =>
    createEstateWorld({
        fakes: { langsmith: { [LANGSMITH_US]: langSmithFixture(), [LANGSMITH_SELF_HOSTED]: { ...langSmithFixture(), selfHosted: true } } },
    });

/** Where a hostile answer points the pager. `SELF` is the request's own URL; `SIBLING` is another path on its host. */
const EVIL_LINKS = [
    'https://evil.example/collect',
    'http://169.254.169.254/latest/meta-data/',
    'https://169.254.169.254/latest/meta-data/',
    '//evil.example/x',
    'https://user:pw@evil.example/',
    'javascript:alert(1)',
    'file:///etc/passwd',
    '/relative/path?after=1',
    '',
    'SELF',
    'SIBLING',
    'SAME_ORIGIN_WITH_USERINFO',
    'SUFFIXED_HOST',
    'UPPER_SCHEME',
];

function evilLink(r: Rng, url: string): string {
    const u = new URL(url);
    const link = r.pick(EVIL_LINKS);
    if (link === 'SELF') return url;
    if (link === 'SIBLING') return `${u.origin}${r.pick(['/api/v1/apps/0oaService1/credentials/secrets', '/secrets/db-password', '/api/v1/runs/query', '/admin', `${u.pathname}/x`, '/'])}`;
    if (link === 'SAME_ORIGIN_WITH_USERINFO') return `https://a:b@${u.host}${u.pathname}`;
    if (link === 'SUFFIXED_HOST') return `https://${u.host}.evil.example${u.pathname}`;
    if (link === 'UPPER_SCHEME') return `HTTP://${u.host}${u.pathname}?after=9`;
    return link;
}

/** A wire that answers as the estate does, and then spoils the answer in one of a dozen ways. */
function hostileWire(inner: FetchLike, r: Rng, rate: number): FetchLike {
    return async (url, init) => {
        const res = await inner(url, init);
        if (!r.chance(rate)) return res;
        const text = await res.text();
        const headers = new Headers(res.headers);
        let status = res.status;
        let body: string = text;
        let parsed: unknown;
        try {
            parsed = JSON.parse(text);
        } catch {
            parsed = undefined;
        }
        switch (r.int(0, 11)) {
            case 0:
                if (parsed !== undefined) body = JSON.stringify(mutateJson(r, parsed));
                break;
            case 1:
                body = r.mutateText(text);
                break;
            case 2:
                body = JSON.stringify(randomJson(r));
                break;
            case 3:
                headers.set('content-type', r.pick(['text/html', 'text/plain', 'application/xml', 'text/event-stream', '']));
                body = r.pick(['<html><body>Sign in</body></html>', '', 'OK', text]);
                break;
            case 4:
                status = r.pick([200, 201, 202, 204, 206, 301, 302, 304, 307, 400, 401, 403, 404, 408, 409, 418, 429, 500, 502, 503, 504]);
                break;
            case 5:
                headers.set('link', `<${evilLink(r, url)}>; rel="next"`);
                break;
            case 6:
                if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
                    const link = evilLink(r, url);
                    body = JSON.stringify({ ...parsed, '@odata.nextLink': link, nextLink: link, nextPageToken: link, nextCursor: link, offset: r.pick([-1, 0, 1e9, link]) });
                }
                break;
            case 7:
                body = JSON.stringify({ value: 'x'.repeat(r.int(1, 300_000)), items: [], padding: [r.unicodeString(2_000)] });
                break;
            case 8:
                body = `{"value":[],"value":${text || 'null'},"__proto__":{"polluted":true}}`;
                break;
            case 9:
                body = `${'['.repeat(20_000)}${']'.repeat(20_000)}`;
                break;
            case 10:
                headers.set('mcp-session-id', r.unicodeString(r.int(0, 400)));
                headers.set('www-authenticate', r.unicodeString(200));
                headers.set('location', evilLink(r, url));
                break;
            default:
                body = text.slice(0, r.int(0, Math.max(0, text.length - 1)));
        }
        // A status that takes no body cannot be given one.
        const bodiless = status === 204 || status === 304;
        try {
            return new Response(bodiless ? null : body, { status, headers });
        } catch {
            // A header the platform refuses to build (a control character): the unspoiled answer.
            return new Response(bodiless ? null : body, { status });
        }
    };
}

describe.each(ROWS)('$name over hostile answers', ({ name, source }) => {
    const config = parseScannerConfig(estateConfig([source]));
    const hosts = configuredHostsOf(config);
    const kind = (source as { kind: string }).kind;

    it('signs a truthful report or refuses to sign, and never leaves the declared surface', async () => {
        await forAll(
            `hostile answers to ${name}`,
            (r) => r,
            async (r) => {
                const recorder = recordRequests(hostileWire(worldFor().fetchImpl, r, r.pick([0.15, 0.5, 1])));
                let outcome: Awaited<ReturnType<typeof runScan>>;
                try {
                    outcome = await runScan({ config, env: estateEnv(), log: quiet, fetchImpl: recorder.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
                } catch (err) {
                    if (!(err instanceof ReportRefusedLocally)) throw err;
                    const problems = readOnlyProblems(recorder.requests, hosts);
                    if (problems.length > 0) throw new Error(problems.join('; '));
                    return;
                }
                const problems = readOnlyProblems(recorder.requests, hosts);
                if (problems.length > 0) throw new Error(problems.join('; '));
                const [read] = outcome.body.population.sources;
                if (outcome.body.population.sources.length !== 1 || read.kind !== kind) throw new Error('the source is missing from the report');
                if (read.status === 'INCOMPLETE' && !(INCOMPLETE_REASONS_V2 as readonly string[]).includes(read.reason ?? '')) throw new Error(`reason ${String(read.reason)}`);
                if (read.status === 'COMPLETE' && 'reason' in read && read.reason !== undefined) throw new Error('a complete source carries a reason');
                if (!verifyAndParseHarnessReport(outcome.raw, [PUBLIC_KEY]).ok) throw new Error('the signed report does not pass its own verifier');
                // Nothing prototype-shaped came through a hostile body.
                if (({} as { polluted?: unknown }).polluted !== undefined) throw new Error('Object.prototype was polluted');
            },
            { iterations: Math.max(25, Math.floor(FUZZ_ITERATIONS / ROWS.length)) },
        );
    });
});

describe('a next link is followed only to the same listing on the same origin', () => {
    const cases: readonly { name: string; kind: EstateSourceKind; first: RegExp; spoil: (url: string, body: unknown) => { body?: unknown; link?: string } }[] = [
        { name: 'Okta, by Link header', kind: 'okta-app', first: /\/api\/v1\/apps$/, spoil: (url) => ({ link: url }) },
        { name: 'GitHub, by Link header', kind: 'cicd', first: /\/actions\/secrets$/, spoil: (url) => ({ link: url }) },
        { name: 'Graph, by @odata.nextLink', kind: 'entra-sp', first: /\/v1\.0\/applications$/, spoil: (url, body) => ({ body: { ...(body as object), '@odata.nextLink': url } }) },
        { name: 'Key Vault, by nextLink', kind: 'vault', first: /\/secrets$/, spoil: (url, body) => ({ body: { ...(body as object), nextLink: url } }) },
    ];
    const TARGETS: readonly [string, (u: URL) => string][] = [
        ['another host', () => 'https://evil.example/api/v1/apps'],
        ['a look-alike host', (u) => `https://${u.host}.evil.example${u.pathname}`],
        ['the metadata address', () => 'https://169.254.169.254/latest/meta-data/'],
        ['clear text on the same host', (u) => `http://${u.host}${u.pathname}?after=1`],
        ['the same host with credentials in the URL', (u) => `https://a:b@${u.host}${u.pathname}?after=1`],
        ['another path on the same host', (u) => `${u.origin}${u.pathname}/0oaService1/credentials/secrets`],
        ['the root of the same host', (u) => `${u.origin}/`],
        ['the page itself', (u) => u.href],
    ];

    describe.each(cases)('$name', ({ kind, first, spoil }) => {
        const config = parseScannerConfig(estateConfig([ESTATE_SOURCES[kind]]));
        const hosts = configuredHostsOf(config);

        it.each(TARGETS)('a link to %s is not followed, and the read is PAGINATION_TORN', async (_label, target) => {
            const world = worldFor();
            let spoiled = false;
            const wire: FetchLike = async (url, init) => {
                const res = await world.fetchImpl(url, init);
                const u = new URL(url);
                if (spoiled || !first.test(u.pathname) || !res.ok) return res;
                spoiled = true;
                const body: unknown = await res.json();
                const change = spoil(target(u), body);
                const headers = new Headers(res.headers);
                if (change.link !== undefined) headers.set('link', `<${change.link}>; rel="next"`);
                return new Response(JSON.stringify(change.body ?? body), { status: 200, headers });
            };
            const recorder = recordRequests(wire);
            const { body } = await runScan({ config, env: estateEnv(), log: quiet, fetchImpl: recorder.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
            expect(spoiled).toBe(true);
            expect(body.population.sources).toEqual([expect.objectContaining({ kind, status: 'INCOMPLETE', reason: 'PAGINATION_TORN' })]);
            expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
            // Nothing was asked of the link's target.
            const asked = recorder.requests.map((r) => r.url);
            expect(asked.filter((u) => u.includes('evil.example') || u.includes('169.254') || u.startsWith('http:') || u.includes('a:b@') || u.includes('credentials/secrets'))).toEqual([]);
        });
    });
});

describe('a listing that never ends is ended', () => {
    /** One second passes per request, so a time box is reachable; the page cap is reachable sooner. */
    function endless(kind: EstateSourceKind, pathname: RegExp, page: (n: number, url: URL) => { body: unknown; link?: string }) {
        const config = parseScannerConfig(estateConfig([ESTATE_SOURCES[kind]], { timeBoxSeconds: 3_600 }));
        const world = worldFor();
        let served = 0;
        let clock = NOW;
        const wire: FetchLike = async (url, init) => {
            clock += 1_000;
            const u = new URL(url);
            if (!pathname.test(u.pathname) || (init.method ?? 'GET') !== 'GET') return world.fetchImpl(url, init);
            served += 1;
            const { body, link } = page(served, u);
            return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json', ...(link === undefined ? {} : { link: `<${link}>; rel="next"` }) } });
        };
        const recorder = recordRequests(wire);
        return {
            run: async () => (await runScan({ config, env: estateEnv(), log: quiet, fetchImpl: recorder.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => clock })).body.population.sources[0],
            served: () => served,
            hosts: configuredHostsOf(config),
            recorder,
        };
    }

    it.each([
        ['Okta apps', 'okta-app', /^\/api\/v1\/apps$/, (n: number, u: URL) => ({ body: [], link: `${u.origin}${u.pathname}?limit=200&after=${n}` })],
        ['GitHub secrets', 'cicd', /\/actions\/secrets$/, (n: number, u: URL) => ({ body: { total_count: 1e9, secrets: [{ name: `S_${n}`, updated_at: '2026-01-01T00:00:00Z' }] }, link: `${u.origin}${u.pathname}?per_page=100&page=${n + 1}` })],
        ['Graph applications', 'entra-sp', /^\/v1\.0\/applications$/, (n: number, u: URL) => ({ body: { value: [], '@odata.nextLink': `${u.origin}${u.pathname}?$skiptoken=${n}` } })],
        ['Key Vault secrets', 'vault', /^\/secrets$/, (n: number, u: URL) => ({ body: { value: [], nextLink: `${u.origin}${u.pathname}?api-version=7.4&$skiptoken=${n}` } })],
        ['Google service accounts', 'gcp-sa', /\/serviceAccounts$/, (n: number) => ({ body: { accounts: [], nextPageToken: `t${n}` } })],
        ['LangSmith deployments', 'runtime', /\/v2\/deployments$/, (n: number) => ({ body: { resources: Array.from({ length: 100 }, (_, i) => ({ id: `d${n}-${i}`, tracer_session_id: null })), offset: n * 100 } })],
    ] as const)('%s: the read stops at a bound and says which', async (_label, kind, pathname, page) => {
        const e = endless(kind, pathname, page);
        const read = await e.run();
        expect(read.status).toBe('INCOMPLETE');
        expect(['BYTE_CAP', 'TIME_BOX', 'PAGINATION_TORN']).toContain(read.reason);
        expect(e.served()).toBeGreaterThan(1);
        expect(e.served()).toBeLessThanOrEqual(MAX_PAGES_PER_SOURCE + 1);
        expect(readOnlyProblems(e.recorder.requests, e.hosts)).toEqual([]);
    });

    it('an MCP server that always has another page of tools is ended too', async () => {
        const config = parseScannerConfig(estateConfig([ESTATE_SOURCES.mcp], { timeBoxSeconds: 3_600 }));
        const world = worldFor();
        let served = 0;
        let clock = NOW;
        const wire: FetchLike = async (url, init) => {
            clock += 1_000;
            const message = JSON.parse(String(init.body)) as { id?: number; method?: string };
            if (message.method !== 'tools/list') return world.fetchImpl(url, init);
            served += 1;
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { tools: [{ name: `tool_${served}`, inputSchema: { type: 'object' } }], nextCursor: `c${served}` } }), {
                status: 200,
                headers: { 'content-type': 'application/json' },
            });
        };
        const { body } = await runScan({ config, env: estateEnv(), log: quiet, fetchImpl: wire, resolveHost: PUBLIC_RESOLVER, now: () => clock });
        expect(body.population.sources[0]).toMatchObject({ kind: 'mcp', status: 'INCOMPLETE' });
        expect(['BYTE_CAP', 'TIME_BOX', 'PAGINATION_TORN']).toContain(body.population.sources[0].reason);
        expect(served).toBeLessThanOrEqual(3_700);
    });
});
