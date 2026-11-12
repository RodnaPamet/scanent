/**
 * THE PARTIAL-FAILURE MATRIX: every network source against every way a read
 * can go wrong.
 *
 * Rows are the source kinds. Columns are failures injected into the fake
 * estate: a refused connection, an answer that never comes, a refused
 * credential, a rate limit, a server error, an answer that is not the API's,
 * a second page that fails after a good first one, an answer over the size
 * cap, and a token exchange that fails. One more row takes every source down
 * at once.
 *
 * For every cell, with every other source of the estate healthy:
 *
 *   1. the source is INCOMPLETE in the signed report, with the reason the
 *      table names, and the report still passes its verifier;
 *   2. every other source is COMPLETE: one source's failure costs no other
 *      source its read;
 *   3. `results.json` states no level for an agent found through the failed
 *      source;
 *   4. compared with a clean earlier run, nothing is closed, resolved or gone,
 *      and the diff is not "the same";
 *   5. `summary.html` says the scan is incomplete at the top, lists the source
 *      as not read in its first section, and holds none of the words it uses
 *      for a clean result;
 *   6. `scan --strict` exits 3 (once per row, through the command line).
 *
 * The reason for an answer that is not the API's is the one the wire gives
 * today, pinned per source in `NOT_THE_API`: a change to it is a change to
 * what an operator reads, and should be made on purpose.
 */
import * as dns from 'dns';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import { diffResults } from '@scanent/report/diff/diff';
import { renderDiffText } from '@scanent/report/render/diff-text';
import { renderSummaryHtml } from '@scanent/report/render/html';
import { LocalResultsSchema } from '@scanent/report/results/schema';
import type { LocalResults } from '@scanent/report/results/types';

import { main } from '../src/cli';
import { parseScannerConfig } from '../src/config';
import { EXIT } from '../src/exit-codes';
import { hostsFor } from '../src/hosts';
import { createSourceWire, MAX_RESPONSE_BYTES, MAX_SOURCE_BYTES, type FetchLike } from '../src/http';
import { scoreScanLocally } from '../src/local-results';
import { rawPublicKeyHex } from '../src/report';
import { loadSigningKey, runScan } from '../src/scan';
import type { IncompleteReason, SourceRead } from '../src/source';
import { entraSource } from '../src/sources/entra';
import { inflectRegisterSource } from '../src/sources/inflect-register';
import { mcpSource } from '../src/sources/mcp';
import { oktaSource } from '../src/sources/okta';
import {
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET_VALUE,
    createSourceFakes,
    ENTRA_DIRECTORY_ID,
    INGEST,
    langSmithFixture,
    LANGSMITH_US,
    MCP_CRM,
    OKTA_ORG,
    OKTA_TOKEN_VALUE,
} from './helpers/agent-harness-source-fakes';
import { SIGNING_PEM } from './helpers/doctor-world';
import {
    createEstateWorld,
    ESTATE_SOURCE_KINDS,
    ESTATE_SOURCES,
    estateConfig,
    estateEnv,
    PUBLIC_RESOLVER,
    type EstateSourceKind,
    type EstateWorld,
    type WorldAnswer,
    type WorldRequest,
} from './helpers/estate-world';
import { capturedLog } from './helpers/output-fixtures';

// A slow runner must not fail a test that is only slow.
jest.setTimeout(60_000);

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const PUBLIC_KEY = rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey);
const SOURCES = ESTATE_SOURCE_KINDS.map((kind) => ESTATE_SOURCES[kind]);
const CONFIG = parseScannerConfig(estateConfig(SOURCES));
const NETWORK_KINDS = ESTATE_SOURCE_KINDS.filter((k) => k !== 'code');

const worldFor = (): EstateWorld => createEstateWorld({ fakes: { langsmith: { [LANGSMITH_US]: langSmithFixture() } } });

/** The hosts one kind reads from, and the hosts it exchanges a token at. */
function hostsOf(kind: EstateSourceKind): { read: string[]; token: string[] } {
    const entries = hostsFor(CONFIG).filter((h) => h.source === kind);
    return { read: entries.filter((h) => h.purpose === 'read').map((h) => h.host), token: entries.filter((h) => h.purpose === 'token').map((h) => h.host) };
}

/** Which request of a kind is its read rather than its exchange. The register's two are on one host, told apart by path. */
function isReadOf(kind: EstateSourceKind, req: WorldRequest): boolean {
    if (!hostsOf(kind).read.includes(req.host)) return false;
    if (kind === 'inflect-register') return req.path === '/api/mcp';
    return true;
}
function isExchangeOf(kind: EstateSourceKind, req: WorldRequest): boolean {
    if (kind === 'inflect-register') return req.host === 'inflect.example.com' && req.path === '/api/mcp/token';
    if (!hostsOf(kind).token.includes(req.host)) return false;
    // Entra and Key Vault exchange at the same host, each under its own directory.
    if (kind === 'entra-sp') return req.path.startsWith('/0d1e2c3b-');
    if (kind === 'vault') return req.path.startsWith('/contoso.onmicrosoft.com/');
    return true;
}

interface Failure {
    readonly name: string;
    /** The answer to a read of the failing kind; `nth` counts that kind's reads from 1. */
    readonly answer: (req: WorldRequest, nth: number) => WorldAnswer;
    /** The reason expected, or a function of the kind where it differs. */
    readonly reason: IncompleteReason | ((kind: EstateSourceKind) => IncompleteReason);
    /** True when the failure is of the exchange, not the read. */
    readonly atExchange?: true;
    /** Kinds this failure applies to; absent, every network kind. */
    readonly only?: readonly EstateSourceKind[];
}

/**
 * What each source reports for a 200 that is not its API's answer. Sources
 * that read JSON listings call it a torn listing. Pinned, not derived.
 */
const NOT_THE_API: Readonly<Record<EstateSourceKind, IncompleteReason>> = {
    'entra-sp': 'PAGINATION_TORN',
    'okta-app': 'PAGINATION_TORN',
    vault: 'PAGINATION_TORN',
    cicd: 'PAGINATION_TORN',
    'gcp-sa': 'PAGINATION_TORN',
    runtime: 'PAGINATION_TORN',
    mcp: 'PAGINATION_TORN',
    code: 'UNPARSEABLE',
    'inflect-register': 'PAGINATION_TORN',
};
const notTheApi = (kind: EstateSourceKind): IncompleteReason => NOT_THE_API[kind];

const status = (code: number, headers: Record<string, string> = {}): WorldAnswer => ({ status: code, body: { error: 'refused' }, headers });
const HAS_EXCHANGE: readonly EstateSourceKind[] = ['entra-sp', 'vault', 'gcp-sa', 'inflect-register'];

const FAILURES: readonly Failure[] = [
    { name: 'a refused connection', answer: () => 'throw', reason: 'UNREACHABLE' },
    { name: 'an answer that never comes', answer: () => 'timeout', reason: 'TIME_BOX' },
    { name: 'HTTP 401', answer: () => status(401), reason: 'AUTH_FAILED' },
    { name: 'HTTP 403', answer: () => status(403), reason: 'AUTH_FAILED' },
    { name: 'HTTP 429', answer: () => status(429), reason: 'RATE_LIMITED' },
    { name: 'HTTP 429 with Retry-After', answer: () => status(429, { 'retry-after': '120' }), reason: 'RATE_LIMITED' },
    { name: 'HTTP 500', answer: () => status(500), reason: 'UNREACHABLE' },
    { name: 'HTTP 502', answer: () => status(502), reason: 'UNREACHABLE' },
    { name: 'HTTP 503', answer: () => status(503, { 'retry-after': '30' }), reason: 'UNREACHABLE' },
    { name: 'a body cut in the middle of its JSON', answer: () => ({ status: 200, raw: '{"value":[{"id":"a0000001-0000-4000-80' }), reason: notTheApi },
    { name: 'a 200 with the wrong content type', answer: () => ({ status: 200, raw: 'OK', headers: { 'content-type': 'text/plain' } }), reason: notTheApi },
    { name: 'a 200 that is an HTML error page', answer: () => ({ status: 200, raw: '<!doctype html><html><body><h1>Sign in</h1></body></html>', headers: { 'content-type': 'text/html' } }), reason: notTheApi },
    { name: 'a 200 that is JSON and not the listing', answer: () => ({ status: 200, body: { message: 'welcome' } }), reason: notTheApi },
    { name: 'a response that declares more than the size cap', answer: () => ({ status: 200, body: {}, headers: { 'content-length': String(MAX_RESPONSE_BYTES + 1) } }), reason: 'BYTE_CAP' },
    { name: 'a response that is larger than the size cap', answer: () => ({ status: 200, raw: `{"padding":"${'x'.repeat(MAX_RESPONSE_BYTES)}"}` }), reason: 'BYTE_CAP', only: ['okta-app', 'mcp'] },
    { name: 'a second request that is refused after a good first one', answer: (_req, nth) => (nth >= 2 ? 'throw' : undefined), reason: 'UNREACHABLE' },
    { name: 'a second request that never answers after a good first one', answer: (_req, nth) => (nth >= 2 ? 'timeout' : undefined), reason: 'TIME_BOX' },
    { name: 'a token exchange that is refused', answer: () => status(401), reason: 'AUTH_FAILED', atExchange: true, only: HAS_EXCHANGE },
    { name: 'a token exchange that answers 400', answer: () => status(400), reason: 'AUTH_FAILED', atExchange: true, only: HAS_EXCHANGE },
    { name: 'a token exchange that hands back no token', answer: () => ({ status: 200, body: { token_type: 'Bearer' } }), reason: 'AUTH_FAILED', atExchange: true, only: HAS_EXCHANGE },
];

let base: string;
let clean: { results: LocalResults; agentsVia: Record<string, string[]> };

async function scanWith(world: EstateWorld, now = NOW) {
    const logged = capturedLog();
    const scan = await runScan({ config: CONFIG, env: estateEnv(), log: logged.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => now });
    const results = scoreScanLocally({ config: CONFIG, raw: scan.raw, body: scan.body, inventory: null });
    return { ...scan, results, logged };
}

beforeAll(async () => {
    base = mkdtempSync(join(tmpdir(), 'scanent-matrix-'));
    // The earlier, clean run every cell is compared with.
    const { results, body } = await scanWith(worldFor(), NOW - 86_400_000);
    expect(body.population.sources.every((s) => s.status === 'COMPLETE')).toBe(true);
    const agentsVia: Record<string, string[]> = {};
    for (const agent of body.agents) for (const via of agent.discoveredVia) (agentsVia[via] ??= []).push(agent.discoveredId);
    clean = { results, agentsVia };
});
afterAll(() => {
    jest.restoreAllMocks();
    rmSync(base, { recursive: true, force: true });
});

/** The words `summary.html` uses only for a result with nothing missing. */
const CLEAN_WORDS = ['<strong>Complete.</strong>', 'Every listed source was read in full', 'Every source this scan lists was read in full', 'None: every agent this scan found is registered.'];

describe.each(NETWORK_KINDS)('%s', (kind) => {
    const applicable = FAILURES.filter((f) => f.only === undefined || f.only.includes(kind));

    it.each(applicable.map((f) => [f.name, f] as const))('%s', async (_name, failure) => {
        const world = worldFor();
        let nth = 0;
        world.inject = (req) => {
            const hit = failure.atExchange === true ? isExchangeOf(kind, req) : isReadOf(kind, req);
            if (!hit) return undefined;
            nth += 1;
            return failure.answer(req, nth);
        };
        const { raw, body, results, logged } = await scanWith(world);
        const expected = typeof failure.reason === 'function' ? failure.reason(kind) : failure.reason;
        expect(nth).toBeGreaterThan(0);

        // 1. The source is INCOMPLETE with the reason, in a report that verifies and is not complete.
        const source = body.population.sources.find((s) => s.kind === kind);
        expect(source).toMatchObject({ kind, status: 'INCOMPLETE', reason: expected });
        expect(verifyAndParseHarnessReport(raw, [PUBLIC_KEY])).toMatchObject({ ok: true, complete: false });
        expect(body.findings).toEqual([expect.objectContaining({ code: 'INCOMPLETE_SOURCE', evidence: `source:${kind}#${expected}` })]);
        expect(logged.lines().filter((l) => l.msg === 'source incomplete')).toEqual([expect.objectContaining({ source: kind, reason: expected })]);

        // 2. Every other source was read in full.
        expect(body.population.sources.filter((s) => s.kind !== kind).map((s) => s.status)).toEqual(Array.from({ length: SOURCES.length - 1 }, () => 'COMPLETE'));
        for (const other of ESTATE_SOURCE_KINDS.filter((k) => k !== kind)) {
            for (const id of clean.agentsVia[other] ?? []) {
                // An agent another source found is still in the report, unless only the failed source's merge put it there.
                if (!(clean.agentsVia[kind] ?? []).includes(id) || body.agents.some((a) => a.discoveredId === id)) {
                    expect(body.agents.map((a) => a.discoveredId)).toContain(id);
                }
            }
        }

        // 3. No level is stated for an agent found through the failed source; the results pass their schema.
        expect(LocalResultsSchema.safeParse(JSON.parse(JSON.stringify(results))).success).toBe(true);
        expect(results.scan.complete).toBe(false);
        for (const agent of results.agents.filter((a) => a.discoveredVia.includes(kind as never))) {
            expect(agent.judgement.state).toBe('NOT_JUDGED');
            expect(agent.judgement).not.toHaveProperty('level');
        }
        // The register reports on agents other sources find: without it nobody is judged.
        if (kind === 'inflect-register') expect(results.estate.judgedCount).toBe(0);

        // 4. Against the clean earlier run: nothing closed, nothing gone, and not "the same".
        const diff = diffResults(clean.results, results);
        expect(diff.findings.filter((f) => f.change === 'CLOSED')).toEqual([]);
        expect(diff.orphanCredentials.filter((o) => o.change === 'CLOSED')).toEqual([]);
        expect(diff.agents.gone).toEqual([]);
        expect(diff.levels.filter((l) => l.change === 'LEVEL_UP' || l.change === 'OBSERVED_LEVEL_UP')).toEqual([]);
        expect(diff.outcome).not.toBe('SAME');
        expect(diff.sources).toContainEqual(expect.objectContaining({ kind, change: 'NOW_INCOMPLETE', to: { status: 'INCOMPLETE', reason: expected } }));
        const text = renderDiffText(diff);
        expect(text).not.toMatch(/^\s*closed\s/m);
        expect(text).not.toMatch(/^\s*gone\s/m);

        // 5. The page says so first, and uses none of its words for a clean result.
        const page = renderSummaryHtml(results);
        expect(page).toContain('<strong>Incomplete:</strong> 1 of 9 sources were not read in full.');
        const firstSection = page.slice(page.indexOf('<section'), page.indexOf('</section>'));
        expect(firstSection).toContain('id="completeness"');
        expect(firstSection).toMatch(new RegExp(`<th scope="row"><code>${kind}</code></th>\\s*<td><span class="tag bad">Incomplete</span></td>\\s*<td><code>${expected}</code></td>`));
        for (const words of CLEAN_WORDS) expect(page).not.toContain(words);
    });

    it('scan --strict exits 3, and without --strict the same run exits 0: delivered, and not everything established', async () => {
        const world = worldFor();
        world.inject = (req) => (isReadOf(kind, req) ? status(503) : undefined);
        jest.spyOn(globalThis, 'fetch').mockImplementation((input, init) => world.fetchImpl(String(input), init ?? {}));
        jest.spyOn(dns.promises, 'lookup').mockImplementation((async () => [{ address: '93.184.216.34', family: 4 }]) as unknown as typeof dns.promises.lookup);
        jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
        jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
        try {
            const dir = join(base, `strict-${kind}`);
            mkdirSync(join(dir, 'out'), { recursive: true, mode: 0o700 });
            const configPath = join(dir, 'config.json');
            writeFileSync(configPath, JSON.stringify(estateConfig(SOURCES)), { mode: 0o600 });
            chmodSync(configPath, 0o600);
            expect(await main(['scan', '--config', configPath, '--out', join(dir, 'out'), '--dry-run', '--strict'], estateEnv())).toBe(EXIT.INCOMPLETE);
            expect(await main(['scan', '--config', configPath, '--out', join(dir, 'out'), '--dry-run'], estateEnv())).toBe(EXIT.OK);
        } finally {
            jest.restoreAllMocks();
        }
    });
});

describe('a second page that fails keeps what the first page read', () => {
    it.each([
        ['Okta apps', 'okta-app', /^\/api\/v1\/apps$/, 'okta:app:'],
        ['Okta API tokens', 'okta-app', /^\/api\/v1\/api-tokens$/, 'okta:'],
    ] as const)('%s: the principals already read are in the report, under an INCOMPLETE source', async (_label, kind, path, prefix) => {
        const world = worldFor();
        let seen = 0;
        world.inject = (req) => {
            if (!hostsOf(kind).read.includes(req.host) || !path.test(req.path)) return undefined;
            seen += 1;
            return seen >= 2 ? 'throw' : undefined;
        };
        const { body } = await scanWith(world);
        expect(seen).toBe(2);
        expect(body.population.sources.find((s) => s.kind === kind)).toMatchObject({ status: 'INCOMPLETE', reason: 'UNREACHABLE' });
        // What the first page held is reported; what the second would have added is not invented.
        const kept = body.agents.filter((a) => a.discoveredId.startsWith(prefix));
        expect(kept.length).toBeGreaterThan(0);
        expect(kept.length).toBeLessThan((clean.agentsVia[kind] ?? []).length);
    });
});

describe('every source down at once', () => {
    const NETWORK_ONLY = parseScannerConfig(estateConfig(NETWORK_KINDS.map((k) => ESTATE_SOURCES[k])));

    it.each([
        ['every connection refused', (): WorldAnswer => 'throw', 'UNREACHABLE'],
        ['every request answered 503', (): WorldAnswer => status(503), 'UNREACHABLE'],
        ['nothing ever answers', (): WorldAnswer => 'timeout', 'TIME_BOX'],
    ] as const)('%s: the scan is an EMPTY_SCAN finding and every source is listed as not read; it is never a clean bill', async (_label, answer, reason) => {
        const world = worldFor();
        world.inject = answer;
        const logged = capturedLog();
        const scan = await runScan({ config: NETWORK_ONLY, env: estateEnv(), log: logged.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
        const results = scoreScanLocally({ config: NETWORK_ONLY, raw: scan.raw, body: scan.body, inventory: null });

        expect(scan.body.agents).toEqual([]);
        expect(scan.body.population.sources).toHaveLength(NETWORK_KINDS.length);
        // The exchange failing is a credential that could not be used; everything else is the reason injected.
        for (const source of scan.body.population.sources) {
            expect(source.status).toBe('INCOMPLETE');
            expect([reason, 'AUTH_FAILED']).toContain(source.reason);
        }
        expect(verifyAndParseHarnessReport(scan.raw, [PUBLIC_KEY])).toMatchObject({ ok: true, complete: false });

        expect(results.estate.empty).toBe(true);
        expect(results.scan.complete).toBe(false);
        expect(results.findings.map((f) => f.code)).toContain('EMPTY_SCAN');
        expect(results.findings.filter((f) => f.code === 'INCOMPLETE_SOURCE')).toHaveLength(NETWORK_KINDS.length);

        const page = renderSummaryHtml(results);
        expect(page).toContain(`<strong>Incomplete:</strong> ${NETWORK_KINDS.length} of ${NETWORK_KINDS.length} sources were not read in full.`);
        expect(page).toContain('This scan found no agents. That is a finding, not a clean result.');
        for (const words of [...CLEAN_WORDS, 'No finding was raised.']) expect(page).not.toContain(words);

        const diff = diffResults(clean.results, results);
        expect(diff.agents.gone).toEqual([]);
        expect(diff.agents.notSeen.length).toBe(clean.results.agents.length);
        expect(diff.findings.filter((f) => f.change === 'CLOSED')).toEqual([]);
        expect(diff.outcome).not.toBe('SAME');
    });

    it('every credential missing from the environment: every source is AUTH_FAILED, none is dropped, and no request is made', async () => {
        const world = worldFor();
        const scan = await runScan({ config: NETWORK_ONLY, env: { SCANNER_SIGNING_KEY: SIGNING_PEM }, log: capturedLog().log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
        // An MCP server that takes no token is still read: the one host that needs no credential.
        const failed = scan.body.population.sources.filter((s) => s.status === 'INCOMPLETE');
        expect(failed.map((s) => s.reason)).toEqual(failed.map(() => 'AUTH_FAILED'));
        expect(scan.body.population.sources).toHaveLength(NETWORK_KINDS.length);
        expect(failed.length).toBe(NETWORK_KINDS.length);
        expect(new Set(world.log.map((r) => r.host))).toEqual(new Set(['mcp.acme.example']));
    });
});

/**
 * THE SIZE CAPS THE CELLS ABOVE DO NOT REACH. Above, one JSON answer over the
 * 4 MiB response cap is BYTE_CAP. Three more bounds stand between a source and
 * an answer of any size, and each could be taken out with every cell above
 * still passing:
 *
 *   • the per-source budget: pages that are each under the response cap and
 *     together over the source's;
 *   • an MCP answer delivered as an event stream, which is read by its own
 *     loop, not the JSON reader's;
 *   • the answer of a token exchange, capped at 64 KiB wherever one is made.
 *
 * Each case is paired with the same answer just inside the bound, read in
 * full, so what stops the read is the bound and nothing else about the answer.
 */
describe('the size caps a listing reaches without one large JSON answer', () => {
    const ASOF = new Date(NOW);
    const transport = (fetchImpl: FetchLike) => ({ fetchImpl, deadline: NOW + 60_000, now: () => NOW });
    const ctxOver = (fetchImpl: FetchLike, caps?: { response?: number; source?: number }) => ({ asOf: ASOF, deadline: NOW + 60_000, now: () => NOW, ...createSourceWire(transport(fetchImpl), caps) });
    const PUBLIC = async () => ['203.0.113.10'];
    const TOKEN_CAP = 64 * 1024;

    it('the default budget of a source is 64 MiB, sixteen answers of the largest size', () => {
        expect(MAX_SOURCE_BYTES).toBe(64 * 1024 * 1024);
        expect(MAX_SOURCE_BYTES / MAX_RESPONSE_BYTES).toBe(16);
    });

    it('pages that are each under the response cap and together over the source budget are BYTE_CAP, and what was read is kept', async () => {
        const okta = () => oktaSource({ orgUrl: OKTA_ORG, apiToken: OKTA_TOKEN_VALUE, ownerProfileKey: 'owner' });
        // The size of every answer of a clean read, as the wire receives it.
        const sizes: number[] = [];
        const fakes = createSourceFakes();
        const measured: FetchLike = async (url, init) => {
            const res = await fakes.fetchImpl(url, init);
            sizes.push(Buffer.byteLength(await res.clone().text()));
            return res;
        };
        const whole = await okta().read(ctxOver(measured));
        expect(whole).toMatchObject({ status: 'COMPLETE' });
        const total = sizes.reduce((a, b) => a + b, 0);
        const largest = Math.max(...sizes);
        expect(sizes.length).toBeGreaterThan(2);
        expect(largest).toBeLessThan(total);

        // No single answer is over the budget, and all of them together are.
        const over = await okta().read(ctxOver(createSourceFakes().fetchImpl, { source: total - 1 }));
        expect(over).toMatchObject({ kind: 'okta-app', status: 'INCOMPLETE', reason: 'BYTE_CAP' });
        expect(over.rows).toBeGreaterThan(0);
        expect(over.rows).toBeLessThanOrEqual(whole.rows);
        const first = await okta().read(ctxOver(createSourceFakes().fetchImpl, { source: largest }));
        expect(first).toMatchObject({ status: 'INCOMPLETE', reason: 'BYTE_CAP' });
        // Exactly the budget is inside it.
        expect(await okta().read(ctxOver(createSourceFakes().fetchImpl, { source: total }))).toMatchObject({ status: 'COMPLETE', rows: whole.rows });
    });

    it('an MCP listing answered as an event stream over the response cap is BYTE_CAP, and one inside it is read', async () => {
        const CAP = 16 * 1024;
        const read = (padding: number): Promise<SourceRead> => {
            const fakes = createSourceFakes();
            const wire: FetchLike = async (url, init) => {
                const res = await fakes.fetchImpl(url, init);
                let rpc: { id?: number; method?: string } = {};
                try {
                    rpc = JSON.parse(String(init.body ?? '')) as typeof rpc;
                } catch {
                    rpc = {};
                }
                if (rpc.method !== 'tools/list') return res;
                // The same answer, as a stream: comment lines first (a server's keep-alive), then the response.
                const answer = await res.text();
                const stream = `${`: ${'k'.repeat(1022)}\n`.repeat(padding)}\nevent: message\ndata: ${answer}\n\n`;
                return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } });
            };
            return mcpSource({
                servers: [{ label: 'crm', url: MCP_CRM, agents: [], pinnedManifestHash: null, token: null, egressPrivateCidrAllowlist: [] }],
                resolveHost: PUBLIC,
            }).read(ctxOver(wire, { response: CAP }));
        };
        expect(await read(0)).toMatchObject({ kind: 'mcp', status: 'COMPLETE' });
        // 32 KiB of keep-alive before the answer: twice the cap, and no content-length to refuse it by.
        const over = await read(32);
        expect(over).toMatchObject({ kind: 'mcp', status: 'INCOMPLETE', reason: 'BYTE_CAP' });
        expect(over.mcpServers).toEqual([]);
    });

    describe.each([
        [
            'a client-credentials exchange (Entra)',
            (fetchImpl: FetchLike) =>
                entraSource({ directoryId: ENTRA_DIRECTORY_ID, clientId: AZURE_CLIENT_ID, clientSecret: AZURE_CLIENT_SECRET_VALUE, includeThirdPartyApplications: false }).read(ctxOver(fetchImpl)),
            (url: string) => new URL(url).hostname === 'login.microsoftonline.com',
        ],
        [
            'the register\'s token exchange',
            (fetchImpl: FetchLike) => inflectRegisterSource({ baseUrl: INGEST, tenantSlug: 'acme', apiKey: 'iflk_fake-ingest-key-3686' }).read(ctxOver(fetchImpl)),
            (url: string) => new URL(url).pathname === '/api/mcp/token',
        ],
    ] as const)('%s', (_label, read, isExchange) => {
        /** The real answer of the exchange with `bytes` of padding added as one more member. */
        const padded = (bytes: number): FetchLike => {
            const fakes = createSourceFakes();
            return async (url, init) => {
                const res = await fakes.fetchImpl(url, init);
                if (!isExchange(url) || !res.ok) return res;
                const body = (await res.json()) as Record<string, unknown>;
                const text = JSON.stringify({ ...body, padding: '' });
                return new Response(JSON.stringify({ ...body, padding: 'p'.repeat(Math.max(0, bytes - Buffer.byteLength(text))) }), { status: res.status, headers: { 'content-type': 'application/json' } });
            };
        };

        it('an answer of exactly 64 KiB is taken, and the source is read', async () => {
            expect(await read(padded(TOKEN_CAP))).toMatchObject({ status: 'COMPLETE' });
        });

        it('an answer one byte over 64 KiB stops the source with BYTE_CAP, and nothing is read with a token from it', async () => {
            const result = await read(padded(TOKEN_CAP + 1));
            expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'BYTE_CAP', rows: 0, observations: [] });
        });
    });
});
