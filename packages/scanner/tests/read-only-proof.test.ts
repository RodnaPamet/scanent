/**
 * THE READ-ONLY PROOF: one recorder over every source and every preflight.
 *
 * Each source suite already holds its own request log to the declared surface,
 * in its own way. This is the one test over all of them, so that "read-only" is
 * a single statement with a single proof:
 *
 *   • one row per source kind of `SourceConfigSchema`, each run twice: its scan
 *     read through `runScan`, and its preflight through `runDoctor`;
 *   • every request either run makes is placed in one class of the declared
 *     surface, or it is UNDECLARED and the row fails;
 *   • nothing but a GET is sent, except what the surface itself lists under
 *     `authenticates`, `lists`, `readsRegister` and `sends`;
 *   • a row that makes no request proves nothing, so each must make one (the
 *     `code` row makes none by design, and is held to its file operations);
 *   • two exhaustiveness checks: the rows are the kinds of the schema, and every
 *     declared path, exchange and message was asked for by some row. A declared
 *     request nobody makes is a wider declaration than the code needs.
 *
 * The detector is proved by mutation: a wire that also issues a DELETE and a
 * GET to a path the surface does not name fails, for both reasons.
 *
 * What this does not cover, and why. The egress proof (`provesEgress`) dials
 * through a probe of its own and makes no HTTP request; `egress-proxy.test.ts`
 * holds it. The OpenShell gateway (`readsGateway`) is declared and no
 * configuration reaches it: its wire answers UNREACHABLE without a request,
 * and this test fails if a gateway call is ever recorded.
 */
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { lstat, readdir, readFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

import { verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { verifyAndParseIntegrationsReport } from '@rodnapamet/scanent-contract/integrations-contract';
import { parseScannerConfig, SourceConfigSchema, type ScannerConfig } from '../src/config';
import { runDoctor } from '../src/doctor/run';
import { createSourceWire, MCP_MESSAGES, type FetchLike } from '../src/http';
import { jsonLineLog } from '../src/log';
import { rawPublicKeyHex } from '../src/report';
import { loadSigningKey, runScan, scanAndPost } from '../src/scan';
import { SCANNER_SURFACE, scannerManifestHash, TOKEN_EXCHANGE_GRANTS } from '../src/scanner-surface';
import type { CodeFs } from '../src/sources/code/files';
import { langchainCodeSource } from '../src/sources/langchain';
import { langSmithFixture, LANGSMITH_SELF_HOSTED, LANGSMITH_US } from './helpers/agent-harness-source-fakes';
import { CODE_ROOT, SIGNING_PEM } from './helpers/doctor-world';
import {
    createEstateWorld,
    ESTATE_SOURCE_KINDS,
    ESTATE_SOURCES,
    estateConfig,
    estateEnv,
    INTEGRATIONS_ESTATE_SOURCE,
    PUBLIC_RESOLVER,
    SELF_HOSTED_RUNTIME,
    type EstateSourceKind,
} from './helpers/estate-world';
import {
    classifyRequest,
    configuredHostsOf,
    matchesTemplate,
    NON_GET_CLASSES,
    readOnlyProblems,
    recordRequests,
    type RecordedRequest,
    type RequestClass,
} from './helpers/request-recorder';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const quiet = jsonLineLog(() => undefined);
const MANIFEST_AT_LOAD = scannerManifestHash();

const worldFor = () =>
    createEstateWorld({
        fakes: { langsmith: { [LANGSMITH_US]: langSmithFixture(), [LANGSMITH_SELF_HOSTED]: { ...langSmithFixture(), selfHosted: true } } },
    });

/** The rows: every source kind once, and the second host a `runtime` source can be on. */
const ROWS: readonly { readonly name: string; readonly kind: EstateSourceKind; readonly source: unknown }[] = [
    ...ESTATE_SOURCE_KINDS.map((kind) => ({ name: kind, kind, source: ESTATE_SOURCES[kind] })),
    { name: 'runtime (self-hosted)', kind: 'runtime', source: SELF_HOSTED_RUNTIME },
];

/** Every request any row made, with its class: what the exhaustiveness checks read. */
const seen: { readonly row: string; readonly via: 'scan' | 'doctor'; readonly request: RecordedRequest; readonly cls: RequestClass }[] = [];

let dir: string;
beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-readonly-'));
});
afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
});

async function scanRow(config: ScannerConfig, fetchImpl: FetchLike) {
    return runScan({ config, env: estateEnv(), log: quiet, fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
}

describe.each(ROWS)('$name', ({ name, kind, source }) => {
    const config = parseScannerConfig(estateConfig([source]));
    const hosts = configuredHostsOf(config);

    it('the scan read: every request is declared, and nothing but a declared exchange or message is not a GET', async () => {
        const recorder = recordRequests(worldFor().fetchImpl);
        const { body, raw } = await scanRow(config, recorder.fetchImpl);

        // The read was a real one: complete, and signed.
        expect(body.population.sources).toEqual([expect.objectContaining({ kind, status: 'COMPLETE' })]);
        expect(verifyAndParseHarnessReport(raw, [rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey)]).ok).toBe(true);

        expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
        for (const request of recorder.requests) seen.push({ row: name, via: 'scan', request, cls: classifyRequest(request, hosts) });
        // A row that records nothing proves nothing.
        if (kind === 'code') expect(recorder.requests).toEqual([]);
        else expect(recorder.requests.length).toBeGreaterThan(0);
        // Reading posts nothing to the tenant's ingest.
        expect(recorder.requests.map((r) => classifyRequest(r, hosts))).not.toContain('INGEST_POST');
    });

    it('the preflight: the same holds, and it asks for nothing the scan read does not', async () => {
        const configPath = join(dir, `${name.replace(/[^a-z-]/g, '')}.json`);
        mkdirSync(join(dir, 'out'), { recursive: true, mode: 0o700 });
        writeFileSync(configPath, JSON.stringify(estateConfig([source], { outputs: [{ kind: 'file', dir: join(dir, 'out') }] })), { mode: 0o600 });
        chmodSync(configPath, 0o600);
        const recorder = recordRequests(worldFor().fetchImpl);
        const report = await runDoctor({
            configPath,
            env: estateEnv(),
            fetchImpl: recorder.fetchImpl,
            resolveHost: PUBLIC_RESOLVER,
            now: () => NOW,
            nodeVersion: 'v24.1.0',
            uid: 1000,
        });
        // The preflight got as far as the reads: nothing failed and nothing was blocked behind a failure.
        expect(report.checks.filter((c) => c.status === 'FAIL').map((c) => `${c.scope} ${c.id}`)).toEqual([]);
        expect(report.checks.filter((c) => c.status === 'SKIPPED' && c.cause === 'BLOCKED').map((c) => `${c.scope} ${c.id}`)).toEqual([]);

        expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
        for (const request of recorder.requests) seen.push({ row: name, via: 'doctor', request, cls: classifyRequest(request, hosts) });
        if (kind === 'code') expect(recorder.requests).toEqual([]);
        else expect(recorder.requests.length).toBeGreaterThan(0);
        expect(recorder.requests.map((r) => classifyRequest(r, hosts))).not.toContain('INGEST_POST');
        // Nothing was written anywhere it can see.
        expect(readdirSync(join(dir, 'out'))).toEqual([]);
    });
});

/**
 * The integrations scanner's Entra source. It runs beside an agent source in
 * this version, so its row is configured with the `code` source, which makes
 * no request: every request the row records is the integrations source's.
 */
describe('entra-integrations', () => {
    const config = parseScannerConfig(estateConfig([ESTATE_SOURCES.code, INTEGRATIONS_ESTATE_SOURCE]));
    const hosts = configuredHostsOf(config);

    it('the scan read: every request is declared, every one is a GET or the declared exchange, and its report verifies', async () => {
        const recorder = recordRequests(worldFor().fetchImpl);
        const scan = await scanRow(config, recorder.fetchImpl);
        expect(scan.integrations?.body.sources).toEqual([{ kind: 'entra-integrations', status: 'COMPLETE', rows: expect.any(Number), signInActivity: { status: 'COMPLETE', rows: 3 } }]);
        expect(verifyAndParseIntegrationsReport(scan.integrations?.raw ?? '', [rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey)]).ok).toBe(true);
        expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
        expect(recorder.requests.length).toBeGreaterThan(0);
        expect([...new Set(recorder.requests.map((r) => classifyRequest(r, hosts)))].sort()).toEqual(['READ', 'TOKEN_EXCHANGE']);
        for (const request of recorder.requests) seen.push({ row: 'entra-integrations', via: 'scan', request, cls: classifyRequest(request, hosts) });
    });

    it('the preflight: the same holds, nothing failed, and nothing was written', async () => {
        const configPath = join(dir, 'entra-integrations.json');
        mkdirSync(join(dir, 'out-integrations'), { recursive: true, mode: 0o700 });
        writeFileSync(configPath, JSON.stringify(estateConfig([ESTATE_SOURCES.code, INTEGRATIONS_ESTATE_SOURCE], { outputs: [{ kind: 'file', dir: join(dir, 'out-integrations') }] })), { mode: 0o600 });
        chmodSync(configPath, 0o600);
        const recorder = recordRequests(worldFor().fetchImpl);
        const report = await runDoctor({ configPath, env: estateEnv(), fetchImpl: recorder.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, nodeVersion: 'v24.1.0', uid: 1000 });
        expect(report.checks.filter((c) => c.status === 'FAIL').map((c) => `${c.scope} ${c.id}`)).toEqual([]);
        expect(report.checks.filter((c) => c.status === 'SKIPPED' && c.cause === 'BLOCKED').map((c) => `${c.scope} ${c.id}`)).toEqual([]);
        expect(report.checks.filter((c) => c.scope === 'entra-integrations' && c.status === 'PASS').map((c) => c.id)).toEqual(['credential.present', 'host.resolves', 'reachable', 'authenticated', 'read.permitted']);
        expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
        expect(recorder.requests.length).toBeGreaterThan(0);
        for (const request of recorder.requests) seen.push({ row: 'entra-integrations', via: 'doctor', request, cls: classifyRequest(request, hosts) });
        expect(readdirSync(join(dir, 'out-integrations'))).toEqual([]);
    });
});

describe('the code source reads files, and only reads them', () => {
    function recordingFs(): { fs: CodeFs; operations: Set<string>; paths: string[] } {
        const operations = new Set<string>();
        const paths: string[] = [];
        const note = (operation: string, path: string) => {
            operations.add(operation);
            paths.push(path);
        };
        return {
            operations,
            paths,
            fs: {
                lstat: (p) => (note('lstat', p), lstat(p)),
                readdir: (p) => (note('readdir', p), readdir(p)),
                readFile: (p) => (note('readFile', p), readFile(p)),
            },
        };
    }
    const [declared] = SCANNER_SURFACE.readsFiles;
    const noNetwork = async (): Promise<Response> => {
        throw new Error('the code source reaches no network');
    };
    const ctx = () => ({ asOf: new Date(NOW), deadline: NOW + 60_000, now: () => NOW, ...createSourceWire({ fetchImpl: noNetwork, deadline: NOW + 60_000, now: () => NOW }) });

    it('the read uses exactly the declared operations, on paths under its root', async () => {
        const rec = recordingFs();
        const read = await langchainCodeSource({ roots: [{ label: 'example', path: CODE_ROOT }], fs: rec.fs }).read(ctx());
        expect(read).toMatchObject({ kind: 'code', status: 'COMPLETE' });
        expect(read.observations.length).toBeGreaterThan(0);
        expect([...rec.operations].sort()).toEqual([...declared.operations].sort());
        expect(rec.paths.length).toBeGreaterThan(0);
        for (const path of rec.paths) expect(path === CODE_ROOT || path.startsWith(`${CODE_ROOT}/`)).toBe(true);
    });

    it('the preflight uses a subset of them and opens no file', async () => {
        const rec = recordingFs();
        const steps = await langchainCodeSource({ roots: [{ label: 'example', path: CODE_ROOT }], fs: rec.fs }).preflight(ctx());
        expect(steps.map((s) => s.outcome)).toEqual(['ok']);
        expect([...rec.operations].sort()).toEqual(['lstat', 'readdir']);
        expect(rec.paths).toEqual([CODE_ROOT, CODE_ROOT]);
    });

    it('the tree is byte for byte what it was', async () => {
        const snapshot = (at: string): Record<string, string> =>
            Object.fromEntries(
                readdirSync(at, { recursive: true, withFileTypes: true })
                    .filter((e) => e.isFile())
                    .map((e) => {
                        const full = join(e.parentPath, e.name);
                        return [full, `${lstatSync(full).mtimeMs}:${readFileSync(full).length}`];
                    }),
            );
        const before = snapshot(CODE_ROOT);
        await langchainCodeSource({ roots: [{ label: 'example', path: CODE_ROOT }] }).read(ctx());
        expect(snapshot(CODE_ROOT)).toEqual(before);
        expect(declared).toMatchObject({ followsSymlinks: false, executes: false });
    });
});

describe('the one post: a signed report to the tenant, and nothing else', () => {
    it('scanAndPost sends exactly one request that is not a read, to the configured ingest', async () => {
        const config = parseScannerConfig(estateConfig([ESTATE_SOURCES['okta-app']]));
        const hosts = configuredHostsOf(config);
        const world = worldFor();
        const recorder = recordRequests(world.fetchImpl);
        const result = await scanAndPost({ config, env: estateEnv(), log: quiet, fetchImpl: recorder.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
        expect(result.ok).toBe(true);
        expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
        const posts = recorder.requests.filter((r) => classifyRequest(r, hosts) === 'INGEST_POST');
        expect(posts).toHaveLength(1);
        expect(posts[0].origin).toBe(hosts.inflectOrigin);
        expect(posts[0].body).toBe(world.fakes.posted[0]);
        for (const request of recorder.requests) seen.push({ row: 'ingest', via: 'scan', request, cls: classifyRequest(request, hosts) });
    });

    it('the same post to another host is not declared: the ingest is the configured tenant and nowhere else', () => {
        const hosts = configuredHostsOf(parseScannerConfig(estateConfig([ESTATE_SOURCES.code])));
        const elsewhere: RecordedRequest = {
            method: 'POST',
            url: 'https://elsewhere.example/api/t/acme/admin/agents/harness-scans',
            origin: 'https://elsewhere.example',
            pathname: '/api/t/acme/admin/agents/harness-scans',
            headerNames: [],
            body: '{}',
            redirect: 'error',
        };
        expect(classifyRequest(elsewhere, hosts)).toBe('UNDECLARED');
        for (const pathname of ['/api/mcp', '/api/mcp/token']) {
            expect(classifyRequest({ ...elsewhere, url: `https://elsewhere.example${pathname}`, pathname, body: JSON.stringify({ method: 'initialize' }) }, hosts)).toBe('UNDECLARED');
        }
    });
});

describe('exhaustiveness', () => {
    it('the rows are the source kinds of the configuration schema, each once', () => {
        const schemaKinds = SourceConfigSchema.options.map((option) => option.shape.kind.value as string).sort();
        // The agent rows, and the integrations row of its own.
        expect([...new Set([...ROWS.map((r) => r.kind as string), INTEGRATIONS_ESTATE_SOURCE.kind])].sort()).toEqual(schemaKinds);
        expect([...ESTATE_SOURCE_KINDS, INTEGRATIONS_ESTATE_SOURCE.kind].sort()).toEqual(schemaKinds);
    });

    it('every declared read path was requested by some row', () => {
        const unrequested: string[] = [];
        for (const read of SCANNER_SURFACE.reads) {
            for (const path of read.paths) {
                const asked = seen.some(
                    ({ request, cls }) => cls === 'READ' && request.method === read.method && matchesTemplate(path, request.pathname) && (!('origin' in read) || read.origin === request.origin),
                );
                if (!asked) unrequested.push(`${read.product} ${read.method} ${path}`);
            }
        }
        expect(unrequested).toEqual([]);
    });

    it('every declared exchange, message and post was sent by some row', () => {
        const unsent: string[] = [];
        for (const auth of SCANNER_SURFACE.authenticates) {
            // Entra and Key Vault share one endpoint template; each row uses it for its own product.
            const rows = auth.product === 'entra' ? ['entra-sp'] : auth.product === 'entra-integrations' ? ['entra-integrations'] : auth.product === 'azure-key-vault' ? ['vault'] : ['gcp-sa'];
            const sent = seen.some(({ row, request, cls }) => rows.includes(row) && cls === 'TOKEN_EXCHANGE' && request.origin === auth.origin && matchesTemplate(auth.path, request.pathname));
            if (!sent) unsent.push(`${auth.product} token exchange`);
        }
        const rpc = (r: RecordedRequest): string => (JSON.parse(r.body ?? '{}') as { method: string }).method;
        for (const list of SCANNER_SURFACE.lists) {
            for (const message of list.jsonRpc) {
                if (!seen.some(({ request, cls }) => cls === 'MCP_MESSAGE' && rpc(request) === message)) unsent.push(`mcp ${message}`);
            }
        }
        for (const register of SCANNER_SURFACE.readsRegister) {
            for (const message of register.jsonRpc) {
                if (!seen.some(({ request, cls }) => cls === 'REGISTER_MESSAGE' && rpc(request) === message)) unsent.push(`register ${message}`);
            }
            if (!seen.some(({ cls }) => cls === 'REGISTER_EXCHANGE')) unsent.push('register exchange');
        }
        if (!seen.some(({ cls }) => cls === 'INGEST_POST')) unsent.push('ingest post');
        expect(unsent).toEqual([]);
        expect([...MCP_MESSAGES]).toEqual([...SCANNER_SURFACE.lists[0].jsonRpc]);
    });

    it('no request of any row was a method other than GET or POST, and every POST is of a class the surface lists', () => {
        expect([...new Set(seen.map((s) => s.request.method))].sort()).toEqual(['GET', 'POST']);
        const posts = seen.filter((s) => s.request.method === 'POST');
        expect(posts.length).toBeGreaterThan(0);
        for (const post of posts) expect(NON_GET_CLASSES.has(post.cls)).toBe(true);
        expect([...NON_GET_CLASSES].sort()).toEqual(['INGEST_POST', 'MCP_MESSAGE', 'REGISTER_EXCHANGE', 'REGISTER_MESSAGE', 'TOKEN_EXCHANGE']);
    });

    it('the manifest hash did not move while the rows ran', () => {
        expect(scannerManifestHash()).toBe(MANIFEST_AT_LOAD);
    });
});

describe('the detector is not vacuous', () => {
    const config = parseScannerConfig(estateConfig([ESTATE_SOURCES['okta-app']]));
    const hosts = configuredHostsOf(config);
    const okta = 'https://acme.okta.com';

    /** A wire that makes one extra request, of the caller's choosing, beside the first real one. */
    async function scanWithExtra(extra: { method: string; url: string; body?: string; redirect?: RequestInit['redirect'] }): Promise<string[]> {
        const recorder = recordRequests(worldFor().fetchImpl);
        let strayed = false;
        const straying: FetchLike = async (url, init) => {
            if (!strayed) {
                strayed = true;
                await recorder.fetchImpl(extra.url, { method: extra.method, headers: init.headers, body: extra.body, redirect: extra.redirect ?? 'error' });
            }
            return recorder.fetchImpl(url, init);
        };
        await scanRow(config, straying);
        return readOnlyProblems(recorder.requests, hosts);
    }

    it('an honest scan has no problem', async () => {
        const recorder = recordRequests(worldFor().fetchImpl);
        await scanRow(config, recorder.fetchImpl);
        expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
    });

    it('a DELETE to a declared path fails, for being undeclared and for not being a GET', async () => {
        expect(await scanWithExtra({ method: 'DELETE', url: `${okta}/api/v1/apps` })).toEqual([
            `DELETE ${okta}/api/v1/apps is not on the declared surface`,
            `DELETE ${okta}/api/v1/apps is not a GET, and the surface lists no such request`,
        ]);
    });

    it('a GET to a path the surface does not name fails', async () => {
        expect(await scanWithExtra({ method: 'GET', url: `${okta}/api/v1/apps/0oaService1/credentials/secrets` })).toEqual([
            `GET ${okta}/api/v1/apps/0oaService1/credentials/secrets is not on the declared surface`,
        ]);
    });

    it.each([
        ['a declared path on a host the configuration does not name', { method: 'GET', url: 'https://other.okta.com/api/v1/apps' }, 'is not on the declared surface'],
        ['a read of a fixed-host product on another host', { method: 'GET', url: 'https://graph.example.com/v1.0/applications' }, 'is not on the declared surface'],
        ['a POST to a declared read path', { method: 'POST', url: `${okta}/api/v1/apps`, body: '{}' }, 'is not a GET'],
        ['a PUT', { method: 'PUT', url: `${okta}/api/v1/apps/0oaService1`, body: '{}' }, 'is not a GET'],
        ['a PATCH', { method: 'PATCH', url: `${okta}/api/v1/apps/0oaService1`, body: '{}' }, 'is not a GET'],
        ['a GET carrying a body', { method: 'GET', url: `${okta}/api/v1/apps`, body: '{}' }, 'is a GET with a body'],
        ['a request that would follow a redirect', { method: 'GET', url: `${okta}/api/v1/apps`, redirect: 'follow' as const }, 'would follow a redirect'],
        ['a request in clear text', { method: 'GET', url: 'http://acme.okta.com/api/v1/apps' }, 'is not https'],
        ['tools/call to an MCP server', { method: 'POST', url: 'https://mcp.acme.example/crm/mcp', body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'x' } }) }, 'is not on the declared surface'],
    ])('%s fails', async (_label, extra, problem) => {
        const problems = await scanWithExtra(extra);
        expect(problems.length).toBeGreaterThan(0);
        expect(problems.join('\n')).toContain(problem);
    });

    it('a token exchange for any grant but the one declared for its endpoint fails', () => {
        const form = (pairs: Record<string, string> | [string, string][]) => new URLSearchParams(pairs).toString();
        const exchange = (url: string, body: string): RecordedRequest => ({ method: 'POST', url, origin: new URL(url).origin, pathname: new URL(url).pathname, headerNames: [], body, redirect: 'error' });
        const microsoft = 'https://login.microsoftonline.com/0d1e2c3b-0000-4000-8000-000000003686/oauth2/v2.0/token';
        const google = 'https://oauth2.googleapis.com/token';
        const jwtBearer = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        expect(classifyRequest(exchange(microsoft, form({ grant_type: 'client_credentials', client_id: 'x', scope: 'y' })), hosts)).toBe('TOKEN_EXCHANGE');
        expect(classifyRequest(exchange(google, form({ grant_type: jwtBearer, assertion: 'a.b.c' })), hosts)).toBe('TOKEN_EXCHANGE');
        for (const [url, body] of [
            [microsoft, form({ grant_type: 'password', username: 'u', password: 'p' })],
            [microsoft, form({ grant_type: 'refresh_token', refresh_token: 'r' })],
            [microsoft, form({ grant_type: jwtBearer, assertion: 'a.b.c' })],
            [microsoft, form([['grant_type', 'client_credentials'], ['grant_type', 'password']])],
            [microsoft, form({ client_id: 'x' })],
            [microsoft, ''],
            [microsoft, JSON.stringify({ grant_type: 'client_credentials' })],
            [google, form({ grant_type: 'client_credentials', client_id: 'x' })],
            [google, form({ grant_type: 'authorization_code', code: 'c' })],
        ] as const) {
            const req = exchange(url, body);
            expect(classifyRequest(req, hosts)).toBe('UNDECLARED');
            expect(readOnlyProblems([req], hosts).join('\n')).toContain('is not on the declared surface');
        }
        // Each declared exchange names a grant, and no product is left without one.
        expect(Object.keys(TOKEN_EXCHANGE_GRANTS).sort()).toEqual([...new Set(SCANNER_SURFACE.authenticates.map((a) => a.product))].sort());
    });

    it('a register call of any tool but the one declared fails, and so does an exchange for a wider audience', () => {
        const registerHosts = configuredHostsOf(parseScannerConfig(estateConfig([ESTATE_SOURCES['inflect-register']])));
        const post = (pathname: string, body: unknown): RecordedRequest => ({
            method: 'POST',
            url: `https://inflect.example.com${pathname}`,
            origin: 'https://inflect.example.com',
            pathname,
            headerNames: [],
            body: JSON.stringify(body),
            redirect: 'error',
        });
        expect(classifyRequest(post('/api/mcp', { method: 'tools/call', params: { name: 'get_harness_register' } }), registerHosts)).toBe('REGISTER_MESSAGE');
        expect(classifyRequest(post('/api/mcp', { method: 'tools/call', params: { name: 'delete_agent' } }), registerHosts)).toBe('UNDECLARED');
        expect(classifyRequest(post('/api/mcp', { method: 'tools/list' }), registerHosts)).toBe('UNDECLARED');
        const grant = 'urn:ietf:params:oauth:grant-type:token-exchange';
        expect(classifyRequest(post('/api/mcp/token', { grant_type: grant, audience: ['get_harness_register'] }), registerHosts)).toBe('REGISTER_EXCHANGE');
        expect(classifyRequest(post('/api/mcp/token', { grant_type: grant, audience: ['get_harness_register', 'delete_agent'] }), registerHosts)).toBe('UNDECLARED');
    });
});
