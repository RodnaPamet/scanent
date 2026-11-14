/**
 * Posting the integrations report: the `inflect` output's second post.
 *
 *   1. The route and the answer: `postIntegrationsReport` posts to the
 *      integrations ingest, reads the tenant's 201, and names a refusal by its
 *      code.
 *   2. The surface: two POST paths, exactly, and no third.
 *   3. The configuration: `integrationsApiKeyEnv`, a key of its own, optional,
 *      read from the variable or its `_FILE`.
 *   4. A run: posted with the second key; not posted, and said once, without
 *      one; an integrations-only run needs no agent key; a refused or failed
 *      integrations post makes the run not delivered; an agents-only run sends
 *      what it always sent.
 *   5. The scheduled path (`scanAndPost`) posts both, by the same rules.
 *   6. `hosts` and `init`.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { verifyAndParseIntegrationsReport } from '@rodnapamet/scanent-contract/integrations-contract';

import { ConfigError, credentialEnvNames, inflectPosts, parseScannerConfig, type ScannerConfig } from '../src/config';
import type { FetchLike } from '../src/http';
import { hostsFor, renderHosts } from '../src/hosts';
import { parseInitAnswers } from '../src/init/answers';
import { accessTablesFor, renderAccessMarkdown } from '../src/init/access-guide';
import { DEFAULT_INTEGRATIONS_INGEST_KEY_ENV, planInit } from '../src/init/plan';
import { collectAnswers, type PromptIo } from '../src/init/prompts';
import { resolveOutputs, scanAndDeliver } from '../src/outputs';
import { ingestUrl, postIntegrationsReport, postReport } from '../src/post';
import { rawPublicKeyHex } from '../src/report';
import { inflectTargets, integrationsIngestTarget, loadSigningKey, scanAndPost } from '../src/scan';
import { INGEST_PATH_TEMPLATE, INTEGRATIONS_INGEST_PATH_TEMPLATE, isDeclaredRequest, SCANNER_SURFACE } from '../src/scanner-surface';
import { resolveSecretEnv } from '../src/secrets';
import { INGEST } from './helpers/agent-harness-source-fakes';
import { INGEST_KEY_VALUE, SIGNING_PEM } from './helpers/doctor-world';
import { createEstateWorld, ESTATE_SOURCES, estateConfig, estateEnv, INTEGRATIONS_ESTATE_SOURCE, PUBLIC_RESOLVER, type EstateWorld } from './helpers/estate-world';
import { capturedLog } from './helpers/output-fixtures';
import { classifyRequest, configuredHostsOf, readOnlyProblems, recordRequests } from './helpers/request-recorder';
import { agentsOf } from './helpers/run-scan';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const PUBLIC = rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey);
/** Built at run time, so no key-shaped literal sits in the file. */
const INTEGRATIONS_KEY_VALUE = ['iflk', 'fake-integrations-key-0160'].join('_');
const KEY_ENV = 'INFLECT_INTEGRATIONS_KEY';

/** The fake estate's configuration, with an `inflect` block extended by `inflect`. */
function configWith(sources: readonly unknown[], inflect: Record<string, unknown> = {}, extra: Record<string, unknown> = {}): ScannerConfig {
    const c = estateConfig(sources, extra);
    return parseScannerConfig({ ...c, inflect: { ...(c.inflect as object), ...inflect } });
}

/** An integrations-only configuration posting to the tenant: no agent key named at all. */
function integrationsOnly(inflect: Record<string, unknown> = { integrationsApiKeyEnv: KEY_ENV }): ScannerConfig {
    const c = estateConfig([INTEGRATIONS_ESTATE_SOURCE], { outputs: [{ kind: 'inflect' }] });
    return parseScannerConfig({ ...c, inflect: { baseUrl: INGEST, tenantSlug: 'acme', ...inflect } });
}

const MIXED = () => configWith([ESTATE_SOURCES['entra-sp'], INTEGRATIONS_ESTATE_SOURCE], { integrationsApiKeyEnv: KEY_ENV });
const MIXED_NO_KEY = () => configWith([ESTATE_SOURCES['entra-sp'], INTEGRATIONS_ESTATE_SOURCE]);
const AGENTS_ONLY = () => configWith([ESTATE_SOURCES['entra-sp']]);
const envWithKey = (): Record<string, string> => ({ ...estateEnv(), [KEY_ENV]: INTEGRATIONS_KEY_VALUE });

async function deliver(config: ScannerConfig, env: Record<string, string>, world: EstateWorld = createEstateWorld()) {
    const logged = capturedLog();
    const result = await scanAndDeliver({ config, env, log: logged.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: [{ kind: 'inflect' }], loadInventory: () => null });
    return { result, logged, world };
}

describe('1. the route and the answer', () => {
    const base = { baseUrl: 'https://inflect.example.com/x?y=1', tenantSlug: 'acme', apiKey: 'second-key', raw: '{"contract":"scanent-integrations/1"}' };

    function answering(status: number, body: string) {
        const calls: { url: string; init: RequestInit }[] = [];
        const fetchImpl: FetchLike = async (url, init) => {
            calls.push({ url, init });
            return new Response(body, { status });
        };
        return { calls, fetchImpl };
    }

    it('posts the report unchanged to the integrations ingest on the base\'s origin, with its key as a bearer token', async () => {
        const { calls, fetchImpl } = answering(201, '{}');
        await postIntegrationsReport({ ...base, fetchImpl });
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe('https://inflect.example.com/api/t/acme/admin/agents/integration-scans');
        expect(calls[0].init).toMatchObject({
            method: 'POST',
            body: base.raw,
            redirect: 'error',
            headers: { Authorization: 'Bearer second-key', 'Content-Type': 'application/json', Accept: 'application/json' },
        });
        expect(ingestUrl(base.baseUrl, '../x', 'integrations')).toBe('https://inflect.example.com/api/t/..%2Fx/admin/agents/integration-scans');
        // The agent report's route is still the default.
        expect(ingestUrl(base.baseUrl, 'acme')).toBe('https://inflect.example.com/api/t/acme/admin/agents/harness-scans');
    });

    it('a 201 is ok, with the completeness and the applications the tenant counted, and nothing else of its body', async () => {
        const body = JSON.stringify({ scanId: 'row', scanRef: 'ref', complete: false, applicationCount: 7, findingsOpened: 1, findingsReopened: 0, findingsResolved: 2 });
        expect(await postIntegrationsReport({ ...base, fetchImpl: answering(201, body).fetchImpl })).toEqual({ ok: true, status: 201, refusal: null, complete: false, applicationCount: 7 });
        // A body that is not the tenant's shape claims nothing.
        for (const odd of ['', 'created', 'null', '{"complete":"yes","applicationCount":"7"}', '{"agentCount":3}']) {
            expect(await postIntegrationsReport({ ...base, fetchImpl: answering(201, odd).fetchImpl })).toEqual({ ok: true, status: 201, refusal: null, complete: null, applicationCount: null });
        }
    });

    it.each([
        [409, '{"error":{"message":"third_party_app_report_refused: REPLAY: scan x is already ingested"}}', 'REPLAY'],
        [400, '{"error":"third_party_app_report_refused: UNTRUSTED_SIGNER"}', 'UNTRUSTED_SIGNER'],
        [400, 'third_party_app_report_refused: SCANNER_MISMATCH: the report names a scanner other than…', 'SCANNER_MISMATCH'],
        [403, 'third_party_app_report_refused: SUBMITTER_MISMATCH: this credential…', 'SUBMITTER_MISMATCH'],
    ])('a %i refusal yields its code and nothing else of the body', async (status, body, code) => {
        expect(await postIntegrationsReport({ ...base, fetchImpl: answering(status, body).fetchImpl })).toEqual({ ok: false, status, refusal: code, complete: null, applicationCount: null });
    });

    it('each report reads only its own ingest\'s refusal prefix', async () => {
        const harness = answering(400, 'harness_report_refused: SIGNATURE').fetchImpl;
        const thirdParty = answering(400, 'third_party_app_report_refused: SIGNATURE').fetchImpl;
        expect((await postIntegrationsReport({ ...base, fetchImpl: harness })).refusal).toBeNull();
        expect((await postReport({ ...base, fetchImpl: thirdParty })).refusal).toBeNull();
        // A 403 without a code (a key without the scope) names none.
        expect(await postIntegrationsReport({ ...base, fetchImpl: answering(403, '{"error":"forbidden"}').fetchImpl })).toMatchObject({ ok: false, status: 403, refusal: null });
    });

    it('refuses a base that is not https before any request', async () => {
        const { calls, fetchImpl } = answering(201, '{}');
        await expect(postIntegrationsReport({ ...base, baseUrl: 'http://inflect.example.com', fetchImpl })).rejects.toThrow('the ingest must be reached over https');
        expect(calls).toEqual([]);
    });
});

describe('2. the surface: two posts, and no third', () => {
    it('declares exactly the two ingest routes, one per report', () => {
        expect(SCANNER_SURFACE.sends).toEqual([
            { method: 'POST', path: '/api/t/{tenantSlug}/admin/agents/harness-scans', report: 'agents' },
            { method: 'POST', path: '/api/t/{tenantSlug}/admin/agents/integration-scans', report: 'integrations' },
        ]);
        expect(INGEST_PATH_TEMPLATE).toBe('/api/t/{tenantSlug}/admin/agents/harness-scans');
        expect(INTEGRATIONS_INGEST_PATH_TEMPLATE).toBe('/api/t/{tenantSlug}/admin/agents/integration-scans');
    });

    it('a POST to either is declared', () => {
        expect(isDeclaredRequest('POST', 'https://inflect.example.com/api/t/acme/admin/agents/harness-scans')).toBe(true);
        expect(isDeclaredRequest('POST', 'https://inflect.example.com/api/t/acme/admin/agents/integration-scans')).toBe(true);
    });

    it.each([
        ['another ingest-shaped path', '/api/t/acme/admin/agents/other-scans'],
        ['the harness path one segment longer', '/api/t/acme/admin/agents/harness-scans/x'],
        ['the integrations path one segment longer', '/api/t/acme/admin/agents/integration-scans/x'],
        ['an empty tenant segment', '/api/t//admin/agents/integration-scans'],
        ['two tenant segments', '/api/t/acme/b/admin/agents/integration-scans'],
        ['the template itself', '/api/t/{tenantSlug}x/admin/agents/integration-scans/'],
        ['the list of scans', '/api/t/acme/admin/agents/integration-scans/list'],
        ['the singular', '/api/t/acme/admin/agents/integration-scan'],
    ])('a POST to %s is not', (_label, pathname) => {
        expect(isDeclaredRequest('POST', `https://inflect.example.com${pathname}`)).toBe(false);
    });

    it('nor is any other method to an ingest route', () => {
        for (const method of ['GET', 'PUT', 'PATCH', 'DELETE']) {
            expect(isDeclaredRequest(method, 'https://inflect.example.com/api/t/acme/admin/agents/integration-scans')).toBe(false);
        }
    });

    it('the recorder classifies the integrations post as an ingest post on the configured tenant only', () => {
        const hosts = configuredHostsOf(MIXED());
        const post = { method: 'POST', url: `${INGEST}/api/t/acme/admin/agents/integration-scans`, origin: INGEST, pathname: '/api/t/acme/admin/agents/integration-scans', headerNames: [], body: '{}', redirect: 'error' as const };
        expect(classifyRequest(post, hosts)).toBe('INGEST_POST');
        expect(classifyRequest({ ...post, origin: 'https://elsewhere.example', url: 'https://elsewhere.example/api/t/acme/admin/agents/integration-scans' }, hosts)).toBe('UNDECLARED');
    });
});

describe('3. the configuration', () => {
    const issues = (json: unknown): string[] => {
        try {
            parseScannerConfig(json);
        } catch (err) {
            if (err instanceof ConfigError) return [...err.issues];
            throw err;
        }
        return [];
    };

    it('the integrations key is optional, a variable NAME, and named among the credentials after the agent key', () => {
        expect(MIXED().inflect?.integrationsApiKeyEnv).toBe(KEY_ENV);
        expect(MIXED_NO_KEY().inflect?.integrationsApiKeyEnv).toBeUndefined();
        expect(credentialEnvNames(MIXED()).slice(0, 3)).toEqual(['SCANNER_SIGNING_KEY', 'INFLECT_INGEST_KEY', KEY_ENV]);
        expect(credentialEnvNames(MIXED_NO_KEY())).not.toContain(KEY_ENV);
        const c = estateConfig([ESTATE_SOURCES['entra-sp'], INTEGRATIONS_ESTATE_SOURCE]);
        expect(issues({ ...c, inflect: { ...(c.inflect as object), integrationsApiKeyEnv: 'lower-case' } })).toEqual(['inflect.integrationsApiKeyEnv: invalid_format']);
    });

    it('is a key of its own: the agent key\'s variable is refused', () => {
        const c = estateConfig([ESTATE_SOURCES['entra-sp'], INTEGRATIONS_ESTATE_SOURCE]);
        expect(issues({ ...c, inflect: { ...(c.inflect as object), integrationsApiKeyEnv: 'INFLECT_INGEST_KEY' } })).toEqual(['inflect.integrationsApiKeyEnv: custom']);
    });

    it('integrations sources alone post with the integrations key and need no agent key; without it, posting is refused', () => {
        expect(integrationsOnly().inflect?.apiKeyEnv).toBeUndefined();
        expect(inflectPosts(integrationsOnly())).toEqual({ agents: false, integrations: true, integrationsWithoutKey: false });
        expect(() => integrationsOnly({})).toThrow('outputs: custom');
        // With the file output, a tenant that only egress needs names no key at all.
        expect(parseScannerConfig({ ...estateConfig([INTEGRATIONS_ESTATE_SOURCE], { outputs: [{ kind: 'file', dir: '/out' }] }), inflect: { baseUrl: INGEST, tenantSlug: 'acme' } }).inflect).toEqual({ baseUrl: INGEST, tenantSlug: 'acme' });
    });

    it('the agent key is still required wherever the agent report is posted or the register read', () => {
        const noAgentKey = (sources: unknown[], extra: Record<string, unknown> = {}) => ({ ...estateConfig(sources, extra), inflect: { baseUrl: INGEST, tenantSlug: 'acme', integrationsApiKeyEnv: KEY_ENV } });
        expect(issues(noAgentKey([ESTATE_SOURCES['entra-sp'], INTEGRATIONS_ESTATE_SOURCE]))).toEqual(['inflect.apiKeyEnv: custom']);
        expect(issues(noAgentKey([{ kind: 'inflect-register' }, INTEGRATIONS_ESTATE_SOURCE], { outputs: [{ kind: 'file', dir: '/out' }] }))).toEqual(['inflect.apiKeyEnv: custom']);
        // Neither posted nor read: an agent source with only a file output names no key.
        expect(issues(noAgentKey([ESTATE_SOURCES['entra-sp']], { outputs: [{ kind: 'file', dir: '/out' }] }))).toEqual([]);
    });

    it('the key may come from its _FILE, as every credential may', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-integrations-key-'));
        try {
            const file = path.join(dir, 'key');
            fs.writeFileSync(file, `${INTEGRATIONS_KEY_VALUE}\n`, { mode: 0o600 });
            const { [KEY_ENV]: _direct, ...env } = envWithKey();
            const resolved = resolveSecretEnv(MIXED(), { ...env, [`${KEY_ENV}_FILE`]: file });
            expect(resolved[KEY_ENV]).toBe(INTEGRATIONS_KEY_VALUE);
            expect(integrationsIngestTarget(MIXED(), resolved)?.apiKey).toBe(INTEGRATIONS_KEY_VALUE);
            // Both forms at once is refused, as for any credential.
            expect(() => resolveSecretEnv(MIXED(), { ...envWithKey(), [`${KEY_ENV}_FILE`]: file })).toThrow(`${KEY_ENV}: both the variable and its _FILE form are set`);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('which keys a run asks for: each report\'s, and none for a report it does not post', () => {
        expect(inflectTargets(MIXED(), envWithKey())).toEqual({
            agents: { inflect: MIXED().inflect, apiKey: INGEST_KEY_VALUE },
            integrations: { inflect: MIXED().inflect, apiKey: INTEGRATIONS_KEY_VALUE },
        });
        expect(inflectTargets(MIXED_NO_KEY(), estateEnv()).integrations).toBeNull();
        expect(inflectTargets(integrationsOnly(), { [KEY_ENV]: INTEGRATIONS_KEY_VALUE }).agents).toBeNull();
        // An agents-only configuration that names the key does not need it set: there is no integrations report.
        expect(inflectTargets(configWith([ESTATE_SOURCES['entra-sp']], { integrationsApiKeyEnv: KEY_ENV }), estateEnv())).toEqual({ agents: { inflect: expect.any(Object), apiKey: INGEST_KEY_VALUE }, integrations: null });
        expect(integrationsIngestTarget(MIXED_NO_KEY(), estateEnv())).toBeNull();
        const { inflect: _inflect, ...noTenant } = estateConfig([INTEGRATIONS_ESTATE_SOURCE], { outputs: [{ kind: 'stdout' }] });
        expect(() => integrationsIngestTarget(parseScannerConfig(noTenant), estateEnv())).toThrow('the configuration has no inflect block to post to');
    });
});

describe('4. a run', () => {
    it('posts the integrations report to its ingest with the second key, after the agent report with the first', async () => {
        const { result, logged, world } = await deliver(MIXED(), envWithKey());
        expect(result).toMatchObject({ ok: true, delivered: [{ kind: 'inflect', ok: true }] });
        expect(world.fakes.posted).toEqual([agentsOf(result).raw]);
        expect(world.fakes.ingestAuth).toEqual([`Bearer ${INGEST_KEY_VALUE}`]);
        expect(world.fakes.integrationsPosted).toEqual([result.scan.integrations?.raw]);
        expect(world.fakes.integrationsIngestAuth).toEqual([`Bearer ${INTEGRATIONS_KEY_VALUE}`]);
        // What was posted is the signed report, byte for byte, and verifies under its contract.
        expect(verifyAndParseIntegrationsReport(world.fakes.integrationsPosted[0], [PUBLIC])).toMatchObject({ ok: true });
        const msgs = logged.lines().map((l) => l.msg);
        expect(msgs.indexOf('report ingested')).toBeLessThan(msgs.indexOf('integrations report ingested'));
        expect(logged.lines().find((l) => l.msg === 'integrations report ingested')).toEqual(
            expect.objectContaining({ level: 'info', scan: result.scan.scanId, complete: true, applications: 3 }),
        );
        expect(msgs).not.toContain('integrations report not posted');
        // Neither key reaches the log.
        expect(logged.text()).not.toContain(INTEGRATIONS_KEY_VALUE);
        expect(logged.text()).not.toContain(INGEST_KEY_VALUE);
    });

    it('with no integrations key configured, does not post that report and says so once, at info', async () => {
        const { result, logged, world } = await deliver(MIXED_NO_KEY(), estateEnv());
        expect(result.ok).toBe(true);
        expect(world.fakes.posted).toHaveLength(1);
        expect(world.fakes.integrationsPosted).toEqual([]);
        const said = logged.lines().filter((l) => l.msg === 'integrations report not posted');
        expect(said).toEqual([{ ts: expect.any(String), level: 'info', msg: 'integrations report not posted', scan: result.scan.scanId, reason: 'no integrations ingest key is configured (inflect.integrationsApiKeyEnv)' }]);
    });

    it('an integrations-only run posts that report alone, and needs no agent key', async () => {
        const env = { SCANNER_SIGNING_KEY: SIGNING_PEM, ENTRA_CLIENT_SECRET: estateEnv().ENTRA_CLIENT_SECRET, [KEY_ENV]: INTEGRATIONS_KEY_VALUE };
        const world = createEstateWorld();
        const recorder = recordRequests(world.fetchImpl);
        const { result, logged } = await deliver(integrationsOnly(), env, { ...world, fetchImpl: recorder.fetchImpl });
        expect(result.ok).toBe(true);
        expect(result.scan.agents).toBeNull();
        expect(world.fakes.posted).toEqual([]);
        expect(world.fakes.integrationsPosted).toEqual([result.scan.integrations?.raw]);
        // Every request on the declared surface; one post, the integrations ingest's.
        const hosts = configuredHostsOf(integrationsOnly());
        expect(readOnlyProblems(recorder.requests, hosts)).toEqual([]);
        expect(recorder.requests.filter((r) => r.method === 'POST' && r.origin === INGEST).map((r) => r.pathname)).toEqual(['/api/t/acme/admin/agents/integration-scans']);
        expect(logged.lines().map((l) => l.msg)).not.toContain('report ingested');
    });

    it('a configured integrations key that is not set stops the run before any source is read', async () => {
        const world = createEstateWorld();
        const logged = capturedLog();
        await expect(
            scanAndDeliver({ config: MIXED(), env: estateEnv(), log: logged.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: [{ kind: 'inflect' }], loadInventory: () => null }),
        ).rejects.toThrow(`the integrations ingest API key is not set (environment variable ${KEY_ENV})`);
        expect(world.log).toEqual([]);
        expect(logged.lines()).toEqual([]);
        // And with --dry-run, which posts nothing, it is not asked for.
        const dry = await scanAndDeliver({ config: MIXED(), env: estateEnv(), log: capturedLog().log, fetchImpl: createEstateWorld().fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: resolveOutputs(MIXED(), { dryRun: true }), stdout: () => undefined, loadInventory: () => null });
        expect(dry.ok).toBe(true);
    });

    it.each([
        ['a replay', 409, 'third_party_app_report_refused: REPLAY: scan x is already ingested', 'REPLAY'],
        ['an untrusted signer', 400, 'third_party_app_report_refused: UNTRUSTED_SIGNER', 'UNTRUSTED_SIGNER'],
        ['a key without the scope', 403, 'forbidden', null],
    ])('a refused integrations post (%s) is not a delivery; the agent report was still posted', async (_label, status, message, refusal) => {
        const world = createEstateWorld();
        world.fakes.integrationsIngest = () => ({ status, body: { error: { message } } });
        const { result, logged } = await deliver(MIXED(), envWithKey(), world);
        expect(result).toMatchObject({ ok: false, delivered: [{ kind: 'inflect', ok: false }] });
        expect(world.fakes.posted).toHaveLength(1);
        expect(logged.lines().find((l) => l.msg === 'report ingested')).toBeDefined();
        expect(logged.lines().filter((l) => l.level === 'error')).toEqual([
            expect.objectContaining({ msg: 'integrations report refused', scan: result.scan.scanId, status, refusal }),
        ]);
        // The tenant's text beyond its code is not logged.
        expect(logged.text()).not.toContain('already ingested');
    });

    it('an integrations post the wire could not make is one error line, and not a delivery', async () => {
        const world = createEstateWorld();
        const failing: FetchLike = async (url, init) => {
            if (url.endsWith('/integration-scans')) throw Object.assign(new TypeError('fetch failed https://inflect.example.com/api/t/acme'), { code: 'ECONNRESET' });
            return world.fetchImpl(url, init);
        };
        const { result, logged } = await deliver(MIXED(), envWithKey(), { ...world, fetchImpl: failing });
        expect(result).toMatchObject({ ok: false, delivered: [{ kind: 'inflect', ok: false }] });
        expect(world.fakes.posted).toHaveLength(1);
        expect(logged.lines().filter((l) => l.level === 'error')).toEqual([expect.objectContaining({ msg: 'integrations post failed', scan: result.scan.scanId, error: 'TypeError ECONNRESET' })]);
        expect(logged.text()).not.toContain('inflect.example.com/api');
    });

    it('an agent post the wire could not make still lets the integrations report be posted, and fails the output', async () => {
        const world = createEstateWorld();
        const failing: FetchLike = async (url, init) => {
            if (url.endsWith('/harness-scans')) throw new TypeError('fetch failed');
            return world.fetchImpl(url, init);
        };
        const { result, logged } = await deliver(MIXED(), envWithKey(), { ...world, fetchImpl: failing });
        expect(result).toMatchObject({ ok: false, delivered: [{ kind: 'inflect', ok: false }] });
        expect(world.fakes.integrationsPosted).toHaveLength(1);
        const msgs = logged.lines().map((l) => l.msg);
        expect(msgs.indexOf('integrations report ingested')).toBeLessThan(msgs.indexOf('output failed'));
        expect(logged.lines().filter((l) => l.level === 'error')).toEqual([expect.objectContaining({ msg: 'output failed', output: 'inflect', error: 'TypeError' })]);
    });

    it('an agents-only run sends what it always sent: one POST, to the agent ingest, the same request to the byte', async () => {
        for (const config of [AGENTS_ONLY(), configWith([ESTATE_SOURCES['entra-sp']], { integrationsApiKeyEnv: KEY_ENV })]) {
            const world = createEstateWorld();
            const calls: { url: string; init: RequestInit }[] = [];
            const recording: FetchLike = async (url, init) => {
                if (init.method === 'POST' && url.startsWith(INGEST)) calls.push({ url, init });
                return world.fetchImpl(url, init);
            };
            const { result, logged } = await deliver(config, estateEnv(), { ...world, fetchImpl: recording });
            expect(result.ok).toBe(true);
            // The request 0.15.0 made, member for member; the signal is a fresh timeout each time.
            expect(calls).toHaveLength(1);
            const { signal, ...init } = calls[0].init;
            expect(signal).toBeInstanceOf(AbortSignal);
            expect({ url: calls[0].url, init }).toEqual({
                url: `${INGEST}/api/t/acme/admin/agents/harness-scans`,
                init: {
                    method: 'POST',
                    headers: { Authorization: `Bearer ${INGEST_KEY_VALUE}`, 'Content-Type': 'application/json', Accept: 'application/json' },
                    body: agentsOf(result).raw,
                    redirect: 'error',
                },
            });
            expect(world.fakes.integrationsPosted).toEqual([]);
            // And the log is what it was: no integrations line at all.
            expect(logged.lines().map((l) => String(l.msg)).filter((m) => m.startsWith('integrations'))).toEqual([]);
            expect(logged.lines().at(-1)).toMatchObject({ msg: 'report ingested', complete: true, agents: 1 });
        }
    });
});

describe('5. the scheduled path', () => {
    it('scanAndPost posts both reports, each with its key, and reports each answer', async () => {
        const world = createEstateWorld();
        const result = await scanAndPost({ config: MIXED(), env: envWithKey(), log: capturedLog().log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
        expect(result).toEqual({
            ok: true,
            agents: { ok: true, status: 201, refusal: null, complete: true, agentCount: 1 },
            integrations: { ok: true, status: 201, refusal: null, complete: true, applicationCount: 3 },
        });
        expect(world.fakes.integrationsIngestAuth).toEqual([`Bearer ${INTEGRATIONS_KEY_VALUE}`]);
    });

    it('integrations-only: no agent key, one post; a refusal makes the run not ok', async () => {
        const env = { SCANNER_SIGNING_KEY: SIGNING_PEM, ENTRA_CLIENT_SECRET: estateEnv().ENTRA_CLIENT_SECRET, [KEY_ENV]: INTEGRATIONS_KEY_VALUE };
        const world = createEstateWorld();
        expect(await scanAndPost({ config: integrationsOnly(), env, log: capturedLog().log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW })).toMatchObject({ ok: true, agents: null, integrations: { ok: true } });
        expect(world.fakes.posted).toEqual([]);
        world.fakes.integrationsIngest = () => ({ status: 409, body: { error: 'third_party_app_report_refused: REPLAY' } });
        expect(await scanAndPost({ config: integrationsOnly(), env, log: capturedLog().log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW })).toMatchObject({ ok: false, integrations: { refusal: 'REPLAY' } });
    });

    it('without the integrations key, posts the agent report and says once that the other was not posted', async () => {
        const logged = capturedLog();
        const world = createEstateWorld();
        const result = await scanAndPost({ config: MIXED_NO_KEY(), env: estateEnv(), log: logged.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
        expect(result).toMatchObject({ ok: true, agents: { ok: true }, integrations: null });
        expect(logged.lines().filter((l) => l.msg === 'integrations report not posted')).toHaveLength(1);
        // A key configured and not set is asked for before the scan, as the agent key is.
        await expect(scanAndPost({ config: MIXED(), env: estateEnv(), log: capturedLog().log, fetchImpl: world.fetchImpl })).rejects.toThrow(KEY_ENV);
    });
});

describe('6. hosts and init', () => {
    it('hosts: the tenant is listed under each scanner whose report is posted to it', () => {
        const tenant = new URL(INGEST).hostname;
        const ingest = (config: ScannerConfig) => hostsFor(config).filter((e) => e.source === 'inflect').map((e) => e.scanner);
        expect(ingest(MIXED())).toEqual(['agents', 'integrations']);
        expect(ingest(MIXED_NO_KEY())).toEqual(['agents']);
        expect(ingest(integrationsOnly())).toEqual(['integrations']);
        expect(renderHosts(hostsFor(integrationsOnly()), 'lines')).toBe(`# integrations scanner\ngraph.microsoft.com:443\n${tenant}:443\nlogin.microsoftonline.com:443\n`);
        // One host, once, for the proxy.
        expect(renderHosts(hostsFor(MIXED()), 'egress-allow').split(',').filter((h) => h.trim() === tenant)).toHaveLength(1);
    });

    const answers = (inflect: Record<string, unknown>, sources: unknown[] = [{ kind: 'entra-integrations', directoryId: '11111111-2222-4333-8444-555555555555', clientId: '66666666-7777-4888-8999-aaaaaaaaaaaa' }]) =>
        parseInitAnswers({ answers: 'scanent-init-answers/1', estate: 'acme-apps', sources, inflect: { baseUrl: INGEST, tenantSlug: 'acme', agentId: 'agt_scanner_acme', ...inflect } });

    it('init plans an integrations-only tenant with the integrations key alone, and names it in the template and the access tables', () => {
        const plan = planInit(answers({ integrationsApiKeyEnv: DEFAULT_INTEGRATIONS_INGEST_KEY_ENV }));
        expect(JSON.parse(plan.configText).inflect).toEqual({ baseUrl: INGEST, tenantSlug: 'acme', integrationsApiKeyEnv: 'INFLECT_INTEGRATIONS_KEY' });
        expect(plan.credentialNames.map((c) => c.name)).toEqual(['SCANNER_SIGNING_KEY', 'INFLECT_INTEGRATIONS_KEY', 'ENTRA_INTEGRATIONS_CLIENT_SECRET']);
        expect(plan.envTemplate).toContain('# Inflect: a second API key, with admin:integrations_ingest and no other scope. It posts the integrations report.\nINFLECT_INTEGRATIONS_KEY=\n');
        expect(plan.envTemplate).not.toContain('INFLECT_INGEST_KEY');
        expect(accessTablesFor(plan.config).map((t) => t.kind)).toEqual(['entra-integrations', 'inflect-integrations']);
        expect(accessTablesFor(plan.config)[1]).toMatchObject({ credential: 'INFLECT_INTEGRATIONS_KEY', hosts: [new URL(INGEST).hostname] });
        // Without the key the answers plan no configuration: there would be nothing to post.
        expect(() => planInit(answers({}))).toThrow('outputs: custom');
    });

    it('init beside an agent source: the integrations key only when asked for, never the agent key\'s variable', () => {
        const agentAndIntegrations = [{ kind: 'code', roots: [{ label: 'a', path: '/estate' }] }, { kind: 'entra-integrations', directoryId: '11111111-2222-4333-8444-555555555555', clientId: '66666666-7777-4888-8999-aaaaaaaaaaaa' }];
        const without = planInit(answers({}, agentAndIntegrations));
        expect(JSON.parse(without.configText).inflect).toEqual({ baseUrl: INGEST, tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' });
        expect(accessTablesFor(without.config).map((t) => t.kind)).toEqual(['code', 'inflect-register', 'entra-integrations']);
        const withKey = planInit(answers({ integrationsApiKeyEnv: 'TENANT_APPS_KEY' }, agentAndIntegrations));
        expect(JSON.parse(withKey.configText).inflect).toEqual({ baseUrl: INGEST, tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY', integrationsApiKeyEnv: 'TENANT_APPS_KEY' });
        expect(withKey.credentialNames.map((c) => c.name)).toEqual(['SCANNER_SIGNING_KEY', 'INFLECT_INGEST_KEY', 'TENANT_APPS_KEY', 'ENTRA_INTEGRATIONS_CLIENT_SECRET']);
        expect(() => planInit(answers({ integrationsApiKeyEnv: 'INFLECT_INGEST_KEY' }, agentAndIntegrations))).toThrow('inflect.integrationsApiKeyEnv: custom');
    });

    it('docs/access.md has the integrations key\'s own section, after the integrations sources', () => {
        const md = renderAccessMarkdown();
        expect(md.indexOf('### An Inflect tenant (posting the integrations report)')).toBeGreaterThan(md.indexOf('Source kind: `github-integrations`'));
        expect(md).toContain('**Grant.** A second API key bound to the scanner agent, with the admin:integrations_ingest scope and no other.');
        expect(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'docs', 'access.md'), 'utf8')).toBe(md);
    });

    /** Answers in order; running out fails the test. */
    function script(lines: readonly string[]): { io: PromptIo; asked: string[]; said: string[] } {
        const queue = [...lines];
        const asked: string[] = [];
        const said: string[] = [];
        return {
            asked,
            said,
            io: {
                ask: async (q) => {
                    asked.push(q);
                    if (queue.length === 0) throw new Error(`no answer scripted for: ${q}`);
                    return queue.shift() as string;
                },
                say: (t) => void said.push(t),
            },
        };
    }
    const DIRECTORY = '11111111-2222-4333-8444-555555555555';
    const CLIENT = '66666666-7777-4888-8999-aaaaaaaaaaaa';
    /** No agent source; Entra's integrations on its own; the three output questions blank. */
    const INTEGRATIONS_ONLY_LINES = ['acme-apps', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', DIRECTORY, CLIENT, 'n', 'n', 'n', '', '', ''];

    it('init at the prompts, integrations alone: posting is asked about, and the key\'s variable NAME is asked for, never its value', async () => {
        const s = script([...INTEGRATIONS_ONLY_LINES, 'y', 'https://tenant.example.com', 'acme', 'agt_scanner_acme', '']);
        const got = await collectAnswers(s.io);
        expect(got.inflect).toEqual({ baseUrl: 'https://tenant.example.com', tenantSlug: 'acme', agentId: 'agt_scanner_acme', readRegister: false, integrationsApiKeyEnv: 'INFLECT_INTEGRATIONS_KEY' });
        expect(s.asked.find((q) => q.startsWith('Post the integrations report to an Inflect tenant?'))).toBeDefined();
        expect(s.asked.find((q) => q.includes("integrations report's API key"))).toContain('a variable NAME, never the key');
        // The register is the agent scanner's, and the agent key is not mentioned.
        expect(s.asked.join('\n')).not.toContain('agent register');
        expect(s.said).toContain('The API key is not asked for here: it goes in INFLECT_INTEGRATIONS_KEY.');
        expect(s.said.join('\n')).not.toContain('INFLECT_INGEST_KEY');
        expect(JSON.parse(planInit(got).configText).inflect).toEqual({ baseUrl: 'https://tenant.example.com', tenantSlug: 'acme', integrationsApiKeyEnv: 'INFLECT_INTEGRATIONS_KEY' });
    });

    it('init at the prompts: a key-shaped answer to the name is refused and asked again, and a name of one\'s own is kept', async () => {
        const pasted = ['iflk', 'D4'.repeat(16)].join('_');
        const s = script([...INTEGRATIONS_ONLY_LINES, 'y', 'https://tenant.example.com', 'acme', 'agt_scanner_acme', pasted, 'not a name', 'APPS_INGEST_KEY']);
        const got = await collectAnswers(s.io);
        expect(got.inflect?.integrationsApiKeyEnv).toBe('APPS_INGEST_KEY');
        expect(s.said.join('\n')).not.toContain(pasted);
        expect(s.said).toContain('An environment variable name: capital letters, digits and underscores, starting with a letter.');
    });

    it('init at the prompts, beside an agent source: posting the integrations report is a choice, and its key is not the agent key', async () => {
        // entra-sp with its integrations source read by the same application; the rest of the kinds declined.
        const lines = (post: string[]) => [
            'acme-prod', 'y', DIRECTORY, CLIENT, 'y', 'y', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n', '', '', '',
            'y', 'https://tenant.example.com', 'acme', 'agt_scanner_acme', 'n', ...post,
        ];
        const declined = await collectAnswers(script(lines(['n'])).io);
        expect(declined.inflect).toEqual({ baseUrl: 'https://tenant.example.com', tenantSlug: 'acme', agentId: 'agt_scanner_acme', readRegister: false });
        const s = script(lines(['y', 'INFLECT_INGEST_KEY', '']));
        const chosen = await collectAnswers(s.io);
        expect(chosen.inflect?.integrationsApiKeyEnv).toBe('INFLECT_INTEGRATIONS_KEY');
        expect(s.said).toContain('A variable of its own, not INFLECT_INGEST_KEY: a key minted for one report does not post the other.');
        expect(JSON.parse(planInit(chosen).configText).inflect).toMatchObject({ apiKeyEnv: 'INFLECT_INGEST_KEY', integrationsApiKeyEnv: 'INFLECT_INTEGRATIONS_KEY' });
    });
});
