/**
 * Proxy and certificate-authority support, at the wire:
 *
 *   1. An untrusted certificate is still UNREACHABLE in the report, and says
 *      why in its message.
 *   2. A proxy in the environment does not weaken the host guard: a
 *      customer-named host is re-resolved before every request, as before.
 *   3. The wire's errors carry the HTTP status where there was one.
 */
import { generateKeyPairSync } from 'crypto';

import { parseScannerConfig } from '../src/config';
import { CERTIFICATE_ERROR_CODES, createSourceWire, TLS_NOT_TRUSTED, type FetchLike } from '../src/http';
import { jsonLineLog } from '../src/log';
import { runScan } from '../src/scan';
import { SourceReadError } from '../src/source';
import { createSourceFakes, LANGSMITH_API_KEY_VALUE, LANGSMITH_SELF_HOSTED, langSmithFixture, MCP_CRM, MCP_TICKETS, MCP_TOKEN_VALUE } from './helpers/agent-harness-source-fakes';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const PEM = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const wireOver = (fetchImpl: FetchLike) => createSourceWire({ fetchImpl, deadline: NOW + 60_000, now: () => NOW });
const caught = async (p: Promise<unknown>): Promise<SourceReadError> => {
    try {
        await p;
    } catch (err) {
        if (err instanceof SourceReadError) return err;
        throw err;
    }
    throw new Error('did not throw');
};

describe('1. an untrusted certificate', () => {
    it.each(CERTIFICATE_ERROR_CODES)('%s is UNREACHABLE, with the TLS message', async (code) => {
        const { http, tokens } = wireOver(async () => {
            throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('certificate'), { code }) });
        });
        const read = await caught(http.getJson('https://acme.okta.com/api/v1/apps', { origin: 'https://acme.okta.com', headers: {} }));
        expect([read.reason, read.message, read.status]).toEqual(['UNREACHABLE', TLS_NOT_TRUSTED, undefined]);
        const exchange = await caught(tokens.clientCredentials({ tokenUrl: 'https://login.microsoftonline.com/t/oauth2/v2.0/token', origin: 'https://login.microsoftonline.com', clientId: 'c', clientSecret: 's', scope: 'x' }));
        expect([exchange.reason, exchange.message]).toEqual(['UNREACHABLE', TLS_NOT_TRUSTED]);
    });

    it('any other failed request keeps the message it had', async () => {
        const { http } = wireOver(async () => {
            throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
        });
        const err = await caught(http.getJson('https://acme.okta.com/x', { origin: 'https://acme.okta.com', headers: {} }));
        expect([err.reason, err.message]).toEqual(['UNREACHABLE', 'the request did not complete']);
    });

    it('the report is unchanged: the source is INCOMPLETE UNREACHABLE, as for any unreachable host', async () => {
        const config = parseScannerConfig({
            estate: 'acme',
            scanner: { agentId: 'agt', signingKeyEnv: 'K' },
            outputs: [{ kind: 'stdout' }],
            schedule: { everyHours: 24 },
            sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiTokenEnv: 'OKTA' }],
        });
        const { body } = await runScan({
            config,
            env: { K: PEM, OKTA: 'v' },
            log: jsonLineLog(() => undefined),
            now: () => NOW,
            fetchImpl: async () => {
                throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'SELF_SIGNED_CERT_IN_CHAIN' } });
            },
        });
        expect(body.population.sources).toEqual([{ kind: 'okta-app', status: 'INCOMPLETE', reason: 'UNREACHABLE', rows: 0 }]);
    });
});

describe('2. a proxy in the environment does not weaken the host guard', () => {
    it('each customer-named host is re-resolved before every request to it', async () => {
        const fakes = createSourceFakes({ langsmith: { [LANGSMITH_SELF_HOSTED]: { ...langSmithFixture(), selfHosted: true } } });
        const events: string[] = [];
        const config = parseScannerConfig({
            estate: 'acme',
            scanner: { agentId: 'agt', signingKeyEnv: 'K' },
            outputs: [{ kind: 'stdout' }],
            schedule: { everyHours: 24 },
            sources: [
                { kind: 'runtime', product: 'langsmith', endpoint: { selfHosted: LANGSMITH_SELF_HOSTED }, apiKeyEnv: 'LS', readDeployments: true },
                { kind: 'mcp', servers: [{ label: 'crm', url: MCP_CRM }, { label: 'tickets', url: MCP_TICKETS, readTokenEnv: 'MCP' }] },
            ],
        });
        const { body } = await runScan({
            config,
            // The proxy variables as a deployment behind a proxy has them.
            env: { K: PEM, LS: LANGSMITH_API_KEY_VALUE, MCP: MCP_TOKEN_VALUE, HTTPS_PROXY: 'http://proxy.corp.example:3128', NODE_USE_ENV_PROXY: '1' },
            log: jsonLineLog(() => undefined),
            now: () => NOW,
            fetchImpl: async (url, init) => {
                events.push(`request ${new URL(url).hostname}`);
                return fakes.fetchImpl(url, init);
            },
            resolveHost: async (host) => {
                events.push(`resolve ${host}`);
                return ['93.184.216.34'];
            },
        });
        expect(body.population.sources.map((s) => s.status)).toEqual(['COMPLETE', 'COMPLETE']);
        // Per host, since the sources run side by side: no request without a resolution of its host since the last one.
        for (const host of ['langsmith.acme.example', 'mcp.acme.example']) {
            const own = events.filter((e) => e.endsWith(` ${host}`));
            const requests = own.filter((e) => e.startsWith('request')).length;
            expect(requests).toBeGreaterThan(1);
            expect(own.filter((e) => e.startsWith('resolve')).length).toBeGreaterThanOrEqual(host === 'mcp.acme.example' ? 4 : requests);
        }
        const ls = events.filter((e) => e.endsWith(' langsmith.acme.example'));
        ls.forEach((e, i) => {
            if (e.startsWith('request')) expect(ls[i - 1]).toBe('resolve langsmith.acme.example');
        });
    });

    it('a customer-named host that resolves to a private address is refused with the proxy set, as without', async () => {
        const fakes = createSourceFakes();
        const config = parseScannerConfig({
            estate: 'acme',
            scanner: { agentId: 'agt', signingKeyEnv: 'K' },
            outputs: [{ kind: 'stdout' }],
            schedule: { everyHours: 24 },
            sources: [{ kind: 'mcp', servers: [{ label: 'crm', url: MCP_CRM }] }],
        });
        let requests = 0;
        const { body } = await runScan({
            config,
            env: { K: PEM, HTTPS_PROXY: 'http://proxy.corp.example:3128', NODE_USE_ENV_PROXY: '1' },
            log: jsonLineLog(() => undefined),
            now: () => NOW,
            fetchImpl: async (url, init) => {
                requests += 1;
                return fakes.fetchImpl(url, init);
            },
            resolveHost: async () => ['10.0.0.7'],
        });
        expect(body.population.sources).toEqual([{ kind: 'mcp', status: 'INCOMPLETE', reason: 'UNREACHABLE', rows: 0 }]);
        expect(requests).toBe(0);
    });
});

describe('3. the status a source answered with', () => {
    it.each([
        [401, 'AUTH_FAILED'],
        [403, 'AUTH_FAILED'],
        [429, 'RATE_LIMITED'],
        [503, 'UNREACHABLE'],
    ])('a read answered %i carries it, with the reason it always had', async (status, reason) => {
        const { http } = wireOver(async () => new Response('{}', { status }));
        const err = await caught(http.getJson('https://acme.okta.com/x', { origin: 'https://acme.okta.com', headers: {} }));
        expect([err.reason, err.status]).toEqual([reason, status]);
    });

    it('a refused token exchange carries it too, and an error with no response carries none', async () => {
        const refused = wireOver(async () => new Response('{}', { status: 400 }));
        const err = await caught(refused.tokens.jwtBearer({ tokenUrl: 'https://oauth2.googleapis.com/token', origin: 'https://oauth2.googleapis.com', assertion: 'a' }));
        expect([err.reason, err.status]).toEqual(['AUTH_FAILED', 400]);
        expect(new SourceReadError('TIME_BOX', 'x').status).toBeUndefined();
    });
});
