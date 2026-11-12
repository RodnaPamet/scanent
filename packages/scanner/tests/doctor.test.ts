/**
 * `scanent doctor` against a whole fake estate: what it reports for a healthy
 * one, for each way a source can fail, and what it never does.
 *
 *   1. A healthy estate is ready, and says what it could not observe.
 *   2. Each failure lands on the check that names it, and what could not be
 *      checked behind it is BLOCKED, never passed and never left out.
 *   3. Write access is reported only where a declared read shows it.
 *   4. It reads only: every request is on the declared surface, nothing is
 *      posted, and the manifest hash is what it was.
 *   5. No credential reaches the table, the JSON or the log.
 *   6. The exit code, row by row.
 */
import { accessSync, chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { main } from '../src/cli';
import type { DoctorFs } from '../src/doctor/local';
import { renderDoctorJson, renderDoctorText, summaryLine } from '../src/doctor/render';
import { runDoctor, type DoctorDeps } from '../src/doctor/run';
import { assertWellFormed, doctorExitCode, isReady, type Check, type DoctorReport } from '../src/doctor/types';
import { isDeclaredMcpMessage, isDeclaredRegisterExchange, isDeclaredRegisterMessage, isDeclaredRequest, scannerManifestHash } from '../src/scanner-surface';
import { INGEST, MCP_CRM, MCP_TICKETS, NEVER_REPORTED } from './helpers/agent-harness-source-fakes';
import { CODE_ROOT, createDoctorWorld, fullEstateConfig, fullEstateEnv, GCP_PROJECT, GITHUB_REPO, WORLD_SECRETS, type DoctorWorld } from './helpers/doctor-world';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
/** The manifest hash before this phase: `doctor` adds no request, so it must not move. */
const MANIFEST_BEFORE_PHASE_3 = scannerManifestHash();

let dir: string;
let configPath: string;
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-doctor-'));
    mkdirSync(join(dir, 'out'), { mode: 0o700 });
    configPath = join(dir, 'config.json');
    writeFileSync(configPath, JSON.stringify(fullEstateConfig(join(dir, 'out'))), { mode: 0o600 });
    chmodSync(configPath, 0o600);
});
afterEach(() => {
    jest.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
});

/** The real file system, except that the code root is mounted read-only as far as `access` can tell. */
const FS: DoctorFs = {
    readFile: (p) => readFileSync(p),
    stat: (p) => statSync(p),
    lstat: (p) => lstatSync(p),
    access: (p, mode) => {
        if (p === CODE_ROOT && (mode & 2) !== 0) throw Object.assign(new Error('EROFS'), { code: 'EROFS' });
        accessSync(p, mode);
    },
};

const all: DoctorReport[] = [];
async function doctor(world: DoctorWorld, over: Partial<DoctorDeps> = {}): Promise<DoctorReport> {
    const report = await runDoctor({
        configPath,
        env: fullEstateEnv(),
        fetchImpl: world.fetchImpl,
        resolveHost: async () => ['93.184.216.34'],
        fs: FS,
        now: () => NOW,
        nodeVersion: 'v24.1.0',
        uid: 1000,
        ...over,
    });
    all.push(report);
    return report;
}

const of = (report: DoctorReport, scope: string, id: string): Check => {
    const found = report.checks.filter((c) => c.scope === scope && c.id === id);
    expect(found).toHaveLength(1);
    return found[0];
};
const statuses = (report: DoctorReport, scope: string) => Object.fromEntries(report.checks.filter((c) => c.scope === scope).map((c) => [c.id, c.status === 'SKIPPED' ? c.cause : c.status]));
const SOURCE_IDS = ['credential.present', 'host.resolves', 'reachable', 'authenticated', 'read.permitted', 'write.absent'];
const NETWORK_SCOPES = ['entra-sp', 'okta-app', 'vault', 'cicd', 'gcp-sa', 'runtime', 'mcp:crm', 'mcp:tickets', 'inflect-register'];

describe('1. a healthy estate', () => {
    it('is ready: every read passed, and what cannot be observed says so', async () => {
        const world = createDoctorWorld();
        world.date = new Date(NOW + 2_000).toUTCString();
        const report = await doctor(world);

        expect(report.checks.filter((c) => c.status === 'FAIL' || c.status === 'WARN')).toEqual([]);
        expect(report.checks.filter((c) => c.status === 'SKIPPED' && c.cause === 'BLOCKED')).toEqual([]);
        expect(report).toMatchObject({ doctor: 'scanent-doctor/1', estate: 'acme-prod', ready: true, exitCode: 0, at: '2026-10-19T03:00:00.000Z' });

        for (const scope of NETWORK_SCOPES) {
            expect(report.checks.filter((c) => c.scope === scope).map((c) => c.id)).toEqual(SOURCE_IDS);
            expect(statuses(report, scope)).toMatchObject({ reachable: 'PASS', authenticated: 'PASS', 'read.permitted': 'PASS', 'write.absent': 'NOT_OBSERVABLE' });
        }
        // A server that takes no token has no credential to be present.
        expect(statuses(report, 'mcp:crm')['credential.present']).toBe('NOT_APPLICABLE');
        expect(of(report, 'mcp:tickets', 'credential.present')).toMatchObject({ status: 'PASS', detail: 'MCP_TICKETS_TOKEN' });
        expect(of(report, 'entra-sp', 'read.permitted').detail).toBe('2 reads');
        expect(of(report, 'vault', 'read.permitted').detail).toBe('2 reads');
        expect(of(report, 'cicd', 'read.permitted').detail).toBe('3 reads');
        expect(of(report, 'entra-sp', 'reachable').detail).toBe('login.microsoftonline.com, graph.microsoft.com');

        expect(statuses(report, 'code')).toEqual({
            'credential.present': 'NOT_APPLICABLE',
            'host.resolves': 'NOT_APPLICABLE',
            reachable: 'NOT_APPLICABLE',
            authenticated: 'NOT_APPLICABLE',
            'read.permitted': 'PASS',
            'write.absent': 'PASS',
        });
        // The ingest: the key is there, and nothing is posted to find out more.
        expect(statuses(report, 'inflect')).toEqual({ 'credential.present': 'PASS', 'post.permitted': 'NOT_OBSERVABLE' });

        expect(statuses(report, 'local')).toEqual({
            'config.valid': 'PASS',
            'config.mode': 'PASS',
            'signing-key': 'PASS',
            'secret-files': 'NOT_APPLICABLE',
            'output.dir': 'PASS',
            inventory: 'NOT_APPLICABLE',
            'tls.verification': 'PASS',
            'tls.extra-ca': 'NOT_APPLICABLE',
            proxy: 'NOT_APPLICABLE',
            'proxy.customer-hosts': 'NOT_APPLICABLE',
            clock: 'PASS',
            egress: 'NOT_APPLICABLE',
        });
        expect(of(report, 'local', 'signing-key').detail).toMatch(/^ed25519 [0-9a-f]{64}$/);
        expect(of(report, 'local', 'output.dir').detail).toContain('nothing was written');
        expect(of(report, 'local', 'clock').detail).toMatch(/^2 seconds from the sources' clocks/);

        // It says what was not checked; it does not say everything passed.
        const summary = summaryLine(report);
        expect(summary).toMatch(/not observable/);
        expect(summary).toMatch(/Ready\. \d+ checks were not checked/);
        expect(summary).not.toMatch(/all checks passed/);
    });

    it('--source limits the source checks; the local checks still run', async () => {
        const report = await doctor(createDoctorWorld(), { only: ['okta-app', 'code'] });
        expect([...new Set(report.checks.map((c) => c.scope))]).toEqual(['local', 'okta-app', 'code']);
        expect(report.checks.filter((c) => c.scope === 'local')).toHaveLength(12);
    });
});

describe('2. each failure lands on its own check, and blocks what is behind it', () => {
    it('a missing credential: the variable is named, and nothing is sent for that source', async () => {
        const world = createDoctorWorld();
        const env = { ...fullEstateEnv(), OKTA_API_TOKEN: '', MCP_TICKETS_TOKEN: undefined };
        const report = await doctor(world, { env });
        expect(of(report, 'okta-app', 'credential.present')).toMatchObject({ status: 'FAIL', class: 'CREDENTIAL', fix: 'Set OKTA_API_TOKEN or OKTA_API_TOKEN_FILE.' });
        expect(statuses(report, 'okta-app')).toEqual({
            'credential.present': 'FAIL',
            'host.resolves': 'BLOCKED',
            reachable: 'BLOCKED',
            authenticated: 'BLOCKED',
            'read.permitted': 'BLOCKED',
            'write.absent': 'BLOCKED',
        });
        expect(world.log.some((r) => r.host === 'acme.okta.com')).toBe(false);
        // One MCP server's missing token does not hide the other server.
        expect(statuses(report, 'mcp:tickets')['credential.present']).toBe('FAIL');
        expect(world.log.some((r) => r.path === new URL(MCP_TICKETS).pathname)).toBe(false);
        expect(statuses(report, 'mcp:crm')['read.permitted']).toBe('PASS');
        expect(report.exitCode).toBe(5);
        expect(report.ready).toBe(false);
    });

    it('a 401: authenticated fails, and the reads behind it are blocked', async () => {
        const world = createDoctorWorld();
        const report = await doctor(world, { env: { ...fullEstateEnv(), OKTA_API_TOKEN: 'wrong-okta-token-value', ENTRA_CLIENT_SECRET: 'wrong-entra-secret-value' } });
        expect(statuses(report, 'okta-app')).toMatchObject({ reachable: 'PASS', authenticated: 'FAIL', 'read.permitted': 'BLOCKED', 'write.absent': 'BLOCKED' });
        expect(of(report, 'okta-app', 'authenticated')).toMatchObject({ class: 'CREDENTIAL', detail: 'the credential was refused (HTTP 401)' });
        // A refused token exchange is the same failure.
        expect(statuses(report, 'entra-sp')).toMatchObject({ reachable: 'PASS', authenticated: 'FAIL', 'read.permitted': 'BLOCKED' });
        expect(world.log.some((r) => r.host === 'graph.microsoft.com')).toBe(false);
        expect(report.exitCode).toBe(5);
    });

    it('a 403 on a read: the credential was accepted, the permission is missing, and the fix is the grant', async () => {
        const world = createDoctorWorld();
        world.override = (r) => (r.host === 'graph.microsoft.com' && r.path === '/v1.0/servicePrincipals' ? { status: 403, body: { error: { code: 'Authorization_RequestDenied' } } } : undefined);
        const report = await doctor(world);
        expect(statuses(report, 'entra-sp')).toMatchObject({ authenticated: 'PASS', 'read.permitted': 'FAIL', 'write.absent': 'BLOCKED' });
        expect(of(report, 'entra-sp', 'read.permitted')).toMatchObject({
            class: 'CREDENTIAL',
            detail: 'servicePrincipals: refused (HTTP 403)',
            fix: 'Grant: Microsoft Graph application permission Application.Read.All, with admin consent.',
        });
        expect(report.exitCode).toBe(5);
    });

    it('a request that never completes: reachable fails with the host, and the exit code is the network\'s', async () => {
        const world = createDoctorWorld();
        world.override = (r) => (r.host === 'api.github.com' ? 'throw' : undefined);
        const report = await doctor(world);
        expect(statuses(report, 'cicd')).toMatchObject({ reachable: 'FAIL', authenticated: 'BLOCKED', 'read.permitted': 'BLOCKED', 'write.absent': 'BLOCKED' });
        expect(of(report, 'cicd', 'reachable')).toMatchObject({ class: 'NETWORK', detail: 'api.github.com gave no answer (UNREACHABLE)' });
        expect((of(report, 'cicd', 'reachable') as { fix: string }).fix).toContain('Open outbound TCP 443 to api.github.com');
        expect(report.exitCode).toBe(6);
    });

    it('behind a proxy, the fix for an unreachable host names the proxy', async () => {
        const world = createDoctorWorld();
        world.override = (r) => (r.host === 'api.github.com' ? 'throw' : undefined);
        const report = await doctor(world, { env: { ...fullEstateEnv(), HTTPS_PROXY: 'http://proxy.corp.example:3128', NODE_USE_ENV_PROXY: '1', NO_PROXY: 'mcp.acme.example' } });
        expect((of(report, 'cicd', 'reachable') as { fix: string }).fix).toBe('Allow api.github.com:443 at the proxy, and check the proxy itself is reachable.');
        // A fixed host behind the proxy is resolved by the proxy, not here.
        expect(of(report, 'cicd', 'host.resolves')).toMatchObject({ status: 'SKIPPED', cause: 'NOT_APPLICABLE' });
        expect(of(report, 'local', 'proxy')).toMatchObject({ status: 'PASS', detail: 'requests go through proxy.corp.example:3128' });
        expect(of(report, 'local', 'proxy.customer-hosts').status).toBe('PASS');
    });

    it('an untrusted certificate is told apart, and the fix is the CA', async () => {
        const world = createDoctorWorld();
        const original = world.fetchImpl;
        const fetchImpl: typeof original = async (url, init) => {
            if (new URL(url).host === 'acme.okta.com') throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'SELF_SIGNED_CERT_IN_CHAIN' } });
            return original(url, init);
        };
        const report = await doctor(world, { fetchImpl });
        expect(of(report, 'okta-app', 'reachable')).toMatchObject({
            status: 'FAIL',
            class: 'NETWORK',
            detail: 'acme.okta.com: the TLS certificate was not trusted',
            fix: 'Mount your CA and set NODE_EXTRA_CA_CERTS.',
        });
    });

    it('a 429: nothing is claimed either way, and the run is incomplete rather than failed', async () => {
        const world = createDoctorWorld();
        world.override = (r) => (r.host === 'acme.okta.com' ? { status: 429 } : undefined);
        const report = await doctor(world, { only: ['okta-app'] });
        expect(statuses(report, 'okta-app')).toMatchObject({ reachable: 'PASS', authenticated: 'BLOCKED', 'read.permitted': 'BLOCKED', 'write.absent': 'BLOCKED' });
        expect(of(report, 'okta-app', 'read.permitted').detail).toBe('rate limited; run again later');
        expect(report.exitCode).toBe(3);
        expect(summaryLine(report)).toMatch(/Not ready: some checks were blocked/);
    });

    it('a 429 after the first read: the credential is known good, the permission is not', async () => {
        const world = createDoctorWorld();
        world.override = (r) => (r.host === 'acme.okta.com' && r.path === '/api/v1/apps' ? { status: 429 } : undefined);
        const report = await doctor(world, { only: ['okta-app'] });
        expect(statuses(report, 'okta-app')).toMatchObject({ authenticated: 'PASS', 'read.permitted': 'BLOCKED', 'write.absent': 'BLOCKED' });
        expect(report.exitCode).toBe(3);
    });

    it('the time box ending part-way is not an unreachable host: what was not reached is blocked', async () => {
        const world = createDoctorWorld();
        let calls = 0;
        // The clock jumps past the 30-second box once the first two requests have been started.
        const report = await doctor(world, { only: ['cicd'], now: () => (calls++ < 4 ? NOW : NOW + 31_000) });
        expect(world.log).toHaveLength(2);
        expect(statuses(report, 'cicd')).toMatchObject({ reachable: 'PASS', authenticated: 'PASS', 'read.permitted': 'BLOCKED', 'write.absent': 'BLOCKED' });
        expect(of(report, 'cicd', 'read.permitted').detail).toMatch(/^the preflight's 30-second time box ended after 2 requests/);
        expect(report.exitCode).toBe(3);
    });

    it('a time box that ends before anything answered is a host that gave no answer', async () => {
        let calls = 0;
        const report = await doctor(createDoctorWorld(), { only: ['cicd'], now: () => (calls++ < 2 ? NOW : NOW + 31_000) });
        expect(of(report, 'cicd', 'reachable')).toMatchObject({ status: 'FAIL', class: 'NETWORK', detail: 'api.github.com gave no answer (TIME_BOX)' });
    });

    it('a server error, and an answer that is not the API\'s, fail the read without blaming the credential', async () => {
        const world = createDoctorWorld();
        world.override = (r) =>
            r.host === 'acme.okta.com' ? { status: 503 } : r.host === 'acme-agents.vault.azure.net' && r.path === '/certificates' ? { status: 200, body: 'not a listing', headers: { 'content-type': 'text/html' } } : undefined;
        const report = await doctor(world, { only: ['okta-app', 'vault'] });
        expect(statuses(report, 'okta-app')).toMatchObject({ reachable: 'PASS', authenticated: 'BLOCKED', 'read.permitted': 'FAIL' });
        expect(of(report, 'okta-app', 'read.permitted')).toMatchObject({ class: 'NETWORK', detail: 'the current API token failed (HTTP 503)' });
        // The vault page parsed as JSON (a string), so the read itself succeeded: one row was asked for, and it answered.
        expect(statuses(report, 'vault')['read.permitted']).toBe('PASS');
    });

    it('a host that does not resolve, or resolves somewhere the scanner may not go, is refused before any request', async () => {
        const world = createDoctorWorld();
        const report = await doctor(world, {
            resolveHost: async (host) => {
                if (host === 'acme.okta.com') throw new Error('ENOTFOUND');
                if (host === 'iam.googleapis.com') return [];
                // A customer-named host resolving to a metadata address.
                if (host === 'mcp.acme.example') return ['169.254.169.254'];
                return ['93.184.216.34'];
            },
        });
        for (const scope of ['okta-app', 'gcp-sa', 'mcp:crm', 'mcp:tickets']) {
            expect(statuses(report, scope)).toMatchObject({ 'host.resolves': 'FAIL', reachable: 'BLOCKED', authenticated: 'BLOCKED', 'read.permitted': 'BLOCKED', 'write.absent': 'BLOCKED' });
        }
        expect(of(report, 'gcp-sa', 'host.resolves').detail).toBe('did not resolve to an address the scanner may reach: iam.googleapis.com');
        expect(world.log.some((r) => ['acme.okta.com', 'iam.googleapis.com', 'oauth2.googleapis.com'].includes(r.host))).toBe(false);
        expect(report.exitCode).toBe(6);
    });

    it('a credential that cannot be used at all sends nothing, and says so', async () => {
        const world = createDoctorWorld();
        const report = await doctor(world, { env: { ...fullEstateEnv(), GCP_SCANNER_KEY: 'not a key file' }, only: ['gcp-sa'] });
        expect(statuses(report, 'gcp-sa')).toMatchObject({ reachable: 'BLOCKED', authenticated: 'FAIL', 'read.permitted': 'BLOCKED', 'write.absent': 'BLOCKED' });
        expect(of(report, 'gcp-sa', 'reachable').detail).toBe('no request was sent: the credential could not be used');
        expect(world.log).toEqual([]);
    });

    it('a code root that is not a listable directory fails the read, by its label', async () => {
        writeFileSync(configPath, JSON.stringify({ ...fullEstateConfig(join(dir, 'out')), sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'gone', path: join(dir, 'absent') }, { label: 'here', path: dir }] }] }));
        const report = await doctor(createDoctorWorld());
        expect(of(report, 'code', 'read.permitted')).toMatchObject({ status: 'FAIL', class: 'CONFIG', detail: 'not a listable directory: gone' });
        expect(statuses(report, 'code')['write.absent']).toBe('BLOCKED');
        expect(report.exitCode).toBe(4);
    });

    it('a writable code root is a warning: mount it read-only', async () => {
        const report = await doctor(createDoctorWorld(), { only: ['code'], fs: { ...FS, access: () => undefined } });
        expect(of(report, 'code', 'write.absent')).toMatchObject({ status: 'WARN', detail: 'writable by the scanner: example', fix: 'Mount each root read-only.' });
        expect(report.exitCode).toBe(3);
    });
});

describe('3. write access, only where a declared read shows it', () => {
    /** An access token in JWT form carrying `roles`, built at run time so no token literal is in this file. */
    const jwt = (claims: unknown) => ['header', JSON.stringify(claims), 'signature'].map((p) => Buffer.from(p).toString('base64url')).join('.');
    const entraWith = (world: DoctorWorld, token: string) => {
        world.override = (r) => {
            if (r.host === 'login.microsoftonline.com') return { status: 200, body: { access_token: token, token_type: 'Bearer' } };
            if (r.host === 'graph.microsoft.com') return { status: 200, body: { value: [] } };
            return undefined;
        };
    };

    it('Entra: a token holding exactly Application.Read.All passes', async () => {
        const world = createDoctorWorld();
        entraWith(world, jwt({ roles: ['Application.Read.All'] }));
        const report = await doctor(world, { only: ['entra-sp'] });
        expect(of(report, 'entra-sp', 'write.absent')).toEqual({ scope: 'entra-sp', id: 'write.absent', status: 'PASS', detail: 'the token holds Application.Read.All' });
        expect(report.exitCode).toBe(0);
    });

    it('Entra: a role that writes is a warning naming it; another read role is listed under a pass', async () => {
        const world = createDoctorWorld();
        entraWith(world, jwt({ roles: ['Application.Read.All', 'Application.ReadWrite.All', 'Directory.Read.All'] }));
        const report = await doctor(world, { only: ['entra-sp'] });
        expect(of(report, 'entra-sp', 'write.absent')).toMatchObject({
            status: 'WARN',
            detail: 'the credential also holds Application.ReadWrite.All',
            fix: 'Remove Application.ReadWrite.All; the scanner needs Application.Read.All only.',
        });
        expect(report.exitCode).toBe(3);

        entraWith(world, jwt({ roles: ['Directory.Read.All', 'Application.Read.All'] }));
        const second = await doctor(world, { only: ['entra-sp'] });
        expect(of(second, 'entra-sp', 'write.absent')).toMatchObject({ status: 'PASS', detail: 'the token holds Application.Read.All, Directory.Read.All' });
    });

    it.each([
        ['not a JWT', 'opaque-token-value'],
        ['a JWT with no roles', jwt({ aud: 'graph' })],
        ['a JWT whose roles are not names', jwt({ roles: ['bad role\u001b[31m'] })],
        ['a JWT whose payload is not JSON', ['a', 'not json', 'c'].map((p) => Buffer.from(p).toString('base64url')).join('.')],
    ])('Entra: %s is not observable, never a pass', async (_label, token) => {
        const world = createDoctorWorld();
        entraWith(world, token);
        const report = await doctor(world, { only: ['entra-sp'] });
        expect(of(report, 'entra-sp', 'write.absent')).toMatchObject({ status: 'SKIPPED', cause: 'NOT_OBSERVABLE' });
    });

    it('GitHub: a classic token with a writing scope is a warning naming the scopes', async () => {
        const world = createDoctorWorld();
        world.githubScopes = 'repo, read:org, workflow';
        const report = await doctor(world, { only: ['cicd'] });
        expect(of(report, 'cicd', 'write.absent')).toMatchObject({ status: 'WARN', detail: 'the credential also holds repo, workflow' });
        expect(report.exitCode).toBe(3);
    });

    it('GitHub: a classic token with no writing scope passes on what the header listed', async () => {
        const world = createDoctorWorld();
        world.githubScopes = 'read:org';
        expect(of(await doctor(world, { only: ['cicd'] }), 'cicd', 'write.absent')).toMatchObject({ status: 'PASS', detail: 'a classic token holding read:org' });
        world.githubScopes = '';
        expect(of(await doctor(world, { only: ['cicd'] }), 'cicd', 'write.absent')).toMatchObject({ status: 'PASS', detail: 'a classic token with no scope' });
    });

    it('GitHub: no scopes header (a fine-grained token), or one that is not scope names, is not observable', async () => {
        const world = createDoctorWorld();
        expect(of(await doctor(world, { only: ['cicd'] }), 'cicd', 'write.absent')).toMatchObject({ status: 'SKIPPED', cause: 'NOT_OBSERVABLE' });
        world.githubScopes = 'REPO; DROP';
        expect(of(await doctor(world, { only: ['cicd'] }), 'cicd', 'write.absent')).toMatchObject({ status: 'SKIPPED', cause: 'NOT_OBSERVABLE' });
    });
});

describe('4. it reads only', () => {
    it('every request of a full run is on the declared surface, and nothing is posted to the ingest', async () => {
        const world = createDoctorWorld();
        await doctor(world);
        expect(world.log.length).toBeGreaterThan(15);
        for (const r of world.log) {
            const url = `https://${r.host}${r.path}`;
            expect(['GET', 'POST']).toContain(r.method);
            // A message to an estate's MCP server is held by its JSON-RPC method; every other request by its method and path.
            const toMcpServer = r.method === 'POST' && [new URL(MCP_CRM).pathname, new URL(MCP_TICKETS).pathname].includes(r.path);
            const declared = toMcpServer ? isDeclaredMcpMessage(r.body ?? '') : isDeclaredRequest(r.method, url);
            expect([r.method, r.path, declared]).toEqual([r.method, r.path, true]);
            if (r.method === 'POST' && r.host === new URL(INGEST).host && r.path === '/api/mcp') expect(isDeclaredRegisterMessage(r.body ?? '')).toBe(true);
            if (r.method === 'POST' && r.path === '/api/mcp/token') expect(isDeclaredRegisterExchange(r.body ?? '')).toBe(true);
            expect(r.path).not.toMatch(/harness-scans/);
        }
        expect(world.fakes.posted).toEqual([]);
        // No tool was called on an estate's MCP server, and no secret value was asked for.
        expect(world.log.filter((r) => (r.body ?? '').includes('"tools/call"') && r.path !== '/api/mcp')).toEqual([]);
        expect(world.log.some((r) => /^\/secrets\/.+/.test(r.path) || /credentials\/secrets/.test(r.path))).toBe(false);
    });

    it('asks for one row at a time, and stops after the first page', async () => {
        const world = createDoctorWorld();
        await doctor(world);
        const count = (host: string, path: string) => world.log.filter((r) => r.host === host && r.path === path).length;
        // The fixtures hold two pages of each listing; a scan would follow them.
        expect(count('graph.microsoft.com', '/v1.0/applications')).toBe(1);
        expect(count('acme.okta.com', '/api/v1/apps')).toBe(1);
        expect(count('acme.okta.com', '/api/v1/api-tokens')).toBe(0);
        expect(count('acme-agents.vault.azure.net', '/secrets')).toBe(1);
        // Every listing is asked for its smallest page.
        const query = (host: string, path: string) => new URLSearchParams(world.log.find((r) => r.host === host && r.path === path)?.query ?? '');
        expect(query('graph.microsoft.com', '/v1.0/applications').get('$top')).toBe('1');
        expect(query('graph.microsoft.com', '/v1.0/servicePrincipals').get('$top')).toBe('1');
        expect(query('acme.okta.com', '/api/v1/apps').get('limit')).toBe('1');
        expect(query('acme-agents.vault.azure.net', '/secrets').get('maxresults')).toBe('1');
        expect(query('acme-agents.vault.azure.net', '/certificates').get('maxresults')).toBe('1');
        expect(query('api.github.com', `/repos/${GITHUB_REPO}/actions/secrets`).get('per_page')).toBe('1');
        expect(query('iam.googleapis.com', `/v1/projects/${GCP_PROJECT}/serviceAccounts`).get('pageSize')).toBe('1');
        expect(query('api.smith.langchain.com', '/api/v1/sessions').get('limit')).toBe('1');
        // And for nothing the read does not ask for: Graph is asked for ids alone.
        expect(query('graph.microsoft.com', '/v1.0/applications').get('$select')).toBe('id');
    });

    it('writes no file: the output directory and the configuration\'s directory are as they were', async () => {
        const before = [statSync(dir).mtimeMs, statSync(join(dir, 'out')).mtimeMs];
        await doctor(createDoctorWorld());
        expect([statSync(dir).mtimeMs, statSync(join(dir, 'out')).mtimeMs]).toEqual(before);
        expect(readdirSync(join(dir, 'out'))).toEqual([]);
    });

    it('the manifest hash is what it was before doctor existed', () => {
        // Pinned by value in outputs.test.ts; here, that running doctor does not change it either.
        expect(scannerManifestHash()).toBe(MANIFEST_BEFORE_PHASE_3);
        expect(all.length).toBeGreaterThan(0);
        for (const report of all) expect(report.scanner.manifestHash).toBe(MANIFEST_BEFORE_PHASE_3);
    });
});

describe('5. no credential reaches any output', () => {
    it('not the table, not the JSON, not stderr', async () => {
        const err: string[] = [];
        jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
        const world = createDoctorWorld();
        world.githubScopes = 'repo';
        const reports = [await doctor(world), await doctor(world, { env: { ...fullEstateEnv(), OKTA_API_TOKEN: 'wrong-okta-token-value-zz' } })];
        const text = reports.map((r) => renderDoctorText(r) + renderDoctorJson(r)).join('') + err.join('');
        for (const secret of [...NEVER_REPORTED, ...WORLD_SECRETS, 'wrong-okta-token-value-zz']) expect(text).not.toContain(secret);
    });
});

describe('6. the model, and the exit code', () => {
    it('every check of every run above is well formed', () => {
        expect(all.length).toBeGreaterThan(20);
        for (const report of all) {
            for (const c of report.checks) {
                expect(() => assertWellFormed(c)).not.toThrow();
                const loose = c as unknown as Record<string, unknown>;
                if (c.status === 'PASS') expect([loose.cause, loose.class, loose.fix]).toEqual([undefined, undefined, undefined]);
                if (c.status === 'SKIPPED') expect(['NOT_APPLICABLE', 'BLOCKED', 'NOT_OBSERVABLE']).toContain(c.cause);
                if (c.status === 'FAIL') expect([typeof c.fix, ['CONFIG', 'CREDENTIAL', 'NETWORK'].includes(c.class)]).toEqual(['string', true]);
                if (c.status === 'WARN') expect(c.fix.length).toBeGreaterThan(0);
                expect(c.detail.length).toBeGreaterThan(0);
            }
            expect(report.ready).toBe(isReady(report.checks));
            expect(report.exitCode).toBe(doctorExitCode(report.checks));
        }
    });

    it('a malformed check is refused by the runner\'s own assertion', () => {
        const bad = [
            { scope: 's', id: 'i', status: 'PASS', detail: 'd', cause: 'BLOCKED' },
            { scope: 's', id: 'i', status: 'SKIPPED', detail: 'd' },
            { scope: 's', id: 'i', status: 'FAIL', detail: 'd', fix: 'f' },
            { scope: 's', id: 'i', status: 'FAIL', detail: 'd', class: 'CONFIG' },
            { scope: 's', id: 'i', status: 'WARN', detail: 'd' },
            { scope: 's', id: 'i', status: 'MAYBE', detail: 'd' },
        ];
        for (const c of bad) expect(() => assertWellFormed(c as unknown as Check)).toThrow(/malformed check/);
    });

    const P: Check = { scope: 's', id: 'p', status: 'PASS', detail: 'd' };
    const W: Check = { scope: 's', id: 'w', status: 'WARN', detail: 'd', fix: 'f' };
    const fail = (cls: 'CONFIG' | 'CREDENTIAL' | 'NETWORK'): Check => ({ scope: 's', id: cls, status: 'FAIL', class: cls, detail: 'd', fix: 'f' });
    const skip = (cause: 'NOT_APPLICABLE' | 'BLOCKED' | 'NOT_OBSERVABLE'): Check => ({ scope: 's', id: cause, status: 'SKIPPED', cause, detail: 'd' });

    it.each([
        ['every check passed', [P], 0],
        ['passes, and things that cannot be checked', [P, skip('NOT_APPLICABLE'), skip('NOT_OBSERVABLE')], 0],
        ['a warning', [P, W], 3],
        ['a blocked check', [P, skip('BLOCKED')], 3],
        ['a network failure beats a warning', [W, fail('NETWORK')], 6],
        ['a credential failure beats a network failure', [fail('NETWORK'), fail('CREDENTIAL')], 5],
        ['a configuration failure beats both', [fail('NETWORK'), fail('CREDENTIAL'), fail('CONFIG')], 4],
        ['no check at all is not ready', [], 3],
    ] as [string, Check[], number][])('%s: exit %i', (_label, checks, code) => {
        expect(doctorExitCode(checks)).toBe(code);
        expect(isReady(checks)).toBe(code === 0);
    });

    it('says all checks passed only when every one did', () => {
        const line = (checks: Check[]) => summaryLine({ checks, counts: { PASS: checks.filter((c) => c.status === 'PASS').length, WARN: checks.filter((c) => c.status === 'WARN').length, FAIL: checks.filter((c) => c.status === 'FAIL').length, SKIPPED: checks.filter((c) => c.status === 'SKIPPED').length }, ready: isReady(checks) });
        expect(line([P, P])).toBe('2 passed, 0 warnings, 0 failed, 0 not checked. Ready: all checks passed.');
        expect(line([P, skip('NOT_OBSERVABLE')])).toBe('1 passed, 0 warnings, 0 failed, 1 not checked (1 not observable). Ready. 1 check was not checked; each says why above.');
        expect(line([P, W])).toBe('1 passed, 1 warning, 0 failed, 0 not checked. Not ready: fix the warnings or accept them.');
        expect(line([P, fail('CONFIG'), skip('BLOCKED')])).toBe('1 passed, 0 warnings, 1 failed, 1 not checked (1 blocked). Not ready: fix the failures and run doctor again.');
    });
});

describe('the command', () => {
    let out: string[];
    let err: string[];
    beforeEach(() => {
        out = [];
        err = [];
        jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
        jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
    });

    it('prints the table, or one JSON document, and exits by the result', async () => {
        const world = createDoctorWorld();
        jest.spyOn(globalThis, 'fetch').mockImplementation(((url: string, init: RequestInit) => world.fetchImpl(String(url), init)) as typeof fetch);
        // Without a credential in the environment, every network source stops at its first check: nothing is sent.
        const code = await main(['doctor', '--config', configPath, '--source', 'okta-app', '--source=code'], {});
        expect(code).toBe(5);
        expect(world.log).toEqual([]);
        const text = out.join('');
        expect(text).toMatch(/^scanent doctor {2}estate acme-prod {2}\d{4}-/);
        expect(text).toContain('  FAIL     credential.present    OKTA_API_TOKEN is not set');
        expect(text).toContain('           fix: Set OKTA_API_TOKEN or OKTA_API_TOKEN_FILE.');
        expect(text).toMatch(/SKIPPED {2}reachable {13}blocked: OKTA_API_TOKEN is not set/);
        expect(text.trimEnd().split('\n').at(-1)).toMatch(/^\d+ passed, .* Not ready: fix the failures and run doctor again\.$/);

        out.length = 0;
        expect(await main(['doctor', '--config', configPath, '--json', '--source', 'code', '--out', join(dir, 'out')], {})).toBe(5);
        const report = JSON.parse(out.join('')) as DoctorReport;
        expect(report).toMatchObject({ doctor: 'scanent-doctor/1', estate: 'acme-prod', ready: false, exitCode: 5 });
        expect(report.counts.PASS + report.counts.WARN + report.counts.FAIL + report.counts.SKIPPED).toBe(report.checks.length);
    });

    it.each([
        [['doctor', '--config', 'x', '--source', 'not-a-kind']],
        [['doctor', '--config', 'x', '--source']],
        [['doctor', '--config', 'x', '--out', 'relative/dir']],
        [['doctor', '--config', 'x', '--out']],
        [['doctor', '--config', 'x', '--dry-run']],
    ])('%j is a usage error and checks nothing', async (argv) => {
        expect(await main(argv, {})).toBe(2);
        expect(out).toEqual([]);
    });

    it('a table cannot be broken by a configured string', () => {
        const report: DoctorReport = {
            doctor: 'scanent-doctor/1',
            estate: 'acme',
            at: 'now',
            scanner: { version: '0', manifestHash: 'sha256:0' },
            ready: false,
            counts: { PASS: 0, WARN: 1, FAIL: 0, SKIPPED: 0 },
            exitCode: 3,
            checks: [{ scope: 'mcp:evil\u001b[2J', id: 'x', status: 'WARN', detail: 'line one\nline two\u202e', fix: 'do\rthis' }],
        };
        const text = renderDoctorText(report);
        for (const ch of ['\u001b', '\r', '\u202e']) expect(text).not.toContain(ch);
        expect(text).toContain('mcp:evil\\u{1b}[2J');
        expect(text.split('\n').filter((l) => l.includes('line one'))).toHaveLength(1);
    });
});
