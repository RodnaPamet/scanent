/**
 * `scanent doctor`, the local checks: each row of the table, with the file
 * system, the environment and the clock passed in.
 */
import { generateKeyPairSync } from 'crypto';

import { harnessKeyFingerprint } from '@rodnapamet/scanent-contract/harness-contract';
import { InventoryRefused } from '@scanent/report/results/inventory';
import { parseScannerConfig, type ScannerConfig } from '../src/config';
import {
    checkClock,
    checkConfigMode,
    checkEgress,
    checkExtraCa,
    checkInventory,
    checkOutputDir,
    checkProxy,
    checkProxyCustomerHosts,
    checkSecretFiles,
    checkSigningKey,
    checkTlsVerification,
    LOCAL_CHECK_IDS,
    outputDirOf,
    type DoctorFs,
    type DoctorStat,
} from '../src/doctor/local';
import { runDoctor } from '../src/doctor/run';
import type { Check } from '../src/doctor/types';

const PEM = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const RSA = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const base = {
    estate: 'acme',
    scanner: { agentId: 'agt', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
    schedule: { everyHours: 24 },
    sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiTokenEnv: 'OKTA_API_TOKEN' }],
};
const config = (extra: Record<string, unknown> = {}): ScannerConfig => parseScannerConfig({ ...base, outputs: [{ kind: 'stdout' }], ...extra });

interface Entry {
    readonly kind: 'file' | 'dir' | 'link';
    readonly mode?: number;
    readonly content?: string | Buffer;
    /** Whether `access` lets the process write here. Default: yes. */
    readonly writable?: boolean;
}

/** A file system of exactly these paths. Anything else is ENOENT. */
function fakeFs(entries: Record<string, Entry>): DoctorFs {
    const missing = (path: string) => Object.assign(new Error(`ENOENT ${path}`), { code: 'ENOENT' });
    const stat = (path: string): DoctorStat => {
        const e = entries[path];
        if (e === undefined) throw missing(path);
        return {
            isFile: () => e.kind === 'file',
            isDirectory: () => e.kind === 'dir',
            isSymbolicLink: () => e.kind === 'link',
            mode: e.mode ?? (e.kind === 'dir' ? 0o700 : 0o600),
            size: Buffer.byteLength(e.content ?? ''),
        };
    };
    return {
        readFile: (path) => {
            const e = entries[path];
            if (e === undefined) throw missing(path);
            if (e.kind !== 'file') throw Object.assign(new Error('EISDIR'), { code: 'EISDIR' });
            return Buffer.from(e.content ?? '');
        },
        stat,
        lstat: stat,
        access: (path) => {
            const e = entries[path];
            if (e === undefined) throw missing(path);
            if (e.writable === false) throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
        },
    };
}

const shape = (c: Check) => [c.status, c.status === 'SKIPPED' ? c.cause : c.status === 'FAIL' ? c.class : null];

describe('config.mode', () => {
    it('passes a private file, warns on one others can write, and is blocked when the mode cannot be read', () => {
        expect(shape(checkConfigMode(fakeFs({ '/c.json': { kind: 'file', mode: 0o600 } }), '/c.json'))).toEqual(['PASS', null]);
        expect(shape(checkConfigMode(fakeFs({ '/c.json': { kind: 'file', mode: 0o644 } }), '/c.json'))).toEqual(['PASS', null]);
        expect(checkConfigMode(fakeFs({ '/c.json': { kind: 'file', mode: 0o664 } }), '/c.json')).toMatchObject({ status: 'WARN', fix: 'chmod 0600 the configuration file.' });
        expect(shape(checkConfigMode(fakeFs({ '/c.json': { kind: 'file', mode: 0o602 } }), '/c.json'))).toEqual(['WARN', null]);
        expect(shape(checkConfigMode(fakeFs({}), '/c.json'))).toEqual(['SKIPPED', 'BLOCKED']);
    });
});

describe('signing-key', () => {
    it('passes an Ed25519 key and shows its public half', () => {
        const check = checkSigningKey(config(), { SCANNER_SIGNING_KEY: PEM }, new Set());
        expect(check).toMatchObject({ status: 'PASS', detail: expect.stringMatching(/^ed25519 [0-9a-f]{64}, fingerprint [0-9a-f]{64}$/) });
        // The fingerprint is the one a report signed with this key shows, not a second spelling of the key.
        const [, publicKeyHex, fingerprint] = /^ed25519 ([0-9a-f]{64}), fingerprint ([0-9a-f]{64})$/.exec(check.detail ?? '') ?? [];
        expect(fingerprint).toBe(harnessKeyFingerprint(publicKeyHex));
        expect(fingerprint).not.toBe(publicKeyHex);
    });

    it('a missing key is a credential failure; a wrong or unparseable one a configuration failure; neither shows the key', () => {
        expect(shape(checkSigningKey(config(), {}, new Set()))).toEqual(['FAIL', 'CREDENTIAL']);
        expect(shape(checkSigningKey(config(), { SCANNER_SIGNING_KEY: '  ' }, new Set()))).toEqual(['FAIL', 'CREDENTIAL']);
        const rsa = checkSigningKey(config(), { SCANNER_SIGNING_KEY: RSA }, new Set());
        expect(shape(rsa)).toEqual(['FAIL', 'CONFIG']);
        expect(JSON.stringify(rsa)).not.toContain(RSA.split('\n')[1]);
        expect(shape(checkSigningKey(config(), { SCANNER_SIGNING_KEY: 'not a pem' }, new Set()))).toEqual(['FAIL', 'CONFIG']);
    });

    it('is blocked, not failed twice, when its secret file was refused', () => {
        expect(shape(checkSigningKey(config(), {}, new Set(['SCANNER_SIGNING_KEY'])))).toEqual(['SKIPPED', 'BLOCKED']);
    });
});

describe('secret-files', () => {
    it('is not applicable when no credential comes from a file', () => {
        const r = checkSecretFiles(config(), { SCANNER_SIGNING_KEY: PEM, OKTA_API_TOKEN: 'v' }, fakeFs({}));
        expect(shape(r.check)).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
        expect(r.resolved.OKTA_API_TOKEN).toBe('v');
    });

    it('passes a file under a secret mount whatever its mode, and resolves its value', () => {
        const fs = fakeFs({ '/run/secrets/key': { kind: 'file', mode: 0o444, content: `${PEM}\n` }, '/var/run/secrets/okta': { kind: 'file', mode: 0o644, content: 'token-value\n' } });
        const r = checkSecretFiles(config(), { SCANNER_SIGNING_KEY_FILE: '/run/secrets/key', OKTA_API_TOKEN_FILE: '/var/run/secrets/okta' }, fs);
        expect(r.check).toMatchObject({ status: 'PASS', detail: '2 credentials read from a file' });
        expect(r.resolved.OKTA_API_TOKEN).toBe('token-value');
        expect(r.unresolved.size).toBe(0);
        // The value is in the resolved environment and nowhere in the check.
        expect(JSON.stringify(r.check)).not.toContain('token-value');
    });

    it('warns on a file others can read outside a secret mount, where the mode is its only protection', () => {
        const fs = fakeFs({ '/home/op/key.pem': { kind: 'file', mode: 0o644, content: PEM }, '/home/op/okta': { kind: 'file', mode: 0o600, content: 'v' } });
        const r = checkSecretFiles(config(), { SCANNER_SIGNING_KEY_FILE: '/home/op/key.pem', OKTA_API_TOKEN_FILE: '/home/op/okta' }, fs);
        expect(r.check).toMatchObject({ status: 'WARN', detail: 'readable by group or others, outside a secret mount: SCANNER_SIGNING_KEY_FILE' });
    });

    it('fails with each refusal\'s code, and leaves those names unresolved', () => {
        const fs = fakeFs({ '/s/open': { kind: 'file', mode: 0o666, content: 'v' } });
        const r = checkSecretFiles(config(), { SCANNER_SIGNING_KEY: PEM, SCANNER_SIGNING_KEY_FILE: '/s/open', OKTA_API_TOKEN_FILE: '/s/absent' }, fs);
        expect(r.check).toMatchObject({ status: 'FAIL', class: 'CONFIG', detail: 'refused: SCANNER_SIGNING_KEY (BOTH_SET), OKTA_API_TOKEN_FILE (UNREADABLE ENOENT)' });
        expect([...r.unresolved].sort()).toEqual(['OKTA_API_TOKEN', 'SCANNER_SIGNING_KEY']);
        expect(r.resolved.SCANNER_SIGNING_KEY).toBeUndefined();
        const ww = checkSecretFiles(config(), { SCANNER_SIGNING_KEY: PEM, OKTA_API_TOKEN_FILE: '/s/open' }, fs);
        expect(ww.check.detail).toBe('refused: OKTA_API_TOKEN_FILE (WORLD_WRITABLE)');
    });
});

describe('output.dir', () => {
    it('is not applicable without a file output, and --out names one', () => {
        expect(outputDirOf(config(), null)).toBeNull();
        expect(outputDirOf(config(), '/flag')).toBe('/flag');
        expect(outputDirOf(config({ outputs: [{ kind: 'file', dir: '/configured' }] }), null)).toBe('/configured');
        expect(outputDirOf(config({ outputs: [{ kind: 'file', dir: '/configured' }] }), '/flag')).toBe('/flag');
        expect(shape(checkOutputDir(null, fakeFs({}), 1000))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
    });

    it('passes a writable directory by permission, and says nothing was written', () => {
        expect(checkOutputDir('/out', fakeFs({ '/out': { kind: 'dir', mode: 0o700 } }), 1000)).toEqual({
            scope: 'local',
            id: 'output.dir',
            status: 'PASS',
            detail: '/out is writable by uid 1000 (by permission; nothing was written)',
        });
    });

    it('passes a directory that does not exist yet when its parent would let it be made', () => {
        expect(checkOutputDir('/data/out', fakeFs({ '/data': { kind: 'dir' } }), 1000)).toMatchObject({ status: 'PASS', detail: expect.stringContaining('does not exist yet') });
        expect(checkOutputDir('/data/out', fakeFs({ '/data': { kind: 'dir', writable: false } }), 1000)).toMatchObject({ status: 'FAIL', class: 'CONFIG' });
        expect(shape(checkOutputDir('/data/out', fakeFs({}), 1000))).toEqual(['FAIL', 'CONFIG']);
        expect(shape(checkOutputDir('/data/out', fakeFs({ '/data': { kind: 'link' } }), 1000))).toEqual(['FAIL', 'CONFIG']);
    });

    it('fails a directory the process cannot write, naming the uid; a link; and a file', () => {
        expect(checkOutputDir('/out', fakeFs({ '/out': { kind: 'dir', writable: false } }), 1000)).toMatchObject({ status: 'FAIL', class: 'CONFIG', detail: '/out is not writable by uid 1000' });
        expect(checkOutputDir('/out', fakeFs({ '/out': { kind: 'dir', writable: false } }), null).detail).toBe('/out is not writable by this user');
        expect(checkOutputDir('/out', fakeFs({ '/out': { kind: 'link' } }), 1000).detail).toBe('/out is a symbolic link');
        expect(checkOutputDir('/out', fakeFs({ '/out': { kind: 'file' } }), 1000).detail).toBe('/out is not a directory');
        const denied: DoctorFs = { ...fakeFs({}), lstat: () => { throw Object.assign(new Error('x'), { code: 'EACCES' }); } };
        expect(checkOutputDir('/out', denied, 1000).detail).toBe('/out could not be read (EACCES)');
    });

    it('warns when other users can write there: the runs are evidence', () => {
        expect(checkOutputDir('/out', fakeFs({ '/out': { kind: 'dir', mode: 0o777 } }), 1000)).toMatchObject({ status: 'WARN', detail: '/out is writable by other users' });
    });
});

describe('inventory', () => {
    const withInventory = config({ inventory: { path: '/etc/scanent/inventory.json' } });
    it('is not applicable when none is configured, and the loader is not called', () => {
        expect(shape(checkInventory(config(), () => { throw new Error('called'); }))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
    });
    it('passes with the row count', () => {
        expect(checkInventory(withInventory, () => ({ rows: [1, 2, 3] }))).toMatchObject({ status: 'PASS', detail: '3 rows' });
        expect(checkInventory(withInventory, () => ({ rows: [1] })).detail).toBe('1 row');
    });
    it('fails with the refusal\'s rows and fields, and lets any other error through', () => {
        expect(checkInventory(withInventory, () => { throw new InventoryRefused(['row 2: owner']); })).toMatchObject({ status: 'FAIL', class: 'CONFIG', detail: 'refused: row 2: owner' });
        expect(() => checkInventory(withInventory, () => { throw new Error('a bug'); })).toThrow('a bug');
    });
});

describe('tls', () => {
    it('verification off is a configuration failure, and anything else passes', () => {
        expect(checkTlsVerification({ NODE_TLS_REJECT_UNAUTHORIZED: '0' })).toMatchObject({ status: 'FAIL', class: 'CONFIG', fix: 'Remove it; add your CA with NODE_EXTRA_CA_CERTS.' });
        expect(shape(checkTlsVerification({}))).toEqual(['PASS', null]);
        expect(shape(checkTlsVerification({ NODE_TLS_REJECT_UNAUTHORIZED: '1' }))).toEqual(['PASS', null]);
    });

    it('an extra CA must be a readable file holding a certificate', () => {
        const cert = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
        const fs = fakeFs({ '/ca/one.pem': { kind: 'file', content: cert }, '/ca/two.pem': { kind: 'file', content: cert + cert }, '/ca/empty.pem': { kind: 'file', content: 'nothing here' }, '/ca': { kind: 'dir' } });
        expect(shape(checkExtraCa({}, fs))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
        expect(checkExtraCa({ NODE_EXTRA_CA_CERTS: '/ca/one.pem' }, fs)).toMatchObject({ status: 'PASS', detail: '1 certificate added to the trusted authorities' });
        expect(checkExtraCa({ NODE_EXTRA_CA_CERTS: '/ca/two.pem' }, fs).detail).toBe('2 certificates added to the trusted authorities');
        expect(shape(checkExtraCa({ NODE_EXTRA_CA_CERTS: '/ca/empty.pem' }, fs))).toEqual(['FAIL', 'CONFIG']);
        expect(shape(checkExtraCa({ NODE_EXTRA_CA_CERTS: '/ca' }, fs))).toEqual(['FAIL', 'CONFIG']);
        expect(checkExtraCa({ NODE_EXTRA_CA_CERTS: '/ca/absent.pem' }, fs)).toMatchObject({ status: 'FAIL', detail: 'the file NODE_EXTRA_CA_CERTS names could not be read (ENOENT)' });
    });
});

describe('proxy', () => {
    const proxy = { HTTPS_PROXY: 'http://user:marker-proxy-password@proxy.corp.example:3128' };
    it('is not applicable with no proxy variable', () => {
        expect(shape(checkProxy({}, 'v24.1.0'))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
        expect(shape(checkProxyCustomerHosts({}, 'v24.1.0', ['a.example']))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
    });

    it('passes with the switch on a Node that honours it, and shows host and port only', () => {
        const c = checkProxy({ ...proxy, NODE_USE_ENV_PROXY: '1' }, 'v24.1.0');
        expect(c).toMatchObject({ status: 'PASS', detail: 'requests go through proxy.corp.example:3128' });
        expect(JSON.stringify(c)).not.toMatch(/marker-proxy-password|user:/);
    });

    it('is not applicable to a configuration that reaches no host: there is no request for it to carry', () => {
        expect(checkProxy(proxy, 'v24.1.0', false)).toMatchObject({ status: 'SKIPPED', cause: 'NOT_APPLICABLE', detail: 'the configuration reaches no host, so no request would use a proxy' });
        expect(shape(checkProxy({ ...proxy, NODE_USE_ENV_PROXY: '1' }, 'v24.1.0', false))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
    });

    it('fails when requests would not use the proxy that is named', () => {
        expect(checkProxy(proxy, 'v24.1.0')).toMatchObject({ status: 'FAIL', class: 'NETWORK', fix: 'Set NODE_USE_ENV_PROXY=1 (the container image sets it).' });
        expect(checkProxy({ ...proxy, NODE_USE_ENV_PROXY: '1' }, 'v20.11.0')).toMatchObject({ status: 'FAIL', class: 'NETWORK' });
        expect(checkProxy({ HTTPS_PROXY: 'not a url' }, 'v24.1.0')).toMatchObject({ status: 'FAIL', class: 'NETWORK', detail: 'HTTPS_PROXY is not an http or https URL' });
        for (const c of [checkProxy(proxy, 'v24.1.0'), checkProxy({ ...proxy, NODE_USE_ENV_PROXY: '1' }, 'v20.11.0')]) expect(JSON.stringify(c)).not.toContain('marker-proxy-password');
    });

    it('warns for each host of the estate\'s own that goes through the proxy', () => {
        const env = { ...proxy, NODE_USE_ENV_PROXY: '1', NO_PROXY: 'langsmith.acme.example' };
        expect(checkProxyCustomerHosts(env, 'v24.1.0', ['langsmith.acme.example', 'mcp.acme.example'])).toMatchObject({
            status: 'WARN',
            detail: expect.stringContaining('reached through the proxy: mcp.acme.example.'),
            fix: 'Add each host to NO_PROXY if it is on your network.',
        });
        expect(shape(checkProxyCustomerHosts(env, 'v24.1.0', ['langsmith.acme.example']))).toEqual(['PASS', null]);
        expect(shape(checkProxyCustomerHosts(env, 'v24.1.0', []))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
    });
});

describe('clock', () => {
    const now = Date.parse('2026-11-12T09:00:00Z');
    const at = (seconds: number) => new Date(now + seconds * 1000).toUTCString();
    it.each([
        [30, 'PASS', null],
        [-30, 'PASS', null],
        [59, 'PASS', null],
        [120, 'WARN', null],
        [-300, 'WARN', null],
        [600, 'FAIL', 'CONFIG'],
    ])('%i seconds off: %s', (seconds, status, cls) => {
        expect(shape(checkClock([at(seconds)], now))).toEqual([status, cls]);
    });

    it('is judged on the worst response, and ignores a header that is not a date', () => {
        expect(checkClock([at(1), at(400), 'not a date'], now)).toMatchObject({ status: 'FAIL', detail: "400 seconds from the sources' clocks (2 responses)" });
    });

    it('with no Date header seen, it is not observable: never a pass', () => {
        expect(shape(checkClock([], now))).toEqual(['SKIPPED', 'NOT_OBSERVABLE']);
        expect(shape(checkClock(['garbage'], now))).toEqual(['SKIPPED', 'NOT_OBSERVABLE']);
    });
});

describe('egress', () => {
    const withEgress = config({
        inflect: { baseUrl: 'https://tenant.example.com', tenantSlug: 't', apiKeyEnv: 'I' },
        outputs: [{ kind: 'inflect' }],
        egress: { proxyUrl: 'http://egress-proxy:3128', canaryHost: 'canary.example.org' },
    });
    const env = { HTTPS_PROXY: 'http://egress-proxy:3128', NODE_USE_ENV_PROXY: '1' };
    const probe = (allowed: number, canary: number, direct: boolean) => ({
        connectThrough: async (_p: URL, target: string) => (target.startsWith('tenant.example.com') ? allowed : canary),
        dialDirect: async () => direct,
    });

    it('is not applicable without an egress block', async () => {
        expect(shape(await checkEgress(config(), env, undefined))).toEqual(['SKIPPED', 'NOT_APPLICABLE']);
    });
    it('passes when the proof holds', async () => {
        expect(shape(await checkEgress(withEgress, env, probe(200, 403, false)))).toEqual(['PASS', null]);
    });
    it.each([
        ['the proxy is not what the environment names', {}, probe(200, 403, false), 'ENV_PROXY_NOT_SET'],
        ['the proxy refuses the tenant', env, probe(403, 403, false), 'ALLOWED_HOST_REFUSED'],
        ['the proxy admits the canary', env, probe(200, 200, false), 'CANARY_NOT_REFUSED'],
        ['there is a way around the proxy', env, probe(200, 403, true), 'DIRECT_EGRESS_OPEN'],
    ])('fails when %s', async (_label, e, p, code) => {
        expect(await checkEgress(withEgress, e, p)).toMatchObject({ status: 'FAIL', class: 'NETWORK', detail: `the egress proof failed: ${code}` });
    });
});

describe('a configuration that cannot be read', () => {
    const run = (content: string | null) =>
        runDoctor({
            configPath: '/etc/scanent/config.json',
            env: {},
            fs: fakeFs(content === null ? {} : { '/etc/scanent/config.json': { kind: 'file', content } }),
            fetchImpl: async () => {
                throw new Error('nothing is requested');
            },
            now: () => 0,
        });

    it.each([
        ['is missing', null, 'the file could not be read (ENOENT)'],
        ['is not JSON', '{ "estate": ', 'the file is not JSON'],
        ['breaks the schema', JSON.stringify({ ...base, extra: true }), '(root): unrecognized_keys'],
    ])('%s: config.valid fails, and every other local check is blocked, not passed and not left out', async (_label, content, detail) => {
        const report = await run(content);
        expect(report.checks.map((c) => c.id)).toEqual([...LOCAL_CHECK_IDS]);
        expect(report.checks[0]).toMatchObject({ status: 'FAIL', class: 'CONFIG', detail });
        expect(report.checks.slice(1).every((c) => c.status === 'SKIPPED' && c.cause === 'BLOCKED')).toBe(true);
        expect(report).toMatchObject({ estate: null, ready: false, exitCode: 4 });
    });

    it('a credential pasted into the configuration is refused by its path, and not repeated', async () => {
        const pasted = ['gh', 'p_', 'A1'.repeat(12)].join('');
        const report = await run(JSON.stringify({ ...base, sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiTokenEnv: pasted }] }));
        expect(report.checks[0].detail).toMatch(/^sources\[0\]\.apiTokenEnv: a credential value in the configuration/);
        expect(JSON.stringify(report)).not.toContain(pasted);
    });
});

describe('certificate verification turned off', () => {
    it('sends nothing: every source is blocked behind tls.verification', async () => {
        let requests = 0;
        const report = await runDoctor({
            configPath: '/c.json',
            env: { NODE_TLS_REJECT_UNAUTHORIZED: '0', SCANNER_SIGNING_KEY: PEM, OKTA_API_TOKEN: 'v' },
            fs: fakeFs({ '/c.json': { kind: 'file', content: JSON.stringify({ ...base, outputs: [{ kind: 'stdout' }] }) } }),
            fetchImpl: async () => {
                requests += 1;
                throw new Error('nothing is requested');
            },
            resolveHost: async () => ['93.184.216.34'],
            now: () => 0,
        });
        expect(requests).toBe(0);
        const okta = report.checks.filter((c) => c.scope === 'okta-app');
        expect(okta.map((c) => (c.status === 'SKIPPED' ? c.cause : c.status))).toEqual(['PASS', 'BLOCKED', 'BLOCKED', 'BLOCKED', 'BLOCKED', 'BLOCKED']);
        expect(report.exitCode).toBe(4);
    });
});
