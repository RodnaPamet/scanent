/**
 * The scanner's egress proxy and the proof each scan takes of it (#5004 part C).
 *
 *   1. THE ALLOWLIST is exact hostnames; anything else refuses to start.
 *   2. THE DECISION: a CONNECT to an allowlisted host on 443 and nothing else.
 *   3. A REAL PROXY, over a loopback socket: the tunnel carries bytes for an
 *      allowed host; every other request is refused before any byte leaves.
 *   4. THE PROOF: met only when the scanner's fetch is pointed at the proxy,
 *      the proxy admits the Inflect host, refuses the canary, and there is no
 *      way around it — and the production probe reads the real proxy's answers.
 */
import { createServer as createTcpServer, connect, type AddressInfo, type Server as TcpServer, type Socket } from 'node:net';
import type { Server } from 'node:http';

import {
    createEgressProxy,
    parseEgressPrivateCidrs,
    decideConnect,
    parseEgressAllowlist,
} from '../src/egress-proxy';
import { nodeEgressProbe, proveEgress, type EgressProbe } from '../src/egress-proof';
import type { ScannerLog } from '../src/log';

const quiet: ScannerLog = { info: () => {}, warn: () => {}, error: () => {} };
const ALLOW = new Set(['inflect.example.com', 'graph.microsoft.com']);

describe('1. the allowlist', () => {
    it('is exact, lower-cased hostnames', () => {
        expect([...parseEgressAllowlist(' Inflect.Example.com , graph.microsoft.com,, ')]).toEqual(['inflect.example.com', 'graph.microsoft.com']);
    });

    it('missing or empty refuses everything rather than failing open', () => {
        expect(parseEgressAllowlist(undefined).size).toBe(0);
        expect(parseEgressAllowlist('').size).toBe(0);
    });

    it.each(['*.example.com', 'https://inflect.example.com', 'inflect.example.com:443', '10.0.0.1', 'localhost', 'a b.example'])(
        'refuses to start on %s',
        (entry) => {
            expect(() => parseEgressAllowlist(entry)).toThrow('not a hostname');
        },
    );
});

describe('2. the decision', () => {
    it('admits an allowlisted host on 443, case-insensitively', () => {
        expect(decideConnect('INFLECT.example.com:443', ALLOW)).toEqual({ allowed: true, host: 'inflect.example.com', port: 443 });
    });

    it.each([
        ['another host', 'example.com:443', 403, 'HOST_NOT_ALLOWED'],
        ['a suffix of an allowed host', 'evil.inflect.example.com:443', 403, 'HOST_NOT_ALLOWED'],
        ['another port', 'inflect.example.com:80', 403, 'PORT_NOT_ALLOWED'],
        ['an IP literal', '1.1.1.1:443', 403, 'IP_LITERAL'],
        ['no port', 'inflect.example.com', 400, 'MALFORMED_TARGET'],
        ['userinfo', 'u@inflect.example.com:443', 400, 'MALFORMED_TARGET'],
        ['nothing', undefined, 400, 'MALFORMED_TARGET'],
    ])('refuses %s', (_label, target, status, reason) => {
        expect(decideConnect(target, ALLOW)).toMatchObject({ allowed: false, status, reason });
    });
});

/** A loopback "internet": an echo server every allowed dial lands on. */
async function harness(allow: ReadonlySet<string>) {
    const dialled: string[] = [];
    const echo: TcpServer = createTcpServer((s) => s.pipe(s));
    await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
    const echoPort = (echo.address() as AddressInfo).port;
    const proxy: Server = createEgressProxy({
        allow,
        log: quiet,
        dial: (host, port) => {
            dialled.push(`${host}:${port}`);
            return connect({ host: '127.0.0.1', port: echoPort });
        },
    });
    await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
    const proxyPort = (proxy.address() as AddressInfo).port;
    const close = async () => {
        await new Promise((r) => proxy.close(r));
        await new Promise((r) => echo.close(r));
    };
    return { proxyPort, echoPort, dialled, close };
}

/** Send raw bytes to the proxy and read until it closes or `until` matches. */
function exchange(port: number, bytes: string, until?: RegExp): Promise<string> {
    return new Promise((resolve, reject) => {
        const s: Socket = connect({ host: '127.0.0.1', port });
        let got = '';
        s.on('data', (d) => {
            got += d.toString('latin1');
            if (until && until.test(got)) {
                s.destroy();
                resolve(got);
            }
        });
        s.on('end', () => resolve(got));
        s.on('close', () => resolve(got));
        s.on('error', reject);
        s.write(bytes);
    });
}

describe('3. a real proxy', () => {
    let h: Awaited<ReturnType<typeof harness>>;
    beforeEach(async () => {
        h = await harness(ALLOW);
    });
    afterEach(async () => {
        await h.close();
    });

    it('opens a tunnel to an allowed host and carries bytes both ways', async () => {
        const got = await exchange(
            h.proxyPort,
            'CONNECT inflect.example.com:443 HTTP/1.1\r\nHost: inflect.example.com:443\r\n\r\nping',
            /ping$/,
        );
        expect(got).toBe('HTTP/1.1 200 Connection Established\r\n\r\nping');
        expect(h.dialled).toEqual(['inflect.example.com:443']);
    });

    it('refuses another host with 403, and dials nothing', async () => {
        const got = await exchange(h.proxyPort, 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n');
        expect(got).toMatch(/^HTTP\/1\.1 403 /);
        expect(h.dialled).toEqual([]);
    });

    it('refuses plain HTTP with 405 — absolute-form or not — and dials nothing', async () => {
        for (const line of ['GET http://inflect.example.com/ HTTP/1.1', 'GET / HTTP/1.1']) {
            const got = await exchange(h.proxyPort, `${line}\r\nHost: inflect.example.com\r\nConnection: close\r\n\r\n`);
            expect(got).toMatch(/^HTTP\/1\.1 405 /);
        }
        expect(h.dialled).toEqual([]);
    });

    it('an empty allowlist refuses even the Inflect host', async () => {
        const closed = await harness(new Set());
        try {
            const got = await exchange(closed.proxyPort, 'CONNECT inflect.example.com:443 HTTP/1.1\r\nHost: inflect.example.com:443\r\n\r\n');
            expect(got).toMatch(/^HTTP\/1\.1 403 /);
            expect(closed.dialled).toEqual([]);
        } finally {
            await closed.close();
        }
    });

    it('the production probe reads the real answers: 200 for an allowed host, 403 for the canary', async () => {
        const proxy = new URL(`http://127.0.0.1:${h.proxyPort}`);
        expect(await nodeEgressProbe.connectThrough(proxy, 'inflect.example.com:443', 2_000)).toBe(200);
        expect(await nodeEgressProbe.connectThrough(proxy, 'example.com:443', 2_000)).toBe(403);
    });

    it('the production probe tells an open port from a closed one', async () => {
        expect(await nodeEgressProbe.dialDirect('127.0.0.1', h.echoPort, 2_000)).toBe(true);
        const free = createTcpServer();
        await new Promise<void>((r) => free.listen(0, '127.0.0.1', r));
        const port = (free.address() as AddressInfo).port;
        await new Promise((r) => free.close(r));
        expect(await nodeEgressProbe.dialDirect('127.0.0.1', port, 2_000)).toBe(false);
    });
});

describe('3b. an allowlisted name is not trusted for where it points', () => {
    /** A proxy on the production path: it resolves with `answers`, and connects to an ADDRESS through `connectAddress`. */
    async function pinned(answers: (host: string) => Promise<readonly string[]>, privateCidrs: string | undefined = undefined) {
        const connected: string[] = [];
        const refusals: Record<string, unknown>[] = [];
        const echo: TcpServer = createTcpServer((s) => s.pipe(s));
        await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
        const echoPort = (echo.address() as AddressInfo).port;
        const proxy: Server = createEgressProxy({
            allow: ALLOW,
            log: { ...quiet, warn: (_msg, fields) => void refusals.push(fields ?? {}) },
            resolve: answers,
            privateCidrs: parseEgressPrivateCidrs(privateCidrs),
            connectAddress: (address, port) => {
                connected.push(`${address}:${port}`);
                return connect({ host: '127.0.0.1', port: echoPort });
            },
        });
        await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
        const port = (proxy.address() as AddressInfo).port;
        const close = async () => {
            await new Promise((r) => proxy.close(r));
            await new Promise((r) => echo.close(r));
        };
        return { port, connected, refusals, close };
    }
    const CONNECT = 'CONNECT inflect.example.com:443 HTTP/1.1\r\nHost: inflect.example.com:443\r\n\r\n';

    it('connects to the address it checked, not to the name', async () => {
        let lookups = 0;
        const p = await pinned(async (host) => {
            lookups += 1;
            expect(host).toBe('inflect.example.com');
            return ['93.184.216.34', '93.184.216.35'];
        });
        try {
            expect(await exchange(p.port, CONNECT, /\r\n\r\n/)).toMatch(/^HTTP\/1\.1 200 /);
            // One lookup, and the dial is to its first answer: the name is not resolved a second time.
            expect(lookups).toBe(1);
            expect(p.connected).toEqual(['93.184.216.34:443']);
        } finally {
            await p.close();
        }
    });

    it.each([
        ['loopback', ['127.0.0.1']],
        ['cloud metadata', ['169.254.169.254']],
        ['the unspecified address', ['0.0.0.0']],
        ['v6 loopback', ['::1']],
        ['a private address', ['10.0.0.7']],
        ['a v4-mapped private address', ['::ffff:10.0.0.7']],
        ['one bad address among good ones', ['93.184.216.34', '127.0.0.1']],
    ])('refuses a name that resolves to %s with 403, and connects to nothing', async (_label, addresses) => {
        const p = await pinned(async () => addresses);
        try {
            expect(await exchange(p.port, CONNECT)).toMatch(/^HTTP\/1\.1 403 /);
            expect(p.connected).toEqual([]);
            expect(p.refusals).toEqual([{ reason: 'ADDRESS_NOT_ALLOWED', host: 'inflect.example.com' }]);
        } finally {
            await p.close();
        }
    });

    it('a private address inside EGRESS_PRIVATE_CIDR_ALLOWLIST is dialled; loopback and metadata are refused inside it too', async () => {
        const inside = await pinned(async () => ['10.20.3.4'], '10.20.0.0/16');
        const outside = await pinned(async () => ['10.21.3.4'], '10.20.0.0/16');
        const never = await pinned(async () => ['169.254.169.254'], '0.0.0.0/0');
        const loopback = await pinned(async () => ['127.0.0.1'], '0.0.0.0/0');
        try {
            expect(await exchange(inside.port, CONNECT, /\r\n\r\n/)).toMatch(/^HTTP\/1\.1 200 /);
            expect(inside.connected).toEqual(['10.20.3.4:443']);
            for (const p of [outside, never, loopback]) {
                expect(await exchange(p.port, CONNECT)).toMatch(/^HTTP\/1\.1 403 /);
                expect(p.connected).toEqual([]);
            }
        } finally {
            for (const p of [inside, outside, never, loopback]) await p.close();
        }
    });

    it('a name that does not resolve, or resolves to nothing, is a 502 and connects to nothing', async () => {
        const failing = await pinned(async () => {
            throw new Error('ENOTFOUND');
        });
        const empty = await pinned(async () => []);
        try {
            for (const p of [failing, empty]) {
                expect(await exchange(p.port, CONNECT)).toMatch(/^HTTP\/1\.1 502 /);
                expect(p.connected).toEqual([]);
                expect(p.refusals).toEqual([{ reason: 'HOST_DID_NOT_RESOLVE', host: 'inflect.example.com' }]);
            }
        } finally {
            await failing.close();
            await empty.close();
        }
    });

    it('a host off the allowlist is refused before anything is resolved', async () => {
        let lookups = 0;
        const p = await pinned(async () => {
            lookups += 1;
            return ['93.184.216.34'];
        });
        try {
            expect(await exchange(p.port, 'CONNECT example.org:443 HTTP/1.1\r\n\r\n')).toMatch(/^HTTP\/1\.1 403 /);
            expect(lookups).toBe(0);
        } finally {
            await p.close();
        }
    });

    it('EGRESS_PRIVATE_CIDR_ALLOWLIST: absent is empty, and an entry that is not a CIDR stops the proxy at start', () => {
        expect(parseEgressPrivateCidrs(undefined)).toEqual([]);
        expect(parseEgressPrivateCidrs(' ')).toEqual([]);
        expect(parseEgressPrivateCidrs('10.0.0.0/8, fd00::/8')).toHaveLength(2);
        expect(() => parseEgressPrivateCidrs('10.0.0.0/8,internal.example')).toThrow('not a CIDR');
    });
});

describe('4. the proof', () => {
    const PROXY = 'http://harness-egress:3128';
    const env = { HTTPS_PROXY: PROXY, NODE_USE_ENV_PROXY: '1' };
    const probe = (over: Partial<{ allowed: number; canary: number; direct: boolean }> = {}): EgressProbe => ({
        connectThrough: async (_p, target) => (target.startsWith('inflect.example.com') ? (over.allowed ?? 200) : (over.canary ?? 403)),
        dialDirect: async () => over.direct ?? false,
    });
    const prove = (p: EgressProbe, e: Record<string, string> = env) =>
        proveEgress({ proxyUrl: PROXY, allowedHost: 'inflect.example.com', canaryHost: 'example.com', env: e, probe: p });

    it('is met when all four hold, and says what it observed', async () => {
        expect(await prove(probe())).toEqual({
            met: true,
            failed: null,
            evidence: 'egress:proxy=harness-egress:3128;allowed=inflect.example.com;canary=example.com:refused;direct=blocked',
        });
    });

    it.each([
        ['the scanner is not pointed at the proxy', probe(), { NODE_USE_ENV_PROXY: '1' }, 'ENV_PROXY_NOT_SET'],
        ['Node is not told to honour it', probe(), { HTTPS_PROXY: PROXY }, 'ENV_PROXY_NOT_SET'],
        ['the proxy refuses the Inflect host', probe({ allowed: 403 }), env, 'ALLOWED_HOST_REFUSED'],
        ['the proxy is unreachable', probe({ allowed: 0 }), env, 'ALLOWED_HOST_REFUSED'],
        ['the proxy admits the canary', probe({ canary: 200 }), env, 'CANARY_NOT_REFUSED'],
        ['the proxy fails rather than refusing the canary', probe({ canary: 502 }), env, 'CANARY_NOT_REFUSED'],
        ['the scanner can go around it', probe({ direct: true }), env, 'DIRECT_EGRESS_OPEN'],
    ])('is not met when %s', async (_label, p, e, failed) => {
        const proof = await prove(p, e);
        expect(proof).toMatchObject({ met: false, failed });
        expect(proof.evidence).toContain(`failed=${failed}`);
    });
});
