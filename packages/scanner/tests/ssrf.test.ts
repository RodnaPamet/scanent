/**
 * Server-side request forgery and DNS rebinding: the two places a name the
 * estate chose becomes an address the scanner dials.
 *
 *   A. `customer-host.ts`, for a host the configuration names (an MCP server, a
 *      self-hosted LangSmith): every spelling of a loopback, link-local,
 *      metadata or private address is refused, as a literal and as a
 *      resolver's answer; and the check is made before EVERY request.
 *   B. `egress-proxy.ts`, against a real listener on loopback: everything but
 *      a CONNECT to an allowlisted name on 443 is refused, a name is resolved
 *      once and the address that was checked is the one dialled, and a
 *      misbehaving client cannot take the proxy down.
 *
 * WHAT IS GUARANTEED ABOUT REBINDING, and what is not. Where the scanner
 * connects by itself, the check resolves the name and `fetch` resolves it
 * again: a resolver that answers differently inside that gap is not caught.
 * What IS held: the check runs before each request, never once per scan, and
 * every address of every answer is checked, so a name that rebinds between two
 * requests is refused at the second. Behind scanent's own proxy the gap does
 * not exist: the proxy resolves once and dials the address it checked. Section
 * A4 holds the first, B3 the second.
 */
import { EventEmitter } from 'node:events';
import type { IncomingMessage, Server } from 'node:http';
import { connect, createServer as createTcpServer, type AddressInfo, type Server as TcpServer, type Socket } from 'node:net';
import { Duplex } from 'node:stream';

import { parseScannerConfig } from '../src/config';
import {
    addressReachable,
    assertResolvesReachable,
    customerOriginProblem,
    isNeverAllowlistable,
    parsePrivateCidrAllowlist,
    type PrivateCidrAllowlist,
} from '../src/customer-host';
import { createEgressProxy, decideConnect, parseEgressAllowlist, parseEgressPrivateCidrs } from '../src/egress-proxy';
import type { FetchLike } from '../src/http';
import { jsonLineLog, type ScannerLog } from '../src/log';
import { runScan } from '../src/scan';
import { SourceReadError } from '../src/source';
import { langSmithFixture, LANGSMITH_SELF_HOSTED, MCP_CRM } from './helpers/agent-harness-source-fakes';
import { createEstateWorld, ESTATE_SOURCES, estateConfig, estateEnv, SELF_HOSTED_RUNTIME } from './helpers/estate-world';

// A slow runner must not fail a test that is only slow.
jest.setTimeout(60_000);

const NONE: PrivateCidrAllowlist = [];
const cidrs = (...entries: string[]): PrivateCidrAllowlist => parsePrivateCidrAllowlist(entries) as PrivateCidrAllowlist;
/** Every private range at once: what an operator who allowlists too much has written. */
const EVERYTHING = cidrs('0.0.0.0/0', '::/0');

describe('A1. an address that must never be reached, in every spelling', () => {
    // Each of these is loopback, "this host" or link-local (cloud metadata among it). No allowlist admits one.
    const NEVER: readonly [string, string][] = [
        ['loopback', '127.0.0.1'],
        ['loopback, another address of the block', '127.255.255.254'],
        ['this host', '0.0.0.0'],
        ['this network', '0.1.2.3'],
        ['cloud metadata', '169.254.169.254'],
        ['link-local', '169.254.0.1'],
        ['v6 loopback', '::1'],
        ['v6 loopback, written out', '0:0:0:0:0:0:0:1'],
        ['v6 unspecified', '::'],
        ['v6 link-local', 'fe80::1'],
        ['v6 link-local, the top of the block', 'febf::1'],
        ['the AWS v6 metadata address', 'fd00:ec2::254'],
        ['the Alibaba metadata address', '100.100.100.200'],
        ['the Oracle metadata address', '192.0.0.192'],
        ['the Alibaba metadata address, v4-mapped in hex', '::ffff:6464:64c8'],
        ['v4-translated loopback', '::ffff:0:127.0.0.1'],
        ['v4-translated loopback, in hex', '::ffff:0:7f00:1'],
        ['v4-translated metadata, in hex', '::ffff:0:a9fe:a9fe'],
        ['local-use NAT64 loopback', '64:ff9b:1::7f00:1'],
        ['local-use NAT64 metadata', '64:ff9b:1:abcd::a9fe:a9fe'],
        ['v4-mapped loopback', '::ffff:127.0.0.1'],
        ['v4-mapped loopback, in hex', '::ffff:7f00:1'],
        ['v4-mapped metadata', '::ffff:169.254.169.254'],
        ['v4-mapped metadata, in hex', '::ffff:a9fe:a9fe'],
        ['v4-compatible loopback', '::127.0.0.1'],
        ['v4-compatible metadata, in hex', '::a9fe:a9fe'],
        ['NAT64 loopback', '64:ff9b::127.0.0.1'],
        ['NAT64 metadata, in hex', '64:ff9b::a9fe:a9fe'],
        ['6to4 loopback', '2002:7f00:1::1'],
        ['6to4 metadata', '2002:a9fe:a9fe::1'],
    ];

    it.each(NEVER)('%s (%s) is refused with no allowlist', (_label, address) => {
        expect(addressReachable(address, NONE)).toBe(false);
    });

    // Every one is refused whatever the allowlist says. The AWS v6 metadata address used to be left out of this
    // case as a unique-local address an allowlist of its range admitted; it, and the two v4 metadata addresses that
    // sit inside ranges an operator may allowlist whole, are now on the never-allowlistable list themselves.
    it.each(NEVER)('%s (%s) is refused inside an allowlist that names everything', (_label, address) => {
        expect(addressReachable(address, EVERYTHING)).toBe(false);
    });

    it('a metadata address inside an allowlisted range stays refused, and its neighbours in the range do not', () => {
        for (const [range, metadata, neighbour] of [
            ['fd00::/8', 'fd00:ec2::254', 'fd00:ec2::253'],
            ['100.64.0.0/10', '100.100.100.200', '100.100.100.201'],
            ['192.0.0.0/24', '192.0.0.192', '192.0.0.8'],
        ] as const) {
            expect(addressReachable(metadata, cidrs(range))).toBe(false);
            expect(isNeverAllowlistable(metadata)).toBe(true);
            expect(addressReachable(neighbour, cidrs(range))).toBe(true);
            expect(customerOriginProblem(`https://${metadata.includes(':') ? `[${metadata}]` : metadata}`, cidrs(range))).not.toBeNull();
        }
    });

    it('the metadata addresses are never allowlistable, in the v4 spelling and each v6 spelling of it', () => {
        for (const address of ['169.254.169.254', '::ffff:169.254.169.254', '::ffff:a9fe:a9fe']) expect(isNeverAllowlistable(address)).toBe(true);
        expect(addressReachable('169.254.169.254', cidrs('169.254.0.0/16'))).toBe(false);
        expect(addressReachable('::ffff:a9fe:a9fe', cidrs('169.254.0.0/16', '::ffff:0:0/96'))).toBe(false);
    });
});

describe('A2. a private address, in every spelling', () => {
    const PRIVATE: readonly [string, string][] = [
        ['10/8', '10.0.0.7'],
        ['172.16/12', '172.31.255.1'],
        ['192.168/16', '192.168.1.1'],
        ['carrier-grade NAT', '100.64.0.1'],
        ['unique-local v6', 'fd12:3456::1'],
        ['unique-local v6, fc', 'fc00::1'],
        ['v4-mapped 10/8', '::ffff:10.0.0.7'],
        ['v4-mapped 10/8, in hex', '::ffff:a00:7'],
        ['v4-mapped 192.168/16, in hex', '::ffff:c0a8:101'],
        ['v4-compatible 10/8', '::10.0.0.7'],
        ['v4-compatible 10/8, in hex', '::a00:7'],
        ['NAT64 10/8', '64:ff9b::10.0.0.7'],
        ['NAT64 10/8, in hex', '64:ff9b::a00:7'],
        ['6to4 10/8', '2002:a00:7::1'],
        ['6to4 192.168/16', '2002:c0a8:101::1'],
        ['v4-translated 10/8', '::ffff:0:10.0.0.7'],
        ['v4-translated 10/8, in hex', '::ffff:0:a00:7'],
        ['local-use NAT64 10/8', '64:ff9b:1::a00:7'],
        ['local-use NAT64 holding a public v4: the prefix itself is local', '64:ff9b:1::5db8:d822'],
        ['site-local v6', 'fec0::1'],
        ['Teredo', '2001:0:4136:e378:8000:63bf:3fff:fdd2'],
        ['v6 multicast', 'ff02::1'],
        ['IETF protocol assignments', '192.0.0.8'],
        ['benchmarking', '198.18.0.1'],
        ['benchmarking, the top of the block', '198.19.255.254'],
        ['multicast', '224.0.0.1'],
        ['reserved', '240.0.0.1'],
        ['broadcast', '255.255.255.255'],
        ['multicast, v4-mapped in hex', '::ffff:e000:1'],
    ];

    it.each(PRIVATE)('%s (%s) is refused with no allowlist', (_label, address) => {
        expect(addressReachable(address, NONE)).toBe(false);
    });

    it.each(PRIVATE)('%s (%s) is reachable only when the allowlist names the range it is in', (_label, address) => {
        expect(addressReachable(address, EVERYTHING)).toBe(true);
        // An allowlist of some other range admits nothing here. (It was 198.18.0.0/15 until that range joined this table.)
        expect(addressReachable(address, cidrs('198.51.100.0/24'))).toBe(false);
    });

    it('a v4 address written inside a v6 one is admitted by the v4 range that holds it, and by no v6 range alone', () => {
        const ten = cidrs('10.0.0.0/8');
        for (const address of ['::ffff:10.0.0.7', '::ffff:a00:7', '::a00:7', '64:ff9b::a00:7', '2002:a00:7::1']) {
            expect(addressReachable(address, ten)).toBe(true);
            expect(addressReachable(address, cidrs('192.168.0.0/16'))).toBe(false);
        }
    });

    it.each([
        ['a public v4 address', '93.184.216.34'],
        ['a public v6 address', '2606:2800:220:1:248:1893:25c8:1946'],
        ['a public address, v4-mapped', '::ffff:93.184.216.34'],
        ['a public address, v4-mapped in hex', '::ffff:5db8:d822'],
        ['a public address through NAT64', '64:ff9b::5db8:d822'],
        ['a public address, v4-translated', '::ffff:0:5db8:d822'],
        ['the address below benchmarking', '198.17.255.255'],
        ['the address above benchmarking', '198.20.0.1'],
        ['the address below multicast', '223.255.255.254'],
        ['a global v6 address beside Teredo', '2001:1::1'],
    ])('%s (%s) is reachable', (_label, address) => {
        expect(addressReachable(address, NONE)).toBe(true);
    });

    it.each([
        ['not an address', 'not-an-address'],
        ['an empty string', ''],
        ['decimal', '2130706433'],
        ['octal', '0177.0.0.1'],
        ['hex', '0x7f.0.0.1'],
        ['a short form', '127.1'],
        ['a zone id', 'fe80::1%eth0'],
        ['a port', '10.0.0.1:443'],
        ['a CIDR', '10.0.0.0/8'],
        ['a trailing dot', '10.0.0.1.'],
        ['a name', 'localhost'],
        ['five octets', '1.2.3.4.5'],
        ['an octet over 255', '256.1.1.1'],
    ])('what a resolver must never answer (%s: %s) is not reachable: an answer that is not an address admits nothing', (_label, address) => {
        expect(addressReachable(address, NONE)).toBe(false);
        expect(addressReachable(address, EVERYTHING)).toBe(false);
    });
});

describe('A3. a host in the configuration, in every spelling a URL allows', () => {
    const REFUSED: readonly [string, string][] = [
        ['loopback', 'https://127.0.0.1'],
        ['loopback in decimal', 'https://2130706433'],
        ['loopback in octal', 'https://0177.0.0.1'],
        ['loopback in hex', 'https://0x7f.0.0.1'],
        ['loopback in one hex number', 'https://0x7f000001'],
        ['loopback, short form', 'https://127.1'],
        ['loopback with a trailing dot', 'https://127.0.0.1.'],
        ['metadata', 'https://169.254.169.254'],
        ['metadata in decimal', 'https://2852039166'],
        ['a private address', 'https://10.0.0.7'],
        ['a private address in hex', 'https://0xa.0.0.7'],
        ['v6 loopback', 'https://[::1]'],
        ['v6 unspecified', 'https://[::]'],
        ['v4-mapped loopback', 'https://[::ffff:127.0.0.1]'],
        ['v4-mapped private', 'https://[::ffff:10.0.0.7]'],
        ['v4-mapped private, in hex', 'https://[::ffff:a00:7]'],
        ['v4-compatible private', 'https://[::10.0.0.7]'],
        ['NAT64 private', 'https://[64:ff9b::10.0.0.7]'],
        ['6to4 private', 'https://[2002:a00:7::1]'],
        ['unique-local v6', 'https://[fd00::1]'],
        ['link-local v6', 'https://[fe80::1]'],
        ['the AWS v6 metadata address', 'https://[fd00:ec2::254]'],
        ['the Alibaba metadata address', 'https://100.100.100.200'],
        ['v4-translated loopback', 'https://[::ffff:0:7f00:1]'],
        ['local-use NAT64 loopback', 'https://[64:ff9b:1::7f00:1]'],
        ['local-use NAT64 private', 'https://[64:ff9b:1::a00:7]'],
        ['site-local v6', 'https://[fec0::1]'],
        ['v6 multicast', 'https://[ff02::1]'],
        ['Teredo', 'https://[2001::1]'],
        ['benchmarking', 'https://198.18.0.1'],
        ['IETF protocol assignments', 'https://192.0.0.8'],
        ['reserved', 'https://240.0.0.1'],
        ['multicast', 'https://224.0.0.1'],
        ['localhost', 'https://localhost'],
        ['localhost in upper case', 'https://LOCALHOST'],
        ['localhost with a trailing dot', 'https://localhost.'],
        ['a subdomain of localhost', 'https://app.localhost'],
        ['the metadata name', 'https://metadata.google.internal'],
        ['the metadata name with a trailing dot', 'https://metadata.google.internal.'],
        ['the metadata name in upper case', 'https://METADATA.GOOGLE.INTERNAL'],
        ['the bare metadata name', 'https://metadata'],
        ['an internal suffix', 'https://langsmith.corp.internal'],
        ['an internal suffix with a trailing dot', 'https://langsmith.corp.internal.'],
        ['a local suffix', 'https://printer.local'],
        ['a local suffix with a trailing dot', 'https://printer.local.'],
        ['userinfo', 'https://user:pw@langsmith.example.com'],
        ['a user name alone', 'https://user@langsmith.example.com'],
        ['clear text', 'http://langsmith.example.com'],
        ['another scheme', 'ftp://langsmith.example.com'],
        ['a path', 'https://langsmith.example.com/api'],
        ['a query', 'https://langsmith.example.com/?x=1'],
        ['a fragment', 'https://langsmith.example.com/#x'],
        ['a zone id', 'https://[fe80::1%25eth0]'],
        ['not a URL', 'langsmith.example.com'],
        ['nothing', ''],
    ];

    it.each(REFUSED)('%s (%s) is refused', (_label, value) => {
        expect(customerOriginProblem(value)).not.toBeNull();
    });

    it('the refusal names a rule and never repeats the value', () => {
        for (const [, value] of REFUSED) {
            const problem = customerOriginProblem(value) as string;
            if (value !== '') expect(problem).not.toContain(value.replace(/^https?:\/\//, ''));
        }
    });

    it('a public name and a public address are accepted, on any port the URL can carry', () => {
        for (const value of ['https://langsmith.example.com', 'https://LANGSMITH.example.com', 'https://93.184.216.34', 'https://langsmith.example.com:8443', 'https://[2606:2800:220:1::1]']) {
            expect(customerOriginProblem(value)).toBeNull();
        }
    });

    it('an allowlist relaxes the suffix rule and admits a private literal inside it, and nothing that is never allowlistable', () => {
        const ten = cidrs('10.0.0.0/8');
        expect(customerOriginProblem('https://langsmith.corp.internal', ten)).toBeNull();
        expect(customerOriginProblem('https://10.0.0.7', ten)).toBeNull();
        expect(customerOriginProblem('https://192.168.1.1', ten)).not.toBeNull();
        for (const value of ['https://127.0.0.1', 'https://169.254.169.254', 'https://[::1]', 'https://[::ffff:7f00:1]', 'https://localhost', 'https://localhost.', 'https://metadata.google.internal.']) {
            expect(customerOriginProblem(value, EVERYTHING)).not.toBeNull();
        }
    });

    it('the configuration refuses each of them for an MCP server and for a self-hosted LangSmith', () => {
        for (const [label, value] of REFUSED) {
            // An MCP endpoint is a URL with a path: that one rule is LangSmith's alone.
            if (label !== 'a path') expect(() => parseScannerConfig(estateConfig([{ kind: 'mcp', servers: [{ label: 'x', url: `${value}/mcp` }] }]))).toThrow();
            expect(() => parseScannerConfig(estateConfig([{ ...SELF_HOSTED_RUNTIME, endpoint: { selfHosted: value } }]))).toThrow();
        }
    });
});

describe('A4. what a name resolves to, checked before every request', () => {
    const refused = async (resolve: () => Promise<readonly string[]>, allowlist: PrivateCidrAllowlist = NONE): Promise<boolean> => {
        try {
            await assertResolvesReachable('mcp.acme.example', resolve, allowlist);
            return false;
        } catch (err) {
            expect(err).toBeInstanceOf(SourceReadError);
            expect((err as SourceReadError).reason).toBe('UNREACHABLE');
            // The message names the rule, never the address.
            expect((err as SourceReadError).message).not.toMatch(/\d+\.\d+\.\d+\.\d+|::/);
            return true;
        }
    };

    it.each([
        ['one public and one private address', ['93.184.216.34', '10.0.0.7']],
        ['one public and the metadata address', ['93.184.216.34', '169.254.169.254']],
        ['a private address last of many', ['93.184.216.34', '93.184.216.35', '93.184.216.36', '192.168.0.1']],
        ['a v4-mapped private address in hex', ['::ffff:a00:7']],
        ['a NAT64 spelling of metadata', ['64:ff9b::a9fe:a9fe']],
        ['v6 loopback beside a public v4', ['93.184.216.34', '::1']],
        ['something that is not an address', ['93.184.216.34', 'not-an-address']],
        ['nothing', []],
    ])('a name that resolves to %s is refused', async (_label, addresses) => {
        expect(await refused(async () => addresses)).toBe(true);
    });

    it('a name that does not resolve is refused, and so is one whose resolver throws anything', async () => {
        expect(await refused(async () => Promise.reject(new Error('ENOTFOUND')))).toBe(true);
        expect(await refused(async () => Promise.reject('not an error'))).toBe(true);
    });

    it('every address public, or private inside the allowlist, is accepted', async () => {
        expect(await refused(async () => ['93.184.216.34', '2606:2800:220:1::1'])).toBe(false);
        expect(await refused(async () => ['10.20.3.4', '10.20.3.5'], cidrs('10.20.0.0/16'))).toBe(false);
        expect(await refused(async () => ['10.20.3.4', '10.99.0.1'], cidrs('10.20.0.0/16'))).toBe(true);
    });

    const NOW = Date.parse('2026-10-19T03:00:00.000Z');
    const quiet = jsonLineLog(() => undefined);

    it.each([
        ['an MCP server', ESTATE_SOURCES.mcp, 'mcp', new URL(MCP_CRM).hostname],
        ['a self-hosted LangSmith', SELF_HOSTED_RUNTIME, 'runtime', new URL(LANGSMITH_SELF_HOSTED).hostname],
    ] as const)('%s: the name is resolved before each request, and a rebind between two requests stops the read', async (_label, source, kind, hostname) => {
        const world = createEstateWorld({ fakes: { langsmith: { [LANGSMITH_SELF_HOSTED]: { ...langSmithFixture(), selfHosted: true } } } });
        const requests: string[] = [];
        const wire: FetchLike = async (url, init) => {
            requests.push(new URL(url).hostname);
            return world.fetchImpl(url, init);
        };
        // An honest resolver: the read completes, and the name was resolved at least once per request to that host.
        let lookups = 0;
        const honest = await runScan({
            config: parseScannerConfig(estateConfig([source])),
            env: estateEnv(),
            log: quiet,
            fetchImpl: wire,
            resolveHost: async () => {
                lookups += 1;
                return ['93.184.216.34'];
            },
            now: () => NOW,
        });
        expect(honest.body.population.sources[0]).toMatchObject({ kind, status: 'COMPLETE' });
        const toHost = requests.filter((h) => h === hostname).length;
        expect(toHost).toBeGreaterThan(1);
        expect(lookups).toBeGreaterThanOrEqual(toHost);

        // A resolver that answers a public address once and the metadata address ever after.
        requests.length = 0;
        let answered = 0;
        const rebound = await runScan({
            config: parseScannerConfig(estateConfig([source])),
            env: estateEnv(),
            log: quiet,
            fetchImpl: wire,
            resolveHost: async (name) => {
                if (name !== hostname) return ['93.184.216.34'];
                answered += 1;
                return answered === 1 ? ['93.184.216.34'] : ['169.254.169.254'];
            },
            now: () => NOW,
        });
        expect(rebound.body.population.sources[0]).toMatchObject({ kind, status: 'INCOMPLETE', reason: 'UNREACHABLE' });
        // Exactly the one request made while the name still pointed somewhere public; the next was never sent.
        expect(requests.filter((h) => h === hostname)).toHaveLength(1);
    });

    it('a redirect is refused, never followed: every request is made with redirect "error", and a 3xx answer ends the read', async () => {
        const world = createEstateWorld();
        const modes = new Set<string | undefined>();
        const asked: string[] = [];
        const wire: FetchLike = async (url, init) => {
            modes.add(init.redirect);
            asked.push(url);
            if (new URL(url).hostname === new URL(MCP_CRM).hostname) {
                return new Response(null, { status: 307, headers: { location: 'https://169.254.169.254/latest/meta-data/' } });
            }
            return world.fetchImpl(url, init);
        };
        const { body } = await runScan({
            config: parseScannerConfig(estateConfig([ESTATE_SOURCES.mcp, ESTATE_SOURCES['okta-app']])),
            env: estateEnv(),
            log: quiet,
            fetchImpl: wire,
            resolveHost: async () => ['93.184.216.34'],
            now: () => NOW,
        });
        expect([...modes]).toEqual(['error']);
        expect(body.population.sources.find((s) => s.kind === 'mcp')).toMatchObject({ status: 'INCOMPLETE', reason: 'UNREACHABLE' });
        expect(body.population.sources.find((s) => s.kind === 'okta-app')).toMatchObject({ status: 'COMPLETE' });
        expect(asked.filter((u) => u.includes('169.254'))).toEqual([]);
    });
});

// ── The egress proxy, against a real listener ──

const quietLog: ScannerLog = { info: () => {}, warn: () => {}, error: () => {} };
const ALLOW = new Set(['inflect.example.com', 'mcp.acme.example']);

interface Harness {
    readonly port: number;
    readonly connected: string[];
    readonly lookups: string[];
    readonly log: { level: string; msg: string; fields: Record<string, unknown> }[];
    readonly proxy: Server;
    close(): Promise<void>;
}

/** A proxy on the production path over loopback: it resolves with `answers`, and "connects" to an echo server, recording the address it was asked to dial. */
async function harness(answers: (host: string, call: number) => readonly string[] | Promise<readonly string[]>, privateCidrs?: string): Promise<Harness> {
    const connected: string[] = [];
    const lookups: string[] = [];
    const log: Harness['log'] = [];
    const echo: TcpServer = createTcpServer((s) => s.pipe(s));
    await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
    const echoPort = (echo.address() as AddressInfo).port;
    const record = (level: string) => (msg: string, fields?: Record<string, unknown>) => void log.push({ level, msg, fields: fields ?? {} });
    const proxy = createEgressProxy({
        allow: ALLOW,
        log: { info: record('info'), warn: record('warn'), error: record('error') },
        resolve: async (host) => {
            lookups.push(host);
            return answers(host, lookups.length);
        },
        privateCidrs: parseEgressPrivateCidrs(privateCidrs),
        connectAddress: (address, port) => {
            connected.push(`${address}:${port}`);
            return connect({ host: '127.0.0.1', port: echoPort });
        },
    });
    await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
    return {
        port: (proxy.address() as AddressInfo).port,
        connected,
        lookups,
        log,
        proxy,
        close: async () => {
            proxy.closeAllConnections();
            await new Promise((r) => proxy.close(r));
            await new Promise((r) => echo.close(r));
        },
    };
}

/** Send raw bytes and read until the proxy closes, `until` matches, or `ms` passes. */
function exchange(port: number, bytes: string | Buffer, until?: RegExp, ms = 5_000): Promise<string> {
    return new Promise((resolve) => {
        const s: Socket = connect({ host: '127.0.0.1', port });
        let got = '';
        const done = () => {
            clearTimeout(timer);
            s.destroy();
            resolve(got);
        };
        const timer = setTimeout(done, ms);
        s.on('data', (d) => {
            got += d.toString('latin1');
            if (until && until.test(got)) done();
        });
        s.on('close', done);
        s.on('error', done);
        s.write(bytes);
    });
}

const CONNECT = (target: string) => `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`;
const OK = /^HTTP\/1\.1 200 /;

describe('B1. what the proxy refuses, and that it keeps serving afterwards', () => {
    let h: Harness;
    beforeAll(async () => {
        h = await harness(() => ['93.184.216.34']);
    });
    afterAll(async () => {
        await h.close();
    });
    const stillServes = async () => expect(await exchange(h.port, CONNECT('inflect.example.com:443'), /\r\n\r\n/)).toMatch(OK);

    it.each([
        ['GET, origin-form', 'GET / HTTP/1.1\r\nHost: inflect.example.com\r\n\r\n', /^HTTP\/1\.1 405 /],
        ['GET, absolute-form', 'GET http://inflect.example.com/ HTTP/1.1\r\nHost: inflect.example.com\r\n\r\n', /^HTTP\/1\.1 405 /],
        ['GET, absolute-form over https', 'GET https://inflect.example.com/ HTTP/1.1\r\nHost: inflect.example.com\r\n\r\n', /^HTTP\/1\.1 405 /],
        ['POST', 'POST / HTTP/1.1\r\nHost: inflect.example.com\r\nContent-Length: 2\r\n\r\n{}', /^HTTP\/1\.1 405 /],
        ['PUT', 'PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n', /^HTTP\/1\.1 405 /],
        ['DELETE', 'DELETE / HTTP/1.1\r\nHost: x\r\n\r\n', /^HTTP\/1\.1 405 /],
        ['OPTIONS', 'OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n', /^HTTP\/1\.1 405 /],
        ['TRACE', 'TRACE / HTTP/1.1\r\nHost: x\r\n\r\n', /^HTTP\/1\.1 405 /],
        ['an upgrade to a websocket', 'GET / HTTP/1.1\r\nHost: inflect.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n', /^HTTP\/1\.1 4\d\d /],
    ])('%s is refused, and nothing is resolved or dialled', async (_label, request, status) => {
        h.lookups.length = 0;
        h.connected.length = 0;
        expect(await exchange(h.port, request)).toMatch(status);
        expect(h.lookups).toEqual([]);
        expect(h.connected).toEqual([]);
        await stillServes();
    });

    it.each([
        ['a port other than 443', 'inflect.example.com:80', 403],
        ['port 8443', 'inflect.example.com:8443', 403],
        ['port 0', 'inflect.example.com:0', 403],
        ['a port past the range', 'inflect.example.com:99999', 403],
        ['a host off the list', 'evil.example:443', 403],
        ['a subdomain of a listed host', 'a.inflect.example.com:443', 403],
        ['a listed host as a suffix', 'inflect.example.com.evil.example:443', 403],
        ['a listed host with a trailing dot', 'inflect.example.com.:443', 403],
        ['an IPv4 literal', '93.184.216.34:443', 403],
        ['loopback', '127.0.0.1:443', 403],
        ['metadata', '169.254.169.254:443', 403],
        ['an IPv4 literal in decimal', '2130706433:443', 403],
        ['an IPv6 literal', '[::1]:443', 400],
        ['userinfo', 'user@inflect.example.com:443', 400],
        ['no port', 'inflect.example.com', 400],
        ['a path', 'inflect.example.com:443/x', 400],
        ['an empty target', ':443', 400],
    ])('a CONNECT to %s (%s) is refused, and nothing is resolved or dialled', async (_label, target, status) => {
        h.lookups.length = 0;
        h.connected.length = 0;
        expect(await exchange(h.port, CONNECT(target))).toMatch(new RegExp(`^HTTP/1\\.1 ${status} `));
        expect(h.lookups).toEqual([]);
        expect(h.connected).toEqual([]);
        await stillServes();
    });

    it('the decision is the same in every spelling of case, and no spelling widens it', () => {
        expect(decideConnect('INFLECT.EXAMPLE.COM:443', ALLOW)).toMatchObject({ allowed: true, host: 'inflect.example.com' });
        for (const target of ['inflect.example.com:443 ', ' inflect.example.com:443', 'inflect.example.com:443\r\nX: y', 'inflect.example.com:+443', 'inflect.example.com:0443x', 'inflect.example.com:443:443', '*:443', 'inflect.*.com:443']) {
            expect(decideConnect(target, ALLOW).allowed).toBe(false);
        }
        expect(() => parseEgressAllowlist('*')).toThrow();
        expect(() => parseEgressAllowlist('inflect.example.com,*.example.com')).toThrow();
    });

    it('a request line of 64 KiB is refused or closed, and the proxy keeps serving', async () => {
        const answer = await exchange(h.port, `CONNECT ${'a'.repeat(64 * 1024)}.example.com:443 HTTP/1.1\r\n\r\n`);
        expect(answer).not.toMatch(OK);
        expect(h.connected.filter((c) => c.includes('aaaa'))).toEqual([]);
        await stillServes();
    });

    it('a flood of headers is refused or closed, and the proxy keeps serving', async () => {
        const headers = Array.from({ length: 5_000 }, (_, i) => `X-Flood-${i}: ${'v'.repeat(40)}\r\n`).join('');
        const answer = await exchange(h.port, `CONNECT inflect.example.com:443 HTTP/1.1\r\n${headers}\r\n`);
        expect(answer).not.toMatch(OK);
        await stillServes();
    });

    it('bytes that are not HTTP are refused or closed, and the proxy keeps serving', async () => {
        for (const junk of [Buffer.from([0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03]), Buffer.alloc(4096, 0), Buffer.from('\r\n\r\n\r\n'), Buffer.from('CONNECT\r\n\r\n')]) {
            expect(await exchange(h.port, junk, undefined, 1_500)).not.toMatch(OK);
        }
        await stillServes();
    });

    it('a slow client that never finishes its request holds one socket and nothing else: others are served meanwhile', async () => {
        const slow = connect({ host: '127.0.0.1', port: h.port });
        await new Promise<void>((r) => slow.once('connect', r));
        slow.write('CONNECT inflect.example.com:443 HTTP/1.1\r\nHost: inf');
        try {
            for (let i = 0; i < 5; i++) await stillServes();
            expect(h.connected.length).toBeGreaterThan(0);
        } finally {
            slow.destroy();
        }
        // The half-sent request never opened anything.
        await stillServes();
    });

    it('fifty clients that connect and hang up at once leave the proxy serving', async () => {
        await Promise.all(
            Array.from({ length: 50 }, (_, i) =>
                new Promise<void>((resolve) => {
                    const s = connect({ host: '127.0.0.1', port: h.port });
                    s.on('error', () => resolve());
                    s.on('close', () => resolve());
                    s.once('connect', () => {
                        s.write(i % 2 === 0 ? CONNECT('evil.example:443') : CONNECT('inflect.example.com:443'));
                        // Hang up without reading: a reset, where the platform gives one.
                        setImmediate(() => (typeof s.resetAndDestroy === 'function' ? s.resetAndDestroy() : s.destroy()));
                    });
                }),
            ),
        );
        await stillServes();
    });
});

describe('B2. a client that goes away mid-answer cannot take the proxy down', () => {
    /** A client socket the proxy is handed for a CONNECT, with no listener of its own: an `error` on it would be uncaught. */
    function strayClient(): Duplex {
        return new Duplex({ read() {}, write(_chunk, _enc, cb) { cb(); } });
    }
    const request = (url: string): IncomingMessage => Object.assign(new EventEmitter(), { url, method: 'CONNECT' }) as unknown as IncomingMessage;
    const reset = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });

    it.each([
        ['a refused target', 'evil.example:443', async () => ['93.184.216.34']],
        ['a malformed target', 'not a target', async () => ['93.184.216.34']],
        ['a name that resolves to a refused address', 'inflect.example.com:443', async () => ['127.0.0.1']],
        ['a name that does not resolve', 'inflect.example.com:443', async () => Promise.reject(new Error('ENOTFOUND'))],
        ['a name still being resolved', 'inflect.example.com:443', () => new Promise<readonly string[]>(() => undefined)],
    ])('a reset from the client after %s is absorbed, however many times it arrives', async (_label, target, resolve) => {
        const proxy = createEgressProxy({ allow: ALLOW, log: quietLog, resolve, connectAddress: () => connect({ host: '127.0.0.1', port: 9 }) });
        const client = strayClient();
        proxy.emit('connect', request(target), client, Buffer.alloc(0));
        await new Promise((r) => setImmediate(r));
        // With no listener, `emit('error')` throws: in the running proxy that is an uncaught exception and the process ends.
        expect(() => client.emit('error', reset)).not.toThrow();
        expect(() => client.emit('error', reset)).not.toThrow();
        expect(client.listenerCount('error')).toBeGreaterThan(0);
    });

    it('a reset from the client, twice, after the tunnel opened is absorbed too, and the upstream is closed', async () => {
        const upstreams: Socket[] = [];
        const echo: TcpServer = createTcpServer((s) => s.pipe(s));
        await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
        const proxy = createEgressProxy({
            allow: ALLOW,
            log: quietLog,
            resolve: async () => ['93.184.216.34'],
            connectAddress: () => {
                const s = connect({ host: '127.0.0.1', port: (echo.address() as AddressInfo).port });
                upstreams.push(s);
                return s;
            },
        });
        const client = strayClient();
        try {
            proxy.emit('connect', request('inflect.example.com:443'), client, Buffer.alloc(0));
            await new Promise<void>((r) => {
                const wait = () => (upstreams.length > 0 && !upstreams[0].connecting ? r() : setTimeout(wait, 5));
                wait();
            });
            expect(() => client.emit('error', reset)).not.toThrow();
            expect(() => client.emit('error', reset)).not.toThrow();
            await new Promise((r) => setTimeout(r, 20));
            expect(upstreams[0].destroyed).toBe(true);
        } finally {
            for (const upstream of upstreams) upstream.destroy();
            await new Promise((r) => echo.close(r));
        }
    });
});

describe('B3. the address that was checked is the address dialled', () => {
    it.each([
        ['loopback', ['127.0.0.1']],
        ['v6 loopback', ['::1']],
        ['link-local, cloud metadata', ['169.254.169.254']],
        ['a private address', ['10.0.0.7']],
        ['a private address beside a public one', ['93.184.216.34', '192.168.0.9']],
        ['a v4-mapped private address in hex', ['::ffff:a00:7']],
        ['a v4-mapped loopback in hex', ['::ffff:7f00:1']],
        ['a NAT64 spelling of metadata', ['64:ff9b::a9fe:a9fe']],
        ['a 6to4 spelling of a private address', ['2002:a00:7::1']],
        ['something that is not an address', ['not-an-address']],
    ])('an allowlisted name that resolves to %s is refused, and no upstream socket is opened', async (_label, addresses) => {
        const h = await harness(() => addresses);
        try {
            expect(await exchange(h.port, CONNECT('mcp.acme.example:443'))).toMatch(/^HTTP\/1\.1 403 /);
            expect(h.connected).toEqual([]);
            expect(h.log.filter((l) => l.msg === 'egress refused').map((l) => l.fields)).toEqual([{ reason: 'ADDRESS_NOT_ALLOWED', host: 'mcp.acme.example' }]);
            expect(h.log.some((l) => l.msg === 'egress allowed')).toBe(false);
        } finally {
            await h.close();
        }
    });

    it('a resolver that answers differently the second time is never asked twice: the tunnel goes to the first, checked answer', async () => {
        const h = await harness((_host, call) => (call === 1 ? ['93.184.216.34'] : ['169.254.169.254']));
        try {
            expect(await exchange(h.port, CONNECT('mcp.acme.example:443'), /\r\n\r\n/)).toMatch(OK);
            expect(h.lookups).toEqual(['mcp.acme.example']);
            expect(h.connected).toEqual(['93.184.216.34:443']);
            // A second tunnel is a second decision: it resolves again, gets the rebound answer, and is refused.
            expect(await exchange(h.port, CONNECT('mcp.acme.example:443'))).toMatch(/^HTTP\/1\.1 403 /);
            expect(h.lookups).toEqual(['mcp.acme.example', 'mcp.acme.example']);
            expect(h.connected).toEqual(['93.184.216.34:443']);
        } finally {
            await h.close();
        }
    });

    it('the first address is dialled when several pass, and only after every one passed', async () => {
        const h = await harness(() => ['93.184.216.34', '93.184.216.35']);
        try {
            expect(await exchange(h.port, CONNECT('inflect.example.com:443'), /\r\n\r\n/)).toMatch(OK);
            expect(h.connected).toEqual(['93.184.216.34:443']);
        } finally {
            await h.close();
        }
    });

    it('a private range the operator allowlisted is dialled; a never-allowlistable address inside it is not', async () => {
        const inside = await harness(() => ['10.20.3.4'], '10.20.0.0/16');
        const never = await harness(() => ['127.0.0.1'], '0.0.0.0/0');
        const mapped = await harness(() => ['::ffff:7f00:1'], '0.0.0.0/0,::/0');
        try {
            expect(await exchange(inside.port, CONNECT('mcp.acme.example:443'), /\r\n\r\n/)).toMatch(OK);
            expect(inside.connected).toEqual(['10.20.3.4:443']);
            expect(await exchange(never.port, CONNECT('mcp.acme.example:443'))).toMatch(/^HTTP\/1\.1 403 /);
            expect(await exchange(mapped.port, CONNECT('mcp.acme.example:443'))).toMatch(/^HTTP\/1\.1 403 /);
            expect([...never.connected, ...mapped.connected]).toEqual([]);
        } finally {
            await inside.close();
            await never.close();
            await mapped.close();
        }
    });
});
