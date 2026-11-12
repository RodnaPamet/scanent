/**
 * The proxy, as the environment names it: what `doctor` reports, never what
 * routes a request.
 */
import { execFile } from 'child_process';
import { readFileSync } from 'fs';
import { createServer } from 'net';
import { join } from 'path';

import { bundledUndiciVersion, describeProxy, isProxied, nodeHonoursEnvProxy, noProxyRulesFor, proxyInEffect, proxyVariableSet } from '../src/proxy-env';

describe('describeProxy', () => {
    it('gives scheme, host and port, and never the userinfo', () => {
        const described = describeProxy({ HTTPS_PROXY: 'http://alice:marker-proxy-password@proxy.corp.example:3128' });
        expect(described).toEqual({ scheme: 'http', host: 'proxy.corp.example', port: 3128 });
        expect(JSON.stringify(described)).not.toMatch(/alice|marker-proxy-password/);
    });

    it('reads either spelling, defaults the port by scheme, and is null for none or nonsense', () => {
        expect(describeProxy({ https_proxy: 'https://proxy.example' })).toEqual({ scheme: 'https', host: 'proxy.example', port: 443 });
        expect(describeProxy({ HTTPS_PROXY: 'http://proxy.example' })).toEqual({ scheme: 'http', host: 'proxy.example', port: 80 });
        expect(describeProxy({})).toBeNull();
        expect(describeProxy({ HTTPS_PROXY: '  ' })).toBeNull();
        expect(describeProxy({ HTTPS_PROXY: 'not a url' })).toBeNull();
        expect(describeProxy({ HTTPS_PROXY: 'socks5://proxy.example:1080' })).toBeNull();
        expect(proxyVariableSet({ HTTPS_PROXY: 'not a url' })).toBe(true);
        expect(proxyVariableSet({ HTTP_PROXY: 'http://p' })).toBe(false);
    });
});

describe('whether Node uses it', () => {
    it.each([
        ['v24.0.0', true],
        ['v25.1.0', true],
        ['v22.21.0', true],
        ['v22.22.0', true],
        ['v22.20.9', false],
        ['v23.9.0', false],
        ['v20.19.0', false],
        ['nonsense', false],
    ])('%s honours NODE_USE_ENV_PROXY: %s', (version, expected) => {
        expect(nodeHonoursEnvProxy(version)).toBe(expected);
    });

    it('is in effect only with a proxy, the switch, and a Node that honours it', () => {
        const env = { HTTPS_PROXY: 'http://p.example:3128', NODE_USE_ENV_PROXY: '1' };
        expect(proxyInEffect(env, 'v24.1.0')).toBe(true);
        expect(proxyInEffect(env, 'v20.0.0')).toBe(false);
        expect(proxyInEffect({ HTTPS_PROXY: 'http://p.example:3128' }, 'v24.1.0')).toBe(false);
        expect(proxyInEffect({ NODE_USE_ENV_PROXY: '1' }, 'v24.1.0')).toBe(false);
    });
});

describe('isProxied, by the NO_PROXY rules of Node 22 (undici 6)', () => {
    // Each row was observed on Node 22.22 with NODE_USE_ENV_PROXY=1 and a local CONNECT proxy.
    const NO_PROXY = 'example.test, .dot.test,*.star.test,port.test:8443,ok.test:443,,';
    const UNDICI = '6.29.1';
    it.each([
        ['example.test', false],
        ['EXAMPLE.test', false],
        ['sub.example.test', true],
        ['other.test', true],
        ['dot.test', true],
        ['sub.dot.test', false],
        ['star.test', true],
        ['sub.star.test', false],
        ['port.test', true],
        ['ok.test', false],
    ])('%s goes through the proxy: %s', (host, expected) => {
        expect(isProxied(host, { NO_PROXY }, 443, UNDICI)).toBe(expected);
    });

    it('everything is proxied with no list, nothing with *, and the lower-case variable is read', () => {
        expect(isProxied('anything.test', {}, 443, UNDICI)).toBe(true);
        expect(isProxied('anything.test', { NO_PROXY: '*' }, 443, UNDICI)).toBe(false);
        expect(isProxied('a.test', { no_proxy: 'a.test' }, 443, UNDICI)).toBe(false);
        expect(isProxied('port.test', { NO_PROXY: 'port.test:8443' }, 8443, UNDICI)).toBe(false);
        // A bare IPv6 entry exempts its address on undici 8.10 and later only. Before, it is split at its last colon
        // into a name and a port, and Node sends the request to the proxy (observed on Node 22 and 24).
        expect(isProxied('[::1]', { NO_PROXY: '::1' }, 443, '8.12.4')).toBe(false);
        expect(isProxied('[::1]', { NO_PROXY: '::1' }, 443, UNDICI)).toBe(true);
        expect(isProxied('[::1]', { NO_PROXY: '[::1]' }, 443, UNDICI)).toBe(false);
    });

    it('an address range is not understood, and so exempts nothing', () => {
        for (const undici of ['6.29.1', '7.30.2', '8.12.4']) expect(isProxied('10.0.0.5', { NO_PROXY: '10.0.0.1-10.0.0.9' }, 443, undici)).toBe(true);
    });
});

describe('the NO_PROXY rules, by the undici a Node bundles', () => {
    it.each([
        ['6.14.0', { subdomains: false, ipv6: false, trailingDot: false, wildcard: false }],
        ['7.21.9', { subdomains: false, ipv6: false, trailingDot: false, wildcard: false }],
        ['7.22.0', { subdomains: true, ipv6: false, trailingDot: false, wildcard: false }],
        ['8.9.9', { subdomains: true, ipv6: false, trailingDot: false, wildcard: false }],
        ['8.10.0', { subdomains: true, ipv6: true, trailingDot: false, wildcard: false }],
        ['8.10.1', { subdomains: true, ipv6: true, trailingDot: true, wildcard: false }],
        ['8.11.0', { subdomains: true, ipv6: true, trailingDot: true, wildcard: true }],
        ['9.0.0', { subdomains: true, ipv6: true, trailingDot: true, wildcard: true }],
        ['', { subdomains: true, ipv6: true, trailingDot: true, wildcard: true }],
        ['nonsense', { subdomains: true, ipv6: true, trailingDot: true, wildcard: true }],
    ])('undici %s', (version, rules) => {
        expect(noProxyRulesFor(version)).toEqual(rules);
    });

    it('this Node says which undici it bundles', () => {
        expect(bundledUndiciVersion()).toBe((process.versions as Record<string, string | undefined>).undici ?? '');
    });

    // What seven Node versions did, recorded; isProxied is held to each of them, whichever Node runs this suite.
    const observed = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'no-proxy-observed.json'), 'utf8')) as {
        observedOn: Record<string, string>;
        hosts: string[];
        rows: { noProxy: string; byNode: Record<string, string> }[];
    };

    it('the record covers the three rule sets Node has shipped, and every row answers for every host', () => {
        expect(Object.keys(observed.observedOn)).toEqual(['22.21.0', '22.23.5', '24.0.0', '24.11.0', '24.22.2', '24.22.3', '26.13.1']);
        expect(observed.rows.length).toBeGreaterThanOrEqual(40);
        for (const row of observed.rows) {
            expect(Object.keys(row.byNode)).toEqual(Object.keys(observed.observedOn));
            for (const answer of Object.values(row.byNode)) expect(answer).toMatch(new RegExp(`^[P-]{${observed.hosts.length}}$`));
        }
    });

    it.each(Object.entries(observed.observedOn))('Node %s (undici %s): isProxied says what that Node did, for every list and host', (node, undici) => {
        for (const row of observed.rows) {
            const said = observed.hosts.map((h) => (isProxied(h, { NO_PROXY: row.noProxy }, 443, undici) ? 'P' : '-')).join('');
            expect({ noProxy: row.noProxy, said }).toEqual({ noProxy: row.noProxy, said: row.byNode[node] });
        }
    });

    // The two steps no Node here was run with (8.10.0, 8.10.1), from undici's source.
    it('undici 8.10.0 reads a bare IPv6 entry, and 8.10.1 drops a trailing dot', () => {
        expect(isProxied('[::1]', { NO_PROXY: '::1' }, 443, '8.9.9')).toBe(true);
        expect(isProxied('[::1]', { NO_PROXY: '::1' }, 443, '8.10.0')).toBe(false);
        expect(isProxied('[::1]', { NO_PROXY: '[::1]:8443' }, 8443, '8.10.0')).toBe(false);
        expect(isProxied('[::1]', { NO_PROXY: '[::1]:8443' }, 443, '8.10.0')).toBe(true);
        expect(isProxied('ok.test', { NO_PROXY: 'ok.test.' }, 443, '8.10.0')).toBe(true);
        expect(isProxied('ok.test', { NO_PROXY: 'ok.test.' }, 443, '8.10.1')).toBe(false);
        expect(isProxied('ok.test.', { NO_PROXY: 'ok.test' }, 443, '8.10.1')).toBe(false);
        expect(isProxied('ok.test', { NO_PROXY: 'none.test,*' }, 443, '8.10.1')).toBe(true);
        expect(isProxied('ok.test', { NO_PROXY: 'none.test,*' }, 443, '8.11.0')).toBe(false);
        expect(isProxied('ok.test', { NO_PROXY: '*:8443' }, 443, '8.11.0')).toBe(true);
        expect(isProxied('ok.test', { NO_PROXY: '*:8443' }, 8443, '8.11.0')).toBe(false);
    });

    it('the lower-case variable wins whenever it is set, even to nothing (observed on Node 22.23.5, 24.22.2 and 26.13.1)', () => {
        for (const undici of ['6.29.1', '7.30.1', '8.12.4']) {
            const both = { NO_PROXY: 'upper.test', no_proxy: 'lower.test' };
            expect(isProxied('upper.test', both, 443, undici)).toBe(true);
            expect(isProxied('lower.test', both, 443, undici)).toBe(false);
            expect(isProxied('upper.test', { NO_PROXY: 'upper.test', no_proxy: '' }, 443, undici)).toBe(true);
            expect(isProxied('upper.test', { NO_PROXY: 'upper.test', no_proxy: ' ' }, 443, undici)).toBe(true);
            expect(isProxied('lower.test', { NO_PROXY: ' ', no_proxy: 'lower.test' }, 443, undici)).toBe(false);
            expect(isProxied('upper.test', { NO_PROXY: 'upper.test' }, 443, undici)).toBe(false);
        }
    });
});

describe('isProxied agrees with the Node that runs it', () => {
    /**
     * Which of `hosts` Node's own `fetch` sends to the proxy under `NO_PROXY`:
     * a second Node process, a CONNECT listener here, and no name resolved off
     * this machine (see the probe).
     */
    async function nodeProxies(noProxy: Readonly<Record<string, string>>, hosts: readonly string[]): Promise<Record<string, boolean>> {
        const connects: string[] = [];
        const proxy = createServer((socket) => {
            socket.on('error', () => undefined);
            socket.once('data', (d) => {
                connects.push(String(d).split('\r\n')[0]);
                socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
            });
        });
        await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
        const { port } = proxy.address() as { port: number };
        try {
            await new Promise<void>((resolve, reject) => {
                execFile(
                    process.execPath,
                    [join(__dirname, 'fixtures', 'no-proxy-probe.js'), ...hosts],
                    { env: { PATH: process.env.PATH, HTTPS_PROXY: `http://127.0.0.1:${port}`, NODE_USE_ENV_PROXY: '1', NODE_NO_WARNINGS: '1', ...noProxy }, timeout: 30_000 },
                    (err) => (err ? reject(err) : resolve()),
                );
            });
        } finally {
            await new Promise((resolve) => proxy.close(resolve));
        }
        return Object.fromEntries(hosts.map((h) => [h, connects.includes(`CONNECT ${h}:443 HTTP/1.1`)]));
    }

    const HOSTS = ['mcp.estate.example', 'other.estate.example', 'sub.dot.test', 'dot.test', 'sub.star.test', 'star.test', 'port.test', 'ok.test', 'sub.ok.test', 'notok.test', 'localhost', '[::1]', 'ok.test.'];
    // A Node that ignores the proxy variables has nothing to agree with; the case is skipped by name there, never passed.
    const onThisNode = nodeHonoursEnvProxy(process.version) ? it.each : it.skip.each;

    onThisNode([
        ['whitespace between entries', 'localhost mcp.estate.example'],
        ['a tab and a newline between entries', 'localhost\tmcp.estate.example\n.dot.test'],
        ['commas', 'localhost,mcp.estate.example'],
        ['commas and spaces together', 'localhost, mcp.estate.example ,, .dot.test'],
        ['a leading dot and a star', '.dot.test,*.star.test'],
        ['ports', 'port.test:8443,ok.test:443'],
        ['one entry that is a star among others', 'ok.test,*'],
        ['a star and a space', '* '],
        ['a star with a port', '*:443'],
        ['a bare name, which may or may not cover its subdomains', 'ok.test'],
        ['a star against a name with no dot', '*ok.test'],
        ['a bare top-level name', 'test'],
        ['a bare IPv6 address', '::1'],
        ['a bracketed IPv6 address', '[::1]'],
        ['a trailing dot', 'ok.test.'],
        ['a lone dot', '.'],
        ['an address range', '10.0.0.0/8'],
        ['empty', ''],
    ])('%s: every host goes where isProxied says it does', async (_label, NO_PROXY) => {
        const actual = await nodeProxies({ NO_PROXY }, HOSTS);
        const said = Object.fromEntries(HOSTS.map((h) => [h, isProxied(h, { NO_PROXY })]));
        expect(said).toEqual(actual);
    }, 60_000);

    onThisNode([
        ['both spellings, differing', { NO_PROXY: 'ok.test', no_proxy: 'port.test' }],
        ['the lower-case one empty', { NO_PROXY: 'ok.test', no_proxy: '' }],
        ['the upper-case one empty', { NO_PROXY: '', no_proxy: 'port.test' }],
    ])('%s: every host goes where isProxied says it does', async (_label, env) => {
        const actual = await nodeProxies(env, HOSTS);
        const said = Object.fromEntries(HOSTS.map((h) => [h, isProxied(h, env)]));
        expect(said).toEqual(actual);
    }, 60_000);

    it('a whitespace-separated list exempts each name in it (the case Node and this function once read differently)', () => {
        const NO_PROXY = 'localhost mcp.estate.example\tthird.test\nfourth.test';
        for (const undici of ['6.29.1', '7.30.2', '8.12.4']) {
            for (const host of ['localhost', 'mcp.estate.example', 'third.test', 'fourth.test']) expect(isProxied(host, { NO_PROXY }, 443, undici)).toBe(false);
            expect(isProxied('other.estate.example', { NO_PROXY }, 443, undici)).toBe(true);
        }
    });
});
