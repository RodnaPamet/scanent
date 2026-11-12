/**
 * The proxy, as the environment names it: what `doctor` reports, never what
 * routes a request.
 */
import { execFile } from 'child_process';
import { createServer } from 'net';
import { join } from 'path';

import { describeProxy, isProxied, nodeHonoursEnvProxy, proxyInEffect, proxyVariableSet } from '../src/proxy-env';

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

describe('isProxied, by Node\'s NO_PROXY rules', () => {
    // Each row was observed on Node 22.22 with NODE_USE_ENV_PROXY=1 and a local CONNECT proxy.
    const NO_PROXY = 'example.test, .dot.test,*.star.test,port.test:8443,ok.test:443,,';
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
        expect(isProxied(host, { NO_PROXY })).toBe(expected);
    });

    it('everything is proxied with no list, nothing with *, and the lower-case variable is read', () => {
        expect(isProxied('anything.test', {})).toBe(true);
        expect(isProxied('anything.test', { NO_PROXY: '*' })).toBe(false);
        expect(isProxied('a.test', { no_proxy: 'a.test' })).toBe(false);
        expect(isProxied('port.test', { NO_PROXY: 'port.test:8443' }, 8443)).toBe(false);
        expect(isProxied('[::1]', { NO_PROXY: '::1' })).toBe(false);
    });

    it('an address range is not understood, and so exempts nothing', () => {
        expect(isProxied('10.0.0.5', { NO_PROXY: '10.0.0.1-10.0.0.9' })).toBe(true);
    });
});

describe('isProxied agrees with the Node that runs it', () => {
    /**
     * Which of `hosts` Node's own `fetch` sends to the proxy under `NO_PROXY`:
     * a second Node process, a CONNECT listener here, and no name resolved off
     * this machine (see the probe).
     */
    async function nodeProxies(NO_PROXY: string, hosts: readonly string[]): Promise<Record<string, boolean>> {
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
                    { env: { PATH: process.env.PATH, HTTPS_PROXY: `http://127.0.0.1:${port}`, NODE_USE_ENV_PROXY: '1', NO_PROXY, NODE_NO_WARNINGS: '1' }, timeout: 30_000 },
                    (err) => (err ? reject(err) : resolve()),
                );
            });
        } finally {
            await new Promise((resolve) => proxy.close(resolve));
        }
        return Object.fromEntries(hosts.map((h) => [h, connects.includes(`CONNECT ${h}:443 HTTP/1.1`)]));
    }

    const HOSTS = ['mcp.estate.example', 'other.estate.example', 'sub.dot.test', 'dot.test', 'sub.star.test', 'port.test', 'ok.test', 'sub.ok.test', 'localhost'];
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
        ['empty', ''],
    ])('%s: every host goes where isProxied says it does', async (_label, NO_PROXY) => {
        const actual = await nodeProxies(NO_PROXY, HOSTS);
        const said = Object.fromEntries(HOSTS.map((h) => [h, isProxied(h, { NO_PROXY })]));
        expect(said).toEqual(actual);
    }, 60_000);

    it('a whitespace-separated list exempts each name in it (the case Node and this function once read differently)', () => {
        const NO_PROXY = 'localhost mcp.estate.example\tthird.test\nfourth.test';
        for (const host of ['localhost', 'mcp.estate.example', 'third.test', 'fourth.test']) expect(isProxied(host, { NO_PROXY })).toBe(false);
        expect(isProxied('other.estate.example', { NO_PROXY })).toBe(true);
    });
});
