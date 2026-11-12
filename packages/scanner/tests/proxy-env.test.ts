/**
 * The proxy, as the environment names it: what `doctor` reports, never what
 * routes a request.
 */
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
