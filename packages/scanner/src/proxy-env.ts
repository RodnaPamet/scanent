/**
 * THE PROXY, AS THE ENVIRONMENT NAMES IT — read for reporting, never to route.
 *
 * The scanner routes nothing itself. With `NODE_USE_ENV_PROXY=1` (set in the
 * image; Node 24, and 22.21 or later) Node's own `fetch` honours `HTTPS_PROXY`
 * and `NO_PROXY`; without it, it ignores them. This module only DESCRIBES that
 * environment for `doctor`:
 *
 *   • `describeProxy` gives the proxy's scheme, host and port, and nothing
 *     else. A proxy URL may carry userinfo, which is a credential; no function
 *     here returns it.
 *   • `isProxied` says whether Node would send a host through the proxy, by
 *     Node's `NO_PROXY` rules: `*`, an exact name, `.suffix`, `*.suffix`, and
 *     an optional `:port`. A bare name matches that name only (observed on
 *     Node 22.22: `example.test` does not exempt `sub.example.test`). An
 *     address range is not understood and exempts nothing here, which can
 *     only cause a warning, never hide one.
 *
 * Neither decides anything about a request.
 */
export type Env = Readonly<Record<string, string | undefined>>;

const first = (env: Env, ...names: string[]): string | undefined => {
    for (const n of names) {
        const v = env[n];
        if (typeof v === 'string' && v.trim() !== '') return v.trim();
    }
    return undefined;
};

/** The https proxy the environment names, without its userinfo; null when none is named or it does not parse. */
export function describeProxy(env: Env): { readonly scheme: 'http' | 'https'; readonly host: string; readonly port: number } | null {
    const raw = first(env, 'HTTPS_PROXY', 'https_proxy');
    if (raw === undefined) return null;
    let u: URL;
    try {
        u = new URL(raw);
    } catch {
        return null;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const scheme = u.protocol === 'http:' ? 'http' : 'https';
    return { scheme, host: u.hostname, port: u.port === '' ? (scheme === 'http' ? 80 : 443) : Number(u.port) };
}

/** Whether a proxy variable is set at all, parseable or not. */
export function proxyVariableSet(env: Env): boolean {
    return first(env, 'HTTPS_PROXY', 'https_proxy') !== undefined;
}

/** Whether this Node honours `NODE_USE_ENV_PROXY`: 24 and later, and 22.21 and later. */
export function nodeHonoursEnvProxy(version: string): boolean {
    const m = /^v?(\d+)\.(\d+)\./.exec(version);
    if (m === null) return false;
    const major = Number(m[1]);
    const minor = Number(m[2]);
    return major >= 24 || (major === 22 && minor >= 21);
}

/** Whether requests go through the proxy at all: one is named, Node is told to use it, and this Node can. */
export function proxyInEffect(env: Env, nodeVersion: string): boolean {
    return describeProxy(env) !== null && env.NODE_USE_ENV_PROXY === '1' && nodeHonoursEnvProxy(nodeVersion);
}

/**
 * Whether Node would send an https request to `hostname` through the proxy,
 * given `NO_PROXY`. Assumes a proxy is in effect; ask `proxyInEffect` first.
 */
export function isProxied(hostname: string, env: Env, port = 443): boolean {
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const list = first(env, 'NO_PROXY', 'no_proxy');
    if (list === undefined) return true;
    for (const rawEntry of list.split(',')) {
        let entry = rawEntry.trim().toLowerCase();
        if (entry === '') continue;
        if (entry === '*') return false;
        const withPort = /^(.*):(\d{1,5})$/.exec(entry);
        // An IPv6 literal has colons of its own; only `name:port` is split.
        if (withPort !== null && !withPort[1].includes(':')) {
            if (Number(withPort[2]) !== port) continue;
            entry = withPort[1];
        }
        if (entry.startsWith('*.')) entry = entry.slice(1);
        if (entry.startsWith('.')) {
            if (host.endsWith(entry) && host.length > entry.length) return false;
        } else if (host === entry) {
            return false;
        }
    }
    return true;
}
