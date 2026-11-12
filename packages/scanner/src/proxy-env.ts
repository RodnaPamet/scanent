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
 *     the `NO_PROXY` rules of the Node that runs. The rules are not one set:
 *     Node's `fetch` takes them from the undici it bundles, and undici has
 *     changed them twice (see `noProxyRulesFor`). The image's Node 24 reads a
 *     bare name as that name and its subdomains; Node 22 reads it as that
 *     name only. A test asks a second Node process which hosts its own
 *     `fetch` sends to the proxy and holds this function to the answer, on
 *     each Node the suite runs under. An address range is not understood by
 *     any of them and exempts nothing.
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
 * How the undici inside a Node reads `NO_PROXY`. Each field is a change in
 * undici's `EnvHttpProxyAgent`, named by the first version that has it.
 */
export interface NoProxyRules {
    /** 7.22.0: an entry exempts its name AND its subdomains, and a leading `.` or `*.` is dropped. Before: a bare name is exact, and `.x` or `*x` is a suffix that leaves `x` itself proxied. */
    readonly subdomains: boolean;
    /** 8.10.0: brackets are dropped from an IPv6 literal on both sides, and a bare IPv6 entry is not split at its last colon. */
    readonly ipv6: boolean;
    /** 8.10.1: one trailing dot is dropped from the host and from an entry. */
    readonly trailingDot: boolean;
    /** 8.11.0: `*` exempts every host wherever it stands in the list, and `*.x` exempts the subdomains of `x` but not `x`. */
    readonly wildcard: boolean;
}

const atLeast = (version: readonly number[], floor: readonly number[]): boolean => {
    for (let i = 0; i < 3; i++) {
        if (version[i] !== floor[i]) return version[i] > floor[i];
    }
    return true;
};

/**
 * The rules of one undici version (`process.versions.undici`). Observed, with
 * `NODE_USE_ENV_PROXY=1` and a local CONNECT proxy, on Node 22.21.0 and
 * 22.23.5 (undici 6.22.0, 6.29.1), 24.0.0 and 24.11.0 (7.8.0, 7.16.0),
 * 24.22.2 and 24.22.3 (7.30.1, 7.30.2) and 26.13.1 (8.12.4); the two steps
 * between (8.10.0, 8.10.1) are read from undici's source and were not run. A
 * version that does not parse, and any later one, gets the newest rules.
 */
export function noProxyRulesFor(undiciVersion: string): NoProxyRules {
    const m = /^(\d+)\.(\d+)\.(\d+)/.exec(undiciVersion);
    const v = m === null ? [Infinity, 0, 0] : [Number(m[1]), Number(m[2]), Number(m[3])];
    return {
        subdomains: atLeast(v, [7, 22, 0]),
        ipv6: atLeast(v, [8, 10, 0]),
        trailingDot: atLeast(v, [8, 10, 1]),
        wildcard: atLeast(v, [8, 11, 0]),
    };
}

/** The undici inside the Node that runs this; empty where Node does not say. */
export function bundledUndiciVersion(): string {
    return (process.versions as Readonly<Record<string, string | undefined>>).undici ?? '';
}

/**
 * Whether Node would send an https request to `hostname` through the proxy,
 * given `NO_PROXY`. Assumes a proxy is in effect; ask `proxyInEffect` first.
 *
 * It follows undici's own steps, in undici's order, for the version given
 * (the running Node's unless told otherwise). The lower-case variable wins
 * whenever it is set, even to nothing: that is what Node does.
 */
export function isProxied(hostname: string, env: Env, port = 443, undiciVersion: string = bundledUndiciVersion()): boolean {
    const rules = noProxyRulesFor(undiciVersion);
    const list = env.no_proxy ?? env.NO_PROXY ?? '';

    let host = hostname.toLowerCase();
    if (rules.ipv6) host = host.replace(/^\[(.+)\]$/, '$1');
    if (rules.trailingDot && host.length > 1 && host.endsWith('.')) host = host.slice(0, -1);

    // Commas AND whitespace separate entries: read as one entry, `a.test
    // b.test` would be a host this function calls proxied while Node dials it
    // directly, and a proxied host may have its address check left to the proxy.
    const entries: { readonly name: string; readonly port: number; readonly subdomainsOnly: boolean }[] = [];
    for (const raw of list.split(/[,\s]/)) {
        if (raw === '') continue;
        let name = raw;
        let entryPort = 0;
        if (rules.ipv6) {
            const bracketed = /^\[(.+)\]:(\d+)$/.exec(raw);
            if (bracketed !== null) {
                name = bracketed[1];
                entryPort = Number.parseInt(bracketed[2], 10);
            } else {
                // A bare IPv6 literal has colons of its own; only `name:port` is split.
                name = raw.replace(/^\[(.+)\]$/, '$1');
                const split = (name.match(/:/g) ?? []).length === 1 ? /^(.+):(\d+)$/.exec(name) : null;
                if (split !== null) {
                    name = split[1];
                    entryPort = Number.parseInt(split[2], 10);
                }
            }
        } else {
            const split = /^(.+):(\d+)$/.exec(raw);
            if (split !== null) {
                name = split[1];
                entryPort = Number.parseInt(split[2], 10);
            }
        }
        if (rules.subdomains) name = name.replace(/^\*?\./, '');
        if (rules.trailingDot) name = name.replace(/^(.+)\.$/, '$1');
        entries.push({ name: name.toLowerCase(), port: entryPort, subdomainsOnly: rules.wildcard && raw.startsWith('*') });
    }

    if (entries.length === 0) return true;
    // Before 8.11.0 a star exempts everything only as the whole value, to the
    // character. (Before 7.22.0 a star entry is also an empty suffix, below.)
    if (!rules.wildcard && list === '*') return false;

    for (const entry of entries) {
        const portDiffers = entry.port !== 0 && entry.port !== port;
        if (rules.wildcard && entry.name === '*') {
            if (portDiffers) continue;
            return false;
        }
        if (portDiffers) continue;
        if (!rules.subdomains) {
            if (!/^[.*]/.test(entry.name)) {
                if (host === entry.name) return false;
            } else if (host.endsWith(entry.name.replace(/^\*/, ''))) {
                return false;
            }
            continue;
        }
        if (!entry.subdomainsOnly && host === entry.name) return false;
        if (host.slice(-(entry.name.length + 1)) === `.${entry.name}`) return false;
    }
    return true;
}
