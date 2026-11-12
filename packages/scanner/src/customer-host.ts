/**
 * A HOST THE CUSTOMER NAMES — checked when the configuration is read, and
 * re-resolved before every request (#3738, owner decisions 2026-10-19).
 *
 * Every other host the scanner reaches is fixed by its kind: Okta's domains,
 * the public cloud's vaults, LangSmith's two cloud API hosts. A self-hosted
 * LangSmith is the first host nobody can enumerate, because it is the
 * customer's own. The owner's ruling is that such a host is validated like any
 * customer-named host in the application: the `publicOrigin` rule kind
 * (`src/app-layer/integrations/config-schema.ts`), which requires https and runs
 * `checkWebhookUrl` at save time, with `safeFetch` re-resolving at use time.
 * The scanner may not import either (`eslint.config.mjs` holds it to the wire
 * contract), so the same two halves live here:
 *
 *   • AT CONFIGURATION. `customerOriginProblem` refuses anything but a bare
 *     https origin, a literal private, loopback, link-local or metadata
 *     address, the blocked names, and the `.local` / `.internal` suffixes —
 *     `checkWebhookUrl`'s rules.
 *   • AT USE. `assertResolvesReachable` resolves the host again before EACH
 *     request and refuses when any address it resolves to is one of those. A
 *     name that pointed at a public address when the file was written and at
 *     169.254.169.254 tonight is caught tonight, and the request carrying the
 *     API key is never started.
 *
 * THE PRIVATE-RANGE ALLOWLIST (owner decision 2026-10-19). A self-hosted
 * LangSmith usually sits on the customer's own network, at a private address.
 * The application's answer to the same problem is its self-hosted egress
 * allowlist (#3328, `src/lib/security/egress-allowlist.ts`,
 * `EGRESS_PRIVATE_CIDR_ALLOWLIST`), and this mirrors it, named
 * `egressPrivateCidrAllowlist` on the self-hosted endpoint:
 *
 *   • NOT TENANT-CONFIGURABLE. The ranges come from the estate's own scanner
 *     configuration file, which only whoever operates the scanner in that
 *     estate can write. No tenant column, form or route reaches it.
 *   • METADATA, LOOPBACK AND LINK-LOCAL STAY REFUSED INSIDE IT.
 *     `NEVER_ALLOWLISTABLE` is the application's list, checked BEFORE the
 *     allowlist, so `0.0.0.0/0` still cannot reach 169.254.169.254 or
 *     127.0.0.1. The blocked names stay refused too.
 *   • IT WIDENS WHICH ADDRESSES ARE ACCEPTABLE AND REMOVES NO OTHER CHECK.
 *     https only, redirects refused, the origin pinned, and the host resolved
 *     again before every request with EVERY address checked: a name that
 *     resolves outside the listed ranges is refused however it resolved when
 *     the file was written. As in the application, an allowlist relaxes only
 *     the `.local` / `.internal` NAME rule, because with one configured the
 *     question becomes the address rather than the name.
 *
 * The CIDR parser is the application's own (`@/lib/security/cidr`, pure and
 * strict), imported rather than copied. `isPrivateAddress` and
 * `NEVER_ALLOWLISTABLE` are copies — their modules read the environment — and
 * `tests/unit/agent-harness-scanner/langsmith-source.test.ts` holds each copy
 * to the application's answer on every address in its tables.
 *
 * What this does not do, and the application's `safeFetch` does: PIN the
 * connection to the address it checked. That takes an undici dispatcher, which
 * is not a Node built-in. The check therefore runs immediately before each
 * request and the request resolves again, so a resolver that answers
 * differently inside that gap is a residual, recorded in the DPIA (R16).
 */
import { promises as dns } from 'dns';

import { inCidr, isV4Mapped, parseAddress, parseCidr, type Cidr } from '@scanent/contract/cidr';

import { httpsOrigin } from './http';
import { isProxied, proxyInEffect, type Env } from './proxy-env';
import { SourceReadError } from './source';

const PRIVATE_V4 = [
    /^10\./,
    /^127\./,
    /^0\./,
    /^169\.254\./, // link-local, cloud metadata among it
    /^192\.168\./,
    /^172\.(1[6-9]|2\d|3[0-1])\./,
    /^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./, // CGNAT 100.64/10
];

/** A raw IP literal (v4 or v6) that is private, loopback or link-local. The application's rule, copied. */
export function isPrivateAddress(host: string): boolean {
    const h = host.toLowerCase().replace(/^\[|\]$/g, '');
    if (h === '::1' || h === '::' || h === '0.0.0.0') return true;
    if (h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) return true;
    if (h.startsWith('::ffff:')) return isPrivateAddress(h.slice(7));
    return PRIVATE_V4.some((re) => re.test(h));
}

const BLOCKED_HOSTNAMES = new Set(['localhost', 'metadata', 'metadata.google.internal']);

/**
 * Ranges no allowlist may admit, whatever it says: the application's list
 * (`NEVER_ALLOWLISTABLE` in `src/lib/security/egress-allowlist.ts`), copied.
 *
 *   127/8, ::1   loopback — the scanner host's own services
 *   0/8, ::      "this host", an alias for loopback
 *   169.254/16   link-local: 169.254.169.254 is cloud metadata
 *   fe80::/10    v6 link-local
 */
const NEVER_ALLOWLISTABLE: readonly Cidr[] = [
    '127.0.0.0/8',
    '0.0.0.0/8',
    '169.254.0.0/16',
    '::1/128',
    '::/128',
    'fe80::/10',
].map((c) => {
    const parsed = parseCidr(c);
    // A literal that did not parse would silently shrink the set; fail at load.
    if (parsed === null) throw new Error(`customer-host: bad built-in CIDR ${c}`);
    return parsed;
});

/** The ranges an estate's configuration lists, parsed. Empty is "no allowlist". */
export type PrivateCidrAllowlist = readonly Cidr[];

/** Parse an estate's `egressPrivateCidrAllowlist`; null when any entry is not a CIDR. */
export function parsePrivateCidrAllowlist(entries: readonly string[]): Cidr[] | null {
    const out: Cidr[] = [];
    for (const entry of entries) {
        const parsed = parseCidr(entry);
        if (parsed === null) return null;
        out.push(parsed);
    }
    return out;
}

function inAny(address: string, ranges: readonly Cidr[]): boolean {
    const addr = parseAddress(address);
    if (addr === null) return false;
    // A v4-mapped v6 is the same destination written differently.
    if (addr.length === 16 && isV4Mapped(addr)) {
        const v4 = new Uint8Array(addr.slice(12));
        if (ranges.some((c) => inCidr(v4, c))) return true;
    }
    return ranges.some((c) => inCidr(addr, c));
}

/** True when no allowlist may admit this address: metadata, loopback, link-local. */
export function isNeverAllowlistable(address: string): boolean {
    return inAny(address, NEVER_ALLOWLISTABLE);
}

/**
 * The IPv4 address an IPv6 address carries inside it, as dotted text, or null.
 *
 * Four ways to write a v4 destination as a v6 address, each of which reaches
 * (directly, or through a translator on the path) the v4 address it embeds:
 *
 *   ::ffff:a.b.c.d    v4-mapped (RFC 4291): the same socket destination
 *   ::a.b.c.d         v4-compatible (RFC 4291, deprecated, still parsed)
 *   64:ff9b::a.b.c.d  NAT64, the well-known prefix (RFC 6052)
 *   2002:AABB:CCDD::  6to4 (RFC 3056): the v4 address is bytes 2 to 5
 *
 * The text check alone (`isPrivateAddress`) knows only the dotted v4-mapped
 * spelling. `::ffff:a00:7` is 10.0.0.7 written in hex, which is how a URL
 * parser normalises `[::ffff:10.0.0.7]`, and it read as a public address.
 */
function embeddedV4(bytes: Uint8Array): string | null {
    if (bytes.length !== 16) return null;
    const dotted = (at: number): string => `${bytes[at]}.${bytes[at + 1]}.${bytes[at + 2]}.${bytes[at + 3]}`;
    const zero = (from: number, to: number): boolean => bytes.slice(from, to).every((b) => b === 0);
    if (isV4Mapped(bytes)) return dotted(12);
    // `::` and `::1` are the unspecified and loopback addresses, not a v4 inside a v6.
    if (zero(0, 12) && !(zero(12, 15) && bytes[15] <= 1)) return dotted(12);
    if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zero(4, 12)) return dotted(12);
    if (bytes[0] === 0x20 && bytes[1] === 0x02) return dotted(2);
    return null;
}

/**
 * May the scanner reach `address`, given the estate's allowlist? A public
 * address, yes. A private one only when it is NOT never-allowlistable AND it
 * falls inside a listed range. Every other answer is no, and an answer that
 * is not an address at all is no: a resolver that says something this parser
 * does not read has named nothing the scanner should dial.
 *
 * An IPv6 address that carries a v4 address inside it is judged as BOTH: the
 * address as written, and the v4 destination it stands for.
 */
export function addressReachable(address: string, allowlist: PrivateCidrAllowlist): boolean {
    const bytes = parseAddress(address);
    if (bytes === null) return false;
    const inner = embeddedV4(bytes);
    const forms = inner === null ? [address] : [address, inner];
    return forms.every((form) => {
        if (isNeverAllowlistable(form)) return false;
        if (!isPrivateAddress(form)) return true;
        return allowlist.length > 0 && inAny(form, allowlist);
    });
}

/**
 * Why `value` is not a customer origin the scanner may send a credential to, or
 * null when it is one. Names the rule, never echoes the value.
 */
export function customerOriginProblem(value: string, allowlist: PrivateCidrAllowlist = []): string | null {
    const origin = httpsOrigin(value);
    if (origin === null) return 'must be a bare https origin: no path, query or credentials';
    // A trailing dot names the same host (`localhost.` is `localhost`); the rules below are about the name without it.
    const host = new URL(origin).hostname.toLowerCase().replace(/\.+$/, '');
    if (BLOCKED_HOSTNAMES.has(host)) return 'names a blocked host';
    // The NAME rule is a proxy for "probably internal". With an allowlist the
    // question becomes the address, which is checked before every request.
    // `.localhost` is loopback by definition (RFC 6761), whatever an allowlist says.
    if (host.endsWith('.localhost')) return 'names a blocked host';
    if (allowlist.length === 0 && (host.endsWith('.local') || host.endsWith('.internal'))) {
        return 'names a host that is internal by its suffix';
    }
    if (isIpLiteral(host) && !addressReachable(host.replace(/^\[|\]$/g, ''), allowlist)) {
        return 'is a private, loopback or link-local address outside the allowlist';
    }
    return null;
}

function isIpLiteral(host: string): boolean {
    const h = host.replace(/^\[|\]$/g, '');
    return /^[\d.]+$/.test(h) || h.includes(':');
}

/** Resolve a hostname to every address it has. The CLI's is DNS; tests pass their own. */
export type ResolveHost = (hostname: string) => Promise<readonly string[]>;

export const resolveWithDns: ResolveHost = async (hostname) =>
    (await dns.lookup(hostname, { all: true })).map((a) => a.address);

/**
 * Resolve `hostname` now and refuse unless EVERY address is one the scanner may
 * reach: public, or private inside the estate's allowlist and never metadata,
 * loopback or link-local. Throws the contract's UNREACHABLE: the host could not
 * be reached as the configuration names it, which is what both a failed lookup
 * and a refused answer mean.
 */
export async function assertResolvesReachable(
    hostname: string,
    resolve: ResolveHost,
    allowlist: PrivateCidrAllowlist = [],
): Promise<void> {
    const literal = hostname.replace(/^\[|\]$/g, '');
    let addresses: readonly string[];
    if (isIpLiteral(literal)) {
        addresses = [literal];
    } else {
        try {
            addresses = await resolve(hostname);
        } catch {
            throw new SourceReadError('UNREACHABLE', 'the configured host did not resolve');
        }
    }
    if (addresses.length === 0) throw new SourceReadError('UNREACHABLE', 'the configured host resolved to nothing');
    if (!addresses.every((a) => addressReachable(a, allowlist))) {
        throw new SourceReadError('UNREACHABLE', 'the configured host resolved to an address the scanner may not reach');
    }
}

/** How a customer-named host is checked before a request. The default is `assertResolvesReachable`. */
export type CustomerHostCheck = (hostname: string, resolve: ResolveHost, allowlist?: PrivateCidrAllowlist) => Promise<void>;

/**
 * `EGRESS_PROXY_CHECKS_ADDRESSES=1`: the operator's statement that the proxy
 * in `HTTPS_PROXY` is scanent's own egress proxy (`egress-proxy.ts`), which
 * resolves each allowlisted name itself, refuses an address the scanner may
 * not reach, and connects to the address it checked.
 *
 * Behind that proxy on an internal network the scanner has no resolver for an
 * outside name, so its own check could only ever fail; and the proxy's check
 * is the stronger one, because it binds the address that is dialled. The
 * deployment templates that run the bundled proxy set this; nothing else may.
 * Set beside any other proxy it turns the address check off, which is why it
 * is a separate, explicit variable and not inferred from `HTTPS_PROXY`.
 */
export const PROXY_CHECKS_ADDRESSES_ENV = 'EGRESS_PROXY_CHECKS_ADDRESSES';

/**
 * Whether the address check for `hostname` is the bundled proxy's: the
 * variable is set, a proxy is in effect, the host goes through it, and it is a
 * name. An IP literal is always checked here; the proxy refuses one anyway.
 */
export function addressCheckedByProxy(hostname: string, env: Env, nodeVersion: string): boolean {
    return (
        env[PROXY_CHECKS_ADDRESSES_ENV] === '1' &&
        proxyInEffect(env, nodeVersion) &&
        !isIpLiteral(hostname) &&
        isProxied(hostname, env)
    );
}

/**
 * The check `scan` and `doctor` make before each request to a customer-named
 * host, for this environment. `onProxied` is told, once per host, which hosts
 * go through a proxy and whether the proxy is the one that checks the address.
 */
export function customerHostCheckFor(
    env: Env,
    nodeVersion: string,
    onProxied: (hostname: string, checkedByProxy: boolean) => void = () => undefined,
): CustomerHostCheck {
    const told = new Set<string>();
    const viaProxy = proxyInEffect(env, nodeVersion);
    return async (hostname, resolve, allowlist = []) => {
        const proxied = viaProxy && isProxied(hostname, env);
        const delegated = addressCheckedByProxy(hostname, env, nodeVersion);
        if (proxied && !told.has(hostname)) {
            told.add(hostname);
            onProxied(hostname, delegated);
        }
        if (delegated) return;
        await assertResolvesReachable(hostname, resolve, allowlist);
    };
}
