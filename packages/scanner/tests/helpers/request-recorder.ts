/**
 * A recorder for every request a scan or a preflight makes, and a judge that
 * holds each one to the declared surface (`scanner-surface.ts`).
 *
 * The recorder wraps a `FetchLike`. It keeps the method, the URL, the NAMES of
 * the headers (never a value: one of them is the credential), the body, and
 * whether the request refuses redirects.
 *
 * The judge places a request in exactly one class, or in `UNDECLARED`. What
 * may be sent other than a GET is not written here: it is read off
 * `SCANNER_SURFACE` (`authenticates`, `lists`, `readsRegister`, `sends`), so a
 * surface that grows changes what this accepts and a request the surface does
 * not name is refused whatever this file says.
 */
import type { ScannerConfig } from '../../src/config';
import type { FetchLike } from '../../src/http';
import { LANGSMITH_CLOUD_ORIGINS } from '../../src/sources/langsmith';
import {
    isDeclaredGatewayCall,
    isDeclaredMcpMessage,
    isDeclaredRegisterExchange,
    isDeclaredRegisterMessage,
    isDeclaredRequest,
    isDeclaredTokenExchange,
    SCANNER_SURFACE,
} from '../../src/scanner-surface';

export interface RecordedRequest {
    readonly method: string;
    readonly url: string;
    readonly origin: string;
    readonly pathname: string;
    /** Lower-case header names, sorted. No value is kept. */
    readonly headerNames: readonly string[];
    readonly body: string | null;
    /** The request's `redirect` mode: every one must be `error`. */
    readonly redirect: string | undefined;
}

export interface Recorder {
    readonly fetchImpl: FetchLike;
    readonly requests: RecordedRequest[];
}

export function recordRequests(inner: FetchLike): Recorder {
    const requests: RecordedRequest[] = [];
    return {
        requests,
        fetchImpl: async (url, init) => {
            const u = new URL(url);
            requests.push({
                method: (init.method ?? 'GET').toUpperCase(),
                url,
                origin: u.origin,
                pathname: u.pathname,
                headerNames: [...new Headers(init.headers).keys()].map((k) => k.toLowerCase()).sort(),
                body: init.body === undefined || init.body === null ? null : String(init.body),
                redirect: init.redirect,
            });
            return inner(url, init);
        },
    };
}

export type RequestClass =
    | 'READ'
    | 'TOKEN_EXCHANGE'
    | 'MCP_MESSAGE'
    | 'REGISTER_MESSAGE'
    | 'REGISTER_EXCHANGE'
    | 'INGEST_POST'
    | 'UNDECLARED';

/** The hosts one configuration names, for the surface entries whose host is not fixed by kind. */
export interface ConfiguredHosts {
    /** The tenant's origin; null when the configuration names none. */
    readonly inflectOrigin: string | null;
    /** Each MCP server's endpoint, origin and path. */
    readonly mcpEndpoints: readonly string[];
    /** By the surface's `product`: the origins that product is configured on. */
    readonly productOrigins: Readonly<Record<string, readonly string[]>>;
}

export function configuredHostsOf(config: ScannerConfig): ConfiguredHosts {
    const productOrigins: Record<string, string[]> = {};
    const mcpEndpoints: string[] = [];
    for (const s of config.sources) {
        if (s.kind === 'okta-app') productOrigins.okta = [new URL(s.orgUrl).origin];
        if (s.kind === 'okta-integrations') productOrigins['okta-integrations'] = [new URL(s.orgUrl).origin];
        if (s.kind === 'vault') productOrigins['azure-key-vault'] = s.vaultUrls.map((v) => new URL(v).origin);
        if (s.kind === 'runtime') {
            productOrigins.langsmith = ['cloud' in s.endpoint ? LANGSMITH_CLOUD_ORIGINS[s.endpoint.cloud] : new URL(s.endpoint.selfHosted).origin];
        }
        if (s.kind === 'mcp') for (const server of s.servers) mcpEndpoints.push(`${new URL(server.url).origin}${new URL(server.url).pathname}`);
    }
    return { inflectOrigin: config.inflect === undefined ? null : new URL(config.inflect.baseUrl).origin, mcpEndpoints, productOrigins };
}

/** Whether `pathname` is `template`, where a `{name}` segment stands for exactly one non-empty segment. */
export function matchesTemplate(template: string, pathname: string): boolean {
    const want = template.split('/');
    const got = pathname.split('/');
    return want.length === got.length && want.every((seg, i) => (/^\{[A-Za-z]+\}$/.test(seg) ? got[i] !== '' : seg === got[i]));
}

function rpcMethodOf(body: string | null): string | null {
    try {
        const method = (JSON.parse(body ?? '') as { method?: unknown } | null)?.method;
        return typeof method === 'string' ? method : null;
    } catch {
        return null;
    }
}

/** The one class a request belongs to, read off the surface; `UNDECLARED` when it has none. */
export function classifyRequest(req: RecordedRequest, hosts: ConfiguredHosts): RequestClass {
    const surface = SCANNER_SURFACE;
    for (const read of surface.reads) {
        if (req.method !== read.method) continue;
        if (!(read.paths as readonly string[]).some((p) => matchesTemplate(p, req.pathname))) continue;
        // A host fixed by kind is held to it; any other is held to the configuration.
        const origins: readonly string[] = 'origin' in read ? [read.origin] : (hosts.productOrigins[read.product] ?? []);
        if (origins.includes(req.origin)) return 'READ';
    }
    for (const auth of surface.authenticates) {
        // The body is judged too: a declared endpoint asked for another grant is not a declared request.
        if (req.method === auth.method && req.origin === auth.origin && matchesTemplate(auth.path, req.pathname) && isDeclaredTokenExchange(auth.product, req.body ?? '')) {
            return 'TOKEN_EXCHANGE';
        }
    }
    for (const list of surface.lists) {
        const rpc = rpcMethodOf(req.body);
        if (
            req.method === list.method &&
            hosts.mcpEndpoints.includes(`${req.origin}${req.pathname}`) &&
            rpc !== null &&
            (list.jsonRpc as readonly string[]).includes(rpc) &&
            isDeclaredMcpMessage(req.body ?? '')
        ) {
            return 'MCP_MESSAGE';
        }
    }
    for (const register of surface.readsRegister) {
        if (req.origin !== hosts.inflectOrigin) continue;
        const rpc = rpcMethodOf(req.body);
        if (
            req.method === register.method &&
            req.pathname === register.path &&
            rpc !== null &&
            (register.jsonRpc as readonly string[]).includes(rpc) &&
            isDeclaredRegisterMessage(req.body ?? '')
        ) {
            return 'REGISTER_MESSAGE';
        }
        if (req.method === register.exchange.method && req.pathname === register.exchange.path && isDeclaredRegisterExchange(req.body ?? '')) {
            return 'REGISTER_EXCHANGE';
        }
    }
    for (const send of surface.sends) {
        if (req.method === send.method && req.origin === hosts.inflectOrigin && matchesTemplate(send.path, req.pathname)) return 'INGEST_POST';
    }
    return 'UNDECLARED';
}

/** Whether a surface family names a method other than GET. Typed loosely: the surface's own types know the answer. */
const sendsOtherThanGet = (entries: readonly { readonly method: string }[]): boolean => entries.some((e) => e.method !== 'GET');

/** The classes a request other than a GET may have: one per surface family that names a method other than GET. */
export const NON_GET_CLASSES: ReadonlySet<RequestClass> = new Set<RequestClass>([
    ...(sendsOtherThanGet(SCANNER_SURFACE.authenticates) ? (['TOKEN_EXCHANGE'] as const) : []),
    ...(sendsOtherThanGet(SCANNER_SURFACE.lists) ? (['MCP_MESSAGE'] as const) : []),
    ...(sendsOtherThanGet(SCANNER_SURFACE.readsRegister) ? (['REGISTER_MESSAGE', 'REGISTER_EXCHANGE'] as const) : []),
    ...(sendsOtherThanGet(SCANNER_SURFACE.sends) ? (['INGEST_POST'] as const) : []),
]);

/**
 * Everything wrong with a request log, one sentence each; empty when every
 * request is on the declared surface. Names the method and the path, never a
 * query (it can carry a cursor), a header value or a body.
 */
export function readOnlyProblems(requests: readonly RecordedRequest[], hosts: ConfiguredHosts): string[] {
    const problems: string[] = [];
    for (const req of requests) {
        const where = `${req.method} ${req.origin}${req.pathname}`;
        const cls = classifyRequest(req, hosts);
        if (cls === 'UNDECLARED') problems.push(`${where} is not on the declared surface`);
        if (req.method !== 'GET' && !NON_GET_CLASSES.has(cls)) problems.push(`${where} is not a GET, and the surface lists no such request`);
        if (req.method === 'GET' && req.body !== null) problems.push(`${where} is a GET with a body`);
        if (req.redirect !== 'error') problems.push(`${where} would follow a redirect`);
        if (new URL(req.url).protocol !== 'https:') problems.push(`${where} is not https`);
        // The product's own check must agree: the judge here is never the more lenient of the two.
        // A message to an MCP server is the one request `isDeclaredRequest` does not judge
        // (the server's host and path are the estate's); `isDeclaredMcpMessage` held it above.
        if (cls !== 'UNDECLARED' && cls !== 'MCP_MESSAGE' && !isDeclaredRequest(req.method, req.url)) {
            problems.push(`${where} is refused by isDeclaredRequest`);
        }
        // The gateway surface is declared and no configuration reaches it.
        if (isDeclaredGatewayCall(req.pathname)) problems.push(`${where} is a gateway call, which no configured source makes`);
    }
    return problems;
}
