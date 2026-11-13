/**
 * WHAT THIS SCANNER CAN REACH, declared once — and hashed into the report.
 *
 * The contract asks a scanner for the `sha256:` manifest hash of its own tool
 * surface (`scan.scanner.manifestHash`). This scanner calls no MCP tool; its
 * surface is the requests it can make. So the manifest is that list — each
 * source's GET endpoints, the one token exchange, and the one POST to the
 * ingest — plus the local files the `code` source reads, and the hash is
 * SHA-256 over its canonical JSON, the construction the report's own signature
 * uses.
 *
 * Two things follow. A change to what the scanner can call changes the hash
 * the tenant sees on every scan, so a widened surface cannot ship silently;
 * and the tests hold every request the fakes saw to this list
 * (`isDeclaredRequest`), so the declaration cannot drift from the code either.
 */
import { createHash } from 'crypto';

import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';
import { HARNESS_CONTRACT_V3 } from '@rodnapamet/scanent-contract/harness-contract';

import { OKTA_READ_PATHS } from './sources/okta';
import { AZURE_KEY_VAULT_COLLECTIONS, AZURE_LOGIN_ORIGIN } from './sources/azure-key-vault';
import { ENTRA_READ_PATHS, GRAPH_ORIGIN } from './sources/entra';
import { GCP_IAM_ORIGIN, GCP_READ_PATHS, GOOGLE_OAUTH_ORIGIN, GOOGLE_TOKEN_PATH } from './sources/gcp-service-accounts';
import { GITHUB_API_ORIGIN, GITHUB_READ_PATHS } from './sources/github-actions';
import { CLIENT_CREDENTIALS_GRANT, HARNESS_REGISTER_TOOL, JWT_BEARER_GRANT, MCP_MESSAGES, TOKEN_EXCHANGE_GRANT, OPENSHELL_METHODS, OPENSHELL_PROFILE_SCOPE, OPENSHELL_READ_SCOPE, OPENSHELL_SERVICE } from './http';
import { INFLECT_MCP_PATH, INFLECT_TOKEN_PATH } from './sources/inflect-register';
import { SKIPPED_DIRECTORIES, SOURCE_EXTENSIONS } from './sources/code/files';
import { LANGSMITH_READ_PATHS } from './sources/langsmith';

export const SCANNER_NAME = 'inflect-agent-harness-scanner';
/**
 * Raised with any change to what the scanner reads or reports. 0.2.0: the
 * LangSmith source. 0.3.0: reports under `inflect-agent-harness/2`. 0.4.0: the
 * `code` source, LangChain and LangGraph. 0.5.0: the Entra source. 0.6.0: the
 * MCP source. 0.7.0: the register source. 0.8.0: the GitHub Actions source.
 * 0.9.0: reports under `inflect-agent-harness/3`, and the GCP service-account
 * source.
 * 0.10.0: the OpenShell source — a gRPC gateway read, declared below as
 * its own surface because it is neither a GET nor JSON-RPC over HTTP.
 * 0.11.0: the register read exchanges the ingest key for a token naming the
 * register tool alone, and the register source reports the gate's enforcement
 * as H2 and H3 verdicts. 0.12.0: the egress proof, and the proxy it
 * runs behind. 0.13.0: the grant of each token exchange is declared inside the
 * surface, so the manifest hash covers it; no request changed. Also in
 * 0.13.0: the `code` source reads agents built directly on a model provider's
 * SDK (Anthropic, OpenAI, Gemini, Bedrock), which changes what it reports and
 * no file operation, so the surface and its hash are as they were.
 */
export const SCANNER_VERSION = '0.13.0';

/** The ingest route, as `docs/contract.md` (Transport) names it. */
export const INGEST_PATH_TEMPLATE = '/api/t/{tenantSlug}/admin/agents/harness-scans';

export const SCANNER_SURFACE = {
    name: SCANNER_NAME,
    version: SCANNER_VERSION,
    contract: HARNESS_CONTRACT_V3,
    reads: [
        { source: 'entra-sp', product: 'entra', method: 'GET', origin: GRAPH_ORIGIN, paths: [...ENTRA_READ_PATHS] },
        { source: 'okta-app', product: 'okta', method: 'GET', paths: [...OKTA_READ_PATHS] },
        // Templates: `{owner}`, `{repo}` and `{file}` each stand for one path segment.
        { source: 'cicd', product: 'github-actions', method: 'GET', origin: GITHUB_API_ORIGIN, paths: [...GITHUB_READ_PATHS] },
        { source: 'gcp-sa', product: 'gcp-iam', method: 'GET', origin: GCP_IAM_ORIGIN, paths: [...GCP_READ_PATHS] },
        {
            source: 'vault',
            product: 'azure-key-vault',
            method: 'GET',
            paths: AZURE_KEY_VAULT_COLLECTIONS.map((c) => `/${c}`),
        },
        {
            source: 'runtime',
            product: 'langsmith',
            method: 'GET',
            paths: [
                ...new Set([
                    ...Object.values(LANGSMITH_READ_PATHS.cloud),
                    ...Object.values(LANGSMITH_READ_PATHS.selfHosted),
                ]),
            ],
        },
    ],
    authenticates: [
        // `grant` is what the body may ask the token endpoint for: a request to a
        // declared endpoint with another grant (a password grant, say) is not a
        // declared request. It is inside the surface, so it is in the manifest
        // hash: a scanner that asked for another grant would show another hash.
        { product: 'azure-key-vault', method: 'POST', origin: AZURE_LOGIN_ORIGIN, path: '/{directoryTenantId}/oauth2/v2.0/token', grant: CLIENT_CREDENTIALS_GRANT },
        { product: 'entra', method: 'POST', origin: AZURE_LOGIN_ORIGIN, path: '/{directoryId}/oauth2/v2.0/token', grant: CLIENT_CREDENTIALS_GRANT },
        // The JWT-bearer grant (RFC 7523): an assertion the scanner signed, for a token to read with.
        { product: 'gcp-iam', method: 'POST', origin: GOOGLE_OAUTH_ORIGIN, path: GOOGLE_TOKEN_PATH, grant: JWT_BEARER_GRANT },
    ],
    // No request: the `code` source reads local files, and never runs them.
    // Declared all the same, so reading code shows in the manifest hash.
    readsFiles: [
        {
            source: 'code',
            product: 'langchain',
            operations: ['lstat', 'readdir', 'readFile'],
            extensions: [...SOURCE_EXTENSIONS],
            skips: [...SKIPPED_DIRECTORIES],
            followsSymlinks: false,
            executes: false,
        },
    ],
    // An MCP server is the estate's own host, named in its configuration. To
    // it the scanner POSTs these JSON-RPC messages and no other: never
    // `tools/call`. No tool of an estate's server is ever called.
    lists: [{ source: 'mcp', method: 'POST', host: 'configured', jsonRpc: [...MCP_MESSAGES] }],
    // The scanner's own tenant's register: the handshake, then ONE tool call,
    // of ONE named read tool, and of no other tool on any endpoint,
    // on a token exchanged for that one tool. The key goes to the
    // exchange; the MCP endpoint sees only the token.
    readsRegister: [
        {
            source: 'inflect-register',
            method: 'POST',
            path: INFLECT_MCP_PATH,
            jsonRpc: ['initialize', 'notifications/initialized', 'tools/call'],
            tool: HARNESS_REGISTER_TOOL,
            exchange: { method: 'POST', path: INFLECT_TOKEN_PATH, audience: [HARNESS_REGISTER_TOOL] },
        },
    ],
    // The client's own OpenShell gateway, named in its configuration. The
    // gateway speaks gRPC and publishes no REST transcoding, so this is neither
    // a `reads` (GET) nor a `lists` (JSON-RPC) entry: it names the ONE service
    // and the FIVE read RPCs the scanner may call on it, out of the 84 that
    // service declares. The siblings it must never call — `ExecSandbox`,
    // `DeleteSandbox`, `AttachSandboxProvider` — sit on the same service, which
    // is why the list is declared rather than assumed.
    //
    // Two scopes, kept apart: `sandbox:read` for the four sandbox reads, and
    // `provider:read` ONLY for `GetProviderProfile`, which an estate reaches
    // only by opting in to reading providers. The opt-in exists because
    // `ListSandboxProviders` returns a message whose `credentials` map is
    // marked secret in the proto.
    readsGateway: [
        {
            source: 'runtime',
            product: 'openshell',
            method: 'POST',
            host: 'configured',
            service: OPENSHELL_SERVICE,
            rpcs: [...OPENSHELL_METHODS],
            scopes: [OPENSHELL_READ_SCOPE, OPENSHELL_PROFILE_SCOPE],
        },
    ],
    sends: [{ method: 'POST', path: INGEST_PATH_TEMPLATE }],
    // The egress proof, only when the configuration names a
    // proxy: two CONNECTs to it — the Inflect host, which it must admit, and
    // the configured canary, which it must refuse — and one direct TCP dial to
    // the Inflect host, which must fail. Each is opened and closed; nothing is
    // sent through a tunnel.
    provesEgress: [
        { method: 'CONNECT', via: 'configured proxy', target: '{inflectHost}:443', expect: 200 },
        { method: 'CONNECT', via: 'configured proxy', target: '{canaryHost}:443', expect: 403 },
        { method: 'TCP', via: 'direct', target: '{inflectHost}:443', expect: 'refused' },
    ],
} as const;

type TokenExchangeProduct = (typeof SCANNER_SURFACE.authenticates)[number]['product'];

/**
 * The OAuth grant each `authenticates` entry asks its token endpoint for, by
 * the entry's `product`. It is READ FROM the surface and holds nothing of its
 * own: the grant is declared once, in the entry, where the manifest hash covers
 * it. (Until 0.13.0 it stood beside the surface, and the hash did not.)
 */
export const TOKEN_EXCHANGE_GRANTS: Readonly<Record<TokenExchangeProduct, string>> = Object.fromEntries(
    SCANNER_SURFACE.authenticates.map((entry) => [entry.product, entry.grant]),
) as Record<TokenExchangeProduct, string>;

/**
 * Whether one form body sent to a product's token endpoint is on the declared
 * surface: it names that product's grant, once, and no other.
 */
export function isDeclaredTokenExchange(product: keyof typeof TOKEN_EXCHANGE_GRANTS, body: string): boolean {
    const grants = new URLSearchParams(body).getAll('grant_type');
    return grants.length === 1 && grants[0] === TOKEN_EXCHANGE_GRANTS[product];
}

/**
 * Whether one gRPC call is on the declared surface: the one service, and one of
 * its declared read RPCs. The path form is gRPC's own,
 * `/<package>.<Service>/<Method>`.
 *
 * Held beside `isDeclaredRequest` the way `isDeclaredMcpMessage` is: the
 * request log of every OpenShell test is checked against it, so the declaration
 * cannot drift from the code.
 */
export function isDeclaredGatewayCall(pathname: string): boolean {
    const m = /^\/([A-Za-z0-9_.]+)\/([A-Za-z0-9_]+)$/.exec(pathname);
    if (m === null) return false;
    const [, service, rpc] = m;
    return service === OPENSHELL_SERVICE && (OPENSHELL_METHODS as readonly string[]).includes(rpc);
}

export function scannerManifestHash(): string {
    return `sha256:${createHash('sha256').update(canonicalJson(SCANNER_SURFACE), 'utf8').digest('hex')}`;
}

/**
 * Whether one request is on the declared surface: a GET to a declared read
 * path, the token exchange, or the POST to the ingest. The request log of every
 * test is held to this.
 */
/**
 * Whether one message to an MCP server is on the declared surface: a JSON-RPC
 * body whose method is one of `MCP_MESSAGES`. The request log of every MCP
 * test is held to this, beside `isDeclaredRequest` for every other request.
 */
export function isDeclaredMcpMessage(body: string): boolean {
    let message: unknown;
    try {
        message = JSON.parse(body);
    } catch {
        return false;
    }
    const method = (message as { method?: unknown } | null)?.method;
    return typeof method === 'string' && (MCP_MESSAGES as readonly string[]).includes(method);
}

/**
 * Whether one message to the scanner's own tenant's `/api/mcp` is on the
 * declared surface: the handshake, or a `tools/call` naming
 * `get_harness_register` and nothing else.
 */
export function isDeclaredRegisterMessage(body: string): boolean {
    let message: { method?: unknown; params?: { name?: unknown } } | null;
    try {
        message = JSON.parse(body) as typeof message;
    } catch {
        return false;
    }
    if (message?.method === 'initialize' || message?.method === 'notifications/initialized') return true;
    return message?.method === 'tools/call' && message.params?.name === HARNESS_REGISTER_TOOL;
}

/**
 * Whether one body sent to the tenant's `/api/mcp/token` is on the declared
 * surface: the token-exchange grant, for an audience of the register tool and
 * nothing else.
 */
export function isDeclaredRegisterExchange(body: string): boolean {
    let message: { grant_type?: unknown; audience?: unknown } | null;
    try {
        message = JSON.parse(body) as typeof message;
    } catch {
        return false;
    }
    const audience = message?.audience;
    return (
        message?.grant_type === TOKEN_EXCHANGE_GRANT &&
        Array.isArray(audience) &&
        audience.length === 1 &&
        audience[0] === HARNESS_REGISTER_TOOL
    );
}

/** Whether `pathname` is `declared`, where a `{name}` segment of `declared` stands for exactly one segment. */
function pathMatches(declared: string, pathname: string): boolean {
    const want = declared.split('/');
    const got = pathname.split('/');
    return want.length === got.length && want.every((seg, i) => (/^\{[a-z]+\}$/.test(seg) ? got[i] !== '' : seg === got[i]));
}

export function isDeclaredRequest(method: string, url: string): boolean {
    const { origin, pathname } = new URL(url);
    if (method === 'GET') {
        // A read that names its origin (one whose host is fixed by kind) is held to it.
        return SCANNER_SURFACE.reads.some(
            (r) => (r.paths as readonly string[]).some((p) => pathMatches(p, pathname)) && (!('origin' in r) || r.origin === origin),
        );
    }
    if (method !== 'POST') return false;
    if (origin === AZURE_LOGIN_ORIGIN) return /^\/[^/]+\/oauth2\/v2\.0\/token$/.test(pathname);
    if (origin === GOOGLE_OAUTH_ORIGIN) return pathname === GOOGLE_TOKEN_PATH;
    // The register read posts to the tenant's `/api/mcp`; its messages are held
    // by `isDeclaredRegisterMessage`.
    if (pathname === INFLECT_MCP_PATH) return true;
    // The register token's exchange, on the same tenant's origin; its body is
    // held by `isDeclaredRegisterExchange`.
    if (pathname === INFLECT_TOKEN_PATH) return true;
    // A gRPC call to the client's gateway: the service and RPC decide, not the
    // host, which the estate configures.
    if (isDeclaredGatewayCall(pathname)) return true;
    return /^\/api\/t\/[^/]+\/admin\/agents\/harness-scans$/.test(pathname);
}
