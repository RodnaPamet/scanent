/**
 * `docs/network-and-permissions.md`, rendered from the declared surface.
 *
 * The document a security reviewer reads before letting the scanner into an
 * estate: every host, every method and path, what is read there, the grant
 * each source asks for, and what is never requested. It is a function of
 * `SCANNER_SURFACE` and the access guide, so it cannot say more or less than
 * the code declares: `npm run docs:network` writes it, and a test compares the
 * committed file with this rendering and fails when a declared path has no
 * sentence here.
 *
 * Two tables are written by hand, because the surface holds paths and not
 * prose: what each path returns that the scanner keeps (`WHAT_IS_READ`), and
 * the requests each API offers that the scanner never makes
 * (`NEVER_REQUESTED`). The first is held complete by the test; every entry of
 * the second is held to be off the declared surface.
 */
import { ACCESS_GUIDE, GUIDE_ORDER, type AccessEntry } from './init/access-guide';
import { JWT_BEARER_GRANT, MAX_RESPONSE_BYTES, MAX_SOURCE_BYTES } from './http';
import { SCANNER_SURFACE, scannerManifestHash, TOKEN_EXCHANGE_GRANTS } from './scanner-surface';
import type { SourceKind } from './source';
import { MAX_FILE_BYTES, MAX_FILES, MAX_MARKER_SCAN_BYTES, MAX_TOTAL_BYTES } from './sources/code/files';
import { AZURE_KEY_VAULT_HOST_SUFFIX } from './sources/azure-key-vault';
import { LANGSMITH_CLOUD_ORIGINS } from './sources/langsmith';
import { OKTA_HOST_SUFFIXES } from './sources/okta';

/** What the scanner keeps from each declared read, keyed `<product> <path>`. */
export const WHAT_IS_READ: Readonly<Record<string, string>> = {
    'entra /v1.0/applications': 'App registrations: ids, the ids and dates of their password and key credentials, and the ids of their owners. Selected by name; no secret text, hint or display name is kept',
    'entra /v1.0/servicePrincipals': 'Service principals: ids, type, whether enabled, the owning directory, credential ids and dates, and owner ids',
    'okta /api/v1/apps': 'OIDC applications: id, sign-on mode, application type, and the owner written in the profile',
    'okta /api/v1/api-tokens': 'API token metadata: id, the user it belongs to, created and expiry dates. Never a token value, which Okta does not return',
    'okta /api/v1/api-tokens/current': "The id of the token the scanner itself reads with, so its own token is not reported as somebody's",
    'github-actions /repos/{owner}/{repo}': "The repository's default branch",
    'github-actions /repos/{owner}/{repo}/contents/.github/workflows': 'The names of the workflow files on the default branch',
    'github-actions /repos/{owner}/{repo}/contents/.github/workflows/{file}': 'One workflow file, read as text for its permissions and the secret names it refers to',
    'github-actions /repos/{owner}/{repo}/actions/secrets': 'The names and update dates of Actions secrets. GitHub returns no value here',
    'gcp-iam /v1/projects/{project}/serviceAccounts': 'Service accounts: unique id, e-mail address (to tell account types apart, not reported), whether disabled',
    'gcp-iam /v1/projects/{project}/serviceAccounts/{account}/keys': 'User-managed key metadata: key id and validity dates. Google returns no key material here',
    'azure-key-vault /secrets': 'Secret metadata: name, whether enabled, created and expiry dates, tags. The listing carries no value',
    'azure-key-vault /certificates': 'Certificate metadata: name, whether enabled, dates, tags',
    'langsmith /api/v1/sessions': 'Tracing projects: id, start time, and aggregate counts of tool runs by tool name over the configured window. No run, input or output',
    'langsmith /v2/deployments': 'Deployments: id and the tracing project each writes to. Only when `readDeployments` is set, because the listing also carries deployment secrets, which are dropped with the page',
    'langsmith /api-host/v2/deployments': 'The same deployments listing, on a self-hosted LangSmith',
};

/** Requests each API offers that the scanner never makes. Each is off the declared surface; a test holds that. */
export const NEVER_REQUESTED: Readonly<Record<SourceKind, readonly { readonly method: string; readonly path: string; readonly why: string }[]>> = {
    'entra-sp': [
        { method: 'POST', path: '/v1.0/applications/{id}/addPassword', why: 'creates a client secret' },
        { method: 'PATCH', path: '/v1.0/servicePrincipals/{id}', why: 'changes a service principal' },
        { method: 'GET', path: '/v1.0/users', why: 'the directory of people is not read; an owner is kept as an id only' },
    ],
    vault: [
        { method: 'GET', path: '/secrets/{name}', why: 'returns the secret value' },
        { method: 'GET', path: '/secrets/{name}/{version}', why: 'returns the secret value' },
        { method: 'GET', path: '/keys', why: 'keys are not read' },
    ],
    'okta-app': [
        { method: 'GET', path: '/api/v1/apps/{id}/credentials/secrets', why: 'returns client secrets' },
        { method: 'GET', path: '/api/v1/users', why: 'the directory of people is not read' },
        { method: 'DELETE', path: '/api/v1/api-tokens/{id}', why: 'revokes a token' },
    ],
    cicd: [
        { method: 'GET', path: '/repos/{owner}/{repo}/actions/secrets/{name}', why: 'one secret is never asked for by name' },
        { method: 'GET', path: '/repos/{owner}/{repo}/contents/{path}', why: 'no file outside `.github/workflows` is read' },
        { method: 'GET', path: '/repos/{owner}/{repo}/actions/runs', why: 'runs and their logs are not read' },
    ],
    'gcp-sa': [
        { method: 'POST', path: '/v1/projects/{project}/serviceAccounts/{account}/keys', why: 'creates a key and returns its private half' },
        { method: 'POST', path: '/v1/projects/{project}/serviceAccounts/{account}:getIamPolicy', why: 'policies are not read' },
        { method: 'POST', path: '/v1/projects/{project}/serviceAccounts/{account}:signBlob', why: 'acts as the account' },
    ],
    runtime: [
        { method: 'GET', path: '/api/v1/runs/{id}', why: 'returns a run with its inputs and outputs' },
        { method: 'POST', path: '/api/v1/runs/query', why: 'returns runs with their inputs and outputs' },
        { method: 'GET', path: '/api/v1/datasets', why: 'datasets are not read' },
    ],
    mcp: [],
    code: [],
    'inflect-register': [],
};

const LANGSMITH_HOSTS = Object.values(LANGSMITH_CLOUD_ORIGINS).map((origin) => new URL(origin).hostname);

/** The hosts one source reaches for its reads, in words. Fixed hosts are named; a configured host says which rule binds it. */
function readHostsOf(kind: SourceKind): string {
    const fixed = SCANNER_SURFACE.reads.filter((r) => r.source === kind && 'origin' in r).map((r) => `\`${new URL((r as { origin: string }).origin).hostname}\` (fixed)`);
    if (fixed.length > 0) return fixed.join(', ');
    switch (kind) {
        case 'okta-app':
            return `the Okta org you configure, which must be on ${OKTA_HOST_SUFFIXES.map((s) => `\`*${s}\``).join(' or ')}`;
        case 'vault':
            return `each vault you configure, which must be on \`*${AZURE_KEY_VAULT_HOST_SUFFIX}\``;
        case 'runtime':
            return `${LANGSMITH_HOSTS.map((h) => `\`${h}\``).join(' or ')} (fixed, by the region you configure), or the self-hosted host you configure`;
        case 'mcp':
            return 'each MCP server you configure';
        case 'inflect-register':
            return 'the tenant you configure';
        default:
            return 'none';
    }
}

const cell = (text: string): string => text.replace(/\|/g, '\\|');
const mib = (bytes: number): string => `${bytes / (1024 * 1024)} MiB`;

function accessLines(entry: AccessEntry): string[] {
    return [
        `**Grant asked for.** ${entry.grant}.`,
        '',
        '**Must not be granted.**',
        '',
        ...entry.notNeeded.map((n) => `- ${n}`),
        '',
    ];
}

/** `docs/network-and-permissions.md`, whole. Never edited by hand. */
export function renderNetworkAndPermissionsMarkdown(): string {
    const s = SCANNER_SURFACE;
    const lines: string[] = [
        '# Network and permissions',
        '',
        '<!-- Generated by `npm run docs:network` from packages/scanner/src/scanner-surface.ts and init/access-guide.ts. Do not edit by hand. -->',
        '',
        'Every request scanent can make, and every permission it asks for. This page is rendered from',
        'the surface the scanner declares in its own code, the same declaration whose hash is in every',
        'signed report, so it lists what the code can do and nothing else.',
        '',
        `Scanner \`${s.name}\`, version ${s.version}, report contract \`${s.contract}\`.`,
        '',
        `Manifest hash: \`${scannerManifestHash()}\``,
        '',
        'The hash is SHA-256 over the canonical JSON of the declared surface. A scanner that can reach',
        'anything this page does not list has a different hash, and every report it signs carries it.',
        '',
        '## What holds for every request',
        '',
        '- **https only**, to port 443. A URL with a user name or password in it is refused.',
        '- **Redirects are refused.** A redirect ends the read; it is never followed, because the request carries a credential.',
        '- **A link to another host or another path is not followed.** A next-page link is used only when it stays on the origin and the path of the listing being read.',
        `- **Bounded.** At most ${mib(MAX_RESPONSE_BYTES)} per response and ${mib(MAX_SOURCE_BYTES)} per source, and one deadline per source (\`timeBoxSeconds\`). Past a bound the source is reported as not read in full.`,
        '- **No retry.** A request that fails is not sent again in the same scan.',
        '- **Only GET**, except the requests listed under "Token exchanges", "MCP servers", "The register read" and "The one post" below.',
        '- **No other outbound traffic.** The scanner sends no telemetry and checks for no update. Besides the requests on this page it makes DNS lookups for the hosts it reaches.',
        '',
        'To list the hosts one configuration reaches, run `scanent hosts --config <file>`.',
        '',
        '## Hosts and grants at a glance',
        '',
        '| Source | Read from | Token from | Grant |',
        '|---|---|---|---|',
    ];
    const tokenHostOf = (kind: SourceKind): string => {
        const products = new Set<string>(s.reads.filter((r) => r.source === kind).map((r) => r.product));
        const hosts = s.authenticates.filter((a) => products.has(a.product)).map((a) => `\`${new URL(a.origin).hostname}\``);
        return hosts.length === 0 ? (kind === 'inflect-register' ? 'the same tenant' : 'none') : hosts.join(', ');
    };
    for (const kind of GUIDE_ORDER) {
        lines.push(`| \`${kind}\` | ${cell(readHostsOf(kind))} | ${tokenHostOf(kind)} | ${cell(ACCESS_GUIDE[kind].grant)} |`);
    }
    lines.push('');

    // ── One section per source that reads over GET ──
    for (const kind of GUIDE_ORDER) {
        const entry = ACCESS_GUIDE[kind];
        const reads = s.reads.filter((r) => r.source === kind);
        if (reads.length === 0) continue;
        lines.push(`## ${entry.title}`, '', `Source kind \`${kind}\`. Reads from: ${readHostsOf(kind)}.`, '');
        lines.push('| Method | Path | What is kept |', '|---|---|---|');
        for (const read of reads) {
            for (const path of read.paths) {
                lines.push(`| ${read.method} | \`${path}\` | ${cell(WHAT_IS_READ[`${read.product} ${path}`] ?? 'NOT DESCRIBED')} |`);
            }
        }
        lines.push('');
        const products = new Set<string>(reads.map((r) => r.product));
        for (const auth of s.authenticates.filter((a) => products.has(a.product))) {
            lines.push(`Before reading, one token exchange: \`${auth.method} ${auth.origin}${auth.path}\`. See "Token exchanges".`, '');
        }
        lines.push(...accessLines(entry));
        const never = NEVER_REQUESTED[kind];
        if (never.length > 0) {
            lines.push('**Never requested.** The API offers these, and the scanner cannot make them:', '');
            for (const n of never) lines.push(`- \`${n.method} ${n.path}\`: ${n.why}.`);
            lines.push('');
        }
    }

    // ── MCP ──
    const mcp = ACCESS_GUIDE.mcp;
    lines.push(`## ${mcp.title}`, '', `Source kind \`mcp\`. Reads from: ${readHostsOf('mcp')}.`, '');
    for (const list of s.lists) {
        lines.push(
            `To each server the scanner sends \`${list.method}\` requests carrying these JSON-RPC messages, and no other:`,
            '',
            ...list.jsonRpc.map((m) => `- \`${m}\``),
            '',
        );
    }
    lines.push(
        'It keeps each tool\'s name and annotations, and a hash of the whole listing. It offers the server no capability (no sampling, no roots, no elicitation).',
        '',
        ...accessLines(mcp),
        '**Never sent.** `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, or any other message: no tool is ever called on an estate\'s server.',
        '',
        'An MCP server is a host the estate names, so before each request its name is resolved and every',
        'address checked: loopback, link-local (cloud metadata) and unspecified addresses are always',
        'refused, and a private address is refused unless the configuration lists its range. The same',
        'holds for a self-hosted LangSmith.',
        '',
    );

    // ── The register ──
    const registerEntry = ACCESS_GUIDE['inflect-register'];
    lines.push('## The register read', '', 'Source kind `inflect-register`. Reads from: the tenant you configure, and only when this source is configured.', '');
    for (const register of s.readsRegister) {
        lines.push(
            `1. \`${register.exchange.method} ${register.exchange.path}\`: the ingest key is exchanged for a short-lived token whose audience is \`${register.exchange.audience.join(', ')}\` and nothing else.`,
            `2. \`${register.method} ${register.path}\` carrying ${register.jsonRpc.map((m) => `\`${m}\``).join(', ')}. The one tool called is \`${register.tool}\`, with no arguments.`,
            '',
        );
    }
    lines.push(...accessLines(registerEntry), '**Never sent.** A call of any other tool, or an exchange for any other audience.', '');

    // ── Code ──
    const code = ACCESS_GUIDE.code;
    lines.push(`## ${code.title}`, '', 'Source kind `code`. No network request at all.', '');
    for (const files of s.readsFiles) {
        lines.push(
            `- File operations: ${files.operations.map((o) => `\`${o}\``).join(', ')}. Nothing is written, created, renamed or removed.`,
            `- Files read: those ending ${files.extensions.map((e) => `\`${e}\``).join(', ')}.`,
            `- Directories not entered: ${files.skips.map((d) => `\`${d}\``).join(', ')}.`,
            `- Symbolic links followed: ${files.followsSymlinks ? 'yes' : 'never'}. Code executed: ${files.executes ? 'yes' : 'never'}. Files are parsed as text.`,
            `- Bounds: ${mib(MAX_FILE_BYTES)} per file that is parsed, ${MAX_FILES.toLocaleString('en-US')} files, ${mib(MAX_TOTAL_BYTES)} in total. A larger file, up to ${mib(MAX_MARKER_SCAN_BYTES)}, is read only to look for a framework's name and is never parsed; one that names a framework is reported as not read.`,
            '',
        );
    }
    lines.push(...accessLines(code));

    // ── Token exchanges ──
    lines.push(
        '## Token exchanges',
        '',
        'A token exchange is a POST by protocol. It asks the identity provider for a token to read with,',
        'and changes nothing in the estate. The token is held in memory for one source read and is never',
        'written or logged.',
        '',
        '| For | Request | Grant type |',
        '|---|---|---|',
    );
    for (const auth of s.authenticates) {
        const grant = TOKEN_EXCHANGE_GRANTS[auth.product] === JWT_BEARER_GRANT ? 'JWT bearer (RFC 7523): an assertion signed with the service-account key' : 'client credentials';
        lines.push(`| \`${auth.product}\` | \`${auth.method} ${auth.origin}${auth.path}\` | ${grant} |`);
    }
    lines.push('');

    // ── The one post ──
    lines.push(
        '## The one post',
        '',
        'Only when the `inflect` output is in effect, the signed report is sent to the tenant you configure:',
        '',
        ...s.sends.map((send) => `- \`${send.method} ${send.path}\``),
        '',
        'The body is the signed report, byte for byte what the file output writes as `report.signed.json`.',
        'With no `inflect` output (`--out`, `--dry-run`, or a configuration that names no tenant) nothing is posted anywhere.',
        '',
    );

    // ── Egress proof ──
    lines.push(
        '## The egress proof',
        '',
        'Only when the configuration has an `egress` block. Before reading, the scanner checks that it is',
        'confined to its proxy. Each connection is opened and closed; nothing is sent through a tunnel.',
        '',
        '| Request | Through | Target | Expected |',
        '|---|---|---|---|',
        ...s.provesEgress.map((p) => `| ${p.method} | ${p.via} | \`${p.target}\` | ${p.expect} |`),
        '',
    );

    // ── Declared and not reachable ──
    lines.push('## Declared, and not reachable from a configuration', '');
    for (const gateway of s.readsGateway) {
        lines.push(
            `The surface also declares ${gateway.rpcs.length} read calls on one gRPC service, \`${gateway.service}\` (${gateway.rpcs.map((r) => `\`${r}\``).join(', ')}), under the scopes ${gateway.scopes.map((x) => `\`${x}\``).join(' and ')}.`,
            'This version carries no gRPC transport and no configuration can select that source: a scan makes no such call.',
            'It is listed because it is part of the manifest hash.',
            '',
        );
    }

    lines.push(
        '## How this page is held to the code',
        '',
        '- It is rendered from the declared surface; a test fails when the committed file differs from the rendering.',
        '- A test runs every source and every preflight against a recorder and fails on any request that is not on the surface, and on any declared request that nothing makes.',
        '- The interface a source is given has one verb, `getJson`, and no method parameter, so a source has no way to spell a write.',
        '',
    );
    return lines.join('\n');
}
