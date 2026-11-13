/**
 * One fake estate with every source kind, for the suites that run whole scans
 * and preflights: the read-only proof, the partial-failure matrix, the secret
 * canaries and the scale tests. No network.
 *
 * It stands on `createSourceFakes` (Okta, Microsoft, Key Vault, LangSmith, MCP,
 * the Inflect tenant), which takes its fixtures, and adds GitHub and Google
 * Cloud with rows of their own: a repository with workflows and secrets, a
 * project with service accounts and keys. The plainer `doctor-world.ts` serves
 * those two empty, which is enough for a preflight and too little to reach the
 * per-file and per-account reads.
 *
 * Every request, to any of them, is seen by `inject` first, so a test can
 * answer one differently, fail it, or stop the clock on it.
 */
import type { FetchLike } from '../../src/http';
import {
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET_VALUE,
    AZURE_TENANT,
    createSourceFakes,
    ENTRA_DIRECTORY_ID,
    INGEST,
    LANGSMITH_API_KEY_VALUE,
    LANGSMITH_SELF_HOSTED,
    LANGSMITH_WORKSPACE_ID,
    MCP_CRM,
    MCP_TICKETS,
    MCP_TOKEN_VALUE,
    OKTA_ORG,
    OKTA_TOKEN_VALUE,
    VAULT,
    type Fakes,
} from './agent-harness-source-fakes';
import { CODE_ROOT, GCP_KEY_JSON, GCP_PROJECT, GITHUB_REPO, GITHUB_TOKEN_VALUE, GOOGLE_ACCESS_TOKEN_VALUE, INGEST_KEY_VALUE, SIGNING_PEM } from './doctor-world';

export interface GithubRepoFixture {
    /** File name to text. */
    workflows: Record<string, string>;
    secrets: { name: string; updated_at: string }[];
    /** Secrets per page; GitHub's own is 30, the reader asks for 100. */
    secretPageSize?: number;
}

/** A GitHub organisation, as its two integrations listings answer. */
export interface GithubOrgFixture {
    /** Pages of `/orgs/{org}/installations`; each page carries the total of every page. */
    installations: unknown[][];
    /** Pages of `/orgs/{org}/hooks`. */
    hooks: unknown[][];
}

/** The organisation the integrations scanner's GitHub source reads. */
export const GITHUB_ORG = 'acme';
/** Its token: an owner's fine-grained token, apart from the repositories' read token. */
export const GITHUB_INTEGRATIONS_TOKEN_VALUE = 'fake-github-integrations-token-value-s2';
/** What a webhook's URL carries beyond its host, and its secret: none of them may reach any output. */
export const GITHUB_HOOK_MARKERS = {
    path: 'HookPathSecretMarker7f3',
    query: 'HookQuerySecretMarker9c1',
    userinfo: 'HookUserinfoMarker2b8',
    secret: 'HookSecretValueMarker5d4',
} as const;

/** One installation as GitHub documents the response of "List app installations for an organization". */
export function githubInstallation(over: Record<string, unknown>): Record<string, unknown> {
    const id = over.id as number;
    return {
        id,
        account: { login: GITHUB_ORG, id: 1, type: 'Organization' },
        repository_selection: 'all',
        access_tokens_url: `https://api.github.com/app/installations/${id}/access_tokens`,
        repositories_url: 'https://api.github.com/installation/repositories',
        html_url: `https://github.com/organizations/${GITHUB_ORG}/settings/installations/${id}`,
        app_id: 9000 + id,
        target_id: 1,
        target_type: 'Organization',
        permissions: { metadata: 'read' },
        events: [],
        created_at: '2025-03-01T00:00:00.000Z',
        updated_at: '2026-03-01T00:00:00.000Z',
        single_file_name: null,
        has_multiple_single_files: false,
        single_file_paths: [],
        app_slug: `app-${id}`,
        suspended_by: null,
        suspended_at: null,
        contact_email: 'apps@vendor.example',
        ...over,
    };
}

export function githubOrgFixture(): Record<string, GithubOrgFixture> {
    return {
        [GITHUB_ORG]: {
            installations: [
                [
                    githubInstallation({
                        id: 41,
                        app_slug: 'acme-deploy-bot',
                        repository_selection: 'selected',
                        permissions: { metadata: 'read', contents: 'write', pull_requests: 'write' },
                        events: ['push', 'pull_request'],
                    }),
                    githubInstallation({ id: 42, app_slug: 'chat-notifier', permissions: { metadata: 'read', issues: 'read', repository_projects: 'read' }, events: ['issues'] }),
                ],
                [
                    githubInstallation({
                        id: 43,
                        app_slug: 'old-ci',
                        permissions: { metadata: 'read', checks: 'read', statuses: 'read' },
                        suspended_at: '2026-05-01T00:00:00.000Z',
                        suspended_by: { login: 'jane-admin', id: 77, type: 'User' },
                    }),
                ],
            ],
            hooks: [
                [
                    {
                        type: 'Organization',
                        id: 7,
                        name: 'web',
                        active: true,
                        events: ['push', 'pull_request'],
                        config: {
                            url: `https://hooks.chat.example/services/${GITHUB_HOOK_MARKERS.path}?token=${GITHUB_HOOK_MARKERS.query}`,
                            content_type: 'json',
                            insecure_ssl: '0',
                            secret: GITHUB_HOOK_MARKERS.secret,
                        },
                        updated_at: '2026-02-01T10:00:00Z',
                        created_at: '2026-01-04T10:00:00Z',
                        url: `https://api.github.com/orgs/${GITHUB_ORG}/hooks/7`,
                        ping_url: `https://api.github.com/orgs/${GITHUB_ORG}/hooks/7/pings`,
                        deliveries_url: `https://api.github.com/orgs/${GITHUB_ORG}/hooks/7/deliveries`,
                    },
                    {
                        type: 'Organization',
                        id: 8,
                        name: 'web',
                        active: false,
                        events: ['*'],
                        config: { url: `https://${GITHUB_HOOK_MARKERS.userinfo}:pw@10.20.30.40:8443/in`, content_type: 'form', insecure_ssl: '1' },
                        updated_at: '2025-12-01T10:00:00Z',
                        created_at: '2025-12-01T10:00:00Z',
                        url: `https://api.github.com/orgs/${GITHUB_ORG}/hooks/8`,
                    },
                ],
            ],
        },
    };
}

export interface GcpProjectFixture {
    /** Pages of the accounts listing. */
    accounts: { uniqueId: string; email: string; disabled?: boolean; displayName?: string; description?: string }[][];
    /** Keys by the account's unique id. */
    keys: Record<string, { name: string; validAfterTime: string; validBeforeTime: string; keyType?: string }[]>;
}

export function githubFixture(): Record<string, GithubRepoFixture> {
    return {
        [GITHUB_REPO]: {
            workflows: {
                'release.yml': 'on: push\npermissions:\n  contents: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n          TOKEN: ${{ secrets.RELEASE_TOKEN }}\n',
                'lint.yml': 'on: pull_request\npermissions:\n  contents: read\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm run lint\n',
            },
            secrets: [
                { name: 'RELEASE_TOKEN', updated_at: '2026-09-01T00:00:00Z' },
                { name: 'UNUSED_DEPLOY_KEY', updated_at: '2025-09-01T00:00:00Z' },
            ],
        },
    };
}

export function gcpFixture(): Record<string, GcpProjectFixture> {
    const unique = '104238856123456789012';
    return {
        [GCP_PROJECT]: {
            accounts: [[{ uniqueId: unique, email: `reporting@${GCP_PROJECT}.iam.gserviceaccount.com` }]],
            keys: {
                [unique]: [
                    {
                        name: `projects/${GCP_PROJECT}/serviceAccounts/reporting@${GCP_PROJECT}.iam.gserviceaccount.com/keys/2f1a9c0e3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f`,
                        validAfterTime: '2026-01-01T00:00:00Z',
                        validBeforeTime: '9999-12-31T23:59:59Z',
                        keyType: 'USER_MANAGED',
                    },
                ],
            },
        },
    };
}

export interface WorldRequest {
    readonly method: string;
    readonly url: string;
    readonly origin: string;
    readonly host: string;
    readonly path: string;
    readonly query: string;
    readonly body: string | null;
}

export type WorldAnswer =
    | { readonly status: number; readonly body?: unknown; readonly raw?: string; readonly headers?: Record<string, string> }
    /** A network failure: the fetch rejects. */
    | 'throw'
    /** The request never answers before its deadline: the fetch rejects the way an aborted one does. */
    | 'timeout'
    | undefined;

export interface EstateWorld {
    readonly fakes: Fakes;
    readonly fetchImpl: FetchLike;
    readonly log: WorldRequest[];
    /** Seen before every fake. Return an answer, or undefined to fall through. */
    inject: ((req: WorldRequest) => WorldAnswer) | null;
}

export function createEstateWorld(opts: {
    fakes?: Parameters<typeof createSourceFakes>[0];
    github?: Record<string, GithubRepoFixture>;
    githubOrgs?: Record<string, GithubOrgFixture>;
    gcp?: Record<string, GcpProjectFixture>;
} = {}): EstateWorld {
    const fakes = createSourceFakes(opts.fakes);
    const github = opts.github ?? githubFixture();
    const githubOrgs = opts.githubOrgs ?? githubOrgFixture();
    const gcp = opts.gcp ?? gcpFixture();
    const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
        new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

    const world: EstateWorld = {
        fakes,
        log: [],
        inject: null,
        fetchImpl: async (url, init) => {
            const u = new URL(url);
            const method = (init.method ?? 'GET').toUpperCase();
            const req: WorldRequest = {
                method,
                url,
                origin: u.origin,
                host: u.host,
                path: u.pathname,
                query: u.search,
                body: init.body === undefined || init.body === null ? null : String(init.body),
            };
            world.log.push(req);
            const injected = world.inject?.(req);
            if (injected === 'throw') throw new TypeError('fetch failed');
            if (injected === 'timeout') throw Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });
            if (injected !== undefined) {
                return new Response(injected.raw ?? (injected.body === undefined ? null : JSON.stringify(injected.body)), {
                    status: injected.status,
                    headers: { 'content-type': 'application/json', ...injected.headers },
                });
            }
            const headers = new Headers(init.headers);
            if (u.origin === 'https://api.github.com') return githubAnswer(u, method, headers);
            if (u.origin === 'https://oauth2.googleapis.com') {
                if (method !== 'POST' || u.pathname !== '/token') return json({ error: 'invalid_request' }, 400);
                return json({ access_token: GOOGLE_ACCESS_TOKEN_VALUE, token_type: 'Bearer', expires_in: 3599 });
            }
            if (u.origin === 'https://iam.googleapis.com') return gcpAnswer(u, method, headers);
            return fakes.fetchImpl(url, init);
        },
    };

    function githubAnswer(u: URL, method: string, headers: Headers): Response {
        const org = /^\/orgs\/([^/]+)\/(installations|hooks)$/.exec(u.pathname);
        if (org !== null) return githubOrgAnswer(u, method, headers, org[1], org[2] as 'installations' | 'hooks');
        if (headers.get('authorization') !== `Bearer ${GITHUB_TOKEN_VALUE}`) return json({ message: 'Bad credentials' }, 401);
        if (method !== 'GET') return json({ message: 'Method Not Allowed' }, 405);
        const m = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(u.pathname);
        const repo = m ? github[`${m[1]}/${m[2]}`] : undefined;
        if (!m || !repo) return json({ message: 'Not Found' }, 404);
        const rest = m[3] ?? '';
        if (rest === '') return json({ full_name: `${m[1]}/${m[2]}`, default_branch: 'main' });
        if (rest === '/contents/.github/workflows') {
            return json(Object.keys(repo.workflows).map((name) => ({ type: 'file', name, path: `.github/workflows/${name}` })));
        }
        const file = /^\/contents\/\.github\/workflows\/([^/]+)$/.exec(rest);
        if (file) {
            const text = repo.workflows[decodeURIComponent(file[1])];
            if (text === undefined) return json({ message: 'Not Found' }, 404);
            return json({ type: 'file', encoding: 'base64', content: Buffer.from(text).toString('base64') });
        }
        if (rest === '/actions/secrets') {
            const size = repo.secretPageSize ?? 100;
            const pageNo = Number(u.searchParams.get('page') ?? '1');
            const items = repo.secrets.slice((pageNo - 1) * size, pageNo * size);
            const more = pageNo * size < repo.secrets.length;
            return json(
                { total_count: repo.secrets.length, secrets: items },
                200,
                more ? { link: `<https://api.github.com${u.pathname}?per_page=100&page=${pageNo + 1}>; rel="next"` } : {},
            );
        }
        // The per-secret endpoint, which a reader must never ask.
        return json({ message: 'Not Found' }, 404);
    }

    /**
     * The organisation's two integrations listings, as GitHub pages them: by
     * `page`, with the next page in the `Link` header. A token that is not an
     * owner's fine-grained token for the organisation is refused 403, as GitHub
     * refuses one without the organisation permission.
     */
    function githubOrgAnswer(u: URL, method: string, headers: Headers, login: string, listing: 'installations' | 'hooks'): Response {
        const auth = headers.get('authorization');
        if (auth !== `Bearer ${GITHUB_INTEGRATIONS_TOKEN_VALUE}`) {
            return auth === `Bearer ${GITHUB_TOKEN_VALUE}`
                ? json({ message: 'Resource not accessible by personal access token', status: '403' }, 403)
                : json({ message: 'Bad credentials' }, 401);
        }
        if (method !== 'GET') return json({ message: 'Method Not Allowed' }, 405);
        const org = githubOrgs[login];
        if (org === undefined) return json({ message: 'Not Found' }, 404);
        const pages = org[listing];
        const pageNo = Number(u.searchParams.get('page') ?? '1');
        const items = pages[pageNo - 1] ?? [];
        const link: Record<string, string> = pageNo < pages.length ? { link: `<https://api.github.com${u.pathname}?per_page=100&page=${pageNo + 1}>; rel="next"` } : {};
        const rate = { 'x-ratelimit-limit': '5000', 'x-ratelimit-remaining': '4990', 'x-ratelimit-resource': 'core' };
        return listing === 'installations'
            ? json({ total_count: pages.flat().length, installations: items }, 200, { ...link, ...rate })
            : json(items, 200, { ...link, ...rate });
    }

    function gcpAnswer(u: URL, method: string, headers: Headers): Response {
        if (headers.get('authorization') !== `Bearer ${GOOGLE_ACCESS_TOKEN_VALUE}`) return json({ error: { status: 'UNAUTHENTICATED' } }, 401);
        if (method !== 'GET') return json({ error: { code: 405 } }, 405);
        const list = /^\/v1\/projects\/([^/]+)\/serviceAccounts$/.exec(u.pathname);
        const keys = /^\/v1\/projects\/([^/]+)\/serviceAccounts\/([^/]+)\/keys$/.exec(u.pathname);
        const project = gcp[(list ?? keys)?.[1] ?? ''];
        if (!project) return json({ error: { code: 403, status: 'PERMISSION_DENIED' } }, 403);
        if (list) {
            const at = Number(u.searchParams.get('pageToken') ?? '0');
            const accounts = project.accounts[at] ?? [];
            const next = at + 1 < project.accounts.length ? String(at + 1) : undefined;
            return json({ ...(accounts.length > 0 ? { accounts } : {}), ...(next ? { nextPageToken: next } : {}) });
        }
        if (keys) {
            const listed = project.keys[keys[2]];
            return json(listed === undefined ? {} : { keys: listed });
        }
        return json({ error: { code: 404 } }, 404);
    }

    return world;
}

/** One source's configuration in the fake estate, by a row name. Each is a member of `sources`. */
export const ESTATE_SOURCES = {
    'entra-sp': { kind: 'entra-sp', directoryId: ENTRA_DIRECTORY_ID, clientId: AZURE_CLIENT_ID, clientSecretEnv: 'ENTRA_CLIENT_SECRET' },
    'okta-app': { kind: 'okta-app', orgUrl: OKTA_ORG, apiTokenEnv: 'OKTA_API_TOKEN' },
    vault: { kind: 'vault', product: 'azure-key-vault', vaultUrls: [VAULT], directoryTenantId: AZURE_TENANT, clientId: AZURE_CLIENT_ID, clientSecretEnv: 'AZURE_CLIENT_SECRET' },
    cicd: { kind: 'cicd', product: 'github-actions', repositories: [GITHUB_REPO], tokenEnv: 'GITHUB_READ_TOKEN' },
    'gcp-sa': { kind: 'gcp-sa', product: 'gcp-iam', projects: [GCP_PROJECT], keyEnv: 'GCP_SCANNER_KEY' },
    runtime: {
        kind: 'runtime',
        product: 'langsmith',
        endpoint: { cloud: 'us' },
        apiKeyEnv: 'LANGSMITH_API_KEY',
        workspaceId: LANGSMITH_WORKSPACE_ID,
        readDeployments: true,
    },
    mcp: { kind: 'mcp', servers: [{ label: 'crm', url: MCP_CRM }, { label: 'tickets', url: MCP_TICKETS, readTokenEnv: 'MCP_TICKETS_TOKEN' }] },
    code: { kind: 'code', product: 'langchain', roots: [{ label: 'example', path: CODE_ROOT }] },
    'inflect-register': { kind: 'inflect-register' },
} as const;

/**
 * The integrations scanner's Entra source on the same fake directory, with the
 * same application and secret as `entra-sp`: one product, two scanners. Apart
 * from `ESTATE_SOURCES`, whose every row is an agent source.
 */
export const INTEGRATIONS_ESTATE_SOURCE = {
    kind: 'entra-integrations',
    directoryId: ENTRA_DIRECTORY_ID,
    clientId: AZURE_CLIENT_ID,
    clientSecretEnv: 'ENTRA_CLIENT_SECRET',
    readSignInActivity: true,
} as const;

/** The integrations scanner's three sources on the fake estate, each by its kind. Apart from `ESTATE_SOURCES`, whose every row is an agent source. */
export const INTEGRATIONS_ESTATE_SOURCES = {
    'entra-integrations': INTEGRATIONS_ESTATE_SOURCE,
    'okta-integrations': { kind: 'okta-integrations', orgUrl: OKTA_ORG, apiTokenEnv: 'OKTA_API_TOKEN' },
    'github-integrations': { kind: 'github-integrations', organization: GITHUB_ORG, tokenEnv: 'GITHUB_INTEGRATIONS_TOKEN' },
} as const;

export type EstateSourceKind = keyof typeof ESTATE_SOURCES;
export const ESTATE_SOURCE_KINDS = Object.keys(ESTATE_SOURCES) as EstateSourceKind[];

/** A self-hosted LangSmith in place of the cloud one: the same kind, a host the estate names. */
export const SELF_HOSTED_RUNTIME = {
    kind: 'runtime',
    product: 'langsmith',
    endpoint: { selfHosted: LANGSMITH_SELF_HOSTED },
    apiKeyEnv: 'LANGSMITH_API_KEY',
    readDeployments: true,
} as const;

/** A configuration of the fake estate holding the sources given. */
export function estateConfig(sources: readonly unknown[], extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        estate: 'acme-prod',
        scanner: { agentId: 'agt_scanner_acme', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        inflect: { baseUrl: INGEST, tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
        schedule: { everyHours: 24 },
        sources,
        ...extra,
    };
}

/** Every credential of the fake estate, in the environment. */
export function estateEnv(): Record<string, string> {
    return {
        SCANNER_SIGNING_KEY: SIGNING_PEM,
        INFLECT_INGEST_KEY: INGEST_KEY_VALUE,
        ENTRA_CLIENT_SECRET: AZURE_CLIENT_SECRET_VALUE,
        OKTA_API_TOKEN: OKTA_TOKEN_VALUE,
        AZURE_CLIENT_SECRET: AZURE_CLIENT_SECRET_VALUE,
        GITHUB_READ_TOKEN: GITHUB_TOKEN_VALUE,
        GITHUB_INTEGRATIONS_TOKEN: GITHUB_INTEGRATIONS_TOKEN_VALUE,
        GCP_SCANNER_KEY: GCP_KEY_JSON,
        LANGSMITH_API_KEY: LANGSMITH_API_KEY_VALUE,
        MCP_TICKETS_TOKEN: MCP_TOKEN_VALUE,
    };
}

/** The resolver the suites use for an estate-named host: one public address. */
export const PUBLIC_RESOLVER = async (): Promise<readonly string[]> => ['93.184.216.34'];
