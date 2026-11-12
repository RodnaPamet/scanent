/**
 * A whole fake estate for the preflight and the hosts list: every source kind
 * at once, no network.
 *
 * It stands on `createSourceFakes` (Okta, Microsoft, Key Vault, LangSmith, MCP,
 * the Inflect tenant) and adds the two APIs those fakes do not carry, GitHub
 * and Google Cloud, each answering only what a read makes. Every request, to
 * any of them, is recorded in one `log`.
 *
 * Credential values here are distinctive and NOT secret-shaped, as in the
 * source fakes; the Google key file is generated at run time.
 */
import { generateKeyPairSync } from 'crypto';
import { resolve } from 'path';

import type { FetchLike } from '../../src/http';
import {
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET_VALUE,
    AZURE_TENANT,
    createSourceFakes,
    ENTRA_DIRECTORY_ID,
    INGEST,
    LANGSMITH_API_KEY_VALUE,
    LANGSMITH_WORKSPACE_ID,
    MCP_CRM,
    MCP_TICKETS,
    MCP_TOKEN_VALUE,
    OKTA_ORG,
    OKTA_TOKEN_VALUE,
    VAULT,
    type Fakes,
} from './agent-harness-source-fakes';

export const GITHUB_TOKEN_VALUE = 'fake-github-read-token-value-p3';
export const GOOGLE_ACCESS_TOKEN_VALUE = 'fake-google-access-token-value-p3';
export const INGEST_KEY_VALUE = 'iflk_fake-ingest-key-p3';
export const GITHUB_REPO = 'acme/payments-api';
export const GCP_PROJECT = 'acme-prod-204';
export const CODE_ROOT = resolve(__dirname, '..', '..', '..', '..', 'examples', 'code-only', 'estate');

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
/** A Google service-account key file, as JSON. It holds a private key: it must never reach any output. */
export const GCP_KEY_JSON = JSON.stringify({
    type: 'service_account',
    client_email: 'scanner@acme-prod-204.iam.gserviceaccount.com',
    private_key_id: 'abcdef0123456789',
    private_key: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
});
const ed = generateKeyPairSync('ed25519');
export const SIGNING_PEM = ed.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

export interface WorldRequest {
    readonly method: string;
    readonly host: string;
    readonly path: string;
    readonly query: string;
    readonly body?: string;
}

type Answer = { status: number; body?: unknown; headers?: Record<string, string> } | 'throw' | undefined;

export interface DoctorWorld {
    readonly fakes: Fakes;
    readonly fetchImpl: FetchLike;
    readonly log: WorldRequest[];
    /** Answer one request differently: an Answer, `'throw'`, or undefined to fall through. Seen before every fake. */
    override: ((req: WorldRequest) => Answer) | null;
    /** The `X-OAuth-Scopes` header GitHub answers with; null for a fine-grained token, which gets none. */
    githubScopes: string | null;
    /** The `Date` header every response carries, when set. */
    date: string | null;
}

export function createDoctorWorld(): DoctorWorld {
    const fakes = createSourceFakes();
    const world: DoctorWorld = {
        fakes,
        log: [],
        override: null,
        githubScopes: null,
        date: null,
        fetchImpl: async (url, init) => {
            const u = new URL(url);
            const method = (init.method ?? 'GET').toUpperCase();
            const req: WorldRequest = { method, host: u.host, path: u.pathname, query: u.search, ...(init.body === undefined || init.body === null ? {} : { body: String(init.body) }) };
            world.log.push(req);
            const dated = (res: Response): Response => {
                if (world.date === null) return res;
                const headers = new Headers(res.headers);
                headers.set('date', world.date);
                return new Response(res.body, { status: res.status, headers });
            };
            const answer = world.override?.(req) ?? own(u, method, new Headers(init.headers));
            if (answer === 'throw') throw new TypeError('fetch failed');
            if (answer !== undefined) {
                return dated(new Response(answer.body === undefined ? null : JSON.stringify(answer.body), {
                    status: answer.status,
                    headers: { 'content-type': 'application/json', ...answer.headers },
                }));
            }
            return dated(await fakes.fetchImpl(url, init));
        },
    };

    function own(u: URL, method: string, headers: Headers): Answer {
        if (u.origin === 'https://api.github.com') {
            if (headers.get('authorization') !== `Bearer ${GITHUB_TOKEN_VALUE}`) return { status: 401, body: { message: 'Bad credentials' } };
            if (method !== 'GET') return { status: 405 };
            const scopes: Record<string, string> = world.githubScopes === null ? {} : { 'x-oauth-scopes': world.githubScopes };
            if (u.pathname === `/repos/${GITHUB_REPO}`) return { status: 200, body: { full_name: GITHUB_REPO, default_branch: 'main' }, headers: scopes };
            if (u.pathname === `/repos/${GITHUB_REPO}/contents/.github/workflows`) return { status: 200, body: [] };
            if (u.pathname === `/repos/${GITHUB_REPO}/actions/secrets`) return { status: 200, body: { total_count: 0, secrets: [] } };
            return { status: 404, body: { message: 'Not Found' } };
        }
        if (u.origin === 'https://oauth2.googleapis.com') {
            if (method !== 'POST' || u.pathname !== '/token') return { status: 400, body: { error: 'invalid_request' } };
            return { status: 200, body: { access_token: GOOGLE_ACCESS_TOKEN_VALUE, token_type: 'Bearer', expires_in: 3599 } };
        }
        if (u.origin === 'https://iam.googleapis.com') {
            if (headers.get('authorization') !== `Bearer ${GOOGLE_ACCESS_TOKEN_VALUE}`) return { status: 401, body: { error: { status: 'UNAUTHENTICATED' } } };
            if (method !== 'GET') return { status: 405 };
            if (u.pathname === `/v1/projects/${GCP_PROJECT}/serviceAccounts`) return { status: 200, body: {} };
            return { status: 404, body: { error: { status: 'NOT_FOUND' } } };
        }
        return undefined;
    }

    return world;
}

/** The configuration of the whole fake estate: every source kind, a file output and the tenant. */
export function fullEstateConfig(outDir: string): Record<string, unknown> {
    return {
        estate: 'acme-prod',
        scanner: { agentId: 'agt_scanner_acme', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        inflect: { baseUrl: INGEST, tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
        outputs: [{ kind: 'file', dir: outDir }, { kind: 'inflect' }],
        schedule: { everyHours: 24 },
        sources: [
            { kind: 'entra-sp', directoryId: ENTRA_DIRECTORY_ID, clientId: AZURE_CLIENT_ID, clientSecretEnv: 'ENTRA_CLIENT_SECRET' },
            { kind: 'okta-app', orgUrl: OKTA_ORG, apiTokenEnv: 'OKTA_API_TOKEN' },
            { kind: 'vault', product: 'azure-key-vault', vaultUrls: [VAULT], directoryTenantId: AZURE_TENANT, clientId: AZURE_CLIENT_ID, clientSecretEnv: 'AZURE_CLIENT_SECRET' },
            { kind: 'cicd', product: 'github-actions', repositories: [GITHUB_REPO], tokenEnv: 'GITHUB_READ_TOKEN' },
            { kind: 'gcp-sa', product: 'gcp-iam', projects: [GCP_PROJECT], keyEnv: 'GCP_SCANNER_KEY' },
            { kind: 'runtime', product: 'langsmith', endpoint: { cloud: 'us' }, apiKeyEnv: 'LANGSMITH_API_KEY', workspaceId: LANGSMITH_WORKSPACE_ID },
            { kind: 'mcp', servers: [{ label: 'crm', url: MCP_CRM }, { label: 'tickets', url: MCP_TICKETS, readTokenEnv: 'MCP_TICKETS_TOKEN' }] },
            { kind: 'code', product: 'langchain', roots: [{ label: 'example', path: CODE_ROOT }] },
            { kind: 'inflect-register' },
        ],
    };
}

/** Every credential of the full estate, in the environment. */
export function fullEstateEnv(): Record<string, string> {
    return {
        SCANNER_SIGNING_KEY: SIGNING_PEM,
        INFLECT_INGEST_KEY: INGEST_KEY_VALUE,
        ENTRA_CLIENT_SECRET: AZURE_CLIENT_SECRET_VALUE,
        OKTA_API_TOKEN: OKTA_TOKEN_VALUE,
        AZURE_CLIENT_SECRET: AZURE_CLIENT_SECRET_VALUE,
        GITHUB_READ_TOKEN: GITHUB_TOKEN_VALUE,
        GCP_SCANNER_KEY: GCP_KEY_JSON,
        LANGSMITH_API_KEY: LANGSMITH_API_KEY_VALUE,
        MCP_TICKETS_TOKEN: MCP_TOKEN_VALUE,
    };
}

/** Every credential value and token of the world: none may appear in any output. */
export const WORLD_SECRETS: readonly string[] = [
    GITHUB_TOKEN_VALUE,
    GOOGLE_ACCESS_TOKEN_VALUE,
    INGEST_KEY_VALUE,
    'BEGIN PRIVATE KEY',
    JSON.parse(GCP_KEY_JSON).private_key.split('\n')[1] as string,
    SIGNING_PEM.split('\n')[1],
];
