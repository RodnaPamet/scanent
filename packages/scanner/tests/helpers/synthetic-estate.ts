/**
 * A synthetic estate of any size, for the scale tests.
 *
 * From a seed and three numbers (agents, credentials, and how many targets the
 * sources that take several are spread over) it builds fixtures for the fakes
 * of `estate-world.ts`, paged the way each API pages: Graph and Key Vault by a
 * next link in the body, Okta and GitHub by a `Link` header, Google by a page
 * token, LangSmith by offset.
 *
 * The agents are spread over the sources that find agents; the credentials
 * over the places a credential is seen: on an Entra application, as a Google
 * service-account key, and as a Key Vault secret tagged with the principal it
 * belongs to. The same seed and numbers give the same estate.
 */
import { AZURE_CLIENT_ID, AZURE_TENANT, ENTRA_DIRECTORY_ID, type GraphFixture, type LangSmithFixture, type OktaFixture, type VaultFixture } from './agent-harness-source-fakes';
import { GCP_PROJECT, GITHUB_REPO } from './doctor-world';
import { createEstateWorld, ESTATE_SOURCES, type EstateWorld, type GcpProjectFixture, type GithubRepoFixture } from './estate-world';
import { rng } from './prng';

export interface SyntheticShape {
    readonly seed: number;
    readonly agents: number;
    readonly credentials: number;
    /** Targets per multi-target source: vaults, repositories, projects. At least 1. */
    readonly targets: number;
}

export interface SyntheticEstate {
    readonly world: EstateWorld;
    /** The `sources` of a configuration that reads the whole estate: every kind. */
    readonly sources: readonly unknown[];
    /** How many agents each source kind was given. */
    readonly agentsBy: Readonly<Record<'entra-sp' | 'okta-app' | 'gcp-sa' | 'runtime' | 'cicd', number>>;
    /** How many credentials each place was given. */
    readonly credentialsBy: Readonly<Record<'entra' | 'gcp' | 'vault', number>>;
}

const hex = (n: number, width: number): string => n.toString(16).padStart(width, '0');
const guid = (prefix: string, n: number): string => `${prefix}${hex(n, 7)}-0000-4000-8000-${hex(n, 12)}`;
const chunk = <T>(items: readonly T[], size: number): T[][] => {
    const pages: T[][] = [];
    for (let i = 0; i < items.length; i += size) pages.push(items.slice(i, i + size));
    return pages.length === 0 ? [[]] : pages;
};
const AS_OF = Date.parse('2026-10-19T03:00:00.000Z');
const iso = (daysAgo: number): string => new Date(AS_OF - daysAgo * 86_400_000).toISOString();

export function syntheticEstate(shape: SyntheticShape): SyntheticEstate {
    const r = rng(shape.seed);
    const targets = Math.max(1, shape.targets);
    // Shares of the agents, by the source that finds them. What is left over goes to Entra.
    const okta = Math.floor(shape.agents * 0.15);
    const gcp = Math.floor(shape.agents * 0.2);
    const runtime = Math.floor(shape.agents * 0.1);
    const cicd = Math.min(Math.floor(shape.agents * 0.05), targets * 20);
    const entra = shape.agents - okta - gcp - runtime - cicd;
    // Shares of the credentials, by where they are seen.
    const gcpKeys = gcp === 0 ? 0 : Math.floor(shape.credentials * 0.25);
    const vaultSecrets = Math.floor(shape.credentials * 0.25);
    const entraSecrets = shape.credentials - gcpKeys - vaultSecrets;

    // ── Entra: one application and one service principal per agent; secrets dealt round the applications ──
    const perApp = entra === 0 ? 0 : Math.floor(entraSecrets / entra);
    const extra = entra === 0 ? 0 : entraSecrets % entra;
    let keyNo = 0;
    const applications = Array.from({ length: entra }, (_, i) => ({
        id: guid('b', i),
        appId: guid('e', i),
        passwordCredentials: Array.from({ length: perApp + (i < extra ? 1 : 0) }, () => ({
            keyId: guid('d', keyNo++),
            startDateTime: iso(r.int(1, 700)),
            endDateTime: r.chance(0.8) ? iso(-r.int(1, 300)) : null,
        })),
        keyCredentials: [],
        owners: r.chance(0.6) ? [{ '@odata.type': '#microsoft.graph.user', id: guid('c', r.int(0, 500)) }] : [],
    }));
    const servicePrincipals = Array.from({ length: entra }, (_, i) => ({
        id: guid('a', i),
        appId: guid('e', i),
        servicePrincipalType: 'Application',
        appOwnerOrganizationId: ENTRA_DIRECTORY_ID,
        accountEnabled: true,
        passwordCredentials: [],
        keyCredentials: [],
        owners: [],
    }));
    const graph: GraphFixture = { applications: chunk(applications, 100), servicePrincipals: chunk(servicePrincipals, 100) };

    // ── Okta: service apps ──
    const oktaFixture: OktaFixture = {
        apps: chunk(
            Array.from({ length: okta }, (_, i) => ({
                id: `0oa${hex(i, 9)}`,
                signOnMode: 'OPENID_CONNECT',
                settings: { oauthClient: { application_type: 'service' } },
                ...(r.chance(0.5) ? { profile: { owner: `owner-${r.int(0, 200)}@acme.example` } } : {}),
            })),
            200,
        ),
        tokens: [[{ id: '00TScannerOwn', name: 'Automation token', userId: '00uScannerOwner', created: iso(40) }]],
        currentTokenId: '00TScannerOwn',
    };

    // ── Key Vault: secrets tagged with the Entra principal each belongs to, dealt round the vaults ──
    const vaultOrigins = Array.from({ length: Math.min(targets, 20) }, (_, v) => `https://acme-agents-${v}.vault.azure.net`);
    const unix = (daysAgo: number) => Math.floor((AS_OF - daysAgo * 86_400_000) / 1000);
    const vaults: Record<string, VaultFixture> = Object.fromEntries(
        vaultOrigins.map((origin, v) => {
            const mine = Array.from({ length: vaultSecrets }, (_, i) => i).filter((i) => i % vaultOrigins.length === v);
            return [
                origin,
                {
                    secrets: chunk(
                        mine.map((i) => ({
                            id: `${origin}/secrets/secret-${i}`,
                            attributes: { enabled: true, created: unix(r.int(1, 700)), ...(r.chance(0.5) ? { exp: unix(-r.int(1, 300)) } : {}) },
                            // Bound to a principal Entra finds, when there is one; otherwise seen unbound.
                            ...(entra > 0 ? { tags: { 'inflect-principal': `entra:sp:${guid('a', i % entra)}` } } : {}),
                        })),
                        25,
                    ),
                    certificates: [[]],
                },
            ];
        }),
    );

    // ── Google Cloud: accounts dealt round the projects, keys dealt round the accounts ──
    const projectIds = Array.from({ length: Math.min(targets, 50) }, (_, p) => (p === 0 ? GCP_PROJECT : `acme-prod-${hex(p, 4)}`));
    const perAccount = gcp === 0 ? 0 : Math.floor(gcpKeys / gcp);
    const extraKeys = gcp === 0 ? 0 : gcpKeys % gcp;
    const gcpProjects: Record<string, GcpProjectFixture> = Object.fromEntries(
        projectIds.map((project, p) => {
            const mine = Array.from({ length: gcp }, (_, i) => i).filter((i) => i % projectIds.length === p);
            const unique = (i: number) => `1${String(i).padStart(20, '0')}`;
            return [
                project,
                {
                    accounts: chunk(mine.map((i) => ({ uniqueId: unique(i), email: `sa-${i}@${project}.iam.gserviceaccount.com` })), 100),
                    keys: Object.fromEntries(
                        mine.map((i) => [
                            unique(i),
                            Array.from({ length: perAccount + (i < extraKeys ? 1 : 0) }, (_, k) => ({
                                name: `projects/${project}/serviceAccounts/sa-${i}@${project}.iam.gserviceaccount.com/keys/${hex(i, 20)}${hex(k, 20)}`,
                                validAfterTime: iso(r.int(1, 700)),
                                validBeforeTime: '9999-12-31T23:59:59Z',
                                keyType: 'USER_MANAGED',
                            })),
                        ]),
                    ),
                },
            ];
        }),
    );

    // ── LangSmith: tracing projects that called a tool in the window ──
    const langsmith: LangSmithFixture = {
        projects: Array.from({ length: runtime }, (_, i) => ({
            id: guid('f', i),
            startTime: iso(r.int(8, 300)),
            runs: [{ id: `r-${i}`, runType: 'tool' as const, name: `tool_${i % 40}`, startTime: iso(1) }],
        })),
        deployments: [],
    };

    // ── GitHub: workflows that hold a secret, dealt round the repositories ──
    const repoNames = Array.from({ length: Math.min(targets, 50) }, (_, g) => (g === 0 ? GITHUB_REPO : `acme/service-${hex(g, 4)}`));
    const github: Record<string, GithubRepoFixture> = Object.fromEntries(
        repoNames.map((repo, g) => {
            const mine = Array.from({ length: cicd }, (_, i) => i).filter((i) => i % repoNames.length === g);
            return [
                repo,
                {
                    workflows: Object.fromEntries(
                        mine.map((i) => [
                            `deploy-${i}.yml`,
                            `on: push\npermissions:\n  contents: read\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh\n        env:\n          TOKEN: \${{ secrets.DEPLOY_TOKEN_${i} }}\n`,
                        ]),
                    ),
                    secrets: mine.map((i) => ({ name: `DEPLOY_TOKEN_${i}`, updated_at: iso(r.int(1, 400)) })),
                    secretPageSize: 100,
                },
            ];
        }),
    );

    const world = createEstateWorld({
        fakes: { graph, okta: oktaFixture, vaults, langsmith: { 'https://api.smith.langchain.com': langsmith } },
        github,
        gcp: gcpProjects,
    });
    const sources = [
        ESTATE_SOURCES['entra-sp'],
        ESTATE_SOURCES['okta-app'],
        { kind: 'vault', product: 'azure-key-vault', vaultUrls: vaultOrigins, directoryTenantId: AZURE_TENANT, clientId: AZURE_CLIENT_ID, clientSecretEnv: 'AZURE_CLIENT_SECRET' },
        { kind: 'cicd', product: 'github-actions', repositories: repoNames, tokenEnv: 'GITHUB_READ_TOKEN' },
        { kind: 'gcp-sa', product: 'gcp-iam', projects: projectIds, keyEnv: 'GCP_SCANNER_KEY' },
        { ...ESTATE_SOURCES.runtime, readDeployments: false },
        ESTATE_SOURCES.mcp,
        ESTATE_SOURCES.code,
        ESTATE_SOURCES['inflect-register'],
    ];
    return { world, sources, agentsBy: { 'entra-sp': entra, 'okta-app': okta, 'gcp-sa': gcp, runtime, cicd }, credentialsBy: { entra: entraSecrets, gcp: gcpKeys, vault: vaultSecrets } };
}
