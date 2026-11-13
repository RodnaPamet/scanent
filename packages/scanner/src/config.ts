/**
 * THE SCANNER'S CONFIGURATION — one estate per file, strict, and credential-free.
 *
 * Three rules, each held by the schema rather than by the operator's care:
 *
 *   • NO CREDENTIAL IS EVER IN THE FILE. Every secret is named by the
 *     environment variable that holds it (`…Env`), and any string in the file
 *     with a secret's shape is refused outright. A configuration that is safe
 *     to commit, diff and attach to a ticket is one nobody has to remember to
 *     scrub.
 *   • NO WRITE CREDENTIAL HAS A FIELD. The network sources take one READ
 *     credential each — an Okta SSWS token for a read-only administrator, an
 *     Entra client that holds `Key Vault Reader`, an Entra client that holds
 *     `Application.Read.All` (and, for the integrations scanner,
 *     `Directory.Read.All`), a LangSmith workspace Viewer key, an MCP server's
 *     read token (`readTokenEnv`, one per server, optional), a GitHub
 *     fine-grained token holding Contents: read and Secrets: read, a Google
 *     service-account key for an account holding
 *     `roles/iam.serviceAccountViewer`, a GitHub fine-grained token holding the
 *     organisation permissions Administration: read and Webhooks: read — the `code`
 *     source takes none, and the only other credential is the
 *     Inflect API key that posts the report, which needs the
 *     `admin:harness_ingest` scope and nothing else (contract, Transport).
 *   • EVERY HOST IS FIXED BY KIND. Okta orgs on Okta's own domains, Key Vaults
 *     on the public cloud's, Entra on Microsoft Graph's public-cloud host, LangSmith on its US or EU cloud host, GitHub
 *     Actions on `api.github.com`, Google Cloud on `iam.googleapis.com` with its token from
 *     `oauth2.googleapis.com` (never a key file's own `token_uri`), the ingest on
 *     https. A typo cannot send a token somewhere new, because there is no
 *     free-form host to type into — with TWO exceptions, each the customer's
 *     own host and each checked as any customer-named host is
 *     (`customer-host.ts`) here and re-resolved before every request: a
 *     self-hosted LangSmith (`endpoint.selfHosted`), and an MCP server's URL. The `code` source has no host: it
 *     reads absolute local paths, each reported only by the label it is given.
 *
 * Strict objects throughout: an unknown key is an error, so a misspelt
 * `ownerTag` is a refused file rather than a default silently used.
 */
import { z } from 'zod';

import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract';
import { DEFAULT_UNUSED_DAYS, MAX_UNUSED_DAYS, MIN_UNUSED_DAYS } from '@rodnapamet/scanent-contract/integrations-findings';

import { customerOriginProblem, parsePrivateCidrAllowlist } from './customer-host';
import { httpsOrigin } from './http';
import { AZURE_KEY_VAULT_HOST_SUFFIX } from './sources/azure-key-vault';
import { GCP_PROJECT_ID } from './sources/gcp-service-accounts';
import { GITHUB_REPOSITORY } from './sources/github-actions';
import {
    LANGSMITH_CLOUD_ORIGINS,
    LANGSMITH_DEFAULT_WINDOW_DAYS,
    LANGSMITH_MAX_WINDOW_DAYS,
} from './sources/langsmith';
import { OKTA_HOST_SUFFIXES } from './sources/okta';
import { ALL_SOURCE_KINDS, isAgentSourceKind } from './scanners';

const envName = z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/, 'an environment variable NAME, never a value');
const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);

function originOnHosts(suffixes: readonly string[], what: string) {
    return z.string().refine((v) => {
        const origin = httpsOrigin(v);
        if (origin === null) return false;
        const host = new URL(origin).hostname;
        return suffixes.some((s) => host.endsWith(s) && host.length > s.length);
    }, `${what} must be an https origin on ${suffixes.join(' or ')}`);
}

const OktaSourceConfigSchema = z
    .object({
        kind: z.literal('okta-app'),
        orgUrl: originOnHosts(OKTA_HOST_SUFFIXES, 'orgUrl'),
        apiTokenEnv: envName,
        ownerProfileKey: z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/).default('owner'),
    })
    .strict();

const AzureKeyVaultSourceConfigSchema = z
    .object({
        kind: z.literal('vault'),
        /** The vault product. One adapter today; the field keeps the kind generic. */
        product: z.literal('azure-key-vault'),
        vaultUrls: z.array(originOnHosts([AZURE_KEY_VAULT_HOST_SUFFIX], 'each vault URL')).min(1).max(20),
        directoryTenantId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$/),
        clientId: z.string().regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/),
        clientSecretEnv: envName,
        principalTag: z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/).default('inflect-principal'),
        ownerTag: z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/).default('owner'),
    })
    .strict();

const guidString = z.string().regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/);

const EntraSourceConfigSchema = z
    .object({
        kind: z.literal('entra-sp'),
        /**
         * The directory's id, a GUID rather than a domain: an application is
         * the estate's own when its `appOwnerOrganizationId` is this id.
         */
        directoryId: guidString,
        /** An application holding `Application.Read.All`, and nothing that writes. */
        clientId: guidString,
        clientSecretEnv: envName,
        /**
         * Also report the service principals of third-party applications
         * consented into the directory (off unless
         * the estate opts in). Microsoft's first-party applications are never
         * reported.
         */
        includeThirdPartyApplications: z.boolean().default(false),
    })
    .strict();

/**
 * The integrations scanner's Entra reader: what the directory has granted to
 * applications. Its own kind beside `entra-sp`, which may name the same
 * directory, client and secret variable: the agent scanner and the
 * integrations scanner read one product with one credential, and each reports
 * it under its own contract.
 */
const EntraIntegrationsSourceConfigSchema = z
    .object({
        kind: z.literal('entra-integrations'),
        directoryId: guidString,
        /** An application holding `Application.Read.All` and `Directory.Read.All`, and nothing that writes. */
        clientId: guidString,
        clientSecretEnv: envName,
        /**
         * Also read each application's last sign-in (the beta report
         * `servicePrincipalSignInActivities`), which needs `AuditLog.Read.All`
         * and a directory licence that records it. Off, "unused" is never
         * concluded, and the results say why.
         */
        readSignInActivity: z.boolean().default(false),
        /** An application with no sign-in within this many days is unused. The owner's default is 90. */
        unusedDays: z.number().int().min(MIN_UNUSED_DAYS).max(MAX_UNUSED_DAYS).default(DEFAULT_UNUSED_DAYS),
    })
    .strict();

/**
 * The integrations scanner's Okta reader: what the org has granted to the
 * applications in it. Its own kind beside `okta-app`, which may name the same
 * org and the same token variable: both read with a Read-only Administrator's
 * SSWS token. Okta records no last use of an application outside its System
 * Log, so there is no sign-in setting here: "unused" is not concluded for Okta.
 */
const OktaIntegrationsSourceConfigSchema = z
    .object({
        kind: z.literal('okta-integrations'),
        orgUrl: originOnHosts(OKTA_HOST_SUFFIXES, 'orgUrl'),
        apiTokenEnv: envName,
    })
    .strict();

/** A GitHub organisation's login, as GitHub allows one. */
export const GITHUB_ORGANIZATION_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;

/**
 * The integrations scanner's GitHub reader: the apps installed on one
 * organisation and its webhooks, read from `api.github.com`. Its own kind
 * beside `cicd`, with its own token: these are the organisation's endpoints,
 * and they take an owner's fine-grained token holding the organisation
 * permissions Administration: read and Webhooks: read.
 */
const GitHubIntegrationsSourceConfigSchema = z
    .object({
        kind: z.literal('github-integrations'),
        organization: z.string().regex(GITHUB_ORGANIZATION_LOGIN, 'an organisation login'),
        tokenEnv: envName,
    })
    .strict();

const GitHubActionsSourceConfigSchema = z
    .object({
        kind: z.literal('cicd'),
        /** The CI/CD product. GitHub Actions is the one adapter; the field keeps the kind generic. */
        product: z.literal('github-actions'),
        /** `owner/repo`, each read from `api.github.com` with the one token. */
        repositories: z
            .array(z.string().regex(GITHUB_REPOSITORY, 'owner/repo'))
            .min(1)
            .max(50)
            .refine((r) => new Set(r.map((x) => x.toLowerCase())).size === r.length, 'each repository appears once'),
        /**
         * A fine-grained token holding Contents: read and Secrets: read on those
         * repositories, and nothing else. Secrets: read lists secret names; no
         * GitHub permission reads a value.
         */
        tokenEnv: envName,
    })
    .strict();

const GcpServiceAccountSourceConfigSchema = z
    .object({
        kind: z.literal('gcp-sa'),
        /** The cloud product. Google Cloud IAM is the one adapter; the field keeps the kind generic. */
        product: z.literal('gcp-iam'),
        /** Project ids, each read from `iam.googleapis.com` as the one service account. */
        projects: z
            .array(z.string().regex(GCP_PROJECT_ID, 'a project id'))
            .min(1)
            .max(50)
            .refine((p) => new Set(p).size === p.length, 'each project appears once'),
        /**
         * The service-account key file's JSON, for an account holding
         * `roles/iam.serviceAccountViewer` on those projects and nothing else.
         * That role lists accounts and key metadata and changes neither.
         */
        keyEnv: envName,
    })
    .strict();

/** An absolute local path: no `..` segment, no control character. */
const absolutePath = z
    .string()
    .max(1024)
    .refine(
        (v) => v.startsWith('/') && !v.split('/').includes('..') && ![...v].some((ch) => ch.charCodeAt(0) < 0x20),
        'an absolute path with no .. segment',
    );

const CodeSourceConfigSchema = z
    .object({
        kind: z.literal('code'),
        /** The framework the detector recognises. One today; the field keeps the kind generic. */
        product: z.literal('langchain'),
        /**
         * The directories to read. Each is reported by its `label` alone, never
         * its path, which can name a person (`/home/<user>/…`).
         */
        roots: z
            .array(z.object({ label: slug, path: absolutePath }).strict())
            .min(1)
            .max(20)
            .superRefine((roots, ctx) => {
                const labels = roots.map((r) => r.label);
                if (new Set(labels).size !== labels.length) ctx.addIssue({ code: 'custom', message: 'each root label appears once' });
            }),
        /**
         * Agents built directly on a model provider's SDK (Anthropic, OpenAI
         * and Azure OpenAI, Google Gemini, AWS Bedrock): a model call that is
         * given tools. Read unless this is `false`. Off, the source parses and
         * reports what it did before it recognised them.
         */
        providerSdks: z.boolean().optional(),
    })
    .strict();

const LangSmithSourceConfigSchema = z
    .object({
        kind: z.literal('runtime'),
        /** The runtime product. LangSmith is the one adapter; the field keeps the kind generic. */
        product: z.literal('langsmith'),
        /**
         * Exactly one of: a cloud data region, whose host is fixed here, or the
         * customer's own self-hosted LangSmith — the one host in this file a
         * person types, refused unless it is a bare https origin that is not a
         * private, loopback, link-local or internal address. A self-hosted
         * LangSmith on the estate's own network names the private ranges it
         * may resolve into (`egressPrivateCidrAllowlist`, after the
         * application's `EGRESS_PRIVATE_CIDR_ALLOWLIST`); metadata, loopback and
         * link-local stay refused inside them (`customer-host.ts`).
         */
        endpoint: z.union([
            z.object({ cloud: z.enum(Object.keys(LANGSMITH_CLOUD_ORIGINS) as [keyof typeof LANGSMITH_CLOUD_ORIGINS]) }).strict(),
            z
                .object({
                    selfHosted: z.string(),
                    egressPrivateCidrAllowlist: z
                        .array(z.string().max(64))
                        .max(32)
                        .refine((v) => parsePrivateCidrAllowlist(v) !== null, 'each entry must be a CIDR, e.g. 10.20.0.0/16 or fd00::/8')
                        .default([]),
                })
                .strict()
                .superRefine((e, ctx) => {
                    const allowlist = parsePrivateCidrAllowlist(e.egressPrivateCidrAllowlist);
                    if (allowlist !== null && customerOriginProblem(e.selfHosted, allowlist) !== null) {
                        ctx.addIssue({ code: 'custom', message: 'selfHosted must be an https origin the scanner may reach', path: ['selfHosted'] });
                    }
                }),
        ]),
        /** A read-scoped LangSmith API key (a workspace Viewer service key). */
        apiKeyEnv: envName,
        /** The workspace (`X-Tenant-Id`); leave out for a key scoped to one workspace. */
        workspaceId: z.string().regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/).optional(),
        /** The bounded window tool usage is summarised over. */
        windowDays: z.number().int().min(1).max(LANGSMITH_MAX_WINDOW_DAYS).default(LANGSMITH_DEFAULT_WINDOW_DAYS),
        /**
         * Whether to list deployments too. OFF unless the estate opts in:
         * the deployments listing carries each
         * deployment's secrets, and a scanner that does not need it should not
         * receive it. Projects are read either way.
         */
        readDeployments: z.boolean().default(false),
    })
    .strict();

/** A principal as another source names it: `<source>:<id…>`, no whitespace. The vault's tag takes the same shape. */
const discoveredIdRef = z.string().regex(/^[a-z][a-z0-9-]{0,31}:\S{1,220}$/, 'a discoveredId, e.g. entra:sp:<objectId>');

const egressPrivateCidrAllowlist = z
    .array(z.string().max(64))
    .max(32)
    .refine((v) => parsePrivateCidrAllowlist(v) !== null, 'each entry must be a CIDR, e.g. 10.20.0.0/16 or fd00::/8')
    .default([]);

/** An MCP server's endpoint: https, no credentials, no query or fragment. A path is allowed — the endpoint is one. */
function mcpEndpointProblem(value: string, allowlist: readonly string[]): string | null {
    let u: URL;
    try {
        u = new URL(value);
    } catch {
        return 'must be a URL';
    }
    if (u.protocol !== 'https:' || u.username !== '' || u.password !== '' || u.search !== '' || u.hash !== '') {
        return 'must be an https URL with no credentials, query or fragment';
    }
    const parsed = parsePrivateCidrAllowlist([...allowlist]);
    return parsed === null ? 'has an allowlist that does not parse' : customerOriginProblem(u.origin, parsed);
}

const McpServerConfigSchema = z
    .object({
        label: slug,
        url: z.string().max(512),
        /** The agents that use this server, by the id the source that finds them gives. */
        agents: z.array(discoveredIdRef).max(1_000).default([]),
        /** `sha256:` of the listing the estate pinned: `pinned` is true only while the live listing matches it. */
        pinnedManifestHash: z.string().regex(/^sha256:[0-9a-f]{64}$/).optional(),
        /**
         * A READ token for the server, by environment variable: sent as a bearer
         * token with `initialize`, the initialized notification and `tools/list`,
         * and nothing else. For Inflect's own `/api/mcp`, a key
         * holding `mcp:read` and no other MCP scope.
         */
        readTokenEnv: envName.optional(),
        /** Private ranges the server's host may resolve into, as for a self-hosted LangSmith. */
        egressPrivateCidrAllowlist,
    })
    .strict()
    .superRefine((s, ctx) => {
        if (mcpEndpointProblem(s.url, s.egressPrivateCidrAllowlist) !== null) {
            ctx.addIssue({ code: 'custom', message: 'url must be an https MCP endpoint the scanner may reach', path: ['url'] });
        }
    });

const McpSourceConfigSchema = z
    .object({
        kind: z.literal('mcp'),
        servers: z
            .array(McpServerConfigSchema)
            .min(1)
            .max(50)
            .superRefine((servers, ctx) => {
                if (new Set(servers.map((s) => s.label)).size !== servers.length) {
                    ctx.addIssue({ code: 'custom', message: 'each server label appears once' });
                }
                if (new Set(servers.map((s) => s.url)).size !== servers.length) {
                    ctx.addIssue({ code: 'custom', message: 'each server URL appears once' });
                }
            }),
    })
    .strict();

/**
 * The scanner's own tenant's register. No field: it is read from
 * `inflect.baseUrl`'s `/api/mcp` with the ingest key `inflect.apiKeyEnv` names,
 * which must also carry `mcp:read`, by the one tool the
 * scanner may call.
 */
const InflectRegisterSourceConfigSchema = z.object({ kind: z.literal('inflect-register') }).strict();

export const SourceConfigSchema = z.discriminatedUnion('kind', [
    EntraSourceConfigSchema,
    OktaSourceConfigSchema,
    AzureKeyVaultSourceConfigSchema,
    CodeSourceConfigSchema,
    LangSmithSourceConfigSchema,
    McpSourceConfigSchema,
    InflectRegisterSourceConfigSchema,
    GitHubActionsSourceConfigSchema,
    GcpServiceAccountSourceConfigSchema,
    EntraIntegrationsSourceConfigSchema,
    OktaIntegrationsSourceConfigSchema,
    GitHubIntegrationsSourceConfigSchema,
]);

const OutputConfigSchema = z.discriminatedUnion('kind', [
    z
        .object({
            kind: z.literal('file'),
            /** The directory each run is written under, as `runs/<scanId>/`. */
            dir: absolutePath,
            /** Keep this many runs and remove older ones. Absent: nothing is ever removed. */
            retainRuns: z.number().int().min(1).max(10_000).optional(),
        })
        .strict(),
    z.object({ kind: z.literal('stdout') }).strict(),
    z.object({ kind: z.literal('inflect') }).strict(),
]);

export type OutputConfig = z.infer<typeof OutputConfigSchema>;

export const ScannerConfigSchema = z
    .object({
        /** The estate this deployment scans: a label for the operator and the scan id, never reported. */
        estate: slug,
        scanner: z
            .object({
                /** The scanner's register id in the tenant; its public key is registered against it. */
                agentId: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
                /** PKCS#8 PEM of the Ed25519 signing key. */
                signingKeyEnv: envName,
            })
            .strict(),
        /**
         * The Inflect tenant the report is posted to and the register is read
         * from. Optional: a run that only writes its results locally names no
         * tenant. Required when the `inflect` output is in effect, when the
         * `inflect-register` source is configured, or when `egress` is set
         * (the egress proof's allowed host is the ingest's).
         */
        inflect: z
            .object({
                baseUrl: z.string().refine((v) => httpsOrigin(v) !== null, 'baseUrl must be an https origin'),
                tenantSlug: slug,
                /** An API key with the `admin:harness_ingest` scope and no other. */
                apiKeyEnv: envName,
            })
            .strict()
            .optional(),
        /**
         * Where one run's results go: files under a directory, the signed
         * report on stdout, the tenant's ingest. Each kind at most once.
         * Absent, a configuration with an `inflect` block posts to it, which
         * is what every configuration written before outputs existed means
         * (`outputs.ts`).
         */
        outputs: z.array(OutputConfigSchema).min(1).max(3).optional(),
        schedule: z.object({ everyHours: z.number().int().min(1).max(720) }).strict(),
        /** Read in a fixed time box each. */
        timeBoxSeconds: z.number().int().min(10).max(3_600).default(600),
        /**
         * The egress proxy this deployment's scanner is confined to. When
         * set, every scan proves the confinement before it reads and
         * reports it as `H3.egress_enforced` on the scanner's own agent
         * (`egress-proof.ts`). Absent, the criterion is left unanswered.
         */
        egress: z
            .object({
                /** `http://<host>:<port>`, the proxy as the scanner's network names it. */
                proxyUrl: z
                    .string()
                    .refine((v) => {
                        try {
                            const u = new URL(v);
                            return u.protocol === 'http:' && u.username === '' && u.password === '' && (u.pathname === '/' || u.pathname === '') && u.search === '';
                        } catch {
                            return false;
                        }
                    }, 'proxyUrl must be http://<host>:<port> with nothing else'),
                /** A host the proxy must refuse. */
                canaryHost: z.string().regex(/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/, 'canaryHost must be a lower-case hostname'),
            })
            .strict()
            .optional(),
        /**
         * The operator's inventory of the agents the estate knows: who owns
         * each and what it is for. Optional. It is what lets a run with no
         * register show an agent as registered, and everything it supplies is
         * labelled as declared, never as observed (`inventory-file.ts`). The
         * file is a `.json` or a `.csv`, read once per scan; it never enters
         * the signed report.
         */
        inventory: z
            .object({
                path: absolutePath.refine((v) => /\.(json|csv)$/i.test(v), 'a .json or a .csv file'),
            })
            .strict()
            .optional(),
        sources: z.array(SourceConfigSchema).min(1).max(ALL_SOURCE_KINDS.length),
    })
    .strict()
    .superRefine((c, ctx) => {
        const kinds = c.sources.map((s) => s.kind);
        if (new Set(kinds).size !== kinds.length) {
            ctx.addIssue({ code: 'custom', message: 'each source kind appears once, as in the report', path: ['sources'] });
        }
        const outputKinds = (c.outputs ?? []).map((o) => o.kind);
        if (new Set(outputKinds).size !== outputKinds.length) {
            ctx.addIssue({ code: 'custom', message: 'each output kind appears once', path: ['outputs'] });
        }
        // Which scanners run follows from the sources configured. The tenant's ingest
        // takes the agent report only, so posting needs an agent source: an
        // `inflect` output in effect (named, or meant by an `inflect` block with
        // no `outputs`) over integrations sources alone would send nothing.
        const inflectOutput = c.outputs !== undefined ? outputKinds.includes('inflect') : c.inflect !== undefined;
        if (inflectOutput && !kinds.some(isAgentSourceKind)) {
            ctx.addIssue({
                code: 'custom',
                message: 'the inflect output posts the agent report, and no agent source is configured: name the file or stdout output',
                path: ['outputs'],
            });
        }
        if (c.inflect === undefined && (outputKinds.includes('inflect') || kinds.includes('inflect-register') || c.egress !== undefined)) {
            ctx.addIssue({
                code: 'custom',
                message: 'the inflect block is required by the inflect output, the inflect-register source and egress',
                path: ['inflect'],
            });
        }
    });

export type ScannerConfig = z.infer<typeof ScannerConfigSchema>;
export type SourceConfig = z.infer<typeof SourceConfigSchema>;
export type InflectConfig = NonNullable<ScannerConfig['inflect']>;
/** A configuration known to name a tenant: what a value that carries an `inflect` block parses to. */
export type ScannerConfigWithInflect = ScannerConfig & { readonly inflect: InflectConfig };

/**
 * The path of the first secret-shaped string in an untrusted JSON tree, or
 * null. A KEY is untrusted too: a secret-shaped key is itself a hit, and it is
 * written `<key>` in the path, which is printed.
 */
export function firstSecretShaped(node: unknown, path: string): string | null {
    if (typeof node === 'string') return looksLikeSecret(node) ? path || '(root)' : null;
    if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i++) {
            const hit = firstSecretShaped(node[i], `${path}[${i}]`);
            if (hit) return hit;
        }
        return null;
    }
    if (node !== null && typeof node === 'object') {
        for (const [k, v] of Object.entries(node)) {
            if (looksLikeSecret(k)) return path ? `${path}.<key>` : '<key>';
            const hit = firstSecretShaped(v, path ? `${path}.${k}` : k);
            if (hit) return hit;
        }
    }
    return null;
}

export class ConfigError extends Error {
    constructor(readonly issues: readonly string[]) {
        super(`invalid scanner configuration: ${issues.join('; ')}`);
        this.name = 'ConfigError';
    }
}

/**
 * Parse a configuration file's JSON. Refuses a secret-shaped string anywhere
 * BEFORE the schema runs, and reports issues by path and code — never by value,
 * since the value refused may be the credential somebody pasted in.
 */
export function parseScannerConfig<T extends { readonly inflect: object }>(json: T): ScannerConfigWithInflect;
export function parseScannerConfig(json: unknown): ScannerConfig;
export function parseScannerConfig(json: unknown): ScannerConfig {
    try {
        return parseScannerConfigValue(json);
    } catch (err) {
        // A value nested hundreds of thousands deep overflows the stack of
        // whatever walks it: a refused configuration, not the engine's message.
        if (err instanceof RangeError) throw new ConfigError(['(root): nested too deeply']);
        throw err;
    }
}

function parseScannerConfigValue(json: unknown): ScannerConfig {
    const secretAt = firstSecretShaped(json, '');
    if (secretAt !== null) {
        throw new ConfigError([`${secretAt}: a credential value in the configuration; name its environment variable instead`]);
    }
    const parsed = ScannerConfigSchema.safeParse(json);
    if (!parsed.success) {
        throw new ConfigError(parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`));
    }
    return parsed.data;
}

/**
 * The environment variable holding one source's read credential. The `code`
 * source holds none, and the `mcp` source one per server at most
 * (`mcpTokenEnvNames`).
 */
export function sourceCredentialEnv(source: Exclude<SourceConfig, { kind: 'code' | 'mcp' | 'inflect-register' }>): string {
    switch (source.kind) {
        case 'entra-sp':
            return source.clientSecretEnv;
        case 'okta-app':
            return source.apiTokenEnv;
        case 'vault':
            return source.clientSecretEnv;
        case 'runtime':
            return source.apiKeyEnv;
        case 'cicd':
            return source.tokenEnv;
        case 'gcp-sa':
            return source.keyEnv;
        case 'entra-integrations':
            return source.clientSecretEnv;
        case 'okta-integrations':
            return source.apiTokenEnv;
        case 'github-integrations':
            return source.tokenEnv;
    }
}

/** The read-token variables an `mcp` source names, one per server that takes a token. */
export function mcpTokenEnvNames(source: Extract<SourceConfig, { kind: 'mcp' }>): string[] {
    return source.servers.flatMap((s) => (s.readTokenEnv === undefined ? [] : [s.readTokenEnv]));
}

/** The environment variables a configuration names, every one of them. The ingest key is one only when the `inflect` block exists. */
export function credentialEnvNames(config: ScannerConfig): string[] {
    const fromSources = config.sources.flatMap((s) =>
        s.kind === 'code' || s.kind === 'inflect-register'
            ? []
            : s.kind === 'mcp'
                ? mcpTokenEnvNames(s)
                : [sourceCredentialEnv(s)],
    );
    return [config.scanner.signingKeyEnv, ...(config.inflect === undefined ? [] : [config.inflect.apiKeyEnv]), ...fromSources];
}
