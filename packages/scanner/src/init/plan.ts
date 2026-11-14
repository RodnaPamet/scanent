/**
 * THE WIZARD'S PLANNER — answers in, the files' contents out. Pure: it reads
 * no file, no clock and no environment.
 *
 * The configuration it builds is passed through `parseScannerConfig`, so what
 * `init` writes is by construction a file `scan` accepts, and the
 * secret-shape refusal runs over every answer a second time.
 *
 * Credentials are named, never held: each source's variable gets its
 * documented default name, and the env template lists those names with
 * nothing after the `=` (or a path, for a secret kept in a file).
 */
import { ConfigError, credentialEnvNames, parseScannerConfig, type ScannerConfig } from '../config';
import { isAgentSourceKind } from '../scanners';
import { accessTablesFor, type AccessTable } from './access-guide';
import { InitError, type InitAnswers, type SourceAnswer } from './answers';

export const DEFAULT_OUTPUT_DIR = '/out';
export const DEFAULT_EVERY_HOURS = 24;
export const DEFAULT_SIGNING_KEY_ENV = 'SCANNER_SIGNING_KEY';
export const DEFAULT_INGEST_KEY_ENV = 'INFLECT_INGEST_KEY';
/** The integrations report's ingest key: a second key, with `admin:integrations_ingest`. */
export const DEFAULT_INTEGRATIONS_INGEST_KEY_ENV = 'INFLECT_INTEGRATIONS_KEY';
/** The `entra-sp` source's secret variable: the integrations source names it too when it reads with the same application. */
export const DEFAULT_ENTRA_SECRET_ENV = 'ENTRA_CLIENT_SECRET';

/** Each kind's product (where the configuration has the field) and the default name of its credential's variable. */
const SOURCE_DEFAULTS: Readonly<Record<Exclude<SourceAnswer['kind'], 'mcp' | 'code'>, { product?: string; envField: string; envName: string; file: boolean; what: string }>> = {
    'entra-sp': { envField: 'clientSecretEnv', envName: DEFAULT_ENTRA_SECRET_ENV, file: false, what: 'Entra: client secret of the application holding Application.Read.All.' },
    vault: { product: 'azure-key-vault', envField: 'clientSecretEnv', envName: 'AZURE_CLIENT_SECRET', file: false, what: 'Azure Key Vault: client secret of the application holding Key Vault Reader.' },
    'okta-app': { envField: 'apiTokenEnv', envName: 'OKTA_API_TOKEN', file: false, what: 'Okta: SSWS API token of a Read-only Administrator.' },
    cicd: { product: 'github-actions', envField: 'tokenEnv', envName: 'GITHUB_READ_TOKEN', file: false, what: 'GitHub: fine-grained token with Contents: Read-only and Secrets: Read-only.' },
    'gcp-sa': { product: 'gcp-iam', envField: 'keyEnv', envName: 'GCP_SCANNER_KEY', file: true, what: 'Google Cloud: the service-account key file (JSON). A file, because the key has line breaks.' },
    runtime: { product: 'langsmith', envField: 'apiKeyEnv', envName: 'LANGSMITH_API_KEY', file: false, what: 'LangSmith: service key holding the workspace Viewer role.' },
    'okta-integrations': { envField: 'apiTokenEnv', envName: 'OKTA_API_TOKEN', file: false, what: 'Okta integrations: SSWS API token of a Read-only Administrator. It may be the okta-app token.' },
    'github-integrations': {
        envField: 'tokenEnv',
        envName: 'GITHUB_INTEGRATIONS_TOKEN',
        file: false,
        what: "GitHub integrations: an organisation owner's fine-grained token with the organisation permissions Administration: Read-only and Webhooks: Read-only.",
    },
    'entra-integrations': {
        envField: 'clientSecretEnv',
        envName: 'ENTRA_INTEGRATIONS_CLIENT_SECRET',
        file: false,
        what: 'Entra integrations: client secret of the application holding Application.Read.All and Directory.Read.All (and AuditLog.Read.All for sign-in activity). It may be the entra-sp application.',
    },
};

/** `MCP_<LABEL>_TOKEN`: the label upper-cased, `-` to `_`. */
export function mcpTokenEnvName(label: string): string {
    return `MCP_${label.toUpperCase().replace(/-/g, '_')}_TOKEN`.slice(0, 64);
}

export interface CredentialName {
    readonly name: string;
    /** Whether the template uses the `_FILE` form: the credential has line breaks an env file cannot carry. */
    readonly file: boolean;
    readonly for: string;
}

export interface InitPlan {
    readonly config: ScannerConfig;
    /** `config.json`: two-space JSON and a trailing newline. */
    readonly configText: string;
    /** `scanent.env` with no signing key path. `renderEnvTemplate` adds one. */
    readonly envTemplate: string;
    readonly credentialNames: readonly CredentialName[];
    readonly access: readonly AccessTable[];
    readonly nextSteps: readonly string[];
}

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

function sourceConfigOf(answer: SourceAnswer): Record<string, unknown> {
    const { kind, ...rest } = answer as { kind: SourceAnswer['kind'] } & Record<string, unknown>;
    if (kind === 'code') return { kind, product: 'langchain', ...rest };
    if (kind === 'mcp') {
        const servers = Array.isArray(rest.servers)
            ? rest.servers.map((raw: unknown) => {
                if (!isRecord(raw)) return raw;
                const { readToken, ...server } = raw;
                // `readToken: true` asks for the default variable name; a given `readTokenEnv` stands.
                if (readToken === true && server.readTokenEnv === undefined && typeof server.label === 'string') {
                    return { ...server, readTokenEnv: mcpTokenEnvName(server.label) };
                }
                return server;
            })
            : rest.servers;
        return { kind, ...rest, servers };
    }
    const d = SOURCE_DEFAULTS[kind];
    return { kind, ...(d.product === undefined ? {} : { product: d.product }), ...rest, [d.envField]: rest[d.envField] ?? d.envName };
}

/** What each credential variable of a configuration is for, in `credentialEnvNames` order. */
function credentialNamesOf(config: ScannerConfig): CredentialName[] {
    const out: CredentialName[] = [];
    const add = (name: string, file: boolean, what: string) => {
        const at = out.findIndex((c) => c.name === name);
        if (at < 0) out.push({ name, file, for: what });
        // One variable two sources share (the two Entra sources, one application): it says what both need.
        else if (!out[at].for.includes(what)) out[at] = { ...out[at], for: `${out[at].for} ${what}` };
    };
    add(config.scanner.signingKeyEnv, true, 'The Ed25519 signing key (PKCS#8 PEM). A file, because a PEM has line breaks.');
    if (config.inflect?.apiKeyEnv !== undefined) add(config.inflect.apiKeyEnv, false, 'Inflect: API key with admin:harness_ingest (and mcp:read when the register is read).');
    if (config.inflect?.integrationsApiKeyEnv !== undefined) {
        add(config.inflect.integrationsApiKeyEnv, false, 'Inflect: a second API key, with admin:integrations_ingest and no other scope. It posts the integrations report.');
    }
    for (const s of config.sources) {
        if (s.kind === 'code' || s.kind === 'inflect-register') continue;
        if (s.kind === 'mcp') {
            for (const server of s.servers) {
                if (server.readTokenEnv !== undefined) add(server.readTokenEnv, false, `MCP server ${server.label}: a token that can list tools and nothing else.`);
            }
            continue;
        }
        const d = SOURCE_DEFAULTS[s.kind];
        const name = (s as unknown as Record<string, string>)[d.envField];
        add(name, d.file, d.what);
    }
    // Held to the configuration's own list, so the template cannot name less or more than `scan` reads.
    const names = credentialEnvNames(config);
    return out.filter((c) => names.includes(c.name));
}

/**
 * `scanent.env`: one line per credential, a NAME and nothing after the `=`,
 * except a path for a secret kept in a file. `signingKeyFile` is the signing
 * key's path when `init` created or found one; a path is not a secret.
 */
export function renderEnvTemplate(credentialNames: readonly CredentialName[], signingKeyFile: string | null = null): string {
    const lines = [
        '# scanent credentials. Fill in each value, or use a secret store.',
        '# This file is read by `docker run --env-file` and by Compose. Keep it 0600.',
        '# There, a value is taken as written: no quotes. For any variable NAME, NAME_FILE=/path reads the value from a file instead.',
        '# Do not load this file with the shell (`. scanent.env`) as it stands: the shell rewrites $, #, ; and spaces in a',
        '# value. From a checkout, keep each value in a file and use the NAME_FILE form, which reads the same everywhere.',
    ];
    credentialNames.forEach((c, i) => {
        lines.push('', `# ${c.for}`);
        lines.push(c.file ? `${c.name}_FILE=${i === 0 && signingKeyFile !== null ? signingKeyFile : ''}` : `${c.name}=`);
    });
    return `${lines.join('\n')}\n`;
}

/** The configuration, the env template, the access tables and the next steps for one set of answers. Throws `InitError`. */
export function planInit(answers: InitAnswers): InitPlan {
    const outputDir = answers.outputDir ?? DEFAULT_OUTPUT_DIR;
    const inflect = answers.inflect ?? null;
    const sources = answers.sources.map(sourceConfigOf);
    const agentSourceAnswered = answers.sources.some((a) => isAgentSourceKind(a.kind));
    if (inflect?.readRegister === true) sources.push({ kind: 'inflect-register' });

    const draft: Record<string, unknown> = {
        estate: answers.estate,
        scanner: {
            agentId: inflect === null ? `scanent-${answers.estate}`.slice(0, 64) : inflect.agentId,
            signingKeyEnv: answers.signingKeyEnv ?? DEFAULT_SIGNING_KEY_ENV,
        },
        ...(inflect === null
            ? {}
            : {
                  inflect: {
                      baseUrl: inflect.baseUrl,
                      tenantSlug: inflect.tenantSlug,
                      // The agent report's key, when there is an agent report to post or a register to read.
                      ...(agentSourceAnswered || inflect.readRegister === true ? { apiKeyEnv: inflect.apiKeyEnv ?? DEFAULT_INGEST_KEY_ENV } : {}),
                      // The integrations report's key only when it was asked for: posting that report is a choice.
                      ...(inflect.integrationsApiKeyEnv === undefined ? {} : { integrationsApiKeyEnv: inflect.integrationsApiKeyEnv }),
                  },
              }),
        outputs: [
            { kind: 'file', dir: outputDir, ...(answers.retainRuns === undefined ? {} : { retainRuns: answers.retainRuns }) },
            ...(inflect === null ? [] : [{ kind: 'inflect' }]),
        ],
        schedule: { everyHours: answers.everyHours ?? DEFAULT_EVERY_HOURS },
        ...(answers.inventoryPath === undefined ? {} : { inventory: { path: answers.inventoryPath } }),
        sources,
    };

    let config: ScannerConfig;
    try {
        config = parseScannerConfig(draft);
    } catch (err) {
        if (!(err instanceof ConfigError)) throw err;
        throw new InitError(err.issues);
    }
    const credentialNames = credentialNamesOf(config);
    return {
        config,
        // The draft, not the parsed value: the file states what was answered and leaves the schema's defaults to the schema.
        configText: `${JSON.stringify(draft, null, 2)}\n`,
        envTemplate: renderEnvTemplate(credentialNames),
        credentialNames,
        access: accessTablesFor(config),
        nextSteps: [
            'Create the access above and put each credential in scanent.env (or your secret store).',
            'scanent doctor --config <dir>/config.json',
            // No --out: the configuration just written already has a file output for that directory.
            'scanent scan --config <dir>/config.json',
        ],
    };
}
