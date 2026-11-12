/**
 * THE ACCESS EACH SOURCE NEEDS — one table per source, in one place.
 *
 * The wizard prints these for the sources an operator chose, `doctor` quotes
 * the grant when a read is refused, and `docs/access.md` is rendered from the
 * same object (`renderAccessMarkdown`; a test compares it with the committed
 * file), so the three cannot disagree.
 *
 * Every grant here is READ-ONLY, and each table says what must NOT be
 * granted: the scanner has no use for a write permission and should not be
 * handed one.
 */
import type { ScannerConfig } from '../config';
import { hostNames, hostsFor } from '../hosts';
import type { SourceKind } from '../source';

export interface AccessEntry {
    readonly kind: SourceKind;
    readonly title: string;
    /** The role or scope, exactly as the product names it. */
    readonly grant: string;
    /** The steps to create it. */
    readonly where: readonly string[];
    /** What it lets the scanner read. */
    readonly reads: readonly string[];
    /** What must not be granted. */
    readonly notNeeded: readonly string[];
    /** The variable the credential goes in, by its default name. */
    readonly credential: string;
    /** The hosts it reaches, in words, for the document. A configuration's real hosts come from `hostsFor`. */
    readonly hostsNote: string;
}

/** One source's table for one configuration: the entry, and the hosts that configuration reaches for it. */
export interface AccessTable extends AccessEntry {
    readonly hosts: readonly string[];
}

/** The order the wizard asks about sources in, and the order the tables print in. */
export const GUIDE_ORDER: readonly SourceKind[] = ['entra-sp', 'vault', 'okta-app', 'cicd', 'gcp-sa', 'runtime', 'mcp', 'code', 'inflect-register'];

export const ACCESS_GUIDE: Readonly<Record<SourceKind, AccessEntry>> = Object.freeze({
    'entra-sp': {
        kind: 'entra-sp',
        title: 'Microsoft Entra ID (service principals and app registrations)',
        grant: 'Microsoft Graph application permission Application.Read.All, with admin consent',
        where: [
            'Entra admin centre: App registrations, New registration.',
            'API permissions: Add a permission, Microsoft Graph, Application permissions, Application.Read.All.',
            'Grant admin consent.',
            'Certificates and secrets: New client secret.',
        ],
        reads: ['Application registrations and service principals', 'Their credential metadata (ids and dates) and their owners'],
        notNeeded: ['Any ReadWrite permission', 'Directory.* permissions', 'Any delegated permission', 'Any directory role'],
        credential: 'ENTRA_CLIENT_SECRET',
        hostsNote: 'login.microsoftonline.com, graph.microsoft.com',
    },
    vault: {
        kind: 'vault',
        title: 'Azure Key Vault (credential metadata)',
        grant: 'Key Vault Reader on each listed vault (RBAC vaults). For a vault on access policies: List on secrets and List on certificates, and nothing else',
        where: ["Each vault: Access control (IAM), Add role assignment, Key Vault Reader, to the application's service principal."],
        reads: ['Names, tags and dates of secrets and certificates'],
        notNeeded: ['Key Vault Secrets User', 'Key Vault Administrator', 'Get on secrets: each of these reads or changes secret values'],
        credential: 'AZURE_CLIENT_SECRET',
        hostsNote: "login.microsoftonline.com, and each vault's host",
    },
    'okta-app': {
        kind: 'okta-app',
        title: 'Okta (service apps and API tokens)',
        grant: 'An SSWS API token created by a user holding the Read-only Administrator role only',
        where: [
            'Okta admin console: Security, Administrators: assign Read-only Administrator to a dedicated user.',
            'Signed in as that user: Security, API, Tokens, Create token.',
        ],
        reads: ['Service apps', 'API token metadata', "The token's own id"],
        notNeeded: ['Super Administrator', 'Org Administrator', 'App Administrator', 'API Access Management Administrator'],
        credential: 'OKTA_API_TOKEN',
        hostsNote: "the Okta org's host",
    },
    cicd: {
        kind: 'cicd',
        title: 'GitHub Actions (workflows and secret names)',
        grant: 'A fine-grained personal access token (or a GitHub App installation) limited to the listed repositories, with Contents: Read-only and Secrets: Read-only. Metadata: Read-only is added by GitHub',
        where: [
            'GitHub: Settings, Developer settings, Personal access tokens, Fine-grained tokens, Generate new token.',
            'Repository access: Only select repositories.',
            'Repository permissions: Contents: Read-only, Secrets: Read-only.',
        ],
        reads: ['Workflow files on the default branch', 'The names of Actions secrets, never a value'],
        notNeeded: ['Any Read and write permission', 'Actions', 'Administration', 'Workflows', 'A classic token with the repo scope'],
        credential: 'GITHUB_READ_TOKEN',
        hostsNote: 'api.github.com',
    },
    'gcp-sa': {
        kind: 'gcp-sa',
        title: 'Google Cloud (service accounts and their keys)',
        grant: 'roles/iam.serviceAccountViewer on each listed project, held by a dedicated service account; one JSON key for that account',
        where: [
            'Google Cloud console: IAM and admin, Service accounts, Create service account.',
            'IAM: Grant access on each project, role Service Account Viewer.',
            'The service account: Keys, Add key, JSON.',
        ],
        reads: ['Service accounts', 'The metadata of their user-managed keys'],
        notNeeded: [
            'roles/iam.serviceAccountAdmin',
            'roles/iam.serviceAccountKeyAdmin',
            'roles/iam.serviceAccountUser',
            'roles/iam.serviceAccountTokenCreator',
            'Editor',
            'Owner',
        ],
        credential: 'GCP_SCANNER_KEY_FILE',
        hostsNote: 'oauth2.googleapis.com, iam.googleapis.com',
    },
    runtime: {
        kind: 'runtime',
        title: 'LangSmith (tracing projects and deployments)',
        grant: 'A service key holding the workspace Viewer role',
        where: ['LangSmith: Settings, API keys, Create API key, Service key, role Viewer.'],
        reads: ['Tracing projects and their aggregate tool statistics', 'Deployments, only when readDeployments is set'],
        notNeeded: ['The Editor or Admin role', 'A personal access token of an administrator'],
        credential: 'LANGSMITH_API_KEY',
        hostsNote: 'api.smith.langchain.com or eu.api.smith.langchain.com, or the self-hosted host',
    },
    mcp: {
        kind: 'mcp',
        title: 'MCP servers (tool listings)',
        grant: 'Per server, a token that can list tools and nothing else; none when the server takes none',
        where: ["The server's own administration."],
        reads: ['Tool names and annotations', 'Tool definitions, kept as hashes'],
        notNeeded: ['Any scope that lets the token call a tool'],
        credential: 'MCP_<LABEL>_TOKEN',
        hostsNote: "each server's host",
    },
    code: {
        kind: 'code',
        title: 'Agent code (local directories)',
        grant: 'Read access to the listed directories for the user the scanner runs as',
        where: ['The file system, or the read-only mount the directories are given to the container as.'],
        reads: ['Python, JavaScript and TypeScript files under the roots. Nothing is run.'],
        notNeeded: ['Write access: mount the roots read-only'],
        credential: '(none)',
        hostsNote: 'none',
    },
    'inflect-register': {
        kind: 'inflect-register',
        title: 'An Inflect tenant (posting results, and reading its agent register)',
        grant: 'An API key bound to the scanner agent with the admin:harness_ingest scope, plus mcp:read when the register is read',
        where: ["The Inflect tenant's API keys page."],
        reads: ["The tenant's agent register, through one tool, when the register is read"],
        notNeeded: ['Any other scope'],
        credential: 'INFLECT_INGEST_KEY',
        hostsNote: "the tenant's host",
    },
});

/** The access tables for the sources one configuration has, in guide order, each with the hosts that configuration reaches. */
export function accessTablesFor(config: ScannerConfig): AccessTable[] {
    const entries = hostsFor(config);
    const kinds = new Set<SourceKind>(config.sources.map((s) => s.kind));
    // The ingest output uses the same key as the register read.
    if (config.inflect !== undefined) kinds.add('inflect-register');
    return GUIDE_ORDER.filter((k) => kinds.has(k)).map((kind) => ({
        ...ACCESS_GUIDE[kind],
        hosts: hostNames(entries.filter((e) => e.source === kind || (kind === 'inflect-register' && e.source === 'inflect'))),
    }));
}

/** One table as plain text, for the terminal. */
export function renderAccessText(table: AccessTable): string {
    const list = (items: readonly string[]) => items.map((i) => `      - ${i}\n`).join('');
    return (
        `${table.title}  [${table.kind}]\n` +
        `    Grant:       ${table.grant}\n` +
        `    Create it:\n${list(table.where)}` +
        `    It reads:\n${list(table.reads)}` +
        `    Do not grant:\n${list(table.notNeeded)}` +
        `    Credential:  ${table.credential}\n` +
        `    Hosts:       ${table.hosts.length === 0 ? 'none' : table.hosts.map((h) => `${h}:443`).join(', ')}\n`
    );
}

const cell = (text: string) => text.replace(/\|/g, '\\|');

/** `docs/access.md`, whole. Rendered from `ACCESS_GUIDE`; never edited by hand. */
export function renderAccessMarkdown(): string {
    const lines: string[] = [
        '# Access the scanner needs',
        '',
        '<!-- Generated by `npm run docs:access` from packages/scanner/src/init/access-guide.ts. Do not edit by hand. -->',
        '',
        'scanent reads and never writes. Each source needs one read-only grant, listed here with where to',
        'create it, what it lets the scanner read, and what must not be granted. `scanent init` prints the',
        'tables for the sources you choose, and `scanent doctor` checks them.',
        '',
        'No credential value goes in the configuration. Each goes in the environment variable named below,',
        'or in a file named by that variable with `_FILE` appended.',
        '',
        '| Source | Grant | Credential | Hosts (port 443) |',
        '|---|---|---|---|',
        ...GUIDE_ORDER.map((k) => {
            const e = ACCESS_GUIDE[k];
            return `| \`${e.kind}\` | ${cell(e.grant)} | \`${e.credential}\` | ${cell(e.hostsNote)} |`;
        }),
        '',
    ];
    for (const k of GUIDE_ORDER) {
        const e = ACCESS_GUIDE[k];
        lines.push(`## ${e.title}`, '', `Source kind: \`${e.kind}\`. Credential: \`${e.credential}\`. Hosts: ${e.hostsNote}.`, '', `**Grant.** ${e.grant}.`, '');
        lines.push('**Where it is created.**', '', ...e.where.map((w, i) => `${i + 1}. ${w}`), '');
        lines.push('**Lets the scanner read.**', '', ...e.reads.map((r) => `- ${r}`), '');
        lines.push('**Not needed, and must not be granted.**', '', ...e.notNeeded.map((n) => `- ${n}`), '');
    }
    return `${lines.join('\n')}`;
}
