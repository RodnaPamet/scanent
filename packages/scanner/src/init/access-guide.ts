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
import { SCANNER_OF_SOURCE, SCANNER_TITLE, SCANNERS, type ScannerSourceKind } from '../scanners';
import { ENTRA_INTEGRATIONS_REQUIRED_ROLES, ENTRA_SIGN_IN_ROLE } from '../sources/entra-integrations';

export interface AccessEntry {
    readonly kind: ScannerSourceKind;
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
    /** The credential is a file with line breaks: it is given as `<credential>_FILE=/path`, never as a value. */
    readonly asFile?: true;
    /** What this grant does NOT let the scanner see, where the product's own rules make the read narrower than its name. */
    readonly limits?: readonly string[];
    /** The hosts it reaches, in words, for the document. A configuration's real hosts come from `hostsFor`. */
    readonly hostsNote: string;
}

/** One source's table for one configuration: the entry, and the hosts that configuration reaches for it. */
export interface AccessTable extends AccessEntry {
    readonly hosts: readonly string[];
}

/** The order the wizard asks about sources in, and the order the tables print in. */
export const GUIDE_ORDER: readonly ScannerSourceKind[] = [
    'entra-sp',
    'vault',
    'okta-app',
    'cicd',
    'gcp-sa',
    'runtime',
    'mcp',
    'code',
    'inflect-register',
    'entra-integrations',
    'okta-integrations',
    'github-integrations',
];

export const ACCESS_GUIDE: Readonly<Record<ScannerSourceKind, AccessEntry>> = Object.freeze({
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
        notNeeded: [
            'Any ReadWrite permission',
            'Directory.* permissions, unless the same application also reads for `entra-integrations`, which needs Directory.Read.All',
            'Any delegated permission',
            'Any directory role',
        ],
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
        reads: ['Service apps', 'API token metadata, as far as the role shows it (see the limit)', "The token's own id"],
        limits: [
            "Okta's role table lets a Read-only Administrator view API tokens of its own user only. With this grant the scan sees every service app, and of API tokens only those of the token's own user: other users' API tokens are not seen, and the report does not say they are absent.",
            'Seeing every API token takes Super Administrator or Org Administrator. Both can write, so this guide does not ask for them; list API tokens in Security, API, Tokens by hand instead.',
            "This is from Okta's documentation and has not been confirmed against a live org.",
        ],
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
        credential: 'GCP_SCANNER_KEY',
        asFile: true,
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
    'entra-integrations': {
        kind: 'entra-integrations',
        title: 'Microsoft Entra ID (applications and what they were granted)',
        grant: `Microsoft Graph application permissions ${ENTRA_INTEGRATIONS_REQUIRED_ROLES.join(' and ')}, with admin consent; ${ENTRA_SIGN_IN_ROLE} as well only when readSignInActivity is set`,
        where: [
            'Entra admin centre: App registrations, New registration (or the application the entra-sp source already uses).',
            `API permissions: Add a permission, Microsoft Graph, Application permissions, ${ENTRA_INTEGRATIONS_REQUIRED_ROLES.join(', ')}.`,
            `For the last sign-in of each application, also ${ENTRA_SIGN_IN_ROLE}.`,
            'Grant admin consent.',
            'Certificates and secrets: New client secret.',
        ],
        reads: [
            'Service principals of applications, with their verified publisher, owners and credential metadata',
            "The owners of this directory's own app registrations",
            'Delegated grants: their scopes, consent type and how many people each was made for, never who',
            'Application permissions: the app roles assigned to each application',
            'Each application\'s last sign-in, to the day, only when readSignInActivity is set',
        ],
        limits: [
            'Sign-in activity is a beta report of Microsoft Graph and needs a licence that records it (Microsoft Entra ID P1 or P2). Without it, or without AuditLog.Read.All, the read is refused and no application is concluded unused.',
            "Graph returns at most 20 owners of an application. An application's owners in the directory that registered it are not visible from another directory.",
        ],
        notNeeded: ['Any ReadWrite permission', 'Any delegated permission', 'Any directory role', 'AuditLog.Read.All, unless readSignInActivity is set'],
        credential: 'ENTRA_INTEGRATIONS_CLIENT_SECRET',
        hostsNote: 'login.microsoftonline.com, graph.microsoft.com',
    },
    'okta-integrations': {
        kind: 'okta-integrations',
        title: 'Okta (applications and the Okta API scopes granted to them)',
        grant: 'An SSWS API token created by a user holding the Read-only Administrator role only. It may be the token the okta-app source uses',
        where: [
            'Okta admin console: Security, Administrators: assign Read-only Administrator to a dedicated user.',
            'Signed in as that user: Security, API, Tokens, Create token.',
        ],
        reads: [
            "Every application of the org except Okta's own (the Admin Console, the End-User Dashboard, the Browser Plugin): its id, label, status and sign-on mode (GET /api/v1/apps)",
            'The Okta API scopes consented to each application, never who consented (GET /api/v1/apps/{appId}/grants)',
        ],
        limits: [
            "Okta's application object records no owner, no publisher verification and no time of last use, so the three findings that need them are not concluded for Okta, and the results say so. Last use is only in the System Log, which this source does not read.",
            'It reads consent grants of Okta API scopes. Scopes of a custom authorization server, and the people and groups assigned to an application, are not read.',
        ],
        notNeeded: ['Super Administrator', 'Org Administrator', 'App Administrator', 'API Access Management Administrator'],
        credential: 'OKTA_API_TOKEN',
        hostsNote: "the Okta org's host",
    },
    'github-integrations': {
        kind: 'github-integrations',
        title: 'GitHub (an organisation\'s app installations and webhooks)',
        grant: "A fine-grained personal access token whose resource owner is the organisation, with the organisation permissions Administration: Read-only and Webhooks: Read-only, created by an organisation owner",
        where: [
            'Signed in as an owner of the organisation: Settings, Developer settings, Personal access tokens, Fine-grained tokens, Generate new token.',
            'Resource owner: the organisation. Repository access: Public repositories (read-only); no repository is needed.',
            'Organization permissions: Administration: Read-only, Webhooks: Read-only.',
            'If the organisation requires approval of fine-grained tokens, approve it in the organisation\'s settings.',
        ],
        reads: [
            "The organisation's GitHub App installations: each app's slug and id, its permissions, its repository selection, its events and whether it is suspended (GET /orgs/{org}/installations)",
            "The organisation's webhooks: each one's target HOST, events, active state and creation date; never its URL or secret (GET /orgs/{org}/hooks)",
        ],
        limits: [
            'GitHub answers both endpoints only for a token of an organisation owner.',
            "The installation response names no owner of an installation, no publisher verification and no last use, so the three findings that need them are not concluded for GitHub, and the results say so.",
            'OAuth apps authorised by members, and repository webhooks, are not read.',
        ],
        notNeeded: [
            'Any Read and write permission',
            'Any repository permission',
            'Members, or any organisation permission other than the two above',
            'A classic token: listing webhooks takes admin:org_hook, which can also change them',
        ],
        credential: 'GITHUB_INTEGRATIONS_TOKEN',
        hostsNote: 'api.github.com',
    },
});

/** The variable an operator sets for an entry's credential: its name, or the `_FILE` form for a credential that is a file. */
export function credentialVariable(entry: AccessEntry): string {
    return entry.asFile === true ? `${entry.credential}_FILE` : entry.credential;
}

const FILE_NOTE = (entry: AccessEntry): string => `a key file: set ${entry.credential}_FILE to its path`;

/** The access tables for the sources one configuration has, in guide order, each with the hosts that configuration reaches. */
export function accessTablesFor(config: ScannerConfig): AccessTable[] {
    const entries = hostsFor(config);
    const kinds = new Set<ScannerSourceKind>(config.sources.map((s) => s.kind));
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
        (table.limits === undefined ? '' : `    Limits:\n${list(table.limits)}`) +
        `    Credential:  ${table.credential}${table.asFile === true ? ` (${FILE_NOTE(table)})` : ''}\n` +
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
        'or in a file named by that variable with `_FILE` appended (`NAME_FILE=/path`). A credential that is',
        'itself a file with line breaks is given only in the `_FILE` form.',
        '',
        'The sources are grouped by the scanner that reads them. One configuration may hold sources of',
        'both; a product read by both (Microsoft Entra ID) is two sources, which may use one application.',
        '',
        '| Scanner | Source | Grant | Credential | Hosts (port 443) |',
        '|---|---|---|---|---|',
        ...GUIDE_ORDER.map((k) => {
            const e = ACCESS_GUIDE[k];
            return `| ${SCANNER_OF_SOURCE[k]} | \`${e.kind}\` | ${cell(e.grant)} | \`${e.credential}\`${e.asFile === true ? ` (${FILE_NOTE(e)})` : ''} | ${cell(e.hostsNote)} |`;
        }),
        '',
    ];
    for (const scanner of SCANNERS) {
        lines.push(`## ${SCANNER_TITLE[scanner]}`, '');
        for (const k of GUIDE_ORDER.filter((kind) => SCANNER_OF_SOURCE[kind] === scanner)) pushEntry(k);
    }
    return `${lines.join('\n')}`;

    function pushEntry(k: ScannerSourceKind): void {
        const e = ACCESS_GUIDE[k];
        lines.push(`### ${e.title}`, '', `Source kind: \`${e.kind}\`. Credential: \`${e.credential}\`${e.asFile === true ? ` (${FILE_NOTE(e)})` : ''}. Hosts: ${e.hostsNote}.`, '', `**Grant.** ${e.grant}.`, '');
        lines.push('**Where it is created.**', '', ...e.where.map((w, i) => `${i + 1}. ${w}`), '');
        lines.push('**Lets the scanner read.**', '', ...e.reads.map((r) => `- ${r}`), '');
        if (e.limits !== undefined) lines.push('**What this grant does not show.**', '', ...e.limits.map((l) => `- ${l}`), '');
        lines.push('**Not needed, and must not be granted.**', '', ...e.notNeeded.map((n) => `- ${n}`), '');
    }
}
