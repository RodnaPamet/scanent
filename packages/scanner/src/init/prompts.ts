/**
 * THE WIZARD'S PROMPTS — the same answers object a file would supply, asked
 * for a line at a time.
 *
 * Two rules hold every question:
 *
 *   • NO QUESTION ASKS FOR A SECRET, and none is worded so it could be read as
 *     asking for one. Where a source has a credential, the prompt says which
 *     variable it goes in and moves on.
 *   • EVERY ANSWER IS CHECKED FOR A SECRET'S SHAPE before anything else looks
 *     at it: the contract's shapes and the credentials this scanner is given
 *     (`secret-shapes.ts`), and for a name, a long bare token. A hit is refused, is not stored, written or repeated back, and
 *     the question is asked again; three refusals of one question end the
 *     wizard. The terminal has already echoed what was typed, which scanent
 *     cannot undo: that is why the refusal says to rotate it.
 *
 * An answer that fails its field's rule repeats the question with the rule,
 * never the value. The rules are the configuration schema's own.
 */
import { ScannerConfigSchema, SourceConfigSchema } from '../config';
import { ANSWERABLE_KINDS, INIT_ANSWERS_SCHEMA, type AnswerableKind, type InitAnswers, type SourceAnswer } from './answers';
import { ACCESS_GUIDE, credentialVariable } from './access-guide';
import { DEFAULT_ENTRA_SECRET_ENV, DEFAULT_EVERY_HOURS, DEFAULT_INGEST_KEY_ENV, DEFAULT_OUTPUT_DIR, mcpTokenEnvName } from './plan';
import { looksLikeBareToken, looksLikeCredential } from './secret-shapes';

export interface PromptIo {
    /** One line of input, without its line break. */
    ask(question: string): Promise<string>;
    say(text: string): void;
}

/** The wizard stopped without answers: three refusals, no source chosen, or input ended. Exit code 2. */
export class InitAborted extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'InitAborted';
    }
}

export const SECRET_REFUSAL =
    'That looks like a credential. It was not stored. scanent never asks for a secret value; if it was real, rotate it.';
export const MAX_REFUSALS = 3;

const KIND_QUESTION: Readonly<Record<AnswerableKind, string>> = {
    'entra-sp': 'Do you have Microsoft Entra ID (service principals and app registrations)?',
    vault: 'Do you have Azure Key Vault?',
    'okta-app': 'Do you have Okta?',
    cicd: 'Do you have GitHub Actions?',
    'gcp-sa': 'Do you have Google Cloud service accounts?',
    runtime: 'Do you have LangSmith?',
    mcp: 'Do you have MCP servers to list?',
    code: 'Do you have agent code in local directories to read?',
    'entra-integrations': 'Also scan what this directory has granted to applications, and who owns them (the integrations scanner)?',
};

/** The placeholder each kind's product and credential name take while one field is being checked. */
const SHELL: Readonly<Record<AnswerableKind, Record<string, unknown>>> = {
    'entra-sp': { clientSecretEnv: 'X' },
    vault: { product: 'azure-key-vault', clientSecretEnv: 'X' },
    'okta-app': { apiTokenEnv: 'X' },
    cicd: { product: 'github-actions', tokenEnv: 'X' },
    'gcp-sa': { product: 'gcp-iam', keyEnv: 'X' },
    runtime: { product: 'langsmith', apiKeyEnv: 'X' },
    mcp: {},
    code: { product: 'langchain' },
    'entra-integrations': { clientSecretEnv: 'X' },
};

/** Whether `candidate`, a source of `kind` so far, breaks a rule at `field` (the first path segment). Uses the configuration's schema. */
function breaksRule(kind: AnswerableKind, candidate: Record<string, unknown>, field: string): boolean {
    const parsed = SourceConfigSchema.safeParse({ kind, ...SHELL[kind], ...candidate });
    return !parsed.success && parsed.error.issues.some((i) => i.path[0] === field && i.code !== 'invalid_type');
}

const list = (text: string): string[] => text.split(',').map((s) => s.trim()).filter((s) => s !== '');

export async function collectAnswers(io: PromptIo): Promise<InitAnswers> {
    /**
     * One answer: trimmed, never credential-shaped, and passing `rule` (which returns the rule's words, or null).
     * `isName` marks a field that holds a name somebody chose, where a long bare token is refused too.
     */
    async function ask(question: string, rule: (value: string) => string | null = () => null, isName = false): Promise<string> {
        let refusals = 0;
        for (;;) {
            const value = (await io.ask(`${question} `)).trim();
            let problem: string | null;
            if (looksLikeCredential(value) || (isName && looksLikeBareToken(value))) problem = SECRET_REFUSAL;
            else problem = rule(value);
            if (problem === null) return value;
            refusals += 1;
            io.say(problem);
            if (refusals >= MAX_REFUSALS) throw new InitAborted('the question was refused three times; nothing was written');
        }
    }
    const yes = async (question: string): Promise<boolean> =>
        /^y(es)?$/i.test(await ask(`${question} [y/N]`, (v) => (/^(y|yes|n|no|)$/i.test(v) ? null : 'Answer y or n.')));
    /** A field of a source, held to that field's rule in the configuration schema. `shape` turns the line into the field's value. */
    const field = (kind: AnswerableKind, sofar: Record<string, unknown>, name: string, question: string, rule: string, shape: (v: string) => unknown = (v) => v) =>
        ask(question, (v) => (v === '' || breaksRule(kind, { ...sofar, [name]: shape(v) }, name) ? rule : null));

    io.say('scanent init: a configuration for one estate. No question asks for a secret; credentials go in environment variables, named as you go.');
    const estate = await ask('Estate name (lower-case letters, digits and hyphens, e.g. acme-prod):', (v) =>
        ScannerConfigSchema.shape.estate.safeParse(v).success ? null : 'Lower-case letters, digits and hyphens, starting with a letter or digit, at most 63 characters.',
        true,
    );

    const sources: SourceAnswer[] = [];
    let integrations: SourceAnswer | null = null;
    for (const kind of ANSWERABLE_KINDS) {
        // The integrations scanner's Entra source is offered with the agent scanner's, below: one directory, two scanners.
        if (kind === 'entra-integrations') continue;
        if (!(await yes(KIND_QUESTION[kind]))) continue;
        const s: Record<string, unknown> = {};
        const guid = 'A GUID: 8-4-4-4-12 hexadecimal digits.';
        if (kind === 'entra-sp') {
            s.directoryId = await field(kind, s, 'directoryId', 'Directory (tenant) ID:', guid);
            s.clientId = await field(kind, s, 'clientId', 'Application (client) ID of the app registration the scanner reads with:', guid);
            if (await yes(KIND_QUESTION['entra-integrations'])) {
                const same = await yes('Read them with the same app registration? It then also needs Directory.Read.All');
                const i: Record<string, unknown> = { directoryId: s.directoryId };
                // The same application holds the same secret: the two sources then name one variable.
                if (same) Object.assign(i, { clientId: s.clientId, clientSecretEnv: DEFAULT_ENTRA_SECRET_ENV });
                else i.clientId = await field('entra-integrations', i, 'clientId', 'Application (client) ID of the app registration the integrations scanner reads with:', guid);
                if (await yes("Also read each application's last sign-in? It needs AuditLog.Read.All and a licence that records sign-ins")) i.readSignInActivity = true;
                integrations = { kind: 'entra-integrations', ...i };
            }
        } else if (kind === 'vault') {
            s.vaultUrls = list(await field(kind, s, 'vaultUrls', 'Vault URLs, comma-separated (https://<name>.vault.azure.net):', 'One to twenty https URLs on vault.azure.net.', list));
            s.directoryTenantId = await field(kind, s, 'directoryTenantId', 'Directory (tenant) ID or verified domain:', 'A directory id or domain.');
            s.clientId = await field(kind, s, 'clientId', 'Application (client) ID of the app registration the scanner reads with:', guid);
        } else if (kind === 'okta-app') {
            s.orgUrl = await field(kind, s, 'orgUrl', 'Okta org URL (https://<org>.okta.com):', 'An https origin on okta.com or oktapreview.com.');
        } else if (kind === 'cicd') {
            s.repositories = list(await field(kind, s, 'repositories', 'Repositories, comma-separated (owner/repo):', 'One to fifty owner/repo names, each once.', list));
        } else if (kind === 'gcp-sa') {
            s.projects = list(await field(kind, s, 'projects', 'Google Cloud project ids, comma-separated:', 'One to fifty project ids, each once.', list));
        } else if (kind === 'runtime') {
            const endpointOf = (v: string) => (v === 'us' || v === 'eu' ? { cloud: v } : { selfHosted: v });
            s.endpoint = endpointOf(
                await field(kind, s, 'endpoint', 'LangSmith region (us or eu), or the https origin of a self-hosted LangSmith:', 'us, eu, or an https origin the scanner may reach.', endpointOf),
            );
            const workspace = await ask('Workspace ID (blank for a key scoped to one workspace):', (v) => (v === '' || !breaksRule(kind, { ...s, workspaceId: v }, 'workspaceId') ? null : guid));
            if (workspace !== '') s.workspaceId = workspace;
        } else if (kind === 'mcp') {
            const servers: Record<string, unknown>[] = [];
            for (;;) {
                const label = await ask(`MCP server ${servers.length + 1}: a short label${servers.length === 0 ? '' : ' (blank to finish)'}:`, (v) =>
                    (v === '' && servers.length > 0) || (v !== '' && !servers.some((x) => x.label === v) && ScannerConfigSchema.shape.estate.safeParse(v).success)
                        ? null
                        : 'Lower-case letters, digits and hyphens, each label once.',
                    true,
                );
                if (label === '') break;
                const url = await ask('Its endpoint URL (https):', (v) =>
                    v !== '' && !servers.some((x) => x.url === v) && !breaksRule(kind, { servers: [{ label, url: v }] }, 'servers') ? null : 'An https URL the scanner may reach, with no credentials, query or fragment, each URL once.',
                );
                const server: Record<string, unknown> = { label, url };
                if (await yes('Does it need a token to list its tools?')) {
                    server.readToken = true;
                    io.say(`The token is not asked for here: it goes in ${mcpTokenEnvName(label)}.`);
                }
                servers.push(server);
            }
            s.servers = servers;
        } else {
            const roots: Record<string, unknown>[] = [];
            for (;;) {
                const label = await ask(`Code root ${roots.length + 1}: a short label${roots.length === 0 ? '' : ' (blank to finish)'}:`, (v) =>
                    (v === '' && roots.length > 0) || (v !== '' && !roots.some((x) => x.label === v) && ScannerConfigSchema.shape.estate.safeParse(v).success)
                        ? null
                        : 'Lower-case letters, digits and hyphens, each label once.',
                    true,
                );
                if (label === '') break;
                const path = await ask('Its directory, as an absolute path where the scanner runs:', (v) =>
                    v !== '' && !breaksRule(kind, { roots: [{ label, path: v }] }, 'roots') ? null : 'An absolute path with no .. segment.',
                );
                roots.push({ label, path });
            }
            s.roots = roots;
        }
        if (kind !== 'mcp' && kind !== 'code') {
            io.say(`The credential is not asked for here: it goes in ${credentialVariable(ACCESS_GUIDE[kind])}.`);
        }
        sources.push({ kind, ...s });
    }
    // No agent source: the integrations scanner can still run on its own, so it is offered here once more.
    if (sources.length === 0 && (await yes('No agent source was chosen. Scan only what an Entra directory has granted to applications, and who owns them (the integrations scanner)?'))) {
        const guid = 'A GUID: 8-4-4-4-12 hexadecimal digits.';
        const i: Record<string, unknown> = {};
        i.directoryId = await field('entra-integrations', i, 'directoryId', 'Directory (tenant) ID:', guid);
        i.clientId = await field('entra-integrations', i, 'clientId', 'Application (client) ID of the app registration the integrations scanner reads with:', guid);
        if (await yes("Also read each application's last sign-in? It needs AuditLog.Read.All and a licence that records sign-ins")) i.readSignInActivity = true;
        integrations = { kind: 'entra-integrations', ...i };
    }
    if (sources.length === 0 && integrations === null) throw new InitAborted('no source was chosen; nothing was written');
    const agentSourceChosen = sources.length > 0;
    if (integrations !== null) {
        if (integrations.clientSecretEnv === undefined) io.say(`The credential is not asked for here: it goes in ${credentialVariable(ACCESS_GUIDE['entra-integrations'])}.`);
        sources.push(integrations);
    }

    const absolute = (v: string) => (v === '' || (v.startsWith('/') && !v.split('/').includes('..')) ? null : 'An absolute path with no .. segment.');
    const outputDir = (await ask(`Directory the results are written under [${DEFAULT_OUTPUT_DIR}]:`, absolute)) || DEFAULT_OUTPUT_DIR;
    const everyText = await ask(`Scan every how many hours, when run on a schedule? [${DEFAULT_EVERY_HOURS}]`, (v) =>
        v === '' || (/^\d{1,3}$/.test(v) && Number(v) >= 1 && Number(v) <= 720) ? null : 'A whole number from 1 to 720.',
    );
    const inventoryPath = await ask('Inventory file of the agents you already know (absolute path to a .json or .csv; blank for none):', (v) =>
        v === '' || (absolute(v) === null && /\.(json|csv)$/i.test(v)) ? null : 'An absolute path to a .json or a .csv file.',
    );

    let inflect: InitAnswers['inflect'] = null;
    // The tenant takes the agent report only: with no agent source there is nothing to post, so the question is not asked.
    if (agentSourceChosen && (await yes('Post results to an Inflect tenant?'))) {
        const shape = ScannerConfigSchema.shape;
        const inflectShape = shape.inflect.unwrap().shape;
        // Said BEFORE the tenant's questions: the next three ask about the tenant, and none of them is the key.
        io.say(`The API key is not asked for here: it goes in ${DEFAULT_INGEST_KEY_ENV}.`);
        const baseUrl = await ask('Tenant base URL (https origin):', (v) => (inflectShape.baseUrl.safeParse(v).success ? null : 'An https origin, with no path.'));
        const tenantSlug = await ask('Tenant slug:', (v) => (inflectShape.tenantSlug.safeParse(v).success ? null : 'Lower-case letters, digits and hyphens.'), true);
        const agentId = await ask(
            "The scanner's agent id in the tenant's register (a name, not a key):",
            (v) => (shape.scanner.shape.agentId.safeParse(v).success ? null : 'Letters, digits, hyphens and underscores, at most 64 characters.'),
            true,
        );
        const readRegister = await yes("Also read the tenant's agent register?");
        inflect = { baseUrl, tenantSlug, agentId, readRegister };
    }

    return {
        answers: INIT_ANSWERS_SCHEMA,
        estate,
        everyHours: everyText === '' ? DEFAULT_EVERY_HOURS : Number(everyText),
        outputDir,
        ...(inventoryPath === '' ? {} : { inventoryPath }),
        sources,
        inflect,
    };
}
