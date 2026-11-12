/**
 * The wizard's planner and its access guide: answers in, a configuration
 * `scan` accepts and an env template of names out.
 */
import { readFileSync } from 'fs';
import { resolve } from 'path';

import { credentialEnvNames, parseScannerConfig } from '../src/config';
import { ACCESS_GUIDE, accessTablesFor, GUIDE_ORDER, renderAccessMarkdown, renderAccessText } from '../src/init/access-guide';
import { InitError, parseInitAnswers, type InitAnswers } from '../src/init/answers';
import { mcpTokenEnvName, planInit, renderEnvTemplate } from '../src/init/plan';

const GUID = '0d1e2c3b-0000-4000-8000-000000003686';
const EVERYTHING: InitAnswers = {
    answers: 'scanent-init-answers/1',
    estate: 'acme-prod',
    sources: [
        { kind: 'entra-sp', directoryId: GUID, clientId: GUID },
        { kind: 'okta-app', orgUrl: 'https://acme.okta.com' },
        { kind: 'vault', vaultUrls: ['https://acme-agents.vault.azure.net'], directoryTenantId: 'contoso.onmicrosoft.com', clientId: GUID },
        { kind: 'cicd', repositories: ['acme/payments-api'] },
        { kind: 'gcp-sa', projects: ['acme-prod-204'] },
        { kind: 'runtime', endpoint: { cloud: 'eu' }, workspaceId: GUID },
        { kind: 'code', roots: [{ label: 'support-bot', path: '/estate/support-bot' }] },
        { kind: 'mcp', servers: [{ label: 'crm-eu', url: 'https://mcp.acme.example/crm/mcp', readToken: true }, { label: 'open', url: 'https://mcp.acme.example/open/mcp' }] },
    ],
};
const CODE_ONLY: InitAnswers = { answers: 'scanent-init-answers/1', estate: 'acme', sources: [{ kind: 'code', roots: [{ label: 'app', path: '/estate/app' }] }] };

/** Every line of an env template that is not a comment or blank. */
const assignments = (template: string) => template.split('\n').filter((l) => l !== '' && !l.startsWith('#'));

describe('planInit', () => {
    it('plans a configuration scan accepts, with every default name and product filled in', () => {
        const plan = planInit(EVERYTHING);
        // What is written is what was planned, and it parses to the same configuration.
        expect(parseScannerConfig(JSON.parse(plan.configText))).toEqual(plan.config);
        expect(plan.configText.endsWith('}\n')).toBe(true);
        expect(plan.config.sources.map((s) => [s.kind, 'product' in s ? s.product : null])).toEqual([
            ['entra-sp', null],
            ['okta-app', null],
            ['vault', 'azure-key-vault'],
            ['cicd', 'github-actions'],
            ['gcp-sa', 'gcp-iam'],
            ['runtime', 'langsmith'],
            ['code', 'langchain'],
            ['mcp', null],
        ]);
        expect(credentialEnvNames(plan.config)).toEqual([
            'SCANNER_SIGNING_KEY',
            'ENTRA_CLIENT_SECRET',
            'OKTA_API_TOKEN',
            'AZURE_CLIENT_SECRET',
            'GITHUB_READ_TOKEN',
            'GCP_SCANNER_KEY',
            'LANGSMITH_API_KEY',
            'MCP_CRM_EU_TOKEN',
        ]);
        expect(plan.credentialNames.map((c) => c.name)).toEqual(credentialEnvNames(plan.config));
        expect(plan.config).toMatchObject({ outputs: [{ kind: 'file', dir: '/out' }], schedule: { everyHours: 24 }, scanner: { agentId: 'scanent-acme-prod' } });
    });

    it('Inflect is absent unless asked for', () => {
        const plan = planInit(EVERYTHING);
        expect(plan.config.inflect).toBeUndefined();
        expect(plan.config.outputs?.map((o) => o.kind)).toEqual(['file']);
        expect(plan.config.sources.some((s) => s.kind === 'inflect-register')).toBe(false);
        expect(plan.configText).not.toMatch(/inflect/i);
        expect(plan.envTemplate).not.toMatch(/INFLECT/);
        expect(plan.access.some((t) => t.kind === 'inflect-register')).toBe(false);
    });

    it('with a tenant: the block, the inflect output beside the file output, and the register source only when asked', () => {
        const inflect = { baseUrl: 'https://tenant.example.com', tenantSlug: 'acme', agentId: 'agt_scanner' };
        const posted = planInit({ ...CODE_ONLY, inflect });
        expect(posted.config).toMatchObject({ inflect: { ...{ baseUrl: inflect.baseUrl, tenantSlug: 'acme' }, apiKeyEnv: 'INFLECT_INGEST_KEY' }, scanner: { agentId: 'agt_scanner' } });
        expect(posted.config.outputs?.map((o) => o.kind)).toEqual(['file', 'inflect']);
        expect(posted.config.sources.map((s) => s.kind)).toEqual(['code']);
        expect(posted.access.map((t) => t.kind)).toEqual(['code', 'inflect-register']);
        const read = planInit({ ...CODE_ONLY, inflect: { ...inflect, readRegister: true } });
        expect(read.config.sources.map((s) => s.kind)).toEqual(['code', 'inflect-register']);
        expect(read.access.find((t) => t.kind === 'inflect-register')?.hosts).toEqual(['tenant.example.com']);
    });

    it('takes the optional answers: schedule, retention, inventory, output directory, names', () => {
        const plan = planInit({
            ...CODE_ONLY,
            everyHours: 6,
            outputDir: '/var/lib/scanent',
            retainRuns: 30,
            inventoryPath: '/etc/scanent/inventory.json',
            signingKeyEnv: 'ACME_SIGNING_KEY',
            sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiTokenEnv: 'ACME_OKTA_TOKEN', ownerProfileKey: 'team' }],
        });
        expect(plan.config).toMatchObject({
            schedule: { everyHours: 6 },
            outputs: [{ kind: 'file', dir: '/var/lib/scanent', retainRuns: 30 }],
            inventory: { path: '/etc/scanent/inventory.json' },
            scanner: { signingKeyEnv: 'ACME_SIGNING_KEY' },
            sources: [{ apiTokenEnv: 'ACME_OKTA_TOKEN', ownerProfileKey: 'team' }],
        });
        // No --out: the configuration it wrote already has that directory as a file output (Phase 3 review).
        expect(plan.nextSteps.at(-1)).toBe('scanent scan --config <dir>/config.json');
        expect(plan.config.outputs).toEqual([{ kind: 'file', dir: '/var/lib/scanent', retainRuns: 30 }]);
    });

    it('names an MCP token after the server\'s label, and keeps a name that was given', () => {
        expect(mcpTokenEnvName('crm-eu')).toBe('MCP_CRM_EU_TOKEN');
        const plan = planInit({ ...CODE_ONLY, sources: [{ kind: 'mcp', servers: [{ label: 'a', url: 'https://mcp.acme.example/a', readToken: true, readTokenEnv: 'GIVEN_NAME' }, { label: 'b', url: 'https://mcp.acme.example/b', readToken: false }] }] });
        expect(credentialEnvNames(plan.config)).toEqual(['SCANNER_SIGNING_KEY', 'GIVEN_NAME']);
    });

    it('refuses answers the configuration would refuse, by path and rule, never by value', () => {
        const bad = (answers: InitAnswers) => {
            try {
                planInit(answers);
            } catch (err) {
                expect(err).toBeInstanceOf(InitError);
                return (err as InitError).issues;
            }
            throw new Error('planned');
        };
        expect(bad({ ...CODE_ONLY, estate: 'Not A Slug' })).toContain('estate: invalid_format');
        expect(bad({ ...CODE_ONLY, sources: [{ kind: 'okta-app', orgUrl: 'https://evil.example.com' }] }).join()).toMatch(/^sources\.0\.orgUrl/);
        expect(bad({ ...CODE_ONLY, sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', unknownField: 1 }] }).join()).toMatch(/unrecognized_keys/);
        expect(bad({ ...CODE_ONLY, sources: [CODE_ONLY.sources[0], CODE_ONLY.sources[0]] })).toEqual(['sources: custom']);
        expect(JSON.stringify(bad({ ...CODE_ONLY, sources: [{ kind: 'okta-app', orgUrl: 'https://evil.example.com' }] }))).not.toContain('evil.example.com');
    });
});

describe('parseInitAnswers', () => {
    it('accepts the documented shape and refuses an unknown key, a missing source and the register as a source', () => {
        expect(parseInitAnswers(JSON.parse(JSON.stringify(EVERYTHING)))).toEqual(EVERYTHING);
        const issues = (json: unknown) => {
            try {
                parseInitAnswers(json);
            } catch (err) {
                return (err as InitError).issues;
            }
            throw new Error('parsed');
        };
        expect(issues({ ...CODE_ONLY, extra: 1 })).toEqual(['(root): unrecognized_keys']);
        expect(issues({ ...CODE_ONLY, answers: 'scanent-init-answers/2' })).toEqual(['answers: invalid_value']);
        expect(issues({ ...CODE_ONLY, sources: [] })).toEqual(['sources: too_small']);
        expect(issues({ ...CODE_ONLY, sources: [{ kind: 'inflect-register' }] })).toEqual(['sources.0.kind: invalid_value']);
        expect(issues({ ...CODE_ONLY, inflect: { baseUrl: 'https://t.example.com', tenantSlug: 't', agentId: 'a', apiKey: 'x' } })).toEqual(['inflect: unrecognized_keys']);
        expect(issues('nonsense')).toEqual(['(root): invalid_type']);
    });

    it('refuses a secret-shaped string anywhere, by its path, before the schema is consulted', () => {
        const pasted = ['gh', 'p_', 'B2'.repeat(12)].join('');
        for (const [json, path] of [
            [{ ...CODE_ONLY, estate: pasted }, 'estate'],
            [{ ...CODE_ONLY, sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiTokenEnv: pasted }] }, 'sources[0].apiTokenEnv'],
            [{ nothing: 'like', the: { schema: [pasted] } }, 'the.schema[0]'],
        ] as [unknown, string][]) {
            let thrown: unknown;
            try {
                parseInitAnswers(json);
            } catch (err) {
                thrown = err;
            }
            expect(thrown).toBeInstanceOf(InitError);
            expect((thrown as InitError).issues).toHaveLength(1);
            expect((thrown as InitError).issues[0]).toMatch(new RegExp(`^${path.replace(/[[\].]/g, '\\$&')}: a credential value`));
            expect((thrown as Error).message).not.toContain(pasted);
        }
    });
});

describe('the env template', () => {
    it('holds names with nothing after the =, or a path, and nothing else', () => {
        for (const template of [planInit(EVERYTHING).envTemplate, renderEnvTemplate(planInit(EVERYTHING).credentialNames, '/etc/scanent/signing-key.pem')]) {
            for (const line of assignments(template)) expect(line).toMatch(/^[A-Z][A-Z0-9_]*=(\/[^\s]*)?$/);
        }
    });

    it('uses the _FILE form for the two credentials an env file cannot carry, and only those', () => {
        const plan = planInit(EVERYTHING);
        expect(assignments(plan.envTemplate)).toEqual([
            'SCANNER_SIGNING_KEY_FILE=',
            'ENTRA_CLIENT_SECRET=',
            'OKTA_API_TOKEN=',
            'AZURE_CLIENT_SECRET=',
            'GITHUB_READ_TOKEN=',
            'GCP_SCANNER_KEY_FILE=',
            'LANGSMITH_API_KEY=',
            'MCP_CRM_EU_TOKEN=',
        ]);
        expect(plan.credentialNames.filter((c) => c.file).map((c) => c.name)).toEqual(['SCANNER_SIGNING_KEY', 'GCP_SCANNER_KEY']);
    });

    it('the only value it ever holds is the signing key\'s path', () => {
        const template = renderEnvTemplate(planInit(EVERYTHING).credentialNames, '/etc/scanent/signing-key.pem');
        expect(assignments(template).filter((l) => !l.endsWith('='))).toEqual(['SCANNER_SIGNING_KEY_FILE=/etc/scanent/signing-key.pem']);
    });

    it('every credential the configuration names has a line, and every line is one of them', () => {
        const plan = planInit({ ...EVERYTHING, inflect: { baseUrl: 'https://t.example.com', tenantSlug: 't', agentId: 'a', readRegister: true } });
        const named = assignments(plan.envTemplate).map((l) => l.split('=')[0].replace(/_FILE$/, ''));
        expect(named).toEqual(credentialEnvNames(plan.config));
    });
});

describe('the access guide', () => {
    it('has a table for every source kind, each naming a grant and what must not be granted', () => {
        expect([...GUIDE_ORDER].sort()).toEqual(Object.keys(ACCESS_GUIDE).sort());
        for (const kind of GUIDE_ORDER) {
            const e = ACCESS_GUIDE[kind];
            expect(e.kind).toBe(kind);
            expect(e.grant.length).toBeGreaterThan(10);
            expect(e.where.length).toBeGreaterThan(0);
            expect(e.reads.length).toBeGreaterThan(0);
            expect(e.notNeeded.length).toBeGreaterThan(0);
        }
        // No grant asks for a permission that writes.
        expect(Object.values(ACCESS_GUIDE).map((e) => e.grant).join(' ')).not.toMatch(/ReadWrite|Read and write|Administrator role(?! only)|Editor|Owner/);
    });

    it('one table per chosen source and none for the others, each with that configuration\'s hosts', () => {
        const tables = accessTablesFor(planInit(EVERYTHING).config);
        expect(tables.map((t) => t.kind)).toEqual(['entra-sp', 'vault', 'okta-app', 'cicd', 'gcp-sa', 'runtime', 'mcp', 'code']);
        expect(Object.fromEntries(tables.map((t) => [t.kind, t.hosts]))).toEqual({
            'entra-sp': ['graph.microsoft.com', 'login.microsoftonline.com'],
            vault: ['acme-agents.vault.azure.net', 'login.microsoftonline.com'],
            'okta-app': ['acme.okta.com'],
            cicd: ['api.github.com'],
            'gcp-sa': ['iam.googleapis.com', 'oauth2.googleapis.com'],
            runtime: ['eu.api.smith.langchain.com'],
            mcp: ['mcp.acme.example'],
            code: [],
        });
        expect(accessTablesFor(planInit(CODE_ONLY).config).map((t) => t.kind)).toEqual(['code']);
    });

    it('prints a table a person can act on', () => {
        const [entra] = accessTablesFor(planInit(EVERYTHING).config);
        const text = renderAccessText(entra);
        expect(text).toContain('Grant:       Microsoft Graph application permission Application.Read.All, with admin consent');
        expect(text).toContain('Credential:  ENTRA_CLIENT_SECRET');
        expect(text).toContain('Hosts:       graph.microsoft.com:443, login.microsoftonline.com:443');
        expect(renderAccessText(accessTablesFor(planInit(CODE_ONLY).config)[0])).toContain('Hosts:       none');
    });

    it('docs/access.md is the guide, rendered: run `npm run docs:access` after changing it', () => {
        expect(readFileSync(resolve(__dirname, '..', '..', '..', 'docs', 'access.md'), 'utf8')).toBe(renderAccessMarkdown());
    });
});
