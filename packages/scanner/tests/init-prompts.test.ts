/**
 * The wizard's prompts: the same answers a file would give, no question that
 * asks for a secret, and a secret-shaped answer refused wherever it is typed.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'fs';
import { PassThrough } from 'stream';
import { tmpdir } from 'os';
import { join } from 'path';

import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract';
import { main, terminalPrompt } from '../src/cli';
import { InitError, parseInitAnswers, type InitAnswers } from '../src/init/answers';
import { planInit } from '../src/init/plan';
import { collectAnswers, InitAborted, MAX_REFUSALS, SECRET_REFUSAL, type PromptIo } from '../src/init/prompts';
import { looksLikeBareToken, looksLikeCredential } from '../src/init/secret-shapes';

const GUID = '0d1e2c3b-0000-4000-8000-000000003686';
/** Built at run time: no credential-shaped literal is in this file. */
const PASTED = ['gh', 'p_', 'D4'.repeat(12)].join('');

interface Script {
    readonly io: PromptIo;
    readonly asked: string[];
    readonly said: string[];
}

/** Answers in order. Running out of answers fails the test rather than hanging it. */
function script(lines: readonly string[]): Script {
    const queue = [...lines];
    const asked: string[] = [];
    const said: string[] = [];
    return {
        asked,
        said,
        io: {
            ask: async (question) => {
                asked.push(question);
                if (queue.length === 0) throw new Error(`no answer scripted for: ${question}`);
                return queue.shift() as string;
            },
            say: (text) => void said.push(text),
        },
    };
}

/** The kind questions, in the order they are asked. `n` to all but the one chosen. */
const KINDS = ['entra-sp', 'vault', 'okta-app', 'cicd', 'gcp-sa', 'runtime', 'mcp', 'code'] as const;
const only = (kind: (typeof KINDS)[number], fields: string[]): string[] => ['acme-prod', ...KINDS.flatMap((k) => (k === kind ? ['y', ...fields] : ['n'])), '', '', '', 'n'];

const CASES: [(typeof KINDS)[number], string[], InitAnswers['sources'][number]][] = [
    ['entra-sp', [GUID, GUID], { kind: 'entra-sp', directoryId: GUID, clientId: GUID }],
    ['vault', ['https://acme-agents.vault.azure.net, https://acme-two.vault.azure.net', 'contoso.onmicrosoft.com', GUID], { kind: 'vault', vaultUrls: ['https://acme-agents.vault.azure.net', 'https://acme-two.vault.azure.net'], directoryTenantId: 'contoso.onmicrosoft.com', clientId: GUID }],
    ['okta-app', ['https://acme.okta.com'], { kind: 'okta-app', orgUrl: 'https://acme.okta.com' }],
    ['cicd', ['acme/payments-api,acme/web'], { kind: 'cicd', repositories: ['acme/payments-api', 'acme/web'] }],
    ['gcp-sa', ['acme-prod-204'], { kind: 'gcp-sa', projects: ['acme-prod-204'] }],
    ['runtime', ['eu', GUID], { kind: 'runtime', endpoint: { cloud: 'eu' }, workspaceId: GUID }],
    ['mcp', ['crm', 'https://mcp.acme.example/crm/mcp', 'y', 'open', 'https://mcp.acme.example/open/mcp', 'n', ''], { kind: 'mcp', servers: [{ label: 'crm', url: 'https://mcp.acme.example/crm/mcp', readToken: true }, { label: 'open', url: 'https://mcp.acme.example/open/mcp' }] }],
    ['code', ['support-bot', '/estate/support-bot', ''], { kind: 'code', roots: [{ label: 'support-bot', path: '/estate/support-bot' }] }],
];

describe('the prompts give the answers a file would', () => {
    it.each(CASES)('%s', async (kind, fields, source) => {
        const s = script(only(kind, fields));
        const answers = await collectAnswers(s.io);
        const asFile: InitAnswers = { answers: 'scanent-init-answers/1', estate: 'acme-prod', everyHours: 24, outputDir: '/out', sources: [source], inflect: null };
        expect(answers).toEqual(asFile);
        // The same object passes the file's own parser, and plans the same configuration.
        expect(parseInitAnswers(JSON.parse(JSON.stringify(answers)))).toEqual(asFile);
        expect(planInit(answers).configText).toBe(planInit(asFile).configText);
    });

    it('every kind at once, with a tenant, a schedule, an output directory and an inventory', async () => {
        const s = script([
            'acme-prod',
            ...CASES.flatMap(([, fields]) => ['y', ...fields]),
            '/var/lib/scanent',
            '6',
            '/etc/scanent/inventory.csv',
            'yes',
            'https://tenant.example.com',
            'acme',
            'agt_scanner_acme',
            'y',
        ]);
        const answers = await collectAnswers(s.io);
        expect(answers).toEqual({
            answers: 'scanent-init-answers/1',
            estate: 'acme-prod',
            everyHours: 6,
            outputDir: '/var/lib/scanent',
            inventoryPath: '/etc/scanent/inventory.csv',
            sources: CASES.map(([, , source]) => source),
            inflect: { baseUrl: 'https://tenant.example.com', tenantSlug: 'acme', agentId: 'agt_scanner_acme', readRegister: true },
        });
        const plan = planInit(answers);
        expect(plan.config.sources.map((x) => x.kind)).toEqual([...KINDS, 'inflect-register']);
        expect(plan.config.outputs?.map((o) => o.kind)).toEqual(['file', 'inflect']);
    });

    it('a self-hosted LangSmith is taken by its origin, and a blank workspace is left out', async () => {
        const answers = await collectAnswers(script(only('runtime', ['https://langsmith.acme.example', ''])).io);
        expect(answers.sources).toEqual([{ kind: 'runtime', endpoint: { selfHosted: 'https://langsmith.acme.example' } }]);
    });
});

describe('no question asks for a secret', () => {
    it('no prompt names a credential as the thing to type, and each source says where its credential goes', async () => {
        const s = script(['acme-prod', ...CASES.flatMap(([, fields]) => ['y', ...fields]), '', '', '', 'y', 'https://tenant.example.com', 'acme', 'agt', 'n']);
        await collectAnswers(s.io);
        for (const q of s.asked) expect(q).not.toMatch(/secret|password|token:|api key|private key|credential/i);
        // The one question that mentions a token asks whether one is needed, never for it.
        expect(s.asked.filter((q) => /token/i.test(q))).toEqual(['Does it need a token to list its tools? [y/N] ', 'Does it need a token to list its tools? [y/N] ']);
        for (const name of ['ENTRA_CLIENT_SECRET', 'AZURE_CLIENT_SECRET', 'OKTA_API_TOKEN', 'GITHUB_READ_TOKEN', 'GCP_SCANNER_KEY_FILE', 'LANGSMITH_API_KEY', 'MCP_CRM_TOKEN', 'INFLECT_INGEST_KEY']) {
            expect(s.said.filter((line) => line.includes(`is not asked for here: it goes in ${name}.`))).toHaveLength(1);
        }
    });
});

describe('a secret-shaped answer', () => {
    expect(looksLikeSecret(PASTED)).toBe(true);

    /** Every free-text question, reached by answering what comes before it validly. */
    const UP_TO: [string, string[], string[]][] = [
        ['the estate name', [], ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', '', '', 'n']],
        ['a yes/no question', ['acme-prod'], ['n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', '', '', 'n']],
        ['the Entra directory id', ['acme-prod', 'y'], [GUID, GUID, 'n', 'n', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['the Entra client id', ['acme-prod', 'y', GUID], [GUID, 'n', 'n', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['the vault URLs', ['acme-prod', 'n', 'y'], ['https://acme-agents.vault.azure.net', 'contoso.onmicrosoft.com', GUID, 'n', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['the Okta org URL', ['acme-prod', 'n', 'n', 'y'], ['https://acme.okta.com', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['the repositories', ['acme-prod', 'n', 'n', 'n', 'y'], ['acme/web', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['the Google projects', ['acme-prod', 'n', 'n', 'n', 'n', 'y'], ['acme-prod-204', 'n', 'n', 'n', '', '', '', 'n']],
        ['the LangSmith endpoint', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'y'], ['us', '', 'n', 'n', '', '', '', 'n']],
        ['the LangSmith workspace', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'y', 'us'], ['', 'n', 'n', '', '', '', 'n']],
        ['an MCP label', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'y'], ['crm', 'https://mcp.acme.example/crm/mcp', 'n', '', 'n', '', '', '', 'n']],
        ['an MCP URL', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'crm'], ['https://mcp.acme.example/crm/mcp', 'n', '', 'n', '', '', '', 'n']],
        ['a code root label', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y'], ['app', '/estate/app', '', '', '', '', 'n']],
        ['a code root path', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app'], ['/estate/app', '', '', '', '', 'n']],
        ['the output directory', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', ''], ['', '', '', 'n']],
        ['the schedule', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', ''], ['', '', 'n']],
        ['the inventory path', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', ''], ['', 'n']],
        ['the tenant URL', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', '', '', 'y'], ['https://tenant.example.com', 'acme', 'agt', 'n']],
        ['the tenant slug', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', '', '', 'y', 'https://tenant.example.com'], ['acme', 'agt', 'n']],
        ['the agent id', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', '', '', 'y', 'https://tenant.example.com', 'acme'], ['agt', 'n']],
    ];

    /**
     * One value of each credential this scanner is given, built from fragments so no scanner of this
     * repository reads one as real. Only the first is a shape the contract's own list knows: the rest
     * are the wizard's (`secret-shapes.ts`), and were accepted at every question before it had them.
     */
    const SHAPES: [string, string][] = [
        ['a GitHub token', PASTED],
        ['an Okta API token', ['00', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7d'].join('')],
        ['a LangSmith key', ['lsv2', 'pt', '0123456789abcdef0123456789abcdef', '0123456789'].join('_')],
        ['an Inflect API key', ['iflk', 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFi'].join('_')],
        ['an Entra client secret', ['abc8Q', 'dEfGhIjKlMnOpQrStUvWxYz0123456789a'].join('~')],
        ['a Google API key', ['AIza', 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q'].join('')],
    ];
    it('the wizard knows more shapes than the contract, and leaves the contract alone', () => {
        expect(SHAPES.map(([, v]) => looksLikeSecret(v))).toEqual([true, false, false, false, false, false]);
        expect(SHAPES.map(([, v]) => looksLikeCredential(v))).toEqual([true, true, true, true, true, true]);
    });

    describe.each(SHAPES)('%s', (_shape, pasted) => {
        it.each(UP_TO)('at %s: refused, asked again, and absent from everything said and returned', async (_label, before, after) => {
            const s = script([...before, pasted, ...after]);
            const answers = await collectAnswers(s.io);
            expect(s.said.filter((line) => line === SECRET_REFUSAL)).toHaveLength(1);
            // The question was asked again, word for word.
            expect(s.asked[before.length + 1]).toBe(s.asked[before.length]);
            expect(JSON.stringify(answers)).not.toContain(pasted);
            expect(s.said.join('\n') + s.asked.join('\n')).not.toContain(pasted);
            // And it is in nothing init would write.
            const plan = planInit(answers);
            expect(plan.configText + plan.envTemplate).not.toContain(pasted);
        });

        it('in an answers file: refused by path wherever it is, and not repeated', () => {
            const base = { answers: 'scanent-init-answers/1', estate: 'acme-prod', sources: [{ kind: 'code', roots: [{ label: 'app', path: '/estate/app' }] }] };
            for (const [json, path] of [
                [{ ...base, inflect: { baseUrl: 'https://tenant.example.com', tenantSlug: 'acme', agentId: pasted } }, 'inflect.agentId'],
                [{ ...base, outputDir: `/out/${pasted}` }, 'outputDir'],
                [{ ...base, sources: [{ kind: 'code', roots: [{ label: 'app', path: `/estate/${pasted}` }] }] }, 'sources[0].roots[0].path'],
                [{ ...base, inflect: { [pasted]: 'x' } }, 'inflect.<key>'],
            ] as [unknown, string][]) {
                let thrown: unknown;
                try {
                    parseInitAnswers(json);
                } catch (err) {
                    thrown = err;
                }
                expect(thrown).toBeInstanceOf(InitError);
                expect((thrown as InitError).issues).toEqual([`${path}: a credential value in the answers; scanent never takes one. If it was real, rotate it`]);
                expect((thrown as Error).message).not.toContain(pasted);
            }
        });
    });

    describe('a long bare token where a NAME is asked for', () => {
        // Forty hexadecimal digits: a token with no prefix to know it by. Lower-case, so it is a valid estate name and label.
        const HEX40 = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b';
        const NAMES = UP_TO.filter(([label]) => ['the estate name', 'an MCP label', 'a code root label', 'the tenant slug', 'the agent id'].includes(label));

        it.each(NAMES)('at %s: refused as a credential, and in nothing that would be written', async (_label, before, after) => {
            const s = script([...before, HEX40, ...after]);
            const answers = await collectAnswers(s.io);
            expect(s.said.filter((line) => line === SECRET_REFUSAL)).toHaveLength(1);
            expect(planInit(answers).configText).not.toContain(HEX40);
        });

        it('covers every question that takes a name, and only those', () => {
            expect(NAMES.map(([label]) => label)).toEqual(['the estate name', 'an MCP label', 'a code root label', 'the tenant slug', 'the agent id']);
        });

        it('a name that reads as one is not refused for being long, and neither is a GUID where a GUID is asked for', async () => {
            const long = 'acme-production-eu-west-1-cluster-22';
            expect(long.length).toBeGreaterThanOrEqual(32);
            const s = script([long, 'y', GUID, GUID, 'n', 'n', 'n', 'n', 'n', 'n', 'n', '', '', '', 'y', 'https://tenant.example.com', 'acme', 'agt_scanner_acme_production_eu_west_1', 'n']);
            const answers = await collectAnswers(s.io);
            expect(s.said).not.toContain(SECRET_REFUSAL);
            expect(answers.estate).toBe(long);
            expect(looksLikeBareToken(GUID.replace(/-/g, ''))).toBe(true);
            expect(looksLikeCredential(GUID)).toBe(false);
        });

        it('in an answers file: refused at the name it is in, and a directory id of the same length is not', () => {
            const base = { answers: 'scanent-init-answers/1', sources: [{ kind: 'entra-sp', directoryId: GUID, clientId: GUID }] };
            const refusedAt = (json: unknown): string | null => {
                try {
                    parseInitAnswers(json);
                    return null;
                } catch (err) {
                    return (err as InitError).issues[0].split(':')[0];
                }
            };
            expect(refusedAt({ ...base, estate: 'acme' })).toBeNull();
            expect(refusedAt({ ...base, estate: HEX40 })).toBe('estate');
            expect(refusedAt({ ...base, estate: 'acme', inflect: { baseUrl: 'https://t.example.com', tenantSlug: 'acme', agentId: HEX40 } })).toBe('inflect.agentId');
            expect(refusedAt({ ...base, estate: 'acme', inflect: { baseUrl: 'https://t.example.com', tenantSlug: HEX40, agentId: 'agt' } })).toBe('inflect.tenantSlug');
            expect(refusedAt({ ...base, estate: 'acme', sources: [{ kind: 'mcp', servers: [{ label: HEX40, url: 'https://mcp.acme.example/mcp' }] }] })).toBe('sources[0].servers[0].label');
            expect(refusedAt({ ...base, estate: 'acme', sources: [{ kind: 'code', roots: [{ label: HEX40, path: '/estate/app' }] }] })).toBe('sources[0].roots[0].label');
        });
    });

    it('says where the API key goes BEFORE the first question about the tenant, not after the last', async () => {
        const events: string[] = [];
        const s = script(['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', '', '', 'y', 'https://tenant.example.com', 'acme', 'agt', 'n']);
        await collectAnswers({
            ask: async (q) => {
                events.push(`ask ${q}`);
                return s.io.ask(q);
            },
            say: (text) => void events.push(`say ${text}`),
        });
        const key = events.indexOf('say The API key is not asked for here: it goes in INFLECT_INGEST_KEY.');
        expect(key).toBeGreaterThan(-1);
        expect(events[key + 1]).toBe('ask Tenant base URL (https origin): ');
        expect(events.filter((e) => e.startsWith('ask') && /agent id/.test(e))).toEqual(["ask The scanner's agent id in the tenant's register (a name, not a key): "]);
    });

    it('three refusals of one question end the wizard', async () => {
        const s = script(['acme-prod', 'n', 'n', 'y', PASTED, PASTED, PASTED, 'never reached']);
        await expect(collectAnswers(s.io)).rejects.toThrow(InitAborted);
        expect(s.said.filter((line) => line === SECRET_REFUSAL)).toHaveLength(MAX_REFUSALS);
        expect(s.said.join('\n')).not.toContain(PASTED);
    });

    it('through the command: exit 2, nothing written, and the value on neither stream', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'scanent-prompts-'));
        const out: string[] = [];
        jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
        jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
        try {
            const s = script([PASTED, PASTED, PASTED]);
            expect(await main(['init', '--dir', join(dir, 'scanent')], {}, { prompt: s.io })).toBe(2);
            expect(readdirSync(dir)).toEqual([]);
            expect(out.join('') + s.said.join('')).not.toContain(PASTED);
            expect(out.join('')).toContain('refused three times; nothing was written');
        } finally {
            jest.restoreAllMocks();
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('an answer that breaks its field\'s rule', () => {
    it.each([
        ['an estate that is not a slug', [], 'Not A Slug', ['acme-prod', 'n', 'n', 'y', 'https://acme.okta.com', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['an Okta URL on another domain', ['acme-prod', 'n', 'n', 'y'], 'https://okta.evil.example', ['https://acme.okta.com', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['a directory id that is not a GUID', ['acme-prod', 'y'], 'contoso', [GUID, GUID, 'n', 'n', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['a vault URL off Azure', ['acme-prod', 'n', 'y'], 'https://vault.evil.example', ['https://a.vault.azure.net', 'contoso.onmicrosoft.com', GUID, 'n', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['a repository without an owner', ['acme-prod', 'n', 'n', 'n', 'y'], 'just-a-name', ['acme/web', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['a LangSmith host on a private address', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'y'], 'https://10.0.0.5', ['eu', '', 'n', 'n', '', '', '', 'n']],
        ['an MCP URL that is not https', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'crm'], 'http://mcp.acme.example/mcp', ['https://mcp.acme.example/mcp', 'n', '', 'n', '', '', '', 'n']],
        ['a code path that is relative', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app'], 'relative/dir', ['/estate/app', '', '', '', '', 'n']],
        ['a schedule that is not a number of hours', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', ''], 'daily', ['12', '', 'n']],
        ['an inventory that is not .json or .csv', ['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'app', '/estate/app', '', '', ''], '/etc/inventory.xlsx', ['', 'n']],
        ['a yes/no that is neither', ['acme-prod'], 'maybe', ['n', 'n', 'y', 'https://acme.okta.com', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
        ['a blank where a value is required', ['acme-prod', 'n', 'n', 'y'], '', ['https://acme.okta.com', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n']],
    ])('%s repeats the question with the rule, never the value', async (_label, before, wrong, after) => {
        const s = script([...before, wrong, ...after]);
        const answers = await collectAnswers(s.io);
        expect(s.asked[before.length + 1]).toBe(s.asked[before.length]);
        if (wrong !== '') expect(s.said.join('\n')).not.toContain(wrong);
        // What came out still plans a configuration scan accepts.
        expect(() => planInit(answers)).not.toThrow();
        if (wrong !== '') expect(JSON.stringify(answers)).not.toContain(wrong);
    });

    it('a label or a URL given twice is asked for again', async () => {
        const s = script(['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'y', 'crm', 'https://mcp.acme.example/a', 'n', 'crm', 'two', 'https://mcp.acme.example/a', 'https://mcp.acme.example/b', 'n', '', 'n', '', '', '', 'n']);
        const answers = await collectAnswers(s.io);
        expect(answers.sources).toEqual([{ kind: 'mcp', servers: [{ label: 'crm', url: 'https://mcp.acme.example/a' }, { label: 'two', url: 'https://mcp.acme.example/b' }] }]);
    });

    it('no source chosen ends the wizard: there is nothing to scan', async () => {
        await expect(collectAnswers(script(['acme-prod', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'n']).io)).rejects.toThrow('no source was chosen');
    });
});

describe('scanent init at the prompts', () => {
    it('writes what the answers plan', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'scanent-prompts-'));
        jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
        jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
        try {
            const s = script(only('okta-app', ['https://acme.okta.com']));
            expect(await main(['init', '--dir', join(dir, 'scanent')], {}, { prompt: s.io })).toBe(0);
            const written = JSON.parse(readFileSync(join(dir, 'scanent', 'config.json'), 'utf8'));
            expect(written).toMatchObject({ estate: 'acme-prod', sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiTokenEnv: 'OKTA_API_TOKEN' }] });
        } finally {
            jest.restoreAllMocks();
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('the terminal', () => {
    it('asks on its output, takes one line per question, and keeps answers that arrive ahead of their questions', async () => {
        const input = new PassThrough();
        const output = new PassThrough();
        const shown: string[] = [];
        output.on('data', (chunk) => shown.push(String(chunk)));
        const terminal = terminalPrompt(input, output);
        // Everything at once, as a paste or a pipe delivers it.
        input.write(['acme-prod', 'n', 'n', 'y', 'https://acme.okta.com', 'n', 'n', 'n', 'n', 'n', '', '', '', 'n'].join('\n') + '\n');
        const answers = await collectAnswers(terminal.io);
        terminal.close();
        expect(answers).toMatchObject({ estate: 'acme-prod', sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com' }], inflect: null });
        expect(shown.join('')).toContain('Do you have Okta? [y/N] ');
        expect(shown.join('')).toContain('it goes in OKTA_API_TOKEN.');
    });

    it('answers a question asked before its line arrives', async () => {
        const input = new PassThrough();
        const terminal = terminalPrompt(input, new PassThrough());
        const pending = terminal.io.ask('Estate name:');
        input.write('acme\n');
        expect(await pending).toBe('acme');
        terminal.close();
    });

    it('input that ends before the questions do ends the wizard, whether a question was waiting or not', async () => {
        const input = new PassThrough();
        const terminal = terminalPrompt(input, new PassThrough());
        const pending = collectAnswers(terminal.io);
        input.end('acme-prod\nn\n');
        await expect(pending).rejects.toThrow(InitAborted);
        await expect(terminal.io.ask('anything')).rejects.toThrow('the input ended before the questions did');
        terminal.close();
    });

    it('a line that arrived before the input ended still answers a question asked after it', async () => {
        // Node 24 throws from prompt() on a closed interface; the queued line
        // must be handed over without prompting, on every supported Node.
        const input = new PassThrough();
        const terminal = terminalPrompt(input, new PassThrough());
        const closed = new Promise((resolve) => input.once('close', resolve));
        input.end('acme\n');
        await closed;
        await new Promise((resolve) => setImmediate(resolve));
        expect(await terminal.io.ask('Estate name:')).toBe('acme');
        await expect(terminal.io.ask('next')).rejects.toThrow('the input ended before the questions did');
        terminal.close();
    });
});
