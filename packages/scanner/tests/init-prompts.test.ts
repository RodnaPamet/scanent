/**
 * The wizard's prompts: the same answers a file would give, no question that
 * asks for a secret, and a secret-shaped answer refused wherever it is typed.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'fs';
import { PassThrough } from 'stream';
import { tmpdir } from 'os';
import { join } from 'path';

import { looksLikeSecret } from '@scanent/contract/harness-contract';
import { main, terminalPrompt } from '../src/cli';
import { parseInitAnswers, type InitAnswers } from '../src/init/answers';
import { planInit } from '../src/init/plan';
import { collectAnswers, InitAborted, MAX_REFUSALS, SECRET_REFUSAL, type PromptIo } from '../src/init/prompts';

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

    it.each(UP_TO)('at %s: refused, asked again, and absent from everything said and returned', async (_label, before, after) => {
        const s = script([...before, PASTED, ...after]);
        const answers = await collectAnswers(s.io);
        expect(s.said.filter((line) => line === SECRET_REFUSAL)).toHaveLength(1);
        // The question was asked again, word for word.
        expect(s.asked[before.length + 1]).toBe(s.asked[before.length]);
        expect(JSON.stringify(answers)).not.toContain(PASTED);
        expect(s.said.join('\n') + s.asked.join('\n')).not.toContain(PASTED);
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
});
