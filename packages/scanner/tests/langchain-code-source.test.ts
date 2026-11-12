/**
 * The LangChain and LangGraph detector — the scanner's `code` source (#3737).
 *
 *   1. Each fixture estate — LangChain Python, LangChain JS, LangGraph —
 *      yields the expected agents, with their tools, their model endpoints and
 *      their credentials.
 *   2. The detector never executes or imports what it reads: definitions whose
 *      import would have a side effect are read, recognised, and never run.
 *   3. Credentials appear by reference only, over the whole signed report.
 *   4. An unreadable location or an unresolvable definition is INCOMPLETE with
 *      a named reason; nothing is left out.
 *   5. Its reports verify under `inflect-agent-harness/3`, beside the other
 *      sources, with no change to the contract.
 */
import { execFileSync } from 'child_process';
import { existsSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { lstat, readdir, readFile } from 'fs/promises';
import { generateKeyPairSync } from 'crypto';
import { join } from 'path';

import {
    LANGCHAIN_JS,
    LANGCHAIN_PYTHON,
    LANGGRAPH,
    NOT_LANGCHAIN,
    PLAIN_LITERAL_KEY,
    SIDE_EFFECT,
    SIDE_EFFECT_ENV,
    UNPARSEABLE,
    fakeOpenAiKey,
    literalCredentials,
    writeCodeEstate,
} from './helpers/agent-harness-code-fixtures';
import { HARNESS_CONTRACT_V3, looksLikeSecret, verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { parseScannerConfig } from '../src/config';
import { jsonLineLog } from '../src/log';
import { rawPublicKeyHex } from '../src/report';
import { runScan } from '../src/scan';
import { scannerManifestHash, SCANNER_SURFACE } from '../src/scanner-surface';
import type { CodeFs } from '../src/sources/code/files';
import { MAX_FILE_BYTES } from '../src/sources/code/files';
import { reportableModelName, type DetectedAgent } from '../src/sources/code/recognize';
import { langchainCodeSource, scanLangChainCode } from '../src/sources/langchain';
import type { SourceContext, SourceRead } from '../src/source';

const REAL_FS: CodeFs = { lstat: (p) => lstat(p), readdir: (p) => readdir(p), readFile: (p) => readFile(p) };
const LATER = { deadline: Number.MAX_SAFE_INTEGER, now: Date.now };
const made: string[] = [];

function estate(...trees: Readonly<Record<string, string>>[]): string {
    const dir = writeCodeEstate(...trees);
    made.push(dir);
    return dir;
}
afterAll(() => {
    for (const dir of made) rmSync(dir, { recursive: true, force: true });
});

async function agentsIn(...trees: Readonly<Record<string, string>>[]) {
    const scan = await scanLangChainCode([{ label: 'acme', path: estate(...trees) }], REAL_FS, LATER);
    return { scan, byName: new Map(scan.agents.map((a) => [a.name, a])) };
}

/** A wire that fails the test if the code source ever touches it. */
const NO_WIRE: Pick<SourceContext, 'http' | 'tokens' | 'mcp' | 'register' | 'openshell'> = {
    http: {
        getJson: async () => {
            throw new Error('the code source makes no request');
        },
    },
    tokens: {
        clientCredentials: async () => {
            throw new Error('the code source exchanges no token');
        },
        jwtBearer: async () => {
            throw new Error('the code source exchanges no token');
        },
    },
    mcp: {
        open: async () => {
            throw new Error('the code source speaks to no MCP server');
        },
        listTools: async () => {
            throw new Error('the code source speaks to no MCP server');
        },
    },
    register: {
        read: async () => {
            throw new Error('the code source reads no register');
        },
    },
    // The code source reads local files and reaches no gateway. Each method
    // throws rather than returning an empty answer, so a source that started
    // calling one would fail this suite instead of quietly reading nothing.
    openshell: {
        listSandboxes: async () => {
            throw new Error('the code source reads no OpenShell gateway');
        },
        getSandbox: async () => {
            throw new Error('the code source reads no OpenShell gateway');
        },
        getSandboxPolicyStatus: async () => {
            throw new Error('the code source reads no OpenShell gateway');
        },
        listSandboxProviders: async () => {
            throw new Error('the code source reads no OpenShell gateway');
        },
        getProviderProfile: async () => {
            throw new Error('the code source reads no OpenShell gateway');
        },
    },
};

function read(source: ReturnType<typeof langchainCodeSource>, deadline = Number.MAX_SAFE_INTEGER): Promise<SourceRead> {
    return source.read({ asOf: new Date(), deadline, now: Date.now, ...NO_WIRE });
}

const summary = (a: DetectedAgent) => ({
    framework: a.framework,
    language: a.language,
    discoveredId: a.discoveredId,
    tools: a.tools.map((t) => [t.kind, t.name, t.server]),
    models: a.models.map((m) => [m.provider, m.model, m.endpoint, m.endpointBasis]),
    credentials: a.credentials.map((c) => [c.ref, c.basis]),
});

describe('1. each fixture estate yields its agents, tools, model endpoints and credentials', () => {
    it('LangChain Python: an executor absorbs the agent it wraps, and is reported once', async () => {
        const { scan, byName } = await agentsIn(LANGCHAIN_PYTHON);
        expect(scan.problems).toEqual([]);
        expect([...byName.keys()]).toEqual(['support_executor']);
        expect(summary(byName.get('support_executor')!)).toEqual({
            framework: 'langchain',
            language: 'python',
            discoveredId: 'code:acme/support/agent.py#support_executor',
            tools: [
                ['function', 'lookup_order', 'code://acme/support/agent.py#L11'],
                ['function', 'refund_order', 'code://acme/support/agent.py#L17'],
                ['function', 'escalate_ticket', 'code://acme/support/agent.py#L26'],
                ['builtin', 'TavilySearchResults', 'code://acme/support/agent.py#L35'],
            ],
            // An endpoint written in code is reported as its origin: the fixture's `/v1` is a path, and a path can hold a key.
            models: [['openai', 'gpt-4o-mini', 'https://llm-gateway.acme.example', 'explicit']],
            credentials: [
                ['env://SUPPORT_OPENAI_KEY', 'environment'],
                ['env://TAVILY_API_KEY', 'provider-default'],
            ],
        });
    });

    it('LangChain JS, and LangGraph JS\'s prebuilt agent beside it', async () => {
        const { scan, byName } = await agentsIn(LANGCHAIN_JS);
        expect(scan.problems).toEqual([]);
        expect(summary(byName.get('researchExecutor')!)).toEqual({
            framework: 'langchain',
            language: 'javascript',
            discoveredId: 'code:acme/research/agent.ts#researchExecutor',
            tools: [
                ['function', 'search_papers', 'code://acme/research/agent.ts#L7'],
                ['function', 'save_note', 'code://acme/research/agent.ts#L13'],
            ],
            models: [['anthropic', 'research-model-v1', 'https://api.anthropic.com', 'provider-default']],
            credentials: [['env://RESEARCH_ANTHROPIC_KEY', 'environment']],
        });
        expect(summary(byName.get('triageAgent')!)).toEqual({
            framework: 'langgraph',
            language: 'javascript',
            discoveredId: 'code:acme/research/triage.js#triageAgent',
            tools: [['builtin', 'TavilySearchResults', 'code://acme/research/triage.js#L6']],
            models: [['openai', 'gpt-4o', 'env://TRIAGE_LLM_URL', 'environment']],
            credentials: [
                ['env://OPENAI_API_KEY', 'provider-default'],
                ['env://TAVILY_API_KEY', 'provider-default'],
            ],
        });
        expect(byName.size).toBe(2);
    });

    it('LangGraph: a compiled StateGraph with a ToolNode and a bound model, and a prebuilt agent over an MCP server', async () => {
        const { scan, byName } = await agentsIn(LANGGRAPH);
        expect(scan.problems).toEqual([]);
        expect(summary(byName.get('ops_graph')!)).toEqual({
            framework: 'langgraph',
            language: 'python',
            discoveredId: 'code:acme/ops/graph.py#ops_graph',
            tools: [
                ['function', 'restart_service', 'code://acme/ops/graph.py#L11'],
                ['function', 'read_metrics', 'code://acme/ops/graph.py#L17'],
            ],
            models: [['anthropic', 'ops-model-v1', 'https://api.anthropic.com', 'provider-default']],
            credentials: [['env://OPS_ANTHROPIC_KEY', 'environment']],
        });
        expect(summary(byName.get('oncall_agent')!)).toEqual({
            framework: 'langgraph',
            language: 'python',
            discoveredId: 'code:acme/ops/graph.py#oncall_agent',
            tools: [
                ['mcp', 'tickets:*', 'https://mcp.acme.example'],
                ['function', 'read_metrics', 'code://acme/ops/graph.py#L17'],
            ],
            models: [['openai', 'gpt-4.1', 'https://api.openai.com/v1', 'provider-default']],
            credentials: [
                ['env://OPENAI_API_KEY', 'provider-default'],
                ['env://TICKETS_MCP_TOKEN', 'environment'],
            ],
        });
        expect(byName.size).toBe(2);
    });

    it('a name that only LOOKS like the framework\'s is not an agent', async () => {
        const { scan } = await agentsIn(NOT_LANGCHAIN);
        expect(scan.agents).toEqual([]);
        expect(scan.problems).toEqual([]);
    });
});

describe('2. the detector never executes or imports scanned code', () => {
    it('reads and recognises definitions whose import would have a side effect, and the side effect never happens', async () => {
        const dir = estate(SIDE_EFFECT);
        const marker = join(dir, 'side-effect-happened');
        const before = process.env[SIDE_EFFECT_ENV];
        process.env[SIDE_EFFECT_ENV] = marker;
        try {
            const scan = await scanLangChainCode([{ label: 'acme', path: dir }], REAL_FS, LATER);
            // The files WERE read: each agent in them was recognised…
            expect(scan.agents.map((a) => a.name).sort()).toEqual(['executed_agent', 'importedAgent', 'loadedAgent']);
            // …and nothing in them ran: no marker file, no global.
            expect(existsSync(marker)).toBe(false);
            expect((globalThis as { __harnessSideEffect?: unknown }).__harnessSideEffect).toBeUndefined();
            // The proof is live: loading one of them for real — in a separate
            // Node process, from this test and never from the scanner — DOES
            // leave the mark before it fails on the package it cannot find.
            expect(() =>
                execFileSync(process.execPath, [join(dir, 'side-effect/agent.js')], {
                    env: { ...process.env, [SIDE_EFFECT_ENV]: marker },
                    stdio: 'ignore',
                }),
            ).toThrow();
            expect(existsSync(marker)).toBe(true);
        } finally {
            delete (globalThis as { __harnessSideEffect?: unknown }).__harnessSideEffect;
            if (before === undefined) delete process.env[SIDE_EFFECT_ENV];
            else process.env[SIDE_EFFECT_ENV] = before;
        }
    });

    it('declares the file reads in the manifest it hashes, and says it executes nothing', () => {
        expect(SCANNER_SURFACE.readsFiles).toEqual([
            expect.objectContaining({ source: 'code', operations: ['lstat', 'readdir', 'readFile'], followsSymlinks: false, executes: false }),
        ]);
        expect(scannerManifestHash()).toMatch(/^sha256:[0-9a-f]{64}$/);
    });
});

describe('3. credentials by reference only', () => {
    it('a literal in the code is reported as where it is written, never as what it is', async () => {
        const { byName } = await agentsIn(literalCredentials());
        expect(byName.get('hardcoded_py')!.credentials).toEqual([
            { ref: 'code://acme/hardcoded/agent.py#L4', basis: 'literal', at: { label: 'acme', path: 'hardcoded/agent.py', line: 4 } },
        ]);
        expect(byName.get('hardcodedJs')!.credentials.map((c) => c.ref)).toEqual(['code://acme/hardcoded/agent.js#L4']);
    });

    it('no literal value reaches the signed report, secret-shaped or not', async () => {
        expect(looksLikeSecret(fakeOpenAiKey())).toBe(true);
        expect(looksLikeSecret(PLAIN_LITERAL_KEY)).toBe(false);
        const dir = estate(LANGCHAIN_PYTHON, literalCredentials());
        const { privateKey, publicKey } = generateKeyPairSync('ed25519');
        const { raw, body } = await runScan({
            config: parseScannerConfig({
                estate: 'acme-code',
                scanner: { agentId: 'agt_scanner_code', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
                inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
                schedule: { everyHours: 24 },
                sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: dir }] }],
            }),
            env: { SCANNER_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
            log: jsonLineLog(() => undefined),
            fetchImpl: async () => {
                throw new Error('the code source makes no request');
            },
        });
        for (const literal of [fakeOpenAiKey(), PLAIN_LITERAL_KEY]) expect(raw).not.toContain(literal);
        // The absolute path is not in it either: only the root's label.
        expect(raw).not.toContain(dir);
        expect(verifyAndParseHarnessReport(raw, [rawPublicKeyHex(publicKey)])).toMatchObject({ ok: true, complete: true });
        expect(body.agents.map((a) => a.discoveredId)).toContain('code:acme/hardcoded/agent.py#hardcoded_py');
    });
});

describe('4. what cannot be read or resolved is INCOMPLETE with its reason, never left out', () => {
    it('a definition built from what the reader cannot see: UNPARSEABLE, and the agent is still reported', async () => {
        const source = langchainCodeSource({ roots: [{ label: 'acme', path: estate({ 'dynamic/assistant.py': UNPARSEABLE['dynamic/assistant.py'] }) }] });
        const result = await read(source);
        expect(result).toMatchObject({ kind: 'code', status: 'INCOMPLETE', reason: 'UNPARSEABLE', rows: 1 });
        expect(result.observations.map((o) => o.discoveredId)).toEqual(['code:acme/dynamic/assistant.py#assistant']);
    });

    it('a file that does not parse: UNPARSEABLE, and the other files are still read', async () => {
        const source = langchainCodeSource({
            roots: [{ label: 'acme', path: estate(LANGGRAPH, { 'broken/agent.py': UNPARSEABLE['broken/agent.py'] }) }],
        });
        const result = await read(source);
        expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'UNPARSEABLE', rows: 2 });
        expect(result.observations.map((o) => o.discoveredId).sort()).toEqual([
            'code:acme/ops/graph.py#oncall_agent',
            'code:acme/ops/graph.py#ops_graph',
        ]);
    });

    it('a root that does not exist: UNREACHABLE', async () => {
        const result = await read(langchainCodeSource({ roots: [{ label: 'gone', path: '/nonexistent/harness-code-root' }] }));
        expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'UNREACHABLE', rows: 0, observations: [] });
    });

    it('a file the operating system refuses: AUTH_FAILED, beside what was read', async () => {
        const dir = estate(LANGCHAIN_PYTHON, LANGGRAPH);
        const denying: CodeFs = {
            ...REAL_FS,
            readFile: async (p) => {
                if (p.endsWith('ops/graph.py')) throw Object.assign(new Error('permission denied'), { code: 'EACCES' });
                return REAL_FS.readFile(p);
            },
        };
        const result = await read(langchainCodeSource({ roots: [{ label: 'acme', path: dir }], fs: denying }));
        expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'AUTH_FAILED' });
        expect(result.observations.map((o) => o.discoveredId)).toEqual(['code:acme/support/agent.py#support_executor']);
    });

    it('a symbolic link is not followed, and the location it names is UNREACHABLE', async () => {
        const dir = estate(LANGCHAIN_PYTHON);
        symlinkSync('/etc', join(dir, 'outside'));
        const result = await read(langchainCodeSource({ roots: [{ label: 'acme', path: dir }] }));
        expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'UNREACHABLE' });
        expect(result.observations).toHaveLength(1);
    });

    it('a file over the size cap: BYTE_CAP', async () => {
        const dir = estate(LANGCHAIN_PYTHON);
        writeFileSync(join(dir, 'huge.py'), `# langchain\n${'x = 1\n'.repeat(Math.ceil(MAX_FILE_BYTES / 6) + 10)}`);
        const result = await read(langchainCodeSource({ roots: [{ label: 'acme', path: dir }] }));
        expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'BYTE_CAP' });
        expect(result.observations).toHaveLength(1);
    });

    it('the scan\'s deadline: TIME_BOX', async () => {
        const result = await read(langchainCodeSource({ roots: [{ label: 'acme', path: estate(LANGCHAIN_PYTHON) }] }), Date.now() - 1);
        expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'TIME_BOX' });
    });

    it('a deadline that passes mid-read stops between files, keeping what was read', async () => {
        const dir = estate(LANGCHAIN_PYTHON, LANGGRAPH, LANGCHAIN_JS);
        let tick = 0;
        const scan = await scanLangChainCode([{ label: 'acme', path: dir }], REAL_FS, { deadline: 4, now: () => tick++ });
        expect(scan.problems).toContainEqual({ reason: 'TIME_BOX', at: null });
        expect(scan.agents.length).toBeGreaterThan(0);
        expect(scan.agents.length).toBeLessThan(5);
    });

    it('a tree with no agent in it is a COMPLETE read of nothing — the ingest calls an empty scan EMPTY_SCAN', async () => {
        const result = await read(langchainCodeSource({ roots: [{ label: 'acme', path: estate({ 'README.py': '# nothing here\n' }) }] }));
        expect(result).toEqual({ kind: 'code', status: 'COMPLETE', rows: 1, observations: [] });
    });
});

describe('5. its reports verify under inflect-agent-harness/3, with no change to the contract', () => {
    it('every fixture estate in one signed report: `code` source, tools, references', async () => {
        const dir = estate(LANGCHAIN_PYTHON, LANGCHAIN_JS, LANGGRAPH);
        const { privateKey, publicKey } = generateKeyPairSync('ed25519');
        const { raw, body } = await runScan({
            config: parseScannerConfig({
                estate: 'acme-code',
                scanner: { agentId: 'agt_scanner_code', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
                inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
                schedule: { everyHours: 24 },
                sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: dir }] }],
            }),
            env: { SCANNER_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
            log: jsonLineLog(() => undefined),
            fetchImpl: async () => {
                throw new Error('the code source makes no request');
            },
        });
        const verdict = verifyAndParseHarnessReport(raw, [rawPublicKeyHex(publicKey)]);
        expect(verdict).toMatchObject({ ok: true, complete: true, body: { contract: HARNESS_CONTRACT_V3 } });
        expect(body.population.sources).toEqual([{ kind: 'code', status: 'COMPLETE', rows: 4 }]);
        expect(body.agents.map((a) => a.discoveredId)).toEqual([
            'code:acme/ops/graph.py#oncall_agent',
            'code:acme/ops/graph.py#ops_graph',
            'code:acme/research/agent.ts#researchExecutor',
            'code:acme/research/triage.js#triageAgent',
            'code:acme/support/agent.py#support_executor',
        ]);
        const support = body.agents.find((a) => a.discoveredId.endsWith('#support_executor'))!;
        expect(support).toMatchObject({ discoveredVia: ['code'], registeredAgentId: null, owner: null, verdicts: [] });
        expect(support.tools).toContainEqual({
            server: 'code://acme/support/agent.py#L11',
            name: 'lookup_order',
            manifestHash: null,
            pinned: false,
            readOnlyHint: null,
        });
        expect(support.credentials).toContainEqual({ ref: 'env://SUPPORT_OPENAI_KEY', ageDays: null, expires: null, boundToAgent: false, grant: 'unknown' });
        // The model endpoints each agent calls, in /2's `models[]`, by reference.
        const models = Object.fromEntries(body.agents.map((a) => [a.discoveredId.split('#')[1], a.models]));
        expect(models).toEqual({
            support_executor: [{ endpoint: 'https://llm-gateway.acme.example', model: 'gpt-4o-mini' }],
            researchExecutor: [{ endpoint: 'https://api.anthropic.com', model: 'research-model-v1' }],
            triageAgent: [{ endpoint: 'env://TRIAGE_LLM_URL', model: 'gpt-4o' }],
            ops_graph: [{ endpoint: 'https://api.anthropic.com', model: 'ops-model-v1' }],
            oncall_agent: [{ endpoint: 'https://api.openai.com/v1', model: 'gpt-4.1' }],
        });
        expect(body.unboundCredentials).toEqual([]);
    });

    it('a key in the path of a model or MCP endpoint URL is in no observation and no report: the origin is what is reported', async () => {
        // None of these has a prefix a secret scan knows: a gateway token, a webhook's three segments, a GUID key.
        const paths = ['/v1/tok-9f8e7d6c5b4a39281706', '/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX', '/key/9f8e7d6c-5b4a-3928-1706-aabbccddeeff/v1', '/proxy/4f3c2b1a0d9e8f7a6b5c4d3e2f1a0b9c/v1'];
        const dir = estate({
            ...Object.fromEntries(
                paths.map((path, i) => [
                    `a${i}/agent.py`,
                    `from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

GATEWAY = "https://gw.acme.example:8443${path}?sig=also-not-kept#nor-this"
client = MultiServerMCPClient({"tickets": {"url": "https://mcp.acme.example${path}", "transport": "streamable_http"}})
agent_${i} = create_react_agent(ChatOpenAI(model="gpt-4o", base_url=GATEWAY), client.get_tools())
`,
                ]),
            ),
            'js/agent.ts': `import { query } from "@anthropic-ai/claude-agent-sdk";
export const run = query({ prompt: "x", options: { mcpServers: { crm: { type: "http", url: "https://crm.acme.example${paths[0]}" } }, env: { ANTHROPIC_BASE_URL: "https://user:pw@gw.acme.example${paths[1]}" } } });
`,
        });
        const source = langchainCodeSource({ roots: [{ label: 'acme', path: dir }] });
        const result = await read(source);
        expect(result.observations.length).toBe(paths.length + 1);
        const logged: string[] = [];
        const { raw, body } = await runScan({
            config: parseScannerConfig({ estate: 'acme-code', scanner: { agentId: 'agt', signingKeyEnv: 'K' }, schedule: { everyHours: 24 }, sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: dir }] }], outputs: [{ kind: 'stdout' }] }),
            env: { K: generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
            log: jsonLineLog((line) => logged.push(line)),
            fetchImpl: async () => {
                throw new Error('the code source makes no request');
            },
        });
        const everything = `${JSON.stringify(result)}\n${raw}\n${logged.join('\n')}`;
        // Each agent's model and MCP server are still found, at their origins.
        const endpoints = body.agents.flatMap((a) => (a.models ?? []).map((m) => m.endpoint));
        expect(endpoints.filter((e) => e === 'https://gw.acme.example:8443')).toHaveLength(paths.length);
        expect(endpoints).toContain('https://gw.acme.example');
        const servers = body.agents.flatMap((a) => a.tools.filter((t) => t.name.endsWith(':*')).map((t) => t.server));
        expect(servers.filter((s) => s === 'https://mcp.acme.example')).toHaveLength(paths.length);
        expect(servers).toContain('https://crm.acme.example');
        // In the signed report: no path segment, query, fragment or user information of any of them.
        for (const path of paths) for (const segment of path.split('/').filter((p) => p.length > 2)) expect(raw).not.toContain(segment);
        for (const part of ['also-not-kept', 'nor-this', 'user:pw', 'mcpEndpoint']) expect(raw).not.toContain(part);
        // In memory the MCP server's whole endpoint is kept for one comparison (below), and nothing else is.
        const kept = everything.split(paths[0].split('/').pop()!).length - 1;
        expect(kept).toBe(2);
        expect(JSON.stringify(result.observations.map((o) => ({ ...o, tools: o.tools?.map((t) => t.tool) })))).not.toContain(paths[0].split('/').pop()!);
    });

    it('a model whose endpoint cannot be known statically is reported where it is configured, never dropped', async () => {
        const dir = estate({
            'local/agent.py': `from langgraph.prebuilt import create_react_agent

local_agent = create_react_agent("house-model-7", [])
`,
        });
        const result = await read(langchainCodeSource({ roots: [{ label: 'acme', path: dir }] }));
        expect(result.status).toBe('COMPLETE');
        expect(result.observations[0].models).toEqual([{ endpoint: 'code://acme/local/agent.py#L3', model: 'house-model-7' }]);
    });

    it('a model name is repeated only when it is shaped like one; anything else is reported as not known, with its entry kept', async () => {
        // Real names, of every form the readers meet.
        for (const name of [
            'gpt-4o-mini',
            'claude-3-5-sonnet-20241022',
            'anthropic.claude-3-sonnet-20240229-v1:0',
            'meta-llama/Llama-3-70b-chat-hf',
            'models/gemini-1.5-pro',
            'llama3.2:3b-instruct-q4_K_M',
            'ft:gpt-4o-mini-2024-07-18:acme::9abcDEF',
            'prod-gpt4@eastus',
        ]) {
            expect(reportableModelName(name)).toBe(name);
        }
        // Not names: a credential with no known shape pasted where the model goes, in hex and in base62;
        // a sentence; a path with a space; something over the length; a leading separator; a known key shape.
        const HEX_TOKEN = 'a3f1'.repeat(10);
        const BASE62_TOKEN = 'Zx9Qm2Lk8Vb4Nc7Ht5Rj1Wp6Ys3Df0GaUeIoPqXz';
        expect(looksLikeSecret(HEX_TOKEN)).toBe(false);
        expect(looksLikeSecret(BASE62_TOKEN)).toBe(false);
        for (const notAName of [HEX_TOKEN, BASE62_TOKEN, `prefix-${HEX_TOKEN}`, 'my model', 'a'.repeat(101), '-gpt-4', '', 'gpt 4o', 'model;drop', fakeOpenAiKey()]) {
            expect(reportableModelName(notAName)).toBeNull();
        }
        // A 31-character run is still a name; the limit is 32.
        expect(reportableModelName(`m-${'a'.repeat(31)}`)).toBe(`m-${'a'.repeat(31)}`);
        expect(reportableModelName(`m-${'a'.repeat(32)}`)).toBeNull();

        // Through the reader and into a signed report: the token is nowhere, and the model entry is still there.
        const dir = estate({
            'pasted/agent.py': `from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

llm = ChatOpenAI(model="${HEX_TOKEN}")
pasted_agent = create_react_agent(llm, [])
`,
            'pasted/other.py': `from langgraph.prebuilt import create_react_agent

string_agent = create_react_agent("${BASE62_TOKEN}", [])
`,
        });
        const result = await read(langchainCodeSource({ roots: [{ label: 'acme', path: dir }] }));
        expect(result.status).toBe('COMPLETE');
        const models = Object.fromEntries(result.observations.map((o) => [o.discoveredId, o.models]));
        expect(models['code:acme/pasted/agent.py#pasted_agent']).toEqual([{ endpoint: 'https://api.openai.com/v1', model: null }]);
        expect(models['code:acme/pasted/other.py#string_agent']).toEqual([{ endpoint: 'code://acme/pasted/other.py#L3', model: null }]);
        expect(JSON.stringify(result)).not.toContain(HEX_TOKEN);
        expect(JSON.stringify(result)).not.toContain(BASE62_TOKEN);

        const { privateKey } = generateKeyPairSync('ed25519');
        const { raw } = await runScan({
            config: parseScannerConfig({
                estate: 'acme-code',
                scanner: { agentId: 'agt_scanner_code', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
                inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
                schedule: { everyHours: 24 },
                sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: dir }] }],
            }),
            env: { SCANNER_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
            log: jsonLineLog(() => undefined),
            fetchImpl: async () => {
                throw new Error('the code source makes no request');
            },
        });
        expect(raw).not.toContain(HEX_TOKEN);
        expect(raw).not.toContain(BASE62_TOKEN);
    });

    it('the configuration takes no credential for the code source, and refuses a relative or escaping root', () => {
        const base = {
            estate: 'acme-code',
            scanner: { agentId: 'agt', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
            inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
            schedule: { everyHours: 24 },
        };
        for (const path of ['relative/repo', '/estate/../etc', '/estate/repo\u0000x']) {
            expect(() =>
                parseScannerConfig({ ...base, sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path }] }] }),
            ).toThrow(/sources\.0\.roots\.0\.path/);
        }
        expect(() =>
            parseScannerConfig({ ...base, sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'a', path: '/x' }], tokenEnv: 'X' }] }),
        ).toThrow(/unrecognized_keys/);
    });
});
