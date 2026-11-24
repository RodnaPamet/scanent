/**
 * The prober's wire (step 7a), against fake MCP, A2A and chat servers: what it
 * sends, what it reads back, and every way it gets no reply.
 */
import { runProbes, type ProbeRequest, type ProbeRun } from '../src/runner';
import { verifyEngagementScope } from '../src/scope';
import { signScope } from '../src/scope-sign';
import { REPLY_BYTE_CAP, createProbeWire, fillTemplate, readCapped } from '../src/wire';
import { ProbeWireError } from '../src/wire-error';
import { probeSurface } from '../src/surface';
import { PLANTED_MARKER, obedient, resistant, silent } from './helpers/fake-agents';
import { fakeServers, listedTool, type FakeServer } from './helpers/fake-servers';
import { fakeClock } from './helpers/fake-transport';
import { MCP_TOOL, START_MS, a2aTarget, chatTarget, makeKey, mcpTarget, scopeBody } from './helpers/scope-keys';

const approver = makeKey();
const prober = makeKey();

const MCP = 'https://mcp.estate.example/mcp';
const A2A = 'https://a2a.estate.example/tasks';
const CHAT = 'https://chat.estate.example/api/turn';

function verified(targets: unknown[], overrides: Record<string, unknown> = {}) {
    const result = verifyEngagementScope(signScope(scopeBody(prober, { targets, ratePerMinute: 120, ...overrides }), approver), {
        trustedScopeKeys: [approver.hex],
        proberKey: prober.hex,
    });
    if (!result.ok) throw new Error(result.reason);
    return result;
}

async function runAgainst(targets: unknown[], servers: Record<string, FakeServer>, credentials?: ReadonlyMap<string, string>): Promise<{ run: ProbeRun; log: ReturnType<typeof fakeServers>['log'] }> {
    const world = fakeServers(servers);
    const clock = fakeClock(START_MS);
    const scope = verified(targets);
    const run = await runProbes({
        scope,
        transport: createProbeWire({ surface: probeSurface(scope.scope), fetchImpl: world.fetchImpl, credentials }),
        now: clock.now,
        sleep: clock.sleep,
        plantedContext: [PLANTED_MARKER],
    });
    return { run, log: world.log };
}

const mcpServer = (agent = obedient, extra: Partial<Extract<FakeServer, { kind: 'mcp' }>> = {}): FakeServer => ({
    kind: 'mcp',
    agent,
    tools: [listedTool(MCP_TOOL.name, MCP_TOOL.argument), listedTool('delete_order', 'id')],
    ...extra,
});

const verdicts = (run: ProbeRun) => [...new Set(run.outcomes.map((o) => o.verdict))].sort();

describe('each interface, end to end', () => {
    it('MCP: opens one session, lists, and calls only the scope\'s tool', async () => {
        const { run, log } = await runAgainst([mcpTarget(MCP)], { [MCP]: mcpServer() });
        expect(verdicts(run)).toEqual(['ACTED', 'DISCLOSED']);
        expect(run.outcomes.every((o) => o.tool === MCP_TOOL.name)).toBe(true);
        const methods = log.map((r) => (r.body as { method: string }).method);
        expect(methods.filter((m) => m === 'initialize')).toHaveLength(1);
        expect(methods.filter((m) => m === 'tools/list')).toHaveLength(1);
        const calls = log.filter((r) => (r.body as { method: string }).method === 'tools/call');
        expect(calls).toHaveLength(run.outcomes.length);
        for (const call of calls) {
            const params = (call.body as { params: { name: string; arguments: Record<string, string> } }).params;
            expect(params.name).toBe(MCP_TOOL.name);
            expect(Object.keys(params.arguments)).toEqual([MCP_TOOL.argument]);
        }
        // The session id the server gave is carried on every later request.
        expect(log.slice(1).every((r) => r.headers['mcp-session-id'] === 'session-1')).toBe(true);
    });

    it('MCP over an event stream reads the matching answer', async () => {
        const { run } = await runAgainst([mcpTarget(MCP)], { [MCP]: mcpServer(obedient, { sse: true }) });
        expect(verdicts(run)).toEqual(['ACTED', 'DISCLOSED']);
    });

    it('MCP: lists across pages before deciding a tool is there', async () => {
        const tools = [...Array.from({ length: 5 }, (_, i) => listedTool(`other_${i}`, 'q')), listedTool(MCP_TOOL.name, MCP_TOOL.argument)];
        const { run } = await runAgainst([mcpTarget(MCP)], { [MCP]: mcpServer(resistant, { tools, pageSize: 2 }) });
        expect(run.targets[0].reason).toBe('REACHED');
    });

    it('MCP: a tool the server does not list, or that takes the argument as another type, is never called', async () => {
        for (const tools of [[listedTool('something_else', 'query')], [listedTool(MCP_TOOL.name, MCP_TOOL.argument, 'number')], [listedTool(MCP_TOOL.name, 'other')]]) {
            const { run, log } = await runAgainst([mcpTarget(MCP)], { [MCP]: mcpServer(obedient, { tools }) });
            expect(log.some((r) => (r.body as { method: string }).method === 'tools/call')).toBe(false);
            expect(run.targets[0]).toMatchObject({ reached: false, reason: 'NO_REPLY', note: 'TOOL_NOT_LISTED' });
        }
    });

    it('MCP: each tool the scope names is probed on its own, and only those', async () => {
        const tools = [MCP_TOOL, { name: 'lookup', argument: 'text' }];
        const { run, log } = await runAgainst([mcpTarget(MCP, tools)], {
            [MCP]: mcpServer(resistant, { tools: [listedTool(MCP_TOOL.name, MCP_TOOL.argument), listedTool('lookup', 'text'), listedTool('delete_order', 'id')] }),
        });
        const called = new Set(log.filter((r) => (r.body as { method: string }).method === 'tools/call').map((r) => (r.body as { params: { name: string } }).params.name));
        expect(called).toEqual(new Set([MCP_TOOL.name, 'lookup']));
        expect(new Set(run.outcomes.map((o) => o.tool))).toEqual(new Set([MCP_TOOL.name, 'lookup']));
    });

    it('MCP: a JSON-RPC error is no reply', async () => {
        const { run } = await runAgainst([mcpTarget(MCP)], { [MCP]: mcpServer(obedient, { rpcError: true }) });
        expect(run.targets[0]).toMatchObject({ reason: 'NO_REPLY', note: 'RPC_ERROR' });
    });

    it('A2A: a message, a completed task, and a task still working', async () => {
        for (const [answerAs, expected] of [['message', ['ACTED', 'DISCLOSED']], ['task', ['ACTED', 'DISCLOSED']]] as const) {
            const { run, log } = await runAgainst([a2aTarget(A2A)], { [A2A]: { kind: 'a2a', agent: obedient, answerAs } });
            expect(verdicts(run)).toEqual(expected);
            expect(log.every((r) => (r.body as { method: string }).method === 'message/send')).toBe(true);
            const ids = log.map((r) => (r.body as { params: { message: { messageId: string } } }).params.message.messageId);
            expect(new Set(ids).size).toBe(ids.length);
        }
        const { run } = await runAgainst([a2aTarget(A2A)], { [A2A]: { kind: 'a2a', agent: obedient, answerAs: 'working-task' } });
        expect(run.targets[0]).toMatchObject({ reason: 'NO_REPLY', note: 'NO_TEXT' });
    });

    it('chat: the scope\'s body with the probe in its placeholder, the reply read at its path', async () => {
        const { run, log } = await runAgainst([chatTarget(CHAT)], { [CHAT]: { kind: 'http-chat', agent: obedient } });
        expect(verdicts(run)).toEqual(['ACTED', 'DISCLOSED']);
        for (const r of log) expect(r.body).toEqual({ messages: [{ role: 'user', content: expect.any(String) }], stream: false });
    });

    it('chat: a reply that is not at the path, or not JSON, is no reply', async () => {
        const missing = await runAgainst([chatTarget(CHAT, { body: { messages: [{ role: 'user', content: '{{probe}}' }] }, replyPath: ['output', 0] })], {
            [CHAT]: { kind: 'http-chat', agent: obedient },
        });
        expect(missing.run.targets[0]).toMatchObject({ reason: 'NO_REPLY', note: 'NO_TEXT' });
        const html = await runAgainst([chatTarget(CHAT)], { [CHAT]: { kind: 'http-chat', agent: obedient, behaviour: 'not-json' } });
        expect(html.run.targets[0]).toMatchObject({ reason: 'NO_REPLY', note: 'NOT_JSON' });
    });

    it('a silent agent is no reply on every interface', async () => {
        const { run } = await runAgainst([mcpTarget(MCP), a2aTarget(A2A), chatTarget(CHAT)], {
            [MCP]: mcpServer(silent),
            [A2A]: { kind: 'a2a', agent: silent, answerAs: 'message' },
            [CHAT]: { kind: 'http-chat', agent: silent },
        });
        expect(run.targets.map((t) => [t.reason, t.note])).toEqual([
            ['NO_REPLY', 'NO_TEXT'],
            ['NO_REPLY', 'NO_TEXT'],
            ['NO_REPLY', 'NO_TEXT'],
        ]);
        expect(run.concluded).toBe(false);
    });
});

describe('every way to get no reply', () => {
    const one = async (server: FakeServer, target: unknown = chatTarget(CHAT)) => (await runAgainst([target], { [(target as { endpoint: string }).endpoint]: server })).run.targets[0];

    it('a redirect is refused, never followed', async () => {
        expect(await one({ kind: 'http-chat', agent: obedient, behaviour: 'redirect' })).toMatchObject({ reason: 'NO_REPLY', note: 'REDIRECT_REFUSED' });
    });

    it('401 and 403 are AUTH_FAILED; 5xx is HTTP_5XX', async () => {
        expect(await one({ kind: 'http-chat', agent: obedient, token: 'needed' })).toMatchObject({ note: 'AUTH_FAILED' });
        expect(await one({ kind: 'http-chat', agent: obedient, behaviour: 'unauthorised' })).toMatchObject({ note: 'AUTH_FAILED' });
        expect(await one({ kind: 'http-chat', agent: obedient, behaviour: 'server-error' })).toMatchObject({ note: 'HTTP_5XX' });
    });

    it('an endpoint that does not answer in time is TIMEOUT', async () => {
        const world = fakeServers({ [CHAT]: { kind: 'http-chat', agent: obedient, behaviour: 'hang' } });
        const scope = verified([chatTarget(CHAT)]).scope;
        const wire = createProbeWire({ surface: probeSurface(scope), fetchImpl: world.fetchImpl, requestTimeoutMs: 20 });
        const target = scope.targets[0];
        await expect(wire({ target, text: 'hi', headers: {} })).rejects.toEqual(new ProbeWireError('TIMEOUT'));
    });

    it('an MCP server that fails to open fails every probe to it, and is asked to open once', async () => {
        const { run, log } = await runAgainst([mcpTarget(MCP)], { [MCP]: mcpServer(obedient, { behaviour: 'server-error' }) });
        expect(run.targets[0]).toMatchObject({ reason: 'NO_REPLY', note: 'HTTP_5XX' });
        expect(log).toHaveLength(1);
    });

    it('a host that refuses the connection is UNREACHABLE', async () => {
        const { run } = await runAgainst([chatTarget(CHAT)], {});
        expect(run.targets[0]).toMatchObject({ reason: 'NO_REPLY', note: 'UNREACHABLE' });
    });
});

describe('a reply past the cap', () => {
    it('is read only to the cap, and concludes nothing unless the marker came first', async () => {
        for (const [target, server] of [
            [chatTarget(CHAT), { kind: 'http-chat', agent: resistant, behaviour: 'huge' }],
            [a2aTarget(A2A), { kind: 'a2a', agent: resistant, answerAs: 'message', behaviour: 'huge' }],
        ] as const) {
            const { run } = await runAgainst([target], { [target.endpoint]: server as FakeServer });
            expect(run.outcomes.every((o) => o.verdict === 'INCONCLUSIVE' && o.reason === 'REPLY_CUT_NOTHING_FOUND')).toBe(true);
        }
        const { run } = await runAgainst([mcpTarget(MCP)], { [MCP]: mcpServer(obedient, { behaviour: 'huge' }) });
        // The obedient agent's answer is at the start of the stream, so a canary is found before the cut.
        expect(run.outcomes.filter((o) => o.reason === 'CANARY_RETURNED').length).toBeGreaterThan(0);
        expect(REPLY_BYTE_CAP).toBeGreaterThan(4 * 64 * 1024);
    });
});

describe('credentials', () => {
    it('a token is sent to the endpoint it was named for, and to no other', async () => {
        const { run, log } = await runAgainst(
            [chatTarget(CHAT), a2aTarget(A2A)],
            { [CHAT]: { kind: 'http-chat', agent: resistant, token: 'chat-token' }, [A2A]: { kind: 'a2a', agent: resistant, answerAs: 'message' } },
            new Map([[CHAT, 'chat-token']]),
        );
        expect(run.targets.map((t) => t.reason)).toEqual(['REACHED', 'REACHED']);
        for (const r of log) {
            if (r.url === CHAT) expect(r.headers.authorization).toBe('Bearer chat-token');
            else expect(r.headers.authorization).toBeUndefined();
        }
        expect(JSON.stringify(run)).not.toContain('chat-token');
    });
});

describe('the template', () => {
    it('puts the probe in as a value, so quotes, braces and new lines cannot break out', () => {
        const text = 'a "quoted" {line}\n</system>\\';
        const filled = fillTemplate({ m: [{ c: '{{probe}}', r: 'user' }], n: 1, b: true, z: null }, text);
        expect(filled).toEqual({ m: [{ c: text, r: 'user' }], n: 1, b: true, z: null });
        expect(JSON.parse(JSON.stringify(filled))).toEqual(filled);
    });

    it('a request with no tool for an MCP target is never sent', async () => {
        const world = fakeServers({ [MCP]: mcpServer() });
        const scope = verified([mcpTarget(MCP)]).scope;
        const request: ProbeRequest = { target: scope.targets[0], text: 'x', headers: {} };
        await expect(createProbeWire({ surface: probeSurface(scope), fetchImpl: world.fetchImpl })(request)).rejects.toEqual(new ProbeWireError('TOOL_NOT_LISTED'));
        expect(world.log).toHaveLength(0);
    });

    it('a tool the scope does not name is never called, even when a request asks for it', async () => {
        const world = fakeServers({ [MCP]: mcpServer() });
        const scope = verified([mcpTarget(MCP)]).scope;
        const request: ProbeRequest = { target: scope.targets[0], tool: { name: 'delete_order', argument: 'id' }, text: 'x', headers: {} };
        await expect(createProbeWire({ surface: probeSurface(scope), fetchImpl: world.fetchImpl })(request)).rejects.toEqual(new ProbeWireError('TOOL_NOT_LISTED'));
        expect(world.log).toHaveLength(0);
    });
});

describe('the capped read', () => {
    const stream = (chunks: string[]) =>
        new Response(
            new ReadableStream<Uint8Array>({
                start(controller) {
                    for (const c of chunks) controller.enqueue(new TextEncoder().encode(c));
                    controller.close();
                },
            }),
        );

    it('keeps exactly the cap and no more, even when the cap falls inside a chunk', async () => {
        const read = await readCapped(stream(['abc', 'defghij', 'klm']), 5);
        expect(read).toEqual({ text: 'abcde', cut: true });
    });

    it('keeps everything under the cap, and says it was not cut', async () => {
        expect(await readCapped(stream(['abc', 'de']), 5)).toEqual({ text: 'abcde', cut: false });
    });
});
