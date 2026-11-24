/**
 * What the prober's wire sends, recorded over whole runs on every interface
 * and held to one list: the scope's endpoints, POST only, redirects refused,
 * the engagement header on every request, the JSON-RPC methods the wire
 * names and no other, `tools/call` of a scope tool only, and a credential only
 * to its own endpoint. The checker is shown to catch what it is for.
 */
import { ENGAGEMENT_HEADER, runProbes, type ScopeTarget } from '../src/runner';
import { verifyEngagementScope } from '../src/scope';
import { signScope } from '../src/scope-sign';
import { PROBE_A2A_MESSAGES, PROBE_MCP_MESSAGES, createProbeWire } from '../src/wire';
import { PLANTED_MARKER, obedient, resistant } from './helpers/fake-agents';
import { fakeServers, listedTool, type LoggedRequest } from './helpers/fake-servers';
import { fakeClock } from './helpers/fake-transport';
import { MCP_TOOL, START_MS, a2aTarget, chatTarget, makeKey, mcpTarget, scopeBody } from './helpers/scope-keys';

const approver = makeKey();
const prober = makeKey();
const MCP = 'https://mcp.estate.example/mcp';
const A2A = 'https://a2a.estate.example/tasks';
const CHAT = 'https://chat.estate.example/api/turn';

/** Every way a recorded request leaves what the scope and the wire allow. */
function surfaceProblems(log: readonly LoggedRequest[], targets: readonly ScopeTarget[], engagementId: string, credentials: ReadonlyMap<string, string>): string[] {
    const problems: string[] = [];
    log.forEach((r, i) => {
        const target = targets.find((t) => t.endpoint === r.url);
        if (target === undefined) return void problems.push(`${i}: not a scope endpoint`);
        if (r.method !== 'POST') problems.push(`${i}: not a POST`);
        if (r.redirect !== 'error') problems.push(`${i}: redirects not refused`);
        if (r.headers[ENGAGEMENT_HEADER.toLowerCase()] !== engagementId) problems.push(`${i}: no engagement header`);
        const token = credentials.get(r.url);
        if (r.headers.authorization !== (token === undefined ? undefined : `Bearer ${token}`)) problems.push(`${i}: a credential not named for this endpoint`);
        const body = r.body as { method?: string; params?: { name?: string; arguments?: Record<string, unknown> } };
        if (target.kind === 'mcp') {
            if (!(PROBE_MCP_MESSAGES as readonly string[]).includes(body.method ?? '')) problems.push(`${i}: an MCP method the wire does not send`);
            if (body.method === 'tools/call') {
                const tool = target.tools.find((t) => t.name === body.params?.name);
                if (tool === undefined) problems.push(`${i}: a tool the scope does not name`);
                else if (Object.keys(body.params?.arguments ?? {}).join() !== tool.argument) problems.push(`${i}: an argument the scope does not name`);
            }
        } else if (target.kind === 'a2a') {
            if (!(PROBE_A2A_MESSAGES as readonly string[]).includes(body.method ?? '')) problems.push(`${i}: an A2A method the wire does not send`);
        } else if (body.method !== undefined || r.body === undefined) {
            problems.push(`${i}: a chat request that is not the scope's template`);
        }
    });
    return problems;
}

async function fullRun(credentials: ReadonlyMap<string, string> = new Map()) {
    const targets = [mcpTarget(MCP, [MCP_TOOL, { name: 'lookup', argument: 'text' }]), a2aTarget(A2A), chatTarget(CHAT)];
    const verified = verifyEngagementScope(signScope(scopeBody(prober, { targets, ratePerMinute: 120 }), approver), {
        trustedScopeKeys: [approver.hex],
        proberKey: prober.hex,
    });
    if (!verified.ok) throw new Error(verified.reason);
    const world = fakeServers({
        [MCP]: {
            kind: 'mcp',
            agent: obedient,
            sse: true,
            tools: [listedTool(MCP_TOOL.name, MCP_TOOL.argument), listedTool('lookup', 'text'), listedTool('delete_order', 'id')],
            ...(credentials.has(MCP) ? { token: credentials.get(MCP) } : {}),
        },
        [A2A]: { kind: 'a2a', agent: resistant, answerAs: 'task' },
        [CHAT]: { kind: 'http-chat', agent: obedient },
    });
    const clock = fakeClock(START_MS);
    const run = await runProbes({
        scope: verified,
        transport: createProbeWire({ fetchImpl: world.fetchImpl, credentials }),
        now: clock.now,
        sleep: clock.sleep,
        plantedContext: [PLANTED_MARKER],
    });
    return { run, log: world.log, targets: verified.scope.targets };
}

describe('the requests a whole run makes', () => {
    it('are every one of them on the list, on all three interfaces', async () => {
        const credentials = new Map([[MCP, 'mcp-token']]);
        const { run, log, targets } = await fullRun(credentials);
        expect(run.targets.map((t) => t.reason)).toEqual(['REACHED', 'REACHED', 'REACHED']);
        expect(log.length).toBeGreaterThan(20);
        expect(surfaceProblems(log, targets, 'eng-2026-12-acme', credentials)).toEqual([]);
        // Every method the wire may send was sent: the list is not wider than what runs.
        const sent = new Set(log.map((r) => (r.body as { method?: string }).method).filter((m): m is string => m !== undefined));
        expect(sent).toEqual(new Set([...PROBE_MCP_MESSAGES, ...PROBE_A2A_MESSAGES]));
    });
});

describe('the checker', () => {
    it('catches a request to another host, another tool, another method, a stray credential, a followed redirect, a missing header', async () => {
        const credentials = new Map([[MCP, 'mcp-token']]);
        const { log, targets } = await fullRun(credentials);
        const call = log.find((r) => (r.body as { method?: string }).method === 'tools/call') as LoggedRequest;
        const chat = log.find((r) => r.url === CHAT) as LoggedRequest;
        const bad: [string, LoggedRequest][] = [
            ['another host', { ...chat, url: 'https://elsewhere.example/api' }],
            ['another tool', { ...call, body: { ...(call.body as object), params: { name: 'delete_order', arguments: { id: '1' } } } }],
            ['another argument', { ...call, body: { ...(call.body as object), params: { name: MCP_TOOL.name, arguments: { other: 'x' } } } }],
            ['another method', { ...call, body: { ...(call.body as object), method: 'resources/read' } }],
            ['a GET', { ...chat, method: 'GET' }],
            ['a followed redirect', { ...chat, redirect: 'follow' }],
            ['a stray credential', { ...chat, headers: { ...chat.headers, authorization: 'Bearer mcp-token' } }],
            ['no engagement header', { ...chat, headers: {} }],
        ];
        for (const [what, request] of bad) {
            expect([what, surfaceProblems([...log, request], targets, 'eng-2026-12-acme', credentials).length]).toEqual([what, 1]);
        }
    });
});
