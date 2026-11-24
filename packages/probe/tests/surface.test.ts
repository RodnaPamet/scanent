/**
 * The declared surface of an engagement, and the check the wire makes against
 * it before every request.
 */
import { createProbeWire } from '../src/wire';
import { ProbeWireError } from '../src/wire-error';
import { PROBE_VERSION, matchesTemplate, offSurface, onSurface, probeSurface, surfaceDigest } from '../src/surface';
import { verifyEngagementScope, type EngagementScope } from '../src/scope';
import { signScope } from '../src/scope-sign';
import { catalogueDigest } from '../src/report';
import { obedient } from './helpers/fake-agents';
import { fakeServers, listedTool } from './helpers/fake-servers';
import { CHAT_REQUEST, MCP_TOOL, a2aTarget, chatTarget, makeKey, mcpTarget, scopeBody } from './helpers/scope-keys';

const approver = makeKey();
const prober = makeKey();
const MCP = 'https://mcp.estate.example/mcp';
const A2A = 'https://a2a.estate.example/tasks';
const CHAT = 'https://chat.estate.example/api/turn';

function scopeOf(overrides: Record<string, unknown> = {}): EngagementScope {
    const result = verifyEngagementScope(
        signScope(scopeBody(prober, { targets: [mcpTarget(MCP), a2aTarget(A2A), chatTarget(CHAT)], ...overrides }), approver),
        { trustedScopeKeys: [approver.hex], proberKey: prober.hex },
    );
    if (!result.ok) throw new Error(result.reason);
    return result.scope;
}

const rpc = (method: string, params: unknown = {}) => ({ jsonrpc: '2.0', id: 1, method, params });

describe('the surface of an engagement', () => {
    it('is built from the scope and the code\'s constants alone', () => {
        const surface = probeSurface(scopeOf());
        expect(surface).toEqual({
            name: 'scanent-probe',
            version: PROBE_VERSION,
            catalogue: catalogueDigest(),
            engagement: 'eng-2026-12-acme',
            targets: [
                { endpoint: MCP, kind: 'mcp', method: 'POST', messages: ['initialize', 'notifications/initialized', 'tools/list', 'tools/call'], tools: [MCP_TOOL] },
                { endpoint: A2A, kind: 'a2a', method: 'POST', messages: ['message/send'] },
                { endpoint: CHAT, kind: 'http-chat', method: 'POST', messages: [], body: CHAT_REQUEST.body },
            ],
        });
        expect(surfaceDigest(surface)).toBe(surfaceDigest(probeSurface(scopeOf())));
        expect(surfaceDigest(surface)).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it('has a digest that moves with every part of the scope it is built from', () => {
        const base = surfaceDigest(probeSurface(scopeOf()));
        const changes: Record<string, unknown>[] = [
            { engagementId: 'eng-2026-12-other' },
            { targets: [mcpTarget(MCP, [{ name: 'lookup', argument: 'text' }]), a2aTarget(A2A), chatTarget(CHAT)] },
            { targets: [mcpTarget(MCP), a2aTarget(A2A)] },
            { targets: [mcpTarget(MCP), a2aTarget(A2A), chatTarget(CHAT, { body: { prompt: '{{probe}}' }, replyPath: ['reply'] })] },
        ];
        for (const change of changes) expect(surfaceDigest(probeSurface(scopeOf(change)))).not.toBe(base);
        // What the scope does not say about requests (the window, the approver) does not move it.
        expect(surfaceDigest(probeSurface(scopeOf({ ratePerMinute: 5, killContact: 'someone else' })))).toBe(base);
    });
});

describe('what the check refuses', () => {
    const surface = probeSurface(scopeOf());
    const chatBody = { messages: [{ role: 'user', content: 'a probe' }], stream: false };

    it('admits each kind of request the wire makes', () => {
        for (const method of ['initialize', 'notifications/initialized', 'tools/list']) expect(onSurface(surface, { url: MCP, method: 'POST', body: rpc(method) })).toBe(true);
        expect(onSurface(surface, { url: MCP, method: 'POST', body: rpc('tools/call', { name: MCP_TOOL.name, arguments: { [MCP_TOOL.argument]: 'a probe' } }) })).toBe(true);
        expect(onSurface(surface, { url: A2A, method: 'POST', body: rpc('message/send', { message: { kind: 'message', role: 'user', messageId: 'm', parts: [{ kind: 'text', text: 'a probe' }] } }) })).toBe(true);
        expect(onSurface(surface, { url: CHAT, method: 'POST', body: chatBody })).toBe(true);
    });

    it.each([
        ['another host', { url: 'https://elsewhere.example/mcp', method: 'POST', body: rpc('tools/list') }, 'not an endpoint of the scope'],
        ['a GET', { url: MCP, method: 'GET', body: rpc('tools/list') }, 'not the method the surface names'],
        ['another MCP message', { url: MCP, method: 'POST', body: rpc('resources/read') }, 'a JSON-RPC message the surface does not name'],
        ['an A2A message to an MCP target', { url: MCP, method: 'POST', body: rpc('message/send') }, 'a JSON-RPC message the surface does not name'],
        ['another tool', { url: MCP, method: 'POST', body: rpc('tools/call', { name: 'delete_order', arguments: { id: '1' } }) }, 'a tool the scope does not name'],
        ['another argument', { url: MCP, method: 'POST', body: rpc('tools/call', { name: MCP_TOOL.name, arguments: { other: 'x' } }) }, 'an argument the scope does not name'],
        ['a second argument', { url: MCP, method: 'POST', body: rpc('tools/call', { name: MCP_TOOL.name, arguments: { [MCP_TOOL.argument]: 'x', confirm: 'yes' } }) }, 'an argument the scope does not name'],
        ['a non-string argument', { url: MCP, method: 'POST', body: rpc('tools/call', { name: MCP_TOOL.name, arguments: { [MCP_TOOL.argument]: 1 } }) }, 'an argument the scope does not name'],
        ['tools/call to A2A', { url: A2A, method: 'POST', body: rpc('tools/call') }, 'a JSON-RPC message the surface does not name'],
        ['an A2A message of two parts', { url: A2A, method: 'POST', body: rpc('message/send', { message: { parts: [{ kind: 'text', text: 'a' }, { kind: 'file' }] } }) }, 'a message of another shape'],
        ['not JSON-RPC', { url: A2A, method: 'POST', body: { hello: 'x' } }, 'not a JSON-RPC message'],
        ['a chat body with an extra key', { url: CHAT, method: 'POST', body: { ...chatBody, model: 'x' } }, "not the scope's body template filled with a probe"],
        ['a chat body with another value', { url: CHAT, method: 'POST', body: { ...chatBody, stream: true } }, "not the scope's body template filled with a probe"],
        ['a chat body with the probe elsewhere', { url: CHAT, method: 'POST', body: { messages: [{ role: 'a probe', content: 'a probe' }], stream: false } }, "not the scope's body template filled with a probe"],
    ])('%s', (_what, request, reason) => {
        expect(offSurface(surface, request)).toBe(reason);
    });

    it('matches a template leaf for leaf, arrays in order', () => {
        expect(matchesTemplate({ a: ['x', '{{probe}}'], n: 1 }, { a: ['x', 'p'], n: 1 })).toBe(true);
        expect(matchesTemplate({ a: ['x', '{{probe}}'] }, { a: ['p', 'x'] })).toBe(false);
        expect(matchesTemplate({ a: ['{{probe}}'] }, { a: ['p', 'q'] })).toBe(false);
        expect(matchesTemplate({ a: '{{probe}}' }, { a: 1 })).toBe(false);
        expect(matchesTemplate({ a: null }, { a: null })).toBe(true);
    });
});

describe('the wire refuses before anything leaves', () => {
    it('a request off the surface is OFF_SURFACE and is never sent', async () => {
        // The wire is handed the surface of a scope that names another tool: its tool call is off that surface.
        const named = scopeOf();
        const other = scopeOf({ targets: [mcpTarget(MCP, [{ name: 'lookup', argument: 'text' }]), a2aTarget(A2A), chatTarget(CHAT)] });
        const world = fakeServers({ [MCP]: { kind: 'mcp', agent: obedient, tools: [listedTool(MCP_TOOL.name, MCP_TOOL.argument)] } });
        const wire = createProbeWire({ surface: probeSurface(other), fetchImpl: world.fetchImpl });
        await expect(wire({ target: named.targets[0], tool: MCP_TOOL, text: 'x', headers: {} })).rejects.toEqual(new ProbeWireError('OFF_SURFACE'));
        // The session opened (those messages are on it); the call did not leave.
        expect(world.log.map((r) => (r.body as { method: string }).method)).toEqual(['initialize', 'notifications/initialized', 'tools/list']);
    });

    it('a chat body that is not the template is never sent', async () => {
        const named = scopeOf();
        const other = scopeOf({ targets: [mcpTarget(MCP), a2aTarget(A2A), chatTarget(CHAT, { body: { prompt: '{{probe}}' }, replyPath: ['reply'] })] });
        const world = fakeServers({ [CHAT]: { kind: 'http-chat', agent: obedient } });
        const wire = createProbeWire({ surface: probeSurface(other), fetchImpl: world.fetchImpl });
        await expect(wire({ target: named.targets[2], text: 'x', headers: {} })).rejects.toEqual(new ProbeWireError('OFF_SURFACE'));
        expect(world.log).toHaveLength(0);
    });

    it('there is no wire without a surface', () => {
        expect(() => createProbeWire({} as never)).toThrow('there is no unchecked mode');
    });
});
