/**
 * Fake MCP, A2A and chat servers as one `fetchImpl`, each answering with a
 * fake agent, and a log of every request the wire made. No socket is opened.
 */
import type { FetchLike } from '../../src/wire';
import type { FakeAgent } from './fake-agents';

export interface LoggedRequest {
    readonly url: string;
    readonly method: string;
    readonly redirect: RequestInit['redirect'];
    readonly headers: Readonly<Record<string, string>>;
    readonly body: unknown;
}

export type ServerBehaviour = 'normal' | 'redirect' | 'unauthorised' | 'server-error' | 'hang' | 'huge' | 'not-json';

interface Base {
    readonly agent: FakeAgent;
    /** When set, a request without `Authorization: Bearer <token>` is refused 401. */
    readonly token?: string;
    readonly behaviour?: ServerBehaviour;
}

export interface McpServer extends Base {
    readonly kind: 'mcp';
    readonly tools: readonly { readonly name: string; readonly inputSchema: unknown }[];
    readonly sse?: boolean;
    /** Tools listed per page: more than this pages with a cursor. */
    readonly pageSize?: number;
    /** Answer tools/call with a JSON-RPC error. */
    readonly rpcError?: boolean;
}

export interface A2aServer extends Base {
    readonly kind: 'a2a';
    readonly answerAs: 'message' | 'task' | 'working-task';
}

export interface ChatServer extends Base {
    readonly kind: 'http-chat';
}

export type FakeServer = McpServer | A2aServer | ChatServer;

const json = (body: unknown, init: ResponseInit = {}) =>
    new Response(JSON.stringify(body), { status: 200, ...init, headers: { 'content-type': 'application/json', ...(init.headers ?? {}) } });

function sse(body: unknown, headers: Record<string, string> = {}): Response {
    const events = `event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info' } })}\n\nevent: message\ndata: ${JSON.stringify(body)}\n\n`;
    return new Response(events, { status: 200, headers: { 'content-type': 'text/event-stream', ...headers } });
}

/** A stream far longer than any cap, with the given text first. */
function huge(first: string): Response {
    const chunk = new TextEncoder().encode('x'.repeat(64 * 1024));
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(new TextEncoder().encode(first));
        },
        pull(controller) {
            sent += 1;
            if (sent > 200) controller.close();
            else controller.enqueue(chunk);
        },
    });
    return new Response(stream, { status: 200, headers: { 'content-type': 'application/json' } });
}

export interface FakeWorld {
    readonly fetchImpl: FetchLike;
    readonly log: LoggedRequest[];
}

export function fakeServers(servers: Readonly<Record<string, FakeServer>>): FakeWorld {
    const log: LoggedRequest[] = [];
    const sessions = new Map<string, number>();

    const fetchImpl: FetchLike = async (url, init) => {
        const headers = Object.fromEntries(new Headers(init.headers).entries());
        const body = typeof init.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : undefined;
        log.push({ url, method: init.method ?? 'GET', redirect: init.redirect, headers, body });
        const server = servers[url];
        if (server === undefined) throw new TypeError('fetch failed: connection refused');
        if (init.method !== 'POST') return new Response(null, { status: 405 });
        if (server.token !== undefined && headers.authorization !== `Bearer ${server.token}`) return new Response(null, { status: 401 });
        switch (server.behaviour ?? 'normal') {
            case 'redirect':
                return new Response(null, { status: 302, headers: { location: 'https://elsewhere.example/' } });
            case 'unauthorised':
                return new Response(null, { status: 403 });
            case 'server-error':
                return new Response('oops', { status: 503 });
            case 'hang':
                return new Promise<Response>((_, reject) => {
                    init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('timed out'), { name: 'TimeoutError' })));
                });
            case 'not-json':
                return new Response('<html>hello</html>', { status: 200, headers: { 'content-type': 'text/html' } });
            default:
                break;
        }
        const rpc = body as { id?: number; method?: string; params?: Record<string, unknown> } | undefined;

        if (server.kind === 'http-chat') {
            const messages = (body as { messages?: { content?: string }[] }).messages;
            const text = messages?.[0]?.content ?? '';
            const reply = server.agent(text);
            if (server.behaviour === 'huge') return huge(`{"reply":"${reply ?? ''}`);
            return json({ reply });
        }

        if (server.kind === 'a2a') {
            const message = rpc?.params?.message as { parts?: { kind: string; text: string }[] } | undefined;
            const reply = server.agent(message?.parts?.[0]?.text ?? '');
            const parts = reply === null ? [] : [{ kind: 'text', text: reply }];
            if (server.behaviour === 'huge') return huge(`{"jsonrpc":"2.0","id":${rpc?.id},"result":{"kind":"message","parts":[{"kind":"text","text":"${reply ?? ''}`);
            if (server.answerAs === 'message') return json({ jsonrpc: '2.0', id: rpc?.id, result: { kind: 'message', role: 'agent', messageId: 'm1', parts } });
            if (server.answerAs === 'working-task') return json({ jsonrpc: '2.0', id: rpc?.id, result: { kind: 'task', id: 't1', status: { state: 'working' } } });
            return json({ jsonrpc: '2.0', id: rpc?.id, result: { kind: 'task', id: 't1', status: { state: 'completed' }, artifacts: [{ parts }] } });
        }

        // MCP, Streamable HTTP.
        const reply = (payload: unknown, extra: Record<string, string> = {}) => (server.sse ? sse(payload, extra) : json(payload, { headers: extra }));
        if (rpc?.method === 'initialize') {
            const id = (sessions.get(url) ?? 0) + 1;
            sessions.set(url, id);
            return reply({ jsonrpc: '2.0', id: rpc.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} } } }, { 'mcp-session-id': `session-${id}` });
        }
        if (headers['mcp-session-id'] !== `session-${sessions.get(url)}`) return new Response(null, { status: 404 });
        if (rpc?.method === 'notifications/initialized') return new Response(null, { status: 202 });
        if (rpc?.method === 'tools/list') {
            const size = server.pageSize ?? server.tools.length;
            const start = typeof rpc.params?.cursor === 'string' ? Number(rpc.params.cursor) : 0;
            const page = server.tools.slice(start, start + size);
            const next = start + size < server.tools.length ? String(start + size) : undefined;
            return reply({ jsonrpc: '2.0', id: rpc.id, result: { tools: page, ...(next === undefined ? {} : { nextCursor: next }) } });
        }
        if (rpc?.method === 'tools/call') {
            if (server.rpcError) return reply({ jsonrpc: '2.0', id: rpc.id, error: { code: -32000, message: 'no' } });
            const args = rpc.params?.arguments as Record<string, string>;
            const text = Object.values(args ?? {})[0] ?? '';
            const answer = server.agent(text);
            if (server.behaviour === 'huge') return huge(`{"jsonrpc":"2.0","id":${rpc.id},"result":{"content":[{"type":"text","text":"${answer ?? ''}`);
            return reply({ jsonrpc: '2.0', id: rpc.id, result: { content: answer === null ? [] : [{ type: 'text', text: answer }], isError: false } });
        }
        return reply({ jsonrpc: '2.0', id: rpc?.id, error: { code: -32601, message: 'method not found' } });
    };
    return { fetchImpl, log };
}

/** A tool listing entry that takes `argument` as a string. */
export const listedTool = (name: string, argument: string, type = 'string') => ({
    name,
    inputSchema: { type: 'object', properties: { [argument]: { type } }, required: [argument] },
});
