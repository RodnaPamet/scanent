/**
 * THE PROBER'S WIRE: how a probe reaches a live agent (step 7a of
 * docs/design/active-flavour.md).
 *
 * Three interfaces, each reached only at the exact endpoint the signed scope
 * names, and only in the ways listed here:
 *
 *   • mcp: once per target per run, `initialize`, `notifications/initialized`
 *     and `tools/list`; then `tools/call` of a tool the SCOPE names, with the
 *     probe in the argument the scope names. A tool the server does not list,
 *     or that does not take that argument as a string, is never called.
 *   • a2a: one JSON-RPC `message/send`, blocking, with the probe as a text
 *     part. No polling.
 *   • http-chat: one POST of the scope's own body template, with the probe in
 *     its one placeholder; the reply is read at the scope's reply path.
 *
 * The disciplines are the scanner's (`packages/scanner/src/http.ts`), written
 * again here because the prober may not import the scanner: every request is
 * a POST with `redirect: 'error'`, a per-request timeout, and a response read
 * as a stream and cut at a byte cap. A credential is sent only to the endpoint
 * it was named for. A failure is a ProbeWireError naming a code; nothing a
 * target said is kept with it.
 *
 * A reply cut at the cap is returned as the text that was read: the verdict
 * reads it, finds the marker if it came early, and otherwise concludes
 * nothing, because a cut reply is longer than a verdict reads.
 */
import { randomUUID } from 'node:crypto';

import { PROBE_PLACEHOLDER } from './scope';
import type { ProbeRequest, ProbeTransport, ScopeMcpTool, ScopeTarget } from './runner';
import { MAX_REPLY_CHARS } from './verdict';
import { ProbeWireError } from './wire-error';

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

/** The JSON-RPC messages the wire sends, and no other. */
export const PROBE_MCP_MESSAGES = ['initialize', 'notifications/initialized', 'tools/list', 'tools/call'] as const;
export const PROBE_A2A_MESSAGES = ['message/send'] as const;
export const MCP_PROTOCOL_VERSION = '2025-06-18';

export const REQUEST_TIMEOUT_MS = 60_000;
/** A reply's byte cap: past it a verdict reads no further, so the read stops. Four bytes a character, at most. */
export const REPLY_BYTE_CAP = 4 * MAX_REPLY_CHARS + 4;
/** The cap on a session message (`initialize`, `tools/list`): a listing, not a reply. */
export const SESSION_BYTE_CAP = 1024 * 1024;
export const MAX_TOOL_PAGES = 20;
export const MAX_LISTED_TOOLS = 5_000;

export interface WireDeps {
    /** A TEST SEAM: production uses the global `fetch`. */
    readonly fetchImpl?: FetchLike;
    /** The token for each endpoint that needs one, already read from the prober's environment. */
    readonly credentials?: ReadonlyMap<string, string>;
    readonly requestTimeoutMs?: number;
}

interface Read {
    readonly text: string;
    readonly cut: boolean;
}

interface McpSession {
    readonly sessionId: string | null;
    readonly protocolVersion: string;
    /** Each listed tool's input schema, by name. */
    readonly tools: ReadonlyMap<string, unknown>;
}

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/** The body as a stream, cut at the cap: never more than the cap is held. */
export async function readCapped(res: Response, cap: number): Promise<Read> {
    if (res.body === null) return { text: '', cut: false };
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    let total = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > cap) {
                const keep = value.byteLength - (total - cap);
                text += decoder.decode(value.subarray(0, Math.max(0, keep)));
                await reader.cancel();
                return { text, cut: true };
            }
            text += decoder.decode(value, { stream: true });
        }
        return { text: text + decoder.decode(), cut: false };
    } catch (err) {
        await reader.cancel().catch(() => undefined);
        throw err;
    }
}

/** The JSON-RPC response with this id, from a JSON body or an event stream. */
function rpcResponseFrom(read: Read, contentType: string, id: number): Record<string, unknown> {
    const candidates: unknown[] = [];
    if (contentType.includes('text/event-stream')) {
        for (const event of read.text.split(/\r?\n\r?\n/)) {
            const data = event
                .split(/\r?\n/)
                .filter((l) => l.startsWith('data:'))
                .map((l) => l.slice(5).replace(/^ /, ''))
                .join('\n');
            if (data === '') continue;
            try {
                candidates.push(JSON.parse(data));
            } catch {
                // A partial event at a cut, or one that is not JSON: not the answer.
            }
        }
    } else {
        try {
            candidates.push(JSON.parse(read.text));
        } catch {
            throw new ProbeWireError('NOT_JSON');
        }
    }
    const answer = candidates.find((c): c is Record<string, unknown> => isObject(c) && c.id === id && ('result' in c || 'error' in c));
    if (answer === undefined) throw new ProbeWireError('NOT_JSON');
    if ('error' in answer) throw new ProbeWireError('RPC_ERROR');
    return answer;
}

/** Every `text` of a list of parts or content items. */
function textsOf(items: unknown, typeKey: 'type' | 'kind'): string[] {
    if (!Array.isArray(items)) return [];
    return items.filter((i): i is Record<string, unknown> => isObject(i) && i[typeKey] === 'text' && typeof i.text === 'string').map((i) => i.text as string);
}

/** The scope's body template with its one placeholder leaf replaced: a deep copy, so escaping is JSON's own. */
export function fillTemplate(template: unknown, text: string): unknown {
    if (template === PROBE_PLACEHOLDER) return text;
    if (Array.isArray(template)) return template.map((item) => fillTemplate(item, text));
    if (isObject(template)) return Object.fromEntries(Object.entries(template).map(([k, v]) => [k, fillTemplate(v, text)]));
    return template;
}

/** The value at a reply path, or undefined. */
function atPath(value: unknown, path: readonly (string | number)[]): unknown {
    let node = value;
    for (const step of path) {
        if (typeof step === 'number') {
            if (!Array.isArray(node) || step >= node.length) return undefined;
            node = node[step];
        } else {
            if (!isObject(node) || !Object.prototype.hasOwnProperty.call(node, step)) return undefined;
            node = node[step];
        }
    }
    return node;
}

export function createProbeWire(deps: WireDeps = {}): ProbeTransport {
    const fetchImpl: FetchLike = deps.fetchImpl ?? ((url, init) => fetch(url, init));
    const timeoutMs = deps.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
    const credentials = deps.credentials ?? new Map<string, string>();
    const sessions = new Map<string, Promise<McpSession>>();
    let rpcId = 0;

    /** One POST to the target's own endpoint, and nowhere else. */
    async function post(
        target: ScopeTarget,
        request: ProbeRequest,
        body: unknown,
        extra: Readonly<Record<string, string>>,
    ): Promise<Response> {
        const headers: Record<string, string> = {
            ...request.headers,
            ...extra,
            'Content-Type': 'application/json',
            Accept: 'application/json, text/event-stream',
        };
        // The token named for this endpoint, sent to this endpoint: the URL posted to IS the endpoint.
        const token = credentials.get(target.endpoint);
        if (token !== undefined) headers.Authorization = `Bearer ${token}`;
        let res: Response;
        try {
            res = await fetchImpl(target.endpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
                redirect: 'error',
                signal: AbortSignal.timeout(timeoutMs),
            });
        } catch (err) {
            const name = err instanceof Error ? err.name : '';
            if (name === 'TimeoutError' || name === 'AbortError') throw new ProbeWireError('TIMEOUT');
            const message = err instanceof Error ? err.message : '';
            throw new ProbeWireError(/redirect/i.test(message) ? 'REDIRECT_REFUSED' : 'UNREACHABLE');
        }
        if (res.status >= 300 && res.status < 400) {
            await res.body?.cancel();
            throw new ProbeWireError('REDIRECT_REFUSED');
        }
        if (res.status === 401 || res.status === 403) {
            await res.body?.cancel();
            throw new ProbeWireError('AUTH_FAILED');
        }
        if (res.status < 200 || res.status >= 300) {
            await res.body?.cancel();
            throw new ProbeWireError(res.status >= 500 ? 'HTTP_5XX' : 'HTTP_4XX');
        }
        return res;
    }

    async function rpc(
        target: ScopeTarget,
        request: ProbeRequest,
        session: McpSession | null,
        method: (typeof PROBE_MCP_MESSAGES)[number] | (typeof PROBE_A2A_MESSAGES)[number],
        params: unknown,
        cap: number,
    ): Promise<{ result: unknown; read: Read }> {
        const id = ++rpcId;
        const extra: Record<string, string> = {};
        if (session?.sessionId) extra['Mcp-Session-Id'] = session.sessionId;
        if (session) extra['MCP-Protocol-Version'] = session.protocolVersion;
        const res = await post(target, request, { jsonrpc: '2.0', id, method, params }, extra);
        const read = await readCapped(res, cap);
        if (read.cut) return { result: undefined, read };
        const answer = rpcResponseFrom(read, res.headers.get('content-type') ?? '', id);
        return { result: answer.result, read };
    }

    async function openSession(target: ScopeTarget, request: ProbeRequest): Promise<McpSession> {
        const id = ++rpcId;
        const res = await post(
            target,
            request,
            {
                jsonrpc: '2.0',
                id,
                method: 'initialize',
                params: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'scanent-probe', version: '1' } },
            },
            {},
        );
        const sessionHeader = res.headers.get('mcp-session-id');
        const sessionId = sessionHeader !== null && /^[\x21-\x7e]{1,256}$/.test(sessionHeader) ? sessionHeader : null;
        const read = await readCapped(res, SESSION_BYTE_CAP);
        if (read.cut) throw new ProbeWireError('SESSION_FAILED');
        const init = rpcResponseFrom(read, res.headers.get('content-type') ?? '', id).result;
        const version = isObject(init) && typeof init.protocolVersion === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(init.protocolVersion) ? init.protocolVersion : null;
        if (version === null) throw new ProbeWireError('SESSION_FAILED');
        const base: McpSession = { sessionId, protocolVersion: version, tools: new Map() };

        const notified = await post(
            target,
            request,
            { jsonrpc: '2.0', method: 'notifications/initialized' },
            { ...(sessionId ? { 'Mcp-Session-Id': sessionId } : {}), 'MCP-Protocol-Version': version },
        );
        await notified.body?.cancel();

        const tools = new Map<string, unknown>();
        let cursor: string | null = null;
        for (let page = 0; page < MAX_TOOL_PAGES; page += 1) {
            const { result, read: listed } = await rpc(target, request, base, 'tools/list', cursor === null ? {} : { cursor }, SESSION_BYTE_CAP);
            if (listed.cut || !isObject(result) || !Array.isArray(result.tools)) throw new ProbeWireError('SESSION_FAILED');
            for (const tool of result.tools) {
                if (isObject(tool) && typeof tool.name === 'string' && tools.size < MAX_LISTED_TOOLS) tools.set(tool.name, tool.inputSchema);
            }
            cursor = typeof result.nextCursor === 'string' && result.nextCursor.length <= 1024 ? result.nextCursor : null;
            if (cursor === null) break;
        }
        return { ...base, tools };
    }

    /** Whether the listed tool takes the scope's argument as a string. */
    function takesStringArgument(inputSchema: unknown, argument: string): boolean {
        if (!isObject(inputSchema) || !isObject(inputSchema.properties)) return false;
        const property = inputSchema.properties[argument];
        return isObject(property) && property.type === 'string';
    }

    async function sendMcp(target: Extract<ScopeTarget, { kind: 'mcp' }>, tool: ScopeMcpTool, request: ProbeRequest): Promise<string> {
        // The plan only ever holds a tool the scope names; this is the same rule, held where the call is made.
        if (!target.tools.some((t) => t.name === tool.name && t.argument === tool.argument)) throw new ProbeWireError('TOOL_NOT_LISTED');
        let opening = sessions.get(target.endpoint);
        if (opening === undefined) {
            opening = openSession(target, request);
            sessions.set(target.endpoint, opening);
        }
        const session = await opening;
        if (!session.tools.has(tool.name) || !takesStringArgument(session.tools.get(tool.name), tool.argument)) {
            throw new ProbeWireError('TOOL_NOT_LISTED');
        }
        const { result, read } = await rpc(target, request, session, 'tools/call', { name: tool.name, arguments: { [tool.argument]: request.text } }, REPLY_BYTE_CAP);
        if (read.cut) return read.text;
        // An error result's text is still the agent's reply: a marker can come back in an error message.
        const texts = isObject(result) ? textsOf(result.content, 'type') : [];
        if (texts.length === 0) throw new ProbeWireError('NO_TEXT');
        return texts.join('\n');
    }

    async function sendA2a(target: ScopeTarget, request: ProbeRequest): Promise<string> {
        const message = { kind: 'message', role: 'user', messageId: randomUUID(), parts: [{ kind: 'text', text: request.text }] };
        const { result, read } = await rpc(target, request, null, 'message/send', { message, configuration: { blocking: true } }, REPLY_BYTE_CAP);
        if (read.cut) return read.text;
        const texts: string[] = [];
        if (isObject(result) && result.kind === 'message') texts.push(...textsOf(result.parts, 'kind'));
        if (isObject(result) && result.kind === 'task') {
            if (Array.isArray(result.artifacts)) for (const a of result.artifacts) if (isObject(a)) texts.push(...textsOf(a.parts, 'kind'));
            if (isObject(result.status) && isObject(result.status.message)) texts.push(...textsOf(result.status.message.parts, 'kind'));
        }
        if (texts.length === 0) throw new ProbeWireError('NO_TEXT');
        return texts.join('\n');
    }

    async function sendChat(target: Extract<ScopeTarget, { kind: 'http-chat' }>, request: ProbeRequest): Promise<string> {
        const res = await post(target, request, fillTemplate(target.request.body, request.text), {});
        const read = await readCapped(res, REPLY_BYTE_CAP);
        if (read.cut) return read.text;
        let parsed: unknown;
        try {
            parsed = JSON.parse(read.text);
        } catch {
            throw new ProbeWireError('NOT_JSON');
        }
        const reply = atPath(parsed, target.request.replyPath);
        if (typeof reply !== 'string') throw new ProbeWireError('NO_TEXT');
        return reply;
    }

    return async (request) => {
        const target = request.target;
        if (target.kind === 'mcp') {
            if (request.tool === undefined) throw new ProbeWireError('TOOL_NOT_LISTED');
            return sendMcp(target, request.tool, request);
        }
        if (target.kind === 'a2a') return sendA2a(target, request);
        return sendChat(target, request);
    };
}
