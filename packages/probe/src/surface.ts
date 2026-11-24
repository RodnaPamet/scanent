/**
 * THE PROBER'S DECLARED SURFACE, PER ENGAGEMENT (step 7b of
 * docs/design/active-flavour.md).
 *
 * Built from the signed scope and the code's own constants, and nothing else:
 * every endpoint the run may reach, the one method, the JSON-RPC messages per
 * kind, the MCP tools and the argument each takes, and a chat target's body
 * template. Its digest is in the signed report, so a reader holding the scope
 * rebuilds it and compares.
 *
 * Unlike the read-only scanner's surface, which tests prove the code keeps to,
 * this one is CHECKED BEFORE EVERY REQUEST (owner decision, 2026-11-24): the
 * wire describes each request and asks `onSurface`, and a request that is not
 * on it is refused before it leaves. The tests use the same function, so the
 * proof and the guard cannot drift apart.
 *
 * The credential rule is the same for every engagement and so lives in code,
 * not here: a token goes only to the endpoint it was named for, and only to an
 * endpoint of the scope.
 */
import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';
import { createHash } from 'node:crypto';

import { catalogueDigestOf } from './catalogue-digest';
import { PROBE_PLACEHOLDER, type EngagementScope } from './scope';

/** The prober's own version: what a surface and a report name. Independent of the scanner's. */
export const PROBE_VERSION = '0.1.0';

/** The JSON-RPC messages a target of each kind may be sent. A chat target is sent its template, not a message. */
export const SURFACE_MESSAGES = {
    mcp: ['initialize', 'notifications/initialized', 'tools/list', 'tools/call'],
    a2a: ['message/send'],
    'http-chat': [],
} as const;

export interface SurfaceTarget {
    readonly endpoint: string;
    readonly kind: EngagementScope['targets'][number]['kind'];
    readonly method: 'POST';
    readonly messages: readonly string[];
    readonly tools?: readonly { readonly name: string; readonly argument: string }[];
    readonly body?: unknown;
}

export interface ProbeSurface {
    readonly name: 'scanent-probe';
    readonly version: string;
    readonly catalogue: string;
    readonly engagement: string;
    readonly targets: readonly SurfaceTarget[];
}

/** The surface of one engagement: the scope's targets, each with what may be sent to it. */
export function probeSurface(scope: EngagementScope): ProbeSurface {
    return {
        name: 'scanent-probe',
        version: PROBE_VERSION,
        catalogue: catalogueDigestOf(),
        engagement: scope.engagementId,
        targets: scope.targets.map((t) => ({
            endpoint: t.endpoint,
            kind: t.kind,
            method: 'POST' as const,
            messages: [...SURFACE_MESSAGES[t.kind]],
            ...(t.kind === 'mcp' ? { tools: t.tools.map((tool) => ({ name: tool.name, argument: tool.argument })) } : {}),
            ...(t.kind === 'http-chat' ? { body: t.request.body } : {}),
        })),
    };
}

/** `sha256:` over the surface's canonical JSON: what the report carries. */
export function surfaceDigest(surface: ProbeSurface): string {
    return `sha256:${createHash('sha256').update(canonicalJson(surface), 'utf8').digest('hex')}`;
}

/** A request as the wire is about to send it. */
export interface SurfaceRequest {
    readonly url: string;
    readonly method: string;
    readonly body: unknown;
}

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Whether a body is the template with its one placeholder filled by a string
 * and nothing else changed: the same keys, the same values, the same order of
 * array items.
 */
export function matchesTemplate(template: unknown, body: unknown): boolean {
    if (template === PROBE_PLACEHOLDER) return typeof body === 'string';
    if (Array.isArray(template)) {
        return Array.isArray(body) && body.length === template.length && template.every((item, i) => matchesTemplate(item, body[i]));
    }
    if (isObject(template)) {
        if (!isObject(body)) return false;
        const keys = Object.keys(template);
        if (Object.keys(body).length !== keys.length) return false;
        return keys.every((k) => Object.prototype.hasOwnProperty.call(body, k) && matchesTemplate(template[k], body[k]));
    }
    return Object.is(template, body);
}

/**
 * Why a request is not on the surface, or null when it is. Checked by the wire
 * before every request; a request this refuses is never sent.
 */
export function offSurface(surface: ProbeSurface, request: SurfaceRequest): string | null {
    const target = surface.targets.find((t) => t.endpoint === request.url);
    if (target === undefined) return 'not an endpoint of the scope';
    if (request.method !== target.method) return 'not the method the surface names';
    if (target.kind === 'http-chat') {
        return matchesTemplate(target.body, request.body) ? null : 'not the scope\'s body template filled with a probe';
    }
    if (!isObject(request.body) || request.body.jsonrpc !== '2.0' || typeof request.body.method !== 'string') return 'not a JSON-RPC message';
    const method = request.body.method;
    if (!target.messages.includes(method)) return 'a JSON-RPC message the surface does not name';
    if (method === 'tools/call') {
        const params = request.body.params;
        if (!isObject(params) || typeof params.name !== 'string' || !isObject(params.arguments)) return 'a tool call of another shape';
        const tool = target.tools?.find((t) => t.name === params.name);
        if (tool === undefined) return 'a tool the scope does not name';
        const args = Object.entries(params.arguments);
        if (args.length !== 1 || args[0][0] !== tool.argument || typeof args[0][1] !== 'string') return 'an argument the scope does not name';
    }
    if (method === 'message/send') {
        const message = isObject(request.body.params) ? request.body.params.message : undefined;
        const parts = isObject(message) ? message.parts : undefined;
        if (!Array.isArray(parts) || parts.length !== 1 || !isObject(parts[0]) || parts[0].kind !== 'text') return 'a message of another shape';
    }
    return null;
}

/** Whether a request is on the surface. */
export function onSurface(surface: ProbeSurface, request: SurfaceRequest): boolean {
    return offSurface(surface, request) === null;
}
