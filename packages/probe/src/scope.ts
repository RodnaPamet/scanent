/**
 * THE ENGAGEMENT SCOPE: what a probe run is allowed to do, signed by somebody
 * in the estate who is not the prober.
 *
 * The active flavour sends crafted inputs to an agent (docs/design/
 * active-flavour.md). Its control is this file: no verified scope, no probe.
 * A scope names exact targets, a UTC window of at most seven days, the probe
 * classes allowed, the person who approved it, a kill contact, a rate cap, and
 * the one prober allowed to run it. It is signed exactly as a report is (a
 * top-level `signature` over SHA-256 of the canonical body), by a key the
 * estate registered in advance and NEVER the prober's own (owner decision 2,
 * 2026-11-24).
 *
 * Pure: no clock, no network, no file. The window is checked against a `now`
 * the caller passes, so the runner can re-check it before every request.
 *
 * Owner decisions, 2026-11-24: version 1 allows `canary` and `disclosure`
 * only (decision 3); the window is at most seven days; the rate cap is 1 to
 * 120 requests per minute per target; and there is no clock skew: before the
 * start or at or after the end is refused.
 */
import { z } from 'zod';

import {
    describeReportSchemaIssue,
    harnessKeyFingerprint,
    harnessSignedMessage,
    looksLikeSecret,
    verifySignedEnvelope,
    type HarnessRefusal,
} from '@rodnapamet/scanent-contract/harness-contract';
import { MAX_PROBE_ENDPOINT_CHARS, MCP_TOOL_NAME, endpointProblem } from '@rodnapamet/scanent-contract/probes-contract-rules';

/** The scope's contract id: its `contract` member, read only once the signature verifies. */
export const ENGAGEMENT_SCOPE_V1 = 'scanent-engagement-scope/1';

/** The probe classes a version 1 scope may allow. `side-effect` is not one (decision 3). */
export const SCOPE_PROBE_CLASSES = ['canary', 'disclosure'] as const;
export type ScopeProbeClass = (typeof SCOPE_PROBE_CLASSES)[number];

/** The interfaces a target is reached through (the design's "What it probes"). */
export const SCOPE_TARGET_KINDS = ['mcp', 'a2a', 'http-chat'] as const;

export const MAX_SCOPE_TARGETS = 50;
export const MAX_SCOPE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
export const MIN_RATE_PER_MINUTE = 1;
export const MAX_RATE_PER_MINUTE = 120;
export const MAX_ENDPOINT_CHARS = MAX_PROBE_ENDPOINT_CHARS;
export const MAX_NAME_CHARS = 120;
export const MAX_CONTACT_CHARS = 200;
const MAX_KEY_CHARS = 256;

/** The exact-endpoint rule, shared with the probes report: one copy, in the contract. */
export { endpointProblem };

/** One line of text a person wrote: no line break, no control character, no secret's shape. */
function personText(max: number) {
    return z
        .string()
        .min(1)
        .max(max)
        .refine((v) => v.trim() === v && v.trim() !== '', 'no leading or trailing space')
        // eslint-disable-next-line no-control-regex
        .refine((v) => !/[\u0000-\u001f\u007f]/.test(v), 'one line, no control character')
        .refine((v) => !looksLikeSecret(v), 'secret-shaped');
}

const endpoint = z
    .string()
    .min(1)
    .max(MAX_ENDPOINT_CHARS)
    .superRefine((v, ctx) => {
        const problem = endpointProblem(v);
        if (problem !== null) ctx.addIssue({ code: 'custom', message: problem });
    });

/** The placeholder a chat target's body template holds, exactly once, as a whole string. */
export const PROBE_PLACEHOLDER = '{{probe}}';
export const MAX_MCP_TOOLS_PER_TARGET = 10;
export const MAX_CHAT_TEMPLATE_BYTES = 8 * 1024;
export const MAX_CHAT_TEMPLATE_DEPTH = 16;
export const MAX_REPLY_PATH = 16;

/**
 * Why a chat body template cannot be sent, or null. It is JSON of at most
 * 8 KiB and depth 16, with exactly one string leaf that IS the placeholder
 * (never a string that merely contains it), and no key or string of a
 * secret's shape: the approver signs exactly what is sent, so it may not hold
 * a credential, which comes from the prober's own environment instead.
 */
export function chatTemplateProblem(body: unknown): string | null {
    let text: string;
    try {
        text = JSON.stringify(body);
    } catch {
        return 'not JSON';
    }
    if (text === undefined || Buffer.byteLength(text, 'utf8') > MAX_CHAT_TEMPLATE_BYTES) return 'larger than 8 KiB';
    let placeholders = 0;
    let problem: string | null = null;
    const walk = (node: unknown, depth: number): void => {
        if (problem !== null) return;
        if (depth > MAX_CHAT_TEMPLATE_DEPTH) {
            problem = 'deeper than 16';
            return;
        }
        if (typeof node === 'string') {
            if (node === PROBE_PLACEHOLDER) placeholders += 1;
            else if (node.includes(PROBE_PLACEHOLDER)) problem = 'the placeholder is a whole string, never part of one';
            else if (looksLikeSecret(node)) problem = 'a string of a secret\'s shape';
            return;
        }
        if (Array.isArray(node)) {
            for (const item of node) walk(item, depth + 1);
            return;
        }
        if (node !== null && typeof node === 'object') {
            for (const [key, value] of Object.entries(node)) {
                if (looksLikeSecret(key) || key.includes(PROBE_PLACEHOLDER)) {
                    problem = 'a key that is a secret\'s shape or the placeholder';
                    return;
                }
                walk(value, depth + 1);
            }
        }
    };
    walk(body, 0);
    if (problem !== null) return problem;
    if (placeholders !== 1) return `the placeholder appears ${placeholders} times, not once`;
    return null;
}

const McpToolSchema = z
    .object({
        name: z.string().regex(MCP_TOOL_NAME, 'a tool name: letters, digits, _ . -, at most 128'),
        argument: z.string().regex(MCP_TOOL_NAME, 'an argument name: letters, digits, _ . -, at most 128'),
    })
    .strict();

const TargetSchema = z.discriminatedUnion('kind', [
    z
        .object({
            kind: z.literal('mcp'),
            endpoint,
            /** The tools a probe may call, and the argument it goes in: the approver's statement that each is safe to call. */
            tools: z
                .array(McpToolSchema)
                .min(1)
                .max(MAX_MCP_TOOLS_PER_TARGET)
                .refine((tools) => new Set(tools.map((t) => t.name)).size === tools.length, 'a tool is named twice'),
        })
        .strict(),
    z.object({ kind: z.literal('a2a'), endpoint }).strict(),
    z
        .object({
            kind: z.literal('http-chat'),
            endpoint,
            request: z
                .object({
                    body: z.unknown().superRefine((v, ctx) => {
                        const problem = chatTemplateProblem(v);
                        if (problem !== null) ctx.addIssue({ code: 'custom', message: problem });
                    }),
                    replyPath: z
                        .array(z.union([z.string().min(1).max(128), z.number().int().min(0).max(10_000)]))
                        .min(1)
                        .max(MAX_REPLY_PATH),
                })
                .strict(),
        })
        .strict(),
]);

export const EngagementScopeSchema = z
    .object({
        contract: z.literal(ENGAGEMENT_SCOPE_V1),
        engagementId: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/, 'letters, digits, - and _, 8 to 64 of them'),
        targets: z.array(TargetSchema).min(1).max(MAX_SCOPE_TARGETS),
        window: z
            .object({
                start: z.string().datetime(),
                end: z.string().datetime(),
            })
            .strict(),
        classes: z.array(z.enum(SCOPE_PROBE_CLASSES)).min(1).max(SCOPE_PROBE_CLASSES.length),
        approver: z
            .object({
                name: personText(MAX_NAME_CHARS),
                role: personText(MAX_NAME_CHARS),
            })
            .strict(),
        killContact: personText(MAX_CONTACT_CHARS),
        ratePerMinute: z.number().int().min(MIN_RATE_PER_MINUTE).max(MAX_RATE_PER_MINUTE),
        proberKey: z
            .string()
            .min(1)
            .max(MAX_KEY_CHARS)
            .refine((v) => harnessKeyFingerprint(v) !== null, 'not a raw Ed25519 public key in hex or base64'),
    })
    .strict()
    .superRefine((scope, ctx) => {
        const endpoints = scope.targets.map((t) => t.endpoint);
        if (new Set(endpoints).size !== endpoints.length) {
            ctx.addIssue({ code: 'custom', path: ['targets'], message: 'an endpoint is named twice' });
        }
        if (new Set(scope.classes).size !== scope.classes.length) {
            ctx.addIssue({ code: 'custom', path: ['classes'], message: 'a class is named twice' });
        }
        const span = Date.parse(scope.window.end) - Date.parse(scope.window.start);
        if (!(span > 0)) ctx.addIssue({ code: 'custom', path: ['window'], message: 'the end is not after the start' });
        else if (span > MAX_SCOPE_WINDOW_MS) {
            ctx.addIssue({ code: 'custom', path: ['window'], message: 'longer than seven days' });
        }
    });

export type EngagementScope = z.infer<typeof EngagementScopeSchema>;

/** Every way a scope file is refused, in the order they are checked. */
export const SCOPE_REFUSALS = [
    'TOO_LARGE',
    'NOT_JSON',
    'NOT_AN_OBJECT',
    'UNSIGNED',
    'MALFORMED_SIGNATURE',
    'UNTRUSTED_SIGNER',
    'BAD_SIGNATURE',
    'SCHEMA',
    'SIGNER_IS_PROBER',
    'PROBER_NOT_NAMED',
] as const satisfies readonly (HarnessRefusal | 'SIGNER_IS_PROBER' | 'PROBER_NOT_NAMED')[];
export type ScopeRefusal = (typeof SCOPE_REFUSALS)[number];

export type ScopeVerifyResult =
    | {
          readonly ok: true;
          readonly scope: EngagementScope;
          /** `sha256:` over the canonical signed body: what a probe report will name. */
          readonly digest: string;
          readonly signerKey: string;
          readonly signerFingerprint: string;
      }
    | { readonly ok: false; readonly reason: ScopeRefusal; readonly issues?: readonly string[] };

/** The digest a scope is named by: SHA-256 of its canonical body, the message its signature covers. */
export function scopeDigest(body: unknown): string {
    return `sha256:${harnessSignedMessage(body).toString('hex')}`;
}

/**
 * Check a scope file, in the only safe order: size, JSON, a signature by a
 * REGISTERED scope key that verifies, the strict schema, then the two rules
 * that keep authorising apart from probing:
 *
 *   • SIGNER_IS_PROBER: the scope was signed by the prober's own key, or by
 *     the key the scope names as its prober. The party that runs the probes
 *     does not authorise them, even when its key was registered as a scope key
 *     by mistake.
 *   • PROBER_NOT_NAMED: the scope names another prober. A scope taken from
 *     one prober cannot be run by a second.
 *
 * `trustedScopeKeys` are the estate's registered scope keys; `proberKey` is
 * the verifying prober's own public key. Both are raw Ed25519 keys, hex or
 * base64. A `proberKey` that is not one is the caller's error, and throws.
 */
export function verifyEngagementScope(
    raw: string,
    options: { readonly trustedScopeKeys: readonly string[]; readonly proberKey: string },
): ScopeVerifyResult {
    const ownFingerprint = harnessKeyFingerprint(options.proberKey);
    if (ownFingerprint === null) throw new TypeError('the prober key is not a raw Ed25519 public key');

    const envelope = verifySignedEnvelope(raw, options.trustedScopeKeys);
    if (!envelope.ok) return { ok: false, reason: envelope.reason };
    const { body, signerKey } = envelope;

    if (body.contract !== ENGAGEMENT_SCOPE_V1) {
        return { ok: false, reason: 'SCHEMA', issues: ['contract: not a contract id this verifier accepts'] };
    }
    const parsed = EngagementScopeSchema.safeParse(body);
    if (!parsed.success) {
        return { ok: false, reason: 'SCHEMA', issues: parsed.error.issues.map(describeReportSchemaIssue) };
    }
    const scope = parsed.data;

    // The envelope verified, so the signer key is an Ed25519 key it could read.
    const signerFingerprint = harnessKeyFingerprint(signerKey) as string;
    const namedProber = harnessKeyFingerprint(scope.proberKey) as string;
    if (signerFingerprint === ownFingerprint || signerFingerprint === namedProber) {
        return { ok: false, reason: 'SIGNER_IS_PROBER' };
    }
    if (namedProber !== ownFingerprint) return { ok: false, reason: 'PROBER_NOT_NAMED' };

    return { ok: true, scope, digest: scopeDigest(body), signerKey, signerFingerprint };
}

/** Why a request may not be sent under a verified scope. */
export type ScopeRequestRefusal = 'NOT_YET_OPEN' | 'CLOSED' | 'TARGET_NOT_NAMED' | 'CLASS_NOT_ALLOWED';

/**
 * Whether the window is open at `now` (epoch ms): from the start, inclusive,
 * to the end, exclusive, with no skew either way. A clock that cannot be read
 * (not a finite number) is CLOSED: a run never proceeds on a time it does not
 * have.
 */
export function scopeWindowRefusal(scope: EngagementScope, now: number): 'NOT_YET_OPEN' | 'CLOSED' | null {
    if (!Number.isFinite(now)) return 'CLOSED';
    if (now < Date.parse(scope.window.start)) return 'NOT_YET_OPEN';
    if (now >= Date.parse(scope.window.end)) return 'CLOSED';
    return null;
}

/** Whether the scope names this exact endpoint, byte for byte. */
export function scopeTargetRefusal(scope: EngagementScope, target: string): 'TARGET_NOT_NAMED' | null {
    return scope.targets.some((t) => t.endpoint === target) ? null : 'TARGET_NOT_NAMED';
}

/** Whether the scope allows this probe class. */
export function scopeClassRefusal(scope: EngagementScope, probeClass: string): 'CLASS_NOT_ALLOWED' | null {
    return (scope.classes as readonly string[]).includes(probeClass) ? null : 'CLASS_NOT_ALLOWED';
}

/**
 * The gate before EVERY request: the window at `now`, then the target, then
 * the class. Null admits the request. The runner calls it with the clock read
 * at the request, so a run that outlives its window stops at the next request.
 */
export function scopeAdmits(
    scope: EngagementScope,
    request: { readonly now: number; readonly target: string; readonly probeClass: string },
): ScopeRequestRefusal | null {
    return (
        scopeWindowRefusal(scope, request.now) ??
        scopeTargetRefusal(scope, request.target) ??
        scopeClassRefusal(scope, request.probeClass)
    );
}
