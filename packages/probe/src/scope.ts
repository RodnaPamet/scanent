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
export const MAX_ENDPOINT_CHARS = 2048;
export const MAX_NAME_CHARS = 120;
export const MAX_CONTACT_CHARS = 200;
const MAX_KEY_CHARS = 256;

/**
 * Why an endpoint is not an exact one, or null. A target is matched by byte
 * equality, so the scope must spell it the one way a URL serialises: https, a
 * host, no credentials, no query, no fragment, no pattern, and exactly
 * `new URL(e).href`. "Exact" is what makes the match safe: a scope cannot name
 * a range, and a request cannot reach a target by spelling it differently.
 */
export function endpointProblem(endpoint: string): string | null {
    if (endpoint.includes('*')) return 'a pattern is not an endpoint';
    if (endpoint.includes('?') || endpoint.includes('#')) return 'an endpoint carries no query or fragment';
    let url: URL;
    try {
        url = new URL(endpoint);
    } catch {
        return 'not a URL';
    }
    if (url.protocol !== 'https:') return 'not https';
    if (url.username !== '' || url.password !== '') return 'an endpoint carries no credentials';
    if (url.hostname === '') return 'no host';
    if (url.href !== endpoint) return 'not in its canonical spelling (new URL(endpoint).href)';
    return null;
}

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

const TargetSchema = z
    .object({
        kind: z.enum(SCOPE_TARGET_KINDS),
        endpoint: z
            .string()
            .min(1)
            .max(MAX_ENDPOINT_CHARS)
            .superRefine((v, ctx) => {
                const problem = endpointProblem(v);
                if (problem !== null) ctx.addIssue({ code: 'custom', message: problem });
            }),
    })
    .strict();

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
