/**
 * The wire contract `scanent-probes/1`: what a probe run found, signed by the
 * prober (docs/design/active-flavour.md, "What it reports").
 *
 * A contract of its own, so no reader of an observation report takes a probe
 * result for one, or the reverse. It is held to the other reports' rules: the
 * same byte cap, the same signature over the same canonical JSON
 * (`verifySignedEnvelope`), the same refusal codes in the same order. Its
 * signer is the PROBER, and the engagement's authoriser is named only by the
 * fingerprint of the key that signed the scope.
 *
 * ‾‾‾ WHAT THE REPORT DELIBERATELY CANNOT SAY ‾‾‾
 *
 *   • THAT IT CONCLUDED. There is no `concluded` member: a reader derives it
 *     (`probeReportConcluded`), true only when some verdict is not
 *     INCONCLUSIVE. Zero is never complete.
 *   • A VERDICT ITS REASON DOES NOT GIVE. Each reason names one verdict
 *     (`VERDICT_OF_REASON`) and one class (`CLASS_OF_REASON`): ACTED only on a
 *     canary probe, DISCLOSED only on a disclosure probe.
 *   • MORE OF A REPLY THAN A VERDICT NEEDS. An excerpt only beside ACTED or
 *     DISCLOSED, at most 280 characters, and never a token of a secret's
 *     shape: enough to show the evidence, and a disclosure says a secret's
 *     shape was disclosed, never the secret.
 *   • A TARGET IT DID NOT NAME, OR A STATE ITS OUTCOMES CONTRADICT. Every
 *     outcome names a listed target, and each target's state is the one its
 *     outcomes give. An outcome of an MCP target names the tool it called,
 *     and no other outcome names one.
 */
import { z } from 'zod';

import { describeReportSchemaIssue, verifySignedEnvelope, type HarnessRefusal } from './harness-contract';
import { looksLikeSecret } from './harness-contract-rules';
import {
    CLASS_OF_REASON,
    ENGAGEMENT_ID,
    MAX_PROBE_ENDPOINT_CHARS,
    MAX_PROBE_EXCERPT_CHARS,
    MAX_PROBE_OUTCOMES,
    MAX_PROBE_TARGETS,
    MCP_TOOL_NAME,
    PROBE_CLASSES_V1,
    PROBE_ID,
    PROBE_RUN_STOPS,
    PROBE_TARGET_KINDS,
    PROBE_TARGET_REASONS,
    PROBE_VERDICT_REASONS,
    PROBE_VERDICTS,
    PROBES_CONTRACT_V1,
    VERDICT_OF_REASON,
    endpointProblem,
} from './probes-contract-rules';

export * from './probes-contract-rules';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;

const endpoint = z
    .string()
    .min(1)
    .max(MAX_PROBE_ENDPOINT_CHARS)
    .superRefine((v, ctx) => {
        const problem = endpointProblem(v);
        if (problem !== null) ctx.addIssue({ code: 'custom', message: problem });
    });

const excerpt = z
    .string()
    .min(1)
    .max(MAX_PROBE_EXCERPT_CHARS)
    .refine((v) => !looksLikeSecret(v) && !v.split(/\s+/).some(looksLikeSecret), 'an excerpt must hold nothing of a secret\'s shape');

const TargetSchema = z
    .object({
        endpoint,
        kind: z.enum(PROBE_TARGET_KINDS),
        reached: z.boolean(),
        reason: z.enum(PROBE_TARGET_REASONS),
    })
    .strict();

const OutcomeSchema = z
    .object({
        probeId: z.string().regex(PROBE_ID, 'a probe id is <class>.<category>.<n>'),
        probeClass: z.enum(PROBE_CLASSES_V1),
        endpoint,
        verdict: z.enum(PROBE_VERDICTS),
        reason: z.enum(PROBE_VERDICT_REASONS),
        /** The MCP tool called: present exactly for an outcome of an MCP target. */
        tool: z.string().regex(MCP_TOOL_NAME).optional(),
        replyDigest: z.string().regex(SHA256).optional(),
        excerpt: excerpt.optional(),
    })
    .strict()
    .superRefine((o, ctx) => {
        if (!o.probeId.startsWith(`${o.probeClass}.`)) ctx.addIssue({ code: 'custom', path: ['probeClass'], message: 'not the class the probe id names' });
        if (VERDICT_OF_REASON[o.reason] !== o.verdict) ctx.addIssue({ code: 'custom', path: ['verdict'], message: 'not the verdict its reason gives' });
        const reasonClass = CLASS_OF_REASON[o.reason];
        if (reasonClass !== 'either' && reasonClass !== o.probeClass) {
            ctx.addIssue({ code: 'custom', path: ['reason'], message: 'a reason of the other probe class' });
        }
        if ((o.reason === 'NO_REPLY') !== (o.replyDigest === undefined)) {
            ctx.addIssue({ code: 'custom', path: ['replyDigest'], message: 'a reply digest exactly when there was a reply' });
        }
        const evidence = o.verdict === 'ACTED' || o.verdict === 'DISCLOSED';
        if (evidence !== (o.excerpt !== undefined)) {
            ctx.addIssue({ code: 'custom', path: ['excerpt'], message: 'an excerpt exactly beside ACTED or DISCLOSED' });
        }
    });

export const ProbesReportBodyV1Schema = z
    .object({
        contract: z.literal(PROBES_CONTRACT_V1),
        engagement: z
            .object({
                id: z.string().regex(ENGAGEMENT_ID),
                scopeDigest: z.string().regex(SHA256),
                scopeSignerFingerprint: z.string().regex(FINGERPRINT),
            })
            .strict(),
        catalogue: z
            .object({
                digest: z.string().regex(SHA256),
                probes: z.number().int().min(1).max(MAX_PROBE_OUTCOMES),
            })
            .strict(),
        run: z
            .object({
                startedAt: z.string().datetime(),
                endedAt: z.string().datetime(),
                stopped: z.enum(PROBE_RUN_STOPS).nullable(),
                /** The digest of the run's declared surface, rebuilt from the scope by whoever holds it. */
                surfaceDigest: z.string().regex(SHA256),
            })
            .strict(),
        targets: z.array(TargetSchema).min(1).max(MAX_PROBE_TARGETS),
        outcomes: z.array(OutcomeSchema).max(MAX_PROBE_OUTCOMES),
    })
    .strict()
    .superRefine((body, ctx) => {
        if (Date.parse(body.run.endedAt) < Date.parse(body.run.startedAt)) {
            ctx.addIssue({ code: 'custom', path: ['run', 'endedAt'], message: 'before the start' });
        }
        const endpoints = body.targets.map((t) => t.endpoint);
        if (new Set(endpoints).size !== endpoints.length) ctx.addIssue({ code: 'custom', path: ['targets'], message: 'a target is named twice' });

        const kindOf = new Map(body.targets.map((t) => [t.endpoint, t.kind]));
        body.outcomes.forEach((o, i) => {
            const kind = kindOf.get(o.endpoint);
            if (kind === undefined) ctx.addIssue({ code: 'custom', path: ['outcomes', i, 'endpoint'], message: 'not a listed target' });
            else if ((kind === 'mcp') !== (o.tool !== undefined)) {
                ctx.addIssue({ code: 'custom', path: ['outcomes', i, 'tool'], message: 'a tool exactly for an outcome of an MCP target' });
            }
        });

        body.targets.forEach((t, i) => {
            const mine = body.outcomes.filter((o) => o.endpoint === t.endpoint);
            const answered = mine.some((o) => o.reason !== 'NO_REPLY');
            const expected =
                t.reason === 'REACHED'
                    ? answered
                    : t.reason === 'NO_REPLY'
                      ? mine.length > 0 && !answered
                      : mine.length === 0; // NOT_RUN and NO_PROBES_FOR_INTERFACE: nothing was sent to it.
            if (!expected) ctx.addIssue({ code: 'custom', path: ['targets', i, 'reason'], message: 'not the state its outcomes give' });
            if (t.reached !== (t.reason === 'REACHED')) ctx.addIssue({ code: 'custom', path: ['targets', i, 'reached'], message: 'reached exactly when REACHED' });
        });
    });

export type ProbesReportBodyV1 = z.infer<typeof ProbesReportBodyV1Schema>;

/**
 * Whether the run concluded anything: some verdict other than INCONCLUSIVE.
 * The report cannot say so itself; every reader asks this.
 */
export function probeReportConcluded(body: Pick<ProbesReportBodyV1, 'outcomes'>): boolean {
    return body.outcomes.some((o) => o.verdict !== 'INCONCLUSIVE');
}

export type ProbesParseResult =
    | { readonly ok: true; readonly body: ProbesReportBodyV1; readonly signerKey: string }
    | { readonly ok: false; readonly reason: HarnessRefusal; readonly issues?: readonly string[] };

/**
 * Check a raw probes report in the only safe order: size, JSON, a signature by
 * a TRUSTED prober key that verifies, the contract id, then the strict schema.
 * `trustedProberKeys` are the public keys of the probers registered to run;
 * the scope's approver key is not one of them.
 */
export function verifyAndParseProbesReport(raw: string, trustedProberKeys: readonly string[]): ProbesParseResult {
    const envelope = verifySignedEnvelope(raw, trustedProberKeys);
    if (!envelope.ok) return { ok: false, reason: envelope.reason };
    if (envelope.body.contract !== PROBES_CONTRACT_V1) {
        return { ok: false, reason: 'SCHEMA', issues: ['contract: not a contract id this verifier accepts'] };
    }
    const parsed = ProbesReportBodyV1Schema.safeParse(envelope.body);
    if (!parsed.success) return { ok: false, reason: 'SCHEMA', issues: parsed.error.issues.map(describeReportSchemaIssue) };
    return { ok: true, body: parsed.data, signerKey: envelope.signerKey };
}
