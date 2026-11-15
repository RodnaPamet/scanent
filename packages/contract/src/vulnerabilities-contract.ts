/**
 * The wire contract `scanent-vulnerabilities/1`: what a static,
 * model-assisted review of a client's code found.
 *
 * A strict schema of its own, held to the agent report's rules rather than a
 * copy of them: the same byte cap, the same signature over the same canonical
 * JSON (`verifySignedEnvelope`), the same refusal codes in the same order, and
 * the same walk for a secret's shape over every string member. A report of one
 * contract is never read by another's verifier.
 *
 * ‾‾‾ WHAT THE REPORT DELIBERATELY CANNOT SAY ‾‾‾
 *
 *   • THE CODE. Every place is a locator, `code://<label>/<path>#L<a>-L<b>`.
 *     What was sent to the model is listed the same way. The report can be
 *     shared without shipping the client's source.
 *   • CRITICAL, OR MORE THAN ITS VERDICT ALLOWS. A `confirmed` finding is at
 *     most HIGH, a `needs_validation` one at most MEDIUM (`SEVERITY_CAP`). A
 *     report that states more is refused, never lowered here.
 *   • A REJECTED CANDIDATE AS A RECORD. A candidate the refutation broke is a
 *     count, and so is a model answer that did not parse or named a place
 *     that does not exist.
 *   • A CLEAN BILL IT DID NOT EARN. `NOT_RUN` carries no finding and sends
 *     nothing; `COMPLETE` needs every repository reviewed and none listed as
 *     not reviewed, and at least one repository: zero is never complete.
 *   • A MODEL IT DOES NOT NAME. A run that ran names its provider, host,
 *     model, revision and the evaluation record that let it run.
 */
import { z } from 'zod';

import { describeReportSchemaIssue, MAX_ID_CHARS, verifySignedEnvelope, type HarnessRefusal } from './harness-contract';
import { looksLikeSecret } from './harness-contract-rules';
import {
    ATTACK_CLASSES,
    ATTACK_TECHNIQUE_ID,
    CWE_ID,
    FINDING_FINGERPRINT,
    INCOMPLETE_RUN_REASONS,
    MAX_FINDINGS,
    MAX_NOT_REVIEWED,
    MAX_PROSE_CHARS,
    MAX_REPOSITORIES,
    MAX_SENT_EXCERPTS,
    MAX_TITLE_CHARS,
    MAX_TRACE_STEPS,
    MODEL_HOST,
    MODEL_NAME,
    MODEL_PROVIDERS,
    NOT_REVIEWED_REASONS,
    NOT_RUN_REASONS,
    OWASP_API_TOP_10_2023,
    OWASP_TOP_10_2021,
    parseCodeRange,
    REPOSITORY_LABEL,
    REPOSITORY_REVIEW_STATUSES,
    SEVERITY_CAP,
    TRACE_STEP_KINDS,
    VULNERABILITIES_CONTRACT_V1,
    VULNERABILITY_CONFIDENCE,
    VULNERABILITY_SEVERITIES,
    VULNERABILITY_VERDICTS,
    withinSeverityCap,
} from './vulnerabilities-contract-rules';

export * from './vulnerabilities-contract-rules';

const SHA256_HEX = /^sha256:[0-9a-f]{64}$/;

const id = z.string().min(1).max(MAX_ID_CHARS);
const count = z.number().int().min(0);

const locator = z.string().refine((v) => parseCodeRange(v) !== null, 'a place is code://<label>/<path>#L<start>-L<end>, never code');

const printable = (v: string): boolean =>
    ![...v].some((ch) => {
        const c = ch.codePointAt(0) as number;
        return c < 0x20 || (c >= 0x7f && c <= 0x9f);
    });

/** Prose: one paragraph, printable, no code fence, no secret's shape. */
const prose = (max: number) =>
    z
        .string()
        .min(1)
        .max(max)
        .refine(printable, 'prose is one printable paragraph')
        .refine((v) => !v.includes('```'), 'prose carries no code block: a place is a locator')
        .refine((v) => !looksLikeSecret(v), 'prose must not have the shape of a secret');

const ScanSchema = z
    .object({
        id,
        asOf: z.string().datetime(),
        scanner: z.object({ agentId: id, version: id, manifestHash: z.string().regex(SHA256_HEX) }).strict(),
    })
    .strict();

const ModelSchema = z
    .object({
        provider: z.enum(MODEL_PROVIDERS),
        /** The endpoint's host, never its URL. */
        host: z.string().regex(MODEL_HOST),
        model: z.string().regex(MODEL_NAME),
        revision: z.string().regex(MODEL_NAME),
    })
    .strict();

const EvaluationRefSchema = z
    .object({
        /** The evaluation record that let this model revision run. */
        recordDigest: z.string().regex(SHA256_HEX),
        /** The corpus it was scored on. */
        corpusDigest: z.string().regex(SHA256_HEX),
    })
    .strict();

const BudgetSchema = z.object({ tokens: count, files: count, seconds: count }).strict();

const RunSchema = z
    .object({
        status: z.enum(['COMPLETE', 'INCOMPLETE', 'NOT_RUN']),
        reason: z.enum([...NOT_RUN_REASONS, ...INCOMPLETE_RUN_REASONS]).optional(),
        model: ModelSchema.nullable(),
        evaluation: EvaluationRefSchema.nullable(),
        budgets: BudgetSchema,
        used: BudgetSchema,
    })
    .strict()
    .superRefine((r, ctx) => {
        const notRun = (NOT_RUN_REASONS as readonly string[]).includes(r.reason ?? '');
        const incomplete = (INCOMPLETE_RUN_REASONS as readonly string[]).includes(r.reason ?? '');
        if (r.status === 'COMPLETE' && r.reason !== undefined) ctx.addIssue({ code: 'custom', message: 'a COMPLETE run carries no reason', path: ['reason'] });
        if (r.status === 'NOT_RUN' && !notRun) ctx.addIssue({ code: 'custom', message: 'a run that did not run names why, from the not-run reasons', path: ['reason'] });
        if (r.status === 'INCOMPLETE' && !incomplete) ctx.addIssue({ code: 'custom', message: 'an INCOMPLETE run names why, from the incomplete reasons', path: ['reason'] });
        if (r.status !== 'NOT_RUN' && (r.model === null || r.evaluation === null)) {
            ctx.addIssue({ code: 'custom', message: 'a run that ran names its model and the evaluation record that let it run', path: ['model'] });
        }
        if (r.reason === 'MODEL_NOT_CONFIGURED' && r.model !== null) ctx.addIssue({ code: 'custom', message: 'no model configured means no model named', path: ['model'] });
        if (r.status === 'NOT_RUN' && (r.used.tokens !== 0 || r.used.files !== 0)) {
            ctx.addIssue({ code: 'custom', message: 'a run that did not run used nothing', path: ['used'] });
        }
    });

const RepositorySchema = z
    .object({
        label: z.string().regex(REPOSITORY_LABEL),
        status: z.enum(REPOSITORY_REVIEW_STATUSES),
        /** Files the reconnaissance selected for review in it. */
        selectedFiles: count,
    })
    .strict();

const NotReviewedSchema = z.object({ locator, reason: z.enum(NOT_REVIEWED_REASONS) }).strict();

const TraceStepSchema = z.object({ kind: z.enum(TRACE_STEP_KINDS), locator }).strict();

export const VulnerabilityFindingSchema = z
    .object({
        /** A stable fingerprint the scanner computes from the class and the trace. */
        id: z.string().regex(FINDING_FINGERPRINT),
        attackClass: z.enum(ATTACK_CLASSES),
        title: prose(MAX_TITLE_CHARS),
        /** Entry point, propagation, sink: each a place, never the code. */
        trace: z.array(TraceStepSchema).min(1).max(MAX_TRACE_STEPS),
        cwe: z.string().regex(CWE_ID),
        owasp: z.enum(OWASP_TOP_10_2021).nullable(),
        owaspApi: z.enum(OWASP_API_TOP_10_2023).nullable(),
        attack: z.string().regex(ATTACK_TECHNIQUE_ID).nullable(),
        verdict: z.enum(VULNERABILITY_VERDICTS),
        confidence: z.enum(VULNERABILITY_CONFIDENCE),
        severity: z.enum(VULNERABILITY_SEVERITIES),
        /** What the condition is that makes it exploitable. */
        condition: prose(MAX_PROSE_CHARS),
        /** For `confirmed`: what to change. Null for `needs_validation`. */
        remediation: prose(MAX_PROSE_CHARS).nullable(),
        /** For `needs_validation`: what would settle it. Null for `confirmed`. */
        toValidate: prose(MAX_PROSE_CHARS).nullable(),
    })
    .strict()
    .superRefine((f, ctx) => {
        if (!withinSeverityCap(f.verdict, f.severity)) {
            ctx.addIssue({ code: 'custom', message: `a ${f.verdict} finding is at most ${SEVERITY_CAP[f.verdict]}`, path: ['severity'] });
        }
        if (f.verdict === 'confirmed' && (f.remediation === null || f.toValidate !== null)) {
            ctx.addIssue({ code: 'custom', message: 'a confirmed finding carries a remediation and nothing to validate', path: ['remediation'] });
        }
        if (f.verdict === 'needs_validation' && (f.toValidate === null || f.remediation !== null)) {
            ctx.addIssue({ code: 'custom', message: 'a finding that needs validation says what would settle it, and carries no remediation', path: ['toValidate'] });
        }
        const kinds = f.trace.map((s) => s.kind);
        if (kinds.length === 1) {
            if (kinds[0] === 'propagation') ctx.addIssue({ code: 'custom', message: 'a one-step trace is an entry point or a sink', path: ['trace'] });
        } else {
            const middle = kinds.slice(1, -1);
            if (kinds[0] !== 'entrypoint' || kinds[kinds.length - 1] !== 'sink' || middle.some((k) => k !== 'propagation')) {
                ctx.addIssue({ code: 'custom', message: 'a trace begins at an entry point, ends at a sink, and propagates between them', path: ['trace'] });
            }
        }
    });

/** `scanent-vulnerabilities/1`, everything the signature covers. */
export const VulnerabilitiesReportBodyV1Schema = z
    .object({
        contract: z.literal(VULNERABILITIES_CONTRACT_V1),
        scan: ScanSchema,
        run: RunSchema,
        repositories: z.array(RepositorySchema).max(MAX_REPOSITORIES),
        /** Places selected for review and not reviewed, each with why. */
        notReviewed: z.array(NotReviewedSchema).max(MAX_NOT_REVIEWED),
        /** What was sent to the model, by place. Never the content. */
        sent: z.array(locator).max(MAX_SENT_EXCERPTS),
        counts: z
            .object({
                /** Candidates the hunting produced. */
                candidates: count,
                /** Candidates the refutation broke. */
                rejected: count,
                /** Model answers that did not parse, or named a place that does not exist. */
                discarded: count,
            })
            .strict(),
        findings: z.array(VulnerabilityFindingSchema).max(MAX_FINDINGS),
    })
    .strict()
    .superRefine((r, ctx) => {
        const labels = r.repositories.map((x) => x.label);
        if (new Set(labels).size !== labels.length) ctx.addIssue({ code: 'custom', message: 'each repository label appears once', path: ['repositories'] });
        const known = new Set(labels);
        const placeIn = (loc: string, path: (string | number)[]) => {
            const range = parseCodeRange(loc);
            if (range !== null && !known.has(range.label)) ctx.addIssue({ code: 'custom', message: 'a place names a repository the report lists', path });
        };
        r.sent.forEach((loc, i) => placeIn(loc, ['sent', i]));
        if (new Set(r.sent).size !== r.sent.length) ctx.addIssue({ code: 'custom', message: 'each excerpt sent is listed once', path: ['sent'] });
        r.notReviewed.forEach((n, i) => placeIn(n.locator, ['notReviewed', i, 'locator']));
        const ids = new Set<string>();
        r.findings.forEach((f, i) => {
            if (ids.has(f.id)) ctx.addIssue({ code: 'custom', message: 'a finding id appears once', path: ['findings', i, 'id'] });
            ids.add(f.id);
            f.trace.forEach((s, j) => placeIn(s.locator, ['findings', i, 'trace', j, 'locator']));
        });
        if (r.counts.rejected > r.counts.candidates) ctx.addIssue({ code: 'custom', message: 'no more candidates are rejected than were found', path: ['counts', 'rejected'] });
        if (r.findings.length > r.counts.candidates - r.counts.rejected) {
            ctx.addIssue({ code: 'custom', message: 'every finding is a candidate that survived the refutation', path: ['counts'] });
        }

        if (r.run.status === 'NOT_RUN') {
            if (r.findings.length > 0 || r.sent.length > 0 || r.counts.candidates > 0) {
                ctx.addIssue({ code: 'custom', message: 'a run that did not run sends nothing and finds nothing', path: ['run', 'status'] });
            }
            if (r.repositories.some((x) => x.status !== 'NOT_REVIEWED')) {
                ctx.addIssue({ code: 'custom', message: 'a run that did not run reviewed no repository', path: ['repositories'] });
            }
            if ((r.run.reason === 'NO_REPOSITORY') !== (r.repositories.length === 0)) {
                ctx.addIssue({ code: 'custom', message: 'NO_REPOSITORY goes with an empty repository list, and only with one', path: ['run', 'reason'] });
            }
        }
        if (r.run.status !== 'NOT_RUN' && r.repositories.length === 0) {
            ctx.addIssue({ code: 'custom', message: 'a run that ran reviewed at least one repository: with none, it did not run (NO_REPOSITORY)', path: ['repositories'] });
        }
        if (r.run.status === 'COMPLETE') {
            if (r.repositories.some((x) => x.status !== 'REVIEWED') || r.notReviewed.length > 0) {
                ctx.addIssue({ code: 'custom', message: 'a COMPLETE run reviewed every repository and every place it selected', path: ['run', 'status'] });
            }
        }
        if (r.run.status === 'INCOMPLETE' && r.repositories.length > 0 && r.repositories.every((x) => x.status === 'REVIEWED') && r.notReviewed.length === 0) {
            ctx.addIssue({ code: 'custom', message: 'an INCOMPLETE run says what it did not review', path: ['notReviewed'] });
        }
    });

export type VulnerabilitiesReportBodyV1 = z.infer<typeof VulnerabilitiesReportBodyV1Schema>;
export type VulnerabilitiesReportBody = VulnerabilitiesReportBodyV1;
export type VulnerabilityFinding = VulnerabilitiesReportBody['findings'][number];
export type VulnerabilitiesRun = VulnerabilitiesReportBody['run'];
export type VulnerabilitiesRepository = VulnerabilitiesReportBody['repositories'][number];

export type VulnerabilitiesParseResult =
    | { ok: true; body: VulnerabilitiesReportBody; signerKey: string; complete: boolean }
    | { ok: false; reason: HarnessRefusal; issues?: string[] };

/**
 * Check a raw vulnerabilities report: the harness contract's envelope checks,
 * in its order (`verifySignedEnvelope`), then this contract's strict schema.
 * An agent or integrations report given here is a SCHEMA refusal.
 */
export function verifyAndParseVulnerabilitiesReport(raw: string, trustedSignerKeys: readonly string[]): VulnerabilitiesParseResult {
    const envelope = verifySignedEnvelope(raw, trustedSignerKeys);
    if (!envelope.ok) return { ok: false, reason: envelope.reason };
    if (envelope.body.contract !== VULNERABILITIES_CONTRACT_V1) {
        return { ok: false, reason: 'SCHEMA', issues: ['contract: not a contract id this verifier accepts'] };
    }
    const parsed = VulnerabilitiesReportBodyV1Schema.safeParse(envelope.body);
    if (!parsed.success) return { ok: false, reason: 'SCHEMA', issues: parsed.error.issues.map(describeReportSchemaIssue) };
    return { ok: true, body: parsed.data, signerKey: envelope.signerKey, complete: parsed.data.run.status === 'COMPLETE' };
}
