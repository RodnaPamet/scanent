/**
 * The wire contract `scanent-agent-rules/1`: what static rules found written
 * into an agent's own surface.
 *
 * A strict schema of its own, held to the agent report's rules rather than a
 * copy of them: the same byte cap, the same signature over the same canonical
 * JSON (`verifySignedEnvelope`), the same refusal codes in the same order, and
 * the same walk for a secret's shape over every string member. A report of one
 * contract is never read by another's verifier.
 *
 * ‾‾‾ WHAT THE REPORT DELIBERATELY CANNOT SAY ‾‾‾
 *
 *   • THE TEXT. A finding is a code, the rule id that fired, the subject and a
 *     locator. Never the description, never an excerpt. The rules run where the
 *     text is and only the finding leaves.
 *   • CRITICAL, OR MORE THAN A CODE ALLOWS. Each code has a ceiling
 *     (`SEVERITY_CEILING`); a finding above it is refused, never lowered here.
 *   • A CLEAN BILL IT DID NOT EARN. A population read in part concludes
 *     nothing; `COMPLETE` means every subject of that kind was read.
 *
 * ‾‾‾ WHAT IT SAYS SO A FINDING CAN BE CLOSED ‾‾‾
 *
 *   • EACH ORIGIN IT READ, AND HOW. `origins[]` names every place the run read
 *     subjects from — an MCP server, a code root — COMPLETE or INCOMPLETE, and
 *     how many subjects the rules ran over there; each finding names its
 *     origin. A consumer closes a finding only when the same scanner read that
 *     origin in full and did not raise it again: an origin left out of a scan,
 *     or read in part, says nothing about it.
 */
import { z } from 'zod';

import { describeReportSchemaIssue, INCOMPLETE_REASONS_V2, MAX_ID_CHARS, verifySignedEnvelope, type HarnessRefusal } from './harness-contract';
import { looksLikeSecret } from './harness-contract-rules';
import {
    AGENT_RULE_LOCATOR,
    AGENT_RULE_SEVERITIES,
    AGENT_RULES_CONTRACT_V1,
    AGENT_RULES_FINDING_CODES,
    CODE_SUBJECT_KINDS,
    AGENT_RULES_SUBJECT_KINDS,
    MAX_AGENT_RULE_FINDINGS,
    AGENT_RULE_ORIGIN_REF,
    MAX_ORIGINS_READ,
    MAX_SUBJECTS_READ,
    ORIGIN_FAMILY_OF_KIND,
    originFamily,
    RULE_ID,
    SEVERITY_CEILING,
    withinCeiling,
    type AgentRuleFindingCode,
} from './agent-rules-contract-rules';

export * from './agent-rules-contract-rules';

const SHA256_HEX = /^sha256:[0-9a-f]{64}$/;

const id = z.string().min(1).max(MAX_ID_CHARS);
const count = z.number().int().min(0);
const reason = z.enum(INCOMPLETE_REASONS_V2);

const ScanSchema = z
    .object({
        id,
        asOf: z.string().datetime(),
        scanner: z.object({ agentId: id, version: id, manifestHash: z.string().regex(SHA256_HEX) }).strict(),
    })
    .strict();

/** One subject kind the run read, and whether it was read in full. */
const PopulationSchema = z
    .object({
        kind: z.enum(AGENT_RULES_SUBJECT_KINDS),
        status: z.enum(['COMPLETE', 'INCOMPLETE']),
        reason: reason.optional(),
        /** How many subjects of this kind the rules were run over. */
        subjects: count.max(MAX_SUBJECTS_READ),
    })
    .strict()
    .superRefine((p, ctx) => {
        if (p.status === 'INCOMPLETE' && p.reason === undefined) ctx.addIssue({ code: 'custom', message: 'an INCOMPLETE population names its reason', path: ['reason'] });
        if (p.status === 'COMPLETE' && p.reason !== undefined) ctx.addIssue({ code: 'custom', message: 'a COMPLETE population carries no reason', path: ['reason'] });
    });

const originRef = z
    .string()
    .regex(AGENT_RULE_ORIGIN_REF)
    .refine((v) => !looksLikeSecret(v), 'an origin ref must not have the shape of a secret');

/** One origin the run read — an MCP server, a code root — and whether every subject there was read in full. */
const OriginSchema = z
    .object({
        ref: originRef,
        status: z.enum(['COMPLETE', 'INCOMPLETE']),
        reason: reason.optional(),
        /** How many subjects the rules were run over there. */
        subjects: count.max(MAX_SUBJECTS_READ),
    })
    .strict()
    .superRefine((s, ctx) => {
        if (s.status === 'INCOMPLETE' && s.reason === undefined) ctx.addIssue({ code: 'custom', message: 'an INCOMPLETE origin names its reason', path: ['reason'] });
        if (s.status === 'COMPLETE' && s.reason !== undefined) ctx.addIssue({ code: 'custom', message: 'a COMPLETE origin carries no reason', path: ['reason'] });
    });

const FindingSchema = z
    .object({
        code: z.enum(AGENT_RULES_FINDING_CODES),
        /** The rule that fired, as provenance and a stable key. */
        ruleId: z.string().regex(RULE_ID),
        severity: z.enum(AGENT_RULE_SEVERITIES),
        subjectKind: z.enum(AGENT_RULES_SUBJECT_KINDS),
        /** The agent or tool it is about, in the scanner's own namespace. */
        subjectRef: z
            .string()
            .min(1)
            .max(480)
            .refine((v) => !looksLikeSecret(v), 'a subject ref must not have the shape of a secret'),
        /** Where the subject was read from: one of `origins[]`. */
        originRef,
        /** `<kind>:<ref>#<field>`, never the text. */
        locator: z
            .string()
            .regex(AGENT_RULE_LOCATOR)
            .refine((v) => !looksLikeSecret(v), 'a locator must not have the shape of a secret'),
    })
    .strict()
    .superRefine((f, ctx) => {
        if (!withinCeiling(f.code, f.severity)) {
            ctx.addIssue({ code: 'custom', message: `a ${f.code} finding is at most ${SEVERITY_CEILING[f.code]}`, path: ['severity'] });
        }
        if (!f.locator.startsWith(`${f.subjectKind}:`)) {
            ctx.addIssue({ code: 'custom', message: 'a locator begins with its finding’s subject kind', path: ['locator'] });
        }
        if (!CODE_SUBJECT_KINDS[f.code].includes(f.subjectKind)) {
            ctx.addIssue({ code: 'custom', message: `a ${f.code} finding is raised on ${CODE_SUBJECT_KINDS[f.code].join(' or ')} only`, path: ['code'] });
        }
        if (originFamily(f.originRef) !== ORIGIN_FAMILY_OF_KIND[f.subjectKind]) {
            ctx.addIssue({ code: 'custom', message: 'a finding’s origin is of the family its subject kind is read from', path: ['originRef'] });
        }
    });

/** `scanent-agent-rules/1`, everything the signature covers. */
export const AgentRulesReportBodyV1Schema = z
    .object({
        contract: z.literal(AGENT_RULES_CONTRACT_V1),
        scan: ScanSchema,
        population: z.array(PopulationSchema).min(1).max(AGENT_RULES_SUBJECT_KINDS.length),
        origins: z.array(OriginSchema).max(MAX_ORIGINS_READ),
        findings: z.array(FindingSchema).max(MAX_AGENT_RULE_FINDINGS),
        counts: z
            .object({
                /** Subjects the rules were run over, across every population. */
                subjects: count.max(MAX_SUBJECTS_READ),
                /** Subjects that fired at least one rule. */
                flagged: count.max(MAX_SUBJECTS_READ),
            })
            .strict(),
    })
    .strict()
    .superRefine((r, ctx) => {
        const kinds = r.population.map((p) => p.kind);
        if (new Set(kinds).size !== kinds.length) ctx.addIssue({ code: 'custom', message: 'each subject kind appears once', path: ['population'] });
        const read = new Set(kinds);
        const total = r.population.reduce((n, p) => n + p.subjects, 0);
        if (r.counts.subjects !== total) ctx.addIssue({ code: 'custom', message: 'counts.subjects is the sum of the populations', path: ['counts', 'subjects'] });
        if (r.counts.flagged > r.counts.subjects) ctx.addIssue({ code: 'custom', message: 'no more subjects are flagged than were read', path: ['counts', 'flagged'] });
        if ((r.counts.flagged > 0) !== (r.findings.length > 0)) ctx.addIssue({ code: 'custom', message: 'a flagged subject means a finding, and a finding a flagged subject', path: ['counts', 'flagged'] });
        if (r.counts.flagged > r.findings.length) ctx.addIssue({ code: 'custom', message: 'no more subjects are flagged than there are findings', path: ['counts', 'flagged'] });
        r.findings.forEach((f, i) => {
            if (!read.has(f.subjectKind)) ctx.addIssue({ code: 'custom', message: 'a finding names a subject kind the report read', path: ['findings', i, 'subjectKind'] });
        });
        // The origins account for the populations, family by family.
        const refs = r.origins.map((o) => o.ref);
        if (new Set(refs).size !== refs.length) ctx.addIssue({ code: 'custom', message: 'each origin appears once', path: ['origins'] });
        const listed = new Set(refs);
        r.findings.forEach((f, i) => {
            if (!listed.has(f.originRef)) ctx.addIssue({ code: 'custom', message: 'a finding names an origin the report lists', path: ['findings', i, 'originRef'] });
        });
        for (const family of ['mcp', 'code'] as const) {
            const populations = r.population.filter((p) => ORIGIN_FAMILY_OF_KIND[p.kind] === family);
            const origins = r.origins.filter((o) => originFamily(o.ref) === family);
            if (populations.length === 0) {
                if (origins.length > 0) ctx.addIssue({ code: 'custom', message: `${family} origins are listed only beside a population read from them`, path: ['origins'] });
                continue;
            }
            if (origins.reduce((n, o) => n + o.subjects, 0) !== populations.reduce((n, p) => n + p.subjects, 0)) {
                ctx.addIssue({ code: 'custom', message: `the ${family} origins’ subjects add up to the populations read from them`, path: ['origins'] });
            }
            const allComplete = origins.every((o) => o.status === 'COMPLETE');
            populations.forEach((p) => {
                if (p.status === 'COMPLETE' && !allComplete) {
                    ctx.addIssue({ code: 'custom', message: `a COMPLETE ${p.kind} population has every ${family} origin read in full`, path: ['population'] });
                }
            });
            if (populations.every((p) => p.status === 'INCOMPLETE') && origins.length > 0 && allComplete) {
                ctx.addIssue({ code: 'custom', message: `an INCOMPLETE ${family} population has an origin read in part`, path: ['origins'] });
            }
        }
    });

export type AgentRulesReportBodyV1 = z.infer<typeof AgentRulesReportBodyV1Schema>;
export type AgentRulesReportBody = AgentRulesReportBodyV1;
export type AgentRuleFinding = AgentRulesReportBody['findings'][number];
export type AgentRulesPopulation = AgentRulesReportBody['population'][number];
export type AgentRulesOrigin = AgentRulesReportBody['origins'][number];

/** Whether every population the report read was read in full. */
export function isAgentRulesScanComplete(body: AgentRulesReportBody): boolean {
    return body.population.every((p) => p.status === 'COMPLETE');
}

export type AgentRulesParseResult =
    | { ok: true; body: AgentRulesReportBody; signerKey: string; complete: boolean }
    | { ok: false; reason: HarnessRefusal; issues?: string[] };

/**
 * Check a raw agent-rules report: the harness contract's envelope checks, in
 * its order (`verifySignedEnvelope`), then this contract's strict schema. A
 * report of any other contract given here is a SCHEMA refusal.
 */
export function verifyAndParseAgentRulesReport(raw: string, trustedSignerKeys: readonly string[]): AgentRulesParseResult {
    const envelope = verifySignedEnvelope(raw, trustedSignerKeys);
    if (!envelope.ok) return { ok: false, reason: envelope.reason };
    if (envelope.body.contract !== AGENT_RULES_CONTRACT_V1) {
        return { ok: false, reason: 'SCHEMA', issues: ['contract: not a contract id this verifier accepts'] };
    }
    const parsed = AgentRulesReportBodyV1Schema.safeParse(envelope.body);
    if (!parsed.success) return { ok: false, reason: 'SCHEMA', issues: parsed.error.issues.map(describeReportSchemaIssue) };
    return { ok: true, body: parsed.data, signerKey: envelope.signerKey, complete: isAgentRulesScanComplete(parsed.data) };
}

// `AgentRuleFindingCode` re-exported for callers of the planner.
export type { AgentRuleFindingCode };
