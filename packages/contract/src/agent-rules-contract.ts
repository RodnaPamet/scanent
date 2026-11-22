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
 *   • EACH SERVER IT READ, AND HOW. `servers[]` names every MCP server the run
 *     read, COMPLETE or INCOMPLETE, and how many of its tools the rules ran
 *     over; each finding names its server. A consumer closes a finding only
 *     when the same scanner read that server in full and did not raise it again:
 *     a server left out of a scan, or read in part, says nothing about it.
 */
import { z } from 'zod';

import { describeReportSchemaIssue, INCOMPLETE_REASONS_V2, MAX_ID_CHARS, verifySignedEnvelope, type HarnessRefusal } from './harness-contract';
import { looksLikeSecret } from './harness-contract-rules';
import {
    AGENT_RULE_LOCATOR,
    AGENT_RULE_SEVERITIES,
    AGENT_RULES_CONTRACT_V1,
    AGENT_RULES_FINDING_CODES,
    AGENT_RULES_SUBJECT_KINDS,
    MAX_AGENT_RULE_FINDINGS,
    AGENT_RULE_SERVER_REF,
    MAX_SERVERS_READ,
    MAX_SUBJECTS_READ,
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

const serverRef = z
    .string()
    .regex(AGENT_RULE_SERVER_REF)
    .refine((v) => !looksLikeSecret(v), 'a server ref must not have the shape of a secret');

/** One MCP server the run read, and whether every tool it lists was read in full. */
const ServerSchema = z
    .object({
        ref: serverRef,
        status: z.enum(['COMPLETE', 'INCOMPLETE']),
        reason: reason.optional(),
        /** How many of its tools the rules were run over. */
        tools: count.max(MAX_SUBJECTS_READ),
    })
    .strict()
    .superRefine((s, ctx) => {
        if (s.status === 'INCOMPLETE' && s.reason === undefined) ctx.addIssue({ code: 'custom', message: 'an INCOMPLETE server names its reason', path: ['reason'] });
        if (s.status === 'COMPLETE' && s.reason !== undefined) ctx.addIssue({ code: 'custom', message: 'a COMPLETE server carries no reason', path: ['reason'] });
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
        /** The server the subject was read from: one of `servers[]`. */
        serverRef,
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
    });

/** `scanent-agent-rules/1`, everything the signature covers. */
export const AgentRulesReportBodyV1Schema = z
    .object({
        contract: z.literal(AGENT_RULES_CONTRACT_V1),
        scan: ScanSchema,
        population: z.array(PopulationSchema).min(1).max(AGENT_RULES_SUBJECT_KINDS.length),
        servers: z.array(ServerSchema).max(MAX_SERVERS_READ),
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
        // The servers account for the MCP tool population, server by server.
        const refs = r.servers.map((s) => s.ref);
        if (new Set(refs).size !== refs.length) ctx.addIssue({ code: 'custom', message: 'each server appears once', path: ['servers'] });
        const listed = new Set(refs);
        r.findings.forEach((f, i) => {
            if (!listed.has(f.serverRef)) ctx.addIssue({ code: 'custom', message: 'a finding names a server the report lists', path: ['findings', i, 'serverRef'] });
        });
        const tools = r.population.find((p) => p.kind === 'mcp-tool');
        if (tools !== undefined) {
            if (r.servers.reduce((n, s) => n + s.tools, 0) !== tools.subjects) {
                ctx.addIssue({ code: 'custom', message: 'the servers’ tools add up to the mcp-tool population', path: ['servers'] });
            }
            const allComplete = r.servers.every((s) => s.status === 'COMPLETE');
            if (tools.status === 'COMPLETE' && !allComplete) {
                ctx.addIssue({ code: 'custom', message: 'a COMPLETE mcp-tool population has every server read in full', path: ['population'] });
            }
            if (tools.status === 'INCOMPLETE' && r.servers.length > 0 && allComplete) {
                ctx.addIssue({ code: 'custom', message: 'an INCOMPLETE mcp-tool population has a server read in part', path: ['servers'] });
            }
        } else if (r.servers.length > 0) {
            ctx.addIssue({ code: 'custom', message: 'servers are listed only beside an mcp-tool population', path: ['servers'] });
        }
    });

export type AgentRulesReportBodyV1 = z.infer<typeof AgentRulesReportBodyV1Schema>;
export type AgentRulesReportBody = AgentRulesReportBodyV1;
export type AgentRuleFinding = AgentRulesReportBody['findings'][number];
export type AgentRulesPopulation = AgentRulesReportBody['population'][number];
export type AgentRulesServer = AgentRulesReportBody['servers'][number];

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
