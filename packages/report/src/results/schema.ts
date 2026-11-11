/**
 * THE STRICT SCHEMA OF `results.json`.
 *
 * A results file read back (by a diff, by a later run) is untrusted input like
 * any other: strict objects throughout, so a file with a member this version
 * does not know is refused rather than half-read, and the rules a level
 * depends on are checked rather than assumed:
 *
 *   • an agent that is NOT JUDGED carries no level, bar or shortfall member,
 *     and at least one reason;
 *   • every agent answers every criterion of the ladder the file names, once
 *     and in ladder order;
 *   • an unanswered criterion has no basis and no evidence, and an answered
 *     one has a basis;
 *   • `scan.complete` is what the listed sources say, and the estate's counts
 *     (agents, judged, per level, shortfalls) are those of the agents listed.
 *
 * PURE: no clock, no I/O.
 */
import { z } from 'zod';

import { HARNESS_FINDING_CODES } from '@scanent/contract/harness-findings';
import { SOURCE_KINDS } from '@scanent/contract/harness-contract-rules';
import { ALL_HARNESS_CRITERIA, HARNESS_LEVELS, isHarnessCriterionId, type HarnessCriterionId } from '@scanent/contract/harness-ladder';

import { RESULTS_SCHEMA, type LocalResults } from './types';

const MAX_TEXT = 4_096;
const id = z.string().min(1).max(256);
const text = z.string().max(MAX_TEXT);
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/);
const count = z.number().int().min(0);
const level = z.enum(HARNESS_LEVELS);
const sourceKind = z.enum(SOURCE_KINDS);
const criterion = z.custom<HarnessCriterionId>((v) => typeof v === 'string' && isHarnessCriterionId(v), 'not a criterion of the ladder');
const reader = z.union([sourceKind, z.literal('inventory')]);

const CellSchema = z
    .object({
        criterion,
        state: z.enum(['EVIDENCED', 'MET_UNEVIDENCED', 'NOT_MET', 'UNANSWERED']),
        basis: z.enum(['OBSERVED', 'DECLARED']).nullable(),
        evidence: text.nullable(),
        readable: z.boolean(),
    })
    .strict()
    .superRefine((cell, ctx) => {
        if (cell.state === 'UNANSWERED' ? cell.basis !== null || cell.evidence !== null : cell.basis === null) {
            ctx.addIssue({ code: 'custom', message: 'a basis goes with an answer, and only with one', path: ['basis'] });
        }
    });

const JudgementSchema = z.discriminatedUnion('state', [
    z
        .object({
            state: z.literal('JUDGED'),
            level,
            observedLevel: level,
            bar: level,
            shortfall: z.boolean(),
            blockingNextRung: z.array(criterion).max(ALL_HARNESS_CRITERIA.length),
            caveats: z.array(id).max(64),
        })
        .strict(),
    z
        .object({
            state: z.literal('NOT_JUDGED'),
            reasons: z.array(id).min(1).max(64),
        })
        .strict(),
]);

const AgentSchema = z
    .object({
        discoveredId: id,
        discoveredVia: z.array(sourceKind).min(1).max(SOURCE_KINDS.length),
        declared: z.object({ name: id, owner: id, purpose: z.string().min(1).max(512), row: z.number().int().min(1) }).strict().nullable(),
        observedOwner: z.object({ kind: z.enum(['user', 'group']), ref: id }).strict().nullable(),
        registration: z.object({ basis: z.enum(['NONE', 'DECLARED_INVENTORY', 'OBSERVED_REGISTER']), ref: id.nullable() }).strict(),
        judgement: JudgementSchema,
        reach: z.enum(['READ_ONLY', 'WRITE_OR_EXTERNAL', 'UNKNOWN']),
        criteria: z.array(CellSchema).length(ALL_HARNESS_CRITERIA.length),
        counts: z
            .object({
                credentials: count,
                tools: count,
                writeCapableTools: count,
                unpinnedWriteTools: count,
                models: count.nullable(),
            })
            .strict(),
    })
    .strict()
    .superRefine((agent, ctx) => {
        if (agent.criteria.some((cell, i) => cell.criterion !== ALL_HARNESS_CRITERIA[i])) {
            ctx.addIssue({ code: 'custom', message: 'every criterion once, in ladder order', path: ['criteria'] });
        }
        if ((agent.registration.basis === 'NONE') !== (agent.registration.ref === null)) {
            ctx.addIssue({ code: 'custom', message: 'a registration names what it rests on, or is none', path: ['registration'] });
        }
    });

const FindingSchema = z
    .object({
        code: z.enum(HARNESS_FINDING_CODES),
        sourceRef: z.string().min(1).max(1_024),
        severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
        type: z.enum(['NONCONFORMITY', 'OBSERVATION']),
        discoveredId: id.nullable(),
        title: text,
        description: z.string().max(16_384),
    })
    .strict();

const credentialSeen = { ref: z.string().min(1).max(512), sourceKind };

export const LocalResultsSchema: z.ZodType<LocalResults> = z
    .object({
        schema: z.literal(RESULTS_SCHEMA),
        ladder: z
            .object({
                version: z.string().regex(/^sha256:[0-9a-f]{64}$/),
                levels: z.array(level).length(HARNESS_LEVELS.length),
                criteria: z.object(Object.fromEntries(HARNESS_LEVELS.map((l) => [l, z.array(criterion)])) as Record<
                    (typeof HARNESS_LEVELS)[number],
                    z.ZodArray<typeof criterion>
                >).strict(),
            })
            .strict(),
        scan: z
            .object({
                id,
                asOf: z.string().datetime(),
                estate: id.nullable(),
                contract: id,
                scanner: z.object({ agentId: id, version: id, manifestHash: z.string().regex(/^sha256:[0-9a-f]{64}$/) }).strict(),
                complete: z.boolean(),
                registerClaimsVerified: z.boolean(),
            })
            .strict(),
        report: z.object({ sha256: sha256Hex, signerKeyFingerprint: sha256Hex, signerPinned: z.boolean() }).strict(),
        inventory: z
            .object({
                provenance: z.literal('DECLARED_BY_OPERATOR'),
                sha256: sha256Hex,
                format: z.enum(['json', 'csv']),
                rows: count,
                matched: count,
                unmatched: z.array(id),
            })
            .strict()
            .nullable(),
        sources: z.array(
            z
                .object({
                    kind: sourceKind,
                    status: z.enum(['COMPLETE', 'INCOMPLETE']),
                    reason: id.nullable(),
                    rows: count,
                    agents: count,
                })
                .strict(),
        ),
        coverage: z
            .object({
                reachableLevel: level,
                unreadable: z.array(
                    z.object({ criterion, why: z.enum(['NO_READER', 'READER_NOT_CONFIGURED']), readers: z.array(reader) }).strict(),
                ),
            })
            .strict(),
        estate: z
            .object({
                empty: z.boolean(),
                agentCount: count,
                judgedCount: count,
                notJudgedCount: count,
                byLevel: z.object(Object.fromEntries(HARNESS_LEVELS.map((l) => [l, count])) as Record<
                    (typeof HARNESS_LEVELS)[number],
                    typeof count
                >).strict(),
                shortfallCount: count,
                registrationBasis: z.enum(['NONE', 'INVENTORY', 'INFLECT_REGISTER', 'BOTH']),
                shadowAgents: z.array(id),
                orphanCredentials: z.array(z.object(credentialSeen).strict()),
                unboundNotConcluded: z.array(
                    z.object({ ...credentialSeen, why: z.enum(['OWN_SOURCE_INCOMPLETE', 'IDENTITY_SOURCE_INCOMPLETE']) }).strict(),
                ),
                registrationConflicts: z.array(
                    z.object({ discoveredId: id, reportedRegisteredAgentId: id, intakeRegisteredAgentId: id }).strict(),
                ),
            })
            .strict(),
        agents: z.array(AgentSchema),
        findings: z.array(FindingSchema),
    })
    .strict()
    .superRefine((r, ctx) => {
        const judged = r.agents.filter((a) => a.judgement.state === 'JUDGED').length;
        if (r.estate.agentCount !== r.agents.length || r.estate.judgedCount !== judged || r.estate.notJudgedCount !== r.agents.length - judged) {
            ctx.addIssue({ code: 'custom', message: 'the counts are the agents listed', path: ['estate'] });
        }
        // What a reader acts on must be what the file lists: a `complete` beside an
        // incomplete source, or a tally that is not the agents', is refused.
        if (r.scan.complete !== (r.sources.length > 0 && r.sources.every((s) => s.status === 'COMPLETE'))) {
            ctx.addIssue({ code: 'custom', message: 'complete means every listed source was read in full, and only that', path: ['scan', 'complete'] });
        }
        const tally = Object.fromEntries(HARNESS_LEVELS.map((l) => [l, 0])) as Record<(typeof HARNESS_LEVELS)[number], number>;
        let shortfalls = 0;
        for (const a of r.agents) {
            if (a.judgement.state !== 'JUDGED') continue;
            tally[a.judgement.level] += 1;
            if (a.judgement.shortfall) shortfalls += 1;
        }
        if (HARNESS_LEVELS.some((l) => r.estate.byLevel[l] !== tally[l])) {
            ctx.addIssue({ code: 'custom', message: 'the agents per level are the judged agents listed', path: ['estate', 'byLevel'] });
        }
        if (r.estate.shortfallCount !== shortfalls) {
            ctx.addIssue({ code: 'custom', message: 'the shortfall count is the judged agents below their bar', path: ['estate', 'shortfallCount'] });
        }
        if (r.estate.empty !== (r.agents.length === 0)) {
            ctx.addIssue({ code: 'custom', message: 'empty means no agents, and only that', path: ['estate', 'empty'] });
        }
        if (new Set(r.agents.map((a) => a.discoveredId)).size !== r.agents.length) {
            ctx.addIssue({ code: 'custom', message: 'a discoveredId appears once', path: ['agents'] });
        }
    });
