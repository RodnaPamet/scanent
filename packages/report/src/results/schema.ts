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

import { HARNESS_FINDING_CODES } from '@rodnapamet/scanent-contract/harness-findings';
import { PAYMENT_CLIENT_LIBRARIES, PAYMENT_PROTOCOLS, SOURCE_KINDS } from '@rodnapamet/scanent-contract/harness-contract-rules';
import { MAX_PAYMENT_CAPABILITIES_PER_AGENT } from '@rodnapamet/scanent-contract/harness-contract';
import { ALL_HARNESS_CRITERIA, HARNESS_LEVELS, isHarnessCriterionId, type HarnessCriterionId } from '@rodnapamet/scanent-contract/harness-ladder';

import {
    APPLICATION_ORIGINS,
    CONSENT_TYPES,
    ENTRA_APPLICATION_ID,
    ENTRA_OBJECT_ID,
    EVENT_NAME,
    GITHUB_INSTALLATION_ID,
    GITHUB_PERMISSION_LEVELS,
    GITHUB_WEBHOOK_ID,
    INTEGRATIONS_CONTRACT_IDS,
    INTEGRATIONS_SOURCE_KINDS,
    isApplicationId,
    ISO_DATE,
    OKTA_APP_STATUSES,
    OKTA_APPLICATION_ID,
    OWNER_KINDS,
    REPOSITORY_SELECTIONS,
    SIGN_IN_READ_STATES,
    WEBHOOK_HOST,
} from '@rodnapamet/scanent-contract/integrations-contract-rules';
import {
    INTEGRATION_FINDING_CODES,
    INTEGRATION_NOT_CONCLUDED_WHY,
    MAX_UNUSED_DAYS,
    MIN_UNUSED_DAYS,
    PERMISSION_VIAS,
} from '@rodnapamet/scanent-contract/integrations-findings';
import { PERMISSION_CLASSES } from '@rodnapamet/scanent-contract/integrations-scopes';

import {
    INTEGRATIONS_ONLY_RESULTS_SCHEMA,
    MODEL_SIGNS,
    RESULTS_SCHEMA,
    type IntegrationsOnlyResults,
    type LocalIntegrationsResults,
    type LocalResults,
    type RunResults,
} from './types';

const MAX_TEXT = 4_096;
const id = z.string().min(1).max(256);
const text = z.string().max(MAX_TEXT);
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/);
const count = z.number().int().min(0);
const level = z.enum(HARNESS_LEVELS);
const sourceKind = z.enum(SOURCE_KINDS);
const criterion = z.custom<HarnessCriterionId>((v) => typeof v === 'string' && isHarnessCriterionId(v), 'not a criterion of the ladder');
const reader = z.union([sourceKind, z.literal('inventory')]);

/** One `/4` payment capability, held to the contract's closed lists and its `code://` locator. */
const PaymentCapabilitySchema = z
    .object({
        protocol: z.enum(PAYMENT_PROTOCOLS),
        library: z.enum(PAYMENT_CLIENT_LIBRARIES),
        at: z.string().min(1).max(512).refine((v) => v.startsWith('code://'), 'a payment capability is located by a code:// locator'),
    })
    .strict();

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
        // Absent in a file written before the member existed; never empty when present.
        toolEvidenceSources: z.array(z.enum(['code', 'mcp'])).min(1).max(2).optional(),
        declared: z.object({ name: id, owner: id, purpose: z.string().min(1).max(512), row: z.number().int().min(1) }).strict().nullable(),
        observedOwner: z.object({ kind: z.enum(['user', 'group']), ref: id }).strict().nullable(),
        registration: z.object({ basis: z.enum(['NONE', 'DECLARED_INVENTORY', 'OBSERVED_REGISTER']), ref: id.nullable() }).strict(),
        judgement: JudgementSchema,
        // Added in 0.13.0, and optional: a results file written before it carries none.
        modelSigns: z.array(z.enum(MODEL_SIGNS)).max(MODEL_SIGNS.length).optional(),
        // Added with `/4`, and optional: a results file written before it carries none.
        paymentCapabilities: z.array(PaymentCapabilitySchema).max(MAX_PAYMENT_CAPABILITIES_PER_AGENT).nullable().optional(),
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
        if (agent.toolEvidenceSources !== undefined && new Set(agent.toolEvidenceSources).size !== agent.toolEvidenceSources.length) {
            ctx.addIssue({ code: 'custom', message: 'a tool-evidence source appears once', path: ['toolEvidenceSources'] });
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

// ── The integrations section ──

const guid = z.string().regex(ENTRA_OBJECT_ID);
const permissionName = z.string().min(1).max(128);
const severity = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const integrationsSourceKind = z.enum(INTEGRATIONS_SOURCE_KINDS);
const applicationId = z.string().refine(isApplicationId, 'an application id of one of the products');
const ApplicationPermissionSchema = z.object({ via: z.enum(PERMISSION_VIAS), resourceAppId: guid.nullable(), name: permissionName.nullable() }).strict();

/** What every product's row has: the planner's conclusions about it. */
const conclusions = {
    privilege: z.enum(['HIGH', 'NOT_HIGH', 'NOT_CONCLUDED']),
    classes: z.array(z.enum(PERMISSION_CLASSES)).max(PERMISSION_CLASSES.length),
    highPermissions: z.array(ApplicationPermissionSchema),
    unknownPermissions: z.array(ApplicationPermissionSchema),
    usage: z.enum(['USED', 'UNUSED', 'NOT_CONCLUDED']),
    displayName: z.string().min(1).max(256).nullable(),
};

const EntraApplicationSchema = z
    .object({
        id: z.string().regex(ENTRA_APPLICATION_ID),
        sourceKind: z.literal('entra-integrations'),
        appId: guid.nullable(),
        origin: z.enum(APPLICATION_ORIGINS),
        publisherVerified: z.boolean().nullable(),
        owners: z.array(z.object({ kind: z.enum(OWNER_KINDS), id: guid }).strict()).max(20).nullable(),
        delegatedGrants: z
            .object({
                read: z.boolean(),
                grants: z.array(
                    z
                        .object({
                            resourceAppId: guid.nullable(),
                            consentType: z.enum(CONSENT_TYPES),
                            principalCount: z.number().int().min(1).nullable(),
                            scopes: z.array(permissionName),
                            unreadableScopes: count,
                        })
                        .strict(),
                ),
            })
            .strict(),
        applicationPermissions: z
            .object({ read: z.boolean(), permissions: z.array(z.object({ resourceAppId: guid.nullable(), roleId: guid, name: permissionName.nullable() }).strict()) })
            .strict(),
        signIn: z.object({ read: z.boolean(), lastSeen: z.string().regex(ISO_DATE).nullable(), daysSince: count.nullable() }).strict(),
        credentials: count,
        ...conclusions,
    })
    .strict();

const OktaApplicationSchema = z
    .object({
        id: z.string().regex(OKTA_APPLICATION_ID),
        sourceKind: z.literal('okta-integrations'),
        appId: z.string().min(1).max(64),
        status: z.enum(OKTA_APP_STATUSES).nullable(),
        signOnMode: z.string().min(1).max(64).nullable(),
        scopeGrants: z.object({ read: z.boolean(), scopes: z.array(permissionName), unreadableScopes: count }).strict(),
        ...conclusions,
    })
    .strict();

const GitHubInstallationSchema = z
    .object({
        id: z.string().regex(GITHUB_INSTALLATION_ID),
        sourceKind: z.literal('github-integrations'),
        appId: z.string().regex(/^[1-9][0-9]{0,19}$/).nullable(),
        repositorySelection: z.enum(REPOSITORY_SELECTIONS).nullable(),
        suspended: z.boolean().nullable(),
        events: z.array(z.string().regex(EVENT_NAME)),
        permissions: z
            .object({ read: z.boolean(), grants: z.array(z.object({ name: permissionName, level: z.enum(GITHUB_PERMISSION_LEVELS) }).strict()), unreadable: count })
            .strict(),
        ...conclusions,
    })
    .strict();

/** Whether a row's grants were read in full, in its product's terms. */
const readInFull = (a: z.infer<typeof ApplicationUnion>): boolean =>
    a.sourceKind === 'okta-integrations' ? a.scopeGrants.read : a.sourceKind === 'github-integrations' ? a.permissions.read : a.delegatedGrants.read && a.applicationPermissions.read;

const ApplicationUnion = z.discriminatedUnion('sourceKind', [EntraApplicationSchema, OktaApplicationSchema, GitHubInstallationSchema]);

const ApplicationSchema = ApplicationUnion.superRefine((a, ctx) => {
    // What the file concludes must be what it lists.
    if ((a.privilege === 'HIGH') !== (a.highPermissions.length > 0) || (a.privilege === 'HIGH') !== (a.classes.length > 0)) {
        ctx.addIssue({ code: 'custom', message: 'a high-privilege application lists what makes it so, and only one does', path: ['privilege'] });
    }
    if (a.privilege === 'NOT_HIGH' && (!readInFull(a) || a.unknownPermissions.length > 0)) {
        ctx.addIssue({ code: 'custom', message: 'not high is concluded only from grants read in full and all known', path: ['privilege'] });
    }
    if (a.sourceKind !== 'entra-integrations') {
        if (a.usage !== 'NOT_CONCLUDED') ctx.addIssue({ code: 'custom', message: 'use is never concluded for a product that records none', path: ['usage'] });
        return;
    }
    if (a.usage !== 'NOT_CONCLUDED' && !a.signIn.read) {
        ctx.addIssue({ code: 'custom', message: 'use is concluded only where sign-in activity was read', path: ['usage'] });
    }
    if (!a.signIn.read && (a.signIn.lastSeen !== null || a.signIn.daysSince !== null)) {
        ctx.addIssue({ code: 'custom', message: 'a sign-in that was not read has no date', path: ['signIn'] });
    }
});

const WebhookSchema = z
    .object({
        id: z.string().regex(GITHUB_WEBHOOK_ID),
        sourceKind: z.literal('github-integrations'),
        host: z.string().regex(WEBHOOK_HOST).nullable(),
        events: z.array(z.string().regex(EVENT_NAME)),
        active: z.boolean().nullable(),
        created: z.string().regex(ISO_DATE).nullable(),
    })
    .strict();

const IntegrationFindingSchema = z
    .object({
        code: z.enum(INTEGRATION_FINDING_CODES),
        sourceRef: z.string().min(1).max(1_024),
        severity,
        applicationId: applicationId.nullable(),
        title: text,
        description: z.string().max(16_384),
    })
    .strict();

export const LocalIntegrationsResultsSchema: z.ZodType<LocalIntegrationsResults> = z
    .object({
        contract: z.enum(INTEGRATIONS_CONTRACT_IDS),
        report: z.object({ file: z.string().min(1).max(256), sha256: sha256Hex }).strict(),
        complete: z.boolean(),
        unusedDays: z.number().int().min(MIN_UNUSED_DAYS).max(MAX_UNUSED_DAYS),
        sources: z.array(
            z
                .object({
                    kind: integrationsSourceKind,
                    status: z.enum(['COMPLETE', 'INCOMPLETE']),
                    reason: id.nullable(),
                    rows: count,
                    applications: count,
                    signInActivity: z.object({ status: z.enum(SIGN_IN_READ_STATES), reason: id.nullable(), rows: count.nullable() }).strict(),
                    detail: z.string().min(1).max(800).optional(),
                    excluded: z.object({ count, what: z.string().min(1).max(400) }).strict().optional(),
                })
                .strict(),
        ).min(1),
        applications: z.array(ApplicationSchema),
        findings: z.array(IntegrationFindingSchema),
        notConcluded: z.array(
            z.object({ code: z.enum(INTEGRATION_FINDING_CODES), applicationId: applicationId.nullable(), sourceKind: integrationsSourceKind, why: z.enum(INTEGRATION_NOT_CONCLUDED_WHY) }).strict(),
        ),
        unknownPermissions: z.array(z.object({ via: z.enum(PERMISSION_VIAS), resourceAppId: guid.nullable(), name: z.string().min(1).max(256) }).strict()),
        webhooks: z.object({ read: z.boolean(), hooks: z.array(WebhookSchema) }).strict().nullable(),
        counts: z.object({ applications: count, highPrivilege: count, unverifiedPublisher: count, noOwner: count, unused: count }).strict(),
    })
    .strict()
    .superRefine((r, ctx) => {
        const complete = r.sources.length > 0 && r.sources.every((s) => s.status === 'COMPLETE' && s.signInActivity.status !== 'INCOMPLETE');
        if (r.complete !== complete) ctx.addIssue({ code: 'custom', message: 'complete means every source and every sign-in read was read in full', path: ['complete'] });
        const by = (code: string) => r.findings.filter((f) => f.code === code).length;
        const c = r.counts;
        if (
            c.applications !== r.applications.length ||
            c.highPrivilege !== by('INTEGRATION_HIGH_PRIVILEGE_GRANT') ||
            c.unverifiedPublisher !== by('INTEGRATION_UNVERIFIED_PUBLISHER') ||
            c.noOwner !== by('INTEGRATION_NO_OWNER') ||
            c.unused !== by('INTEGRATION_UNUSED')
        ) {
            ctx.addIssue({ code: 'custom', message: 'the counts are the applications and findings listed', path: ['counts'] });
        }
        if (new Set(r.applications.map((a) => a.id)).size !== r.applications.length) {
            ctx.addIssue({ code: 'custom', message: 'an application id appears once', path: ['applications'] });
        }
        // An empty inventory from a whole read is a finding, never a quiet empty list.
        for (const s of r.sources) {
            if (s.status === 'COMPLETE' && s.applications === 0 && !r.findings.some((f) => f.code === 'INTEGRATION_EMPTY_INVENTORY' && f.sourceRef.endsWith(`:${s.kind}`))) {
                ctx.addIssue({ code: 'custom', message: 'a source read in full that holds no application is a finding', path: ['findings'] });
            }
        }
    });

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
                    // Added in 0.13.0, and optional: a results file written before it carries none.
                    detail: z.string().min(1).max(400).optional(),
                    notRead: z.array(z.object({ where: z.string().min(1).max(600), reason: id }).strict()).max(25).optional(),
                    notReadTotal: count.optional(),
                })
                .strict()
                .superRefine((s, ctx) => {
                    const noted = s.detail !== undefined || s.notRead !== undefined || s.notReadTotal !== undefined;
                    if (noted && s.status === 'COMPLETE') ctx.addIssue({ code: 'custom', message: 'a source read in full names nothing it did not read' });
                    if ((s.notRead === undefined) !== (s.notReadTotal === undefined)) {
                        ctx.addIssue({ code: 'custom', message: 'notRead and notReadTotal are given together' });
                    }
                    if (s.notRead !== undefined && s.notReadTotal !== undefined && s.notReadTotal < s.notRead.length) {
                        ctx.addIssue({ code: 'custom', message: 'notReadTotal counts at least the places listed' });
                    }
                }),
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
                // Added in 0.13.0, and optional, as `modelSigns` is.
                unregisteredIdentities: z.array(id).optional(),
                // Added with `/4`, and optional, as `unregisteredIdentities` is.
                payingAgents: z.array(id).optional(),
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
        // Added with the integrations scanner, and optional: an agents-only run, and a file written before it, carries none.
        integrations: LocalIntegrationsResultsSchema.optional(),
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
        // An unregistered automated identity is the file's own statement about an agent it
        // lists: unregistered, and with no sign of a model. It is in one list or the other.
        const identities = new Set(r.estate.unregisteredIdentities ?? []);
        const byId = new Map(r.agents.map((a) => [a.discoveredId, a]));
        for (const identity of identities) {
            const agent = byId.get(identity);
            if (agent === undefined || agent.registration.basis !== 'NONE' || agent.modelSigns === undefined || agent.modelSigns.length > 0) {
                ctx.addIssue({
                    code: 'custom',
                    message: 'an unregistered identity is a listed agent with no registration and no sign of a model',
                    path: ['estate', 'unregisteredIdentities'],
                });
            }
        }
        if (r.estate.shadowAgents.some((shadow) => identities.has(shadow))) {
            ctx.addIssue({ code: 'custom', message: 'a principal is a shadow agent or an unregistered identity, not both', path: ['estate', 'shadowAgents'] });
        }
        // The paying agents are exactly the listed agents whose own facts name a payment capability.
        if (r.estate.payingAgents !== undefined) {
            const paying = r.agents.filter((a) => (a.paymentCapabilities ?? []).length > 0).map((a) => a.discoveredId);
            const listed = r.estate.payingAgents;
            if (new Set(listed).size !== listed.length || listed.length !== paying.length || new Set([...listed, ...paying]).size !== paying.length) {
                ctx.addIssue({
                    code: 'custom',
                    message: 'the paying agents are the listed agents that report a payment capability',
                    path: ['estate', 'payingAgents'],
                });
            }
        }
        if (r.agents.some((a) => a.paymentCapabilities != null && new Set(a.paymentCapabilities.map((c) => `${c.library}\u0000${c.at}`)).size !== a.paymentCapabilities.length)) {
            ctx.addIssue({ code: 'custom', message: 'each payment capability appears once', path: ['agents'] });
        }
        if (r.agents.some((a) => a.modelSigns !== undefined && new Set(a.modelSigns).size !== a.modelSigns.length)) {
            ctx.addIssue({ code: 'custom', message: 'a model sign appears once', path: ['agents'] });
        }
        const tally = Object.fromEntries(HARNESS_LEVELS.map((l) => [l, 0])) as Record<(typeof HARNESS_LEVELS)[number], number>;
        let shortfalls = 0;
        for (const a of r.agents) {
            if (a.judgement.state !== 'JUDGED') continue;
            tally[a.judgement.level] += 1;
            // An unregistered identity is held to no bar.
            if (a.judgement.shortfall && !identities.has(a.discoveredId)) shortfalls += 1;
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

/** `results.json` of a run in which only the integrations scanner ran. Strict, as the agent results are. */
export const IntegrationsOnlyResultsSchema: z.ZodType<IntegrationsOnlyResults> = z
    .object({
        schema: z.literal(INTEGRATIONS_ONLY_RESULTS_SCHEMA),
        scanners: z.tuple([z.literal('integrations')]),
        scan: z
            .object({
                id,
                asOf: z.string().datetime(),
                estate: id.nullable(),
                scanner: z.object({ agentId: id, version: id, manifestHash: z.string().regex(/^sha256:[0-9a-f]{64}$/) }).strict(),
            })
            .strict(),
        signer: z.object({ keyFingerprint: sha256Hex, pinned: z.boolean() }).strict(),
        integrations: LocalIntegrationsResultsSchema,
    })
    .strict();

/**
 * A run's `results.json`, by the schema it names: the agent results, or the
 * integrations scanner's alone. Null when it names neither, or fails the one
 * it names: a file is never half-read under the other's rules.
 */
export function parseRunResults(json: unknown): { readonly ok: true; readonly results: RunResults } | { readonly ok: false; readonly issues: readonly string[] } {
    const schema = json !== null && typeof json === 'object' ? (json as { schema?: unknown }).schema : undefined;
    const parsed = schema === INTEGRATIONS_ONLY_RESULTS_SCHEMA ? IntegrationsOnlyResultsSchema.safeParse(json) : LocalResultsSchema.safeParse(json);
    return parsed.success ? { ok: true, results: parsed.data } : { ok: false, issues: parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`) };
}

