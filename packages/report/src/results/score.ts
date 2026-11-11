/**
 * LOCAL SCORING — one scan, judged where it was taken.
 *
 * `scoreReportLocally` turns a signed report body (and, when the operator has
 * one, an inventory) into `LocalResults`. It decides nothing the contract
 * already decides: the level is `scoreHarness`, a cell is `criterionState`
 * over `collapseVerdicts`, the bar is `harnessBarFor`, and the findings are
 * `planHarnessScan`'s. What it adds is what a tenant would have supplied and a
 * standalone run cannot: a prior state built from the run itself, the
 * inventory in the register's place, and an account of what was not read.
 *
 * THE PRIOR STATE. Nothing is stored between runs, so the planner is given:
 *
 *   previousLevels         none: a fall in level is a fact about two runs
 *   acceptedShortfalls     none: acceptance is a workflow this run has no part in
 *   openOrphanCredentials  none: nothing was open before this run
 *   registeredAgentIds     every non-null `registeredAgentId` in the body. The
 *                          scanner's builder takes that member from the
 *                          register source alone, so the row exists
 *   intakeClaims           one per inventory row that names an agent in the scan
 *
 * THE INVENTORY TAKES THE PLANNER'S "REGISTER'S OWN RECORD" PATH on purpose.
 * The rules on that path are the ones an inventory should have: a link the
 * report itself carries wins over it; it closes SHADOW_AGENT only on a
 * complete scan; on an incomplete scan it links the agent and neither raises
 * nor resolves the finding. No planner code changes, so the rule cannot drift
 * between a tenant and a standalone run.
 *
 * DECLARED VERDICTS FOLLOW THE OBSERVED ONES into the collapse, so a declared
 * "met" never outvotes an observed NOT MET (least favourable wins), and where
 * both say the same the observed one stands.
 *
 * PURE: no clock, no I/O, no hashing. Same input, same value.
 */
import { LADDER_VERSION, type HarnessReportAgent, type HarnessReportBody } from '@scanent/contract/harness-contract';
import {
    harnessBarFor,
    isHarnessShortfall,
    isWriteCapable,
    orphanCredentialRefOf,
    planHarnessScan,
    shadowRefOf,
    shortfallRefOf,
    type HarnessSourceKind,
    type IntakeClaim,
    type PlannedAgent,
    type PlannedFinding,
} from '@scanent/contract/harness-findings';
import { isScanComplete } from '@scanent/contract/harness-contract-rules';
import {
    ALL_HARNESS_CRITERIA,
    collapseVerdicts,
    criterionState,
    HARNESS_CRITERIA,
    HARNESS_LEVELS,
    scoreHarness,
    type CriterionVerdict,
    type HarnessCriterionId,
    type HarnessLevel,
} from '@scanent/contract/harness-ladder';

import { declaredVerdicts, inventoryRegistrationRef, type InventoryRow } from './inventory';
import { judgementBasisOf } from './judgement';
import {
    RESULTS_SCHEMA,
    type CriterionReaders,
    type EstateRegistrationBasis,
    type LocalAgentResult,
    type LocalCriterionCell,
    type LocalFinding,
    type LocalJudgement,
    type LocalResults,
    type ReaderKind,
    type RegistrationBasis,
    type ScoreInput,
} from './types';

const REGISTRATION_BASIS: Readonly<Record<'REPORT' | 'INTAKE', RegistrationBasis>> = {
    REPORT: 'OBSERVED_REGISTER',
    INTAKE: 'DECLARED_INVENTORY',
};

/** By code unit, not by locale: the order must not depend on where the scan ran. */
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * What this run could have evidenced: per criterion whether a configured
 * reader can report it met, the highest level that follows, and why each
 * other criterion is out of reach.
 */
export function coverageOf(
    table: CriterionReaders,
    configured: readonly ReaderKind[],
): { readonly readable: ReadonlySet<HarnessCriterionId>; readonly coverage: LocalResults['coverage'] } {
    const has = new Set<ReaderKind>(configured);
    const readable = new Set<HarnessCriterionId>(ALL_HARNESS_CRITERIA.filter((c) => table[c].metBy.some((r) => has.has(r))));
    // The ladder's own rule, over a met-with-evidence answer for everything readable.
    const reachableLevel = scoreHarness([...readable].map((criterion) => ({ criterion, met: true, evidence: 'readable' }))).level;
    const unreadable = ALL_HARNESS_CRITERIA.filter((c) => !readable.has(c)).map((criterion) => ({
        criterion,
        why: table[criterion].metBy.length === 0 ? ('NO_READER' as const) : ('READER_NOT_CONFIGURED' as const),
        readers: [...table[criterion].metBy],
    }));
    return { readable, coverage: { reachableLevel, unreadable } };
}

/** The SHADOW_AGENT text for a run whose registrations do not come from a register. */
function localShadowFinding(finding: PlannedFinding, agent: PlannedAgent, where: string, inventorySupplied: boolean): PlannedFinding {
    const found = `A scan (${where}) found agent ${agent.discoveredId} via ${agent.discoveredVia.join(', ')}.`;
    return {
        ...finding,
        description: inventorySupplied
            ? `${found} It is not in the operator's inventory, so it has no declared owner or purpose on record. `
              + 'Add it to the inventory, or retire the principal.'
            : `${found} For this run no inventory was supplied, so no agent can be shown as registered. `
              + 'Supply an inventory that names the agents the estate knows, or retire the principal.',
    };
}

/** Score one scan. See the module comment for what is the contract's and what is added here. */
export function scoreReportLocally(input: ScoreInput): LocalResults {
    const { body, inventory, meta } = input;
    const scanner = body.scan.scanner.agentId;
    const sources = body.population.sources;
    const readInFull = new Set<string>(sources.filter((s) => s.status === 'COMPLETE').map((s) => s.kind));
    const registerRead = sources.some((s) => s.kind === 'inflect-register');

    // ── The inventory, matched by exact id ──
    const rowByAgent = new Map<string, { readonly row: InventoryRow; readonly number: number }>();
    const scanned = new Set(body.agents.map((a) => a.discoveredId));
    const unmatched: string[] = [];
    (inventory?.rows ?? []).forEach((row, i) => {
        if (scanned.has(row.discoveredId)) rowByAgent.set(row.discoveredId, { row, number: i + 1 });
        else unmatched.push(row.discoveredId);
    });

    // ── Declared verdicts, after the observed ones ──
    const declaredOf = new Map<string, readonly CriterionVerdict[]>();
    if (inventory !== null) {
        for (const [id, { row, number }] of rowByAgent) declaredOf.set(id, declaredVerdicts(row, number, inventory, body.scan.asOf));
    }
    const withDeclared = (a: HarnessReportAgent): HarnessReportAgent => {
        const declared = declaredOf.get(a.discoveredId);
        return declared === undefined ? a : { ...a, verdicts: [...a.verdicts, ...declared] };
    };
    const judgedBody = { ...body, agents: body.agents.map(withDeclared) } as HarnessReportBody;

    // ── The contract's planner, over a prior state built from this run ──
    const intakeClaims = new Map<string, IntakeClaim>();
    for (const [id, { number }] of rowByAgent) {
        intakeClaims.set(id, { registeredAgentId: inventoryRegistrationRef(number), status: 'ACTIVE', deleted: false });
    }
    const plan = planHarnessScan(judgedBody, {
        previousLevels: new Map(),
        acceptedShortfalls: new Set(),
        openOrphanCredentials: new Set(),
        registeredAgentIds: new Set(body.agents.flatMap((a) => (a.registeredAgentId === null ? [] : [a.registeredAgentId]))),
        intakeClaims,
    });

    const configured: ReaderKind[] = [...input.readers.configuredSources, ...(inventory === null ? [] : (['inventory'] as const))];
    const { readable, coverage } = coverageOf(input.readers.table, configured);

    // ── Each agent ──
    const observedOf = new Map(body.agents.map((a) => [a.discoveredId, a]));
    const notJudged = new Set<string>();
    const agents: LocalAgentResult[] = plan.agents.map((planned) => {
        const observed = observedOf.get(planned.discoveredId) as HarnessReportAgent;
        const declared = new Set(declaredOf.get(planned.discoveredId) ?? []);
        const collapsed = collapseVerdicts(planned.verdicts);
        const criteria: LocalCriterionCell[] = ALL_HARNESS_CRITERIA.map((criterion) => {
            const verdict = collapsed.get(criterion);
            return {
                criterion,
                state: criterionState(verdict),
                basis: verdict === undefined ? null : declared.has(verdict) ? 'DECLARED' : 'OBSERVED',
                evidence: verdict?.evidence ?? null,
                readable: readable.has(criterion),
            };
        });

        const basis = judgementBasisOf(planned.discoveredVia, sources);
        let judgement: LocalJudgement;
        if (basis.judged) {
            judgement = {
                state: 'JUDGED',
                level: planned.level,
                observedLevel: scoreHarness(observed.verdicts).level,
                bar: harnessBarFor(planned.reach),
                shortfall: isHarnessShortfall(planned.level, planned.reach),
                blockingNextRung: planned.blockingNextRung,
                caveats: basis.caveats,
            };
        } else {
            notJudged.add(planned.discoveredId);
            judgement = { state: 'NOT_JUDGED', reasons: basis.reasons };
        }

        const row = rowByAgent.get(planned.discoveredId);
        return {
            discoveredId: planned.discoveredId,
            discoveredVia: planned.discoveredVia as readonly HarnessSourceKind[],
            declared: row === undefined ? null : { name: row.row.name, owner: row.row.owner, purpose: row.row.purpose, row: row.number },
            observedOwner: planned.ownerKind === null || planned.ownerRef === null ? null : { kind: planned.ownerKind, ref: planned.ownerRef },
            registration: {
                basis: planned.linkBasis === null ? 'NONE' : REGISTRATION_BASIS[planned.linkBasis],
                ref: planned.registeredAgentId,
            },
            judgement,
            reach: planned.reach,
            criteria,
            counts: {
                credentials: observed.credentials.length,
                tools: planned.tools.length,
                writeCapableTools: planned.tools.filter(isWriteCapable).length,
                unpinnedWriteTools: planned.tools.filter((t) => isWriteCapable(t) && !t.pinned).length,
                models: planned.models === null ? null : planned.models.length,
            },
        };
    });
    agents.sort((a, b) => byCodeUnit(a.discoveredId, b.discoveredId));

    // ── Findings: the planner's, less a level stated for an agent not judged ──
    const plannedById = new Map(plan.agents.map((a) => [a.discoveredId, a]));
    const agentOfRef = new Map<string, string>();
    for (const a of plan.agents) {
        agentOfRef.set(shadowRefOf(a.discoveredId), a.discoveredId);
        agentOfRef.set(shortfallRefOf(a.discoveredId), a.discoveredId);
        agentOfRef.set(`UNPINNED_WRITE_TOOL:${a.discoveredId}`, a.discoveredId);
    }
    const where = `scan ${body.scan.id}, scanner ${scanner}`;
    const levelOf = new Map(agents.map((a) => [a.discoveredId, a.judgement]));
    const findings: LocalFinding[] = [];
    for (const planned of plan.assert) {
        const discoveredId = agentOfRef.get(planned.sourceRef) ?? null;
        let finding = planned;
        if (planned.code === 'HARNESS_SHORTFALL' && discoveredId !== null) {
            // Its title states a level, and none may be stated for this agent.
            if (notJudged.has(discoveredId)) continue;
            const judgement = levelOf.get(discoveredId);
            if (judgement?.state === 'JUDGED' && judgement.level !== judgement.observedLevel) {
                finding = {
                    ...planned,
                    description:
                        `${planned.description} The level ${judgement.level} rests in part on what the operator declared in the `
                        + `inventory; on what the sources observed alone it is ${judgement.observedLevel}.`,
                };
            }
        }
        if (planned.code === 'SHADOW_AGENT' && discoveredId !== null && !registerRead) {
            finding = localShadowFinding(planned, plannedById.get(discoveredId) as PlannedAgent, where, inventory !== null);
        }
        findings.push({
            code: finding.code,
            sourceRef: finding.sourceRef,
            severity: finding.severity,
            type: finding.type,
            discoveredId,
            title: finding.title,
            description: finding.description,
        });
    }
    const asserted = new Set(findings.map((f) => f.sourceRef));

    // ── Credentials seen unbound: opened by the planner, or not concluded ──
    const orphanCredentials: { ref: string; sourceKind: string }[] = [];
    const unboundNotConcluded: LocalResults['estate']['unboundNotConcluded'][number][] = [];
    for (const u of body.unboundCredentials) {
        if (asserted.has(orphanCredentialRefOf(scanner, u.sourceKind, u.ref))) {
            orphanCredentials.push({ ref: u.ref, sourceKind: u.sourceKind });
        } else {
            unboundNotConcluded.push({
                ref: u.ref,
                sourceKind: u.sourceKind,
                why: readInFull.has(u.sourceKind) ? 'IDENTITY_SOURCE_INCOMPLETE' : 'OWN_SOURCE_INCOMPLETE',
            });
        }
    }

    const byLevel = Object.fromEntries(HARNESS_LEVELS.map((level) => [level, 0])) as Record<HarnessLevel, number>;
    let shortfallCount = 0;
    for (const a of agents) {
        if (a.judgement.state !== 'JUDGED') continue;
        byLevel[a.judgement.level] += 1;
        if (a.judgement.shortfall) shortfallCount += 1;
    }
    const registrationBasis: EstateRegistrationBasis =
        registerRead && inventory !== null ? 'BOTH' : registerRead ? 'INFLECT_REGISTER' : inventory !== null ? 'INVENTORY' : 'NONE';

    return {
        schema: RESULTS_SCHEMA,
        ladder: {
            version: LADDER_VERSION,
            levels: [...HARNESS_LEVELS],
            criteria: Object.fromEntries(HARNESS_LEVELS.map((level) => [level, [...HARNESS_CRITERIA[level]]])) as unknown as Record<
                HarnessLevel,
                readonly HarnessCriterionId[]
            >,
        },
        scan: {
            id: body.scan.id,
            asOf: body.scan.asOf,
            estate: meta.estate,
            contract: body.contract,
            scanner: {
                agentId: scanner,
                version: body.scan.scanner.version,
                manifestHash: body.scan.scanner.manifestHash,
            },
            complete: isScanComplete(body),
            registerClaimsVerified: meta.registerClaimsVerified,
        },
        report: {
            sha256: meta.report.sha256,
            signerKeyFingerprint: meta.report.signerKeyFingerprint,
            signerPinned: meta.report.signerPinned,
        },
        inventory:
            inventory === null
                ? null
                : {
                      provenance: 'DECLARED_BY_OPERATOR',
                      sha256: inventory.sha256,
                      format: inventory.format,
                      rows: inventory.rows.length,
                      matched: rowByAgent.size,
                      unmatched,
                  },
        sources: sources.map((s) => ({
            kind: s.kind,
            status: s.status,
            reason: s.reason ?? null,
            rows: s.rows,
            agents: body.agents.filter((a) => (a.discoveredVia as readonly string[]).includes(s.kind)).length,
        })),
        coverage,
        estate: {
            empty: agents.length === 0,
            agentCount: agents.length,
            judgedCount: agents.length - notJudged.size,
            notJudgedCount: notJudged.size,
            byLevel,
            shortfallCount,
            registrationBasis,
            shadowAgents: findings.flatMap((f) => (f.code === 'SHADOW_AGENT' && f.discoveredId !== null ? [f.discoveredId] : [])).sort(byCodeUnit),
            orphanCredentials,
            unboundNotConcluded,
            // Every intake claim here is an inventory row, whose id (`inventory:row-<n>`)
            // is never a register id: the planner's "the two differ" is true of every
            // agent in both, and says nothing. An inventory names an agent; it holds no
            // registration to disagree with. The overlap is on the agent itself
            // (`declared` beside an OBSERVED_REGISTER registration).
            registrationConflicts: [],
        },
        agents,
        findings,
    };
}
