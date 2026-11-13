/**
 * LOCAL SCORING — one scan, judged where it was taken.
 *
 * `scoreReportLocally` turns a signed report body (and, when the operator has
 * one, an inventory) into `LocalResults`. It decides nothing the contract
 * already decides: every row of the agent table — its cells, whether it is
 * judged, its level, observed level and bar — is the contract's shared table
 * model (`buildHarnessMatrix`, the one Inflect's harness tab reads), and the
 * findings are `planHarnessScan`'s. What it adds is what a tenant would have supplied and a
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
 *   spendingAuthority      none: the scanner reads no spending authority a
 *                          register holds, and an inventory has no place for
 *                          one. So a registered agent whose code pays raises
 *                          SPENDING_AGENT_UNDECLARED here, and its text says
 *                          that this run saw no authority, not that none exists
 *   onRecordAsAgent        none: nothing is on record before this run, so a
 *                          principal with no sign of a model and no
 *                          registration is an unregistered identity, whether
 *                          or not the scan was complete
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
 * both say the same the observed one stands. The planner is given both, so a
 * finding rests on the same level the table shows; the table model is given
 * them apart, so it can say which a cell rests on.
 *
 * PURE: no clock, no I/O, no hashing. Same input, same value.
 */
import { LADDER_VERSION, type HarnessReportAgent, type HarnessReportBody } from '@rodnapamet/scanent-contract/harness-contract';
import {
    isWriteCapable,
    orphanCredentialRefOf,
    planHarnessScan,
    shadowRefOf,
    shortfallRefOf,
    spendingUndeclaredRefOf,
    toolEvidenceSourcesOf,
    unregisteredIdentityRefOf,
    type HarnessSourceKind,
    type IntakeClaim,
    type PlannedAgent,
    type PlannedFinding,
} from '@rodnapamet/scanent-contract/harness-findings';
import { isScanComplete } from '@rodnapamet/scanent-contract/harness-contract-rules';
import { HARNESS_CRITERIA, HARNESS_LEVELS, type CriterionVerdict, type HarnessCriterionId, type HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';
import { buildHarnessMatrix, type HarnessMatrixCoverage } from '@rodnapamet/scanent-contract/harness-matrix-model';

import { declaredVerdicts, inventoryRegistrationRef, type InventoryRow } from './inventory';
import {
    RESULTS_SCHEMA,
    type EstateRegistrationBasis,
    type LocalAgentResult,
    type LocalFinding,
    type LocalJudgement,
    type LocalResults,
    type ReaderKind,
    type RegistrationBasis,
    type ScoreInput,
} from './types';

/** How many not-read places one source's result names. The schema holds the same number. */
export const MAX_NOT_READ_PLACES = 25;

const REGISTRATION_BASIS: Readonly<Record<'REPORT' | 'INTAKE', RegistrationBasis>> = {
    REPORT: 'OBSERVED_REGISTER',
    INTAKE: 'DECLARED_INVENTORY',
};

/** By code unit, not by locale: the order must not depend on where the scan ran. */
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The planner's UNREGISTERED_IDENTITY text for a run whose registrations come
 * from what this run read: the register source, the operator's inventory,
 * both or neither. Code, severity and key are the planner's.
 */
function localIdentityFinding(finding: PlannedFinding, agent: PlannedAgent, where: string, registerRead: boolean, inventorySupplied: boolean): PlannedFinding {
    const names = registerRead && inventorySupplied ? 'the register or the operator\'s inventory' : registerRead ? 'the register' : inventorySupplied ? 'the operator\'s inventory' : 'any register or inventory this run read';
    return {
        ...finding,
        description:
            `A scan (${where}) found ${agent.discoveredId} via ${agent.discoveredVia.join(', ')}. It is not in ${names}. `
            + 'Nothing the scan read shows that it runs a model: it was not found in agent code, in a tracing system or on an MCP server, '
            + 'and its report lists no tool and no model endpoint. So it is reported as an automated identity and not as an agent, '
            + 'and it is not held to the agent bar. The scan cannot show that it runs no model. '
            + 'If it is an agent, register it or add it to the inventory, and it is then scored as one. '
            + 'If it is not, it still needs an owner on record; or retire the principal.',
    };
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

/** How many payment call sites a finding names before it stops listing; the planner's own number. */
const MAX_PAYMENT_SITES_NAMED = 10;

/**
 * The planner's SPENDING_AGENT_UNDECLARED text for a run that reads no
 * spending authority. The planner's says the register holds none; this run
 * cannot know that, so the text says what was seen, and what was not read.
 */
function localSpendingFinding(finding: PlannedFinding, paying: readonly PlannedAgent[], where: string, registerRead: boolean): PlannedFinding {
    const sites = paying.flatMap((p) => (p.paymentCapabilities ?? []).map((c) => `${c.library} at ${c.at}`));
    const named = sites.slice(0, MAX_PAYMENT_SITES_NAMED);
    const more = sites.length > MAX_PAYMENT_SITES_NAMED ? ` and ${sites.length - MAX_PAYMENT_SITES_NAMED} more` : '';
    const ids = paying.map((p) => p.discoveredId).join(', ');
    const registeredIn = paying.every((p) => p.linkBasis === 'INTAKE') ? 'in the operator\'s inventory' : 'in the register';
    return {
        ...finding,
        title: `Agent ${ids} can pay, and this run saw no spending authority for it`,
        description:
            `A scan (${where}) read the code of ${ids} and found it calling a payment client: ${named.join('; ')}${more}. `
            + `The agent is registered ${registeredIn}. This run read no spending authority for it: the scanner does not read `
            + `the spending authorities a register holds${registerRead ? '' : ' (and no register was read)'}, and an inventory has no place for one. `
            + 'So this says the code can pay; it does not show that no authority was declared. '
            + 'If a reviewed spending authority for the agent is on record, this finding is answered there. If not, declare one '
            + '(how much it may spend, where, and until when) and have a second person review it, or remove the payment client '
            + 'from the agent. A scan that no longer sees the payment client does not close it, because a static read cannot '
            + 'show that an agent has no other way to pay.',
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
        spendingAuthority: new Map(),
        onRecordAsAgent: new Set(),
    });

    const configured: ReaderKind[] = [...input.readers.configuredSources, ...(inventory === null ? [] : (['inventory'] as const))];

    // ── The table: cells, judgement, level and bar are the shared model's ──
    // The planner's agents, with the OBSERVED verdicts only: the model adds the
    // declared ones itself, after them, and keeps the two apart.
    const observedOf = new Map(body.agents.map((a) => [a.discoveredId, a]));
    const matrix = buildHarnessMatrix({
        agents: plan.agents.map((planned) => ({ ...planned, verdicts: (observedOf.get(planned.discoveredId) as HarnessReportAgent).verdicts })),
        sources,
        readers: { table: input.readers.table, configured },
        declared: declaredOf,
    });
    const coverage = matrix.coverage as HarnessMatrixCoverage;

    // ── Each agent ──
    const notJudged = new Set<string>();
    const agents: LocalAgentResult[] = plan.agents.map((planned, i) => {
        const observed = observedOf.get(planned.discoveredId) as HarnessReportAgent;
        const tableRow = matrix.rows[i];
        const t = tableRow.judgement;
        let judgement: LocalJudgement;
        if (t.kind === 'JUDGED') {
            judgement = {
                state: 'JUDGED',
                level: tableRow.level as HarnessLevel,
                observedLevel: tableRow.observedLevel as HarnessLevel,
                bar: tableRow.bar,
                // Where the level stands against the bar, as the ladder has it. Whether
                // the agent is held to that bar at all is its class, which the files
                // say beside it; the count of shortfalls below uses `countsAsShortfall`.
                shortfall: tableRow.barStatus === 'BELOW_BAR',
                blockingNextRung: tableRow.blockingNextRung as readonly HarnessCriterionId[],
                caveats: t.caveats,
            };
        } else {
            notJudged.add(planned.discoveredId);
            judgement = { state: 'NOT_JUDGED', reasons: t.reasons };
        }

        const row = rowByAgent.get(planned.discoveredId);
        return {
            discoveredId: planned.discoveredId,
            discoveredVia: planned.discoveredVia as readonly HarnessSourceKind[],
            // The planner's own rule, over the tools as the report lists them: a
            // diff closes an unpinned-write-tool finding only on these.
            toolEvidenceSources: [...toolEvidenceSourcesOf(observed)].sort(),
            declared: row === undefined ? null : { name: row.row.name, owner: row.row.owner, purpose: row.row.purpose, row: row.number },
            observedOwner: planned.ownerKind === null || planned.ownerRef === null ? null : { kind: planned.ownerKind, ref: planned.ownerRef },
            registration: {
                basis: planned.linkBasis === null ? 'NONE' : REGISTRATION_BASIS[planned.linkBasis],
                ref: planned.registeredAgentId,
            },
            judgement,
            modelSigns: [...planned.modelSigns],
            paymentCapabilities: planned.paymentCapabilities === null ? null : [...planned.paymentCapabilities],
            reach: planned.reach,
            criteria: tableRow.cells.map((c) => ({ criterion: c.criterion, state: c.verdictState, basis: c.basis, evidence: c.evidence, readable: c.readable })),
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
        agentOfRef.set(unregisteredIdentityRefOf(a.discoveredId), a.discoveredId);
        agentOfRef.set(shortfallRefOf(a.discoveredId), a.discoveredId);
        agentOfRef.set(`UNPINNED_WRITE_TOOL:${a.discoveredId}`, a.discoveredId);
    }
    // A spending finding is keyed by the register row. It is about an agent
    // when exactly one paying agent is linked to that row, and about the row
    // otherwise.
    const payingByRow = new Map<string, PlannedAgent[]>();
    for (const a of plan.agents) {
        if (a.registeredAgentId === null || (a.paymentCapabilities ?? []).length === 0) continue;
        payingByRow.set(a.registeredAgentId, [...(payingByRow.get(a.registeredAgentId) ?? []), a]);
    }
    const payingOfRef = new Map<string, PlannedAgent[]>();
    for (const [row, paying] of payingByRow) {
        payingOfRef.set(spendingUndeclaredRefOf(row), paying);
        if (paying.length === 1) agentOfRef.set(spendingUndeclaredRefOf(row), paying[0].discoveredId);
    }
    const where = `scan ${body.scan.id}, scanner ${scanner}`;
    const levelOf = new Map(agents.map((a) => [a.discoveredId, a.judgement]));
    const findings: LocalFinding[] = [];
    for (const planned of plan.assert) {
        const discoveredId = agentOfRef.get(planned.sourceRef) ?? null;
        let finding = planned;
        if (planned.code === 'UNREGISTERED_IDENTITY' && discoveredId !== null) {
            finding = localIdentityFinding(planned, plannedById.get(discoveredId) as PlannedAgent, where, registerRead, inventory !== null);
        }
        if (planned.code === 'SPENDING_AGENT_UNDECLARED') {
            finding = localSpendingFinding(planned, payingOfRef.get(planned.sourceRef) ?? [], where, registerRead);
        }
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
    for (const a of agents) if (a.judgement.state === 'JUDGED') byLevel[a.judgement.level] += 1;
    // An unregistered automated identity is held to no bar, and is not counted.
    const shortfallCount = matrix.rows.filter((r) => r.countsAsShortfall).length;
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
        sources: sources.map((s) => {
            // A note is only ever about a source the report itself lists as not read in full.
            const note = s.status === 'COMPLETE' ? undefined : input.sourceNotes?.find((n) => n.kind === s.kind);
            return {
                kind: s.kind,
                status: s.status,
                reason: s.reason ?? null,
                rows: s.rows,
                agents: body.agents.filter((a) => (a.discoveredVia as readonly string[]).includes(s.kind)).length,
                ...(note === undefined || note.detail === null ? {} : { detail: note.detail }),
                ...(note === undefined || note.notReadTotal === 0
                    ? {}
                    : { notRead: note.notRead.slice(0, MAX_NOT_READ_PLACES), notReadTotal: Math.max(note.notReadTotal, note.notRead.length) }),
            };
        }),
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
            unregisteredIdentities: findings
                .flatMap((f) => (f.code === 'UNREGISTERED_IDENTITY' && f.discoveredId !== null ? [f.discoveredId] : []))
                .sort(byCodeUnit),
            payingAgents: agents.filter((a) => (a.paymentCapabilities ?? []).length > 0).map((a) => a.discoveredId),
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
