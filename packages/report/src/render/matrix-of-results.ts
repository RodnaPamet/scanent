/**
 * THE TABLE MODEL OF A RESULTS FILE.
 *
 * A page is rendered from `LocalResults` alone (the content of `results.json`),
 * and the shared table model (`buildHarnessMatrix`) is built from a scan. This
 * module gives the model what the results hold, so every rendering shows the
 * model's own rows and nothing a renderer worked out for itself:
 *
 *   verdicts   one per answered criterion, the collapsed verdict the results
 *              stored, OBSERVED ones as the agent's verdicts and DECLARED ones
 *              as the inventory's. The model collapses them again and reaches
 *              the same cell, level and blocking criteria.
 *   readers    what the results say was readable: every criterion outside
 *              `coverage.unreadable` is given one reader this run "configured",
 *              and every one inside keeps the readers the results name. The
 *              model's coverage and each cell's `readable` follow exactly.
 *   sources    as listed, so the model decides who is judged.
 *
 * One thing a results file does not keep is an OBSERVED verdict that a
 * declared NOT MET outvoted. So the level on observation alone is the one the
 * results stored for a judged agent, which was scored with every verdict.
 *
 * Pure: results in, model out.
 */
import type { CriterionVerdict, HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';
import {
    buildHarnessMatrix,
    type CriterionReaders,
    type HarnessMatrixModel,
    type HarnessMatrixRow,
    type ReaderKind,
} from '@rodnapamet/scanent-contract/harness-matrix-model';
import { ALL_HARNESS_CRITERIA } from '@rodnapamet/scanent-contract/harness-ladder';

import type { LocalAgentResult, LocalCriterionCell, LocalResults } from '../results/types';
import { agentClassification } from './csv';

/**
 * The one reader a results file can name for a criterion it says was readable:
 * it does not record which source would have answered, only that one could.
 */
const READABLE_PER_RESULTS = 'results-readable' as ReaderKind;

function verdictOf(cell: LocalCriterionCell): CriterionVerdict | null {
    if (cell.state === 'UNANSWERED') return null;
    if (cell.state === 'MET_UNEVIDENCED') return { criterion: cell.criterion, met: true, evidence: null };
    return { criterion: cell.criterion, met: cell.state === 'EVIDENCED', evidence: cell.evidence };
}

function readersOf(r: LocalResults): { readonly table: CriterionReaders; readonly configured: readonly ReaderKind[] } {
    const unreadable = new Map(r.coverage.unreadable.map((u) => [u.criterion, u]));
    const table = Object.fromEntries(
        ALL_HARNESS_CRITERIA.map((criterion) => {
            const u = unreadable.get(criterion);
            const metBy: readonly ReaderKind[] = u === undefined ? [READABLE_PER_RESULTS] : [...u.readers];
            return [criterion, { reportedBy: metBy, metBy }];
        }),
    ) as unknown as CriterionReaders;
    return { table, configured: [READABLE_PER_RESULTS] };
}

/** Build the shared table model from a results file. Rows are in the results' order (by id). */
export function harnessMatrixOfResults(r: LocalResults): HarnessMatrixModel {
    const declared = new Map<string, CriterionVerdict[]>();
    const agents = r.agents.map((a: LocalAgentResult) => {
        const observed: CriterionVerdict[] = [];
        const fromInventory: CriterionVerdict[] = [];
        for (const cell of a.criteria) {
            const v = verdictOf(cell);
            if (v !== null) (cell.basis === 'DECLARED' ? fromInventory : observed).push(v);
        }
        if (fromInventory.length > 0) declared.set(a.discoveredId, fromInventory);
        const registered = a.registration.basis !== 'NONE';
        return {
            discoveredId: a.discoveredId,
            discoveredVia: a.discoveredVia,
            verdicts: observed,
            reach: a.reach,
            registeredAgentId: registered ? (a.registration.ref ?? a.discoveredId) : null,
            linkBasis: a.registration.basis === 'OBSERVED_REGISTER' ? ('REPORT' as const) : registered ? ('INTAKE' as const) : null,
            unregisteredIdentity: agentClassification(a) === 'UNREGISTERED_IDENTITY',
            modelSigns: a.modelSigns ?? [],
            paymentCapabilities: a.paymentCapabilities ?? null,
            nameHint: a.declared === null ? null : { text: a.declared.name, basis: 'DECLARED' as const },
        };
    });
    const model = buildHarnessMatrix({ agents, sources: r.sources, readers: readersOf(r), declared });
    const stored = new Map(r.agents.map((a) => [a.discoveredId, a.judgement]));
    const rows = model.rows.map((row): HarnessMatrixRow => {
        const j = stored.get(row.discoveredId);
        if (row.level === null || j === undefined || j.state !== 'JUDGED') return row;
        return { ...row, observedLevel: j.observedLevel as HarnessLevel };
    });
    return { ...model, rows };
}
