/**
 * THE DIFFERENCE BETWEEN TWO RUNS, SCANNER BY SCANNER.
 *
 * A run holds the reports of the scanners its sources called for. Two runs
 * that both ran only the agent scanner are compared exactly as before, by
 * `diffResults`, and the comparison is that diff, unchanged. Once either run
 * holds an integrations section, the comparison is this document: one member
 * per scanner, each compared by its own rules, and each scanner's own
 * honesty kept (an incomplete side concludes nothing).
 *
 * A scanner that ran in one run and not the other is a difference, as a
 * source that is added or no longer read is: it is named, and nothing about
 * what it would have found is concluded. Two runs that share no scanner are
 * refused: there is nothing to compare.
 *
 * Pure: two sides in, one object out.
 */
import { DiffRefused, diffResults, type DiffOutcome, type ResultsDiff } from './diff';
import { diffIntegrations, type IntegrationsDiff, type IntegrationsDiffInput } from './integrations-diff';
import type { LocalResults } from '../results/types';

export const RUN_DIFF_SCHEMA = 'scanent-run-diff/1';

/** One run's side: each scanner's results, or null when that scanner did not run. */
export interface RunDiffSide {
    readonly agents: LocalResults | null;
    readonly integrations: IntegrationsDiffInput | null;
}

/** A scanner that was not compared, because it did not run in both runs. */
export interface ScannerNotCompared {
    readonly compared: false;
    /** `ADDED`: ran in the new run only. `NO_LONGER_RUN`: in the old run only. `NOT_RUN`: in neither. */
    readonly change: 'ADDED' | 'NO_LONGER_RUN' | 'NOT_RUN';
}

export interface RunDiff {
    readonly schema: typeof RUN_DIFF_SCHEMA;
    readonly scanners: {
        readonly agents: ResultsDiff | ScannerNotCompared;
        readonly integrations: IntegrationsDiff | ScannerNotCompared;
    };
    readonly summary: { readonly differences: number; readonly notConcluded: number };
    readonly outcome: DiffOutcome;
}

/** Why two runs could not be compared at all, beyond `DiffRefused`'s rules. */
export class RunsShareNoScanner extends Error {
    constructor() {
        super('the two runs share no scanner: one ran only the agent scanner and the other only the integrations scanner');
        this.name = 'RunsShareNoScanner';
    }
}

function notCompared(old: unknown, next: unknown): ScannerNotCompared {
    return { compared: false, change: old === null && next === null ? 'NOT_RUN' : old === null ? 'ADDED' : 'NO_LONGER_RUN' };
}

/** The integrations side of a run whose agent results carry an integrations section. */
export function integrationsSideOf(r: LocalResults): IntegrationsDiffInput | null {
    if (r.integrations === undefined) return null;
    return { scan: { id: r.scan.id, asOf: r.scan.asOf, estate: r.scan.estate, scannerAgentId: r.scan.scanner.agentId }, integrations: r.integrations };
}

/**
 * Compare two runs. Both ran only the agent scanner: the agent diff itself.
 * Otherwise the per-scanner document. Throws `DiffRefused` where a scanner's
 * own rules refuse, and `RunsShareNoScanner` when no scanner ran in both.
 */
export function diffRuns(prev: RunDiffSide, next: RunDiffSide, opts: { readonly allowDifferentScanner?: boolean } = {}): ResultsDiff | RunDiff {
    if (prev.integrations === null && next.integrations === null && prev.agents !== null && next.agents !== null) {
        return diffResults(prev.agents, next.agents, opts);
    }
    const agentsBoth = prev.agents !== null && next.agents !== null;
    const integrationsBoth = prev.integrations !== null && next.integrations !== null;
    if (!agentsBoth && !integrationsBoth) throw new RunsShareNoScanner();

    const agents = prev.agents !== null && next.agents !== null ? diffResults(prev.agents, next.agents, opts) : notCompared(prev.agents, next.agents);
    const integrations =
        prev.integrations !== null && next.integrations !== null
            ? diffIntegrations(prev.integrations, next.integrations, opts)
            : notCompared(prev.integrations, next.integrations);

    const count = (d: ResultsDiff | IntegrationsDiff | ScannerNotCompared): { differences: number; notConcluded: number } =>
        'compared' in d ? { differences: d.change === 'NOT_RUN' ? 0 : 1, notConcluded: 0 } : d.summary;
    const a = count(agents);
    const i = count(integrations);
    const differences = a.differences + i.differences;
    const unconcluded = a.notConcluded + i.notConcluded;
    return {
        schema: RUN_DIFF_SCHEMA,
        scanners: { agents, integrations },
        summary: { differences, notConcluded: unconcluded },
        outcome: differences > 0 ? 'DIFFERENT' : unconcluded > 0 ? 'SAME_AS_FAR_AS_COMPARED' : 'SAME',
    };
}

export { DiffRefused };
