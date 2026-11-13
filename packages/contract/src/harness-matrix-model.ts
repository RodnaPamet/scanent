/**
 * THE HARNESS MATRIX — one table model of agents × criteria, for every surface.
 *
 * A scan is shown as a table: one row per agent, one column per criterion of
 * the ladder, grouped by the level that first requires it. scanent's local
 * results (`summary.html`, `agents.csv`, `results.json`, `diff`) and Inflect's
 * harness tab both show it. This module is the table's ONE definition, so the
 * two cannot say different things about the same scan: what a cell is, when an
 * agent is given a level, where it stands against its bar, and in what order
 * rows are read. A surface decides how a row LOOKS; it decides nothing about
 * what the row says.
 *
 * ## The rules it holds, each one a rule a surface used to hold for itself
 *
 *   • A CELL IS THE LADDER'S RULE. Its state is `criterionState` over
 *     `collapseVerdicts`, so a criterion reported more than once shows its least
 *     favourable answer, and a "met" with no evidence reference is shown as
 *     `MET_UNEVIDENCED`, which counts as not met. Cells and level never disagree.
 *   • A DECLARATION IS NEVER SHOWN AS AN OBSERVATION. Declared verdicts (an
 *     operator's inventory) follow the observed ones into the collapse, so a
 *     declared "met" never outvotes an observed NOT MET, and where both say the
 *     same the observed one stands. A cell decided by a declaration is
 *     `DECLARED` or `NOT_MET_DECLARED`, and `observedLevel` is the level with
 *     every declaration removed.
 *   • NOT READABLE IS NOT UNANSWERED. A criterion no configured reader could
 *     have reported met is `NOT_READABLE`: nothing this run read could have
 *     seen it, which is not the same as a source that could have and did not.
 *     Both count as not met.
 *   • AN INCOMPLETE SOURCE CLOSES NOTHING. An agent is judged only when every
 *     source that could have reported a verdict about it was read in full
 *     (`harnessJudgementOf`). Otherwise it is NOT JUDGED, with the reasons as
 *     codes, and the row states NO level, observed level, blocking criteria or
 *     bar standing: `null`, never H0.
 *   • ZERO IS NEVER COMPLETE. A scan that found no agents is `EMPTY`, whatever
 *     its sources say: an empty population evidences nothing.
 *   • AN UNREGISTERED AUTOMATED IDENTITY IS HELD TO NO BAR. Its row still says
 *     where its level stands against the bar its reach would carry
 *     (`barStatus`), and says it is not held to it (`heldToBar: false`), so it
 *     is never counted as a shortfall (`countsAsShortfall`).
 *
 * ## Safe in a browser bundle
 *
 * PURE: no clock, no I/O, no hashing, no schema. Its one runtime import is the
 * ladder, which imports nothing; every other import is a type, erased at build.
 * So a client component can hold the same functions the server ran, and the
 * package's Node-only modules never reach a page through this one. A test
 * holds that.
 *
 * ## What it does not hold
 *
 * Columns a product adds beside a row — Inflect's register name, acceptance,
 * drift, the latest-ingested level; scanent's declared owner and purpose, its
 * counts — stay with the product, keyed by `discoveredId`. The model does not
 * know them and a row does not carry them.
 */
import type { HarnessPaymentCapability } from './harness-contract';
import type { HarnessSourceKind, ModelSign, StoredReach } from './harness-findings';
import {
    ALL_HARNESS_CRITERIA,
    collapseVerdicts,
    criterionState,
    HARNESS_CRITERIA,
    HARNESS_LEVEL_NAMES,
    HARNESS_LEVELS,
    levelAtLeast,
    rungOf,
    scoreHarness,
    shortfallBarFor,
    type CriterionState,
    type CriterionVerdict,
    type HarnessCriterionId,
    type HarnessLevel,
    type HarnessReach,
} from './harness-ladder';

// ─── Readers: what a run could have evidenced ───────────────────────────────

/** What can report a verdict: a source kind, or the operator's inventory. */
export type ReaderKind = HarnessSourceKind | 'inventory';

/**
 * For each criterion, the readers that report a verdict about it at all
 * (`reportedBy`) and the ones that can report it MET (`metBy`, a subset). A
 * reader that can only say NOT MET (the `code` source) evidences a failure and
 * never a pass, so it does not make a criterion readable.
 *
 * The table belongs to whoever owns the readers: scanent's scanner holds it and
 * holds it to its sources by test. The model only consumes it.
 */
export type CriterionReaders = Readonly<
    Record<HarnessCriterionId, { readonly reportedBy: readonly ReaderKind[]; readonly metBy: readonly ReaderKind[] }>
>;

/** Why no configured reader could have evidenced a criterion. */
export type UnreadableWhy = 'NO_READER' | 'READER_NOT_CONFIGURED';

/** What a run could have evidenced at best. */
export interface HarnessMatrixCoverage {
    /** The highest level this run could have stated for any agent. */
    readonly reachableLevel: HarnessLevel;
    /** Every criterion no configured reader could have reported met, in ladder order. */
    readonly unreadable: readonly {
        readonly criterion: HarnessCriterionId;
        readonly why: UnreadableWhy;
        /** The readers that could report it met; empty for `NO_READER`. */
        readonly readers: readonly ReaderKind[];
    }[];
}

/**
 * What a run could have evidenced: per criterion whether a configured reader
 * can report it met, the highest level that follows, and why each other
 * criterion is out of reach.
 */
export function harnessCoverageOf(
    table: CriterionReaders,
    configured: readonly ReaderKind[],
): { readonly readable: ReadonlySet<HarnessCriterionId>; readonly coverage: HarnessMatrixCoverage } {
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

// ─── Columns ────────────────────────────────────────────────────────────────

/** One level's criteria, as a group of columns. */
export interface HarnessMatrixColumnGroup {
    readonly level: HarnessLevel;
    /** The level's name on the ladder, e.g. "Registered". */
    readonly name: string;
    /** In the ladder's order. Never empty: a level with no criteria (H0) has no group. */
    readonly criteria: readonly HarnessCriterionId[];
}

/** The columns, grouped by the level that first requires each criterion, lowest level first. */
export const HARNESS_MATRIX_COLUMNS: readonly HarnessMatrixColumnGroup[] = Object.freeze(
    HARNESS_LEVELS.filter((level) => HARNESS_CRITERIA[level].length > 0).map((level) =>
        Object.freeze({ level, name: HARNESS_LEVEL_NAMES[level], criteria: Object.freeze([...HARNESS_CRITERIA[level]]) }),
    ),
);

const LEVEL_OF_CRITERION: ReadonlyMap<HarnessCriterionId, HarnessLevel> = new Map(
    HARNESS_MATRIX_COLUMNS.flatMap((g) => g.criteria.map((c): [HarnessCriterionId, HarnessLevel] => [c, g.level])),
);

// ─── Cells ──────────────────────────────────────────────────────────────────

/**
 * What one cell shows. A closed set of seven, in the order a legend lists them.
 * Only `EVIDENCED` and `DECLARED` are met; the other five are five different
 * ways of not being met, kept apart because each is a different conversation:
 *
 *   EVIDENCED         met, with evidence, and a source observed it
 *   DECLARED          met, with evidence, on what an operator declared; no source observed it
 *   MET_UNEVIDENCED   reported met with no evidence reference; counts as not met
 *   NOT_MET           not met: a source saw it fail
 *   NOT_MET_DECLARED  not met on what an operator declared; no source saw it fail
 *   UNANSWERED        a configured reader could have reported it, and none did
 *   NOT_READABLE      nothing the run was configured to read could have reported it met
 *
 * These are also the words `agents.csv` and a comparison of two runs use for a
 * cell, so a reader of every surface sees one word for one cell.
 */
export const HARNESS_MATRIX_CELL_STATES = [
    'EVIDENCED',
    'DECLARED',
    'MET_UNEVIDENCED',
    'NOT_MET',
    'NOT_MET_DECLARED',
    'UNANSWERED',
    'NOT_READABLE',
] as const;

export type HarnessMatrixCellState = (typeof HARNESS_MATRIX_CELL_STATES)[number];

/** Where the verdict that decided a cell came from. */
export type VerdictBasis = 'OBSERVED' | 'DECLARED';

/** One (agent, criterion) cell. */
export interface HarnessMatrixCell {
    readonly criterion: HarnessCriterionId;
    /** The level that first requires the criterion: the column group it sits in. */
    readonly level: HarnessLevel;
    readonly state: HarnessMatrixCellState;
    /** The ladder's own reading of the deciding verdict (`criterionState`). */
    readonly verdictState: CriterionState;
    /** Where the deciding verdict came from; null when the criterion is unanswered. */
    readonly basis: VerdictBasis | null;
    /** The deciding verdict's evidence reference, as reported; null when there is none. */
    readonly evidence: string | null;
    /** Whether any reader the run configured could have reported the criterion met. */
    readonly readable: boolean;
}

/**
 * The seven-state reading of one cell, from the ladder's four-state reading,
 * where its verdict came from and whether it was readable. Readability only
 * ever changes an UNANSWERED cell: a verdict that arrived is shown as it is.
 */
export function harnessMatrixCellState(cell: {
    readonly state: CriterionState;
    readonly basis: VerdictBasis | null;
    readonly readable: boolean;
}): HarnessMatrixCellState {
    if (cell.state === 'EVIDENCED') return cell.basis === 'DECLARED' ? 'DECLARED' : 'EVIDENCED';
    if (cell.state === 'MET_UNEVIDENCED') return 'MET_UNEVIDENCED';
    if (cell.state === 'NOT_MET') return cell.basis === 'DECLARED' ? 'NOT_MET_DECLARED' : 'NOT_MET';
    return cell.readable ? 'UNANSWERED' : 'NOT_READABLE';
}

/** Is this cell met, by the ladder's rule? Only an evidenced verdict is, observed or declared. */
export function isHarnessMatrixCellMet(state: HarnessMatrixCellState): boolean {
    return state === 'EVIDENCED' || state === 'DECLARED';
}

// ─── Judgement: when an agent may be given a level ──────────────────────────

/**
 * Which source kinds report verdicts under an id another source discovers.
 *
 * A `Record` over every kind, so a kind added to the contract is a compile
 * error here until somebody decides which it is.
 *
 *   inflect-register  true: it reports a registered agent under the id the
 *                     source that found the principal gave it, for example
 *                     `entra:sp:<objectId>`.
 *   vault, mcp        false: both attach to another source's id (a credential's
 *                     principal tag, a server's configured agents) and report
 *                     no verdict at all. The scanner's tests hold that.
 *   every other kind  false: its verdicts are about the principals it lists.
 */
export const CROSS_AGENT_VERDICT_SOURCE: Readonly<Record<HarnessSourceKind, boolean>> = Object.freeze({
    'entra-sp': false,
    'okta-app': false,
    vault: false,
    mcp: false,
    runtime: false,
    cicd: false,
    'inflect-register': true,
    code: false,
    'gcp-sa': false,
});

/** A source as a scan lists it, as far as a judgement needs. */
export interface HarnessMatrixSource {
    readonly kind: string;
    readonly status: 'COMPLETE' | 'INCOMPLETE';
    readonly reason?: string | null | undefined;
}

/** The reason a kind in `discoveredVia` gets when the scan does not list that source at all. */
export const SOURCE_NOT_LISTED = 'NOT_LISTED';
/** The reason every agent gets when the scan's stored sources could not be read back. */
export const SOURCES_UNREADABLE = 'SOURCES_UNREADABLE';
/** The reason an agent gets when its stored verdicts could not be read back. */
export const VERDICTS_UNREADABLE = 'VERDICTS_UNREADABLE';

/**
 * May an agent be given a level?
 *
 *   JUDGED      every source that could have reported a verdict about it was
 *               read in full. `caveats` are `OTHER_SOURCE_INCOMPLETE:<kind>`,
 *               one per incomplete source that bears on neither.
 *   NOT_JUDGED  `reasons`, never empty: `SOURCE_INCOMPLETE:<kind>:<reason>`,
 *               `VERDICT_SOURCE_INCOMPLETE:<kind>:<reason>`, or one of the two
 *               unreadable codes above. Codes and operands, never prose.
 */
export type HarnessMatrixJudgement =
    | { readonly kind: 'JUDGED'; readonly caveats: readonly string[] }
    | { readonly kind: 'NOT_JUDGED'; readonly reasons: readonly string[] };

const isCrossAgentVerdictSource = (kind: string): boolean =>
    Object.hasOwn(CROSS_AGENT_VERDICT_SOURCE, kind) && CROSS_AGENT_VERDICT_SOURCE[kind as HarnessSourceKind];

/**
 * A level is derived from verdicts, and unanswered counts as no, so a verdict a
 * partial read missed cannot RAISE a level by being absent. It can still leave
 * one too high: a source that stopped early may have held a NOT MET for a
 * criterion another source reported as met, and the collapse would have taken
 * the NOT MET. So an agent is judged only when every source that could have
 * reported a verdict about it was read in full:
 *
 *   1. every kind it was discovered through, and
 *   2. every listed source that reports verdicts about agents OTHER sources
 *      discover (`CROSS_AGENT_VERDICT_SOURCE`).
 *
 * An incomplete source that bears on neither is a caveat beside the level, not
 * a reason to withhold it. `sources` null is a scan whose sources could not be
 * read back: nothing about any agent is known to have been read in full.
 * Reasons and caveats follow the order the agent and the scan list their
 * sources in, so the answer is deterministic.
 */
export function harnessJudgementOf(discoveredVia: readonly string[], sources: readonly HarnessMatrixSource[] | null): HarnessMatrixJudgement {
    if (sources === null) return { kind: 'NOT_JUDGED', reasons: [SOURCES_UNREADABLE] };
    const listed = new Map(sources.map((s) => [s.kind, s]));
    const reasons: string[] = [];
    for (const kind of discoveredVia) {
        const source = listed.get(kind);
        if (source === undefined) reasons.push(`SOURCE_INCOMPLETE:${kind}:${SOURCE_NOT_LISTED}`);
        else if (source.status !== 'COMPLETE') reasons.push(`SOURCE_INCOMPLETE:${kind}:${source.reason ?? 'UNKNOWN'}`);
    }
    const caveats: string[] = [];
    for (const source of sources) {
        if (source.status === 'COMPLETE' || discoveredVia.includes(source.kind)) continue;
        if (isCrossAgentVerdictSource(source.kind)) reasons.push(`VERDICT_SOURCE_INCOMPLETE:${source.kind}:${source.reason ?? 'UNKNOWN'}`);
        else caveats.push(`OTHER_SOURCE_INCOMPLETE:${source.kind}`);
    }
    return reasons.length > 0 ? { kind: 'NOT_JUDGED', reasons } : { kind: 'JUDGED', caveats };
}

// ─── The bar ────────────────────────────────────────────────────────────────

/** Reach as the ladder spells it. A `Record`, so a stored reach added later is a compile error here. */
const LADDER_REACH: Readonly<Record<StoredReach, HarnessReach | 'unknown'>> = {
    READ_ONLY: 'read-only',
    WRITE_OR_EXTERNAL: 'write-or-external',
    UNKNOWN: 'unknown',
};

/** The bar a reach carries: `shortfallBarFor`, over reach as a scan stores it. Unknown reach takes the higher bar. */
export function harnessMatrixBarFor(reach: StoredReach): HarnessLevel {
    return shortfallBarFor(LADDER_REACH[reach]);
}

/**
 * Where a level stands against the bar its reach carries. `NOT_JUDGED` for an
 * agent with no level: a level that cannot be stated cannot be compared.
 */
export type HarnessBarStatus = 'AT_BAR' | 'BELOW_BAR' | 'NOT_JUDGED';

/** `BELOW_BAR` when the level is under the bar for its reach, ordinal by `levelAtLeast`. */
export function harnessBarStatusOf(level: HarnessLevel | null, reach: StoredReach): HarnessBarStatus {
    if (level === null) return 'NOT_JUDGED';
    return levelAtLeast(level, harnessMatrixBarFor(reach)) ? 'AT_BAR' : 'BELOW_BAR';
}

// ─── Rows ───────────────────────────────────────────────────────────────────

/**
 * One agent of one scan, as a planner gives it (`PlannedAgent` satisfies this,
 * with `verdicts` replaced by the observed verdicts alone) or as a product has
 * stored it.
 */
export interface HarnessMatrixAgentInput {
    readonly discoveredId: string;
    readonly discoveredVia: readonly string[];
    /**
     * The OBSERVED verdicts, as the scan reported them: not collapsed, and
     * without anything declared. `null` is verdicts a product stored and could
     * not read back: every cell is then unanswered and the agent is NOT JUDGED
     * (`VERDICTS_UNREADABLE`), failing closed.
     */
    readonly verdicts: readonly CriterionVerdict[] | null;
    readonly reach: StoredReach;
    /** The register row (or inventory row) the agent is linked to; null is not registered. */
    readonly registeredAgentId: string | null;
    /** Where that link came from: a register claim the report carried, an intake's record, or none. */
    readonly linkBasis: 'REPORT' | 'INTAKE' | null;
    /** The planner's class: not registered, and showing no sign of a model. Held to no bar. */
    readonly unregisteredIdentity: boolean;
    readonly modelSigns: readonly ModelSign[];
    /**
     * `/4`'s payment capabilities. THREE STATES: `null` NOT REPORTED, `[]` a
     * code read that saw no payment client called (never "cannot pay"),
     * entries what it saw.
     */
    readonly paymentCapabilities: readonly HarnessPaymentCapability[] | null;
    /** What to call the agent, when something other than the scan names it. */
    readonly nameHint?: HarnessMatrixNameHint | null;
}

/** A name to show for an agent, and who gave it. A declared name is never shown as a registered one. */
export interface HarnessMatrixNameHint {
    readonly text: string;
    /** `DECLARED`: an operator's inventory. `REGISTER`: the agent register's own name. */
    readonly basis: 'DECLARED' | 'REGISTER';
}

/** What a principal is, on what the scan read. */
export type HarnessMatrixClassification = 'REGISTERED' | 'SHADOW_AGENT' | 'UNREGISTERED_IDENTITY';

export interface HarnessMatrixRow {
    readonly discoveredId: string;
    readonly discoveredVia: readonly string[];
    readonly nameHint: HarnessMatrixNameHint | null;
    readonly classification: HarnessMatrixClassification;
    readonly registration: { readonly ref: string | null; readonly basis: 'REPORT' | 'INTAKE' | null };
    readonly reach: StoredReach;
    readonly modelSigns: readonly ModelSign[];
    readonly paymentCapabilities: readonly HarnessPaymentCapability[] | null;
    readonly judgement: HarnessMatrixJudgement;
    /** Observed and declared verdicts together. Null when not judged: no level is stated, not even H0. */
    readonly level: HarnessLevel | null;
    /** Declared verdicts removed. Null when not judged. Equal to `level` when nothing was declared. */
    readonly observedLevel: HarnessLevel | null;
    /** The criteria standing between `level` and the next rung, in ladder order. Null when not judged. */
    readonly blockingNextRung: readonly HarnessCriterionId[] | null;
    /** The bar the agent's reach carries. A fact about its reach, so stated whether or not it is judged. */
    readonly bar: HarnessLevel;
    /** Where `level` stands against `bar`. */
    readonly barStatus: HarnessBarStatus;
    /** False for an unregistered automated identity, which is held to no bar. */
    readonly heldToBar: boolean;
    /** Judged, held to a bar, and below it: what a finding and a count call a shortfall. */
    readonly countsAsShortfall: boolean;
    /** Every criterion, in ladder order. */
    readonly cells: readonly HarnessMatrixCell[];
}

// ─── The model ──────────────────────────────────────────────────────────────

/** `EMPTY` before anything else: a scan that found nobody evidences nothing, whatever its sources say. */
export type HarnessMatrixCompleteness = 'COMPLETE' | 'INCOMPLETE' | 'EMPTY';

export interface HarnessMatrixPopulation {
    readonly agentCount: number;
    readonly judgedCount: number;
    readonly notJudgedCount: number;
    readonly completeness: HarnessMatrixCompleteness;
}

export interface HarnessMatrixInput {
    readonly agents: readonly HarnessMatrixAgentInput[];
    /** The scan's sources as it lists them; null when they could not be read back. */
    readonly sources: readonly HarnessMatrixSource[] | null;
    /**
     * The criterion-reader table and the readers the run was configured with
     * (the inventory among them when one was supplied). Absent or null: which
     * readers ran is not known, so no criterion is NOT_READABLE and the model
     * states no coverage; an unanswered criterion is UNANSWERED.
     */
    readonly readers?: { readonly table: CriterionReaders; readonly configured: readonly ReaderKind[] } | null;
    /**
     * Declared verdicts, by `discoveredId`, each carrying its declaration's own
     * evidence reference. They follow the observed ones into the collapse.
     */
    readonly declared?: ReadonlyMap<string, readonly CriterionVerdict[]> | null;
}

export interface HarnessMatrixModel {
    readonly columns: readonly HarnessMatrixColumnGroup[];
    /** In the order the agents were given. Sort with `compareHarnessMatrixRows` for worst first. */
    readonly rows: readonly HarnessMatrixRow[];
    /** What the run could have evidenced; null when the readers are not known. */
    readonly coverage: HarnessMatrixCoverage | null;
    readonly population: HarnessMatrixPopulation;
}

/** One scan's completeness, in one expression: every listed source read in full, at least one listed, and a non-empty population. */
export function harnessMatrixCompleteness(sources: readonly HarnessMatrixSource[] | null, agentCount: number): HarnessMatrixCompleteness {
    if (agentCount === 0) return 'EMPTY';
    return sources !== null && sources.length > 0 && sources.every((s) => s.status === 'COMPLETE') && agentCount > 0 ? 'COMPLETE' : 'INCOMPLETE';
}

function rowOf(
    agent: HarnessMatrixAgentInput,
    sources: readonly HarnessMatrixSource[] | null,
    declared: readonly CriterionVerdict[],
    readable: (criterion: HarnessCriterionId) => boolean,
): HarnessMatrixRow {
    const observed = agent.verdicts ?? [];
    const all = [...observed, ...declared];
    const declaredSet = new Set<CriterionVerdict>(declared);
    const collapsed = collapseVerdicts(all);
    const cells = ALL_HARNESS_CRITERIA.map((criterion): HarnessMatrixCell => {
        const verdict = collapsed.get(criterion);
        const verdictState = criterionState(verdict);
        const basis: VerdictBasis | null = verdict === undefined ? null : declaredSet.has(verdict) ? 'DECLARED' : 'OBSERVED';
        const isReadable = readable(criterion);
        return {
            criterion,
            level: LEVEL_OF_CRITERION.get(criterion) as HarnessLevel,
            state: harnessMatrixCellState({ state: verdictState, basis, readable: isReadable }),
            verdictState,
            basis,
            evidence: verdict?.evidence ?? null,
            readable: isReadable,
        };
    });

    const basisOfJudgement = harnessJudgementOf(agent.discoveredVia, sources);
    const judgement: HarnessMatrixJudgement =
        agent.verdicts === null
            ? {
                  kind: 'NOT_JUDGED',
                  reasons: [...(basisOfJudgement.kind === 'NOT_JUDGED' ? basisOfJudgement.reasons : []), VERDICTS_UNREADABLE],
              }
            : basisOfJudgement;
    const judged = judgement.kind === 'JUDGED';
    const score = scoreHarness(all);
    const level = judged ? score.level : null;
    const barStatus = harnessBarStatusOf(level, agent.reach);
    const heldToBar = !agent.unregisteredIdentity;

    return {
        discoveredId: agent.discoveredId,
        discoveredVia: agent.discoveredVia,
        nameHint: agent.nameHint ?? null,
        classification:
            agent.registeredAgentId !== null ? 'REGISTERED' : agent.unregisteredIdentity ? 'UNREGISTERED_IDENTITY' : 'SHADOW_AGENT',
        registration: { ref: agent.registeredAgentId, basis: agent.registeredAgentId === null ? null : agent.linkBasis },
        reach: agent.reach,
        modelSigns: agent.modelSigns,
        paymentCapabilities: agent.paymentCapabilities,
        judgement,
        level,
        observedLevel: judged ? scoreHarness(observed).level : null,
        blockingNextRung: judged ? score.blockingNextRung : null,
        bar: harnessMatrixBarFor(agent.reach),
        barStatus,
        heldToBar,
        countsAsShortfall: heldToBar && barStatus === 'BELOW_BAR',
        cells,
    };
}

/** Build the table for one scan. See the module comment for the rules it holds. */
export function buildHarnessMatrix(input: HarnessMatrixInput): HarnessMatrixModel {
    const readers = input.readers ?? null;
    const reach = readers === null ? null : harnessCoverageOf(readers.table, readers.configured);
    const readable = reach === null ? () => true : (criterion: HarnessCriterionId) => reach.readable.has(criterion);
    const rows = input.agents.map((agent) => rowOf(agent, input.sources, input.declared?.get(agent.discoveredId) ?? [], readable));
    const judgedCount = rows.filter((r) => r.judgement.kind === 'JUDGED').length;
    return {
        columns: HARNESS_MATRIX_COLUMNS,
        rows,
        coverage: reach === null ? null : reach.coverage,
        population: {
            agentCount: rows.length,
            judgedCount,
            notJudgedCount: rows.length - judgedCount,
            completeness: harnessMatrixCompleteness(input.sources, rows.length),
        },
    };
}

// ─── Order ──────────────────────────────────────────────────────────────────

/** What a row is ordered by. A `HarnessMatrixRow` is one; so is a stored row with these three members. */
export interface HarnessMatrixRowRank {
    readonly discoveredId: string;
    readonly level: HarnessLevel | null;
    readonly barStatus: HarnessBarStatus;
}

const BAR_GROUP: Readonly<Record<HarnessBarStatus, number>> = { NOT_JUDGED: 0, BELOW_BAR: 1, AT_BAR: 2 };

/** By code unit, not by locale: the order must not depend on where the table is read. */
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Worst first: agents not judged, then those below the bar their reach
 * carries, then those at it; within each, the lowest level first; then by
 * `discoveredId`, by code unit. The order a reader needs when a surface can
 * show only the first rows.
 *
 * It orders by `barStatus`, where the level stands against the bar, and not by
 * `countsAsShortfall`: an unregistered identity below the bar its reach would
 * carry sorts among the agents below theirs. A level the ladder does not know
 * sorts as the lowest.
 */
export function compareHarnessMatrixRows(a: HarnessMatrixRowRank, b: HarnessMatrixRowRank): number {
    const group = (BAR_GROUP[a.barStatus] ?? 0) - (BAR_GROUP[b.barStatus] ?? 0);
    if (group !== 0) return group;
    const rung = (r: HarnessMatrixRowRank): number => (r.level === null ? 0 : Math.max(0, rungOf(r.level)));
    return rung(a) - rung(b) || byCodeUnit(a.discoveredId, b.discoveredId);
}
