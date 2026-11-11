/**
 * THE DIFFERENCE BETWEEN TWO RUNS — and what could not be compared.
 *
 * Both sides are `LocalResults`. The comparison holds one rule above the
 * others: ABSENCE IS EVIDENCE ONLY ON A FULL READ. An agent that is in the
 * old run and not in the new one is `GONE` only when every source it was
 * found through was read in full by the new run; otherwise it is `NOT_SEEN`,
 * with the sources that were not read. The same rule decides whether an
 * orphan credential or a finding is `CLOSED` or merely no longer reported
 * (`NOT_CONCLUDED`), and a level is compared only where both runs judged the
 * agent.
 *
 * Whatever could not be concluded is listed in `notConcluded`, and a diff
 * with no difference and a non-empty list is `SAME_AS_FAR_AS_COMPARED`, never
 * `SAME`: "nothing changed" is not reported on a partial read.
 *
 * Pure: two results in, one object out.
 */
import { rungOf, type CriterionState, type HarnessCriterionId, type HarnessLevel } from '@scanent/contract/harness-ladder';

import type { LocalAgentResult, LocalFinding, LocalResults, VerdictBasis } from '../results/types';

export const DIFF_SCHEMA = 'scanent-diff/1';

export type DiffRefusal = 'NOT_LATER' | 'LADDER_DIFFERS' | 'SCANNER_DIFFERS';

const REFUSAL_TEXT: Readonly<Record<DiffRefusal, string>> = {
    NOT_LATER: 'the new scan is not later than the old one; give the older run first',
    LADDER_DIFFERS: 'the two runs were scored on different ladder versions, so their levels cannot be compared',
    SCANNER_DIFFERS: 'the two runs are from different scanners; what one did not see says nothing about the other (--allow-different-scanner compares them anyway)',
};

/** Two results that may not be compared. The message names the rule, never a value. */
export class DiffRefused extends Error {
    constructor(readonly reason: DiffRefusal) {
        super(REFUSAL_TEXT[reason]);
        this.name = 'DiffRefused';
    }
}

export interface DiffSide {
    readonly scanId: string;
    readonly asOf: string;
    readonly estate: string | null;
    readonly scannerAgentId: string;
    readonly complete: boolean;
    readonly agentCount: number;
    /** Null: no inventory was supplied to that run. */
    readonly inventorySha256: string | null;
    readonly signerPinned: boolean;
    readonly registerClaimsVerified: boolean;
}

export type SourceReadState = 'COMPLETE' | 'INCOMPLETE' | 'ABSENT';

export interface SourceChange {
    readonly kind: string;
    readonly change: 'NOW_INCOMPLETE' | 'NOW_COMPLETE' | 'REASON_CHANGED' | 'ADDED' | 'NO_LONGER_READ';
    readonly from: { readonly status: SourceReadState; readonly reason: string | null };
    readonly to: { readonly status: SourceReadState; readonly reason: string | null };
}

export interface AgentNotSeen {
    readonly discoveredId: string;
    /** Why its absence concludes nothing: the sources not read in full, a different scanner or estate, or an empty new run. */
    readonly unread: readonly { readonly kind: string; readonly status: 'INCOMPLETE' | 'ABSENT' }[];
    readonly differentScanner: boolean;
    /** The two runs name different estates: "read in full" is about another place. */
    readonly differentEstate: boolean;
    /** The new run found no agent at all, which evidences nothing about any one of them. */
    readonly newScanEmpty: boolean;
}

export interface LevelChange {
    readonly discoveredId: string;
    readonly change: 'LEVEL_UP' | 'LEVEL_DOWN' | 'OBSERVED_LEVEL_UP' | 'OBSERVED_LEVEL_DOWN' | 'NOW_NOT_JUDGED' | 'NOW_JUDGED';
    /** Set for the four level changes only: no level is compared across a change of judgement. */
    readonly from: HarnessLevel | null;
    readonly to: HarnessLevel | null;
    /** The new run's reasons, for `NOW_NOT_JUDGED`; the old run's, for `NOW_JUDGED`. */
    readonly reasons: readonly string[];
}

export interface CriterionChange {
    readonly discoveredId: string;
    readonly criterion: HarnessCriterionId;
    readonly from: { readonly state: CriterionState; readonly basis: VerdictBasis | null };
    readonly to: { readonly state: CriterionState; readonly basis: VerdictBasis | null };
    /** False when the agent was not judged on one side: reported, not concluded. */
    readonly concluded: boolean;
}

export interface AttributeChange {
    readonly discoveredId: string;
    readonly attribute: 'reach' | 'bar' | 'shortfall' | 'registration';
    readonly from: string;
    readonly to: string;
}

export type ClosureChange = 'OPENED' | 'CLOSED' | 'NOT_CONCLUDED';

export interface OrphanChange {
    readonly ref: string;
    readonly sourceKind: string;
    readonly change: ClosureChange;
    /** For `NOT_CONCLUDED`: `STILL_SEEN_UNBOUND`, `SOURCE_INCOMPLETE`, `SOURCE_ABSENT`, `DIFFERENT_SCANNER`, `DIFFERENT_ESTATE` or `NEW_SCAN_EMPTY`. */
    readonly why: string | null;
}

export interface FindingChange {
    readonly sourceRef: string;
    readonly code: string;
    readonly discoveredId: string | null;
    readonly title: string;
    readonly change: ClosureChange;
    /** For `NOT_CONCLUDED`: why its absence closes nothing. */
    readonly why: string | null;
}

export type DiffOutcome = 'SAME' | 'DIFFERENT' | 'SAME_AS_FAR_AS_COMPARED';

export interface ResultsDiff {
    readonly schema: typeof DIFF_SCHEMA;
    readonly ladderVersion: string;
    readonly old: DiffSide;
    readonly new: DiffSide;
    /** `INVENTORY_DIFFERS`, `SCANNER_DIFFERS`, `ESTATE_DIFFERS`, `SIGNER_NOT_PINNED:<side>`, `REGISTER_CLAIMS_NOT_VERIFIED:<side>`. */
    readonly warnings: readonly string[];
    readonly sources: readonly SourceChange[];
    readonly agents: {
        readonly added: readonly string[];
        readonly gone: readonly string[];
        readonly notSeen: readonly AgentNotSeen[];
    };
    readonly levels: readonly LevelChange[];
    readonly criteria: readonly CriterionChange[];
    readonly attributes: readonly AttributeChange[];
    readonly orphanCredentials: readonly OrphanChange[];
    readonly findings: readonly FindingChange[];
    /** Every comparison that could not be made, one code each. */
    readonly notConcluded: readonly string[];
    readonly summary: { readonly differences: number; readonly notConcluded: number };
    readonly outcome: DiffOutcome;
}

function sideOf(r: LocalResults): DiffSide {
    return {
        scanId: r.scan.id,
        asOf: r.scan.asOf,
        estate: r.scan.estate,
        scannerAgentId: r.scan.scanner.agentId,
        complete: readInFull(r),
        agentCount: r.estate.agentCount,
        inventorySha256: r.inventory === null ? null : r.inventory.sha256,
        signerPinned: r.report.signerPinned,
        registerClaimsVerified: r.scan.registerClaimsVerified,
    };
}

/**
 * Whether a run read every source it lists in full. Derived from the sources,
 * never read from the stored `scan.complete`: a results file is untrusted
 * input, and what a diff closes must rest on the statuses themselves.
 */
function readInFull(r: LocalResults): boolean {
    return r.sources.length > 0 && r.sources.every((s) => s.status === 'COMPLETE');
}

const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function sourceStates(r: LocalResults): Map<string, { status: SourceReadState; reason: string | null }> {
    return new Map(r.sources.map((s) => [s.kind, { status: s.status, reason: s.reason }]));
}

const ABSENT = { status: 'ABSENT' as const, reason: null };

/** Why a finding that is no longer reported is not closed, or null when it is. */
function findingStillOpenWhy(
    finding: LocalFinding,
    next: LocalResults,
    prevAgents: ReadonlyMap<string, LocalAgentResult>,
    nextAgents: ReadonlyMap<string, LocalAgentResult>,
    gone: ReadonlySet<string>,
): string | null {
    const complete = readInFull(next);
    if (finding.discoveredId !== null) {
        const agent = nextAgents.get(finding.discoveredId);
        if (agent === undefined) return gone.has(finding.discoveredId) ? 'AGENT_GONE' : 'AGENT_NOT_SEEN';
        if (finding.code === 'SHADOW_AGENT') {
            // A link the register holds closes it on any scan; one the operator
            // declared closes it only on a complete scan (the planner's rule).
            if (agent.registration.basis === 'OBSERVED_REGISTER') return null;
            if (agent.registration.basis === 'DECLARED_INVENTORY') return complete ? null : 'SCAN_INCOMPLETE';
            return 'AGENT_NOT_REGISTERED';
        }
        if (agent.judgement.state !== 'JUDGED') return 'AGENT_NOT_JUDGED';
        if (finding.code === 'UNPINNED_WRITE_TOOL') {
            // A tool's absence closes nothing unless the source that would have
            // reported it was read in full (the planner's `toolEvidenceSourcesOf`,
            // over where the agent was found in either run): `code` for an agent
            // found through `code`, `mcp` for one found through any other kind.
            // A source the new run does not list was not read at all. Results
            // carry no tool's server, so every listed source must be complete too.
            const via = [...(prevAgents.get(finding.discoveredId)?.discoveredVia ?? []), ...agent.discoveredVia];
            const evidence = [...new Set(via.map((kind) => (kind === 'code' ? 'code' : 'mcp')))];
            if (evidence.some((kind) => !next.sources.some((s) => s.kind === kind))) return 'SOURCE_ABSENT';
            // A listed source that was not read in full is an incomplete scan.
            if (!complete) return 'SCAN_INCOMPLETE';
        }
        return null;
    }
    if (finding.code === 'EMPTY_SCAN') return next.estate.agentCount > 0 ? null : 'NO_AGENTS';
    if (finding.code === 'INCOMPLETE_SOURCE') {
        const kind = finding.sourceRef.slice(finding.sourceRef.lastIndexOf(':') + 1);
        const state = next.sources.find((s) => s.kind === kind);
        return state === undefined ? 'SOURCE_ABSENT' : state.status === 'COMPLETE' ? null : 'SOURCE_INCOMPLETE';
    }
    return complete ? null : 'SCAN_INCOMPLETE';
}

/**
 * Compare two runs. `prev` is the older. Throws `DiffRefused` when the two may
 * not be compared at all.
 */
export function diffResults(prev: LocalResults, next: LocalResults, opts: { readonly allowDifferentScanner?: boolean } = {}): ResultsDiff {
    if (prev.ladder.version !== next.ladder.version) throw new DiffRefused('LADDER_DIFFERS');
    const differentScanner = prev.scan.scanner.agentId !== next.scan.scanner.agentId;
    if (differentScanner && opts.allowDifferentScanner !== true) throw new DiffRefused('SCANNER_DIFFERS');
    const before = Date.parse(prev.scan.asOf);
    const after = Date.parse(next.scan.asOf);
    if (!(after > before)) throw new DiffRefused('NOT_LATER');

    const notConcluded: string[] = [];
    const warnings: string[] = [];
    if ((prev.inventory?.sha256 ?? null) !== (next.inventory?.sha256 ?? null)) warnings.push('INVENTORY_DIFFERS');
    if (differentScanner) warnings.push('SCANNER_DIFFERS');
    // Two estates under one scanner id: what the new run read in full is another place.
    const differentEstate = prev.scan.estate !== null && next.scan.estate !== null && prev.scan.estate !== next.scan.estate;
    if (differentEstate) warnings.push('ESTATE_DIFFERS');
    // An empty population is what a scanner reading the wrong place looks like: it closes nothing.
    const newScanEmpty = next.agents.length === 0;
    /** Why the two runs are not of one population, so that nothing absent from the new one is concluded; null when they are. */
    const otherPopulation = differentScanner ? 'DIFFERENT_SCANNER' : differentEstate ? 'DIFFERENT_ESTATE' : null;
    for (const [side, r] of [['old', prev], ['new', next]] as const) {
        if (!r.report.signerPinned) warnings.push(`SIGNER_NOT_PINNED:${side}`);
        if (!r.scan.registerClaimsVerified) warnings.push(`REGISTER_CLAIMS_NOT_VERIFIED:${side}`);
        if (!readInFull(r)) notConcluded.push(`SCAN_INCOMPLETE:${side}`);
    }

    // ── Completeness, first ──
    const was = sourceStates(prev);
    const now = sourceStates(next);
    const sources: SourceChange[] = [];
    for (const kind of [...new Set([...was.keys(), ...now.keys()])].sort(byCodeUnit)) {
        const from = was.get(kind) ?? ABSENT;
        const to = now.get(kind) ?? ABSENT;
        const change: SourceChange['change'] | null =
            from.status === 'ABSENT'
                ? 'ADDED'
                : to.status === 'ABSENT'
                    ? 'NO_LONGER_READ'
                    : from.status !== to.status
                        ? to.status === 'COMPLETE'
                            ? 'NOW_COMPLETE'
                            : 'NOW_INCOMPLETE'
                        : from.reason !== to.reason
                            ? 'REASON_CHANGED'
                            : null;
        if (change !== null) sources.push({ kind, change, from, to });
    }

    // ── Agents ──
    const prevAgents = new Map(prev.agents.map((a) => [a.discoveredId, a]));
    const nextAgents = new Map(next.agents.map((a) => [a.discoveredId, a]));
    const added = next.agents.filter((a) => !prevAgents.has(a.discoveredId)).map((a) => a.discoveredId).sort(byCodeUnit);
    const gone: string[] = [];
    const notSeen: AgentNotSeen[] = [];
    for (const agent of prev.agents) {
        if (nextAgents.has(agent.discoveredId)) continue;
        const unread = agent.discoveredVia.flatMap((kind) => {
            const status = (now.get(kind) ?? ABSENT).status;
            return status === 'COMPLETE' ? [] : [{ kind, status }];
        });
        // An agent found through no source at all proves nothing by its absence.
        if (unread.length === 0 && agent.discoveredVia.length > 0 && otherPopulation === null && !newScanEmpty) gone.push(agent.discoveredId);
        else {
            notSeen.push({ discoveredId: agent.discoveredId, unread, differentScanner, differentEstate, newScanEmpty });
            notConcluded.push(`AGENT_NOT_SEEN:${agent.discoveredId}`);
        }
    }
    gone.sort(byCodeUnit);
    notSeen.sort((a, b) => byCodeUnit(a.discoveredId, b.discoveredId));
    const goneSet = new Set(gone);

    // ── Levels, criteria and attributes, for agents both runs hold ──
    const levels: LevelChange[] = [];
    const criteria: CriterionChange[] = [];
    const attributes: AttributeChange[] = [];
    for (const b of next.agents) {
        const a = prevAgents.get(b.discoveredId);
        if (a === undefined) {
            if (b.judgement.state !== 'JUDGED') notConcluded.push(`AGENT_NOT_JUDGED:${b.discoveredId}`);
            continue;
        }
        const id = b.discoveredId;
        const ja = a.judgement;
        const jb = b.judgement;
        const bothJudged = ja.state === 'JUDGED' && jb.state === 'JUDGED';
        if (ja.state === 'JUDGED' && jb.state === 'JUDGED') {
            if (ja.level !== jb.level) {
                levels.push({ discoveredId: id, change: rungOf(jb.level) > rungOf(ja.level) ? 'LEVEL_UP' : 'LEVEL_DOWN', from: ja.level, to: jb.level, reasons: [] });
            }
            if (ja.observedLevel !== jb.observedLevel) {
                levels.push({
                    discoveredId: id,
                    change: rungOf(jb.observedLevel) > rungOf(ja.observedLevel) ? 'OBSERVED_LEVEL_UP' : 'OBSERVED_LEVEL_DOWN',
                    from: ja.observedLevel,
                    to: jb.observedLevel,
                    reasons: [],
                });
            }
            if (ja.bar !== jb.bar) attributes.push({ discoveredId: id, attribute: 'bar', from: ja.bar, to: jb.bar });
            if (ja.shortfall !== jb.shortfall) {
                attributes.push({ discoveredId: id, attribute: 'shortfall', from: ja.shortfall ? 'yes' : 'no', to: jb.shortfall ? 'yes' : 'no' });
            }
        } else {
            notConcluded.push(`AGENT_NOT_JUDGED:${id}`);
            if (ja.state === 'JUDGED' && jb.state === 'NOT_JUDGED') {
                levels.push({ discoveredId: id, change: 'NOW_NOT_JUDGED', from: null, to: null, reasons: jb.reasons });
            } else if (ja.state === 'NOT_JUDGED' && jb.state === 'JUDGED') {
                levels.push({ discoveredId: id, change: 'NOW_JUDGED', from: null, to: null, reasons: ja.reasons });
            }
        }
        if (a.reach !== b.reach) attributes.push({ discoveredId: id, attribute: 'reach', from: a.reach, to: b.reach });
        if (a.registration.basis !== b.registration.basis) {
            attributes.push({ discoveredId: id, attribute: 'registration', from: a.registration.basis, to: b.registration.basis });
        }
        const cellsBefore = new Map(a.criteria.map((c) => [c.criterion, c]));
        for (const cell of b.criteria) {
            const old = cellsBefore.get(cell.criterion);
            const from = { state: old?.state ?? ('UNANSWERED' as const), basis: old?.basis ?? null };
            if (from.state === cell.state && from.basis === cell.basis) continue;
            criteria.push({ discoveredId: id, criterion: cell.criterion, from, to: { state: cell.state, basis: cell.basis }, concluded: bothJudged });
            if (!bothJudged) notConcluded.push(`CRITERION_NOT_CONCLUDED:${id}:${cell.criterion}`);
        }
    }
    const byAgent = <T extends { readonly discoveredId: string }>(list: T[]): T[] => list.sort((x, y) => byCodeUnit(x.discoveredId, y.discoveredId));
    byAgent(levels);
    byAgent(attributes);

    // ── Orphan credentials ──
    const keyOf = (c: { readonly sourceKind: string; readonly ref: string }): string => `${c.sourceKind}\u0000${c.ref}`;
    const orphansBefore = new Set(prev.estate.orphanCredentials.map(keyOf));
    const orphansNow = new Set(next.estate.orphanCredentials.map(keyOf));
    const stillUnbound = new Set(next.estate.unboundNotConcluded.map(keyOf));
    const orphanCredentials: OrphanChange[] = [];
    for (const c of next.estate.orphanCredentials) {
        if (!orphansBefore.has(keyOf(c))) orphanCredentials.push({ ref: c.ref, sourceKind: c.sourceKind, change: 'OPENED', why: null });
    }
    for (const c of prev.estate.orphanCredentials) {
        if (orphansNow.has(keyOf(c))) continue;
        const status = (now.get(c.sourceKind) ?? ABSENT).status;
        const why = otherPopulation !== null
            ? otherPopulation
            : stillUnbound.has(keyOf(c))
                ? 'STILL_SEEN_UNBOUND'
                : status === 'INCOMPLETE'
                    ? 'SOURCE_INCOMPLETE'
                    : status === 'ABSENT'
                        ? 'SOURCE_ABSENT'
                        : newScanEmpty
                            ? 'NEW_SCAN_EMPTY'
                            : null;
        orphanCredentials.push({ ref: c.ref, sourceKind: c.sourceKind, change: why === null ? 'CLOSED' : 'NOT_CONCLUDED', why });
        if (why !== null) notConcluded.push(`ORPHAN_NOT_CONCLUDED:${c.sourceKind}:${c.ref}`);
    }

    // ── Findings, by reference. Orphan credentials are compared above. ──
    const refsBefore = new Set(prev.findings.map((f) => f.sourceRef));
    const refsNow = new Set(next.findings.map((f) => f.sourceRef));
    const findings: FindingChange[] = [];
    for (const f of next.findings) {
        if (f.code === 'ORPHAN_CREDENTIAL' || refsBefore.has(f.sourceRef)) continue;
        findings.push({ sourceRef: f.sourceRef, code: f.code, discoveredId: f.discoveredId, title: f.title, change: 'OPENED', why: null });
    }
    for (const f of prev.findings) {
        if (f.code === 'ORPHAN_CREDENTIAL' || refsNow.has(f.sourceRef)) continue;
        // A different scanner or estate concludes nothing; an empty run still shows a source now read in full.
        const why = otherPopulation ?? findingStillOpenWhy(f, next, prevAgents, nextAgents, goneSet);
        findings.push({ sourceRef: f.sourceRef, code: f.code, discoveredId: f.discoveredId, title: f.title, change: why === null ? 'CLOSED' : 'NOT_CONCLUDED', why });
        if (why !== null) notConcluded.push(`FINDING_NOT_CONCLUDED:${f.sourceRef}`);
    }

    const concluded = (list: readonly { readonly change: ClosureChange }[]): number => list.filter((x) => x.change !== 'NOT_CONCLUDED').length;
    const differences =
        sources.length
        + added.length
        + gone.length
        + levels.length
        + criteria.filter((c) => c.concluded).length
        + attributes.length
        + concluded(orphanCredentials)
        + concluded(findings);
    const unconcluded = [...new Set(notConcluded)];
    return {
        schema: DIFF_SCHEMA,
        ladderVersion: next.ladder.version,
        old: sideOf(prev),
        new: sideOf(next),
        warnings,
        sources,
        agents: { added, gone, notSeen },
        levels,
        criteria,
        attributes,
        orphanCredentials,
        findings,
        notConcluded: unconcluded,
        summary: { differences, notConcluded: unconcluded.length },
        outcome: differences > 0 ? 'DIFFERENT' : unconcluded.length > 0 ? 'SAME_AS_FAR_AS_COMPARED' : 'SAME',
    };
}

/** The exit code a diff ends with: 0 same, 1 different, 3 same as far as could be compared. */
export function diffExitCode(diff: Pick<ResultsDiff, 'outcome'>): 0 | 1 | 3 {
    return diff.outcome === 'DIFFERENT' ? 1 : diff.outcome === 'SAME_AS_FAR_AS_COMPARED' ? 3 : 0;
}
