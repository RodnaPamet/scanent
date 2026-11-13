/**
 * THE DIFFERENCE BETWEEN TWO RUNS' INTEGRATIONS — held to the agent diff's
 * rule: ABSENCE IS EVIDENCE ONLY ON A FULL READ.
 *
 * An application in the old run and not in the new one is `GONE` only when
 * the new run read its source in full, found at least one application there,
 * and is of the same population (same scanner, same estate); otherwise it is
 * NOT SEEN, with the reason. A finding no longer raised is `CLOSED` only when
 * the new run concluded the question it answers: its application is there,
 * and the new run's own planner listed no "not concluded" entry for that
 * question about it. Otherwise it is NOT_CONCLUDED, with the planner's reason.
 * Every question the new run could not answer is listed, so a diff with no
 * difference and an incomplete side is `SAME_AS_FAR_AS_COMPARED`, never
 * `SAME`.
 *
 * Pure: two sides in, one object out.
 */
import { DiffRefused, type ClosureChange, type DiffOutcome, type SourceReadState } from './diff';
import type { LocalIntegrationsResults } from '../results/types';

export const INTEGRATIONS_DIFF_SCHEMA = 'scanent-integrations-diff/1';

/** One run's side: what identifies the scan, and its integrations section. */
export interface IntegrationsDiffInput {
    readonly scan: { readonly id: string; readonly asOf: string; readonly estate: string | null; readonly scannerAgentId: string };
    readonly integrations: LocalIntegrationsResults;
}

export interface IntegrationsDiffSide {
    readonly scanId: string;
    readonly asOf: string;
    readonly estate: string | null;
    readonly scannerAgentId: string;
    readonly complete: boolean;
    readonly applicationCount: number;
}

export interface IntegrationsSourceChange {
    /** The source kind, or `<kind>#signInActivity` for its sign-in read. */
    readonly kind: string;
    readonly change: 'NOW_INCOMPLETE' | 'NOW_COMPLETE' | 'REASON_CHANGED' | 'ADDED' | 'NO_LONGER_READ';
    readonly from: { readonly status: SourceReadState | 'NOT_READ'; readonly reason: string | null };
    readonly to: { readonly status: SourceReadState | 'NOT_READ'; readonly reason: string | null };
}

export interface ApplicationNotSeen {
    readonly id: string;
    /** `SOURCE_INCOMPLETE`, `SOURCE_ABSENT`, `NEW_SOURCE_EMPTY`, `DIFFERENT_SCANNER` or `DIFFERENT_ESTATE`. */
    readonly why: string;
}

export interface IntegrationFindingChange {
    readonly sourceRef: string;
    readonly code: string;
    readonly applicationId: string | null;
    readonly title: string;
    readonly change: ClosureChange;
    /** For `NOT_CONCLUDED`: why its absence closes nothing. */
    readonly why: string | null;
}

export interface IntegrationsDiff {
    readonly schema: typeof INTEGRATIONS_DIFF_SCHEMA;
    readonly old: IntegrationsDiffSide;
    readonly new: IntegrationsDiffSide;
    /** `SCANNER_DIFFERS`, `ESTATE_DIFFERS`, `UNUSED_DAYS_DIFFER`. */
    readonly warnings: readonly string[];
    readonly sources: readonly IntegrationsSourceChange[];
    readonly applications: { readonly added: readonly string[]; readonly gone: readonly string[]; readonly notSeen: readonly ApplicationNotSeen[] };
    readonly findings: readonly IntegrationFindingChange[];
    /** Every comparison that could not be made, one code each. */
    readonly notConcluded: readonly string[];
    readonly summary: { readonly differences: number; readonly notConcluded: number };
    readonly outcome: DiffOutcome;
}

const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function sideOf(s: IntegrationsDiffInput): IntegrationsDiffSide {
    return {
        scanId: s.scan.id,
        asOf: s.scan.asOf,
        estate: s.scan.estate,
        scannerAgentId: s.scan.scannerAgentId,
        complete: readInFull(s.integrations),
        applicationCount: s.integrations.applications.length,
    };
}

/** Derived from the statuses, never from the stored `complete`: a results file is untrusted input. */
function readInFull(i: LocalIntegrationsResults): boolean {
    return i.sources.length > 0 && i.sources.every((s) => s.status === 'COMPLETE' && s.signInActivity.status !== 'INCOMPLETE');
}

type State = { readonly status: SourceReadState | 'NOT_READ'; readonly reason: string | null };
const ABSENT: State = { status: 'ABSENT', reason: null };

function statesOf(i: LocalIntegrationsResults): Map<string, State> {
    const out = new Map<string, State>();
    for (const s of i.sources) {
        out.set(s.kind, { status: s.status, reason: s.reason });
        out.set(`${s.kind}#signInActivity`, { status: s.signInActivity.status, reason: s.signInActivity.reason });
    }
    return out;
}

/** Compare two runs' integrations. `prev` is the older. Throws `DiffRefused` when they may not be compared. */
export function diffIntegrations(prev: IntegrationsDiffInput, next: IntegrationsDiffInput, opts: { readonly allowDifferentScanner?: boolean } = {}): IntegrationsDiff {
    const differentScanner = prev.scan.scannerAgentId !== next.scan.scannerAgentId;
    if (differentScanner && opts.allowDifferentScanner !== true) throw new DiffRefused('SCANNER_DIFFERS');
    if (!(Date.parse(next.scan.asOf) > Date.parse(prev.scan.asOf))) throw new DiffRefused('NOT_LATER');
    const a = prev.integrations;
    const b = next.integrations;

    const warnings: string[] = [];
    const notConcluded: string[] = [];
    if (differentScanner) warnings.push('SCANNER_DIFFERS');
    const differentEstate = prev.scan.estate !== null && next.scan.estate !== null && prev.scan.estate !== next.scan.estate;
    if (differentEstate) warnings.push('ESTATE_DIFFERS');
    if (a.unusedDays !== b.unusedDays) warnings.push('UNUSED_DAYS_DIFFER');
    const otherPopulation = differentScanner ? 'DIFFERENT_SCANNER' : differentEstate ? 'DIFFERENT_ESTATE' : null;
    for (const [label, i] of [['old', a], ['new', b]] as const) if (!readInFull(i)) notConcluded.push(`SCAN_INCOMPLETE:${label}`);

    const was = statesOf(a);
    const now = statesOf(b);
    const sources: IntegrationsSourceChange[] = [];
    for (const kind of [...new Set([...was.keys(), ...now.keys()])].sort(byCodeUnit)) {
        const from = was.get(kind) ?? ABSENT;
        const to = now.get(kind) ?? ABSENT;
        const change: IntegrationsSourceChange['change'] | null =
            from.status === 'ABSENT' || (from.status === 'NOT_READ' && to.status !== 'NOT_READ')
                ? 'ADDED'
                : to.status === 'ABSENT' || (to.status === 'NOT_READ' && from.status !== 'NOT_READ')
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

    const before = new Map(a.applications.map((x) => [x.id, x]));
    const after = new Map(b.applications.map((x) => [x.id, x]));
    const added = b.applications.filter((x) => !before.has(x.id)).map((x) => x.id).sort(byCodeUnit);
    const gone: string[] = [];
    const notSeen: ApplicationNotSeen[] = [];
    for (const app of a.applications) {
        if (after.has(app.id)) continue;
        const source = b.sources.find((s) => s.kind === app.sourceKind);
        const why =
            otherPopulation ??
            (source === undefined
                ? 'SOURCE_ABSENT'
                : source.status !== 'COMPLETE'
                    ? 'SOURCE_INCOMPLETE'
                    : source.applications === 0
                        ? 'NEW_SOURCE_EMPTY'
                        : null);
        if (why === null) gone.push(app.id);
        else {
            notSeen.push({ id: app.id, why });
            notConcluded.push(`APPLICATION_NOT_SEEN:${app.id}`);
        }
    }
    gone.sort(byCodeUnit);
    notSeen.sort((x, y) => byCodeUnit(x.id, y.id));
    const goneSet = new Set(gone);

    /** Why a finding no longer raised is not closed, or null when the new run concluded it. */
    const stillOpenWhy = (code: string, applicationId: string | null, sourceRef: string): string | null => {
        if (otherPopulation !== null) return otherPopulation;
        if (applicationId === null) {
            // The empty inventory: closed by a presence, on any read.
            const kind = sourceRef.slice(sourceRef.lastIndexOf(':') + 1);
            const source = b.sources.find((s) => s.kind === kind);
            return source === undefined ? 'SOURCE_ABSENT' : source.applications > 0 ? null : 'NO_APPLICATIONS';
        }
        const app = after.get(applicationId);
        if (app === undefined) return goneSet.has(applicationId) ? 'APPLICATION_GONE' : 'APPLICATION_NOT_SEEN';
        const open = b.notConcluded.find((n) => n.code === code && (n.applicationId === applicationId || (n.applicationId === null && n.sourceKind === app.sourceKind)));
        return open === undefined ? null : open.why;
    };

    const refsBefore = new Set(a.findings.map((f) => f.sourceRef));
    const refsNow = new Set(b.findings.map((f) => f.sourceRef));
    const findings: IntegrationFindingChange[] = [];
    for (const f of b.findings) {
        if (!refsBefore.has(f.sourceRef)) findings.push({ sourceRef: f.sourceRef, code: f.code, applicationId: f.applicationId, title: f.title, change: 'OPENED', why: null });
    }
    for (const f of a.findings) {
        if (refsNow.has(f.sourceRef)) continue;
        const why = stillOpenWhy(f.code, f.applicationId, f.sourceRef);
        findings.push({ sourceRef: f.sourceRef, code: f.code, applicationId: f.applicationId, title: f.title, change: why === null ? 'CLOSED' : 'NOT_CONCLUDED', why });
        if (why !== null) notConcluded.push(`FINDING_NOT_CONCLUDED:${f.sourceRef}`);
    }
    // What the new run could not answer at all is a comparison that was not made.
    for (const n of b.notConcluded) notConcluded.push(`QUESTION_NOT_CONCLUDED:${n.code}:${n.applicationId ?? n.sourceKind}`);

    const differences = sources.length + added.length + gone.length + findings.filter((f) => f.change !== 'NOT_CONCLUDED').length;
    const unconcluded = [...new Set(notConcluded)];
    return {
        schema: INTEGRATIONS_DIFF_SCHEMA,
        old: sideOf(prev),
        new: sideOf(next),
        warnings,
        sources,
        applications: { added, gone, notSeen },
        findings,
        notConcluded: unconcluded,
        summary: { differences, notConcluded: unconcluded.length },
        outcome: differences > 0 ? 'DIFFERENT' : unconcluded.length > 0 ? 'SAME_AS_FAR_AS_COMPARED' : 'SAME',
    };
}
