/**
 * WHEN AN AGENT MAY BE GIVEN A LEVEL.
 *
 * A level is derived from verdicts, and unanswered counts as no, so a verdict a
 * partial read missed cannot RAISE a level by being absent. It can still leave
 * one too high: a source that stopped early may have held a NOT MET for a
 * criterion another source reported as met, and the ladder's collapse rule
 * would have taken the NOT MET. So an agent is judged only when every source
 * that could have reported a verdict about it was read in full:
 *
 *   1. every kind it was discovered through, and
 *   2. every listed source that reports verdicts about agents OTHER sources
 *      discover (`CROSS_AGENT_VERDICT_SOURCE`).
 *
 * Anything else is NOT JUDGED, with the reasons as codes and operands, never
 * prose. An incomplete source that bears on neither is a caveat beside the
 * level, not a reason to withhold it.
 *
 * PURE: no clock, no I/O.
 */
import type { HarnessSourceKind } from '@rodnapamet/scanent-contract/harness-findings';

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

/** A source as a report lists it, as far as a judgement needs. */
export interface ListedSource {
    readonly kind: string;
    readonly status: 'COMPLETE' | 'INCOMPLETE';
    readonly reason?: string | undefined;
}

/** The reason a kind in `discoveredVia` gets when the report does not list that source at all. */
export const SOURCE_NOT_LISTED = 'NOT_LISTED';

export type JudgementBasis =
    | { readonly judged: true; readonly caveats: readonly string[] }
    | { readonly judged: false; readonly reasons: readonly string[] };

const isCrossAgentVerdictSource = (kind: string): boolean =>
    Object.hasOwn(CROSS_AGENT_VERDICT_SOURCE, kind) && CROSS_AGENT_VERDICT_SOURCE[kind as HarnessSourceKind];

/**
 * May this agent be given a level? `reasons` and `caveats` follow the order the
 * agent and the report list their sources in, so the answer is deterministic.
 */
export function judgementBasisOf(discoveredVia: readonly string[], sources: readonly ListedSource[]): JudgementBasis {
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
    return reasons.length > 0 ? { judged: false, reasons } : { judged: true, caveats };
}
