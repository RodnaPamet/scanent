/**
 * A diff as plain text, for a terminal or a ticket.
 *
 * One summary line first, then the sections in the order the comparison was
 * made: completeness before anything it bears on. Whatever could not be
 * concluded is never worded as a change: an agent that was not seen is "not
 * seen", with the reason, and the words for a concluded absence are kept for
 * the entries that earned them. A closing block lists every comparison that
 * could not be made.
 *
 * The strings in a diff are scanned data, and the reader is a terminal: every
 * line is passed through `terminalLine`, so an id can neither forge a line of
 * this output nor send the terminal an escape sequence.
 */
import { terminalLine } from './escape';
import type { AgentNotSeen, FindingChange, OrphanChange, ResultsDiff } from '../diff/diff';

const SUMMARY: Readonly<Record<ResultsDiff['outcome'], string>> = {
    SAME: 'No difference, and every comparison could be made.',
    DIFFERENT: 'The two runs differ.',
    SAME_AS_FAR_AS_COMPARED: 'No difference was found, but not every comparison could be made. This is not a statement that nothing changed.',
};

const WARNING_TEXT: Readonly<Record<string, string>> = {
    INVENTORY_DIFFERS: 'the two runs were scored against different inventories (or one had none), so declared criteria and registrations show as changes',
    SCANNER_DIFFERS: 'the two runs are from different scanners, so nothing absent from the new run is concluded',
    ESTATE_DIFFERS: 'the two runs name different estates, so nothing absent from the new run is concluded',
    SIGNER_NOT_PINNED: 'the signed report was verified against the key it carries itself: integrity, not origin',
    REGISTER_CLAIMS_NOT_VERIFIED: 'the report’s register links are taken as stated, not read by the run that scored it',
};

const SOURCE_TEXT: Readonly<Record<string, string>> = {
    NOW_INCOMPLETE: 'was read in full and is now incomplete',
    NOW_COMPLETE: 'was incomplete and is now read in full',
    REASON_CHANGED: 'is still incomplete, for a different reason',
    ADDED: 'is new in this run',
    NO_LONGER_READ: 'is no longer listed',
};

const LEVEL_TEXT: Readonly<Record<string, string>> = {
    LEVEL_UP: 'level up',
    LEVEL_DOWN: 'level down',
    OBSERVED_LEVEL_UP: 'level on observation alone up',
    OBSERVED_LEVEL_DOWN: 'level on observation alone down',
    NOW_NOT_JUDGED: 'was judged and is now not judged; no level is compared',
    NOW_JUDGED: 'was not judged and is now judged; no level is compared',
};

function side(label: string, s: ResultsDiff['old']): string[] {
    return [
        `${label}: scan ${s.scanId}, as of ${s.asOf}`,
        `     ${s.complete ? 'complete' : 'INCOMPLETE'}, ${s.agentCount} agent${s.agentCount === 1 ? '' : 's'}, inventory ${s.inventorySha256 === null ? 'none' : `sha256:${s.inventorySha256}`}, signer ${s.signerPinned ? 'pinned' : 'not pinned'}`,
    ];
}

function section(title: string, lines: readonly string[]): string[] {
    return lines.length === 0 ? [] : ['', title, ...lines.map((l) => `  ${l}`)];
}

function notSeenLine(a: AgentNotSeen): string {
    const because = a.differentScanner
        ? 'the runs are from different scanners'
        : a.differentEstate
            ? 'the runs name different estates'
            : a.unread.length > 0
                ? a.unread.map((u) => `${u.kind} ${u.status === 'ABSENT' ? 'was not listed' : 'was not read in full'}`).join('; ')
                : a.newScanEmpty
                    ? 'the new run found no agent at all'
                    : 'it was found through no listed source';
    return `not seen   ${a.discoveredId}  (${because}; nothing is concluded)`;
}

function closureLine(change: OrphanChange['change'], subject: string, why: string | null): string {
    if (change === 'OPENED') return `opened     ${subject}`;
    if (change === 'CLOSED') return `closed     ${subject}`;
    return `no longer reported, not concluded   ${subject}  (${why ?? 'UNKNOWN'})`;
}

function findingLine(f: FindingChange): string {
    return closureLine(f.change, `${f.code} ${f.sourceRef}`, f.why);
}

export function renderDiffText(diff: ResultsDiff): string {
    const d = diff;
    const lines: string[] = [
        `scanent diff: ${SUMMARY[d.outcome]}`,
        `${d.summary.differences} difference${d.summary.differences === 1 ? '' : 's'}; ${d.summary.notConcluded} comparison${d.summary.notConcluded === 1 ? '' : 's'} not concluded.`,
        '',
        ...side('old', d.old),
        ...side('new', d.new),
        `ladder ${d.ladderVersion}`,
    ];
    lines.push(
        ...section(
            'Warnings',
            d.warnings.map((w) => {
                const [code, which] = w.split(':');
                return `${w}: ${which === undefined ? '' : `${which} run: `}${WARNING_TEXT[code] ?? 'see the code'}`;
            }),
        ),
        ...section(
            'Completeness',
            d.sources.map((s) => {
                const reasons = [s.from.reason, s.to.reason].some((r) => r !== null) ? ` (${s.from.reason ?? '-'} -> ${s.to.reason ?? '-'})` : '';
                return `${s.kind} ${SOURCE_TEXT[s.change]}${reasons}`;
            }),
        ),
        ...section('Agents', [
            ...d.agents.added.map((id) => `new        ${id}`),
            ...d.agents.gone.map((id) => `gone       ${id}  (every source it was found through was read in full)`),
            ...d.agents.notSeen.map(notSeenLine),
        ]),
        ...section(
            'Levels',
            d.levels.map((l) =>
                l.from !== null && l.to !== null
                    ? `${l.discoveredId}: ${LEVEL_TEXT[l.change]}, ${l.from} -> ${l.to}`
                    : `${l.discoveredId}: ${LEVEL_TEXT[l.change]}${l.reasons.length > 0 ? ` (${l.reasons.join('; ')})` : ''}`,
            ),
        ),
        ...section(
            'Criteria',
            d.criteria.filter((c) => c.concluded).map((c) => `${c.discoveredId} ${c.criterion}: ${cell(c.from)} -> ${cell(c.to)}`),
        ),
        ...section(
            'Criteria reported, not concluded (the agent was not judged in one of the runs)',
            d.criteria.filter((c) => !c.concluded).map((c) => `${c.discoveredId} ${c.criterion}: ${cell(c.from)} -> ${cell(c.to)}`),
        ),
        ...section(
            'Reach, bar, shortfall and registration',
            d.attributes.map((a) => `${a.discoveredId} ${a.attribute}: ${a.from} -> ${a.to}`),
        ),
        ...section(
            'Orphan credentials',
            d.orphanCredentials.map((c) => closureLine(c.change, `${c.ref} (${c.sourceKind})`, c.why)),
        ),
        ...section('Findings', d.findings.map(findingLine)),
        ...section('Not concluded', d.notConcluded),
    );
    // Every line is one line: whatever a scanned string carried, it is shown, not obeyed.
    return `${lines.map(terminalLine).join('\n')}\n`;
}

function cell(c: { readonly state: string; readonly basis: string | null }): string {
    return c.basis === null ? c.state : `${c.state}/${c.basis}`;
}
