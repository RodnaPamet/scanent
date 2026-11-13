/**
 * A run diff — one comparison per scanner — as plain text.
 *
 * The agent scanner's comparison is `renderDiffText`'s, unchanged, under its
 * own heading; the integrations scanner's follows the same rules: whatever
 * could not be concluded is never worded as a change, and a closing block
 * lists every comparison that could not be made. A scanner that ran in one
 * run only is named as such, and nothing about it is concluded.
 *
 * Every line is passed through `terminalLine`, as the agent diff's are.
 */
import { renderDiffText } from './diff-text';
import { terminalLine } from './escape';
import type { DiffOutcome } from '../diff/diff';
import type { IntegrationsDiff, IntegrationsDiffSide } from '../diff/integrations-diff';
import type { RunDiff, ScannerNotCompared } from '../diff/run-diff';

const SUMMARY: Readonly<Record<DiffOutcome, string>> = {
    SAME: 'No difference, and every comparison could be made.',
    DIFFERENT: 'The two runs differ.',
    SAME_AS_FAR_AS_COMPARED: 'No difference was found, but not every comparison could be made. This is not a statement that nothing changed.',
};

const NOT_COMPARED_TEXT: Readonly<Record<ScannerNotCompared['change'], string>> = {
    ADDED: 'ran in the new run only: nothing is compared, and nothing it found is a change',
    NO_LONGER_RUN: 'ran in the old run only: nothing is compared, and nothing is concluded about what it would find now',
    NOT_RUN: 'ran in neither run',
};

const WARNING_TEXT: Readonly<Record<string, string>> = {
    SCANNER_DIFFERS: 'the two runs are from different scanners, so nothing absent from the new run is concluded',
    ESTATE_DIFFERS: 'the two runs name different estates, so nothing absent from the new run is concluded',
    UNUSED_DAYS_DIFFER: 'the two runs judged "unused" over different windows, so an unused finding opened or closed may be the window and not the application',
};

const SOURCE_TEXT: Readonly<Record<string, string>> = {
    NOW_INCOMPLETE: 'was read in full and is now incomplete',
    NOW_COMPLETE: 'was incomplete and is now read in full',
    REASON_CHANGED: 'is still incomplete, for a different reason',
    ADDED: 'is new in this run',
    NO_LONGER_READ: 'is no longer read',
};

const NOT_SEEN_TEXT: Readonly<Record<string, string>> = {
    SOURCE_INCOMPLETE: 'its source was not read in full',
    SOURCE_ABSENT: 'its source is no longer listed',
    NEW_SOURCE_EMPTY: 'its source reported no application at all',
    DIFFERENT_SCANNER: 'the runs are from different scanners',
    DIFFERENT_ESTATE: 'the runs name different estates',
};

function section(title: string, lines: readonly string[]): string[] {
    return lines.length === 0 ? [] : ['', title, ...lines.map((l) => `  ${l}`)];
}

function side(label: string, s: IntegrationsDiffSide): string[] {
    return [
        `${label}: scan ${s.scanId}, as of ${s.asOf}`,
        `     ${s.complete ? 'complete' : 'INCOMPLETE'}, ${s.applicationCount} application${s.applicationCount === 1 ? '' : 's'}`,
    ];
}

/** The integrations scanner's comparison: the lines under its heading. */
export function integrationsDiffLines(d: IntegrationsDiff): string[] {
    return [
        `${SUMMARY[d.outcome]}`,
        `${d.summary.differences} difference${d.summary.differences === 1 ? '' : 's'}; ${d.summary.notConcluded} comparison${d.summary.notConcluded === 1 ? '' : 's'} not concluded.`,
        '',
        ...side('old', d.old),
        ...side('new', d.new),
        ...section('Warnings', d.warnings.map((w) => `${w}: ${WARNING_TEXT[w] ?? 'see the code'}`)),
        ...section(
            'Completeness',
            d.sources.map((s) => {
                const reasons = [s.from.reason, s.to.reason].some((r) => r !== null) ? ` (${s.from.reason ?? '-'} -> ${s.to.reason ?? '-'})` : '';
                return `${s.kind} ${SOURCE_TEXT[s.change]}${reasons}`;
            }),
        ),
        ...section('Applications', [
            ...d.applications.added.map((id) => `new        ${id}`),
            ...d.applications.gone.map((id) => `gone       ${id}  (its source was read in full)`),
            ...d.applications.notSeen.map((x) => `not seen   ${x.id}  (${NOT_SEEN_TEXT[x.why] ?? x.why}; nothing is concluded)`),
        ]),
        ...section(
            'Findings',
            d.findings.map((f) =>
                f.change === 'OPENED'
                    ? `opened     ${f.code} ${f.sourceRef}`
                    : f.change === 'CLOSED'
                        ? `closed     ${f.code} ${f.sourceRef}`
                        : `no longer raised, not concluded   ${f.code} ${f.sourceRef}  (${f.why ?? 'UNKNOWN'})`,
            ),
        ),
        ...section('Not concluded', d.notConcluded),
    ];
}

export function renderRunDiffText(diff: RunDiff): string {
    const { agents, integrations } = diff.scanners;
    const lines: string[] = [
        `scanent diff: ${SUMMARY[diff.outcome]}`,
        `${diff.summary.differences} difference${diff.summary.differences === 1 ? '' : 's'}; ${diff.summary.notConcluded} comparison${diff.summary.notConcluded === 1 ? '' : 's'} not concluded, across both scanners.`,
        '',
        '== Agent scanner ==',
    ];
    if ('compared' in agents) lines.push(`The agent scanner ${NOT_COMPARED_TEXT[agents.change]}.`);
    else lines.push(...renderDiffText(agents).replace(/\n$/, '').split('\n'));
    lines.push('', '== Integrations scanner ==');
    if ('compared' in integrations) lines.push(`The integrations scanner ${NOT_COMPARED_TEXT[integrations.change]}.`);
    else lines.push(...integrationsDiffLines(integrations));
    // Every line is one line. The agent part was already passed through once; passing again changes nothing.
    return `${lines.map(terminalLine).join('\n')}\n`;
}
