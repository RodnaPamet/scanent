/**
 * `agents.csv` and `findings.csv` — the results for a spreadsheet.
 *
 * RFC 4180: CRLF line ends, a header row, every field quoted, a quote doubled.
 * UTF-8 with a byte-order mark, because the reader is a spreadsheet and an
 * owner's name is not always ASCII.
 *
 * ONE function writes every cell (`csvCell`), whoever supplied its text:
 *
 *   • a cell that a spreadsheet would read as a formula (it starts with `=`,
 *     `+`, `-`, `@`, a tab or a carriage return, with or without leading
 *     white space) is prefixed with a single quote, so it is shown and never
 *     evaluated. The rule has no exception for cells scanent wrote itself;
 *   • every control character becomes a space, so one record is one line.
 */
import { ALL_HARNESS_CRITERIA } from '@scanent/contract/harness-ladder';

import type { LocalAgentResult, LocalCriterionCell, LocalResults } from '../results/types';

export const CSV_BOM = '﻿';
const CRLF = '\r\n';

/** One cell, neutralised and quoted. */
export function csvCell(value: string | number): string {
    const text = String(value);
    const formula = /^[ \t\r\n]*[=+\-@]/.test(text) || /^[\t\r]/.test(text);
    let clean = '';
    for (const ch of text) {
        const code = ch.codePointAt(0) as number;
        clean += code < 0x20 || code === 0x7f || code === 0x2028 || code === 0x2029 ? ' ' : ch;
    }
    return `"${(formula ? `'${clean}` : clean).replace(/"/g, '""')}"`;
}

function csvFile(header: readonly string[], rows: readonly (readonly (string | number)[])[]): string {
    return CSV_BOM + [header, ...rows].map((row) => row.map(csvCell).join(',') + CRLF).join('');
}

/** The word one criterion cell holds in `agents.csv`. */
export function csvCriterionState(cell: LocalCriterionCell): string {
    if (cell.state === 'EVIDENCED') return cell.basis === 'DECLARED' ? 'DECLARED' : 'EVIDENCED';
    if (cell.state === 'UNANSWERED') return cell.readable ? 'UNANSWERED' : 'NOT_READABLE';
    return cell.state;
}

export const AGENTS_CSV_LEADING_COLUMNS = [
    'discoveredId',
    'declaredName',
    'declaredOwner',
    'declaredPurpose',
    'observedOwnerKind',
    'observedOwnerRef',
    'discoveredVia',
    'registration',
    'judged',
    'level',
    'observedLevel',
    'notJudgedReasons',
    'reach',
    'bar',
    'shortfall',
    'blockingNextRung',
    'credentials',
    'tools',
    'writeCapableTools',
    'unpinnedWriteTools',
] as const;

function agentRow(agent: LocalAgentResult): (string | number)[] {
    const j = agent.judgement;
    const judged = j.state === 'JUDGED';
    const cells = new Map(agent.criteria.map((c) => [c.criterion, c]));
    return [
        agent.discoveredId,
        agent.declared?.name ?? '',
        agent.declared?.owner ?? '',
        agent.declared?.purpose ?? '',
        agent.observedOwner?.kind ?? '',
        agent.observedOwner?.ref ?? '',
        agent.discoveredVia.join(';'),
        agent.registration.basis,
        judged ? 'yes' : 'no',
        // Empty, never H0, for an agent that was not judged.
        judged ? j.level : '',
        judged ? j.observedLevel : '',
        judged ? '' : j.reasons.join(';'),
        agent.reach,
        judged ? j.bar : '',
        judged ? (j.shortfall ? 'yes' : 'no') : '',
        judged ? j.blockingNextRung.join(';') : '',
        agent.counts.credentials,
        agent.counts.tools,
        agent.counts.writeCapableTools,
        agent.counts.unpinnedWriteTools,
        ...ALL_HARNESS_CRITERIA.map((criterion) => {
            const cell = cells.get(criterion);
            return cell === undefined ? 'UNANSWERED' : csvCriterionState(cell);
        }),
    ];
}

/** One row per agent; a header and no rows for an empty estate. */
export function renderAgentsCsv(results: LocalResults): string {
    return csvFile([...AGENTS_CSV_LEADING_COLUMNS, ...ALL_HARNESS_CRITERIA], results.agents.map(agentRow));
}

export const FINDINGS_CSV_COLUMNS = ['code', 'severity', 'type', 'sourceRef', 'discoveredId', 'title', 'description'] as const;

/** One row per finding. */
export function renderFindingsCsv(results: LocalResults): string {
    return csvFile(
        FINDINGS_CSV_COLUMNS,
        results.findings.map((f) => [f.code, f.severity, f.type, f.sourceRef, f.discoveredId ?? '', f.title, f.description]),
    );
}
