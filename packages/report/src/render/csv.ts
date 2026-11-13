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
 *     white space or invisible characters, the full-width forms of the
 *     operators included) is prefixed with a single quote, so it is shown and
 *     never evaluated. The rule has no exception for cells scanent wrote itself;
 *   • every control character becomes a space, so one record is one line, and
 *     a bidirectional control becomes U+FFFD, so a cell reads as it is written.
 */
import { ALL_HARNESS_CRITERIA } from '@rodnapamet/scanent-contract/harness-ladder';
import { harnessMatrixCellState, type HarnessMatrixCellState } from '@rodnapamet/scanent-contract/harness-matrix-model';

import { isBidiControl } from './escape';
import type { LocalAgentResult, LocalCriterionCell, LocalResults } from '../results/types';

export const CSV_BOM = '﻿';
const CRLF = '\r\n';

/**
 * A cell some spreadsheet may read as a formula: an operator, ASCII or
 * full-width, after any run of white space (Unicode's, a no-break space and a
 * byte-order mark included), control characters and invisible format
 * characters. Importers differ on which of those they trim, so all are skipped.
 */
const FORMULA_START = /^[\s\p{Cc}\p{Cf}]*[=+\-@\uff1d\uff0b\uff0d\uff20]/u;

/** One cell, neutralised and quoted. */
export function csvCell(value: string | number): string {
    const text = String(value);
    const formula = FORMULA_START.test(text) || /^[\t\r]/.test(text);
    let clean = '';
    for (const ch of text) {
        const code = ch.codePointAt(0) as number;
        if (isBidiControl(code)) clean += '\ufffd';
        else clean += code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029 ? ' ' : ch;
    }
    return `"${(formula ? `'${clean}` : clean).replace(/"/g, '""')}"`;
}

function csvFile(header: readonly string[], rows: readonly (readonly (string | number)[])[]): string {
    return CSV_BOM + [header, ...rows].map((row) => row.map(csvCell).join(',') + CRLF).join('');
}

/**
 * The word one criterion cell holds in `agents.csv`, and in a comparison of two
 * runs: the table model's cell state (`harnessMatrixCellState`), whose seven
 * names are these words, so a reader of every file sees the same word for the
 * same cell, and so does a reader of Inflect's harness tab.
 *
 * A verdict taken from the operator's inventory is never given the word of an
 * observed one. `DECLARED` is a criterion met on what the operator wrote, and
 * `NOT_MET_DECLARED` one not met on it (a row with no axes, no tier, or a tier
 * dated outside the window): no source saw anything either way.
 */
export function csvCriterionState<T extends Pick<LocalCriterionCell, 'state' | 'basis' | 'readable'>>(cell: T): HarnessMatrixCellState {
    return harnessMatrixCellState(cell);
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
    'classification',
    'modelSigns',
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
    'paymentCapabilities',
] as const;

/**
 * The `paymentCapabilities` cell: `NOT_REPORTED` when the run did not say (a
 * report before `/4`, an agent no code read reported, a file written before
 * the member), `NONE_SEEN` when a code read saw no payment client in the
 * agent's own file (which is not "cannot pay"), and otherwise each place,
 * `<library> at <locator>`, separated by `;`.
 */
export function csvPaymentCapabilities(agent: Pick<LocalAgentResult, 'paymentCapabilities'>): string {
    const caps = agent.paymentCapabilities;
    if (caps === undefined || caps === null) return 'NOT_REPORTED';
    if (caps.length === 0) return 'NONE_SEEN';
    return caps.map((c) => `${c.library} at ${c.at}`).join(';');
}

/**
 * What a principal is, on what the run read: registered (by a register or
 * the inventory), a shadow agent (unregistered, with a sign of a model) or an
 * unregistered automated identity (unregistered, with none). A file written
 * before `modelSigns` existed has no signs to go on, and every unregistered
 * principal in it is a shadow agent, as its own findings say.
 */
export function agentClassification(agent: Pick<LocalAgentResult, 'registration' | 'modelSigns'>): 'REGISTERED' | 'SHADOW_AGENT' | 'UNREGISTERED_IDENTITY' {
    if (agent.registration.basis !== 'NONE') return 'REGISTERED';
    return agent.modelSigns !== undefined && agent.modelSigns.length === 0 ? 'UNREGISTERED_IDENTITY' : 'SHADOW_AGENT';
}

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
        agentClassification(agent),
        (agent.modelSigns ?? []).join(';'),
        judged ? 'yes' : 'no',
        // Empty, never H0, for an agent that was not judged.
        judged ? j.level : '',
        judged ? j.observedLevel : '',
        judged ? '' : j.reasons.join(';'),
        agent.reach,
        judged ? j.bar : '',
        // An unregistered identity is held to no bar, so it is neither below one nor at it.
        judged ? (agentClassification(agent) === 'UNREGISTERED_IDENTITY' ? 'not held to a bar' : j.shortfall ? 'yes' : 'no') : '',
        judged ? j.blockingNextRung.join(';') : '',
        agent.counts.credentials,
        agent.counts.tools,
        agent.counts.writeCapableTools,
        agent.counts.unpinnedWriteTools,
        csvPaymentCapabilities(agent),
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
