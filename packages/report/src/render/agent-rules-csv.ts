/**
 * `agent-rule-findings.csv` — the agent-surface rules' findings for a
 * spreadsheet, written only by a run that configured an `mcp` source.
 *
 * The agent CSVs' rules, by their own function (`csvFile`, every cell through
 * `csvCell`). A row is a rule that fired and where: the code, the rule id, the
 * severity, the subject and the locator. There is no text column, because the
 * scanner never kept the text the rule read.
 *
 * A run whose read was not complete says so in its own rows: one row per
 * subject kind that was not concluded, with `NOT_CONCLUDED` as its severity
 * and the reason in place of a rule, so an empty file is never mistaken for a
 * clean one.
 */
import type { LocalAgentRulesResults } from '../results/types';
import { csvFile } from './csv';

export const AGENT_RULE_FINDINGS_CSV_COLUMNS = ['severity', 'code', 'ruleId', 'subjectKind', 'subjectRef', 'serverRef', 'locator', 'sourceRef'] as const;

export function renderAgentRuleFindingsCsv(a: LocalAgentRulesResults): string {
    const rows: (readonly string[])[] = a.findings.map((f) => [f.severity, f.code, f.ruleId, f.subjectKind, f.subjectRef, f.serverRef, f.locator, f.sourceRef]);
    for (const n of a.notConcluded) rows.push(['NOT_CONCLUDED', n.why, n.reason, n.scope, '', '', '', '']);
    return csvFile(AGENT_RULE_FINDINGS_CSV_COLUMNS, rows);
}
