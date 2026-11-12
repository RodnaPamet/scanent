/**
 * `scanent doctor` — the two renderings: a table for a person, JSON for a script.
 *
 * Every string printed in the table goes through the terminal escaper `diff`
 * uses, so a configured label or a role name can neither start a new line nor
 * send an escape sequence.
 */
import { terminalLine } from '@scanent/report/render/escape';

import type { Check, DoctorReport, SkipCause } from './types';

const CAUSE_WORDS: Readonly<Record<SkipCause, string>> = {
    NOT_APPLICABLE: 'not applicable',
    BLOCKED: 'blocked',
    NOT_OBSERVABLE: 'not observable',
};

/** The line under the table: the count of each status, what was not checked and why, and whether the estate is ready. */
export function summaryLine(report: Pick<DoctorReport, 'checks' | 'counts' | 'ready'>): string {
    const { counts, checks } = report;
    const causes = (['NOT_OBSERVABLE', 'NOT_APPLICABLE', 'BLOCKED'] as const)
        .map((cause) => ({ cause, n: checks.filter((c) => c.status === 'SKIPPED' && c.cause === cause).length }))
        .filter((x) => x.n > 0)
        .map((x) => `${x.n} ${CAUSE_WORDS[x.cause]}`);
    const head =
        `${counts.PASS} passed, ${counts.WARN} warning${counts.WARN === 1 ? '' : 's'}, ${counts.FAIL} failed, ` +
        `${counts.SKIPPED} not checked${causes.length > 0 ? ` (${causes.join(', ')})` : ''}.`;
    let verdict: string;
    if (counts.FAIL > 0) verdict = 'Not ready: fix the failures and run doctor again.';
    else if (!report.ready) {
        verdict = counts.WARN > 0 ? 'Not ready: fix the warnings or accept them.' : 'Not ready: some checks were blocked; run doctor again.';
    } else if (counts.SKIPPED === 0) verdict = 'Ready: all checks passed.';
    else verdict = `Ready. ${counts.SKIPPED} check${counts.SKIPPED === 1 ? ' was' : 's were'} not checked; each says why above.`;
    return `${head} ${verdict}`;
}

function detailOf(check: Check): string {
    if (check.status !== 'SKIPPED') return check.detail;
    return `${CAUSE_WORDS[check.cause]}: ${check.detail}`;
}

/** The table. Scopes in the order their first check appears. */
export function renderDoctorText(report: DoctorReport): string {
    const out: string[] = [`scanent doctor  estate ${terminalLine(report.estate ?? '(configuration not read)')}  ${report.at}`, ''];
    const scopes: string[] = [];
    for (const c of report.checks) if (!scopes.includes(c.scope)) scopes.push(c.scope);
    const width = Math.max(...report.checks.map((c) => c.id.length), 0);
    for (const scope of scopes) {
        out.push(terminalLine(scope));
        for (const c of report.checks.filter((x) => x.scope === scope)) {
            out.push(`  ${c.status.padEnd(8)} ${terminalLine(c.id).padEnd(width)}  ${terminalLine(detailOf(c))}`.trimEnd());
            if (c.status === 'WARN' || c.status === 'FAIL') out.push(`  ${' '.repeat(8)} fix: ${terminalLine(c.fix)}`);
        }
    }
    out.push('', summaryLine(report), '');
    return out.join('\n');
}

/** The `scanent-doctor/1` document, one line of JSON per member for a diff, and a trailing newline. */
export function renderDoctorJson(report: DoctorReport): string {
    return `${JSON.stringify(report, null, 2)}\n`;
}
