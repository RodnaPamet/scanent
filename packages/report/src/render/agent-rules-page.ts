/**
 * THE "AGENT SURFACE" SECTION OF `summary.html`.
 *
 * Present only for a run that configured an `mcp` source. Static: no script
 * and no style of its own, so the page's policy is unchanged by it. What it
 * shows is the report's, in the planner's order, and it never shows text, for
 * there is none: the scanner kept only the rule that fired and where.
 *
 * The honesty line comes first. "No finding" is said only of a complete read;
 * a partial read keeps its findings and says nothing clean.
 */
import { SUBJECT_KIND_TITLE } from '@rodnapamet/scanent-contract/agent-rules-contract-rules';
import type { INCOMPLETE_REASONS_V2 } from '@rodnapamet/scanent-contract/harness-contract';

import type { LocalAgentRulesResults } from '../results/types';
import { html, type SafeHtml } from './escape';
import { AGENT_RULES_RUN_FILE_NAMES } from './files';
import { fixed, plural, SEVERITY_CLASS } from './words';

/** The most rows the page lists; the CSV holds them all. */
export const AGENT_RULES_MAX_ROWS = 500;

/** A population's reason in words. One entry per reason the contract allows. */
const REASON_TEXT: Readonly<Record<(typeof INCOMPLETE_REASONS_V2)[number], string>> = {
    BYTE_CAP: 'a definition was longer than the rules read, or there were more findings than a report carries',
    TIME_BOX: 'the read ran out of its time',
    AUTH_FAILED: 'a server refused the credentials',
    UNREACHABLE: 'a server could not be reached',
    PAGINATION_TORN: 'the listing changed while it was being read',
    RATE_LIMITED: 'a server limited the rate of requests',
    UNPARSEABLE: 'a server answered with something the scanner could not read',
};

function outcomeLine(a: LocalAgentRulesResults): SafeHtml {
    if (a.outcome === 'NO_FINDING_ON_A_COMPLETE_READ') {
        return html`<p class="status ok"><strong>No rule fired.</strong> Every tool definition the MCP servers list was read in full.</p>`;
    }
    if (a.outcome === 'NOT_CONCLUDED') {
        return html`<p class="status bad"><strong>Not concluded:</strong> not every tool definition was read, and no rule fired on those that were. This is not a clean result.</p>`;
    }
    const partial = a.population.some((p) => p.status === 'INCOMPLETE');
    return partial
        ? html`<p class="status bad"><strong>Incomplete:</strong> not every tool definition was read. A finding below is real; an absence is not a clean result.</p>`
        : html`<p class="status ok"><strong>Complete.</strong> Every tool definition the MCP servers list was read in full.</p>`;
}

export function agentRulesSection(a: LocalAgentRulesResults): SafeHtml {
    const shown = a.findings.slice(0, AGENT_RULES_MAX_ROWS);
    return html`<section id="agent-surface" aria-labelledby="agent-surface-h">
<h2 id="agent-surface-h">Agent surface</h2>
<p>Static rules run over the text of each MCP tool definition the scan read: its description and its input schema. A rule is a sign of an attack written into the text, such as a hidden instruction or an executable payload. It is a suggestion a person confirms, never proof, and it changes no agent's level. The text itself never left the scanner. A report of its own, <code>${a.report.file}</code> (contract <code>scanent-agent-rules/1</code>, SHA-256 <code class="id">${a.report.sha256}</code>), signed with the same key as the agent report.</p>
${outcomeLine(a)}
<dl class="stats">
<div class="stat"><dt>Tool definitions read</dt><dd><span class="big">${a.counts.subjects}</span></dd></div>
<div class="stat"><dt>With a finding</dt><dd><span class="big">${a.counts.flagged}</span></dd></div>
<div class="stat"><dt>Findings</dt><dd><span class="big">${a.counts.findings}</span></dd></div>
</dl>
${a.notConcluded.length === 0
        ? ''
        : html`<h3>Not concluded</h3>
<ul>${a.notConcluded.map((n) => html`<li>${SUBJECT_KIND_TITLE[n.scope]}: ${fixed(REASON_TEXT, n.reason, 'the read did not complete')} <code>${n.reason}</code>.</li>`)}</ul>`}
${a.findings.length === 0
        ? ''
        : html`${a.findings.length > shown.length ? html`<p class="callout">This list shows the first ${shown.length} of ${a.findings.length} findings, most severe first. The full list is in <code>${AGENT_RULES_RUN_FILE_NAMES.findings}</code>.</p>` : ''}<div class="scroll"><table class="findings">
<caption>${plural(a.findings.length, 'rule finding', 'rule findings')}, most severe first</caption>
<thead><tr><th scope="col">Severity</th><th scope="col">Code</th><th scope="col">Rule</th><th scope="col">Where</th></tr></thead>
<tbody>
${shown.map(
        (f) => html`<tr>
<td><span class="tag ${fixed(SEVERITY_CLASS, f.severity, 'sev-low')}">${f.severity}</span></td>
<td><code>${f.code}</code></td>
<td><code class="id">${f.ruleId}</code></td>
<td><code class="id">${f.locator}</code></td>
</tr>`,
    )}
</tbody>
</table></div>`}
</section>`;
}
