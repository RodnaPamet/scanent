/**
 * `summary.html` — the results as one page somebody opens.
 *
 * ONE FILE, NOTHING LOADED. No script element, no link, no image, no frame,
 * no import, no web font and no inline event handler; one style block. A
 * Content-Security-Policy meta makes the browser hold the same line.
 *
 * EVERY SCANNED STRING IS ESCAPED. The page is built with the `html` template
 * of `escape.ts`, which escapes whatever is interpolated. Scanned data never
 * becomes a tag name, an attribute name, a class, a URL or a link: classes and
 * state codes come from the fixed tables in this file, keyed by enum values,
 * and a value the tables do not know falls back to a fixed neutral entry.
 *
 * WHAT COULD NOT BE READ COMES FIRST. Completeness per source is the first
 * section after the header, and what this run could not have evidenced is the
 * second, so nobody reads a level before they have read what it rests on. An
 * agent that could not be judged shows the words "Not judged" and its reasons,
 * and no level anywhere. An empty scan is shown as a finding, never as a clean
 * result.
 *
 * NO CLOCK AND NO PATH. The page holds no generation time and no absolute
 * path, so the same results give the same bytes.
 */
import { harnessBarFor } from '@rodnapamet/scanent-contract/harness-findings';
import { HARNESS_LEVEL_NAMES, HARNESS_LEVELS, levelAtLeast, type HarnessCriterionId, type HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';

import type { LocalAgentResult, LocalCriterionCell, LocalFinding, LocalResults } from '../results/types';
import { html, htmlText, type HtmlValue, type SafeHtml } from './escape';
import { RUN_FILE_NAMES } from './files';

/**
 * Above this many agents the matrix shows the first ones and says so. A run at
 * or below it shows every agent, in order of id.
 */
export const MATRIX_MAX_AGENTS = 500;

/**
 * The most rows any one list on the page shows: shadow agents, orphan
 * credentials, findings, the inventory's unmatched ids. Without it the page
 * grows with the estate (a 5,000-agent run measured 14 MiB and 15,000 table
 * rows), and a page nobody can open shows nothing. A list over the cap says
 * how many it shows, how many the run holds and which file holds the rest; the
 * counts in the summary are always over the whole run, and no other file is
 * shortened.
 */
export const SECTION_MAX_ROWS = MATRIX_MAX_AGENTS;

/**
 * The most findings the page lists. Five for each agent the matrix can show:
 * an agent raises a few findings, so a run the matrix shows whole has its
 * findings shown whole too, and a row here is small beside a matrix row.
 */
export const FINDINGS_MAX_ROWS = 5 * MATRIX_MAX_AGENTS;

/** The first `max` of a list, and the notice to show when that is not all of it. */
function capped<T>(
    all: readonly T[],
    max: number,
    what: string,
    order: string,
    file: string,
): { readonly shown: readonly T[]; readonly notice: SafeHtml | '' } {
    if (all.length <= max) return { shown: all, notice: '' };
    return {
        shown: all.slice(0, max),
        notice: html`<p class="callout">This list shows the first ${max} of ${all.length} ${what}, ${order}. The full list is in <code>${file}</code>.</p>`,
    };
}

/**
 * Which agents the matrix shows when the run holds more than it can: the ones
 * that most need a reader. Not judged first, then below their bar, then the
 * lowest level; within each, in order of id (the order the results list them in).
 */
function matrixSelection(agents: readonly LocalAgentResult[]): readonly LocalAgentResult[] {
    if (agents.length <= MATRIX_MAX_AGENTS) return agents;
    const rank = (a: LocalAgentResult): number => {
        const j = a.judgement;
        if (j.state !== 'JUDGED') return 0;
        const rung = Math.max(0, HARNESS_LEVELS.indexOf(j.level));
        return (j.shortfall ? 1 : 1 + HARNESS_LEVELS.length) + rung;
    };
    return agents
        .map((agent, i): [LocalAgentResult, number, number] => [agent, rank(agent), i])
        .sort(([, ra, ia], [, rb, ib]) => ra - rb || ia - ib)
        .slice(0, MATRIX_MAX_AGENTS)
        .map(([agent]) => agent);
}

// ── Fixed tables: every class and code on the page comes from one of these ──

interface CellStyle {
    readonly code: string;
    readonly cls: string;
    readonly text: string;
}

const CELL_EVIDENCED: CellStyle = { code: 'E', cls: 'c-e', text: 'Evidenced: a source observed it' };
const CELL_DECLARED: CellStyle = { code: 'D', cls: 'c-d', text: 'Evidenced on what the operator declared in the inventory, not observed' };
const CELL_UNEVIDENCED: CellStyle = { code: 'M', cls: 'c-m', text: 'Reported met without evidence; counts as not met' };
const CELL_NOT_MET: CellStyle = { code: 'N', cls: 'c-n', text: 'Not met: a source saw it fail' };
const CELL_UNANSWERED: CellStyle = { code: '·', cls: 'c-u', text: 'Unanswered: a configured reader could have reported it and none did; counts as not met' };
const CELL_NOT_READABLE: CellStyle = { code: '–', cls: 'c-x', text: 'Not readable: nothing this run was configured to read could have reported it; counts as not met' };

const LEGEND: readonly CellStyle[] = [CELL_EVIDENCED, CELL_DECLARED, CELL_UNEVIDENCED, CELL_NOT_MET, CELL_UNANSWERED, CELL_NOT_READABLE];

function cellStyle(cell: LocalCriterionCell): CellStyle {
    switch (cell.state) {
        case 'EVIDENCED':
            return cell.basis === 'DECLARED' ? CELL_DECLARED : CELL_EVIDENCED;
        case 'MET_UNEVIDENCED':
            return CELL_UNEVIDENCED;
        case 'NOT_MET':
            return CELL_NOT_MET;
        default:
            return cell.readable ? CELL_UNANSWERED : CELL_NOT_READABLE;
    }
}

const SEVERITY_CLASS: Readonly<Record<string, string>> = { LOW: 'sev-low', MEDIUM: 'sev-medium', HIGH: 'sev-high', CRITICAL: 'sev-critical' };
const SEVERITY_ORDER: Readonly<Record<string, number>> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

const REACH_TEXT: Readonly<Record<string, string>> = {
    READ_ONLY: 'Read only',
    WRITE_OR_EXTERNAL: 'Write or external',
    UNKNOWN: 'Unknown',
};

const REGISTRATION_TEXT: Readonly<Record<string, string>> = {
    NONE: 'Not registered',
    DECLARED_INVENTORY: 'Declared by the operator',
    OBSERVED_REGISTER: 'In the Inflect register',
};

const ESTATE_REGISTRATION_TEXT: Readonly<Record<string, string>> = {
    NONE: 'Nothing: no inventory was supplied and the Inflect register was not read',
    INVENTORY: 'The operator’s inventory (declared by the operator, not observed)',
    INFLECT_REGISTER: 'The Inflect register',
    BOTH: 'The Inflect register, and the operator’s inventory (declared by the operator)',
};

const UNREADABLE_TEXT: Readonly<Record<string, string>> = {
    NO_READER: 'No reader in scanent reports this criterion',
    READER_NOT_CONFIGURED: 'A reader exists; this run did not configure it',
};

const UNBOUND_TEXT: Readonly<Record<string, string>> = {
    OWN_SOURCE_INCOMPLETE: 'The source that listed it was not read in full',
    IDENTITY_SOURCE_INCOMPLETE: 'A source that could name the agent it is bound to was not read in full',
};

/** Twenty-one fixed widths; a bar's class is picked by its share, never written from data. */
const BAR_STEPS = 20;

function fixed(table: Readonly<Record<string, string>>, key: string, fallback: string): string {
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : fallback;
}

function levelName(level: HarnessLevel): string {
    return fixed(HARNESS_LEVEL_NAMES, level, '');
}

function plural(n: number, one: string, many: string): string {
    return `${n} ${n === 1 ? one : many}`;
}

/** `H2.credential_bound` → `credential bound`: the id's own words, for a column head. */
function criterionWords(criterion: string): string {
    return criterion.slice(criterion.indexOf('.') + 1).replace(/_/g, ' ');
}

/** A reason code and a sentence for it. The code is always shown beside the sentence. */
function reasonSentence(code: string): string {
    const [head, kind, reason] = code.split(':');
    if (head === 'SOURCE_INCOMPLETE' && kind !== undefined) {
        return reason === 'NOT_LISTED'
            ? `It was found through ${kind}, which the report does not list as a source`
            : `A source it was found through, ${kind}, was not read in full (${reason ?? 'no reason given'})`;
    }
    if (head === 'VERDICT_SOURCE_INCOMPLETE' && kind !== undefined) {
        return `${kind}, which reports on agents other sources find, was not read in full (${reason ?? 'no reason given'})`;
    }
    if (head === 'OTHER_SOURCE_INCOMPLETE' && kind !== undefined) {
        return `Another source, ${kind}, was not read in full; it does not bear on this agent`;
    }
    return 'See the code';
}

// ── Sections ──

function header(r: LocalResults): SafeHtml {
    const incomplete = r.sources.filter((s) => s.status !== 'COMPLETE').length;
    const status = r.scan.complete
        ? html`<p class="status ok"><strong>Complete.</strong> Every listed source was read in full.</p>`
        : r.sources.length === 0
            ? html`<p class="status bad"><strong>Incomplete:</strong> the report lists no source, so this scan evidences nothing.</p>`
            : html`<p class="status bad"><strong>Incomplete:</strong> ${incomplete} of ${plural(r.sources.length, 'source was', 'sources were')} not read in full.</p>`;
    return html`<header class="top">
<p class="brand">scanent, the Agent Estate Scanner</p>
<h1>Agent estate scan results</h1>
<dl class="meta">
<div><dt>Estate</dt><dd>${r.scan.estate === null ? 'Not stated (scored from a bare report)' : r.scan.estate}</dd></div>
<div><dt>Scan</dt><dd><code>${r.scan.id}</code></dd></div>
<div><dt>As of (UTC)</dt><dd>${r.scan.asOf}</dd></div>
</dl>
${status}
</header>`;
}

function completeness(r: LocalResults): SafeHtml {
    const notJudged = r.estate.notJudgedCount;
    const meaning = r.scan.complete
        ? html`<p>Every source this scan lists was read in full, so each result below rests on a whole read.</p>`
        : html`<p>A source that was not read in full may hold agents, tools and verdicts this page does not show.
${notJudged > 0 ? html`<strong>${plural(notJudged, 'agent is', 'agents are')} not judged</strong> for that reason and ${notJudged === 1 ? 'has' : 'have'} no level here. ` : ''}Nothing on this page is shown as gone, closed or resolved on a partial read.</p>`;
    const rows = r.sources.map(
        (s) => html`<tr class="${s.status === 'COMPLETE' ? 'row-ok' : 'row-bad'}">
<th scope="row"><code>${s.kind}</code></th>
<td>${s.status === 'COMPLETE' ? html`<span class="tag ok">Complete</span>` : html`<span class="tag bad">Incomplete</span>`}</td>
<td>${s.reason === null ? '' : html`<code>${s.reason}</code>`}</td>
<td class="num">${s.rows}</td>
<td class="num">${s.agents}</td>
</tr>`,
    );
    return html`<section id="completeness" aria-labelledby="completeness-h">
<h2 id="completeness-h">Completeness per source</h2>
${meaning}
${r.sources.length === 0
        ? html`<p class="callout bad">The report lists no source at all. A scan that looked nowhere evidences nothing.</p>`
        : html`<div class="scroll"><table>
<caption>Each source this scan lists, and whether it was read in full</caption>
<thead><tr><th scope="col">Source</th><th scope="col">Status</th><th scope="col">Reason</th><th scope="col" class="num">Rows read</th><th scope="col" class="num">Agents found</th></tr></thead>
<tbody>
${rows}
</tbody>
</table></div>`}
</section>`;
}

function coverage(r: LocalResults): SafeHtml {
    const reachable = r.coverage.reachableLevel;
    const readOnlyBar = harnessBarFor('READ_ONLY');
    const writeBar = harnessBarFor('WRITE_OR_EXTERNAL');
    const belowEveryBar = !levelAtLeast(reachable, readOnlyBar);
    const registerRead = r.sources.some((s) => s.kind === 'inflect-register');
    const rows = r.coverage.unreadable.map(
        (u) => html`<tr>
<th scope="row"><code>${u.criterion}</code></th>
<td>${fixed(UNREADABLE_TEXT, u.why, 'See the code')} <code>${u.why}</code></td>
<td>${u.readers.length === 0 ? 'None' : u.readers.map((reader, i) => html`${i > 0 ? ', ' : ''}<code>${reader}</code>`)}</td>
</tr>`,
    );
    return html`<section id="coverage" aria-labelledby="coverage-h">
<h2 id="coverage-h">What this scan could not evidence</h2>
<p>The highest level this run could have stated for any agent is <strong>${reachable} ${levelName(reachable)}</strong>${reachable === HARNESS_LEVELS[0] ? ', the lowest rung: this run can show that an agent exists and what it holds, and nothing about how it is governed' : ''}.
A criterion nobody answered counts as not met, so no agent is shown above that level, whatever its real state.</p>
<p>The bar is ${readOnlyBar} for an agent that only reads and ${writeBar} for one that can write or reach outside the estate.
${belowEveryBar
        ? html`<strong>This run could not have shown any agent at its bar</strong>, so every judged agent is reported below it. That is a limit of what was read, stated here so it is not mistaken for a failure a source observed.`
        : levelAtLeast(reachable, writeBar)
            ? 'This run could have shown an agent at either bar.'
            : html`This run could have shown a read-only agent at its bar, and <strong>could not have shown an agent that can write at its bar</strong>.`}</p>
${r.inventory === null
        ? registerRead
            ? html`<p>No inventory was supplied; registration is read from the Inflect register.</p>`
            : html`<p class="callout">For this run no inventory was supplied, so no agent can be shown as registered. Supply an inventory that names the agents the estate knows to show who owns each one.</p>`
        : ''}
${rows.length === 0
        ? html`<p>Every criterion had a configured reader.</p>`
        : html`<details class="fold">
<summary>${rows.length} of ${plural(r.ladder.levels.reduce((n, level) => n + r.ladder.criteria[level].length, 0), 'criterion', 'criteria')} had no configured reader. Show which, and what would read each</summary>
<div class="scroll"><table>
<caption>Criteria no configured reader could have reported met</caption>
<thead><tr><th scope="col">Criterion</th><th scope="col">Why</th><th scope="col">Readers that would</th></tr></thead>
<tbody>
${rows}
</tbody>
</table></div>
</details>`}
</section>`;
}

function emptyEstate(r: LocalResults): SafeHtml {
    const finding = r.findings.find((f) => f.code === 'EMPTY_SCAN');
    return html`<section id="summary" aria-labelledby="summary-h">
<h2 id="summary-h">Estate summary</h2>
<div class="callout bad">
<p><strong>This scan found no agents. That is a finding, not a clean result.</strong></p>
<p>${finding === undefined ? 'An empty population is what a scanner reading the wrong place, or nothing, looks like.' : finding.description}</p>
<p>No level is stated for anything, and no agent, shadow agent or credential table follows.</p>
</div>
</section>`;
}

function stat(label: string, value: number, note: string): SafeHtml {
    return html`<div class="stat"><dt>${label}</dt><dd><span class="big">${value}</span> <span class="note">${note}</span></dd></div>`;
}

function summary(r: LocalResults): SafeHtml {
    const e = r.estate;
    const most = Math.max(1, ...HARNESS_LEVELS.map((level) => e.byLevel[level] ?? 0));
    const rows = HARNESS_LEVELS.map((level) => {
        const count = e.byLevel[level] ?? 0;
        const step = Math.round((count / most) * BAR_STEPS);
        return html`<tr>
<th scope="row">${level} ${levelName(level)}</th>
<td class="num">${count}</td>
<td class="barcell"><span class="bar w-${step}"></span></td>
</tr>`;
    });
    return html`<section id="summary" aria-labelledby="summary-h">
<h2 id="summary-h">Estate summary</h2>
<dl class="stats">
${stat('Agents found', e.agentCount, '')}
${stat('Judged', e.judgedCount, 'have a level')}
${stat('Not judged', e.notJudgedCount, e.notJudgedCount === 0 ? '' : 'no level stated')}
${stat('Below their bar', e.shortfallCount, 'of the judged agents')}
${stat('Shadow agents', e.shadowAgents.length, 'not registered')}
${stat('Orphan credentials', e.orphanCredentials.length, 'bound to no agent')}
</dl>
<p>Registration is taken from: ${fixed(ESTATE_REGISTRATION_TEXT, e.registrationBasis, 'Not stated')}.</p>
<div class="scroll"><table class="levels">
<caption>Judged agents per level${e.notJudgedCount > 0 ? html` (${plural(e.notJudgedCount, 'agent', 'agents')} not judged and not counted here)` : ''}</caption>
<thead><tr><th scope="col">Level</th><th scope="col" class="num">Agents</th><th scope="col">Share</th></tr></thead>
<tbody>
${rows}
</tbody>
</table></div>
${e.registrationConflicts.length === 0
        ? ''
        : html`<p class="callout">${plural(e.registrationConflicts.length, 'agent is', 'agents are')} named by both the report and the inventory with different registrations. The report’s link stands.</p>`}
</section>`;
}

function agentLabel(agent: LocalAgentResult): SafeHtml {
    return agent.declared === null
        ? html`<code class="id">${agent.discoveredId}</code>`
        : html`<span class="name">${agent.declared.name}</span> <span class="decl">(name declared by the operator)</span><br><code class="id">${agent.discoveredId}</code>`;
}

function matrixRow(agent: LocalAgentResult, order: readonly HarnessCriterionId[]): SafeHtml {
    const j = agent.judgement;
    const cells = new Map(agent.criteria.map((c) => [c.criterion, c]));
    const under =
        j.state === 'NOT_JUDGED'
            ? html`<ul class="reasons">${j.reasons.map((code) => html`<li>${reasonSentence(code)}. <code>${code}</code></li>`)}</ul>`
            : j.caveats.length === 0
                ? ''
                : html`<ul class="reasons">${j.caveats.map((code) => html`<li>${reasonSentence(code)}. <code>${code}</code></li>`)}</ul>`;
    const level =
        j.state === 'JUDGED'
            ? html`<td class="lvl"><strong>${j.level}</strong> ${levelName(j.level)}${j.level === j.observedLevel ? '' : html`<br><span class="decl">${j.observedLevel} on observation alone; the rest is declared by the operator</span>`}</td>
<td class="lvl">${j.bar} <span class="tag ${j.shortfall ? 'bad' : 'ok'}">${j.shortfall ? 'Below bar' : 'At bar'}</span></td>`
            : html`<td class="lvl"><span class="tag warn">Not judged</span></td>
<td class="lvl"><span class="tag warn">Not judged</span></td>`;
    return html`<tr>
<th scope="row" class="agent">${agentLabel(agent)}${under}</th>
<td>${fixed(REGISTRATION_TEXT, agent.registration.basis, 'Not stated')}</td>
<td>${fixed(REACH_TEXT, agent.reach, 'Unknown')}</td>
${level}
${order.map((criterion) => {
        const cell = cells.get(criterion);
        const style = cell === undefined ? CELL_UNANSWERED : cellStyle(cell);
        return html`<td class="cell ${style.cls}" title="${criterion}: ${style.text}"><span aria-hidden="true">${style.code}</span><span class="vh">${style.text}</span></td>`;
    })}
</tr>`;
}

function matrix(r: LocalResults): SafeHtml {
    const levels = r.ladder.levels.filter((level) => r.ladder.criteria[level].length > 0);
    const order = levels.flatMap((level) => r.ladder.criteria[level]);
    const shown = matrixSelection(r.agents);
    return html`<section id="matrix" aria-labelledby="matrix-h">
<h2 id="matrix-h">Agents and criteria</h2>
${r.agents.length > MATRIX_MAX_AGENTS
        ? html`<p class="callout">This table shows the first ${MATRIX_MAX_AGENTS} of ${r.agents.length} agents: those not judged, then those below their bar, then the lowest levels, in order of their id within each. The counts above are over all ${r.agents.length}. The full list is in <code>${RUN_FILE_NAMES.agents}</code>.</p>`
        : ''}
<p>An agent reaches a level only when every criterion on it and below it is evidenced. A level is stated only for an agent every relevant source was read in full for.</p>
<ul class="legend" aria-label="What each cell code means">
${LEGEND.map((s) => html`<li><span class="cell ${s.cls}" aria-hidden="true">${s.code}</span> ${s.text}</li>`)}
</ul>
<div class="scroll matrix" tabindex="0" role="region" aria-labelledby="matrix-h">
<table>
<caption>One row per agent, one column per criterion, grouped by level</caption>
<thead>
<tr>
<th scope="col" rowspan="2" class="agent">Agent</th>
<th scope="col" rowspan="2">Registration</th>
<th scope="col" rowspan="2">Reach</th>
<th scope="col" rowspan="2">Level</th>
<th scope="col" rowspan="2">Bar</th>
${levels.map((level) => html`<th scope="colgroup" colspan="${r.ladder.criteria[level].length}" class="group">${level} ${levelName(level)}</th>`)}
</tr>
<tr>
${order.map((criterion) => html`<th scope="col" class="crit"><span title="${criterion}">${criterionWords(criterion)}</span></th>`)}
</tr>
</thead>
<tbody>
${shown.map((agent) => matrixRow(agent, order))}
</tbody>
</table>
</div>
</section>`;
}

function shadowAgents(r: LocalResults): SafeHtml {
    const byId = new Map(r.agents.map((a) => [a.discoveredId, a]));
    const shadow = capped(r.estate.shadowAgents, SECTION_MAX_ROWS, 'shadow agents', 'in the order the results list them', RUN_FILE_NAMES.agents);
    const body =
        r.estate.registrationBasis === 'NONE'
            ? html`<p>With no inventory and no register read, every agent this scan found is unregistered, so the list would repeat the table above. Supply an inventory to see which agents the estate does not know.</p>`
            : r.estate.shadowAgents.length === 0
                ? r.scan.complete
                    ? html`<p>None: every agent this scan found is registered.</p>`
                    : html`<p>None raised. The scan is incomplete, so this is not a statement that none exist.</p>`
                : html`${shadow.notice}<div class="scroll"><table>
<caption>Agents found by this scan that are not registered</caption>
<thead><tr><th scope="col">Agent</th><th scope="col">Found through</th><th scope="col">Reach</th></tr></thead>
<tbody>
${shadow.shown.map((id) => {
                    const agent = byId.get(id);
                    return html`<tr><th scope="row"><code class="id">${id}</code></th><td>${(agent?.discoveredVia ?? []).map((kind, i) => html`${i > 0 ? ', ' : ''}<code>${kind}</code>`)}</td><td>${fixed(REACH_TEXT, agent?.reach ?? 'UNKNOWN', 'Unknown')}</td></tr>`;
                })}
</tbody>
</table></div>`;
    return html`<section id="shadow" aria-labelledby="shadow-h">
<h2 id="shadow-h">Shadow agents</h2>
${body}
</section>`;
}

function orphans(r: LocalResults): SafeHtml {
    const e = r.estate;
    const concluded = capped(e.orphanCredentials, SECTION_MAX_ROWS, 'orphan credentials', 'in the order the results list them', RUN_FILE_NAMES.results);
    const unbound = capped(e.unboundNotConcluded, SECTION_MAX_ROWS, 'credentials seen unbound', 'in the order the results list them', RUN_FILE_NAMES.results);
    return html`<section id="orphans" aria-labelledby="orphans-h">
<h2 id="orphans-h">Orphan credentials</h2>
${e.orphanCredentials.length === 0
        ? html`<p>None concluded.${e.unboundNotConcluded.length > 0 || !r.scan.complete ? ' That is not a statement that none exist: see below and the completeness table.' : ''}</p>`
        : html`${concluded.notice}<div class="scroll"><table>
<caption>Credentials a source, read in full, saw bound to no agent</caption>
<thead><tr><th scope="col">Credential reference</th><th scope="col">Source</th></tr></thead>
<tbody>
${concluded.shown.map((c) => html`<tr><th scope="row"><code class="id">${c.ref}</code></th><td><code>${c.sourceKind}</code></td></tr>`)}
</tbody>
</table></div>`}
${e.unboundNotConcluded.length === 0
        ? ''
        : html`<h3>Seen unbound, not concluded</h3>
<p>These were seen bound to no agent, and this scan could not conclude that none uses them.</p>
${unbound.notice}<div class="scroll"><table>
<caption>Credentials seen unbound that could not be concluded as orphans</caption>
<thead><tr><th scope="col">Credential reference</th><th scope="col">Source</th><th scope="col">Why not concluded</th></tr></thead>
<tbody>
${unbound.shown.map((c) => html`<tr><th scope="row"><code class="id">${c.ref}</code></th><td><code>${c.sourceKind}</code></td><td>${fixed(UNBOUND_TEXT, c.why, 'See the code')} <code>${c.why}</code></td></tr>`)}
</tbody>
</table></div>`}
</section>`;
}

function findings(r: LocalResults): SafeHtml {
    const ordered = r.findings
        .map((f, i): [LocalFinding, number] => [f, i])
        .sort(([a, i], [b, k]) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) || i - k)
        .map(([f]) => f);
    const listed = capped(ordered, FINDINGS_MAX_ROWS, 'findings', 'most severe first', RUN_FILE_NAMES.findings);
    return html`<section id="findings" aria-labelledby="findings-h">
<h2 id="findings-h">Findings</h2>
${ordered.length === 0
        ? html`<p>No finding was raised.${r.scan.complete ? '' : ' The scan is incomplete, so this is not a clean result.'}</p>`
        : html`${listed.notice}<div class="scroll"><table class="findings">
<caption>${plural(ordered.length, 'finding', 'findings')}, most severe first</caption>
<thead><tr><th scope="col">Severity</th><th scope="col">Code</th><th scope="col">Subject</th><th scope="col">Finding</th></tr></thead>
<tbody>
${listed.shown.map(
            (f) => html`<tr>
<td><span class="tag ${fixed(SEVERITY_CLASS, f.severity, 'sev-low')}">${f.severity}</span></td>
<td><code>${f.code}</code></td>
<td>${f.discoveredId === null ? 'The scan' : html`<code class="id">${f.discoveredId}</code>`}</td>
<td><details><summary>${f.title}</summary><p>${f.description}</p><p class="ref">Reference <code class="id">${f.sourceRef}</code></p></details></td>
</tr>`,
        )}
</tbody>
</table></div>`}
</section>`;
}

function inventory(r: LocalResults): SafeHtml {
    const inv = r.inventory;
    if (inv === null) return html``;
    const unmatched = capped(inv.unmatched, SECTION_MAX_ROWS, 'declared agents this scan did not find', 'in the order the results list them', RUN_FILE_NAMES.results);
    return html`<section id="inventory" aria-labelledby="inventory-h">
<h2 id="inventory-h">Inventory</h2>
<p>Everything in the inventory is <strong>declared by the operator</strong>. scanent did not observe it, and it is never sent anywhere.</p>
<dl class="meta">
<div><dt>Rows</dt><dd>${inv.rows}</dd></div>
<div><dt>Matched an agent this scan found</dt><dd>${inv.matched}</dd></div>
<div><dt>Declared, not found by this scan</dt><dd>${inv.unmatched.length}</dd></div>
</dl>
${inv.unmatched.length === 0
        ? ''
        : html`<p>Declared by the operator and not found by this scan. This is not a statement that they are gone: the scan may not read where they live.</p>
${unmatched.notice}<ul class="ids">${unmatched.shown.map((id) => html`<li><code class="id">${id}</code></li>`)}</ul>`}
</section>`;
}

function provenance(r: LocalResults): SafeHtml {
    const row = (label: string, value: HtmlValue): SafeHtml => html`<div><dt>${label}</dt><dd>${value}</dd></div>`;
    return html`<section id="provenance" aria-labelledby="provenance-h">
<h2 id="provenance-h">Provenance</h2>
<dl class="meta wide">
${row('Scanner', html`<code>${r.scan.scanner.agentId}</code>, version ${r.scan.scanner.version}`)}
${row('Scanner manifest', html`<code class="id">${r.scan.scanner.manifestHash}</code>`)}
${row('Ladder version', html`<code class="id">${r.ladder.version}</code>`)}
${row('Report contract', html`<code>${r.scan.contract}</code>`)}
${row('Signed report SHA-256', html`<code class="id">${r.report.sha256}</code>`)}
${row('Signer key fingerprint', html`<code class="id">${r.report.signerKeyFingerprint}</code>`)}
${row('Signer', r.report.signerPinned ? 'Pinned: verified against a key supplied apart from the report' : 'Not pinned: verified against the key the report itself carries, which shows integrity and not origin')}
${row('Register claims', r.scan.registerClaimsVerified ? 'Read by this run' : 'Taken from the report as stated; not verified by this run')}
${row('Inventory SHA-256', r.inventory === null ? 'No inventory was supplied' : html`<code class="id">${r.inventory.sha256}</code> (${r.inventory.format})`)}
${row('Files of this run', Object.values(RUN_FILE_NAMES).map((name, i) => html`${i > 0 ? ', ' : ''}<code>${name}</code>`))}
</dl>
<p>The signed report is the record; this page and the other files are derived from it and from the inventory. The same inputs give the same files.</p>
</section>`;
}

// ── Style: one block, no url(), no import, no font ──

const BAR_WIDTHS = Array.from({ length: BAR_STEPS + 1 }, (_, i) => `.w-${i}{width:${(i * 100) / BAR_STEPS}%}`).join('');

const STYLE_ELEMENT: SafeHtml = html`<style>
:root{color-scheme:light dark;--bg:#ffffff;--panel:#f5f7f9;--text:#1a1f24;--muted:#4a5560;--line:#c9d1d9;--accent:#0b5cad;
--ok:#1a6e3a;--ok-bg:#e6f4ea;--bad:#a4262c;--bad-bg:#fde7e9;--warn:#7a4b00;--warn-bg:#fff4d6;--decl:#5b3fa0;--decl-bg:#efe9fb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1419;--panel:#171d24;--text:#e6edf3;--muted:#a9b4be;--line:#3a444f;--accent:#79b8ff;
--ok:#7ee2a0;--ok-bg:#12301f;--bad:#ffa3a3;--bad-bg:#3a1518;--warn:#ffd479;--warn-bg:#33270a;--decl:#c9b6ff;--decl-bg:#261d40}}
*{box-sizing:border-box}
html{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.5;background:var(--bg);color:var(--text)}
body{margin:0 auto;max-width:78rem;padding:1.5rem 1.25rem 4rem}
h1{font-size:1.9rem;line-height:1.2;margin:.1rem 0 1rem}
h2{font-size:1.3rem;margin:0 0 .6rem;padding-top:.4rem}
h3{font-size:1.05rem;margin:1.4rem 0 .4rem}
p{margin:.5rem 0;max-width:62rem}
section{margin-top:2.25rem;border-top:1px solid var(--line);padding-top:1rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em;overflow-wrap:anywhere}
a{color:var(--accent)}
.skip{position:absolute;left:-999rem;top:0;background:var(--bg);color:var(--accent);padding:.5rem .75rem;border:2px solid var(--accent)}
.skip:focus{left:.5rem;top:.5rem;z-index:10}
.brand{margin:0;color:var(--muted);font-size:.9rem;letter-spacing:.02em}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:.5rem 1.5rem;margin:.5rem 0 1rem}
.meta.wide{grid-template-columns:1fr}
.meta dt,.stats dt{color:var(--muted);font-size:.82rem}
.meta dd,.stats dd{margin:0}
.status{padding:.6rem .8rem;border-left:.3rem solid;border-radius:.2rem;max-width:none}
.status.ok{background:var(--ok-bg);border-color:var(--ok)}
.status.bad{background:var(--bad-bg);border-color:var(--bad)}
.callout{background:var(--panel);border-left:.3rem solid var(--muted);padding:.6rem .8rem;border-radius:.2rem}
.callout.bad{background:var(--bad-bg);border-color:var(--bad)}
div.callout p{margin:.3rem 0}
nav.contents{margin:1rem 0 0}
nav.contents ul{list-style:none;display:flex;flex-wrap:wrap;gap:.3rem 1.1rem;padding:0;margin:0;font-size:.92rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(10.5rem,1fr));gap:.75rem;margin:.75rem 0 1rem}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:.4rem;padding:.6rem .8rem}
.big{font-size:1.7rem;font-weight:650;line-height:1.1}
.note{color:var(--muted);font-size:.82rem}
.scroll{overflow-x:auto;max-width:100%}
table{border-collapse:collapse;width:100%;font-size:.92rem;margin:.5rem 0}
caption{text-align:left;color:var(--muted);font-size:.85rem;padding:.2rem 0 .4rem}
th,td{border-bottom:1px solid var(--line);padding:.4rem .6rem;text-align:left;vertical-align:top}
thead th{background:var(--panel);border-bottom:2px solid var(--line);font-weight:600}
tbody th{font-weight:500}
.num{text-align:right;font-variant-numeric:tabular-nums}
.tag{display:inline-block;padding:0 .45rem;border-radius:.8rem;font-size:.8rem;font-weight:600;border:1px solid;white-space:nowrap}
.tag.ok{color:var(--ok);background:var(--ok-bg)}
.tag.bad,.tag.sev-high,.tag.sev-critical{color:var(--bad);background:var(--bad-bg)}
.tag.warn,.tag.sev-medium{color:var(--warn);background:var(--warn-bg)}
.tag.sev-low{color:var(--muted);background:var(--panel)}
.tag.sev-critical{border-width:2px}
.decl{color:var(--decl);font-size:.8rem}
.name{font-weight:600}
.reasons{margin:.3rem 0 0;padding-left:1.1rem;color:var(--muted);font-size:.8rem;font-weight:400}
.levels{max-width:40rem}
.barcell{width:50%}
.bar{display:block;height:.8rem;background:var(--accent);border-radius:.15rem;min-width:1px}
${BAR_WIDTHS}
.legend{list-style:none;display:grid;grid-template-columns:repeat(auto-fit,minmax(21rem,1fr));gap:.3rem 1.25rem;padding:0;margin:.75rem 0;font-size:.86rem}
.cell{text-align:center;font-weight:700;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.legend .cell{display:inline-block;width:1.6rem;border:1px solid var(--line);border-radius:.2rem;margin-right:.3rem}
.c-e{color:var(--ok);background:var(--ok-bg)}
.c-d{color:var(--decl);background:var(--decl-bg)}
.c-m{color:var(--warn);background:var(--warn-bg)}
.c-n{color:var(--bad);background:var(--bad-bg)}
.c-u{color:var(--muted)}
.c-x{color:var(--muted);background:var(--panel)}
.matrix{border:1px solid var(--line);border-radius:.3rem}
.matrix table{margin:0;width:auto;min-width:100%}
.matrix th.agent{position:sticky;left:0;background:var(--bg);min-width:15rem;max-width:24rem;border-right:2px solid var(--line);z-index:1}
.matrix thead th.agent{background:var(--panel);z-index:2}
.matrix td,.matrix th{border-right:1px solid var(--line)}
.matrix td.cell{padding:.4rem .3rem;min-width:1.9rem;vertical-align:middle}
.matrix td.lvl{white-space:nowrap}
.matrix td.lvl .decl{white-space:normal;display:inline-block;max-width:14rem}
th.group{text-align:center;white-space:nowrap}
th.crit{vertical-align:bottom;padding:.4rem .2rem;font-weight:500;font-size:.78rem}
th.crit span{writing-mode:vertical-rl;transform:rotate(180deg);white-space:nowrap;max-height:11rem}
.id{font-size:.82em}
.ids{columns:2 22rem;padding-left:1.1rem}
details summary{cursor:pointer}
.fold{margin:.75rem 0}
.fold summary{font-weight:600}
.ref{color:var(--muted);font-size:.82rem}
.findings td:last-child{min-width:18rem}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap}
.print-footer{display:none}
footer.end{margin-top:2.5rem;color:var(--muted);font-size:.82rem;border-top:1px solid var(--line);padding-top:.75rem}
@media print{
:root{--bg:#ffffff;--panel:#ffffff;--text:#000000;--muted:#333333;--line:#888888;--accent:#000000;--ok:#000000;--ok-bg:#ffffff;--bad:#000000;--bad-bg:#ffffff;--warn:#000000;--warn-bg:#ffffff;--decl:#000000;--decl-bg:#ffffff}
html{font-size:10.5pt}
body{max-width:none;padding:0 0 2.2em}
.skip,nav.contents{display:none}
section{break-before:auto;break-inside:auto}
#matrix{break-before:page}
h2,h3,caption{break-after:avoid}
tr{break-inside:avoid}
thead{display:table-header-group}
.scroll{overflow:visible}
.matrix{border:0}
.matrix table{font-size:7pt}
.matrix th.agent{position:static;min-width:0}
details:not([open])>*:not(summary){display:block}
details::details-content{content-visibility:visible;display:block}
.bar{border:1px solid #000;background:#000;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.print-footer{display:block;position:fixed;bottom:0;left:0;right:0;font-size:8pt;color:#000;border-top:1px solid #888;padding-top:.2em;background:#fff}
}
</style>`;

/** The page. A function of the results alone. */
export function renderSummaryHtml(results: LocalResults): string {
    const r = results;
    const title = r.scan.estate === null ? `scanent results: ${r.scan.id}` : `scanent results: ${r.scan.estate}, ${r.scan.id}`;
    const sections: readonly (readonly [string, string, SafeHtml])[] = r.estate.empty
        ? [
              ['completeness', 'Completeness', completeness(r)],
              ['coverage', 'Not evidenced', coverage(r)],
              ['summary', 'Summary', emptyEstate(r)],
              ['findings', 'Findings', findings(r)],
              ...(r.inventory === null ? [] : [['inventory', 'Inventory', inventory(r)] as const]),
              ['provenance', 'Provenance', provenance(r)],
          ]
        : [
              ['completeness', 'Completeness', completeness(r)],
              ['coverage', 'Not evidenced', coverage(r)],
              ['summary', 'Summary', summary(r)],
              ['matrix', 'Agents and criteria', matrix(r)],
              ['shadow', 'Shadow agents', shadowAgents(r)],
              ['orphans', 'Orphan credentials', orphans(r)],
              ['findings', 'Findings', findings(r)],
              ...(r.inventory === null ? [] : [['inventory', 'Inventory', inventory(r)] as const]),
              ['provenance', 'Provenance', provenance(r)],
          ];
    // The style block is this module's own constant text, built as the
    // literal part of a template, so nothing scanned can enter it.
    const page = html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
${STYLE_ELEMENT}
</head>
<body>
<a class="skip" href="#main">Skip to the results</a>
${header(r)}
<nav class="contents" aria-label="Contents">
<ul>
${sections.map(([id, label]) => html`<li><a href="#${id}">${label}</a></li>`)}
</ul>
</nav>
<main id="main">
${sections.map(([, , body]) => body)}
</main>
<footer class="end">Scan <code>${r.scan.id}</code>, as of ${r.scan.asOf} UTC. Ladder <code>${r.ladder.version}</code>.</footer>
<p class="print-footer">Scan ${r.scan.id}, as of ${r.scan.asOf} UTC</p>
</body>
</html>
`;
    return htmlText(page);
}
