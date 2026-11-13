/**
 * `summary.html` — the results as one page somebody opens.
 *
 * ONE FILE, NOTHING LOADED. The page carries its data as one JSON block and
 * its interactive view as one inline script, and its look as one style block.
 * No link, no image, no frame, no import, no web font, no inline event handler
 * and no request of any kind. A Content-Security-Policy meta allows exactly
 * that script and that style, by their SHA-256 hashes, and nothing else:
 * nothing may be fetched, connected to, framed or submitted.
 *
 * READABLE WITH NO SCRIPT. Every section below is rendered here, on the
 * server side of the file, and is the whole page when the script does not
 * run. The interactive view (`page-script.ts`) is built into an element that
 * is hidden until it is complete; it then hides the static sections it
 * repeats (`dup`), and printing shows the static page again.
 *
 * EVERY SCANNED STRING IS ESCAPED. The static page is built with the `html`
 * template of `escape.ts`, which escapes whatever is interpolated, and the
 * JSON block is written by `scriptJson`, which nothing in it can end. Scanned
 * data never becomes a tag name, an attribute name, a class, a URL or a link:
 * classes and state codes come from the fixed tables in `words.ts`, keyed by
 * enum values, and a value the tables do not know falls back to a fixed
 * neutral entry. The one address the view may link to is an evidence
 * reference that is an absolute https URL.
 *
 * WHAT COULD NOT BE READ COMES FIRST. Completeness per source is the first
 * section after the header, and what this run could not have evidenced is the
 * second, so nobody reads a level before they have read what it rests on. An
 * agent that could not be judged shows the words "Not judged" and its reasons,
 * and no level anywhere. An empty scan is shown as a finding, never as a clean
 * result.
 *
 * ONE TABLE MODEL. Every row the page shows, static or interactive, is a row
 * of the contract's shared table model (`harnessMatrixOfResults`), so where an
 * agent stands against its bar is the model's `heldToBar` and
 * `countsAsShortfall`: an unregistered automated identity is held to none.
 *
 * NO CLOCK AND NO PATH. The page holds no generation time and no absolute
 * path, so the same results (and the same previous run) give the same bytes.
 */
import { HARNESS_CONTRACT_V2, HARNESS_CONTRACT_V3 } from '@rodnapamet/scanent-contract/harness-contract-rules';
import { harnessBarFor } from '@rodnapamet/scanent-contract/harness-findings';
import { HARNESS_LEVELS, levelAtLeast, type HarnessCriterionId } from '@rodnapamet/scanent-contract/harness-ladder';
import {
    compareHarnessMatrixRows,
    harnessMatrixCellState,
    type HarnessMatrixModel,
    type HarnessMatrixRow,
    type HarnessMatrixRowRank,
} from '@rodnapamet/scanent-contract/harness-matrix-model';

import type { LocalAgentResult, LocalCriterionCell, LocalFinding, LocalResults } from '../results/types';
import { html, htmlText, scriptElement, type HtmlValue, type SafeHtml } from './escape';
import { RUN_FILE_NAMES } from './files';
import { harnessMatrixOfResults } from './matrix-of-results';
import { findingsBySeverity, scriptJson, summaryPageData, type DriftRecord, type SummaryContext } from './page-data';
import { PAGE_SCRIPT } from './page-script';
import { cspHashSource } from './sha256';
import {
    CAVEATS,
    CELL_STYLE,
    ESTATE_REGISTRATION_TEXT,
    fixed,
    LEGEND,
    levelName,
    MODEL_SIGN_TEXT,
    plural,
    criterionWords,
    REACH_TEXT,
    reasonSentence,
    REGISTRATION_TEXT,
    SEVERITY_CLASS,
    standingOf,
    STANDING_TEXT,
    SUBJECT_WITHOUT_AGENT,
    UNBOUND_TEXT,
    UNREADABLE_TEXT,
    type CellStyle,
} from './words';

export type { PreviousRun, SummaryContext } from './page-data';

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
 * that most need a reader, in the table model's order (`compareHarnessMatrixRows`
 * over the model's own rows): not judged first, then below their bar, then the
 * lowest level; within each, in order of id (the order the results list them in).
 */
function matrixSelection(agents: readonly LocalAgentResult[], rows: ReadonlyMap<string, HarnessMatrixRowRank>): readonly LocalAgentResult[] {
    if (agents.length <= MATRIX_MAX_AGENTS) return agents;
    const notJudged = (agent: LocalAgentResult): HarnessMatrixRowRank => ({ discoveredId: agent.discoveredId, level: null, barStatus: 'NOT_JUDGED' });
    return agents
        .map((agent): [LocalAgentResult, HarnessMatrixRowRank] => [agent, rows.get(agent.discoveredId) ?? notJudged(agent)])
        .sort(([, a], [, b]) => compareHarnessMatrixRows(a, b))
        .slice(0, MATRIX_MAX_AGENTS)
        .map(([agent]) => agent);
}

/** Twenty-one fixed widths; a bar's class is picked by its share, never written from data. */
const BAR_STEPS = 20;

/** A cell the results do not hold reads as unanswered. */
const cellStyle = (cell: LocalCriterionCell | undefined): CellStyle => CELL_STYLE[cell === undefined ? 'UNANSWERED' : harnessMatrixCellState(cell)];

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
    const noted = r.sources.filter((s) => s.detail !== undefined || s.notRead !== undefined);
    const notes = noted.map((s) => {
        const listed = s.notRead ?? [];
        const more = (s.notReadTotal ?? listed.length) - listed.length;
        return html`<div class="callout bad">
<p><strong><code>${s.kind}</code> was not read in full</strong>${s.detail === undefined ? '' : html`: ${s.detail}`}.</p>
${listed.length === 0
            ? ''
            : html`<p>What was not read${more > 0 ? html` (the first ${listed.length} of ${listed.length + more} places)` : ''}:</p>
<ul>
${listed.map((place) => html`<li><code>${place.where}</code> <span class="tag bad">${place.reason}</span></li>`)}
</ul>`}
</div>`;
    });
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
${notes}
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
    return html`<section id="summary" class="dup" aria-labelledby="summary-h">
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
    const identities = e.unregisteredIdentities;
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
    return html`<section id="summary" class="dup" aria-labelledby="summary-h">
<h2 id="summary-h">Estate summary</h2>
<dl class="stats">
${stat('Agents found', e.agentCount, identities === undefined || identities.length === 0 ? '' : 'agents and automated identities')}
${stat('Judged', e.judgedCount, 'have a level')}
${stat('Not judged', e.notJudgedCount, e.notJudgedCount === 0 ? '' : 'no level stated')}
${stat('Below their bar', e.shortfallCount, identities === undefined || identities.length === 0 ? 'of the judged agents' : 'of the judged agents held to a bar')}
${stat('Shadow agents', e.shadowAgents.length, identities === undefined ? 'not registered' : 'not registered, with a sign of a model')}
${identities === undefined ? '' : stat('Unregistered identities', identities.length, 'no sign of a model')}
${e.payingAgents === undefined ? '' : stat('Can pay', e.payingAgents.length, 'code calls a payment client')}
${stat('Orphan credentials', e.orphanCredentials.length, 'bound to no agent')}
</dl>
<p>Registration is taken from: ${fixed(ESTATE_REGISTRATION_TEXT, e.registrationBasis, 'Not stated')}.</p>
<div class="scroll"><table class="levels">
<caption>Judged agents per level${e.notJudgedCount > 0 ? html` (${plural(e.notJudgedCount, 'agent', 'agents')} not judged and not counted here)` : ''}${identities === undefined || identities.length === 0 ? '' : html`. ${plural(identities.length, 'unregistered identity is', 'unregistered identities are')} counted at the level observed, and held to no bar`}</caption>
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

/** The bar cell: the bar, and where the model says the agent stands against it. */
function barTag(row: HarnessMatrixRow | undefined): SafeHtml {
    const standing = row === undefined ? 'NOT_JUDGED' : standingOf(row);
    if (standing === 'NO_BAR') return html`<span class="tag plain">${STANDING_TEXT.NO_BAR}</span>`;
    return html`<span class="tag ${standing === 'BELOW_BAR' ? 'bad' : 'ok'}">${STANDING_TEXT[standing]}</span>`;
}

function matrixRow(agent: LocalAgentResult, order: readonly HarnessCriterionId[], row: HarnessMatrixRow | undefined): SafeHtml {
    const j = agent.judgement;
    const pays = (agent.paymentCapabilities ?? []).length > 0 ? html`<br><span class="tag warn">Code calls a payment client</span>` : '';
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
<td class="lvl">${j.bar} ${barTag(row)}</td>`
            : html`<td class="lvl"><span class="tag warn">Not judged</span></td>
<td class="lvl"><span class="tag warn">Not judged</span></td>`;
    return html`<tr>
<th scope="row" class="agent">${agentLabel(agent)}${pays}${under}</th>
<td>${fixed(REGISTRATION_TEXT, agent.registration.basis, 'Not stated')}</td>
<td>${fixed(REACH_TEXT, agent.reach, 'Unknown')}</td>
${level}
${order.map((criterion) => {
        const style = cellStyle(cells.get(criterion));
        return html`<td class="cell ${style.cls}" title="${criterion}: ${style.text}"><span aria-hidden="true">${style.code}</span><span class="vh">${style.text}</span></td>`;
    })}
</tr>`;
}

function matrix(r: LocalResults, model: HarnessMatrixModel): SafeHtml {
    const rows = new Map(model.rows.map((row) => [row.discoveredId, row]));
    const levels = r.ladder.levels.filter((level) => r.ladder.criteria[level].length > 0);
    const order = levels.flatMap((level) => r.ladder.criteria[level]);
    const shown = matrixSelection(r.agents, rows);
    return html`<section id="matrix" class="dup" aria-labelledby="matrix-h">
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
${shown.map((agent) => matrixRow(agent, order, rows.get(agent.discoveredId)))}
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
                    ? (r.estate.unregisteredIdentities ?? []).length === 0
                        ? html`<p>None: every agent this scan found is registered.</p>`
                        : html`<p>None: every principal this scan found that shows a sign of a model is registered. The unregistered identities that show none are listed in the next section.</p>`
                    : html`<p>None raised. The scan is incomplete, so this is not a statement that none exist.</p>`
                : html`${shadow.notice}<div class="scroll"><table>
<caption>${r.estate.unregisteredIdentities === undefined ? 'Agents found by this scan that are not registered' : 'Not registered, and showing a sign of a model'}</caption>
<thead><tr><th scope="col">Agent</th><th scope="col">Found through</th><th scope="col">Reach</th></tr></thead>
<tbody>
${shadow.shown.map((id) => {
                    const agent = byId.get(id);
                    return html`<tr><th scope="row"><code class="id">${id}</code></th><td>${(agent?.discoveredVia ?? []).map((kind, i) => html`${i > 0 ? ', ' : ''}<code>${kind}</code>`)}</td><td>${fixed(REACH_TEXT, agent?.reach ?? 'UNKNOWN', 'Unknown')}</td></tr>`;
                })}
</tbody>
</table></div>`;
    return html`<section id="shadow" class="dup" aria-labelledby="shadow-h">
<h2 id="shadow-h">Shadow agents</h2>
${body}
</section>`;
}


/**
 * The principals nothing names and nothing shows to run a model. They are not
 * called agents here and are held to no bar, and they are still listed: an
 * identity nobody has classified does not leave the page.
 */
function unregisteredIdentities(r: LocalResults): SafeHtml {
    const all = r.estate.unregisteredIdentities ?? [];
    const byId = new Map(r.agents.map((a) => [a.discoveredId, a]));
    const listed = capped(all, SECTION_MAX_ROWS, 'unregistered identities', 'in the order the results list them', RUN_FILE_NAMES.agents);
    const meaning = html`<p>An unregistered automated identity is a principal that no register or inventory names, and that shows no sign of a model: it was not ${MODEL_SIGN_TEXT.FOUND_IN_CODE.slice('found '.length)}, ${MODEL_SIGN_TEXT.FOUND_IN_RUNTIME.slice('found '.length)} or ${MODEL_SIGN_TEXT.FOUND_ON_MCP_SERVER.slice('found '.length)}, and its report lists no tool and no model endpoint. A build workflow that holds a key, or a service account, looks like this.</p>
<p><strong>The scan cannot show that one of these runs no model.</strong> Each is a finding of medium severity, and none is held to the agent bar. If one is an agent, register it or add it to the inventory, and it is then scored as one. If it is not, it still needs an owner on record.</p>`;
    return html`<section id="identities" class="dup" aria-labelledby="identities-h">
<h2 id="identities-h">Unregistered identities</h2>
${meaning}
${all.length === 0
        ? r.scan.complete
            ? html`<p>None.</p>`
            : html`<p>None raised. The scan is incomplete, so this is not a statement that none exist.</p>`
        : html`${listed.notice}<div class="scroll"><table>
<caption>Not registered, and showing no sign of a model</caption>
<thead><tr><th scope="col">Identity</th><th scope="col">Found through</th><th scope="col" class="num">Credentials</th></tr></thead>
<tbody>
${listed.shown.map((id) => {
            const agent = byId.get(id);
            return html`<tr><th scope="row"><code class="id">${id}</code></th><td>${(agent?.discoveredVia ?? []).map((kind, i) => html`${i > 0 ? ', ' : ''}<code>${kind}</code>`)}</td><td class="num">${agent?.counts.credentials ?? 0}</td></tr>`;
        })}
</tbody>
</table></div>`}
</section>`;
}

/**
 * Where agents' code calls a payment client (`/4`). Three states per agent,
 * never collapsed: seen calling one, read and none seen, and not reported.
 * "None seen" is what a read of the agent's own file saw: a payment client
 * wrapped in another module, or loaded by a name the reader cannot follow, is
 * out of its sight, so it is never "cannot pay".
 */
function payments(r: LocalResults): SafeHtml {
    const paying = r.estate.payingAgents ?? [];
    const byId = new Map(r.agents.map((a) => [a.discoveredId, a]));
    const read = r.agents.filter((a) => a.paymentCapabilities !== undefined && a.paymentCapabilities !== null).length;
    const code = r.sources.find((s) => s.kind === 'code');
    const spending = new Map<string, LocalFinding>();
    for (const f of r.findings) if (f.code === 'SPENDING_AGENT_UNDECLARED' && f.discoveredId !== null) spending.set(f.discoveredId, f);
    const listed = capped(paying, SECTION_MAX_ROWS, 'agents whose code calls a payment client', 'in the order the results list them', RUN_FILE_NAMES.agents);
    const meaning = html`<p>An agent whose code calls a payment client can pay for something on its own. scanent reads this from code: the payer side of the x402 protocol, in an agent's own file. It reports where the call is, never an amount, a wallet or a key. It does not read any spending limit, so it cannot say whether one is in place.</p>
<p>${plural(read, 'agent was', 'agents were')} read for this, out of ${r.agents.length}. For the others the report says nothing about payment.</p>`;
    const none =
        r.scan.contract === HARNESS_CONTRACT_V2 || r.scan.contract === HARNESS_CONTRACT_V3
            ? html`<p>Not reported: this report's contract, <code>${r.scan.contract}</code>, carries no payment facts.</p>`
            : code === undefined
                ? html`<p>None seen. This scan did not read code, so this is not a statement that no agent can pay.</p>`
                : code.status !== 'COMPLETE'
                    ? html`<p>None seen. The code was not read in full, so this is not a statement that no agent can pay.</p>`
                    : html`<p>None seen in the code this scan read. That is not a statement that no agent can pay: a payment client wrapped in another module is out of the reader's sight.</p>`;
    return html`<section id="payments" aria-labelledby="payments-h">
<h2 id="payments-h">Payment capabilities</h2>
${meaning}
${paying.length === 0
        ? none
        : html`${listed.notice}<div class="scroll"><table>
<caption>Agents whose code calls a payment client</caption>
<thead><tr><th scope="col">Agent</th><th scope="col">Registration</th><th scope="col">Where the code calls it</th><th scope="col">Spending authority</th></tr></thead>
<tbody>
${listed.shown.map((id) => {
            const agent = byId.get(id);
            const sites = agent?.paymentCapabilities ?? [];
            const registered = agent !== undefined && agent.registration.basis !== 'NONE';
            const finding = spending.get(id);
            return html`<tr><th scope="row"><code class="id">${id}</code></th><td>${fixed(REGISTRATION_TEXT, agent?.registration.basis ?? 'NONE', 'Not stated')}</td><td><ul class="reasons">${sites.map((s) => html`<li><code>${s.library}</code> at <code class="id">${s.at}</code></li>`)}</ul></td><td>${registered
                ? finding === undefined
                    ? 'See the findings'
                    : html`<span class="tag bad">None seen by this run</span>`
                : 'Register it first: it is a shadow agent'}</td></tr>`;
        })}
</tbody>
</table></div>`}
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
    const ordered = findingsBySeverity(r.findings);
    const listed = capped(ordered, FINDINGS_MAX_ROWS, 'findings', 'most severe first', RUN_FILE_NAMES.findings);
    return html`<section id="findings" class="dup" aria-labelledby="findings-h">
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
<td>${f.discoveredId === null ? fixed(SUBJECT_WITHOUT_AGENT, f.code, 'The scan') : html`<code class="id">${f.discoveredId}</code>`}</td>
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

/**
 * What changed since the run the output directory named as the latest, as the
 * interactive view shows it, for a reader with no script and for print. Each
 * list says how many it holds and shows at most `DRIFT_MAX_ROWS`. Whatever the
 * comparison could not conclude is never worded as a change.
 */
function drift(d: DriftRecord): SafeHtml {
    const list = <T>(title: string, part: { readonly total: number; readonly rows: readonly T[] }, line: (x: T) => SafeHtml, none: string): SafeHtml =>
        html`<h3>${title} (${part.total})</h3>
${part.total === 0
            ? html`<p>${none}</p>`
            : html`<ul>${part.rows.map((x) => html`<li>${line(x)}</li>`)}</ul>${part.total > part.rows.length ? html`<p class="note">The first ${part.rows.length} of ${part.total}.</p>` : ''}`}`;
    const body =
        d.kind === 'FIRST'
            ? html`<p>This output directory held no earlier run, so there is nothing to compare with.</p>`
            : d.kind === 'NOT_COMPARED'
                ? html`<p class="callout">Not compared with ${d.scanId === null ? 'the previous run' : html`<code class="id">${d.scanId}</code>`}: ${d.text}.</p>`
                : html`<p>Compared with <code class="id">${d.old.scanId}</code>, as of ${d.old.asOf} UTC (${d.old.complete ? 'complete' : 'incomplete'}, ${plural(d.old.agentCount, 'agent', 'agents')}). <strong>${d.outcomeText}</strong></p>
<p>${plural(d.differences, 'difference', 'differences')}; ${plural(d.notConcludedCount, 'comparison', 'comparisons')} not concluded. The full comparison is <code>scanent diff</code> on the two results files.</p>
${d.warnings.length === 0 ? '' : html`<ul class="callout">${d.warnings.map((w) => html`<li><code>${w.code}</code>: ${w.text}.</li>`)}</ul>`}
${list('Levels', d.levels, (l) => html`<code class="id">${l.id}</code>: ${l.text}${l.from !== null && l.to !== null ? `, ${l.from} to ${l.to}` : ''}`, 'No level changed where both runs judged the agent.')}
${list('New agents', d.added, (id) => html`<code class="id">${id}</code>`, 'None.')}
${list('Gone', d.gone, (id) => html`<code class="id">${id}</code> (every source it was found through was read in full)`, 'None concluded gone.')}
${list('Not seen, not concluded', d.notSeen, (x) => html`<code class="id">${x.id}</code>: ${x.why}`, 'None.')}
${list('Completeness', { total: d.sources.length, rows: d.sources }, (x) => html`<code>${x.kind}</code> ${x.text}${x.from !== null || x.to !== null ? ` (${x.from ?? '-'} to ${x.to ?? '-'})` : ''}`, 'No source changed.')}
${list('Findings', d.findings, (f) => html`<code>${f.code}</code> ${f.change === 'NOT_CONCLUDED' ? `no longer reported, not concluded (${f.why ?? 'UNKNOWN'})` : f.change.toLowerCase()} <code class="id">${f.ref}</code>`, 'No finding opened or closed.')}`;
    return html`<section id="drift" class="dup" aria-labelledby="drift-h">
<h2 id="drift-h">Since the previous run</h2>
${body}
</section>`;
}

/** The statements every rendering closes with: what the results do not say. */
function limits(): SafeHtml {
    return html`<section id="limits" aria-labelledby="limits-h">
<h2 id="limits-h">What this page does not say</h2>
<ul>${CAVEATS.map((c) => html`<li>${c}</li>`)}</ul>
</section>`;
}

/**
 * What the page may say about the report's `registeredAgentId` claims. Three
 * cases, and the middle one is the common one: a run with no register source
 * read no register, so "read by this run" would be a claim about nothing.
 */
function registerClaimsText(r: LocalResults): string {
    if (!r.scan.registerClaimsVerified) return 'Taken from the report as stated; not verified by this run';
    return r.sources.some((s) => s.kind === 'inflect-register')
        ? 'Read from the register by this run'
        : 'No register was read by this run';
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
${row('Register claims', registerClaimsText(r))}
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
[hidden]{display:none!important}
html.js .dup{display:none}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.muted{color:var(--muted)}
.small,.note{font-size:.84rem}
.note{color:var(--muted)}
.block{display:block}
.tag.plain{color:var(--muted);background:var(--panel)}
.dash{margin-top:2.25rem;border-top:1px solid var(--line);padding-top:1rem}
.d-section{border-top:0;margin-top:2rem;padding-top:0}
.dash>.d-section:first-child{margin-top:0}
.btn{font:inherit;font-size:.88rem;padding:.35rem .75rem;border:1px solid var(--line);border-radius:.35rem;background:var(--panel);color:var(--text);cursor:pointer}
.btn:hover:not([disabled]){border-color:var(--accent)}
.btn[disabled]{opacity:.55;cursor:default}
.linkish{font:inherit;padding:0;border:0;background:none;color:var(--accent);cursor:pointer;text-align:left;text-decoration:underline;text-underline-offset:.15em}
.hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(16rem,22rem);gap:1rem 2rem;align-items:start;background:var(--panel);border:1px solid var(--line);border-radius:.6rem;padding:1rem 1.25rem;margin:1rem 0}
.eyebrow{margin:0;color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.hero-big{font-size:1.9rem;font-weight:700;line-height:1.15;margin:.35rem 0}
.hero-num{font-variant-numeric:tabular-nums}
.bad-text{color:var(--bad)}
.ladder{list-style:none;margin:0;padding:0;display:grid;gap:.15rem}
.ladder-row{display:grid;grid-template-columns:minmax(0,10.5rem) minmax(3rem,1fr) 3rem;gap:.5rem;align-items:center;width:100%;font:inherit;font-size:.82rem;text-align:left;padding:.2rem .35rem;border:1px solid transparent;border-radius:.3rem;background:none;color:var(--text);cursor:pointer}
.ladder-row:hover{border-color:var(--line);background:var(--bg)}
.ladder-level{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ladder-n{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.meter{display:block;height:.6rem;background:var(--bg);border:1px solid var(--line);border-radius:.3rem;overflow:hidden}
.meter-fill{display:block;height:100%;background:var(--accent);min-width:0}
.meter-fill.out{background:var(--muted);opacity:.5}
.meter-fill.bad{background:var(--bad)}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:.6rem;margin:1rem 0}
.tile{display:flex;flex-direction:column;align-items:flex-start;gap:.1rem;font:inherit;text-align:left;padding:.65rem .8rem;border:1px solid var(--line);border-left:.3rem solid var(--line);border-radius:.45rem;background:var(--panel);color:var(--text);cursor:pointer}
.tile:hover{border-color:var(--accent)}
.tile.bad{border-left-color:var(--bad)}
.tile.warn{border-left-color:var(--warn)}
.tile-num{font-size:1.6rem;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.tile-label{font-weight:600;font-size:.9rem}
.tile-note{color:var(--muted);font-size:.78rem}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(19rem,1fr));gap:1rem;margin:1.5rem 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:.6rem;padding:.9rem 1rem;margin:0}
.card h3{margin:0 0 .5rem}
.d-section .card{margin:1rem 0}
.chart{display:block;width:100%;height:auto;max-height:15rem}
.ch-grid{stroke:var(--line);stroke-width:1}
.ch-axis{fill:var(--muted);font-size:11px}
.ch-value{fill:var(--text);font-size:11px;font-weight:600}
.ch-mark{fill:var(--muted);font-size:9px}
.ch-label{fill:var(--text);font-size:11px}
.ch-bar{fill:var(--accent)}
.ch-bar.out{fill:var(--muted);opacity:.45}
.ch-bar.nj{fill:var(--warn)}
.ch-bar.sev-critical,.ch-bar.sev-high{fill:var(--bad)}
.ch-bar.sev-medium{fill:var(--warn)}
.ch-bar.sev-low{fill:var(--muted)}
.ch-reach{stroke:var(--muted);stroke-width:1.5;stroke-dasharray:4 3}
.ch-hit{cursor:pointer}
.ch-hit:focus-visible rect{stroke:var(--text);stroke-width:2.5}
.ch-hit:hover rect{opacity:.85}
.sources{list-style:none;margin:0;padding:0;display:grid;gap:.45rem}
.sources li{display:grid;grid-template-columns:minmax(0,1fr);gap:.15rem}
.src-n{font-size:.8rem;color:var(--muted)}
.drift-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));gap:.25rem 1.5rem}
.drift-col h3{margin-top:.8rem}
.plain-list{list-style:none;padding:0;margin:.3rem 0}
.plain-list li{margin:.25rem 0}
.toolbar{display:flex;flex-wrap:wrap;gap:.5rem .75rem;align-items:flex-end;margin:.75rem 0;padding:.6rem .75rem;background:var(--panel);border:1px solid var(--line);border-radius:.45rem}
.field{display:flex;flex-direction:column;gap:.15rem;font-size:.8rem;min-width:0}
.field label,.label-spacer{color:var(--muted);font-weight:600}
.field input,.field select{font:inherit;font-size:.88rem;padding:.3rem .45rem;border:1px solid var(--line);border-radius:.3rem;background:var(--bg);color:var(--text);max-width:16rem}
.field input[type=search]{width:16rem;max-width:100%}
.count{font-size:.85rem;color:var(--muted);margin:.4rem 0}
.pager{display:flex;flex-wrap:wrap;gap:.5rem .75rem;align-items:flex-end;margin:.6rem 0}
.page-of{font-size:.85rem;color:var(--muted);padding-bottom:.4rem}
.empty{padding:1rem;color:var(--muted)}
.agent-btn{font:inherit;font-weight:500;padding:0;border:0;background:none;color:var(--accent);cursor:pointer;text-align:left;text-decoration:underline;text-underline-offset:.15em;overflow-wrap:anywhere}
.badges .tag{margin:.2rem .25rem 0 0}
.badges{display:block}
.cb{font:inherit;font-weight:700;width:100%;min-width:1.6rem;padding:.15rem 0;border:0;background:none;color:inherit;cursor:pointer}
.cell.inline{display:inline-block;min-width:1.4rem;border:1px solid var(--line);border-radius:.2rem}
.matrix td.cell{padding:.25rem .15rem}
.dash .matrix td.lvl{white-space:normal;min-width:9rem}
.dash .matrix td.lvl .tag{white-space:nowrap}
.drawer-back{position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:20}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(40rem,100%);overflow-y:auto;background:var(--bg);color:var(--text);border-left:1px solid var(--line);box-shadow:-.5rem 0 1.5rem rgba(0,0,0,.25);z-index:21;padding:0 1.1rem 2rem}
.drawer-head{position:sticky;top:0;display:flex;justify-content:space-between;align-items:center;gap:1rem;background:var(--bg);border-bottom:1px solid var(--line);padding:.8rem 0;z-index:1}
.drawer-head h2{margin:0;padding:0;font-size:1.15rem;overflow-wrap:anywhere}
body.drawer-open{overflow:hidden}
.kv{display:grid;grid-template-columns:minmax(8rem,12rem) minmax(0,1fr);gap:.35rem 1rem;margin:.75rem 0}
.kv dt{color:var(--muted);font-size:.85rem}
.kv dd{margin:0;overflow-wrap:anywhere}
.tags .tag{margin-right:.3rem}
.crit-table td,.crit-table th{font-size:.85rem}
.ev{overflow-wrap:anywhere}
@media (max-width:40rem){
body{padding:1rem .75rem 3rem}
.hero{grid-template-columns:1fr}
.hero-big{font-size:1.5rem}
.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}
.kv{grid-template-columns:1fr}
.field input[type=search]{width:100%}
.toolbar .field{flex:1 1 9rem}
.field select{max-width:100%}
}
footer.end{margin-top:2.5rem;color:var(--muted);font-size:.82rem;border-top:1px solid var(--line);padding-top:.75rem}
@media print{
:root{--bg:#ffffff;--panel:#ffffff;--text:#000000;--muted:#333333;--line:#888888;--accent:#000000;--ok:#000000;--ok-bg:#ffffff;--bad:#000000;--bad-bg:#ffffff;--warn:#000000;--warn-bg:#ffffff;--decl:#000000;--decl-bg:#ffffff}
html{font-size:10.5pt}
body{max-width:none;padding:0 0 2.2em}
.skip,nav.contents,#dash,.drawer,.drawer-back{display:none!important}
html.js .dup{display:block}
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
/** The style block's own text, between its tags: what its CSP hash is over. */
export const STYLE_TEXT = htmlText(STYLE_ELEMENT).slice('<style>'.length, -'</style>'.length);

/**
 * The page's Content-Security-Policy. Nothing may be loaded, fetched,
 * connected to, framed or submitted; the one inline script and the one style
 * block run because their hashes are named; the script may not hand a string
 * to an HTML sink (Trusted Types, where the browser has them).
 */
export const PAGE_CSP = [
    "default-src 'none'",
    `script-src ${cspHashSource(PAGE_SCRIPT)}`,
    `style-src ${cspHashSource(STYLE_TEXT)}`,
    "connect-src 'none'",
    "img-src 'none'",
    "font-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "require-trusted-types-for 'script'",
].join('; ');

/**
 * The page. A function of the results and, for a run written to a directory,
 * of what the run knew of the run before it (`context.previous`).
 */
export function renderSummaryHtml(results: LocalResults, context: SummaryContext = {}): string {
    const r = results;
    const model = harnessMatrixOfResults(r);
    const data = summaryPageData(r, context);
    const title = r.scan.estate === null ? `scanent results: ${r.scan.id}` : `scanent results: ${r.scan.estate}, ${r.scan.id}`;
    const driftSection = data.drift === null ? [] : [['drift', 'Since the previous run', drift(data.drift)] as const];
    const sections: readonly (readonly [string, string, SafeHtml])[] = r.estate.empty
        ? [
              ['completeness', 'Completeness', completeness(r)],
              ['coverage', 'Not evidenced', coverage(r)],
              ['summary', 'Summary', emptyEstate(r)],
              ...driftSection,
              ['findings', 'Findings', findings(r)],
              ...(r.inventory === null ? [] : [['inventory', 'Inventory', inventory(r)] as const]),
              ['provenance', 'Provenance', provenance(r)],
              ['limits', 'Limits', limits()],
          ]
        : [
              ['completeness', 'Completeness', completeness(r)],
              ['coverage', 'Not evidenced', coverage(r)],
              ['summary', 'Summary', summary(r)],
              ...driftSection,
              ['matrix', 'Agents and criteria', matrix(r, model)],
              ['shadow', 'Shadow agents', shadowAgents(r)],
              // Absent for results written before the member existed: there, every unregistered principal is a shadow agent.
              ...(r.estate.unregisteredIdentities === undefined ? [] : [['identities', 'Unregistered identities', unregisteredIdentities(r)] as const]),
              // Absent for results written before the member existed: they hold no payment facts.
              ...(r.estate.payingAgents === undefined ? [] : [['payments', 'Payment capabilities', payments(r)] as const]),
              ['orphans', 'Orphan credentials', orphans(r)],
              ['findings', 'Findings', findings(r)],
              ...(r.inventory === null ? [] : [['inventory', 'Inventory', inventory(r)] as const]),
              ['provenance', 'Provenance', provenance(r)],
              ['limits', 'Limits', limits()],
          ];
    // The interactive view goes after what could not be read and what could
    // not be evidenced, so a reader meets those first with or without it.
    const view = html`<div id="dash" class="dash" hidden></div>`;
    const [first, second, ...rest] = sections;
    // The style block is this module's own constant text, built as the
    // literal part of a template, so nothing scanned can enter it.
    const page = html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${PAGE_CSP}">
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
${first[2]}
${second[2]}
${view}
${rest.map(([, , body]) => body)}
</main>
<footer class="end">Scan <code>${r.scan.id}</code>, as of ${r.scan.asOf} UTC. Ladder <code>${r.ladder.version}</code>.</footer>
<p class="print-footer">Scan ${r.scan.id}, as of ${r.scan.asOf} UTC</p>
${scriptElement('json', scriptJson(data), 'scan-data')}
${scriptElement('code', PAGE_SCRIPT)}
</body>
</html>
`;
    return htmlText(page);
}
