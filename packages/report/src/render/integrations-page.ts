/**
 * THE INTEGRATIONS SECTION OF `summary.html` — static, and an interactive view
 * built the way the agent view is.
 *
 * A page of a run that configured no integrations source holds none of this:
 * not a section, not a data block, not a script, not a style and not a hash in
 * its Content-Security-Policy. So an agents-only page is, byte for byte, the
 * page it was before there were two scanners.
 *
 * The same rules as the agent view, applied here:
 *
 *   • READABLE WITH NO SCRIPT. Every table is rendered here; the view is built
 *     into an element that stays hidden until it is complete, then hides the
 *     static tables it repeats, and printing shows them again.
 *   • THE SCRIPT DECIDES NOTHING. Every cell's words are decided here
 *     (`integrationsPageData`) and carried in the data block; the script
 *     searches, filters, pages and draws text it is given.
 *   • WHAT COULD NOT BE READ COMES FIRST. The section opens with its sources'
 *     completeness, and an application whose grants were not read in full
 *     says so in its row rather than looking clean.
 *   • EVERY SCANNED STRING IS ESCAPED (the `html` template) and the data
 *     block is written by `scriptJson`; no scanned value becomes a link.
 */
import { CLASS_WORDS } from '@rodnapamet/scanent-contract/integrations-findings';

import type { LocalApplicationResult, LocalIntegrationFinding, LocalIntegrationsResults } from '../results/types';
import { html, htmlText, type SafeHtml } from './escape';
import { INTEGRATION_RUN_FILE_NAMES } from './files';
import { printable, type IntegrationsPreviousRun } from './page-data';
import { fixed, plural, PREVIOUS_NOT_COMPARED_TEXT, SEVERITY_CLASS, SEVERITY_ORDER } from './words';

export const INTEGRATIONS_PAGE_DATA_SCHEMA = 'scanent-integrations-page/1';

/** The most applications the static table lists; the CSV holds every one. */
export const INTEGRATIONS_MAX_ROWS = 500;

// ── Fixed words, keyed by the results' own enum values ──

export const ORIGIN_TEXT: Readonly<Record<string, string>> = {
    THIS_DIRECTORY: 'Registered in this directory',
    OTHER_DIRECTORY: 'Registered in another directory',
    UNKNOWN: 'Registering directory not stated',
};

export const PRIVILEGE_TEXT: Readonly<Record<string, string>> = {
    HIGH: 'High privilege',
    NOT_HIGH: 'No high-privilege grant',
    NOT_CONCLUDED: 'Not concluded',
};

export const USAGE_TEXT: Readonly<Record<string, string>> = {
    USED: 'Signed in within the window',
    UNUSED: 'Not signed in within the window',
    NOT_CONCLUDED: 'Not concluded',
};

export const NOT_CONCLUDED_TEXT: Readonly<Record<string, string>> = {
    GRANTS_NOT_READ_IN_FULL: 'its grants were not all read, and what was read raises nothing',
    ONLY_UNKNOWN_PERMISSIONS: 'every permission it holds is one the classification table does not know',
    PUBLISHER_NOT_KNOWN: 'the read could not tell whether its publisher is verified',
    OWNERS_NOT_READ: 'its owners were not read',
    SIGN_IN_NOT_READ: 'sign-in activity was not read: the source is configured without it',
    SIGN_IN_READ_INCOMPLETE: 'sign-in activity was not read in full, and this application was not in what was read',
    SOURCE_INCOMPLETE: 'the source was not read in full, so an empty answer concludes nothing',
};

export const INTEGRATION_FINDING_TEXT: Readonly<Record<string, string>> = {
    INTEGRATION_HIGH_PRIVILEGE_GRANT: 'High-privilege grant',
    INTEGRATION_UNVERIFIED_PUBLISHER: 'Unverified publisher',
    INTEGRATION_NO_OWNER: 'No owner',
    INTEGRATION_UNUSED: 'Unused',
    INTEGRATION_EMPTY_INVENTORY: 'Empty inventory',
};

const SIGN_IN_STATE_TEXT: Readonly<Record<string, string>> = {
    NOT_READ: 'Not read (not configured)',
    COMPLETE: 'Read in full',
    INCOMPLETE: 'Not read in full',
};

// ── One application in words ──

function publisherText(a: LocalApplicationResult): string {
    if (a.origin === 'THIS_DIRECTORY') return 'This directory';
    return a.publisherVerified === null ? 'Not known' : a.publisherVerified ? 'Verified' : 'Not verified';
}

function ownersText(a: LocalApplicationResult): string {
    if (a.owners === null) return 'Not read';
    return a.owners.length === 0 ? 'None' : plural(a.owners.length, 'owner', 'owners');
}

function grantsText(a: LocalApplicationResult): string {
    const scopes = a.delegatedGrants.grants.reduce((n, g) => n + g.scopes.length + g.unreadableScopes, 0);
    const forAll = a.delegatedGrants.grants.some((g) => g.consentType === 'AllPrincipals');
    const people = a.delegatedGrants.grants.reduce((n, g) => n + (g.principalCount ?? 0), 0);
    const delegated = scopes === 0 ? 'no delegated scope' : `${plural(scopes, 'delegated scope', 'delegated scopes')}${forAll ? ', for everyone' : `, for ${plural(people, 'person', 'people')}`}`;
    const application = plural(a.applicationPermissions.permissions.length, 'application permission', 'application permissions');
    const unread = !a.delegatedGrants.read || !a.applicationPermissions.read ? '; not all read' : '';
    return `${delegated}; ${application}${unread}`;
}

function signInText(a: LocalApplicationResult): string {
    if (!a.signIn.read) return 'Not read';
    return a.signIn.lastSeen === null ? 'No sign-in recorded' : `${a.signIn.lastSeen} (${plural(a.signIn.daysSince ?? 0, 'day', 'days')} before the scan)`;
}

function privilegeText(a: LocalApplicationResult): string {
    const base = fixed(PRIVILEGE_TEXT, a.privilege, 'Not concluded');
    return a.privilege === 'HIGH' ? `${base}: ${a.classes.map((c) => CLASS_WORDS[c]).join(', ')}` : base;
}

const worst = (findings: readonly LocalIntegrationFinding[]): number => Math.min(9, ...findings.map((f) => SEVERITY_ORDER[f.severity] ?? 9));

// ── The data the view is given ──

export interface IntegrationsPageData {
    readonly schema: typeof INTEGRATIONS_PAGE_DATA_SCHEMA;
    readonly rows: readonly {
        readonly id: string;
        readonly name: string;
        readonly cells: readonly string[];
        readonly codes: readonly string[];
        /** The most severe finding's rank: 0 critical to 3 low, 9 none. */
        readonly rank: number;
        readonly hay: string;
    }[];
    readonly columns: readonly string[];
    readonly codes: readonly { readonly code: string; readonly text: string }[];
}

export const INTEGRATIONS_COLUMNS = ['Application', 'Publisher', 'Owners', 'Grants', 'Privilege', 'Last sign-in', 'Findings'] as const;

export function integrationCells(a: LocalApplicationResult, findings: readonly LocalIntegrationFinding[]): string[] {
    return [
        a.displayName === null ? a.id : `${a.displayName} (${a.id})`,
        `${publisherText(a)}. ${fixed(ORIGIN_TEXT, a.origin, 'Not stated')}`,
        ownersText(a),
        grantsText(a),
        privilegeText(a),
        signInText(a),
        findings.length === 0 ? 'None' : findings.map((f) => `${f.severity} ${fixed(INTEGRATION_FINDING_TEXT, f.code, f.code)}`).join('; '),
    ];
}

/** Applications with their findings, worst first and then by id: the order the view and the PDF show them in. */
export function applicationsByConcern(i: LocalIntegrationsResults): { readonly app: LocalApplicationResult; readonly findings: readonly LocalIntegrationFinding[] }[] {
    const by = new Map<string, LocalIntegrationFinding[]>();
    for (const f of i.findings) if (f.applicationId !== null) by.set(f.applicationId, [...(by.get(f.applicationId) ?? []), f]);
    return i.applications
        .map((app) => ({ app, findings: by.get(app.id) ?? [] }))
        .sort((x, y) => worst(x.findings) - worst(y.findings) || (x.app.id < y.app.id ? -1 : x.app.id > y.app.id ? 1 : 0));
}

/** The integrations view's data. Every string has its unprintable characters replaced, as the agent view's. */
export function integrationsPageData(i: LocalIntegrationsResults): IntegrationsPageData {
    const rows = applicationsByConcern(i).map(({ app, findings }) => {
        const cells = integrationCells(app, findings).map(printable);
        return {
            id: printable(app.id),
            name: printable(app.displayName ?? app.id),
            cells,
            codes: findings.map((f) => f.code),
            rank: worst(findings),
            hay: cells.slice(0, 2).join(' ').toLowerCase(),
        };
    });
    return {
        schema: INTEGRATIONS_PAGE_DATA_SCHEMA,
        rows,
        columns: [...INTEGRATIONS_COLUMNS],
        codes: Object.entries(INTEGRATION_FINDING_TEXT).map(([code, text]) => ({ code, text })),
    };
}

// ── The static section ──

function sourcesTable(i: LocalIntegrationsResults): SafeHtml {
    return html`<div class="scroll"><table>
<caption>Each integrations source, and whether it was read in full</caption>
<thead><tr><th scope="col">Source</th><th scope="col">Status</th><th scope="col">Reason</th><th scope="col" class="num">Rows read</th><th scope="col" class="num">Applications</th><th scope="col">Sign-in activity</th></tr></thead>
<tbody>
${i.sources.map(
        (s) => html`<tr class="${s.status === 'COMPLETE' ? 'row-ok' : 'row-bad'}">
<th scope="row"><code>${s.kind}</code></th>
<td>${s.status === 'COMPLETE' ? html`<span class="tag ok">Complete</span>` : html`<span class="tag bad">Incomplete</span>`}</td>
<td>${s.reason === null ? '' : html`<code>${s.reason}</code>`}</td>
<td class="num">${s.rows}</td>
<td class="num">${s.applications}</td>
<td>${fixed(SIGN_IN_STATE_TEXT, s.signInActivity.status, s.signInActivity.status)}${s.signInActivity.reason === null ? '' : html` <code>${s.signInActivity.reason}</code>`}</td>
</tr>`,
    )}
</tbody>
</table></div>
${i.sources.filter((s) => s.detail !== undefined).map((s) => html`<p class="callout bad"><strong><code>${s.kind}</code> was not read in full</strong>: ${s.detail ?? ''}.</p>`)}`;
}

function applicationsTable(i: LocalIntegrationsResults): SafeHtml {
    const ordered = applicationsByConcern(i);
    const shown = ordered.slice(0, INTEGRATIONS_MAX_ROWS);
    return html`${ordered.length > shown.length ? html`<p class="callout">This table shows the first ${shown.length} of ${ordered.length} applications, those with the most severe findings first. The full list is in <code>${INTEGRATION_RUN_FILE_NAMES.applications}</code>.</p>` : ''}<div class="scroll"><table>
<caption>One row per application, those with the most severe findings first</caption>
<thead><tr>${INTEGRATIONS_COLUMNS.map((c) => html`<th scope="col">${c}</th>`)}</tr></thead>
<tbody>
${shown.map(({ app, findings }) => {
        const cells = integrationCells(app, findings);
        return html`<tr><th scope="row">${app.displayName === null ? '' : html`<span class="name">${app.displayName}</span><br>`}<code class="id">${app.id}</code></th>${cells.slice(1).map((c) => html`<td>${c}</td>`)}</tr>`;
    })}
</tbody>
</table></div>`;
}

function findingsTable(i: LocalIntegrationsResults): SafeHtml {
    const ordered = [...i.findings].map((f, k): [LocalIntegrationFinding, number] => [f, k]).sort(([a, x], [b, y]) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) || x - y).map(([f]) => f);
    if (ordered.length === 0) {
        return html`<p>No integration finding was raised.${i.complete ? '' : ' The integrations scan is incomplete, so this is not a clean result.'}${i.notConcluded.length > 0 ? ' Some questions were not concluded: see below.' : ''}</p>`;
    }
    const shown = ordered.slice(0, INTEGRATIONS_MAX_ROWS * 5);
    return html`${ordered.length > shown.length ? html`<p class="callout">This list shows the first ${shown.length} of ${ordered.length} findings, most severe first. The full list is in <code>${INTEGRATION_RUN_FILE_NAMES.findings}</code>.</p>` : ''}<div class="scroll"><table class="findings">
<caption>${plural(ordered.length, 'integration finding', 'integration findings')}, most severe first</caption>
<thead><tr><th scope="col">Severity</th><th scope="col">Code</th><th scope="col">Subject</th><th scope="col">Finding</th></tr></thead>
<tbody>
${shown.map(
        (f) => html`<tr>
<td><span class="tag ${fixed(SEVERITY_CLASS, f.severity, 'sev-low')}">${f.severity}</span></td>
<td><code>${f.code}</code></td>
<td>${f.applicationId === null ? 'A source' : html`<code class="id">${f.applicationId}</code>`}</td>
<td><details><summary>${f.title}</summary><p>${f.description}</p><p class="ref">Reference <code class="id">${f.sourceRef}</code></p></details></td>
</tr>`,
    )}
</tbody>
</table></div>`;
}

function notConcluded(i: LocalIntegrationsResults): SafeHtml {
    if (i.notConcluded.length === 0) return html``;
    const grouped = new Map<string, { code: string; why: string; n: number; scoped: boolean }>();
    for (const n of i.notConcluded) {
        const key = `${n.code}\u0000${n.why}\u0000${n.applicationId === null ? 'source' : 'app'}`;
        const g = grouped.get(key) ?? { code: n.code, why: n.why, n: 0, scoped: n.applicationId !== null };
        g.n += 1;
        grouped.set(key, g);
    }
    return html`<h3>Not concluded</h3>
<p>Each of these is a question the scan could not answer either way. None of them is a clean result.</p>
<ul>${[...grouped.values()].map((g) => html`<li><code>${g.code}</code>${g.scoped ? html` for ${plural(g.n, 'application', 'applications')}` : ''}: ${fixed(NOT_CONCLUDED_TEXT, g.why, 'see the code')} <code>${g.why}</code>.</li>`)}</ul>`;
}

function unknownPermissions(i: LocalIntegrationsResults): SafeHtml {
    if (i.unknownPermissions.length === 0) return html``;
    const shown = i.unknownPermissions.slice(0, INTEGRATIONS_MAX_ROWS);
    return html`<h3>Permissions the classification does not know (${i.unknownPermissions.length})</h3>
<p>These are not called high and not called low: a person judges them. A permission on an API other than Microsoft Graph is always one.</p>
${i.unknownPermissions.length > shown.length ? html`<p class="callout">The first ${shown.length} of ${i.unknownPermissions.length}. The full list is in <code>results.json</code>.</p>` : ''}<ul class="ids">${shown.map((u) => html`<li><code class="id">${u.name}</code> <span class="note">on ${u.resourceAppId ?? 'an API the read did not find'}</span></li>`)}</ul>`;
}

/** Why an application not seen is not concluded gone, in words. */
export const NOT_SEEN_TEXT: Readonly<Record<string, string>> = {
    SOURCE_INCOMPLETE: 'its source was not read in full',
    SOURCE_ABSENT: 'its source is no longer listed',
    NEW_SOURCE_EMPTY: 'its source reported no application at all, which evidences nothing about any one',
    DIFFERENT_SCANNER: 'the runs are from different scanners',
    DIFFERENT_ESTATE: 'the runs name different estates',
};

/** The most entries each list of the integrations comparison shows; each says how many it holds. */
export const INTEGRATIONS_DRIFT_MAX_ROWS = 200;

/**
 * What changed in the integrations since the run the output directory named
 * as the latest. Whatever could not be concluded is never worded as a change:
 * an application not seen is "not seen", with the reason.
 */
export function integrationsDrift(previous: IntegrationsPreviousRun | null): SafeHtml {
    if (previous === null) return html`<h3>Since the previous run</h3><p>This output directory held no earlier run, so there is nothing to compare with.</p>`;
    if (previous.kind === 'NOT_COMPARED') {
        return html`<h3>Since the previous run</h3><p class="callout">Not compared with ${previous.scanId === null ? 'the previous run' : html`<code class="id">${previous.scanId}</code>`}: ${fixed(PREVIOUS_NOT_COMPARED_TEXT, previous.reason, 'not compared')}.</p>`;
    }
    const d = previous.diff;
    const list = <T>(title: string, all: readonly T[], line: (x: T) => SafeHtml, none: string): SafeHtml =>
        html`<h4>${title} (${all.length})</h4>${all.length === 0
            ? html`<p>${none}</p>`
            : html`<ul>${all.slice(0, INTEGRATIONS_DRIFT_MAX_ROWS).map((x) => html`<li>${line(x)}</li>`)}</ul>${all.length > INTEGRATIONS_DRIFT_MAX_ROWS ? html`<p class="note">The first ${INTEGRATIONS_DRIFT_MAX_ROWS} of ${all.length}.</p>` : ''}`}`;
    const outcome = d.outcome === 'DIFFERENT' ? 'The integrations differ.' : d.outcome === 'SAME' ? 'No difference, and every comparison could be made.' : 'No difference was found, but not every comparison could be made. This is not a statement that nothing changed.';
    return html`<h3>Since the previous run</h3>
<p>Compared with <code class="id">${d.old.scanId}</code>, as of ${d.old.asOf} UTC (${d.old.complete ? 'complete' : 'incomplete'}, ${plural(d.old.applicationCount, 'application', 'applications')}). <strong>${outcome}</strong></p>
<p>${plural(d.summary.differences, 'difference', 'differences')}; ${plural(d.summary.notConcluded, 'comparison', 'comparisons')} not concluded. The full comparison is <code>scanent diff</code> on the two results files.</p>
${list('New applications', d.applications.added, (id) => html`<code class="id">${id}</code>`, 'None.')}
${list('Gone', d.applications.gone, (id) => html`<code class="id">${id}</code> (its source was read in full)`, 'None concluded gone.')}
${list('Not seen, not concluded', d.applications.notSeen, (x) => html`<code class="id">${x.id}</code>: ${fixed(NOT_SEEN_TEXT, x.why, x.why)}`, 'None.')}
${list('Findings', d.findings, (f) => html`<code>${f.code}</code> ${f.change === 'NOT_CONCLUDED' ? `no longer raised, not concluded (${f.why ?? 'UNKNOWN'})` : f.change.toLowerCase()} <code class="id">${f.sourceRef}</code>`, 'No finding opened or closed.')}`;
}

/**
 * The integrations section, whole. `previous` absent: rendered outside a run
 * directory, with no comparison. `alone`: the run in which the integrations
 * scanner was the only one, so there is no agent report to name beside it.
 */
export function integrationsSection(i: LocalIntegrationsResults, previous?: IntegrationsPreviousRun | null, alone = false): SafeHtml {
    const c = i.counts;
    const signInRead = i.sources.some((s) => s.signInActivity.status !== 'NOT_READ');
    return html`<section id="integrations" aria-labelledby="integrations-h">
<h2 id="integrations-h">Integrations</h2>
<p>What the directories this run read have granted to applications, and whether anybody owns those grants. A report of its own, <code>${i.report.file}</code> (contract <code>${i.contract}</code>, SHA-256 <code class="id">${i.report.sha256}</code>), ${alone ? 'signed with the scanner\'s key.' : 'signed with the same key as the agent report.'}</p>
${i.complete
        ? html`<p class="status ok"><strong>Complete.</strong> Every integrations source was read in full.</p>`
        : html`<p class="status bad"><strong>Incomplete:</strong> not everything the integrations sources hold was read. A finding below is real; an absence is not a clean result.</p>`}
${sourcesTable(i)}
<dl class="stats">
<div class="stat"><dt>Applications</dt><dd><span class="big">${c.applications}</span></dd></div>
<div class="stat"><dt>High-privilege grant</dt><dd><span class="big">${c.highPrivilege}</span></dd></div>
<div class="stat"><dt>Unverified publisher</dt><dd><span class="big">${c.unverifiedPublisher}</span></dd></div>
<div class="stat"><dt>No owner</dt><dd><span class="big">${c.noOwner}</span></dd></div>
<div class="stat"><dt>Unused for ${i.unusedDays} days</dt><dd><span class="big">${c.unused}</span>${signInRead ? '' : html` <span class="note">sign-in activity not read</span>`}</dd></div>
</dl>
${findingsTable(i)}
${notConcluded(i)}
<div id="integrations-dash" hidden></div>
<div class="idup">
<h3>Applications</h3>
${i.applications.length === 0
        ? html`<p class="callout bad">No application was reported.${i.complete ? ' A directory read in full that holds none is a finding, not a clean result.' : ' The read was not complete.'}</p>`
        : applicationsTable(i)}
</div>
${unknownPermissions(i)}
${previous === undefined ? '' : integrationsDrift(previous)}
</section>`;
}

/** What the header says of the integrations scan, beside the agent scan's status. */
export function integrationsStatus(i: LocalIntegrationsResults): SafeHtml {
    return i.complete
        ? html`<p class="status ok"><strong>Integrations: complete.</strong> Every integrations source was read in full.</p>`
        : html`<p class="status bad"><strong>Integrations: incomplete.</strong> See the integrations section.</p>`;
}

// ── The view's style and script ──

/** A second style block, present only with the section: the view's own rules, so the page's first block is unchanged. */
export const INTEGRATIONS_STYLE_ELEMENT: SafeHtml = html`<style>
html.ijs .idup{display:none}
@media print{html.ijs .idup{display:block}#integrations-dash{display:none!important}}
</style>`;

/** The second style block's own text, between its tags: what its CSP hash is over. */
export const INTEGRATIONS_STYLE_TEXT = htmlText(INTEGRATIONS_STYLE_ELEMENT).slice('<style>'.length, -'</style>'.length);

/**
 * The view: a search box, a filter by finding, a page of rows at a time. It
 * reads the data block, builds into `#integrations-dash`, and only then marks
 * the page so the static table hides. It decides no word it shows.
 * `createElement` and `textContent` only; no `innerHTML`, no network, no timer,
 * no storage. Kept free of template syntax and backticks, as the agent view's.
 */
export const INTEGRATIONS_SCRIPT = String.raw`(function () {
'use strict';
var root = document.getElementById('integrations-dash');
var holder = document.getElementById('integrations-data');
if (!root || !holder) return;
var D;
try { D = JSON.parse(holder.textContent || ''); } catch (err) { return; }
if (!D || D.schema !== 'scanent-integrations-page/1' || !Array.isArray(D.rows)) return;
var PAGE = 100;
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
var state = { q: '', code: '', page: 0 };
var toolbar = el('div', 'toolbar');
var search = el('input');
search.type = 'search';
search.id = 'i-search';
var searchField = el('div', 'field');
var searchLabel = el('label', null, 'Search applications');
searchLabel.setAttribute('for', 'i-search');
searchField.appendChild(searchLabel);
searchField.appendChild(search);
var pick = el('select');
pick.id = 'i-code';
pick.appendChild(el('option', null, 'Any finding')).value = '';
pick.appendChild(el('option', null, 'No finding')).value = '-';
for (var c = 0; c < D.codes.length; c++) { var o = el('option', null, D.codes[c].text); o.value = D.codes[c].code; pick.appendChild(o); }
var pickField = el('div', 'field');
var pickLabel = el('label', null, 'Finding');
pickLabel.setAttribute('for', 'i-code');
pickField.appendChild(pickLabel);
pickField.appendChild(pick);
toolbar.appendChild(searchField);
toolbar.appendChild(pickField);
var count = el('p', 'count');
var table = el('table');
var head = el('thead');
var headRow = el('tr');
for (var h = 0; h < D.columns.length; h++) { var th = el('th', null, D.columns[h]); th.setAttribute('scope', 'col'); headRow.appendChild(th); }
head.appendChild(headRow);
table.appendChild(head);
var body = el('tbody');
table.appendChild(body);
var wrap = el('div', 'scroll');
wrap.appendChild(table);
var pager = el('div', 'pager');
var prev = el('button', 'btn', 'Previous');
prev.type = 'button';
var next = el('button', 'btn', 'Next');
next.type = 'button';
var where = el('span', 'page-of');
pager.appendChild(prev);
pager.appendChild(where);
pager.appendChild(next);
function matches(r) {
  if (state.q !== '' && r.hay.indexOf(state.q) < 0) return false;
  if (state.code === '-') return r.codes.length === 0;
  if (state.code !== '') return r.codes.indexOf(state.code) >= 0;
  return true;
}
function draw() {
  var shown = D.rows.filter(matches);
  var pages = Math.max(1, Math.ceil(shown.length / PAGE));
  if (state.page >= pages) state.page = pages - 1;
  while (body.firstChild) body.removeChild(body.firstChild);
  var slice = shown.slice(state.page * PAGE, state.page * PAGE + PAGE);
  for (var i = 0; i < slice.length; i++) {
    var tr = el('tr');
    var first = el('th', null, slice[i].cells[0]);
    first.setAttribute('scope', 'row');
    tr.appendChild(first);
    for (var k = 1; k < slice[i].cells.length; k++) tr.appendChild(el('td', null, slice[i].cells[k]));
    body.appendChild(tr);
  }
  if (slice.length === 0) { var none = el('tr'); var td = el('td', 'empty', 'No application matches.'); td.setAttribute('colspan', String(D.columns.length)); none.appendChild(td); body.appendChild(none); }
  count.textContent = shown.length + ' of ' + D.rows.length + ' applications';
  where.textContent = 'Page ' + (state.page + 1) + ' of ' + pages;
  prev.disabled = state.page === 0;
  next.disabled = state.page >= pages - 1;
}
search.addEventListener('input', function () { state.q = search.value.trim().toLowerCase(); state.page = 0; draw(); });
pick.addEventListener('change', function () { state.code = pick.value; state.page = 0; draw(); });
prev.addEventListener('click', function () { if (state.page > 0) { state.page -= 1; draw(); } });
next.addEventListener('click', function () { state.page += 1; draw(); });
root.appendChild(el('h3', null, 'Applications'));
root.appendChild(toolbar);
root.appendChild(count);
root.appendChild(wrap);
root.appendChild(pager);
draw();
root.hidden = false;
document.documentElement.classList.add('ijs');
})();
`;
