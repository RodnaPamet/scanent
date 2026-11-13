/**
 * THE INTERACTIVE VIEW OF `summary.html` — one inline script, as text.
 *
 * It reads the JSON block the page carries (`page-data.ts`), builds the view
 * into the empty `#dash` element, and only then marks the page as scripted, so
 * a page whose script did not run, or failed, is the static page unchanged.
 *
 * WHAT IT DOES NOT DO: decide what a row says. Cell states, levels, bars and
 * standings arrive as the shared table model computed them, in the model's
 * order; the script looks them up by index in the tables the data carries. It
 * sorts, filters, counts what it shows, pages and draws.
 *
 * HOW IT TOUCHES THE PAGE: `createElement`, `createElementNS`, `textContent`
 * and `setAttribute` with attribute names written here. No `innerHTML`, no
 * `eval`, no timer taking a string, no network API, no storage. The only
 * address it ever sets is an evidence reference the data marked as an
 * absolute https URL, and it checks the prefix again. The page's
 * Content-Security-Policy allows this script by its hash and nothing else.
 *
 * The text below is JavaScript, kept free of template syntax, backticks and
 * the sequence that would end a script element; a test holds that, and that
 * it parses.
 */
export const PAGE_SCRIPT = String.raw`(function () {
'use strict';
var root = document.getElementById('dash');
var holder = document.getElementById('scan-data');
if (!root || !holder) return;
var D;
try { D = JSON.parse(holder.textContent || ''); } catch (err) { return; }
if (!D || D.schema !== 'scanent-summary-page/1') return;

var SVG_NS = 'http://www.w3.org/2000/svg';
var has = function (o, k) { return o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k); };
var word = function (table, key, fallback) { return has(table, key) ? table[key] : fallback; };
var plural = function (n, one, many) { return n + ' ' + (n === 1 ? one : many); };
var byCodeUnit = function (a, b) { return a < b ? -1 : a > b ? 1 : 0; };

function add(parent, kids) {
  if (kids === null || kids === undefined || kids === false) return parent;
  if (Array.isArray(kids)) { for (var i = 0; i < kids.length; i++) add(parent, kids[i]); return parent; }
  if (typeof kids === 'string' || typeof kids === 'number') { parent.appendChild(document.createTextNode(String(kids))); return parent; }
  parent.appendChild(kids);
  return parent;
}
function el(tag, attrs, kids) {
  var e = document.createElement(tag);
  if (attrs) {
    for (var k in attrs) {
      if (!has(attrs, k)) continue;
      var v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === 'cls') e.className = v;
      else if (k === 'text') e.textContent = String(v);
      else e.setAttribute(k, v === true ? '' : String(v));
    }
  }
  return add(e, kids);
}
function sv(tag, attrs, kids) {
  var e = document.createElementNS(SVG_NS, tag);
  if (attrs) for (var k in attrs) if (has(attrs, k) && attrs[k] !== null && attrs[k] !== undefined) e.setAttribute(k, String(attrs[k]));
  if (kids) for (var i = 0; i < kids.length; i++) if (kids[i]) e.appendChild(kids[i]);
  return e;
}
function svgText(x, y, text, cls, anchor) {
  var t = sv('text', { x: x, y: y, 'class': cls || 'ch-label', 'text-anchor': anchor || 'middle' });
  t.textContent = text;
  return t;
}
function tag(text, kind) { return el('span', { cls: 'tag ' + kind }, text); }
function code(text) { return el('code', null, text); }
function idCode(text) { return el('code', { cls: 'id' }, text); }
function button(text, cls, onClick, attrs) {
  var b = el('button', Object.assign({ type: 'button', cls: cls || 'btn' }, attrs || {}), text);
  b.addEventListener('click', onClick);
  return b;
}
function option(value, text, selected) { return el('option', { value: value, selected: selected ? true : null }, text); }
function labelled(labelText, control) {
  var id = 'f-' + (labelled.n = (labelled.n || 0) + 1);
  control.id = id;
  return el('div', { cls: 'field' }, [el('label', { 'for': id }, labelText), control]);
}

// ── The data, indexed ──
var T = D.text;
var STATES = D.states;
var CRITERIA = D.criteria;
var LEVELS = D.levels.map(function (l) { return l.level; });
var LEVEL_NAME = {};
D.levels.forEach(function (l) { LEVEL_NAME[l.level] = l.name; });
var rung = function (level) { var i = LEVELS.indexOf(level); return i < 0 ? 0 : i; };
var levelText = function (level) { return level + ' ' + word(LEVEL_NAME, level, ''); };
var SOURCE = {};
D.sources.forEach(function (s) { SOURCE[s.kind] = s; });
var UNREADABLE = {};
D.coverage.unreadable.forEach(function (u) { UNREADABLE[u.criterion] = u; });
var GROUP_OF = {};
D.columns.forEach(function (g) { g.criteria.forEach(function (c) { GROUP_OF[c] = g; }); });

var AGENTS = D.agents;
var AGENT = new Map();
AGENTS.forEach(function (a, i) {
  a.order = i;
  a.findings = [];
  a.codes = {};
  var hay = [a.id, a.name, a.owner, a.purpose, a.ref, a.observedOwner ? a.observedOwner.ref : null].concat(a.via);
  a.hay = hay.filter(function (x) { return typeof x === 'string'; }).join(' ').toLowerCase();
  a.evidence = {};
  for (var k = 0; k + 1 < a.ev.length; k += 2) a.evidence[a.ev[k]] = D.evidence[a.ev[k + 1]];
  AGENT.set(a.id, a);
});
D.findings.forEach(function (f, i) {
  f.order = i;
  if (typeof f.ref !== 'string') f.ref = f.code + ':' + (f.agent === null ? '' : f.agent);
  var a = f.agent === null ? undefined : AGENT.get(f.agent);
  if (a) { a.findings.push(f); a.codes[f.code] = true; }
});
var stateOf = function (a, i) { return STATES[Number(a.cells.charAt(i))] || STATES[STATES.length - 2]; };
var payState = function (a) { return a.pay === null ? 'NOT_REPORTED' : a.pay.length > 0 ? 'CAN_PAY' : 'NONE_SEEN'; };
var payingKnown = D.estate.paying !== null;
var identitiesKnown = D.estate.identities !== null;
var incomplete = D.sources.filter(function (s) { return s.status !== 'COMPLETE'; });

// ── The drawer ──
var drawerBack = el('div', { cls: 'drawer-back', hidden: true });
var drawerTitle = el('h2', { id: 'drawer-h' });
var drawerBody = el('div', { cls: 'drawer-body' });
var drawerClose = button('Close', 'btn', function () { closeDrawer(); }, { 'aria-label': 'Close the details' });
var drawer = el('aside', { cls: 'drawer', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'drawer-h', hidden: true, tabindex: '-1' }, [
  el('div', { cls: 'drawer-head' }, [drawerTitle, drawerClose]),
  drawerBody,
]);
var returnFocus = null;
drawerBack.addEventListener('click', function () { closeDrawer(); });
drawer.addEventListener('keydown', function (ev) {
  if (ev.key === 'Escape') { ev.preventDefault(); closeDrawer(); return; }
  if (ev.key !== 'Tab') return;
  var focusable = drawer.querySelectorAll('button, a[href], select, input, [tabindex="0"]');
  if (focusable.length === 0) return;
  var first = focusable[0];
  var last = focusable[focusable.length - 1];
  if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
  else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
});
function openDrawer(title, body) {
  if (drawer.hidden) returnFocus = document.activeElement;
  drawerTitle.textContent = title;
  drawerBody.textContent = '';
  add(drawerBody, body);
  drawerBack.hidden = false;
  drawer.hidden = false;
  document.body.classList.add('drawer-open');
  drawer.scrollTop = 0;
  drawerClose.focus();
}
function closeDrawer() {
  drawer.hidden = true;
  drawerBack.hidden = true;
  document.body.classList.remove('drawer-open');
  if (returnFocus && document.contains(returnFocus)) returnFocus.focus();
  returnFocus = null;
}

function evidenceNode(e) {
  if (!e) return el('span', { cls: 'muted' }, 'No evidence reference');
  var node = typeof e.h === 'string' && e.h.indexOf('https://') === 0
    ? el('a', { href: e.h, rel: 'noopener noreferrer', target: '_blank', cls: 'ev' }, e.t)
    : el('code', { cls: 'ev' }, e.t);
  if (!e.r) return node;
  return el('span', null, [node, el('span', { cls: 'note' }, ' User information in the reference was replaced by ***.')]);
}
function reasonList(codes) {
  return el('ul', { cls: 'reasons' }, codes.map(function (c) { return el('li', null, [word(T.reasons, c, 'See the code') + '. ', code(c)]); }));
}
function standingNode(a) {
  if (a.standing === 'NOT_JUDGED') return tag('Not judged', 'warn');
  if (a.standing === 'NO_BAR') return tag(T.standing.NO_BAR, 'plain');
  return tag(T.standing[a.standing], a.standing === 'BELOW_BAR' ? 'bad' : 'ok');
}
function levelNode(a) {
  if (!a.judged) return tag('Not judged', 'warn');
  return el('span', null, [el('strong', null, a.level), ' ' + word(LEVEL_NAME, a.level, ''),
    a.observed !== a.level ? el('span', { cls: 'decl block' }, a.observed + ' on observation alone; the rest is declared by the operator') : null]);
}
function badges(a) {
  var out = [];
  if (a.cls === 'SHADOW_AGENT') out.push(tag('Shadow agent', 'warn'));
  if (a.cls === 'UNREGISTERED_IDENTITY') out.push(tag('Unregistered identity', 'plain'));
  if (a.pay !== null && a.pay.length > 0) out.push(tag('Can pay', 'warn'));
  return out;
}
function agentTitle(a) { return a.name === null ? a.id : a.name; }
function sevTag(s) { return tag(word(T.severity, s, s), 'sev-' + String(s).toLowerCase()); }

function cellSection(a, i) {
  var c = CRITERIA[i];
  var s = stateOf(a, i);
  var basis = a.basis.charAt(i);
  var g = GROUP_OF[c];
  var u = UNREADABLE[c];
  return el('div', { cls: 'cell-detail' }, [
    el('dl', { cls: 'kv' }, [
      el('dt', null, 'Criterion'), el('dd', null, [code(c), g ? ' (required from ' + levelText(g.level) + ')' : '']),
      el('dt', null, 'State'), el('dd', null, [el('span', { cls: 'cell inline ' + s.cls, 'aria-hidden': 'true' }, s.code), ' ' + s.text]),
      el('dt', null, 'Basis'), el('dd', null, basis === 'O' ? T.basis.OBSERVED : basis === 'D' ? T.basis.DECLARED : 'No verdict was reported'),
      el('dt', null, 'Evidence'), el('dd', null, basis === '-' ? el('span', { cls: 'muted' }, 'None: no verdict') : evidenceNode(a.evidence[i])),
      u ? el('dt', null, 'Why not readable') : null,
      u ? el('dd', null, [word(T.unreadable, u.why, 'See the code') + ' ', code(u.why), u.readers.length > 0 ? el('span', { cls: 'block' }, ['Readers that would: ', u.readers.join(', ')]) : null]) : null,
    ]),
  ]);
}

function showCell(a, i) {
  openDrawer(CRITERIA[i], [
    el('p', { cls: 'muted' }, ['For ', idCode(a.id), a.name === null ? '' : ' (' + a.name + ', name declared by the operator)']),
    cellSection(a, i),
    el('p', null, button('Show everything about this agent', 'btn', function () { showAgent(a); })),
  ]);
}

function showAgent(a) {
  var via = a.via.map(function (k, n) {
    var s = SOURCE[k];
    return el('span', null, [n > 0 ? ', ' : '', code(k), s ? (s.status === 'COMPLETE' ? ' (read in full)' : ' (not read in full: ' + (s.reason || 'no reason given') + ')') : ' (not listed as a source)']);
  });
  var counts = a.counts;
  var signs = a.signs === null ? 'Not recorded in this results file'
    : a.signs.length === 0 ? 'None: nothing the scan read shows that it runs a model'
    : a.signs.map(function (s) { return word(T.signs, s, s); }).join('; ');
  var pay = a.pay === null ? 'Not reported'
    : a.pay.length === 0 ? 'Code was read and no payment client was seen in the agent’s own file. That is not evidence that it cannot pay.'
    : el('ul', { cls: 'plain-list' }, a.pay.map(function (p) { return el('li', null, [code(p.library), ' (' + p.protocol + ') at ', idCode(p.at)]); }));
  var bar = a.standing === 'NO_BAR'
    ? 'Held to no bar: an unregistered automated identity. Against the bar its reach would carry (' + a.bar + '), its level is ' + (a.barStatus === 'BELOW_BAR' ? 'below it' : 'at it') + '.'
    : a.standing === 'NOT_JUDGED' ? 'Its bar is ' + a.bar + '. No level is stated, so it is not compared with the bar.'
    : 'Its bar is ' + a.bar + ', and it is ' + (a.standing === 'BELOW_BAR' ? 'below it' : 'at it') + '.';
  var rows = D.columns.map(function (g) {
    return el('tbody', null, [
      el('tr', null, el('th', { scope: 'colgroup', colspan: '4', cls: 'group' }, levelText(g.level))),
      g.criteria.map(function (c) {
        var i = CRITERIA.indexOf(c);
        var s = stateOf(a, i);
        var basis = a.basis.charAt(i);
        return el('tr', null, [
          el('th', { scope: 'row' }, code(c)),
          el('td', null, [el('span', { cls: 'cell inline ' + s.cls, 'aria-hidden': 'true' }, s.code), ' ' + s.label]),
          el('td', null, basis === 'O' ? 'Observed' : basis === 'D' ? 'Declared' : '–'),
          el('td', null, basis === '-' ? '' : evidenceNode(a.evidence[i])),
        ]);
      }),
    ]);
  });
  openDrawer(agentTitle(a), [
    el('p', null, [idCode(a.id), a.name === null ? null : el('span', { cls: 'decl' }, ' (name declared by the operator)')]),
    el('p', { cls: 'tags' }, [tag(word(T.classification, a.cls, a.cls), a.cls === 'REGISTERED' ? 'ok' : a.cls === 'SHADOW_AGENT' ? 'warn' : 'plain'), ' ', standingNode(a)].concat(a.pay && a.pay.length > 0 ? [' ', tag('Can pay', 'warn')] : [])),
    !a.judged ? el('div', { cls: 'callout bad' }, [el('p', null, el('strong', null, 'Not judged: no level is stated for this agent.')), reasonList(a.notes)]) : null,
    a.judged && a.notes.length > 0 ? el('div', { cls: 'callout' }, [el('p', null, 'Judged, with a caveat:'), reasonList(a.notes)]) : null,
    el('dl', { cls: 'kv' }, [
      el('dt', null, 'Registration'), el('dd', null, [word(T.registration, a.reg, 'Not stated'), a.ref === null ? '' : el('span', { cls: 'block' }, idCode(a.ref))]),
      el('dt', null, 'Reach'), el('dd', null, word(T.reach, a.reach, 'Unknown')),
      el('dt', null, 'Found through'), el('dd', null, via),
      a.owner !== null ? el('dt', null, 'Owner (declared)') : null, a.owner !== null ? el('dd', null, [a.owner, el('span', { cls: 'decl' }, ' declared by the operator')]) : null,
      a.purpose !== null ? el('dt', null, 'Purpose (declared)') : null, a.purpose !== null ? el('dd', null, [a.purpose, el('span', { cls: 'decl' }, ' declared by the operator')]) : null,
      el('dt', null, 'Owner (observed)'), el('dd', null, a.observedOwner === null ? 'None read from the estate' : [a.observedOwner.kind + ' ', idCode(a.observedOwner.ref)]),
      el('dt', null, 'Level'), el('dd', null, levelNode(a)),
      el('dt', null, 'Bar'), el('dd', null, bar),
      a.blocking !== null && a.blocking.length > 0 ? el('dt', null, 'Between it and the next rung') : null,
      a.blocking !== null && a.blocking.length > 0 ? el('dd', null, a.blocking.map(function (c, n) { return el('span', null, [n > 0 ? ', ' : '', code(c)]); })) : null,
      el('dt', null, 'Credentials, tools'), el('dd', null, counts[0] + ' credentials; ' + counts[1] + ' tools, ' + counts[2] + ' that can write, ' + counts[3] + ' of those not pinned'),
      el('dt', null, 'Models'), el('dd', null, counts[4] === null ? 'Not reported' : plural(counts[4], 'model endpoint', 'model endpoints')),
      el('dt', null, 'Signs of a model'), el('dd', null, signs),
      el('dt', null, 'Payment'), el('dd', null, pay),
    ]),
    el('h3', null, 'Criteria'),
    el('div', { cls: 'scroll' }, el('table', { cls: 'crit-table' }, [
      el('caption', null, 'Every criterion of the ladder for this agent, by the level that first requires it'),
      el('thead', null, el('tr', null, [el('th', { scope: 'col' }, 'Criterion'), el('th', { scope: 'col' }, 'State'), el('th', { scope: 'col' }, 'Basis'), el('th', { scope: 'col' }, 'Evidence')])),
    ].concat(rows))),
    el('h3', null, 'Findings'),
    a.findings.length === 0 ? el('p', null, 'None about this agent.') : el('ul', { cls: 'plain-list' }, a.findings.map(function (f) {
      return el('li', null, [sevTag(f.severity), ' ', code(f.code), ' ', f.title,
        f.description === null ? el('p', { cls: 'note' }, 'The description is in ' + D.files.findings + '.') : el('details', null, [el('summary', null, 'Description'), el('p', null, f.description), el('p', { cls: 'note' }, ['Reference ', idCode(f.ref)])])]);
    })),
  ]);
}

// ── Filters and order: what the table shows ──
var F = { q: '', level: '', standing: '', cls: '', source: '', code: '', pay: '', criterion: '', state: '', sort: 'model', page: 0, size: 50 };
var shown = AGENTS.slice();
function matches(a) {
  if (F.q !== '' && a.hay.indexOf(F.q) < 0) return false;
  if (F.level !== '' && (F.level === 'none' ? a.judged : a.level !== F.level)) return false;
  if (F.standing !== '' && a.standing !== F.standing) return false;
  if (F.cls !== '' && a.cls !== F.cls) return false;
  if (F.source !== '' && a.via.indexOf(F.source) < 0) return false;
  if (F.code !== '' && !a.codes[F.code]) return false;
  if (F.pay !== '' && payState(a) !== F.pay) return false;
  if (F.state !== '') {
    var target = String(STATES.map(function (s) { return s.state; }).indexOf(F.state));
    if (F.criterion !== '') { if (a.cells.charAt(CRITERIA.indexOf(F.criterion)) !== target) return false; }
    else if (a.cells.indexOf(target) < 0) return false;
  }
  return true;
}
var ORDER = {
  model: function (a, b) { return a.order - b.order; },
  id: function (a, b) { return byCodeUnit(a.id, b.id); },
  name: function (a, b) { return byCodeUnit(agentTitle(a).toLowerCase(), agentTitle(b).toLowerCase()) || byCodeUnit(a.id, b.id); },
  'level-asc': function (a, b) { return (a.judged ? rung(a.level) + 1 : 0) - (b.judged ? rung(b.level) + 1 : 0) || a.order - b.order; },
  'level-desc': function (a, b) { return (b.judged ? rung(b.level) + 1 : 0) - (a.judged ? rung(a.level) + 1 : 0) || a.order - b.order; },
};
function refilter() {
  shown = AGENTS.filter(matches).sort(ORDER[F.sort] || ORDER.model);
  var pages = Math.max(1, Math.ceil(shown.length / F.size));
  if (F.page >= pages) F.page = pages - 1;
  drawMatrix();
}

// ── The overview ──
function overview() {
  var e = D.estate;
  var band = el('section', { id: 'd-overview', 'aria-labelledby': 'd-overview-h', cls: 'd-section' }, el('h2', { id: 'd-overview-h' }, 'Overview'));
  if (D.sources.length === 0) {
    band.appendChild(el('div', { cls: 'callout bad' }, el('p', null, [el('strong', null, D.say.status.strong), ' ' + D.say.status.rest])));
  } else if (incomplete.length > 0) {
    band.appendChild(el('div', { cls: 'callout bad' }, [
      el('p', null, [el('strong', null, 'Read this first: ' + incomplete.length + ' of ' + plural(D.sources.length, 'source was', 'sources were') + ' not read in full.'),
        ' A source that was not read in full may hold agents, tools and verdicts this page does not show. Nothing here is shown as gone, closed or resolved on a partial read.']),
      el('ul', { cls: 'plain-list' }, incomplete.map(function (s) {
        return el('li', null, [code(s.kind), ' ', tag('Incomplete', 'bad'), ' ', s.reason === null ? '' : code(s.reason), s.detail === null ? '' : ': ' + s.detail]);
      })),
      e.notJudgedCount > 0 ? el('p', null, plural(e.notJudgedCount, 'agent is', 'agents are') + ' not judged for that reason and ' + (e.notJudgedCount === 1 ? 'has' : 'have') + ' no level here.') : null,
    ]));
  } else {
    band.appendChild(el('p', { cls: 'status ' + D.say.status.tone }, [el('strong', null, D.say.status.strong), ' ' + D.say.status.rest]));
  }
  if (D.say.empty !== null) {
    band.appendChild(el('div', { cls: 'callout bad' }, D.say.empty.map(function (line, n) { return el('p', null, n === 0 ? el('strong', null, line) : line); })));
  }
  var judgedHeld = AGENTS.filter(function (a) { return a.judged && a.standing !== 'NO_BAR'; }).length;
  var reach = D.coverage.reachable;
  var hero = el('div', { cls: 'hero' }, [
    el('div', { cls: 'hero-main' }, [
      el('p', { cls: 'eyebrow' }, 'Agent estate, as of ' + D.scan.asOf + ' UTC'),
      D.completeness === 'EMPTY' ? el('p', { cls: 'hero-big bad-text' }, 'No agents found')
        : el('p', { cls: 'hero-big' + (e.shortfallCount > 0 ? ' bad-text' : '') }, [el('span', { cls: 'hero-num' }, String(e.shortfallCount)), ' below their bar']),
      D.completeness === 'EMPTY' ? null : el('p', { cls: 'muted' }, 'of ' + plural(judgedHeld, 'judged agent', 'judged agents') + ' held to a bar. ' + plural(e.notJudgedCount, 'agent is', 'agents are') + ' not judged and have no level.'),
      el('p', { cls: 'muted small' }, ['The highest level this run could have stated for any agent is ', el('strong', null, levelText(reach)),
        '. The bar is ' + D.bars.readOnly + ' for an agent that only reads and ' + D.bars.write + ' for one that can write or reach outside the estate.']),
    ]),
    ladder(),
  ]);
  band.appendChild(hero);
  var tiles = el('div', { cls: 'tiles', role: 'group', 'aria-label': 'Counts over the whole scan. Each one filters the table.' });
  function tile(label, value, note, onClick, tone) {
    tiles.appendChild(button([el('span', { cls: 'tile-num' }, String(value)), el('span', { cls: 'tile-label' }, label), note ? el('span', { cls: 'tile-note' }, note) : null], 'tile' + (tone ? ' ' + tone : ''), onClick));
  }
  var go = function (target) { return function () { var t = document.getElementById(target); if (t) t.scrollIntoView(); }; };
  var filterTo = function (patch) { return function () { setFilters(patch); go('d-matrix')(); }; };
  tile('Agents found', e.agentCount, identitiesKnown && e.identities.length > 0 ? 'agents and automated identities' : '', filterTo({}), '');
  tile('Not judged', e.notJudgedCount, 'no level stated', filterTo({ standing: 'NOT_JUDGED' }), e.notJudgedCount > 0 ? 'warn' : '');
  tile('Below their bar', e.shortfallCount, identitiesKnown ? 'of the judged agents held to a bar' : 'of the judged agents', filterTo({ standing: 'BELOW_BAR' }), e.shortfallCount > 0 ? 'bad' : '');
  tile('Shadow agents', e.shadow.length, identitiesKnown ? 'not registered, with a sign of a model' : 'not registered', filterTo({ cls: 'SHADOW_AGENT' }), e.shadow.length > 0 ? 'warn' : '');
  if (identitiesKnown) tile('Unregistered identities', e.identities.length, 'no sign of a model; held to no bar', filterTo({ cls: 'UNREGISTERED_IDENTITY' }), '');
  tile('Orphan credentials', e.orphans.length, 'bound to no agent', go('orphans'), e.orphans.length > 0 ? 'warn' : '');
  if (payingKnown) tile('Can pay', e.paying.length, 'code calls a payment client', filterTo({ pay: 'CAN_PAY' }), e.paying.length > 0 ? 'warn' : '');
  tile('Sources incomplete', incomplete.length + ' of ' + D.sources.length, 'see completeness', go('completeness'), incomplete.length > 0 || D.sources.length === 0 ? 'bad' : '');
  tile('Findings', D.findings.length, 'most severe first', go('d-findings'), '');
  band.appendChild(tiles);
  band.appendChild(el('p', { cls: 'muted small' }, 'Registration is taken from: ' + e.registration + '.'));
  return band;
}

function ladder() {
  var e = D.estate;
  var max = 1;
  LEVELS.forEach(function (l) { max = Math.max(max, e.byLevel[l] || 0); });
  var list = el('ul', { cls: 'ladder', 'aria-label': 'Judged agents per level' });
  LEVELS.slice().reverse().forEach(function (l) {
    var n = e.byLevel[l] || 0;
    var meter = el('span', { cls: 'meter' }, el('span', { cls: 'meter-fill' + (rung(l) > rung(D.coverage.reachable) ? ' out' : '') }));
    meter.firstChild.style.width = (n / max * 100).toFixed(1) + '%';
    list.appendChild(el('li', null, button([el('span', { cls: 'ladder-level' }, levelText(l)), meter, el('span', { cls: 'ladder-n' }, String(n))], 'ladder-row', function () { setFilters({ level: l }); var t = document.getElementById('d-matrix'); if (t) t.scrollIntoView(); }, { 'aria-label': levelText(l) + ': ' + plural(n, 'agent', 'agents') + '. Show them in the table.' })));
  });
  list.appendChild(el('li', null, button([el('span', { cls: 'ladder-level' }, 'Not judged'), el('span', { cls: 'meter' }), el('span', { cls: 'ladder-n' }, String(e.notJudgedCount))], 'ladder-row', function () { setFilters({ level: 'none' }); var t = document.getElementById('d-matrix'); if (t) t.scrollIntoView(); }, { 'aria-label': 'Not judged: ' + plural(e.notJudgedCount, 'agent', 'agents') + '. Show them in the table.' })));
  return list;
}

// ── Charts ──
function card(id, title, kids) {
  return el('section', { cls: 'card', id: id, 'aria-labelledby': id + '-h' }, [el('h3', { id: id + '-h' }, title)].concat(kids));
}
function focusableBar(g, label, onActivate) {
  g.setAttribute('tabindex', '0');
  g.setAttribute('role', 'button');
  g.setAttribute('aria-label', label);
  g.setAttribute('class', 'ch-hit');
  g.addEventListener('click', onActivate);
  g.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onActivate(); } });
  var t = sv('title');
  t.textContent = label;
  g.appendChild(t);
  return g;
}
function levelChart() {
  var e = D.estate;
  var cats = LEVELS.map(function (l) { return { key: l, label: l, n: e.byLevel[l] || 0, cls: rung(l) > rung(D.coverage.reachable) ? 'ch-bar out' : 'ch-bar' }; });
  cats.push({ key: 'none', label: 'NJ', n: e.notJudgedCount, cls: 'ch-bar nj' });
  var W = 360, H = 200, left = 34, bottom = 40, top = 18, gap = 8;
  var bw = (W - left - 8 - gap * (cats.length - 1)) / cats.length;
  var max = 1;
  cats.forEach(function (c) { max = Math.max(max, c.n); });
  var kids = [];
  // Whole numbers only, each once: as many ticks as there are values up to four.
  var ticks = Math.min(4, max);
  max = Math.ceil(max / ticks) * ticks;
  for (var t = 0; t <= ticks; t++) {
    var y = top + (H - top - bottom) * (1 - t / ticks);
    kids.push(sv('line', { x1: left, x2: W - 4, y1: y, y2: y, 'class': 'ch-grid' }));
    kids.push(svgText(left - 6, y + 4, String(max * t / ticks), 'ch-axis', 'end'));
  }
  var reachX = null;
  cats.forEach(function (c, i) {
    var x = left + i * (bw + gap);
    var h = (H - top - bottom) * (c.n / max);
    var g = sv('g');
    g.appendChild(sv('rect', { x: x, y: H - bottom - h, width: bw, height: Math.max(h, c.n > 0 ? 1 : 0), rx: 2, 'class': c.cls }));
    g.appendChild(svgText(x + bw / 2, H - bottom - h - 4, String(c.n), 'ch-value'));
    g.appendChild(svgText(x + bw / 2, H - bottom + 14, c.label, 'ch-axis'));
    if (c.key === D.bars.readOnly) g.appendChild(svgText(x + bw / 2, H - bottom + 28, 'read bar', 'ch-mark'));
    if (c.key === D.bars.write) g.appendChild(svgText(x + bw / 2, H - bottom + 28, 'write bar', 'ch-mark'));
    var name = c.key === 'none' ? 'Not judged' : levelText(c.key);
    kids.push(focusableBar(g, name + ': ' + plural(c.n, 'agent', 'agents') + (c.cls.indexOf('out') >= 0 ? ', above what this run could state' : '') + '. Show them in the table.', function () { setFilters({ level: c.key }); var m = document.getElementById('d-matrix'); if (m) m.scrollIntoView(); }));
    if (c.key === D.coverage.reachable) reachX = x + bw + gap / 2;
  });
  if (reachX !== null && rung(D.coverage.reachable) < LEVELS.length - 1) {
    kids.push(sv('line', { x1: reachX, x2: reachX, y1: top - 8, y2: H - bottom, 'class': 'ch-reach' }));
    kids.push(svgText(reachX + 3, top - 8, 'beyond this run', 'ch-mark', 'start'));
  }
  var svgEl = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'chart', role: 'group', 'aria-label': 'Judged agents per level, and those not judged' }, kids);
  return card('d-levels', 'Levels across the estate', [
    svgEl,
    el('p', { cls: 'note' }, 'Judged agents per level. NJ is not judged: no level is stated. A level to the right of the dashed line could not have been stated by this run, so an empty bar there says nothing about the agents. Select a bar to filter the table.'),
  ]);
}
function severityChart() {
  var counts = {};
  D.findings.forEach(function (f) { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  var sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  var max = 1;
  sevs.forEach(function (s) { max = Math.max(max, counts[s] || 0); });
  var W = 360, rowH = 34, left = 70, H = rowH * sevs.length + 8;
  var kids = [];
  sevs.forEach(function (s, i) {
    var n = counts[s] || 0;
    var y = 6 + i * rowH;
    var w = (W - left - 46) * n / max;
    var g = sv('g');
    g.appendChild(svgText(left - 8, y + 18, word(T.severity, s, s), 'ch-axis', 'end'));
    g.appendChild(sv('rect', { x: left, y: y + 4, width: Math.max(w, n > 0 ? 1 : 0), height: rowH - 12, rx: 2, 'class': 'ch-bar sev-' + s.toLowerCase() }));
    g.appendChild(svgText(left + w + 6, y + 18, String(n), 'ch-value', 'start'));
    kids.push(focusableBar(g, word(T.severity, s, s) + ': ' + plural(n, 'finding', 'findings') + '. Show them in the findings table.', function () { setFindingFilters({ severity: s }); var t = document.getElementById('d-findings'); if (t) t.scrollIntoView(); }));
  });
  return card('d-severity', 'Findings by severity', [
    sv('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'chart', role: 'group', 'aria-label': 'Findings by severity' }, kids),
    el('p', { cls: 'note' }, D.say.noFindings !== null ? D.say.noFindings : plural(D.findings.length, 'finding', 'findings') + ' in all. Select a bar to filter the findings.'),
  ]);
}
function coverageCard() {
  var max = 1;
  D.sources.forEach(function (s) { max = Math.max(max, s.agents); });
  var ordered = incomplete.concat(D.sources.filter(function (s) { return s.status === 'COMPLETE'; }));
  var readable = CRITERIA.length - D.coverage.unreadable.length;
  var list = el('ul', { cls: 'sources' }, ordered.map(function (s) {
    var meter = el('span', { cls: 'meter' }, el('span', { cls: 'meter-fill' + (s.status === 'COMPLETE' ? '' : ' bad') }));
    meter.firstChild.style.width = (s.agents / max * 100).toFixed(1) + '%';
    return el('li', null, [
      el('span', { cls: 'src-kind' }, [code(s.kind), ' ', s.status === 'COMPLETE' ? tag('Complete', 'ok') : tag('Incomplete', 'bad')]),
      meter,
      el('span', { cls: 'src-n' }, plural(s.agents, 'agent', 'agents') + ', ' + plural(s.rows, 'row', 'rows') + ' read' + (s.reason === null ? '' : ' (' + s.reason + ')')),
    ]);
  }));
  return card('d-coverage', 'Coverage per source', [
    D.sources.length === 0 ? el('p', { cls: 'callout bad' }, D.say.status.strong + ' ' + D.say.status.rest) : list,
    el('p', { cls: 'note' }, readable + ' of ' + CRITERIA.length + ' criteria had a reader this run configured. The highest level it could have stated is ' + levelText(D.coverage.reachable) + '. Not readable is not the same as unanswered.'),
  ]);
}

// ── Since the previous run ──
function driftSection() {
  var d = D.drift;
  if (d === null) return null;
  var s = el('section', { id: 'd-drift', cls: 'd-section', 'aria-labelledby': 'd-drift-h' }, el('h2', { id: 'd-drift-h' }, 'Since the previous run'));
  if (d.kind === 'FIRST') { s.appendChild(el('p', null, 'This output directory held no earlier run, so there is nothing to compare with.')); return s; }
  if (d.kind === 'NOT_COMPARED') { s.appendChild(el('div', { cls: 'callout' }, el('p', null, ['Not compared with ', d.scanId === null ? 'the previous run' : idCode(d.scanId), ': ' + d.text + '.']))); return s; }
  s.appendChild(el('p', null, ['Compared with ', idCode(d.old.scanId), ', as of ' + d.old.asOf + ' UTC (' + (d.old.complete ? 'complete' : 'incomplete') + ', ' + plural(d.old.agentCount, 'agent', 'agents') + '). ', el('strong', null, d.outcomeText)]));
  s.appendChild(el('p', { cls: 'muted' }, plural(d.differences, 'difference', 'differences') + '; ' + plural(d.notConcludedCount, 'comparison', 'comparisons') + ' not concluded. The full comparison: scanent diff on the two results files.'));
  if (d.warnings.length > 0) s.appendChild(el('div', { cls: 'callout' }, el('ul', { cls: 'plain-list' }, d.warnings.map(function (w) { return el('li', null, [code(w.code), ': ' + w.text + '.']); }))));
  function list(title, part, line, none) {
    var kids = [el('h3', null, title + ' (' + part.total + ')')];
    if (part.total === 0) kids.push(el('p', { cls: 'muted' }, none));
    else {
      kids.push(el('ul', { cls: 'plain-list' }, part.rows.map(line)));
      if (part.total > part.rows.length) kids.push(el('p', { cls: 'note' }, 'The first ' + part.rows.length + ' of ' + part.total + '.'));
    }
    return el('div', { cls: 'drift-col' }, kids);
  }
  var agentLink = function (id) { var a = AGENT.get(id); return a ? button(id, 'linkish', function () { showAgent(a); }) : idCode(id); };
  var grid = el('div', { cls: 'drift-grid' }, [
    list('Levels', d.levels, function (l) { return el('li', null, [agentLink(l.id), ': ' + l.text + (l.from !== null && l.to !== null ? ', ' + l.from + ' to ' + l.to : '')]); }, 'No level changed where both runs judged the agent.'),
    list('New agents', d.added, function (id) { return el('li', null, agentLink(id)); }, 'None.'),
    list('Gone', d.gone, function (id) { return el('li', null, [idCode(id), ' (every source it was found through was read in full)']); }, 'None concluded gone.'),
    list('Not seen, not concluded', d.notSeen, function (x) { return el('li', null, [idCode(x.id), ': ' + x.why]); }, 'None.'),
    list('Completeness', { total: d.sources.length, rows: d.sources }, function (x) { return el('li', null, [code(x.kind), ' ' + x.text + (x.from !== null || x.to !== null ? ' (' + (x.from || '-') + ' to ' + (x.to || '-') + ')' : '')]); }, 'No source changed.'),
    list('Findings', d.findings, function (f) { return el('li', null, [code(f.code), ' ' + (f.change === 'NOT_CONCLUDED' ? 'no longer reported, not concluded (' + (f.why || 'UNKNOWN') + ')' : f.change.toLowerCase()) + ' ', idCode(f.ref)]); }, 'No finding opened or closed.'),
  ]);
  s.appendChild(grid);
  return s;
}

// ── The matrix ──
var tableHost = el('div', { cls: 'scroll matrix', role: 'region', 'aria-labelledby': 'd-matrix-h', tabindex: '0' });
var countLine = el('p', { cls: 'count', 'aria-live': 'polite' });
var pager = el('div', { cls: 'pager' });
var controls = {};

function select(name, label, options) {
  var s = el('select', null, options.map(function (o) { return option(o[0], o[1], F[name] === o[0]); }));
  s.addEventListener('change', function () { F[name] = s.value; F.page = 0; refilter(); });
  controls[name] = s;
  return labelled(label, s);
}
function setFilters(patch) {
  ['q', 'level', 'standing', 'cls', 'source', 'code', 'pay', 'criterion', 'state'].forEach(function (k) { F[k] = has(patch, k) ? patch[k] : ''; });
  F.page = 0;
  for (var k in controls) if (has(controls, k)) controls[k].value = k === 'q' ? F.q : F[k];
  refilter();
}

function matrixSection() {
  var s = el('section', { id: 'd-matrix', cls: 'd-section', 'aria-labelledby': 'd-matrix-h' }, [
    el('h2', { id: 'd-matrix-h' }, 'Agents and criteria'),
    el('p', null, 'An agent reaches a level only when every criterion on it and below it is evidenced. A level is stated only for an agent every relevant source was read in full for. The rows start with the agents that most need a reader: not judged, then below their bar, then the lowest levels.'),
  ]);
  var search = el('input', { type: 'search', placeholder: 'Id, name, owner, purpose or source', autocomplete: 'off', spellcheck: 'false' });
  search.addEventListener('input', function () { F.q = search.value.trim().toLowerCase(); F.page = 0; refilter(); });
  controls.q = search;
  var codes = {};
  D.findings.forEach(function (f) { if (f.agent !== null) codes[f.code] = (codes[f.code] || 0) + 1; });
  var kinds = {};
  AGENTS.forEach(function (a) { a.via.forEach(function (k) { kinds[k] = true; }); });
  var tools = el('div', { cls: 'toolbar', role: 'search', 'aria-label': 'Filter the agents' }, [
    labelled('Search', search),
    select('level', 'Level', [['', 'Any level']].concat(LEVELS.map(function (l) { return [l, levelText(l)]; })).concat([['none', 'Not judged']])),
    select('standing', 'Against the bar', [['', 'Any'], ['BELOW_BAR', T.standing.BELOW_BAR], ['AT_BAR', T.standing.AT_BAR], ['NO_BAR', T.standing.NO_BAR], ['NOT_JUDGED', T.standing.NOT_JUDGED]]),
    select('cls', 'Classification', [['', 'Any'], ['REGISTERED', T.classification.REGISTERED], ['SHADOW_AGENT', T.classification.SHADOW_AGENT], ['UNREGISTERED_IDENTITY', T.classification.UNREGISTERED_IDENTITY]]),
    select('source', 'Found through', [['', 'Any source']].concat(Object.keys(kinds).sort(byCodeUnit).map(function (k) { return [k, k]; }))),
    select('code', 'Finding', [['', 'Any finding']].concat(Object.keys(codes).sort(byCodeUnit).map(function (c) { return [c, c + ' (' + codes[c] + ')']; }))),
    select('pay', 'Payment', [['', 'Any'], ['CAN_PAY', 'Code calls a payment client'], ['NONE_SEEN', 'None seen'], ['NOT_REPORTED', 'Not reported']]),
    select('criterion', 'Criterion', [['', 'Any criterion']].concat(CRITERIA.map(function (c) { return [c, c]; }))),
    select('state', 'Cell state', [['', 'Any state']].concat(STATES.map(function (st) { return [st.state, st.code + ' ' + st.label]; }))),
    select('sort', 'Order', [['model', 'Most in need of a reader first'], ['level-asc', 'Lowest level first'], ['level-desc', 'Highest level first'], ['id', 'Id, A to Z'], ['name', 'Name, A to Z']]),
    el('div', { cls: 'field' }, [el('span', { cls: 'label-spacer', 'aria-hidden': 'true' }, ' '), button('Clear filters', 'btn', function () { setFilters({}); })]),
  ]);
  s.appendChild(tools);
  s.appendChild(el('ul', { cls: 'legend', 'aria-label': 'What each cell code means' }, STATES.map(function (st) { return el('li', null, [el('span', { cls: 'cell ' + st.cls, 'aria-hidden': 'true' }, st.code), ' ' + st.text]); })));
  s.appendChild(el('p', { cls: 'note' }, 'Select an agent for everything about it, or a cell for its evidence. In the table, the arrow keys move between cells.'));
  s.appendChild(countLine);
  s.appendChild(tableHost);
  s.appendChild(pager);
  return s;
}

function matrixHead() {
  var top = el('tr', null, [
    el('th', { scope: 'col', rowspan: '2', cls: 'agent' }, 'Agent'),
    el('th', { scope: 'col', rowspan: '2' }, 'Registration'),
    el('th', { scope: 'col', rowspan: '2' }, 'Reach'),
    el('th', { scope: 'col', rowspan: '2' }, 'Level'),
    el('th', { scope: 'col', rowspan: '2' }, 'Bar'),
  ].concat(D.columns.map(function (g) { return el('th', { scope: 'colgroup', colspan: String(g.criteria.length), cls: 'group' }, levelText(g.level)); })));
  var second = el('tr', null, CRITERIA.map(function (c) { return el('th', { scope: 'col', cls: 'crit', title: c }, el('span', null, c.slice(c.indexOf('.') + 1).split('_').join(' '))); }));
  return el('thead', null, [top, second]);
}

function drawMatrix() {
  var total = AGENTS.length;
  var pages = Math.max(1, Math.ceil(shown.length / F.size));
  var from = F.page * F.size;
  var slice = shown.slice(from, from + F.size);
  countLine.textContent = shown.length === total
    ? 'Showing ' + (shown.length === 0 ? 0 : from + 1) + ' to ' + (from + slice.length) + ' of ' + plural(total, 'agent', 'agents') + '.'
    : 'Showing ' + (shown.length === 0 ? 0 : from + 1) + ' to ' + (from + slice.length) + ' of ' + shown.length + ' matching, out of ' + plural(total, 'agent', 'agents') + '.';
  var body = el('tbody');
  slice.forEach(function (a) {
    var name = a.name === null ? idCode(a.id) : el('span', null, [el('span', { cls: 'name' }, a.name), el('span', { cls: 'decl' }, ' (declared)'), el('br'), idCode(a.id)]);
    var open = button(name, 'agent-btn', function () { showAgent(a); }, { 'aria-label': agentTitle(a) + ': show everything about this agent', 'data-col': '-1' });
    var tr = el('tr', null, [
      el('th', { scope: 'row', cls: 'agent' }, [open, el('span', { cls: 'badges' }, badges(a)),
        !a.judged ? el('span', { cls: 'block note' }, a.notes.map(function (c) { return word(T.reasons, c, c); }).join('. ') + '.') : null]),
      el('td', null, word(T.registration, a.reg, 'Not stated')),
      el('td', null, word(T.reach, a.reach, 'Unknown')),
      el('td', { cls: 'lvl' }, levelNode(a)),
      el('td', { cls: 'lvl' }, [a.bar + ' ', standingNode(a)]),
    ]);
    for (var i = 0; i < CRITERIA.length; i++) {
      var st = stateOf(a, i);
      var b = el('button', { type: 'button', cls: 'cb', tabindex: '-1', 'data-col': String(i), 'aria-label': CRITERIA[i] + ': ' + st.text }, st.code);
      b.addEventListener('click', (function (agent, index) { return function () { showCell(agent, index); }; })(a, i));
      tr.appendChild(el('td', { cls: 'cell ' + st.cls }, b));
    }
    body.appendChild(tr);
  });
  var table = el('table', null, [el('caption', null, 'One row per agent, one column per criterion, grouped by the level that first requires it'), matrixHead(), body]);
  if (slice.length === 0) {
    tableHost.textContent = '';
    tableHost.appendChild(el('p', { cls: 'empty' }, 'No agent matches these filters.'));
  } else {
    tableHost.textContent = '';
    tableHost.appendChild(table);
  }
  pager.textContent = '';
  var size = el('select', null, [25, 50, 100, 250].map(function (n) { return option(String(n), String(n), n === F.size); }));
  size.addEventListener('change', function () { F.size = Number(size.value); F.page = 0; refilter(); });
  pager.appendChild(labelled('Rows per page', size));
  var prev = button('Previous page', 'btn', function () { if (F.page > 0) { F.page -= 1; drawMatrix(); } }, { disabled: F.page === 0 ? true : null });
  var next = button('Next page', 'btn', function () { if (F.page < pages - 1) { F.page += 1; drawMatrix(); } }, { disabled: F.page >= pages - 1 ? true : null });
  pager.appendChild(prev);
  pager.appendChild(el('span', { cls: 'page-of' }, 'Page ' + (F.page + 1) + ' of ' + pages));
  pager.appendChild(next);
}

tableHost.addEventListener('keydown', function (ev) {
  var t = ev.target;
  if (!t || !t.getAttribute || t.getAttribute('data-col') === null) return;
  var col = Number(t.getAttribute('data-col'));
  var row = t.closest('tr');
  var target = null;
  if (ev.key === 'ArrowRight') target = row.querySelector('[data-col="' + (col + 1) + '"]');
  else if (ev.key === 'ArrowLeft') target = row.querySelector('[data-col="' + (col - 1) + '"]');
  else if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
    var other = ev.key === 'ArrowDown' ? row.nextElementSibling : row.previousElementSibling;
    if (other) target = other.querySelector('[data-col="' + col + '"]');
  } else if (ev.key === 'Home') target = row.querySelector('[data-col="-1"]');
  else if (ev.key === 'End') target = row.querySelector('[data-col="' + (CRITERIA.length - 1) + '"]');
  if (target) { ev.preventDefault(); target.focus(); }
});

// ── A paged list: the shadow agents, the identities, the findings ──
function pagedList(opts) {
  var state = { page: 0, size: opts.size || 25 };
  var host = el('div');
  var counter = el('p', { cls: 'count', 'aria-live': 'polite' });
  var nav = el('div', { cls: 'pager' });
  function draw() {
    var items = opts.items();
    var pages = Math.max(1, Math.ceil(items.length / state.size));
    if (state.page >= pages) state.page = pages - 1;
    var from = state.page * state.size;
    var slice = items.slice(from, from + state.size);
    counter.textContent = items.length === 0 ? '' : 'Showing ' + (from + 1) + ' to ' + (from + slice.length) + ' of ' + items.length + '.';
    host.textContent = '';
    host.appendChild(items.length === 0 ? opts.empty() : el('div', { cls: 'scroll' }, el('table', { cls: opts.cls || '' }, [el('caption', null, opts.caption), el('thead', null, el('tr', null, opts.head.map(function (h) { return el('th', { scope: 'col' }, h); }))), el('tbody', null, slice.map(opts.row))])));
    nav.textContent = '';
    if (pages > 1) {
      nav.appendChild(button('Previous page', 'btn', function () { state.page -= 1; draw(); }, { disabled: state.page === 0 ? true : null }));
      nav.appendChild(el('span', { cls: 'page-of' }, 'Page ' + (state.page + 1) + ' of ' + pages));
      nav.appendChild(button('Next page', 'btn', function () { state.page += 1; draw(); }, { disabled: state.page >= pages - 1 ? true : null }));
    }
  }
  return { node: el('div', null, [counter, host, nav]), draw: function (reset) { if (reset) state.page = 0; draw(); } };
}

function agentButton(id) {
  var a = AGENT.get(id);
  return a ? button(idCode(id), 'linkish', function () { showAgent(a); }, { 'aria-label': id + ': show everything about this agent' }) : idCode(id);
}

function unregisteredSection() {
  var e = D.estate;
  var s = el('section', { id: 'd-shadow', cls: 'd-section', 'aria-labelledby': 'd-shadow-h' }, el('h2', { id: 'd-shadow-h' }, 'Shadow agents and unregistered identities'));
  function block(title, ids, intro, noneText, caption) {
    var list = pagedList({
      items: function () { return ids.map(function (id) { return AGENT.get(id); }).filter(function (a) { return a !== undefined; }); },
      caption: caption,
      head: ['Agent', 'Found through', 'Reach', 'Credentials'],
      row: function (a) { return el('tr', null, [el('th', { scope: 'row' }, agentButton(a.id)), el('td', null, a.via.join(', ')), el('td', null, word(T.reach, a.reach, 'Unknown')), el('td', { cls: 'num' }, String(a.counts[0]))]); },
      empty: function () { return el('p', null, noneText); },
    });
    list.draw(true);
    return el('div', { cls: 'card' }, [el('h3', null, title + ' (' + ids.length + ')'), el('p', null, intro), list.node]);
  }
  var none = D.say.noneListed;
  if (e.registrationBasis === 'NONE') {
    s.appendChild(el('p', null, 'With no inventory and no register read, every agent this scan found is unregistered. Supply an inventory to see which agents the estate does not know.'));
  }
  s.appendChild(block('Shadow agents', e.shadow, identitiesKnown ? 'Not registered, and showing a sign of a model.' : 'Agents found by this scan that are not registered.', none, 'Shadow agents'));
  if (identitiesKnown) {
    s.appendChild(block('Unregistered identities', e.identities, 'Not registered, and showing no sign of a model: a build workflow that holds a key, or a service account, looks like this. The scan cannot show that one of these runs no model. Each is a finding of medium severity, and none is held to the agent bar.', none, 'Unregistered identities'));
  }
  return s;
}

var FF = { severity: '', code: '', q: '' };
var findingControls = {};
var findingList = null;
function setFindingFilters(patch) {
  FF.severity = patch.severity || '';
  FF.code = patch.code || '';
  FF.q = patch.q || '';
  for (var k in findingControls) if (has(findingControls, k)) findingControls[k].value = FF[k];
  if (findingList) findingList.draw(true);
}
function findingsSection() {
  var s = el('section', { id: 'd-findings', cls: 'd-section', 'aria-labelledby': 'd-findings-h' }, el('h2', { id: 'd-findings-h' }, 'Findings'));
  var codes = {};
  D.findings.forEach(function (f) { codes[f.code] = (codes[f.code] || 0) + 1; });
  function sel(name, label, opts) {
    var x = el('select', null, opts.map(function (o) { return option(o[0], o[1], false); }));
    x.addEventListener('change', function () { FF[name] = x.value; findingList.draw(true); });
    findingControls[name] = x;
    return labelled(label, x);
  }
  var q = el('input', { type: 'search', placeholder: 'Title, code, reference or agent', autocomplete: 'off', spellcheck: 'false' });
  q.addEventListener('input', function () { FF.q = q.value.trim().toLowerCase(); findingList.draw(true); });
  findingControls.q = q;
  s.appendChild(el('div', { cls: 'toolbar', role: 'search', 'aria-label': 'Filter the findings' }, [
    labelled('Search', q),
    sel('severity', 'Severity', [['', 'Any severity'], ['CRITICAL', 'Critical'], ['HIGH', 'High'], ['MEDIUM', 'Medium'], ['LOW', 'Low']]),
    sel('code', 'Code', [['', 'Any code']].concat(Object.keys(codes).sort(byCodeUnit).map(function (c) { return [c, c + ' (' + codes[c] + ')']; }))),
  ]));
  var described = D.findings.filter(function (f) { return f.description !== null; }).length;
  if (described < D.findings.length) s.appendChild(el('p', { cls: 'callout' }, 'Every finding is listed. The ' + described + ' most severe carry their description here; the rest are in ' + D.files.findings + '.'));
  findingList = pagedList({
    size: 50,
    cls: 'findings',
    items: function () {
      return D.findings.filter(function (f) {
        if (FF.severity !== '' && f.severity !== FF.severity) return false;
        if (FF.code !== '' && f.code !== FF.code) return false;
        if (FF.q !== '' && [f.title, f.code, f.ref, f.agent || ''].join(' ').toLowerCase().indexOf(FF.q) < 0) return false;
        return true;
      });
    },
    caption: 'Findings, most severe first',
    head: ['Severity', 'Code', 'Subject', 'Finding'],
    row: function (f) {
      return el('tr', null, [
        el('td', null, sevTag(f.severity)),
        el('td', null, code(f.code)),
        el('td', null, f.agent === null ? (f.code === 'SPENDING_AGENT_UNDECLARED' ? 'One registration, several agents' : 'The scan') : agentButton(f.agent)),
        el('td', null, f.description === null ? [f.title, el('span', { cls: 'block note' }, 'The description is in ' + D.files.findings + '.')]
          : el('details', null, [el('summary', null, f.title), el('p', null, f.description), el('p', { cls: 'note' }, ['Reference ', idCode(f.ref)])])),
      ]);
    },
    empty: function () { return el('p', null, D.say.noFindings !== null ? D.say.noFindings : 'No finding matches these filters.'); },
  });
  findingList.draw(true);
  s.appendChild(findingList.node);
  return s;
}

// ── Build, then show ──
try {
  add(root, [
    overview(),
    D.completeness === 'EMPTY' ? null : el('div', { cls: 'charts' }, [levelChart(), severityChart(), coverageCard()]),
    driftSection(),
    D.completeness === 'EMPTY' ? null : matrixSection(),
    D.completeness === 'EMPTY' ? null : unregisteredSection(),
    findingsSection(),
  ]);
  document.body.appendChild(drawerBack);
  document.body.appendChild(drawer);
  if (D.completeness !== 'EMPTY') refilter();
  var targets = { summary: 'd-overview', matrix: 'd-matrix', shadow: 'd-shadow', identities: 'd-shadow', findings: 'd-findings', drift: 'd-drift' };
  var links = document.querySelectorAll('nav.contents a');
  for (var i = 0; i < links.length; i++) {
    var to = links[i].getAttribute('href').slice(1);
    if (has(targets, to) && document.getElementById(targets[to])) links[i].setAttribute('href', '#' + targets[to]);
  }
  root.hidden = false;
  document.documentElement.classList.add('js');
} catch (err) {
  root.textContent = '';
  root.hidden = true;
}
})();
`;
