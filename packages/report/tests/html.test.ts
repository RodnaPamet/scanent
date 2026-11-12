/**
 * `summary.html`.
 *
 *   1. Nothing a scanner or an operator controls becomes markup: every string
 *      is escaped, wherever it lands.
 *   2. The page loads nothing: one file, one style block, no script.
 *   3. Completeness comes first, and what could not be judged is said, not
 *      scored: no level for an agent that was not judged, no clean bill for
 *      an empty scan.
 *   4. It states where it came from.
 *   5. The basics of an accessible page hold.
 *   6. The same results give the same bytes.
 *
 * "Inside a tag" is decided by a small tokenizer below, not by a guess at the
 * surrounding text.
 */
import { LADDER_VERSION } from '@rodnapamet/scanent-contract/harness-contract';
import { ALL_HARNESS_CRITERIA } from '@rodnapamet/scanent-contract/harness-ladder';

import { escapeHtml, html, htmlText, joinHtml, type SafeHtml } from '../src/render/escape';
import { RUN_FILE_NAMES } from '../src/render/files';
import { MATRIX_MAX_AGENTS, renderSummaryHtml } from '../src/render/html';
import { scoreReportLocally } from '../src/results/score';
import type { LocalResults } from '../src/results/types';
import { fullRow, input, inventoryOf, standaloneBody, withSource } from './helpers/fixtures';
import { ALPHA, BRAVO, emptyResults, hostile, inventoryResults, notJudgedResults, plainResults } from './helpers/results';

interface Tag {
    readonly name: string;
    readonly closing: boolean;
    readonly attrs: ReadonlyMap<string, string>;
}
interface Parsed {
    readonly tags: readonly Tag[];
    /** Text between tags, outside the style block, entities left as written. */
    readonly text: readonly string[];
    readonly style: readonly string[];
}

/** Tokenize a page into tags, text and style blocks. Throws on markup it cannot read. */
function tokenize(page: string): Parsed {
    const tags: Tag[] = [];
    const text: string[] = [];
    const style: string[] = [];
    let i = 0;
    while (i < page.length) {
        const lt = page.indexOf('<', i);
        if (lt < 0) {
            text.push(page.slice(i));
            break;
        }
        if (lt > i) text.push(page.slice(i, lt));
        if (page.startsWith('<!doctype html>', lt)) {
            i = lt + '<!doctype html>'.length;
            continue;
        }
        const m = /^<(\/?)([a-zA-Z][a-zA-Z0-9]*)/.exec(page.slice(lt, lt + 40));
        if (m === null) throw new Error(`a "<" that starts no tag at ${lt}: ${page.slice(lt, lt + 30)}`);
        let j = lt + m[0].length;
        const attrs = new Map<string, string>();
        for (;;) {
            while (/\s/.test(page[j])) j += 1;
            if (page[j] === '>') {
                j += 1;
                break;
            }
            const a = /^([a-zA-Z][a-zA-Z0-9-]*)(?:="([^"]*)")?/.exec(page.slice(j));
            if (a === null) throw new Error(`an attribute that cannot be read at ${j}: ${page.slice(j, j + 30)}`);
            if (attrs.has(a[1])) throw new Error(`attribute ${a[1]} twice`);
            attrs.set(a[1], a[2] ?? '');
            j += a[0].length;
        }
        tags.push({ name: m[2].toLowerCase(), closing: m[1] === '/', attrs });
        if (m[2].toLowerCase() === 'style' && m[1] === '') {
            const end = page.indexOf('</style>', j);
            if (end < 0) throw new Error('an unterminated style block');
            style.push(page.slice(j, end));
            j = end;
        }
        i = j;
    }
    return { tags, text, style };
}

const ALLOWED_TAGS = new Set([
    'html', 'head', 'meta', 'title', 'style', 'body', 'a', 'header', 'p', 'h1', 'h2', 'h3', 'dl', 'div', 'dt', 'dd', 'code', 'strong', 'nav', 'ul', 'li', 'main',
    'section', 'table', 'caption', 'thead', 'tbody', 'tr', 'th', 'td', 'span', 'br', 'details', 'summary', 'footer',
]);
const ALLOWED_ATTRS = new Set([
    'lang', 'charset', 'http-equiv', 'content', 'name', 'class', 'href', 'id', 'aria-labelledby', 'aria-label', 'aria-hidden', 'scope', 'colspan', 'rowspan', 'title',
    'tabindex', 'role',
]);

const PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='x",
    '</style><script>alert(2)</script>',
    'javascript:alert(1)',
    '&lt;b&gt; already escaped',
    '`${alert(1)}`',
    ']]> --> <!-- <![CDATA[',
    '</td></tr></table><iframe src="https://evil.example/">',
    '<link rel=stylesheet href=https://evil.example/x.css>',
    '" style="background:url(https://evil.example/x)" x="',
];

function assertSafe(page: string): Parsed {
    const parsed = tokenize(page);
    for (const tag of parsed.tags) {
        expect(ALLOWED_TAGS).toContain(tag.name);
        for (const [name, value] of tag.attrs) {
            expect(ALLOWED_ATTRS).toContain(name);
            expect(name.startsWith('on')).toBe(false);
            if (name === 'href') expect(value).toMatch(/^#[a-z-]+$/);
            if (name !== 'title' && name !== 'aria-label' && name !== 'content') expect(value).toMatch(/^[A-Za-z0-9 #_.=,;'-]*$/);
        }
    }
    expect(parsed.style).toHaveLength(1);
    expect(parsed.tags.filter((t) => t.name === 'style' && !t.closing)).toHaveLength(1);
    return parsed;
}

describe('1. scanned strings never become markup', () => {
    it.each(PAYLOADS)('every scanner- and operator-controlled string as %j is escaped everywhere', (payload) => {
        for (const base of [plainResults(), inventoryResults(), notJudgedResults(), emptyResults()]) {
            const page = renderSummaryHtml(hostile(base, payload));
            assertSafe(page);
            // The payload is on the page, and only in its escaped form.
            expect(page).toContain(escapeHtml(payload));
            if (escapeHtml(payload) !== payload) expect(page).not.toContain(payload);
            expect(page).not.toMatch(/<script|<img|<iframe|<link|<object|<embed|<form|<base/i);
        }
    });

    it('no bidirectional control reaches the page: an id cannot be made to read as another', () => {
        expect(escapeHtml('agent\u202etxt.exe\u202c \u2066x\u2069\u200e\u200f\u061c')).toBe('agent\ufffdtxt.exe\ufffd \ufffdx\ufffd\ufffd\ufffd\ufffd');
        // Tab and line feed stay; every other control is replaced, as before.
        expect(escapeHtml('a\tb\nc\u001b\u009b\u2028')).toBe('a\tb\nc\ufffd\ufffd\ufffd');
        for (const base of [plainResults(), inventoryResults(), notJudgedResults(), emptyResults()]) {
            const page = renderSummaryHtml(hostile(base, '\u202etxt.exe\u202c\u2066x\u2069'));
            assertSafe(page);
            expect(page).not.toMatch(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/);
        }
    });

    it('a URL-shaped string is text, never a link or an attribute other than a title', () => {
        const page = renderSummaryHtml(hostile(inventoryResults(), 'javascript:alert(1)'));
        const { tags } = assertSafe(page);
        for (const tag of tags) {
            for (const [name, value] of tag.attrs) {
                if (name !== 'title') expect(value).not.toContain('javascript:');
            }
        }
        expect(tags.filter((t) => t.name === 'a' && !t.closing).every((t) => (t.attrs.get('href') ?? '').startsWith('#'))).toBe(true);
    });

    it('no scanned string reaches an attribute, a class or an id at all', () => {
        for (const base of [plainResults(), inventoryResults(), notJudgedResults(), emptyResults()]) {
            const { tags, text } = tokenize(renderSummaryHtml(hostile(base, 'ZZMARKERZZ')));
            for (const tag of tags) for (const value of tag.attrs.values()) expect(value).not.toContain('ZZMARKERZZ');
            // It is on the page, as text.
            expect(text.some((t) => t.includes('ZZMARKERZZ'))).toBe(true);
        }
    });

    it('the escaper covers the six characters and replaces control characters', () => {
        expect(escapeHtml('&<>"\'`')).toBe('&amp;&lt;&gt;&quot;&#39;&#96;');
        expect(escapeHtml('a\u0000b\u001bc\u007fd e\tf\ng')).toBe('a�b�c�d�e\tf\ng');
        expect(escapeHtml('plain text 123')).toBe('plain text 123');
    });

    it('the template escapes strings, numbers and arrays, and passes its own fragments through', () => {
        const inner = html`<b>${'<i>'}</b>`;
        expect(htmlText(html`<p>${inner}${[inner, '<', 7]}${3}</p>`)).toBe('<p><b>&lt;i&gt;</b><b>&lt;i&gt;</b>&lt;73</p>');
        expect(htmlText(joinHtml([inner, '&']))).toBe('<b>&lt;i&gt;</b>&amp;');
    });

    it('an object that only looks like a fragment is escaped as text, and is no fragment', () => {
        const forged = { __safeHtml: true, toString: () => '<script>' } as unknown as SafeHtml;
        expect(htmlText(html`<p>${forged}</p>`)).toBe('<p>&lt;script&gt;</p>');
        expect(() => htmlText(forged)).toThrow('not a fragment');
    });
});

describe('2. one self-contained file', () => {
    const pages = [plainResults(), inventoryResults(), notJudgedResults(), emptyResults()].map(renderSummaryHtml);

    it('has no script, link, image, frame, import, url() or event handler, and one style block', () => {
        for (const page of pages) {
            const { tags, style } = assertSafe(page);
            expect(tags.some((t) => ['script', 'link', 'img', 'iframe', 'object', 'embed', 'base'].includes(t.name))).toBe(false);
            expect(style[0]).not.toMatch(/url\(|@import|@font-face|expression\(|javascript:/i);
            expect(page).not.toMatch(/\ssrc=/);
            expect(page).not.toMatch(/\sstyle=/);
        }
    });

    it('names no address outside itself: no http(s) URL but the fixture\'s own tool servers, shown as text', () => {
        for (const page of pages) {
            const { tags } = tokenize(page);
            for (const tag of tags) for (const value of tag.attrs.values()) expect(value).not.toMatch(/https?:|\/\//);
        }
    });

    it('tells the browser to load nothing and send no referrer', () => {
        for (const page of pages) {
            expect(page).toContain('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">');
            expect(page).toContain('<meta name="referrer" content="no-referrer">');
            expect(page).toContain('<meta charset="utf-8">');
            expect(page).toContain('<meta name="viewport"');
        }
    });
});

describe('3. honest states', () => {
    it('says why a source stopped and names the places not read, as text', () => {
        const results = scoreReportLocally({
            ...input(withSource(standaloneBody(), 'entra-sp', 'UNPARSEABLE')),
            sourceNotes: [
                {
                    kind: 'entra-sp',
                    detail: 'a file that names a framework could not be read as code',
                    notRead: [
                        { where: 'code://acme/agents/<b>bold</b>.py#L12', reason: 'UNPARSEABLE' },
                        { where: 'code://acme/tools.ts#L3', reason: 'UNPARSEABLE' },
                    ],
                    notReadTotal: 7,
                },
            ],
        });
        const page = renderSummaryHtml(results);
        const { text, tags } = assertSafe(page);
        const words = text.join('').replace(/\s+/g, ' ');
        expect(words).toContain('was not read in full: a file that names a framework could not be read as code.');
        expect(words).toContain('the first 2 of 7 places');
        expect(words).toContain('code://acme/tools.ts#L3');
        // The path's markup is text on the page, never an element of it.
        expect(page).toContain('code://acme/agents/&lt;b&gt;bold&lt;/b&gt;.py#L12');
        expect(tags.filter((t) => t.name === 'b')).toHaveLength(0);
    });

    it('a source that stopped with nothing more said of it adds no note', () => {
        const page = renderSummaryHtml(notJudgedResults());
        expect(page.includes('What was not read')).toBe(false);
        expect(page.includes('was not read in full</strong>')).toBe(false);
    });

    it('completeness comes before every other section', () => {
        for (const page of [plainResults(), inventoryResults(), notJudgedResults(), emptyResults()].map(renderSummaryHtml)) {
            const offsets = [...page.matchAll(/<section id="([a-z]+)"/g)].map((m) => [m[1], m.index] as const);
            expect(offsets[0][0]).toBe('completeness');
            expect(offsets[1][0]).toBe('coverage');
            expect(new Set(offsets.map(([id]) => id)).size).toBe(offsets.length);
        }
    });

    it('a complete scan says so, and an incomplete one counts the sources and marks the row in words', () => {
        expect(renderSummaryHtml(plainResults())).toContain('<strong>Complete.</strong>');
        const page = renderSummaryHtml(notJudgedResults());
        expect(page).toContain('<strong>Incomplete:</strong> 1 of 2 sources were not read in full.');
        expect(page).toContain('<span class="tag bad">Incomplete</span>');
        expect(page).toContain('<code>AUTH_FAILED</code>');
        expect(page).toContain('2 agents are not judged');
        expect(page).toContain('Nothing on this page is shown as gone, closed or resolved on a partial read.');
    });

    it('a report that lists no source is incomplete, and says it evidences nothing', () => {
        const page = renderSummaryHtml(scoreReportLocally(input({ ...standaloneBody(), population: { sources: [] } }, { configuredSources: [] })));
        expect(page).toContain('the report lists no source, so this scan evidences nothing');
        expect(page).toContain('A scan that looked nowhere evidences nothing.');
    });

    it('an agent that was not judged shows "Not judged", its reasons, and no level in its row', () => {
        const page = renderSummaryHtml(notJudgedResults());
        const matrix = page.slice(page.indexOf('<section id="matrix"'), page.indexOf('<section id="shadow"'));
        const rows = matrix.slice(matrix.indexOf('<tbody>')).split('<tr>').slice(1);
        expect(rows).toHaveLength(2);
        for (const row of rows) {
            expect(row.match(/Not judged/g)).toHaveLength(2);
            expect(row).toContain('SOURCE_INCOMPLETE:entra-sp:AUTH_FAILED');
            expect(row).toContain('A source it was found through, entra-sp, was not read in full (AUTH_FAILED)');
            const levelCells = row.split('<td class="lvl">').slice(1).map((c) => c.slice(0, c.indexOf('</td>')));
            expect(levelCells).toHaveLength(2);
            for (const cell of levelCells) expect(cell).not.toMatch(/H\d/);
        }
        // The estate's count of levels holds nobody.
        const levels = page.slice(page.indexOf('class="levels"'), page.indexOf('<section id="matrix"'));
        expect(levels.match(/<td class="num">0<\/td>/g)).toHaveLength(6);
    });

    it('a judged agent shows its level, its bar and whether it is below it', () => {
        const page = renderSummaryHtml(inventoryResults());
        expect(page).toContain('<strong>H1</strong> Registered');
        expect(page).toContain('H0 on observation alone; the rest is declared by the operator');
        expect(page).toContain('<span class="tag bad">Below bar</span>');
        expect(page).toContain('<span class="name">Invoice triage</span> <span class="decl">(name declared by the operator)</span>');
        expect(page).toContain(`<code class="id">${ALPHA}</code>`);
    });

    it('a judged agent beside an unrelated incomplete source carries the caveat', () => {
        const page = renderSummaryHtml(scoreReportLocally(input(withSource(standaloneBody(), 'mcp', 'TIME_BOX'))));
        expect(page).toContain('OTHER_SOURCE_INCOMPLETE:mcp');
        expect(page).toContain('Another source, mcp, was not read in full; it does not bear on this agent');
    });

    it('an empty scan is a finding, never a clean result, and has no matrix', () => {
        const page = renderSummaryHtml(emptyResults());
        expect(page).toContain('This scan found no agents. That is a finding, not a clean result.');
        expect(page).toContain('An empty population is');
        expect(page).not.toContain('<section id="matrix"');
        expect(page).not.toContain('<section id="shadow"');
        expect(page).not.toContain('<section id="orphans"');
        expect(page).toContain('EMPTY_SCAN');
        // No level is stated for anything: the only level named is the one the run could have reached.
        const afterCoverage = page.slice(page.indexOf('<section id="summary"'), page.indexOf('<section id="provenance"'));
        expect(afterCoverage).not.toMatch(/\bH[0-5]\b/);
    });

    it('with no inventory it says no agent can be shown as registered, and does not list every agent twice', () => {
        const page = renderSummaryHtml(plainResults());
        expect(page).toContain('no inventory was supplied, so no agent can be shown as registered');
        expect(page).toContain('every agent this scan found is unregistered, so the list would repeat the table above');
        expect(page).not.toContain('<section id="inventory"');
        expect(page).toContain('This run could not have shown any agent at its bar');
    });

    it('with an inventory it lists the shadow agents, labels declarations, and names what was declared and not found', () => {
        const page = renderSummaryHtml(inventoryResults());
        const shadow = page.slice(page.indexOf('<section id="shadow"'), page.indexOf('<section id="orphans"'));
        expect(shadow).toContain(`<code class="id">${BRAVO}</code>`);
        expect(shadow).not.toContain(ALPHA);
        const inventory = page.slice(page.indexOf('<section id="inventory"'), page.indexOf('<section id="provenance"'));
        expect(inventory).toContain('declared by the operator');
        expect(inventory).toContain('<code class="id">entra:sp:zulu</code>');
        expect(inventory).toContain('This is not a statement that they are gone');
        expect(page).toContain('<li><a href="#inventory">Inventory</a></li>');
    });

    it('what the run could not evidence is listed, with why and the readers that would', () => {
        const page = renderSummaryHtml(plainResults());
        const coverage = page.slice(page.indexOf('<section id="coverage"'), page.indexOf('<section id="summary"'));
        expect(coverage).toContain('<code>NO_READER</code>');
        expect(coverage).toContain('<code>READER_NOT_CONFIGURED</code>');
        expect(coverage).toContain('<code>inflect-register</code>');
        expect(coverage).toContain('<code>H5.independent_audit</code>');
    });

    it('a run that reads the register says where registration comes from, and what it could have shown', () => {
        const body = standaloneBody();
        const registered = scoreReportLocally(
            input({ ...body, population: { sources: [...body.population.sources, { kind: 'inflect-register', status: 'COMPLETE', rows: 0 }] } }),
        );
        const page = renderSummaryHtml(registered);
        expect(page).toContain('No inventory was supplied; registration is read from the Inflect register.');
        expect(page).toContain('This run could have shown an agent at either bar.');
        expect(page).toContain('Registration is taken from: The Inflect register.');
    });

    it('orphan credentials are listed, and those not concluded apart with the reason', () => {
        const body = standaloneBody();
        const unbound = [{ ref: 'entra://sp/unused/password/1', sourceKind: 'entra-sp' as const }];
        const concluded = renderSummaryHtml(scoreReportLocally(input({ ...body, unboundCredentials: unbound })));
        expect(concluded).toContain('Credentials a source, read in full, saw bound to no agent');
        expect(concluded).toContain('<code class="id">entra://sp/unused/password/1</code>');
        expect(concluded).not.toContain('Seen unbound, not concluded');
        const open = renderSummaryHtml(scoreReportLocally(input(withSource({ ...body, unboundCredentials: unbound }, 'entra-sp', 'TIME_BOX'))));
        expect(open).toContain('Seen unbound, not concluded');
        expect(open).toContain('<code>OWN_SOURCE_INCOMPLETE</code>');
        expect(open).toContain('None concluded. That is not a statement that none exist');
    });

    it('above the cap the matrix shows the first agents by id and names agents.csv', () => {
        const base = plainResults();
        const many: LocalResults = {
            ...base,
            agents: Array.from({ length: MATRIX_MAX_AGENTS + 3 }, (_, i) => ({ ...base.agents[0], discoveredId: `entra:sp:${String(i).padStart(4, '0')}` })),
        };
        const page = renderSummaryHtml(many);
        expect(page).toContain(`This table shows the first ${MATRIX_MAX_AGENTS} of ${MATRIX_MAX_AGENTS + 3} agents`);
        expect(page).toContain(`<code>${RUN_FILE_NAMES.agents}</code>`);
        const matrix = page.slice(page.indexOf('<section id="matrix"'), page.indexOf('<section id="shadow"'));
        expect(matrix.match(/<th scope="row" class="agent">/g)).toHaveLength(MATRIX_MAX_AGENTS);
        expect(matrix).toContain('entra:sp:0499');
        expect(matrix).not.toContain('entra:sp:0500');
    });

    it('findings are listed most severe first, each with its description', () => {
        const results = plainResults();
        const page = renderSummaryHtml(results);
        const findings = page.slice(page.indexOf('<section id="findings"'), page.indexOf('<section id="provenance"'));
        for (const f of results.findings) expect(findings).toContain(escapeHtml(f.description));
        const severities = [...findings.matchAll(/<span class="tag sev-[a-z]+">([A-Z]+)<\/span>/g)].map((m) => m[1]);
        const rank = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        expect(severities).toEqual([...severities].sort((a, b) => rank.indexOf(a) - rank.indexOf(b)));
        expect(severities.length).toBe(results.findings.length);
    });

    it('with no findings on an incomplete scan it does not call the result clean', () => {
        const none: LocalResults = { ...notJudgedResults(), findings: [] };
        expect(renderSummaryHtml(none)).toContain('No finding was raised. The scan is incomplete, so this is not a clean result.');
    });
});

describe('4. provenance', () => {
    it('names the scanner, its manifest, the ladder, the contract, the report hash and the signer', () => {
        const results = inventoryResults();
        const page = renderSummaryHtml(results);
        const provenance = page.slice(page.indexOf('<section id="provenance"'));
        for (const value of [
            results.scan.scanner.agentId,
            results.scan.scanner.version,
            results.scan.scanner.manifestHash,
            LADDER_VERSION,
            results.scan.contract,
            results.report.sha256,
            results.report.signerKeyFingerprint,
            results.inventory?.sha256 as string,
            ...Object.values(RUN_FILE_NAMES),
        ]) {
            expect(provenance).toContain(value);
        }
        expect(provenance).toContain('Pinned: verified against a key supplied apart from the report');
        expect(page).toContain(`<title>scanent results: acme, ${results.scan.id}</title>`);
    });

    it('says "read from the register" only for a run that read one, and that none was read otherwise', () => {
        const provenanceOf = (results: LocalResults): string => {
            const page = renderSummaryHtml(results);
            return page.slice(page.indexOf('<section id="provenance"'));
        };
        // No register source: this run's own results, and no register was read.
        const none = provenanceOf(plainResults());
        expect(none).toContain('<dt>Register claims</dt><dd>No register was read by this run</dd>');
        expect(none).not.toContain('Read from the register by this run');
        // The register source is listed: the claims are this run's own read.
        const body = standaloneBody();
        const withRegister = provenanceOf(
            scoreReportLocally(input({ ...body, population: { sources: [...body.population.sources, { kind: 'inflect-register', status: 'COMPLETE', rows: 0 }] } })),
        );
        expect(withRegister).toContain('<dt>Register claims</dt><dd>Read from the register by this run</dd>');
        expect(withRegister).not.toContain('No register was read');
    });

    it('says when the signer was not pinned and the register claims were not verified', () => {
        const page = renderSummaryHtml(
            scoreReportLocally(
                input(standaloneBody(), { meta: { estate: null, registerClaimsVerified: false, report: { sha256: 'c'.repeat(64), signerKeyFingerprint: 'd'.repeat(64), signerPinned: false } } }),
            ),
        );
        expect(page).toContain('Not pinned: verified against the key the report itself carries');
        expect(page).toContain('Taken from the report as stated; not verified by this run');
        expect(page).toContain('Not stated (scored from a bare report)');
        expect(page).toContain('<title>scanent results: acme-20261103T033000Z-0a1b2c3d</title>');
    });
});

describe('5. accessibility basics', () => {
    it.each([
        ['two agents', plainResults()],
        ['an inventory', inventoryResults()],
        ['not judged', notJudgedResults()],
        ['an empty scan', emptyResults()],
    ])('%s: language, headings, captions, scopes, a skip link and both media queries', (_label, results) => {
        const page = renderSummaryHtml(results);
        const { tags, style } = tokenize(page);
        const open = tags.filter((t) => !t.closing);
        expect(open.find((t) => t.name === 'html')?.attrs.get('lang')).toBe('en');
        expect(open.filter((t) => t.name === 'h1')).toHaveLength(1);
        const headings = open.filter((t) => /^h[1-6]$/.test(t.name)).map((t) => Number(t.name[1]));
        headings.forEach((level, i) => expect(level - (headings[i - 1] ?? 0)).toBeLessThanOrEqual(1));
        expect(open.filter((t) => t.name === 'caption')).toHaveLength(open.filter((t) => t.name === 'table').length);
        for (const th of open.filter((t) => t.name === 'th')) expect(['col', 'row', 'colgroup']).toContain(th.attrs.get('scope'));
        // The skip link is the first element of the body, and its target exists.
        expect(open[open.findIndex((t) => t.name === 'body') + 1].attrs.get('class')).toBe('skip');
        const ids = new Set(open.flatMap((t) => (t.attrs.has('id') ? [t.attrs.get('id') as string] : [])));
        for (const a of open.filter((t) => t.name === 'a')) expect(ids).toContain((a.attrs.get('href') as string).slice(1));
        for (const t of open) if (t.attrs.has('aria-labelledby')) expect(ids).toContain(t.attrs.get('aria-labelledby'));
        expect(style[0]).toContain('@media (prefers-color-scheme:dark)');
        expect(style[0]).toContain('@media print');
        expect(style[0]).toContain('thead{display:table-header-group}');
        expect(style[0]).toContain('tr{break-inside:avoid}');
        expect(style[0]).not.toMatch(/outline:\s*(none|0)/);
    });

    it('every matrix cell has a short code and its full meaning as text', () => {
        const page = renderSummaryHtml(inventoryResults());
        const cells = [...page.matchAll(/<td class="cell c-[a-z]" title="([^"]+)"><span aria-hidden="true">([^<]+)<\/span><span class="vh">([^<]+)<\/span><\/td>/g)];
        expect(cells).toHaveLength(2 * ALL_HARNESS_CRITERIA.length);
        for (const [, title, code, text] of cells) {
            expect(code.trim().length).toBeGreaterThan(0);
            expect(title.endsWith(text)).toBe(true);
        }
        // Declared, observed and unreadable each have their own code, and the legend explains all seven.
        expect(new Set(cells.map((c) => c[2]))).toEqual(new Set(['E', 'D', '·', '–']));
        expect(page.match(/<li><span class="cell c-[a-z]" aria-hidden="true">/g)).toHaveLength(7);
    });

    it('a cell reported met without evidence, and one not met, have their own codes', () => {
        const base = inventoryResults();
        const mixed: LocalResults = {
            ...base,
            agents: base.agents.map((a) => ({
                ...a,
                criteria: a.criteria.map((c, i) =>
                    i === 0 ? { ...c, state: 'MET_UNEVIDENCED' as const, basis: 'OBSERVED' as const } : i === 1 ? { ...c, state: 'NOT_MET' as const, basis: 'OBSERVED' as const } : c,
                ),
            })),
        };
        const page = renderSummaryHtml(mixed);
        expect(page).toContain('<td class="cell c-m" title="H1.registered: Reported met without evidence; counts as not met">');
        expect(page).toContain('<td class="cell c-n" title="H1.owner: Not met: a source saw it fail">');
    });

    it('a criterion not met on the inventory alone does not say that a source saw it fail', () => {
        // The operator's row has no axes: nothing was observed, and the page must not say something was.
        const base = inventoryResults();
        const declaredMiss: LocalResults = {
            ...base,
            agents: base.agents.map((a) => ({
                ...a,
                criteria: a.criteria.map((c) => (c.criterion === 'H1.axes_declared' ? { ...c, state: 'NOT_MET' as const, basis: 'DECLARED' as const } : c)),
            })),
        };
        const page = renderSummaryHtml(declaredMiss);
        expect(page).toContain('<td class="cell c-n" title="H1.axes_declared: Not met on what the operator declared in the inventory; no source saw it fail"><span aria-hidden="true">n</span>');
        expect(page).not.toContain('H1.axes_declared: Not met: a source saw it fail');
    });
});

describe('6. determinism', () => {
    it('two renders of the same results are byte-identical, and hold no clock reading of their own', () => {
        const results = scoreReportLocally(input(standaloneBody(), { inventory: inventoryOf([fullRow(ALPHA)]) }));
        const first = renderSummaryHtml(results);
        expect(renderSummaryHtml(scoreReportLocally(input(standaloneBody(), { inventory: inventoryOf([fullRow(ALPHA)]) })))).toBe(first);
        // The only times on the page are the scan's own.
        const years = [...first.matchAll(/\b20\d\d-\d\d-\d\dT[0-9:.]+Z/g)].map((m) => m[0]);
        expect(new Set(years)).toEqual(new Set([results.scan.asOf]));
    });
});
