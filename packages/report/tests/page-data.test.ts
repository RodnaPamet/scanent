/**
 * The data behind `summary.html`'s interactive view, and the table model it
 * is read from.
 *
 *   1. A results file rebuilds the shared table model's rows exactly: every
 *      cell, level, bar and standing is what the scorer's model said.
 *   2. An unregistered identity is held to no bar, on every surface: the page
 *      no longer calls it "Below bar".
 *   3. What reaches the script is made safe once: printable text, JSON that
 *      cannot end its element, evidence linked only when it is https.
 *   4. The comparison with the previous run says what was compared, and never
 *      words what it could not conclude as a change.
 *   5. The CSP hash is SHA-256, by Node's own reckoning.
 */
import { createHash } from 'node:crypto';

import { HARNESS_MATRIX_CELL_STATES, harnessMatrixCellState } from '@rodnapamet/scanent-contract/harness-matrix-model';

import { diffResults } from '../src/diff/diff';
import { scriptElement } from '../src/render/escape';
import { agentClassification } from '../src/render/csv';
import { renderSummaryHtml } from '../src/render/html';
import { harnessMatrixOfResults } from '../src/render/matrix-of-results';
import { DRIFT_MAX_ROWS, driftRecord, evidenceRecord, findingRef, printable, scriptJson, summaryPageData } from '../src/render/page-data';
import { base64, cspHashSource, sha256Bytes } from '../src/render/sha256';
import { standingOf } from '../src/render/words';
import { scoreReportLocally } from '../src/results/score';
import type { LocalResults } from '../src/results/types';
import { ALPHA, BRAVO, fullRow, input, inventoryOf, standaloneBody, withSource } from './helpers/fixtures';
import { withoutScriptElements } from './helpers/html';
import { CHARLIE, emptyResults, identityResults, inventoryResults, laterBody, notJudgedResults, plainResults } from './helpers/results';

const FIXTURES: readonly (readonly [string, () => LocalResults])[] = [
    ['two agents', plainResults],
    ['an inventory', inventoryResults],
    ['not judged', notJudgedResults],
    ['an unregistered identity', identityResults],
    ['an empty scan', emptyResults],
    ['an unrelated incomplete source', () => scoreReportLocally(input(withSource(standaloneBody(), 'mcp', 'TIME_BOX')))],
];

const staticOf = (page: string): string => withoutScriptElements(page);

describe('1. the table model, rebuilt from a results file', () => {
    it.each(FIXTURES)('%s: every row says what the scorer stored', (_label, make) => {
        const r = make();
        const model = harnessMatrixOfResults(r);
        expect(model.coverage).toEqual(r.coverage);
        expect(model.population.agentCount).toBe(r.estate.agentCount);
        expect(model.population.notJudgedCount).toBe(r.estate.notJudgedCount);
        expect(model.population.completeness).toBe(r.estate.empty ? 'EMPTY' : r.scan.complete ? 'COMPLETE' : 'INCOMPLETE');
        expect(model.rows.filter((row) => row.countsAsShortfall)).toHaveLength(r.estate.shortfallCount);
        r.agents.forEach((a, i) => {
            const row = model.rows[i];
            expect(row.discoveredId).toBe(a.discoveredId);
            expect(row.classification).toBe(agentClassification(a));
            expect(row.cells.map((c) => c.state)).toEqual(a.criteria.map((c) => harnessMatrixCellState(c)));
            expect(row.cells.map((c) => c.evidence)).toEqual(a.criteria.map((c) => (c.state === 'MET_UNEVIDENCED' || c.state === 'UNANSWERED' ? null : c.evidence)));
            const j = a.judgement;
            if (j.state === 'JUDGED') {
                expect([row.level, row.observedLevel, row.bar, row.blockingNextRung]).toEqual([j.level, j.observedLevel, j.bar, j.blockingNextRung]);
                expect(row.barStatus).toBe(j.shortfall ? 'BELOW_BAR' : 'AT_BAR');
                expect(row.judgement).toEqual({ kind: 'JUDGED', caveats: j.caveats });
            } else {
                expect([row.level, row.observedLevel, row.blockingNextRung, row.barStatus]).toEqual([null, null, null, 'NOT_JUDGED']);
                expect(row.judgement).toEqual({ kind: 'NOT_JUDGED', reasons: j.reasons });
            }
        });
    });

    it('a declaration that outvotes an observation keeps the level on observation alone the scorer stored', () => {
        const base = inventoryResults();
        const alpha = base.agents.find((a) => a.discoveredId === ALPHA);
        expect(alpha?.judgement.state).toBe('JUDGED');
        const row = harnessMatrixOfResults(base).rows.find((r) => r.discoveredId === ALPHA);
        expect(row?.observedLevel).toBe(alpha?.judgement.state === 'JUDGED' ? alpha.judgement.observedLevel : null);
    });
});

describe('2. an unregistered identity is held to no bar', () => {
    it('the static matrix says "Held to no bar" for it and "Below bar" only for the agents held to one', () => {
        const r = identityResults();
        const charlie = r.agents.find((a) => a.discoveredId === CHARLIE);
        // Its level is below the bar its reach would carry, and that is not a shortfall.
        expect(charlie?.judgement.state === 'JUDGED' && charlie.judgement.shortfall).toBe(true);
        const page = renderSummaryHtml(r);
        const matrix = page.slice(page.indexOf('<section id="matrix"'), page.indexOf('<section id="shadow"'));
        const rows = matrix.slice(matrix.indexOf('<tbody>')).split('<tr>').slice(1);
        const charlieRow = rows.find((row) => row.includes(CHARLIE)) as string;
        expect(charlieRow).toContain('<span class="tag plain">Held to no bar</span>');
        expect(charlieRow).not.toContain('Below bar');
        for (const row of rows.filter((x) => !x.includes(CHARLIE))) expect(row).toContain('<span class="tag bad">Below bar</span>');
        expect(staticOf(page).match(/Below bar/g)).toHaveLength(r.estate.shortfallCount);
    });

    it('the data the script reads says the same, by the model\'s heldToBar and countsAsShortfall', () => {
        const data = summaryPageData(identityResults());
        const charlie = data.agents.find((a) => a.id === CHARLIE);
        expect(charlie).toMatchObject({ cls: 'UNREGISTERED_IDENTITY', standing: 'NO_BAR', barStatus: 'BELOW_BAR' });
        expect(data.agents.filter((a) => a.standing === 'BELOW_BAR')).toHaveLength(data.estate.shortfallCount);
        expect(standingOf({ barStatus: 'BELOW_BAR', heldToBar: false, countsAsShortfall: false })).toBe('NO_BAR');
        expect(standingOf({ barStatus: 'NOT_JUDGED', heldToBar: false, countsAsShortfall: false })).toBe('NOT_JUDGED');
    });
});

describe('3. what reaches the script', () => {
    it('rows are in the model\'s order, cells are indices into the model\'s states, and nothing is recomputed', () => {
        const data = summaryPageData(notJudgedResults());
        expect(data.states.map((s) => s.state)).toEqual([...HARNESS_MATRIX_CELL_STATES]);
        expect(data.agents.every((a) => a.cells.length === data.criteria.length && /^[0-6]+$/.test(a.cells))).toBe(true);
        expect(data.agents.every((a) => !a.judged && a.level === null && a.standing === 'NOT_JUDGED' && a.notes.length > 0)).toBe(true);
        for (const a of data.agents) for (const code of a.notes) expect(data.text.reasons[code]).toMatch(/was not read in full/);
    });

    it('every string is printable: a bidirectional control or a line separator becomes U+FFFD, keys included', () => {
        expect(printable('a‮b\u2028c\td\ne\u0007')).toBe('a�b�c\td\ne�');
        const r = notJudgedResults();
        const armed: LocalResults = { ...r, sources: r.sources.map((s) => ({ ...s, reason: s.reason === null ? null : 'X‮Y' })) };
        const json = scriptJson(summaryPageData(armed));
        expect(json).not.toMatch(/[‮\u2028\u2029]/);
        expect(json).toContain('X�Y');
    });

    it('the JSON cannot end its element, open a comment, or read differently once parsed', () => {
        const value = { a: '</script><!-- & \' ` > \u2028\u2029', b: [1, null, true] };
        const json = scriptJson(value);
        expect(json).not.toMatch(/[<>&'`\u2028\u2029]/);
        expect(JSON.parse(json)).toEqual(value);
        expect(() => scriptElement('json', '{"a":"<"}', 'scan-data')).toThrow('a data block may hold no "<"');
        expect(() => scriptElement('code', 'x = "</script>"')).toThrow();
        expect(() => scriptElement('code', 'x = "<!--"')).toThrow();
        expect(() => scriptElement('json', '{}', 'Bad Id"')).toThrow('not a fixed element id');
    });

    const EVIDENCE: readonly (readonly [string, string | null, boolean])[] = [
        ['https://evidence.example/run/1#L2', 'https://evidence.example/run/1#L2', false],
        ['http://evidence.example/run/1', null, false],
        ['javascript:alert(1)', null, false],
        ['/relative/path', null, false],
        ['inventory:sha256:abc#row-1', null, false],
        ['code://example/support/agent.py#L12', null, false],
        ['https://user:pass@evidence.example/x', null, true],
        ['git@host and https://tok@evidence.example/x', null, true],
    ];
    it.each(EVIDENCE)('evidence %j: linked to %j, user information redacted: %j', (reference, href, redacted) => {
        const e = evidenceRecord(reference);
        expect(e.h).toBe(href);
        expect(e.r).toBe(redacted);
        if (redacted) expect(e.t).toContain('//***@');
        if (redacted) expect(e.t).not.toMatch(/pass|tok@/);
    });

    it('a finding\'s reference is carried only when it is not the code and the agent', () => {
        const data = summaryPageData(plainResults());
        const r = plainResults();
        for (const f of data.findings) expect(findingRef(f)).toBe(r.findings.find((x) => x.code === f.code && x.discoveredId === f.agent && x.title === f.title)?.sourceRef);
        expect(data.findings.some((f) => f.ref === undefined)).toBe(true);
    });
});

describe('4. the comparison with the previous run', () => {
    const earlier = (): LocalResults => scoreReportLocally(input(standaloneBody(), { inventory: inventoryOf([fullRow(ALPHA)]) }));
    const later = (): LocalResults =>
        scoreReportLocally(input(laterBody((b) => ({ ...b, agents: b.agents.filter((a) => a.discoveredId !== BRAVO) })), { inventory: inventoryOf([fullRow(ALPHA)]) }));

    it('none, refused, unreadable and compared are four different statements', () => {
        expect(driftRecord(null)).toEqual({ kind: 'FIRST' });
        expect(driftRecord({ kind: 'NOT_COMPARED', scanId: 'x', reason: 'LADDER_DIFFERS' })).toMatchObject({ kind: 'NOT_COMPARED', text: expect.stringContaining('ladder') });
        expect(driftRecord({ kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' })).toMatchObject({ text: expect.stringContaining('could not be read') });
        const compared = driftRecord({ kind: 'COMPARED', diff: diffResults(earlier(), later()) });
        expect(compared).toMatchObject({ kind: 'COMPARED', outcome: 'DIFFERENT', gone: { total: 1, rows: [BRAVO] } });
    });

    it('each list carries at most its cap and says how many it holds', () => {
        const diff = diffResults(earlier(), later());
        const many = { ...diff, agents: { ...diff.agents, added: Array.from({ length: DRIFT_MAX_ROWS + 7 }, (_, i) => `entra:sp:new-${i}`) } };
        const record = driftRecord({ kind: 'COMPARED', diff: many });
        expect(record.kind === 'COMPARED' && [record.added.total, record.added.rows.length]).toEqual([DRIFT_MAX_ROWS + 7, DRIFT_MAX_ROWS]);
    });

    it('the static page has the section only when the run knew of a previous one, and says what was compared', () => {
        expect(renderSummaryHtml(later())).not.toContain('id="drift"');
        const first = staticOf(renderSummaryHtml(later(), { previous: null }));
        expect(first).toContain('This output directory held no earlier run, so there is nothing to compare with.');
        const page = staticOf(renderSummaryHtml(later(), { previous: { kind: 'COMPARED', diff: diffResults(earlier(), later()) } }));
        const section = page.slice(page.indexOf('<section id="drift"'), page.indexOf('<section id="matrix"'));
        expect(section).toContain('The two runs differ.');
        expect(section).toContain(`<code class="id">${BRAVO}</code> (every source it was found through was read in full)`);
        expect(page).toContain('<li><a href="#drift">Since the previous run</a></li>');
        const refused = staticOf(renderSummaryHtml(later(), { previous: { kind: 'NOT_COMPARED', scanId: null, reason: 'SCANNER_DIFFERS' } }));
        expect(refused).toContain('Not compared with the previous run: The two runs are from different scanners');
    });
});

describe('5. SHA-256 for the CSP', () => {
    const TEXTS: readonly string[] = ['', 'abc', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'a'.repeat(1000), 'é ✓ 😀 \u2028', '\ud800 lone'];
    it.each(TEXTS)('%j hashes as Node hashes it', (text) => {
        const node = createHash('sha256').update(text, 'utf8').digest();
        expect(Buffer.from(sha256Bytes(text)).equals(node)).toBe(true);
        expect(cspHashSource(text)).toBe(`'sha256-${node.toString('base64')}'`);
    });

    it('base64 pads as the standard does', () => {
        for (const n of [0, 1, 2, 3, 4, 5]) {
            const bytes = Uint8Array.from({ length: n }, (_, i) => i * 37);
            expect(base64(bytes)).toBe(Buffer.from(bytes).toString('base64'));
        }
    });
});
