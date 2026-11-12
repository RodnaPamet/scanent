/**
 * `summary.html` on a large estate.
 *
 * The page is one file somebody opens. Before its lists were capped it grew
 * with the estate. Measured on the fixture of `helpers/scale.ts` (two
 * credentials per agent, about three and a half findings per agent, as many
 * unbound credentials as agents, up to 4,000 declared agents the scan did not
 * find), 2026-11-12, Node 22:
 *
 *   agents   before the caps          with the caps
 *      100   1.02 MiB                 1.02 MiB   (the same bytes)
 *      500   5.03 MiB                 5.03 MiB   (the same bytes)
 *    2,000   9.07 MiB                 5.38 MiB
 *    5,000   17.12 MiB, 1.4 s         5.38 MiB, 0.3 s
 *
 * By section at 5,000 agents, with the caps: the matrix 3.73 MiB (500 rows of
 * about 7.5 KiB, which is the matrix cap doing what it always did), findings
 * 1.33 MiB (2,500 rows), shadow agents 62 KiB, orphan credentials 58 KiB, the
 * inventory 27 KiB, everything else under 10 KiB.
 *
 * What is held here:
 *
 *   1. The page stays under a stated size however large the run.
 *   2. Every capped list says how many it shows, how many the run holds, and
 *      the file that holds the rest.
 *   3. The counts at the top are over the whole run, never over what is shown.
 *   4. The matrix shows the agents that most need a reader, not the first by id.
 *   5. A run the caps do not reach is rendered exactly as before: no notice,
 *      every row.
 *   6. Nothing is dropped from the other files.
 */
import type { HarnessReportBodyV3 } from '@scanent/contract/harness-contract';

import { parseCsv } from './helpers/results';
import { scaleAgentId, scaleBody, scaleResults } from './helpers/scale';
import { CSV_BOM, renderAgentsCsv, renderFindingsCsv } from '../src/render/csv';
import { RUN_FILE_NAMES } from '../src/render/files';
import { FINDINGS_MAX_ROWS, MATRIX_MAX_AGENTS, renderSummaryHtml, SECTION_MAX_ROWS } from '../src/render/html';
import { renderResultsJson } from '../src/render/results-json';
import { LocalResultsSchema } from '../src/results/schema';
import { scoreReportLocally } from '../src/results/score';
import type { LocalResults } from '../src/results/types';
import { input } from './helpers/fixtures';

/** The page may not pass this at any size of run. Measured 5.38 MiB at 5,000 agents; the headroom is for longer ids. */
const MAX_PAGE_BYTES = 6 * 1024 * 1024;

type Section = 'completeness' | 'coverage' | 'summary' | 'matrix' | 'shadow' | 'orphans' | 'findings' | 'inventory' | 'provenance';

function sectionOf(page: string, id: Section): string {
    const start = page.indexOf(`<section id="${id}"`);
    if (start < 0) throw new Error(`the page has no ${id} section`);
    const end = page.indexOf('</section>', start);
    return page.slice(start, end);
}

const count = (text: string, needle: string): number => text.split(needle).length - 1;

/** The number a summary tile shows under `label`. */
function tile(page: string, label: string): number {
    const m = new RegExp(`<dt>${label}</dt><dd><span class="big">(\\d+)</span>`).exec(page);
    if (m === null) throw new Error(`no tile ${label}`);
    return Number(m[1]);
}

describe('summary.html at 5,000 agents', () => {
    const N = 5_000;
    let results: LocalResults;
    let page: string;

    beforeAll(() => {
        results = scaleResults(N, { unbound: N, absent: 4_000 });
        page = renderSummaryHtml(results);
    });

    it('the fixture is the size it says, and is a results file the schema accepts', () => {
        expect(results.agents).toHaveLength(N);
        expect(results.estate.orphanCredentials).toHaveLength(N);
        expect(results.inventory?.unmatched).toHaveLength(4_000);
        expect(results.findings.length).toBeGreaterThan(3 * N);
        expect(LocalResultsSchema.safeParse(JSON.parse(JSON.stringify(results))).success).toBe(true);
    });

    it('1. the page is under its stated size', () => {
        expect(Buffer.byteLength(page, 'utf8')).toBeLessThan(MAX_PAGE_BYTES);
    });

    it('2. every capped list says how many it shows, how many there are, and where the rest is', () => {
        const matrix = sectionOf(page, 'matrix');
        expect(matrix).toContain(`This table shows the first ${MATRIX_MAX_AGENTS} of ${N} agents`);
        expect(matrix).toContain(`The full list is in <code>${RUN_FILE_NAMES.agents}</code>`);
        expect(count(matrix, '<th scope="row" class="agent">')).toBe(MATRIX_MAX_AGENTS);

        const shadow = sectionOf(page, 'shadow');
        expect(shadow).toContain(`This list shows the first ${SECTION_MAX_ROWS} of ${results.estate.shadowAgents.length} shadow agents`);
        expect(shadow).toContain(`<code>${RUN_FILE_NAMES.agents}</code>`);
        expect(count(shadow, '<tr><th scope="row">')).toBe(SECTION_MAX_ROWS);

        const orphans = sectionOf(page, 'orphans');
        expect(orphans).toContain(`This list shows the first ${SECTION_MAX_ROWS} of ${N} orphan credentials`);
        expect(orphans).toContain(`<code>${RUN_FILE_NAMES.results}</code>`);
        expect(count(orphans, '<tr><th scope="row">')).toBe(SECTION_MAX_ROWS);

        const findings = sectionOf(page, 'findings');
        expect(findings).toContain(`This list shows the first ${FINDINGS_MAX_ROWS} of ${results.findings.length} findings, most severe first`);
        expect(findings).toContain(`<code>${RUN_FILE_NAMES.findings}</code>`);
        expect(count(findings, '<details>')).toBe(FINDINGS_MAX_ROWS);
        // The caption still counts the run, not the rows shown.
        expect(findings).toContain(`<caption>${results.findings.length} findings, most severe first</caption>`);

        const inventory = sectionOf(page, 'inventory');
        expect(inventory).toContain(`This list shows the first ${SECTION_MAX_ROWS} of 4000 declared agents this scan did not find`);
        expect(count(inventory, '<li><code class="id">')).toBe(SECTION_MAX_ROWS);
    });

    it('2b. the findings shown are the most severe ones', () => {
        const findings = sectionOf(page, 'findings');
        const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        const shown = [...findings.matchAll(/<span class="tag sev-[a-z]+">([A-Z]+)<\/span>/g)].map((m) => order[m[1]]);
        expect(shown).toHaveLength(FINDINGS_MAX_ROWS);
        expect([...shown].sort((a, b) => a - b)).toEqual(shown);
        const worstLeftOut = Math.min(...results.findings.map((f) => order[f.severity]).sort((a, b) => a - b).slice(FINDINGS_MAX_ROWS));
        expect(Math.max(...shown)).toBeLessThanOrEqual(worstLeftOut);
    });

    it('3. the counts at the top are over the whole run', () => {
        expect(tile(page, 'Agents found')).toBe(N);
        expect(tile(page, 'Judged')).toBe(results.estate.judgedCount);
        expect(tile(page, 'Not judged')).toBe(0);
        expect(tile(page, 'Below their bar')).toBe(results.estate.shortfallCount);
        expect(tile(page, 'Shadow agents')).toBe(results.estate.shadowAgents.length);
        expect(tile(page, 'Orphan credentials')).toBe(N);
        expect(results.estate.shadowAgents.length).toBeGreaterThan(SECTION_MAX_ROWS);
        // The inventory's own counts too.
        expect(sectionOf(page, 'inventory')).toContain('<dt>Declared, not found by this scan</dt><dd>4000</dd>');
        // And the per-level table adds up to every judged agent.
        const perLevel = [...sectionOf(page, 'summary').matchAll(/<td class="num">(\d+)<\/td>/g)].map((m) => Number(m[1]));
        expect(perLevel.reduce((a, b) => a + b, 0)).toBe(results.estate.judgedCount);
    });

    it('6. nothing is dropped from the other files', () => {
        const agents = parseCsv(renderAgentsCsv(results).slice(CSV_BOM.length));
        expect(agents).toHaveLength(N + 1);
        expect(new Set(agents.slice(1).map((row) => row[0])).size).toBe(N);
        expect(parseCsv(renderFindingsCsv(results).slice(CSV_BOM.length))).toHaveLength(results.findings.length + 1);
        const reread = JSON.parse(renderResultsJson(results)) as LocalResults;
        expect(reread.agents).toHaveLength(N);
        expect(reread.findings).toHaveLength(results.findings.length);
        expect(reread.estate.orphanCredentials).toHaveLength(N);
        expect(reread.inventory?.unmatched).toHaveLength(4_000);
    });

    it('the same results give the same page', () => {
        expect(renderSummaryHtml(results)).toBe(page);
    });
});

describe('4. the matrix above its cap shows the agents that most need a reader', () => {
    const TOTAL = MATRIX_MAX_AGENTS + 200;
    /** The LAST 120 agents by id were found through a source that was not read in full. */
    const lateNotJudged = (i: number): boolean => i >= TOTAL - 120;
    let results: LocalResults;
    let matrix: string;

    beforeAll(() => {
        const body = scaleBody(TOTAL);
        const mixed: HarnessReportBodyV3 = {
            ...body,
            population: { sources: [...body.population.sources, { kind: 'gcp-sa', status: 'INCOMPLETE', reason: 'TIME_BOX', rows: 0 }] },
            agents: body.agents.map((a, i) => (lateNotJudged(i) ? { ...a, discoveredVia: ['gcp-sa'] } : a)),
        };
        results = scoreReportLocally(input(mixed));
        matrix = sectionOf(renderSummaryHtml(results), 'matrix');
    });

    it('every agent that could not be judged is shown, though each sorts after the cap by id', () => {
        expect(results.estate.notJudgedCount).toBe(120);
        for (let i = TOTAL - 120; i < TOTAL; i++) expect(matrix).toContain(`<code class="id">${scaleAgentId(i)}</code>`);
        expect(count(matrix, '<span class="tag warn">Not judged</span>')).toBe(2 * 120);
        expect(count(matrix, '<th scope="row" class="agent">')).toBe(MATRIX_MAX_AGENTS);
    });

    it('they come first, then agents below their bar, in order of id within each', () => {
        const ids = [...matrix.matchAll(/<th scope="row" class="agent">(?:<span class="name">[^<]*<\/span>[^<]*<span class="decl">[^<]*<\/span><br>)?<code class="id">([^<]+)<\/code>/g)].map((m) => m[1]);
        expect(ids).toHaveLength(MATRIX_MAX_AGENTS);
        const byId = new Map(results.agents.map((a) => [a.discoveredId, a]));
        const rank = (id: string): number => {
            const j = byId.get(id)!.judgement;
            return j.state !== 'JUDGED' ? 0 : j.shortfall ? 1 : 2;
        };
        const ranks = ids.map(rank);
        expect([...ranks].sort((a, b) => a - b)).toEqual(ranks);
        for (const r of [0, 1, 2]) {
            const group = ids.filter((id) => rank(id) === r);
            expect([...group].sort()).toEqual(group);
        }
        // Nobody left out needed a reader more than somebody shown.
        const leftOut = results.agents.filter((a) => !ids.includes(a.discoveredId)).map((a) => rank(a.discoveredId));
        expect(Math.min(...leftOut)).toBeGreaterThanOrEqual(Math.max(...ranks));
        expect(matrix).toContain(`The counts above are over all ${TOTAL}.`);
    });
});

describe('5. a run the caps do not reach is rendered as it always was', () => {
    it('at the matrix cap exactly: no notice anywhere, every agent, finding and credential shown', () => {
        const results = scaleResults(MATRIX_MAX_AGENTS, { unbound: SECTION_MAX_ROWS, absent: SECTION_MAX_ROWS });
        const page = renderSummaryHtml(results);
        expect(results.findings.length).toBeLessThanOrEqual(FINDINGS_MAX_ROWS);
        expect(page).not.toContain('This list shows the first');
        expect(page).not.toContain('This table shows the first');
        const matrix = sectionOf(page, 'matrix');
        expect(count(matrix, '<th scope="row" class="agent">')).toBe(MATRIX_MAX_AGENTS);
        // In order of id, as the results list them.
        const ids = [...matrix.matchAll(/<code class="id">(entra:sp:agent-\d+)<\/code>/g)].map((m) => m[1]);
        expect(ids).toEqual(results.agents.map((a) => a.discoveredId));
        expect(count(sectionOf(page, 'findings'), '<details>')).toBe(results.findings.length);
        expect(count(sectionOf(page, 'orphans'), '<tr><th scope="row">')).toBe(SECTION_MAX_ROWS);
        expect(count(sectionOf(page, 'shadow'), '<tr><th scope="row">')).toBe(results.estate.shadowAgents.length);
        expect(count(sectionOf(page, 'inventory'), '<li><code class="id">')).toBe(SECTION_MAX_ROWS);
    });

    it('one past a cap is where each notice starts', () => {
        const one = scaleResults(MATRIX_MAX_AGENTS + 1, { unbound: SECTION_MAX_ROWS + 1, absent: SECTION_MAX_ROWS + 1 });
        const page = renderSummaryHtml(one);
        expect(sectionOf(page, 'matrix')).toContain(`This table shows the first ${MATRIX_MAX_AGENTS} of ${MATRIX_MAX_AGENTS + 1} agents`);
        expect(sectionOf(page, 'orphans')).toContain(`the first ${SECTION_MAX_ROWS} of ${SECTION_MAX_ROWS + 1} orphan credentials`);
        expect(sectionOf(page, 'inventory')).toContain(`the first ${SECTION_MAX_ROWS} of ${SECTION_MAX_ROWS + 1} declared agents`);
    });

    it('credentials seen unbound and not concluded are capped the same way', () => {
        const base = scaleResults(4);
        const many: LocalResults = {
            ...base,
            estate: {
                ...base.estate,
                unboundNotConcluded: Array.from({ length: SECTION_MAX_ROWS + 7 }, (_, i) => ({ ref: `entra://app/held-${i}/password/1`, sourceKind: 'entra-sp', why: 'OWN_SOURCE_INCOMPLETE' as const })),
            },
        };
        const orphans = sectionOf(renderSummaryHtml(many), 'orphans');
        expect(orphans).toContain(`This list shows the first ${SECTION_MAX_ROWS} of ${SECTION_MAX_ROWS + 7} credentials seen unbound`);
        expect(count(orphans, '<code>OWN_SOURCE_INCOMPLETE</code>')).toBe(SECTION_MAX_ROWS);
    });
});
