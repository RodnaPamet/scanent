/**
 * `report.pdf` — the results as a document to file, print or send.
 *
 * WRITTEN IN THIS PROCESS by pdfkit, a JavaScript PDF library: no browser, no
 * native module, no network. It says what `summary.html` says, from the same
 * data (`summaryPageData`: the shared table model's rows, in its order, and
 * the fixed words of `words.ts`), in this order:
 *
 *   cover          scan, time, scanner, manifest hash, the estate in numbers
 *   completeness   per source, FIRST, and what this run could not evidence
 *   findings       by severity, then each, most severe first
 *   levels         one row per agent: registration, reach, level, bar
 *   matrix         agents × criteria, by the state codes, on landscape pages
 *   agents         one section per agent: every criterion by its state
 *   lists          shadow agents, unregistered identities, orphan credentials
 *   comparison     with the previous run, when the run knew one
 *   limits         what the results do not say
 *
 * Every list over its cap says how many it shows and which file holds the rest.
 *
 * REAL TEXT. Every word is text in a standard PDF font (Helvetica, Courier),
 * which a reader selects and searches; no font is embedded, so no font licence
 * applies. Those fonts cover Latin-1 and the Windows-1252 punctuation. A
 * character outside that set is written as `\u{…}` and a control character
 * likewise, so what was there can still be read; `summary.html` and the CSV
 * files hold such text as it was.
 *
 * THE SAME INPUT GIVES THE SAME BYTES. The document's dates are the scan's own
 * `asOf`, its identifier is pdfkit's hash of those fields, and nothing else
 * varies, so a test can hash it.
 *
 * NOTHING SECRET. The renderer returns, beside the bytes, every string it
 * wrote, so the file output can refuse the file by the same check it applies
 * to every other one.
 */
import PDFDocument from 'pdfkit';

import type { HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';
import { MATRIX_MAX_AGENTS } from '@scanent/report/render/html';
import { INTEGRATION_RUN_FILE_NAMES, INTEGRATIONS_ONLY_RUN_FILE_NAMES } from '@scanent/report/render/files';
import {
    applicationsByConcern,
    exclusionText,
    INTEGRATIONS_COLUMNS,
    integrationCells,
    NOT_CONCLUDED_TEXT,
    NOT_SEEN_TEXT,
    notConcludedByProduct,
    permissionPlace,
    productOfKind,
    webhookLine,
} from '@scanent/report/render/integrations-page';
import { productOfApplicationId } from '@rodnapamet/scanent-contract/integrations-contract-rules';
import { findingRef, summaryPageData, type AgentRecord, type IntegrationsPreviousRun, type SummaryContext, type SummaryPageData } from '@scanent/report/render/page-data';
import { criterionWords, PREVIOUS_NOT_COMPARED_TEXT } from '@scanent/report/render/words';
import type { IntegrationsOnlyResults, LocalIntegrationsResults, LocalResults } from '@scanent/report/results/types';

/** The most agents the levels table and the matrix list: the page's own matrix cap. */
export const PDF_AGENTS_MAX = MATRIX_MAX_AGENTS;
/** The most agents given a section of their own, in the model's order (worst first). */
export const PDF_AGENT_SECTIONS_MAX = 100;
/** The most findings listed with their description, most severe first. */
export const PDF_FINDINGS_MAX = 300;
/** The most entries any other list holds. */
export const PDF_LIST_MAX = 500;

export interface RenderedPdf {
    readonly bytes: Uint8Array;
    /** Every string written into the document, one per line: what the secret check reads. */
    readonly text: string;
}

// ── Text the standard fonts can show ──

/** Windows-1252's characters above Latin-1's range, which the standard fonts carry. */
const WIN_ANSI_EXTRA = new Set([
    0x152, 0x153, 0x160, 0x161, 0x178, 0x17d, 0x17e, 0x192, 0x2c6, 0x2dc, 0x2013, 0x2014, 0x2018, 0x2019, 0x201a, 0x201c, 0x201d, 0x201e, 0x2020, 0x2021,
    0x2022, 0x2026, 0x2030, 0x2039, 0x203a, 0x20ac, 0x2122,
]);

/** One line of text as the standard fonts can show it; anything else as a visible escape. */
export function pdfText(value: string): string {
    let out = '';
    for (const ch of value) {
        const code = ch.codePointAt(0) as number;
        const shown = (code >= 0x20 && code <= 0x7e) || (code >= 0xa0 && code <= 0xff) || WIN_ANSI_EXTRA.has(code);
        out += shown ? ch : `\\u{${code.toString(16)}}`;
    }
    return out;
}

// ── Layout ──

const MARGIN = 48;
const FONT = 'Helvetica';
const BOLD = 'Helvetica-Bold';
const MONO = 'Courier';
const INK = '#1a1f24';
const MUTED = '#4a5560';
const LINE = '#c9d1d9';
const BAD = '#a4262c';

/** Light fills for the cell codes; the code letter is always printed, so colour is never the only signal. */
const CELL_FILL: Readonly<Record<string, string>> = {
    'c-e': '#dcefe2',
    'c-d': '#e9e1f8',
    'c-m': '#fbedc4',
    'c-n': '#f8d9dc',
    'c-u': '#ffffff',
    'c-x': '#eceff2',
};

interface Column {
    readonly title: string;
    readonly width: number;
    readonly mono?: boolean;
}

class Writer {
    readonly lines: string[] = [];

    constructor(readonly doc: PDFDocument) {}

    get left(): number {
        return this.doc.page.margins.left;
    }

    get width(): number {
        return this.doc.page.width - this.doc.page.margins.left - this.doc.page.margins.right;
    }

    get bottom(): number {
        return this.doc.page.height - this.doc.page.margins.bottom;
    }

    /** Start a new page when fewer than `height` points are left on this one. */
    ensure(height: number): void {
        if (this.doc.y + height > this.bottom) this.page();
    }

    page(layout: 'portrait' | 'landscape' = 'portrait'): void {
        this.doc.addPage({ size: 'A4', layout, margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN } });
        this.doc.x = this.left;
        this.doc.y = MARGIN;
    }

    /** Write a paragraph, logging it. */
    para(text: string, opts: { font?: string; size?: number; color?: string; gap?: number; indent?: number } = {}): void {
        const shown = pdfText(text);
        this.lines.push(shown);
        const size = opts.size ?? 10;
        this.doc.font(opts.font ?? FONT).fontSize(size).fillColor(opts.color ?? INK);
        const indent = opts.indent ?? 0;
        const width = this.width - indent;
        this.ensure(Math.min(this.doc.heightOfString(shown, { width }), size * 3));
        this.doc.text(shown, this.left + indent, this.doc.y, { width });
        this.doc.y += opts.gap ?? 4;
    }

    heading(text: string, level: 1 | 2 | 3): void {
        const size = level === 1 ? 18 : level === 2 ? 14 : 11.5;
        this.ensure(size * 4);
        if (level < 3) this.doc.y += 6;
        this.para(text, { font: BOLD, size, gap: level === 3 ? 3 : 6 });
    }

    bullet(text: string, opts: { font?: string; size?: number; color?: string } = {}): void {
        this.para(`•  ${text}`, { ...opts, indent: 8, gap: 2 });
    }

    /** Label and value pairs, one per line. */
    facts(pairs: readonly (readonly [string, string])[], mono: readonly string[] = []): void {
        for (const [label, value] of pairs) {
            const shownLabel = pdfText(label);
            const shownValue = pdfText(value);
            this.lines.push(`${shownLabel}: ${shownValue}`);
            const labelWidth = 150;
            const valueFont = mono.includes(label) ? MONO : FONT;
            this.doc.font(valueFont).fontSize(9.5);
            const h = Math.max(12, this.doc.heightOfString(shownValue, { width: this.width - labelWidth }));
            this.ensure(h);
            const y = this.doc.y;
            this.doc.font(BOLD).fontSize(9.5).fillColor(MUTED).text(shownLabel, this.left, y, { width: labelWidth - 8 });
            this.doc.font(valueFont).fontSize(9.5).fillColor(INK).text(shownValue, this.left + labelWidth, y, { width: this.width - labelWidth });
            this.doc.y = y + h + 3;
        }
        this.doc.x = this.left;
    }

    /** A table that breaks across pages, repeating its header. */
    table(columns: readonly Column[], rows: readonly (readonly string[])[], size = 8.5): void {
        const header = (): void => {
            this.doc.font(BOLD).fontSize(size);
            const h = Math.max(...columns.map((c) => this.doc.heightOfString(pdfText(c.title), { width: c.width - 6 }))) + 6;
            this.ensure(h + size * 2);
            const y = this.doc.y;
            this.doc.rect(this.left, y, columns.reduce((n, c) => n + c.width, 0), h).fill('#eef1f4');
            let x = this.left;
            for (const c of columns) {
                this.doc.font(BOLD).fontSize(size).fillColor(INK).text(pdfText(c.title), x + 3, y + 3, { width: c.width - 6 });
                x += c.width;
            }
            this.doc.y = y + h;
        };
        this.lines.push(columns.map((c) => pdfText(c.title)).join(' | '));
        header();
        for (const row of rows) {
            const cells = row.map((cell) => pdfText(cell));
            this.lines.push(cells.join(' | '));
            const h = Math.max(...cells.map((cell, i) => this.doc.font(columns[i].mono === true ? MONO : FONT).fontSize(size).heightOfString(cell, { width: columns[i].width - 6 }))) + 5;
            if (this.doc.y + h > this.bottom) {
                this.page();
                header();
            }
            const y = this.doc.y;
            let x = this.left;
            cells.forEach((cell, i) => {
                const c = columns[i];
                this.doc.font(c.mono === true ? MONO : FONT).fontSize(size).fillColor(INK).text(cell, x + 3, y + 2.5, { width: c.width - 6 });
                x += c.width;
            });
            this.doc.y = y + h;
            this.doc.moveTo(this.left, this.doc.y).lineTo(x, this.doc.y).lineWidth(0.4).stroke(LINE);
        }
        this.doc.x = this.left;
        this.doc.y += 6;
    }

    /** A notice that a list was cut, naming the file that holds the rest. */
    capped(shown: number, total: number, what: string, file: string): void {
        if (total > shown) this.para(`This list shows the first ${shown} of ${total} ${what}. The full list is in ${file}.`, { color: MUTED, size: 9 });
    }
}

const levelText = (d: SummaryPageData, level: HarnessLevel | null): string =>
    level === null ? 'Not judged' : `${level} ${d.levels.find((l) => l.level === level)?.name ?? ''}`;
const word = (table: Readonly<Record<string, string>>, key: string, fallback: string): string => (Object.prototype.hasOwnProperty.call(table, key) ? table[key] : fallback);
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
const agentLabel = (a: AgentRecord): string => (a.name === null ? a.id : `${a.id} (${a.name}, name declared by the operator)`);
const levelCell = (d: SummaryPageData, a: AgentRecord): string =>
    !a.judged ? 'Not judged' : a.observed !== a.level ? `${levelText(d, a.level)}; ${a.observed} on observation alone` : levelText(d, a.level);
const barCell = (d: SummaryPageData, a: AgentRecord): string => `${a.bar}: ${word(d.text.standing, a.standing, a.standing)}`;

function cover(w: Writer, d: SummaryPageData, results: LocalResults): void {
    w.para('scanent, the Agent Estate Scanner', { color: MUTED, size: 10 });
    w.heading('Agent estate scan results', 1);
    const incomplete = d.sources.filter((s) => s.status !== 'COMPLETE');
    w.para(
        d.sources.length === 0
            ? 'Incomplete: the report lists no source, so this scan evidences nothing.'
            : incomplete.length === 0
                ? 'Complete. Every listed source was read in full.'
                : `Incomplete: ${incomplete.length} of ${plural(d.sources.length, 'source was', 'sources were')} not read in full. Read the completeness section first.`,
        { font: BOLD, color: incomplete.length > 0 || d.sources.length === 0 ? BAD : INK, gap: 10 },
    );
    w.facts(
        [
            ['Estate', d.scan.estate ?? 'Not stated (scored from a bare report)'],
            ['Scan', d.scan.id],
            ['As of (UTC)', d.scan.asOf],
            ['Scanner', `${d.scan.scanner}, version ${d.scan.version}`],
            ['Scanner manifest', results.scan.scanner.manifestHash],
            ['Report contract', d.scan.contract],
            ['Ladder version', d.scan.ladder],
            ['Signed report SHA-256', results.report.sha256],
            ['Signer', results.report.signerPinned ? 'Pinned: verified against a key supplied apart from the report' : 'Not pinned: verified against the key the report itself carries'],
        ],
        ['Scan', 'Scanner manifest', 'Ladder version', 'Signed report SHA-256'],
    );
}

function estate(w: Writer, d: SummaryPageData): void {
    const e = d.estate;
    w.heading('The estate in numbers', 2);
    if (d.completeness === 'EMPTY') {
        w.para('This scan found no agents. That is a finding, not a clean result. No level is stated for anything.', { font: BOLD, color: BAD });
    }
    const incomplete = d.sources.filter((s) => s.status !== 'COMPLETE').length;
    w.facts([
        ['Agents found', String(e.agentCount)],
        ['Judged', `${e.judgedCount} (have a level)`],
        ['Not judged', `${e.notJudgedCount} (no level stated)`],
        ['Below their bar', `${e.shortfallCount} of the judged agents held to a bar`],
        ['Shadow agents', String(e.shadow.length)],
        ...(e.identities === null ? [] : [['Unregistered identities', `${e.identities.length} (no sign of a model; held to no bar)`] as const]),
        ['Orphan credentials', String(e.orphans.length)],
        ...(e.paying === null ? [] : [['Can pay', `${e.paying.length} (code calls a payment client)`] as const]),
        ['Sources incomplete', `${incomplete} of ${d.sources.length}`],
        ['Findings', String(d.findings.length)],
        ['Registration from', e.registration],
    ]);
    if (d.completeness !== 'EMPTY') {
        w.heading('Judged agents per level', 3);
        const most = Math.max(1, ...d.levels.map((l) => e.byLevel[l.level] ?? 0));
        for (const l of [...d.levels].reverse()) {
            const n = e.byLevel[l.level] ?? 0;
            w.ensure(14);
            const y = w.doc.y;
            const label = pdfText(`${l.level} ${l.name}`);
            w.lines.push(`${label}: ${n}`);
            w.doc.font(FONT).fontSize(9).fillColor(INK).text(label, w.left, y, { width: 140 });
            w.doc.rect(w.left + 150, y + 1, 220, 8).fill('#eef1f4');
            if (n > 0) w.doc.rect(w.left + 150, y + 1, (220 * n) / most, 8).fill('#0b5cad');
            w.doc.font(BOLD).fontSize(9).fillColor(INK).text(String(n), w.left + 380, y, { width: 60 });
            w.doc.y = y + 13;
        }
        w.para(`Not judged, and not counted above: ${e.notJudgedCount}.`, { size: 9, color: MUTED });
    }
}

function completeness(w: Writer, d: SummaryPageData): void {
    w.heading('1. Completeness per source', 2);
    if (d.sources.length === 0) {
        w.para('The report lists no source at all. A scan that looked nowhere evidences nothing.', { font: BOLD, color: BAD });
    } else {
        w.para(
            d.scan.complete
                ? 'Every source this scan lists was read in full, so each result below rests on a whole read.'
                : 'A source that was not read in full may hold agents, tools and verdicts this document does not show. Nothing here is shown as gone, closed or resolved on a partial read.',
        );
        const ordered = [...d.sources.filter((s) => s.status !== 'COMPLETE'), ...d.sources.filter((s) => s.status === 'COMPLETE')];
        w.table(
            [
                { title: 'Source', width: 120, mono: true },
                { title: 'Status', width: 80 },
                { title: 'Reason', width: 140, mono: true },
                { title: 'Rows read', width: 80 },
                { title: 'Agents found', width: 79 },
            ],
            ordered.map((s) => [s.kind, s.status === 'COMPLETE' ? 'Complete' : 'Incomplete', s.reason ?? '', String(s.rows), String(s.agents)]),
        );
        for (const s of ordered) if (s.detail !== null) w.para(`${s.kind} was not read in full: ${s.detail}.${s.notReadTotal > 0 ? ` ${plural(s.notReadTotal, 'place was', 'places were')} not read; results.json names them.` : ''}`, { size: 9 });
    }
    w.heading('What this scan could not evidence', 3);
    w.para(
        `The highest level this run could have stated for any agent is ${levelText(d, d.coverage.reachable)}. A criterion nobody answered counts as not met, so no agent is shown above that level, whatever its real state. The bar is ${d.bars.readOnly} for an agent that only reads and ${d.bars.write} for one that can write or reach outside the estate.`,
    );
    if (d.coverage.unreadable.length > 0) {
        w.table(
            [
                { title: 'Criterion with no configured reader', width: 170, mono: true },
                { title: 'Why', width: 200 },
                { title: 'Readers that would', width: 129 },
            ],
            d.coverage.unreadable.map((u) => [u.criterion, `${word(d.text.unreadable, u.why, 'See the code')} (${u.why})`, u.readers.length === 0 ? 'None' : u.readers.join(', ')]),
        );
    }
}

function findings(w: Writer, d: SummaryPageData): void {
    w.heading('2. Findings by severity', 2);
    const counts = new Map<string, number>();
    for (const f of d.findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
    w.facts(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => [word(d.text.severity, s, s), String(counts.get(s) ?? 0)] as const));
    if (d.findings.length === 0) {
        w.para(d.scan.complete ? 'No finding was raised.' : 'No finding was raised. The scan is incomplete, so this is not a clean result.');
        return;
    }
    const shown = d.findings.slice(0, PDF_FINDINGS_MAX);
    w.capped(shown.length, d.findings.length, 'findings, most severe first', d.files.findings);
    for (const f of shown) {
        w.ensure(40);
        w.para(`${f.severity}  ${f.code}  ${f.agent === null ? (f.code === 'SPENDING_AGENT_UNDECLARED' ? 'One registration, several agents' : 'The scan') : f.agent}`, { font: BOLD, size: 9, gap: 1 });
        w.para(f.title, { size: 9, gap: 1 });
        if (f.description !== null) w.para(f.description, { size: 8.5, color: MUTED, gap: 1 });
        w.para(`Reference ${findingRef(f)}`, { font: MONO, size: 7.5, color: MUTED, gap: 6 });
    }
}

function levels(w: Writer, d: SummaryPageData): void {
    w.page();
    w.heading('3. Agents and their levels', 2);
    w.para('One row per agent, those that most need a reader first: not judged, then below their bar, then the lowest levels. An unregistered automated identity is held to no bar.');
    const shown = d.agents.slice(0, PDF_AGENTS_MAX);
    w.capped(shown.length, d.agents.length, 'agents', d.files.agents);
    w.table(
        [
            { title: 'Agent', width: 175, mono: true },
            { title: 'Registration', width: 82 },
            { title: 'Reach', width: 62 },
            { title: 'Level', width: 100 },
            { title: 'Bar', width: 80 },
        ],
        shown.map((a) => [agentLabel(a), word(d.text.registration, a.reg, 'Not stated'), word(d.text.reach, a.reach, 'Unknown'), levelCell(d, a), barCell(d, a)]),
        8,
    );
}

function matrix(w: Writer, d: SummaryPageData): void {
    w.page('landscape');
    w.heading('4. Agents and criteria', 2);
    w.para('Each cell is the shared table model\'s state for one criterion, by its code. The criteria are numbered; the key is below the table.', { size: 9 });
    w.para(d.states.map((s) => `${s.code} ${s.text}`).join('.  ') + '.', { size: 8, color: MUTED });
    const shown = d.agents.slice(0, PDF_AGENTS_MAX);
    w.capped(shown.length, d.agents.length, 'agents', d.files.agents);
    const doc = w.doc;
    const idWidth = 200;
    const lvlWidth = 46;
    const cellW = 18;
    const rowH = 12;
    const head = (): void => {
        w.ensure(rowH * 4);
        let y = doc.y;
        let x = w.left + idWidth + lvlWidth * 2;
        for (const g of d.columns) {
            const width = g.criteria.length * cellW;
            doc.rect(x, y, width, rowH).fill('#eef1f4');
            doc.font(BOLD).fontSize(7).fillColor(INK).text(pdfText(g.level), x, y + 2.5, { width, align: 'center' });
            x += width;
        }
        y += rowH;
        doc.font(BOLD).fontSize(7).fillColor(INK);
        doc.text('Agent', w.left + 2, y + 2.5, { width: idWidth - 4 });
        doc.text('Level', w.left + idWidth + 2, y + 2.5, { width: lvlWidth - 4 });
        doc.text('Standing', w.left + idWidth + lvlWidth + 2, y + 2.5, { width: lvlWidth - 4 });
        d.criteria.forEach((_c, i) => doc.text(String(i + 1), w.left + idWidth + lvlWidth * 2 + i * cellW, y + 2.5, { width: cellW, align: 'center' }));
        doc.y = y + rowH;
    };
    w.lines.push(['Agent', 'Level', 'Standing', ...d.criteria.map((_c, i) => String(i + 1))].join(' | '));
    head();
    const standingShort: Readonly<Record<string, string>> = { AT_BAR: 'At bar', BELOW_BAR: 'Below', NOT_JUDGED: 'Not judged', NO_BAR: 'No bar' };
    for (const a of shown) {
        if (doc.y + rowH > w.bottom) {
            w.page('landscape');
            head();
        }
        const y = doc.y;
        const id = pdfText(a.id);
        const level = a.judged ? (a.level as string) : '-';
        const standing = word(standingShort, a.standing, a.standing);
        doc.font(MONO).fontSize(6.5).fillColor(INK).text(id.length > 54 ? `${id.slice(0, 53)}…` : id, w.left + 2, y + 3, { width: idWidth - 4, lineBreak: false });
        doc.font(FONT).fontSize(7).fillColor(INK).text(level, w.left + idWidth + 2, y + 2.5, { width: lvlWidth - 4, lineBreak: false });
        doc.font(FONT).fontSize(7).fillColor(a.standing === 'BELOW_BAR' ? BAD : INK).text(standing, w.left + idWidth + lvlWidth + 2, y + 2.5, { width: lvlWidth - 4, lineBreak: false });
        const codes: string[] = [];
        for (let i = 0; i < d.criteria.length; i++) {
            const state = d.states[Number(a.cells.charAt(i))];
            const x = w.left + idWidth + lvlWidth * 2 + i * cellW;
            doc.rect(x + 0.5, y + 0.5, cellW - 1, rowH - 1).fill(CELL_FILL[state.cls] ?? '#ffffff');
            doc.font(BOLD).fontSize(7.5).fillColor(INK).text(state.code, x, y + 2.5, { width: cellW, align: 'center', lineBreak: false });
            codes.push(state.code);
        }
        w.lines.push(`${id} | ${level} | ${standing} | ${codes.join(' ')}`);
        doc.y = y + rowH;
        doc.moveTo(w.left, doc.y).lineTo(w.left + idWidth + lvlWidth * 2 + d.criteria.length * cellW, doc.y).lineWidth(0.3).stroke(LINE);
    }
    doc.x = w.left;
    doc.y += 8;
    w.heading('Key to the criteria', 3);
    const half = Math.ceil(d.criteria.length / 2);
    const keyRows = Array.from({ length: half }, (_, i) => {
        const right = d.criteria[i + half];
        return [`${i + 1}`, d.criteria[i], criterionWords(d.criteria[i]), right === undefined ? '' : `${i + half + 1}`, right ?? '', right === undefined ? '' : criterionWords(right)];
    });
    w.table(
        [
            { title: 'No.', width: 30 },
            { title: 'Criterion', width: 140, mono: true },
            { title: 'In words', width: 200 },
            { title: 'No.', width: 30 },
            { title: 'Criterion', width: 140, mono: true },
            { title: 'In words', width: 205 },
        ],
        keyRows,
        7.5,
    );
}

function agentSections(w: Writer, d: SummaryPageData): void {
    w.page();
    w.heading('5. Each agent', 2);
    const shown = d.agents.slice(0, PDF_AGENT_SECTIONS_MAX);
    w.para('One section per agent, in the order of the table above. Every criterion is listed under its state.');
    w.capped(shown.length, d.agents.length, 'agents', d.files.agents);
    const byAgent = new Map<string, SummaryPageData['findings'][number][]>();
    for (const f of d.findings) if (f.agent !== null) byAgent.set(f.agent, [...(byAgent.get(f.agent) ?? []), f]);
    for (const a of shown) {
        w.ensure(140);
        w.heading(a.name === null ? a.id : a.name, 3);
        const source = new Map(d.sources.map((s) => [s.kind, s]));
        w.facts(
            [
                ['Id', a.id],
                ...(a.name === null ? [] : [['Name', `${a.name} (declared by the operator)`] as const]),
                ['Classification', word(d.text.classification, a.cls, a.cls)],
                ['Registration', `${word(d.text.registration, a.reg, 'Not stated')}${a.ref === null ? '' : ` (${a.ref})`}`],
                ['Reach', word(d.text.reach, a.reach, 'Unknown')],
                [
                    'Found through',
                    a.via
                        .map((k) => {
                            const s = source.get(k);
                            return `${k} (${s === undefined ? 'not listed as a source' : s.status === 'COMPLETE' ? 'read in full' : `not read in full: ${s.reason ?? 'no reason given'}`})`;
                        })
                        .join(', '),
                ],
                ...(a.owner === null ? [] : [['Owner', `${a.owner} (declared by the operator)`] as const]),
                ...(a.purpose === null ? [] : [['Purpose', `${a.purpose} (declared by the operator)`] as const]),
                ['Owner observed', a.observedOwner === null ? 'None read from the estate' : `${a.observedOwner.kind} ${a.observedOwner.ref}`],
                ['Level', levelCell(d, a)],
                [
                    'Bar',
                    a.standing === 'NO_BAR'
                        ? `Held to no bar: an unregistered automated identity. Against the bar its reach would carry (${a.bar}), its level is ${a.barStatus === 'BELOW_BAR' ? 'below it' : 'at it'}.`
                        : a.standing === 'NOT_JUDGED'
                            ? `${a.bar}. No level is stated, so it is not compared with the bar.`
                            : `${a.bar}, and it is ${a.standing === 'BELOW_BAR' ? 'below it' : 'at it'}.`,
                ],
                ...(a.blocking !== null && a.blocking.length > 0 ? [['Next rung needs', a.blocking.join(', ')] as const] : []),
                ['Credentials, tools', `${a.counts[0]} credentials; ${a.counts[1]} tools, ${a.counts[2]} that can write, ${a.counts[3]} of those not pinned`],
                [
                    'Payment',
                    a.pay === null
                        ? 'Not reported'
                        : a.pay.length === 0
                            ? 'Code read; no payment client seen in the agent\'s own file. Not evidence that it cannot pay.'
                            : a.pay.map((p) => `${p.library} (${p.protocol}) at ${p.at}`).join('; '),
                ],
            ],
            ['Id', 'Registration', 'Found through', 'Owner observed'],
        );
        if (!a.judged) {
            w.para('Not judged: no level is stated for this agent.', { font: BOLD, size: 9, color: BAD, gap: 1 });
            for (const code of a.notes) w.bullet(`${word(d.text.reasons, code, 'See the code')}. ${code}`, { size: 8.5 });
        } else if (a.notes.length > 0) {
            for (const code of a.notes) w.bullet(`Caveat: ${word(d.text.reasons, code, 'See the code')}. ${code}`, { size: 8.5 });
        }
        d.states.forEach((state, s) => {
            const criteria = d.criteria.flatMap((c, i) => (Number(a.cells.charAt(i)) === s ? [i] : []));
            if (criteria.length === 0) return;
            const items = criteria.map((i) => {
                const ev = a.ev.findIndex((v, k) => k % 2 === 0 && v === i);
                const evidence = ev < 0 ? null : d.evidence[a.ev[ev + 1]];
                return evidence === undefined || evidence === null ? d.criteria[i] : `${d.criteria[i]} (evidence ${evidence.t})`;
            });
            w.para(`${state.code} ${state.label}: ${items.join('; ')}`, { size: 8.5, gap: 2 });
        });
        const own = byAgent.get(a.id) ?? [];
        w.para(own.length === 0 ? 'Findings: none about this agent.' : `Findings: ${own.map((f) => `${f.severity} ${f.code}`).join('; ')}`, { size: 8.5, color: MUTED, gap: 8 });
    }
}

function lists(w: Writer, d: SummaryPageData): void {
    const e = d.estate;
    const none = d.scan.complete ? 'None.' : 'None raised. The scan is incomplete, so this is not a statement that none exist.';
    w.heading('6. Shadow agents, unregistered identities and orphan credentials', 2);
    const list = (title: string, ids: readonly string[], intro: string, file: string): void => {
        w.heading(`${title} (${ids.length})`, 3);
        w.para(intro, { size: 9 });
        if (ids.length === 0) {
            w.para(none, { size: 9 });
            return;
        }
        const shown = ids.slice(0, PDF_LIST_MAX);
        w.capped(shown.length, ids.length, title.toLowerCase(), file);
        for (const id of shown) w.bullet(id, { font: MONO, size: 8 });
    };
    list('Shadow agents', e.shadow, e.identities === null ? 'Agents found by this scan that are not registered.' : 'Not registered, and showing a sign of a model.', d.files.agents);
    if (e.identities !== null) {
        list(
            'Unregistered identities',
            e.identities,
            'Not registered, and showing no sign of a model. The scan cannot show that one of these runs no model. None is held to the agent bar.',
            d.files.agents,
        );
    }
    list('Orphan credentials', e.orphans.map((o) => `${o.ref} (${o.kind})`), 'Credentials a source, read in full, saw bound to no agent.', d.files.results);
    if (e.unbound.length > 0) {
        list(
            'Seen unbound, not concluded',
            e.unbound.map((u) => `${u.ref} (${u.kind}): ${word(d.text.unbound, u.why, 'See the code')}`),
            'Seen bound to no agent; this scan could not conclude that none uses them.',
            d.files.results,
        );
    }
    if (e.paying !== null) list('Agents whose code calls a payment client', e.paying, 'Read from code. Where none is seen, that is what the reader saw in the agent\'s own file, not evidence that it cannot pay.', d.files.agents);
}

function comparison(w: Writer, d: SummaryPageData): void {
    const c = d.drift;
    if (c === null) return;
    w.heading('7. Since the previous run', 2);
    if (c.kind === 'FIRST') {
        w.para('This output directory held no earlier run, so there is nothing to compare with.');
        return;
    }
    if (c.kind === 'NOT_COMPARED') {
        w.para(`Not compared with ${c.scanId ?? 'the previous run'}: ${c.text}.`);
        return;
    }
    w.para(`Compared with ${c.old.scanId}, as of ${c.old.asOf} UTC (${c.old.complete ? 'complete' : 'incomplete'}, ${plural(c.old.agentCount, 'agent', 'agents')}). ${c.outcomeText}`);
    w.para(`${plural(c.differences, 'difference', 'differences')}; ${plural(c.notConcludedCount, 'comparison', 'comparisons')} not concluded. The full comparison is scanent diff on the two results files.`, { size: 9 });
    for (const warning of c.warnings) w.bullet(`${warning.code}: ${warning.text}.`, { size: 8.5 });
    const part = <T>(title: string, l: { readonly total: number; readonly rows: readonly T[] }, line: (x: T) => string, empty: string): void => {
        w.heading(`${title} (${l.total})`, 3);
        if (l.total === 0) w.para(empty, { size: 9 });
        for (const x of l.rows) w.bullet(line(x), { size: 8.5 });
        if (l.total > l.rows.length) w.para(`The first ${l.rows.length} of ${l.total}.`, { size: 8.5, color: MUTED });
    };
    part('Levels', c.levels, (l) => `${l.id}: ${l.text}${l.from !== null && l.to !== null ? `, ${l.from} to ${l.to}` : ''}`, 'No level changed where both runs judged the agent.');
    part('New agents', c.added, (id) => id, 'None.');
    part('Gone', c.gone, (id) => `${id} (every source it was found through was read in full)`, 'None concluded gone.');
    part('Not seen, not concluded', c.notSeen, (x) => `${x.id}: ${x.why}`, 'None.');
    part('Completeness', { total: c.sources.length, rows: c.sources }, (s) => `${s.kind} ${s.text}`, 'No source changed.');
    part('Findings', c.findings, (f) => `${f.code} ${f.change === 'NOT_CONCLUDED' ? `no longer reported, not concluded (${f.why ?? 'UNKNOWN'})` : f.change.toLowerCase()} ${f.ref}`, 'No finding opened or closed.');
}

/**
 * The integrations scanner's section, only for a run that configured it: its
 * sources' completeness first, then its findings, what it could not conclude,
 * and its applications, those with the most severe findings first.
 */
function integrationsSection(w: Writer, i: LocalIntegrationsResults, opts: { readonly previous?: IntegrationsPreviousRun | null; readonly alone?: boolean } = {}): void {
    if (opts.alone !== true) w.page();
    w.heading('Integrations', 2);
    w.para(
        `What the directories and organisations this run read (${i.sources.map((s) => productOfKind(s.kind)).join(', ')}) have granted to applications, and whether anybody owns those grants: the report ${i.report.file}, contract ${i.contract}, ${opts.alone === true ? "signed with the scanner's key" : 'signed with the same key as the agent report'}.`,
    );
    w.para(i.complete ? 'Complete. Every integrations source was read in full.' : 'Incomplete: not everything the integrations sources hold was read. A finding below is real; an absence is not a clean result.', {
        font: BOLD,
        color: i.complete ? INK : BAD,
    });
    w.facts([['Integrations report SHA-256', i.report.sha256]], ['Integrations report SHA-256']);
    w.table(
        [
            { title: 'Source', width: 105, mono: true },
            { title: 'Product', width: 70 },
            { title: 'Status', width: 55 },
            { title: 'Reason', width: 85, mono: true },
            { title: 'Rows read', width: 45 },
            { title: 'Applications', width: 55 },
            { title: 'Sign-in activity', width: 84 },
        ],
        i.sources.map((s) => [
            s.kind,
            productOfKind(s.kind),
            s.status === 'COMPLETE' ? 'Complete' : 'Incomplete',
            s.reason ?? '',
            String(s.rows),
            String(s.applications),
            s.kind === 'entra-integrations' ? `${s.signInActivity.status}${s.signInActivity.reason === null ? '' : ` ${s.signInActivity.reason}`}` : `Not exposed by ${productOfKind(s.kind)}`,
        ]),
    );
    for (const s of i.sources) if (s.detail !== undefined) w.para(`${s.kind} was not read in full: ${s.detail}.`, { size: 9 });
    for (const s of i.sources) if (s.excluded !== undefined) w.para(exclusionText(s.kind, s.excluded), { size: 8.5, color: MUTED });
    w.facts([
        ['Applications', String(i.counts.applications)],
        ['High-privilege grant', String(i.counts.highPrivilege)],
        ['Unverified publisher', String(i.counts.unverifiedPublisher)],
        ['No owner', String(i.counts.noOwner)],
        [`Unused for ${i.unusedDays} days`, String(i.counts.unused)],
    ]);
    w.heading('Integration findings', 3);
    const order: Readonly<Record<string, number>> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    const findings = i.findings.map((f, k): [typeof f, number] => [f, k]).sort(([a, x], [b, y]) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || x - y).map(([f]) => f);
    if (findings.length === 0) w.para(i.complete ? 'No integration finding was raised.' : 'No integration finding was raised. The integrations scan is incomplete, so this is not a clean result.');
    const shown = findings.slice(0, PDF_FINDINGS_MAX);
    w.capped(shown.length, findings.length, 'integration findings, most severe first', INTEGRATION_RUN_FILE_NAMES.findings);
    for (const f of shown) {
        w.ensure(40);
        w.para(`${f.severity}  ${f.code}  ${f.applicationId === null ? `A source (${productOfKind(f.sourceRef.slice(f.sourceRef.lastIndexOf(':') + 1))})` : `${productOfApplicationId(f.applicationId)}: ${f.applicationId}`}`, { font: BOLD, size: 9, gap: 1 });
        w.para(f.title, { size: 9, gap: 1 });
        w.para(f.description, { size: 8.5, color: MUTED, gap: 1 });
        w.para(`Reference ${f.sourceRef}`, { font: MONO, size: 7.5, color: MUTED, gap: 6 });
    }
    if (i.notConcluded.length > 0) {
        w.heading('Not concluded', 3);
        for (const p of notConcludedByProduct(i)) {
            w.para(p.product, { font: BOLD, size: 9, gap: 2 });
            for (const g of p.lines) {
                w.bullet(`${g.code} ${g.scoped ? `for ${plural(g.n, 'application', 'applications')}` : 'for every application'}: ${word(NOT_CONCLUDED_TEXT, g.why, 'see the code')} (${g.why}).`, { size: 8.5 });
            }
        }
    }
    w.heading('Applications', 3);
    const apps = applicationsByConcern(i);
    const listed = apps.slice(0, PDF_LIST_MAX);
    w.capped(listed.length, apps.length, 'applications', INTEGRATION_RUN_FILE_NAMES.applications);
    if (apps.length === 0) w.para(i.complete ? 'No application was reported. A directory read in full that holds none is a finding, not a clean result.' : 'No application was reported, and the read was not complete.');
    else {
        w.table(
            INTEGRATIONS_COLUMNS.map((title, k) => ({ title, width: [100, 45, 60, 40, 80, 65, 55, 54][k], mono: k === 0 })),
            listed.map(({ app, findings: own }) => integrationCells(app, own)),
            7,
        );
    }
    if (i.unknownPermissions.length > 0) {
        w.heading(`Permissions the classification does not know (${i.unknownPermissions.length})`, 3);
        w.para('Not called high and not called low: a person judges them.', { size: 9 });
        for (const u of i.unknownPermissions.slice(0, PDF_LIST_MAX)) w.bullet(`${u.name} on ${permissionPlace(u)}`, { font: MONO, size: 8 });
        w.capped(Math.min(PDF_LIST_MAX, i.unknownPermissions.length), i.unknownPermissions.length, 'unknown permissions', 'results.json');
    }
    if (i.webhooks !== null) {
        const hooks = i.webhooks.hooks;
        w.heading(`GitHub organisation webhooks (${hooks.length})`, 3);
        w.para('By target host only: a webhook URL can carry a secret in its path or query, so it is never kept. No finding is raised about a webhook in this version.', { size: 9 });
        if (!i.webhooks.read) w.para('The webhooks were not listed in full: this is what was seen, not the whole list.', { size: 9, color: BAD });
        if (hooks.length === 0) w.para(i.webhooks.read ? 'The organisation has no webhook.' : 'None was seen.', { size: 9 });
        for (const h of hooks.slice(0, PDF_LIST_MAX)) w.bullet(webhookLine(h), { size: 8.5 });
        w.capped(Math.min(PDF_LIST_MAX, hooks.length), hooks.length, 'webhooks', 'results.json');
    }
    if (opts.previous !== undefined) integrationsComparison(w, opts.previous);
}

/** The integrations compared with the previous run, by the same rules as the page: nothing not concluded is worded as a change. */
function integrationsComparison(w: Writer, previous: IntegrationsPreviousRun | null): void {
    w.heading('Integrations since the previous run', 3);
    if (previous === null) {
        w.para('This output directory held no earlier run, so there is nothing to compare with.', { size: 9 });
        return;
    }
    if (previous.kind === 'NOT_COMPARED') {
        w.para(`Not compared with ${previous.scanId ?? 'the previous run'}: ${word(PREVIOUS_NOT_COMPARED_TEXT, previous.reason, 'not compared')}.`, { size: 9 });
        return;
    }
    const d = previous.diff;
    const outcome =
        d.outcome === 'DIFFERENT'
            ? 'The integrations differ.'
            : d.outcome === 'SAME'
                ? 'No difference, and every comparison could be made.'
                : 'No difference was found, but not every comparison could be made. This is not a statement that nothing changed.';
    w.para(`Compared with ${d.old.scanId}, as of ${d.old.asOf} UTC (${d.old.complete ? 'complete' : 'incomplete'}, ${plural(d.old.applicationCount, 'application', 'applications')}). ${outcome}`, { size: 9 });
    w.para(`${plural(d.summary.differences, 'difference', 'differences')}; ${plural(d.summary.notConcluded, 'comparison', 'comparisons')} not concluded. The full comparison is scanent diff on the two results files.`, { size: 9 });
    const part = <T>(title: string, all: readonly T[], line: (x: T) => string, empty: string): void => {
        w.para(`${title} (${all.length})`, { font: BOLD, size: 9, gap: 2 });
        if (all.length === 0) w.para(empty, { size: 8.5 });
        for (const x of all.slice(0, PDF_LIST_MAX)) w.bullet(line(x), { size: 8.5 });
        if (all.length > PDF_LIST_MAX) w.para(`The first ${PDF_LIST_MAX} of ${all.length}.`, { size: 8.5, color: MUTED });
    };
    part('New applications', d.applications.added, (id) => `${productOfApplicationId(id)}: ${id}`, 'None.');
    part('Gone', d.applications.gone, (id) => `${productOfApplicationId(id)}: ${id} (its source was read in full)`, 'None concluded gone.');
    part('Not seen, not concluded', d.applications.notSeen, (x) => `${productOfApplicationId(x.id)}: ${x.id}: ${word(NOT_SEEN_TEXT, x.why, x.why)}`, 'None.');
    part(
        'Findings',
        d.findings,
        (f) => `${f.code} ${f.change === 'NOT_CONCLUDED' ? `no longer raised, not concluded (${f.why ?? 'UNKNOWN'})` : f.change.toLowerCase()} ${f.sourceRef}`,
        'No finding opened or closed.',
    );
}

function limits(w: Writer, d: SummaryPageData): void {
    w.heading('What this document does not say', 2);
    for (const c of d.text.caveats) w.bullet(c, { size: 9 });
    w.para(`The files of this run: ${Object.values(d.files).join(', ')}.`, { size: 9, color: MUTED });
}

function footers(w: Writer, d: { readonly scan: { readonly id: string; readonly asOf: string } }): void {
    const range = w.doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
        w.doc.switchToPage(range.start + i);
        const margins = w.doc.page.margins;
        const bottom = margins.bottom;
        margins.bottom = 0;
        const text = pdfText(`scanent results. Scan ${d.scan.id}, as of ${d.scan.asOf} UTC. Page ${i + 1} of ${range.count}.`);
        w.lines.push(text);
        w.doc.font(FONT).fontSize(7.5).fillColor(MUTED).text(text, margins.left, w.doc.page.height - 30, { width: w.doc.page.width - margins.left - margins.right, align: 'center', lineBreak: false });
        margins.bottom = bottom;
    }
}

function newDocument(title: string, asOf: string, subject: string): PDFDocument {
    const when = new Date(asOf);
    return new PDFDocument({
        size: 'A4',
        margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
        bufferPages: true,
        compress: true,
        displayTitle: true,
        lang: 'en',
        info: {
            Title: pdfText(title),
            Author: 'scanent, the Agent Estate Scanner',
            Subject: subject,
            Creator: 'scanent',
            Producer: 'scanent',
            CreationDate: when,
            ModDate: when,
        },
    });
}

function finish(w: Writer): RenderedPdf {
    w.doc.end();
    const chunks: Buffer[] = [];
    for (let chunk = w.doc.read(); chunk !== null; chunk = w.doc.read()) chunks.push(chunk);
    return { bytes: new Uint8Array(Buffer.concat(chunks)), text: `${w.lines.join('\n')}\n` };
}

/** The document, from the results and what the run knew of the run before it. */
export function renderReportPdf(results: LocalResults, context: SummaryContext = {}): RenderedPdf {
    const d = summaryPageData(results, context);
    const title = results.scan.estate === null ? `scanent results: ${results.scan.id}` : `scanent results: ${results.scan.estate}, ${results.scan.id}`;
    const w = new Writer(newDocument(title, results.scan.asOf, 'Agent estate scan results'));
    w.lines.push(pdfText(title));
    cover(w, d, results);
    estate(w, d);
    w.page();
    completeness(w, d);
    findings(w, d);
    if (d.completeness !== 'EMPTY') {
        levels(w, d);
        matrix(w, d);
        agentSections(w, d);
        w.page();
        lists(w, d);
    }
    comparison(w, d);
    if (results.integrations !== undefined) {
        integrationsSection(w, results.integrations, context.integrationsPrevious === undefined ? {} : { previous: context.integrationsPrevious });
    }
    limits(w, d);
    footers(w, d);
    return finish(w);
}

/** What the document of an integrations-only run says first, and again in its limits. */
export const PDF_NO_AGENT_SCAN_TEXT =
    'The agent scanner did not run: this configuration names no agent source. This document says nothing about agents, and nothing in it is an agent result, clean or otherwise.';

/**
 * The document of a run in which only the integrations scanner ran: a cover
 * that names the scanners that ran, the integrations section, and its limits.
 * No agent section, so no reader takes an absent agent scan for a clean one.
 */
export function renderIntegrationsOnlyPdf(results: IntegrationsOnlyResults, context: Pick<SummaryContext, 'integrationsPrevious'> = {}): RenderedPdf {
    const r = results;
    const i = r.integrations;
    const title = r.scan.estate === null ? `scanent results: ${r.scan.id}` : `scanent results: ${r.scan.estate}, ${r.scan.id}`;
    const w = new Writer(newDocument(title, r.scan.asOf, 'Integrations scan results'));
    w.lines.push(pdfText(title));
    w.para('scanent, the Agent Estate Scanner', { color: MUTED, size: 10 });
    w.heading('Integrations scan results', 1);
    w.para(i.complete ? 'Integrations: complete. Every integrations source was read in full.' : 'Integrations: incomplete. Read the integrations section\'s completeness first.', {
        font: BOLD,
        color: i.complete ? INK : BAD,
        gap: 6,
    });
    w.para(`No agent scan. ${PDF_NO_AGENT_SCAN_TEXT}`, { font: BOLD, gap: 10 });
    w.facts(
        [
            ['Estate', r.scan.estate ?? 'Not stated (scored from a bare report)'],
            ['Scan', r.scan.id],
            ['As of (UTC)', r.scan.asOf],
            ['Scanners that ran', 'The integrations scanner only'],
            ['Scanner', `${r.scan.scanner.agentId}, version ${r.scan.scanner.version}`],
            ['Scanner manifest', r.scan.scanner.manifestHash],
            ['Report contract', i.contract],
            ['Signed report SHA-256', i.report.sha256],
            ['Signer', r.signer.pinned ? 'Pinned: verified against a key supplied apart from the report' : 'Not pinned: verified against the key the report itself carries'],
        ],
        ['Scan', 'Scanner manifest', 'Signed report SHA-256'],
    );
    integrationsSection(w, i, { alone: true, ...(context.integrationsPrevious === undefined ? {} : { previous: context.integrationsPrevious }) });
    w.heading('What this document does not say', 2);
    for (const c of [
        PDF_NO_AGENT_SCAN_TEXT,
        'An application absent from this document is not concluded gone, unused or clean: only what a source read in full concludes an absence.',
        'A permission the classification does not know is neither high nor low. A person judges it.',
        'Whether an application should hold a grant is your organisation\'s decision. The scan shows what is held, and who owns it.',
    ]) {
        w.bullet(c, { size: 9 });
    }
    w.para(`The files of this run: ${Object.values(INTEGRATIONS_ONLY_RUN_FILE_NAMES).join(', ')}.`, { size: 9, color: MUTED });
    footers(w, { scan: { id: r.scan.id, asOf: r.scan.asOf } });
    return finish(w);
}
