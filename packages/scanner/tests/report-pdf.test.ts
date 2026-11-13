/**
 * `report.pdf`.
 *
 *   1. It is a PDF, written in this process, the same bytes for the same input,
 *      dated by the scan and by nothing else.
 *   2. Its words are real text, read back from the file, in the order the page
 *      keeps: completeness before any level.
 *   3. It says what the page says about what could not be read, not judged,
 *      not readable, empty, declared, and held to no bar.
 *   4. A large estate is cut where the page cuts it, and says so.
 *   5. A character the standard fonts cannot show is written as an escape.
 */
import type { LocalResults } from '@scanent/report/results/types';

import { PDF_AGENT_SECTIONS_MAX, PDF_AGENTS_MAX, pdfText, renderReportPdf } from '../src/report-pdf';
import { EXAMPLE_AGENT, pdfTextOf, scanExample } from './helpers/output-fixtures';

const T1 = Date.parse('2026-11-03T03:30:00.000Z');

let clean: LocalResults;
beforeAll(async () => {
    clean = (await scanExample(T1)).results;
});

const textOf = (r: LocalResults): { lines: string; joined: string } => pdfTextOf(renderReportPdf(r).bytes);

describe('1. a PDF, deterministic', () => {
    it('starts and ends as a PDF, and two renders are the same bytes', () => {
        const a = renderReportPdf(clean);
        const b = renderReportPdf(JSON.parse(JSON.stringify(clean)) as LocalResults);
        const latin = Buffer.from(a.bytes).toString('latin1');
        expect(latin.startsWith('%PDF-')).toBe(true);
        expect(latin.trimEnd().endsWith('%%EOF')).toBe(true);
        expect(Buffer.from(a.bytes).equals(Buffer.from(b.bytes))).toBe(true);
    });

    it('is dated by the scan, and names scanent as its maker, not the library', () => {
        const latin = Buffer.from(renderReportPdf(clean).bytes).toString('latin1');
        const stamp = clean.scan.asOf.replace(/[-:T]/g, '').slice(0, 14);
        // The information dictionary refers to its values; each date is the scan's, and there is no other date.
        expect(latin).toMatch(/\/CreationDate \d+ 0 R/);
        expect(latin).toMatch(/\/ModDate \d+ 0 R/);
        expect([...latin.matchAll(/\(D:(\d{14})Z\)/g)].map((m) => m[1])).toEqual([stamp, stamp]);
        expect(latin).toContain('(scanent)');
        expect(latin).not.toContain('PDFKit');
        // A different scan time is a different document; nothing else in the input is a clock.
        const later = renderReportPdf({ ...clean, scan: { ...clean.scan, asOf: '2026-11-04T03:30:00.000Z' } });
        expect(Buffer.from(later.bytes).equals(Buffer.from(renderReportPdf(clean).bytes))).toBe(false);
    });
});

describe('2. real text, in the page\'s order', () => {
    it('the cover names the scan, its time, the scanner\'s version and its manifest hash', () => {
        const { lines } = textOf(clean);
        for (const value of [clean.scan.id, clean.scan.asOf, clean.scan.scanner.version, 'Scanner manifest']) expect(lines).toContain(value);
        expect(textOf(clean).joined.replace(/\s/g, '')).toContain(clean.scan.scanner.manifestHash);
    });

    it('completeness comes before findings, findings before levels, levels before the matrix and each agent', () => {
        const { lines } = textOf(clean);
        const at = ['1. Completeness per source', 'What this scan could not evidence', '2. Findings by severity', '3. Agents and their levels', '4. Agents and criteria', '5. Each agent', 'What this document does not say'].map((h) => lines.indexOf(h));
        for (const i of at) expect(i).toBeGreaterThanOrEqual(0);
        expect([...at].sort((x, y) => x - y)).toEqual(at);
        expect(textOf(clean).joined).toContain(EXAMPLE_AGENT);
    });

    it('every page carries the scan and its page number', () => {
        const { lines } = textOf(clean);
        const pages = [...lines.matchAll(/Page (\d+) of (\d+)\./g)];
        expect(pages.length).toBeGreaterThan(3);
        expect(pages.map((m) => Number(m[1]))).toEqual(Array.from({ length: pages.length }, (_, i) => i + 1));
        expect(new Set(pages.map((m) => m[2]))).toEqual(new Set([String(pages.length)]));
    });
});

describe('3. what the page says, the document says', () => {
    it('a source not read in full is stated first, and an agent found through it is not judged, with its reason and no level', () => {
        const r: LocalResults = {
            ...clean,
            scan: { ...clean.scan, complete: false },
            sources: clean.sources.map((s) => ({ ...s, status: 'INCOMPLETE' as const, reason: 'TIME_BOX' })),
            estate: { ...clean.estate, judgedCount: 0, notJudgedCount: 1, byLevel: { H0: 0, H1: 0, H2: 0, H3: 0, H4: 0, H5: 0 } },
            agents: clean.agents.map((a) => ({ ...a, judgement: { state: 'NOT_JUDGED' as const, reasons: ['SOURCE_INCOMPLETE:code:TIME_BOX'] } })),
        };
        const { lines, joined } = textOf(r);
        expect(lines).toContain('Incomplete: 1 of 1 source was not read in full. Read the completeness section first.');
        expect(lines.indexOf('Incomplete')).toBeLessThan(lines.indexOf('2. Findings by severity'));
        expect(joined).toContain('Not judged: no level is stated for this agent.');
        expect(joined).toContain('A source it was found through, code, was not read in full (TIME_BOX). SOURCE_INCOMPLETE:code:TIME_BOX');
        expect(lines).not.toContain('Complete. Every listed source was read in full.');
    });

    it('not readable and unanswered are told apart, and each state is named in the key', () => {
        const { joined } = textOf(clean);
        expect(joined).toContain('Not readable: nothing this run was configured to read could have reported it');
        expect(joined).toContain('Unanswered: a configured reader could have reported it and none did');
        expect(joined).toContain('READER_NOT_CONFIGURED');
    });

    it('an empty scan is a finding, and no level, matrix or agent section follows', () => {
        const empty: LocalResults = {
            ...clean,
            agents: [],
            findings: clean.findings.filter((f) => f.discoveredId === null),
            estate: { ...clean.estate, empty: true, agentCount: 0, judgedCount: 0, notJudgedCount: 0, shortfallCount: 0, shadowAgents: [], unregisteredIdentities: [], payingAgents: [] },
        };
        const { lines } = textOf(empty);
        expect(lines).toContain('This scan found no agents. That is a finding, not a clean result. No level is stated for anything.');
        expect(lines).not.toContain('4. Agents and criteria');
        expect(lines).not.toContain('5. Each agent');
    });

    it('an unregistered identity is held to no bar, in words', () => {
        const identity: LocalResults = {
            ...clean,
            agents: clean.agents.map((a) => ({ ...a, registration: { basis: 'NONE' as const, ref: null }, declared: null, modelSigns: [] })),
            estate: { ...clean.estate, shortfallCount: 0, unregisteredIdentities: [EXAMPLE_AGENT], shadowAgents: [] },
        };
        const { joined } = textOf(identity);
        expect(joined).toContain('Held to no bar: an unregistered automated identity.');
        expect(joined).not.toContain('H3: Below bar');
        expect(joined).toContain('H3: Held to no bar');
    });

    it('closes with what it does not say', () => {
        const { joined } = textOf(clean);
        expect(joined).toContain('It is a finding, never a clean result.');
        expect(joined).toContain('It is not evidence that the agent cannot pay.');
    });
});

describe('4. a large estate', () => {
    it('lists the first agents in the model\'s order where the page does, gives sections to fewer, and says where the rest are', () => {
        const n = PDF_AGENTS_MAX + 20;
        const template = clean.agents[0];
        const many: LocalResults = {
            ...clean,
            agents: Array.from({ length: n }, (_, i) => ({ ...template, discoveredId: `code:example/many.py#agent_${String(i).padStart(4, '0')}` })),
            estate: { ...clean.estate, agentCount: n },
        };
        const rendered = renderReportPdf(many);
        expect(rendered.text).toContain(`This list shows the first ${PDF_AGENTS_MAX} of ${n} agents. The full list is in agents.csv.`);
        expect(rendered.text).toContain(`This list shows the first ${PDF_AGENT_SECTIONS_MAX} of ${n} agents. The full list is in agents.csv.`);
        expect(rendered.text).toContain('agent_0499');
        expect(rendered.text).not.toContain('agent_0500');
        expect(rendered.bytes.byteLength).toBeLessThan(2 * 1024 * 1024);
    });
});

describe('5. characters the standard fonts cannot show', () => {
    it('are written as escapes; Latin-1 and the Windows-1252 punctuation are written as they are', () => {
        expect(pdfText('café – “x” €')).toBe('café – “x” €');
        expect(pdfText('名前 ‮ \u0007')).toBe('\\u{540d}\\u{524d} \\u{202e} \\u{7}');
        const named: LocalResults = { ...clean, agents: clean.agents.map((a) => ({ ...a, declared: a.declared === null ? null : { ...a.declared, name: 'Agent 名前' } })) };
        const declared = named.agents[0].declared;
        if (declared === null) return;
        expect(textOf(named).joined).toContain('Agent \\u{540d}\\u{524d}');
    });
});
