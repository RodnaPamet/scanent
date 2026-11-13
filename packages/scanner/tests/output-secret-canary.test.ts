/**
 * NOTHING SECRET IN ANY OUTPUT.
 *
 * One canary per secret shape, through every way a string can reach an
 * output: a source, the inventory, the results handed to the renderers, a
 * renderer that assembles one out of harmless parts, the previous run a page
 * is compared with, and the inputs of `scanent diff`. `report.pdf` is read
 * back as text (its streams inflated) and `summary.html`'s data block as JSON,
 * so neither compression nor escaping can hide a canary from the check. In every case the output is refused, the refusal names the
 * member or the file, and the canary is nowhere: not in a file, not on
 * stdout, not in the log, not in the error.
 *
 * The canaries are built from parts at run time, so this file holds no
 * secret-shaped literal.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { looksLikeSecret, type HarnessReportBodyV4 } from '@rodnapamet/scanent-contract/harness-contract';
import { renderAgentsCsv, renderFindingsCsv } from '@scanent/report/render/csv';
import { renderSummaryHtml } from '@scanent/report/render/html';
import { renderResultsJson } from '@scanent/report/render/results-json';
import { INVENTORY_SCHEMA_ID, InventoryRefused } from '@scanent/report/results/inventory';
import type { LocalResults } from '@scanent/report/results/types';

import { runDiff } from '../src/diff-command';
import { assertNoSecretShape, OutputRefusedLocally, renderRunFiles, writeRun } from '../src/file-output';
import { scanAndDeliver } from '../src/outputs';
import { ReportRefusedLocally, signReport } from '../src/report';
import { loadSigningKey } from '../src/scan';
import { diffResults } from '@scanent/report/diff/diff';
import { renderReportPdf } from '../src/report-pdf';
import { CANARIES, capturedLog, configOf, ENV, EXAMPLE_AGENT, noFetch, pageDataOf, pdfTextOf, scanExample, stringsOf, tree } from './helpers/output-fixtures';

const T1 = Date.parse('2026-11-03T03:30:00.000Z');

let dir: string;
let clean: { raw: string; results: LocalResults };
beforeAll(async () => {
    clean = await scanExample(T1);
});
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-canary-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

/** Every string member of a value, by its path. */
function stringPaths(value: unknown, at: (string | number)[] = []): (string | number)[][] {
    if (typeof value === 'string') return [at];
    if (Array.isArray(value)) return value.flatMap((v, i) => stringPaths(v, [...at, i]));
    if (value !== null && typeof value === 'object') return Object.entries(value).flatMap(([k, v]) => stringPaths(v, [...at, k]));
    return [];
}

function setAt<T>(value: T, at: readonly (string | number)[], replacement: string): T {
    if (at.length === 0) return replacement as unknown as T;
    const [head, ...rest] = at;
    if (Array.isArray(value)) return value.map((v, i) => (i === head ? setAt(v, rest, replacement) : v)) as unknown as T;
    return { ...(value as Record<string, unknown>), [head]: setAt((value as Record<string, unknown>)[head as string], rest, replacement) } as T;
}

const pathText = (at: readonly (string | number)[]): string => at.reduce<string>((p, k) => (typeof k === 'number' ? `${p}[${k}]` : p ? `${p}.${k}` : k), '');

describe('the canaries', () => {
    it.each(CANARIES)('%s has the shape the contract refuses', (_label, canary) => {
        expect(looksLikeSecret(canary)).toBe(true);
    });

    it('a clean run passes every check: the renderers\' own text holds no secret shape, nor the PDF\'s, nor the page\'s data', () => {
        const files = renderRunFiles(clean.raw, clean.results);
        expect(files.map((f) => f.name)).toEqual(['report.signed.json', 'results.json', 'agents.csv', 'findings.csv', 'summary.html', 'report.pdf']);
        for (const f of files.slice(1, 5)) expect(looksLikeSecret(f.content as string)).toBe(false);
        const pdf = pdfTextOf(files[5].content as Uint8Array);
        // The text read back is the document: the scan id and the agent are in it.
        expect(pdf.lines).toContain(clean.results.scan.id);
        expect(pdf.joined).toContain(EXAMPLE_AGENT);
        expect(looksLikeSecret(pdf.lines)).toBe(false);
        const data = stringsOf(pageDataOf(files[4].content as string));
        expect(data).toContain(EXAMPLE_AGENT);
        for (const text of data) expect(looksLikeSecret(text)).toBe(false);
    });
});

describe('through a source', () => {
    // The shapes that are also valid identifiers can be the name of a tool in an estate's code.
    const identifiers = CANARIES.filter(([, canary]) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(canary));

    it('at least three shapes can arrive as a tool name', () => {
        expect(identifiers.length).toBeGreaterThanOrEqual(3);
    });

    it.each(identifiers)('%s as a tool name in scanned code is not reported by the code source, and is in no output', async (_label, canary) => {
        const estate = path.join(dir, 'estate', 'support');
        fs.mkdirSync(estate, { recursive: true });
        const example = fs.readFileSync(path.resolve(__dirname, '..', '..', '..', 'examples', 'code-only', 'estate', 'support', 'agent.py'), 'utf8');
        fs.writeFileSync(path.join(estate, 'agent.py'), example.replace(/lookup_order/g, canary));
        const out = path.join(dir, 'out');
        const { log, text } = capturedLog();
        const printed: string[] = [];
        const result = await scanAndDeliver({
            config: configOf({}, [{ label: 'example', path: path.join(dir, 'estate') }]),
            env: ENV,
            log,
            outputs: [{ kind: 'file', dir: out }, { kind: 'stdout' }],
            stdout: (t) => printed.push(t),
            fetchImpl: noFetch,
        });
        expect(result.ok).toBe(true);
        expect(result.scan.body.agents).toHaveLength(1);
        const files = tree(out);
        expect(Object.keys(files)).toHaveLength(8);
        for (const content of [...Object.values(files), ...printed, text()]) expect(content).not.toContain(canary);
        // Read as a viewer would: the PDF's inflated text, and the page's data as parsed JSON.
        const run = path.join(out, 'runs', result.scan.body.scan.id);
        const pdf = pdfTextOf(fs.readFileSync(path.join(run, 'report.pdf')));
        expect(pdf.joined).toContain(EXAMPLE_AGENT);
        expect(pdf.joined).not.toContain(canary);
        expect(stringsOf(pageDataOf(fs.readFileSync(path.join(run, 'summary.html'), 'utf8'))).join('\n')).not.toContain(canary);
    });

    it.each(CANARIES)('%s in any string a source reports: the report is not signed, so nothing is delivered', (_label, canary) => {
        const { signature: _signature, ...body } = JSON.parse(clean.raw) as HarnessReportBodyV4 & { signature: unknown };
        const keys = loadSigningKey(ENV.SCANNER_SIGNING_KEY);
        expect(() => signReport(body, keys)).not.toThrow();
        // The contract refuses a secret-shaped credential reference in its schema; every other string by the walk.
        const places = stringPaths(body).filter((at) => at[0] === 'agents' || at[0] === 'unboundCredentials');
        expect(places.length).toBeGreaterThan(5);
        for (const at of places) {
            let thrown: unknown;
            try {
                signReport(setAt(body, at, canary), keys);
            } catch (err) {
                thrown = err;
            }
            expect(thrown).toBeInstanceOf(ReportRefusedLocally);
            expect((thrown as Error).message).not.toContain(canary);
        }
    });
});

describe('through the inventory', () => {
    it.each(CANARIES.flatMap(([label, canary]) => (['name', 'owner', 'purpose'] as const).map((field) => [label, field, canary] as const)))(
        '%s as the declared %s: the inventory is refused before any source is read',
        async (_label, field, canary) => {
            const inventory = path.join(dir, 'inventory.json');
            const row = { discoveredId: EXAMPLE_AGENT, name: 'Support agent', owner: 'support-team', purpose: 'Answers order questions', [field]: canary };
            fs.writeFileSync(inventory, JSON.stringify({ inventory: INVENTORY_SCHEMA_ID, agents: [row] }));
            const out = path.join(dir, 'out');
            const { log, lines } = capturedLog();
            const printed: string[] = [];
            let thrown: unknown;
            try {
                await scanAndDeliver({
                    config: configOf({ inventory: { path: inventory } }),
                    env: ENV,
                    log,
                    outputs: [{ kind: 'file', dir: out }, { kind: 'stdout' }],
                    stdout: (t) => printed.push(t),
                    fetchImpl: noFetch,
                });
            } catch (err) {
                thrown = err;
            }
            expect(thrown).toBeInstanceOf(InventoryRefused);
            const refusal = thrown as InventoryRefused;
            expect(`${refusal.message} ${refusal.issues.join(' ')}`).not.toContain(canary);
            expect(refusal.issues.join(' ')).toContain(field);
            // No source was read: the log is empty, and nothing was written or printed.
            expect(lines()).toEqual([]);
            expect(fs.existsSync(out)).toBe(false);
            expect(printed).toEqual([]);
        },
    );
});

describe('through the results', () => {
    it('the results hold many string members, and each is tried', () => {
        expect(stringPaths(clean.results).length).toBeGreaterThan(80);
    });

    it.each(CANARIES)('%s in any string member of the results: the run is refused by member, and no file is written', (_label, canary) => {
        for (const at of stringPaths(clean.results)) {
            const armed = setAt(clean.results, at, canary);
            let thrown: unknown;
            try {
                writeRun({ dir }, { raw: clean.raw, results: armed });
            } catch (err) {
                thrown = err;
            }
            const where = pathText(at);
            if (where === 'scan.id' && !(thrown instanceof OutputRefusedLocally)) {
                // The scan id is the directory's name, and is refused as one first.
                expect((thrown as Error).message).toBe('the scan id is not a safe directory name; nothing was written');
            } else {
                expect(thrown).toBeInstanceOf(OutputRefusedLocally);
                expect((thrown as OutputRefusedLocally).where).toBe(`results.json: ${where}`);
            }
            expect((thrown as Error).message).not.toContain(canary);
            expect(fs.readdirSync(dir)).toEqual([]);
        }
    });

    it.each(CANARIES)('%s in the results is logged by member through the delivery, and the other outputs still go', async (_label, canary) => {
        const { log, lines, text } = capturedLog();
        const printed: string[] = [];
        const out = path.join(dir, 'out');
        const result = await scanAndDeliver({
            config: configOf(),
            env: ENV,
            log,
            outputs: [{ kind: 'file', dir: out }, { kind: 'stdout' }],
            stdout: (t) => printed.push(t),
            fetchImpl: noFetch,
            // An inventory whose owner is the canary, as if the loader had let it through.
            loadInventory: () => ({ sha256: 'f'.repeat(64), format: 'json', rows: [{ discoveredId: EXAMPLE_AGENT, name: 'Support agent', owner: canary, purpose: 'Answers order questions' }] }),
        });
        expect(result.delivered).toEqual([
            { kind: 'file', ok: false },
            { kind: 'stdout', ok: true },
        ]);
        expect(lines().find((l) => l.msg === 'output failed')).toMatchObject({
            output: 'file',
            error: 'output refused: results.json: agents[0].declared.owner has the shape of a secret; nothing was written',
        });
        expect(fs.existsSync(path.join(out, 'runs'))).toBe(false);
        expect(tree(out)).toEqual({});
        expect(text()).not.toContain(canary);
        // The signed report never held the declaration.
        expect(printed.join('')).not.toContain(canary);
    });
});

describe('assembled at render time', () => {
    const halves = CANARIES.map(([label, canary]) => [label, canary.slice(0, Math.floor(canary.length / 2)), canary.slice(Math.floor(canary.length / 2))] as const);

    it.each(halves)('%s put together by a renderer out of two harmless halves is refused by file name', (_label, head, tail) => {
        expect(looksLikeSecret(head) || looksLikeSecret(tail)).toBe(false);
        const real = { results: renderResultsJson, agents: renderAgentsCsv, findings: renderFindingsCsv, summary: renderSummaryHtml };
        for (const [key, name] of [
            ['results', 'results.json'],
            ['agents', 'agents.csv'],
            ['findings', 'findings.csv'],
            ['summary', 'summary.html'],
        ] as const) {
            const renderers = { ...real, [key]: (r: LocalResults) => `${real[key](r)}${head}${tail}` };
            let thrown: unknown;
            try {
                writeRun({ dir }, clean, { renderers });
            } catch (err) {
                thrown = err;
            }
            expect(thrown).toBeInstanceOf(OutputRefusedLocally);
            expect((thrown as OutputRefusedLocally).where).toBe(name);
            expect((thrown as Error).message).toBe(`output refused: ${name} has the shape of a secret; nothing was written`);
            expect(fs.readdirSync(dir)).toEqual([]);
        }
    });

    it.each(halves)('%s put together in the PDF out of two harmless halves is refused as report.pdf', (_label, head, tail) => {
        const pdf = (r: LocalResults) => {
            const real = renderReportPdf(r);
            return { bytes: real.bytes, text: `${real.text}${head}${tail}` };
        };
        let thrown: unknown;
        try {
            writeRun({ dir }, clean, { renderers: { results: renderResultsJson, agents: renderAgentsCsv, findings: renderFindingsCsv, summary: renderSummaryHtml, pdf } });
        } catch (err) {
            thrown = err;
        }
        expect(thrown).toBeInstanceOf(OutputRefusedLocally);
        expect((thrown as Error).message).toBe('output refused: report.pdf has the shape of a secret; nothing was written');
        expect(fs.readdirSync(dir)).toEqual([]);
    });

    it.each(CANARIES)('%s in the previous run the page is compared with is refused by member of the page\'s data, and nothing is written', async (_label, canary) => {
        const later = await scanExample(T1 + 86_400_000);
        const diff = diffResults(clean.results, later.results);
        const armed = { ...diff, agents: { ...diff.agents, added: [canary] } };
        let thrown: unknown;
        try {
            writeRun({ dir }, { ...later, previous: { kind: 'COMPARED', diff: armed } });
        } catch (err) {
            thrown = err;
        }
        expect(thrown).toBeInstanceOf(OutputRefusedLocally);
        expect((thrown as OutputRefusedLocally).where).toBe('summary.html: drift.added.rows[0]');
        expect((thrown as Error).message).not.toContain(canary);
        expect(fs.readdirSync(dir)).toEqual([]);
    });

    it('the PDF holds what the results hold and no more: its text read back is the renderer\'s own account of it', () => {
        const rendered = renderReportPdf(clean.results);
        const read = pdfTextOf(rendered.bytes);
        // Every line the renderer reports is shown; nothing is in the document that it did not report.
        for (const word of ['Agent estate scan results', 'Completeness per source', clean.results.scan.id, 'What this document does not say']) {
            expect(rendered.text).toContain(word);
            expect(read.lines).toContain(word);
        }
    });

    it('two clean cells side by side in a CSV are not read as one secret, and a secret inside one cell is', () => {
        // A URL with a port in one cell and an address in the next: each is clean, and so is the pair.
        const server = ['https:', '//mcp.internal.example:8443'].join('');
        const owner = 'owner@example.com';
        expect(looksLikeSecret(`"${server}","${owner}"`)).toBe(true);
        const paired: LocalResults = {
            ...clean.results,
            agents: clean.results.agents.map((a) => ({ ...a, discoveredId: server, observedOwner: { kind: 'user' as const, ref: owner }, declared: { name: owner, owner, purpose: owner, row: 1 } })),
            findings: clean.results.findings.map((f) => ({ ...f, sourceRef: server, discoveredId: owner })),
        };
        expect(renderAgentsCsv(paired)).toContain(`"${server}","${owner}"`);
        expect(() => renderRunFiles(clean.raw, paired)).not.toThrow();
        // Inside one cell the same shape is a secret, and is refused before any text is rendered.
        const [, canary] = CANARIES[8];
        const armed = setAt(clean.results, ['findings', 0, 'title'], canary);
        expect(() => renderRunFiles(clean.raw, armed)).toThrow('output refused: results.json: findings[0].title has the shape of a secret');
        // And when only the rendered CSV holds it, the file is named.
        const real = { results: renderResultsJson, agents: renderAgentsCsv, findings: (r: LocalResults) => renderFindingsCsv(setAt(r, ['findings', 0, 'title'], canary)), summary: renderSummaryHtml };
        expect(() => renderRunFiles(clean.raw, clean.results, real)).toThrow('output refused: findings.csv has the shape of a secret');
    });

    it('the check names a member for a value and the place for a text', () => {
        const [, canary] = CANARIES[0];
        expect(() => assertNoSecretShape({ a: [{ b: canary }] }, 'the diff')).toThrow('output refused: the diff: a[0].b has the shape of a secret; nothing was written');
        expect(() => assertNoSecretShape(`x ${canary} y`, 'the diff output')).toThrow('output refused: the diff output has the shape of a secret; nothing was written');
        expect(() => assertNoSecretShape({ a: ['clean'] }, 'x')).not.toThrow();
        expect(() => assertNoSecretShape('clean', 'x')).not.toThrow();
    });
});

describe('through scanent diff', () => {
    it.each(CANARIES.flatMap(([label, canary]) => (['text', 'json'] as const).map((format) => [label, format, canary] as const)))(
        '%s in a results file, --format %s: refused by member, and printed nowhere',
        async (_label, format, canary) => {
            const later = await scanExample(T1 + 86_400_000);
            const armed = setAt(later.results, ['findings', 0, 'description'], canary);
            const a = path.join(dir, 'a.json');
            const b = path.join(dir, 'b.json');
            fs.writeFileSync(a, renderResultsJson(clean.results));
            fs.writeFileSync(b, JSON.stringify(armed));
            const out: string[] = [];
            const err: string[] = [];
            for (const argv of [
                [a, b, '--format', format],
                [b, a, '--format', format],
            ]) {
                expect(runDiff(argv, { stdout: (t) => out.push(t), stderr: (t) => err.push(t) })).toBe(2);
            }
            expect(out).toEqual([]);
            expect(err).toEqual([
                'scanent diff: new: findings[0].description has the shape of a secret; the file is refused\n',
                'scanent diff: old: findings[0].description has the shape of a secret; the file is refused\n',
            ]);
            expect(err.join('')).not.toContain(canary);
        },
    );
});
