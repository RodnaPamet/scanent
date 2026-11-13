/**
 * `agents.csv`, `findings.csv` and `results.json`.
 *
 *   1. A cell a spreadsheet would evaluate is neutralised, whoever wrote it.
 *   2. The files are RFC 4180 and read back whole.
 *   3. The content says what the results say, and an agent that was not
 *      judged has no level in any cell.
 *   4. `results.json` is stable text that round-trips through the schema.
 */
import { ALL_HARNESS_CRITERIA } from '@rodnapamet/scanent-contract/harness-ladder';

import { agentClassification, AGENTS_CSV_LEADING_COLUMNS, CSV_BOM, csvCell, csvCriterionState, FINDINGS_CSV_COLUMNS, renderAgentsCsv, renderFindingsCsv } from '../src/render/csv';
import { renderResultsJson, stableJson } from '../src/render/results-json';
import { LocalResultsSchema } from '../src/results/schema';
import { scoreReportLocally } from '../src/results/score';
import type { LocalResults } from '../src/results/types';
import { fullRow, input, inventoryOf } from './helpers/fixtures';
import { ALPHA, BRAVO, CHARLIE, emptyResults, hostile, inventoryResults, notJudgedResults, parseCsv, plainResults, withIdentityBody } from './helpers/results';

const body = (csv: string): string[][] => parseCsv(csv.slice(CSV_BOM.length));

describe('1. formula injection', () => {
    it.each([
        ['=', '=1+1'],
        ['+', '+1'],
        ['-', '-agent'],
        ['@', '@SUM(1)'],
        ['a tab', '\tx'],
        ['a carriage return', '\rx'],
        ['spaces then =', '   =1+1'],
        ['spaces then +', ' +1'],
        ['spaces then -', '  -1'],
        ['spaces then @', ' @x'],
        ['a tab then =', '\t=1+1'],
        ['a line feed then =', '\n=1+1'],
        ['a no-break space then =', '\u00a0=1+1'],
        ['a byte-order mark then =', '\ufeff=1+1'],
        ['a zero-width space then =', '\u200b=1+1'],
        ['a word joiner then +', '\u2060+1'],
        ['a right-to-left mark then @', '\u200f@SUM(1)'],
        ['an ideographic space then -', '\u3000-1'],
        ['a full-width =', '\uff1d1+1'],
        ['a full-width +', '\uff0b1'],
        ['a full-width -', '\uff0d1'],
        ['a full-width @', '\uff20SUM(1)'],
        ['a C1 control then =', '\u0085=1'],
    ])('a cell starting with %s is written starting with a single quote', (_label, value) => {
        const cell = csvCell(value);
        expect(cell.startsWith('"\'')).toBe(true);
        expect(cell.endsWith('"')).toBe(true);
    });

    it.each(['agent', 'a=b', 'x+y', 'me@example.com', 'entra:sp:alpha', '', ' leading space', '0', "'quoted"])('an ordinary cell %j is left as it is', (value) => {
        expect(csvCell(value)).toBe(`"${value}"`);
    });

    it('a bidirectional control is replaced, and a C1 control becomes a space, so a cell reads as it is written', () => {
        expect(csvCell('agent\u202etxt.exe\u202c')).toBe('"agent\ufffdtxt.exe\ufffd"');
        expect(csvCell('a\u2066b\u2069\u200e\u200f\u061c')).toBe('"a\ufffdb\ufffd\ufffd\ufffd\ufffd"');
        expect(csvCell('a\u009bb\u007fc')).toBe('"a b c"');
        for (const attack of ['\u202e=1', 'x\u2067y']) {
            const armed = hostile(plainResults(), attack);
            for (const csv of [renderAgentsCsv(armed), renderFindingsCsv(armed)]) {
                expect(csv).not.toMatch(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/);
                for (const cell of body(csv).flat()) expect(cell).not.toMatch(/^[\s\ufffd]*[=+\-@]/);
            }
        }
    });

    it('a number is written as its digits', () => {
        expect(csvCell(12)).toBe('"12"');
        expect(csvCell(0)).toBe('"0"');
    });

    it.each(["=cmd|' /C calc'!A0", "@SUM(1+1)*cmd|' /C calc'!A0", '-agent'])('%j is neutralised as a name, an id and a finding text', (attack) => {
        const results = inventoryResults();
        const armed: LocalResults = {
            ...results,
            agents: results.agents.map((a) => ({
                ...a,
                discoveredId: a.discoveredId === ALPHA ? attack : a.discoveredId,
                declared: a.declared === null ? null : { ...a.declared, name: attack, owner: attack, purpose: attack },
                observedOwner: a.observedOwner === null ? null : { ...a.observedOwner, ref: attack },
            })),
            findings: results.findings.map((f) => ({ ...f, title: attack, description: attack, sourceRef: attack, discoveredId: attack })),
        };
        for (const csv of [renderAgentsCsv(armed), renderFindingsCsv(armed)]) {
            const cells = body(csv).flat();
            expect(cells.some((c) => c === `'${attack}`)).toBe(true);
            expect(cells.filter((c) => /^[ \t\r\n]*[=+\-@]/.test(c))).toEqual([]);
        }
    });

    it('no cell of a file whose every string is hostile starts a formula', () => {
        for (const attack of ['=HYPERLINK("http://x","y")', '+1', '-1', '@x', '\t=1', '\r=1']) {
            const armed = hostile(plainResults(), attack);
            for (const csv of [renderAgentsCsv(armed), renderFindingsCsv(armed)]) {
                for (const cell of body(csv).flat()) expect(cell).not.toMatch(/^[ \t\r\n]*[=+\-@]/);
            }
        }
    });
});

describe('2. structure', () => {
    it('starts with the byte-order mark, ends every record with CRLF and quotes every field', () => {
        for (const csv of [renderAgentsCsv(plainResults()), renderFindingsCsv(plainResults())]) {
            expect(csv.startsWith(CSV_BOM)).toBe(true);
            expect(csv.endsWith('\r\n')).toBe(true);
            // The reader refuses an unquoted field and a bare line feed.
            const records = body(csv);
            expect(records.length).toBeGreaterThan(1);
            expect(new Set(records.map((r) => r.length)).size).toBe(1);
            expect(csv.replace(/\r\n/g, '')).not.toMatch(/[\r\n]/);
        }
    });

    it('quotes, commas and line breaks in a value survive as data, on one line', () => {
        const awkward = 'a "quoted", name\nsecond line\r\nthird\u0000';
        const armed = hostile(inventoryResults(), awkward);
        const agents = renderAgentsCsv(armed);
        const records = body(agents);
        expect(records).toHaveLength(1 + armed.agents.length);
        expect(records[1][1]).toBe('a "quoted", name second line  third ');
        expect(agents.split('\r\n')).toHaveLength(records.length + 1);
        expect(body(renderFindingsCsv(armed))).toHaveLength(1 + armed.findings.length);
    });
});

describe('3. content', () => {
    it('agents.csv has the leading columns and then the 25 criteria in ladder order', () => {
        const [header] = body(renderAgentsCsv(plainResults()));
        expect(header).toEqual([...AGENTS_CSV_LEADING_COLUMNS, ...ALL_HARNESS_CRITERIA]);
        expect(header.slice(AGENTS_CSV_LEADING_COLUMNS.length)).toHaveLength(25);
    });

    it('one row per agent, saying what the results say', () => {
        const results = inventoryResults();
        const [header, ...rows] = body(renderAgentsCsv(results));
        const col = (row: string[], name: string) => row[header.indexOf(name)];
        expect(rows.map((r) => col(r, 'discoveredId'))).toEqual([ALPHA, BRAVO]);
        const alpha = rows[0];
        expect(col(alpha, 'declaredName')).toBe('Invoice triage');
        expect(col(alpha, 'declaredOwner')).toBe('finance-operations');
        expect(col(alpha, 'observedOwnerKind')).toBe('user');
        expect(col(alpha, 'registration')).toBe('DECLARED_INVENTORY');
        expect(col(alpha, 'judged')).toBe('yes');
        expect(col(alpha, 'level')).toBe('H1');
        expect(col(alpha, 'observedLevel')).toBe('H0');
        expect(col(alpha, 'shortfall')).toBe('yes');
        expect(col(alpha, 'credentials')).toBe('1');
        // Declared, observed, and what nothing configured could have read.
        expect(col(alpha, 'H1.owner')).toBe('DECLARED');
        expect(col(alpha, 'H2.credential_bound')).toBe('EVIDENCED');
        expect(col(alpha, 'H4.receipts')).toBe('NOT_READABLE');
        const bravo = rows[1];
        expect(col(bravo, 'declaredName')).toBe('');
        expect(col(bravo, 'registration')).toBe('NONE');
        expect(col(bravo, 'unpinnedWriteTools')).toBe('1');
        expect(col(bravo, 'H2.credential_bound')).toBe('UNANSWERED');
    });

    it('says what each principal is: registered, a shadow agent, or an unregistered identity held to no bar', () => {
        const withInventory = scoreReportLocally(input(withIdentityBody(), { inventory: inventoryOf([fullRow(ALPHA)]) }));
        const [header, ...rows] = body(renderAgentsCsv(withInventory));
        const col = (id: string, name: string) => rows.find((r) => r[header.indexOf('discoveredId')] === id)![header.indexOf(name)];
        expect(col(ALPHA, 'classification')).toBe('REGISTERED');
        expect(col(BRAVO, 'classification')).toBe('SHADOW_AGENT');
        expect(col(BRAVO, 'modelSigns')).toBe('LISTS_A_TOOL');
        expect(col(BRAVO, 'shortfall')).toBe('yes');
        expect(col(CHARLIE, 'classification')).toBe('UNREGISTERED_IDENTITY');
        expect(col(CHARLIE, 'modelSigns')).toBe('');
        // Its level is still there; what it is not is below a bar.
        expect(col(CHARLIE, 'level')).toBe('H0');
        expect(col(CHARLIE, 'shortfall')).toBe('not held to a bar');
        // A file written before the signs existed: an unregistered principal is a shadow agent, as that file's findings say.
        expect(agentClassification({ registration: { basis: 'NONE', ref: null } })).toBe('SHADOW_AGENT');
        expect(agentClassification({ registration: { basis: 'NONE', ref: null }, modelSigns: [] })).toBe('UNREGISTERED_IDENTITY');
        expect(agentClassification({ registration: { basis: 'OBSERVED_REGISTER', ref: 'agt_1' }, modelSigns: [] })).toBe('REGISTERED');
    });

    it('an agent that was not judged has empty level, observedLevel, bar and shortfall cells, and its reasons', () => {
        const [header, ...rows] = body(renderAgentsCsv(notJudgedResults()));
        const col = (row: string[], name: string) => row[header.indexOf(name)];
        expect(rows).toHaveLength(2);
        for (const row of rows) {
            expect(col(row, 'judged')).toBe('no');
            expect([col(row, 'level'), col(row, 'observedLevel'), col(row, 'bar'), col(row, 'shortfall'), col(row, 'blockingNextRung')]).toEqual(['', '', '', '', '']);
            expect(col(row, 'notJudgedReasons')).toBe('SOURCE_INCOMPLETE:entra-sp:AUTH_FAILED');
            // No cell of the row states a level.
            expect(row.filter((c) => /^H[0-5]$/.test(c))).toEqual([]);
        }
    });

    it('an empty estate gives a header-only agents.csv and an EMPTY_SCAN finding', () => {
        const results = emptyResults();
        expect(body(renderAgentsCsv(results))).toHaveLength(1);
        const [header, ...rows] = body(renderFindingsCsv(results));
        expect(header).toEqual([...FINDINGS_CSV_COLUMNS]);
        expect(rows.map((r) => r[0])).toContain('EMPTY_SCAN');
    });

    it('findings.csv has one row per finding, in the results\' order', () => {
        const results = plainResults();
        const [, ...rows] = body(renderFindingsCsv(results));
        expect(rows.map((r) => r[3])).toEqual(results.findings.map((f) => f.sourceRef));
        expect(rows.map((r) => r[4])).toEqual(results.findings.map((f) => f.discoveredId ?? ''));
    });

    it('names each cell state, and an unknown one as it is', () => {
        const cell = { criterion: 'H1.owner', evidence: null } as const;
        expect(csvCriterionState({ ...cell, state: 'EVIDENCED', basis: 'OBSERVED', readable: true })).toBe('EVIDENCED');
        expect(csvCriterionState({ ...cell, state: 'EVIDENCED', basis: 'DECLARED', readable: true })).toBe('DECLARED');
        expect(csvCriterionState({ ...cell, state: 'MET_UNEVIDENCED', basis: 'OBSERVED', readable: true })).toBe('MET_UNEVIDENCED');
        expect(csvCriterionState({ ...cell, state: 'NOT_MET', basis: 'OBSERVED', readable: false })).toBe('NOT_MET');
        // Not met on the operator's inventory is not the word for a failure a source saw.
        expect(csvCriterionState({ ...cell, state: 'NOT_MET', basis: 'DECLARED', readable: true })).toBe('NOT_MET_DECLARED');
        expect(csvCriterionState({ ...cell, state: 'UNANSWERED', basis: null, readable: true })).toBe('UNANSWERED');
        expect(csvCriterionState({ ...cell, state: 'UNANSWERED', basis: null, readable: false })).toBe('NOT_READABLE');
    });

    it('a criterion an agent row does not carry is written as unanswered', () => {
        const results = plainResults();
        const trimmed: LocalResults = { ...results, agents: results.agents.map((a) => ({ ...a, criteria: [] })) };
        const [header, row] = body(renderAgentsCsv(trimmed));
        expect(row.slice(AGENTS_CSV_LEADING_COLUMNS.length)).toEqual(header.slice(AGENTS_CSV_LEADING_COLUMNS.length).map(() => 'UNANSWERED'));
    });
});

describe('4. results.json', () => {
    it('is the results, with sorted keys, two-space indentation and one trailing newline', () => {
        const results = inventoryResults();
        const text = renderResultsJson(results);
        expect(text.endsWith('}\n')).toBe(true);
        expect(text.endsWith('\n\n')).toBe(false);
        expect(JSON.parse(text)).toEqual(results);
        expect(LocalResultsSchema.parse(JSON.parse(text))).toEqual(results);
        expect(text).toContain('\n  "agents": [');
        const top = Object.keys(JSON.parse(text) as object);
        expect(top).toEqual([...top].sort());
    });

    it('is the same text for the same results, whatever order their keys were built in', () => {
        const results = plainResults();
        const reversed = Object.fromEntries(Object.entries(results).reverse()) as unknown as LocalResults;
        expect(renderResultsJson(reversed)).toBe(renderResultsJson(results));
        expect(renderResultsJson(plainResults())).toBe(renderResultsJson(results));
    });

    it('keeps array order and writes null, numbers and booleans as they are', () => {
        expect(stableJson({ b: [3, 1, 2], a: null, c: { z: true, y: 1 } })).toBe('{\n  "a": null,\n  "b": [\n    3,\n    1,\n    2\n  ],\n  "c": {\n    "y": 1,\n    "z": true\n  }\n}\n');
    });
});
