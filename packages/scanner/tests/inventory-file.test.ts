/**
 * The inventory file: read once, capped, hashed, decoded, then judged.
 *
 *   1. A JSON and a CSV file with the same rows are the same inventory.
 *   2. The CSV decoder is RFC 4180, and strict where a file is ambiguous.
 *   3. Every refusal names the row and the field, and never the value or the path.
 *   4. A file that cannot be read whole is refused, never treated as empty.
 *   5. The configuration names the file; nothing else does.
 *   6. The files the documents show are files this version reads, with the values it takes.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
    INVENTORY_AUTONOMY_LEVEL_MAX,
    INVENTORY_AUTONOMY_LEVEL_MIN,
    INVENTORY_AXES,
    INVENTORY_DATA_ACCESS_SCOPES,
    INVENTORY_PROVENANCES,
    INVENTORY_REVERSIBILITIES,
    INVENTORY_RISK_TIERS,
    INVENTORY_SCHEMA_ID,
    INVENTORY_TIER_MAX_AGE_DAYS,
    InventoryRefused,
} from '@scanent/report/results/inventory';

import { ConfigError, parseScannerConfig } from '../src/config';
import {
    decodeCsvRecords,
    decodeInventoryCsv,
    INVENTORY_CSV_OPTIONAL_COLUMNS,
    INVENTORY_CSV_REQUIRED_COLUMNS,
    inventoryFormatOf,
    loadInventoryFile,
    MAX_INVENTORY_BYTES,
} from '../src/inventory-file';
import { loadConfiguredInventory } from '../src/local-results';

const HEADER = 'discoveredId,name,owner,purpose,autonomyLevel,dataAccessScope,reversibility,provenance,riskTier,riskAssessedOn';
const ROW = 'entra:sp:alpha,Invoice triage,finance-operations,Sorts incoming invoices,2,WRITE_TENANT_DATA,COMPENSABLE,FIRST_PARTY,MODERATE,2026-09-30';
const ALPHA = {
    discoveredId: 'entra:sp:alpha',
    name: 'Invoice triage',
    owner: 'finance-operations',
    purpose: 'Sorts incoming invoices',
    axes: { autonomyLevel: 2, dataAccessScope: 'WRITE_TENANT_DATA', reversibility: 'COMPENSABLE', provenance: 'FIRST_PARTY' },
    riskTier: 'MODERATE',
    riskAssessedOn: '2026-09-30',
};

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-inventory-'));
});
afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
});

function write(name: string, content: string | Buffer): string {
    const file = path.join(dir, name);
    fs.writeFileSync(file, content);
    return file;
}

/** The issues a refused file names. Fails if it was not refused. */
function refusal(run: () => unknown): readonly string[] {
    try {
        run();
    } catch (err) {
        expect(err).toBeInstanceOf(InventoryRefused);
        return (err as InventoryRefused).issues;
    }
    throw new Error('expected the inventory to be refused');
}
const csvRefusal = (text: string) => refusal(() => loadInventoryFile(write('inventory.csv', text)));

describe('1. one inventory, two forms', () => {
    it('reads a JSON file, with the hash of its bytes', () => {
        const text = JSON.stringify({ inventory: INVENTORY_SCHEMA_ID, agents: [ALPHA] }, null, 2);
        const parsed = loadInventoryFile(write('inventory.json', text));
        expect(parsed).toEqual({ sha256: createHash('sha256').update(text).digest('hex'), format: 'json', rows: [ALPHA] });
    });

    it('reads a CSV file to the same rows', () => {
        const text = `${HEADER}\r\n${ROW}\r\n`;
        const parsed = loadInventoryFile(write('inventory.csv', text));
        expect(parsed).toEqual({ sha256: createHash('sha256').update(text).digest('hex'), format: 'csv', rows: [ALPHA] });
    });

    it('hashes the bytes, so the same rows in another form are another file', () => {
        const a = loadInventoryFile(write('a.csv', `${HEADER}\r\n${ROW}\r\n`));
        const b = loadInventoryFile(write('b.csv', `${HEADER}\n${ROW}\n`));
        expect(a.rows).toEqual(b.rows);
        expect(a.sha256).not.toBe(b.sha256);
    });

    it('tells the form by the extension, in either case, and nothing else is one', () => {
        expect(inventoryFormatOf('/etc/scanent/inventory.json')).toBe('json');
        expect(inventoryFormatOf('/etc/scanent/INVENTORY.CSV')).toBe('csv');
        expect(inventoryFormatOf('/etc/scanent/inventory.yaml')).toBeNull();
        expect(inventoryFormatOf('/etc/scanent/inventory')).toBeNull();
        expect(inventoryFormatOf('/etc/scanent/json')).toBeNull();
        expect(refusal(() => loadInventoryFile(write('inventory.txt', '{}')))).toEqual(['(file): the inventory is a .json or a .csv file']);
    });

    it('takes a byte-order mark in either form', () => {
        const bom = Buffer.from([0xef, 0xbb, 0xbf]);
        const json = Buffer.concat([bom, Buffer.from(JSON.stringify({ inventory: INVENTORY_SCHEMA_ID, agents: [ALPHA] }))]);
        expect(loadInventoryFile(write('inventory.json', json)).rows).toEqual([ALPHA]);
        const csv = Buffer.concat([bom, Buffer.from(`${HEADER}\r\n${ROW}\r\n`)]);
        expect(loadInventoryFile(write('inventory.csv', csv)).rows).toEqual([ALPHA]);
        // And as text, for a caller that decoded the bytes itself.
        expect(decodeInventoryCsv(`${String.fromCharCode(0xfeff)}${HEADER}\n${ROW}`)).toEqual({ inventory: INVENTORY_SCHEMA_ID, agents: [ALPHA] });
    });

    it('needs only the four required columns, in any order', () => {
        const parsed = loadInventoryFile(write('inventory.csv', 'purpose,owner,discoveredId,name\nSorts invoices,finance,entra:sp:alpha,Triage\n'));
        expect(parsed.rows).toEqual([{ discoveredId: 'entra:sp:alpha', name: 'Triage', owner: 'finance', purpose: 'Sorts invoices' }]);
        expect([...INVENTORY_CSV_REQUIRED_COLUMNS, ...INVENTORY_CSV_OPTIONAL_COLUMNS].join(',')).toBe(HEADER);
    });

    it('reads an empty optional cell as absent', () => {
        const parsed = loadInventoryFile(write('inventory.csv', `${HEADER}\nentra:sp:alpha,Triage,finance,Sorts invoices,,,,,,\n`));
        expect(parsed.rows).toEqual([{ discoveredId: 'entra:sp:alpha', name: 'Triage', owner: 'finance', purpose: 'Sorts invoices' }]);
    });

    it('reads the autonomy level, the one number, from its digits: every rung, and 0 as a level and not as nothing', () => {
        const lines = [0, 1, 2, 3, 4, 5, 6].map((level) => `a:${level},n,o,p,${level},NONE,REVERSIBLE,THIRD_PARTY,,`);
        const parsed = loadInventoryFile(write('inventory.csv', `${HEADER}\n${lines.join('\n')}\n`));
        expect(parsed.rows.map((r) => r.axes?.autonomyLevel)).toEqual([0, 1, 2, 3, 4, 5, 6]);
        expect(parsed.rows.every((r) => r.axes?.provenance === 'THIRD_PARTY' && r.riskTier === undefined)).toBe(true);
        // A quoted cell is the same cell.
        const quoted = loadInventoryFile(write('quoted.csv', `${HEADER}\na,n,o,p,"4",NONE,REVERSIBLE,FIRST_PARTY,,\n`));
        expect(quoted.rows[0].axes).toEqual({ autonomyLevel: 4, dataAccessScope: 'NONE', reversibility: 'REVERSIBLE', provenance: 'FIRST_PARTY' });
    });

    it('a header and no rows is an inventory that names nobody', () => {
        expect(loadInventoryFile(write('inventory.csv', `${HEADER}\r\n`)).rows).toEqual([]);
    });

    it('reads names that are not ASCII', () => {
        const parsed = loadInventoryFile(write('inventory.csv', 'discoveredId,name,owner,purpose\nentra:sp:alpha,Фактури,Финансови операции,Сортира фактури\n'));
        expect(parsed.rows[0].owner).toBe('Финансови операции');
    });
});

describe('2. the CSV decoder', () => {
    const records = (text: string) => {
        const decoded = decodeCsvRecords(text);
        if ('malformedAtRecord' in decoded) throw new Error(`malformed at record ${decoded.malformedAtRecord}`);
        return decoded.records;
    };

    it.each([
        ['plain fields', 'a,b,c', [['a', 'b', 'c']]],
        ['CRLF and LF line ends', 'a,b\r\nc,d\ne,f', [['a', 'b'], ['c', 'd'], ['e', 'f']]],
        ['a trailing line end', 'a,b\r\n', [['a', 'b']]],
        ['empty fields', 'a,,c\n,,', [['a', '', 'c'], ['', '', '']]],
        ['a trailing empty field', 'a,b,', [['a', 'b', '']]],
        ['a quoted field', '"a b",c', [['a b', 'c']]],
        ['a comma inside quotes', '"a,b",c', [['a,b', 'c']]],
        ['a doubled quote inside quotes', '"say ""hi""",c', [['say "hi"', 'c']]],
        ['a line break inside quotes', '"a\nb",c\nd,e', [['a\nb', 'c'], ['d', 'e']]],
        ['a quoted empty field', '"",b', [['', 'b']]],
        ['a quoted field at the end of the text', 'a,"b"', [['a', 'b']]],
        ['a quoted empty field at the end of the text', 'a,""', [['a', '']]],
        ['spaces kept as data', ' a , b ', [[' a ', ' b ']]],
        ['a blank line between records, which is not a record', 'a,b\n\nc,d\n\n', [['a', 'b'], ['c', 'd']]],
        ['nothing', '', []],
        ['only line ends', '\r\n\n', []],
    ])('reads %s', (_label, text, expected) => {
        expect(records(text)).toEqual(expected);
    });

    it.each([
        ['a quote in the middle of an unquoted field', 'a,b"c,d', 1],
        ['text after a closing quote', 'a,b\n"c"d,e', 2],
        ['a quote that never closes', 'a,b\nc,d\n"e,f', 3],
        ['a quote opened after a closed one', '"a""b" "c"', 1],
    ])('refuses %s, naming the record', (_label, text, record) => {
        expect(decodeCsvRecords(text)).toEqual({ malformedAtRecord: record });
        expect(csvRefusal(text)).toEqual([`record ${record}: not well-formed CSV`]);
    });

    it('keeps a quoted cell that looks like a formula as the text it is', () => {
        // Neutralising is the output's job; the decoder must not alter data.
        const parsed = loadInventoryFile(write('inventory.csv', 'discoveredId,name,owner,purpose\nentra:sp:alpha,"=SUM(1,2)",finance,"He said ""go"""\n'));
        expect(parsed.rows[0]).toMatchObject({ name: '=SUM(1,2)', purpose: 'He said "go"' });
    });
});

describe('3. a refusal names the row and the field', () => {
    const VALUE = 'zz-refused-zz';

    it.each([
        ['no header at all', '', ['header: missing']],
        ['an unknown column', `${HEADER},${VALUE}\n`, ['header: 1 unknown column']],
        ['two unknown columns', `discoveredId,name,owner,purpose,${VALUE},notes\n`, ['header: 2 unknown columns']],
        ['a column in another case', 'DiscoveredId,name,owner,purpose\n', ['header: 1 unknown column']],
        ['a column with a space', 'discoveredId, name,owner,purpose\n', ['header: 1 unknown column']],
        ['a column twice', 'discoveredId,name,owner,purpose,name\n', ['header: a column appears once']],
        ['a missing required column', 'discoveredId,name,owner\n', ['header: required column purpose is missing']],
        ['two missing required columns', 'discoveredId,purpose,riskTier\n', ['header: required column name is missing', 'header: required column owner is missing']],
        ['a row with too few fields', `discoveredId,name,owner,purpose\na,b,c,d\n${VALUE},b,c\n`, ['row 2: 3 fields where the header has 4']],
        ['a row with too many fields', `discoveredId,name,owner,purpose\na,b,c,d,${VALUE}\n`, ['row 1: 5 fields where the header has 4']],
        ['an empty required cell', 'discoveredId,name,owner,purpose\na,,c,d\n', ['row 1: name: too_small', 'row 1: name: blank']],
        ['a duplicate id', 'discoveredId,name,owner,purpose\na,b,c,d\ne,f,g,h\na,b,c,d\n', ['row 3: discoveredId: a discoveredId appears once']],
        [
            'one axis without the others',
            `discoveredId,name,owner,purpose,autonomyLevel\na,b,c,d,3\n`,
            ['row 1: axes.dataAccessScope: invalid_value', 'row 1: axes.reversibility: invalid_value', 'row 1: axes.provenance: invalid_value'],
        ],
        ['three axes without the autonomy level', `${HEADER}\na,b,c,d,,NONE,REVERSIBLE,FIRST_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['an axis value off its list', `${HEADER}\na,b,c,d,3,${VALUE},TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.dataAccessScope: invalid_value']],
        ['an axis value in lower case', `${HEADER}\na,b,c,d,3,NONE,terminal,THIRD_PARTY,,\n`, ['row 1: axes.reversibility: invalid_value']],
        ['an autonomy level above the ladder', `${HEADER}\na,b,c,d,7,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: too_big']],
        ['an autonomy level far above the ladder', `${HEADER}\na,b,c,d,999999999,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: too_big']],
        ['an autonomy level too long to be a number', `${HEADER}\na,b,c,d,1000000000,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['a negative autonomy level', `${HEADER}\na,b,c,d,-1,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['an autonomy level with a leading zero', `${HEADER}\na,b,c,d,03,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['an autonomy level with a fraction', `${HEADER}\na,b,c,d,3.0,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['an autonomy level with a space', `${HEADER}\na,b,c,d, 3,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['an autonomy level in words', `${HEADER}\na,b,c,d,${VALUE},NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['an autonomy level in another notation', `${HEADER}\na,b,c,d,0x3,NONE,TERMINAL,THIRD_PARTY,,\n`, ['row 1: axes.autonomyLevel: invalid_type']],
        ['a tier the register does not have', `${HEADER}\na,b,c,d,,,,,MEDIUM,2026-09-30\n`, ['row 1: riskTier: invalid_value']],
        ['a tier without its date', `${HEADER}\na,b,c,d,,,,,HIGH,\n`, ['row 1: riskAssessedOn: a risk tier and the date it was assessed come together or not at all']],
        ['a date that is not one', `${HEADER}\na,b,c,d,,,,,HIGH,2026-02-30\n`, ['row 1: riskAssessedOn: not a YYYY-MM-DD date']],
        ['a line break inside a quoted name', `discoveredId,name,owner,purpose\na,"${VALUE}\nsecond",c,d\n`, ['row 1: name: a control character']],
        ['a lone carriage return in a cell', `discoveredId,name,owner,purpose\na,b\rc,d,e\n`, ['row 1: name: a control character']],
    ])('%s', (_label, text, expected) => {
        const issues = csvRefusal(text);
        expect(issues).toEqual(expected);
        expect(issues.join(' ')).not.toContain(VALUE);
    });

    it('refuses a secret-shaped cell by row and field, before any other rule', () => {
        const canary = ['gh', 'p_', 'Q'.repeat(36)].join('');
        const issues = csvRefusal(`discoveredId,name,owner,purpose\na,b,c,d\ne,f,${canary},\n`);
        expect(issues).toEqual(['row 2: owner: a credential value in the inventory']);
        expect(issues.join(' ')).not.toContain(canary);
    });

    it('refuses a secret-shaped JSON value by path', () => {
        const canary = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
        const text = JSON.stringify({ inventory: INVENTORY_SCHEMA_ID, agents: [{ ...ALPHA, purpose: `key ${canary}` }] });
        const issues = refusal(() => loadInventoryFile(write('inventory.json', text)));
        expect(issues).toEqual(['row 1: purpose: a credential value in the inventory']);
        expect(issues.join(' ')).not.toContain(canary);
    });

    it('never repeats the path or the value in a refusal', () => {
        const file = write('inventory.json', `{"inventory": "${INVENTORY_SCHEMA_ID}", "agents": [{"discoveredId": "zz-refused-zz"}]}`);
        const issues = refusal(() => loadInventoryFile(file));
        expect(issues.join(' ')).not.toContain(dir);
        expect(issues.join(' ')).not.toContain(VALUE);
        expect(issues.length).toBeGreaterThan(0);
    });
});

describe('3b. a file of the schema before this one is told what changed', () => {
    const V1_HEADER = 'discoveredId,name,owner,purpose,autonomy,dataClass,reach,riskTier,riskAssessedOn';
    const V1_ROW = 'entra:sp:alpha,Invoice triage,finance-operations,Sorts incoming invoices,human-approves,confidential,write,MEDIUM,2026-09-30';
    const changed =
        'the axes are now autonomyLevel (a whole number, 0 to 6), dataAccessScope, reversibility and provenance, '
        + 'in place of autonomy, dataClass and reach, and the risk tier MEDIUM is now MODERATE';

    it('as CSV, by its columns: a CSV file names no schema', () => {
        const issues = csvRefusal(`${V1_HEADER}\n${V1_ROW}\n`);
        expect(issues).toEqual(['header: 3 unknown columns', `header: columns of scanent-inventory/1; this version reads ${INVENTORY_SCHEMA_ID}: ${changed}`]);
        expect(issues.join(' ')).not.toMatch(/human-approves|confidential|Invoice/);
        // One old column among the new ones is enough.
        expect(csvRefusal(`${HEADER},reach\n`)).toEqual(['header: 1 unknown column', `header: columns of scanent-inventory/1; this version reads ${INVENTORY_SCHEMA_ID}: ${changed}`]);
    });

    it('as JSON, by the id it names', () => {
        const text = JSON.stringify({
            inventory: 'scanent-inventory/1',
            agents: [{ discoveredId: 'entra:sp:alpha', name: 'n', owner: 'o', purpose: 'p', axes: { autonomy: 'human-approves', dataClass: 'confidential', reach: 'write' }, riskTier: 'MEDIUM', riskAssessedOn: '2026-09-30' }],
        });
        expect(refusal(() => loadInventoryFile(write('inventory.json', text)))).toEqual([`inventory: the file names "scanent-inventory/1"; this version reads ${INVENTORY_SCHEMA_ID}: ${changed}`]);
    });

    it('says nothing of the schema before to a header that is only unknown', () => {
        expect(csvRefusal('discoveredId,name,owner,purpose,notes\n')).toEqual(['header: 1 unknown column']);
        expect(csvRefusal('discoveredId,name,owner,purpose,Autonomy\n')).toEqual(['header: 1 unknown column']);
    });
});

describe('4. a file that cannot be read whole', () => {
    it('is refused when it is missing, by the error\'s code and not its text', () => {
        const missing = path.join(dir, 'nowhere.json');
        const issues = refusal(() => loadInventoryFile(missing));
        expect(issues).toEqual(['(file): could not be read (ENOENT)']);
        expect(issues.join(' ')).not.toContain(dir);
    });

    it('is refused when it is a directory', () => {
        fs.mkdirSync(path.join(dir, 'inventory.json'));
        expect(refusal(() => loadInventoryFile(path.join(dir, 'inventory.json')))).toEqual(['(file): could not be read (EISDIR)']);
    });

    it('is refused by its size before a byte of it is read', () => {
        const big = path.join(dir, 'inventory.csv');
        // Sparse: one byte over the cap on disk, nothing allocated for it here.
        fs.closeSync(fs.openSync(big, 'w'));
        fs.truncateSync(big, MAX_INVENTORY_BYTES + 1);
        const reads = jest.spyOn(jest.requireActual<typeof fs>('fs'), 'readSync');
        const whole = jest.spyOn(jest.requireActual<typeof fs>('fs'), 'readFileSync');
        try {
            expect(refusal(() => loadInventoryFile(big))).toEqual([`(file): larger than ${MAX_INVENTORY_BYTES} bytes`]);
            expect(reads).not.toHaveBeenCalled();
            expect(whole).not.toHaveBeenCalled();
            // A file under the cap is read through the same descriptor, in full.
            const small = write('small.csv', `${HEADER}\n${ROW}\n`);
            expect(loadInventoryFile(small).rows).toHaveLength(1);
            expect(reads).toHaveBeenCalled();
            expect(whole).not.toHaveBeenCalled();
        } finally {
            reads.mockRestore();
            whole.mockRestore();
        }
    });

    it('is refused when it is not a regular file, without reading it', () => {
        // A device that never ends, under an inventory's name.
        const link = path.join(dir, 'inventory.json');
        fs.symlinkSync('/dev/zero', link);
        expect(refusal(() => loadInventoryFile(link))).toEqual(['(file): not a regular file']);
    });

    it('is refused when the read fails with no code to name', () => {
        const readFile = () => {
            throw new Error(`cannot open ${dir}/inventory.json`);
        };
        expect(refusal(() => loadInventoryFile('/etc/scanent/inventory.json', { readFile }))).toEqual(['(file): could not be read (error)']);
        const odd = () => {
            throw Object.assign(new Error('x'), { code: 'not a code; rm -rf' });
        };
        expect(refusal(() => loadInventoryFile('/etc/scanent/inventory.json', { readFile: odd }))).toEqual(['(file): could not be read (error)']);
    });

    it('is refused when it is larger than the cap, and read at exactly the cap', () => {
        const row = `${ROW}\n`;
        const over = Buffer.alloc(MAX_INVENTORY_BYTES + 1, 0x20);
        expect(refusal(() => loadInventoryFile('/x/inventory.csv', { readFile: () => over }))).toEqual([`(file): larger than ${MAX_INVENTORY_BYTES} bytes`]);
        // At the cap the file is read and judged on its content.
        const atCap = Buffer.concat([Buffer.from(`${HEADER}\n${row}`), Buffer.alloc(MAX_INVENTORY_BYTES - HEADER.length - 1 - row.length, 0x0a)]);
        expect(atCap.byteLength).toBe(MAX_INVENTORY_BYTES);
        expect(loadInventoryFile('/x/inventory.csv', { readFile: () => atCap }).rows).toEqual([ALPHA]);
    });

    it('is refused when it is not UTF-8', () => {
        expect(refusal(() => loadInventoryFile(write('inventory.csv', Buffer.from([0x64, 0xff, 0xfe, 0x0a]))))).toEqual(['(file): not UTF-8']);
        expect(refusal(() => loadInventoryFile(write('inventory.json', Buffer.from([0x7b, 0xc3, 0x28, 0x7d]))))).toEqual(['(file): not UTF-8']);
    });

    it('is refused when it is not JSON, or is JSON cut short', () => {
        expect(refusal(() => loadInventoryFile(write('inventory.json', 'discoveredId,name')))).toEqual(['(file): not JSON']);
        const whole = JSON.stringify({ inventory: INVENTORY_SCHEMA_ID, agents: [ALPHA, { ...ALPHA, discoveredId: 'entra:sp:bravo' }] });
        expect(refusal(() => loadInventoryFile(write('inventory.json', whole.slice(0, whole.length - 40))))).toEqual(['(file): not JSON']);
    });

    it('is refused, never read as empty, when the file is empty', () => {
        expect(refusal(() => loadInventoryFile(write('inventory.json', '')))).toEqual(['(file): not JSON']);
        expect(refusal(() => loadInventoryFile(write('inventory.csv', '')))).toEqual(['header: missing']);
    });
});

describe('5. the configuration names the file', () => {
    const config = (extra: Record<string, unknown> = {}) => ({
        estate: 'acme',
        scanner: { agentId: 'agt_scanner', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
        schedule: { everyHours: 24 },
        sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: '/srv/code' }] }],
        ...extra,
    });
    const issuesOf = (extra: Record<string, unknown>): readonly string[] => {
        try {
            parseScannerConfig(config(extra));
        } catch (err) {
            expect(err).toBeInstanceOf(ConfigError);
            return (err as ConfigError).issues;
        }
        throw new Error('expected the configuration to be refused');
    };

    it('is optional: a configuration without it parses to what it always did', () => {
        const parsed = parseScannerConfig(config());
        expect(Object.hasOwn(parsed, 'inventory')).toBe(false);
        expect(Object.keys(parsed).sort()).toEqual(['estate', 'inflect', 'scanner', 'schedule', 'sources', 'timeBoxSeconds']);
        expect(loadConfiguredInventory(parsed)).toBeNull();
    });

    it('takes an absolute path to a .json or a .csv file', () => {
        expect(parseScannerConfig(config({ inventory: { path: '/etc/scanent/inventory.json' } })).inventory).toEqual({ path: '/etc/scanent/inventory.json' });
        expect(parseScannerConfig(config({ inventory: { path: '/etc/scanent/Inventory.CSV' } })).inventory).toEqual({ path: '/etc/scanent/Inventory.CSV' });
    });

    it.each([
        ['a relative path', { path: 'inventory.json' }, ['inventory.path: custom']],
        ['a path with a .. segment', { path: '/etc/scanent/../inventory.json' }, ['inventory.path: custom']],
        ['another extension', { path: '/etc/scanent/inventory.yaml' }, ['inventory.path: custom']],
        ['no extension', { path: '/etc/scanent/inventory' }, ['inventory.path: custom']],
        ['no path', {}, ['inventory.path: invalid_type']],
        ['an unknown key', { path: '/etc/scanent/inventory.json', format: 'csv' }, ['inventory: unrecognized_keys']],
        ['a path that is not text', { path: 7 }, ['inventory.path: invalid_type']],
    ])('refuses %s', (_label, inventory, expected) => {
        expect(issuesOf({ inventory })).toEqual(expected);
    });

    it('loads the file the configuration names, and refuses the run when it cannot', () => {
        const file = write('inventory.csv', `${HEADER}\n${ROW}\n`);
        const parsed = parseScannerConfig(config({ inventory: { path: file } }));
        expect(loadConfiguredInventory(parsed)).toMatchObject({ format: 'csv', rows: [ALPHA] });

        fs.rmSync(file);
        expect(() => loadConfiguredInventory(parsed)).toThrow(InventoryRefused);
        expect(refusal(() => loadConfiguredInventory(parsed))).toEqual(['(file): could not be read (ENOENT)']);
    });
});

describe('6. the files the documents show', () => {
    const REPO = path.resolve(__dirname, '..', '..', '..');
    const doc = (rel: string): string => fs.readFileSync(path.join(REPO, rel), 'utf8');
    /** The fenced blocks of a document, without their fences. */
    const blocks = (text: string): string[] => [...text.matchAll(/^```[a-z]*\n([\s\S]*?)^```/gm)].map((m) => m[1]);
    const load = (name: string, text: string) => loadInventoryFile(`/nowhere/${name}`, { readFile: () => Buffer.from(text) });
    const VALUES = [...INVENTORY_DATA_ACCESS_SCOPES, ...INVENTORY_REVERSIBILITIES, ...INVENTORY_PROVENANCES, ...INVENTORY_RISK_TIERS];

    it('docs/scanner.md: its JSON inventory is read whole, and declares the axes and a tier', () => {
        const shown = blocks(doc('docs/scanner.md')).filter((b) => b.includes('"agents"') && b.includes('"inventory": "scanent-inventory/'));
        expect(shown).toHaveLength(1);
        const parsed = load('inventory.json', shown[0]);
        expect(parsed.rows).toHaveLength(1);
        expect(Object.keys(parsed.rows[0].axes ?? {})).toEqual([...INVENTORY_AXES]);
        expect(INVENTORY_RISK_TIERS).toContain(parsed.rows[0].riskTier);
    });

    it('docs/guide/run-it.md: its CSV inventory is read whole, with every column this version takes', () => {
        const shown = blocks(doc('docs/guide/run-it.md')).filter((b) => b.startsWith('discoveredId,'));
        expect(shown).toHaveLength(1);
        expect(shown[0].split('\n')[0]).toBe(HEADER);
        const parsed = load('inventory.csv', shown[0]);
        expect(parsed.rows).toHaveLength(1);
        expect(Object.keys(parsed.rows[0].axes ?? {})).toEqual([...INVENTORY_AXES]);
        expect(INVENTORY_RISK_TIERS).toContain(parsed.rows[0].riskTier);
    });

    it.each(['docs/scanner.md', 'docs/guide/run-it.md', 'docs/design/phase-2-standalone-results.md'])('%s names every axis, every value and every tier, and the ladder\'s two ends', (rel) => {
        const text = doc(rel);
        for (const name of [...INVENTORY_AXES, ...VALUES]) expect([name, text.includes(`\`${name}\``)]).toEqual([name, true]);
        expect(text).toMatch(new RegExp(`from ${INVENTORY_AUTONOMY_LEVEL_MIN} to ${INVENTORY_AUTONOMY_LEVEL_MAX}\\b`));
        expect(text).toContain(`${INVENTORY_TIER_MAX_AGE_DAYS} days`);
    });

    it('docs/scanner.md and the design note give the CSV columns as the code has them, and name the schema read and the one refused', () => {
        const optional = INVENTORY_CSV_OPTIONAL_COLUMNS.join(',');
        expect(doc('docs/scanner.md')).toContain(`\`${optional}\``);
        expect(doc('docs/design/phase-2-standalone-results.md')).toContain(`\`${HEADER}\``);
        for (const rel of ['docs/scanner.md', 'docs/design/phase-2-standalone-results.md', 'docs/security-pack/support-and-maintenance.md', 'packages/scanner/tests/fixtures/compat/README.md']) {
            const text = doc(rel);
            expect([rel, text.includes(`\`${INVENTORY_SCHEMA_ID}\``)]).toEqual([rel, true]);
            expect([rel, /scanent-inventory\/1`|`\/1`/.test(text)]).toEqual([rel, true]);
        }
    });

    it('no document outside the design notes and the fixtures still shows a value of the schema before', () => {
        // `MEDIUM` alone is still a finding's severity; as a risk tier it is told by what stands beside it.
        const retired = /human-approves|human-reviews|dataClass|"reach"|,reach,|`reach`: `read-only`|"riskTier": "MEDIUM"|,MEDIUM,\d{4}-|`riskTier`[^\n]*`MEDIUM`, `HIGH`|risk rating \(`LOW`, `MEDIUM`/;
        const walk = (dir: string): string[] =>
            fs.readdirSync(path.join(REPO, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith('.md') ? [path.join(dir, e.name)] : []));
        const files = ['README.md', ...walk('docs').filter((f) => !f.startsWith(path.join('docs', 'design'))), ...walk('examples'), ...walk('deploy')];
        expect(files.length).toBeGreaterThan(20);
        const hits = files.filter((f) => {
            const text = doc(f);
            // The page that says what changed names the old columns once, as retired; nothing else may.
            return retired.test(f === path.join('docs', 'scanner.md') ? text.replace(/`autonomy`,\s+`dataClass` and `reach`/g, '') : text);
        });
        expect(hits).toEqual([]);
    });
});

