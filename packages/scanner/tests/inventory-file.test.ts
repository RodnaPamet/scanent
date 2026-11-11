/**
 * The inventory file: read once, capped, hashed, decoded, then judged.
 *
 *   1. A JSON and a CSV file with the same rows are the same inventory.
 *   2. The CSV decoder is RFC 4180, and strict where a file is ambiguous.
 *   3. Every refusal names the row and the field, and never the value or the path.
 *   4. A file that cannot be read whole is refused, never treated as empty.
 *   5. The configuration names the file; nothing else does.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { INVENTORY_SCHEMA_ID, InventoryRefused } from '@scanent/report/results/inventory';

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

const HEADER = 'discoveredId,name,owner,purpose,autonomy,dataClass,reach,riskTier,riskAssessedOn';
const ROW = 'entra:sp:alpha,Invoice triage,finance-operations,Sorts incoming invoices,human-approves,confidential,write,MEDIUM,2026-09-30';
const ALPHA = {
    discoveredId: 'entra:sp:alpha',
    name: 'Invoice triage',
    owner: 'finance-operations',
    purpose: 'Sorts incoming invoices',
    axes: { autonomy: 'human-approves', dataClass: 'confidential', reach: 'write' },
    riskTier: 'MEDIUM',
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
        const parsed = loadInventoryFile(write('inventory.csv', `${HEADER}\nentra:sp:alpha,Triage,finance,Sorts invoices,,,,,\n`));
        expect(parsed.rows).toEqual([{ discoveredId: 'entra:sp:alpha', name: 'Triage', owner: 'finance', purpose: 'Sorts invoices' }]);
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
        ['one axis without the others', `discoveredId,name,owner,purpose,autonomy\na,b,c,d,autonomous\n`, ['row 1: axes.dataClass: invalid_value', 'row 1: axes.reach: invalid_value']],
        ['an axis value off its list', `${HEADER}\na,b,c,d,${VALUE},public,write,,\n`, ['row 1: axes.autonomy: invalid_value']],
        ['a tier without its date', `${HEADER}\na,b,c,d,,,,HIGH,\n`, ['row 1: riskAssessedOn: a risk tier and the date it was assessed come together or not at all']],
        ['a date that is not one', `${HEADER}\na,b,c,d,,,,HIGH,2026-02-30\n`, ['row 1: riskAssessedOn: not a YYYY-MM-DD date']],
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
        const file = write('inventory.json', '{"inventory": "scanent-inventory/1", "agents": [{"discoveredId": "zz-refused-zz"}]}');
        const issues = refusal(() => loadInventoryFile(file));
        expect(issues.join(' ')).not.toContain(dir);
        expect(issues.join(' ')).not.toContain(VALUE);
        expect(issues.length).toBeGreaterThan(0);
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
