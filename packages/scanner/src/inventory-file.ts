/**
 * THE INVENTORY FILE — read once, capped, hashed, decoded, then judged.
 *
 * The operator's inventory (`inventory.path` in the configuration) is a JSON
 * or a CSV file, told apart by its extension. This module does the parts that
 * touch the machine: refuse a file that is too large before reading it, read
 * the bytes, hash them,
 * and decode it into the row objects `@scanent/report` judges. Both forms
 * reach ONE schema (`parseInventory`), so a rule cannot hold for one and not
 * the other.
 *
 * A missing, unreadable or refused inventory is an error, never an empty
 * inventory: scoring against half of one would report known agents as shadow
 * agents. Every refusal names the row and the field, never the value.
 *
 * THE CSV FORM. RFC 4180: comma-separated, fields optionally in double quotes,
 * a quote inside a quoted field doubled, CRLF or LF line ends, UTF-8, an
 * optional byte-order mark. The first record is the header, and it must be
 * the four required columns plus any of the optional ones, each once. An
 * empty optional cell is an absent value. The decoder is strict where a
 * spreadsheet export is not ambiguous and refuses where it is: a quote in the
 * middle of an unquoted field, text after a closing quote, a record with a
 * different number of fields.
 */
import { createHash } from 'crypto';
import { closeSync, fstatSync, openSync, readSync } from 'fs';

import { INVENTORY_SCHEMA_ID, InventoryRefused, parseInventory, type ParsedInventory } from '@scanent/report/results/inventory';

/** The largest inventory file read. 5,000 rows of the longest fields fit several times over. */
export const MAX_INVENTORY_BYTES = 5 * 1024 * 1024;

export const INVENTORY_CSV_REQUIRED_COLUMNS = ['discoveredId', 'name', 'owner', 'purpose'] as const;
export const INVENTORY_CSV_OPTIONAL_COLUMNS = ['autonomy', 'dataClass', 'reach', 'riskTier', 'riskAssessedOn'] as const;
const AXIS_COLUMNS: readonly string[] = ['autonomy', 'dataClass', 'reach'];
const CSV_COLUMNS: readonly string[] = [...INVENTORY_CSV_REQUIRED_COLUMNS, ...INVENTORY_CSV_OPTIONAL_COLUMNS];

/** The form a path names, by its extension; null when it is neither. */
export function inventoryFormatOf(path: string): 'json' | 'csv' | null {
    const lower = path.toLowerCase();
    return lower.endsWith('.json') ? 'json' : lower.endsWith('.csv') ? 'csv' : null;
}

/**
 * RFC 4180 records. `null` when the text is not well-formed CSV; the caller
 * names the record. A record is an array of fields; a blank line is not a
 * record (a spreadsheet's trailing newline is not an agent).
 */
export function decodeCsvRecords(text: string): { readonly records: string[][] } | { readonly malformedAtRecord: number } {
    const records: string[][] = [];
    let record: string[] = [];
    let field = '';
    let quoted = false;
    /** The current field began with a quote, and that quote has closed. */
    let closed = false;
    let i = 0;
    const endField = () => {
        record.push(field);
        field = '';
        closed = false;
    };
    const endRecord = () => {
        endField();
        // A line holding nothing at all is not a record.
        if (!(record.length === 1 && record[0] === '')) records.push(record);
        record = [];
    };
    while (i < text.length) {
        const ch = text[i];
        if (quoted) {
            if (ch === '"') {
                if (text[i + 1] === '"') {
                    field += '"';
                    i += 2;
                    continue;
                }
                quoted = false;
                closed = true;
            } else {
                field += ch;
            }
            i += 1;
            continue;
        }
        if (ch === ',') endField();
        else if (ch === '\n') endRecord();
        else if (ch === '\r' && text[i + 1] === '\n') {
            endRecord();
            i += 1;
        } else if (closed) {
            // Text after a closing quote: `"a"b`.
            return { malformedAtRecord: records.length + 1 };
        } else if (ch === '"') {
            // A quote opens a field only at its start: `a"b` is not a field.
            if (field !== '') return { malformedAtRecord: records.length + 1 };
            quoted = true;
        } else {
            field += ch;
        }
        i += 1;
    }
    if (quoted) return { malformedAtRecord: records.length + 1 };
    if (field !== '' || closed || record.length > 0) endRecord();
    return { records };
}

/** CSV text to the object the JSON form is: the same rows, for the same schema. */
export function decodeInventoryCsv(text: string): unknown {
    const decoded = decodeCsvRecords(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
    if ('malformedAtRecord' in decoded) {
        throw new InventoryRefused([`record ${decoded.malformedAtRecord}: not well-formed CSV`]);
    }
    const [header, ...rows] = decoded.records;
    if (header === undefined) throw new InventoryRefused(['header: missing']);

    const unknown = header.filter((column) => !CSV_COLUMNS.includes(column)).length;
    if (unknown > 0) throw new InventoryRefused([`header: ${unknown} unknown column${unknown === 1 ? '' : 's'}`]);
    if (new Set(header).size !== header.length) throw new InventoryRefused(['header: a column appears once']);
    const missing = INVENTORY_CSV_REQUIRED_COLUMNS.filter((column) => !header.includes(column));
    if (missing.length > 0) throw new InventoryRefused(missing.map((column) => `header: required column ${column} is missing`));

    const issues: string[] = [];
    const agents = rows.map((cells, index) => {
        if (cells.length !== header.length) {
            issues.push(`row ${index + 1}: ${cells.length} fields where the header has ${header.length}`);
            return {};
        }
        const row: Record<string, unknown> = {};
        const axes: Record<string, string> = {};
        header.forEach((column, c) => {
            const value = cells[c];
            // A required cell is passed on even when empty, so the schema refuses it by name.
            const required = (INVENTORY_CSV_REQUIRED_COLUMNS as readonly string[]).includes(column);
            if (value === '' && !required) return;
            if (AXIS_COLUMNS.includes(column)) axes[column] = value;
            else row[column] = value;
        });
        if (Object.keys(axes).length > 0) row.axes = axes;
        return row;
    });
    if (issues.length > 0) throw new InventoryRefused(issues);
    return { inventory: INVENTORY_SCHEMA_ID, agents };
}

/**
 * Read a file of at most `MAX_INVENTORY_BYTES`, never holding more than one
 * byte over the cap. The size is asked of the open descriptor before a byte is
 * read, and the read itself stops at the cap plus one: a file that grows, or
 * one whose size is not stated (a pipe, a device), is still bounded. Only a
 * regular file is read.
 */
function readCappedFile(path: string): Buffer {
    const fd = openSync(path, 'r');
    try {
        const stat = fstatSync(fd);
        if (stat.isDirectory()) throw Object.assign(new Error('a directory'), { code: 'EISDIR' });
        if (!stat.isFile()) throw new InventoryRefused(['(file): not a regular file']);
        if (stat.size > MAX_INVENTORY_BYTES) throw new InventoryRefused([`(file): larger than ${MAX_INVENTORY_BYTES} bytes`]);
        const buffer = Buffer.alloc(Math.min(stat.size, MAX_INVENTORY_BYTES) + 1);
        let length = 0;
        while (length < buffer.byteLength) {
            const read = readSync(fd, buffer, length, buffer.byteLength - length, null);
            if (read === 0) break;
            length += read;
        }
        // One byte more than the size stated: the file grew while it was read.
        if (length > stat.size) throw new InventoryRefused(['(file): changed while it was read']);
        return buffer.subarray(0, length);
    } finally {
        closeSync(fd);
    }
}

export interface InventoryFileDeps {
    /** How the file is read. A TEST SEAM: production reads the path. */
    readonly readFile?: (path: string) => Buffer;
}

/**
 * Load the inventory at `path`. Throws `InventoryRefused` for anything other
 * than a whole, valid inventory. The message of a read failure is the error's
 * code (`ENOENT`), never its text, which would repeat the path.
 */
export function loadInventoryFile(path: string, deps: InventoryFileDeps = {}): ParsedInventory {
    const format = inventoryFormatOf(path);
    if (format === null) throw new InventoryRefused(['(file): the inventory is a .json or a .csv file']);

    let bytes: Buffer;
    try {
        bytes = (deps.readFile ?? readCappedFile)(path);
    } catch (err) {
        if (err instanceof InventoryRefused) throw err;
        const code = (err as NodeJS.ErrnoException | null)?.code;
        throw new InventoryRefused([`(file): could not be read (${typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'error'})`]);
    }
    if (bytes.byteLength > MAX_INVENTORY_BYTES) throw new InventoryRefused([`(file): larger than ${MAX_INVENTORY_BYTES} bytes`]);
    const sha256 = createHash('sha256').update(bytes).digest('hex');

    let text: string;
    try {
        text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
    } catch {
        throw new InventoryRefused(['(file): not UTF-8']);
    }

    let decoded: unknown;
    if (format === 'json') {
        try {
            decoded = JSON.parse(text);
        } catch {
            throw new InventoryRefused(['(file): not JSON']);
        }
    } else {
        decoded = decodeInventoryCsv(text);
    }
    return parseInventory(decoded, { sha256, format });
}
