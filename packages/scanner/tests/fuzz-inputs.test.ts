/**
 * Hostile input from the operator's side: an inventory, a configuration file,
 * the two sides of a diff, a signed report read back, and an address.
 *
 * For any bytes one of these readers is given, it returns what it parsed or
 * refuses with its own typed error, and a refusal names a place and a rule,
 * never the value that was refused: the value may be the credential somebody
 * pasted into the wrong file.
 *
 *   1. CSV: `decodeCsvRecords` and `decodeInventoryCsv`, and the round trip
 *      with the report package's CSV writer.
 *   2. The inventory file, whole.
 *   3. The configuration, as a value and through the command line.
 *   4. A diff's inputs.
 *   5. The contract: a signed report altered in any way, and an address.
 */
import { generateKeyPairSync } from 'crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';
import { parseAddress, parseCidr } from '@rodnapamet/scanent-contract/cidr';
import { HARNESS_REFUSALS, verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract-rules';
import { csvCell } from '@scanent/report/render/csv';
import { InventoryRefused } from '@scanent/report/results/inventory';

import { exitCodeForError, main } from '../src/cli';
import { ConfigError, parseScannerConfig } from '../src/config';
import { addressReachable, customerOriginProblem, parsePrivateCidrAllowlist } from '../src/customer-host';
import { DiffInputError, loadDiffSide, MAX_DIFF_INPUT_BYTES, runDiff } from '../src/diff-command';
import { EXIT } from '../src/exit-codes';
import { decodeCsvRecords, decodeInventoryCsv, loadInventoryFile, MAX_INVENTORY_BYTES } from '../src/inventory-file';
import { rawPublicKeyHex, signReport } from '../src/report';
import { validV4ReportBody } from '../../contract/tests/helpers/agent-harness-fake-scanner';
import { fullEstateConfig } from './helpers/doctor-world';
import { CANARIES, scanExample } from './helpers/output-fixtures';
import { forAll, FUZZ_ITERATIONS, mutateJson, randomJson, type Rng, TEST_TIMEOUT_MS } from './helpers/prng';

jest.setTimeout(TEST_TIMEOUT_MS);

/** A marker no reader produces: a refusal that holds it repeated a value from its input. */
const MARK = 'q7Zk-canary-value-';
const marked = (r: Rng): string => `${MARK}${r.int(0, 1e9)}`;

/** Replace some string leaves of a JSON value with marked ones, and sometimes a secret-shaped one. */
function withCanaries(r: Rng, value: unknown): unknown {
    if (typeof value === 'string') return r.chance(0.3) ? (r.chance(0.2) ? r.pick(CANARIES)[1] : marked(r)) : value;
    if (Array.isArray(value)) return value.map((v) => withCanaries(r, v));
    if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, withCanaries(r, v)]));
    return value;
}

function repeatsNothing(message: string): void {
    if (message.includes(MARK)) throw new Error('the refusal repeats a value from its input');
    for (const [what, canary] of CANARIES) if (message.includes(canary)) throw new Error(`the refusal repeats ${what}`);
}

let dir: string;
beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-fuzz-inputs-'));
});
afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
});

/** Deeper than any stack: a value this deep parses as JSON, and overflows whatever then walks it by recursion. */
const DEEPLY = 500_000;

describe('1. CSV', () => {
    const CSV_PIECES = ['"', '""', ',', '\r\n', '\n', '\r', 'a', ' ', '\ufeff', '=1+1', '@x', '\t', '\u0000', '"a,b"', '"a""b"', '"a\nb"', 'discoveredId', 'name', 'owner', 'purpose', 'reach'];

    it('decodeCsvRecords returns records or the record it stopped at, for any text', async () => {
        await forAll(
            'decodeCsvRecords',
            (r) => (r.chance(0.5) ? Array.from({ length: r.int(0, 60) }, () => r.pick(CSV_PIECES)).join('') : r.unicodeString(r.int(0, 300))),
            (text) => {
                const decoded = decodeCsvRecords(text);
                if ('malformedAtRecord' in decoded) {
                    if (!Number.isInteger(decoded.malformedAtRecord) || decoded.malformedAtRecord < 1) throw new Error('a refusal names no record');
                    return;
                }
                for (const record of decoded.records) for (const field of record) if (typeof field !== 'string') throw new Error('a field is not text');
            },
        );
    });

    it('whatever the CSV writer writes, the reader reads back: no field is split, joined or lost', async () => {
        /** What the writer put between the quotes of one cell, undoubled. */
        const written = (field: string): string => csvCell(field).slice(1, -1).replace(/""/g, '"');
        await forAll(
            'CSV round trip',
            (r) => Array.from({ length: r.int(1, 6) }, () => Array.from({ length: r.int(1, 5) }, () => r.unicodeString(r.int(0, 30)))),
            (rows) => {
                const text = rows.map((row) => `${row.map(csvCell).join(',')}\r\n`).join('');
                const decoded = decodeCsvRecords(text);
                if ('malformedAtRecord' in decoded) throw new Error(`the writer's own output is malformed at record ${decoded.malformedAtRecord}`);
                // A line holding one empty field is a blank line to the reader, by its own rule: not a record.
                const expected = rows.map((row) => row.map(written)).filter((row) => !(row.length === 1 && row[0] === ''));
                if (JSON.stringify(decoded.records) !== JSON.stringify(expected)) throw new Error('the round trip changed a field');
            },
        );
    });

    it('a field of ordinary text, with quotes, commas and any letters, comes back exactly', async () => {
        const ORDINARY = ['a', 'B', '7', ' ', ',', '"', '""', "'", ';', '\u00e9', '\u4e2d', '\ud83d\ude00', '<', '&', '(', '.', ':', '/'];
        await forAll(
            'CSV round trip of ordinary text',
            (r) => Array.from({ length: r.int(1, 6) }, () => Array.from({ length: r.int(1, 5) }, () => `x${Array.from({ length: r.int(0, 20) }, () => r.pick(ORDINARY)).join('')}`)),
            (rows) => {
                const decoded = decodeCsvRecords(rows.map((row) => `${row.map(csvCell).join(',')}\r\n`).join(''));
                if ('malformedAtRecord' in decoded || JSON.stringify(decoded.records) !== JSON.stringify(rows)) throw new Error('ordinary text did not come back as written');
            },
        );
    });

    it('decodeInventoryCsv gives rows or InventoryRefused, and a refusal never quotes a cell', async () => {
        const header = 'discoveredId,name,owner,purpose,autonomyLevel,dataAccessScope,reversibility,provenance,riskTier,riskAssessedOn';
        await forAll(
            'decodeInventoryCsv',
            (r) => {
                const row = () => [marked(r), marked(r), marked(r), marked(r), r.pick(['', '3', '7', marked(r)]), '', r.pick(['', 'TERMINAL']), r.pick(['', 'FIRST_PARTY', marked(r)]), r.pick(['', 'HIGH', marked(r)]), ''].map(csvCell).join(',');
                const text = `${r.chance(0.8) ? header : marked(r)}\r\n${Array.from({ length: r.int(0, 5) }, row).join('\r\n')}\r\n`;
                return r.chance(0.6) ? r.mutateText(text) : text;
            },
            (text) => {
                try {
                    decodeInventoryCsv(text);
                } catch (err) {
                    if (!(err instanceof InventoryRefused)) throw err;
                    repeatsNothing(err.message);
                }
            },
        );
    });
});

describe('2. the inventory file', () => {
    const valid = {
        inventory: 'scanent-inventory/2',
        agents: [{ discoveredId: 'entra:sp:alpha', name: 'Invoice triage', owner: 'finance', purpose: 'Sorts invoices', axes: { autonomyLevel: 2, dataAccessScope: 'WRITE_TENANT_DATA', reversibility: 'COMPENSABLE', provenance: 'FIRST_PARTY' }, riskTier: 'LOW', riskAssessedOn: '2026-09-30' }],
    };

    it('any bytes are an inventory or InventoryRefused, and a refusal repeats nothing from the file', async () => {
        await forAll(
            'loadInventoryFile',
            (r) => {
                const mode = r.int(0, 4);
                const json = Buffer.from(JSON.stringify(withCanaries(r, mode === 0 ? valid : mutateJson(r, valid))));
                if (mode <= 1) return { name: 'inventory.json', bytes: json };
                if (mode === 2) return { name: 'inventory.json', bytes: r.mutate(json) };
                if (mode === 3) return { name: 'inventory.csv', bytes: r.mutate(Buffer.from(`discoveredId,name,owner,purpose\r\n"${marked(r)}","${marked(r)}","o","p"\r\n`)) };
                return { name: r.pick(['inventory.json', 'inventory.csv']), bytes: r.bytes(r.int(0, 400)) };
            },
            ({ name, bytes }) => {
                try {
                    loadInventoryFile(`/nowhere/${name}`, { readFile: () => bytes });
                } catch (err) {
                    if (!(err instanceof InventoryRefused)) throw err;
                    repeatsNothing(err.message);
                }
            },
        );
    });

    it.each([
        ['one byte over the cap', Buffer.alloc(MAX_INVENTORY_BYTES + 1, 0x20)],
        ['a megabyte of opening brackets', Buffer.from('['.repeat(1024 * 1024))],
        ['a megabyte of quotes in a CSV', Buffer.from(`discoveredId,name,owner,purpose\r\n${'"'.repeat(1024 * 1024)}`)],
        ['a UTF-16 file', Buffer.from(String.fromCharCode(0xfeff) + JSON.stringify(valid), 'utf16le')],
        ['a NUL-filled file', Buffer.alloc(4096)],
    ])('%s is refused, in bounded time', (_label, bytes) => {
        const started = Date.now();
        for (const name of ['inventory.json', 'inventory.csv']) {
            expect(() => loadInventoryFile(`/nowhere/${name}`, { readFile: () => bytes })).toThrow(InventoryRefused);
        }
        expect(Date.now() - started).toBeLessThan(10_000);
    });

    it('an inventory nested deeper than the stack is InventoryRefused, not a stack overflow that ends the scan', () => {
        // It parses as JSON; what walked it afterwards overflowed, and the scan stopped with the engine's own message.
        for (const text of [
            `${'['.repeat(DEEPLY)}${']'.repeat(DEEPLY)}`,
            `{"inventory":"scanent-inventory/2","agents":${'['.repeat(DEEPLY)}${']'.repeat(DEEPLY)}}`,
            `{"inventory":"scanent-inventory/2","agents":[${'{"axes":'.repeat(DEEPLY)}1${'}'.repeat(DEEPLY)}]}`,
        ]) {
            let thrown: unknown;
            try {
                loadInventoryFile('/nowhere/inventory.json', { readFile: () => Buffer.from(text) });
            } catch (err) {
                thrown = err;
            }
            expect(thrown).toBeInstanceOf(InventoryRefused);
            expect((thrown as Error).message.length).toBeLessThan(400);
        }
    });
});

describe('3. the configuration', () => {
    const valid = () => fullEstateConfig('/var/lib/scanent/out');

    it('a configuration nested deeper than the stack is a ConfigError, not a stack overflow', () => {
        for (const text of [`${'['.repeat(DEEPLY)}${']'.repeat(DEEPLY)}`, `{"estate":"acme","sources":${'{"a":'.repeat(DEEPLY)}1${'}'.repeat(DEEPLY)}}`]) {
            const json: unknown = JSON.parse(text);
            expect(() => parseScannerConfig(json)).toThrow(ConfigError);
        }
    });

    it('any value is a configuration or ConfigError, and the message never repeats a value from the file', async () => {
        await forAll(
            'parseScannerConfig',
            (r) => {
                const mode = r.int(0, 3);
                if (mode === 0) return randomJson(r);
                if (mode === 1) return withCanaries(r, valid());
                return withCanaries(r, mutateJson(r, mutateJson(r, valid())));
            },
            (json) => {
                try {
                    const config = parseScannerConfig(json);
                    if (config.sources.length === 0) throw new Error('a configuration with no source was accepted');
                } catch (err) {
                    if (!(err instanceof ConfigError)) throw err;
                    repeatsNothing(err.message);
                }
            },
        );
    });

    it('the command line ends with a documented exit code or its own error on a spoiled file, repeating none of it and reaching no network', async () => {
        const out: string[] = [];
        const write = (chunk: unknown): boolean => (out.push(String(chunk)), true);
        const stdout = jest.spyOn(process.stdout, 'write').mockImplementation(write);
        const stderr = jest.spyOn(process.stderr, 'write').mockImplementation(write);
        const network = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => {
            throw new Error('no test reaches the network');
        });
        try {
            await forAll(
                'main over a spoiled configuration',
                (r) => {
                    const text = JSON.stringify(withCanaries(r, mutateJson(r, valid())), null, 1);
                    return r.chance(0.5) ? r.mutateText(text) : text;
                },
                async (text, i) => {
                    const path = join(dir, `config-${i % 8}.json`);
                    writeFileSync(path, text, { mode: 0o600 });
                    out.length = 0;
                    // `hosts` reads the configuration and nothing else: no source, no network, no file written.
                    let code: number;
                    try {
                        code = await main(['hosts', '--config', path], {});
                    } catch (err) {
                        // What the command line's own wrapper turns into an exit code: a refused configuration, and nothing else.
                        if (!(err instanceof ConfigError)) throw err;
                        if (exitCodeForError(err) !== EXIT.CONFIG) throw new Error('a refused configuration is not a configuration error');
                        repeatsNothing(err.message);
                        return;
                    }
                    if (code !== EXIT.OK) throw new Error(`exit code ${String(code)}`);
                    repeatsNothing(out.join(''));
                },
                // Each case runs the command line whole; a tenth of the budget is hundreds of files.
                { iterations: Math.max(20, Math.floor(FUZZ_ITERATIONS / 10)) },
            );
            expect(network).not.toHaveBeenCalled();
        } finally {
            stdout.mockRestore();
            stderr.mockRestore();
            network.mockRestore();
        }
    });
});

describe('4. the inputs of a diff', () => {
    const NOW = Date.parse('2026-10-19T03:00:00.000Z');
    let resultsText: string;
    let reportText: string;

    beforeAll(async () => {
        const { raw, results } = await scanExample(NOW);
        resultsText = JSON.stringify(results);
        reportText = raw;
    });

    it('any text is a results value or DiffInputError, and the message repeats nothing from the file', async () => {
        await forAll(
            'loadDiffSide',
            (r) => {
                const base = r.chance(0.5) ? resultsText : reportText;
                const mode = r.int(0, 3);
                if (mode === 0) return JSON.stringify(withCanaries(r, mutateJson(r, JSON.parse(base))));
                if (mode === 1) return r.mutateText(base);
                if (mode === 2) return JSON.stringify(randomJson(r));
                return JSON.stringify(withCanaries(r, JSON.parse(base)));
            },
            (text) => {
                try {
                    const results = loadDiffSide(text, 'old', null);
                    if (results.schema !== 'scanent-results/1') throw new Error('something that is not a results value was returned');
                } catch (err) {
                    if (!(err instanceof DiffInputError)) throw err;
                    repeatsNothing(err.message);
                }
            },
        );
    });

    it('the command ends with a documented exit code on any two files, and never repeats their content', async () => {
        await forAll(
            'runDiff',
            (r) => [r.chance(0.5) ? resultsText : r.mutateText(resultsText), r.chance(0.5) ? reportText : JSON.stringify(withCanaries(r, mutateJson(r, JSON.parse(resultsText))))],
            ([a, b], i) => {
                const paths = [join(dir, `a-${i % 4}.json`), join(dir, `b-${i % 4}.json`)];
                writeFileSync(paths[0], a);
                writeFileSync(paths[1], b);
                const printed: string[] = [];
                const code = runDiff(paths, { stdout: (t) => printed.push(t), stderr: (t) => printed.push(t) });
                if (![0, 1, 2, 3].includes(code)) throw new Error(`exit code ${code}`);
                if (code === 2) repeatsNothing(printed.join(''));
            },
            { iterations: Math.max(20, Math.floor(FUZZ_ITERATIONS / 4)) },
        );
    });

    it('a results file or a report nested deeper than the stack is refused as an input, with the exit code of one', () => {
        const deepMember = `${'{"a":'.repeat(DEEPLY)}1${'}'.repeat(DEEPLY)}`;
        const texts = [
            `{"schema":"scanent-results/1","agents":${deepMember}}`,
            `{"contract":"inflect-agent-harness/3","signature":${deepMember}}`,
            `{"contract":"inflect-agent-harness/3","signature":{"signerKey":"00"},"agents":${'['.repeat(DEEPLY)}${']'.repeat(DEEPLY)}}`,
            `${'['.repeat(DEEPLY)}${']'.repeat(DEEPLY)}`,
        ];
        for (const [i, text] of texts.entries()) {
            expect(() => loadDiffSide(text, 'old', null)).toThrow(DiffInputError);
            const deep = join(dir, `deep-${i}.json`);
            const small = join(dir, 'small-for-deep.json');
            writeFileSync(deep, text);
            writeFileSync(small, resultsText);
            for (const paths of [[deep, small], [small, deep]]) {
                const printed: string[] = [];
                expect(runDiff(paths, { stdout: (t) => printed.push(t), stderr: (t) => printed.push(t) })).toBe(EXIT.USAGE);
                expect(printed.join('')).toMatch(/^scanent diff: (old|new): /);
                expect(printed.join('')).not.toMatch(/call stack/i);
            }
        }
    });

    it('an input over the size cap is refused before it is parsed', () => {
        const big = join(dir, 'big.json');
        // A sparse file: the size is what is asked, and nothing of it is read.
        writeFileSync(big, '');
        // eslint-disable-next-line @typescript-eslint/no-require-imports -- only this case needs truncate
        (require('fs') as typeof import('fs')).truncateSync(big, MAX_DIFF_INPUT_BYTES + 1);
        const small = join(dir, 'small.json');
        writeFileSync(small, resultsText);
        const printed: string[] = [];
        const started = Date.now();
        expect(runDiff([big, small], { stdout: (t) => printed.push(t), stderr: (t) => printed.push(t) })).toBe(EXIT.USAGE);
        expect(Date.now() - started).toBeLessThan(2_000);
        expect(printed.join('')).toMatch(/old/);
    });
});

describe('5. the contract', () => {
    const pair = generateKeyPairSync('ed25519');
    const KEY = rawPublicKeyHex(pair.publicKey);
    const signed = signReport(validV4ReportBody(), pair);

    const bodyOf = (raw: string): unknown => {
        const { signature: _signature, ...body } = JSON.parse(raw) as Record<string, unknown>;
        return body;
    };

    it('the fixture verifies', () => {
        expect(verifyAndParseHarnessReport(signed, [KEY]).ok).toBe(true);
    });

    it('a signed report altered in any way is accepted unchanged or refused with a reason of the contract, never a throw', async () => {
        let refused = 0;
        await forAll(
            'verifyAndParseHarnessReport',
            (r) => {
                const mode = r.int(0, 3);
                if (mode === 0) return r.mutateText(signed);
                if (mode === 1) return JSON.stringify(mutateJson(r, JSON.parse(signed)));
                if (mode === 2) return r.mutate(Buffer.from(signed)).toString('utf8');
                return JSON.stringify(randomJson(r));
            },
            (raw) => {
                const verdict = verifyAndParseHarnessReport(raw, [KEY]);
                if (verdict.ok) {
                    // The signature is over the canonical JSON of the body, so white space, member order
                    // and the spelling of the signature itself (hex is read in either case) may differ.
                    // A BODY that differs and still verifies is a forgery.
                    if (canonicalJson(bodyOf(raw)) !== canonicalJson(bodyOf(signed))) throw new Error('an altered report verified');
                    return;
                }
                refused += 1;
                if (!(HARNESS_REFUSALS as readonly string[]).includes(verdict.reason)) throw new Error(`reason ${verdict.reason}`);
            },
        );
        expect(refused).toBeGreaterThan(0);
    });

    it('parseAddress and parseCidr return bytes or null for any text', async () => {
        const PIECES = ['::', ':', '.', '0', '1', '255', '256', 'ffff', 'g', '[', ']', '/', '%eth0', ' ', '0x7f', '010', '1:2:3:4:5:6:7:8', '::ffff:', '10.0.0.1', '-', '+', 'e'];
        await forAll(
            'parseAddress',
            (r) => (r.chance(0.8) ? Array.from({ length: r.int(0, 24) }, () => r.pick(PIECES)).join('') : r.unicodeString(r.int(0, 80))),
            (text) => {
                const address = parseAddress(text);
                if (address !== null && address.length !== 4 && address.length !== 16) throw new Error('an address of another length');
                const cidr = parseCidr(text);
                if (cidr !== null && (cidr.prefixBits < 0 || cidr.prefixBits > cidr.bytes.length * 8)) throw new Error('a prefix longer than the address');
                // The callers: none throws on what the parser was given.
                addressReachable(text, []);
                parsePrivateCidrAllowlist([text]);
                customerOriginProblem(`https://${text}`);
            },
        );
    });

    it.each([
        // An over-long literal around `::` once threw RangeError from `Array(-1)`.
        ['more than eight groups around ::', '1:2:3:4::5:6:7:8:9'],
        ['nine groups', '1:2:3:4:5:6:7:8:9'],
        ['two ::', '1::2::3'],
        ['a thousand groups', Array.from({ length: 1000 }, () => '1').join(':')],
        ['a megabyte of colons', ':'.repeat(1024 * 1024)],
        ['a megabyte of digits', '1'.repeat(1024 * 1024)],
        ['an empty string', ''],
        ['brackets alone', '[]'],
    ])('parseAddress returns null for %s', (_label, text) => {
        expect(parseAddress(text)).toBeNull();
        expect(parseCidr(`${text}/8`)).toBeNull();
    });

    it('looksLikeSecret answers for any text, in bounded time on a long one', async () => {
        await forAll('looksLikeSecret', (r) => r.unicodeString(r.int(0, 400)), (text) => void looksLikeSecret(text));
        const started = Date.now();
        for (const text of ['a'.repeat(1024 * 1024), 'ey'.repeat(512 * 1024), '-----BEGIN '.repeat(100_000), `https://${'a:'.repeat(400_000)}@x`, `${'A'.repeat(1024 * 1024)}.${'A'.repeat(100)}.`]) looksLikeSecret(text);
        expect(Date.now() - started).toBeLessThan(5_000);
    });
});
