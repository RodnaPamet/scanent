/**
 * What the output tests share: a key, a configuration over the code-only
 * example, a scan of it, and a way to read a directory tree back.
 */
import { generateKeyPairSync } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { inflateSync } from 'node:zlib';

import type { LocalResults } from '@scanent/report/results/types';

import { parseScannerConfig, type ScannerConfig } from '../../src/config';
import { scoreScanLocally } from '../../src/local-results';
import { jsonLineLog, type ScannerLog } from '../../src/log';
import { rawPublicKeyHex } from '../../src/report';
import { runScan } from '../../src/scan';

export const REPO = path.resolve(__dirname, '..', '..', '..', '..');
export const ESTATE = path.join(REPO, 'examples', 'code-only', 'estate');
export const EXAMPLE_AGENT = 'code:example/support/agent.py#support_executor';

const pair = generateKeyPairSync('ed25519');
export const PEM = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
export const PUBLIC_HEX = rawPublicKeyHex(pair.publicKey);
export const ENV = { SCANNER_SIGNING_KEY: PEM, INFLECT_INGEST_KEY: 'ingest-key-for-tests' };

export const INFLECT = { baseUrl: 'https://inflect.example.com', tenantSlug: 'example', apiKeyEnv: 'INFLECT_INGEST_KEY' };

/** The example's configuration as plain JSON, with whatever a test changes. */
export function configJson(extra: Record<string, unknown> = {}, roots = [{ label: 'example', path: ESTATE }]): Record<string, unknown> {
    return {
        estate: 'example-code',
        scanner: { agentId: 'agt_example', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        inflect: INFLECT,
        schedule: { everyHours: 24 },
        sources: [{ kind: 'code', product: 'langchain', roots }],
        ...extra,
    };
}

export function configOf(extra: Record<string, unknown> = {}, roots = [{ label: 'example', path: ESTATE }]): ScannerConfig {
    return parseScannerConfig(configJson(extra, roots) as unknown);
}

/** A log that keeps its lines. */
export function capturedLog(): { log: ScannerLog; lines: () => Record<string, unknown>[]; text: () => string } {
    const raw: string[] = [];
    return {
        log: jsonLineLog((l) => raw.push(l)),
        lines: () => raw.map((l) => JSON.parse(l) as Record<string, unknown>),
        text: () => raw.join(''),
    };
}

/** A `fetch` that fails the test if anything calls it. */
export const noFetch = async (): Promise<Response> => {
    throw new Error('no test reaches the network');
};

/** One scan of the example at a fixed time, and its local results. */
export async function scanExample(now: number, config: ScannerConfig = configOf()): Promise<{ raw: string; results: LocalResults }> {
    const { raw, body } = await runScan({ config, env: ENV, log: jsonLineLog(() => undefined), fetchImpl: noFetch, now: () => now });
    return { raw, results: scoreScanLocally({ config, raw, body, inventory: null }) };
}

/** Every file under a directory, by its relative path, with its content. */
export function tree(dir: string): Record<string, string> {
    const out: Record<string, string> = {};
    const walk = (at: string) => {
        if (!fs.existsSync(at)) return;
        for (const entry of fs.readdirSync(at, { withFileTypes: true })) {
            const full = path.join(at, entry.name);
            if (entry.isDirectory()) walk(full);
            else out[path.relative(dir, full)] = fs.readFileSync(full, 'utf8');
        }
    };
    walk(dir);
    return out;
}

/**
 * The text a PDF shows, read back from its bytes the way a viewer would find
 * it: every content stream inflated, and every string the text operators show
 * (`(…)` and `<hex>` operands of `Tj`, `TJ`, `'` and `"`) decoded as Latin-1,
 * which is what the standard fonts' WinAnsi encoding is for every character
 * scanent writes. One line per text operator, so a string pdfkit split across
 * operators is still in `joined`, which has nothing between them.
 */
export function pdfTextOf(pdf: Uint8Array): { readonly lines: string; readonly joined: string } {
    const bytes = Buffer.from(pdf);
    const pieces: string[] = [];
    let at = 0;
    for (;;) {
        const start = bytes.indexOf('stream', at, 'latin1');
        if (start < 0) break;
        let from = start + 'stream'.length;
        if (bytes[from] === 0x0d) from += 1;
        if (bytes[from] === 0x0a) from += 1;
        const end = bytes.indexOf('endstream', from, 'latin1');
        if (end < 0) break;
        const raw = bytes.subarray(from, end);
        let content: string;
        try {
            content = inflateSync(raw).toString('latin1');
        } catch {
            content = raw.toString('latin1');
        }
        pieces.push(...textShownBy(content));
        at = end + 'endstream'.length;
    }
    return { lines: pieces.join('\n'), joined: pieces.join('') };
}

const PDF_ESCAPES: Readonly<Record<string, string>> = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' };

/**
 * The strings shown by the text operators of one content stream, one per
 * operator. A single pass over the stream with no regular expression, so its
 * time is linear in the stream whatever the stream holds: literal strings
 * (escapes, octal codes and balanced parentheses), hex strings, and arrays of
 * them, each kept only when the next token is `Tj`, `TJ`, `'` or `"`.
 */
function textShownBy(content: string): string[] {
    const shown: string[] = [];
    let operands: string[] = [];
    let i = 0;
    const literal = (): string => {
        // `content[i]` is '('.
        let depth = 1;
        let out = '';
        i += 1;
        while (i < content.length && depth > 0) {
            const c = content[i];
            if (c === '\\') {
                const next = content[i + 1] ?? '';
                if (next >= '0' && next <= '7') {
                    let digits = '';
                    let j = i + 1;
                    while (j < content.length && digits.length < 3 && content[j] >= '0' && content[j] <= '7') digits += content[j++];
                    out += String.fromCharCode(parseInt(digits, 8));
                    i = j;
                    continue;
                }
                out += PDF_ESCAPES[next] ?? next;
                i += 2;
                continue;
            }
            if (c === '(') depth += 1;
            if (c === ')') depth -= 1;
            if (depth > 0) out += c;
            i += 1;
        }
        return out;
    };
    const hex = (): string => {
        // `content[i]` is '<' and the next is not.
        const close = content.indexOf('>', i + 1);
        const end = close < 0 ? content.length : close;
        let digits = '';
        for (let j = i + 1; j < end; j += 1) if (!/\s/.test(content[j])) digits += content[j];
        i = end + 1;
        return Buffer.from(digits, 'hex').toString('latin1');
    };
    while (i < content.length) {
        const c = content[i];
        if (c === '(') {
            operands.push(literal());
        } else if (c === '<' && content[i + 1] !== '<') {
            operands.push(hex());
        } else if (c === '[') {
            i += 1;
            let joined = '';
            while (i < content.length && content[i] !== ']') {
                if (content[i] === '(') joined += literal();
                else if (content[i] === '<' && content[i + 1] !== '<') joined += hex();
                else i += 1;
            }
            i += 1;
            operands.push(joined);
        } else if (/\s/.test(c)) {
            i += 1;
        } else {
            let token = '';
            while (i < content.length && !/[\s()<>[\]]/.test(content[i])) token += content[i++];
            if (token === '') {
                i += 1;
                continue;
            }
            if (token === 'Tj' || token === 'TJ' || token === "'" || token === '"') {
                if (operands.length > 0) shown.push(operands[operands.length - 1]);
                operands = [];
            } else if (!/^[-+.0-9]+$/.test(token) && !token.startsWith('/')) {
                operands = [];
            }
        }
    }
    return shown;
}

/** The JSON a `summary.html` carries for its script, parsed. */
export function pageDataOf(html: string): unknown {
    const m = /<script type="application\/json" id="scan-data">([^<]*)<\/script>/.exec(html);
    if (m === null) throw new Error('the page carries no data block');
    return JSON.parse(m[1]) as unknown;
}

/** Every string in a value, keys included. */
export function stringsOf(value: unknown): string[] {
    if (typeof value === 'string') return [value];
    if (Array.isArray(value)) return value.flatMap(stringsOf);
    if (value !== null && typeof value === 'object') return Object.entries(value).flatMap(([k, v]) => [k, ...stringsOf(v)]);
    return [];
}

/** One canary per secret shape, built from parts so this file holds no secret-shaped literal. */
export const CANARIES: readonly (readonly [string, string])[] = [
    ['a GitHub token', ['gh', 'p_', 'A'.repeat(24)].join('')],
    ['a GitHub fine-grained token', ['github', '_pat_', 'A1'.repeat(12)].join('')],
    ['an AWS access key id', ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('')],
    ['a Slack token', ['xo', 'xb-', '1234567890-abcdef'].join('')],
    ['an sk- key', ['s', 'k-', 'a'.repeat(24)].join('')],
    ['an sk-ant- key', ['s', 'k-ant-', 'a1b2'.repeat(6)].join('')],
    ['a private key header', ['-----BEGIN ', 'PRIVATE KEY', '-----'].join('')],
    ['a JSON web token', ['ey', 'J', 'a'.repeat(12), '.', 'b'.repeat(12), '.sig'].join('')],
    ['a URL with a password', ['https:', '//user:', 'hunter2', '@db.example'].join('')],
];
