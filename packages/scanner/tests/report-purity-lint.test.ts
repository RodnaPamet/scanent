/**
 * The lint boundary of `@scanent/report`: local results are pure functions.
 *
 * `eslint.config.mjs` refuses, under `packages/report/src`, any Node built-in,
 * the process, the network, a timer, the clock and a random source. This runs
 * the real ESLint over a probe file at a path in that package, so the rule is
 * held as configured rather than as described, and over the same text at a
 * path in the scanner, where all of it is allowed.
 *
 * The probe is passed on stdin: no file is written into the source tree.
 */
import { execFileSync } from 'node:child_process';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const ESLINT = path.join(REPO_ROOT, 'node_modules', 'eslint', 'bin', 'eslint.js');

const PROBE = `import { readFileSync } from 'fs';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { scoreHarness } from '@rodnapamet/scanent-contract/harness-ladder';
import * as yaml from 'js-yaml';

export const a = readFileSync('/etc/hostname', 'utf8');
export const b = createHash('sha256');
export const c = z.string();
export const d = scoreHarness([]);
export const e = yaml.load('a: 1');
export const f = Date.now();
export const g = new Date();
export const h = new Date(0);
export const i = Math.random();
export const j = process.env.HOME;
export const k = Buffer.from('x');
export const l = setTimeout(() => undefined, 1);
export const m = fetch('https://example.com');
export const n = Date.parse('2026-01-01');
export const o = Date.UTC(2026, 0, 1);
export const p = crypto.randomUUID();
export const q = performance.now();
export const r = globalThis.process.env.HOME;
export const s = globalThis.fetch('https://example.com');
export const t = Date();
export const u = new WebSocket('wss://example.com');
export const Clock = Date;
export const v = new Clock();
export const w = new XMLHttpRequest();
`;

interface LintMessage {
    readonly ruleId: string | null;
    readonly line: number;
    readonly message: string;
}

function lint(filePath: string): LintMessage[] {
    let out: string;
    try {
        out = execFileSync(process.execPath, [ESLINT, '--stdin', '--stdin-filename', filePath, '--format', 'json'], {
            cwd: REPO_ROOT,
            input: PROBE,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
        });
    } catch (err) {
        // ESLint exits 1 when it reports errors, with the report on stdout.
        out = (err as { stdout?: string }).stdout ?? '';
    }
    const [result] = JSON.parse(out) as { messages: LintMessage[] }[];
    return result.messages;
}

const lineOf = (text: string): number => PROBE.split('\n').findIndex((l) => l.includes(text)) + 1;

describe('under packages/report/src', () => {
    const messages = lint('packages/report/src/results/probe.ts');
    const at = (text: string) => messages.filter((m) => m.line === lineOf(text)).map((m) => m.ruleId);

    it.each([
        ['a Node built-in', "from 'fs'", 'no-restricted-imports'],
        ['a Node built-in by its node: name', "from 'node:crypto'", 'no-restricted-imports'],
        ['a package its manifest does not declare', "from 'js-yaml'", 'no-restricted-imports'],
        ['the clock', 'Date.now()', 'no-restricted-properties'],
        ['the clock, by a Date with no argument', 'new Date();', 'no-restricted-syntax'],
        ['a random source', 'Math.random()', 'no-restricted-properties'],
        ['the process', 'process.env', 'no-restricted-globals'],
        ['a buffer', 'Buffer.from', 'no-restricted-globals'],
        ['a timer', 'setTimeout(', 'no-restricted-globals'],
        ['the network', "fetch('https", 'no-restricted-globals'],
        ['a random source, by the crypto global', 'crypto.randomUUID()', 'no-restricted-globals'],
        ['the clock, by the performance global', 'performance.now()', 'no-restricted-globals'],
        ['the process, through globalThis', 'globalThis.process', 'no-restricted-globals'],
        ['the network, through globalThis', 'globalThis.fetch', 'no-restricted-globals'],
        ['the clock, by Date called as a function', 't = Date();', 'no-restricted-syntax'],
        ['the clock, by Date under another name', 'Clock = Date;', 'no-restricted-syntax'],
        ['the network, by a socket', 'new WebSocket(', 'no-restricted-globals'],
        ['the network, by a request object', 'new XMLHttpRequest(', 'no-restricted-globals'],
    ])('refuses %s', (_label, text, rule) => {
        expect(lineOf(text)).toBeGreaterThan(0);
        expect(at(text)).toContain(rule);
    });

    it.each([
        ['the contract', "from '@rodnapamet/scanent-contract/harness-ladder'"],
        ['zod', "from 'zod'"],
        ['a Date made from a value', 'new Date(0)'],
        ['parsing a date', 'Date.parse('],
        ['making a UTC day', 'Date.UTC('],
    ])('allows %s', (_label, text) => {
        expect(lineOf(text)).toBeGreaterThan(0);
        expect(at(text)).toEqual([]);
    });
});

describe('the same text under packages/scanner/src', () => {
    it('is refused nothing: the scanner reads files, the clock and the network', () => {
        const messages = lint('packages/scanner/src/probe.ts');
        expect(messages.map((m) => [m.line, m.ruleId])).toEqual([]);
    });
});
