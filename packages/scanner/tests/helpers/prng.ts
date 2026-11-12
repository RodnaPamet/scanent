/**
 * A seeded generator for the property tests, and the two settings they share.
 * No dependency: a property that fails must fail again from its seed on any
 * machine.
 *
 *   FUZZ_SEED         the seed; a fixed constant unless set, so CI is the same every run
 *   FUZZ_ITERATIONS   cases per property; 200 unless set, 50,000 under SCANENT_LONG=1
 *   SCANENT_LONG=1    `npm run test:long`: the long budget, and the suites skipped otherwise
 *
 * A failure names the seed and the iteration, and writes the input to a file
 * under the system's temporary directory: an input can be megabytes, and an
 * assertion message is not the place for it.
 */
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

export const LONG = process.env.SCANENT_LONG === '1';
export const FUZZ_SEED = Number.parseInt(process.env.FUZZ_SEED ?? '', 10) || 0x5ca7e47;
export const FUZZ_ITERATIONS = Number.parseInt(process.env.FUZZ_ITERATIONS ?? '', 10) || (LONG ? 50_000 : 200);

/** `describe` for a suite that runs only under `SCANENT_LONG=1`. */
export const describeLong = LONG ? describe : describe.skip;

export interface Rng {
    /** A float in [0, 1). */
    next(): number;
    /** An integer in [min, max], both included. */
    int(min: number, max: number): number;
    /** True with probability `p`. */
    chance(p: number): boolean;
    pick<T>(items: readonly T[]): T;
    bytes(length: number): Buffer;
    /** A string of `length` code units drawn from text that parsers get wrong. */
    unicodeString(length: number): string;
    /** A copy of `input` with a few bytes flipped, dropped, repeated or spliced in. */
    mutate(input: Buffer): Buffer;
    /** The same, over text: it stays valid UTF-16, so a mutation is never just a decoding error. */
    mutateText(input: string): string;
}

/** mulberry32: small, fast, and good enough to drive a mutator. */
export function rng(seed: number): Rng {
    let a = seed >>> 0;
    const next = (): number => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (min: number, max: number): number => min + Math.floor(next() * (max - min + 1));
    const pick = <T>(items: readonly T[]): T => items[int(0, items.length - 1)];
    const bytes = (length: number): Buffer => {
        const out = Buffer.alloc(length);
        for (let i = 0; i < length; i++) out[i] = int(0, 255);
        return out;
    };
    /** Text a parser is likely to mishandle: lone surrogates, bidi controls, NUL, separators, quotes, long runs. */
    const HOSTILE: readonly string[] = [
        '\u0000', '\ud800', '\udfff', '\u202e', '\u2066', '\u2028', '\u2029', '\ufeff', '\u0085', '\r', '\n', '\r\n', '\t',
        '"', "'", '\\', '`', '${', '}}', '<', '>', '&', '%00', '../', '\u00e9', '\u4e2d', '\ud83d\ude00', ' ', ',', ';', ':', '=',
    ];
    const unicodeString = (length: number): string => {
        let out = '';
        while (out.length < length) {
            const r = next();
            if (r < 0.35) out += pick(HOSTILE);
            else if (r < 0.9) out += String.fromCharCode(int(0x20, 0x7e));
            else out += String.fromCharCode(int(0, 0xffff));
        }
        return out.slice(0, length);
    };
    const mutate = (input: Buffer): Buffer => {
        let out = Buffer.from(input);
        const edits = int(1, 4);
        for (let e = 0; e < edits; e++) {
            const at = out.length === 0 ? 0 : int(0, out.length - 1);
            const span = Math.min(int(1, 16), Math.max(0, out.length - at));
            switch (int(0, 4)) {
                case 0: // flip a bit
                    if (out.length > 0) out[at] ^= 1 << int(0, 7);
                    break;
                case 1: // drop a run
                    out = Buffer.concat([out.subarray(0, at), out.subarray(at + span)]);
                    break;
                case 2: // repeat a run
                    out = Buffer.concat([out.subarray(0, at + span), out.subarray(at, at + span), out.subarray(at + span)]);
                    break;
                case 3: // splice in random bytes
                    out = Buffer.concat([out.subarray(0, at), bytes(int(1, 8)), out.subarray(at)]);
                    break;
                default: // truncate
                    out = out.subarray(0, at);
            }
        }
        return out;
    };
    const mutateText = (input: string): string => {
        let out = input;
        const edits = int(1, 4);
        for (let e = 0; e < edits; e++) {
            const at = out.length === 0 ? 0 : int(0, out.length - 1);
            const span = int(1, 12);
            switch (int(0, 5)) {
                case 0:
                    out = out.slice(0, at) + out.slice(at + span);
                    break;
                case 1:
                    out = out.slice(0, at + span) + out.slice(at, at + span) + out.slice(at + span);
                    break;
                case 2:
                    out = out.slice(0, at) + unicodeString(int(1, 6)) + out.slice(at);
                    break;
                case 3:
                    out = out.slice(0, at) + pick(['{', '}', '[', ']', '(', ')', '"', "'", ':', ',', '\\', '\n', '#', '/*', '`']) + out.slice(at);
                    break;
                case 4:
                    out = out.slice(0, at) + out.slice(at, at + span).split('').reverse().join('') + out.slice(at + span);
                    break;
                default:
                    out = out.slice(0, at);
            }
        }
        return out;
    };
    return { next, int, chance: (p) => next() < p, pick, bytes, unicodeString, mutate, mutateText };
}

/** Thrown by `forAll` when a case fails: names the seed and iteration, and the file holding the input. */
export class PropertyFailed extends Error {
    constructor(name: string, seed: number, iteration: number, inputFile: string, cause: unknown) {
        const why = cause instanceof Error ? `${cause.name}: ${cause.message.slice(0, 400)}` : String(cause).slice(0, 400);
        super(`${name} failed at iteration ${iteration} of seed ${seed} (rerun with FUZZ_SEED=${seed}). Input written to ${inputFile}. ${why}`);
        this.name = 'PropertyFailed';
    }
}

function saveInput(input: unknown): string {
    const dir = mkdtempSync(join(tmpdir(), 'scanent-fuzz-'));
    const file = join(dir, 'input');
    writeFileSync(file, Buffer.isBuffer(input) ? input : typeof input === 'string' ? input : JSON.stringify(input, null, 1) ?? String(input));
    return file;
}

/**
 * Run `check` over `iterations` inputs made by `generate`, each from its own
 * generator seeded by the suite's seed and the iteration, so one failing case
 * reproduces alone. `check` may be async.
 */
export async function forAll<T>(
    name: string,
    generate: (r: Rng, iteration: number) => T,
    check: (input: T, iteration: number) => void | Promise<void>,
    opts: { readonly iterations?: number; readonly seed?: number } = {},
): Promise<void> {
    const seed = opts.seed ?? FUZZ_SEED;
    const iterations = opts.iterations ?? FUZZ_ITERATIONS;
    for (let i = 0; i < iterations; i++) {
        const input = generate(rng((seed ^ Math.imul(i + 1, 0x9e3779b1)) >>> 0), i);
        try {
            await check(input, i);
        } catch (err) {
            throw new PropertyFailed(name, seed, i, saveInput(input), err);
        }
    }
}

/** JSON from a generator: every type, nested, with keys and strings a parser gets wrong. */
export function randomJson(r: Rng, depth = 0): unknown {
    const roll = r.int(0, depth > 4 ? 5 : 9);
    switch (roll) {
        case 0:
            return null;
        case 1:
            return r.chance(0.5);
        case 2:
            return r.pick([0, -1, 1, 1e308, -1e308, 2 ** 53, 0.1, 1e-7, 4294967296, -0]);
        case 3:
            return r.unicodeString(r.int(0, 24));
        case 4:
            return r.pick(['', '__proto__', 'constructor', 'toString', 'null', 'true', '0', '-1', '[]', '{}']);
        case 5:
            return 'x'.repeat(r.int(0, 2_000));
        case 6:
        case 7:
            return Array.from({ length: r.int(0, 5) }, () => randomJson(r, depth + 1));
        default: {
            const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
            const n = r.int(0, 5);
            for (let i = 0; i < n; i++) {
                out[r.pick(['id', 'name', 'value', 'items', 'next', '__proto__', 'constructor', 'length', r.unicodeString(r.int(1, 8))])] = randomJson(r, depth + 1);
            }
            return { ...out };
        }
    }
}

/** A copy of a JSON value with one node replaced, removed, or wrapped: the shape a source expects, wrong in one place. */
export function mutateJson(r: Rng, value: unknown): unknown {
    const paths: (string | number)[][] = [];
    const walk = (node: unknown, path: (string | number)[]): void => {
        paths.push(path);
        if (Array.isArray(node)) node.forEach((v, i) => walk(v, [...path, i]));
        else if (node !== null && typeof node === 'object') for (const [k, v] of Object.entries(node)) walk(v, [...path, k]);
    };
    walk(value, []);
    const target = r.pick(paths);
    const replace = (node: unknown, path: (string | number)[]): unknown => {
        if (path.length === 0) {
            switch (r.int(0, 5)) {
                case 0:
                    return randomJson(r);
                case 1:
                    return null;
                case 2:
                    return [node, node];
                case 3:
                    return { value: node };
                case 4:
                    return typeof node === 'string' ? r.unicodeString(r.int(0, 300)) : String(JSON.stringify(node)).slice(0, 50);
                default:
                    return typeof node === 'number' ? r.pick([-1, 1e308, 0.5, Number.MAX_SAFE_INTEGER]) : r.int(-5, 5);
            }
        }
        const [head, ...rest] = path;
        if (Array.isArray(node)) return node.map((v, i) => (i === head ? replace(v, rest) : v));
        const obj = node as Record<string, unknown>;
        if (rest.length === 0 && r.chance(0.2)) {
            const { [head as string]: _removed, ...kept } = obj;
            return kept;
        }
        return { ...obj, [head]: replace(obj[head as string], rest) };
    };
    return replace(value, target);
}
