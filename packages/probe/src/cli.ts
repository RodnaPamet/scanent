/**
 * `scanent-probe`: the active flavour's own command line (decision 1: its own
 * entry point and image, never a mode of `scanent`).
 *
 * Step 2 of the order of work: the scope only. `scope sign` is the
 * approver's; `scope verify` is what the prober will run before it sends
 * anything. There is no probing command yet.
 *
 * Nothing a file or a flag carried is echoed: a refusal names its reason and,
 * for the schema, paths and rules.
 */
import { closeSync, constants, openSync, readFileSync, statSync, writeSync } from 'node:fs';
import { resolve } from 'node:path';

import { MAX_REPORT_BYTES, harnessKeyFingerprint } from '@rodnapamet/scanent-contract/harness-contract';

import { ScopeSignRefused, loadScopeSigningKey, signScope } from './scope-sign';
import { scopeClassRefusal, scopeTargetRefusal, scopeWindowRefusal, verifyEngagementScope } from './scope';

/** The exit codes, the same numbers `scanent` uses for the same meanings (packages/scanner/src/exit-codes.ts). */
export const PROBE_EXIT = Object.freeze({ OK: 0, FAILED: 1, USAGE: 2, CONFIG: 4 } as const);

export interface ProbeCliIo {
    readonly out: (text: string) => void;
    readonly err: (text: string) => void;
    /** The directory relative paths are resolved against. Absent, the process's own. */
    readonly cwd?: string;
    /** The clock, epoch ms. Absent, `Date.now`. */
    readonly now?: () => number;
}

export const PROBE_HELP = [
    'scanent-probe: the active flavour. Nothing is probed without a verified engagement scope.',
    '',
    'Usage:',
    '  scanent-probe scope sign --key <pem file> --in <scope.json> --out <signed.json>',
    '      Sign a scope with the approver\'s key. The output file is never overwritten.',
    '  scanent-probe scope verify --scope <file> --trusted-key <key> [--trusted-key <key>...]',
    '                             --prober-key <key> [--target <url>] [--class <class>]',
    '      Check a scope as the prober will: a registered signer, the strict format, a',
    '      signer that is not the prober, this prober named, and the window open now.',
    '  scanent-probe help',
    '',
    'Keys are raw Ed25519 public keys, hex or base64 (what `scanent keygen` prints).',
    'See docs/engagement-scope.md.',
    '',
].join('\n');

interface Flags {
    readonly values: ReadonlyMap<string, readonly string[]>;
}

/** Flags of one command: each takes a value; only `repeatable` ones may repeat. Null on a usage error. */
function parseFlags(
    argv: readonly string[],
    allowed: readonly string[],
    repeatable: readonly string[],
): { flags: Flags } | { problem: string } {
    const values = new Map<string, string[]>();
    for (let i = 0; i < argv.length; i += 1) {
        const name = argv[i];
        if (!allowed.includes(name)) return { problem: 'an argument this command does not take' };
        const value = argv[i + 1];
        if (value === undefined || value.startsWith('--')) return { problem: `${name} needs a value` };
        const seen = values.get(name) ?? [];
        if (seen.length > 0 && !repeatable.includes(name)) return { problem: `${name} is given twice` };
        values.set(name, [...seen, value]);
        i += 1;
    }
    return { flags: { values } };
}

const one = (flags: Flags, name: string): string | undefined => flags.values.get(name)?.[0];

/** A file's text, or null when it cannot be read or is over the size any scope may be. */
function readBounded(path: string): string | null | 'TOO_LARGE' {
    try {
        if (statSync(path).size > MAX_REPORT_BYTES) return 'TOO_LARGE';
        return readFileSync(path, 'utf8');
    } catch {
        return null;
    }
}

function runSign(argv: readonly string[], io: ProbeCliIo, cwd: string): number {
    const parsed = parseFlags(argv, ['--key', '--in', '--out'], []);
    if ('problem' in parsed) {
        io.err(`scope sign: ${parsed.problem}\n`);
        return PROBE_EXIT.USAGE;
    }
    const keyPath = one(parsed.flags, '--key');
    const inPath = one(parsed.flags, '--in');
    const outPath = one(parsed.flags, '--out');
    if (keyPath === undefined || inPath === undefined || outPath === undefined) {
        io.err('scope sign: --key, --in and --out are all required\n');
        return PROBE_EXIT.USAGE;
    }

    const pem = readBounded(resolve(cwd, keyPath));
    if (typeof pem !== 'string' || pem === 'TOO_LARGE') {
        io.err('scope sign: the key file could not be read\n');
        return PROBE_EXIT.CONFIG;
    }
    const text = readBounded(resolve(cwd, inPath));
    if (text === null || text === 'TOO_LARGE') {
        io.err(`scope sign: the scope file ${text === null ? 'could not be read' : 'is too large'}\n`);
        return PROBE_EXIT.CONFIG;
    }
    let body: unknown;
    try {
        body = JSON.parse(text);
    } catch {
        io.err('scope sign: the scope file is not JSON\n');
        return PROBE_EXIT.CONFIG;
    }

    let signed: string;
    try {
        signed = signScope(body, loadScopeSigningKey(pem));
    } catch (err) {
        if (err instanceof ScopeSignRefused) {
            io.err(`scope sign: refused\n${err.issues.map((i) => `  ${i}\n`).join('')}`);
            return PROBE_EXIT.FAILED;
        }
        throw err;
    }

    // Created, never replaced: a signed scope is a record of what was authorised.
    let fd: number;
    try {
        fd = openSync(
            resolve(cwd, outPath),
            constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
            0o644,
        );
    } catch (err) {
        const exists = (err as NodeJS.ErrnoException).code === 'EEXIST';
        io.err(`scope sign: ${exists ? 'the output file exists; it is never overwritten' : 'the output file could not be created'}\n`);
        return exists ? PROBE_EXIT.USAGE : PROBE_EXIT.FAILED;
    }
    try {
        writeSync(fd, signed);
    } finally {
        closeSync(fd);
    }
    io.out('scope: signed\n');
    return PROBE_EXIT.OK;
}

function runVerify(argv: readonly string[], io: ProbeCliIo, cwd: string): number {
    const parsed = parseFlags(argv, ['--scope', '--trusted-key', '--prober-key', '--target', '--class'], ['--trusted-key']);
    if ('problem' in parsed) {
        io.err(`scope verify: ${parsed.problem}\n`);
        return PROBE_EXIT.USAGE;
    }
    const scopePath = one(parsed.flags, '--scope');
    const trusted = parsed.flags.values.get('--trusted-key') ?? [];
    const proberKey = one(parsed.flags, '--prober-key');
    if (scopePath === undefined || trusted.length === 0 || proberKey === undefined) {
        io.err('scope verify: --scope, at least one --trusted-key and --prober-key are required\n');
        return PROBE_EXIT.USAGE;
    }
    if (harnessKeyFingerprint(proberKey) === null) {
        io.err('scope verify: --prober-key is not a raw Ed25519 public key in hex or base64\n');
        return PROBE_EXIT.USAGE;
    }
    if (trusted.some((k) => harnessKeyFingerprint(k) === null)) {
        io.err('scope verify: a --trusted-key is not a raw Ed25519 public key in hex or base64\n');
        return PROBE_EXIT.USAGE;
    }

    const raw = readBounded(resolve(cwd, scopePath));
    if (raw === null) return refuse(io, 'NO_SCOPE');
    if (raw === 'TOO_LARGE') return refuse(io, 'TOO_LARGE');

    const result = verifyEngagementScope(raw, { trustedScopeKeys: trusted, proberKey });
    if (!result.ok) return refuse(io, result.reason, result.issues);

    const now = (io.now ?? Date.now)();
    const target = one(parsed.flags, '--target');
    const probeClass = one(parsed.flags, '--class');
    const refusal =
        scopeWindowRefusal(result.scope, now) ??
        (target === undefined ? null : scopeTargetRefusal(result.scope, target)) ??
        (probeClass === undefined ? null : scopeClassRefusal(result.scope, probeClass));
    if (refusal !== null) return refuse(io, refusal);

    // Every value printed was held to a closed format by the schema.
    io.out(
        [
            'scope: verified',
            `engagement: ${result.scope.engagementId}`,
            `window: ${result.scope.window.start} to ${result.scope.window.end}`,
            `classes: ${result.scope.classes.join(', ')}`,
            `targets: ${result.scope.targets.length}`,
            `rate: ${result.scope.ratePerMinute} per minute per target`,
            `digest: ${result.digest}`,
            `signer key fingerprint: ${result.signerFingerprint}`,
            '',
        ].join('\n'),
    );
    return PROBE_EXIT.OK;
}

function refuse(io: ProbeCliIo, reason: string, issues?: readonly string[]): number {
    io.err(`scope: refused (${reason})\n${(issues ?? []).map((i) => `  ${i}\n`).join('')}`);
    return PROBE_EXIT.FAILED;
}

export function main(argv: readonly string[], io: ProbeCliIo): number {
    const cwd = io.cwd ?? process.cwd();
    const [command, sub, ...rest] = argv;
    if (command === undefined || command === 'help' || command === '--help') {
        io.out(PROBE_HELP);
        return command === undefined ? PROBE_EXIT.USAGE : PROBE_EXIT.OK;
    }
    if (command === 'scope' && sub === 'sign') return runSign(rest, io, cwd);
    if (command === 'scope' && sub === 'verify') return runVerify(rest, io, cwd);
    io.err('scanent-probe: not a command; see scanent-probe help\n');
    return PROBE_EXIT.USAGE;
}

export function run(): void {
    const code = main(process.argv.slice(2), {
        out: (text) => process.stdout.write(text),
        err: (text) => process.stderr.write(text),
    });
    process.exitCode = code;
}
