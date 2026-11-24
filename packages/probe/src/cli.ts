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
import { closeSync, constants, existsSync, fstatSync, openSync, readSync, writeSync } from 'node:fs';
import { resolve } from 'node:path';

import { MAX_REPORT_BYTES, harnessKeyFingerprint } from '@rodnapamet/scanent-contract/harness-contract';

import { ScopeSignRefused, loadScopeSigningKey, rawPublicKeyHex, signScope } from './scope-sign';
import { ProbeReportRefused, buildProbeReport, signProbeReport } from './report';
import { planRequests, runProbes } from './runner';
import { createProbeWire, type FetchLike } from './wire';
import { scopeClassRefusal, scopeTargetRefusal, scopeWindowRefusal, verifyEngagementScope } from './scope';

/** The exit codes, the same numbers `scanent` uses for the same meanings (packages/scanner/src/exit-codes.ts). */
export const PROBE_EXIT = Object.freeze({ OK: 0, FAILED: 1, USAGE: 2, CONFIG: 4 } as const);

export interface ProbeCliIo {
    readonly out: (text: string) => void;
    readonly err: (text: string) => void;
    /** The environment the prober's key, credentials and markers are read from. Absent, the process's own. */
    readonly env?: Readonly<Record<string, string | undefined>>;
    /** A TEST SEAM: how requests are sent. Absent, the global `fetch`. */
    readonly fetchImpl?: FetchLike;
    /** A TEST SEAM: how the run waits between requests. Absent, a timer. */
    readonly sleep?: (ms: number) => Promise<void>;
    /** Whether a stop was asked for by a signal. The stop file is checked beside it. */
    readonly stopRequested?: () => boolean;
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
    '  scanent-probe run --scope <file> --trusted-key <key>... --signing-key-env <NAME> --out <report.json>',
    '                    [--credential <endpoint>=<ENV>]... [--planted-marker-env <NAME>]... [--stop-file <path>]',
    '      Send the probes the scope allows, to its targets only, and write the signed report.',
    '      The prober\'s key is read from NAME (or NAME_FILE); the scope must name it. A',
    '      credential is read from its variable and sent only to its endpoint.',
    '  scanent-probe run --dry-run --scope <file> --trusted-key <key>... --prober-key <key>',
    '      Verify the scope and list every request a run would send. Nothing is sent.',
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

/**
 * A regular file's text, or null when it cannot be read, or TOO_LARGE. The
 * size is asked of the open descriptor, and the read stops one byte past the
 * cap: a file swapped or grown between the check and the read is still bounded,
 * and one that grew while it was read is refused rather than cut. The same
 * read as the scanner's inventory file (`packages/scanner/src/inventory-file.ts`).
 */
function readBounded(path: string): string | null | 'TOO_LARGE' {
    let fd: number;
    try {
        fd = openSync(path, 'r');
    } catch {
        return null;
    }
    try {
        const stat = fstatSync(fd);
        if (!stat.isFile()) return null;
        if (stat.size > MAX_REPORT_BYTES) return 'TOO_LARGE';
        const buffer = Buffer.alloc(stat.size + 1);
        let length = 0;
        while (length < buffer.byteLength) {
            const read = readSync(fd, buffer, length, buffer.byteLength - length, null);
            if (read === 0) break;
            length += read;
        }
        if (length > stat.size) return null;
        return buffer.subarray(0, length).toString('utf8');
    } catch {
        return null;
    } finally {
        closeSync(fd);
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

/**
 * `run --dry-run`: the scope verified as `scope verify` verifies it, then the
 * requests a run would send, one line each. The rendered text is not printed:
 * it holds this plan's canary halves, which a real run would not reuse. Without
 * `--dry-run` it refuses: this build sends nothing.
 */
function runDry(argv: readonly string[], io: ProbeCliIo, cwd: string): number {
    const parsed = parseFlags(argv.filter((a) => a !== '--dry-run'), ['--scope', '--trusted-key', '--prober-key'], ['--trusted-key']);
    if ('problem' in parsed) {
        io.err(`run: ${parsed.problem}\n`);
        return PROBE_EXIT.USAGE;
    }
    const scopePath = one(parsed.flags, '--scope');
    const trusted = parsed.flags.values.get('--trusted-key') ?? [];
    const proberKey = one(parsed.flags, '--prober-key');
    if (scopePath === undefined || trusted.length === 0 || proberKey === undefined) {
        io.err('run: --scope, at least one --trusted-key and --prober-key are required\n');
        return PROBE_EXIT.USAGE;
    }
    if (harnessKeyFingerprint(proberKey) === null || trusted.some((k) => harnessKeyFingerprint(k) === null)) {
        io.err('run: a key is not a raw Ed25519 public key in hex or base64\n');
        return PROBE_EXIT.USAGE;
    }
    const raw = readBounded(resolve(cwd, scopePath));
    if (raw === null) return refuse(io, 'NO_SCOPE');
    if (raw === 'TOO_LARGE') return refuse(io, 'TOO_LARGE');
    const result = verifyEngagementScope(raw, { trustedScopeKeys: trusted, proberKey });
    if (!result.ok) return refuse(io, result.reason, result.issues);

    const plan = planRequests(result.scope);
    const index = new Map(result.scope.targets.map((t, i) => [t.endpoint, i + 1]));
    io.out(
        [
            `dry run: ${plan.length} request${plan.length === 1 ? '' : 's'}, none sent`,
            `engagement: ${result.scope.engagementId}`,
            `digest: ${result.digest}`,
            ...plan.map((p) => `target ${index.get(p.endpoint)}  ${p.probeId}  (${p.probeClass})${p.tool === undefined ? '' : `  tool ${p.tool}`}`),
            '',
        ].join('\n'),
    );
    return PROBE_EXIT.OK;
}

/** A variable name the prober will read. */
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;

/**
 * A secret from the environment: the variable, or a file named by NAME_FILE.
 * Both set is refused, as the scanner refuses it. One trailing new line is
 * removed. Never echoed.
 */
function readSecretEnv(env: Readonly<Record<string, string | undefined>>, name: string): { value: string } | { problem: string } {
    const direct = env[name];
    const file = env[`${name}_FILE`];
    if (direct !== undefined && file !== undefined) return { problem: `${name} and ${name}_FILE are both set` };
    let value = direct;
    if (file !== undefined) {
        const read = readBounded(file);
        if (typeof read !== 'string' || read === 'TOO_LARGE') return { problem: `${name}_FILE could not be read` };
        value = read.replace(/\r?\n$/, '');
    }
    if (value === undefined || value.trim() === '') return { problem: `${name} is not set` };
    return { value };
}

/**
 * `run`: send the probes the scope allows and write the signed report. The
 * prober's key is read from the environment and must be the one the scope
 * names; a credential is read from the variable named for its endpoint and
 * goes to that endpoint only. The report file is created, never replaced.
 * What is printed is counts, reasons and notes: never an excerpt, a
 * credential or a marker.
 */
async function runLive(argv: readonly string[], io: ProbeCliIo, cwd: string): Promise<number> {
    const parsed = parseFlags(
        argv,
        ['--scope', '--trusted-key', '--signing-key-env', '--out', '--credential', '--planted-marker-env', '--stop-file'],
        ['--trusted-key', '--credential', '--planted-marker-env'],
    );
    if ('problem' in parsed) {
        io.err(`run: ${parsed.problem}\n`);
        return PROBE_EXIT.USAGE;
    }
    const flags = parsed.flags;
    const scopePath = one(flags, '--scope');
    const trusted = flags.values.get('--trusted-key') ?? [];
    const keyEnv = one(flags, '--signing-key-env');
    const outPath = one(flags, '--out');
    if (scopePath === undefined || trusted.length === 0 || keyEnv === undefined || outPath === undefined) {
        io.err('run: --scope, at least one --trusted-key, --signing-key-env and --out are required\n');
        return PROBE_EXIT.USAGE;
    }
    const markerEnvs = flags.values.get('--planted-marker-env') ?? [];
    const credentialFlags = (flags.values.get('--credential') ?? []).map((v) => {
        const at = v.lastIndexOf('=');
        return at <= 0 ? null : { endpoint: v.slice(0, at), env: v.slice(at + 1) };
    });
    if (trusted.some((k) => harnessKeyFingerprint(k) === null)) {
        io.err('run: a --trusted-key is not a raw Ed25519 public key in hex or base64\n');
        return PROBE_EXIT.USAGE;
    }
    if ([keyEnv, ...markerEnvs].some((n) => !ENV_NAME.test(n)) || credentialFlags.some((c) => c === null || !ENV_NAME.test(c.env))) {
        io.err('run: a variable name is not upper-case letters, digits and _, or a --credential is not <endpoint>=<VARIABLE>\n');
        return PROBE_EXIT.USAGE;
    }
    const out = resolve(cwd, outPath);
    if (existsSync(out)) {
        io.err('run: the output file exists; it is never overwritten\n');
        return PROBE_EXIT.USAGE;
    }

    const env = io.env ?? process.env;
    const pem = readSecretEnv(env, keyEnv);
    if ('problem' in pem) {
        io.err(`run: the prober's key: ${pem.problem}\n`);
        return PROBE_EXIT.CONFIG;
    }
    let keys: ReturnType<typeof loadScopeSigningKey>;
    try {
        keys = loadScopeSigningKey(pem.value);
    } catch {
        io.err('run: the prober\'s key is not an Ed25519 private key in PEM\n');
        return PROBE_EXIT.CONFIG;
    }

    const raw = readBounded(resolve(cwd, scopePath));
    if (raw === null) return refuse(io, 'NO_SCOPE');
    if (raw === 'TOO_LARGE') return refuse(io, 'TOO_LARGE');
    const verified = verifyEngagementScope(raw, { trustedScopeKeys: trusted, proberKey: rawPublicKeyHex(keys.publicKey) });
    if (!verified.ok) return refuse(io, verified.reason, verified.issues);

    const endpoints = new Set(verified.scope.targets.map((t) => t.endpoint));
    const credentials = new Map<string, string>();
    for (const c of credentialFlags as { endpoint: string; env: string }[]) {
        if (!endpoints.has(c.endpoint)) {
            io.err('run: a --credential names an endpoint the scope does not\n');
            return PROBE_EXIT.USAGE;
        }
        const token = readSecretEnv(env, c.env);
        if ('problem' in token) {
            io.err(`run: a credential: ${token.problem}\n`);
            return PROBE_EXIT.CONFIG;
        }
        credentials.set(c.endpoint, token.value);
    }
    const plantedContext: string[] = [];
    for (const name of markerEnvs) {
        const marker = readSecretEnv(env, name);
        if ('problem' in marker) {
            io.err(`run: a planted marker: ${marker.problem}\n`);
            return PROBE_EXIT.CONFIG;
        }
        plantedContext.push(marker.value);
    }

    const stopFile = one(flags, '--stop-file');
    const stopPath = stopFile === undefined ? undefined : resolve(cwd, stopFile);
    const run = await runProbes({
        scope: verified,
        transport: createProbeWire({ fetchImpl: io.fetchImpl, credentials }),
        now: io.now ?? Date.now,
        sleep: io.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms))),
        shouldStop: () => (io.stopRequested?.() ?? false) || (stopPath !== undefined && existsSync(stopPath)),
        plantedContext,
    });

    let report: string;
    try {
        report = signProbeReport(buildProbeReport(run, verified), keys, verified);
    } catch (err) {
        if (err instanceof ProbeReportRefused) {
            io.err(`run: the report was not made\n${err.issues.map((i) => `  ${i}\n`).join('')}`);
            return PROBE_EXIT.FAILED;
        }
        throw err;
    }
    let fd: number;
    try {
        fd = openSync(out, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    } catch {
        io.err('run: the report file could not be created\n');
        return PROBE_EXIT.FAILED;
    }
    try {
        writeSync(fd, report);
    } finally {
        closeSync(fd);
    }

    const count = (v: string) => run.outcomes.filter((o) => o.verdict === v).length;
    io.out(
        [
            `run: ${run.outcomes.length} probe${run.outcomes.length === 1 ? '' : 's'} sent${run.stopped === null ? '' : `, stopped early (${run.stopped})`}`,
            `engagement: ${verified.scope.engagementId}`,
            `verdicts: ${count('ACTED')} acted, ${count('DISCLOSED')} disclosed, ${count('RESISTED')} resisted, ${count('INCONCLUSIVE')} inconclusive`,
            ...run.targets.map((t, i) => `target ${i + 1}  ${t.kind}  ${t.reason}${t.note === undefined ? '' : `  (${t.note})`}`),
            `concluded: ${run.concluded ? 'yes' : 'no: no probe got a verdict'}`,
            'report: written',
            '',
        ].join('\n'),
    );
    return PROBE_EXIT.OK;
}

function refuse(io: ProbeCliIo, reason: string, issues?: readonly string[]): number {
    io.err(`scope: refused (${reason})\n${(issues ?? []).map((i) => `  ${i}\n`).join('')}`);
    return PROBE_EXIT.FAILED;
}

export function main(argv: readonly string[], io: ProbeCliIo): number | Promise<number> {
    const cwd = io.cwd ?? process.cwd();
    const [command, sub, ...rest] = argv;
    if (command === undefined || command === 'help' || command === '--help') {
        io.out(PROBE_HELP);
        return command === undefined ? PROBE_EXIT.USAGE : PROBE_EXIT.OK;
    }
    if (command === 'scope' && sub === 'sign') return runSign(rest, io, cwd);
    if (command === 'scope' && sub === 'verify') return runVerify(rest, io, cwd);
    if (command === 'run') {
        const args = sub === undefined ? [] : [sub, ...rest];
        return args.includes('--dry-run') ? runDry(args, io, cwd) : runLive(args, io, cwd);
    }
    io.err('scanent-probe: not a command; see scanent-probe help\n');
    return PROBE_EXIT.USAGE;
}

export function run(): void {
    // A signal ends a run at its next request; a second one ends the process.
    let stop = false;
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
        process.on(signal, () => {
            if (stop) process.exit(signal === 'SIGINT' ? 130 : 143);
            stop = true;
        });
    }
    Promise.resolve(
        main(process.argv.slice(2), {
            out: (text) => process.stdout.write(text),
            err: (text) => process.stderr.write(text),
            stopRequested: () => stop,
        }),
    ).then(
        (code) => {
            process.exitCode = code;
            process.exit();
        },
        () => {
            process.stderr.write('scanent-probe stopped on an error it could not name\n');
            process.exit(PROBE_EXIT.FAILED);
        },
    );
}
