#!/usr/bin/env node
/**
 * `scanent` (alias `aes`) — the command line of the Agent Estate Scanner.
 *
 *   init        [--dir <dir>] [--answers <file>]            write a configuration, an env template and a signing key (`init/`)
 *   keygen      --out <file>                                create a signing key (`keygen.ts`)
 *   doctor      --config <file> [--json]                    is this estate ready to scan? reads only (`doctor/`)
 *   hosts       --config <file> [--format ...]              the hosts the configuration reaches, offline (`hosts.ts`)
 *   scan        --config <file> [--out <dir>] [--dry-run] [--strict]   one scan, delivered to the outputs in effect
 *   schedule    --config <file> [--out <dir>]               scan now, then every `schedule.everyHours`
 *   public-key  --config <file>                             print the raw public key to register in the tenant
 *   diff        <old> <new> [...]                           what changed between two runs (`diff-command.ts`)
 *   support-bundle --config <file> [--out <file>] [...]     how this deployment is set up and how its last run went, for support (`support-bundle.ts`)
 *   help                                                    the commands
 *
 * Exit codes are `exit-codes.ts`'s table: 0 done, 1 failed, 2 usage, 3
 * incomplete, 4 configuration, 5 credential, 6 network.
 *
 * Where a run's results go is the configuration's `outputs`, adjusted by the
 * two flags (`outputs.ts`): `--out <dir>` writes the run's files under a
 * directory, and `--dry-run` posts nothing and prints the signed report.
 *
 * Run it after `npm run build`: as `npx scanent` or `npx aes` (both are the
 * launcher `bin/scanent.js`, which starts this file's `run`), or directly as
 * `node dist/cli.js`.
 * Credentials come from the environment variables the configuration names, or
 * from the file `<NAME>_FILE` names (`secrets.ts`).
 * The CLI passes no `fetchImpl`: that seam belongs to the tests.
 */
import { readFileSync, writeFileSync } from 'fs';
import { isAbsolute, resolve as resolvePath } from 'path';
import { createInterface } from 'readline';

import { InventoryRefused } from '@scanent/report/results/inventory';

import { ConfigError, parseScannerConfig, type ScannerConfig } from './config';
import { runDiff } from './diff-command';
import { renderDoctorJson, renderDoctorText } from './doctor/render';
import { runDoctor } from './doctor/run';
import { EXIT } from './exit-codes';
import { OutputRefusedLocally } from './file-output';
import { HOSTS_FORMATS, hostsFor, renderHosts, type HostsFormat } from './hosts';
import { renderAccessText } from './init/access-guide';
import { InitError, parseInitAnswers, type InitAnswers } from './init/answers';
import { planInit } from './init/plan';
import { collectAnswers, InitAborted, type PromptIo } from './init/prompts';
import { checkInitTarget, CONFIG_FILE, InitRefused, writeInit } from './init/write';
import { generateSigningKey, KeygenError } from './keygen';
import { jsonLineLog } from './log';
import { OutputsError, resolveOutputs, scanAndDeliver } from './outputs';
import { publicKeyFingerprint, rawPublicKeyHex } from './report';
import { loadSigningKey } from './scan';
import { runOnSchedule } from './schedule';
import { resolveSecretEnv, SecretFileError } from './secrets';
import type { ScannerSourceKind } from './scanners';
import { buildSupportBundle, renderSupportBundle } from './support-bundle';

/** The value of `--name <value>` or `--name=<value>`; null when the flag is absent or has no value. */
/**
 * The line that ties a key to the reports it signs. A report's summary prints
 * "Signer key fingerprint", which is a checksum of the key and so does not look
 * like the key: without this line a reader comparing the two sees two strings
 * that share nothing.
 */
function fingerprintLine(publicKeyHex: string): string {
    return `Signer key fingerprint, as a report's summary shows it: ${publicKeyFingerprint(publicKeyHex)}`;
}

function arg(argv: readonly string[], name: string): string | null {
    const joined = argv.find((a) => a.startsWith(`${name}=`));
    if (joined !== undefined) return joined.slice(name.length + 1) || null;
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
}

/** Every value of a flag that may repeat, in either form. */
function args(argv: readonly string[], name: string): string[] {
    const out: string[] = [];
    for (let i = 0; i < argv.length; i++) {
        if (argv[i].startsWith(`${name}=`)) out.push(argv[i].slice(name.length + 1));
        else if (argv[i] === name && i + 1 < argv.length) out.push(argv[++i]);
    }
    return out;
}

/** Whether a value flag is present at all, with or without its value. */
const named = (argv: readonly string[], name: string): boolean => argv.some((a) => a === name || a.startsWith(`${name}=`));

/** The flags each command takes. A value flag takes its value in either form. */
const FLAGS: Readonly<Record<string, { readonly value: readonly string[]; readonly bare: readonly string[] }>> = {
    scan: { value: ['--config', '--out'], bare: ['--dry-run', '--strict'] },
    schedule: { value: ['--config', '--out'], bare: ['--dry-run'] },
    'public-key': { value: ['--config', '--out'], bare: ['--dry-run'] },
    doctor: { value: ['--config', '--out', '--source'], bare: ['--json'] },
    hosts: { value: ['--config', '--format'], bare: [] },
    init: { value: ['--dir', '--answers'], bare: ['--force', '--no-keygen', '--print-access'] },
    keygen: { value: ['--out'], bare: [] },
    'support-bundle': { value: ['--config', '--out', '--runs'], bare: ['--include-identifiers', '--doctor'] },
};

/**
 * The first argument after the command that is not one of its flags, or null.
 * A flag that is not known is refused, never ignored: `--out=<dir>` mistyped
 * would otherwise run a scan that posts and writes nothing where it was told.
 */
function unknownArgument(command: string, rest: readonly string[]): string | null {
    const { value, bare } = FLAGS[command];
    for (let i = 0; i < rest.length; i++) {
        const a = rest[i];
        if (bare.includes(a)) continue;
        if (value.includes(a)) i += 1;
        else if (!value.some((flag) => a.startsWith(`${flag}=`))) return a;
    }
    return null;
}

/**
 * The usage error. Its FIRST line is as it has always read, byte for byte:
 * scripts match on it. It predates `--out`, `diff`, `help` and the Phase 3
 * commands, so a second line points to `help` and names every command.
 */
const USAGE_LINE = 'usage: scanent <scan|schedule|public-key> --config <file> [--dry-run]\n';
export const USAGE_HINT = "run 'scanent help' for every command: init, keygen, doctor, hosts, scan, schedule, public-key, diff, support-bundle\n";
const USAGE = `${USAGE_LINE}${USAGE_HINT}`;
const DOCTOR_USAGE = `usage: scanent doctor --config <file> [--json] [--out <absolute dir>] [--source <kind>]...\n`;
const HOSTS_USAGE = 'usage: scanent hosts --config <file> [--format lines|json|egress-allow]\n';
const SUPPORT_USAGE = 'usage: scanent support-bundle --config <file> [--out <file>] [--runs <absolute dir>] [--doctor] [--include-identifiers]\n';

export const HELP = `scanent, the Agent Estate Scanner (alias: aes)

  scanent init       [--dir <dir>] [--answers <file>] [--force] [--no-keygen] [--print-access]
  scanent keygen     --out <file>
  scanent doctor     --config <file> [--json] [--out <dir>] [--source <kind>]...
  scanent hosts      --config <file> [--format lines|json|egress-allow]
  scanent scan       --config <file> [--out <dir>] [--dry-run] [--strict]
  scanent schedule   --config <file> [--out <dir>]
  scanent public-key --config <file>
  scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]
  scanent support-bundle --config <file> [--out <file>] [--runs <dir>] [--doctor] [--include-identifiers]
  scanent help        (also --help or -h, alone or after any command but diff)

  init         Write a configuration, an env template of credential NAMES and a
               signing key under <dir> (default ./scanent), and print the
               read-only access each chosen source needs. Asks at the terminal,
               or reads --answers <file>. It never asks for a secret value.
               --force         replace an existing config.json and scanent.env
                               (a signing key is never replaced)
               --no-keygen     do not create a signing key
               --print-access  print the access tables and write nothing
  keygen       Create an Ed25519 signing key in a new file (mode 0600) and
               print its public key. An existing file is never replaced.
  doctor       Check that the estate is ready to scan: the configuration, the
               signing key, each credential, each host, and that each source
               can be read. Reads only; writes and posts nothing.
               --json          one scanent-doctor/1 document on stdout
               --out <dir>     check this output directory
               --source <kind> check only this source (may repeat)
               Exit 0 ready, 3 warnings or blocked checks, 4 configuration,
               5 a credential, 6 the network.
  hosts        Print the hosts the configuration reaches, each on port 443.
               Offline. --format egress-allow prints the EGRESS_ALLOW value.
  scan         One scan, delivered to the configuration's outputs.
               --out <dir>   also write the run's files under <dir>/runs/<scanId>/
                             (report.signed.json, results.json, agents.csv,
                             findings.csv, summary.html, manifest.json)
               --dry-run     post nothing; print the signed report to stdout
               --strict      exit 3 when the run was delivered but a source was
                             incomplete or no agent was found
  schedule     Scan now, then every schedule.everyHours.
  public-key   Print the raw public key of the signing key.
  diff         Compare two runs: results.json files or signed reports.
               Exit 0 no difference, 1 a difference, 2 an error,
               3 no difference found but not everything could be compared.
  support-bundle
               One scanent-support/1 document for whoever helps with this
               deployment: versions, the shape of the configuration, which
               credential variables are set (never a value), and how the last
               run went. Hosts, labels, paths and agent ids are replaced by
               tokens. Read it before you send it.
               --out <file>           write it to a new file (mode 0600);
                                      without it, to stdout
               --runs <dir>           read the last run from this output directory
               --doctor               include the checks of 'scanent doctor'
                                      (makes the requests doctor makes)
               --include-identifiers  keep the names instead of tokens

Credentials are read from the environment variables the configuration names.
For each such NAME, NAME_FILE may instead name a file holding the value.
A proxy is taken from HTTPS_PROXY and NO_PROXY (with NODE_USE_ENV_PROXY=1, which
the container image sets); a private certificate authority from NODE_EXTRA_CA_CERTS.

Exit codes: 0 done, 1 failed, 2 usage, 3 incomplete, 4 configuration,
5 credential, 6 network.
`;

/** What the command line reads besides its arguments and environment. TEST SEAMS: production uses the process's own. */
export interface CliIo {
    /** The wizard's prompts. Absent, they are asked on stdin and written to stderr. */
    readonly prompt?: PromptIo;
    /** Whether stdin is a terminal. Absent, the process's own. */
    readonly interactive?: boolean;
    /** The directory relative paths are resolved against. Absent, the process's own. */
    readonly cwd?: string;
}

/**
 * Failures of the configuration FILE itself (unreadable, not JSON), marked as
 * they pass so `exitCodeForError` can class them without changing what is
 * thrown: callers and tests still see the original error.
 */
const CONFIG_FILE_FAILURES = new WeakSet<object>();

function loadConfig(file: string): ScannerConfig {
    try {
        let text: string;
        try {
            text = readFileSync(file, 'utf8');
        } catch (err) {
            // The errno code only: the path is the caller's own argument and is not repeated.
            const code = (err as NodeJS.ErrnoException | null)?.code;
            throw new ConfigError([`(root): the file could not be read (${typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'error'})`]);
        }
        let json: unknown;
        try {
            json = JSON.parse(text) as unknown;
        } catch {
            // Node's own message quotes the bytes around the error, which is where a
            // mistyped or pasted credential sits. None of the file is repeated.
            throw new ConfigError(['(root): the file is not JSON']);
        }
        return parseScannerConfig(json);
    } catch (err) {
        if (err !== null && typeof err === 'object') CONFIG_FILE_FAILURES.add(err);
        throw err;
    }
}

/**
 * The exit code for an error a command threw: 4 for a refused configuration,
 * secret file or inventory, and 1 for everything else — a missing signing key
 * included, as it has always been.
 */
export function exitCodeForError(err: unknown): number {
    if (err instanceof ConfigError || err instanceof SecretFileError || err instanceof InventoryRefused) return EXIT.CONFIG;
    if (err !== null && typeof err === 'object' && CONFIG_FILE_FAILURES.has(err)) return EXIT.CONFIG;
    return EXIT.FAILED;
}

const stdout = (text: string) => void process.stdout.write(text);
const stderr = (text: string) => void process.stderr.write(text);

const isCleanPath = (v: string): boolean => !v.split('/').includes('..') && ![...v].some((ch) => ch.charCodeAt(0) < 0x20);

/** `scanent keygen --out <file>`. */
function runKeygen(argv: readonly string[], cwd: string): number {
    const out = arg(argv, '--out');
    if (out === null || unknownArgument('keygen', argv) !== null || !isCleanPath(out)) {
        stderr('usage: scanent keygen --out <file>\n');
        return EXIT.USAGE;
    }
    const path = isAbsolute(out) ? out : resolvePath(cwd, out);
    try {
        const { publicKeyHex } = generateSigningKey(path);
        stdout(`${publicKeyHex}\n`);
        stderr(`signing key written to ${path} (mode 0600). The line above is its public key; the private key is in the file only.\n`);
        stderr(`${fingerprintLine(publicKeyHex)}\n`);
        return EXIT.OK;
    } catch (err) {
        if (!(err instanceof KeygenError)) throw err;
        stderr(`${err.message}\n`);
        return err.reason === 'EXISTS' ? EXIT.USAGE : EXIT.FAILED;
    }
}

/**
 * The wizard's prompts on the process's own terminal: questions on stderr
 * (stdout stays clean), answers a line at a time from stdin. Lines are
 * queued as they arrive, so answers typed or pasted ahead of a question are
 * kept, in order; input that ends before the questions do ends the wizard.
 */
export function terminalPrompt(
    input: NodeJS.ReadableStream = process.stdin,
    output: NodeJS.WritableStream = process.stderr,
): { readonly io: PromptIo; close(): void } {
    const rl = createInterface({ input, output });
    const queued: string[] = [];
    let waiting: ((line: string | null) => void) | null = null;
    let ended = false;
    rl.on('line', (line) => {
        if (waiting === null) queued.push(line);
        else {
            const resolve = waiting;
            waiting = null;
            resolve(line);
        }
    });
    rl.on('close', () => {
        ended = true;
        waiting?.(null);
    });
    const next = (): Promise<string | null> => {
        if (queued.length > 0) return Promise.resolve(queued.shift() as string);
        if (ended) return Promise.resolve(null);
        return new Promise((resolve) => {
            waiting = resolve;
        });
    };
    return {
        io: {
            async ask(question) {
                // A closed interface cannot prompt: Node 24 throws "readline was
                // closed" from prompt() where Node 22 wrote nothing. Lines that
                // arrived before the end are still answers; after them the
                // wizard ends with its own message.
                if (!ended) {
                    rl.setPrompt(question);
                    rl.prompt();
                }
                const line = await next();
                if (line === null) throw new InitAborted('the input ended before the questions did; nothing was written');
                return line;
            },
            say: (text) => void output.write(`${text}\n`),
        },
        close: () => rl.close(),
    };
}

const INIT_USAGE = 'usage: scanent init [--dir <dir>] [--answers <file>] [--force] [--no-keygen] [--print-access]\n';

/** `scanent init`. Makes no network request and reads no credential. */
async function runInit(argv: readonly string[], io: CliIo): Promise<number> {
    const cwd = io.cwd ?? process.cwd();
    const missingValue = (['--dir', '--answers'] as const).some((flag) => named(argv, flag) && arg(argv, flag) === null);
    const dirArg = arg(argv, '--dir');
    if (unknownArgument('init', argv) !== null || missingValue || (dirArg !== null && !isCleanPath(dirArg))) {
        stderr(INIT_USAGE);
        return EXIT.USAGE;
    }
    const dir = dirArg === null ? resolvePath(cwd, 'scanent') : isAbsolute(dirArg) ? dirArg : resolvePath(cwd, dirArg);
    const answersFile = arg(argv, '--answers');
    const refused = (err: InitRefused): number => {
        stderr(`${err.message}\n`);
        return err.reason === 'NOT_WRITTEN' ? EXIT.FAILED : EXIT.USAGE;
    };

    // Before a question is asked or the answers are read: a directory that is in the
    // way is said now, not after the whole wizard has been answered.
    if (!argv.includes('--print-access')) {
        try {
            checkInitTarget(dir, { force: argv.includes('--force') });
        } catch (err) {
            if (!(err instanceof InitRefused)) throw err;
            return refused(err);
        }
    }

    let answers: InitAnswers;
    if (answersFile !== null) {
        let json: unknown;
        try {
            json = JSON.parse(readFileSync(isAbsolute(answersFile) ? answersFile : resolvePath(cwd, answersFile), 'utf8'));
        } catch (err) {
            const code = (err as NodeJS.ErrnoException).code;
            stderr(`the answers file could not be read: ${typeof code === 'string' ? code : 'not JSON'}\n`);
            return EXIT.CONFIG;
        }
        try {
            answers = parseInitAnswers(json);
        } catch (err) {
            if (!(err instanceof InitError)) throw err;
            stderr(`${err.message}\n`);
            return EXIT.CONFIG;
        }
    } else {
        if (!(io.interactive ?? process.stdin.isTTY === true) && io.prompt === undefined) {
            stderr(`init asks its questions at a terminal, and stdin is not one. Pass --answers <file> instead.\n${INIT_USAGE}`);
            return EXIT.USAGE;
        }
        const terminal = io.prompt === undefined ? terminalPrompt() : null;
        try {
            answers = await collectAnswers(io.prompt ?? (terminal as NonNullable<typeof terminal>).io);
        } catch (err) {
            if (!(err instanceof InitAborted)) throw err;
            stderr(`${err.message}\n`);
            return EXIT.USAGE;
        } finally {
            terminal?.close();
        }
    }

    let plan;
    try {
        plan = planInit(answers);
    } catch (err) {
        if (!(err instanceof InitError)) throw err;
        stderr(`${err.message}\n`);
        return EXIT.CONFIG;
    }
    const tables = plan.access.map(renderAccessText).join('\n');
    if (argv.includes('--print-access')) {
        stdout(tables);
        return EXIT.OK;
    }

    let written;
    try {
        written = writeInit(plan, dir, { force: argv.includes('--force'), keygen: !argv.includes('--no-keygen') });
    } catch (err) {
        if (!(err instanceof InitRefused)) throw err;
        return refused(err);
    }
    const lines: string[] = ['', 'Written:'];
    for (const f of written.files) lines.push(`  ${f.path}  (mode 0${f.mode.toString(8)})`);
    if (written.signingKey === null) {
        lines.push('', 'No signing key was created. Create one with: scanent keygen --out <file>');
    } else {
        if (!written.signingKey.created) lines.push('', `Kept the existing signing key at ${written.signingKey.path}; it was not replaced.`);
        if (written.signingKey.publicKeyHex !== null) {
            lines.push(
                '',
                `Signing key, public half: ${written.signingKey.publicKeyHex}`,
                '  Register this only if you post to a tenant.',
                `  ${fingerprintLine(written.signingKey.publicKeyHex)}`,
            );
        }
    }
    if (written.warnings.length > 0) lines.push('', ...written.warnings.map((w) => `Warning: ${w}`));
    lines.push('', 'Access to create, read-only, for the sources you chose:', '', tables);
    lines.push('Next:');
    plan.nextSteps.forEach((step, i) => lines.push(`  ${i + 1}. ${step.replace('<dir>/config.json', `${written.dir}/${CONFIG_FILE}`)}`));
    if (written.signingKey !== null) {
        lines.push(
            '',
            `scanent.env names the signing key by its path, ${written.signingKey.path}.`,
            'Run doctor and scan where that path is the same: in a container, mount this directory at the path given to --dir.',
        );
    }
    lines.push('');
    stderr(lines.join('\n'));
    return EXIT.OK;
}

/**
 * `scanent support-bundle`. Reads the configuration, the environment's
 * variable names and the last run's files. Unless `--doctor` is given it
 * resolves no credential and makes no request; with it, the preflight resolves
 * and uses every credential, as `scanent doctor` does.
 */
async function runSupportBundle(argv: readonly string[], file: string, env: NodeJS.ProcessEnv, cwd: string): Promise<number> {
    const out = arg(argv, '--out');
    const runs = arg(argv, '--runs');
    const badOut = named(argv, '--out') && (out === null || !isCleanPath(out));
    const badRuns = named(argv, '--runs') && (runs === null || !runs.startsWith('/') || !isCleanPath(runs));
    if (badOut || badRuns) {
        stderr(SUPPORT_USAGE);
        return EXIT.USAGE;
    }
    const bundle = await buildSupportBundle({
        configPath: file,
        env,
        runsDir: runs,
        includeIdentifiers: argv.includes('--include-identifiers'),
        doctor: argv.includes('--doctor') ? () => runDoctor({ configPath: file, env }) : undefined,
    });
    let text: string;
    try {
        text = renderSupportBundle(bundle);
    } catch (err) {
        if (!(err instanceof OutputRefusedLocally)) throw err;
        stderr(`${err.message}\n`);
        return EXIT.FAILED;
    }
    if (out === null) {
        stdout(text);
    } else {
        const path = isAbsolute(out) ? out : resolvePath(cwd, out);
        try {
            // A new file, private to its owner. An existing one is never replaced.
            writeFileSync(path, text, { flag: 'wx', mode: 0o600 });
        } catch (err) {
            const code = (err as NodeJS.ErrnoException | null)?.code;
            stderr(`the support bundle was not written (${typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'error'}); an existing file is never replaced\n`);
            return code === 'EEXIST' ? EXIT.USAGE : EXIT.FAILED;
        }
    }
    stderr(
        bundle.identifiers === 'REPLACED'
            ? 'support bundle written. Hosts, labels, paths and agent ids are replaced by tokens; credential variable NAMES are kept. Read it before you send it.\n'
            : 'support bundle written WITH the estate\'s hosts, labels, paths and agent ids (--include-identifiers). Read it before you send it.\n',
    );
    return EXIT.OK;
}

const TLS_OFF = 'NODE_TLS_REJECT_UNAUTHORIZED=0 turns certificate verification off; scanent does not send credentials over an unverified connection. Remove it; add your CA with NODE_EXTRA_CA_CERTS.\n';

const DOCTOR_KINDS: readonly ScannerSourceKind[] = ['entra-sp', 'okta-app', 'vault', 'mcp', 'runtime', 'cicd', 'code', 'inflect-register', 'gcp-sa', 'entra-integrations'];

export async function main(argv: readonly string[], env: NodeJS.ProcessEnv, io: CliIo = {}): Promise<number> {
    const log = jsonLineLog();
    const [command] = argv;
    // The commands that read no configuration.
    // `diff` takes paths of its own, so help is looked for there only as the command.
    if (command === 'help' || (command !== 'diff' && (argv.includes('--help') || argv.includes('-h')))) {
        process.stdout.write(HELP);
        return 0;
    }
    if (command === 'diff') {
        return runDiff(argv.slice(1), {
            stdout: (text) => void process.stdout.write(text),
            stderr: (text) => void process.stderr.write(text),
        });
    }
    if (command === 'init') return runInit(argv.slice(1), io);
    if (command === 'keygen') return runKeygen(argv.slice(1), io.cwd ?? process.cwd());

    const file = arg(argv, '--config');
    if (!command || !file) {
        // A command with usage of its own says that; everything else gets the line scripts know, and where to look.
        process.stderr.write(command === 'doctor' ? DOCTOR_USAGE : command === 'hosts' ? HOSTS_USAGE : command === 'support-bundle' ? SUPPORT_USAGE : USAGE);
        return 2;
    }
    if (!(command in FLAGS)) {
        process.stderr.write(`unknown command: ${command}\n`);
        return 2;
    }
    const unknown = unknownArgument(command, argv.slice(1));
    if (unknown !== null) {
        // The argument is the caller's own, but it may be a mistyped secret: it is not echoed.
        process.stderr.write(`${USAGE_LINE}unknown argument for ${command}; run 'scanent help' for every command and flag\n`);
        return 2;
    }

    if (command === 'doctor') {
        const out = arg(argv, '--out');
        const only = args(argv, '--source');
        const badOut = named(argv, '--out') && (out === null || !out.startsWith('/') || !isCleanPath(out));
        if (badOut || only.some((k) => !(DOCTOR_KINDS as readonly string[]).includes(k)) || (named(argv, '--source') && only.length === 0)) {
            process.stderr.write(`${DOCTOR_USAGE}  kinds: ${DOCTOR_KINDS.join(', ')}\n`);
            return EXIT.USAGE;
        }
        if (only.length > 0) {
            // A kind the configuration does not hold would check nothing and report Ready on it.
            // A configuration that cannot be read is doctor's own to report, so that case passes through.
            let present: readonly string[] | null = null;
            try {
                present = loadConfig(file).sources.map((s) => s.kind);
            } catch {
                present = null;
            }
            const absent = present === null ? [] : [...new Set(only)].filter((k) => !(present as readonly string[]).includes(k));
            if (present !== null && absent.length > 0) {
                process.stderr.write(
                    `--source ${absent.join(', ')}: the configuration has no such source, so nothing would be checked.\n  it has: ${[...new Set(present)].join(', ')}\n`,
                );
                return EXIT.USAGE;
            }
        }
        const report = await runDoctor({ configPath: file, env, out, only: only as ScannerSourceKind[] });
        process.stdout.write(argv.includes('--json') ? renderDoctorJson(report) : renderDoctorText(report));
        return report.exitCode;
    }

    // Before the configuration is loaded: a bundle is most wanted when it cannot be.
    if (command === 'support-bundle') return runSupportBundle(argv.slice(1), file, env, io.cwd ?? process.cwd());

    // A scanner that sends an estate's read credentials must not do it over an
    // unverified connection because a variable was left in a shell profile.
    if ((command === 'scan' || command === 'schedule') && env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
        process.stderr.write(TLS_OFF);
        return EXIT.CONFIG;
    }

    const config = loadConfig(file);

    if (command === 'hosts') {
        const format = arg(argv, '--format') ?? 'lines';
        if (!(HOSTS_FORMATS as readonly string[]).includes(format) || (named(argv, '--format') && arg(argv, '--format') === null)) {
            process.stderr.write(HOSTS_USAGE);
            return EXIT.USAGE;
        }
        process.stdout.write(renderHosts(hostsFor(config), format as HostsFormat));
        return EXIT.OK;
    }

    // Each credential the configuration names, from its variable or its `_FILE`.
    // Resolved once: a rotated secret file takes effect at the next start.
    const secrets = resolveSecretEnv(config, env);

    /** The outputs this call delivers to, or null (with one line on stderr) when it names none or names one wrongly. */
    const outputsFor = (dryRun: boolean) => {
        try {
            if (argv.some((a) => a === '--out' || a.startsWith('--out=')) && arg(argv, '--out') === null) throw new OutputsError('--out takes a directory');
            return resolveOutputs(config, { out: arg(argv, '--out'), dryRun });
        } catch (err) {
            if (!(err instanceof OutputsError)) throw err;
            process.stderr.write(`${err.message}\n`);
            return null;
        }
    };

    switch (command) {
        case 'public-key': {
            const pem = secrets[config.scanner.signingKeyEnv];
            if (!pem) throw new Error(`environment variable ${config.scanner.signingKeyEnv} is not set`);
            const publicKeyHex = rawPublicKeyHex(loadSigningKey(pem).publicKey);
            // The key alone on stdout, so a script can take it; the fingerprint beside it.
            process.stdout.write(`${publicKeyHex}\n`);
            process.stderr.write(`${fingerprintLine(publicKeyHex)}\n`);
            return 0;
        }
        case 'scan': {
            const outputs = outputsFor(argv.includes('--dry-run'));
            if (outputs === null) return 2;
            const result = await scanAndDeliver({ config, env: secrets, log, outputs });
            if (!result.ok) return EXIT.FAILED;
            if (argv.includes('--strict')) {
                // Delivered, and not everything could be established, for any scanner that ran: zero is never complete.
                const { agents, integrations } = result.scan;
                if (agents !== null && (agents.body.agents.length === 0 || agents.body.population.sources.some((s) => s.status === 'INCOMPLETE'))) return EXIT.INCOMPLETE;
                if (
                    integrations !== null &&
                    (integrations.body.applications.length === 0 || integrations.body.sources.some((s) => s.status === 'INCOMPLETE' || s.signInActivity.status === 'INCOMPLETE'))
                ) {
                    return EXIT.INCOMPLETE;
                }
            }
            return EXIT.OK;
        }
        default: {
            const outputs = outputsFor(false);
            if (outputs === null) return 2;
            await runOnSchedule({
                everyHours: config.schedule.everyHours,
                log,
                run: async () => {
                    await scanAndDeliver({ config, env: secrets, log, outputs });
                },
            });
            return 0;
        }
    }
}

/**
 * Start the command line as a process: the signal handlers, then `main`, then
 * the exit code. `node dist/cli.js` and the `scanent` / `aes` launcher
 * (`bin/scanent.js`) both start here.
 */
export function run(): void {
    // In the container the scanner is process 1, and process 1 is not stopped
    // by a signal it has no handler for: `docker stop` would wait out its grace
    // period and kill it. A scan cut short posts nothing, and a post cut short
    // either landed or did not, so stopping at once loses nothing.
    for (const [signal, code] of [['SIGTERM', 143], ['SIGINT', 130]] as const) {
        process.once(signal, () => process.exit(code));
    }
    main(process.argv.slice(2), process.env).then(
        (code) => process.exit(code),
        (err: unknown) => {
            jsonLineLog().error('scanner stopped', { error: err instanceof Error ? err.message : 'unknown' });
            process.exit(exitCodeForError(err));
        },
    );
}

if (require.main === module) run();
