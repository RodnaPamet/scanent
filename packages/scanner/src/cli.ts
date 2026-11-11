#!/usr/bin/env node
/**
 * `scanent` (alias `aes`) — the command line of the Agent Estate Scanner.
 *
 *   scan        --config <file> [--out <dir>] [--dry-run]   one scan, delivered to the outputs in effect
 *   schedule    --config <file> [--out <dir>]               scan now, then every `schedule.everyHours`
 *   public-key  --config <file>                             print the raw public key to register in the tenant
 *   diff        <old> <new> [...]                           what changed between two runs (`diff-command.ts`)
 *   help                                                    the commands
 *
 * Where a run's results go is the configuration's `outputs`, adjusted by the
 * two flags (`outputs.ts`): `--out <dir>` writes the run's files under a
 * directory, and `--dry-run` posts nothing and prints the signed report.
 *
 * Run it after `npm run build`: as `npx scanent` or `npx aes` (both are the
 * launcher `bin/scanent.js`, which starts this file's `run`), or directly as
 * `node dist/cli.js`.
 * Credentials come from the environment variables the configuration names.
 * The CLI passes no `fetchImpl`: that seam belongs to the tests.
 */
import { readFileSync } from 'fs';

import { parseScannerConfig } from './config';
import { runDiff } from './diff-command';
import { jsonLineLog } from './log';
import { OutputsError, resolveOutputs, scanAndDeliver } from './outputs';
import { rawPublicKeyHex } from './report';
import { loadSigningKey } from './scan';
import { runOnSchedule } from './schedule';

/** The value of `--name <value>` or `--name=<value>`; null when the flag is absent or has no value. */
function arg(argv: readonly string[], name: string): string | null {
    const joined = argv.find((a) => a.startsWith(`${name}=`));
    if (joined !== undefined) return joined.slice(name.length + 1) || null;
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
}

/** The flags the three configured commands take. `--config` and `--out` take a value, in either form. */
const VALUE_FLAGS: readonly string[] = ['--config', '--out'];
const BARE_FLAGS: readonly string[] = ['--dry-run'];

/**
 * The first argument after the command that is not one of its flags, or null.
 * A flag that is not known is refused, never ignored: `--out=<dir>` mistyped
 * would otherwise run a scan that posts and writes nothing where it was told.
 */
function unknownArgument(rest: readonly string[]): string | null {
    for (let i = 0; i < rest.length; i++) {
        const a = rest[i];
        if (BARE_FLAGS.includes(a)) continue;
        if (VALUE_FLAGS.includes(a)) i += 1;
        else if (!VALUE_FLAGS.some((flag) => a.startsWith(`${flag}=`))) return a;
    }
    return null;
}

/** The usage error, as it has always read. `help` prints the full set of commands. */
// Kept byte for byte: scripts match on it. It predates `--out`, `diff` and `help`,
// which `scanent help` (or `--help` after any command but `diff`) lists.
const USAGE = 'usage: scanent <scan|schedule|public-key> --config <file> [--dry-run]\n';

export const HELP = `scanent, the Agent Estate Scanner (alias: aes)

  scanent scan       --config <file> [--out <dir>] [--dry-run]
  scanent schedule   --config <file> [--out <dir>]
  scanent public-key --config <file>
  scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]
  scanent help        (also --help or -h, alone or after scan, schedule or public-key)

  scan         One scan, delivered to the configuration's outputs.
               --out <dir>   also write the run's files under <dir>/runs/<scanId>/
                             (report.signed.json, results.json, agents.csv,
                             findings.csv, summary.html, manifest.json)
               --dry-run     post nothing; print the signed report to stdout
  schedule     Scan now, then every schedule.everyHours.
  public-key   Print the raw public key of the signing key.
  diff         Compare two runs: results.json files or signed reports.
               Exit 0 no difference, 1 a difference, 2 an error,
               3 no difference found but not everything could be compared.

Credentials are read from the environment variables the configuration names.
`;

export async function main(argv: readonly string[], env: NodeJS.ProcessEnv): Promise<number> {
    const log = jsonLineLog();
    const [command] = argv;
    // The two commands that read no configuration.
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
    const file = arg(argv, '--config');
    if (!command || !file) {
        process.stderr.write(USAGE);
        return 2;
    }
    if (['scan', 'schedule', 'public-key'].includes(command)) {
        const unknown = unknownArgument(argv.slice(1));
        if (unknown !== null) {
            // The argument is the caller's own, but it may be a mistyped secret: it is not echoed.
            process.stderr.write(`${USAGE}unknown argument for ${command}; run 'scanent help' for every command and flag\n`);
            return 2;
        }
    }
    const config = parseScannerConfig(JSON.parse(readFileSync(file, 'utf8')) as unknown);

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
            const pem = env[config.scanner.signingKeyEnv];
            if (!pem) throw new Error(`environment variable ${config.scanner.signingKeyEnv} is not set`);
            process.stdout.write(`${rawPublicKeyHex(loadSigningKey(pem).publicKey)}\n`);
            return 0;
        }
        case 'scan': {
            const outputs = outputsFor(argv.includes('--dry-run'));
            if (outputs === null) return 2;
            return (await scanAndDeliver({ config, env, log, outputs })).ok ? 0 : 1;
        }
        case 'schedule': {
            const outputs = outputsFor(false);
            if (outputs === null) return 2;
            await runOnSchedule({
                everyHours: config.schedule.everyHours,
                log,
                run: async () => {
                    await scanAndDeliver({ config, env, log, outputs });
                },
            });
            return 0;
        }
        default:
            process.stderr.write(`unknown command: ${command}\n`);
            return 2;
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
            process.exit(1);
        },
    );
}

if (require.main === module) run();
