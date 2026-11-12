/**
 * The command line's exit codes beyond 0, 1 and 2, and what did not move.
 *
 *   1. `scan --strict`: 3 when the run was delivered and not everything could
 *      be established; without it, 0 as always; a failed output is still 1.
 *   2. A refused configuration, secret file or inventory is 4 from the
 *      process, with one log line; a missing signing key is still 1.
 *   3. `NODE_TLS_REJECT_UNAUTHORIZED=0` stops `scan` and `schedule` with 4
 *      before anything is read.
 *   4. The help lists every command; the usage line is what it was.
 */
import { generateKeyPairSync } from 'crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

import { verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import { InventoryRefused } from '@scanent/report/results/inventory';
import { exitCodeForError, HELP, main, run } from '../src/cli';
import { ConfigError } from '../src/config';
import { rawPublicKeyHex } from '../src/report';
import * as schedule from '../src/schedule';
import { SecretFileError } from '../src/secrets';

const REPO = resolve(__dirname, '..', '..', '..');
const KEYS = generateKeyPairSync('ed25519');
const PEM = KEYS.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const PUBLIC_HEX = rawPublicKeyHex(KEYS.publicKey);
const ENV = { SCANNER_SIGNING_KEY: PEM, INFLECT_INGEST_KEY: 'ingest-key-for-tests' };

let dir: string;
let out: string[];
let err: string[];
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-exit-'));
    out = [];
    err = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
});
afterEach(() => {
    jest.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
});

function configWith(roots: { label: string; path: string }[], extra: Record<string, unknown> = {}): string {
    const path = join(dir, `config-${Math.random().toString(16).slice(2)}.json`);
    writeFileSync(path, JSON.stringify({ estate: 'acme', scanner: { agentId: 'agt', signingKeyEnv: 'SCANNER_SIGNING_KEY' }, outputs: [{ kind: 'stdout' }], schedule: { everyHours: 24 }, sources: [{ kind: 'code', product: 'langchain', roots }], ...extra }));
    return path;
}
const EXAMPLE = { label: 'example', path: join(REPO, 'examples', 'code-only', 'estate') };
/** The body of the signed report `scan` printed. */
const printed = (raw: string) => {
    const verified = verifyAndParseHarnessReport(raw.trim(), [PUBLIC_HEX]);
    if (!verified.ok) throw new Error('the printed report did not verify');
    return verified.body;
};

describe('1. scan --strict', () => {
    it('a complete run that found agents is 0', async () => {
        expect(await main(['scan', '--config', configWith([EXAMPLE]), '--strict'], ENV)).toBe(0);
        expect(out).toHaveLength(1);
    });

    it('a delivered run with an incomplete source is 3 with --strict, and 0 without', async () => {
        const config = configWith([EXAMPLE, { label: 'gone', path: join(dir, 'absent') }]);
        expect(await main(['scan', '--config', config, '--strict'], ENV)).toBe(3);
        const body = printed(out[0]);
        expect(body.population.sources.map((s) => s.status)).toEqual(['INCOMPLETE']);
        // Delivered all the same: what was read is real.
        expect(body.agents.length).toBeGreaterThan(0);
        expect(await main(['scan', '--config', config], ENV)).toBe(0);
    });

    it('a complete run that found no agent is 3: zero is never complete', async () => {
        mkdirSync(join(dir, 'empty'));
        const config = configWith([{ label: 'empty', path: join(dir, 'empty') }]);
        expect(await main(['scan', '--config', config, '--strict'], ENV)).toBe(3);
        const body = printed(out[0]);
        expect(body.population.sources.map((s) => s.status)).toEqual(['COMPLETE']);
        expect(body.agents).toEqual([]);
        expect(await main(['scan', '--config', config], ENV)).toBe(0);
    });

    it('a failed output is 1, and wins over incomplete', async () => {
        jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"error":"harness_report_refused: SIGNATURE"}', { status: 400 }));
        const config = configWith([{ label: 'gone', path: join(dir, 'absent') }], {
            inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'example', apiKeyEnv: 'INFLECT_INGEST_KEY' },
            outputs: [{ kind: 'inflect' }],
        });
        expect(await main(['scan', '--config', config, '--strict'], ENV)).toBe(1);
    });

    it('schedule does not take it: a flag is refused, never ignored', async () => {
        const loop = jest.spyOn(schedule, 'runOnSchedule');
        expect(await main(['schedule', '--config', configWith([EXAMPLE]), '--strict'], ENV)).toBe(2);
        expect(loop).not.toHaveBeenCalled();
        expect(err.join('')).toContain('unknown argument for schedule');
    });
});

describe('2. what the process exits with when a command throws', () => {
    const savedArgv = process.argv;
    const savedEnv = { ...process.env };
    afterEach(() => {
        process.argv = savedArgv;
        for (const k of ['SCANNER_SIGNING_KEY', 'SCANNER_SIGNING_KEY_FILE']) {
            if (savedEnv[k] === undefined) delete process.env[k];
            else process.env[k] = savedEnv[k];
        }
    });

    function start(argv: string[]): Promise<number> {
        jest.spyOn(process, 'once').mockImplementation((() => process) as typeof process.once);
        const exited = new Promise<number>((done) => {
            jest.spyOn(process, 'exit').mockImplementation(((code?: number) => done(code ?? 0)) as typeof process.exit);
        });
        process.argv = ['node', 'cli.js', ...argv];
        run();
        return exited;
    }
    const lastLine = () => JSON.parse(err.join('').trim().split('\n').at(-1) as string) as Record<string, unknown>;

    it('a configuration that is missing, not JSON, or refused by the schema is 4, with the paths and no value', async () => {
        process.env.SCANNER_SIGNING_KEY = PEM;
        expect(await start(['scan', '--config', join(dir, 'absent.json'), '--dry-run'])).toBe(4);
        // (Under Jest a file-system error is from another realm, so the log line cannot be read for its message here.)
        expect(lastLine()).toMatchObject({ level: 'error', msg: 'scanner stopped' });

        const notJson = join(dir, 'bad.json');
        writeFileSync(notJson, '{ "estate": ');
        expect(await start(['scan', '--config', notJson, '--dry-run'])).toBe(4);

        const refused = join(dir, 'refused.json');
        writeFileSync(refused, JSON.stringify({ ...JSON.parse(readFileSync(configWith([EXAMPLE]), 'utf8')), apiKey: 'marker-pasted-value' }));
        expect(await start(['public-key', '--config', refused])).toBe(4);
        expect(lastLine()).toMatchObject({ msg: 'scanner stopped', error: 'invalid scanner configuration: (root): unrecognized_keys' });
        expect(err.join('')).not.toContain('marker-pasted-value');
    });

    it('a refused secret file is 4', async () => {
        process.env.SCANNER_SIGNING_KEY = PEM;
        process.env.SCANNER_SIGNING_KEY_FILE = join(dir, 'also.pem');
        expect(await start(['scan', '--config', configWith([EXAMPLE]), '--dry-run'])).toBe(4);
        expect(lastLine().error).toBe('SCANNER_SIGNING_KEY: both the variable and its _FILE form are set; set exactly one');
    });

    it('a refused inventory is 4', async () => {
        process.env.SCANNER_SIGNING_KEY = PEM;
        const config = configWith([EXAMPLE], { inventory: { path: join(dir, 'absent-inventory.json') } });
        expect(await start(['scan', '--config', config, '--dry-run'])).toBe(4);
        expect(String(lastLine().error)).toMatch(/^invalid inventory: /);
    });

    it('a missing signing key is still 1', async () => {
        delete process.env.SCANNER_SIGNING_KEY;
        expect(await start(['scan', '--config', configWith([EXAMPLE]), '--dry-run'])).toBe(1);
        expect(await start(['public-key', '--config', configWith([EXAMPLE])])).toBe(1);
    });

    it('classes errors by their type, and anything it does not know is 1', () => {
        expect(exitCodeForError(new ConfigError(['x: y']))).toBe(4);
        expect(exitCodeForError(new SecretFileError('N', 'EMPTY'))).toBe(4);
        expect(exitCodeForError(new InventoryRefused(['row 1: owner']))).toBe(4);
        expect(exitCodeForError(new Error('anything else'))).toBe(1);
        expect(exitCodeForError(new SyntaxError('JSON from somewhere else'))).toBe(1);
        expect(exitCodeForError('a string')).toBe(1);
        expect(exitCodeForError(null)).toBe(1);
    });
});

describe('3. certificate verification turned off', () => {
    it.each(['scan', 'schedule'])('%s exits 4 before the configuration is read', async (command) => {
        const fetched = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('nothing is requested'));
        const loop = jest.spyOn(schedule, 'runOnSchedule');
        // The configuration does not exist: reading it would throw.
        expect(await main([command, '--config', join(dir, 'absent.json')], { ...ENV, NODE_TLS_REJECT_UNAUTHORIZED: '0' })).toBe(4);
        expect(err.join('')).toMatch(/^NODE_TLS_REJECT_UNAUTHORIZED=0 turns certificate verification off/);
        expect(err.join('')).toContain('NODE_EXTRA_CA_CERTS');
        expect(out).toEqual([]);
        expect(fetched).not.toHaveBeenCalled();
        expect(loop).not.toHaveBeenCalled();
    });

    it('any other value, and commands that send no credential, are not stopped', async () => {
        const config = configWith([EXAMPLE]);
        expect(await main(['scan', '--config', config, '--dry-run'], { ...ENV, NODE_TLS_REJECT_UNAUTHORIZED: '1' })).toBe(0);
        out.length = 0;
        expect(await main(['public-key', '--config', config], { ...ENV, NODE_TLS_REJECT_UNAUTHORIZED: '0' })).toBe(0);
        expect(await main(['hosts', '--config', config], { NODE_TLS_REJECT_UNAUTHORIZED: '0' })).toBe(0);
    });
});

describe('4. help and usage', () => {
    it('the help lists every command, the new flags, the _FILE rule and the exit codes', async () => {
        expect(await main(['help'], {})).toBe(0);
        expect(out.join('')).toBe(HELP);
        for (const line of [
            'scanent init       [--dir <dir>] [--answers <file>] [--force] [--no-keygen] [--print-access]',
            'scanent keygen     --out <file>',
            'scanent doctor     --config <file> [--json] [--out <dir>] [--source <kind>]...',
            'scanent hosts      --config <file> [--format lines|json|egress-allow]',
            'scanent scan       --config <file> [--out <dir>] [--dry-run] [--strict]',
            'scanent schedule   --config <file> [--out <dir>]',
            'scanent public-key --config <file>',
            'scanent diff <old> <new>',
            'NAME_FILE may instead name a file holding the value',
            'Exit codes: 0 done, 1 failed, 2 usage, 3 incomplete, 4 configuration,',
        ]) {
            expect(HELP).toContain(line);
        }
        for (const command of ['init', 'keygen', 'doctor', 'hosts']) {
            out.length = 0;
            expect(await main([command, '--help'], {})).toBe(0);
            expect(out.join('')).toBe(HELP);
        }
    });

    it('doctor and hosts without --config are a usage error that names their own flags', async () => {
        // Was the three-command usage line, which names neither command (Phase 3 review).
        for (const [command, usage] of [
            ['doctor', 'usage: scanent doctor --config <file> [--json] [--out <absolute dir>] [--source <kind>]...\n'],
            ['hosts', 'usage: scanent hosts --config <file> [--format lines|json|egress-allow]\n'],
        ]) {
            err.length = 0;
            expect(await main([command], {})).toBe(2);
            expect(err.join('')).toBe(usage);
        }
    });
});
