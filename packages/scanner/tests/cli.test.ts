/**
 * The command line: what each command does, and what it refuses.
 *
 *   1. A call without a command or a configuration is a usage error (2), and
 *      so is a command the scanner does not have.
 *   2. `public-key` prints the key to register, and nothing else.
 *   3. `scan --dry-run` over the code-only example reads files, signs, prints
 *      the report and posts nothing; `scan` posts it and exits by the answer.
 *   4. `schedule` hands the estate's cadence to the loop.
 *   5. `run` is the process: it installs the signal handlers, and its exit code
 *      is `main`'s, or 1 with one log line when `main` throws.
 *
 * No test reaches the network: the only source is `code`, and the global
 * `fetch` is replaced wherever a post is expected.
 */
import { generateKeyPairSync } from 'crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

import { HARNESS_CONTRACT_V3, verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import { main, run, USAGE_HINT } from '../src/cli';
import { ConfigError } from '../src/config';
import { rawPublicKeyHex } from '../src/report';
import * as schedule from '../src/schedule';

const REPO = resolve(__dirname, '..', '..', '..');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const PUBLIC_HEX = rawPublicKeyHex(publicKey);
const ENV = { SCANNER_SIGNING_KEY: PEM, INFLECT_INGEST_KEY: 'ingest-key-for-tests' };

let dir: string;
let configFile: string;
let out: string[];
let err: string[];

beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-cli-'));
    configFile = join(dir, 'config.json');
    const template = readFileSync(join(REPO, 'examples', 'code-only', 'config.template.json'), 'utf8');
    writeFileSync(configFile, template.replace('__REPO__', REPO));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

beforeEach(() => {
    out = [];
    err = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
});
afterEach(() => jest.restoreAllMocks());

/** A `fetch` that fails the test if anything calls it. */
function noNetwork(): jest.SpyInstance {
    return jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no test reaches the network'));
}

describe('1. usage', () => {
    it.each([
        ['no arguments', []],
        ['a command without --config', ['scan']],
        ['--config without its value', ['scan', '--config']],
        ['--config without a command', []],
    ])('%s is a usage error and reads nothing', async (_label, argv) => {
        expect(await main(argv, ENV)).toBe(2);
        // The first line is the one scripts have always matched; the second (Phase 3 review) says where every command is listed.
        expect(err.join('')).toBe(`usage: scanent <scan|schedule|public-key> --config <file> [--dry-run]\n${USAGE_HINT}`);
        expect(USAGE_HINT).toBe("run 'scanent help' for every command: init, keygen, doctor, hosts, scan, schedule, public-key, diff\n");
        expect(out).toEqual([]);
    });

    it('a command the scanner does not have is named and refused', async () => {
        const fetched = noNetwork();
        expect(await main(['publish', '--config', configFile], ENV)).toBe(2);
        expect(err.join('')).toBe('unknown command: publish\n');
        expect(out).toEqual([]);
        expect(fetched).not.toHaveBeenCalled();
    });

    it('a configuration that is missing or malformed stops the command', async () => {
        await expect(main(['scan', '--config', join(dir, 'absent.json')], ENV)).rejects.toThrow(/ENOENT/);
        const bad = join(dir, 'bad.json');
        writeFileSync(bad, '{ "estate": ');
        // A ConfigError that repeats none of the file (Phase 3 review): Node's SyntaxError quotes the bytes around the error.
        await expect(main(['scan', '--config', bad], ENV)).rejects.toThrow(new ConfigError(['(root): the file is not JSON']));
        const unknownField = join(dir, 'extra.json');
        writeFileSync(unknownField, JSON.stringify({ ...JSON.parse(readFileSync(configFile, 'utf8')), apiKey: 'x' }));
        await expect(main(['scan', '--config', unknownField], ENV)).rejects.toThrow();
    });
});

describe('2. public-key', () => {
    it('prints the raw public key of the configured signing key', async () => {
        expect(await main(['public-key', '--config', configFile], ENV)).toBe(0);
        expect(out.join('')).toBe(`${PUBLIC_HEX}\n`);
        expect(PUBLIC_HEX).toMatch(/^[0-9a-f]{64}$/);
    });

    it('names the missing variable, and never a key', async () => {
        await expect(main(['public-key', '--config', configFile], {})).rejects.toThrow('environment variable SCANNER_SIGNING_KEY is not set');
        expect(out).toEqual([]);
    });

    it('refuses a signing key that is not Ed25519', async () => {
        const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
        await expect(main(['public-key', '--config', configFile], { SCANNER_SIGNING_KEY: rsa })).rejects.toThrow('the signing key must be Ed25519');
    });
});

describe('3. scan', () => {
    it('--dry-run prints a signed report of the example estate and posts nothing', async () => {
        const fetched = noNetwork();
        expect(await main(['scan', '--config', configFile, '--dry-run'], ENV)).toBe(0);
        expect(fetched).not.toHaveBeenCalled();

        expect(out).toHaveLength(1);
        const raw = out[0].replace(/\n$/, '');
        const verified = verifyAndParseHarnessReport(raw, [PUBLIC_HEX]);
        expect(verified).toMatchObject({ ok: true, complete: true });
        const report = JSON.parse(raw) as { contract: string; body?: unknown };
        expect(JSON.stringify(report)).toContain(HARNESS_CONTRACT_V3);
        expect(raw).toContain('code:example/support/agent.py#');
        // The root's path names a checkout; only its label is reported.
        expect(raw).not.toContain(REPO);
        // The log goes to stderr as JSON lines, and the key is in neither stream.
        const lines = err.join('').trim().split('\n').map((l) => JSON.parse(l) as { msg: string; level: string });
        expect(lines.map((l) => l.msg)).toEqual(['source read', 'report signed']);
        expect(out.join('') + err.join('')).not.toContain(ENV.INFLECT_INGEST_KEY);
    });

    it('--dry-run needs the signing key and says which variable', async () => {
        await expect(main(['scan', '--config', configFile, '--dry-run'], {})).rejects.toThrow(
            'the signing key is not set (environment variable SCANNER_SIGNING_KEY)',
        );
    });

    it('posts the report to the tenant\'s ingest and exits 0 on a 201', async () => {
        const fetched = jest
            .spyOn(globalThis, 'fetch')
            .mockResolvedValue(new Response(JSON.stringify({ complete: true, agentCount: 1 }), { status: 201 }));
        expect(await main(['scan', '--config', configFile], ENV)).toBe(0);
        expect(fetched).toHaveBeenCalledTimes(1);
        const [url, init] = fetched.mock.calls[0] as [string, RequestInit];
        expect(url).toBe('https://inflect.example.com/api/t/example/admin/agents/harness-scans');
        expect(init).toMatchObject({ method: 'POST', redirect: 'error' });
        expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${ENV.INFLECT_INGEST_KEY}`);
        expect(verifyAndParseHarnessReport(String(init.body), [PUBLIC_HEX])).toMatchObject({ ok: true });
        // Nothing is printed: the report went to the ingest.
        expect(out).toEqual([]);
        expect(err.join('')).toContain('"msg":"report ingested"');
    });

    it('exits 1 when the ingest refuses the report, and logs the refusal code', async () => {
        jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"error":"harness_report_refused: SIGNATURE"}', { status: 400 }));
        expect(await main(['scan', '--config', configFile], ENV)).toBe(1);
        const refused = err.join('').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>).find((l) => l.msg === 'report refused');
        expect(refused).toMatchObject({ level: 'error', status: 400, refusal: 'SIGNATURE' });
    });

    it('does not scan at all without the ingest key', async () => {
        const fetched = noNetwork();
        await expect(main(['scan', '--config', configFile], { SCANNER_SIGNING_KEY: PEM, INFLECT_INGEST_KEY: '  ' })).rejects.toThrow(
            'the ingest API key is not set (environment variable INFLECT_INGEST_KEY)',
        );
        expect(fetched).not.toHaveBeenCalled();
        expect(err).toEqual([]);
    });
});

describe('4. schedule', () => {
    it('runs on the estate\'s cadence, and each run scans and posts', async () => {
        const fetched = jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 201 }));
        const loop = jest.spyOn(schedule, 'runOnSchedule').mockImplementation(async (opts) => {
            await opts.run();
            await opts.run();
            return 2;
        });
        expect(await main(['schedule', '--config', configFile], ENV)).toBe(0);
        expect(loop).toHaveBeenCalledTimes(1);
        expect(loop.mock.calls[0][0].everyHours).toBe(24);
        expect(fetched).toHaveBeenCalledTimes(2);
    });

    it('a refused post does not fail the run: the loop carries on', async () => {
        jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 503 }));
        let threw = false;
        jest.spyOn(schedule, 'runOnSchedule').mockImplementation(async (opts) => {
            await opts.run().catch(() => {
                threw = true;
            });
            return 1;
        });
        expect(await main(['schedule', '--config', configFile], ENV)).toBe(0);
        expect(threw).toBe(false);
    });
});

describe('5. run, the process', () => {
    const savedArgv = process.argv;
    const savedEnv = { key: process.env.SCANNER_SIGNING_KEY };
    afterEach(() => {
        process.argv = savedArgv;
        if (savedEnv.key === undefined) delete process.env.SCANNER_SIGNING_KEY;
        else process.env.SCANNER_SIGNING_KEY = savedEnv.key;
    });

    /** Start `run` with the process's edges replaced; resolves with the first exit code. */
    function start(argv: string[]) {
        const handlers = new Map<string, () => void>();
        const once = jest.spyOn(process, 'once').mockImplementation(((event: string, handler: () => void) => {
            handlers.set(event, handler);
            return process;
        }) as typeof process.once);
        const codes: number[] = [];
        const exited = new Promise<number>((done) => {
            jest.spyOn(process, 'exit').mockImplementation(((code?: number) => {
                codes.push(code ?? 0);
                done(code ?? 0);
            }) as typeof process.exit);
        });
        process.argv = ['node', 'cli.js', ...argv];
        run();
        return { handlers, once, codes, exited };
    }

    it('exits with main\'s code', async () => {
        const { exited } = start([]);
        expect(await exited).toBe(2);
        expect(err.join('')).toContain('usage: scanent');
    });

    it('reads its arguments and environment from the process', async () => {
        process.env.SCANNER_SIGNING_KEY = PEM;
        const { exited } = start(['public-key', '--config', configFile]);
        expect(await exited).toBe(0);
        expect(out.join('')).toBe(`${PUBLIC_HEX}\n`);
    });

    it('exits 1 with one log line when the command throws, and the line carries the message only', async () => {
        delete process.env.SCANNER_SIGNING_KEY;
        const { exited } = start(['public-key', '--config', configFile]);
        expect(await exited).toBe(1);
        const line = JSON.parse(err.join('').trim()) as Record<string, unknown>;
        expect(line).toMatchObject({ level: 'error', msg: 'scanner stopped', error: 'environment variable SCANNER_SIGNING_KEY is not set' });
    });

    it('a rejection that is not an Error is logged as unknown', async () => {
        jest.spyOn(schedule, 'runOnSchedule').mockRejectedValue('a string, not an Error');
        process.env.SCANNER_SIGNING_KEY = PEM;
        const { exited } = start(['schedule', '--config', configFile]);
        expect(await exited).toBe(1);
        expect(JSON.parse(err.join('').trim())).toMatchObject({ msg: 'scanner stopped', error: 'unknown' });
    });

    it('stops at once on SIGTERM and SIGINT, with the conventional codes', async () => {
        const { handlers, once, codes, exited } = start([]);
        expect(once.mock.calls.map(([signal]) => signal)).toEqual(['SIGTERM', 'SIGINT']);
        await exited;
        codes.length = 0;
        handlers.get('SIGTERM')!();
        handlers.get('SIGINT')!();
        expect(codes).toEqual([143, 130]);
    });
});
