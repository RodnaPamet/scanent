/**
 * What the command line refuses to repeat, and what it refuses to do on absent
 * evidence:
 *
 *   1. A configuration file that is not JSON stops every command with a fixed
 *      message. None of the file's bytes reaches a stream or an error.
 *   2. A secret-shaped KEY is a hit, and is not printed as part of the path.
 *   3. `doctor --source <kind>` for a kind the configuration lacks is a usage
 *      error, never "Ready" over zero checks.
 *   4. `init` says a directory is in the way before it asks anything, and holds
 *      what it keeps (a directory, a signing key) to what it writes.
 *   5. A missing signing key says how to supply one.
 *   6. The access guide names a file credential once, and Okta's limit.
 */
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { exitCodeForError, main } from '../src/cli';
import { ConfigError, firstSecretShaped, parseScannerConfig } from '../src/config';
import { ACCESS_GUIDE, credentialVariable, renderAccessMarkdown, renderAccessText, accessTablesFor } from '../src/init/access-guide';
import { parseInitAnswers } from '../src/init/answers';
import { planInit } from '../src/init/plan';
import type { PromptIo } from '../src/init/prompts';
import { checkInitTarget, InitRefused, writeInit } from '../src/init/write';
import { generateSigningKey } from '../src/keygen';

const CODE_ONLY = {
    answers: 'scanent-init-answers/1' as const,
    estate: 'acme',
    sources: [{ kind: 'code' as const, roots: [{ label: 'app', path: '/estate/app' }] }],
};
/** Built at run time: no credential-shaped literal is in this file. */
const GH = ['gh', 'p_', 'E5'.repeat(18)].join('');

let dir: string;
let out: string[];
let err: string[];
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-hardening-'));
    out = [];
    err = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
});
afterEach(() => {
    jest.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
});

const write = (name: string, text: string): string => {
    const path = join(dir, name);
    writeFileSync(path, text);
    return path;
};
const validConfig = (): string => write('config.json', planInit({ ...CODE_ONLY, outputDir: join(dir, 'out') }).configText);

describe('1. a configuration file that is not JSON', () => {
    // A value somebody forgot to quote, and an env file given as the configuration.
    const UNQUOTED = 'S3cr3tPassw0rdValue99';
    const FILES: [string, string, string[]][] = [
        ['a mistyped value', `{"estate": "acme", "scanner": {"agentId": "a", "signingKeyEnv": ${UNQUOTED}}}`, [UNQUOTED, 'S3cr3t', 'gKeyEnv']],
        ['a filled env file', `OKTA_API_TOKEN=${UNQUOTED}\n`, [UNQUOTED, 'OKTA_API_T', 'S3cr3t']],
    ];

    it.each(FILES)('%s: scan, schedule, hosts and public-key stop with exit 4 and repeat none of it', async (_label, text, bytes) => {
        const file = write('bad.json', text);
        for (const command of ['scan', 'schedule', 'hosts', 'public-key']) {
            let thrown: unknown;
            try {
                await main([command, '--config', file], {});
            } catch (e) {
                thrown = e;
            }
            expect(thrown).toEqual(new ConfigError(['(root): the file is not JSON']));
            expect(exitCodeForError(thrown)).toBe(4);
            // `run()` logs the error's message: that, and both streams, hold none of the file.
            const everything = (thrown as Error).message + String((thrown as Error).stack) + out.join('') + err.join('');
            for (const b of bytes) expect(everything).not.toContain(b);
        }
    });

    it('a file that cannot be read gives its errno code and not its path', async () => {
        const secretName = join(dir, 'named-after-a-thing.json');
        let thrown: unknown;
        try {
            await main(['hosts', '--config', secretName], {});
        } catch (e) {
            thrown = e;
        }
        expect(thrown).toEqual(new ConfigError(['(root): the file could not be read (ENOENT)']));
        expect((thrown as Error).message).not.toContain('named-after-a-thing');
        expect(exitCodeForError(thrown)).toBe(4);
    });

    it('doctor and init --answers already said so in fixed words, and still do', async () => {
        const file = write('bad.json', FILES[0][1]);
        expect(await main(['doctor', '--config', file], {})).toBe(4);
        expect(out.join('')).toContain('the file is not JSON');
        expect(await main(['init', '--dir', join(dir, 'x'), '--answers', file], {})).toBe(4);
        expect(err.join('')).toBe('the answers file could not be read: not JSON\n');
        expect(out.join('') + err.join('')).not.toContain(FILES[0][2][0]);
    });
});

describe('2. a secret-shaped key', () => {
    it('is a hit, and is written <key> in the path', () => {
        expect(firstSecretShaped({ inflect: { [GH]: 'x' } }, '')).toBe('inflect.<key>');
        expect(firstSecretShaped({ [GH]: { nested: 1 } }, '')).toBe('<key>');
        expect(firstSecretShaped({ a: [{ [GH]: 1 }] }, '')).toBe('a[0].<key>');
        // A value under an ordinary key is reported as before.
        expect(firstSecretShaped({ inflect: { apiKeyEnv: GH } }, '')).toBe('inflect.apiKeyEnv');
        expect(firstSecretShaped({ inflect: { apiKeyEnv: 'INFLECT_INGEST_KEY' } }, '')).toBeNull();
    });

    it('the configuration parser and init --answers refuse it without printing it', async () => {
        const config = { ...(JSON.parse(planInit(CODE_ONLY).configText) as Record<string, unknown>), [GH]: 'x' };
        let thrown: unknown;
        try {
            parseScannerConfig(config);
        } catch (e) {
            thrown = e;
        }
        expect(thrown).toEqual(new ConfigError(['<key>: a credential value in the configuration; name its environment variable instead']));
        expect((thrown as Error).message).not.toContain(GH);

        const answers = write('answers.json', JSON.stringify({ ...CODE_ONLY, inflect: { [GH]: GH } }));
        expect(await main(['init', '--dir', join(dir, 'x'), '--answers', answers], {})).toBe(4);
        expect(err.join('')).toBe('invalid init answers: inflect.<key>: a credential value in the answers; scanent never takes one. If it was real, rotate it\n');
        expect(() => parseInitAnswers({ ...CODE_ONLY, inflect: { [GH]: 'x' } })).toThrow('inflect.<key>');
    });
});

describe('3. doctor --source', () => {
    it('for a kind the configuration does not hold: exit 2 naming the kinds it has, and no report', async () => {
        const config = validConfig();
        expect(await main(['doctor', '--config', config, '--source', 'okta-app'], {})).toBe(2);
        expect(err.join('')).toBe('--source okta-app: the configuration has no such source, so nothing would be checked.\n  it has: code\n');
        // No report at all: in particular, not one that says Ready.
        expect(out).toEqual([]);

        err.length = 0;
        expect(await main(['doctor', '--config', config, '--json', '--source', 'code', '--source', 'mcp', '--source', 'mcp'], {})).toBe(2);
        expect(err.join('')).toContain('--source mcp: the configuration has no such source');
        expect(out).toEqual([]);
    });

    it('for a kind it does hold: the source is checked, as before', async () => {
        const config = validConfig();
        const code = await main(['doctor', '--config', config, '--json', '--source', 'code'], {});
        const report = JSON.parse(out.join('')) as { checks: { scope: string }[]; ready: boolean };
        expect(report.checks.some((c) => c.scope === 'code')).toBe(true);
        expect(code).not.toBe(2);
    });

    it('with a configuration that cannot be read, doctor reports that itself', async () => {
        const bad = write('bad.json', '{');
        expect(await main(['doctor', '--config', bad, '--source', 'okta-app'], {})).toBe(4);
        expect(out.join('')).toContain('the file is not JSON');
    });
});

describe('4. init and what is already there', () => {
    const never: PromptIo = {
        ask: async (q) => {
            throw new Error(`asked although the directory was in the way: ${q}`);
        },
        say: () => undefined,
    };
    const answersFile = () => write('answers.json', JSON.stringify(CODE_ONLY));
    const mode = (p: string) => statSync(p).mode & 0o777;

    it('an existing config.json is said before the first question, and before the answers file is read', async () => {
        const target = join(dir, 'scanent');
        writeInit(planInit(CODE_ONLY), target);
        const before = readFileSync(join(target, 'config.json'), 'utf8');
        expect(await main(['init', '--dir', target], {}, { prompt: never })).toBe(2);
        expect(err.join('')).toBe(`${join(target, 'config.json')} already exists; pass --force to replace it\n`);
        err.length = 0;
        // An answers file that does not exist is never opened: the directory is refused first.
        expect(await main(['init', '--dir', target, '--answers', join(dir, 'absent.json')], {})).toBe(2);
        expect(err.join('')).toContain('already exists');
        expect(readFileSync(join(target, 'config.json'), 'utf8')).toBe(before);
    });

    it('--print-access writes nothing, so an existing directory does not stop it', async () => {
        const target = join(dir, 'scanent');
        writeInit(planInit(CODE_ONLY), target);
        expect(await main(['init', '--dir', target, '--answers', answersFile(), '--print-access'], {})).toBe(0);
    });

    it('a directory every user can write to is refused, and nothing is written into it', async () => {
        const target = join(dir, 'open');
        mkdirSync(target);
        chmodSync(target, 0o777);
        expect(() => checkInitTarget(target)).toThrow(InitRefused);
        expect(await main(['init', '--dir', target, '--answers', answersFile()], {})).toBe(2);
        expect(err.join('')).toBe(`${target} is writable by every user, so any of them could replace the signing key; run: chmod 700 ${target}\n`);
        expect(readdirSync(target)).toEqual([]);
    });

    it('a directory its group can write to is used, with a warning that says what to run', async () => {
        const target = join(dir, 'group');
        mkdirSync(target);
        chmodSync(target, 0o770);
        expect(await main(['init', '--dir', target, '--answers', answersFile()], {})).toBe(0);
        expect(err.join('')).toContain(`Warning: ${target} is writable by its group; init makes its own directory 0700. Run: chmod 700 ${target}\n`);
        expect(readdirSync(target).sort()).toEqual(['config.json', 'scanent.env', 'signing-key.pem']);
    });

    it.each([
        ['writable by every user', 0o666, 'writable by other users'],
        ['writable by its group', 0o660, 'writable by other users'],
    ])('an existing signing key %s is refused, not kept and named in the env file', async (_label, bits, why) => {
        const target = join(dir, 'kept');
        mkdirSync(target, { mode: 0o700 });
        const key = join(target, 'signing-key.pem');
        generateSigningKey(key);
        chmodSync(key, bits);
        expect(await main(['init', '--dir', target, '--answers', answersFile()], {})).toBe(2);
        expect(err.join('')).toBe(
            `${key} is an existing signing key that is ${why}; it was not used. Make it a regular file only its owner can write (chmod 600), or move it away\n`,
        );
        expect(readdirSync(target)).toEqual(['signing-key.pem']);
        expect(mode(key)).toBe(bits);
    });

    it('an existing signing key that is a link, or not a file, is refused', () => {
        const target = join(dir, 'linked');
        mkdirSync(target, { mode: 0o700 });
        const real = join(dir, 'elsewhere.pem');
        generateSigningKey(real);
        symlinkSync(real, join(target, 'signing-key.pem'));
        expect(() => writeInit(planInit(CODE_ONLY), target)).toThrow(new InitRefused('KEY_UNSAFE', join(target, 'signing-key.pem'), 'a symbolic link'));
        expect(readdirSync(target)).toEqual(['signing-key.pem']);

        const other = join(dir, 'notfile');
        mkdirSync(join(other, 'signing-key.pem'), { recursive: true });
        chmodSync(other, 0o700);
        expect(() => writeInit(planInit(CODE_ONLY), other)).toThrow(new InitRefused('KEY_UNSAFE', join(other, 'signing-key.pem'), 'not a regular file'));
    });

    it('an existing signing key others can read is kept, with a warning; one only its owner can read is kept silently', async () => {
        const target = join(dir, 'readable');
        mkdirSync(target, { mode: 0o700 });
        const key = join(target, 'signing-key.pem');
        const { publicKeyHex } = generateSigningKey(key);
        chmodSync(key, 0o644);
        const written = writeInit(planInit(CODE_ONLY), target);
        expect(written.signingKey).toEqual({ path: key, created: false, publicKeyHex });
        expect(written.warnings).toEqual([`${key} can be read by other users; init writes a key 0600. Run: chmod 600 ${key}`]);

        chmodSync(key, 0o600);
        expect(writeInit(planInit(CODE_ONLY), target, { force: true }).warnings).toEqual([]);
        // A directory that does not exist yet has nothing to warn about.
        expect(checkInitTarget(join(dir, 'new'))).toEqual([]);
    });

    it("init's next steps run scan without --out: the configuration it wrote already has the file output", async () => {
        const target = join(dir, 'next');
        expect(await main(['init', '--dir', target, '--answers', write('a.json', JSON.stringify({ ...CODE_ONLY, outputDir: '/var/lib/scanent' }))], {})).toBe(0);
        expect(err.join('')).toContain(`  3. scanent scan --config ${target}/config.json\n`);
        expect(err.join('')).not.toContain('--out');
        expect((JSON.parse(readFileSync(join(target, 'config.json'), 'utf8')) as { outputs: unknown }).outputs).toEqual([{ kind: 'file', dir: '/var/lib/scanent' }]);
    });
});

describe('5. a missing signing key', () => {
    it('scan says which variable, its _FILE form, that init wrote one, and keygen', async () => {
        const config = validConfig();
        await expect(main(['scan', '--config', config], {})).rejects.toThrow(
            'the signing key is not set (environment variable SCANNER_SIGNING_KEY): set SCANNER_SIGNING_KEY or SCANNER_SIGNING_KEY_FILE ' +
                '(init writes the _FILE form in scanent.env; load that file), or make a key with scanent keygen',
        );
    });
});

describe('6. the access guide', () => {
    it('names a credential that is a file once, with its _FILE form beside it, never _FILE_FILE', () => {
        expect(ACCESS_GUIDE['gcp-sa'].credential).toBe('GCP_SCANNER_KEY');
        expect(credentialVariable(ACCESS_GUIDE['gcp-sa'])).toBe('GCP_SCANNER_KEY_FILE');
        expect(credentialVariable(ACCESS_GUIDE['okta-app'])).toBe('OKTA_API_TOKEN');
        const markdown = renderAccessMarkdown();
        expect(markdown).toContain('| `GCP_SCANNER_KEY` (a key file: set GCP_SCANNER_KEY_FILE to its path) |');
        expect(markdown).not.toContain('`GCP_SCANNER_KEY_FILE`');
        // Every other name in the table can take the header's `_FILE` suffix and still be a name the scanner reads.
        for (const entry of Object.values(ACCESS_GUIDE)) expect(entry.credential.endsWith('_FILE')).toBe(false);
        const plan = planInit({ ...CODE_ONLY, sources: [{ kind: 'gcp-sa', projects: ['acme-prod-204'] }] });
        expect(plan.envTemplate).toContain('\nGCP_SCANNER_KEY_FILE=\n');
        expect(renderAccessText(accessTablesFor(plan.config)[0])).toContain('    Credential:  GCP_SCANNER_KEY (a key file: set GCP_SCANNER_KEY_FILE to its path)\n');
    });

    it("says what Okta's read-only role does not show, in the document and at the terminal", () => {
        const limits = ACCESS_GUIDE['okta-app'].limits ?? [];
        expect(limits.join(' ')).toMatch(/API tokens of its own user only/);
        expect(limits.join(' ')).toMatch(/not been confirmed against a live org/);
        expect(renderAccessMarkdown()).toContain('**What this grant does not show.**');
        const plan = planInit({ ...CODE_ONLY, sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com' }] });
        expect(renderAccessText(accessTablesFor(plan.config)[0])).toContain('    Limits:\n      - Okta\'s role table');
        // A source with no stated limit prints no empty heading.
        expect(renderAccessText(accessTablesFor(planInit(CODE_ONLY).config)[0])).not.toContain('Limits:');
    });
});
