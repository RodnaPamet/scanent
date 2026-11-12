/**
 * The wizard's writer and its command: what lands on disk, with which modes,
 * and what is never replaced.
 */
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { main } from '../src/cli';
import { credentialEnvNames, parseScannerConfig } from '../src/config';
import { planInit } from '../src/init/plan';
import { InitRefused, writeInit } from '../src/init/write';
import { rawPublicKeyHex } from '../src/report';
import { loadSigningKey } from '../src/scan';

const ANSWERS = {
    answers: 'scanent-init-answers/1' as const,
    estate: 'acme',
    sources: [
        { kind: 'code' as const, roots: [{ label: 'app', path: '/estate/app' }] },
        { kind: 'okta-app' as const, orgUrl: 'https://acme.okta.com' },
    ],
};

let dir: string;
let out: string[];
let err: string[];
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-init-'));
    out = [];
    err = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
});
afterEach(() => {
    jest.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
});

const mode = (path: string) => statSync(path).mode & 0o777;
const refusal = (fn: () => unknown) => {
    try {
        fn();
    } catch (e) {
        if (e instanceof InitRefused) return e.reason;
        throw e;
    }
    return 'written';
};

describe('writeInit', () => {
    it('writes the configuration, the env template and a signing key, 0600 in a 0700 directory, whatever the umask', () => {
        const old = process.umask(0o000);
        try {
            const target = join(dir, 'scanent');
            const written = writeInit(planInit(ANSWERS), target);
            expect(readdirSync(target).sort()).toEqual(['config.json', 'scanent.env', 'signing-key.pem']);
            expect(mode(target)).toBe(0o700);
            for (const f of readdirSync(target)) expect([f, mode(join(target, f))]).toEqual([f, 0o600]);
            expect(written.files.map((f) => [f.path, f.mode])).toEqual([
                [join(target, 'config.json'), 0o600],
                [join(target, 'scanent.env'), 0o600],
                [join(target, 'signing-key.pem'), 0o600],
            ]);
            // The configuration is one scan accepts; the key is one it signs with.
            const config = parseScannerConfig(JSON.parse(readFileSync(join(target, 'config.json'), 'utf8')));
            expect(credentialEnvNames(config)).toEqual(['SCANNER_SIGNING_KEY', 'OKTA_API_TOKEN']);
            const key = loadSigningKey(readFileSync(join(target, 'signing-key.pem'), 'utf8'));
            expect(written.signingKey).toEqual({ path: join(target, 'signing-key.pem'), created: true, publicKeyHex: rawPublicKeyHex(key.publicKey) });
            // The env file names the key by its path, and holds no other value.
            expect(readFileSync(join(target, 'scanent.env'), 'utf8').split('\n').filter((l) => l !== '' && !l.startsWith('#'))).toEqual([
                `SCANNER_SIGNING_KEY_FILE=${join(target, 'signing-key.pem')}`,
                'OKTA_API_TOKEN=',
            ]);
        } finally {
            process.umask(old);
        }
    });

    it('refuses an existing file without --force, and writes nothing at all', () => {
        writeFileSync(join(dir, 'scanent.env'), 'OKTA_API_TOKEN=kept\n');
        expect(refusal(() => writeInit(planInit(ANSWERS), dir))).toBe('EXISTS');
        expect(readdirSync(dir)).toEqual(['scanent.env']);
        expect(readFileSync(join(dir, 'scanent.env'), 'utf8')).toBe('OKTA_API_TOKEN=kept\n');
    });

    it('--force replaces the two files, by rename, and leaves no temporary file', () => {
        writeFileSync(join(dir, 'config.json'), '{"old":true}');
        writeFileSync(join(dir, 'scanent.env'), 'OLD=1\n');
        writeInit(planInit(ANSWERS), dir, { force: true });
        expect(JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8'))).toMatchObject({ estate: 'acme' });
        expect(readFileSync(join(dir, 'scanent.env'), 'utf8')).toContain('OKTA_API_TOKEN=');
        expect(readdirSync(dir).sort()).toEqual(['config.json', 'scanent.env', 'signing-key.pem']);
        expect(mode(join(dir, 'config.json'))).toBe(0o600);
    });

    it('never replaces a signing key, with or without --force, and still names it in the env file', () => {
        const first = writeInit(planInit(ANSWERS), dir);
        const pem = readFileSync(join(dir, 'signing-key.pem'), 'utf8');
        const second = writeInit(planInit(ANSWERS), dir, { force: true });
        expect(readFileSync(join(dir, 'signing-key.pem'), 'utf8')).toBe(pem);
        expect(second.signingKey).toEqual({ path: join(dir, 'signing-key.pem'), created: false, publicKeyHex: first.signingKey?.publicKeyHex });
        expect(second.files.map((f) => f.path)).toEqual([join(dir, 'config.json'), join(dir, 'scanent.env')]);
        expect(readFileSync(join(dir, 'scanent.env'), 'utf8')).toContain(`SCANNER_SIGNING_KEY_FILE=${join(dir, 'signing-key.pem')}`);
    });

    it('keeps a file at the key\'s path that is not a key, and says it has no public half to show', () => {
        writeFileSync(join(dir, 'signing-key.pem'), 'not a key');
        expect(writeInit(planInit(ANSWERS), dir).signingKey).toEqual({ path: join(dir, 'signing-key.pem'), created: false, publicKeyHex: null });
        expect(readFileSync(join(dir, 'signing-key.pem'), 'utf8')).toBe('not a key');
    });

    it('--no-keygen creates no key and leaves its path empty in the template', () => {
        const written = writeInit(planInit(ANSWERS), dir, { keygen: false });
        expect(written.signingKey).toBeNull();
        expect(readdirSync(dir).sort()).toEqual(['config.json', 'scanent.env']);
        expect(readFileSync(join(dir, 'scanent.env'), 'utf8')).toMatch(/^SCANNER_SIGNING_KEY_FILE=$/m);
    });

    it('refuses a directory that is a link, or is not a directory', () => {
        mkdirSync(join(dir, 'real'));
        symlinkSync(join(dir, 'real'), join(dir, 'link'));
        writeFileSync(join(dir, 'file'), '');
        expect(refusal(() => writeInit(planInit(ANSWERS), join(dir, 'link')))).toBe('DIR_IS_LINK');
        expect(readdirSync(join(dir, 'real'))).toEqual([]);
        expect(refusal(() => writeInit(planInit(ANSWERS), join(dir, 'file')))).toBe('DIR_NOT_A_DIRECTORY');
        expect(refusal(() => writeInit(planInit(ANSWERS), join(dir, 'file', 'below')))).toBe('NOT_WRITTEN');
    });
});

describe('scanent init --answers', () => {
    const answersFile = () => {
        const path = join(dir, 'answers.json');
        writeFileSync(path, JSON.stringify(ANSWERS));
        return path;
    };

    it('writes the files, prints the public key, the access tables and the next steps, and no private key', async () => {
        const fetched = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('init makes no request'));
        const target = join(dir, 'scanent');
        expect(await main(['init', '--dir', target, '--answers', answersFile()], {})).toBe(0);
        expect(fetched).not.toHaveBeenCalled();
        expect(readdirSync(target).sort()).toEqual(['config.json', 'scanent.env', 'signing-key.pem']);
        const pem = readFileSync(join(target, 'signing-key.pem'), 'utf8');
        const printed = err.join('');
        expect(out).toEqual([]);
        expect(printed).toContain(`${join(target, 'config.json')}  (mode 0600)`);
        expect(printed).toContain(`Signing key, public half: ${rawPublicKeyHex(loadSigningKey(pem).publicKey)}`);
        expect(printed).toContain('Okta (service apps and API tokens)  [okta-app]');
        expect(printed).toContain('Agent code (local directories)  [code]');
        expect(printed).not.toContain('[entra-sp]');
        expect(printed).toContain(`2. scanent doctor --config ${join(target, 'config.json')}`);
        expect(printed).not.toContain(pem.split('\n')[1]);
        expect(printed).not.toContain('PRIVATE KEY');
    });

    it('the default directory is ./scanent under the working directory, and a relative --dir is taken from it', async () => {
        expect(await main(['init', '--answers', answersFile()], {}, { cwd: dir })).toBe(0);
        expect(readdirSync(join(dir, 'scanent')).sort()).toEqual(['config.json', 'scanent.env', 'signing-key.pem']);
        expect(await main(['init', '--dir', 'other', '--answers', 'answers.json', '--no-keygen'], {}, { cwd: dir })).toBe(0);
        expect(readdirSync(join(dir, 'other')).sort()).toEqual(['config.json', 'scanent.env']);
        expect(err.join('')).toContain('No signing key was created.');
    });

    it('a second run is refused with exit 2 and changes nothing; --force replaces and keeps the key', async () => {
        const target = join(dir, 'scanent');
        expect(await main(['init', '--dir', target, '--answers', answersFile()], {})).toBe(0);
        const before = Object.fromEntries(readdirSync(target).map((f) => [f, readFileSync(join(target, f), 'utf8')]));
        err.length = 0;
        expect(await main(['init', '--dir', target, '--answers', answersFile()], {})).toBe(2);
        expect(err.join('')).toBe(`${join(target, 'config.json')} already exists; pass --force to replace it\n`);
        expect(Object.fromEntries(readdirSync(target).map((f) => [f, readFileSync(join(target, f), 'utf8')]))).toEqual(before);
        expect(await main(['init', '--dir', target, '--answers', answersFile(), '--force'], {})).toBe(0);
        expect(readFileSync(join(target, 'signing-key.pem'), 'utf8')).toBe(before['signing-key.pem']);
        expect(err.join('')).toContain('Kept the existing signing key');
    });

    it('--print-access prints the tables on stdout and writes nothing', async () => {
        const target = join(dir, 'scanent');
        expect(await main(['init', '--dir', target, '--answers', answersFile(), '--print-access'], {})).toBe(0);
        expect(out.join('')).toContain('Grant:       An SSWS API token created by a user holding the Read-only Administrator role only');
        expect(out.join('')).toContain('Hosts:       acme.okta.com:443');
        expect(() => statSync(target)).toThrow(/ENOENT/);
    });

    it.each([
        ['is missing', null, /could not be read: ENOENT/],
        ['is not JSON', '{ nope', /could not be read: not JSON/],
        ['breaks the schema', JSON.stringify({ ...ANSWERS, extra: 1 }), /invalid init answers: \(root\): unrecognized_keys/],
        ['plans a configuration that is refused', JSON.stringify({ ...ANSWERS, estate: 'Not A Slug' }), /invalid init answers: estate: invalid_format/],
    ])('exits 4 and writes nothing when the answers file %s', async (_label, content, message) => {
        const path = join(dir, 'a.json');
        if (content !== null) writeFileSync(path, content);
        const target = join(dir, 'scanent');
        expect(await main(['init', '--dir', target, '--answers', path], {})).toBe(4);
        expect(err.join('')).toMatch(message);
        expect(() => statSync(target)).toThrow(/ENOENT/);
    });

    it('a secret-shaped string in the answers file exits 4 naming its path, and is not repeated', async () => {
        const pasted = ['gh', 'p_', 'C3'.repeat(12)].join('');
        const path = join(dir, 'a.json');
        writeFileSync(path, JSON.stringify({ ...ANSWERS, sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiToken: pasted }] }));
        expect(await main(['init', '--dir', join(dir, 'scanent'), '--answers', path], {})).toBe(4);
        expect(err.join('')).toMatch(/sources\[0\]\.apiToken: a credential value in the answers/);
        expect(out.join('') + err.join('')).not.toContain(pasted);
        expect(() => statSync(join(dir, 'scanent'))).toThrow(/ENOENT/);
    });

    it.each([
        [['init', '--bogus']],
        [['init', '--dir']],
        [['init', '--answers']],
        [['init', '--dir', '/tmp/../etc']],
        [['init', 'stray']],
    ])('%j is a usage error', async (argv) => {
        expect(await main(argv, {}, { cwd: dir, interactive: true })).toBe(2);
        expect(err.join('')).toContain('usage: scanent init');
        expect(readdirSync(dir)).toEqual([]);
    });

    it('without --answers and without a terminal, it says to pass --answers and exits 2', async () => {
        expect(await main(['init', '--dir', join(dir, 'scanent')], {}, { interactive: false })).toBe(2);
        expect(err.join('')).toContain('stdin is not one. Pass --answers <file> instead.');
        expect(readdirSync(dir)).toEqual([]);
    });
});
