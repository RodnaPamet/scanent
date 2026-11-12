/**
 * `scanent keygen`: a signing key in a new file, its public half printed, the
 * private half never.
 */
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { main } from '../src/cli';
import { generateSigningKey, KeygenError } from '../src/keygen';
import { rawPublicKeyHex } from '../src/report';
import { loadSigningKey } from '../src/scan';

let dir: string;
let out: string[];
let err: string[];
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-keygen-'));
    out = [];
    err = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
});
afterEach(() => {
    jest.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
});

describe('generateSigningKey', () => {
    it('writes an Ed25519 key the scanner loads, mode 0600, and returns its public half', () => {
        const path = join(dir, 'key.pem');
        const { publicKeyHex } = generateSigningKey(path);
        expect(statSync(path).mode & 0o777).toBe(0o600);
        const loaded = loadSigningKey(readFileSync(path, 'utf8'));
        expect(loaded.privateKey.asymmetricKeyType).toBe('ed25519');
        expect(rawPublicKeyHex(loaded.publicKey)).toBe(publicKeyHex);
        expect(publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    });

    it('never replaces a file, and says which way it failed', () => {
        const path = join(dir, 'key.pem');
        writeFileSync(path, 'something else');
        expect(() => generateSigningKey(path)).toThrow(KeygenError);
        expect(readFileSync(path, 'utf8')).toBe('something else');
        try {
            generateSigningKey(join(dir, 'no-such-directory', 'key.pem'));
            throw new Error('written');
        } catch (e) {
            expect(e).toMatchObject({ reason: 'NOT_WRITTEN', code: 'ENOENT' });
        }
    });
});

describe('the command', () => {
    it('prints the public key on stdout, the path on stderr, and the private key nowhere', async () => {
        expect(await main(['keygen', '--out', 'signing.pem'], {}, { cwd: dir })).toBe(0);
        const pem = readFileSync(join(dir, 'signing.pem'), 'utf8');
        expect(out.join('')).toBe(`${rawPublicKeyHex(loadSigningKey(pem).publicKey)}\n`);
        expect(err.join('')).toContain(join(dir, 'signing.pem'));
        const body = pem.split('\n')[1];
        expect(out.join('') + err.join('')).not.toContain(body);
        expect(out.join('') + err.join('')).not.toContain('PRIVATE KEY');
        // What public-key prints for the same key.
        const config = join(dir, 'c.json');
        writeFileSync(config, JSON.stringify({ estate: 'a', scanner: { agentId: 'a', signingKeyEnv: 'K' }, outputs: [{ kind: 'stdout' }], schedule: { everyHours: 1 }, sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'r', path: dir }] }] }));
        const first = out.join('');
        out.length = 0;
        expect(await main(['public-key', '--config', config], { K_FILE: join(dir, 'signing.pem') })).toBe(0);
        expect(out.join('')).toBe(first);
    });

    it('refuses an existing file with exit 2 and leaves it alone', async () => {
        writeFileSync(join(dir, 'k.pem'), 'kept');
        expect(await main(['keygen', '--out', join(dir, 'k.pem')], {})).toBe(2);
        expect(readFileSync(join(dir, 'k.pem'), 'utf8')).toBe('kept');
        expect(out).toEqual([]);
    });

    it.each([[['keygen']], [['keygen', '--out']], [['keygen', '--out', 'a', '--force']], [['keygen', '--out', '../a']]])('%j is a usage error', async (argv) => {
        expect(await main(argv, {}, { cwd: dir })).toBe(2);
        expect(err.join('')).toBe('usage: scanent keygen --out <file>\n');
    });

    it('a directory that does not exist is a failure, not a usage error', async () => {
        expect(await main(['keygen', '--out', join(dir, 'missing', 'k.pem')], {})).toBe(1);
    });
});
