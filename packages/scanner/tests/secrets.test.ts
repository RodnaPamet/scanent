/**
 * Secrets from files: `NAME_FILE` beside `NAME`, for the names the
 * configuration gives and no other.
 */
import { generateKeyPairSync } from 'crypto';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

import { verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import { main } from '../src/cli';
import { parseScannerConfig } from '../src/config';
import { rawPublicKeyHex } from '../src/report';
import { isSecretFilePath, MAX_SECRET_FILE_BYTES, readSecretFile, resolveSecretEnv, secretOrigin, SecretFileError } from '../src/secrets';

const REPO = resolve(__dirname, '..', '..', '..');
const config = parseScannerConfig({
    estate: 'acme',
    scanner: { agentId: 'agt', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
    outputs: [{ kind: 'stdout' }],
    schedule: { everyHours: 24 },
    sources: [{ kind: 'okta-app', orgUrl: 'https://acme.okta.com', apiTokenEnv: 'OKTA_API_TOKEN' }],
});

let dir: string;
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-secrets-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const file = (name: string, content: string | Buffer, mode = 0o600): string => {
    const path = join(dir, name);
    writeFileSync(path, content);
    chmodSync(path, mode);
    return path;
};
const reasonOf = (fn: () => unknown): string => {
    try {
        fn();
    } catch (err) {
        if (err instanceof SecretFileError) return err.reason;
        throw err;
    }
    return 'accepted';
};

describe('the four cases of one name', () => {
    it('the variable alone is its value, as before', () => {
        expect(resolveSecretEnv(config, { OKTA_API_TOKEN: 'direct-value' }).OKTA_API_TOKEN).toBe('direct-value');
        expect(secretOrigin('OKTA_API_TOKEN', { OKTA_API_TOKEN: 'direct-value' })).toEqual({ from: 'env' });
    });

    it('the _FILE alone is the file\'s content', () => {
        const path = file('okta', 'from-the-file\n');
        const env = { OKTA_API_TOKEN_FILE: path };
        expect(resolveSecretEnv(config, env).OKTA_API_TOKEN).toBe('from-the-file');
        expect(secretOrigin('OKTA_API_TOKEN', env)).toEqual({ from: 'file', path });
        // An empty variable beside its file counts as unset.
        expect(resolveSecretEnv(config, { OKTA_API_TOKEN: '  ', OKTA_API_TOKEN_FILE: path }).OKTA_API_TOKEN).toBe('from-the-file');
    });

    it('both set is refused, naming the variable and neither value', () => {
        const path = file('okta', 'from-the-file-zz\n');
        let thrown: unknown;
        try {
            resolveSecretEnv(config, { OKTA_API_TOKEN: 'direct-value-zz', OKTA_API_TOKEN_FILE: path });
        } catch (err) {
            thrown = err;
        }
        expect(thrown).toBeInstanceOf(SecretFileError);
        expect(thrown).toMatchObject({ reason: 'BOTH_SET', variable: 'OKTA_API_TOKEN' });
        expect((thrown as Error).message).not.toMatch(/zz/);
    });

    it('neither set stays absent', () => {
        const out = resolveSecretEnv(config, { UNRELATED: 'x' });
        expect(out.OKTA_API_TOKEN).toBeUndefined();
        expect(out.UNRELATED).toBe('x');
        expect(secretOrigin('OKTA_API_TOKEN', {})).toEqual({ from: 'absent' });
    });

    it('only the names the configuration gives are looked up', () => {
        // The file does not exist: reading it would throw.
        const out = resolveSecretEnv(config, { SOMETHING_ELSE_FILE: join(dir, 'absent'), OKTA_API_TOKEN: 'v' });
        expect(out.SOMETHING_ELSE).toBeUndefined();
        expect(out.SOMETHING_ELSE_FILE).toBe(join(dir, 'absent'));
    });
});

describe('reading one file', () => {
    it('removes exactly one trailing line break', () => {
        expect(readSecretFile('N', file('a', 'value\n'))).toBe('value');
        expect(readSecretFile('N', file('b', 'value\r\n'))).toBe('value');
        expect(readSecretFile('N', file('c', 'value\n\n'))).toBe('value\n');
        expect(readSecretFile('N', file('d', 'value'))).toBe('value');
        expect(readSecretFile('N', file('e', 'line one\nline two\n'))).toBe('line one\nline two');
    });

    it('accepts a world-readable file and a link to a regular file', () => {
        expect(readSecretFile('N', file('docker', 'v\n', 0o444))).toBe('v');
        expect(readSecretFile('N', file('kube', 'v\n', 0o644))).toBe('v');
        const target = file('target', 'linked\n');
        symlinkSync(target, join(dir, 'link'));
        expect(readSecretFile('N', join(dir, 'link'))).toBe('linked');
    });

    it('refuses each thing a secret file must not be, by code', () => {
        mkdirSync(join(dir, 'directory'));
        expect(reasonOf(() => readSecretFile('N', 'relative/path'))).toBe('FILE_PATH');
        expect(reasonOf(() => readSecretFile('N', `${dir}/../etc/passwd`))).toBe('FILE_PATH');
        expect(reasonOf(() => readSecretFile('N', `${dir}/a\nb`))).toBe('FILE_PATH');
        expect(reasonOf(() => readSecretFile('N', join(dir, 'directory')))).toBe('NOT_A_FILE');
        expect(reasonOf(() => readSecretFile('N', file('big', Buffer.alloc(MAX_SECRET_FILE_BYTES + 1, 0x61))))).toBe('TOO_LARGE');
        expect(reasonOf(() => readSecretFile('N', file('edge', Buffer.alloc(MAX_SECRET_FILE_BYTES, 0x61))))).toBe('accepted');
        expect(reasonOf(() => readSecretFile('N', file('open', 'v\n', 0o666)))).toBe('WORLD_WRITABLE');
        expect(reasonOf(() => readSecretFile('N', file('empty', '')))).toBe('EMPTY');
        expect(reasonOf(() => readSecretFile('N', file('blank', '\n')))).toBe('EMPTY');
        expect(reasonOf(() => readSecretFile('N', file('nul', Buffer.from([0x61, 0x00, 0x62]))))).toBe('NOT_TEXT');
        expect(reasonOf(() => readSecretFile('N', file('latin', Buffer.from([0xff, 0xfe, 0x61]))))).toBe('NOT_TEXT');
        expect(reasonOf(() => readSecretFile('N', join(dir, 'absent')))).toBe('UNREADABLE');
        expect(isSecretFilePath('/run/secrets/key')).toBe(true);
    });

    it('a read failure carries the errno code, and a file that grows after its stat is still capped', () => {
        expect(() => readSecretFile('N', join(dir, 'absent'))).toThrow(/N: the secret file could not be read \(ENOENT\)/);
        const grows = { statSync: () => ({ isFile: () => true, size: 10, mode: 0o600 }), readFileSync: () => Buffer.alloc(MAX_SECRET_FILE_BYTES + 1, 0x61) };
        expect(reasonOf(() => readSecretFile('N', '/x', grows))).toBe('TOO_LARGE');
        const odd = {
            statSync: () => {
                throw new Error('no code');
            },
            readFileSync: () => Buffer.alloc(0),
        };
        expect(() => readSecretFile('N', '/x', odd)).toThrow(/^N: the secret file could not be read$/);
    });

    it('no refusal\'s message holds a byte of the file', () => {
        const marker = 'marker-secret-file-content-p3';
        const cases = [file('ww', `${marker}\n`, 0o666), file('nul2', Buffer.concat([Buffer.from(marker), Buffer.from([0])]))];
        for (const path of cases) {
            try {
                readSecretFile('N', path);
                throw new Error('accepted');
            } catch (err) {
                expect(err).toBeInstanceOf(SecretFileError);
                expect((err as Error).message).not.toContain(marker);
            }
        }
    });
});

describe('through the command line', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    let out: string[];
    let configFile: string;

    beforeEach(() => {
        out = [];
        jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
        jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
        configFile = join(dir, 'config.json');
        writeFileSync(configFile, readFileSync(join(REPO, 'examples', 'code-only', 'config.local.template.json'), 'utf8').replace(/__REPO__/g, REPO));
    });
    afterEach(() => jest.restoreAllMocks());

    it('scan --dry-run signs with a key given only as a file, and the report verifies', async () => {
        const keyFile = file('signing-key.pem', pem, 0o444);
        expect(await main(['scan', '--config', configFile, '--dry-run'], { SCANNER_SIGNING_KEY_FILE: keyFile })).toBe(0);
        expect(verifyAndParseHarnessReport(out.join('').trim(), [rawPublicKeyHex(publicKey)])).toMatchObject({ ok: true });
    });

    it('public-key reads the key from its file', async () => {
        expect(await main(['public-key', '--config', configFile], { SCANNER_SIGNING_KEY_FILE: file('k.pem', pem) })).toBe(0);
        expect(out.join('')).toBe(`${rawPublicKeyHex(publicKey)}\n`);
    });

    it('a refused secret file stops the command with a SecretFileError', async () => {
        await expect(main(['scan', '--config', configFile, '--dry-run'], { SCANNER_SIGNING_KEY: pem, SCANNER_SIGNING_KEY_FILE: file('k2.pem', pem) })).rejects.toMatchObject({
            name: 'SecretFileError',
            reason: 'BOTH_SET',
        });
        expect(out).toEqual([]);
    });
});
