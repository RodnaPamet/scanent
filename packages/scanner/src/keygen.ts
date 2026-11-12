/**
 * `scanent keygen` — the Ed25519 signing key, made here so a first run needs no
 * second tool.
 *
 * The private key is written to a NEW file (exclusive create, mode 0600) and
 * goes nowhere else: it is never printed, never logged and never returned.
 * What comes back is the raw public key in hex, the value `public-key`
 * prints. An existing file is refused, and there is no overwrite: replacing a
 * signing key silently would orphan every earlier report's signature.
 */
import { generateKeyPairSync } from 'crypto';
import { chmodSync, closeSync, constants, openSync, writeSync } from 'fs';

import { rawPublicKeyHex } from './report';

export const SIGNING_KEY_MODE = 0o600;

export class KeygenError extends Error {
    constructor(
        readonly reason: 'EXISTS' | 'NOT_WRITTEN',
        readonly code?: string,
    ) {
        super(reason === 'EXISTS' ? 'the signing key file already exists; it was not replaced' : `the signing key could not be written${code ? ` (${code})` : ''}`);
        this.name = 'KeygenError';
    }
}

/** Create a signing key at `path`, which must not exist. Returns the raw public key in hex. */
export function generateSigningKey(path: string): { readonly publicKeyHex: string } {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    let fd: number;
    try {
        fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, SIGNING_KEY_MODE);
    } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        throw new KeygenError(code === 'EEXIST' ? 'EXISTS' : 'NOT_WRITTEN', typeof code === 'string' ? code : undefined);
    }
    try {
        writeSync(fd, pem);
    } finally {
        closeSync(fd);
    }
    // The mode whatever the umask was.
    chmodSync(path, SIGNING_KEY_MODE);
    return { publicKeyHex: rawPublicKeyHex(publicKey) };
}
