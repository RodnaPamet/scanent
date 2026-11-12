/**
 * THE WIZARD'S WRITER — `config.json`, `scanent.env` and, unless told not to,
 * a signing key, in one directory.
 *
 *   • Nothing is replaced without `--force`, and the check for both files
 *     happens before either is written: a refused run writes nothing.
 *   • A signing key is NEVER replaced, with or without `--force`. Replacing it
 *     silently would orphan every earlier report's signature.
 *   • Files are 0600 and the directory 0700 whatever the umask. With `--force`
 *     a file is written beside the old one and renamed over it, so a reader
 *     never sees half a file.
 *   • A directory that is a symbolic link is refused: the files would land
 *     wherever the link points.
 */
import { chmodSync, closeSync, constants, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'fs';
import { randomBytes } from 'crypto';
import { join } from 'path';

import { generateSigningKey } from '../keygen';
import { rawPublicKeyHex } from '../report';
import { loadSigningKey } from '../scan';
import { renderEnvTemplate, type InitPlan } from './plan';

export const INIT_DIR_MODE = 0o700;
export const INIT_FILE_MODE = 0o600;
export const CONFIG_FILE = 'config.json';
export const ENV_FILE = 'scanent.env';
export const SIGNING_KEY_FILE = 'signing-key.pem';

/** `init` would not write: the reason, and the file or directory it is about. */
export class InitRefused extends Error {
    constructor(
        readonly reason: 'EXISTS' | 'DIR_IS_LINK' | 'DIR_NOT_A_DIRECTORY' | 'NOT_WRITTEN',
        readonly path: string,
        readonly code?: string,
    ) {
        super(
            reason === 'EXISTS'
                ? `${path} already exists; pass --force to replace it`
                : reason === 'DIR_IS_LINK'
                    ? `${path} is a symbolic link; name the directory itself`
                    : reason === 'DIR_NOT_A_DIRECTORY'
                        ? `${path} is not a directory`
                        : `${path} could not be written${code ? ` (${code})` : ''}`,
        );
        this.name = 'InitRefused';
    }
}

export interface WrittenInit {
    readonly dir: string;
    readonly files: readonly { readonly path: string; readonly mode: number }[];
    /** The signing key in the directory: created by this run, found there and kept, or absent. */
    readonly signingKey: { readonly path: string; readonly created: boolean; readonly publicKeyHex: string | null } | null;
}

function exists(path: string): boolean {
    try {
        lstatSync(path);
        return true;
    } catch (err) {
        // ENOTDIR: a parent is a file, so nothing is there; creating it is what then fails, and says so.
        if (['ENOENT', 'ENOTDIR'].includes((err as NodeJS.ErrnoException).code ?? '')) return false;
        throw err;
    }
}

function writeNew(path: string, content: string): void {
    const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, INIT_FILE_MODE);
    try {
        writeSync(fd, content);
    } finally {
        closeSync(fd);
    }
    chmodSync(path, INIT_FILE_MODE);
}

function write(path: string, content: string, replace: boolean): void {
    try {
        if (!replace) {
            writeNew(path, content);
            return;
        }
        const temp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
        try {
            writeNew(temp, content);
            renameSync(temp, path);
        } catch (err) {
            try {
                unlinkSync(temp);
            } catch {
                // Nothing to remove.
            }
            throw err;
        }
    } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        throw new InitRefused(code === 'EEXIST' ? 'EXISTS' : 'NOT_WRITTEN', path, typeof code === 'string' ? code : undefined);
    }
}

/** Write a plan's files under `dir`. Throws `InitRefused`, having written nothing when an existing file is in the way. */
export function writeInit(plan: InitPlan, dir: string, opts: { readonly force?: boolean; readonly keygen?: boolean } = {}): WrittenInit {
    const force = opts.force === true;
    const configPath = join(dir, CONFIG_FILE);
    const envPath = join(dir, ENV_FILE);
    const keyPath = join(dir, SIGNING_KEY_FILE);

    if (exists(dir)) {
        const st = lstatSync(dir);
        if (st.isSymbolicLink()) throw new InitRefused('DIR_IS_LINK', dir);
        if (!st.isDirectory()) throw new InitRefused('DIR_NOT_A_DIRECTORY', dir);
        // Both files are looked for before either is written.
        if (!force) for (const path of [configPath, envPath]) if (exists(path)) throw new InitRefused('EXISTS', path);
    } else {
        try {
            mkdirSync(dir, { recursive: true, mode: INIT_DIR_MODE });
            chmodSync(dir, INIT_DIR_MODE);
        } catch (err) {
            const code = (err as NodeJS.ErrnoException).code;
            throw new InitRefused('NOT_WRITTEN', dir, typeof code === 'string' ? code : undefined);
        }
    }

    let signingKey: WrittenInit['signingKey'] = null;
    if (exists(keyPath)) {
        // Kept, always. Its public half is shown when the file is a key this scanner can use.
        let publicKeyHex: string | null = null;
        try {
            publicKeyHex = rawPublicKeyHex(loadSigningKey(readFileSync(keyPath, 'utf8')).publicKey);
        } catch {
            publicKeyHex = null;
        }
        signingKey = { path: keyPath, created: false, publicKeyHex };
    } else if (opts.keygen !== false) {
        signingKey = { path: keyPath, created: true, publicKeyHex: generateSigningKey(keyPath).publicKeyHex };
    }

    write(configPath, plan.configText, force && exists(configPath));
    write(envPath, renderEnvTemplate(plan.credentialNames, signingKey?.path ?? null), force && exists(envPath));
    return {
        dir,
        files: [
            { path: configPath, mode: INIT_FILE_MODE },
            { path: envPath, mode: INIT_FILE_MODE },
            ...(signingKey?.created ? [{ path: keyPath, mode: INIT_FILE_MODE }] : []),
        ],
        signingKey,
    };
}
