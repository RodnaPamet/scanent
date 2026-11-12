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
 *   • WHAT IS KEPT IS HELD TO THE SAME STANDARD AS WHAT IS WRITTEN. An
 *     existing directory that any user can write to, and an existing signing
 *     key that is a link, not a regular file, or writable by anyone but its
 *     owner, are refused: any local user could swap the key the env file is
 *     about to name. A key others can READ, and a directory the group can
 *     write to, are kept with a warning that says what to run.
 *   • The target is checked BEFORE a question is asked (`checkInitTarget`), so
 *     nobody answers the wizard to be told the directory was in the way.
 */
import { accessSync, chmodSync, closeSync, constants, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'fs';
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
        readonly reason: 'EXISTS' | 'DIR_IS_LINK' | 'DIR_NOT_A_DIRECTORY' | 'NOT_WRITTEN' | 'DIR_UNSAFE' | 'KEY_UNSAFE',
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
                        : reason === 'DIR_UNSAFE'
                            ? `${path} is writable by every user, so any of them could replace the signing key; run: chmod 700 ${path}`
                            : reason === 'KEY_UNSAFE'
                                ? `${path} is an existing signing key that is ${code ?? 'not safe to use'}; it was not used. Make it a regular file only its owner can write (chmod 600), or move it away`
                                : `${path} could not be written${code ? ` (${code})` : ''}`,
        );
        this.name = 'InitRefused';
    }
}

export interface WrittenInit {
    readonly dir: string;
    readonly files: readonly { readonly path: string; readonly mode: number }[];
    /** What was kept although it is looser than what `init` writes: each line says what to run. */
    readonly warnings: readonly string[];
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

/**
 * Whether `init` may write under `dir`, decided without writing anything:
 * the directory, the two files `--force` governs, and a signing key already
 * there. Throws `InitRefused`; returns the warnings for what will be kept.
 * `writeInit` runs it again, so a caller that skips it loses nothing.
 */
export function checkInitTarget(dir: string, opts: { readonly force?: boolean } = {}): readonly string[] {
    const warnings: string[] = [];
    if (!exists(dir)) return warnings;
    const st = lstatSync(dir);
    if (st.isSymbolicLink()) throw new InitRefused('DIR_IS_LINK', dir);
    if (!st.isDirectory()) throw new InitRefused('DIR_NOT_A_DIRECTORY', dir);
    // Both files are looked for before either is written.
    if (opts.force !== true) for (const path of [join(dir, CONFIG_FILE), join(dir, ENV_FILE)]) if (exists(path)) throw new InitRefused('EXISTS', path);
    if ((st.mode & 0o002) !== 0) throw new InitRefused('DIR_UNSAFE', dir);
    try {
        accessSync(dir, constants.W_OK | constants.X_OK);
    } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        throw new InitRefused('NOT_WRITTEN', dir, typeof code === 'string' ? code : undefined);
    }
    if ((st.mode & 0o020) !== 0) warnings.push(`${dir} is writable by its group; init makes its own directory 0700. Run: chmod 700 ${dir}`);

    const keyPath = join(dir, SIGNING_KEY_FILE);
    if (exists(keyPath)) {
        const key = lstatSync(keyPath);
        if (key.isSymbolicLink()) throw new InitRefused('KEY_UNSAFE', keyPath, 'a symbolic link');
        if (!key.isFile()) throw new InitRefused('KEY_UNSAFE', keyPath, 'not a regular file');
        if ((key.mode & 0o022) !== 0) throw new InitRefused('KEY_UNSAFE', keyPath, 'writable by other users');
        if ((key.mode & 0o044) !== 0) warnings.push(`${keyPath} can be read by other users; init writes a key 0600. Run: chmod 600 ${keyPath}`);
    }
    return warnings;
}

/** Write a plan's files under `dir`. Throws `InitRefused`, having written nothing when an existing file is in the way. */
export function writeInit(plan: InitPlan, dir: string, opts: { readonly force?: boolean; readonly keygen?: boolean } = {}): WrittenInit {
    const force = opts.force === true;
    const configPath = join(dir, CONFIG_FILE);
    const envPath = join(dir, ENV_FILE);
    const keyPath = join(dir, SIGNING_KEY_FILE);

    const warnings = checkInitTarget(dir, { force });
    if (!exists(dir)) {
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
        warnings,
        signingKey,
    };
}
