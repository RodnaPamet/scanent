/**
 * SECRETS FROM FILES — `NAME_FILE` beside `NAME`.
 *
 * A container platform hands a secret to a process as a mounted file far more
 * readily than as an environment variable, and two of the scanner's
 * credentials (the PEM signing key, a Google key file) have line breaks an env
 * file cannot carry. So for each variable the configuration names, and for no
 * other, `<NAME>_FILE` may name a file holding the value.
 *
 *   • BOTH SET IS REFUSED, never resolved by precedence: a precedence rule
 *     means one of two credentials is silently ignored, and the one ignored
 *     may be the one somebody just rotated.
 *   • The file is a regular file (a link to one is followed: a Kubernetes
 *     secret is a link), at most 64 KiB, text, and writable by its owner
 *     alone: a file its group or every user can write lets somebody else swap
 *     the signing key. A file others can READ is accepted, because Docker
 *     mounts a secret 0444 and Kubernetes 0644 inside a mount only that
 *     container sees, and neither makes one writable. Ownership and the
 *     directory are not checked: a secret mount's owner and directory are the
 *     platform's, and differ between platforms.
 *   • Exactly one trailing line break is removed.
 *
 * Nothing here logs, and no error carries a byte of a file's content.
 */
import { readFileSync, statSync } from 'fs';

import { credentialEnvNames, type ScannerConfig } from './config';

export type Env = Readonly<Record<string, string | undefined>>;

export type SecretFileReason = 'BOTH_SET' | 'FILE_PATH' | 'NOT_A_FILE' | 'TOO_LARGE' | 'WORLD_WRITABLE' | 'GROUP_WRITABLE' | 'EMPTY' | 'NOT_TEXT' | 'UNREADABLE';

/** The largest secret file read. The largest real credential, a Google key file, is under 3 KiB. */
export const MAX_SECRET_FILE_BYTES = 64 * 1024;

const WHY: Readonly<Record<SecretFileReason, string>> = {
    BOTH_SET: 'both the variable and its _FILE form are set; set exactly one',
    FILE_PATH: 'the _FILE path must be absolute, with no .. segment and no control character',
    NOT_A_FILE: 'the _FILE path is not a regular file',
    TOO_LARGE: `the secret file is larger than ${MAX_SECRET_FILE_BYTES} bytes`,
    WORLD_WRITABLE: 'the secret file is writable by other users',
    GROUP_WRITABLE: 'the secret file is writable by its group; make it writable by its owner alone (chmod g-w)',
    EMPTY: 'the secret file is empty',
    NOT_TEXT: 'the secret file is not text',
    UNREADABLE: 'the secret file could not be read',
};

/** A secret file that was refused: the variable, the reason code, and never the content. */
export class SecretFileError extends Error {
    constructor(
        /** The variable the configuration names (without `_FILE`). */
        readonly variable: string,
        readonly reason: SecretFileReason,
        /** The errno code of a read failure (`ENOENT`, `EACCES`), when there was one. */
        readonly code?: string,
    ) {
        super(`${variable}: ${WHY[reason]}${code === undefined ? '' : ` (${code})`}`);
        this.name = 'SecretFileError';
    }
}

/** How a secret file is read. A TEST SEAM: production uses the file system. */
export interface SecretFs {
    statSync(path: string): { isFile(): boolean; readonly size: number; readonly mode: number };
    readFileSync(path: string): Buffer;
}

const NODE_FS: SecretFs = { statSync: (p) => statSync(p), readFileSync: (p) => readFileSync(p) };

const isSet = (v: string | undefined): v is string => typeof v === 'string' && v.trim() !== '';

function errnoOf(err: unknown): string | undefined {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    return typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : undefined;
}

/** Whether `path` is one a secret may be read from: absolute, no `..`, no control character. */
export function isSecretFilePath(path: string): boolean {
    return path.length <= 4096 && path.startsWith('/') && !path.split('/').includes('..') && ![...path].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f);
}

/** The value one secret file holds, for the variable `variable`. Throws `SecretFileError`. */
export function readSecretFile(variable: string, path: string, fs: SecretFs = NODE_FS): string {
    if (!isSecretFilePath(path)) throw new SecretFileError(variable, 'FILE_PATH');
    let bytes: Buffer;
    try {
        const stat = fs.statSync(path);
        if (!stat.isFile()) throw new SecretFileError(variable, 'NOT_A_FILE');
        if (stat.size > MAX_SECRET_FILE_BYTES) throw new SecretFileError(variable, 'TOO_LARGE');
        if ((stat.mode & 0o002) !== 0) throw new SecretFileError(variable, 'WORLD_WRITABLE');
        if ((stat.mode & 0o020) !== 0) throw new SecretFileError(variable, 'GROUP_WRITABLE');
        bytes = fs.readFileSync(path);
    } catch (err) {
        if (err instanceof SecretFileError) throw err;
        throw new SecretFileError(variable, 'UNREADABLE', errnoOf(err));
    }
    // The size is checked again on what was read: a file can grow between the two calls.
    if (bytes.byteLength > MAX_SECRET_FILE_BYTES) throw new SecretFileError(variable, 'TOO_LARGE');
    if (bytes.includes(0)) throw new SecretFileError(variable, 'NOT_TEXT');
    let text: string;
    try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
        throw new SecretFileError(variable, 'NOT_TEXT');
    }
    const value = text.endsWith('\r\n') ? text.slice(0, -2) : text.endsWith('\n') ? text.slice(0, -1) : text;
    if (value.trim() === '') throw new SecretFileError(variable, 'EMPTY');
    return value;
}

/** Where one configured credential comes from, without reading it. */
export function secretOrigin(name: string, env: Env): { readonly from: 'env' | 'file' | 'both' | 'absent'; readonly path?: string } {
    const direct = isSet(env[name]);
    const file = env[`${name}_FILE`];
    if (direct && isSet(file)) return { from: 'both' };
    if (direct) return { from: 'env' };
    if (isSet(file)) return { from: 'file', path: file.trim() };
    return { from: 'absent' };
}

/**
 * A copy of `env` in which every credential the configuration names holds its
 * value, whether it came from the variable or from its `_FILE`. Only those
 * names are looked up: an unrelated `X_FILE` is not read. Throws
 * `SecretFileError` for the first name that is refused.
 */
export function resolveSecretEnv(config: ScannerConfig, env: Env, fs: SecretFs = NODE_FS): Env {
    const out: Record<string, string | undefined> = { ...env };
    for (const name of new Set(credentialEnvNames(config))) {
        const origin = secretOrigin(name, env);
        if (origin.from === 'both') throw new SecretFileError(name, 'BOTH_SET');
        if (origin.from === 'file') out[name] = readSecretFile(name, origin.path as string, fs);
    }
    return out;
}
