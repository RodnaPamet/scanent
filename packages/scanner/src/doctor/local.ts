/**
 * `scanent doctor` — the checks that reach no source: the configuration file,
 * the signing key, secret files, the output directory, the inventory, TLS and
 * proxy settings, the clock and the egress proof.
 *
 * Nothing here writes. "Writable" is decided by permission (`access`), never
 * by creating a file, and the detail says so. The file system, the
 * environment and the clock are all passed in.
 */
import { constants } from 'fs';
import { dirname } from 'path';

import { InventoryRefused } from '@scanent/report/results/inventory';

import { credentialEnvNames, type ScannerConfig } from '../config';
import { proveEgress, type EgressProbe } from '../egress-proof';
import { addressCheckedByProxy, PROXY_CHECKS_ADDRESSES_ENV } from '../customer-host';
import { describeProxy, isProxied, nodeHonoursEnvProxy, proxyInEffect, proxyVariableSet } from '../proxy-env';
import { publicKeyFingerprint, rawPublicKeyHex } from '../report';
import { loadSigningKey } from '../scan';
import { readSecretFile, secretOrigin, SecretFileError, type Env, type SecretFs } from '../secrets';
import type { Check } from './types';

export interface DoctorStat {
    isFile(): boolean;
    isDirectory(): boolean;
    isSymbolicLink(): boolean;
    readonly mode: number;
    readonly size: number;
}

/** How the local checks see the file system. A TEST SEAM: production uses `fs`. */
export interface DoctorFs {
    readFile(path: string): Buffer;
    /** Follows links. */
    stat(path: string): DoctorStat;
    lstat(path: string): DoctorStat;
    /** Throws when the process may not; `mode` is `fs.constants.W_OK` and friends. */
    access(path: string, mode: number): void;
}

const SCOPE = 'local';
const pass = (id: string, detail: string): Check => ({ scope: SCOPE, id, status: 'PASS', detail });
const warn = (id: string, detail: string, fix: string): Check => ({ scope: SCOPE, id, status: 'WARN', detail, fix });
const fail = (id: string, cls: 'CONFIG' | 'CREDENTIAL' | 'NETWORK', detail: string, fix: string): Check => ({ scope: SCOPE, id, status: 'FAIL', class: cls, detail, fix });
const skip = (id: string, cause: 'NOT_APPLICABLE' | 'BLOCKED' | 'NOT_OBSERVABLE', detail: string): Check => ({ scope: SCOPE, id, status: 'SKIPPED', cause, detail });

const errnoOf = (err: unknown): string => {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    return typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'error';
};

/** The local check ids, in the order the table lists them. */
export const LOCAL_CHECK_IDS = [
    'config.valid',
    'config.mode',
    'signing-key',
    'secret-files',
    'output.dir',
    'inventory',
    'tls.verification',
    'tls.extra-ca',
    'proxy',
    'proxy.customer-hosts',
    'clock',
    'egress',
] as const;

export function checkConfigMode(fs: DoctorFs, path: string): Check {
    let mode: number;
    try {
        mode = fs.stat(path).mode;
    } catch (err) {
        return skip('config.mode', 'BLOCKED', `the file's mode could not be read (${errnoOf(err)})`);
    }
    if ((mode & 0o022) !== 0) return warn('config.mode', 'the configuration is writable by group or others', 'chmod 0600 the configuration file.');
    return pass('config.mode', 'not writable by group or others');
}

export function checkTlsVerification(env: Env): Check {
    if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
        return fail('tls.verification', 'CONFIG', 'NODE_TLS_REJECT_UNAUTHORIZED=0 turns certificate verification off', 'Remove it; add your CA with NODE_EXTRA_CA_CERTS.');
    }
    return pass('tls.verification', 'certificate verification is on');
}

const MAX_CA_BYTES = 8 * 1024 * 1024;

export function checkExtraCa(env: Env, fs: DoctorFs): Check {
    const path = env.NODE_EXTRA_CA_CERTS;
    if (typeof path !== 'string' || path.trim() === '') return skip('tls.extra-ca', 'NOT_APPLICABLE', 'NODE_EXTRA_CA_CERTS is not set');
    const fix = 'Point NODE_EXTRA_CA_CERTS at a readable PEM file holding your certificate authority.';
    let text: string;
    try {
        const stat = fs.stat(path);
        if (!stat.isFile() || stat.size > MAX_CA_BYTES) return fail('tls.extra-ca', 'CONFIG', 'NODE_EXTRA_CA_CERTS does not name a PEM file', fix);
        text = fs.readFile(path).toString('latin1');
    } catch (err) {
        return fail('tls.extra-ca', 'CONFIG', `the file NODE_EXTRA_CA_CERTS names could not be read (${errnoOf(err)})`, fix);
    }
    const count = text.split('-----BEGIN CERTIFICATE-----').length - 1;
    if (count === 0) return fail('tls.extra-ca', 'CONFIG', 'the file NODE_EXTRA_CA_CERTS names holds no certificate', fix);
    return pass('tls.extra-ca', `${count} certificate${count === 1 ? '' : 's'} added to the trusted authorities`);
}

/** `reachesNetwork`: whether the configuration names any host at all. One that reads only local files has no request for a proxy to carry. */
export function checkProxy(env: Env, nodeVersion: string, reachesNetwork = true): Check {
    if (!proxyVariableSet(env)) return skip('proxy', 'NOT_APPLICABLE', 'no proxy is configured');
    if (!reachesNetwork) return skip('proxy', 'NOT_APPLICABLE', 'the configuration reaches no host, so no request would use a proxy');
    const proxy = describeProxy(env);
    if (proxy === null) return fail('proxy', 'NETWORK', 'HTTPS_PROXY is not an http or https URL', 'Set HTTPS_PROXY to http://<host>:<port>.');
    const where = `${proxy.host}:${proxy.port}`;
    if (env.NODE_USE_ENV_PROXY !== '1') {
        return fail('proxy', 'NETWORK', `HTTPS_PROXY names ${where} but NODE_USE_ENV_PROXY is not 1: requests would not use the proxy`, 'Set NODE_USE_ENV_PROXY=1 (the container image sets it).');
    }
    if (!nodeHonoursEnvProxy(nodeVersion)) {
        return fail('proxy', 'NETWORK', `this Node (${nodeVersion}) does not honour NODE_USE_ENV_PROXY: requests would not use the proxy`, 'Run on Node 24, or 22.21 or later; the container image does.');
    }
    return pass('proxy', `requests go through ${where}`);
}

/** `customerHosts`: the hosts the configuration names that are checked before each request (a self-hosted LangSmith, MCP servers). */
export function checkProxyCustomerHosts(env: Env, nodeVersion: string, customerHosts: readonly string[]): Check {
    if (!proxyInEffect(env, nodeVersion)) return skip('proxy.customer-hosts', 'NOT_APPLICABLE', 'no proxy is in effect');
    if (customerHosts.length === 0) return skip('proxy.customer-hosts', 'NOT_APPLICABLE', 'the configuration names no host of your own');
    // scanent's own egress proxy checks the address it dials; any other proxy resolves again on its own, unchecked.
    const proxied = customerHosts.filter((h) => isProxied(h, env) && !addressCheckedByProxy(h, env, nodeVersion));
    if (proxied.length > 0) {
        return warn(
            'proxy.customer-hosts',
            `reached through the proxy: ${proxied.join(', ')}. The address check binds this machine's resolver, not the proxy's`,
            'Add each host to NO_PROXY if it is on your network.',
        );
    }
    const delegated = customerHosts.filter((h) => addressCheckedByProxy(h, env, nodeVersion));
    if (delegated.length > 0) {
        return pass('proxy.customer-hosts', `${PROXY_CHECKS_ADDRESSES_ENV}=1: the egress proxy resolves and checks the address of ${delegated.join(', ')}`);
    }
    return pass('proxy.customer-hosts', `${customerHosts.length} host${customerHosts.length === 1 ? '' : 's'} of your own bypass${customerHosts.length === 1 ? 'es' : ''} the proxy`);
}

const MOUNTED_SECRET_DIRS = ['/run/secrets/', '/var/run/secrets/'];

/**
 * The `_FILE` secrets in use, each held to the loader's rules, and the
 * environment with every credential that could be resolved filled in.
 * `unresolved` names the variables whose file was refused: a check that needs
 * one is blocked by this check, not failed a second time.
 */
export function checkSecretFiles(config: ScannerConfig, env: Env, fs: DoctorFs): { check: Check; resolved: Env; unresolved: ReadonlySet<string> } {
    const secretFs: SecretFs = { statSync: (p) => fs.stat(p), readFileSync: (p) => fs.readFile(p) };
    const resolved: Record<string, string | undefined> = { ...env };
    const unresolved = new Set<string>();
    const refused: string[] = [];
    const loose: string[] = [];
    let inUse = 0;
    for (const name of new Set(credentialEnvNames(config))) {
        const origin = secretOrigin(name, env);
        if (origin.from === 'both') {
            refused.push(`${name} (BOTH_SET)`);
            unresolved.add(name);
            resolved[name] = undefined;
        } else if (origin.from === 'file') {
            inUse += 1;
            const path = origin.path as string;
            try {
                resolved[name] = readSecretFile(name, path, secretFs);
                // Only where the mode is the file's sole protection: outside a container platform's secret mount.
                if (!MOUNTED_SECRET_DIRS.some((d) => path.startsWith(d)) && (fs.stat(path).mode & 0o044) !== 0) loose.push(`${name}_FILE`);
            } catch (err) {
                if (!(err instanceof SecretFileError)) throw err;
                refused.push(`${name}_FILE (${err.reason}${err.code === undefined ? '' : ` ${err.code}`})`);
                unresolved.add(name);
                resolved[name] = undefined;
            }
        }
    }
    let check: Check;
    if (refused.length > 0) {
        check = fail('secret-files', 'CONFIG', `refused: ${refused.join(', ')}`, 'Set exactly one of NAME and NAME_FILE; a secret file is a regular text file under 64 KiB that other users cannot write.');
    } else if (inUse === 0) {
        check = skip('secret-files', 'NOT_APPLICABLE', 'no credential is read from a file');
    } else if (loose.length > 0) {
        check = warn('secret-files', `readable by group or others, outside a secret mount: ${loose.join(', ')}`, 'chmod 0600 each file, or mount it as a container secret.');
    } else {
        check = pass('secret-files', `${inUse} credential${inUse === 1 ? '' : 's'} read from a file`);
    }
    return { check, resolved, unresolved };
}

export function checkSigningKey(config: ScannerConfig, resolved: Env, unresolved: ReadonlySet<string>): Check {
    const name = config.scanner.signingKeyEnv;
    if (unresolved.has(name)) return skip('signing-key', 'BLOCKED', `${name} could not be read: see secret-files`);
    const pem = resolved[name];
    if (typeof pem !== 'string' || pem.trim() === '') {
        return fail('signing-key', 'CREDENTIAL', `${name} is not set`, `Create a key with 'scanent keygen --out <file>' and set ${name}_FILE to its path.`);
    }
    try {
        const publicKeyHex = rawPublicKeyHex(loadSigningKey(pem).publicKey);
        return pass('signing-key', `ed25519 ${publicKeyHex}, fingerprint ${publicKeyFingerprint(publicKeyHex)}`);
    } catch {
        return fail('signing-key', 'CONFIG', `${name} is not an Ed25519 private key in PKCS#8 PEM`, `Create a key with 'scanent keygen --out <file>'.`);
    }
}

/** The directory the file output writes under: `--out`, else the configuration's file output, else null. */
export function outputDirOf(config: ScannerConfig, out: string | null): string | null {
    return out ?? config.outputs?.flatMap((o) => (o.kind === 'file' ? [o.dir] : []))[0] ?? null;
}

export function checkOutputDir(dir: string | null, fs: DoctorFs, uid: number | null): Check {
    if (dir === null) return skip('output.dir', 'NOT_APPLICABLE', 'no file output is in effect');
    const who = uid === null ? 'this user' : `uid ${uid}`;
    const fix = `Make the directory writable by ${who}, or run the container with --user set to its owner.`;
    const writable = (path: string): boolean => {
        try {
            fs.access(path, constants.W_OK | constants.X_OK);
            return true;
        } catch {
            return false;
        }
    };
    let stat: DoctorStat;
    try {
        stat = fs.lstat(dir);
    } catch (err) {
        if (errnoOf(err) !== 'ENOENT') return fail('output.dir', 'CONFIG', `${dir} could not be read (${errnoOf(err)})`, fix);
        const parent = dirname(dir);
        let parentOk = false;
        try {
            const p = fs.lstat(parent);
            parentOk = p.isDirectory() && !p.isSymbolicLink() && writable(parent);
        } catch {
            parentOk = false;
        }
        if (!parentOk) return fail('output.dir', 'CONFIG', `${dir} does not exist and ${who} cannot create it`, `Create ${dir} and make it writable by ${who}.`);
        return pass('output.dir', `${dir} does not exist yet and ${who} can create it (by permission; nothing was written)`);
    }
    if (stat.isSymbolicLink()) return fail('output.dir', 'CONFIG', `${dir} is a symbolic link`, 'Name the directory itself.');
    if (!stat.isDirectory()) return fail('output.dir', 'CONFIG', `${dir} is not a directory`, 'Name a directory.');
    if (!writable(dir)) return fail('output.dir', 'CONFIG', `${dir} is not writable by ${who}`, fix);
    if ((stat.mode & 0o002) !== 0) return warn('output.dir', `${dir} is writable by other users`, `chmod 0700 ${dir}: the runs are evidence.`);
    return pass('output.dir', `${dir} is writable by ${who} (by permission; nothing was written)`);
}

export function checkInventory(config: ScannerConfig, load: (config: ScannerConfig) => { readonly rows: readonly unknown[] } | null): Check {
    if (config.inventory === undefined) return skip('inventory', 'NOT_APPLICABLE', 'no inventory is configured');
    try {
        const inventory = load(config);
        const rows = inventory?.rows.length ?? 0;
        return pass('inventory', `${rows} row${rows === 1 ? '' : 's'}`);
    } catch (err) {
        if (!(err instanceof InventoryRefused)) throw err;
        return fail('inventory', 'CONFIG', `refused: ${err.issues.join("; ")}`, 'Correct the inventory file, or remove inventory from the configuration.');
    }
}

export const CLOCK_WARN_SECONDS = 60;
export const CLOCK_FAIL_SECONDS = 300;

/** `dates`: the `Date` header of each probe response that carried one. No new request is made for this. */
export function checkClock(dates: readonly string[], nowMs: number): Check {
    const offsets = dates.map((d) => Date.parse(d)).filter((t) => Number.isFinite(t)).map((t) => Math.abs(t - nowMs) / 1000);
    if (offsets.length === 0) return skip('clock', 'NOT_OBSERVABLE', 'no response carried a Date header to compare with; check this machine is time-synchronised');
    const worst = Math.round(Math.max(...offsets));
    const seen = `${worst} second${worst === 1 ? '' : 's'} from the sources' clocks (${offsets.length} response${offsets.length === 1 ? '' : 's'})`;
    if (worst > CLOCK_FAIL_SECONDS) return fail('clock', 'CONFIG', seen, 'Synchronise this machine\'s clock: token exchanges and signed assertions fail when it is wrong.');
    if (worst >= CLOCK_WARN_SECONDS) return warn('clock', seen, 'Synchronise this machine\'s clock.');
    return pass('clock', seen);
}

export async function checkEgress(config: ScannerConfig, env: Env, probe: EgressProbe | undefined): Promise<Check> {
    if (config.egress === undefined || config.inflect === undefined) return skip('egress', 'NOT_APPLICABLE', 'the configuration has no egress block');
    const proof = await proveEgress({
        proxyUrl: config.egress.proxyUrl,
        allowedHost: new URL(config.inflect.baseUrl).hostname,
        canaryHost: config.egress.canaryHost,
        env,
        probe,
    });
    if (proof.met) return pass('egress', 'the proxy admits the tenant host, refuses the canary, and there is no way around it');
    return fail('egress', 'NETWORK', `the egress proof failed: ${proof.failed ?? 'unknown'}`, 'Check HTTPS_PROXY, NODE_USE_ENV_PROXY=1, the proxy\'s allowlist, and that the scanner has no route but the proxy.');
}
