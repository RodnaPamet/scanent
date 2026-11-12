/**
 * `scanent doctor` — the preflight: is this estate ready to be scanned?
 *
 * It reads what `scan` would read, with the same credentials, through the
 * same wire, and it reports what it OBSERVED. Three rules:
 *
 *   • IT WRITES NOTHING, ANYWHERE. No report, no file, no post. It never sends
 *     a write to a client's system to learn whether a write would be allowed:
 *     where a declared read reveals the credential's grant (an Entra token's
 *     roles, a GitHub classic token's scopes) it says what it saw, and
 *     everywhere else the check is NOT_OBSERVABLE with what to confirm by hand.
 *   • IT ADDS NO REQUEST. Every probe is `HarnessSource.preflight`, whose
 *     requests are ones the source's `read` already makes; the manifest hash
 *     is unchanged, and the tests hold every request to the declared surface.
 *   • ABSENCE IS NEVER A PASS. A check passes only on something seen. One
 *     whose prerequisite failed is BLOCKED and says by what; it is never left
 *     out. Zero checks is not ready.
 */
import { accessSync, lstatSync, readFileSync, statSync } from 'fs';

import { ConfigError, parseScannerConfig, sourceCredentialEnv, type ScannerConfig, type SourceConfig } from '../config';
import { assertResolvesReachable, parsePrivateCidrAllowlist, resolveWithDns, type PrivateCidrAllowlist, type ResolveHost } from '../customer-host';
import type { EgressProbe } from '../egress-proof';
import { hostsFor } from '../hosts';
import { createSourceWire, TLS_NOT_TRUSTED, type FetchLike } from '../http';
import { ACCESS_GUIDE } from '../init/access-guide';
import { loadConfiguredInventory } from '../local-results';
import { isProxied, proxyInEffect } from '../proxy-env';
import { buildSources } from '../scan';
import { scannerManifestHash, SCANNER_VERSION } from '../scanner-surface';
import type { Env } from '../secrets';
import { SourceReadError, type HarnessSource, type ProbeStep, type SourceKind } from '../source';
import {
    checkClock,
    checkConfigMode,
    checkEgress,
    checkExtraCa,
    checkInventory,
    checkOutputDir,
    checkProxy,
    checkProxyCustomerHosts,
    checkSecretFiles,
    checkSigningKey,
    checkTlsVerification,
    LOCAL_CHECK_IDS,
    outputDirOf,
    type DoctorFs,
} from './local';
import { assertWellFormed, countsOf, doctorExitCode, DOCTOR_SCHEMA, isReady, type Check, type DoctorReport, type FailClass, type SkipCause } from './types';

/** One probe's time box and byte budget: a preflight is a handful of one-row reads. */
export const DOCTOR_PROBE_SECONDS = 30;
export const DOCTOR_PROBE_BYTES = 1024 * 1024;

export interface DoctorDeps {
    readonly configPath: string;
    readonly env: Env;
    /** `--out`: check this directory instead of the configuration's file output. */
    readonly out?: string | null;
    /** `--source`: limit the source checks to these kinds. Local checks always run. */
    readonly only?: readonly SourceKind[];
    /** TEST SEAMS, as in `ScanDeps`: production uses the global fetch, DNS, the file system and the clock. */
    readonly fetchImpl?: FetchLike;
    readonly resolveHost?: ResolveHost;
    readonly egressProbe?: EgressProbe;
    readonly fs?: DoctorFs;
    readonly now?: () => number;
    readonly nodeVersion?: string;
    readonly uid?: number | null;
}

const NODE_FS: DoctorFs = {
    readFile: (p) => readFileSync(p),
    stat: (p) => statSync(p),
    lstat: (p) => lstatSync(p),
    access: (p, mode) => accessSync(p, mode),
};

const SOURCE_CHECK_IDS = ['credential.present', 'host.resolves', 'reachable', 'authenticated', 'read.permitted', 'write.absent'] as const;
type SourceCheckId = (typeof SOURCE_CHECK_IDS)[number];

/** One thing the source checks are reported for: a source, or one MCP server. */
interface Target {
    readonly scope: string;
    readonly kind: SourceKind;
    /** The variable holding its credential; null when it takes none. */
    readonly credential: string | null;
    /** Its hosts. `guard` is the allowlist of a host that is checked before each request, else null. */
    readonly hosts: readonly { readonly host: string; readonly guard: PrivateCidrAllowlist | null }[];
    /** The MCP server's label, to pick its steps out of the source's. */
    readonly stepScope?: string;
}

function targetsOf(config: ScannerConfig, sources: readonly SourceConfig[]): Target[] {
    const all = hostsFor(config);
    const out: Target[] = [];
    for (const s of sources) {
        if (s.kind === 'code') {
            out.push({ scope: 'code', kind: 'code', credential: null, hosts: [] });
        } else if (s.kind === 'mcp') {
            for (const server of s.servers) {
                out.push({
                    scope: `mcp:${server.label}`,
                    kind: 'mcp',
                    credential: server.readTokenEnv ?? null,
                    hosts: [{ host: new URL(server.url).hostname, guard: parsePrivateCidrAllowlist(server.egressPrivateCidrAllowlist) ?? [] }],
                    stepScope: server.label,
                });
            }
        } else if (s.kind === 'inflect-register') {
            out.push({
                scope: s.kind,
                kind: s.kind,
                credential: config.inflect?.apiKeyEnv ?? null,
                hosts: all.filter((e) => e.source === s.kind).map((e) => ({ host: e.host, guard: null })),
            });
        } else {
            const guard =
                s.kind === 'runtime' && 'selfHosted' in s.endpoint ? parsePrivateCidrAllowlist(s.endpoint.egressPrivateCidrAllowlist) ?? [] : null;
            out.push({
                scope: s.kind,
                kind: s.kind,
                credential: sourceCredentialEnv(s),
                hosts: all.filter((e) => e.source === s.kind).map((e) => ({ host: e.host, guard: e.purpose === 'read' ? guard : null })),
            });
        }
    }
    return out;
}

const isSet = (v: string | undefined): boolean => typeof v === 'string' && v.trim() !== '';

/** Builds one scope's checks; each constructor names the status, so no check has a default one. */
function scoped(scope: string) {
    return {
        pass: (id: string, detail: string): Check => ({ scope, id, status: 'PASS', detail }),
        warn: (id: string, detail: string, fix: string): Check => ({ scope, id, status: 'WARN', detail, fix }),
        fail: (id: string, cls: FailClass, detail: string, fix: string): Check => ({ scope, id, status: 'FAIL', class: cls, detail, fix }),
        skip: (id: string, cause: SkipCause, detail: string): Check => ({ scope, id, status: 'SKIPPED', cause, detail }),
    };
}

/** `ids` after `after`, each BLOCKED by `why`. */
function blockedAfter(scope: string, after: SourceCheckId, why: string): Check[] {
    return SOURCE_CHECK_IDS.slice(SOURCE_CHECK_IDS.indexOf(after) + 1).map((id) => scoped(scope).skip(id, 'BLOCKED', why));
}

async function hostCheck(t: Target, env: Env, nodeVersion: string, resolve: ResolveHost): Promise<Check> {
    const c = scoped(t.scope);
    const viaProxy = proxyInEffect(env, nodeVersion);
    const failed: string[] = [];
    let resolved = 0;
    let byProxy = 0;
    for (const { host, guard } of t.hosts) {
        if (guard !== null) {
            // A host the estate names: the same check `scan` makes before every request, proxied or not.
            try {
                await assertResolvesReachable(host, resolve, guard);
                resolved += 1;
            } catch {
                failed.push(host);
            }
        } else if (viaProxy && isProxied(host, env)) {
            byProxy += 1;
        } else {
            try {
                if ((await resolve(host)).length === 0) failed.push(host);
                else resolved += 1;
            } catch {
                failed.push(host);
            }
        }
    }
    if (failed.length > 0) {
        return c.fail(
            'host.resolves',
            'NETWORK',
            `did not resolve to an address the scanner may reach: ${failed.join(', ')}`,
            viaProxy ? 'Check DNS for the host, or add it to NO_PROXY if it is on your network.' : 'Check DNS for the host from where the scanner runs; behind a proxy, set HTTPS_PROXY.',
        );
    }
    if (resolved === 0) return c.skip('host.resolves', 'NOT_APPLICABLE', `resolved by the proxy (${byProxy} host${byProxy === 1 ? '' : 's'})`);
    return c.pass('host.resolves', `${resolved} host${resolved === 1 ? '' : 's'}${byProxy > 0 ? `; ${byProxy} resolved by the proxy` : ''}`);
}

const isAuthFailure = (e: SourceReadError) => e.reason === 'AUTH_FAILED' && e.status !== 403;
const gotNoAnswer = (e: SourceReadError) => e.status === undefined && (e.reason === 'UNREACHABLE' || e.reason === 'TIME_BOX');
/** A failure in fixed words: the reason code and, when there was one, the status. Never the server's text. */
const failureWords = (e: SourceReadError) => (e.status === undefined ? e.reason : `HTTP ${e.status}`);

/** `reachable`, `authenticated`, `read.permitted` and `write.absent`, from what a preflight tried. */
function probeChecks(t: Target, steps: readonly ProbeStep[], env: Env, nodeVersion: string): Check[] {
    const c = scoped(t.scope);
    const requests = steps.filter((s) => s.id !== 'write');
    const failing = requests.find((s) => s.outcome !== 'ok');
    const err = failing === undefined ? null : (failing.outcome as SourceReadError);
    const okRequests = requests.filter((s) => s.outcome === 'ok');
    const grant = ACCESS_GUIDE[t.kind].grant;
    const out: Check[] = [];

    if (requests.length === 0) {
        // Nothing was tried: that is not a pass of anything.
        return [c.skip('reachable', 'BLOCKED', 'the preflight made no request'), ...blockedAfter(t.scope, 'reachable', 'the preflight made no request')];
    }

    // The time box ending after requests had already been answered is not a host that gave no answer:
    // the estate is larger than one preflight covers in its time, and what was not reached was not checked.
    if (err !== null && err.reason === 'TIME_BOX' && okRequests.length > 0) {
        const why = `the preflight's ${DOCTOR_PROBE_SECONDS}-second time box ended after ${okRequests.length} request${okRequests.length === 1 ? '' : 's'}; run doctor again, or with --source`;
        const hosts = [...new Set(okRequests.map((s) => s.host).filter((h): h is string => h !== undefined && h !== ''))];
        return [
            c.pass('reachable', hosts.length > 0 ? hosts.join(', ') : 'answered'),
            c.pass('authenticated', 'the credential was accepted'),
            c.skip('read.permitted', 'BLOCKED', why),
            c.skip('write.absent', 'BLOCKED', why),
        ];
    }

    // reachable
    if (err !== null && failing !== undefined && gotNoAnswer(err)) {
        const host = failing.host || 'the host';
        const tls = err.message === TLS_NOT_TRUSTED;
        const proxied = proxyInEffect(env, nodeVersion) && failing.host !== undefined && failing.host !== '' && isProxied(failing.host, env);
        out.push(
            c.fail(
                'reachable',
                'NETWORK',
                tls ? `${host}: the TLS certificate was not trusted` : `${host} gave no answer (${err.reason})`,
                tls
                    ? 'Mount your CA and set NODE_EXTRA_CA_CERTS.'
                    : proxied
                        ? `Allow ${host}:443 at the proxy, and check the proxy itself is reachable.`
                        : `Open outbound TCP 443 to ${host}; behind a proxy, set HTTPS_PROXY and NODE_USE_ENV_PROXY=1.`,
            ),
            ...blockedAfter(t.scope, 'reachable', `${host} gave no answer`),
        );
        return out;
    }
    // An answer was SEEN when a request succeeded, or failed with a status or in a way only a response can.
    const answered = okRequests.length > 0 || (err !== null && (err.status !== undefined || ['PAGINATION_TORN', 'BYTE_CAP', 'RATE_LIMITED'].includes(err.reason)));
    if (!answered && err !== null) {
        const why = 'no request was answered';
        out.push(c.skip('reachable', 'BLOCKED', err.reason === 'AUTH_FAILED' ? 'no request was sent: the credential could not be used' : why));
        if (err.reason === 'AUTH_FAILED') {
            out.push(
                c.fail('authenticated', 'CREDENTIAL', 'the credential could not be used', t.credential === null ? 'Check the credential.' : `Check the value of ${t.credential}: it is not in the form the source takes.`),
                ...blockedAfter(t.scope, 'authenticated', 'the credential could not be used'),
            );
        } else {
            out.push(
                c.skip('authenticated', 'BLOCKED', why),
                c.fail('read.permitted', 'CONFIG', `${failing?.what ?? 'the read'} failed (${failureWords(err)})`, 'Check the source\'s configuration, and run doctor again.'),
                c.skip('write.absent', 'BLOCKED', why),
            );
        }
        return out;
    }
    const hosts = [...new Set(requests.filter((s) => s.outcome === 'ok' || s === failing).map((s) => s.host).filter((h): h is string => h !== undefined && h !== ''))];
    out.push(c.pass('reachable', hosts.length > 0 ? hosts.join(', ') : 'answered'));

    // authenticated
    if (err !== null && isAuthFailure(err)) {
        out.push(
            c.fail(
                'authenticated',
                'CREDENTIAL',
                `the credential was refused (${failureWords(err)})`,
                t.credential === null ? 'Check what the server requires to list its tools.' : `Check the value of ${t.credential}: it may be wrong, expired or revoked.`,
            ),
            ...blockedAfter(t.scope, 'authenticated', 'the credential was refused'),
        );
        return out;
    }
    if (okRequests.length === 0 && err !== null && err.status !== 403) {
        // The first request was answered, with neither a success nor a refusal of the credential: nothing was learnt about it.
        const why = err.status === 429 ? 'rate limited; run again later' : `the first request failed (${failureWords(err)})`;
        out.push(c.skip('authenticated', 'BLOCKED', why));
        if (err.status === 429) out.push(c.skip('read.permitted', 'BLOCKED', why));
        else out.push(c.fail('read.permitted', 'NETWORK', `${failing?.what ?? 'the read'} failed (${failureWords(err)})`, 'Check the host is the one the configuration should name, and run doctor again.'));
        out.push(c.skip('write.absent', 'BLOCKED', why));
        return out;
    }
    out.push(c.pass('authenticated', t.credential === null && t.kind === 'mcp' ? 'no token needed' : 'the credential was accepted'));

    // read.permitted
    if (err !== null && failing !== undefined) {
        if (err.status === 403) {
            out.push(c.fail('read.permitted', 'CREDENTIAL', `${failing.what}: refused (HTTP 403)`, `Grant: ${grant}.`));
        } else if (err.status === 429) {
            out.push(c.skip('read.permitted', 'BLOCKED', 'rate limited; run again later'));
        } else {
            out.push(c.fail('read.permitted', 'NETWORK', `${failing.what} failed (${failureWords(err)})`, 'Check the host is the one the configuration should name, and run doctor again.'));
        }
        out.push(c.skip('write.absent', 'BLOCKED', 'the reads did not all succeed'));
        return out;
    }
    const reads = requests.filter((s) => s.id === 'read').length;
    if (reads === 0) {
        out.push(c.skip('read.permitted', 'BLOCKED', 'no read was made'), c.skip('write.absent', 'BLOCKED', 'no read was made'));
        return out;
    }
    out.push(c.pass('read.permitted', `${reads} read${reads === 1 ? '' : 's'}`));

    // write.absent
    const write = steps.find((s) => s.id === 'write')?.observed?.write;
    if (write === undefined) {
        out.push(c.skip('write.absent', 'NOT_OBSERVABLE', 'no read this scanner makes shows whether the credential can write; confirm its grant by hand'));
    } else if (write.state === 'READ_ONLY') {
        out.push(c.pass('write.absent', write.detail));
    } else if (write.state === 'WRITE') {
        out.push(c.warn('write.absent', `the credential also holds ${write.names.join(', ')}`, write.fix));
    } else {
        out.push(c.skip('write.absent', 'NOT_OBSERVABLE', write.verify));
    }
    return out;
}

/** The `code` source: no credential and no host; the roots are listed, and writability is read from permission. */
function codeChecks(t: Target, roots: readonly { readonly label: string; readonly path: string }[], steps: readonly ProbeStep[] | null, fs: DoctorFs): Check[] {
    const c = scoped(t.scope);
    const out: Check[] = (['credential.present', 'host.resolves', 'reachable', 'authenticated'] as const).map((id) =>
        c.skip(id, 'NOT_APPLICABLE', 'the code source reads local files'),
    );
    if (steps === null) {
        return [...out, c.skip('read.permitted', 'BLOCKED', 'the preflight did not run'), c.skip('write.absent', 'BLOCKED', 'the preflight did not run')];
    }
    const unread = roots.filter((r) => !steps.some((s) => s.scope === r.label && s.outcome === 'ok'));
    if (unread.length > 0 || roots.length === 0) {
        out.push(
            c.fail('read.permitted', 'CONFIG', `not a listable directory: ${unread.map((r) => r.label).join(', ')}`, 'Check each root exists, is a directory and not a link, and is readable by the user the scanner runs as.'),
            c.skip('write.absent', 'BLOCKED', 'the roots could not all be listed'),
        );
        return out;
    }
    out.push(c.pass('read.permitted', `${roots.length} root${roots.length === 1 ? '' : 's'} listed`));
    const writable = roots.filter((r) => {
        try {
            fs.access(r.path, 2 /* W_OK */);
            return true;
        } catch {
            return false;
        }
    });
    out.push(
        writable.length > 0
            ? c.warn('write.absent', `writable by the scanner: ${writable.map((r) => r.label).join(', ')}`, 'Mount each root read-only.')
            : c.pass('write.absent', 'no root is writable by the scanner'),
    );
    return out;
}

function reportOf(estate: string | null, at: string, checks: readonly Check[]): DoctorReport {
    for (const c of checks) assertWellFormed(c);
    return {
        doctor: DOCTOR_SCHEMA,
        estate,
        at,
        scanner: { version: SCANNER_VERSION, manifestHash: scannerManifestHash() },
        ready: isReady(checks),
        counts: countsOf(checks),
        exitCode: doctorExitCode(checks),
        checks,
    };
}

/** Read and parse the configuration, or say why not: the issue paths, never a value. */
function loadConfig(fs: DoctorFs, path: string): { config: ScannerConfig } | { problem: string } {
    let text: string;
    try {
        text = fs.readFile(path).toString('utf8');
    } catch (err) {
        const code = (err as NodeJS.ErrnoException | null)?.code;
        return { problem: `the file could not be read (${typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'error'})` };
    }
    let json: unknown;
    try {
        json = JSON.parse(text);
    } catch {
        return { problem: 'the file is not JSON' };
    }
    try {
        return { config: parseScannerConfig(json) };
    } catch (err) {
        if (!(err instanceof ConfigError)) throw err;
        return { problem: err.issues.join('; ') };
    }
}

export async function runDoctor(deps: DoctorDeps): Promise<DoctorReport> {
    const fs = deps.fs ?? NODE_FS;
    const now = deps.now ?? Date.now;
    const env = deps.env;
    const nodeVersion = deps.nodeVersion ?? process.version;
    const uid = deps.uid === undefined ? (typeof process.getuid === 'function' ? process.getuid() : null) : deps.uid;
    const resolve = deps.resolveHost ?? resolveWithDns;
    const at = new Date(now()).toISOString();
    const local = scoped('local');

    const loaded = loadConfig(fs, deps.configPath);
    if ('problem' in loaded) {
        return reportOf(null, at, [
            local.fail('config.valid', 'CONFIG', loaded.problem, 'Correct the configuration; scanent init writes a valid one.'),
            ...LOCAL_CHECK_IDS.filter((id) => id !== 'config.valid').map((id) => local.skip(id, 'BLOCKED', 'the configuration could not be read')),
        ]);
    }
    const { config } = loaded;
    const wanted = deps.only === undefined || deps.only.length === 0 ? config.sources : config.sources.filter((s) => deps.only?.includes(s.kind));
    const targets = targetsOf(config, wanted);

    const secrets = checkSecretFiles(config, env, fs);
    const tls = checkTlsVerification(env);
    const customerHosts = [...new Set(targets.flatMap((t) => t.hosts.filter((h) => h.guard !== null).map((h) => h.host)))];

    // ─── The sources ───
    const sourceChecks: Check[] = [];
    const dates: string[] = [];
    const { sources } = buildSources({ ...config, sources: wanted }, secrets.resolved, { resolveHost: deps.resolveHost });
    const fetchImpl: FetchLike = deps.fetchImpl ?? ((url, init) => fetch(url, init));

    /** One source's preflight, in its own wire, time box and byte budget. A throw is the reader's fault, and still a failed read. */
    const stepsOf = new Map<HarnessSource, Promise<readonly ProbeStep[]>>();
    const runPreflight = (source: HarnessSource): Promise<readonly ProbeStep[]> => {
        let running = stepsOf.get(source);
        if (running === undefined) {
            const asOf = new Date(now());
            const deadline = asOf.getTime() + DOCTOR_PROBE_SECONDS * 1000;
            const wire = createSourceWire({ fetchImpl, deadline, now }, { source: DOCTOR_PROBE_BYTES });
            running = source.preflight({ asOf, deadline, now, ...wire }).catch((): readonly ProbeStep[] => [
                { id: 'read', what: 'the preflight', outcome: new SourceReadError('UNPARSEABLE', 'the preflight itself failed') },
            ]);
            stepsOf.set(source, running);
        }
        return running;
    };

    const perTarget = await Promise.all(
        targets.map(async (t): Promise<Check[]> => {
            const c = scoped(t.scope);
            const source = sources.find((s) => s.kind === t.kind);
            if (t.kind === 'code') {
                const roots = wanted.flatMap((s) => (s.kind === 'code' ? s.roots : []));
                return codeChecks(t, roots, source === undefined ? null : await runPreflight(source), fs);
            }
            const out: Check[] = [];
            // credential.present
            if (t.credential === null) {
                out.push(c.skip('credential.present', 'NOT_APPLICABLE', 'the server takes no token'));
            } else if (secrets.unresolved.has(t.credential)) {
                return [c.skip('credential.present', 'BLOCKED', `${t.credential} could not be read: see secret-files`), ...blockedAfter(t.scope, 'credential.present', `${t.credential} could not be read`)];
            } else if (!isSet(secrets.resolved[t.credential])) {
                return [
                    c.fail('credential.present', 'CREDENTIAL', `${t.credential} is not set`, `Set ${t.credential} or ${t.credential}_FILE.`),
                    ...blockedAfter(t.scope, 'credential.present', `${t.credential} is not set`),
                ];
            } else {
                out.push(c.pass('credential.present', t.credential));
            }
            // Nothing is sent, and no credential leaves, while certificate verification is off.
            if (tls.status === 'FAIL') return [...out, ...blockedAfter(t.scope, 'credential.present', 'certificate verification is off: see tls.verification')];
            // host.resolves
            const hosts = await hostCheck(t, env, nodeVersion, resolve);
            out.push(hosts);
            if (hosts.status === 'FAIL') return [...out, ...blockedAfter(t.scope, 'host.resolves', 'the host did not resolve')];
            if (source === undefined) return [...out, ...blockedAfter(t.scope, 'host.resolves', 'the source could not be constructed')];
            const all = await runPreflight(source);
            const steps = t.stepScope === undefined ? all : all.filter((s) => s.scope === t.stepScope);
            for (const s of steps) if (typeof s.observed?.date === 'string') dates.push(s.observed.date);
            return [...out, ...probeChecks(t, steps, env, nodeVersion)];
        }),
    );
    for (const checks of perTarget) sourceChecks.push(...checks);

    // The ingest: its use is a write (the post of a report), so doctor checks the key is there and sends nothing.
    const postsToInflect = hostsFor(config).some((e) => e.source === 'inflect');
    if (postsToInflect && config.inflect !== undefined && (deps.only === undefined || deps.only.length === 0)) {
        const c = scoped('inflect');
        const name = config.inflect.apiKeyEnv;
        const present = isSet(secrets.resolved[name]);
        sourceChecks.push(
            secrets.unresolved.has(name)
                ? c.skip('credential.present', 'BLOCKED', `${name} could not be read: see secret-files`)
                : present
                    ? c.pass('credential.present', name)
                    : c.fail('credential.present', 'CREDENTIAL', `${name} is not set`, `Set ${name} or ${name}_FILE.`),
            c.skip('post.permitted', 'NOT_OBSERVABLE', 'doctor does not post; the first scan shows whether the key may post'),
        );
    }

    // ─── The local checks, in the table's order ───
    const checks: Check[] = [
        local.pass('config.valid', `${config.sources.length} source${config.sources.length === 1 ? '' : 's'}`),
        checkConfigMode(fs, deps.configPath),
        checkSigningKey(config, secrets.resolved, secrets.unresolved),
        secrets.check,
        checkOutputDir(outputDirOf(config, deps.out ?? null), fs, uid),
        // The inventory's own capped reader in production; the seam only when a test supplies a file system.
        checkInventory(config, (c) => (deps.fs === undefined ? loadConfiguredInventory(c) : loadConfiguredInventory(c, { readFile: (p) => fs.readFile(p) }))),
        tls,
        checkExtraCa(env, fs),
        checkProxy(env, nodeVersion, hostsFor(config).length > 0),
        checkProxyCustomerHosts(env, nodeVersion, customerHosts),
        checkClock(dates, now()),
        tls.status === 'FAIL' ? local.skip('egress', config.egress === undefined ? 'NOT_APPLICABLE' : 'BLOCKED', config.egress === undefined ? 'the configuration has no egress block' : 'certificate verification is off') : await checkEgress(config, env, deps.egressProbe),
        ...sourceChecks,
    ];
    return reportOf(config.estate, at, checks);
}
