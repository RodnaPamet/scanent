/**
 * `scanent support-bundle`: one JSON document, `scanent-support/1`, that says
 * how a deployment is set up and how its last run went, for whoever is asked
 * to help with it.
 *
 * WHAT IT NEVER HOLDS. A credential's value: the command asks where each
 * credential comes from (`secretOrigin`) and never resolves one, so no secret
 * file is opened and no value is in memory to leak. A request or response
 * body. A finding's text. The whole document passes `assertNoSecretShape`
 * before a byte is written, and a document that holds a secret's shape is
 * refused, not trimmed.
 *
 * WHAT IT REPLACES UNLESS ASKED NOT TO. Everything that names the estate: the
 * estate label, hosts, labels, paths, the tenant, and every discovered id.
 * Each becomes a token, `<category>-<8 hex>`, made with a key that is drawn
 * for this one bundle and kept nowhere. The same name reads as the same token
 * throughout one bundle, so "the host that fails is the host of source 2" is
 * still said; two bundles cannot be matched to each other, and a token cannot
 * be turned back into the name. A doctor check's free text is left out in this
 * mode, because text cannot be proved clean of names; its scope, id, status
 * and class stay. `--include-identifiers` keeps the names and the text.
 *
 * WHAT IT READS. The configuration file; the environment's variable NAMES and
 * whether each is set; and, when the output directory holds one, the last
 * run's `latest.json`, `results.json` and `manifest.json`. It makes no network
 * request unless `--doctor` asks for the preflight, which is `scanent doctor`.
 */
import { createHmac, randomBytes } from 'crypto';
import { readFileSync, statSync } from 'fs';
import { join } from 'path';

import { HARNESS_CONTRACT_IDS } from '@scanent/contract/harness-contract-rules';
import { LADDER_VERSION } from '@scanent/contract/harness-contract';
import { stableJson } from '@scanent/report/render/results-json';
import { INVENTORY_SCHEMA_ID } from '@scanent/report/results/inventory';
import { RESULTS_SCHEMA } from '@scanent/report/results/types';

import { ConfigError, mcpTokenEnvNames, parseScannerConfig, sourceCredentialEnv, type ScannerConfig } from './config';
import { PROXY_CHECKS_ADDRESSES_ENV } from './customer-host';
import { outputDirOf } from './doctor/local';
import { DOCTOR_SCHEMA, type Check, type DoctorReport } from './doctor/types';
import { assertNoSecretShape, SCAN_ID_PATTERN } from './file-output';
import { hostsFor } from './hosts';
import { nodeHonoursEnvProxy, proxyInEffect, proxyVariableSet } from './proxy-env';
import { scannerManifestHash, SCANNER_VERSION } from './scanner-surface';
import { secretOrigin, type Env } from './secrets';

export const SUPPORT_SCHEMA = 'scanent-support/1';

/** The largest file of a last run this command reads. A results file over it is reported as too large, not read. */
export const MAX_SUPPORT_INPUT_BYTES = 64 * 1024 * 1024;

/** What an estate's name is replaced by. The category says what kind of thing it was. */
export type TokenCategory = 'estate' | 'host' | 'label' | 'path' | 'tenant' | 'agent' | 'scan' | 'credential-ref' | 'id';

export interface Identifiers {
    /** `REPLACED`: every name below is a token. `INCLUDED`: the names themselves. */
    readonly mode: 'REPLACED' | 'INCLUDED';
    /** The name, or its token. */
    of(category: TokenCategory, value: string): string;
}

/** The names as they are. */
export const includedIdentifiers: Identifiers = { mode: 'INCLUDED', of: (_category, value) => value };

/**
 * Tokens under a key. One key, one mapping: the same (category, value) is the
 * same token, and nothing but the key holder can produce it.
 */
export function replacedIdentifiers(key: Buffer): Identifiers {
    return {
        mode: 'REPLACED',
        of: (category, value) => `${category}-${createHmac('sha256', key).update(category).update('\0').update(value).digest('hex').slice(0, 8)}`,
    };
}

export interface SupportCredential {
    /** The environment variable the configuration names. A name, never a value. */
    readonly variable: string;
    readonly usedBy: string;
    /** Where the value would come from. `both` is refused at a scan. */
    readonly from: 'env' | 'file' | 'both' | 'absent';
}

export interface SupportSource {
    readonly kind: string;
    /** How many entries each list of the source's configuration holds (servers, roots, vaults). */
    readonly counts: Readonly<Record<string, number>>;
    readonly hosts: readonly { readonly host: string; readonly purpose: string; readonly named: 'fixed' | 'configured' }[];
}

export interface SupportConfig {
    readonly estate: string;
    readonly tenant: null | { readonly host: string; readonly slug: string };
    /** The outputs the configuration lists; null when it lists none (the default applies). */
    readonly outputs: null | readonly { readonly kind: string; readonly dir?: string; readonly retainRuns?: number | null }[];
    readonly scheduleEveryHours: number;
    readonly timeBoxSeconds: number;
    readonly egressProof: boolean;
    readonly inventory: null | 'json' | 'csv';
    readonly sources: readonly SupportSource[];
    readonly credentials: readonly SupportCredential[];
}

export interface SupportDoctorCheck {
    readonly scope: string;
    readonly id: string;
    readonly status: Check['status'];
    readonly class?: string;
    readonly cause?: string;
    /** Present only with identifiers included: the text may name a host or a path. */
    readonly detail?: string;
    readonly fix?: string;
}

export interface SupportLastRun {
    readonly scan: string;
    readonly asOf: string | null;
    readonly complete: boolean | null;
    readonly agentCount: number | null;
    /** Why the run's results could not be read; null when they were. */
    readonly resultsProblem: null | 'ABSENT' | 'TOO_LARGE' | 'NOT_JSON' | 'UNKNOWN_SCHEMA';
    readonly resultsSchema: string | null;
    readonly scanner: null | { readonly version: string; readonly manifestHash: string };
    readonly contract: string | null;
    readonly sources: readonly { readonly kind: string; readonly status: string; readonly reason: string | null; readonly rows: number | null; readonly agents: number | null }[];
    readonly counts: null | {
        readonly judged: number | null;
        readonly notJudged: number | null;
        readonly shortfall: number | null;
        readonly shadowAgents: number;
        readonly orphanCredentials: number;
        readonly findings: number;
        readonly findingsByCode: Readonly<Record<string, number>>;
    };
    readonly agents: readonly { readonly id: string; readonly via: readonly string[]; readonly judgement: string | null; readonly level: string | null }[];
    /** Each file of the run and its size, from the run's own manifest; empty when there is none. */
    readonly files: readonly { readonly name: string; readonly bytes: number }[];
    /** Not on disk: a run records neither. Named so that nobody looks for them. */
    readonly notRecorded: readonly ['exitCode', 'durations'];
}

export interface SupportBundle {
    readonly support: typeof SUPPORT_SCHEMA;
    readonly at: string;
    readonly identifiers: Identifiers['mode'];
    readonly versions: {
        readonly scanner: string;
        readonly manifestHash: string;
        readonly contracts: readonly string[];
        readonly ladder: string;
        readonly results: string;
        readonly inventory: string;
        readonly doctor: string;
        readonly node: string;
        readonly platform: string;
        readonly arch: string;
    };
    /** Null when the configuration could not be read; `configProblem` then says why. */
    readonly config: SupportConfig | null;
    readonly configProblem: string | null;
    readonly environment: {
        readonly httpsProxySet: boolean;
        readonly noProxySet: boolean;
        readonly nodeUseEnvProxy: boolean;
        readonly nodeHonoursEnvProxy: boolean;
        readonly proxyInEffect: boolean;
        readonly extraCaSet: boolean;
        readonly tlsVerificationOff: boolean;
        readonly proxyChecksAddresses: boolean;
        readonly egressAllowSet: boolean;
        readonly egressPrivateCidrAllowlistSet: boolean;
    };
    /** Null unless `--doctor` was given. */
    readonly doctor: null | {
        readonly ready: boolean;
        readonly exitCode: number;
        readonly counts: DoctorReport['counts'];
        readonly checks: readonly SupportDoctorCheck[];
    };
    /** Null when there is no file output, or its directory holds no `latest.json`. */
    readonly lastRun: SupportLastRun | null;
}

/** How files are read. A TEST SEAM: production uses the file system. */
export interface SupportFs {
    readFile(path: string): Buffer;
    /** The file's size in bytes. Throws when it is not there. */
    size(path: string): number;
}

const NODE_FS: SupportFs = { readFile: (p) => readFileSync(p), size: (p) => statSync(p).size };

export interface SupportBundleDeps {
    readonly configPath: string;
    readonly env: Env;
    /** The output directory to read the last run from, instead of the configuration's file output. */
    readonly runsDir?: string | null;
    readonly includeIdentifiers: boolean;
    /** The preflight to include: `runDoctor` bound to the same configuration. Absent, no request is made. */
    readonly doctor?: () => Promise<DoctorReport>;
    /** TEST SEAMS: production uses the file system, the clock, this process and fresh random bytes. */
    readonly fs?: SupportFs;
    readonly now?: () => number;
    readonly runtime?: { readonly node: string; readonly platform: string; readonly arch: string };
    readonly tokenKey?: Buffer;
}

const isSet = (v: string | undefined): boolean => typeof v === 'string' && v.trim() !== '';
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const rec = (v: unknown): Record<string, unknown> => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** The configuration, or the reason it could not be read. The reason is `doctor`'s: paths and codes, no value of the file. */
function loadConfig(fs: SupportFs, path: string): { readonly config: ScannerConfig } | { readonly problem: string } {
    let text: string;
    try {
        text = fs.readFile(path).toString('utf8');
    } catch (err) {
        const code = (err as NodeJS.ErrnoException | null)?.code;
        return { problem: `the file could not be read (${typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'error'})` };
    }
    let json: unknown;
    try {
        json = JSON.parse(text) as unknown;
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

function credentialsOf(config: ScannerConfig, env: Env): SupportCredential[] {
    const named: { variable: string; usedBy: string }[] = [{ variable: config.scanner.signingKeyEnv, usedBy: 'signing-key' }];
    if (config.inflect !== undefined) named.push({ variable: config.inflect.apiKeyEnv, usedBy: 'tenant' });
    for (const s of config.sources) {
        if (s.kind === 'code' || s.kind === 'inflect-register') continue;
        const variables = s.kind === 'mcp' ? mcpTokenEnvNames(s) : [sourceCredentialEnv(s)];
        for (const variable of variables) named.push({ variable, usedBy: s.kind });
    }
    return named.map(({ variable, usedBy }) => ({ variable, usedBy, from: secretOrigin(variable, env).from }));
}

function configSection(config: ScannerConfig, env: Env, ids: Identifiers): SupportConfig {
    const hosts = hostsFor(config);
    const host = (name: string, named: 'fixed' | 'configured') => (named === 'fixed' ? name : ids.of('host', name));
    return {
        estate: ids.of('estate', config.estate),
        tenant:
            config.inflect === undefined
                ? null
                : { host: ids.of('host', new URL(config.inflect.baseUrl).hostname), slug: ids.of('tenant', config.inflect.tenantSlug) },
        outputs:
            config.outputs === undefined
                ? null
                : config.outputs.map((o) => (o.kind === 'file' ? { kind: o.kind, dir: ids.of('path', o.dir), retainRuns: o.retainRuns ?? null } : { kind: o.kind })),
        scheduleEveryHours: config.schedule.everyHours,
        timeBoxSeconds: config.timeBoxSeconds,
        egressProof: config.egress !== undefined,
        inventory: config.inventory === undefined ? null : /\.csv$/i.test(config.inventory.path) ? 'csv' : 'json',
        sources: config.sources.map((s) => ({
            kind: s.kind,
            counts: Object.fromEntries(
                Object.entries(s)
                    .filter(([, v]) => Array.isArray(v))
                    .map(([k, v]) => [k, (v as unknown[]).length])
                    .sort(([a], [b]) => (a < b ? -1 : 1)),
            ),
            hosts: hosts.filter((h) => h.source === s.kind).map((h) => ({ host: host(h.host, h.named), purpose: h.purpose, named: h.named })),
        })),
        credentials: credentialsOf(config, env),
    };
}

/** A doctor scope is `local`, a source kind, or `<kind>:<label>`. The label is the estate's. */
function scopeOf(scope: string, ids: Identifiers): string {
    const at = scope.indexOf(':');
    return at < 0 ? scope : `${scope.slice(0, at)}:${ids.of('label', scope.slice(at + 1))}`;
}

function doctorSection(report: DoctorReport, ids: Identifiers): NonNullable<SupportBundle['doctor']> {
    return {
        ready: report.ready,
        exitCode: report.exitCode,
        counts: report.counts,
        checks: report.checks.map((c) => ({
            scope: scopeOf(c.scope, ids),
            id: c.id,
            status: c.status,
            ...(c.status === 'FAIL' ? { class: c.class } : {}),
            ...(c.status === 'SKIPPED' ? { cause: c.cause } : {}),
            ...(ids.mode === 'INCLUDED' ? { detail: c.detail, ...(c.status === 'FAIL' || c.status === 'WARN' ? { fix: c.fix } : {}) } : {}),
        })),
    };
}

/** A file's JSON, or why not. Never larger than the cap, and never a throw. */
function readJson(fs: SupportFs, path: string): { readonly value: unknown } | { readonly problem: 'ABSENT' | 'TOO_LARGE' | 'NOT_JSON' } {
    let bytes: Buffer;
    try {
        if (fs.size(path) > MAX_SUPPORT_INPUT_BYTES) return { problem: 'TOO_LARGE' };
        bytes = fs.readFile(path);
    } catch {
        return { problem: 'ABSENT' };
    }
    if (bytes.byteLength > MAX_SUPPORT_INPUT_BYTES) return { problem: 'TOO_LARGE' };
    try {
        return { value: JSON.parse(bytes.toString('utf8')) as unknown };
    } catch {
        return { problem: 'NOT_JSON' };
    }
}

/** A scan id is `<estate>-<stamp>-<8 hex>`: the estate in it is replaced, the stamp kept. */
function scanOf(scanId: string, ids: Identifiers): string {
    if (ids.mode === 'INCLUDED') return scanId;
    const stamp = SCAN_ID_PATTERN.exec(scanId)?.[1];
    return stamp === undefined ? ids.of('scan', scanId) : `${ids.of('scan', scanId)}-${stamp}`;
}

function lastRunSection(fs: SupportFs, dir: string, ids: Identifiers): SupportLastRun | null {
    const pointer = readJson(fs, join(dir, 'latest.json'));
    if ('problem' in pointer) return null;
    const latest = rec(pointer.value);
    const scanId = str(latest.scanId);
    // A pointer that names no run of this output names nothing this command will open.
    if (scanId === null || !SCAN_ID_PATTERN.test(scanId)) return null;
    const runDir = join(dir, 'runs', scanId);

    const manifest = readJson(fs, join(runDir, 'manifest.json'));
    const files =
        'problem' in manifest
            ? []
            : list(rec(manifest.value).files).flatMap((f) => {
                const name = str(rec(f).name);
                const bytes = num(rec(f).bytes);
                return name !== null && /^[a-z.-]{1,64}$/.test(name) && bytes !== null ? [{ name, bytes }] : [];
            });

    const base = {
        scan: scanOf(scanId, ids),
        asOf: str(latest.asOf),
        complete: bool(latest.complete),
        agentCount: num(latest.agentCount),
        files,
        notRecorded: ['exitCode', 'durations'] as const,
    };
    const none = { resultsSchema: null, scanner: null, contract: null, sources: [], counts: null, agents: [] };
    const read = readJson(fs, join(runDir, 'results.json'));
    if ('problem' in read) return { ...base, ...none, resultsProblem: read.problem };
    const results = rec(read.value);
    const schema = str(results.schema);
    // A results file of another schema is named and not read further: its members may mean something else.
    if (schema !== RESULTS_SCHEMA) return { ...base, ...none, resultsSchema: schema === null ? null : schema.slice(0, 64), resultsProblem: 'UNKNOWN_SCHEMA' };

    const scan = rec(results.scan);
    const scanner = rec(scan.scanner);
    const estate = rec(results.estate);
    const findings = list(results.findings);
    const findingsByCode: Record<string, number> = {};
    for (const f of findings) {
        const code = str(rec(f).code);
        if (code !== null && /^[A-Z_]{1,64}$/.test(code)) findingsByCode[code] = (findingsByCode[code] ?? 0) + 1;
    }
    const code = (v: unknown): string | null => {
        const s = str(v);
        return s !== null && /^[A-Za-z0-9_.:/-]{1,128}$/.test(s) ? s : null;
    };
    return {
        ...base,
        resultsProblem: null,
        resultsSchema: schema,
        scanner: { version: code(scanner.version) ?? 'unknown', manifestHash: code(scanner.manifestHash) ?? 'unknown' },
        contract: code(scan.contract),
        sources: list(results.sources).map((s) => {
            const source = rec(s);
            return {
                kind: code(source.kind) ?? 'unknown',
                status: code(source.status) ?? 'unknown',
                reason: code(source.reason),
                rows: num(source.rows),
                agents: num(source.agents),
            };
        }),
        counts: {
            judged: num(estate.judgedCount),
            notJudged: num(estate.notJudgedCount),
            shortfall: num(estate.shortfallCount),
            shadowAgents: list(estate.shadowAgents).length,
            orphanCredentials: list(estate.orphanCredentials).length,
            findings: findings.length,
            findingsByCode: Object.fromEntries(Object.entries(findingsByCode).sort(([a], [b]) => (a < b ? -1 : 1))),
        },
        agents: list(results.agents).flatMap((a) => {
            const agent = rec(a);
            const id = str(agent.discoveredId);
            if (id === null) return [];
            const judgement = rec(agent.judgement);
            return [
                {
                    id: ids.of('agent', id),
                    via: list(agent.discoveredVia).flatMap((v) => (code(v) === null ? [] : [code(v) as string])),
                    judgement: code(judgement.state),
                    level: code(judgement.level),
                },
            ];
        }),
    };
}

/** Build the bundle. Reads files, and the network only through `deps.doctor`. */
export async function buildSupportBundle(deps: SupportBundleDeps): Promise<SupportBundle> {
    const fs = deps.fs ?? NODE_FS;
    const env = deps.env;
    const runtime = deps.runtime ?? { node: process.version, platform: process.platform, arch: process.arch };
    const ids = deps.includeIdentifiers ? includedIdentifiers : replacedIdentifiers(deps.tokenKey ?? randomBytes(32));
    const loaded = loadConfig(fs, deps.configPath);
    const config = 'config' in loaded ? loaded.config : null;
    const runsDir = deps.runsDir ?? (config === null ? null : outputDirOf(config, null));
    const doctor = deps.doctor === undefined ? null : doctorSection(await deps.doctor(), ids);
    return {
        support: SUPPORT_SCHEMA,
        at: new Date((deps.now ?? Date.now)()).toISOString(),
        identifiers: ids.mode,
        versions: {
            scanner: SCANNER_VERSION,
            manifestHash: scannerManifestHash(),
            contracts: [...HARNESS_CONTRACT_IDS],
            ladder: LADDER_VERSION,
            results: RESULTS_SCHEMA,
            inventory: INVENTORY_SCHEMA_ID,
            doctor: DOCTOR_SCHEMA,
            node: runtime.node,
            platform: runtime.platform,
            arch: runtime.arch,
        },
        config: config === null ? null : configSection(config, env, ids),
        configProblem: 'problem' in loaded ? loaded.problem : null,
        environment: {
            httpsProxySet: proxyVariableSet(env),
            noProxySet: isSet(env.NO_PROXY) || isSet(env.no_proxy),
            nodeUseEnvProxy: env.NODE_USE_ENV_PROXY === '1',
            nodeHonoursEnvProxy: nodeHonoursEnvProxy(runtime.node),
            proxyInEffect: proxyInEffect(env, runtime.node),
            extraCaSet: isSet(env.NODE_EXTRA_CA_CERTS),
            tlsVerificationOff: env.NODE_TLS_REJECT_UNAUTHORIZED === '0',
            proxyChecksAddresses: env[PROXY_CHECKS_ADDRESSES_ENV] === '1',
            egressAllowSet: isSet(env.EGRESS_ALLOW),
            egressPrivateCidrAllowlistSet: isSet(env.EGRESS_PRIVATE_CIDR_ALLOWLIST),
        },
        doctor,
        lastRun: runsDir === null ? null : lastRunSection(fs, runsDir, ids),
    };
}

/**
 * The bundle as the text that is written. Refuses, with `OutputRefusedLocally`,
 * a bundle that holds a secret's shape anywhere, as data and as text: nothing
 * of it is written then.
 */
export function renderSupportBundle(bundle: SupportBundle): string {
    assertNoSecretShape(bundle, 'the support bundle');
    const text = stableJson(bundle);
    assertNoSecretShape(text, 'the support bundle');
    return text;
}
