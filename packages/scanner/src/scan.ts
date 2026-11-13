/**
 * ONE SCAN OF ONE ESTATE: read every configured source, build the report,
 * sign it, and (unless asked not to) post it.
 *
 * A source whose credential is missing from the environment is NOT dropped and
 * does not stop the scan: it is reported INCOMPLETE `AUTH_FAILED`, because the
 * estate has that source whether or not this run could read it, and a report
 * that left it out would describe a smaller estate than the one configured.
 * The signing key and the ingest key are different — without either there is
 * no report to send, so their absence stops the run.
 *
 * Sources are read in parallel, each in its own time box and byte budget, so
 * one slow inventory cannot starve another of its deadline.
 */
import { createPrivateKey, createPublicKey, randomBytes, type KeyObject } from 'crypto';

import type { HarnessReportBodyV4 } from '@rodnapamet/scanent-contract/harness-contract';
import type { IntegrationsReportBody } from '@rodnapamet/scanent-contract/integrations-contract';

import { DEFAULT_UNUSED_DAYS } from '@rodnapamet/scanent-contract/integrations-findings';

import { sourceCredentialEnv, type InflectConfig, type ScannerConfig } from './config';
import { customerHostCheckFor, type CustomerHostCheck, type ResolveHost } from './customer-host';
import { createSourceWire, type FetchLike } from './http';
import { buildIntegrationsReportBody, signIntegrationsReport } from './integrations-report';
import type { IntegrationsSource, IntegrationsSourceRead } from './integrations-source';
import type { ScannerLog } from './log';
import { postReport, type PostResult } from './post';
import { buildReportBody, signReport } from './report';
import { isAgentSourceKind } from './scanners';
import type { SourceNote } from '@scanent/report/results/types';

import {
    MAX_NOT_READ_LOCATIONS,
    sourceResult,
    SourceReadError,
    toolCallsOf,
    type HarnessSource,
    type NotReadLocation,
    type SourceRead,
} from './source';
import { azureKeyVaultSource } from './sources/azure-key-vault';
import { entraSource } from './sources/entra';
import { entraIntegrationsSource } from './sources/entra-integrations';
import { githubIntegrationsSource } from './sources/github-integrations';
import { oktaIntegrationsSource } from './sources/okta-integrations';
import { gcpServiceAccountSource } from './sources/gcp-service-accounts';
import { githubActionsSource } from './sources/github-actions';
import { proveEgress, type EgressProbe, type EgressProof } from './egress-proof';
import { inflectRegisterSource } from './sources/inflect-register';
import { langchainCodeSource } from './sources/langchain';
import { langSmithSource } from './sources/langsmith';
import { mcpSource } from './sources/mcp';
import { oktaSource } from './sources/okta';

export type Env = Readonly<Record<string, string | undefined>>;

export interface ScanDeps {
    readonly config: ScannerConfig;
    readonly env: Env;
    readonly log: ScannerLog;
    /** The wire. A TEST SEAM: the CLI never passes one, so production uses the global fetch. */
    readonly fetchImpl?: FetchLike;
    /** How a customer-named host is re-resolved. A TEST SEAM, like `fetchImpl`: production uses DNS. */
    readonly resolveHost?: ResolveHost;
    /** How the egress proof reaches the network. A TEST SEAM: production dials. */
    readonly egressProbe?: EgressProbe;
    readonly now?: () => number;
    /** The Node version, for whether a proxy is in effect. A TEST SEAM: production uses the process's own. */
    readonly nodeVersion?: string;
}

/** The Ed25519 signing key, from PKCS#8 PEM. Anything else is refused. */
export function loadSigningKey(pem: string): { privateKey: KeyObject; publicKey: KeyObject } {
    const privateKey = createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('the signing key must be Ed25519');
    return { privateKey, publicKey: createPublicKey(privateKey) };
}

/** What to do about a signing key that is not set. Names the variable and both ways to supply it, and no value. */
export function signingKeyMissing(name: string): string {
    return (
        `the signing key is not set (environment variable ${name}): set ${name} or ${name}_FILE ` +
        '(init writes the _FILE form in scanent.env; load that file), or make a key with scanent keygen'
    );
}

function requiredEnv(env: Env, name: string, what: string): string {
    const v = env[name];
    if (typeof v !== 'string' || v.trim() === '') throw new Error(`${what} is not set (environment variable ${name})`);
    return v;
}

/**
 * The configured sources, constructed — or, where a credential is missing,
 * already reported unreadable. The agent scanner's in `sources`, the
 * integrations scanner's in `integrations`: the two are read into two reports.
 */
export function buildSources(
    config: ScannerConfig,
    env: Env,
    seams: { readonly resolveHost?: ResolveHost; readonly checkHost?: CustomerHostCheck; readonly egressProof?: EgressProof } = {},
): {
    sources: HarnessSource[];
    unreadable: SourceRead[];
    integrations: { sources: IntegrationsSource[]; unreadable: IntegrationsSourceRead[] };
} {
    const sources: HarnessSource[] = [];
    const unreadable: SourceRead[] = [];
    const integrations: { sources: IntegrationsSource[]; unreadable: IntegrationsSourceRead[] } = { sources: [], unreadable: [] };
    for (const s of config.sources) {
        if (s.kind === 'entra-integrations') {
            const secret = env[s.clientSecretEnv];
            if (typeof secret !== 'string' || secret.trim() === '') {
                // A source that could not be read is reported, never omitted: so is its sign-in read, when it was asked for.
                integrations.unreadable.push({
                    kind: s.kind,
                    status: 'INCOMPLETE',
                    reason: 'AUTH_FAILED',
                    detail: 'credential not set',
                    rows: 0,
                    signInActivity: s.readSignInActivity ? { status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0 } : { status: 'NOT_READ' },
                    applications: [],
                });
            } else {
                integrations.sources.push(
                    entraIntegrationsSource({ directoryId: s.directoryId, clientId: s.clientId, clientSecret: secret.trim(), readSignInActivity: s.readSignInActivity }),
                );
            }
            continue;
        }
        if (s.kind === 'okta-integrations' || s.kind === 'github-integrations') {
            const name = s.kind === 'okta-integrations' ? s.apiTokenEnv : s.tokenEnv;
            const credential = env[name];
            if (typeof credential !== 'string' || credential.trim() === '') {
                // Reported, never omitted. A GitHub source that read nothing lists no webhook, and says it read none.
                integrations.unreadable.push({
                    kind: s.kind,
                    status: 'INCOMPLETE',
                    reason: 'AUTH_FAILED',
                    detail: 'credential not set',
                    rows: 0,
                    signInActivity: { status: 'NOT_READ' },
                    applications: [],
                    ...(s.kind === 'github-integrations' ? { webhooks: { read: false, hooks: [] } } : {}),
                });
            } else if (s.kind === 'okta-integrations') {
                integrations.sources.push(oktaIntegrationsSource({ orgUrl: s.orgUrl, apiToken: credential.trim() }));
            } else {
                integrations.sources.push(githubIntegrationsSource({ organization: s.organization, token: credential.trim() }));
            }
            continue;
        }
        if (s.kind === 'code') {
            // Reads files under its roots and holds no credential.
            sources.push(langchainCodeSource({ roots: s.roots, providerSdks: s.providerSdks }));
            continue;
        }
        if (s.kind === 'inflect-register') {
            // Read with the ingest key, from the tenant the report is posted to.
            // The schema refuses this source without an `inflect` block.
            const inflect = config.inflect;
            const apiKey = inflect === undefined ? undefined : env[inflect.apiKeyEnv];
            if (inflect === undefined || typeof apiKey !== 'string' || apiKey.trim() === '') {
                unreadable.push(sourceResult(s.kind, 0, [], new SourceReadError('AUTH_FAILED', 'the ingest key is not set')));
            } else {
                sources.push(
                    inflectRegisterSource({
                        baseUrl: inflect.baseUrl,
                        tenantSlug: inflect.tenantSlug,
                        apiKey: apiKey.trim(),
                        scannerAgentId: config.scanner.agentId,
                        egressProof: seams.egressProof,
                    }),
                );
            }
            continue;
        }
        if (s.kind === 'mcp') {
            // One optional read token per server. A server whose token is
            // configured and missing is unread; the others are still read.
            sources.push(
                mcpSource({
                    servers: s.servers.map((server) => {
                        const value = server.readTokenEnv === undefined ? undefined : env[server.readTokenEnv];
                        return {
                            label: server.label,
                            url: server.url,
                            agents: server.agents,
                            pinnedManifestHash: server.pinnedManifestHash ?? null,
                            token:
                                server.readTokenEnv === undefined
                                    ? null
                                    : typeof value === 'string' && value.trim() !== ''
                                        ? { value: value.trim() }
                                        : ('MISSING' as const),
                            egressPrivateCidrAllowlist: server.egressPrivateCidrAllowlist,
                        };
                    }),
                    resolveHost: seams.resolveHost,
                    checkHost: seams.checkHost,
                }),
            );
            continue;
        }
        const secret = env[sourceCredentialEnv(s)];
        if (typeof secret !== 'string' || secret.trim() === '') {
            unreadable.push(sourceResult(s.kind, 0, [], new SourceReadError('AUTH_FAILED', 'credential not set')));
            continue;
        }
        if (s.kind === 'entra-sp') {
            sources.push(
                entraSource({
                    directoryId: s.directoryId,
                    clientId: s.clientId,
                    clientSecret: secret.trim(),
                    includeThirdPartyApplications: s.includeThirdPartyApplications,
                }),
            );
        } else if (s.kind === 'okta-app') {
            sources.push(oktaSource({ orgUrl: s.orgUrl, apiToken: secret.trim(), ownerProfileKey: s.ownerProfileKey }));
        } else if (s.kind === 'cicd') {
            sources.push(githubActionsSource({ repositories: s.repositories, token: secret.trim() }));
        } else if (s.kind === 'gcp-sa') {
            sources.push(gcpServiceAccountSource({ projects: s.projects, keyJson: secret.trim() }));
        } else if (s.kind === 'runtime') {
            sources.push(
                langSmithSource({
                    endpoint: s.endpoint,
                    apiKey: secret.trim(),
                    workspaceId: s.workspaceId ?? null,
                    windowDays: s.windowDays,
                    readDeployments: s.readDeployments,
                    resolveHost: seams.resolveHost,
                    checkHost: seams.checkHost,
                }),
            );
        } else {
            sources.push(
                azureKeyVaultSource({
                    vaultUrls: s.vaultUrls,
                    directoryTenantId: s.directoryTenantId,
                    clientId: s.clientId,
                    clientSecret: secret.trim(),
                    principalTag: s.principalTag,
                    ownerTag: s.ownerTag,
                }),
            );
        }
    }
    return { sources, unreadable, integrations };
}

function scanIdFor(estate: string, asOf: Date): string {
    const stamp = asOf.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
    return `${estate}-${stamp}-${randomBytes(4).toString('hex')}`;
}

/** Read, build and sign. Returns the serialised report and the body it carries. */
/**
 * What the sources said about a read that stopped, beyond the reason the
 * signed report carries: for the local results. One note per source KIND, as
 * the report lists sources; two sources of one kind are joined.
 */
export function sourceNotesOf(reads: readonly SourceRead[]): readonly SourceNote[] {
    const byKind = new Map<string, { details: string[]; notRead: NotReadLocation[]; total: number }>();
    for (const r of reads) {
        if (r.status === 'COMPLETE') continue;
        const note = byKind.get(r.kind) ?? { details: [], notRead: [], total: 0 };
        if (r.detail !== undefined && !note.details.includes(r.detail)) note.details.push(r.detail);
        note.notRead.push(...(r.notRead ?? []));
        note.total += r.notReadTotal ?? 0;
        byKind.set(r.kind, note);
    }
    return [...byKind].map(([kind, note]) => ({
        kind,
        detail: note.details.length === 0 ? null : note.details.join('; '),
        notRead: note.notRead.slice(0, MAX_NOT_READ_LOCATIONS),
        notReadTotal: note.total,
    }));
}

/**
 * The integrations scanner's part of one run, present only when an
 * integrations source is configured: its signed report, its body, the
 * sources' own words about a read that stopped, and the window "unused" is
 * planned over.
 */
export interface IntegrationsScan {
    readonly raw: string;
    readonly body: IntegrationsReportBody;
    readonly sourceNotes: readonly SourceNote[];
    readonly unusedDays: number;
}

/** The agent scanner's part of one run: its signed report, its body, and the sources' own words about a read that stopped. */
export interface AgentScan {
    readonly raw: string;
    readonly body: HarnessReportBodyV4;
    readonly sourceNotes: readonly SourceNote[];
}

export interface ScanResult extends AgentScan {
    /** Absent unless an integrations source is configured: an agents-only run is what it was before scanners. */
    readonly integrations?: IntegrationsScan;
}

/**
 * One run of every scanner the configuration's sources call for. Which
 * scanners run follows from the sources configured: `agents` is null when no
 * agent source is, and `integrations` when no integrations source is. One
 * scan id and one moment for both.
 */
export interface RunScan {
    readonly scanId: string;
    readonly asOf: string;
    readonly agents: AgentScan | null;
    readonly integrations: IntegrationsScan | null;
}

/**
 * What the integrations sources said beyond the report, one note per kind, for
 * the local results: why a read stopped, and what the source left out on
 * purpose (the product's own applications), with how many.
 */
export function integrationsSourceNotesOf(reads: readonly IntegrationsSourceRead[]): readonly SourceNote[] {
    return reads
        .filter((r) => r.status !== 'COMPLETE' || r.signInActivity.status === 'INCOMPLETE' || r.excluded !== undefined)
        .map((r) => {
            const details = [
                ...(r.status === 'INCOMPLETE' && r.detail !== undefined ? [r.detail] : []),
                ...(r.signInActivity.status === 'INCOMPLETE' && r.signInActivity.detail !== undefined ? [`sign-in activity: ${r.signInActivity.detail}`] : []),
            ];
            return {
                kind: r.kind,
                detail: details.length === 0 ? null : details.join('; '),
                notRead: [],
                notReadTotal: 0,
                ...(r.excluded === undefined ? {} : { excluded: { count: r.excluded.count, what: r.excluded.what } }),
            };
        });
}

/** One scan of the agent scanner, with the integrations part when configured. Refuses a configuration with no agent source. */
export async function runScan(deps: ScanDeps): Promise<ScanResult> {
    const run = await runScanAll(deps);
    if (run.agents === null) throw new Error('the configuration has no agent source: the agent scanner did not run');
    return run.integrations === null ? run.agents : { ...run.agents, integrations: run.integrations };
}

/** Read every configured source of every scanner, build each scanner's report and sign it with the one key. */
export async function runScanAll(deps: ScanDeps): Promise<RunScan> {
    const { config, env, log } = deps;
    const now = deps.now ?? Date.now;
    const fetchImpl: FetchLike = deps.fetchImpl ?? ((url, init) => fetch(url, init));
    const pem = env[config.scanner.signingKeyEnv];
    if (typeof pem !== 'string' || pem.trim() === '') throw new Error(signingKeyMissing(config.scanner.signingKeyEnv));
    const keys = loadSigningKey(pem);

    const asOf = new Date(now());
    const deadline = asOf.getTime() + config.timeBoxSeconds * 1000;
    // The egress proof, once per scan and before any source reads, so a scan
    // taken outside its confinement says so in the same report.
    const egressProof = config.egress && config.inflect
        ? await proveEgress({
              proxyUrl: config.egress.proxyUrl,
              allowedHost: new URL(config.inflect.baseUrl).hostname,
              canaryHost: config.egress.canaryHost,
              env,
              probe: deps.egressProbe,
          })
        : undefined;
    if (egressProof) {
        if (egressProof.met) log.info('egress proven', {});
        else log.warn('egress not proven', { failed: egressProof.failed });
    }
    // A host the estate names is resolved and checked before each request. Through a
    // proxy that check binds this machine's resolver and not the proxy's, unless the
    // proxy is scanent's own, which checks the address it dials: either way, say so once.
    const checkHost = customerHostCheckFor(env, deps.nodeVersion ?? process.version, (host, checkedByProxy) => {
        if (checkedByProxy) log.info('customer host checked by the egress proxy', { host });
        else log.warn('customer host reached through a proxy', { host, note: "the address check binds this machine's resolver, not the proxy's" });
    });
    const { sources, unreadable, integrations } = buildSources(config, env, { resolveHost: deps.resolveHost, checkHost, egressProof });

    // Every source of every scanner in parallel, each in its own wire, time box and byte budget.
    const integrationReadsPending = Promise.all(
        integrations.sources.map(async (source): Promise<IntegrationsSourceRead> => {
            const wire = createSourceWire({ fetchImpl, deadline, now });
            try {
                return await source.read({ asOf, deadline, now, ...wire });
            } catch {
                return {
                    kind: source.kind,
                    status: 'INCOMPLETE',
                    reason: 'UNREACHABLE',
                    detail: 'the reader stopped on an error of its own',
                    rows: 0,
                    signInActivity: { status: 'NOT_READ' },
                    applications: [],
                    ...(source.kind === 'github-integrations' ? { webhooks: { read: false, hooks: [] } } : {}),
                };
            }
        }),
    );
    const reads = await Promise.all(
        sources.map(async (source) => {
            const { http, tokens, mcp, register, openshell } = createSourceWire({ fetchImpl, deadline, now });
            try {
                return await source.read({ asOf, http, tokens, mcp, register, openshell, deadline, now });
            } catch (err) {
                return sourceResult(source.kind, 0, [], err);
            }
        }),
    );
    const integrationReads = [...(await integrationReadsPending), ...integrations.unreadable];

    for (const r of [...reads, ...unreadable]) {
        const fields = { source: r.kind, status: r.status, rows: r.rows, principals: r.observations.length, toolCalls: toolCallsOf(r) };
        if (r.status === 'COMPLETE') log.info('source read', fields);
        else {
            log.warn('source incomplete', { ...fields, reason: r.reason ?? null, detail: r.detail ?? null });
            for (const place of r.notRead ?? []) log.warn('not read', { source: r.kind, where: place.where, reason: place.reason });
            const unlisted = (r.notReadTotal ?? 0) - (r.notRead ?? []).length;
            if (unlisted > 0) log.warn('not read: more places than are listed', { source: r.kind, unlisted });
        }
        // The listing hash is what an estate pins a server to: the log is where
        // the operator reads it. The label is the estate's own; the URL is not logged.
        for (const server of r.mcpServers ?? []) {
            log.info('mcp server read', { server: server.label, tools: server.tools.length, manifestHash: server.manifestHash });
        }
    }

    for (const r of integrationReads) {
        const read = { source: r.kind, status: r.status, rows: r.rows, applications: r.applications.length, signInActivity: r.signInActivity.status };
        if (r.status === 'COMPLETE') log.info('integrations source read', read);
        else log.warn('integrations source incomplete', { ...read, reason: r.reason ?? null, detail: r.detail ?? null });
        if (r.signInActivity.status === 'INCOMPLETE') log.warn('sign-in activity incomplete', { source: r.kind, reason: r.signInActivity.reason, detail: r.signInActivity.detail ?? null });
    }

    const identity = { scanId: scanIdFor(config.estate, asOf), asOf, scannerAgentId: config.scanner.agentId };
    // The agent scanner runs when an agent source is configured: an agent source
    // whose credential is missing still counts, and is reported unreadable.
    const agentsConfigured = config.sources.some((s) => isAgentSourceKind(s.kind));
    let agents: AgentScan | null = null;
    if (agentsConfigured) {
        const body = buildReportBody(identity, [...reads, ...unreadable]);
        const raw = signReport(body, keys);
        log.info('report signed', { scan: body.scan.id, agents: body.agents.length, sources: body.population.sources.length });
        agents = { raw, body, sourceNotes: sourceNotesOf([...reads, ...unreadable]) };
    }
    if (integrationReads.length === 0) return { scanId: identity.scanId, asOf: asOf.toISOString(), agents, integrations: null };

    // One report per scanner: the same key, the same scan id.
    const integrationsBody = buildIntegrationsReportBody(identity, integrationReads);
    const integrationsRaw = signIntegrationsReport(integrationsBody, keys);
    log.info('integrations report signed', { scan: integrationsBody.scan.id, applications: integrationsBody.applications.length, sources: integrationsBody.sources.length });
    const unusedDays = config.sources.find((s) => s.kind === 'entra-integrations')?.unusedDays;
    return {
        scanId: identity.scanId,
        asOf: asOf.toISOString(),
        agents,
        integrations: {
            raw: integrationsRaw,
            body: integrationsBody,
            sourceNotes: integrationsSourceNotesOf(integrationReads),
            unusedDays: unusedDays ?? DEFAULT_UNUSED_DAYS,
        },
    };
}

/** The `inflect` block and the ingest key it names, or a refusal that names what is missing. */
export function ingestTarget(config: ScannerConfig, env: Env): { inflect: InflectConfig; apiKey: string } {
    if (config.inflect === undefined) throw new Error('the configuration has no inflect block to post to');
    return { inflect: config.inflect, apiKey: requiredEnv(env, config.inflect.apiKeyEnv, 'the ingest API key') };
}

/** Post one signed report to the tenant's ingest, and log the answer. */
export async function postSignedReport(
    deps: Pick<ScanDeps, 'fetchImpl' | 'log'>,
    target: { readonly inflect: InflectConfig; readonly apiKey: string },
    scan: { readonly raw: string; readonly body: HarnessReportBodyV4 },
): Promise<PostResult> {
    const result = await postReport({
        baseUrl: target.inflect.baseUrl,
        tenantSlug: target.inflect.tenantSlug,
        apiKey: target.apiKey,
        raw: scan.raw,
        fetchImpl: deps.fetchImpl ?? ((url, init) => fetch(url, init)),
    });
    if (result.ok) {
        deps.log.info('report ingested', { scan: scan.body.scan.id, complete: result.complete, agents: result.agentCount });
    } else {
        deps.log.error('report refused', { scan: scan.body.scan.id, status: result.status, refusal: result.refusal });
    }
    return result;
}

/** One scheduled run: scan, then post to the tenant's ingest. */
export async function scanAndPost(deps: ScanDeps): Promise<PostResult> {
    // The key is asked for before the scan: without it there is nowhere to send a report.
    const target = ingestTarget(deps.config, deps.env);
    return postSignedReport(deps, target, await runScan(deps));
}
