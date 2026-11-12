/**
 * `scanent support-bundle`: what the document holds, what it never holds, and
 * what it replaces unless told not to.
 *
 * The estate is the fake one every source suite uses (`helpers/estate-world`),
 * scanned for real into a temporary output directory, so the last run the
 * bundle reads is one the scanner wrote.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { HARNESS_CONTRACT_IDS } from '@rodnapamet/scanent-contract/harness-contract-rules';
import { RESULTS_SCHEMA } from '@scanent/report/results/types';

import { HELP, main } from '../src/cli';
import { parseScannerConfig } from '../src/config';
import type { DoctorReport } from '../src/doctor/types';
import { OutputRefusedLocally } from '../src/file-output';
import { hostsFor } from '../src/hosts';
import { scanAndDeliver } from '../src/outputs';
import { scannerManifestHash, SCANNER_VERSION } from '../src/scanner-surface';
import {
    buildSupportBundle,
    includedIdentifiers,
    MAX_SUPPORT_INPUT_BYTES,
    renderSupportBundle,
    replacedIdentifiers,
    SUPPORT_SCHEMA,
    type SupportBundle,
    type SupportFs,
} from '../src/support-bundle';
import { NEVER_REPORTED } from './helpers/agent-harness-source-fakes';
import { createEstateWorld, ESTATE_SOURCES, estateConfig, estateEnv, PUBLIC_RESOLVER } from './helpers/estate-world';
import { CANARIES, capturedLog, configJson, ENV, EXAMPLE_AGENT } from './helpers/output-fixtures';

const NOW = Date.UTC(2026, 10, 12, 9, 0, 0);
const RUNTIME = { node: 'v24.1.0', platform: 'linux', arch: 'x64' };

let dir: string;
let outDir: string;

beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-support-'));
    outDir = path.join(dir, 'out');
});
afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
});

function writeConfig(json: unknown, name = 'config.json'): string {
    const p = path.join(dir, name);
    fs.writeFileSync(p, typeof json === 'string' ? json : JSON.stringify(json));
    return p;
}

/** The fake estate, every network source and the code source, with a file output. */
function estateJson(): Record<string, unknown> {
    const { 'inflect-register': register, ...rest } = ESTATE_SOURCES;
    return estateConfig([...Object.values(rest), register], { outputs: [{ kind: 'file', dir: outDir }] });
}

/** One real scan of the fake estate into `outDir`. */
async function scanEstate(): Promise<void> {
    const world = createEstateWorld();
    const config = parseScannerConfig(estateJson());
    const result = await scanAndDeliver({
        config,
        env: estateEnv(),
        log: capturedLog().log,
        outputs: [{ kind: 'file', dir: outDir }],
        fetchImpl: world.fetchImpl,
        resolveHost: PUBLIC_RESOLVER,
        now: () => NOW,
    });
    expect(result.ok).toBe(true);
}

const DOCTOR: DoctorReport = {
    doctor: 'scanent-doctor/1',
    estate: 'acme-prod',
    at: new Date(NOW).toISOString(),
    scanner: { version: SCANNER_VERSION, manifestHash: scannerManifestHash() },
    ready: false,
    counts: { PASS: 1, WARN: 1, FAIL: 1, SKIPPED: 1 },
    exitCode: 6,
    checks: [
        { scope: 'local', id: 'config.valid', status: 'PASS', detail: '9 sources' },
        { scope: 'mcp:crm', id: 'reachable', status: 'FAIL', class: 'NETWORK', detail: 'mcp.acme.example gave no answer', fix: 'Open TCP 443 to mcp.acme.example.' },
        { scope: 'okta-app', id: 'read.permitted', status: 'WARN', detail: 'acme.okta.com answered with fewer scopes', fix: 'Grant the read scope.' },
        { scope: 'mcp:tickets', id: 'authenticated', status: 'SKIPPED', cause: 'BLOCKED', detail: 'the host did not resolve' },
    ],
};

const build = (over: Partial<Parameters<typeof buildSupportBundle>[0]> = {}): Promise<SupportBundle> =>
    buildSupportBundle({ env: estateEnv(), includeIdentifiers: false, now: () => NOW, runtime: RUNTIME, ...over, configPath: over.configPath ?? writeConfig(estateJson()) });

/** Every string of a JSON value: keys and values. */
function stringsOf(node: unknown): string[] {
    if (typeof node === 'string') return [node];
    if (Array.isArray(node)) return node.flatMap(stringsOf);
    if (node !== null && typeof node === 'object') return Object.entries(node).flatMap(([k, v]) => [k, ...stringsOf(v)]);
    return [];
}

describe('the document', () => {
    it('is scanent-support/1, with exactly these members', async () => {
        await scanEstate();
        const bundle = await build();
        expect(Object.keys(bundle).sort()).toEqual(['at', 'config', 'configProblem', 'doctor', 'environment', 'identifiers', 'lastRun', 'support', 'versions']);
        expect(bundle.support).toBe(SUPPORT_SCHEMA);
        expect(SUPPORT_SCHEMA).toBe('scanent-support/1');
        expect(bundle.at).toBe(new Date(NOW).toISOString());
        expect(bundle.identifiers).toBe('REPLACED');
        expect(bundle.configProblem).toBeNull();
        expect(bundle.doctor).toBeNull();
    });

    it('names the versions a supporter asks for first', async () => {
        const { versions } = await build();
        expect(versions).toEqual({
            scanner: SCANNER_VERSION,
            manifestHash: scannerManifestHash(),
            contracts: [...HARNESS_CONTRACT_IDS],
            ladder: expect.stringMatching(/\S/),
            results: RESULTS_SCHEMA,
            inventory: 'scanent-inventory/2',
            doctor: 'scanent-doctor/1',
            node: 'v24.1.0',
            platform: 'linux',
            arch: 'x64',
        });
    });

    it('gives the shape of the configuration: kinds, counts, outputs, schedule, and where each credential would come from', async () => {
        const { config, doctor } = await build({
            env: { ...estateEnv(), OKTA_API_TOKEN: undefined, GCP_SCANNER_KEY: undefined, GCP_SCANNER_KEY_FILE: '/run/secrets/gcp', MCP_TICKETS_TOKEN_FILE: '/run/secrets/mcp' },
            doctor: async () => DOCTOR,
        });
        expect(config).not.toBeNull();
        expect(config?.sources.map((s) => s.kind)).toEqual(['entra-sp', 'okta-app', 'vault', 'cicd', 'gcp-sa', 'runtime', 'mcp', 'code', 'inflect-register']);
        const counts = Object.fromEntries((config?.sources ?? []).map((s) => [s.kind, s.counts]));
        expect(counts.mcp).toEqual({ servers: 2 });
        expect(counts.code).toEqual({ roots: 1 });
        expect(counts.vault).toEqual({ vaultUrls: 1 });
        expect(counts.cicd).toEqual({ repositories: 1 });
        expect(counts['okta-app']).toEqual({});
        expect(config?.outputs).toEqual([{ kind: 'file', dir: expect.stringMatching(/^path-[0-9a-f]{8}$/), retainRuns: null }]);
        expect(config?.scheduleEveryHours).toBe(24);
        expect(config?.timeBoxSeconds).toBe(600);
        expect(config?.egressProof).toBe(false);
        expect(config?.inventory).toBeNull();
        // Names, and where from. One of each answer.
        const from = Object.fromEntries((config?.credentials ?? []).map((c) => [c.variable, c.from]));
        // The token the same bundle gives the label `tickets`, read off a doctor scope.
        const mcpScope = doctor?.checks[3].scope ?? '';
        expect(from).toEqual({
            SCANNER_SIGNING_KEY: 'env',
            INFLECT_INGEST_KEY: 'env',
            ENTRA_CLIENT_SECRET: 'env',
            OKTA_API_TOKEN: 'absent',
            AZURE_CLIENT_SECRET: 'env',
            GITHUB_READ_TOKEN: 'env',
            GCP_SCANNER_KEY: 'file',
            LANGSMITH_API_KEY: 'env',
            // `MCP_TICKETS_TOKEN` is the name `init` derives from the server's label, so the label in it is a token too.
            [`MCP_${mcpScope.slice('mcp:'.length)}_TOKEN`]: 'both',
        });
        expect(mcpScope).toMatch(/^mcp:label-[0-9a-f]{8}$/);
        expect(JSON.stringify(config)).not.toMatch(/tickets/i);
        // A name the operator chose is theirs and is kept, and with the names asked for the derived one is kept as well.
        const own = structuredClone(estateJson());
        const mcp = (own.sources as { kind: string; servers?: { readTokenEnv?: string }[] }[]).find((x) => x.kind === 'mcp');
        const server = mcp?.servers?.find((x) => x.readTokenEnv !== undefined);
        if (server === undefined) throw new Error('the fake estate has an MCP server with a read token');
        server.readTokenEnv = 'OUR_OWN_NAME';
        const chosen = await build({ configPath: writeConfig(own, 'own.json') });
        expect(chosen.config?.credentials.map((c) => c.variable)).toContain('OUR_OWN_NAME');
        const included = await build({ includeIdentifiers: true });
        expect(included.config?.credentials.map((c) => c.variable)).toContain('MCP_TICKETS_TOKEN');
        expect((config?.credentials ?? []).map((c) => c.usedBy)).toEqual(['signing-key', 'tenant', 'entra-sp', 'okta-app', 'vault', 'cicd', 'gcp-sa', 'runtime', 'mcp']);
        // A host fixed by the product is named; one the estate names is a token.
        const hosts = (config?.sources ?? []).flatMap((s) => s.hosts);
        expect(hosts.filter((h) => h.named === 'fixed').map((h) => h.host)).toEqual(expect.arrayContaining(['graph.microsoft.com', 'api.github.com']));
        for (const h of hosts.filter((h) => h.named === 'configured')) expect(h.host).toMatch(/^host-[0-9a-f]{8}$/);
    });

    it('says what the environment sets, by presence only', async () => {
        const off = (await build({ env: {} })).environment;
        expect(off).toEqual({
            httpsProxySet: false,
            noProxySet: false,
            nodeUseEnvProxy: false,
            nodeHonoursEnvProxy: true,
            proxyInEffect: false,
            extraCaSet: false,
            tlsVerificationOff: false,
            proxyChecksAddresses: false,
            egressAllowSet: false,
            egressPrivateCidrAllowlistSet: false,
        });
        const on = await build({
            env: {
                HTTPS_PROXY: 'http://user:proxy-password@proxy.acme.internal:3128',
                NO_PROXY: 'mcp.acme.example',
                NODE_USE_ENV_PROXY: '1',
                NODE_EXTRA_CA_CERTS: '/etc/acme/ca.pem',
                NODE_TLS_REJECT_UNAUTHORIZED: '0',
                EGRESS_PROXY_CHECKS_ADDRESSES: '1',
                EGRESS_ALLOW: 'mcp.acme.example',
                EGRESS_PRIVATE_CIDR_ALLOWLIST: '10.20.0.0/16',
            },
        });
        expect(Object.values(on.environment)).toEqual(new Array(10).fill(true));
        // Presence only: not the proxy, its password, the CA's path, a host or a range.
        const text = JSON.stringify(on);
        for (const value of ['proxy-password', 'proxy.acme.internal', '/etc/acme/ca.pem', '10.20.0.0', '3128']) expect(text).not.toContain(value);
        expect((await build({ env: {}, runtime: { ...RUNTIME, node: 'v22.11.0' } })).environment.nodeHonoursEnvProxy).toBe(false);
    });
});

describe('the last run', () => {
    it('is read from the output directory the configuration names: sources, counts, files', async () => {
        await scanEstate();
        const { lastRun } = await build();
        expect(lastRun).not.toBeNull();
        expect(lastRun?.resultsProblem).toBeNull();
        expect(lastRun?.resultsSchema).toBe(RESULTS_SCHEMA);
        expect(lastRun?.scan).toMatch(/^scan-[0-9a-f]{8}-20261112T090000Z$/);
        expect(lastRun?.asOf).toBe(new Date(NOW).toISOString());
        expect(lastRun?.scanner).toEqual({ version: SCANNER_VERSION, manifestHash: scannerManifestHash() });
        expect(lastRun?.contract).toBe(HARNESS_CONTRACT_IDS[HARNESS_CONTRACT_IDS.length - 1]);
        expect(lastRun?.sources.map((s) => s.kind).sort()).toEqual(['cicd', 'code', 'entra-sp', 'gcp-sa', 'inflect-register', 'mcp', 'okta-app', 'runtime', 'vault']);
        for (const s of lastRun?.sources ?? []) {
            expect(['COMPLETE', 'INCOMPLETE']).toContain(s.status);
            expect(s.status === 'COMPLETE' ? s.reason : typeof s.reason).toBe(s.status === 'COMPLETE' ? null : 'string');
        }
        expect(lastRun?.agentCount).toBeGreaterThan(0);
        expect(lastRun?.agents).toHaveLength(lastRun?.agentCount ?? -1);
        for (const a of lastRun?.agents ?? []) expect(a.id).toMatch(/^agent-[0-9a-f]{8}$/);
        expect(lastRun?.counts?.findings).toBeGreaterThan(0);
        expect(Object.values(lastRun?.counts?.findingsByCode ?? {}).reduce((a, b) => a + b, 0)).toBe(lastRun?.counts?.findings);
        expect(lastRun?.files.map((f) => f.name).sort()).toEqual(['agents.csv', 'findings.csv', 'report.signed.json', 'results.json', 'summary.html']);
        for (const f of lastRun?.files ?? []) expect(f.bytes).toBeGreaterThan(0);
        // A run records neither on disk, and the bundle says so instead of leaving a gap.
        expect(lastRun?.notRecorded).toEqual(['exitCode', 'durations']);
    });

    it('is null, not an error, with no output directory, an empty one, or no file output at all', async () => {
        expect((await build()).lastRun).toBeNull();
        fs.mkdirSync(outDir);
        expect((await build()).lastRun).toBeNull();
        const { outputs: _outputs, ...noOutput } = estateJson();
        expect((await build({ configPath: writeConfig(noOutput, 'no-output.json') })).lastRun).toBeNull();
    });

    it('--runs reads another directory than the configuration names', async () => {
        await scanEstate();
        const elsewhere = path.join(dir, 'elsewhere');
        fs.renameSync(outDir, elsewhere);
        expect((await build()).lastRun).toBeNull();
        expect((await build({ runsDir: elsewhere })).lastRun?.agentCount).toBeGreaterThan(0);
    });

    it('opens nothing a pointer names outside the runs of this output', async () => {
        fs.mkdirSync(outDir);
        const read: string[] = [];
        const recording: SupportFs = {
            readFile: (p) => (read.push(p), fs.readFileSync(p)),
            size: (p) => (read.push(p), fs.statSync(p).size),
        };
        const configPath = writeConfig(estateJson());
        for (const scanId of ['../../../etc', '/etc/passwd', 'acme-prod-20261112T090000Z-zzzzzzzz', '', 7]) {
            fs.writeFileSync(path.join(outDir, 'latest.json'), JSON.stringify({ scanId, dir: 'runs/x' }));
            expect((await build({ configPath, fs: recording })).lastRun).toBeNull();
        }
        fs.writeFileSync(path.join(outDir, 'latest.json'), 'not json');
        expect((await build({ configPath, fs: recording })).lastRun).toBeNull();
        expect([...new Set(read)].sort()).toEqual([configPath, path.join(outDir, 'latest.json')].sort());
    });

    it('names a results file it cannot use, and reads nothing from it', async () => {
        await scanEstate();
        const scanId = (JSON.parse(fs.readFileSync(path.join(outDir, 'latest.json'), 'utf8')) as { scanId: string }).scanId;
        const results = path.join(outDir, 'runs', scanId, 'results.json');
        const original = fs.readFileSync(results, 'utf8');
        const withResults = async (text: string | null) => {
            fs.chmodSync(results, 0o640);
            if (text === null) fs.rmSync(results);
            else fs.writeFileSync(results, text);
            return (await build()).lastRun;
        };
        const other = await withResults(original.replace(`"schema": "${RESULTS_SCHEMA}"`, '"schema": "scanent-results/2"'));
        expect(other).toMatchObject({ resultsProblem: 'UNKNOWN_SCHEMA', resultsSchema: 'scanent-results/2', sources: [], agents: [], counts: null, scanner: null });
        expect(await withResults('{"schema": 7}')).toMatchObject({ resultsProblem: 'UNKNOWN_SCHEMA', resultsSchema: null });
        expect(await withResults('{ not json')).toMatchObject({ resultsProblem: 'NOT_JSON', sources: [] });
        expect(await withResults(null)).toMatchObject({ resultsProblem: 'ABSENT', sources: [] });
        // The pointer's own facts are still given.
        expect((await build()).lastRun?.agentCount).toBeGreaterThan(0);

        fs.writeFileSync(results, original);
        const big: SupportFs = { readFile: (p) => fs.readFileSync(p), size: (p) => (p === results ? MAX_SUPPORT_INPUT_BYTES + 1 : fs.statSync(p).size) };
        expect((await build({ fs: big })).lastRun).toMatchObject({ resultsProblem: 'TOO_LARGE', sources: [] });
        // A file that grew after its size was read is refused by what was read.
        const grew: SupportFs = { readFile: (p) => (p === results ? Buffer.alloc(MAX_SUPPORT_INPUT_BYTES + 1, 0x20) : fs.readFileSync(p)), size: () => 10 };
        expect((await build({ fs: grew })).lastRun).toMatchObject({ resultsProblem: 'TOO_LARGE' });

        fs.rmSync(path.join(outDir, 'runs', scanId, 'manifest.json'));
        expect((await build()).lastRun?.files).toEqual([]);
    });

    it('takes only well-formed members from a results file whose members are not what they should be', async () => {
        await scanEstate();
        const scanId = (JSON.parse(fs.readFileSync(path.join(outDir, 'latest.json'), 'utf8')) as { scanId: string }).scanId;
        const results = path.join(outDir, 'runs', scanId, 'results.json');
        fs.chmodSync(results, 0o640);
        fs.writeFileSync(
            results,
            JSON.stringify({
                schema: RESULTS_SCHEMA,
                scan: 'not an object',
                sources: [null, 7, { kind: 'a kind with spaces', status: ['COMPLETE'], reason: 9, rows: '4', agents: Number.NaN }],
                estate: [],
                agents: [null, { discoveredId: 7 }, { discoveredId: 'okta:app:0oa1', discoveredVia: ['okta-app', 'has space', 3], judgement: null }],
                findings: [{ code: 'lower case' }, { code: 'SHADOW_AGENT' }, 'x'],
            }),
        );
        const lastRun = (await build({ includeIdentifiers: true })).lastRun;
        expect(lastRun?.scanner).toEqual({ version: 'unknown', manifestHash: 'unknown' });
        expect(lastRun?.contract).toBeNull();
        expect(lastRun?.sources).toEqual([
            { kind: 'unknown', status: 'unknown', reason: null, rows: null, agents: null },
            { kind: 'unknown', status: 'unknown', reason: null, rows: null, agents: null },
            { kind: 'unknown', status: 'unknown', reason: null, rows: null, agents: null },
        ]);
        expect(lastRun?.agents).toEqual([{ id: 'okta:app:0oa1', via: ['okta-app'], judgement: null, level: null }]);
        expect(lastRun?.counts).toEqual({ judged: null, notJudged: null, shortfall: null, shadowAgents: 0, orphanCredentials: 0, findings: 3, findingsByCode: { SHADOW_AGENT: 1 } });
    });
});

describe('identifiers', () => {
    /** Everything that names the fake estate: its label, tenant, the hosts and paths it configures, its labels, and the agents the scan found. */
    function estateNames(): string[] {
        const config = parseScannerConfig(estateJson());
        const results = JSON.parse(
            fs.readFileSync(path.join(outDir, 'runs', (JSON.parse(fs.readFileSync(path.join(outDir, 'latest.json'), 'utf8')) as { scanId: string }).scanId, 'results.json'), 'utf8'),
        ) as { agents: { discoveredId: string }[]; scan: { id: string } };
        return [
            'acme-prod',
            ...hostsFor(config).filter((h) => h.named === 'configured').map((h) => h.host),
            outDir,
            'mcp:crm',
            'mcp:tickets',
            results.scan.id,
            ...results.agents.map((a) => a.discoveredId),
        ];
    }

    it('are absent by default: the estate, its hosts, paths, labels, scan id and agent ids, and every word of a doctor check', async () => {
        await scanEstate();
        const names = estateNames();
        expect(names.length).toBeGreaterThan(12);
        const bundle = await build({ doctor: async () => DOCTOR });
        const text = renderSupportBundle(bundle);
        for (const name of names) expect(text).not.toContain(name);
        // The text of a check may name anything; none of it is carried.
        for (const check of DOCTOR.checks) {
            expect(text).not.toContain(check.detail);
            if ('fix' in check) expect(text).not.toContain(check.fix);
        }
        expect(bundle.doctor?.checks).toEqual([
            { scope: 'local', id: 'config.valid', status: 'PASS' },
            { scope: expect.stringMatching(/^mcp:label-[0-9a-f]{8}$/), id: 'reachable', status: 'FAIL', class: 'NETWORK' },
            { scope: 'okta-app', id: 'read.permitted', status: 'WARN' },
            { scope: expect.stringMatching(/^mcp:label-[0-9a-f]{8}$/), id: 'authenticated', status: 'SKIPPED', cause: 'BLOCKED' },
        ]);
        expect(bundle.doctor).toMatchObject({ ready: false, exitCode: 6, counts: DOCTOR.counts });
        // The tenant's slug is a short word; it is looked for as a whole string, not inside others.
        expect(stringsOf(bundle)).not.toContain('acme');
    });

    it('are present with --include-identifiers, and a doctor check keeps its text', async () => {
        await scanEstate();
        const bundle = await build({ includeIdentifiers: true, doctor: async () => DOCTOR });
        expect(bundle.identifiers).toBe('INCLUDED');
        const text = renderSupportBundle(bundle);
        for (const name of estateNames()) expect(text).toContain(name);
        expect(stringsOf(bundle)).toContain('acme');
        expect(bundle.doctor?.checks).toEqual(DOCTOR.checks);
        // A credential's value is in neither mode.
        for (const value of Object.values(estateEnv())) expect(text).not.toContain(value);
    });

    it('map one name to one token within a bundle, and to another in the next', async () => {
        await scanEstate();
        const first = await build({ doctor: async () => DOCTOR });
        const second = await build({ doctor: async () => DOCTOR });
        // The tenant's host is named three times: as the tenant, as the register it is read from, and as where the report goes.
        const tenantHost = (b: SupportBundle) => b.config?.tenant?.host;
        const registerHost = (b: SupportBundle) => b.config?.sources.find((s) => s.kind === 'inflect-register')?.hosts[0].host;
        expect(tenantHost(first)).toMatch(/^host-[0-9a-f]{8}$/);
        expect(registerHost(first)).toBe(tenantHost(first));
        expect(registerHost(second)).toBe(tenantHost(second));
        expect(tenantHost(second)).not.toBe(tenantHost(first));
        // The same holds for every token of the two bundles: none is shared.
        const tokens = (b: SupportBundle) => new Set(stringsOf(b).flatMap((s) => s.match(/\b(?:estate|host|label|path|tenant|agent|scan)-[0-9a-f]{8}\b/g) ?? []));
        const shared = [...tokens(first)].filter((t) => tokens(second).has(t));
        expect(tokens(first).size).toBeGreaterThan(10);
        expect(shared).toEqual([]);
        // Two different names are two tokens, and two categories of one name are two tokens.
        const ids = replacedIdentifiers(Buffer.alloc(32, 1));
        expect(ids.of('host', 'a.example')).toBe(ids.of('host', 'a.example'));
        expect(ids.of('host', 'a.example')).not.toBe(ids.of('host', 'b.example'));
        expect(ids.of('host', 'a.example').slice(-8)).not.toBe(ids.of('label', 'a.example').slice(-8));
        expect(replacedIdentifiers(Buffer.alloc(32, 2)).of('host', 'a.example')).not.toBe(ids.of('host', 'a.example'));
        expect(includedIdentifiers.of('host', 'a.example')).toBe('a.example');
    });

    it('with one key give one document, byte for byte', async () => {
        await scanEstate();
        const key = Buffer.alloc(32, 7);
        expect(renderSupportBundle(await build({ tokenKey: key }))).toBe(renderSupportBundle(await build({ tokenKey: key })));
    });
});

describe('secrets', () => {
    it('never opens a secret file and never carries a credential value, whatever the value looks like', async () => {
        await scanEstate();
        const secretFile = path.join(dir, 'gcp-key.json');
        const read: string[] = [];
        const recording: SupportFs = { readFile: (p) => (read.push(p), fs.readFileSync(p)), size: (p) => (read.push(p), fs.statSync(p).size) };
        const configPath = writeConfig(estateJson());
        for (const [shape, canary] of CANARIES) {
            fs.writeFileSync(secretFile, canary);
            const env: Record<string, string | undefined> = Object.fromEntries(Object.keys(estateEnv()).map((name) => [name, canary]));
            env.GCP_SCANNER_KEY = undefined;
            env.GCP_SCANNER_KEY_FILE = secretFile;
            for (const includeIdentifiers of [false, true]) {
                const text = renderSupportBundle(await build({ configPath, env, includeIdentifiers, fs: recording, doctor: async () => DOCTOR }));
                expect(`${shape}: ${text.includes(canary)}`).toBe(`${shape}: false`);
                // The path of a secret file is the estate's too, and is in neither mode.
                expect(text).not.toContain(secretFile);
            }
        }
        expect(read).not.toContain(secretFile);
        expect(read.every((p) => p === configPath || p.startsWith(outDir))).toBe(true);
    });

    it('carries nothing a scan of the estate must never report', async () => {
        await scanEstate();
        for (const includeIdentifiers of [false, true]) {
            const text = renderSupportBundle(await build({ includeIdentifiers }));
            for (const never of NEVER_REPORTED) expect(text).not.toContain(never);
            for (const value of Object.values(estateEnv())) expect(text).not.toContain(value);
        }
    });

    it('is refused whole when a secret-shaped string would be in it, or carries none of it', async () => {
        await scanEstate();
        const scanId = (JSON.parse(fs.readFileSync(path.join(outDir, 'latest.json'), 'utf8')) as { scanId: string }).scanId;
        const results = path.join(outDir, 'runs', scanId, 'results.json');
        const original = JSON.parse(fs.readFileSync(results, 'utf8')) as unknown;
        fs.chmodSync(results, 0o640);
        /** The results file with every string value replaced by the canary, the schema id apart. */
        const planted = (node: unknown, canary: string, key = ''): unknown => {
            if (typeof node === 'string') return key === 'schema' ? node : canary;
            if (Array.isArray(node)) return node.map((v) => planted(v, canary));
            if (node !== null && typeof node === 'object') return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, planted(v, canary, k)]));
            return node;
        };
        let refused = 0;
        for (const [shape, canary] of CANARIES) {
            fs.writeFileSync(results, JSON.stringify(planted(original, canary)));
            for (const includeIdentifiers of [false, true]) {
                const bundle = await build({ includeIdentifiers, doctor: async () => ({ ...DOCTOR, checks: [{ scope: `mcp:${canary}`, id: 'reachable', status: 'PASS', detail: canary }] }) });
                let text = '';
                try {
                    text = renderSupportBundle(bundle);
                } catch (err) {
                    expect(err).toBeInstanceOf(OutputRefusedLocally);
                    expect((err as Error).message).not.toContain(canary);
                    refused += 1;
                }
                expect(`${shape}: ${text.includes(canary)}`).toBe(`${shape}: false`);
            }
        }
        // With identifiers included the agent ids and the check's text are the canary, so every such bundle is refused.
        expect(refused).toBeGreaterThanOrEqual(CANARIES.length);
    });
});

describe('a configuration that cannot be read', () => {
    it.each([
        ['is missing', null, /^the file could not be read \(ENOENT\)$/],
        ['is not JSON', '{ "estate": ', /^the file is not JSON$/],
        ['is refused by the schema', JSON.stringify({ ...configJson(), estate: 'Not A Slug' }), /^estate: /],
    ])('%s: the bundle is still made, and says why', async (_name, content, problem) => {
        const configPath = content === null ? path.join(dir, 'absent.json') : writeConfig(content);
        const bundle = await build({ configPath });
        expect(bundle.config).toBeNull();
        expect(bundle.configProblem).toMatch(problem);
        expect(bundle.lastRun).toBeNull();
        expect(bundle.versions.scanner).toBe(SCANNER_VERSION);
        // Nothing of the file is repeated.
        expect(renderSupportBundle(bundle)).not.toContain('Not A Slug');
    });
});

describe('the network', () => {
    it('is not touched unless the preflight is asked for', async () => {
        const fetched = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no test reaches the network'));
        let asked = 0;
        await build();
        expect(asked).toBe(0);
        const withDoctor = await build({ doctor: async () => ((asked += 1), DOCTOR) });
        expect(asked).toBe(1);
        expect(withDoctor.doctor?.checks).toHaveLength(4);
        expect(fetched).not.toHaveBeenCalled();
    });
});

describe('the command', () => {
    let out: string[];
    let err: string[];
    let fetched: jest.SpyInstance;
    const LOCAL_ENV = { SCANNER_SIGNING_KEY: ENV.SCANNER_SIGNING_KEY };

    beforeEach(() => {
        out = [];
        err = [];
        jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
        jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
        fetched = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no test reaches the network'));
    });

    const localConfig = (): string => {
        const { inflect: _inflect, ...rest } = configJson({ outputs: [{ kind: 'file', dir: outDir }] });
        return writeConfig(rest);
    };

    it('prints one document to stdout after a scan, with the agent as a token, and makes no request', async () => {
        const config = localConfig();
        expect(await main(['scan', '--config', config], LOCAL_ENV)).toBe(0);
        out.length = 0;
        err.length = 0;
        expect(await main(['support-bundle', '--config', config], LOCAL_ENV)).toBe(0);
        const bundle = JSON.parse(out.join('')) as SupportBundle;
        expect(bundle.support).toBe('scanent-support/1');
        expect(bundle.lastRun?.agents).toEqual([{ id: expect.stringMatching(/^agent-[0-9a-f]{8}$/), via: ['code'], judgement: expect.any(String), level: expect.anything() }]);
        expect(out.join('')).not.toContain(EXAMPLE_AGENT);
        expect(out.join('')).not.toContain(ENV.SCANNER_SIGNING_KEY);
        expect(err.join('')).toBe('support bundle written. Hosts, labels, paths and agent ids are replaced by tokens; credential variable NAMES are kept. Read it before you send it.\n');
        expect(fetched).not.toHaveBeenCalled();
    });

    it('--include-identifiers keeps the names and says so; --doctor adds the checks of doctor', async () => {
        const config = localConfig();
        expect(await main(['scan', '--config', config], LOCAL_ENV)).toBe(0);
        out.length = 0;
        err.length = 0;
        expect(await main(['support-bundle', '--config', config, '--include-identifiers', '--doctor'], LOCAL_ENV)).toBe(0);
        const bundle = JSON.parse(out.join('')) as SupportBundle;
        expect(bundle.identifiers).toBe('INCLUDED');
        expect(bundle.lastRun?.agents[0].id).toBe(EXAMPLE_AGENT);
        expect(bundle.doctor?.checks.find((c) => c.id === 'config.valid')).toMatchObject({ scope: 'local', status: 'PASS', detail: '1 source' });
        expect(err.join('')).toContain('WITH the estate\'s hosts, labels, paths and agent ids (--include-identifiers)');
        // A code-only estate reaches no host, with or without the preflight.
        expect(fetched).not.toHaveBeenCalled();
    });

    it('--out writes a new private file, relative to the working directory, and never replaces one', async () => {
        const config = localConfig();
        expect(await main(['support-bundle', '--config', config, '--out', 'support.json'], LOCAL_ENV, { cwd: dir })).toBe(0);
        const file = path.join(dir, 'support.json');
        expect(out.join('')).toBe('');
        expect((JSON.parse(fs.readFileSync(file, 'utf8')) as SupportBundle).support).toBe('scanent-support/1');
        expect(fs.statSync(file).mode & 0o777).toBe(0o600);
        const before = fs.readFileSync(file, 'utf8');
        err.length = 0;
        expect(await main(['support-bundle', `--out=${file}`, '--config', config], LOCAL_ENV)).toBe(2);
        expect(err.join('')).toBe('the support bundle was not written (EEXIST); an existing file is never replaced\n');
        expect(fs.readFileSync(file, 'utf8')).toBe(before);
        err.length = 0;
        expect(await main(['support-bundle', '--config', config, '--out', path.join(dir, 'no-such-dir', 'x.json')], LOCAL_ENV)).toBe(1);
        expect(err.join('')).toBe('the support bundle was not written (ENOENT); an existing file is never replaced\n');
    });

    it('still makes a bundle when the configuration cannot be read', async () => {
        expect(await main(['support-bundle', '--config', path.join(dir, 'absent.json')], {})).toBe(0);
        const bundle = JSON.parse(out.join('')) as SupportBundle;
        expect(bundle.config).toBeNull();
        expect(bundle.configProblem).toBe('the file could not be read (ENOENT)');
    });

    it('writes nothing when the bundle would hold a secret\'s shape', async () => {
        const canary = CANARIES[0][1];
        const config = localConfig();
        fs.mkdirSync(path.join(outDir, 'runs', 'example-code-20261112T090000Z-00000000'), { recursive: true });
        fs.writeFileSync(path.join(outDir, 'latest.json'), JSON.stringify({ scanId: 'example-code-20261112T090000Z-00000000', asOf: canary }));
        const file = path.join(dir, 'refused.json');
        expect(await main(['support-bundle', '--config', config, '--out', file], LOCAL_ENV)).toBe(1);
        expect(fs.existsSync(file)).toBe(false);
        expect(out.join('')).toBe('');
        expect(err.join('')).toBe('output refused: the support bundle: lastRun.asOf has the shape of a secret; nothing was written\n');
    });

    it.each([
        [['support-bundle'], 'no configuration'],
        [['support-bundle', '--config', 'c.json', '--runs', 'relative/dir'], 'a relative --runs'],
        [['support-bundle', '--config', 'c.json', '--runs'], '--runs with no value'],
        [['support-bundle', '--config', 'c.json', '--out', '../x.json'], 'an --out that climbs'],
        [['support-bundle', '--config', 'c.json', '--out'], '--out with no value'],
    ])('%j is a usage error (%s)', async (argv) => {
        expect(await main(argv, {})).toBe(2);
        expect(err.join('')).toBe('usage: scanent support-bundle --config <file> [--out <file>] [--runs <absolute dir>] [--doctor] [--include-identifiers]\n');
        expect(out.join('')).toBe('');
    });

    it('refuses a flag it does not know, without repeating it, and help lists the command', async () => {
        expect(await main(['support-bundle', '--config', 'c.json', '--include-secrets'], {})).toBe(2);
        expect(err.join('')).not.toContain('--include-secrets');
        expect(HELP).toContain('  scanent support-bundle --config <file> [--out <file>] [--runs <dir>] [--doctor] [--include-identifiers]\n');
        expect(HELP).toContain('Read it before you send it.');
    });
});
