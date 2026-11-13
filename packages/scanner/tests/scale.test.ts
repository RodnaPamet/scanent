/**
 * A large estate, end to end: read, signed, scored, rendered, compared.
 *
 * Two shapes of `helpers/synthetic-estate.ts`:
 *
 *   bounded   500 agents,  1,000 credentials, 10 targets   runs always
 *   full    5,000 agents, 10,000 credentials, 50 targets   runs under SCANENT_LONG=1 (`npm run test:long`)
 *
 * (The full shape is the report's agent cap exactly: 4,997 synthetic agents
 * and three the fixture's register and code root add.)
 *
 * "Targets" are the vaults, repositories and projects the multi-target sources
 * are spread over. The contract's `MAX_SOURCES` is 50, but a configuration
 * holds each source KIND once, so an estate has nine sources at most; the
 * fan-out is in their targets (20 vaults, 50 repositories, 50 projects, as
 * many as the configuration schema takes).
 *
 * MEASURED, 2026-11-12, Node 22, one run each (`node --expose-gc`), fakes in
 * place of the network, so this is the scanner's own cost and no provider's:
 *
 *   shape      scan     score + render   heap growth   report     results.json   summary.html
 *   bounded    0.18 s   0.46 s           77 MiB        0.38 MiB   3.4 MiB        4.4 MiB
 *   full       0.84 s   1.94 s           366 MiB       3.79 MiB   33.7 MiB       5.3 MiB
 *
 * AND WITH `report.pdf` AND THE PAGE'S INTERACTIVE VIEW, 2026-11-13, the same way:
 *
 *   shape      scan     score + render   heap growth   summary.html   report.pdf
 *   bounded    0.20 s   2.2 s            264 MiB       5.1 MiB        0.34 MiB
 *   full       0.88 s   7.2 s            870 MiB       11.8 MiB       0.34 MiB
 *
 * The render is now mostly the PDF's text layout (about 1.2 s at either size:
 * the PDF lists at most 500 agents) and the page's data for every agent. The
 * heap growth is measured before any collection, so it counts what the
 * renderers allocated and dropped: after a collection the full shape holds
 * 144 MiB more than before the scan.
 *
 * The full shape made 1,645 requests, and the scan alone grew the heap by
 * 54 MiB: the rest is the local results, which hold every criterion of every
 * agent. Peak resident memory of the test process was 758 MiB, of which about
 * 350 MiB is the test runner before any scan. The ceilings below are those
 * figures with headroom for a slower runner: they catch a change that makes
 * the scan quadratic or holds the estate twice, not one that costs a tenth more.
 *
 * WHAT THE CAPS DO. The report may carry 5,000 agents and 5 MiB. Past the
 * agent count the scanner cuts in a fixed order and marks every source that
 * lost an agent INCOMPLETE `BYTE_CAP`: the report is never complete over a
 * slice. Past the byte size it refuses to sign at all, and nothing is written.
 * The two are not the same limit: at 5 MiB a report averages 1,048 bytes an
 * agent, which 5,000 agents with two credentials each fit (708 bytes an
 * agent) and 5,000 agents with five tools each do not (1,687 bytes an agent).
 */
import { generateKeyPairSync } from 'crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { MAX_AGENTS, MAX_REPORT_BYTES, verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { LocalResultsSchema } from '@scanent/report/results/schema';
import type { LocalResults } from '@scanent/report/results/types';

import { parseScannerConfig } from '../src/config';
import { MAX_DIFF_INPUT_BYTES, runDiff } from '../src/diff-command';
import { renderRunFiles } from '../src/file-output';
import { scoreScanLocally } from '../src/local-results';
import { scanAndDeliver } from '../src/outputs';
import { buildReportBody, rawPublicKeyHex, ReportRefusedLocally, signReport } from '../src/report';
import { loadSigningKey, runScan } from '../src/scan';
import type { Observation, SourceRead } from '../src/source';
import { SIGNING_PEM } from './helpers/doctor-world';
import { estateConfig, estateEnv, PUBLIC_RESOLVER } from './helpers/estate-world';
import { capturedLog, tree } from './helpers/output-fixtures';
import { describeLong, TEST_TIMEOUT_MS } from './helpers/prng';

jest.setTimeout(TEST_TIMEOUT_MS);
import { configuredHostsOf, readOnlyProblems, recordRequests } from './helpers/request-recorder';
import { syntheticEstate, type SyntheticShape } from './helpers/synthetic-estate';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const PUBLIC_KEY = rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey);

interface Ceilings {
    readonly scanMs: number;
    readonly renderMs: number;
    readonly heapBytes: number;
    readonly reportBytes: number;
}

const BOUNDED: SyntheticShape = { seed: 20261112, agents: 500, credentials: 1_000, targets: 10 };
/** Agents the fixture's register and code root add to any estate: a confirmed Entra principal, the scanner's own row, the example agent. */
const FIXTURE_AGENTS = 3;
// The report's cap exactly: 4,997 synthetic agents and the fixture's three.
const FULL: SyntheticShape = { seed: 20261112, agents: MAX_AGENTS - FIXTURE_AGENTS, credentials: 10_000, targets: 50 };
// About ten times the measured time and three times the measured heap: a shared runner is slow, and unevenly so.
const BOUNDED_CEILINGS: Ceilings = { scanMs: 5_000, renderMs: 8_000, heapBytes: 450 * 1024 * 1024, reportBytes: 1024 * 1024 };
const FULL_CEILINGS: Ceilings = { scanMs: 20_000, renderMs: 30_000, heapBytes: 1280 * 1024 * 1024, reportBytes: MAX_REPORT_BYTES };

let base: string;
beforeAll(() => {
    base = mkdtempSync(join(tmpdir(), 'scanent-scale-'));
});
afterAll(() => {
    rmSync(base, { recursive: true, force: true });
});

function scaleSuite(shape: SyntheticShape, ceilings: Ceilings): void {
    const estate = syntheticEstate(shape);
    const config = parseScannerConfig(estateConfig(estate.sources));
    const recorder = recordRequests(estate.world.fetchImpl);
    let scan: Awaited<ReturnType<typeof runScan>>;
    let results: LocalResults;
    let files: ReturnType<typeof renderRunFiles>;
    let scanMs = 0;
    let renderMs = 0;
    let heapGrowth = 0;

    beforeAll(async () => {
        global.gc?.();
        const heap = process.memoryUsage().heapUsed;
        let t = Date.now();
        scan = await runScan({ config, env: estateEnv(), log: capturedLog().log, fetchImpl: recorder.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
        scanMs = Date.now() - t;
        t = Date.now();
        results = scoreScanLocally({ config, raw: scan.raw, body: scan.body, inventory: null });
        files = renderRunFiles(scan.raw, results);
        renderMs = Date.now() - t;
        heapGrowth = process.memoryUsage().heapUsed - heap;
    });

    it('every source is read in full, and the scan is complete', () => {
        expect(scan.body.population.sources.map((s) => [s.kind, s.status])).toEqual(
            ['entra-sp', 'okta-app', 'vault', 'mcp', 'runtime', 'cicd', 'inflect-register', 'code', 'gcp-sa'].map((kind) => [kind, 'COMPLETE']),
        );
    });

    it('every agent of the estate is in the report, once, found through the source that holds it', () => {
        const ids = scan.body.agents.map((a) => a.discoveredId);
        expect(new Set(ids).size).toBe(ids.length);
        const through = (prefix: string): number => ids.filter((id) => id.startsWith(prefix)).length;
        // The fixture register confirms one Entra principal that is not in the synthetic directory: one more.
        expect(through('entra:sp:')).toBe(estate.agentsBy['entra-sp'] + 1);
        expect(through('okta:app:')).toBe(estate.agentsBy['okta-app']);
        expect(through('gcp:sa:')).toBe(estate.agentsBy['gcp-sa']);
        expect(through('langsmith:project:')).toBe(estate.agentsBy.runtime);
        expect(scan.body.agents.filter((a) => a.discoveredVia.includes('cicd'))).toHaveLength(estate.agentsBy.cicd);
        expect(ids.length).toBe(shape.agents + FIXTURE_AGENTS);
        expect(ids.length).toBeLessThanOrEqual(MAX_AGENTS);
    });

    it('every credential is on the agent it belongs to, and none is left unbound', () => {
        const held = scan.body.agents.flatMap((a) => a.credentials.map((c) => c.ref));
        const of = (scheme: string): number => held.filter((ref) => ref.startsWith(scheme)).length;
        expect(of('entra://')).toBe(estate.credentialsBy.entra);
        expect(of('gcp-sa-key://')).toBe(estate.credentialsBy.gcp);
        expect(of('azure-kv://')).toBe(estate.credentialsBy.vault);
        expect(scan.body.unboundCredentials).toEqual([]);
    });

    it('the report is signed, passes its own verifier, and is under the size a report may be', () => {
        const verdict = verifyAndParseHarnessReport(scan.raw, [PUBLIC_KEY]);
        expect(verdict.ok).toBe(true);
        expect(verdict.ok && verdict.complete).toBe(true);
        expect(Buffer.byteLength(scan.raw, 'utf8')).toBeLessThan(ceilings.reportBytes);
    });

    it('every request was on the declared surface', () => {
        expect(recorder.requests.length).toBeGreaterThan(50);
        expect(readOnlyProblems(recorder.requests, configuredHostsOf(config))).toEqual([]);
    });

    it('the results pass their own schema, judge every agent, and each file holds the whole run', () => {
        expect(LocalResultsSchema.safeParse(JSON.parse(JSON.stringify(results))).success).toBe(true);
        expect(results.estate.agentCount).toBe(scan.body.agents.length);
        expect(results.estate.notJudgedCount).toBe(0);
        const byName = Object.fromEntries(files.flatMap((f) => (typeof f.content === 'string' ? [[f.name, f.content]] : [])));
        expect((JSON.parse(byName['results.json']) as LocalResults).agents).toHaveLength(scan.body.agents.length);
        expect(byName['agents.csv'].split('\r\n').length - 2).toBe(scan.body.agents.length);
        expect(byName['findings.csv'].split('\r\n').length - 2).toBe(results.findings.length);
        // The page carries every agent for its interactive view: about half a kilobyte each beside the capped static page.
        expect(Buffer.byteLength(byName['summary.html'], 'utf8')).toBeLessThan(14 * 1024 * 1024);
        const pdf = files.find((f) => f.name === 'report.pdf')?.content as Uint8Array;
        expect(Buffer.from(pdf.subarray(0, 5)).toString('latin1')).toBe('%PDF-');
        expect(pdf.byteLength).toBeLessThan(4 * 1024 * 1024);
    });

    it('time and memory stay under their ceilings', () => {
        expect(scanMs).toBeLessThan(ceilings.scanMs);
        expect(renderMs).toBeLessThan(ceilings.renderMs);
        expect(heapGrowth).toBeLessThan(ceilings.heapBytes);
    });

    it('two runs of this size are compared inside the diff\'s input cap, and are the same', () => {
        const dir = mkdtempSync(join(base, 'diff-'));
        const text = files.find((f) => f.name === 'results.json')?.content as string;
        expect(Buffer.byteLength(text, 'utf8')).toBeLessThan(MAX_DIFF_INPUT_BYTES);
        const later = JSON.parse(text) as { scan: { id: string; asOf: string } };
        later.scan = { ...later.scan, id: `${later.scan.id}-later`, asOf: new Date(NOW + 86_400_000).toISOString() };
        writeFileSync(join(dir, 'old.json'), text);
        writeFileSync(join(dir, 'new.json'), JSON.stringify(later));
        const printed: string[] = [];
        const started = Date.now();
        const code = runDiff([join(dir, 'old.json'), join(dir, 'new.json')], { stdout: (t) => printed.push(t), stderr: (t) => printed.push(t) });
        expect(printed.join('')).toContain('No difference, and every comparison could be made.');
        expect(code).toBe(0);
        expect(Date.now() - started).toBeLessThan(ceilings.renderMs);
    });
}

describe('bounded: 500 agents, 1,000 credentials, 10 targets', () => scaleSuite(BOUNDED, BOUNDED_CEILINGS));
describeLong('full: 5,000 agents, 10,000 credentials, 50 targets', () => scaleSuite(FULL, FULL_CEILINGS));

describe('at the contract\'s caps', () => {
    const pair = generateKeyPairSync('ed25519');
    const identity = { scanId: 'acme-prod-20261019T030000Z-0a1b2c3d', asOf: new Date(NOW), scannerAgentId: 'agt_scanner_acme' };
    /** `n` agents of one source, each with `tools` tools: what a runtime or a code source reports. */
    const reads = (n: number, tools: number, kind: 'entra-sp' | 'gcp-sa' = 'entra-sp', from = 0): SourceRead => ({
        kind,
        status: 'COMPLETE',
        rows: n,
        observations: Array.from({ length: n }, (_, i): Observation => ({
            discoveredId: `${kind === 'entra-sp' ? 'entra:sp' : 'gcp:sa'}:${String(from + i).padStart(8, '0')}`,
            owner: null,
            credentials: [],
            verdicts: [],
            tools: Array.from({ length: tools }, (_, t) => ({ tool: { server: 'https://mcp.internal.example/crm/mcp', name: `tool_${t}`, manifestHash: null, pinned: false, readOnlyHint: true } })),
        })),
    });

    it('exactly the agent cap is reported whole and complete', () => {
        const body = buildReportBody(identity, [reads(MAX_AGENTS, 0)]);
        expect(body.agents).toHaveLength(MAX_AGENTS);
        expect(body.population.sources).toEqual([{ kind: 'entra-sp', status: 'COMPLETE', rows: MAX_AGENTS }]);
        expect(verifyAndParseHarnessReport(signReport(body, pair), [rawPublicKeyHex(pair.publicKey)])).toMatchObject({ ok: true, complete: true });
    });

    it('one agent over the cap: the report carries the cap, and the source that lost an agent is INCOMPLETE BYTE_CAP, never complete', () => {
        const body = buildReportBody(identity, [reads(MAX_AGENTS + 1, 0)]);
        expect(body.agents).toHaveLength(MAX_AGENTS);
        expect(body.population.sources).toEqual([{ kind: 'entra-sp', status: 'INCOMPLETE', reason: 'BYTE_CAP', rows: MAX_AGENTS + 1 }]);
        expect(body.findings).toEqual([expect.objectContaining({ code: 'INCOMPLETE_SOURCE' })]);
        const verdict = verifyAndParseHarnessReport(signReport(body, pair), [rawPublicKeyHex(pair.publicKey)]);
        expect(verdict).toMatchObject({ ok: true, complete: false });
    });

    it('only a source that lost an agent is marked: one that kept all of its own stays complete', () => {
        // Ids sort `entra:sp:` before `gcp:sa:`, so the cut falls on the second source alone.
        const body = buildReportBody(identity, [reads(MAX_AGENTS - 10, 0, 'entra-sp'), reads(20, 0, 'gcp-sa')]);
        expect(body.agents).toHaveLength(MAX_AGENTS);
        expect(body.population.sources).toEqual([
            { kind: 'entra-sp', status: 'COMPLETE', rows: MAX_AGENTS - 10 },
            { kind: 'gcp-sa', status: 'INCOMPLETE', reason: 'BYTE_CAP', rows: 20 },
        ]);
    });

    it('a report over the byte cap is refused before it leaves: it is not cut to fit, and the refusal says how large it was', () => {
        // Every count is inside the schema: 5,000 agents, ten tools each. The bytes are not.
        const body = buildReportBody(identity, [reads(MAX_AGENTS, 10)]);
        expect(body.agents).toHaveLength(MAX_AGENTS);
        expect(Buffer.byteLength(JSON.stringify(body), 'utf8')).toBeGreaterThan(MAX_REPORT_BYTES);
        let refusal: unknown;
        try {
            signReport(body, pair);
        } catch (err) {
            refusal = err;
        }
        expect(refusal).toBeInstanceOf(ReportRefusedLocally);
        expect((refusal as ReportRefusedLocally).message).toMatch(/^the scanner refused to sign its report: \(report\): \d+ bytes, over the 5242880 a report may be/);
        // The same body under the cap is signed: the refusal is about the size and nothing else.
        expect(() => signReport(buildReportBody(identity, [reads(2_000, 10)]), pair)).not.toThrow();
    });

    it('what the contract\'s own verifier would refuse as too large is what the scanner refuses to sign', () => {
        const fits = signReport(buildReportBody(identity, [reads(3_000, 10)]), pair);
        expect(Buffer.byteLength(fits, 'utf8')).toBeLessThanOrEqual(MAX_REPORT_BYTES);
        expect(verifyAndParseHarnessReport(fits, [rawPublicKeyHex(pair.publicKey)]).ok).toBe(true);
        expect(verifyAndParseHarnessReport(`${fits}${' '.repeat(MAX_REPORT_BYTES)}`, [rawPublicKeyHex(pair.publicKey)])).toEqual({ ok: false, reason: 'TOO_LARGE' });
    });

    it('a whole run whose report is over the byte cap writes nothing, prints nothing and posts nothing', async () => {
        // An estate whose agents each carry many credentials: every count inside its cap, the bytes not.
        const estate = syntheticEstate({ seed: 7, agents: 1_500, credentials: 90_000, targets: 20 });
        const dir = join(base, 'too-large');
        mkdirSync(dir, { mode: 0o700 });
        const config = parseScannerConfig(estateConfig(estate.sources, { outputs: [{ kind: 'file', dir }, { kind: 'stdout' }, { kind: 'inflect' }] }));
        const printed: string[] = [];
        const logged = capturedLog();
        await expect(
            scanAndDeliver({
                config,
                env: estateEnv(),
                log: logged.log,
                fetchImpl: estate.world.fetchImpl,
                resolveHost: PUBLIC_RESOLVER,
                now: () => NOW,
                outputs: [{ kind: 'file', dir }, { kind: 'stdout' }, { kind: 'inflect' }],
                stdout: (t) => printed.push(t),
            }),
        ).rejects.toBeInstanceOf(ReportRefusedLocally);
        expect(tree(dir)).toEqual({});
        expect(printed).toEqual([]);
        expect(estate.world.fakes.posted).toEqual([]);
        expect(logged.lines().some((l) => l.msg === 'report signed')).toBe(false);
    }, 120_000);
});
