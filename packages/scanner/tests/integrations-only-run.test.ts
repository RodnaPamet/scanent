/**
 * The integrations scanner on its own: the `integrations-only` example, which
 * names no agent source, scanned end to end against the fake directory.
 *
 *   1. One signed report, the integrations scanner's; no agent report, no
 *      agent file, and nothing logged as an agent report.
 *   2. results.json, latest.json, the page and the PDF say which scanner ran,
 *      and that no agent scan did: never an agent scan that found nothing.
 *   3. `--out` twice, then three times: the second run compares its
 *      integrations with the first (a finding opened, one closed); the third,
 *      whose sign-in read failed, concludes nothing it could not read.
 *   4. `scanent diff` on the results files: the integrations compared by the
 *      same rules, and the agent scanner named as run by neither.
 *   5. A run of the other scanner in the same directory: neither run's page
 *      invents a comparison with a scan that did not run.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { verifyAndParseIntegrationsReport } from '@rodnapamet/scanent-contract/integrations-contract';
import { INTEGRATIONS_ONLY_RUN_FILE_NAMES, RUN_FILE_NAMES } from '@scanent/report/render/files';
import { INTEGRATIONS_ONLY_PAGE_CSP, NO_AGENT_SCAN_TEXT } from '@scanent/report/render/html';
import { parseRunResults } from '@scanent/report/results/schema';
import { INTEGRATIONS_ONLY_RESULTS_SCHEMA, type IntegrationsOnlyResults, type LocalResults } from '@scanent/report/results/types';

import { parseScannerConfig, type ScannerConfig } from '../src/config';
import { runDiff } from '../src/diff-command';
import { resolveOutputs, scanAndDeliver, type DeliveryResult } from '../src/outputs';
import { rawPublicKeyHex } from '../src/report';
import { PDF_NO_AGENT_SCAN_TEXT } from '../src/report-pdf';
import { loadSigningKey } from '../src/scan';
import { ENTRA, ENTRA_DIRECTORY_ID, graphFixture } from './helpers/agent-harness-source-fakes';
import { SIGNING_PEM } from './helpers/doctor-world';
import { createEstateWorld, ESTATE_SOURCES, estateEnv, PUBLIC_RESOLVER, type EstateWorld } from './helpers/estate-world';
import { capturedLog, pdfTextOf } from './helpers/output-fixtures';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const DAY = 86_400_000;
const PUBLIC = rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey);
const ENV = { SCANNER_SIGNING_KEY: SIGNING_PEM, ENTRA_INTEGRATIONS_CLIENT_SECRET: estateEnv().ENTRA_CLIENT_SECRET };
const SUPPORT_APP_ID = 'e0000001-0000-4000-8000-000000003686';

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-integrations-only-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

/** The committed example, pointed at the fake directory. Its own output directory is replaced by `--out`. */
function exampleConfig(): ScannerConfig {
    const example = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'deploy', 'examples', 'integrations-only.json'), 'utf8');
    return parseScannerConfig(
        JSON.parse(example.replaceAll('11111111-2222-4333-8444-555555555555', ENTRA_DIRECTORY_ID).replaceAll('66666666-7777-4888-8999-aaaaaaaaaaaa', '11111111-2222-3333-4444-555555555555')),
    );
}

/** The directory a little later: the reporting app has signed in, and the support app now holds a mail grant. */
function laterWorld(): EstateWorld {
    const graph = graphFixture();
    graph.signInActivities = [...(graph.signInActivities ?? []), [{ id: 'activity-reporting', appId: 'e0000002-0000-4000-8000-000000003686', lastSignInActivity: { lastSignInDateTime: '2026-10-19T09:00:00Z' } }]];
    graph.oauth2PermissionGrants = [...(graph.oauth2PermissionGrants ?? []), [{ id: 'grant-support-mail', clientId: ENTRA.spSupport, consentType: 'AllPrincipals', principalId: null, resourceId: ENTRA.spGraph, scope: 'Mail.Read' }]];
    return createEstateWorld({ fakes: { graph } });
}

async function scanOut(at: number, world: EstateWorld = createEstateWorld(), config: ScannerConfig = exampleConfig(), env: Record<string, string> = ENV): Promise<{ result: DeliveryResult; log: ReturnType<typeof capturedLog> }> {
    const log = capturedLog();
    const result = await scanAndDeliver({ config, env, log: log.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => at, outputs: resolveOutputs(config, { out: dir }), loadInventory: () => null });
    expect(result.ok).toBe(true);
    return { result, log };
}

const runDir = (scanId: string) => path.join(dir, 'runs', scanId);
const read = (scanId: string, name: string) => fs.readFileSync(path.join(runDir(scanId), name), 'utf8');

function diffOf(older: string, newer: string): { code: number; json: Record<string, unknown>; text: string } {
    const outJson: string[] = [];
    const outText: string[] = [];
    const io = (out: string[]) => ({ stdout: (t: string) => void out.push(t), stderr: (t: string) => void out.push(t) });
    const files = [path.join(runDir(older), 'results.json'), path.join(runDir(newer), 'results.json')];
    const code = runDiff([...files, '--format', 'json'], io(outJson));
    expect(runDiff(files, io(outText))).toBe(code);
    return { code, json: JSON.parse(outJson.join('')) as Record<string, unknown>, text: outText.join('') };
}

describe('1. one scanner, one report', () => {
    it('the example names no agent source, writes files and posts nothing', () => {
        const config = exampleConfig();
        expect(config.sources.map((s) => s.kind)).toEqual(['entra-integrations']);
        expect(config.inflect).toBeUndefined();
        expect(resolveOutputs(config, { out: dir })).toEqual([{ kind: 'file', dir, retainRuns: 90 }]);
    });

    it('the integrations report alone: verified under its contract, and no agent report is built, signed or logged', async () => {
        const { result, log } = await scanOut(NOW);
        expect(result.scan.agents).toBeNull();
        const raw = result.scan.integrations?.raw ?? '';
        expect(verifyAndParseIntegrationsReport(raw, [PUBLIC])).toMatchObject({ ok: true, complete: true });
        expect(log.lines().map((l) => l.msg)).toContain('integrations report signed');
        expect(log.lines().map((l) => l.msg)).not.toContain('report signed');
        expect(log.lines().filter((l) => l.msg === 'source read' || l.msg === 'source incomplete')).toEqual([]);
        const files = fs.readdirSync(runDir(result.scan.scanId)).sort();
        expect(files).toEqual(Object.values(INTEGRATIONS_ONLY_RUN_FILE_NAMES).sort());
        for (const agentFile of [RUN_FILE_NAMES.report, RUN_FILE_NAMES.agents, RUN_FILE_NAMES.findings]) expect(files).not.toContain(agentFile);
        expect(read(result.scan.scanId, INTEGRATIONS_ONLY_RUN_FILE_NAMES.report)).toBe(raw);
        const manifest = JSON.parse(read(result.scan.scanId, 'manifest.json')) as { files: { name: string }[] };
        expect(manifest.files.map((f) => f.name)).toEqual(['report.integrations.signed.json', 'results.json', 'integrations.csv', 'integration-findings.csv', 'summary.html', 'report.pdf']);
    });

    it('stdout prints the one report the run made', async () => {
        const out: string[] = [];
        const result = await scanAndDeliver({ config: exampleConfig(), env: ENV, log: capturedLog().log, fetchImpl: createEstateWorld().fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: [{ kind: 'stdout' }], stdout: (t) => void out.push(t), loadInventory: () => null });
        expect(result.ok).toBe(true);
        expect(out).toEqual([`${result.scan.integrations?.raw}\n`]);
    });
});

describe('2. which scanner ran, said everywhere', () => {
    it('results.json and latest.json name the integrations scanner, and carry no agent member', async () => {
        const { result } = await scanOut(NOW);
        const json = JSON.parse(read(result.scan.scanId, 'results.json')) as IntegrationsOnlyResults;
        expect(parseRunResults(json)).toMatchObject({ ok: true });
        expect(json).toMatchObject({ schema: INTEGRATIONS_ONLY_RESULTS_SCHEMA, scanners: ['integrations'], scan: { id: result.scan.scanId, estate: 'acme-apps' }, signer: { pinned: true } });
        for (const member of ['agents', 'estate', 'ladder', 'findings', 'sources']) expect(Object.keys(json)).not.toContain(member);
        expect(json.integrations.counts.applications).toBe(3);
        const latest = JSON.parse(fs.readFileSync(path.join(dir, 'latest.json'), 'utf8')) as Record<string, unknown>;
        expect(latest).toEqual({ scanId: result.scan.scanId, dir: `runs/${result.scan.scanId}`, asOf: new Date(NOW).toISOString(), complete: true, scanners: ['integrations'], applicationCount: 3 });
    });

    it('the page: the integrations section only, under a policy naming its one script, and the absent agent scan said first', async () => {
        const { result } = await scanOut(NOW);
        const page = read(result.scan.scanId, 'summary.html');
        expect(page).toContain(`content="${INTEGRATIONS_ONLY_PAGE_CSP.replace(/'/g, '&#39;')}"`);
        expect(page).toContain('<h1>Integrations scan results</h1>');
        expect(page).toContain(NO_AGENT_SCAN_TEXT);
        expect(page.indexOf(NO_AGENT_SCAN_TEXT)).toBeLessThan(page.indexOf('<main'));
        expect(page).toContain('<dt>Scanners that ran</dt><dd>The integrations scanner only</dd>');
        expect(page).toContain('<section id="integrations"');
        expect(page).toContain('signed with the scanner&#39;s key.');
        expect(page).toContain('This output directory held no earlier run, so there is nothing to compare with.');
        for (const absent of ['Agent estate scan results', 'agents.csv', 'id="matrix"', 'summary-data', 'same key as the agent report']) expect(page).not.toContain(absent);
    });

    it('the PDF: a cover naming the scanner that ran and the absent agent scan, then the integrations section', async () => {
        const { result } = await scanOut(NOW);
        const pdf = pdfTextOf(fs.readFileSync(path.join(runDir(result.scan.scanId), 'report.pdf')));
        expect(pdf.joined).toContain('Integrations scan results');
        expect(pdf.joined).toContain('The integrations scanner only');
        expect(pdf.joined).toContain('Integration findings');
        expect(pdf.joined.replace(/\s+/g, ' ')).toContain(PDF_NO_AGENT_SCAN_TEXT.slice(0, 40));
        for (const absent of ['Agent estate scan results', 'Agents found', 'Each agent']) expect(pdf.joined).not.toContain(absent);
    });
});

describe('3. --out twice, then three times: the comparison', () => {
    it('the second run compares with the first: a finding opened and one closed, on the page and in the PDF', async () => {
        const first = await scanOut(NOW);
        const second = await scanOut(NOW + DAY, laterWorld());
        const a = first.result.scan.scanId;
        const b = second.result.scan.scanId;
        expect(JSON.parse(fs.readFileSync(path.join(dir, 'latest.json'), 'utf8'))).toMatchObject({ scanId: b });

        const page = read(b, 'summary.html');
        expect(page).toContain(`Compared with <code class="id">${a}</code>`);
        expect(page).toContain('The integrations differ.');
        expect(page).toContain('<code>INTEGRATION_HIGH_PRIVILEGE_GRANT</code> opened');
        expect(page).toContain('<code>INTEGRATION_UNUSED</code> closed');
        const pdf = pdfTextOf(fs.readFileSync(path.join(runDir(b), 'report.pdf'))).joined;
        expect(pdf).toContain('Integrations since the previous run');
        expect(pdf).toContain(`Compared with ${a}`);

        const d = diffOf(a, b);
        expect(d.code).toBe(1);
        expect(d.json).toMatchObject({ schema: 'scanent-run-diff/1', outcome: 'DIFFERENT', scanners: { agents: { compared: false, change: 'NOT_RUN' } } });
        const integrations = (d.json.scanners as { integrations: { findings: { code: string; change: string; applicationId: string | null }[]; notConcluded: string[] } }).integrations;
        expect(integrations.findings.filter((f) => f.change === 'OPENED').map((f) => f.code)).toEqual(['INTEGRATION_HIGH_PRIVILEGE_GRANT']);
        expect(integrations.findings.filter((f) => f.change === 'CLOSED').map((f) => f.code)).toEqual(['INTEGRATION_UNUSED']);
        expect(integrations.notConcluded).toEqual([]);
        expect(d.text).toContain('== Agent scanner ==\nThe agent scanner ran in neither run.');
        expect(d.text).toContain('== Integrations scanner ==');
        expect(d.text).toMatch(/opened {5}INTEGRATION_HIGH_PRIVILEGE_GRANT /);
        expect(d.text).toMatch(/closed {5}INTEGRATION_UNUSED /);
    });

    it('a third run whose sign-in read failed concludes nothing it could not read', async () => {
        await scanOut(NOW);
        const second = await scanOut(NOW + DAY, laterWorld());
        const failing = laterWorld();
        failing.inject = (req) => (req.path.startsWith('/beta/reports/') ? { status: 503, body: { error: { code: 'ServiceUnavailable' } } } : undefined);
        const third = await scanOut(NOW + 2 * DAY, failing);
        const b = second.result.scan.scanId;
        const c = third.result.scan.scanId;
        expect(third.result.scan.integrations?.body.sources[0]).toMatchObject({ status: 'COMPLETE', signInActivity: { status: 'INCOMPLETE' } });

        const d = diffOf(b, c);
        const integrations = (d.json.scanners as { integrations: { findings: { code: string; change: string; why: string | null }[]; notConcluded: string[]; sources: { kind: string; change: string }[] } }).integrations;
        // The unused finding is no longer raised, and its absence closes nothing: the read that would answer it failed.
        expect(integrations.findings.filter((f) => f.code === 'INTEGRATION_UNUSED')).toEqual([expect.objectContaining({ change: 'NOT_CONCLUDED', why: 'SIGN_IN_READ_INCOMPLETE' })]);
        expect(integrations.findings.filter((f) => f.change === 'CLOSED')).toEqual([]);
        expect(integrations.sources).toEqual([expect.objectContaining({ kind: 'entra-integrations#signInActivity', change: 'NOW_INCOMPLETE' })]);
        expect(integrations.notConcluded).toEqual(expect.arrayContaining(['SCAN_INCOMPLETE:new']));
        expect(d.text).toContain('no longer raised, not concluded   INTEGRATION_UNUSED');

        const page = read(c, 'summary.html');
        expect(page).toContain('<strong>Integrations: incomplete.</strong>');
        expect(page).toContain('no longer raised, not concluded (SIGN_IN_READ_INCOMPLETE)');
        expect(page).not.toContain('<code>INTEGRATION_UNUSED</code> closed');
    });
});

describe('4. the two scanners in one directory', () => {
    it('neither run compares with a scan that did not run, and diff refuses two runs that share no scanner', async () => {
        const integrations = await scanOut(NOW);
        const agentsConfig = parseScannerConfig({ ...exampleConfig(), sources: [ESTATE_SOURCES['entra-sp']] });
        const agents = await scanOut(NOW + DAY, createEstateWorld(), agentsConfig, { ...ENV, ENTRA_CLIENT_SECRET: estateEnv().ENTRA_CLIENT_SECRET });
        const a = integrations.result.scan.scanId;
        const b = agents.result.scan.agents?.body.scan.id ?? '';
        const agentPage = read(b, 'summary.html');
        expect(agentPage).toContain('The previous run did not run the agent scanner, so there is no agent scan to compare with');
        expect((JSON.parse(read(b, 'results.json')) as LocalResults).integrations).toBeUndefined();

        // And back: the integrations run after an agents-only run says the previous run had no integrations.
        const after = await scanOut(NOW + 2 * DAY);
        expect(read(after.result.scan.scanId, 'summary.html')).toContain('The previous run did not run the integrations scanner, so there are no integrations to compare with');

        const err: string[] = [];
        expect(runDiff([path.join(runDir(a), 'results.json'), path.join(runDir(b), 'results.json')], { stdout: () => undefined, stderr: (t) => void err.push(t) })).toBe(2);
        expect(err.join('')).toContain('the two runs share no scanner');
    });

    it('an agents-and-integrations run after an integrations-only one compares its integrations, and names the agent scanner as added', async () => {
        const first = await scanOut(NOW);
        const both = parseScannerConfig({ ...exampleConfig(), sources: [ESTATE_SOURCES['entra-sp'], ...exampleConfig().sources] });
        const second = await scanOut(NOW + DAY, laterWorld(), both, { ...ENV, ENTRA_CLIENT_SECRET: estateEnv().ENTRA_CLIENT_SECRET });
        const b = second.result.scan.scanId;
        const page = read(b, 'summary.html');
        expect(page).toContain('The previous run did not run the agent scanner');
        expect(page).toContain(`Compared with <code class="id">${first.result.scan.scanId}</code>`);
        const d = diffOf(first.result.scan.scanId, b);
        expect(d.json).toMatchObject({ outcome: 'DIFFERENT', scanners: { agents: { compared: false, change: 'ADDED' }, integrations: { schema: 'scanent-integrations-diff/1' } } });
        expect(d.text).toContain('The agent scanner ran in the new run only');
    });
});

it('the support app the later directory grants mail to is the one the opened finding names', async () => {
    // A guard on the fixture itself: the opened finding is about the application the later directory changed.
    const config = exampleConfig();
    await scanOut(NOW, createEstateWorld(), config);
    const second = await scanOut(NOW + DAY, laterWorld(), config);
    const results = JSON.parse(read(second.result.scan.scanId, 'results.json')) as IntegrationsOnlyResults;
    const support = results.integrations.applications.find((x) => x.appId === SUPPORT_APP_ID);
    expect(results.integrations.findings.filter((f) => f.code === 'INTEGRATION_HIGH_PRIVILEGE_GRANT').map((f) => f.applicationId)).toContain(support?.id);
});
