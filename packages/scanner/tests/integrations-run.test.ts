/**
 * One run, two scanners: an agent source and the integrations scanner's Entra
 * source, over the fake estate.
 *
 *   1. Two signed reports, one per scanner, with the same key and scan id; the
 *      agent report is unchanged in kind and file name.
 *   2. The results: `results.json` gains an `integrations` section the
 *      contract's planner decided, valid against the results schema; an
 *      agents-only run's results have none.
 *   3. The outputs: the files of the run (three more, and only then), the two
 *      CSVs, the page's section and its own script, the PDF's section; stdout
 *      prints both reports; the `inflect` output posts the agent report only.
 *   4. Nothing secret in any of it: a canary in what the directory returns
 *      reaches no file, and a canary in the results refuses the run.
 *   5. The configuration: an integrations source runs with an agent source or
 *      on its own (posting, which carries the agent report, needs an agent
 *      source), `hosts` lists its hosts, `init` plans it. The run on its own
 *      is `integrations-only-run.test.ts`.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { verifyAndParseIntegrationsReport } from '@rodnapamet/scanent-contract/integrations-contract';
import { INTEGRATION_RUN_FILE_NAMES, RUN_FILE_NAMES } from '@scanent/report/render/files';
import { pageCsp, renderSummaryHtml } from '@scanent/report/render/html';
import { INTEGRATIONS_CSV_COLUMNS, renderIntegrationFindingsCsv, renderIntegrationsCsv } from '@scanent/report/render/integrations-csv';
import { INTEGRATIONS_SCRIPT, INTEGRATIONS_STYLE_TEXT, integrationsPageData } from '@scanent/report/render/integrations-page';
import { cspHashSource } from '@scanent/report/render/sha256';
import { LocalResultsSchema } from '@scanent/report/results/schema';
import type { LocalResults } from '@scanent/report/results/types';

import { ConfigError, credentialEnvNames, parseScannerConfig } from '../src/config';
import { OutputRefusedLocally, renderRunFiles, writeRun } from '../src/file-output';
import { hostsFor } from '../src/hosts';
import { parseInitAnswers } from '../src/init/answers';
import { planInit } from '../src/init/plan';
import { scoreScanLocally } from '../src/local-results';
import { scanAndDeliver } from '../src/outputs';
import { rawPublicKeyHex } from '../src/report';
import { renderReportPdf } from '../src/report-pdf';
import { loadSigningKey, runScan, type ScanResult } from '../src/scan';
import { ENTRA, ENTRA_DIRECTORY_ID, graphFixture } from './helpers/agent-harness-source-fakes';
import { SIGNING_PEM } from './helpers/doctor-world';
import { createEstateWorld, ESTATE_SOURCES, estateConfig, estateEnv, INTEGRATIONS_ESTATE_SOURCE, PUBLIC_RESOLVER } from './helpers/estate-world';
import { CANARIES, capturedLog, pdfTextOf, stringsOf } from './helpers/output-fixtures';
import { agentsOf } from './helpers/run-scan';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const PUBLIC = rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey);
const CONFIG = parseScannerConfig(estateConfig([ESTATE_SOURCES['entra-sp'], INTEGRATIONS_ESTATE_SOURCE]));
const AGENTS_ONLY = parseScannerConfig(estateConfig([ESTATE_SOURCES['entra-sp']]));

async function scan(config = CONFIG, world = createEstateWorld()): Promise<ScanResult> {
    return runScan({ config, env: estateEnv(), log: capturedLog().log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW });
}

function resultsOf(s: ScanResult, config = CONFIG): LocalResults {
    return scoreScanLocally({ config, raw: s.raw, body: s.body, inventory: null, sourceNotes: s.sourceNotes, ...(s.integrations === undefined ? {} : { integrations: s.integrations }) });
}

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-integrations-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('1. two reports, one key, one scan id', () => {
    it('the agent report and the integrations report each verify under their own contract, and neither under the other', async () => {
        const s = await scan();
        expect(s.integrations).toBeDefined();
        const agents = verifyAndParseHarnessReport(s.raw, [PUBLIC]);
        const integrations = verifyAndParseIntegrationsReport(s.integrations?.raw ?? '', [PUBLIC]);
        expect(agents).toMatchObject({ ok: true, body: { contract: 'inflect-agent-harness/4' } });
        expect(integrations).toMatchObject({ ok: true, complete: true, body: { contract: 'scanent-integrations/1' } });
        expect(s.integrations?.body.scan).toEqual(s.body.scan);
        expect(JSON.parse(s.integrations?.raw ?? '{}').signature.signerKey).toBe(JSON.parse(s.raw).signature.signerKey);
        expect(verifyAndParseHarnessReport(s.integrations?.raw ?? '', [PUBLIC])).toMatchObject({ ok: false, reason: 'SCHEMA' });
        // The agent report lists the agent sources only.
        expect(s.body.population.sources.map((x) => x.kind)).toEqual(['entra-sp']);
        expect(s.integrations?.body.applications.map((a) => a.id)).toHaveLength(3);
    });

    it('an agents-only run produces no integrations report at all', async () => {
        expect((await scan(AGENTS_ONLY)).integrations).toBeUndefined();
    });

    it('a missing credential is reported, never omitted: INCOMPLETE AUTH_FAILED, its sign-in read too', async () => {
        const config = parseScannerConfig(estateConfig([ESTATE_SOURCES.code, { ...INTEGRATIONS_ESTATE_SOURCE, clientSecretEnv: 'NOT_SET_HERE' }]));
        const s = await scan(config);
        expect(s.integrations?.body.sources).toEqual([{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0, signInActivity: { status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0 } }]);
        const r = resultsOf(s, config);
        expect(r.integrations?.findings).toEqual([]);
        expect(r.integrations?.notConcluded).toEqual([{ code: 'INTEGRATION_EMPTY_INVENTORY', applicationId: null, sourceKind: 'entra-integrations', why: 'SOURCE_INCOMPLETE' }]);
        expect(r.integrations?.sources[0].detail).toContain('credential not set');
    });
});

describe('2. the results', () => {
    it('an integrations section the planner decided, valid against the results schema', async () => {
        const r = resultsOf(await scan());
        expect(LocalResultsSchema.safeParse(r).success).toBe(true);
        const i = r.integrations;
        expect(i).toMatchObject({ contract: 'scanent-integrations/1', complete: true, unusedDays: 90, report: { file: 'report.integrations.signed.json' } });
        expect(i?.counts).toEqual({ applications: 3, highPrivilege: 2, unverifiedPublisher: 1, noOwner: 1, unused: 2 });
        expect(i?.findings.map((f) => `${f.code} ${f.applicationId?.slice(-36)}`)).toEqual([
            `INTEGRATION_HIGH_PRIVILEGE_GRANT ${ENTRA.spReporting}`,
            `INTEGRATION_UNUSED ${ENTRA.spReporting}`,
            `INTEGRATION_HIGH_PRIVILEGE_GRANT ${ENTRA.spThirdParty}`,
            `INTEGRATION_UNVERIFIED_PUBLISHER ${ENTRA.spThirdParty}`,
            `INTEGRATION_NO_OWNER ${ENTRA.spThirdParty}`,
            `INTEGRATION_UNUSED ${ENTRA.spThirdParty}`,
        ]);
        // The reporting application holds a role on the third party's API, and a delegated scope there: unknown, listed, never high.
        expect(i?.unknownPermissions).toEqual([
            { resourceAppId: 'e0000006-0000-4000-8000-000000003686', name: 'Records.Export.All' },
            { resourceAppId: 'e0000006-0000-4000-8000-000000003686', name: 'records.read' },
        ]);
        // Nothing of it enters the agent results.
        expect(r.findings.every((f) => !f.code.startsWith('INTEGRATION_'))).toBe(true);
        expect(r.sources.map((x) => x.kind)).toEqual(['entra-sp']);
        // A results file with a broken integrations section is refused.
        const broken = { ...r, integrations: { ...i, counts: { ...i?.counts, noOwner: 0 } } };
        expect(LocalResultsSchema.safeParse(broken).success).toBe(false);
        const unconcluded = { ...r, integrations: { ...i, applications: i?.applications.map((a) => ({ ...a, usage: 'UNUSED', signIn: { read: false, lastSeen: null, daysSince: null } })) } };
        expect(LocalResultsSchema.safeParse(unconcluded).success).toBe(false);
    });

    it('sign-in activity not configured: "unused" is not concluded, and the results say so', async () => {
        const config = parseScannerConfig(estateConfig([ESTATE_SOURCES['entra-sp'], { ...INTEGRATIONS_ESTATE_SOURCE, readSignInActivity: false, unusedDays: 30 }]));
        const r = resultsOf(await scan(config), config);
        expect(r.integrations?.unusedDays).toBe(30);
        expect(r.integrations?.counts.unused).toBe(0);
        expect(r.integrations?.notConcluded).toContainEqual({ code: 'INTEGRATION_UNUSED', applicationId: null, sourceKind: 'entra-integrations', why: 'SIGN_IN_NOT_READ' });
        expect(r.integrations?.applications.every((a) => a.usage === 'NOT_CONCLUDED')).toBe(true);
    });

    it('an agents-only run\'s results have no integrations member', async () => {
        const s = await scan(AGENTS_ONLY);
        expect('integrations' in resultsOf(s, AGENTS_ONLY)).toBe(false);
    });
});

describe('3. the outputs', () => {
    it('the file output writes the integrations report and its two CSVs beside the agent files, in the manifest', async () => {
        const result = await scanAndDeliver({
            config: CONFIG,
            env: estateEnv(),
            log: capturedLog().log,
            fetchImpl: createEstateWorld().fetchImpl,
            resolveHost: PUBLIC_RESOLVER,
            now: () => NOW,
            outputs: [{ kind: 'file', dir }],
            loadInventory: () => null,
        });
        expect(result.ok).toBe(true);
        const runDir = path.join(dir, 'runs', agentsOf(result).body.scan.id);
        expect(fs.readdirSync(runDir).sort()).toEqual([...Object.values(RUN_FILE_NAMES), ...Object.values(INTEGRATION_RUN_FILE_NAMES)].sort());
        const manifest = JSON.parse(fs.readFileSync(path.join(runDir, 'manifest.json'), 'utf8')) as { files: { name: string }[] };
        expect(manifest.files.map((f) => f.name)).toEqual([
            'report.signed.json',
            'results.json',
            'agents.csv',
            'findings.csv',
            'summary.html',
            'report.pdf',
            'report.integrations.signed.json',
            'integrations.csv',
            'integration-findings.csv',
        ]);
        expect(fs.readFileSync(path.join(runDir, 'report.integrations.signed.json'), 'utf8')).toBe(result.scan.integrations?.raw);
        const results = JSON.parse(fs.readFileSync(path.join(runDir, 'results.json'), 'utf8')) as LocalResults;
        expect(LocalResultsSchema.safeParse(results).success).toBe(true);
        expect(results.integrations?.counts.applications).toBe(3);
    });

    it('the integrations report and its results come together or not at all', async () => {
        const s = await scan();
        const r = resultsOf(s);
        expect(() => renderRunFiles(s.raw, r)).toThrow('come together');
        const agentsOnly = resultsOf(await scan(AGENTS_ONLY), AGENTS_ONLY);
        expect(() => renderRunFiles(s.raw, agentsOnly, undefined, {}, s.integrations?.raw)).toThrow('come together');
    });

    it('the two CSVs: one row per application and per finding; what was not read says NOT_READ', async () => {
        const config = parseScannerConfig(estateConfig([ESTATE_SOURCES['entra-sp'], { ...INTEGRATIONS_ESTATE_SOURCE, readSignInActivity: false }]));
        const i = resultsOf(await scan(config), config).integrations;
        if (i === undefined) throw new Error('no integrations section');
        const apps = renderIntegrationsCsv(i).replace(/^\uFEFF/, '').trimEnd().split('\r\n');
        expect(apps[0]).toBe(INTEGRATIONS_CSV_COLUMNS.map((c) => `"${c}"`).join(','));
        expect(apps).toHaveLength(4);
        const third = apps.find((l) => l.includes(ENTRA.spThirdParty)) ?? '';
        expect(third).toContain('"OTHER_DIRECTORY","no","0"');
        // User.Read.All reads profiles, not content: below the bar (owner decision, 2026-11-13).
        expect(third).toContain('"HIGH","MAIL;WRITE"');
        expect(third).toContain('"NOT_READ"');
        const findings = renderIntegrationFindingsCsv(i).replace(/^\uFEFF/, '').trimEnd().split('\r\n');
        expect(findings).toHaveLength(1 + i.findings.length);
        expect(findings.filter((l) => l.includes('"Acme Mail Sync"'))).toHaveLength(i.findings.filter((f) => f.applicationId?.endsWith(ENTRA.spThirdParty)).length);
    });

    it('the page: a section, its own data block, script and style, named in the policy by their hashes; the agent page is untouched', async () => {
        const r = resultsOf(await scan());
        const html = renderSummaryHtml(r);
        expect(html).toContain('<section id="integrations"');
        expect(html).toContain('<strong>Integrations: complete.</strong>');
        const attribute = (csp: string) => `content="${csp.replace(/'/g, '&#39;')}"`;
        expect(html).toContain(attribute(pageCsp(true)));
        expect(pageCsp(true)).toContain(cspHashSource(INTEGRATIONS_SCRIPT));
        expect(pageCsp(true)).toContain(cspHashSource(INTEGRATIONS_STYLE_TEXT));
        expect(html).toContain(`<style>${INTEGRATIONS_STYLE_TEXT}</style>`);
        expect(html).toContain(`<script>${INTEGRATIONS_SCRIPT}</script>`);
        const data = JSON.parse(/<script type="application\/json" id="integrations-data">([^<]*)<\/script>/.exec(html)?.[1] ?? 'null') as ReturnType<typeof integrationsPageData>;
        expect(data).toEqual(JSON.parse(JSON.stringify(integrationsPageData(r.integrations as NonNullable<typeof r.integrations>))));
        // Worst first (a HIGH finding, then by id), and every cell decided before the script sees it.
        expect(data.rows.map((row) => [row.id.slice(-36), row.rank])).toEqual([[ENTRA.spReporting, 1], [ENTRA.spThirdParty, 1], [ENTRA.spSupport, 9]]);
        expect(data.rows[1].cells[4]).toBe('High privilege: mail, a write');
        // The agents-only page names none of it.
        const agentsOnly = renderSummaryHtml(resultsOf(await scan(AGENTS_ONLY), AGENTS_ONLY));
        for (const absent of ['integrations', 'ijs', cspHashSource(INTEGRATIONS_SCRIPT)]) expect(agentsOnly).not.toContain(absent);
        expect(agentsOnly).toContain(attribute(pageCsp(false)));
    });

    it('the view decides nothing and touches the page only by building elements', () => {
        expect(() => new Function(INTEGRATIONS_SCRIPT)).not.toThrow();
        expect(INTEGRATIONS_SCRIPT).not.toMatch(/`|\$\{|<\/|<!--|<script/i);
        for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'fetch(', 'XMLHttpRequest', 'WebSocket', 'localStorage', 'sessionStorage', 'setTimeout', 'setInterval', 'href', '.src', 'severity', 'HIGH', 'privilege']) {
            expect(`${banned}: ${INTEGRATIONS_SCRIPT.includes(banned)}`).toBe(`${banned}: false`);
        }
    });

    it('the PDF: a section of its own after the agent sections', async () => {
        const r = resultsOf(await scan());
        const pdf = renderReportPdf(r);
        expect(pdf.text).toContain('Integrations');
        expect(pdf.text).toContain('INTEGRATION_UNVERIFIED_PUBLISHER');
        expect(pdfTextOf(pdf.bytes).joined).toContain('Integration findings');
        expect(pdf.text.indexOf('Integration findings')).toBeGreaterThan(pdf.text.indexOf('Each agent'));
        expect(renderReportPdf(resultsOf(await scan(AGENTS_ONLY), AGENTS_ONLY)).text).not.toContain('Integration findings');
    });

    it('stdout prints both signed reports, one per line, the agent report first', async () => {
        const printed: string[] = [];
        const result = await scanAndDeliver({ config: CONFIG, env: estateEnv(), log: capturedLog().log, fetchImpl: createEstateWorld().fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: [{ kind: 'stdout' }], stdout: (t) => void printed.push(t), loadInventory: () => null });
        expect(printed).toEqual([`${agentsOf(result).raw}\n`, `${result.scan.integrations?.raw}\n`]);
    });

    it('the inflect output posts the agent report alone, and says the integrations report was not sent', async () => {
        const world = createEstateWorld();
        const logged = capturedLog();
        const result = await scanAndDeliver({ config: CONFIG, env: estateEnv(), log: logged.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: [{ kind: 'inflect' }], loadInventory: () => null });
        expect(result.ok).toBe(true);
        expect(world.fakes.posted).toEqual([agentsOf(result).raw]);
        expect(logged.lines().find((l) => l.msg === 'integrations report not posted')).toMatchObject({ scan: agentsOf(result).body.scan.id });
    });
});

describe('4. nothing secret', () => {
    it.each(CANARIES)('%s returned by the directory as a display name, a scope or a role name reaches no output', async (_name, canary) => {
        const graph = graphFixture();
        (graph.servicePrincipals[1][2] as Record<string, unknown>).displayName = `sync ${canary}`;
        (graph.servicePrincipals[1][1] as { appRoles: { value: string }[] }).appRoles[0].value = canary;
        graph.oauth2PermissionGrants = [[{ clientId: ENTRA.spThirdParty, consentType: 'AllPrincipals', principalId: null, resourceId: ENTRA.spGraph, scope: `Mail.Read ${canary}` }]];
        const world = createEstateWorld({ fakes: { graph } });
        const logged = capturedLog();
        const result = await scanAndDeliver({ config: CONFIG, env: estateEnv(), log: logged.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: [{ kind: 'file', dir }], loadInventory: () => null });
        expect(result.ok).toBe(true);
        const runDir = path.join(dir, 'runs', agentsOf(result).body.scan.id);
        for (const name of fs.readdirSync(runDir)) {
            const bytes = fs.readFileSync(path.join(runDir, name));
            const text = name.endsWith('.pdf') ? pdfTextOf(bytes).joined : bytes.toString('utf8');
            expect(`${name}: ${text.includes(canary)}`).toBe(`${name}: false`);
        }
        expect(logged.text()).not.toContain(canary);
    });

    it.each(CANARIES)('%s planted in the integrations results refuses the whole run, by path, and writes nothing', async (_name, canary) => {
        const s = await scan();
        const r = resultsOf(s);
        const planted: LocalResults = { ...r, integrations: { ...(r.integrations as NonNullable<LocalResults['integrations']>), unknownPermissions: [{ resourceAppId: null, name: canary }] } };
        let thrown: unknown;
        try {
            writeRun({ dir }, { raw: s.raw, results: planted, integrationsRaw: s.integrations?.raw });
        } catch (err) {
            thrown = err;
        }
        expect(thrown).toBeInstanceOf(OutputRefusedLocally);
        expect((thrown as Error).message).toContain('results.json');
        expect((thrown as Error).message).not.toContain(canary);
        expect(fs.existsSync(path.join(dir, 'runs', s.body.scan.id))).toBe(false);
        expect(stringsOf(integrationsPageData(planted.integrations as NonNullable<LocalResults['integrations']>))).not.toContain(canary);
    });
});

describe('5. the configuration', () => {
    it('an integrations source runs on its own; posting, which carries the agent report only, needs an agent source', () => {
        const alone = { outputs: [{ kind: 'file', dir: '/out' }] };
        const { inflect: _inflect, ...noInflect } = estateConfig([INTEGRATIONS_ESTATE_SOURCE], alone);
        expect(parseScannerConfig(noInflect).sources.map((s) => s.kind)).toEqual(['entra-integrations']);
        // An inflect block with no outputs means "post", and there is no agent report to post.
        expect(() => parseScannerConfig(estateConfig([INTEGRATIONS_ESTATE_SOURCE]))).toThrow('outputs: custom');
        expect(() => parseScannerConfig(estateConfig([INTEGRATIONS_ESTATE_SOURCE], { outputs: [{ kind: 'inflect' }] }))).toThrow('outputs: custom');
        expect(parseScannerConfig(estateConfig([INTEGRATIONS_ESTATE_SOURCE], { outputs: [{ kind: 'stdout' }] })).sources).toHaveLength(1);
        expect(parseScannerConfig(estateConfig([ESTATE_SOURCES.code, INTEGRATIONS_ESTATE_SOURCE])).sources).toHaveLength(2);
        expect(() => parseScannerConfig(estateConfig([ESTATE_SOURCES.code, { ...INTEGRATIONS_ESTATE_SOURCE, extra: 1 }]))).toThrow(ConfigError);
        expect(() => parseScannerConfig(estateConfig([ESTATE_SOURCES.code, { ...INTEGRATIONS_ESTATE_SOURCE, unusedDays: 0 }]))).toThrow(ConfigError);
        expect(parseScannerConfig(estateConfig([ESTATE_SOURCES.code, { kind: 'entra-integrations', directoryId: ENTRA_DIRECTORY_ID, clientId: ENTRA_DIRECTORY_ID, clientSecretEnv: 'X' }])).sources[1]).toMatchObject({ readSignInActivity: false, unusedDays: 90 });
    });

    it('the two Entra sources may name one secret, which the environment then holds once', () => {
        expect(credentialEnvNames(CONFIG).filter((n) => n === 'ENTRA_CLIENT_SECRET')).toHaveLength(2);
        expect(new Set(credentialEnvNames(CONFIG)).size).toBe(credentialEnvNames(CONFIG).length - 1);
    });

    it('hosts: the identity platform and Graph, under the integrations source and its scanner', () => {
        expect(hostsFor(CONFIG).filter((e) => e.source === 'entra-integrations')).toEqual([
            { scanner: 'integrations', host: 'graph.microsoft.com', port: 443, source: 'entra-integrations', purpose: 'read', named: 'fixed' },
            { scanner: 'integrations', host: 'login.microsoftonline.com', port: 443, source: 'entra-integrations', purpose: 'token', named: 'fixed' },
        ]);
    });

    it('the integrations example, pointed at the fake directory, scans with both scanners on one secret and writes every file', async () => {
        const example = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'deploy', 'examples', 'integrations.json'), 'utf8');
        const config = parseScannerConfig(
            JSON.parse(example.replaceAll('11111111-2222-4333-8444-555555555555', ENTRA_DIRECTORY_ID).replaceAll('66666666-7777-4888-8999-aaaaaaaaaaaa', '11111111-2222-3333-4444-555555555555').replace('"/out"', JSON.stringify(dir))),
        );
        const env = { SCANNER_SIGNING_KEY: SIGNING_PEM, ENTRA_CLIENT_SECRET: estateEnv().ENTRA_CLIENT_SECRET };
        const result = await scanAndDeliver({ config, env, log: capturedLog().log, fetchImpl: createEstateWorld().fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => NOW, outputs: config.outputs ?? [], loadInventory: () => null });
        expect(result.ok).toBe(true);
        expect(agentsOf(result).body.population.sources).toEqual([expect.objectContaining({ kind: 'entra-sp', status: 'COMPLETE' })]);
        expect(result.scan.integrations?.body.sources).toEqual([expect.objectContaining({ kind: 'entra-integrations', status: 'COMPLETE', signInActivity: { status: 'COMPLETE', rows: 3 } })]);
        expect(fs.readdirSync(path.join(dir, 'runs', agentsOf(result).body.scan.id))).toHaveLength(10);
    });

    it('init: an answers file plans it, with its own secret variable unless it shares the agent source\'s', () => {
        const plan = planInit(
            parseInitAnswers({
                answers: 'scanent-init-answers/1',
                estate: 'acme',
                sources: [
                    { kind: 'code', roots: [{ label: 'app', path: '/estate' }] },
                    { kind: 'entra-integrations', directoryId: ENTRA_DIRECTORY_ID, clientId: ENTRA_DIRECTORY_ID, readSignInActivity: true },
                ],
            }),
        );
        expect(plan.config.sources.map((s) => s.kind)).toEqual(['code', 'entra-integrations']);
        expect(plan.credentialNames.map((c) => c.name)).toContain('ENTRA_INTEGRATIONS_CLIENT_SECRET');
        expect(plan.access.map((a) => a.kind)).toEqual(['code', 'entra-integrations']);
        // On its own, it plans a configuration that writes files and posts nothing.
        const alone = planInit(parseInitAnswers({ answers: 'scanent-init-answers/1', estate: 'acme', sources: [{ kind: 'entra-integrations', directoryId: ENTRA_DIRECTORY_ID, clientId: ENTRA_DIRECTORY_ID }] }));
        expect(alone.config.sources.map((s) => s.kind)).toEqual(['entra-integrations']);
        expect(alone.config.outputs?.map((o) => o.kind)).toEqual(['file']);
    });
});
