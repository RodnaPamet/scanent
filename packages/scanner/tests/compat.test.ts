/**
 * Upgrade and compatibility: what an earlier version wrote, read by this one.
 *
 * The fixtures under `fixtures/compat/<version>/` were made by that version
 * (`fixtures/compat/README.md`) and are never edited. Every directory there is
 * read here, so a release that adds one is covered without a line of test.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import { HARNESS_CONTRACT_IDS } from '@scanent/contract/harness-contract-rules';
import { diffResults, TOOL_EVIDENCE_OLDER_RULE } from '@scanent/report/diff/diff';
import { InventoryRefused, INVENTORY_SCHEMA_ID, RETIRED_INVENTORY_SCHEMAS } from '@scanent/report/results/inventory';
import { RESULTS_SCHEMA, type LocalResults } from '@scanent/report/results/types';

import { parseScannerConfig } from '../src/config';
import { DiffInputError, loadDiffSide, runDiff } from '../src/diff-command';
import { assertWellFormed, countsOf, doctorExitCode, DOCTOR_SCHEMA, isReady, type DoctorReport } from '../src/doctor/types';
import { loadInventoryFile } from '../src/inventory-file';
import { parseInitAnswers } from '../src/init/answers';
import { planInit } from '../src/init/plan';
import { loadConfiguredInventory, scoreScanLocally } from '../src/local-results';
import { runScan } from '../src/scan';
import { buildSupportBundle } from '../src/support-bundle';
import { capturedLog, configOf, ENV, EXAMPLE_AGENT, noFetch, REPO } from './helpers/output-fixtures';

const COMPAT = path.join(__dirname, 'fixtures', 'compat');
/** The example inventory of this version: the same two agents every fixture's inventory declares. */
const CURRENT_INVENTORY = path.join(REPO, 'examples', 'code-only', 'inventory.example.json');
/** The issues a refused inventory file names. Fails if it was read. */
function inventoryRefusal(file: string): readonly string[] {
    try {
        loadInventoryFile(file);
    } catch (err) {
        expect(err).toBeInstanceOf(InventoryRefused);
        return (err as InventoryRefused).issues;
    }
    throw new Error('the inventory was read');
}
const VERSIONS = fs
    .readdirSync(COMPAT, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-compat-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

it('there is a fixture directory for every released version, and 0.12.0 is among them', () => {
    expect(VERSIONS.length).toBeGreaterThan(0);
    expect(VERSIONS).toContain('0.12.0');
    for (const v of VERSIONS) expect(v).toMatch(/^\d+\.\d+\.\d+$/);
});

describe.each(VERSIONS)('what %s wrote', (version) => {
    const root = path.join(COMPAT, version);
    const read = (rel: string): string => fs.readFileSync(path.join(root, rel), 'utf8');
    const latest = JSON.parse(read('out/latest.json')) as { scanId: string; dir: string; asOf: string; complete: boolean; agentCount: number };
    const run = `out/${latest.dir}`;
    const publicKey = read('public-key.txt').trim();

    it('is in the repository byte for byte: every file of the run has the hash its manifest gives', () => {
        const manifest = JSON.parse(read(`${run}/manifest.json`)) as { manifest: string; scanId: string; files: { name: string; bytes: number; sha256: string }[] };
        expect(manifest.manifest).toBe('scanent-run/1');
        expect(manifest.scanId).toBe(latest.scanId);
        expect(manifest.files.map((f) => f.name).sort()).toEqual(['agents.csv', 'findings.csv', 'report.signed.json', 'results.json', 'summary.html']);
        for (const file of manifest.files) {
            const bytes = fs.readFileSync(path.join(root, run, file.name));
            expect(`${file.name} ${bytes.byteLength}`).toBe(`${file.name} ${file.bytes}`);
            expect(`${file.name} ${createHash('sha256').update(bytes).digest('hex')}`).toBe(`${file.name} ${file.sha256}`);
        }
    });

    it('the signed report still verifies with its key, under a contract this version reads, and with no other key', () => {
        const raw = read(`${run}/report.signed.json`);
        const verified = verifyAndParseHarnessReport(raw, [publicKey]);
        expect(verified.ok).toBe(true);
        if (!verified.ok) return;
        expect(HARNESS_CONTRACT_IDS).toContain(verified.body.contract);
        expect(verified.body.agents.map((a) => a.discoveredId)).toEqual([EXAMPLE_AGENT]);
        const other = verifyAndParseHarnessReport(raw, ['0'.repeat(64)]);
        expect(other.ok).toBe(false);
        // One byte of the body changed: refused.
        expect(verifyAndParseHarnessReport(raw.replace(EXAMPLE_AGENT, `${EXAMPLE_AGENT}x`), [publicKey]).ok).toBe(false);
    });

    it('the results file still reads whole, and so does the signed report as a side of a diff', () => {
        const results = loadDiffSide(read(`${run}/results.json`), 'old', null);
        expect(results.schema).toBe(RESULTS_SCHEMA);
        expect(results.scan.id).toBe(latest.scanId);
        expect(results.scan.asOf).toBe(latest.asOf);
        expect(results.scan.complete).toBe(latest.complete);
        expect(results.estate.agentCount).toBe(latest.agentCount);
        expect(results.agents.map((a) => a.discoveredId)).toEqual([EXAMPLE_AGENT]);
        const fromReport = loadDiffSide(read(`${run}/report.signed.json`), 'old', publicKey);
        expect(fromReport.agents.map((a) => a.discoveredId)).toEqual([EXAMPLE_AGENT]);
        expect(fromReport.report.signerPinned).toBe(true);
    });

    it('a diff against a run of the same example by this version works, and says which rule it used', async () => {
        const old = loadDiffSide(read(`${run}/results.json`), 'old', null);
        // The same example, the same two agents declared, a day later, by this version. The
        // inventory is this version's: a fixture's own may be of a schema since retired (below).
        const config = configOf({ estate: old.scan.estate, scanner: { agentId: old.scan.scanner.agentId, signingKeyEnv: 'SCANNER_SIGNING_KEY' }, inventory: { path: CURRENT_INVENTORY } });
        const now = Date.parse(old.scan.asOf) + 24 * 3_600_000;
        const scan = await runScan({ config, env: ENV, log: capturedLog().log, fetchImpl: noFetch, now: () => now });
        const current: LocalResults = scoreScanLocally({ config, raw: scan.raw, body: scan.body, inventory: loadConfiguredInventory(config) });
        const diff = diffResults(old, current);
        // Nothing about the estate changed between the two versions' runs.
        expect(diff.agents.added).toEqual([]);
        expect(diff.agents.notSeen).toEqual([]);
        expect(diff.findings.filter((f) => f.change !== 'NOT_CONCLUDED')).toEqual([]);
        // The older file has no `toolEvidenceSources`: when a finding's closure rests on it, the diff says it fell back.
        // This version's results carry `toolEvidenceSources`; 0.12.0's do not, and still read. The
        // diff may name the older rule, once, and only when a finding's closure rested on it.
        expect(current.agents.every((a) => Array.isArray(a.toolEvidenceSources) && a.toolEvidenceSources.length > 0)).toBe(true);
        if (version === '0.12.0') expect(old.agents.every((a) => a.toolEvidenceSources === undefined)).toBe(true);
        expect(diff.warnings.filter((w) => w === TOOL_EVIDENCE_OLDER_RULE).length).toBeLessThanOrEqual(1);

        // And through the command, from the two files.
        const oldFile = path.join(root, run, 'results.json');
        const newFile = path.join(dir, 'new.json');
        fs.writeFileSync(newFile, JSON.stringify(current));
        const out: string[] = [];
        const err: string[] = [];
        const code = runDiff([oldFile, newFile, '--format', 'json'], { stdout: (t) => void out.push(t), stderr: (t) => void err.push(t) });
        expect(err.join('')).toBe('');
        expect([0, 1, 3]).toContain(code);
        expect((JSON.parse(out.join('')) as { schema: string }).schema).toBe('scanent-diff/1');
    });

    it('the pointer and the run are what the support bundle reads as a last run', async () => {
        const bundle = await buildSupportBundle({ configPath: path.join(dir, 'absent.json'), env: {}, runsDir: path.join(root, 'out'), includeIdentifiers: true });
        expect(bundle.lastRun).toMatchObject({
            scan: latest.scanId,
            asOf: latest.asOf,
            complete: latest.complete,
            agentCount: latest.agentCount,
            resultsProblem: null,
            resultsSchema: RESULTS_SCHEMA,
            scanner: { version },
            sources: [{ kind: 'code', status: 'COMPLETE', reason: null }],
            agents: [{ id: EXAMPLE_AGENT, via: ['code'] }],
        });
    });

    const inventoryId = (JSON.parse(read('inventory.example.json')) as { inventory: string }).inventory;

    it('its inventory is of a schema this version reads or one it retired by name, and 0.12.0 wrote scanent-inventory/1', () => {
        expect([INVENTORY_SCHEMA_ID, ...Object.keys(RETIRED_INVENTORY_SCHEMAS)]).toContain(inventoryId);
        if (version === '0.12.0') expect(inventoryId).toBe('scanent-inventory/1');
    });

    it('the inventory still loads from JSON and from CSV to the same rows, or, of a retired schema, is refused whole in both forms and told what changed', () => {
        const jsonFile = path.join(root, 'inventory.example.json');
        const csvFile = path.join(root, 'inventory.example.csv');
        if (inventoryId === INVENTORY_SCHEMA_ID) {
            const json = loadInventoryFile(jsonFile);
            const csv = loadInventoryFile(csvFile);
            expect(json.format).toBe('json');
            expect(csv.format).toBe('csv');
            expect(json.rows).toHaveLength(2);
            expect(csv.rows).toEqual(json.rows);
            expect(json.rows[0].discoveredId).toBe(EXAMPLE_AGENT);
            return;
        }
        // Nothing was released with the retired schema, so no file of it is converted: it is refused, and the
        // refusal names the schema the file gave, the one this version reads, and every member that changed.
        const changed = RETIRED_INVENTORY_SCHEMAS[inventoryId];
        expect(changed).toMatch(/\S/);
        expect(inventoryRefusal(jsonFile)).toEqual([`inventory: the file names "${inventoryId}"; this version reads ${INVENTORY_SCHEMA_ID}: ${changed}`]);
        // A CSV file names no schema; its columns are what tell it apart.
        const csvIssues = inventoryRefusal(csvFile);
        expect(csvIssues).toHaveLength(2);
        expect(csvIssues[0]).toMatch(/^header: \d+ unknown columns?$/);
        expect(csvIssues[1]).toBe(`header: columns of ${inventoryId}; this version reads ${INVENTORY_SCHEMA_ID}: ${changed}`);
        // Neither refusal repeats a row.
        expect([...inventoryRefusal(jsonFile), ...csvIssues].join(' ')).not.toMatch(/support-operations|Billing|order/);
    });

    it("this version's example inventory declares the same agents that version's did, in the same order", () => {
        const then = JSON.parse(read('inventory.example.json')) as { agents: { discoveredId: string; name: string; owner: string; purpose: string }[] };
        const now = loadInventoryFile(CURRENT_INVENTORY);
        expect(now.rows.map(({ discoveredId, name, owner, purpose }) => ({ discoveredId, name, owner, purpose }))).toEqual(
            then.agents.map(({ discoveredId, name, owner, purpose }) => ({ discoveredId, name, owner, purpose })),
        );
        expect(now.rows[0].discoveredId).toBe(EXAMPLE_AGENT);
    });

    it('the doctor report is still one this version would have produced from its checks', () => {
        const report = JSON.parse(read('doctor.json')) as DoctorReport;
        expect(report.doctor).toBe(DOCTOR_SCHEMA);
        expect(Object.keys(report).sort()).toEqual(['at', 'checks', 'counts', 'doctor', 'estate', 'exitCode', 'ready', 'scanner']);
        expect(report.checks.length).toBeGreaterThan(0);
        for (const check of report.checks) expect(() => assertWellFormed(check)).not.toThrow();
        expect(countsOf(report.checks)).toEqual(report.counts);
        expect(doctorExitCode(report.checks)).toBe(report.exitCode);
        expect(isReady(report.checks)).toBe(report.ready);
        expect(report.scanner.version).toBe(version);
    });

    const configs = fs.readdirSync(path.join(root, 'configs')).sort();

    it('holds example configurations and answers files', () => {
        expect(configs.filter((f) => f.endsWith('.answers.json')).length).toBeGreaterThan(0);
        expect(configs.filter((f) => !f.endsWith('.answers.json')).length).toBeGreaterThan(0);
    });

    it.each(configs.filter((f) => !f.endsWith('.answers.json')))('the configuration %s still parses', (file) => {
        const config = parseScannerConfig(JSON.parse(read(`configs/${file}`).replaceAll('__REPO__', REPO)));
        expect(config.sources.length).toBeGreaterThan(0);
    });

    it.each(configs.filter((f) => f.endsWith('.answers.json')))('the answers file %s still plans, to the configuration that version wrote', (file) => {
        const plan = planInit(parseInitAnswers(JSON.parse(read(`configs/${file}`))));
        // What init writes for the same answers may gain a member in a later version; what it wrote then must still parse.
        const then = parseScannerConfig(JSON.parse(read(`configs/${file.replace('.answers.json', '.json')}`)));
        const now = parseScannerConfig(JSON.parse(plan.configText));
        expect(now.sources.map((s) => s.kind)).toEqual(then.sources.map((s) => s.kind));
        expect(now.estate).toBe(then.estate);
    });
});

describe('a file of a schema this version does not read is refused whole, and told which it reads', () => {
    const root = path.join(COMPAT, '0.12.0');
    const latest = JSON.parse(fs.readFileSync(path.join(root, 'out/latest.json'), 'utf8')) as { dir: string };
    const results = (): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(root, 'out', latest.dir, 'results.json'), 'utf8')) as Record<string, unknown>;
    const refusal = (value: unknown): string => {
        try {
            loadDiffSide(JSON.stringify(value), 'old', null);
        } catch (err) {
            expect(err).toBeInstanceOf(DiffInputError);
            return (err as Error).message;
        }
        throw new Error('the file was read');
    };

    it('results: a later schema id, no id, and a known id with an unknown member', () => {
        expect(refusal({ ...results(), schema: 'scanent-results/2' })).toBe('old: the file names "scanent-results/2" as its schema; this version reads scanent-results/1');
        const { schema: _schema, ...noId } = results();
        expect(refusal(noId)).toBe('old: the file names no schema; this version reads scanent-results/1 files and signed inflect-agent-harness/2 and inflect-agent-harness/3 reports');
        expect(refusal({ ...results(), addedLater: { level: 'H5' } })).toBe('old: not a valid scanent-results/1 file ((root): unrecognized_keys)');
        // An unknown member deeper down is refused too: nothing is skipped over.
        const deep = results();
        (deep.scan as Record<string, unknown>).addedLater = true;
        expect(refusal(deep)).toMatch(/^old: not a valid scanent-results\/1 file \(scan: unrecognized_keys\)$/);
    });

    it('the command exits 2 on each and prints no comparison', () => {
        const good = path.join(root, 'out', latest.dir, 'results.json');
        const later = path.join(dir, 'later.json');
        fs.writeFileSync(later, JSON.stringify({ ...results(), schema: 'scanent-results/2' }));
        const out: string[] = [];
        const err: string[] = [];
        expect(runDiff([good, later], { stdout: (t) => void out.push(t), stderr: (t) => void err.push(t) })).toBe(2);
        expect(out.join('')).toBe('');
        expect(err.join('')).toBe('scanent diff: new: the file names "scanent-results/2" as its schema; this version reads scanent-results/1\n');
    });

    it('inventory: a later schema id, an earlier one, no id, and a known id with an unknown member', () => {
        const inventory = JSON.parse(fs.readFileSync(CURRENT_INVENTORY, 'utf8')) as Record<string, unknown>;
        const refused = (value: unknown): readonly string[] => {
            const file = path.join(dir, 'inventory.json');
            fs.writeFileSync(file, JSON.stringify(value));
            return inventoryRefusal(file);
        };
        expect(INVENTORY_SCHEMA_ID).toBe('scanent-inventory/2');
        expect(refused({ ...inventory, inventory: 'scanent-inventory/3' })).toEqual(['inventory: the file names "scanent-inventory/3"; this version reads scanent-inventory/2']);
        // The earlier id is refused even over rows this version would read: the id decides.
        expect(refused({ ...inventory, inventory: 'scanent-inventory/1' })).toEqual([
            `inventory: the file names "scanent-inventory/1"; this version reads scanent-inventory/2: ${RETIRED_INVENTORY_SCHEMAS['scanent-inventory/1']}`,
        ]);
        // And the file 0.12.0 read, as it is in the repository.
        expect(inventoryRefusal(path.join(root, 'inventory.example.json'))).toEqual([
            `inventory: the file names "scanent-inventory/1"; this version reads scanent-inventory/2: ${RETIRED_INVENTORY_SCHEMAS['scanent-inventory/1']}`,
        ]);
        const { inventory: _id, ...noId } = inventory;
        expect(refused(noId)).toEqual(['inventory: the file names no schema; this version reads scanent-inventory/2']);
        expect(refused({ ...inventory, addedLater: [] })).toEqual(['(file): 1 unknown field']);
        const rows = inventory.agents as Record<string, unknown>[];
        expect(refused({ ...inventory, agents: [{ ...rows[0], addedLater: 'x' }, rows[1]] })).toEqual(['row 1: 1 unknown field']);
    });
});
