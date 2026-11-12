/**
 * From a real scan to its local results.
 *
 * The scanner reads `examples/code-only`, signs the report, and scores that
 * same report with no tenant. Nothing here posts anywhere, and `fetch` fails
 * the test if anything calls it.
 *
 *   1. With no inventory, the example's agent is a shadow agent at H0, and the
 *      results say what a code-only run could not have seen.
 *   2. With an inventory that names it, the agent is registered at H1 on the
 *      operator's declaration, and nothing of the inventory is in the report.
 *   3. A source that was not read in full leaves its agents unjudged.
 *   4. The results name the report they describe: its bytes and its signer.
 */
import { createHash, generateKeyPairSync } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { harnessKeyFingerprint, LADDER_VERSION, verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import { firstSecretShapedMember } from '@scanent/contract/harness-findings';
import { INVENTORY_SCHEMA_ID, InventoryRefused } from '@scanent/report/results/inventory';
import { LocalResultsSchema } from '@scanent/report/results/schema';

import { parseScannerConfig, type ScannerConfig } from '../src/config';
import { loadConfiguredInventory, scoreScanLocally } from '../src/local-results';
import { jsonLineLog } from '../src/log';
import { rawPublicKeyHex } from '../src/report';
import { runScan } from '../src/scan';
import { scannerManifestHash } from '../src/scanner-surface';

const ESTATE = path.resolve(__dirname, '..', '..', '..', 'examples', 'code-only', 'estate');
const NOW = Date.parse('2026-11-03T03:30:00.000Z');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const ENV = { SCANNER_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-local-'));
});
afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
});

function configOf(extra: Record<string, unknown> = {}, roots = [{ label: 'example', path: ESTATE }]): ScannerConfig {
    return parseScannerConfig({
        estate: 'example-code',
        scanner: { agentId: 'agt_example', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'example', apiKeyEnv: 'INFLECT_INGEST_KEY' },
        schedule: { everyHours: 24 },
        sources: [{ kind: 'code', product: 'langchain', roots }],
        ...extra,
    });
}

async function scan(config: ScannerConfig) {
    return runScan({
        config,
        env: ENV,
        log: jsonLineLog(() => undefined),
        fetchImpl: async () => {
            throw new Error('a code-only scan makes no request');
        },
        now: () => NOW,
    });
}

describe('1. a code-only scan, with no inventory', () => {
    it('finds the example agent, states H0 for it, and says why nothing higher could be stated', async () => {
        const config = configOf();
        const { raw, body } = await scan(config);
        expect(body.agents).toHaveLength(1);
        const id = body.agents[0].discoveredId;

        const results = scoreScanLocally({ config, raw, body, inventory: loadConfiguredInventory(config) });
        expect(LocalResultsSchema.safeParse(JSON.parse(JSON.stringify(results))).success).toBe(true);
        expect(results.scan).toMatchObject({ id: body.scan.id, asOf: '2026-11-03T03:30:00.000Z', estate: 'example-code', complete: true, registerClaimsVerified: true });
        expect(results.scan.scanner.manifestHash).toBe(scannerManifestHash());
        expect(results.ladder.version).toBe(LADDER_VERSION);
        expect(results.sources).toEqual([{ kind: 'code', status: 'COMPLETE', reason: null, rows: body.population.sources[0].rows, agents: 1 }]);

        expect(results.inventory).toBeNull();
        expect(results.agents).toHaveLength(1);
        expect(results.agents[0]).toMatchObject({
            discoveredId: id,
            declared: null,
            registration: { basis: 'NONE', ref: null },
            judgement: { state: 'JUDGED', level: 'H0', observedLevel: 'H0', shortfall: true },
        });
        expect(results.estate).toMatchObject({ empty: false, agentCount: 1, judgedCount: 1, registrationBasis: 'NONE', shadowAgents: [id] });
        expect(results.findings.find((f) => f.code === 'SHADOW_AGENT')?.description).toContain('no inventory was supplied');

        // Code can show a control missing and never one working: nothing is readable.
        expect(results.coverage.reachableLevel).toBe('H0');
        expect(results.agents[0].criteria.every((c) => c.readable === false)).toBe(true);
        expect(results.coverage.unreadable).toHaveLength(results.agents[0].criteria.length);
    });
});

describe('2. with an inventory that names the agent', () => {
    it('is registered at H1 on the operator\'s declaration, and the report is unchanged by it', async () => {
        const plain = configOf();
        const { body: first } = await scan(plain);
        const id = first.agents[0].discoveredId;

        const file = path.join(dir, 'inventory.json');
        const row = {
            discoveredId: id,
            name: 'Support assistant',
            owner: 'support-operations',
            purpose: 'Answers support questions',
            axes: { autonomyLevel: 1, dataAccessScope: 'READ_TENANT_DATA', reversibility: 'REVERSIBLE', provenance: 'FIRST_PARTY' },
            riskTier: 'LOW',
            riskAssessedOn: '2026-10-01',
        };
        fs.writeFileSync(file, JSON.stringify({ inventory: INVENTORY_SCHEMA_ID, agents: [row, { ...row, discoveredId: 'code:example/gone.py#agent' }] }));
        const config = configOf({ inventory: { path: file } });

        const inventory = loadConfiguredInventory(config);
        const { raw, body } = await scan(config);
        const results = scoreScanLocally({ config, raw, body, inventory });

        expect(results.inventory).toMatchObject({
            provenance: 'DECLARED_BY_OPERATOR',
            sha256: createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
            format: 'json',
            rows: 2,
            matched: 1,
            unmatched: ['code:example/gone.py#agent'],
        });
        const agent = results.agents[0];
        expect(agent.declared).toEqual({ name: 'Support assistant', owner: 'support-operations', purpose: 'Answers support questions', row: 1 });
        expect(agent.registration).toEqual({ basis: 'DECLARED_INVENTORY', ref: 'inventory:row-1' });
        expect(agent.judgement).toMatchObject({ state: 'JUDGED', level: 'H1', observedLevel: 'H0' });
        expect(agent.criteria.filter((c) => c.basis === 'DECLARED').map((c) => c.criterion)).toEqual([
            'H1.registered',
            'H1.owner',
            'H1.axes_declared',
            'H1.tier_scored_fresh',
        ]);
        expect(results.estate.shadowAgents).toEqual([]);
        expect(results.coverage.reachableLevel).toBe('H1');

        // Nothing the operator declared is in the signed report.
        for (const declared of ['Support assistant', 'support-operations', 'Answers support questions', 'inventory:']) expect(raw).not.toContain(declared);
        expect(body.agents[0].registeredAgentId).toBeNull();
        expect(body.agents[0].verdicts.some((v) => v.criterion.startsWith('H1.'))).toBe(false);
        expect(verifyAndParseHarnessReport(raw, [rawPublicKeyHex(publicKey)])).toMatchObject({ ok: true });
    });

    it('stops before the scan when the inventory cannot be loaded', () => {
        const config = configOf({ inventory: { path: path.join(dir, 'missing.csv') } });
        expect(() => loadConfiguredInventory(config)).toThrow(InventoryRefused);
    });
});

describe('3. a source that was not read in full', () => {
    it('leaves its agents unjudged, with the reason, and states no level for them', async () => {
        const config = configOf({}, [
            { label: 'example', path: ESTATE },
            { label: 'missing', path: path.join(dir, 'does-not-exist') },
        ]);
        const { raw, body } = await scan(config);
        expect(body.population.sources[0].status).toBe('INCOMPLETE');
        expect(body.agents).toHaveLength(1);

        const results = scoreScanLocally({ config, raw, body, inventory: null });
        expect(results.scan.complete).toBe(false);
        expect(results.agents[0].judgement).toEqual({
            state: 'NOT_JUDGED',
            reasons: [`SOURCE_INCOMPLETE:code:${body.population.sources[0].reason}`],
        });
        expect(results.estate).toMatchObject({ judgedCount: 0, notJudgedCount: 1, shortfallCount: 0 });
        expect(results.findings.map((f) => f.code).sort()).toEqual(expect.arrayContaining(['INCOMPLETE_SOURCE', 'SHADOW_AGENT']));
        expect(results.findings.some((f) => f.code === 'HARNESS_SHORTFALL')).toBe(false);
        expect(JSON.stringify(results.agents)).not.toMatch(/"(level|observedLevel|bar)":/);
    });
});

describe('4. the results name the report they describe', () => {
    it('by the hash of its bytes and the fingerprint of the key that signed it', async () => {
        const config = configOf();
        const { raw, body } = await scan(config);
        const results = scoreScanLocally({ config, raw, body, inventory: null });
        expect(results.report).toEqual({
            sha256: createHash('sha256').update(raw, 'utf8').digest('hex'),
            signerKeyFingerprint: harnessKeyFingerprint(rawPublicKeyHex(publicKey)),
            signerPinned: true,
        });
        expect(firstSecretShapedMember(results)).toBeNull();
    });

    it('is the same value for the same scan', async () => {
        const config = configOf();
        const { raw, body } = await scan(config);
        const once = scoreScanLocally({ config, raw, body, inventory: null });
        const twice = scoreScanLocally({ config, raw, body, inventory: null });
        expect(JSON.stringify(once)).toBe(JSON.stringify(twice));
    });

    it.each([
        ['is not JSON', 'not json'],
        ['carries no signature', JSON.stringify({ contract: 'inflect-agent-harness/3' })],
        ['is not an object', 'null'],
        ['carries a key that is not one', JSON.stringify({ signature: { signerKey: 'zz' } })],
        ['carries a signer key that is not text', JSON.stringify({ signature: { signerKey: 7 } })],
    ])('refuses to describe a report that %s', async (_label, raw) => {
        const config = configOf();
        const { body } = await scan(config);
        expect(() => scoreScanLocally({ config, raw, body, inventory: null })).toThrow('the signed report carries no Ed25519 signer key');
    });
});
