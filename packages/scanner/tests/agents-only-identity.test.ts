/**
 * An agents-only run writes, byte for byte, what it wrote before the
 * integrations scanner existed.
 *
 * `fixtures/agents-only-identity/` was recorded by the code of 0.14.0, before
 * the platform split (`SCANENT_RECORD_IDENTITY=1` writes it, and nothing else
 * does). Each scenario is scanned again here with the same clock, signing key
 * and scan id, and every file the run would write is compared with the
 * recording by its SHA-256.
 *
 * TWO MEMBERS ARE ALLOWED TO DIFFER, AND ONLY TWO: `scan.scanner.manifestHash`
 * and `scan.scanner.version`. The declared surface is one for the image and its
 * hash is in every report (`docs/design/scanners.md`, decision 2), so a surface
 * that gained the integrations scanner's requests has a new hash, by design;
 * and the release that carries it has a new version, which the surface names.
 * The test puts the recorded values back into the body, signs it again with
 * the same key (Ed25519 signs deterministically), and from there on demands
 * identity: the signed bytes, the results, both CSV files, the page, the PDF
 * and the manifest. It also checks that those two are the only members that
 * differed.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';

jest.mock('crypto', () => {
    const actual = jest.requireActual<typeof import('crypto')>('crypto');
    return {
        ...actual,
        // The scan id's four random bytes, fixed so the run directory and every file naming it are the recording's.
        randomBytes: (n: number) => (n === 4 ? Buffer.from('5ca1ab1e', 'hex') : actual.randomBytes(n)),
    };
});

import type { HarnessReportBodyV4 } from '@rodnapamet/scanent-contract/harness-contract';
import { loadInventoryFile } from '../src/inventory-file';
import { parseScannerConfig, type ScannerConfig } from '../src/config';
import { renderRunFiles, writeRun } from '../src/file-output';
import { scoreScanLocally } from '../src/local-results';
import { jsonLineLog } from '../src/log';
import { previousRunOf } from '../src/previous-run';
import { signReport } from '../src/report';
import { runScan, type ScanDeps } from '../src/scan';
import { SCANNER_VERSION, scannerManifestHash } from '../src/scanner-surface';
import { isAgentSourceKind } from '../src/scanners';
import { ESTATE, REPO } from './helpers/output-fixtures';
import { createEstateWorld, ESTATE_SOURCES, estateConfig, estateEnv, PUBLIC_RESOLVER } from './helpers/estate-world';

const FIXTURES = path.join(__dirname, 'fixtures', 'agents-only-identity');
const RECORD = process.env.SCANENT_RECORD_IDENTITY === '1';

/** A fixed Ed25519 key, from a fixed seed: the recording and this run sign with the same one. */
const SEED = Buffer.alloc(32, 7);
const PRIVATE = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]), format: 'der', type: 'pkcs8' });
const KEYS = { privateKey: PRIVATE, publicKey: createPublicKey(PRIVATE) };
const PEM = PRIVATE.export({ type: 'pkcs8', format: 'pem' }).toString();

const AT = Date.parse('2026-11-13T03:00:00.000Z');
const LATER = Date.parse('2026-11-14T03:00:00.000Z');

interface Recording {
    readonly manifestHash: string;
    readonly raw: string;
    readonly files: Readonly<Record<string, string>>;
}

interface Scenario {
    readonly name: string;
    readonly config: ScannerConfig;
    readonly deps: (config: ScannerConfig, now: number) => ScanDeps;
    readonly inventory: boolean;
}

const quiet = jsonLineLog(() => undefined);

function codeOnly(extra: Record<string, unknown> = {}): ScannerConfig {
    return parseScannerConfig({
        estate: 'example-code',
        scanner: { agentId: 'agt_example', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        schedule: { everyHours: 24 },
        sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'example', path: ESTATE }] }],
        ...extra,
    });
}

const offline = (config: ScannerConfig, now: number): ScanDeps => ({
    config,
    env: { SCANNER_SIGNING_KEY: PEM },
    log: quiet,
    fetchImpl: async () => {
        throw new Error('no request in this scenario');
    },
    now: () => now,
});

function estateDeps(failOkta: boolean) {
    return (config: ScannerConfig, now: number): ScanDeps => {
        const world = createEstateWorld();
        if (failOkta) world.inject = (req) => (req.url.includes('okta') ? { status: 503, body: { errorCode: 'E0000009' } } : undefined);
        return { config, env: { ...estateEnv(), SCANNER_SIGNING_KEY: PEM }, log: quiet, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => now };
    };
}

/** Every agent source of the fake estate, and no integrations source: what the recording was made with. */
const everyAgentSource = Object.values(ESTATE_SOURCES);
// The fake estate's rows are the agent scanner's alone, so the scenarios are agents-only by construction.
if (!everyAgentSource.every((s) => isAgentSourceKind(s.kind))) throw new Error('an estate row is not an agent source');

const SCENARIOS: readonly Scenario[] = [
    { name: 'code-only', config: codeOnly(), deps: offline, inventory: false },
    {
        name: 'code-only-inventory',
        config: codeOnly({ inventory: { path: path.join(REPO, 'examples', 'code-only', 'inventory.example.json') } }),
        deps: offline,
        inventory: true,
    },
    { name: 'estate-every-agent-source', config: parseScannerConfig(estateConfig(everyAgentSource)), deps: estateDeps(false), inventory: false },
    { name: 'estate-one-source-down', config: parseScannerConfig(estateConfig(everyAgentSource)), deps: estateDeps(true), inventory: false },
];

/** What a recording's scanner member held: put back before comparing. */
interface RecordedScanner {
    readonly manifestHash: string;
    readonly version: string;
}

const recordedScannerOf = (raw: string): RecordedScanner => {
    const scanner = (JSON.parse(raw) as { scan: { scanner: RecordedScanner } }).scan.scanner;
    return { manifestHash: scanner.manifestHash, version: scanner.version };
};

/** One scan, with the recorded manifest hash and version put back and the body signed again. */
async function scanAt(s: Scenario, now: number, recorded: RecordedScanner | null): Promise<{ raw: string; body: HarnessReportBodyV4; sourceNotes: Parameters<typeof scoreScanLocally>[0]['sourceNotes'] }> {
    const scan = await runScan(s.deps(s.config, now));
    expect(scan.body.scan.scanner.manifestHash).toBe(scannerManifestHash());
    if (recorded === null) return scan;
    const body: HarnessReportBodyV4 = { ...scan.body, scan: { ...scan.body.scan, scanner: { ...scan.body.scan.scanner, ...recorded } } };
    return { raw: signReport(body, KEYS), body, sourceNotes: scan.sourceNotes };
}

const sha = (content: string | Uint8Array) => createHash('sha256').update(content).digest('hex');

async function filesOf(s: Scenario, recorded: RecordedScanner | null): Promise<{ manifestHash: string; raw: string; files: Record<string, string> }> {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-identity-'));
    try {
        const inventory = s.inventory && s.config.inventory !== undefined ? loadInventoryFile(s.config.inventory.path) : null;
        // A first run, written, so the second has a previous run to compare with.
        const first = await scanAt(s, AT, recorded);
        const firstResults = scoreScanLocally({ config: s.config, raw: first.raw, body: first.body, inventory, sourceNotes: first.sourceNotes });
        writeRun({ dir }, { raw: first.raw, results: firstResults, previous: null });
        const second = await scanAt(s, LATER, recorded);
        const results = scoreScanLocally({ config: s.config, raw: second.raw, body: second.body, inventory, sourceNotes: second.sourceNotes });
        const previous = previousRunOf(dir, results);
        const files: Record<string, string> = {};
        for (const f of renderRunFiles(first.raw, firstResults, undefined, { previous: null })) files[`first/${f.name}`] = sha(f.content);
        for (const f of renderRunFiles(second.raw, results, undefined, { previous })) files[`second/${f.name}`] = sha(f.content);
        for (const name of fs.readdirSync(path.join(dir, 'runs', firstResults.scan.id)).sort()) {
            files[`written/${name}`] = sha(fs.readFileSync(path.join(dir, 'runs', firstResults.scan.id, name)));
        }
        return { manifestHash: first.body.scan.scanner.manifestHash, raw: second.raw, files };
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

describe.each(SCENARIOS)('an agents-only run, $name', (s) => {
    const file = path.join(FIXTURES, `${s.name}.json`);

    if (RECORD) {
        it('is recorded', async () => {
            const out = await filesOf(s, null);
            fs.mkdirSync(FIXTURES, { recursive: true });
            fs.writeFileSync(file, `${JSON.stringify(out, null, 2)}\n`);
        });
        return;
    }

    it('writes every file the recording holds, byte for byte, with the recorded manifest hash and version put back', async () => {
        const recorded = JSON.parse(fs.readFileSync(file, 'utf8')) as Recording;
        const now = await filesOf(s, recordedScannerOf(recorded.raw));
        expect(now.raw).toBe(recorded.raw);
        expect(now.files).toEqual(recorded.files);
    });

    it('differs from the recording, before they are put back, in the manifest hash and the version alone', async () => {
        const recorded = JSON.parse(fs.readFileSync(file, 'utf8')) as Recording;
        const scan = await runScan(s.deps(s.config, LATER));
        const { signature: _signature, ...wasBody } = JSON.parse(recorded.raw) as Record<string, unknown> & { scan: { scanner: Record<string, unknown> } };
        const was = { ...wasBody, scan: { ...wasBody.scan, scanner: { ...wasBody.scan.scanner, manifestHash: scannerManifestHash(), version: SCANNER_VERSION } } };
        expect(JSON.parse(JSON.stringify(scan.body))).toEqual(was);
    });
});
