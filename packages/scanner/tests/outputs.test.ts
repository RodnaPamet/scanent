/**
 * Outputs: which are in effect, and how a run is delivered to them.
 *
 *   1. A configuration written before outputs existed means what it meant.
 *   2. The resolution rules, row by row.
 *   3. The schema: the `inflect` block is optional, and required where
 *      something needs it.
 *   4. Delivery: file, then stdout, then inflect; each attempted whatever
 *      happened to the others; delivered only when all were.
 *   5. The scanner's declared surface did not change.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';
import { verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { INVENTORY_SCHEMA_ID, InventoryRefused } from '@scanent/report/results/inventory';
import { RUN_FILE_NAMES } from '@scanent/report/render/files';

import { ConfigError, credentialEnvNames, parseScannerConfig, ScannerConfigSchema } from '../src/config';
import { NOWHERE_TO_DELIVER, OutputsError, resolveOutputs, scanAndDeliver } from '../src/outputs';
import { ingestTarget, scanAndPost } from '../src/scan';
import { isDeclaredRequest, scannerManifestHash, SCANNER_SURFACE } from '../src/scanner-surface';
import { capturedLog, configJson, configOf, ENV, EXAMPLE_AGENT, INFLECT, noFetch, PUBLIC_HEX, tree } from './helpers/output-fixtures';

const NOW = Date.parse('2026-11-03T03:30:00.000Z');

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-outputs-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const withoutInflect = (extra: Record<string, unknown> = {}): Record<string, unknown> => {
    const { inflect: _inflect, ...rest } = configJson(extra);
    return rest;
};

describe('1. backward compatibility', () => {
    it('a configuration with an inflect block and no outputs parses to what it always did', () => {
        const parsed = configOf();
        expect(parsed).toEqual({
            estate: 'example-code',
            scanner: { agentId: 'agt_example', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
            inflect: INFLECT,
            schedule: { everyHours: 24 },
            timeBoxSeconds: 600,
            sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'example', path: expect.any(String) }] }],
        });
        expect('outputs' in parsed).toBe(false);
        expect(credentialEnvNames(parsed)).toEqual(['SCANNER_SIGNING_KEY', 'INFLECT_INGEST_KEY']);
    });

    it('and resolves to posting, or to printing with --dry-run', () => {
        expect(resolveOutputs(configOf())).toEqual([{ kind: 'inflect' }]);
        expect(resolveOutputs(configOf(), { dryRun: true })).toEqual([{ kind: 'stdout' }]);
        expect(resolveOutputs(configOf(), { out: null, dryRun: false })).toEqual([{ kind: 'inflect' }]);
    });
});

describe('2. resolution', () => {
    const local = parseScannerConfig(withoutInflect() as unknown);

    it.each([
        ['configured outputs are used as they are, in delivery order', configOf({ outputs: [{ kind: 'inflect' }, { kind: 'stdout' }, { kind: 'file', dir: '/out' }] }), {}, [{ kind: 'file', dir: '/out' }, { kind: 'stdout' }, { kind: 'inflect' }]],
        ['--out adds a file output', configOf(), { out: '/var/scanent' }, [{ kind: 'file', dir: '/var/scanent' }, { kind: 'inflect' }]],
        ['--out replaces a configured directory and keeps its retention', configOf({ outputs: [{ kind: 'file', dir: '/out', retainRuns: 30 }] }), { out: '/elsewhere' }, [{ kind: 'file', dir: '/elsewhere', retainRuns: 30 }]],
        ['--dry-run removes inflect and adds stdout', configOf({ outputs: [{ kind: 'file', dir: '/out' }, { kind: 'inflect' }] }), { dryRun: true }, [{ kind: 'file', dir: '/out' }, { kind: 'stdout' }]],
        ['--dry-run does not add stdout twice', configOf({ outputs: [{ kind: 'stdout' }, { kind: 'inflect' }] }), { dryRun: true }, [{ kind: 'stdout' }]],
        ['--out with --dry-run writes the files and prints', configOf(), { out: '/out', dryRun: true }, [{ kind: 'file', dir: '/out' }, { kind: 'stdout' }]],
        ['no inflect block and --out is a local-only run', local, { out: '/out' }, [{ kind: 'file', dir: '/out' }]],
        ['no inflect block and --dry-run prints', local, { dryRun: true }, [{ kind: 'stdout' }]],
    ] as const)('%s', (_label, config, flags, expected) => {
        expect(resolveOutputs(config, flags)).toEqual(expected);
    });

    it('nothing to deliver to is an error before anything is read', () => {
        expect(() => resolveOutputs(local)).toThrow(OutputsError);
        expect(() => resolveOutputs(local)).toThrow('nowhere to deliver: configure outputs, or pass --out or --dry-run');
        expect(NOWHERE_TO_DELIVER).toBe('nowhere to deliver: configure outputs, or pass --out or --dry-run');
    });

    it.each(['relative/out', './out', '/out/../etc', '', `/${'a'.repeat(1100)}`, '/out\u0000'])('--out %j is refused: an absolute path with no .. segment', (out) => {
        expect(() => resolveOutputs(configOf(), { out })).toThrow('--out takes an absolute path with no .. segment');
    });

    it('does not change the configuration it was given', () => {
        const config = configOf({ outputs: [{ kind: 'inflect' }, { kind: 'file', dir: '/out' }] });
        const before = JSON.stringify(config);
        resolveOutputs(config, { out: '/x', dryRun: true });
        expect(JSON.stringify(config)).toBe(before);
    });
});

describe('3. the schema', () => {
    const issues = (json: unknown): string[] => {
        try {
            parseScannerConfig(json);
        } catch (err) {
            if (err instanceof ConfigError) return [...err.issues];
            throw err;
        }
        return [];
    };

    it('a configuration with no inflect block is accepted, and names no ingest key', () => {
        const parsed = parseScannerConfig(withoutInflect({ outputs: [{ kind: 'file', dir: '/out', retainRuns: 90 }, { kind: 'stdout' }] }) as unknown);
        expect(parsed.inflect).toBeUndefined();
        expect(parsed.outputs).toEqual([{ kind: 'file', dir: '/out', retainRuns: 90 }, { kind: 'stdout' }]);
        expect(credentialEnvNames(parsed)).toEqual(['SCANNER_SIGNING_KEY']);
        expect(parseScannerConfig(withoutInflect() as unknown).outputs).toBeUndefined();
    });

    it.each([
        ['the inflect output', withoutInflect({ outputs: [{ kind: 'inflect' }] })],
        ['the inflect-register source', { ...withoutInflect(), sources: [{ kind: 'inflect-register' }] }],
        ['egress', withoutInflect({ egress: { proxyUrl: 'http://proxy:3128', canaryHost: 'canary.example.com' } })],
    ])('the inflect block is required by %s, and the refusal names it', (_label, json) => {
        expect(issues(json)).toEqual(['inflect: custom']);
    });

    it.each([
        ['an empty list', []],
        ['a kind twice', [{ kind: 'stdout' }, { kind: 'stdout' }]],
        ['two file outputs', [{ kind: 'file', dir: '/a' }, { kind: 'file', dir: '/b' }]],
        ['four entries', [{ kind: 'stdout' }, { kind: 'inflect' }, { kind: 'file', dir: '/a' }, { kind: 'stdout' }]],
        ['an unknown kind', [{ kind: 's3', bucket: 'x' }]],
        ['a relative directory', [{ kind: 'file', dir: 'out' }]],
        ['a directory with a .. segment', [{ kind: 'file', dir: '/out/../etc' }]],
        ['a file output with no directory', [{ kind: 'file' }]],
        ['an unknown key', [{ kind: 'stdout', pretty: true }]],
        ['retention of zero', [{ kind: 'file', dir: '/out', retainRuns: 0 }]],
        ['retention above the cap', [{ kind: 'file', dir: '/out', retainRuns: 10_001 }]],
        ['a fractional retention', [{ kind: 'file', dir: '/out', retainRuns: 1.5 }]],
    ])('outputs: %s is refused', (_label, outputs) => {
        const found = issues(configJson({ outputs }));
        expect(found.length).toBeGreaterThan(0);
        for (const issue of found) expect(issue.startsWith('outputs')).toBe(true);
        expect(ScannerConfigSchema.safeParse(configJson({ outputs })).success).toBe(false);
    });

    it('a configuration that carries the block is typed as carrying it', () => {
        const parsed = parseScannerConfig({ ...configJson(), inflect: INFLECT });
        // No narrowing needed: the overload knows the block is there.
        expect(parsed.inflect.tenantSlug).toBe('example');
    });
});

describe('4. delivery', () => {
    const created = () => new Response(JSON.stringify({ complete: true, agentCount: 1 }), { status: 201 });

    it('file, then stdout, then inflect, whatever order they were configured in', async () => {
        const order: string[] = [];
        const { log, lines } = capturedLog();
        const printed: string[] = [];
        const result = await scanAndDeliver({
            config: configOf(),
            env: ENV,
            log,
            now: () => NOW,
            outputs: [{ kind: 'inflect' }, { kind: 'stdout' }, { kind: 'file', dir }],
            stdout: (text) => {
                order.push('stdout');
                printed.push(text);
            },
            file: {
                writeFile: (p, content) => {
                    if (order[order.length - 1] !== 'file') order.push('file');
                    fs.writeFileSync(p, content, { flag: 'wx' });
                },
            },
            fetchImpl: async () => {
                order.push('inflect');
                return created();
            },
        });
        expect(order).toEqual(['file', 'stdout', 'inflect']);
        expect(result.ok).toBe(true);
        expect(result.delivered).toEqual([
            { kind: 'file', ok: true },
            { kind: 'stdout', ok: true },
            { kind: 'inflect', ok: true },
        ]);
        // One scan, delivered three times: the same bytes everywhere.
        expect(printed).toEqual([`${result.scan.raw}\n`]);
        const run = path.join(dir, 'runs', result.scan.body.scan.id);
        expect(fs.readFileSync(path.join(run, RUN_FILE_NAMES.report), 'utf8')).toBe(result.scan.raw);
        expect(verifyAndParseHarnessReport(result.scan.raw, [PUBLIC_HEX])).toMatchObject({ ok: true });
        expect(lines().map((l) => l.msg)).toEqual(['source read', 'report signed', 'results written', 'report ingested']);
        expect(lines()[2]).toMatchObject({ dir: `runs/${result.scan.body.scan.id}`, files: 7, removedRuns: 0 });
    });

    it('stdout alone writes the report and a newline, and logs nothing more than a scan does', async () => {
        const { log, lines } = capturedLog();
        const printed: string[] = [];
        const result = await scanAndDeliver({ config: configOf(), env: ENV, log, outputs: [{ kind: 'stdout' }], stdout: (t) => printed.push(t), fetchImpl: noFetch });
        expect(result.ok).toBe(true);
        expect(printed).toEqual([`${result.scan.raw}\n`]);
        expect(lines().map((l) => l.msg)).toEqual(['source read', 'report signed']);
    });

    it('the default stdout is the process\'s', async () => {
        const out: string[] = [];
        const spy = jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
        try {
            const result = await scanAndDeliver({ config: configOf(), env: ENV, log: capturedLog().log, outputs: [{ kind: 'stdout' }], fetchImpl: noFetch });
            expect(out).toEqual([`${result.scan.raw}\n`]);
        } finally {
            spy.mockRestore();
        }
    });

    it('every output is attempted when another fails, and the run is not delivered', async () => {
        const { log, lines, text } = capturedLog();
        const printed: string[] = [];
        let posted = 0;
        const result = await scanAndDeliver({
            config: configOf(),
            env: ENV,
            log,
            outputs: [{ kind: 'file', dir }, { kind: 'stdout' }, { kind: 'inflect' }],
            stdout: (t) => printed.push(t),
            file: {
                writeFile: () => {
                    throw Object.assign(new Error(`ENOSPC: no space left on device, write '${dir}/x'`), { code: 'ENOSPC' });
                },
            },
            fetchImpl: async () => {
                posted += 1;
                return created();
            },
        });
        expect(result.ok).toBe(false);
        expect(result.delivered).toEqual([
            { kind: 'file', ok: false },
            { kind: 'stdout', ok: true },
            { kind: 'inflect', ok: true },
        ]);
        expect(printed).toHaveLength(1);
        expect(posted).toBe(1);
        const failed = lines().filter((l) => l.msg === 'output failed');
        expect(failed).toEqual([expect.objectContaining({ level: 'error', output: 'file', error: 'Error ENOSPC', scan: result.scan.body.scan.id })]);
        // The log names the kind of failure, not the path it happened at.
        expect(text()).not.toContain(dir);
        expect(tree(dir)).toEqual({});
    });

    it('a run written whose pointer could not be replaced is a failed output that names the run, not "nothing written"', async () => {
        const { log, lines, text } = capturedLog();
        fs.mkdirSync(path.join(dir, 'latest.json'));
        const result = await scanAndDeliver({ config: configOf(), env: ENV, log, outputs: [{ kind: 'file', dir }], fetchImpl: noFetch });
        const id = result.scan.body.scan.id;
        expect(result).toMatchObject({ ok: false, delivered: [{ kind: 'file', ok: false }] });
        const [failed] = lines().filter((l) => l.msg === 'output failed');
        expect(failed).toMatchObject({ output: 'file', scan: id });
        expect(failed.error).toMatch(new RegExp(`^results written to runs/${id}, but latest\\.json was not updated \\([A-Z]+\\); it does not name this run$`));
        expect(text()).not.toContain(dir);
        // The run is there, whole.
        expect(fs.readdirSync(path.join(dir, 'runs', id))).toHaveLength(7);
    });

    it('a failed post is one error line, and the file output still stands', async () => {
        const { log, lines } = capturedLog();
        const result = await scanAndDeliver({
            config: configOf(),
            env: ENV,
            log,
            outputs: [{ kind: 'file', dir }, { kind: 'inflect' }],
            fetchImpl: async () => {
                throw new TypeError('fetch failed');
            },
        });
        expect(result.delivered).toEqual([
            { kind: 'file', ok: true },
            { kind: 'inflect', ok: false },
        ]);
        expect(lines().filter((l) => l.level === 'error')).toEqual([expect.objectContaining({ msg: 'output failed', output: 'inflect', error: 'TypeError' })]);
        expect(Object.keys(tree(dir)).length).toBe(8);
    });

    it('a refused post is not a delivery, and a thrown non-error is logged as unknown', async () => {
        const refused = await scanAndDeliver({
            config: configOf(),
            env: ENV,
            log: capturedLog().log,
            outputs: [{ kind: 'inflect' }],
            fetchImpl: async () => new Response('{"error":"harness_report_refused: REPLAY"}', { status: 409 }),
        });
        expect(refused).toMatchObject({ ok: false, delivered: [{ kind: 'inflect', ok: false }] });
        const { log, lines } = capturedLog();
        const odd = await scanAndDeliver({
            config: configOf(),
            env: ENV,
            log,
            outputs: [{ kind: 'stdout' }],
            stdout: () => {
                throw 'a string, not an Error';
            },
        });
        expect(odd.ok).toBe(false);
        expect(lines().find((l) => l.msg === 'output failed')).toMatchObject({ output: 'stdout', error: 'unknown' });
    });

    it('the ingest key is required before the scan when, and only when, the inflect output is in effect', async () => {
        const { log, lines } = capturedLog();
        const env = { SCANNER_SIGNING_KEY: ENV.SCANNER_SIGNING_KEY };
        await expect(scanAndDeliver({ config: configOf(), env, log, outputs: [{ kind: 'inflect' }], fetchImpl: noFetch })).rejects.toThrow(
            'the ingest API key is not set (environment variable INFLECT_INGEST_KEY)',
        );
        expect(lines()).toEqual([]);
        const local = await scanAndDeliver({ config: configOf(), env, log, outputs: [{ kind: 'file', dir }], fetchImpl: noFetch });
        expect(local.ok).toBe(true);
    });

    it('a configuration with no inflect block has nowhere to post, and says so', async () => {
        const config = parseScannerConfig(withoutInflect() as unknown);
        expect(() => ingestTarget(config, ENV)).toThrow('the configuration has no inflect block to post to');
        await expect(scanAndPost({ config, env: ENV, log: capturedLog().log, fetchImpl: noFetch })).rejects.toThrow('no inflect block');
        await expect(scanAndDeliver({ config, env: ENV, log: capturedLog().log, outputs: [{ kind: 'inflect' }], fetchImpl: noFetch })).rejects.toThrow('no inflect block');
    });

    it('a local-only run needs no tenant at all: no inflect block, no ingest key, no request', async () => {
        const config = parseScannerConfig(withoutInflect({ outputs: [{ kind: 'file', dir }] }) as unknown);
        const result = await scanAndDeliver({
            config,
            env: { SCANNER_SIGNING_KEY: ENV.SCANNER_SIGNING_KEY },
            log: capturedLog().log,
            outputs: resolveOutputs(config),
            fetchImpl: noFetch,
        });
        expect(result.ok).toBe(true);
        const results = JSON.parse(fs.readFileSync(path.join(dir, 'runs', result.scan.body.scan.id, RUN_FILE_NAMES.results), 'utf8')) as { agents: { discoveredId: string }[] };
        expect(results.agents.map((a) => a.discoveredId)).toEqual([EXAMPLE_AGENT]);
    });

    it('a configured inventory that cannot be loaded stops the run before any source is read', async () => {
        const { log, lines } = capturedLog();
        const config = configOf({ inventory: { path: path.join(dir, 'absent.json') } });
        await expect(scanAndDeliver({ config, env: ENV, log, outputs: [{ kind: 'stdout' }], stdout: () => undefined, fetchImpl: noFetch })).rejects.toThrow(InventoryRefused);
        expect(lines()).toEqual([]);
    });

    it('a configured inventory is what the written results are scored against', async () => {
        const inventory = path.join(dir, 'inventory.json');
        fs.writeFileSync(
            inventory,
            JSON.stringify({ inventory: INVENTORY_SCHEMA_ID, agents: [{ discoveredId: EXAMPLE_AGENT, name: 'Support agent', owner: 'support-team', purpose: 'Answers order questions' }] }),
        );
        const out = path.join(dir, 'out');
        const result = await scanAndDeliver({ config: configOf({ inventory: { path: inventory } }), env: ENV, log: capturedLog().log, outputs: [{ kind: 'file', dir: out }], fetchImpl: noFetch });
        const run = path.join(out, 'runs', result.scan.body.scan.id);
        const results = JSON.parse(fs.readFileSync(path.join(run, RUN_FILE_NAMES.results), 'utf8')) as { agents: { declared: { owner: string } | null }[] };
        expect(results.agents[0].declared).toMatchObject({ owner: 'support-team' });
        // Nothing the inventory says is in the signed report.
        expect(result.scan.raw).not.toContain('support-team');
        expect(fs.readFileSync(path.join(run, RUN_FILE_NAMES.summary), 'utf8')).toContain('declared by the operator');
    });
});

describe('5. the declared surface', () => {
    it('outputs added no request: but for the version, the grants 0.13.0 declared inside it and the contract id, the surface hashes to what it did before them', () => {
        // 0.13.0 put each token exchange's grant inside the surface, so the hash moved once, on purpose,
        // and the surface names its own version. The move to `inflect-agent-harness/4` changed the
        // contract id it names, and no request. Put those three back and the surface is, to the byte,
        // the one from before outputs existed: nothing else was added to it, by outputs or by anything since.
        expect(SCANNER_SURFACE.version).toBe('0.14.0');
        expect(SCANNER_SURFACE.contract).toBe('inflect-agent-harness/4');
        const withoutGrants = {
            ...SCANNER_SURFACE,
            version: '0.12.0',
            contract: 'inflect-agent-harness/3',
            authenticates: SCANNER_SURFACE.authenticates.map((entry) => Object.fromEntries(Object.entries(entry).filter(([key]) => key !== 'grant'))),
        };
        expect(`sha256:${createHash('sha256').update(canonicalJson(withoutGrants), 'utf8').digest('hex')}`).toBe(MANIFEST_BEFORE_OUTPUTS);
        expect(scannerManifestHash()).not.toBe(MANIFEST_BEFORE_OUTPUTS);
        expect(scannerManifestHash()).toBe(`sha256:${createHash('sha256').update(canonicalJson(SCANNER_SURFACE), 'utf8').digest('hex')}`);
        // Every token exchange names exactly one grant, and it is one of the two the scanner has always used.
        expect(SCANNER_SURFACE.authenticates.map((entry) => [entry.product, entry.grant])).toEqual([
            ['azure-key-vault', 'client_credentials'],
            ['entra', 'client_credentials'],
            ['gcp-iam', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
        ]);
        expect(JSON.stringify(SCANNER_SURFACE)).not.toMatch(/scanent-results|results\.json|latest\.json|summary\.html/);
    });

    it('the one write is still the ingest post', () => {
        expect(isDeclaredRequest('POST', 'https://inflect.example.com/api/t/example/admin/agents/harness-scans')).toBe(true);
        expect(isDeclaredRequest('PUT', 'https://inflect.example.com/api/t/example/admin/agents/harness-scans')).toBe(false);
    });
});

/** `scannerManifestHash()` at commit b40808c, before outputs existed. */
const MANIFEST_BEFORE_OUTPUTS = 'sha256:a24a44586e1207d9490552806bf182e7074bd6e519054db7e143ed7f73a3bcea';
