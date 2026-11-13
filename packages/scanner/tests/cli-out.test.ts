/**
 * End to end, through the command line: `--out`, local-only runs, the
 * inventory, an incomplete source, `diff` and `help`.
 *
 * Over `examples/code-only`, with a generated key. `fetch` fails the test if
 * anything calls it: none of this reaches a network.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { LADDER_VERSION, verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { CSV_BOM } from '@scanent/report/render/csv';
import { RUN_FILE_NAMES } from '@scanent/report/render/files';
import { INVENTORY_SCHEMA_ID } from '@scanent/report/results/inventory';
import { LocalResultsSchema } from '@scanent/report/results/schema';
import type { LocalResults } from '@scanent/report/results/types';

import { HELP, main, USAGE_HINT } from '../src/cli';
import { parseScannerConfig } from '../src/config';
import { jsonLineLog } from '../src/log';
import { resolveOutputs, scanAndDeliver } from '../src/outputs';
import { DIFF_USAGE } from '../src/diff-command';
import * as schedule from '../src/schedule';
import { configJson, ENV, EXAMPLE_AGENT, PUBLIC_HEX, REPO } from './helpers/output-fixtures';
import { agentsOf } from './helpers/run-scan';

const LOCAL_ENV = { SCANNER_SIGNING_KEY: ENV.SCANNER_SIGNING_KEY };

let dir: string;
let outDir: string;
let out: string[];
let err: string[];
let fetched: jest.SpyInstance;

beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-cli-out-'));
    outDir = path.join(dir, 'out');
    out = [];
    err = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
    fetched = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no test reaches the network'));
});
afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
});

function writeConfig(json: Record<string, unknown>, name = 'config.json'): string {
    const p = path.join(dir, name);
    fs.writeFileSync(p, JSON.stringify(json));
    return p;
}

function withoutInflect(extra: Record<string, unknown> = {}): Record<string, unknown> {
    const { inflect: _inflect, ...rest } = configJson(extra);
    return rest;
}

function runs(): string[] {
    return fs.existsSync(path.join(outDir, 'runs')) ? fs.readdirSync(path.join(outDir, 'runs')).sort() : [];
}

function read(run: string, name: string): string {
    return fs.readFileSync(path.join(outDir, 'runs', run, name), 'utf8');
}

function resultsOf(run: string): LocalResults {
    return LocalResultsSchema.parse(JSON.parse(read(run, RUN_FILE_NAMES.results)));
}

describe('scan --out', () => {
    it('--out <dir> --dry-run prints the signed report, posts nothing and writes the seven files', async () => {
        expect(await main(['scan', '--config', writeConfig(configJson()), '--out', outDir, '--dry-run'], LOCAL_ENV)).toBe(0);
        expect(fetched).not.toHaveBeenCalled();

        expect(out).toHaveLength(1);
        const raw = out[0].replace(/\n$/, '');
        expect(verifyAndParseHarnessReport(raw, [PUBLIC_HEX])).toMatchObject({ ok: true, complete: true });

        const [run] = runs();
        expect(runs()).toHaveLength(1);
        expect(fs.readdirSync(path.join(outDir, 'runs', run)).sort()).toEqual(Object.values(RUN_FILE_NAMES).sort());
        expect(read(run, RUN_FILE_NAMES.report)).toBe(raw);

        const results = resultsOf(run);
        expect(results.agents.map((a) => a.discoveredId)).toEqual([EXAMPLE_AGENT]);
        expect(results.sources).toEqual([{ kind: 'code', status: 'COMPLETE', reason: null, rows: 1, agents: 1 }]);
        expect(results.ladder.version).toBe(LADDER_VERSION);
        expect(results.report.sha256).toBe(createHash('sha256').update(read(run, RUN_FILE_NAMES.report), 'utf8').digest('hex'));
        expect(results.scan).toMatchObject({ estate: 'example-code', complete: true, registerClaimsVerified: true });

        const page = read(run, RUN_FILE_NAMES.summary);
        expect(page).toContain(EXAMPLE_AGENT);
        expect(page).toContain('no inventory was supplied');
        expect(page).toContain(`<title>scanent results: example-code, ${results.scan.id}</title>`);

        const agents = read(run, RUN_FILE_NAMES.agents);
        expect(agents.startsWith(CSV_BOM)).toBe(true);
        expect(agents.trimEnd().split('\r\n')).toHaveLength(2);
        expect(read(run, RUN_FILE_NAMES.findings)).toContain('"SHADOW_AGENT"');

        // The checkout's path is in no file: a code root is reported by its label.
        for (const name of Object.values(RUN_FILE_NAMES)) expect(read(run, name)).not.toContain(REPO);
        const log = err.join('').trim().split('\n').map((l) => JSON.parse(l) as { msg: string });
        expect(log.map((l) => l.msg)).toEqual(['source read', 'report signed', 'results written']);
    });

    it('--out without --dry-run writes the files and posts, in that order', async () => {
        fetched.mockImplementation(async () => {
            // By the time anything leaves the estate, the run is on disk.
            expect(runs()).toHaveLength(1);
            return new Response(JSON.stringify({ complete: true, agentCount: 1 }), { status: 201 });
        });
        expect(await main(['scan', '--config', writeConfig(configJson()), '--out', outDir], ENV)).toBe(0);
        expect(fetched).toHaveBeenCalledTimes(1);
        expect(out).toEqual([]);
    });

    it('exits 1 when one output failed, having attempted the others', async () => {
        fetched.mockResolvedValue(new Response('', { status: 503 }));
        expect(await main(['scan', '--config', writeConfig(configJson()), '--out', outDir], ENV)).toBe(1);
        expect(runs()).toHaveLength(1);
    });

    it.each([
        ['a relative directory', ['--out', 'relative/out'], '--out takes an absolute path with no .. segment\n'],
        ['no directory', ['--out'], '--out takes a directory\n'],
    ])('--out with %s is refused before anything is read: exit 2', async (_label, flags, message) => {
        expect(await main(['scan', '--config', writeConfig(configJson()), '--dry-run', ...flags], LOCAL_ENV)).toBe(2);
        expect(err.join('')).toBe(message);
        expect(out).toEqual([]);
    });
});

describe('a run with no tenant', () => {
    it('with no inflect block and a file output, scan needs no ingest key and writes the files', async () => {
        const config = writeConfig(withoutInflect({ outputs: [{ kind: 'file', dir: outDir }] }));
        expect(await main(['scan', '--config', config], LOCAL_ENV)).toBe(0);
        expect(fetched).not.toHaveBeenCalled();
        expect(out).toEqual([]);
        expect(runs()).toHaveLength(1);
        expect(resultsOf(runs()[0]).agents).toHaveLength(1);
    });

    it('with no outputs, no inflect block and no flag there is nowhere to deliver: exit 2, nothing read', async () => {
        expect(await main(['scan', '--config', writeConfig(withoutInflect())], LOCAL_ENV)).toBe(2);
        expect(err.join('')).toBe('nowhere to deliver: configure outputs, or pass --out or --dry-run\n');
        expect(out).toEqual([]);
        expect(fetched).not.toHaveBeenCalled();
        // The same for the schedule: it does not start a loop that can deliver nothing.
        const loop = jest.spyOn(schedule, 'runOnSchedule');
        expect(await main(['schedule', '--config', writeConfig(withoutInflect())], LOCAL_ENV)).toBe(2);
        expect(loop).not.toHaveBeenCalled();
    });

    it('schedule --out writes a run each time, and a run that fails does not stop the loop', async () => {
        const config = writeConfig(withoutInflect());
        let failures = 0;
        jest.spyOn(schedule, 'runOnSchedule').mockImplementation(async (opts) => {
            for (let i = 0; i < 2; i++) await opts.run().catch(() => (failures += 1));
            return 2;
        });
        expect(await main(['schedule', '--config', config, '--out', outDir], LOCAL_ENV)).toBe(0);
        expect(failures).toBe(0);
        // Two runs in the same second share a stamp and differ by their random suffix.
        expect(runs()).toHaveLength(2);
        expect(fetched).not.toHaveBeenCalled();
    });
});

describe('the inventory', () => {
    it('an agent the inventory names is H1 on the operator\'s declaration, H0 on observation, and not a shadow agent', async () => {
        const inventory = path.join(dir, 'inventory.json');
        fs.writeFileSync(
            inventory,
            JSON.stringify({
                inventory: INVENTORY_SCHEMA_ID,
                agents: [
                    {
                        discoveredId: EXAMPLE_AGENT,
                        name: 'Support agent',
                        owner: 'support-team',
                        purpose: 'Answers order questions',
                        axes: { autonomyLevel: 1, dataAccessScope: 'READ_TENANT_DATA', reversibility: 'REVERSIBLE', provenance: 'FIRST_PARTY' },
                        riskTier: 'LOW',
                        riskAssessedOn: new Date(Date.now() - 86_400_000).toISOString().slice(0, 10),
                    },
                ],
            }),
        );
        expect(await main(['scan', '--config', writeConfig(configJson({ inventory: { path: inventory } })), '--out', outDir, '--dry-run'], LOCAL_ENV)).toBe(0);
        const [run] = runs();
        const results = resultsOf(run);
        expect(results.agents[0].judgement).toMatchObject({ state: 'JUDGED', level: 'H1', observedLevel: 'H0' });
        expect(results.estate.shadowAgents).toEqual([]);
        expect(results.findings.map((f) => f.code)).not.toContain('SHADOW_AGENT');
        expect(read(run, RUN_FILE_NAMES.summary)).toContain('declared by the operator');
        expect(read(run, RUN_FILE_NAMES.agents)).toContain('"Support agent","support-team"');
        // The declaration is local: it is not in the signed report.
        expect(out.join('')).not.toContain('support-team');
    });

    it('an inventory that cannot be read stops the run before any source is read', async () => {
        const config = writeConfig(configJson({ inventory: { path: path.join(dir, 'absent.csv') } }));
        await expect(main(['scan', '--config', config, '--out', outDir, '--dry-run'], LOCAL_ENV)).rejects.toThrow(/inventory/i);
        expect(err).toEqual([]);
        expect(out).toEqual([]);
        expect(fs.existsSync(outDir)).toBe(false);
    });
});

describe('the committed examples', () => {
    it('config.local.template.json with inventory.example.json: no tenant, the agent declared, one declared agent not found', async () => {
        const template = fs.readFileSync(path.join(REPO, 'examples', 'code-only', 'config.local.template.json'), 'utf8');
        const config = parseScannerConfig(JSON.parse(template.replace(/__REPO__/g, REPO)) as unknown);
        expect(config.inflect).toBeUndefined();
        const result = await scanAndDeliver({
            config,
            env: LOCAL_ENV,
            log: jsonLineLog(() => undefined),
            outputs: resolveOutputs(config, { out: outDir }),
            // A fixed time inside the inventory's 365 days.
            now: () => Date.parse('2026-11-03T03:30:00.000Z'),
        });
        expect(result.ok).toBe(true);
        expect(fetched).not.toHaveBeenCalled();
        const results = resultsOf(agentsOf(result).body.scan.id);
        expect(results.agents[0]).toMatchObject({
            discoveredId: EXAMPLE_AGENT,
            declared: { name: 'Support order lookup', owner: 'support-operations', row: 1 },
            judgement: { state: 'JUDGED', level: 'H1', observedLevel: 'H0' },
        });
        expect(results.inventory).toMatchObject({ rows: 2, matched: 1, unmatched: ['code:example/billing/agent.py#billing_executor'] });
        expect(results.coverage.reachableLevel).toBe('H1');
    });
});

describe('an incomplete source', () => {
    it('the run still delivers, the agent is not judged, and no output states a level for it', async () => {
        const roots = [
            { label: 'example', path: path.join(REPO, 'examples', 'code-only', 'estate') },
            { label: 'missing', path: path.join(dir, 'no-such-root') },
        ];
        expect(await main(['scan', '--config', writeConfig(configJson({}, roots)), '--out', outDir, '--dry-run'], LOCAL_ENV)).toBe(0);
        const [run] = runs();
        const results = resultsOf(run);
        expect(results.scan.complete).toBe(false);
        expect(results.agents[0].judgement).toEqual({ state: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:code:UNREACHABLE'] });
        expect(results.findings.map((f) => f.code).sort()).toEqual(['INCOMPLETE_SOURCE', 'SHADOW_AGENT', 'UNPINNED_WRITE_TOOL']);

        const page = read(run, RUN_FILE_NAMES.summary);
        expect(page).toContain('<strong>Incomplete:</strong> 1 of 1 source was not read in full.');
        expect(page.match(/<span class="tag warn">Not judged<\/span>/g)).toHaveLength(2);
        const matrix = page.slice(page.indexOf('<section id="matrix"'), page.indexOf('<section id="shadow"'));
        const row = matrix.slice(matrix.indexOf('<tbody>'));
        expect(row.split('<td class="lvl">').slice(1).map((c) => c.slice(0, c.indexOf('</td>'))).join('')).not.toMatch(/H\d/);

        const [header, line] = read(run, RUN_FILE_NAMES.agents).slice(1).trimEnd().split('\r\n').map((l) => l.slice(1, -1).split('","'));
        const col = (name: string) => line[header.indexOf(name)];
        expect([col('judged'), col('level'), col('observedLevel'), col('bar'), col('shortfall')]).toEqual(['no', '', '', '', '']);
        expect(read(run, RUN_FILE_NAMES.findings)).not.toContain('HARNESS_SHORTFALL');
        expect(JSON.parse(fs.readFileSync(path.join(outDir, 'latest.json'), 'utf8'))).toMatchObject({ complete: false, agentCount: 1 });
    });
});

describe('diff and help', () => {
    it('two runs into one directory compare as the same; a run with one more agent differs', async () => {
        const config = writeConfig(configJson());
        expect(await main(['scan', '--config', config, '--out', outDir, '--dry-run'], LOCAL_ENV)).toBe(0);
        const firstRun = runs()[0];
        const before = fs.readFileSync(path.join(outDir, 'runs', firstRun, RUN_FILE_NAMES.results), 'utf8');
        // A later run has a later time: `diff` refuses two runs taken in the same millisecond.
        await new Promise((r) => setTimeout(r, 25));
        expect(await main(['scan', '--config', config, '--out', outDir, '--dry-run'], LOCAL_ENV)).toBe(0);
        expect(runs()).toHaveLength(2);
        const secondRun = runs().find((r) => r !== firstRun) as string;
        // The first run is untouched by the second, and the pointer names the newer one.
        expect(fs.readFileSync(path.join(outDir, 'runs', firstRun, RUN_FILE_NAMES.results), 'utf8')).toBe(before);
        const [older, newer] = [firstRun, secondRun].sort((a, b) => (resultsOf(a).scan.asOf < resultsOf(b).scan.asOf ? -1 : 1));
        expect((JSON.parse(fs.readFileSync(path.join(outDir, 'latest.json'), 'utf8')) as { scanId: string }).scanId).toBe(newer);

        const a = path.join(outDir, 'runs', older, RUN_FILE_NAMES.results);
        const b = path.join(outDir, 'runs', newer, RUN_FILE_NAMES.results);
        out.length = 0;
        expect(await main(['diff', a, b], {})).toBe(0);
        expect(out.join('')).toContain('No difference, and every comparison could be made.');

        // The estate, copied, with one more agent definition.
        const estate = path.join(dir, 'estate');
        fs.cpSync(path.join(REPO, 'examples', 'code-only', 'estate'), estate, { recursive: true });
        fs.mkdirSync(path.join(estate, 'billing'));
        fs.writeFileSync(
            path.join(estate, 'billing', 'agent.py'),
            fs.readFileSync(path.join(estate, 'support', 'agent.py'), 'utf8').replace(/support_executor/g, 'billing_executor'),
        );
        await new Promise((r) => setTimeout(r, 25));
        const grown = writeConfig(configJson({}, [{ label: 'example', path: estate }]), 'grown.json');
        expect(await main(['scan', '--config', grown, '--out', outDir, '--dry-run'], LOCAL_ENV)).toBe(0);
        const third = runs().find((r) => r !== firstRun && r !== secondRun) as string;
        out.length = 0;
        expect(await main(['diff', b, path.join(outDir, 'runs', third, RUN_FILE_NAMES.results)], {})).toBe(1);
        expect(out.join('')).toContain('  new        code:example/billing/agent.py#billing_executor');
        // And the signed reports of the same two runs say the same.
        out.length = 0;
        expect(await main(['diff', path.join(outDir, 'runs', newer, RUN_FILE_NAMES.report), path.join(outDir, 'runs', third, RUN_FILE_NAMES.report), '--trust-key', PUBLIC_HEX], {})).toBe(1);
        expect(out.join('')).toContain('  new        code:example/billing/agent.py#billing_executor');
    }, 20_000);

    it('diff needs no configuration, and its usage is its own', async () => {
        expect(await main(['diff'], {})).toBe(2);
        expect(err.join('')).toBe(`${DIFF_USAGE}\n`);
        expect(DIFF_USAGE).toBe('usage: scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]');
    });

    it.each(['help', '--help', '-h'])('%s prints the commands to stdout and exits 0', async (word) => {
        expect(await main([word], {})).toBe(0);
        expect(out.join('')).toBe(HELP);
        expect(err).toEqual([]);
        for (const line of [
            'scanent scan       --config <file> [--out <dir>] [--dry-run]',
            'scanent schedule   --config <file> [--out <dir>]',
            'scanent public-key --config <file>',
            'scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]',
            'scanent help',
        ]) {
            expect(HELP).toContain(line);
        }
    });

    it.each([
        ['scan', '--help'],
        ['schedule', '-h'],
        ['public-key', '--help'],
    ])('%s %s prints the commands and exits 0, reading no configuration', async (command, flag) => {
        expect(await main([command, flag], {})).toBe(0);
        expect(out.join('')).toBe(HELP);
        expect(err).toEqual([]);
        expect(await main([command, '--config', path.join(dir, 'no-such-config.json'), flag], {})).toBe(0);
    });

    it('--out=<dir> writes the run where it names, as --out <dir> does', async () => {
        const config = writeConfig(configJson());
        const equals = path.join(dir, 'equals');
        expect(await main(['scan', `--config=${config}`, `--out=${equals}`, '--dry-run'], LOCAL_ENV)).toBe(0);
        expect(fs.readdirSync(path.join(equals, 'runs'))).toHaveLength(1);
        expect(fs.existsSync(path.join(equals, 'latest.json'))).toBe(true);
        // With no directory after the sign it is refused, as a bare --out is.
        err.length = 0;
        expect(await main(['scan', '--config', config, '--out=', '--dry-run'], LOCAL_ENV)).toBe(2);
        expect(err.join('')).toBe('--out takes a directory\n');
    });

    it.each([
        ['a flag the command does not have', ['--bogus']],
        ['a flag of another command', ['--format', 'json']],
        ['a mistyped flag with a value', ['--output=/tmp/x']],
        ['a stray word', ['immediately']],
    ])('scan and schedule refuse %s before anything is read or run', async (_label, extra) => {
        const config = writeConfig(configJson());
        for (const command of ['scan', 'schedule']) {
            err.length = 0;
            expect(await main([command, '--config', config, '--out', outDir, ...extra], LOCAL_ENV)).toBe(2);
            expect(err.join('')).toBe(
                'usage: scanent <scan|schedule|public-key> --config <file> [--dry-run]\n'
                + `unknown argument for ${command}; run 'scanent help' for every command and flag\n`,
            );
            // The argument itself is not repeated: it may be a mistyped secret.
            expect(err.join('')).not.toContain(extra[0]);
        }
        expect(out).toEqual([]);
        expect(fs.existsSync(outDir)).toBe(false);
    });

    it('the usage error is what it always was, byte for byte', async () => {
        expect(await main(['scan'], {})).toBe(2);
        // Its first line, byte for byte; a second line now points to `help` (Phase 3 review).
        expect(err.join('').split('\n')[0]).toBe('usage: scanent <scan|schedule|public-key> --config <file> [--dry-run]');
        expect(err.join('')).toBe(`usage: scanent <scan|schedule|public-key> --config <file> [--dry-run]\n${USAGE_HINT}`);
    });
});
