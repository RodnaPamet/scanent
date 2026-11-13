/**
 * `scanent diff`: reading two runs, and the exit code.
 *
 *   1. Usage.
 *   2. Results files and signed reports are told apart by content, and may be
 *      mixed. A signed report is verified before it is believed.
 *   3. What is refused, by side and by rule, never by a value from the file.
 *   4. The four exit codes, and the two formats.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { diffResults } from '@scanent/report/diff/diff';
import { renderResultsJson } from '@scanent/report/render/results-json';
import { INVENTORY_SCHEMA_ID, parseInventory } from '@scanent/report/results/inventory';
import type { LocalResults } from '@scanent/report/results/types';

import { DIFF_USAGE, DiffInputError, loadDiffSide, MAX_DIFF_INPUT_BYTES, parseDiffArgs, runDiff } from '../src/diff-command';
import { scoreScanLocally } from '../src/local-results';
import { jsonLineLog } from '../src/log';
import { runScan } from '../src/scan';
import { configOf, ENV, EXAMPLE_AGENT, noFetch, PUBLIC_HEX, scanExample } from './helpers/output-fixtures';

const T1 = Date.parse('2026-11-03T03:30:00.000Z');
const DAY = 24 * 3_600_000;

let dir: string;
let first: { raw: string; results: LocalResults };
let second: { raw: string; results: LocalResults };
beforeAll(async () => {
    first = await scanExample(T1);
    second = await scanExample(T1 + DAY);
});
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-diff-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function file(name: string, content: string): string {
    const p = path.join(dir, name);
    fs.writeFileSync(p, content);
    return p;
}
const resultsFile = (name: string, results: LocalResults): string => file(name, renderResultsJson(results));

function run(argv: string[]): { code: number; out: string; err: string } {
    const out: string[] = [];
    const err: string[] = [];
    const code = runDiff(argv, { stdout: (t) => out.push(t), stderr: (t) => err.push(t) });
    return { code, out: out.join(''), err: err.join('') };
}

/** The second run with one more agent, as a later scan that found it would report. */
function withNewAgent(results: LocalResults): LocalResults {
    const copy = { ...results.agents[0], discoveredId: 'code:example/billing/agent.py#billing_executor' };
    return {
        ...results,
        agents: [copy, ...results.agents],
        estate: { ...results.estate, agentCount: 2, judgedCount: 2, byLevel: { ...results.estate.byLevel, H0: 2 }, shortfallCount: 2 },
    };
}

describe('1. usage', () => {
    it.each([
        ['no paths', []],
        ['one path', ['a.json']],
        ['three paths', ['a.json', 'b.json', 'c.json']],
        ['an unknown flag', ['a.json', 'b.json', '--verbose']],
        ['a format it does not have', ['a.json', 'b.json', '--format', 'yaml']],
        ['--format without a value', ['a.json', 'b.json', '--format']],
        ['a trust key that is not 64 hex characters', ['a.json', 'b.json', '--trust-key', 'abc']],
        ['--trust-key without a value', ['a.json', 'b.json', '--trust-key']],
    ])('%s is a usage error: exit 2, the usage line, nothing read', (_label, argv) => {
        const { code, out, err } = run(argv);
        expect(code).toBe(2);
        expect(err).toBe(`${DIFF_USAGE}\n`);
        expect(out).toBe('');
        expect(parseDiffArgs(argv)).toBeNull();
    });

    it('reads its flags in any position', () => {
        expect(parseDiffArgs(['--format', 'json', 'a', '--allow-different-scanner', 'b', '--trust-key', PUBLIC_HEX])).toEqual({
            paths: ['a', 'b'],
            format: 'json',
            trustKey: PUBLIC_HEX,
            allowDifferentScanner: true,
        });
        expect(parseDiffArgs(['a', 'b'])).toEqual({ paths: ['a', 'b'], format: 'text', trustKey: null, allowDifferentScanner: false });
    });
});

describe('2. inputs', () => {
    it('two results files of the same estate: no difference, exit 0', () => {
        const { code, out, err } = run([resultsFile('old.json', first.results), resultsFile('new.json', second.results)]);
        expect(code).toBe(0);
        expect(err).toBe('');
        expect(out.startsWith('scanent diff: No difference, and every comparison could be made.\n')).toBe(true);
        expect(out).toContain(`old: scan ${first.results.scan.id}`);
        expect(out).toContain(`new: scan ${second.results.scan.id}`);
    });

    it('a results file is known by its content, whatever it is called', () => {
        const { code } = run([resultsFile('monday.txt', first.results), resultsFile('tuesday', second.results)]);
        expect(code).toBe(0);
    });

    it('a new agent is a difference: exit 1, listed as new', () => {
        const { code, out } = run([resultsFile('old.json', first.results), resultsFile('new.json', withNewAgent(second.results))]);
        expect(code).toBe(1);
        expect(out).toContain('scanent diff: The two runs differ.');
        expect(out).toContain('  new        code:example/billing/agent.py#billing_executor');
    });

    it('two signed reports are verified and scored: the output says the signer is not pinned', () => {
        const { code, out } = run([file('old.signed.json', first.raw), file('new.signed.json', second.raw)]);
        expect(code).toBe(0);
        expect(out).toContain('SIGNER_NOT_PINNED:old');
        expect(out).toContain('SIGNER_NOT_PINNED:new');
        expect(out).toContain('REGISTER_CLAIMS_NOT_VERIFIED:new');
        expect(out).toContain('signer not pinned');
    });

    it('with --trust-key the signer is pinned', () => {
        const { code, out } = run([file('old.signed.json', first.raw), file('new.signed.json', second.raw), '--trust-key', PUBLIC_HEX]);
        expect(code).toBe(0);
        expect(out).not.toContain('SIGNER_NOT_PINNED');
        expect(out).toContain('signer pinned');
    });

    it('a results file against a signed report compares, and states the inventory difference', async () => {
        const inventory = parseInventory(
            {
                inventory: INVENTORY_SCHEMA_ID,
                agents: [
                    {
                        discoveredId: EXAMPLE_AGENT,
                        name: 'Support agent',
                        owner: 'support-team',
                        purpose: 'Answers order questions',
                        axes: { autonomyLevel: 1, dataAccessScope: 'READ_TENANT_DATA', reversibility: 'REVERSIBLE', provenance: 'FIRST_PARTY' },
                        riskTier: 'LOW',
                        riskAssessedOn: '2026-09-30',
                    },
                ],
            },
            { sha256: 'e'.repeat(64), format: 'json' },
        );
        const config = configOf();
        const scan = await runScan({ config, env: ENV, log: jsonLineLog(() => undefined), fetchImpl: noFetch, now: () => T1 });
        const declared = scoreScanLocally({ config, raw: scan.raw, body: scan.body, inventory });
        const { code, out } = run([resultsFile('old.json', declared), file('new.signed.json', second.raw)]);
        expect(code).toBe(1);
        expect(out).toContain('INVENTORY_DIFFERS');
        expect(out).toContain(`inventory sha256:${'e'.repeat(64)}`);
        expect(out).toContain('inventory none');
        expect(out).toContain(`${EXAMPLE_AGENT}: level down, H1 -> H0`);
        expect(out).toContain(`${EXAMPLE_AGENT} registration: DECLARED_INVENTORY -> NONE`);
    });

    it('a signed report is scored as a bare report: no estate label, register claims not verified', () => {
        const side = loadDiffSide(first.raw, 'old', null);
        expect(side.scan).toMatchObject({ estate: null, registerClaimsVerified: false, id: first.results.scan.id });
        expect(side.report).toEqual({ ...first.results.report, signerPinned: false });
        expect(side.agents).toEqual(first.results.agents);
        expect(loadDiffSide(first.raw, 'old', PUBLIC_HEX).report.signerPinned).toBe(true);
    });
});

describe('3. refusals', () => {
    const good = () => resultsFile('good.json', second.results);

    it.each([
        ['a file that does not exist', () => path.join(dir, 'absent.json'), 'old: the file could not be read'],
        ['a directory', () => dir, 'old: the file could not be read'],
        ['text that is not JSON', () => file('x.json', '{ "schema": '), 'old: not JSON'],
        ['a JSON array', () => file('x.json', '[]'), 'old: not a results file or a signed report'],
        // Phase 4: an object that names no schema, or another one, is told which this version reads.
        ['a JSON object that is neither', () => file('x.json', '{"hello":"world"}'), 'old: the file names no schema; this version reads scanent-results/1 files and signed inflect-agent-harness/2, inflect-agent-harness/3 and inflect-agent-harness/4 reports'],
        ['a results file of a later schema', () => file('x.json', JSON.stringify({ ...first.results, schema: 'scanent-results/2' })), 'old: the file names "scanent-results/2" as its schema; this version reads scanent-results/1'],
        ['a schema id of another family, which is not repeated', () => file('x.json', '{"schema":"zz-something-else/1"}'), 'old: the file names a schema this version does not know as its schema; this version reads scanent-results/1'],
        ['a schema id that is not text', () => file('x.json', '{"schema":2}'), 'old: the file names a schema this version does not know as its schema; this version reads scanent-results/1'],
        ['a results file with a member missing', () => file('x.json', JSON.stringify({ ...first.results, coverage: undefined })), 'old: not a valid scanent-results/1 file (coverage: invalid_type)'],
        ['a results file with an unknown member', () => file('x.json', JSON.stringify({ ...first.results, extra: 1 })), 'old: not a valid scanent-results/1 file ((root): unrecognized_keys)'],
    ])('%s: exit 2, the side and the rule', (_label, make, message) => {
        const { code, out, err } = run([make(), good()]);
        expect(code).toBe(2);
        expect(out).toBe('');
        expect(err).toBe(`scanent diff: ${message}\n`);
    });

    it('the side refused is named: a bad second file is "new"', () => {
        expect(run([good(), file('x.json', 'nope')]).err).toBe('scanent diff: new: not JSON\n');
    });

    it('a not-judged agent that carries a level is not a valid results file', () => {
        const forged = JSON.parse(renderResultsJson(first.results)) as { agents: { judgement: Record<string, unknown> }[] };
        forged.agents[0].judgement = { state: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:code:TIME_BOX'], level: 'H5' };
        const { code, err } = run([file('x.json', JSON.stringify(forged)), good()]);
        expect(code).toBe(2);
        expect(err).toContain('old: not a valid scanent-results/1 file');
    });

    it('a signed report that was altered after signing is refused', () => {
        const tampered = first.raw.replace('support_executor', 'support_executoX');
        expect(tampered).not.toBe(first.raw);
        const { code, err } = run([file('x.json', tampered), good()]);
        expect(code).toBe(2);
        expect(err).toBe('scanent diff: old: the signed report was refused (BAD_SIGNATURE)\n');
    });

    it('a signed report from a key other than the trusted one is refused', () => {
        const other = 'ab'.repeat(32);
        const { code, err } = run([file('x.json', first.raw), good(), '--trust-key', other]);
        expect(code).toBe(2);
        expect(err).toBe('scanent diff: old: the signed report was refused (UNTRUSTED_SIGNER)\n');
    });

    it('a signed report with no usable signature is refused', () => {
        const parsed = JSON.parse(first.raw) as Record<string, unknown>;
        expect(run([file('x.json', JSON.stringify({ ...parsed, signature: null })), good()]).err).toContain('old: the signed report was refused (');
        expect(run([file('y.json', JSON.stringify({ ...parsed, signature: { sig: 'x' } })), good()]).err).toContain('old: the signed report was refused (');
    });

    it('the runs in the wrong order, or the same run twice, are refused', () => {
        const a = resultsFile('a.json', first.results);
        const b = resultsFile('b.json', second.results);
        expect(run([b, a])).toMatchObject({ code: 2, out: '', err: 'scanent diff: the new scan is not later than the old one; give the older run first\n' });
        expect(run([a, a]).code).toBe(2);
    });

    it('different ladder versions are refused', () => {
        const other: LocalResults = { ...second.results, ladder: { ...second.results.ladder, version: `sha256:${'0'.repeat(64)}` } };
        const { code, err } = run([resultsFile('a.json', first.results), resultsFile('b.json', other)]);
        expect(code).toBe(2);
        expect(err).toContain('different ladder versions');
    });

    it('different scanners are refused without the flag, and compared with it', () => {
        const other: LocalResults = { ...second.results, scan: { ...second.results.scan, scanner: { ...second.results.scan.scanner, agentId: 'agt_other' } } };
        const a = resultsFile('a.json', first.results);
        const b = resultsFile('b.json', other);
        expect(run([a, b])).toMatchObject({ code: 2, out: '' });
        expect(run([a, b]).err).toContain('--allow-different-scanner');
        const allowed = run([a, b, '--allow-different-scanner']);
        expect(allowed.code).toBe(0);
        expect(allowed.out).toContain('SCANNER_DIFFERS');
    });

    it('a file larger than the cap is not read', () => {
        const big = path.join(dir, 'big.json');
        const fd = fs.openSync(big, 'w');
        fs.ftruncateSync(fd, MAX_DIFF_INPUT_BYTES + 1);
        fs.closeSync(fd);
        expect(run([big, good()])).toMatchObject({ code: 2, err: 'scanent diff: old: the file could not be read\n' });
    });

    it('an error that is not about the inputs is not swallowed', () => {
        expect(() =>
            runDiff([good(), good()], {
                stdout: () => undefined,
                stderr: () => undefined,
                readFile: () => {
                    throw new RangeError('unexpected');
                },
            }),
        ).not.toThrow();
        const io = { stdout: () => { throw new RangeError('the pipe closed'); }, stderr: () => undefined };
        expect(() => runDiff([resultsFile('a.json', first.results), good()], io)).toThrow('the pipe closed');
        expect(new DiffInputError('x').name).toBe('DiffInputError');
    });
});

describe('3b. nothing secret, and nothing a terminal obeys, is printed', () => {
    const renamed = (results: LocalResults, id: string): LocalResults => ({ ...results, agents: results.agents.map((a) => ({ ...a, discoveredId: id })) });

    it('a secret shape that only the comparison assembles refuses the output: exit 2, nothing on stdout', () => {
        // Clean as a member of either file; `AGENT_NOT_SEEN:` in front of it makes a URL with a password.
        const id = '//operator:hunter2hunter2@db.internal.example';
        const a = resultsFile('a.json', renamed(first.results, id));
        const b = resultsFile('b.json', { ...second.results, sources: second.results.sources.map((s) => ({ ...s, status: 'INCOMPLETE' as const, reason: 'TIME_BOX' })), scan: { ...second.results.scan, complete: false } });
        for (const format of ['text', 'json']) {
            const result = run([a, b, '--format', format]);
            expect(result.code).toBe(2);
            expect(result.out).toBe('');
            // The data check names the member, never the value.
            expect(result.err).toMatch(/^scanent diff: output refused: the diff: notConcluded\[\d+\] has the shape of a secret; nothing was written\n$/);
            expect(result.err).not.toContain('hunter2');
        }
    });

    it('a rendered text with a secret shape is refused even when no member of the diff has one', () => {
        const a = resultsFile('a.json', first.results);
        const b = resultsFile('b.json', second.results);
        const out: string[] = [];
        const err: string[] = [];
        const code = runDiff([a, b], {
            stdout: (t) => out.push(t),
            stderr: (t) => err.push(t),
            // A renderer that joins two clean values into one secret-shaped line.
            render: () => 'scan https://operator' + ':hunter2hunter2' + '@db.internal.example\n',
        });
        expect(code).toBe(2);
        expect(out).toEqual([]);
        expect(err.join('')).toBe('scanent diff: output refused: the diff output has the shape of a secret; nothing was written\n');
        // The same call with the real renderer prints, so the refusal above is the check and not the inputs.
        expect(run([a, b]).code).toBe(0);
    });

    it('an id carrying an escape sequence, a line break and a C1 control prints as one visible line, in both formats', () => {
        const id = 'evil\u001b[2J\u0007\nscanent diff: No difference, and every comparison could be made.\r\u009b31m';
        const a = resultsFile('a.json', first.results);
        const b = resultsFile('b.json', withNewAgent({ ...second.results, agents: [{ ...second.results.agents[0], discoveredId: `${EXAMPLE_AGENT}` }] }));
        const hostile = resultsFile('c.json', JSON.parse(fs.readFileSync(b, 'utf8').replace('code:example/billing/agent.py#billing_executor', JSON.stringify(id).slice(1, -1))) as LocalResults);
        const text = run([a, hostile]);
        expect(text.code).toBe(1);
        expect(text.out).not.toMatch(/[^\P{Cc}\n]/u);
        expect(text.out.split('\n').filter((l) => l.startsWith('scanent diff:'))).toEqual(['scanent diff: The two runs differ.']);
        expect(text.out).toContain('  new        evil\\u{1b}[2J\\u{7}\\u{a}scanent diff: No difference');
        const json = run([a, hostile, '--format', 'json']);
        expect(json.out).not.toMatch(/[^\P{Cc}\n]/u);
        expect((JSON.parse(json.out) as { agents: { added: string[] } }).agents.added).toEqual([id]);
    });
});

describe('4. exit codes and formats', () => {
    async function incompletePair(): Promise<[string, string]> {
        const config = configOf({}, [
            { label: 'example', path: path.resolve(__dirname, '..', '..', '..', 'examples', 'code-only', 'estate') },
            { label: 'missing', path: '/nonexistent/scanent-estate' },
        ]);
        const a = await scanExample(T1, config);
        const b = await scanExample(T1 + DAY, config);
        return [resultsFile('a.json', a.results), resultsFile('b.json', b.results)];
    }

    it('identical runs with an agent that was not judged exit 3: the same as far as could be compared', async () => {
        const [a, b] = await incompletePair();
        const { code, out } = run([a, b]);
        expect(code).toBe(3);
        expect(out).toContain('No difference was found, but not every comparison could be made.');
        expect(out).toContain(`AGENT_NOT_JUDGED:${EXAMPLE_AGENT}`);
        // No level is stated for the agent anywhere in the comparison.
        expect(out).not.toMatch(/\bH[0-5]\b/);
    });

    it('--format json is the diff object itself', async () => {
        const a = resultsFile('a.json', first.results);
        const b = resultsFile('b.json', withNewAgent(second.results));
        const { code, out } = run([a, b, '--format', 'json']);
        expect(code).toBe(1);
        expect(JSON.parse(out)).toEqual(JSON.parse(JSON.stringify(diffResults(first.results, withNewAgent(second.results)))));
        expect(out.endsWith('}\n')).toBe(true);
        const same = run([a, resultsFile('c.json', second.results), '--format', 'json']);
        expect(same.code).toBe(0);
        expect(JSON.parse(same.out)).toMatchObject({ schema: 'scanent-diff/1', outcome: 'SAME' });
    });
});
